package ldrclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

var (
	ErrSlotBusy         = errors.New("ldrclient: an unresolved intent already holds this slot")
	ErrMustResolve      = errors.New("ldrclient: stored unsettled intents must be resolved before composing")
	ErrFailClosed       = errors.New("ldrclient: client failed closed due to violation or suspected rollback")
	ErrKeyRevoked       = errors.New("ldrclient: key is revoked and signs nothing more")
	ErrNotActivated     = errors.New("ldrclient: member has not completed O25 enrollment verification")
	ErrOutboxUncertain  = errors.New("ldrclient: durable outbox state uncertain after persistence failure; reconcile required")
	ErrEpochsUncertain  = errors.New("ldrclient: durable epoch key state uncertain after persistence failure; reconcile required")
	ErrCursorsUncertain = errors.New("ldrclient: durable cursor state uncertain after persistence failure; reconcile required")
	ErrNoEpochKey       = errors.New("ldrclient: no epoch key available for payload encryption")
	ErrEnrollmentCheck  = errors.New("ldrclient: committed enrollment disagrees with saved P3 request")
	ErrViolation        = errors.New("ldrclient: sequencer violation detected on replay")
)

var transientAdmission = map[string]bool{
	"overloaded":      true,
	"quota":           true,
	"clock_uncertain": true,
}

type signedAnchor struct {
	head [32]byte
	time uint64
}

type replayContext struct {
	anchors map[uint64]signedAnchor
	ops     map[ldrstore.StoredOpKey]uint64
}

func newReplayContext() *replayContext {
	return &replayContext{
		anchors: make(map[uint64]signedAnchor),
		ops:     make(map[ldrstore.StoredOpKey]uint64),
	}
}

func (rc *replayContext) prune(headTime, validityMaxMS uint64) {
	var retired map[uint64]bool
	for seq, a := range rc.anchors {
		if headTime > a.time+validityMaxMS {
			if retired == nil {
				retired = make(map[uint64]bool)
			}
			retired[seq] = true
			delete(rc.anchors, seq)
		}
	}
	if len(retired) == 0 {
		return
	}
	for k := range rc.ops {
		if retired[k.SeenSeq] {
			delete(rc.ops, k)
		}
	}
}

type verifiedEntry struct {
	frame     ldrrelay.ControlFrameWire
	decoded   *ldrrelay.DecodedIntent // nil for time_anchor
	touched   []string
	owed      []LocalNotice
	disputeID string // populated for committed dispute_open at this exact seq
}

type committedRegisterActivation struct {
	Actor       string
	Register    string
	WriterRev   uint64
	BindingGen  uint64
	Incarnation string
	Cred        string
}

// Client is the durable local LDR client for one pinned line and local directory.
// Safe for concurrent use within one process and protected by an exclusive OS
// flock across processes.
type Client struct {
	mu       sync.Mutex
	dir      string
	lockFile *os.File
	closed   bool

	cfg        persistedConfig
	desc       ldrcrypto.CreationDescriptor
	profDigest [32]byte
	coreProf   ldrcore.Profile
	validityMS uint64

	// Optional local keys attached to this client instance.
	credKeys    *CredentialKeyBundle
	operatorKey *SigningKeyMaterial
	rootKey     *SigningKeyMaterial

	// Authoritative verified local state (rebuilt from verified.wal on Open).
	state          ldrcore.State
	entries        []verifiedEntry
	ckGen          uint64
	ckSeq          uint64
	ckHead         [32]byte
	rctx           *replayContext
	touched        map[string]projCoord
	source         map[string]projCoord
	viewOf         map[string]string
	regActivations map[string]map[uint64]committedRegisterActivation

	// Durable outbox, epoch keys, and projection/delivery cursors.
	outbox                 persistedOutbox
	outboxUncertain        bool
	outboxUncertainReason  string
	pendingStops           map[string]*KeyStop // validated Rule 8 stops awaiting durable outbox.cbor write
	slots                  map[string]string   // slot -> unsettled op_id
	epochs                 persistedEpochs
	epochsUncertain        bool
	epochsUncertainReason  string
	cursors                persistedCursors
	cursorsUncertain       bool
	cursorsUncertainReason string
	registers              persistedRegisters
	registersUncertain     bool
	registersUncertainMsg  string

	// Optional durability hooks (nil defaults to OS SyncFile/SyncDir).
	syncFileFn func(*os.File) error
	syncDirFn  func(string) error
}

// SetSyncHooks overrides file/directory durability barriers used by Client
// outbox persistence and reconciliation (nil restores OS SyncFile/SyncDir).
// Intended for fault-injection tests controlling write visibility vs sync success.
func (c *Client) SetSyncHooks(syncFile func(*os.File) error, syncDir func(string) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncFileFn = syncFile
	c.syncDirFn = syncDir
}

func (c *Client) persistOutboxLocked(ob persistedOutbox) error {
	return saveOutboxWithHooks(c.outboxPath(), ob, c.syncFileFn, c.syncDirFn)
}

func (c *Client) markOutboxUncertainOnErrLocked(err error) {
	if err == nil || errors.Is(err, ldrstore.ErrPreWrite) {
		return
	}
	c.outboxUncertain = true
	c.outboxUncertainReason = err.Error()
}

func (c *Client) persistEpochsLocked(ep persistedEpochs) error {
	return saveEpochsWithHooks(c.epochsPath(), ep, c.syncFileFn, c.syncDirFn)
}

func (c *Client) markEpochsUncertainOnErrLocked(err error) {
	if err == nil || errors.Is(err, ldrstore.ErrPreWrite) {
		return
	}
	c.epochsUncertain = true
	c.epochsUncertainReason = err.Error()
}

func clonePersistedEpochs(ep persistedEpochs) persistedEpochs {
	cp := persistedEpochs{
		Keys:     make(map[uint64][]byte, len(ep.Keys)),
		BadWraps: make(map[uint64]bool, len(ep.BadWraps)),
	}
	for k, v := range ep.Keys {
		cp.Keys[k] = bytes.Clone(v)
	}
	for k, v := range ep.BadWraps {
		if v {
			cp.BadWraps[k] = true
		}
	}
	return cp
}

func (c *Client) persistCursorsLocked(cur persistedCursors) error {
	return saveCursorsWithHooks(c.cursorsPath(), cur, c.syncFileFn, c.syncDirFn)
}

func (c *Client) markCursorsUncertainOnErrLocked(err error) {
	if err == nil || errors.Is(err, ldrstore.ErrPreWrite) {
		return
	}
	c.cursorsUncertain = true
	c.cursorsUncertainReason = err.Error()
}

func clonePersistedCursors(cur persistedCursors) persistedCursors {
	cp := cur
	cp.Notices = make(map[string]*LocalNotice, len(cur.Notices))
	for id, n := range cur.Notices {
		if n != nil {
			nc := *n
			cp.Notices[id] = &nc
		}
	}
	return cp
}

// InitDirOptions configures initializing a fresh client directory for a pinned descriptor.
type InitDirOptions struct {
	Dir                   string
	DirKind               string // DirKindAdmin or DirKindMember (inferred from Activated if empty)
	SignedDescriptor      []byte
	CredKeys              *CredentialKeyBundle // required for DirKindMember; optional for DirKindAdmin
	ExpectedGrant         *ldrcrypto.JoinGrant // required for DirKindMember (P3 ceremony evidence)
	ExpectedJoinReq       []byte               // required for DirKindMember (P3 join_request_id)
	ExpectedJoinReqDigest *[32]byte            // required for DirKindMember (P3 join_request_digest)
	Activated             bool                 // true for admin dirs; false for joining member dirs until O25 gate passes
}

// InitClientDir initializes a fresh durable client directory pinned to SignedDescriptor.
// Joining member directories MUST provide complete P3 ceremony evidence
// (CredKeys, ExpectedGrant, ExpectedJoinReq, ExpectedJoinReqDigest) and start
// with Activated=false; administrative directories are explicitly marked DirKindAdmin.
func InitClientDir(opts InitDirOptions) (*Client, error) {
	if opts.Dir == "" {
		return nil, errors.New("ldrclient: empty client directory")
	}
	kind := opts.DirKind
	if kind == "" {
		if opts.Activated {
			kind = DirKindAdmin
		} else {
			kind = DirKindMember
		}
	}
	switch kind {
	case DirKindMember:
		if opts.Activated {
			return nil, fmt.Errorf("%w: joining member directory cannot start activated", ErrEnrollmentCheck)
		}
		if opts.CredKeys == nil || opts.ExpectedGrant == nil || opts.ExpectedGrant.NamespaceID == "" ||
			len(opts.ExpectedJoinReq) == 0 || opts.ExpectedJoinReqDigest == nil {
			return nil, fmt.Errorf("%w: joining member directory requires complete P3 ceremony evidence (cred keys, grant, request_id, request_digest)", ErrEnrollmentCheck)
		}
	case DirKindAdmin:
		if !opts.Activated {
			return nil, errors.New("ldrclient: administrative directory must specify Activated=true")
		}
	default:
		return nil, fmt.Errorf("ldrclient: invalid dir_kind %q", kind)
	}

	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(opts.SignedDescriptor)
	if err != nil {
		return nil, err
	}
	if opts.CredKeys != nil {
		if _, err := marshalCredentialKeys(opts.CredKeys); err != nil {
			return nil, err
		}
	}

	// Reserve the fresh directory under an exclusive OS flock BEFORE writing
	// any client artifacts so repeated initialization, partially initialized
	// directories, legacy v1 directories, or an already-open directory fail
	// closed without touching existing credentials, outbox, or history.
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(opts.Dir, ".client.lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flockExclusive(lf); err != nil {
		_ = lf.Close()
		return nil, err
	}
	cleanupLock := func() {
		_ = funlock(lf)
		_ = lf.Close()
	}

	entries, err := os.ReadDir(opts.Dir)
	if err != nil {
		cleanupLock()
		return nil, err
	}
	for _, ent := range entries {
		if ent.Name() != ".client.lock" {
			cleanupLock()
			return nil, fmt.Errorf("%w: found existing entry %q in %s", ErrDirInitialized, ent.Name(), opts.Dir)
		}
	}

	if err := os.Mkdir(filepath.Join(opts.Dir, "sidecars"), 0o700); err != nil {
		cleanupLock()
		if os.IsExist(err) {
			return nil, ErrDirInitialized
		}
		return nil, err
	}
	var reqDigCopy *[32]byte
	if opts.ExpectedJoinReqDigest != nil {
		d := *opts.ExpectedJoinReqDigest
		reqDigCopy = &d
	}
	cfg := persistedConfig{
		DirKind:               kind,
		SignedDescriptor:      bytes.Clone(opts.SignedDescriptor),
		LineID:                bytes.Clone(desc.LineID),
		DescriptorDigest:      cd,
		GenesisAnchor:         genesis,
		ExpectedGrant:         opts.ExpectedGrant,
		ExpectedJoinReqID:     bytes.Clone(opts.ExpectedJoinReq),
		ExpectedJoinReqDigest: reqDigCopy,
	}
	if opts.CredKeys != nil {
		cid := opts.CredKeys.CredID
		cfg.ExpectedCredID = &cid
		if err := SaveCredentialKeysCreateOnly(filepath.Join(opts.Dir, "cred.key"), opts.CredKeys); err != nil {
			cleanupLock()
			return nil, err
		}
	}
	// Durably create verified.wal (O_EXCL) BEFORE config.cbor/outbox.cbor so a
	// missing verified.wal on an initialized directory always fails closed as a lost WAL.
	if err := initEmptyVerifiedWAL(filepath.Join(opts.Dir, "verified.wal")); err != nil {
		cleanupLock()
		return nil, err
	}
	if err := saveConfigCreateOnly(filepath.Join(opts.Dir, "config.cbor"), cfg); err != nil {
		cleanupLock()
		return nil, err
	}
	if err := saveOutboxCreateOnly(filepath.Join(opts.Dir, "outbox.cbor"), persistedOutbox{
		Activated: opts.Activated,
		KeyStops:  make(map[string]*KeyStop),
	}); err != nil {
		cleanupLock()
		return nil, err
	}
	if err := ldrstore.SyncDir(opts.Dir); err != nil {
		cleanupLock()
		return nil, err
	}
	// Hand the already-held exclusive lock directly to openClientLocked (zero TOCTOU gap).
	return openClientLocked(opts.Dir, lf, nil, nil, true)
}

// OpenClient opens an existing client directory, acquires its exclusive OS lock,
// enforces durability barriers on outbox.cbor and verified.wal, verifies its
// pinned creation descriptor and ceremony configuration, and replays verified.wal
// from genesis. On restart, any unsettled outbox entry automatically sets
// MustResolve = true (§5.7 rule 3).
func OpenClient(dir string) (*Client, error) {
	return OpenClientWithSyncHooks(dir, nil, nil)
}

// OpenClientWithSyncHooks opens an existing client directory using the provided
// file/directory durability hooks (nil defaults to OS SyncFile/SyncDir).
func OpenClientWithSyncHooks(dir string, syncFile func(*os.File) error, syncDir func(string) error) (*Client, error) {
	return openClient(dir, syncFile, syncDir, true)
}

func openClient(dir string, syncFile func(*os.File) error, syncDir func(string) error, recoverOutbox bool) (*Client, error) {
	if dir == "" {
		return nil, errors.New("ldrclient: empty client directory")
	}
	lockPath := filepath.Join(dir, ".client.lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flockExclusive(lf); err != nil {
		_ = lf.Close()
		return nil, err
	}
	return openClientLocked(dir, lf, syncFile, syncDir, recoverOutbox)
}

func openClientLocked(dir string, lf *os.File, syncFile func(*os.File) error, syncDir func(string) error, recoverOutbox bool) (*Client, error) {
	cleanupLock := func() {
		_ = funlock(lf)
		_ = lf.Close()
	}

	// Enforce durability barriers on outbox.cbor, epochs.cbor, and cursors.cbor
	// (if present) before trusting persisted activation, key, or cursor state on reopen.
	if err := syncOutboxBarrier(filepath.Join(dir, "outbox.cbor"), syncFile, syncDir); err != nil {
		cleanupLock()
		return nil, err
	}
	if err := syncOutboxBarrier(filepath.Join(dir, "epochs.cbor"), syncFile, syncDir); err != nil {
		cleanupLock()
		return nil, err
	}
	if err := syncOutboxBarrier(filepath.Join(dir, "cursors.cbor"), syncFile, syncDir); err != nil {
		cleanupLock()
		return nil, err
	}
	if err := syncOutboxBarrier(filepath.Join(dir, "registers.cbor"), syncFile, syncDir); err != nil {
		cleanupLock()
		return nil, err
	}

	cfg, err := loadConfig(filepath.Join(dir, "config.cbor"))
	if err != nil {
		cleanupLock()
		return nil, err
	}
	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(cfg.SignedDescriptor)
	if err != nil || !bytes.Equal(desc.LineID, cfg.LineID) || cd != cfg.DescriptorDigest || genesis != cfg.GenesisAnchor {
		cleanupLock()
		return nil, fmt.Errorf("ldrclient: pinned config descriptor verification failed: %v", err)
	}
	profDigest, err := desc.Profile.Digest()
	if err != nil {
		cleanupLock()
		return nil, err
	}
	ob, err := loadOutbox(filepath.Join(dir, "outbox.cbor"))
	if err != nil {
		cleanupLock()
		return nil, err
	}
	ep, err := loadEpochs(filepath.Join(dir, "epochs.cbor"))
	if err != nil {
		cleanupLock()
		return nil, err
	}
	cur, err := loadCursors(filepath.Join(dir, "cursors.cbor"))
	if err != nil {
		cleanupLock()
		return nil, err
	}
	regs, err := loadRegisters(filepath.Join(dir, "registers.cbor"))
	if err != nil {
		cleanupLock()
		return nil, err
	}

	c := &Client{
		dir:            dir,
		lockFile:       lf,
		cfg:            cfg,
		desc:           desc,
		profDigest:     profDigest,
		coreProf:       ldrcore.Profile{FreshnessMS: int64(desc.Profile.FreshnessMS), ValidityMaxMS: int64(desc.Profile.MaxValidityMS)},
		validityMS:     min(60_000, desc.Profile.MaxValidityMS),
		ckHead:         genesis,
		rctx:           newReplayContext(),
		touched:        make(map[string]projCoord),
		source:         make(map[string]projCoord),
		viewOf:         make(map[string]string),
		regActivations: make(map[string]map[uint64]committedRegisterActivation),
		outbox:         ob,
		pendingStops:   make(map[string]*KeyStop),
		slots:          make(map[string]string),
		epochs:         ep,
		cursors:        cur,
		registers:      regs,
		syncFileFn:     syncFile,
		syncDirFn:      syncDir,
	}
	// If cred.key exists on disk, it MUST decode cleanly — never ignore a
	// corrupt or unreadable cred.key (which could allow later replacement!).
	if _, statErr := os.Stat(c.credKeyPath()); statErr == nil {
		ck, err := LoadCredentialKeys(c.credKeyPath())
		if err != nil {
			cleanupLock()
			return nil, fmt.Errorf("ldrclient: existing cred.key failed to decode: %w", err)
		}
		c.credKeys = ck
	} else if !os.IsNotExist(statErr) {
		cleanupLock()
		return nil, statErr
	}
	if c.cfg.DirKind == DirKindMember {
		if err := c.validateMemberCeremonyConfigLocked(); err != nil {
			cleanupLock()
			return nil, err
		}
	}
	// Rebuild slot index and enforce restart §5.7 rule 3: start a fresh
	// resolution epoch whenever unsettled intents exist, marking every
	// unsettled intent NeedsResolve so all active signers must be queried.
	hasUnsettled := false
	for _, e := range c.outbox.Entries {
		if e.Status == ldrcore.OutPending || e.Status == ldrcore.OutReconcile {
			c.slots[e.Slot] = e.OpID
			hasUnsettled = true
		}
	}
	if recoverOutbox && hasUnsettled {
		candidate := clonePersistedOutbox(c.outbox)
		candidate.ResolveEpoch++
		candidate.MustResolve = true
		for _, e := range candidate.Entries {
			if e.Status == ldrcore.OutPending || e.Status == ldrcore.OutReconcile {
				e.NeedsResolve = true
			}
		}
		if err := c.persistOutboxLocked(candidate); err != nil {
			cleanupLock()
			return nil, err
		}
		c.outbox = candidate
	}

	// Replay verified.wal from seq 1 (with durability barrier) to reconstruct exact verified state.
	frames, err := loadVerifiedWAL(c.walPath(), syncFile, syncDir)
	if err != nil {
		cleanupLock()
		return nil, err
	}
	for _, fr := range frames {
		if err := c.verifyAndApplyFrameLocked(fr, false); err != nil {
			cleanupLock()
			return nil, fmt.Errorf("ldrclient: verified.wal replay failed: %w", err)
		}
	}
	if c.cursors.ScannedSeq > c.ckSeq || c.cursors.ProjectedSeq > c.ckSeq {
		cleanupLock()
		return nil, fmt.Errorf("%w: persisted cursors (scanned=%d projected=%d) exceed verified.wal seq %d",
			ldrstore.ErrCorruptWAL, c.cursors.ScannedSeq, c.cursors.ProjectedSeq, c.ckSeq)
	}
	// Defense-in-depth: a reopened member directory claiming Activated=true
	// MUST be backed by a verified credential_enroll record in verified.wal
	// matching its complete saved P3 ceremony evidence.
	if c.cfg.DirKind == DirKindMember && c.outbox.Activated {
		if err := c.verifyEnrolledMemberLocked(false, true); err != nil {
			cleanupLock()
			return nil, fmt.Errorf("ldrclient: persisted activated flag lacks verified enrollment: %w", err)
		}
	}
	return c, nil
}

// Close releases the client directory lock.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.lockFile != nil {
		_ = funlock(c.lockFile)
		err := c.lockFile.Close()
		c.lockFile = nil
		return err
	}
	return nil
}

// AttachAdminReaderKeys persists and attaches a reader credential key bundle
// strictly create-only inside an existing administrative (DirKindAdmin)
// directory so P9 epoch activation can run on an already-activated admin
// directory. Refuses with ErrCredentialExists if any cred.key already exists
// (including one that cannot be decoded).
func (c *Client) AttachAdminReaderKeys(ck *CredentialKeyBundle) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain {
		return ErrOutboxUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		return ErrFailClosed
	}
	if c.cfg.DirKind != DirKindAdmin {
		return fmt.Errorf("%w: AttachAdminReaderKeys is only valid on DirKindAdmin directories", ErrEnrollmentCheck)
	}
	if ck == nil {
		return errors.New("ldrclient: nil credential key bundle")
	}
	if c.credKeys != nil {
		return ErrCredentialExists
	}
	if _, err := os.Stat(c.credKeyPath()); err == nil {
		return ErrCredentialExists
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := SaveCredentialKeysCreateOnly(c.credKeyPath(), ck); err != nil {
		return err
	}
	c.credKeys = ck
	return nil
}

// EnsureAdminReaderRequest creates (create-only) or safely resumes an in-progress
// P3 reader-only (actor_limit=0, reader=true) JoinRequest for an administrative
// (DirKindAdmin) directory. If a credential already exists and is enrolled, was
// attached without a matching pending request, cannot be decoded, or disagrees
// on namespace or explicit signing algorithm, refuses with ErrCredentialExists
// without overwriting cred.key.
func (c *Client) EnsureAdminReaderRequest(namespace, alg string) (ldrcrypto.JoinRequest, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain {
		return ldrcrypto.JoinRequest{}, false, ErrOutboxUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		return ldrcrypto.JoinRequest{}, false, ErrFailClosed
	}
	if c.cfg.DirKind != DirKindAdmin {
		return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: admin reader-request requires a DirKindAdmin directory", ErrEnrollmentCheck)
	}
	if namespace == "" {
		return ldrcrypto.JoinRequest{}, false, errors.New("ldrclient: empty namespace")
	}
	reqPath := c.adminReaderReqPath()
	_, keyStatErr := os.Stat(c.credKeyPath())
	if c.credKeys != nil || keyStatErr == nil {
		ck := c.credKeys
		if ck == nil {
			var err error
			ck, err = LoadCredentialKeys(c.credKeyPath())
			if err != nil {
				return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: existing cred.key cannot be decoded: %v", ErrCredentialExists, err)
			}
			c.credKeys = ck
		}
		tok := ldrrelay.CredToken(ck.CredID)
		// Never reissue or replace once this credential is enrolled, tombstoned, or stopped.
		if c.state.Line.Credentials[tok] != nil || slices.Contains(c.state.Line.Tombstones.Creds, tok) || c.signsNoMoreLocked("cred:"+tok) {
			return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: admin directory already has an enrolled or retired reader credential", ErrCredentialExists)
		}
		if alg != "" && ck.Signing.Alg != alg {
			return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: existing pending reader credential uses alg %s, not %s", ErrCredentialExists, ck.Signing.Alg, alg)
		}
		// Allow safe idempotent resume ONLY if a matching pending request artifact
		// exists alongside cred.key for the exact same credential and namespace.
		req, _, err := LoadJoinRequest(reqPath)
		if err != nil {
			return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: existing cred.key has no valid resumable pending request", ErrCredentialExists)
		}
		if req.CredID != ck.CredID ||
			!req.SigningKey.Equal(ck.Signing.Signer.PublicKey()) ||
			!req.EncryptionKey.Equal(ck.Encryption.PublicKey()) ||
			!bytes.Equal(req.LineID, c.cfg.LineID) ||
			req.DescriptorDigest != c.cfg.DescriptorDigest ||
			req.Grant.NamespaceID != namespace ||
			req.Grant.ActorLimit != 0 ||
			!req.Grant.Reader {
			return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: existing pending reader request disagrees with credential or requested namespace", ErrCredentialExists)
		}
		return req, true, nil
	}
	if !os.IsNotExist(keyStatErr) {
		return ldrcrypto.JoinRequest{}, false, keyStatErr
	}
	if _, err := os.Stat(reqPath); err == nil {
		return ldrcrypto.JoinRequest{}, false, fmt.Errorf("%w: orphaned pending admin reader request exists without cred.key", ErrCredentialExists)
	} else if !os.IsNotExist(err) {
		return ldrcrypto.JoinRequest{}, false, err
	}

	credKeys, err := GenerateCredentialKeys(alg)
	if err != nil {
		return ldrcrypto.JoinRequest{}, false, err
	}
	reqID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, reqID); err != nil {
		return ldrcrypto.JoinRequest{}, false, err
	}
	grant := ldrcrypto.JoinGrant{NamespaceID: namespace, ActorLimit: 0, Reader: true}
	req, err := ldrcrypto.SignJoinRequest(credKeys.Signing.Signer, ldrcrypto.JoinRequest{
		RequestID:        reqID,
		LineID:           c.cfg.LineID,
		Generation:       1,
		DescriptorDigest: c.cfg.DescriptorDigest,
		EncryptionKey:    credKeys.Encryption.PublicKey(),
		Grant:            grant,
	})
	if err != nil {
		return ldrcrypto.JoinRequest{}, false, err
	}
	if err := SaveCredentialKeysCreateOnly(c.credKeyPath(), credKeys); err != nil {
		return ldrcrypto.JoinRequest{}, false, err
	}
	c.credKeys = credKeys
	if err := saveJoinRequestCreateOnly(reqPath, req); err != nil {
		return ldrcrypto.JoinRequest{}, false, err
	}
	return req, false, nil
}

// AttachOperatorKey attaches an in-memory operator signing key for admin actions.
func (c *Client) AttachOperatorKey(km *SigningKeyMaterial) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operatorKey = km
}

// AttachRootKey attaches an in-memory root signing key for root actions.
func (c *Client) AttachRootKey(km *SigningKeyMaterial) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootKey = km
}

// Descriptor returns the pinned creation descriptor, CD, genesis, and profile digest.
func (c *Client) Descriptor() (ldrcrypto.CreationDescriptor, [32]byte, [32]byte, [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.desc, c.cfg.DescriptorDigest, c.cfg.GenesisAnchor, c.profDigest
}

// State returns a deep copy of the verified derived state.
func (c *Client) State() ldrcore.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Clone()
}

// Checkpoint returns the durable verified (gen, seq, head).
func (c *Client) Checkpoint() (uint64, uint64, [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ckGen, c.ckSeq, c.ckHead
}

// CredID returns this client's credential ID if present.
func (c *Client) CredID() ([32]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credKeys == nil {
		return [32]byte{}, false
	}
	return c.credKeys.CredID, true
}

// OutboxSnapshot returns a copy of all stored outbox entries.
func (c *Client) OutboxSnapshot() []OutboxEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]OutboxEntry, len(c.outbox.Entries))
	for i, e := range c.outbox.Entries {
		out[i] = *e
	}
	return out
}

// Stops returns all Rule 8 stopped keys on this device.
func (c *Client) Stops() []KeyStop {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []KeyStop
	for _, p := range c.devicePrincipalsLocked() {
		if c.signsNoMoreLocked(p) {
			ks := KeyStop{Key: p}
			if t := c.outbox.KeyStops[p]; t != nil {
				ks = *t
			} else if t := c.pendingStops[p]; t != nil {
				ks = *t
			}
			ks.Verified = c.revokedInRecordsLocked(p)
			out = append(out, ks)
		}
	}
	return out
}

// Status returns a concise JSON-friendly status summary (no private keys).
type ClientStatus struct {
	DirKind                string   `json:"dir_kind"`
	LineID                 string   `json:"line_id"`
	CredID                 string   `json:"cred_id,omitempty"`
	Activated              bool     `json:"activated"`
	OutboxUncertain        bool     `json:"outbox_uncertain,omitempty"`
	OutboxUncertainReason  string   `json:"outbox_uncertain_reason,omitempty"`
	EpochsUncertain        bool     `json:"epochs_uncertain,omitempty"`
	EpochsUncertainReason  string   `json:"epochs_uncertain_reason,omitempty"`
	CursorsUncertain       bool     `json:"cursors_uncertain,omitempty"`
	CursorsUncertainReason string   `json:"cursors_uncertain_reason,omitempty"`
	Generation             uint64   `json:"generation"`
	CheckpointSeq          uint64   `json:"checkpoint_seq"`
	CheckpointHd           string   `json:"checkpoint_head"`
	KeyEpoch               int64    `json:"key_epoch"`
	AuthEpoch              int64    `json:"auth_epoch"`
	HasEpochKeys           []uint64 `json:"has_epoch_keys"`
	ProjectedSeq           uint64   `json:"projected_seq"`
	ScannedSeq             uint64   `json:"scanned_seq"`
	MustResolve            bool     `json:"must_resolve"`
	Suspect                bool     `json:"suspect"`
	Halted                 string   `json:"halted,omitempty"`
	OutboxCount            int      `json:"outbox_count"`
	StoppedKeys            []string `json:"stopped_keys,omitempty"`
}

func (c *Client) Status() ClientStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	epKeys := make([]uint64, 0, len(c.epochs.Keys))
	for k := range c.epochs.Keys {
		epKeys = append(epKeys, k)
	}
	sort.Slice(epKeys, func(i, j int) bool { return epKeys[i] < epKeys[j] })
	var cid string
	if c.credKeys != nil {
		cid = hex.EncodeToString(c.credKeys.CredID[:])
	}
	var stopped []string
	for _, p := range c.devicePrincipalsLocked() {
		if c.signsNoMoreLocked(p) {
			stopped = append(stopped, p)
		}
	}
	return ClientStatus{
		DirKind:                c.cfg.DirKind,
		LineID:                 hex.EncodeToString(c.cfg.LineID),
		CredID:                 cid,
		Activated:              c.outbox.Activated,
		OutboxUncertain:        c.outboxUncertain,
		OutboxUncertainReason:  c.outboxUncertainReason,
		EpochsUncertain:        c.epochsUncertain,
		EpochsUncertainReason:  c.epochsUncertainReason,
		CursorsUncertain:       c.cursorsUncertain,
		CursorsUncertainReason: c.cursorsUncertainReason,
		Generation:             c.ckGen,
		CheckpointSeq:          c.ckSeq,
		CheckpointHd:           hex.EncodeToString(c.ckHead[:]),
		KeyEpoch:               c.state.Line.KeyEpoch,
		AuthEpoch:              c.state.Line.AuthEpoch,
		HasEpochKeys:           epKeys,
		ProjectedSeq:           c.cursors.ProjectedSeq,
		ScannedSeq:             c.cursors.ScannedSeq,
		MustResolve:            c.outbox.MustResolve,
		Suspect:                c.outbox.Suspect,
		Halted:                 c.outbox.Halted,
		OutboxCount:            len(c.outbox.Entries),
		StoppedKeys:            stopped,
	}
}

// Dial opens a pinned TLS 1.3 channel-bound SessionClient for the requested origin
// ("credential", "operator", or "root"). Refuses stopped/revoked keys before dialing!
func (c *Client) Dial(ctx context.Context, role string) (*ldrrelay.SessionClient, error) {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return nil, ErrOutboxUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		c.mu.Unlock()
		return nil, ErrFailClosed
	}
	var prin ldrcrypto.Principal
	var signer ldrcrypto.Signer
	switch role {
	case ldrcrypto.PrincipalCredential:
		if c.credKeys == nil {
			c.mu.Unlock()
			return nil, errors.New("ldrclient: no credential key bundle loaded")
		}
		prin = ldrcrypto.CredentialPrincipal(c.credKeys.CredID)
		signer = c.credKeys.Signing.Signer
	case ldrcrypto.PrincipalOperator:
		if c.operatorKey == nil {
			c.mu.Unlock()
			return nil, errors.New("ldrclient: no operator key attached")
		}
		prin = ldrcrypto.OperatorPrincipal(c.operatorKey.Signer.PublicKey())
		signer = c.operatorKey.Signer
	case ldrcrypto.PrincipalRoot:
		if c.rootKey == nil {
			c.mu.Unlock()
			return nil, errors.New("ldrclient: no root key attached")
		}
		prin = ldrcrypto.RootPrincipal(c.rootKey.Signer.PublicKey())
		signer = c.rootKey.Signer
	default:
		c.mu.Unlock()
		return nil, fmt.Errorf("ldrclient: unknown role %q", role)
	}
	tok, err := ldrrelay.PrincipalToken(prin)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.signsNoMoreLocked(tok) {
		c.mu.Unlock()
		return nil, ErrKeyRevoked
	}
	origin := c.desc.RelayOrigin
	lineID := bytes.Clone(c.cfg.LineID)
	profDig := c.profDigest
	gen := c.ckGen
	if gen == 0 {
		gen = 1
	}
	c.mu.Unlock()

	sess, err := ldrrelay.DialSession(ctx, origin, lineID, profDig, gen, prin, signer)
	if err != nil {
		var ae *ldrrelay.AuthError
		if errors.As(err, &ae) && ae.Class == ldrcore.ClassUnresolved && ae.Code == "revoked" {
			c.mu.Lock()
			c.recordToldRevokedLocked(tok, "revoked")
			if perr := c.persistOutboxLocked(c.outbox); perr != nil {
				c.markOutboxUncertainOnErrLocked(perr)
			}
			c.mu.Unlock()
			return nil, ErrKeyRevoked
		}
		return nil, err
	}
	return sess, nil
}

// Sync fetches all new control-only frames from sess in bounded pages, verifies
// every chain head, real signature, signedContext rule, and ldrcore.Apply
// transition, persists each verified frame durably to verified.wal, and unwraps
// any newly committed epoch wraps for this credential.
func (c *Client) Sync(ctx context.Context, sess *ldrrelay.SessionClient) (int, error) {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return 0, ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return 0, ErrEpochsUncertain
	}
	if c.outbox.Halted != "" {
		reason := c.outbox.Halted
		c.mu.Unlock()
		return 0, fmt.Errorf("%w: %s", ErrViolation, reason)
	}
	c.mu.Unlock()

	applied := 0
	for {
		c.mu.Lock()
		fromSeq := c.ckSeq + 1
		c.mu.Unlock()

		page, err := sess.ControlLog(ctx, fromSeq, ldrrelay.MaxLogPageSize)
		if err != nil {
			if strings.Contains(err.Error(), "revoked") {
				return applied, ErrKeyRevoked
			}
			return applied, err
		}
		if len(page) == 0 {
			break
		}
		for _, fr := range page {
			c.mu.Lock()
			if err := c.verifyAndApplyFrameLocked(fr, true); err != nil {
				c.outbox.Halted = err.Error()
				if perr := c.persistOutboxLocked(c.outbox); perr != nil {
					c.markOutboxUncertainOnErrLocked(perr)
				}
				c.mu.Unlock()
				return applied, fmt.Errorf("%w: %v", ErrViolation, err)
			}
			c.mu.Unlock()
			applied++
		}
		if uint64(len(page)) < ldrrelay.MaxLogPageSize {
			break
		}
	}

	// Unwrap any epoch activations naming this credential whose key we don't yet hold.
	if err := c.unwrapAvailableEpochs(ctx, sess); err != nil {
		return applied, err
	}
	return applied, nil
}

func (c *Client) validateMemberCeremonyConfigLocked() error {
	if c.credKeys == nil {
		return fmt.Errorf("%w: member directory missing credential keys", ErrEnrollmentCheck)
	}
	if c.cfg.ExpectedCredID == nil || *c.cfg.ExpectedCredID != c.credKeys.CredID {
		return fmt.Errorf("%w: member directory expected_cred_id missing or disagrees with local cred.key", ErrEnrollmentCheck)
	}
	if c.cfg.ExpectedGrant == nil || c.cfg.ExpectedGrant.NamespaceID == "" {
		return fmt.Errorf("%w: member directory missing expected_grant", ErrEnrollmentCheck)
	}
	if len(c.cfg.ExpectedJoinReqID) == 0 {
		return fmt.Errorf("%w: member directory missing expected_join_req_id", ErrEnrollmentCheck)
	}
	if c.cfg.ExpectedJoinReqDigest == nil {
		return fmt.Errorf("%w: member directory missing expected_join_req_digest", ErrEnrollmentCheck)
	}
	return nil
}

// verifyEnrolledMemberLocked verifies that this joining member directory has
// complete P3 ceremony evidence AND that verified replay history contains the
// exact matching credential_enroll record (cred_id, signing_key, encryption_key,
// grant, join_request_id, and join_request_digest).
func (c *Client) verifyEnrolledMemberLocked(requireActiveReaderEpoch, allowRevoked bool) error {
	if c.cfg.DirKind != DirKindMember {
		return fmt.Errorf("%w: administrative directory is not a joining member directory", ErrEnrollmentCheck)
	}
	if err := c.validateMemberCeremonyConfigLocked(); err != nil {
		return err
	}
	myTok := ldrrelay.CredToken(c.credKeys.CredID)
	wantSig, err := ldrrelay.KeyToken(c.credKeys.Signing.Signer.PublicKey())
	if err != nil {
		return err
	}
	wantEnc, err := ldrrelay.KeyToken(c.credKeys.Encryption.PublicKey())
	if err != nil {
		return err
	}
	wantReqID := hex.EncodeToString(c.cfg.ExpectedJoinReqID)
	wantReqDig := hex.EncodeToString(c.cfg.ExpectedJoinReqDigest[:])

	// Locate the actual verified credential_enroll record in verified history.
	var enrollRec *ldrcore.Record
	enrollCount := 0
	for _, ve := range c.entries {
		if ve.decoded == nil || ve.decoded.OpType != "credential_enroll" {
			continue
		}
		if ve.decoded.Record.Cred == myTok {
			r := ve.decoded.Record
			enrollRec = &r
			enrollCount++
		}
	}
	if enrollCount == 0 {
		return fmt.Errorf("%w: no verified credential_enroll record found for local credential", ErrEnrollmentCheck)
	}
	if enrollCount > 1 {
		return fmt.Errorf("%w: duplicate credential_enroll records (%d) for local credential", ErrViolation, enrollCount)
	}
	if enrollRec.SigningKey != wantSig || enrollRec.EncryptionKey != wantEnc {
		return fmt.Errorf("%w: verified credential_enroll keys do not match local credential keys", ErrEnrollmentCheck)
	}
	if enrollRec.Grant == nil ||
		enrollRec.Grant.Namespace != c.cfg.ExpectedGrant.NamespaceID ||
		enrollRec.Grant.ActorLimit != int64(c.cfg.ExpectedGrant.ActorLimit) ||
		enrollRec.Grant.Reader != c.cfg.ExpectedGrant.Reader {
		return fmt.Errorf("%w: verified credential_enroll grant differs from saved P3 join request", ErrEnrollmentCheck)
	}
	if enrollRec.JoinRequest != wantReqID {
		return fmt.Errorf("%w: verified credential_enroll join_request_id does not match saved P3 request", ErrEnrollmentCheck)
	}
	if enrollRec.JoinRequestDigest != wantReqDig {
		return fmt.Errorf("%w: verified credential_enroll join_request_digest does not match saved P3 request", ErrEnrollmentCheck)
	}

	cr := c.state.Line.Credentials[myTok]
	if cr == nil {
		return fmt.Errorf("%w: credential not enrolled in verified state", ErrEnrollmentCheck)
	}
	if !allowRevoked && cr.Revoked {
		return fmt.Errorf("%w: credential already revoked", ErrKeyRevoked)
	}
	if cr.SigningKey != wantSig || cr.EncryptionKey != wantEnc {
		return fmt.Errorf("%w: enrolled state keys do not match local credential keys", ErrEnrollmentCheck)
	}
	if cr.Namespace != c.cfg.ExpectedGrant.NamespaceID ||
		cr.ActorLimit != int64(c.cfg.ExpectedGrant.ActorLimit) ||
		cr.Reader != c.cfg.ExpectedGrant.Reader {
		return fmt.Errorf("%w: enrolled state grant differs from saved P3 join request", ErrEnrollmentCheck)
	}
	if requireActiveReaderEpoch && cr.Reader {
		hasAny := false
		for ep := range c.epochs.Keys {
			if slices.Contains(c.state.Line.Readers[int64(ep)], myTok) {
				hasAny = true
				break
			}
		}
		if !hasAny {
			return fmt.Errorf("%w: reader credential awaiting first epoch activation", ErrNoEpochKey)
		}
	}
	return nil
}

// VerifyEnrollmentAndActivate implements the O25 full-replay onboarding activation
// gate (§6 of LDR-GO-RELAY-DESIGN.md): obtains a fresh anchor, replays control
// frames 1..fseq from genesis, verifies the actual committed credential_enroll
// record matches the complete saved P3 request (keys, grant, join_request_id,
// join_request_digest), verifies epoch wrap availability for readers, durably
// persists Activated=true, and publishes the in-memory flag ONLY after persistence
// succeeds. On an ambiguous persistence failure, ordinary operations stay fenced
// pending ReconcileDurability.
func (c *Client) VerifyEnrollmentAndActivate(ctx context.Context, sess *ldrrelay.SessionClient) error {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return ErrEpochsUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		c.mu.Unlock()
		return ErrFailClosed
	}
	c.mu.Unlock()

	ar, err := c.Anchor(ctx, sess)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain {
		return ErrOutboxUncertain
	}
	if c.epochsUncertain {
		return ErrEpochsUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		return ErrFailClosed
	}
	if ar.Seq == 0 || c.ckSeq < ar.Seq || c.entries[ar.Seq-1].frame.Head != ar.Head {
		return fmt.Errorf("%w: synced checkpoint (%d) did not verify fresh anchor (%d)", ErrViolation, c.ckSeq, ar.Seq)
	}
	if err := c.verifyEnrolledMemberLocked(true, false); err != nil {
		return err
	}
	// Stage and persist candidate outbox BEFORE publishing Activated in memory!
	candidate := c.outbox
	candidate.Activated = true
	if err := c.persistOutboxLocked(candidate); err != nil {
		c.markOutboxUncertainOnErrLocked(err)
		return err
	}
	c.outbox.Activated = true
	return nil
}

// verifyClientReconcilePreservesPrefixLocked verifies that a freshly replayed
// candidate from durable verified.wal monotonically extends the previously
// verified checkpoint and frames without truncating or diverging from history.
func verifyClientReconcilePreservesPrefixLocked(prev, cand *Client) error {
	if cand.ckSeq < prev.ckSeq || len(cand.entries) < len(prev.entries) {
		return fmt.Errorf("%w: durable verified.wal length %d shorter than verified checkpoint %d",
			ldrstore.ErrCorruptWAL, len(cand.entries), prev.ckSeq)
	}
	for i, oldEntry := range prev.entries {
		oldFr := oldEntry.frame
		newFr := cand.entries[i].frame
		if newFr.Gen != oldFr.Gen ||
			newFr.Seq != oldFr.Seq ||
			newFr.SeqTime != oldFr.SeqTime ||
			newFr.PrevHead != oldFr.PrevHead ||
			newFr.Head != oldFr.Head ||
			newFr.Origin != oldFr.Origin ||
			newFr.OpType != oldFr.OpType ||
			!bytes.Equal(newFr.IntentBytes, oldFr.IntentBytes) {
			return fmt.Errorf("%w: durable verified.wal frame %d diverged from verified history", ldrstore.ErrCorruptWAL, oldFr.Seq)
		}
	}
	if prev.ckSeq > 0 && cand.entries[prev.ckSeq-1].frame.Head != prev.ckHead {
		return fmt.Errorf("%w: durable verified.wal head at seq %d diverged from verified checkpoint", ldrstore.ErrCorruptWAL, prev.ckSeq)
	}
	return nil
}

// ReconcileDurability enforces explicit file+directory durability barriers on
// outbox.cbor, epochs.cbor, cursors.cbor, and verified.wal, reconstructs and
// verifies a fresh candidate from the durable frames, requires the candidate
// and cursors to monotonically preserve previously published state, validates
// activation evidence against the candidate, and lifts outboxUncertain and
// cursorsUncertain ONLY when every barrier and check succeeds.
func (c *Client) ReconcileDurability() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := syncOutboxBarrier(c.outboxPath(), c.syncFileFn, c.syncDirFn); err != nil {
		return err
	}
	if err := syncOutboxBarrier(c.epochsPath(), c.syncFileFn, c.syncDirFn); err != nil {
		return err
	}
	if err := syncOutboxBarrier(c.cursorsPath(), c.syncFileFn, c.syncDirFn); err != nil {
		return err
	}
	if err := syncOutboxBarrier(c.registersPath(), c.syncFileFn, c.syncDirFn); err != nil {
		return err
	}
	ob, err := loadOutbox(c.outboxPath())
	if err != nil {
		return err
	}
	if ob.NextOp < c.outbox.NextOp {
		return fmt.Errorf("%w: reconciled outbox next_op %d regressed below %d", ldrstore.ErrCorruptWAL, ob.NextOp, c.outbox.NextOp)
	}
	if ob.ResolveEpoch < c.outbox.ResolveEpoch {
		return fmt.Errorf("%w: reconciled outbox resolve_epoch %d regressed below %d", ldrstore.ErrCorruptWAL, ob.ResolveEpoch, c.outbox.ResolveEpoch)
	}
	ep, err := loadEpochs(c.epochsPath())
	if err != nil {
		return err
	}
	for id, prevKey := range c.epochs.Keys {
		gotKey, ok := ep.Keys[id]
		if !ok || !bytes.Equal(prevKey, gotKey) {
			return fmt.Errorf("%w: reconciled epochs.cbor lost or altered epoch %d key", ldrstore.ErrCorruptWAL, id)
		}
	}
	for id, bad := range c.epochs.BadWraps {
		if bad && !ep.BadWraps[id] && ep.Keys[id] == nil {
			return fmt.Errorf("%w: reconciled epochs.cbor lost bad_wrap marker for epoch %d", ldrstore.ErrCorruptWAL, id)
		}
	}
	cur, err := loadCursors(c.cursorsPath())
	if err != nil {
		return err
	}
	if cur.ScannedSeq < c.cursors.ScannedSeq {
		return fmt.Errorf("%w: reconciled scanned_seq %d regressed below %d", ldrstore.ErrCorruptWAL, cur.ScannedSeq, c.cursors.ScannedSeq)
	}
	if cur.Rebuilds < c.cursors.Rebuilds {
		return fmt.Errorf("%w: reconciled rebuilds %d regressed below %d", ldrstore.ErrCorruptWAL, cur.Rebuilds, c.cursors.Rebuilds)
	}
	if cur.Rebuilds == c.cursors.Rebuilds && cur.ProjectedSeq < c.cursors.ProjectedSeq {
		return fmt.Errorf("%w: reconciled projected_seq %d regressed below %d", ldrstore.ErrCorruptWAL, cur.ProjectedSeq, c.cursors.ProjectedSeq)
	}
	for id, prevNotice := range c.cursors.Notices {
		gotNotice := cur.Notices[id]
		if gotNotice == nil {
			return fmt.Errorf("%w: reconciled cursors.cbor lost previously persisted notice %q", ldrstore.ErrCorruptWAL, id)
		}
		if prevNotice.Acked && !gotNotice.Acked {
			return fmt.Errorf("%w: reconciled cursors.cbor regressed acknowledged notice %q", ldrstore.ErrCorruptWAL, id)
		}
	}
	regs, err := loadRegisters(c.registersPath())
	if err != nil {
		return err
	}
	if c.registersUncertain {
		for k, w := range c.registers.Writers {
			if _, exists := regs.Writers[k]; !exists {
				cp := *w
				regs.Writers[k] = &cp
			}
		}
		for _, w := range regs.Writers {
			w.TrustedCounter = false
		}
	}
	frames, err := loadVerifiedWAL(c.walPath(), c.syncFileFn, c.syncDirFn)
	if err != nil {
		return err
	}

	// Reconstruct and verify a fresh candidate strictly from durable WAL frames.
	cand := &Client{
		dir:            c.dir,
		cfg:            c.cfg,
		desc:           c.desc,
		profDigest:     c.profDigest,
		coreProf:       c.coreProf,
		validityMS:     c.validityMS,
		credKeys:       c.credKeys,
		operatorKey:    c.operatorKey,
		rootKey:        c.rootKey,
		ckHead:         c.cfg.GenesisAnchor,
		rctx:           newReplayContext(),
		touched:        make(map[string]projCoord),
		source:         make(map[string]projCoord),
		viewOf:         make(map[string]string),
		regActivations: make(map[string]map[uint64]committedRegisterActivation),
		outbox:         ob,
		pendingStops:   make(map[string]*KeyStop),
		slots:          make(map[string]string),
		epochs:         ep,
		cursors:        cur,
	}
	for _, fr := range frames {
		if err := cand.verifyAndApplyFrameLocked(fr, false); err != nil {
			return fmt.Errorf("%w: durable verified.wal replay failed: %v", ldrstore.ErrCorruptWAL, err)
		}
	}
	if err := verifyClientReconcilePreservesPrefixLocked(c, cand); err != nil {
		return err
	}
	if cur.ScannedSeq > cand.ckSeq || cur.ProjectedSeq > cand.ckSeq {
		return fmt.Errorf("%w: reconciled cursors (scanned=%d projected=%d) exceed durable verified.wal seq %d",
			ldrstore.ErrCorruptWAL, cur.ScannedSeq, cur.ProjectedSeq, cand.ckSeq)
	}
	// Validate activation evidence against the DURABLY RECONSTRUCTED candidate
	// (never against stale in-memory c.entries/c.state!).
	if c.cfg.DirKind == DirKindMember && ob.Activated {
		if !c.outbox.Activated {
			if err := cand.verifyEnrolledMemberLocked(true, false); err != nil {
				return err
			}
		} else {
			if err := cand.verifyEnrolledMemberLocked(false, true); err != nil {
				return err
			}
		}
	}
	// Carry forward any validated Rule 8 stops whose prior outbox write failed
	// (including ErrPreWrite) and durably persist them BEFORE clearing
	// pendingStops or outboxUncertain.
	if len(c.pendingStops) > 0 {
		for p, st := range c.pendingStops {
			if ob.KeyStops == nil {
				ob.KeyStops = make(map[string]*KeyStop)
			}
			if ob.KeyStops[p] == nil {
				cp := *st
				ob.KeyStops[p] = &cp
			}
			c.suspendSignerOnLocked(&ob, p)
		}
		if err := c.persistOutboxLocked(ob); err != nil {
			return err
		}
	}
	// If register counter durability was uncertain, durably persist the
	// untrusted-counter requirement BEFORE clearing registersUncertain or
	// installing candidate state so an immediate close+reopen still forces
	// fresh register_activate re-incarnation (§9).
	if c.registersUncertain {
		if err := c.persistRegistersLocked(regs); err != nil {
			return err
		}
	}
	slots := make(map[string]string)
	for _, e := range ob.Entries {
		if e.Status == ldrcore.OutPending || e.Status == ldrcore.OutReconcile {
			slots[e.Slot] = e.OpID
		}
	}
	c.state = cand.state
	c.entries = cand.entries
	c.ckGen = cand.ckGen
	c.ckSeq = cand.ckSeq
	c.ckHead = cand.ckHead
	c.rctx = cand.rctx
	c.touched = cand.touched
	c.source = cand.source
	c.viewOf = cand.viewOf
	c.regActivations = cand.regActivations
	c.epochs = ep
	c.outbox = ob
	c.pendingStops = make(map[string]*KeyStop)
	c.cursors = cur
	c.registers = regs
	c.registersUncertain = false
	c.registersUncertainMsg = ""
	c.slots = slots
	c.outboxUncertain = false
	c.outboxUncertainReason = ""
	c.epochsUncertain = false
	c.epochsUncertainReason = ""
	c.cursorsUncertain = false
	c.cursorsUncertainReason = ""
	return nil
}

// Anchor requests a fresh anchor over sess and syncs verified local state up to it.
// Fails closed if Halted, Suspect, or stopped (G2 / Rule 8).
func (c *Client) Anchor(ctx context.Context, sess *ldrrelay.SessionClient) (ldrrelay.AnchorReply, error) {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ldrrelay.AnchorReply{}, ErrOutboxUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		c.mu.Unlock()
		return ldrrelay.AnchorReply{}, ErrFailClosed
	}
	c.mu.Unlock()

	ar, err := sess.AnchorRequest(ctx)
	if err != nil {
		return ldrrelay.AnchorReply{}, err
	}
	if ar.Class == ldrcore.ClassUnresolved && ar.Code == "revoked" {
		return ar, ErrKeyRevoked
	}
	if ar.Class != ldrcore.ClassOutcome {
		return ar, fmt.Errorf("ldrclient: anchor refused (%s / %s)", ar.Class, ar.Code)
	}
	if _, err := c.Sync(ctx, sess); err != nil {
		return ar, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ckSeq < ar.Seq {
		return ar, fmt.Errorf("%w: relay did not deliver log up to announced anchor seq %d", ErrViolation, ar.Seq)
	}
	return ar, nil
}

func (c *Client) verifyAndApplyFrameLocked(fr ldrrelay.ControlFrameWire, persist bool) error {
	if fr.Gen != 1 {
		return fmt.Errorf("unexpected generation %d", fr.Gen)
	}
	if fr.Seq <= c.ckSeq {
		if fr.Seq < 1 || c.entries[fr.Seq-1].frame.Head != fr.Head {
			return fmt.Errorf("divergent history at already-verified seq %d", fr.Seq)
		}
		return nil
	}
	if fr.Seq != c.ckSeq+1 {
		return fmt.Errorf("non-consecutive seq %d after %d", fr.Seq, c.ckSeq)
	}
	if fr.PrevHead != c.ckHead {
		return fmt.Errorf("seq %d prev_head does not link to checkpoint", fr.Seq)
	}
	if fr.SeqTime > uint64(ldrcore.MaxCounter) {
		return fmt.Errorf("seq %d seq_time %d out of domain", fr.Seq, fr.SeqTime)
	}

	var next ldrcore.State
	var dec *ldrrelay.DecodedIntent
	var opKey *ldrstore.StoredOpKey

	if fr.Origin == ldrcore.OriginSequencer {
		if fr.Seq == 1 || fr.OpType != "time_anchor" || len(fr.IntentBytes) != 0 ||
			fr.PayloadCommit != nil || len(fr.WrapCommits) != 0 {
			return fmt.Errorf("seq %d invalid sequencer frame", fr.Seq)
		}
		wantHead, err := ldrcrypto.AnchorChainHead(c.ckHead, c.profDigest, c.cfg.LineID, fr.Gen, fr.Seq, fr.SeqTime)
		if err != nil || wantHead != fr.Head {
			return fmt.Errorf("seq %d time_anchor head mismatch", fr.Seq)
		}
		var out ldrcore.Outcome
		next, out = ldrcore.Apply(c.state, ldrcore.Record{Origin: ldrcore.OriginSequencer, Type: "time_anchor"}, int64(fr.SeqTime), c.coreProf)
		if out.Kind != ldrcore.Committed {
			return fmt.Errorf("seq %d time_anchor failed Apply (%s %s)", fr.Seq, out.Kind, out.Reason)
		}
	} else {
		lim := ldrcrypto.Limits{MaxBytes: int(c.desc.Profile.MaxRecordBytes), MaxDepth: 16, MaxItems: 4096}
		env, err := ldrcrypto.UnmarshalSignedIntent(fr.IntentBytes, lim)
		if err != nil {
			return fmt.Errorf("seq %d invalid signed intent: %v", fr.Seq, err)
		}
		dec, err = ldrrelay.DecodeWireIntentBody(env.BodyBytes, c.desc.Profile, lim)
		if err != nil {
			return fmt.Errorf("seq %d invalid intent body: %v", fr.Seq, err)
		}
		if !bytes.Equal(dec.LineID, c.cfg.LineID) || dec.ProfileDigest != c.profDigest {
			return fmt.Errorf("seq %d line/profile digest mismatch", fr.Seq)
		}
		if dec.Generation != fr.Gen {
			return fmt.Errorf("seq %d signed generation %d != frame gen %d", fr.Seq, dec.Generation, fr.Gen)
		}
		// Compare outer origin, op_type, and sidecar commitment metadata against
		// the signed body BEFORE applying or persisting.
		if err := ldrrelay.VerifyControlFrameMetadata(fr, dec); err != nil {
			return err
		}
		pubKey, err := c.resolveReplaySignerKeyLocked(dec.Principal, fr.Seq == 1 && dec.OpType == "line_init")
		if err != nil {
			return fmt.Errorf("seq %d unauthorized signer: %v", fr.Seq, err)
		}
		if err := env.Verify(pubKey); err != nil {
			return fmt.Errorf("seq %d signature verification failed: %v", fr.Seq, err)
		}
		k := ldrstore.StoredOpKey{
			Generation: dec.Generation,
			Signer:     dec.PrincipalToken,
			SeenSeq:    dec.SeenSeq,
			OpID:       dec.OpID,
		}
		opKey = &k
		// §11.2 replay checks: unique op identity, anchor on chain, historical deadline!
		if prevSeq, dup := c.rctx.ops[k]; dup {
			return fmt.Errorf("seq %d duplicates committed op identity from seq %d", fr.Seq, prevSeq)
		}
		if dec.OpType == "line_init" {
			if fr.Seq != 1 {
				return fmt.Errorf("seq %d line_init only permitted at seq 1", fr.Seq)
			}
			// Shared pinned bootstrap check matching relay Submit & startup replay:
			// validates genesis anchor, descriptor digest, embedded profile digest,
			// and canonical 1-of-2 root key pair.
			if cls, code := ldrrelay.ValidateLineInitBootstrap(c.desc, c.cfg.DescriptorDigest, c.cfg.GenesisAnchor, c.profDigest, dec); cls != "" {
				return fmt.Errorf("seq %d line_init bootstrap failed (%s/%s)", fr.Seq, cls, code)
			}
		} else {
			if fr.Seq == 1 {
				return fmt.Errorf("seq %d non-line_init op %q at genesis", fr.Seq, dec.OpType)
			}
			anc, held := c.rctx.anchors[dec.SeenSeq]
			if !held {
				return fmt.Errorf("seq %d anchored at unknown/retired seq %d", fr.Seq, dec.SeenSeq)
			}
			if anc.head != dec.SeenHead {
				return fmt.Errorf("seq %d seen_head diverges from verified chain", fr.Seq)
			}
			if fr.SeqTime > anc.time+min(dec.ValidityMS, c.desc.Profile.MaxValidityMS) {
				return fmt.Errorf("seq %d committed past signed validity deadline", fr.Seq)
			}
		}
		wantHead, err := ldrcrypto.ClientChainHead(c.ckHead, c.profDigest, c.cfg.LineID, fr.Gen, fr.Seq, fr.SeqTime, fr.Origin, fr.IntentBytes)
		if err != nil || wantHead != fr.Head {
			return fmt.Errorf("seq %d chain head mismatch", fr.Seq)
		}
		var out ldrcore.Outcome
		next, out = ldrcore.Apply(c.state, dec.Record, int64(fr.SeqTime), c.coreProf)
		if out.Kind != ldrcore.Committed {
			return fmt.Errorf("seq %d (%s) failed Apply on replay (%s %s)", fr.Seq, dec.OpType, out.Kind, out.Reason)
		}
	}

	// Single durable step: persist verified frame BEFORE updating in-memory checkpoint.
	if persist {
		if err := appendVerifiedFrameWAL(c.walPath(), fr); err != nil {
			return err
		}
	}

	coord := projCoord{gen: fr.Gen, seq: fr.Seq}
	touched := diffTouchedObjects(c.state, next)
	var owed []LocalNotice
	var disputeID string
	if dec != nil {
		owed = c.deriveOwedNoticesLocked(&next, fr, dec)
		if dec.OpType == "dispute_open" {
			if call := next.Calls[dec.Record.Call]; call != nil {
				disputeID = fmt.Sprintf("%d", call.DisputeCount)
			}
		}
		if dec.OpType == "register_activate" {
			rkey := dec.Record.Actor + "/" + dec.Record.Register
			if w := next.Line.RegisterWriters[rkey]; w != nil {
				if c.regActivations == nil {
					c.regActivations = make(map[string]map[uint64]committedRegisterActivation)
				}
				if c.regActivations[rkey] == nil {
					c.regActivations[rkey] = make(map[uint64]committedRegisterActivation)
				}
				c.regActivations[rkey][uint64(w.WriterRev)] = committedRegisterActivation{
					Actor:       dec.Record.Actor,
					Register:    dec.Record.Register,
					WriterRev:   uint64(w.WriterRev),
					BindingGen:  uint64(w.BindingGen),
					Incarnation: w.Incarnation,
					Cred:        dec.Record.Cred,
				}
			}
		}
	}
	c.entries = append(c.entries, verifiedEntry{frame: fr, decoded: dec, touched: touched, owed: owed, disputeID: disputeID})
	for _, obj := range touched {
		c.touched[obj] = coord
		c.viewOf[projViewPath(obj)] = obj
	}
	if dec != nil {
		for _, pf := range recordProjFiles(fr, dec.Record, "") {
			c.source[pf.path] = coord
		}
	}
	c.state = next
	c.ckGen = fr.Gen
	c.ckSeq = fr.Seq
	c.ckHead = fr.Head
	c.rctx.anchors[fr.Seq] = signedAnchor{head: fr.Head, time: fr.SeqTime}
	if opKey != nil {
		c.rctx.ops[*opKey] = fr.Seq
	}
	c.rctx.prune(fr.SeqTime, c.desc.Profile.MaxValidityMS)

	// Rule 8: verifying a revocation stops that key on this device immediately.
	if c.stopRevokedLocked() && persist {
		if perr := c.persistOutboxLocked(c.outbox); perr != nil {
			c.markOutboxUncertainOnErrLocked(perr)
		}
	}
	return nil
}

func (c *Client) resolveReplaySignerKeyLocked(p ldrcrypto.Principal, isInit bool) (ldrcrypto.PublicKey, error) {
	if isInit && p.Kind == ldrcrypto.PrincipalRoot && c.state.Line.Generation == 0 {
		for _, rk := range c.desc.RootKeys {
			if rk.Equal(*p.Key) {
				return rk, nil
			}
		}
		return ldrcrypto.PublicKey{}, errors.New("line_init signer not in provisioned root_keys")
	}
	l := &c.state.Line
	switch p.Kind {
	case ldrcrypto.PrincipalRoot:
		tok, err := ldrrelay.KeyToken(*p.Key)
		if err != nil {
			return ldrcrypto.PublicKey{}, err
		}
		if slices.Contains(l.RootKeys, tok) {
			return *p.Key, nil
		}
	case ldrcrypto.PrincipalOperator:
		tok, err := ldrrelay.KeyToken(*p.Key)
		if err != nil {
			return ldrcrypto.PublicKey{}, err
		}
		if slices.Contains(l.Operators, tok) {
			return *p.Key, nil
		}
	case ldrcrypto.PrincipalCredential:
		cr := l.Credentials[ldrrelay.CredToken(p.CredID)]
		if cr != nil && !cr.Revoked {
			return ldrrelay.ParseKeyToken(cr.SigningKey)
		}
	}
	return ldrcrypto.PublicKey{}, errors.New("principal not active in verified state")
}

// --- Epoch Wrap Context, P9 Epoch Activation, and Unwrapping ---

// BuildEpochWrapContext deterministically computes the P9 HPKE EpochWrapContext
// shared by the generating reader/operator and the unwrapping recipient.
func BuildEpochWrapContext(lineID []byte, gen uint64, profDigest [32]byte, newEpoch, expectEpoch, authEpoch uint64, opPrincipal ldrcrypto.Principal, seenSeq uint64, opID string, recipientCredID [32]byte, recipientEncKey ldrcrypto.PublicKey, readerSetDigest [32]byte) (ldrcrypto.EpochWrapContext, error) {
	pCBOR, err := opPrincipal.ToCBOR()
	if err != nil {
		return ldrcrypto.EpochWrapContext{}, err
	}
	opIDBytes, err := ldrcrypto.MarshalCBOR([]any{lineID, gen, pCBOR, seenSeq, opID})
	if err != nil {
		return ldrcrypto.EpochWrapContext{}, err
	}
	return ldrcrypto.EpochWrapContext{
		LineID:          bytes.Clone(lineID),
		Generation:      gen,
		ProfileDigest:   profDigest,
		NewEpoch:        newEpoch,
		ExpectEpoch:     expectEpoch,
		AuthEpoch:       authEpoch,
		OpIdentityBytes: opIDBytes,
		RecipientCredID: recipientCredID,
		RecipientEncKey: recipientEncKey,
		ReaderSetDigest: readerSetDigest,
	}, nil
}

func (c *Client) unwrapAvailableEpochs(ctx context.Context, sess *ldrrelay.SessionClient) error {
	c.mu.Lock()
	if c.epochsUncertain {
		c.mu.Unlock()
		return ErrEpochsUncertain
	}
	if c.credKeys == nil {
		c.mu.Unlock()
		return nil
	}
	myCredID := c.credKeys.CredID
	myEncPriv := c.credKeys.Encryption
	myEncPub := myEncPriv.PublicKey()
	type task struct {
		epoch  uint64
		commit ldrcrypto.Commitment
		wctx   ldrcrypto.EpochWrapContext
	}
	var tasks []task
	for _, ve := range c.entries {
		if ve.decoded == nil || ve.decoded.OpType != "key_epoch_activate" {
			continue
		}
		if ve.decoded.Record.Expect.KeyEpoch == nil {
			continue
		}
		expEp := uint64(*ve.decoded.Record.Expect.KeyEpoch)
		newEp := expEp + 1
		if _, have := c.epochs.Keys[newEp]; have || c.epochs.BadWraps[newEp] {
			continue
		}
		var myCommit *ldrcrypto.Commitment
		credIDs := make([][32]byte, 0, len(ve.decoded.Manifest))
		for _, ent := range ve.decoded.Manifest {
			credIDs = append(credIDs, ent.CredID)
			if ent.CredID == myCredID {
				cc := ent.Commit
				myCommit = &cc
			}
		}
		if myCommit == nil {
			continue
		}
		rsDig, err := ldrcrypto.ReaderSetDigest(credIDs)
		if err != nil {
			continue
		}
		wctx, err := BuildEpochWrapContext(
			c.cfg.LineID, ve.decoded.Generation, c.profDigest,
			newEp, expEp, uint64(ve.decoded.Record.AuthEpoch),
			ve.decoded.Principal, ve.decoded.SeenSeq, ve.decoded.OpID,
			myCredID, myEncPub, rsDig,
		)
		if err != nil {
			continue
		}
		tasks = append(tasks, task{epoch: newEp, commit: *myCommit, wctx: wctx})
	}
	c.mu.Unlock()

	if len(tasks) == 0 {
		return nil
	}
	var firstFetchErr error
	for _, tk := range tasks {
		raw, err := c.fetchVerifiedSidecar(ctx, sess, ldrstore.SidecarWrap, tk.commit)
		if err != nil {
			// Transport, cancellation, missing-sidecar, or commitment-mismatch
			// fetch errors are retryable — NEVER poison durable BadWraps until
			// verified committed bytes themselves fail unwrap!
			if firstFetchErr == nil {
				firstFetchErr = err
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		epochKey, unwrapErr := ldrcrypto.UnwrapEpochKey(myEncPriv, raw, tk.wctx)

		c.mu.Lock()
		if c.epochsUncertain {
			c.mu.Unlock()
			return ErrEpochsUncertain
		}
		cand := clonePersistedEpochs(c.epochs)
		if unwrapErr != nil {
			// Verified committed wrap bytes failed cryptographic unwrap:
			// permanently bad wrap (§6.3, §10.2; does not stop control replay).
			cand.BadWraps[tk.epoch] = true
		} else {
			cand.Keys[tk.epoch] = epochKey
			delete(cand.BadWraps, tk.epoch)
		}
		if saveErr := c.persistEpochsLocked(cand); saveErr != nil {
			c.markEpochsUncertainOnErrLocked(saveErr)
			c.mu.Unlock()
			return saveErr
		}
		c.epochs = cand
		c.mu.Unlock()
	}
	return firstFetchErr
}

// PayloadContextBytes constructs the non-circular AAD/KDF context binding all
// visible control fields of a payload-bearing record (excluding payload_commit and sig).
func PayloadContextBytes(profDigest [32]byte, lineID []byte, gen uint64, origin string, principal ldrcrypto.Principal, actorID string, bindingGen uint64, opID, opType string, authEpoch, keyEpoch, seenSeq uint64, seenHead [32]byte, expect ldrcrypto.ExpectMap, fields ldrcrypto.Map) ([]byte, error) {
	pCBOR, err := principal.ToCBOR()
	if err != nil {
		return nil, err
	}
	if expect == nil {
		expect = ldrcrypto.ExpectMap{}
	}
	em, err := expect.ToCBORMap()
	if err != nil {
		return nil, err
	}
	if fields == nil {
		fields = ldrcrypto.Map{}
	}
	return ldrcrypto.MarshalCBOR([]any{
		"ldr.payload-context",
		uint64(1),
		profDigest[:],
		lineID,
		gen,
		origin,
		pCBOR,
		actorID,
		bindingGen,
		opID,
		opType,
		authEpoch,
		keyEpoch,
		seenSeq,
		seenHead[:],
		em,
		fields,
	})
}

func payloadContextFromDecoded(dec *ldrrelay.DecodedIntent, rawBodyBytes []byte) ([]byte, error) {
	v, err := ldrcrypto.UnmarshalCBORDefault(rawBodyBytes)
	if err != nil {
		return nil, err
	}
	m := v.(map[string]any)
	rawExp, _ := ldrcrypto.ParseExpectMap(m["expect"])
	rawFields := m["fields"].(map[string]any)
	fEntries := make(ldrcrypto.Map, 0, len(rawFields))
	for k, val := range rawFields {
		fEntries = append(fEntries, ldrcrypto.MapEntry{Key: k, Value: val})
	}
	return PayloadContextBytes(
		dec.ProfileDigest, dec.LineID, dec.Generation, dec.Origin, dec.Principal,
		dec.Record.Actor, uint64(dec.Record.BindingGen), dec.OpID, dec.OpType,
		uint64(dec.Record.AuthEpoch), uint64(dec.Record.KeyEpoch),
		dec.SeenSeq, dec.SeenHead, rawExp, fEntries,
	)
}

func (c *Client) fetchVerifiedSidecar(ctx context.Context, sess *ldrrelay.SessionClient, kind string, commit ldrcrypto.Commitment) ([]byte, error) {
	cachePath := c.sidecarCachePath(kind, commit.Digest)
	verify := func(data []byte) error {
		if kind == ldrstore.SidecarPayload {
			return ldrcrypto.VerifyPayloadSidecar(commit, data)
		}
		return ldrcrypto.VerifyWrapSidecar(commit, data)
	}
	if cached, err := os.ReadFile(cachePath); err == nil {
		if verify(cached) == nil {
			return cached, nil
		}
	}
	if sess == nil {
		return nil, ldrstore.ErrMissingSidecar
	}
	raw, err := sess.FetchSidecar(ctx, kind, commit.Digest)
	if err != nil {
		return nil, err
	}
	if err := verify(raw); err != nil {
		return nil, err
	}
	_ = ldrstore.AtomicWriteFile(cachePath, raw, 0o600)
	return raw, nil
}

// ReadPayload fetches, commitment-verifies, and decrypts the payload of committed
// seq, reporting the exact 3-state diagnostic of §10.2 without stopping replay:
//   - ldrcore.ReadNone (ciphertext-free record)
//   - ldrcore.ReadNoKey (reader holds no key for this epoch)
//   - ldrcore.ReadUndecryptable (commitment/AEAD failure; never blames writer)
//   - ldrcore.ReadMalformed (authenticated JSON payload failed author rule)
//   - ldrcore.ReadOK (authenticated, valid plaintext)
func (c *Client) ReadPayload(ctx context.Context, sess *ldrrelay.SessionClient, seq uint64) ([]byte, string, error) {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return nil, "", ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return nil, "", ErrEpochsUncertain
	}
	if !c.outbox.Activated {
		c.mu.Unlock()
		return nil, "", ErrNotActivated
	}
	if seq < 1 || seq > uint64(len(c.entries)) {
		c.mu.Unlock()
		return nil, "", fmt.Errorf("ldrclient: seq %d not in verified store", seq)
	}
	ve := c.entries[seq-1]
	if ve.decoded == nil || ve.decoded.PayloadCommit.Length == 0 {
		c.mu.Unlock()
		return nil, ldrcore.ReadNone, nil
	}
	ep := uint64(ve.decoded.Record.KeyEpoch)
	epochKey, haveKey := c.epochs.Keys[ep]
	if !haveKey {
		c.mu.Unlock()
		return nil, ldrcore.ReadNoKey, nil
	}
	epochKey = bytes.Clone(epochKey)
	commit := ve.decoded.PayloadCommit
	dec := ve.decoded
	intentBytes := bytes.Clone(ve.frame.IntentBytes)
	c.mu.Unlock()

	rawSidecar, err := c.fetchVerifiedSidecar(ctx, sess, ldrstore.SidecarPayload, commit)
	if err != nil {
		return nil, ldrcore.ReadUndecryptable, nil
	}
	env, err := ldrcrypto.UnmarshalSignedIntent(intentBytes, ldrcrypto.DefaultLimits())
	if err != nil {
		return nil, ldrcore.ReadUndecryptable, nil
	}
	ctxBytes, err := payloadContextFromDecoded(dec, env.BodyBytes)
	if err != nil {
		return nil, ldrcore.ReadUndecryptable, nil
	}
	pt, err := ldrcrypto.OpenPayload(epochKey, ctxBytes, rawSidecar)
	if err != nil {
		return nil, ldrcore.ReadUndecryptable, nil
	}
	// Example plaintext author-validity check (§10.2): call_status requires non-empty reason.
	if dec.OpType == "call_status" {
		var obj map[string]any
		if json.Unmarshal(pt, &obj) != nil {
			return pt, ldrcore.ReadMalformed, nil
		}
		if reason, _ := obj["reason"].(string); strings.TrimSpace(reason) == "" {
			return pt, ldrcore.ReadMalformed, nil
		}
	}
	return pt, ldrcore.ReadOK, nil
}

// --- Outbox Discipline (Persist-Before-Send & Rule 8) ---

// ComposeParams specifies one mutation to sign and persist in the local outbox.
type ComposeParams struct {
	Action    string
	Origin    string // root | operator | credential | actor
	OpType    string
	ActorID   string // required when Origin == actor
	Expect    ldrcrypto.ExpectMap
	Fields    ldrcrypto.Map
	Plaintext []byte // required for payload-bearing op types
}

// ComposeAndPersist validates local preconditions (fail-closed, MustResolve,
// Rule 8 stopped key, slot occupancy, activation), encrypts any payload using
// active K_epoch, signs the exact wire intent ONCE, and durably persists it to
// outbox.cbor (F_FULLFSYNC) BEFORE returning opID. Sends nothing.
func (c *Client) ComposeAndPersist(p ComposeParams) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.outboxUncertain {
		return "", ErrOutboxUncertain
	}
	if c.epochsUncertain {
		return "", ErrEpochsUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		return "", ErrFailClosed
	}
	if c.outbox.MustResolve {
		return "", ErrMustResolve
	}
	// Provisional unactivated member directories may not sign or stage ANY
	// mutation, even if an administrative key happens to be attached. Separate
	// administrative directories (DirKindAdmin) start Activated=true.
	if !c.outbox.Activated {
		return "", ErrNotActivated
	}

	prin, signer, slotActor, bindingGen, err := c.resolveComposeSignerLocked(p.Origin, p.ActorID)
	if err != nil {
		return "", err
	}
	prinTok, err := ldrrelay.PrincipalToken(prin)
	if err != nil {
		return "", err
	}
	if c.signsNoMoreLocked(prinTok) {
		return "", ErrKeyRevoked
	}

	gen := c.ckGen
	if p.OpType == "line_init" && c.ckSeq == 0 {
		gen = 1
	} else if c.ckSeq == 0 {
		return "", ldrcore.ErrNoLine
	}

	slot := slotActor + "|" + computeSlotTarget(p.OpType, p.Fields)
	if _, busy := c.slots[slot]; busy {
		return "", ErrSlotBusy
	}

	nextOp := c.outbox.NextOp + 1
	opID := fmt.Sprintf("op-%d", nextOp)
	authEpoch := uint64(c.state.Line.AuthEpoch)
	keyEpoch := uint64(c.state.Line.KeyEpoch)
	validity := c.validityMS
	if p.OpType == "line_init" {
		validity = 0
	}

	var payloadPkg []byte
	payloadCommit := ldrcrypto.EmptyPayloadCommit()
	if len(p.Plaintext) > 0 {
		epKey, ok := c.epochs.Keys[keyEpoch]
		if !ok || keyEpoch == 0 {
			return "", ErrNoEpochKey
		}
		ctxBytes, err := PayloadContextBytes(
			c.profDigest, c.cfg.LineID, gen, p.Origin, prin,
			p.ActorID, bindingGen, opID, p.OpType,
			authEpoch, keyEpoch, c.ckSeq, c.ckHead, p.Expect, p.Fields,
		)
		if err != nil {
			return "", err
		}
		payloadPkg, err = ldrcrypto.SealPayload(epKey, ctxBytes, p.Plaintext)
		if err != nil {
			return "", err
		}
		payloadCommit, err = ldrcrypto.CommitPayload(payloadPkg)
		if err != nil {
			return "", err
		}
	}

	body, err := ldrrelay.BuildWireIntentBody(ldrrelay.WireIntentInput{
		ProfileDigest: c.profDigest,
		LineID:        c.cfg.LineID,
		Generation:    gen,
		Origin:        p.Origin,
		Principal:     prin,
		ActorID:       p.ActorID,
		BindingGen:    bindingGen,
		OpID:          opID,
		OpType:        p.OpType,
		AuthEpoch:     authEpoch,
		KeyEpoch:      keyEpoch,
		SeenSeq:       c.ckSeq,
		SeenHead:      c.ckHead,
		ValidityMS:    validity,
		PayloadCommit: payloadCommit,
		Expect:        p.Expect,
		Fields:        p.Fields,
	})
	if err != nil {
		return "", err
	}
	env, err := ldrcrypto.SignIntent(signer, body)
	if err != nil {
		return "", err
	}
	dig, err := env.Digest()
	if err != nil {
		return "", err
	}

	entry := &OutboxEntry{
		OpID:           opID,
		Action:         p.Action,
		Slot:           slot,
		Gen:            gen,
		SignerToken:    prinTok,
		Principal:      prin,
		SeenSeq:        c.ckSeq,
		SeenHead:       c.ckHead,
		OpType:         p.OpType,
		IntentBytes:    env.RawBytes,
		IntentDigest:   dig,
		PayloadSidecar: payloadPkg,
		WrapSidecars:   make(map[[32]byte][]byte),
		Status:         ldrcore.OutPending,
	}
	cand := clonePersistedOutbox(c.outbox)
	cand.NextOp = nextOp
	cand.Entries = append(cand.Entries, entry)
	candSlots := cloneSlots(c.slots)
	candSlots[slot] = opID
	if err := c.persistOutboxLocked(cand); err != nil {
		c.markOutboxUncertainOnErrLocked(err)
		return "", err
	}
	c.outbox = cand
	c.slots = candSlots
	return opID, nil
}

// ComposeEpochActivate implements P9: requires this device to be an active
// entitled reader (so epoch key generation happens only on an enrolled reader),
// generates a fresh 32-byte K_epoch, wraps to every entitled reader, signs with
// the attached operator key, and durably persists to outbox.cbor BEFORE sending.
func (c *Client) ComposeEpochActivate(action string) (string, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.outboxUncertain {
		return "", nil, ErrOutboxUncertain
	}
	if c.epochsUncertain {
		return "", nil, ErrEpochsUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		return "", nil, ErrFailClosed
	}
	if c.outbox.MustResolve {
		return "", nil, ErrMustResolve
	}
	if !c.outbox.Activated {
		return "", nil, ErrNotActivated
	}
	if c.operatorKey == nil {
		return "", nil, errors.New("ldrclient: operator key required for key_epoch_activate")
	}
	if c.ckSeq == 0 {
		return "", nil, ldrcore.ErrNoLine
	}

	entitled := c.state.Line.EntitledReaders()
	if len(entitled) == 0 {
		return "", nil, errors.New("ldrclient: no entitled readers to activate epoch for")
	}
	// P9 enforcement: honest epoch key generation MUST run on an active entitled reader.
	if c.credKeys == nil {
		return "", nil, errors.New("ldrclient: P9 requires epoch activation to run on an enrolled entitled reader credential")
	}
	myTok := ldrrelay.CredToken(c.credKeys.CredID)
	if !slices.Contains(entitled, myTok) {
		return "", nil, errors.New("ldrclient: P9 requires epoch key generator to be an entitled reader")
	}

	opPrin := ldrcrypto.OperatorPrincipal(c.operatorKey.Signer.PublicKey())
	opTok, err := ldrrelay.PrincipalToken(opPrin)
	if err != nil {
		return "", nil, err
	}
	if c.signsNoMoreLocked(opTok) {
		return "", nil, ErrKeyRevoked
	}
	slot := opTok + "|key_epoch"
	if _, busy := c.slots[slot]; busy {
		return "", nil, ErrSlotBusy
	}

	epochKey, err := ldrcrypto.GenerateEpochKey()
	if err != nil {
		return "", nil, err
	}
	curEpoch := uint64(c.state.Line.KeyEpoch)
	newEpoch := curEpoch + 1
	authEpoch := uint64(c.state.Line.AuthEpoch)

	credIDs := make([][32]byte, 0, len(entitled))
	encKeys := make(map[[32]byte]ldrcrypto.PublicKey, len(entitled))
	for _, tok := range entitled {
		idB, err := hex.DecodeString(tok)
		if err != nil || len(idB) != 32 {
			return "", nil, errors.New("ldrclient: invalid entitled reader cred_id")
		}
		var cid [32]byte
		copy(cid[:], idB)
		ek, err := ldrrelay.ParseKeyToken(c.state.Line.Credentials[tok].EncryptionKey)
		if err != nil {
			return "", nil, err
		}
		credIDs = append(credIDs, cid)
		encKeys[cid] = ek
	}
	sort.Slice(credIDs, func(i, j int) bool { return bytes.Compare(credIDs[i][:], credIDs[j][:]) < 0 })
	rsDigest, err := ldrcrypto.ReaderSetDigest(credIDs)
	if err != nil {
		return "", nil, err
	}

	nextOp := c.outbox.NextOp + 1
	opID := fmt.Sprintf("op-%d", nextOp)
	manifest := make([]ldrcrypto.WrapManifestEntry, 0, len(credIDs))
	wraps := make(map[[32]byte][]byte, len(credIDs))
	for _, cid := range credIDs {
		wctx, err := BuildEpochWrapContext(
			c.cfg.LineID, c.ckGen, c.profDigest,
			newEpoch, curEpoch, authEpoch,
			opPrin, c.ckSeq, opID,
			cid, encKeys[cid], rsDigest,
		)
		if err != nil {
			return "", nil, err
		}
		wb, err := ldrcrypto.WrapEpochKey(epochKey, wctx)
		if err != nil {
			return "", nil, err
		}
		wc, err := ldrcrypto.CommitWrap(wb)
		if err != nil {
			return "", nil, err
		}
		manifest = append(manifest, ldrcrypto.WrapManifestEntry{CredID: cid, Commit: wc})
		wraps[cid] = wb
	}

	body, err := ldrrelay.BuildWireIntentBody(ldrrelay.WireIntentInput{
		ProfileDigest: c.profDigest,
		LineID:        c.cfg.LineID,
		Generation:    c.ckGen,
		Origin:        ldrcore.OriginOperator,
		Principal:     opPrin,
		OpID:          opID,
		OpType:        "key_epoch_activate",
		AuthEpoch:     authEpoch,
		KeyEpoch:      curEpoch,
		SeenSeq:       c.ckSeq,
		SeenHead:      c.ckHead,
		ValidityMS:    c.validityMS,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"key_epoch": curEpoch},
		Manifest:      manifest,
	})
	if err != nil {
		return "", nil, err
	}
	env, err := ldrcrypto.SignIntent(c.operatorKey.Signer, body)
	if err != nil {
		return "", nil, err
	}
	dig, err := env.Digest()
	if err != nil {
		return "", nil, err
	}

	entry := &OutboxEntry{
		OpID:         opID,
		Action:       action,
		Slot:         slot,
		Gen:          c.ckGen,
		SignerToken:  opTok,
		Principal:    opPrin,
		SeenSeq:      c.ckSeq,
		SeenHead:     c.ckHead,
		OpType:       "key_epoch_activate",
		IntentBytes:  env.RawBytes,
		IntentDigest: dig,
		WrapSidecars: wraps,
		Status:       ldrcore.OutPending,
	}
	cand := clonePersistedOutbox(c.outbox)
	cand.NextOp = nextOp
	cand.Entries = append(cand.Entries, entry)
	candSlots := cloneSlots(c.slots)
	candSlots[slot] = opID
	if err := c.persistOutboxLocked(cand); err != nil {
		c.markOutboxUncertainOnErrLocked(err)
		return "", nil, err
	}
	c.outbox = cand
	c.slots = candSlots
	return opID, epochKey, nil
}

func cloneOutboxEntry(e *OutboxEntry) *OutboxEntry {
	if e == nil {
		return nil
	}
	cp := *e
	cp.IntentBytes = bytes.Clone(e.IntentBytes)
	cp.PayloadSidecar = bytes.Clone(e.PayloadSidecar)
	cp.WrapSidecars = make(map[[32]byte][]byte, len(e.WrapSidecars))
	for k, v := range e.WrapSidecars {
		cp.WrapSidecars[k] = bytes.Clone(v)
	}
	return &cp
}

func clonePersistedOutbox(ob persistedOutbox) persistedOutbox {
	cp := ob
	cp.KeyStops = make(map[string]*KeyStop, len(ob.KeyStops))
	for k, v := range ob.KeyStops {
		if v != nil {
			ks := *v
			cp.KeyStops[k] = &ks
		}
	}
	cp.Entries = make([]*OutboxEntry, len(ob.Entries))
	for i, e := range ob.Entries {
		cp.Entries[i] = cloneOutboxEntry(e)
	}
	return cp
}

func cloneSlots(s map[string]string) map[string]string {
	cp := make(map[string]string, len(s))
	for k, v := range s {
		cp[k] = v
	}
	return cp
}

func isOutboxFinal(status string) bool {
	return status == ldrcore.OutDone || status == ldrcore.OutClosed
}

func storedSubmitReply(e *OutboxEntry) ldrrelay.SubmitReply {
	return ldrrelay.SubmitReply{
		Class:   e.LastClass,
		Code:    e.LastCode,
		Outcome: ldrstore.StoredOutcome{Kind: e.OutcomeKind, Reason: e.OutcomeReason, Seq: e.OutcomeSeq},
	}
}

// Send transmits the exact persisted bytes of opID over sess, settles the outbox
// entry per §5.7, and persists the result durably BEFORE publishing entry or
// slot changes in memory. Revalidates entry status and slot ownership after
// network I/O so late replies never re-settle finalized entries or release
// slots owned by newer operations. Never re-signs or alters bytes!
func (c *Client) Send(ctx context.Context, sess *ldrrelay.SessionClient, opID string) (ldrrelay.SubmitReply, error) {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, ErrOutboxUncertain
	}
	if !c.outbox.Activated {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, ErrNotActivated
	}
	idx, e := c.findOutboxIndexLocked(opID)
	if e == nil {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, fmt.Errorf("ldrclient: unknown outbox op %q", opID)
	}
	if e.Status != ldrcore.OutPending {
		rep := storedSubmitReply(e)
		c.mu.Unlock()
		return rep, nil
	}
	if c.signsNoMoreLocked(e.SignerToken) {
		cand := clonePersistedOutbox(c.outbox)
		cand.Entries[idx].Status = ldrcore.OutReconcile
		if perr := c.persistOutboxLocked(cand); perr != nil {
			c.markOutboxUncertainOnErrLocked(perr)
		} else {
			c.outbox = cand
		}
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, ErrKeyRevoked
	}
	if c.outbox.MustResolve {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, ErrMustResolve
	}
	candSend := clonePersistedOutbox(c.outbox)
	candSend.Entries[idx].Sends++
	if err := c.persistOutboxLocked(candSend); err != nil {
		c.markOutboxUncertainOnErrLocked(err)
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, err
	}
	c.outbox = candSend
	cur := c.outbox.Entries[idx]
	intentBytes := bytes.Clone(cur.IntentBytes)
	payloadSidecar := bytes.Clone(cur.PayloadSidecar)
	wrapSidecars := make(map[[32]byte][]byte, len(cur.WrapSidecars))
	for k, v := range cur.WrapSidecars {
		wrapSidecars[k] = bytes.Clone(v)
	}
	c.mu.Unlock()

	rep, err := sess.Submit(ctx, intentBytes, payloadSidecar, wrapSidecars)

	c.mu.Lock()
	if err != nil {
		defer c.mu.Unlock()
		idx, current := c.findOutboxIndexLocked(opID)
		if c.outboxUncertain || current == nil || isOutboxFinal(current.Status) || c.signsNoMoreLocked(current.SignerToken) {
			return ldrrelay.SubmitReply{}, err
		}
		// The relay may already have committed these exact bytes. Require a new
		// query pass before another mutation, including in a long-lived client.
		cand := clonePersistedOutbox(c.outbox)
		cand.ResolveEpoch++
		cand.MustResolve = true
		cand.Entries[idx].NeedsResolve = true
		if saveErr := c.persistOutboxLocked(cand); saveErr != nil {
			// Even a pre-write failure leaves the remote outcome uncertain.
			// Reopening reconstructs the barrier from the durable pending entry.
			c.outboxUncertain = true
			c.outboxUncertainReason = saveErr.Error()
			return ldrrelay.SubmitReply{}, errors.Join(err, saveErr)
		}
		c.outbox = cand
		return ldrrelay.SubmitReply{}, err
	}

	if c.outboxUncertain {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, ErrOutboxUncertain
	}
	idx, cur = c.findOutboxIndexLocked(opID)
	if cur == nil {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, fmt.Errorf("ldrclient: unknown outbox op %q", opID)
	}
	if isOutboxFinal(cur.Status) {
		// Already finalized while Submit was in flight: ignore late reply and
		// leave finalized entry and any reused slot untouched.
		settled := storedSubmitReply(cur)
		c.mu.Unlock()
		return settled, nil
	}
	if cur.Status == ldrcore.OutReconcile && (rep.Class == ldrcore.ClassAdmission || rep.Class == ldrcore.ClassUnknown) {
		// Entry transitioned to OutReconcile while Submit was in flight; a
		// non-definitive reply must not overwrite its stored reason.
		settled := storedSubmitReply(cur)
		c.mu.Unlock()
		return settled, nil
	}
	cand := clonePersistedOutbox(c.outbox)
	candSlots := cloneSlots(c.slots)
	c.applySettlementToCandidateLocked(&cand, candSlots, idx, rep)
	saveErr := c.persistOutboxLocked(cand)
	if saveErr != nil {
		c.markOutboxUncertainOnErrLocked(saveErr)
		c.mu.Unlock()
		return rep, saveErr
	}
	c.outbox = cand
	c.slots = candSlots
	c.mu.Unlock()
	return rep, nil
}

// ResolveAll queries unsettled outbox intents authorized for sessPrincipal over
// sess without re-sending bytes (§5.7 rules 3 & 5, G1 fix, Rule 8).
//
// Each answered entry is durably persisted before its entry/slot update is
// published in memory, preserving progress across sequential passes for
// multiple active signers. MustResolve clears ONLY once every unsettled intent
// of every active (non-stopped) signer has received a non-admission answer in
// the current resolution round. Late replies after network I/O revalidate entry
// status and slot ownership before applying.
func (c *Client) ResolveAll(ctx context.Context, sess *ldrrelay.SessionClient, sessPrincipal ldrcrypto.Principal) error {
	sessTok, err := ldrrelay.PrincipalToken(sessPrincipal)
	if err != nil {
		return err
	}
	isReconciler := sessPrincipal.Kind == ldrcrypto.PrincipalRoot || sessPrincipal.Kind == ldrcrypto.PrincipalOperator

	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ErrOutboxUncertain
	}
	if !c.outbox.Activated {
		c.mu.Unlock()
		return ErrNotActivated
	}
	var todoOpIDs []string
	for _, e := range c.outbox.Entries {
		if e.Status != ldrcore.OutPending && e.Status != ldrcore.OutReconcile {
			continue
		}
		if c.signsNoMoreLocked(e.SignerToken) {
			continue
		}
		if e.SignerToken != sessTok && !isReconciler {
			continue
		}
		todoOpIDs = append(todoOpIDs, e.OpID)
	}
	c.mu.Unlock()

	incomplete := false
	for _, opID := range todoOpIDs {
		c.mu.Lock()
		if c.outboxUncertain {
			c.mu.Unlock()
			return ErrOutboxUncertain
		}
		_, cur := c.findOutboxIndexLocked(opID)
		if cur == nil || isOutboxFinal(cur.Status) || c.signsNoMoreLocked(cur.SignerToken) {
			c.mu.Unlock()
			continue
		}
		queryEpoch := c.outbox.ResolveEpoch
		key := ldrstore.StoredOpKey{Generation: cur.Gen, Signer: cur.SignerToken, SeenSeq: cur.SeenSeq, OpID: cur.OpID}
		dig := cur.IntentDigest
		c.mu.Unlock()

		rep, err := sess.Query(ctx, key, dig)
		if err != nil {
			incomplete = true
			continue
		}

		c.mu.Lock()
		if c.outboxUncertain {
			c.mu.Unlock()
			return ErrOutboxUncertain
		}
		idx, cur := c.findOutboxIndexLocked(opID)
		if cur == nil || isOutboxFinal(cur.Status) || c.signsNoMoreLocked(cur.SignerToken) {
			// Finalized or stopped while Query was in flight: ignore late reply
			// without touching finalized entries or reused slot owners.
			c.mu.Unlock()
			continue
		}
		stalePass := c.outbox.ResolveEpoch != queryEpoch
		if stalePass && (rep.Class == ldrcore.ClassUnknown || rep.Class == ldrcore.ClassAdmission) {
			// A newer resolution pass began (e.g. stale-checkpoint refusal) while
			// this query was in flight; a non-definitive reply from the earlier pass
			// MUST NOT clear NeedsResolve or overwrite the entry's state (§5.7 rule 3).
			incomplete = true
			c.mu.Unlock()
			continue
		}
		cand := clonePersistedOutbox(c.outbox)
		candSlots := cloneSlots(c.slots)
		candEntry := cand.Entries[idx]
		switch {
		case rep.Class == ldrcore.ClassAdmission:
			incomplete = true
			if candEntry.Status == ldrcore.OutReconcile {
				c.mu.Unlock()
				continue
			}
			c.applySettlementToCandidateLocked(&cand, candSlots, idx, rep)
		case candEntry.Status == ldrcore.OutReconcile && rep.Class == ldrcore.ClassUnknown:
			// Relay has no outcome for an OutReconcile intent: preserve its
			// stored reason while marking this entry answered for this pass.
			candEntry.NeedsResolve = false
		default:
			c.applySettlementToCandidateLocked(&cand, candSlots, idx, rep)
			if candEntry.Status == ldrcore.OutPending || candEntry.Status == ldrcore.OutReconcile {
				if !stalePass {
					candEntry.NeedsResolve = false
				} else {
					incomplete = true
				}
			}
		}
		if cand.MustResolve && !incomplete && !c.hasActiveNeedsResolveInOutboxLocked(&cand) {
			cand.MustResolve = false
		}
		if saveErr := c.persistOutboxLocked(cand); saveErr != nil {
			c.markOutboxUncertainOnErrLocked(saveErr)
			c.mu.Unlock()
			return saveErr
		}
		c.outbox = cand
		c.slots = candSlots
		c.mu.Unlock()
	}

	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ErrOutboxUncertain
	}
	if c.outbox.MustResolve && !incomplete && !c.hasActiveNeedsResolveInOutboxLocked(&c.outbox) {
		cand := clonePersistedOutbox(c.outbox)
		cand.MustResolve = false
		if saveErr := c.persistOutboxLocked(cand); saveErr != nil {
			c.markOutboxUncertainOnErrLocked(saveErr)
			c.mu.Unlock()
			return saveErr
		}
		c.outbox = cand
	}
	c.mu.Unlock()
	return nil
}

func (c *Client) applySettlementToCandidateLocked(ob *persistedOutbox, slots map[string]string, idx int, rep ldrrelay.SubmitReply) {
	e := ob.Entries[idx]
	e.LastClass = rep.Class
	e.LastCode = rep.Code
	e.OutcomeKind = rep.Outcome.Kind
	e.OutcomeReason = rep.Outcome.Reason
	e.OutcomeSeq = rep.Outcome.Seq

	switch rep.Class {
	case ldrcore.ClassOutcome:
		e.Status = ldrcore.OutDone
		e.NeedsResolve = false
		if slots[e.Slot] == e.OpID {
			delete(slots, e.Slot)
		}
	case ldrcore.ClassRefusal:
		e.Status = ldrcore.OutClosed
		e.NeedsResolve = false
		if slots[e.Slot] == e.OpID {
			delete(slots, e.Slot)
		}
		if rep.Code == "expired" || rep.Code == "unknown_anchor" {
			hasUnsettled := false
			hasActive := false
			for _, other := range ob.Entries {
				if other.Status == ldrcore.OutPending || other.Status == ldrcore.OutReconcile {
					hasUnsettled = true
					other.NeedsResolve = true
					if !c.signsNoMoreInOutboxLocked(ob, other.SignerToken) {
						hasActive = true
					}
				}
			}
			if hasUnsettled {
				// Start a fresh resolution epoch so any in-flight non-definitive
				// queries issued before this stale-checkpoint refusal cannot clear
				// NeedsResolve on remaining entries (§5.7 rule 3).
				ob.ResolveEpoch++
			}
			if hasActive {
				ob.MustResolve = true
			}
		}
	case ldrcore.ClassUnresolved:
		e.Status = ldrcore.OutReconcile
		if rep.Code == "history_unavailable" {
			ob.Suspect = true
		} else if rep.Code == "revoked" {
			c.recordToldRevokedOnLocked(ob, e.SignerToken, rep.Code)
		}
	case ldrcore.ClassMismatch:
		e.Status = ldrcore.OutReconcile
	case ldrcore.ClassAdmission:
		if !transientAdmission[rep.Code] {
			e.Status = ldrcore.OutReconcile
		}
	}
}

func (c *Client) findOutboxIndexLocked(opID string) (int, *OutboxEntry) {
	for i, e := range c.outbox.Entries {
		if e.OpID == opID {
			return i, e
		}
	}
	return -1, nil
}

func (c *Client) hasActiveNeedsResolveInOutboxLocked(ob *persistedOutbox) bool {
	for _, e := range ob.Entries {
		if (e.Status == ldrcore.OutPending || e.Status == ldrcore.OutReconcile) &&
			e.NeedsResolve && !c.signsNoMoreInOutboxLocked(ob, e.SignerToken) {
			return true
		}
	}
	return false
}

func (c *Client) devicePrincipalsLocked() []string {
	var out []string
	if c.credKeys != nil {
		out = append(out, ldrcore.CredentialPrincipal(ldrrelay.CredToken(c.credKeys.CredID)))
	}
	if c.operatorKey != nil {
		if tok, err := ldrrelay.KeyToken(c.operatorKey.Signer.PublicKey()); err == nil {
			out = append(out, ldrcore.OperatorPrincipal(tok))
		}
	}
	if c.rootKey != nil {
		if tok, err := ldrrelay.KeyToken(c.rootKey.Signer.PublicKey()); err == nil {
			out = append(out, ldrcore.RootPrincipal(tok))
		}
	}
	return out
}

func (c *Client) revokedInRecordsLocked(p string) bool {
	l := &c.state.Line
	switch {
	case strings.HasPrefix(p, "cred:"):
		cr := l.Credentials[strings.TrimPrefix(p, "cred:")]
		return cr != nil && cr.Revoked
	case strings.HasPrefix(p, "op:"):
		return slices.Contains(l.Tombstones.OperatorKeys, strings.TrimPrefix(p, "op:"))
	case strings.HasPrefix(p, "root:"):
		return slices.Contains(l.Tombstones.RootKeys, strings.TrimPrefix(p, "root:"))
	}
	return false
}

func (c *Client) signsNoMoreInOutboxLocked(ob *persistedOutbox, p string) bool {
	return ob.KeyStops[p] != nil || c.pendingStops[p] != nil || c.revokedInRecordsLocked(p)
}

func (c *Client) signsNoMoreLocked(p string) bool {
	return c.signsNoMoreInOutboxLocked(&c.outbox, p)
}

func (c *Client) recordToldRevokedOnLocked(ob *persistedOutbox, p, code string) {
	if ob.KeyStops[p] == nil {
		ob.KeyStops[p] = &KeyStop{Key: p, Told: true, Seq: c.ckSeq, Head: c.ckHead, Code: code}
	}
	c.suspendSignerOnLocked(ob, p)
}

func (c *Client) recordToldRevokedLocked(p, code string) {
	c.recordToldRevokedOnLocked(&c.outbox, p, code)
}

func (c *Client) suspendSignerOnLocked(ob *persistedOutbox, p string) bool {
	changed := false
	for _, e := range ob.Entries {
		if e.Status == ldrcore.OutPending && e.SignerToken == p {
			e.Status = ldrcore.OutReconcile
			changed = true
		}
	}
	return changed
}

func (c *Client) suspendSignerLocked(p string) bool {
	return c.suspendSignerOnLocked(&c.outbox, p)
}

func (c *Client) stopRevokedLocked() bool {
	changed := false
	for _, p := range c.devicePrincipalsLocked() {
		if c.signsNoMoreLocked(p) {
			if c.suspendSignerLocked(p) {
				changed = true
			}
		}
	}
	return changed
}

func (c *Client) resolveComposeSignerLocked(origin, actorID string) (ldrcrypto.Principal, ldrcrypto.Signer, string, uint64, error) {
	switch origin {
	case ldrcore.OriginActor:
		if c.credKeys == nil {
			return ldrcrypto.Principal{}, nil, "", 0, ldrcore.ErrNotSigner
		}
		myTok := ldrrelay.CredToken(c.credKeys.CredID)
		a := c.state.Line.Actors[actorID]
		if a == nil || !a.Live || a.Cred != myTok {
			return ldrcrypto.Principal{}, nil, "", 0, ldrcore.ErrNotSigner
		}
		return ldrcrypto.CredentialPrincipal(c.credKeys.CredID), c.credKeys.Signing.Signer, "actor:" + actorID, uint64(a.BindingGen), nil
	case ldrcore.OriginCredential:
		if c.credKeys == nil {
			return ldrcrypto.Principal{}, nil, "", 0, ldrcore.ErrNotSigner
		}
		return ldrcrypto.CredentialPrincipal(c.credKeys.CredID), c.credKeys.Signing.Signer, "cred:" + ldrrelay.CredToken(c.credKeys.CredID), 0, nil
	case ldrcore.OriginOperator:
		if c.operatorKey == nil {
			return ldrcrypto.Principal{}, nil, "", 0, ldrcore.ErrNotSigner
		}
		p := ldrcrypto.OperatorPrincipal(c.operatorKey.Signer.PublicKey())
		tok, _ := ldrrelay.PrincipalToken(p)
		return p, c.operatorKey.Signer, tok, 0, nil
	case ldrcore.OriginRoot:
		if c.rootKey == nil {
			return ldrcrypto.Principal{}, nil, "", 0, ldrcore.ErrNotSigner
		}
		p := ldrcrypto.RootPrincipal(c.rootKey.Signer.PublicKey())
		tok, _ := ldrrelay.PrincipalToken(p)
		return p, c.rootKey.Signer, tok, 0, nil
	default:
		return ldrcrypto.Principal{}, nil, "", 0, ldrcore.ErrNotSigner
	}
}

func computeSlotTarget(opType string, fields ldrcrypto.Map) string {
	getStr := func(k string) string {
		for _, ent := range fields {
			if ent.Key == k {
				if s, ok := ent.Value.(string); ok {
					return s
				}
			}
		}
		return ""
	}
	switch opType {
	case "line_init":
		return "line"
	case "key_epoch_activate":
		return "key_epoch"
	case "actor_declare", "actor_move", "actor_remove", "actor_addressing":
		return "actor:" + getStr("actor_id")
	case "register_activate":
		return "register:" + getStr("actor_id") + "/" + getStr("register")
	case "broadcast_create", "broadcast_read", "broadcast_reply":
		return "broadcast:" + getStr("broadcast_id")
	case "call_open", "call_turn", "call_bye", "call_status", "call_note", "call_ratify", "call_attach",
		"dispute_open", "dispute_measure", "dispute_resolve", "dispute_arbitrate":
		return "call:" + getStr("call_id")
	default:
		return opType
	}
}
