package ldrclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	ErrSlotBusy        = errors.New("ldrclient: an unresolved intent already holds this slot")
	ErrMustResolve     = errors.New("ldrclient: stored unsettled intents must be resolved before composing")
	ErrFailClosed      = errors.New("ldrclient: client failed closed due to violation or suspected rollback")
	ErrKeyRevoked      = errors.New("ldrclient: key is revoked and signs nothing more")
	ErrNotActivated    = errors.New("ldrclient: member has not completed O25 enrollment verification")
	ErrNoEpochKey      = errors.New("ldrclient: no epoch key available for payload encryption")
	ErrEnrollmentCheck = errors.New("ldrclient: committed enrollment disagrees with saved P3 request")
	ErrViolation       = errors.New("ldrclient: sequencer violation detected on replay")
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
	frame   ldrrelay.ControlFrameWire
	decoded *ldrrelay.DecodedIntent // nil for time_anchor
	touched []string
	owed    []LocalNotice
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
	state   ldrcore.State
	entries []verifiedEntry
	ckGen   uint64
	ckSeq   uint64
	ckHead  [32]byte
	rctx    *replayContext
	touched map[string]projCoord
	source  map[string]projCoord
	viewOf  map[string]string

	// Durable outbox, epoch keys, and projection/delivery cursors.
	outbox  persistedOutbox
	slots   map[string]string // slot -> unsettled op_id
	epochs  persistedEpochs
	cursors persistedCursors
}

// InitDirOptions configures initializing a fresh client directory for a pinned descriptor.
type InitDirOptions struct {
	Dir              string
	SignedDescriptor []byte
	CredKeys         *CredentialKeyBundle // optional (for member credential)
	ExpectedGrant    *ldrcrypto.JoinGrant // optional (for P3 onboarding verification)
	ExpectedJoinReq  []byte               // optional
	Activated        bool                 // true for root/operator admin dirs; false for joining members until O25 gate passes
}

// InitClientDir initializes a fresh durable client directory pinned to SignedDescriptor.
func InitClientDir(opts InitDirOptions) (*Client, error) {
	if opts.Dir == "" {
		return nil, errors.New("ldrclient: empty client directory")
	}
	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(opts.SignedDescriptor)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(opts.Dir, "sidecars"), 0o700); err != nil {
		return nil, err
	}
	cfg := persistedConfig{
		SignedDescriptor:  bytes.Clone(opts.SignedDescriptor),
		LineID:            bytes.Clone(desc.LineID),
		DescriptorDigest:  cd,
		GenesisAnchor:     genesis,
		ExpectedGrant:     opts.ExpectedGrant,
		ExpectedJoinReqID: bytes.Clone(opts.ExpectedJoinReq),
	}
	if opts.CredKeys != nil {
		cid := opts.CredKeys.CredID
		cfg.ExpectedCredID = &cid
		if err := SaveCredentialKeys(filepath.Join(opts.Dir, "cred.key"), opts.CredKeys); err != nil {
			return nil, err
		}
	}
	if err := saveConfig(filepath.Join(opts.Dir, "config.cbor"), cfg); err != nil {
		return nil, err
	}
	if err := saveOutbox(filepath.Join(opts.Dir, "outbox.cbor"), persistedOutbox{
		Activated: opts.Activated,
		KeyStops:  make(map[string]*KeyStop),
	}); err != nil {
		return nil, err
	}
	return OpenClient(opts.Dir)
}

// OpenClient opens an existing client directory, acquires its exclusive OS lock,
// verifies its pinned creation descriptor, and replays verified.wal from genesis.
// On restart, any unsettled outbox entry automatically sets MustResolve = true (§5.7 rule 3).
func OpenClient(dir string) (*Client, error) {
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
	cleanupLock := func() {
		_ = funlock(lf)
		_ = lf.Close()
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

	c := &Client{
		dir:        dir,
		lockFile:   lf,
		cfg:        cfg,
		desc:       desc,
		profDigest: profDigest,
		coreProf:   ldrcore.Profile{FreshnessMS: int64(desc.Profile.FreshnessMS), ValidityMaxMS: int64(desc.Profile.MaxValidityMS)},
		validityMS: min(60_000, desc.Profile.MaxValidityMS),
		ckHead:     genesis,
		rctx:       newReplayContext(),
		touched:    make(map[string]projCoord),
		source:     make(map[string]projCoord),
		viewOf:     make(map[string]string),
		outbox:     ob,
		slots:      make(map[string]string),
		epochs:     ep,
		cursors:    cur,
	}
	if ck, err := LoadCredentialKeys(c.credKeyPath()); err == nil {
		c.credKeys = ck
	}
	// Rebuild slot index and enforce restart §5.7 rule 3 (MustResolve if unsettled).
	hasUnsettled := false
	for _, e := range c.outbox.Entries {
		if e.Status == ldrcore.OutPending || e.Status == ldrcore.OutReconcile {
			c.slots[e.Slot] = e.OpID
			hasUnsettled = true
		}
	}
	if hasUnsettled && !c.outbox.MustResolve {
		c.outbox.MustResolve = true
		if err := saveOutbox(c.outboxPath(), c.outbox); err != nil {
			cleanupLock()
			return nil, err
		}
	}

	// Replay verified.wal from seq 1 to reconstruct exact verified state.
	frames, err := loadVerifiedWAL(c.walPath())
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
			}
			ks.Verified = c.revokedInRecordsLocked(p)
			out = append(out, ks)
		}
	}
	return out
}

// Status returns a concise JSON-friendly status summary (no private keys).
type ClientStatus struct {
	LineID        string   `json:"line_id"`
	CredID        string   `json:"cred_id,omitempty"`
	Activated     bool     `json:"activated"`
	Generation    uint64   `json:"generation"`
	CheckpointSeq uint64   `json:"checkpoint_seq"`
	CheckpointHd  string   `json:"checkpoint_head"`
	KeyEpoch      int64    `json:"key_epoch"`
	AuthEpoch     int64    `json:"auth_epoch"`
	HasEpochKeys  []uint64 `json:"has_epoch_keys"`
	ProjectedSeq  uint64   `json:"projected_seq"`
	ScannedSeq    uint64   `json:"scanned_seq"`
	MustResolve   bool     `json:"must_resolve"`
	Suspect       bool     `json:"suspect"`
	Halted        string   `json:"halted,omitempty"`
	OutboxCount   int      `json:"outbox_count"`
	StoppedKeys   []string `json:"stopped_keys,omitempty"`
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
		LineID:        hex.EncodeToString(c.cfg.LineID),
		CredID:        cid,
		Activated:     c.outbox.Activated,
		Generation:    c.ckGen,
		CheckpointSeq: c.ckSeq,
		CheckpointHd:  hex.EncodeToString(c.ckHead[:]),
		KeyEpoch:      c.state.Line.KeyEpoch,
		AuthEpoch:     c.state.Line.AuthEpoch,
		HasEpochKeys:  epKeys,
		ProjectedSeq:  c.cursors.ProjectedSeq,
		ScannedSeq:    c.cursors.ScannedSeq,
		MustResolve:   c.outbox.MustResolve,
		Suspect:       c.outbox.Suspect,
		Halted:        c.outbox.Halted,
		OutboxCount:   len(c.outbox.Entries),
		StoppedKeys:   stopped,
	}
}

// Dial opens a pinned TLS 1.3 channel-bound SessionClient for the requested origin
// ("credential", "operator", or "root"). Refuses stopped/revoked keys before dialing!
func (c *Client) Dial(ctx context.Context, role string) (*ldrrelay.SessionClient, error) {
	c.mu.Lock()
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
			_ = saveOutbox(c.outboxPath(), c.outbox)
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
				_ = saveOutbox(c.outboxPath(), c.outbox)
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

// VerifyEnrollmentAndActivate implements the O25 full-replay onboarding activation
// gate (§6 of LDR-GO-RELAY-DESIGN.md): obtains a fresh anchor, replays control
// frames 1..fseq from genesis, verifies the credential's committed keys and grant
// match the saved P3 request, unwraps the current epoch key if reader==true, and
// atomically flips Activated = true.
func (c *Client) VerifyEnrollmentAndActivate(ctx context.Context, sess *ldrrelay.SessionClient) error {
	ar, err := c.Anchor(ctx, sess)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credKeys == nil {
		return errors.New("ldrclient: member activation requires credential keys")
	}
	if ar.Seq == 0 || c.ckSeq < ar.Seq || c.entries[ar.Seq-1].frame.Head != ar.Head {
		return fmt.Errorf("%w: synced checkpoint (%d) did not verify fresh anchor (%d)", ErrViolation, c.ckSeq, ar.Seq)
	}
	myTok := ldrrelay.CredToken(c.credKeys.CredID)
	cr := c.state.Line.Credentials[myTok]
	if cr == nil {
		return fmt.Errorf("%w: credential not enrolled in verified state", ErrEnrollmentCheck)
	}
	if cr.Revoked {
		return fmt.Errorf("%w: credential already revoked", ErrKeyRevoked)
	}
	wantSig, err := ldrrelay.KeyToken(c.credKeys.Signing.Signer.PublicKey())
	if err != nil {
		return err
	}
	wantEnc, err := ldrrelay.KeyToken(c.credKeys.Encryption.PublicKey())
	if err != nil {
		return err
	}
	if cr.SigningKey != wantSig || cr.EncryptionKey != wantEnc {
		return fmt.Errorf("%w: enrolled keys do not match local credential keys", ErrEnrollmentCheck)
	}
	if c.cfg.ExpectedGrant != nil {
		if cr.Namespace != c.cfg.ExpectedGrant.NamespaceID ||
			cr.ActorLimit != int64(c.cfg.ExpectedGrant.ActorLimit) ||
			cr.Reader != c.cfg.ExpectedGrant.Reader {
			return fmt.Errorf("%w: enrolled grant differs from saved P3 join request", ErrEnrollmentCheck)
		}
	}
	if cr.Reader {
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
	c.outbox.Activated = true
	return saveOutbox(c.outboxPath(), c.outbox)
}

// Anchor requests a fresh anchor over sess and syncs verified local state up to it.
// Fails closed if Halted, Suspect, or stopped (G2 / Rule 8).
func (c *Client) Anchor(ctx context.Context, sess *ldrrelay.SessionClient) (ldrrelay.AnchorReply, error) {
	c.mu.Lock()
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

	var next ldrcore.State
	var dec *ldrrelay.DecodedIntent
	var opKey *ldrstore.StoredOpKey

	if fr.Origin == ldrcore.OriginSequencer {
		if fr.OpType != "time_anchor" || len(fr.IntentBytes) != 0 {
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
			if fr.Seq != 1 || dec.SeenSeq != 0 || dec.SeenHead != c.cfg.GenesisAnchor {
				return fmt.Errorf("seq %d line_init not anchored on pinned genesis", fr.Seq)
			}
			if dec.DescriptorDigest == nil || *dec.DescriptorDigest != c.cfg.DescriptorDigest {
				return fmt.Errorf("seq %d line_init descriptor digest mismatch", fr.Seq)
			}
		} else {
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
	if dec != nil {
		owed = c.deriveOwedNoticesLocked(&next, fr, dec)
	}
	c.entries = append(c.entries, verifiedEntry{frame: fr, decoded: dec, touched: touched, owed: owed})
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
		_ = saveOutbox(c.outboxPath(), c.outbox)
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
	changed := false
	for _, tk := range tasks {
		raw, err := c.fetchVerifiedSidecar(ctx, sess, ldrstore.SidecarWrap, tk.commit)
		if err != nil {
			// Failed wrap MUST NOT stop replay (§6.3, §10.2).
			c.mu.Lock()
			c.epochs.BadWraps[tk.epoch] = true
			c.mu.Unlock()
			changed = true
			continue
		}
		epochKey, err := ldrcrypto.UnwrapEpochKey(myEncPriv, raw, tk.wctx)
		if err != nil {
			c.mu.Lock()
			c.epochs.BadWraps[tk.epoch] = true
			c.mu.Unlock()
			changed = true
			continue
		}
		c.mu.Lock()
		c.epochs.Keys[tk.epoch] = epochKey
		delete(c.epochs.BadWraps, tk.epoch)
		c.mu.Unlock()
		changed = true
	}
	if changed {
		c.mu.Lock()
		err := saveEpochs(c.epochsPath(), c.epochs)
		c.mu.Unlock()
		return err
	}
	return nil
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

	if c.outbox.Halted != "" || c.outbox.Suspect {
		return "", ErrFailClosed
	}
	if c.outbox.MustResolve {
		return "", ErrMustResolve
	}
	if !c.outbox.Activated && p.Origin != ldrcore.OriginRoot && p.Origin != ldrcore.OriginOperator {
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

	c.outbox.NextOp++
	opID := fmt.Sprintf("op-%d", c.outbox.NextOp)
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
			c.outbox.NextOp--
			return "", ErrNoEpochKey
		}
		ctxBytes, err := PayloadContextBytes(
			c.profDigest, c.cfg.LineID, gen, p.Origin, prin,
			p.ActorID, bindingGen, opID, p.OpType,
			authEpoch, keyEpoch, c.ckSeq, c.ckHead, p.Expect, p.Fields,
		)
		if err != nil {
			c.outbox.NextOp--
			return "", err
		}
		payloadPkg, err = ldrcrypto.SealPayload(epKey, ctxBytes, p.Plaintext)
		if err != nil {
			c.outbox.NextOp--
			return "", err
		}
		payloadCommit, err = ldrcrypto.CommitPayload(payloadPkg)
		if err != nil {
			c.outbox.NextOp--
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
		c.outbox.NextOp--
		return "", err
	}
	env, err := ldrcrypto.SignIntent(signer, body)
	if err != nil {
		c.outbox.NextOp--
		return "", err
	}
	dig, err := env.Digest()
	if err != nil {
		c.outbox.NextOp--
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
	c.outbox.Entries = append(c.outbox.Entries, entry)
	c.slots[slot] = opID
	if err := saveOutbox(c.outboxPath(), c.outbox); err != nil {
		// Roll back in-memory state on disk failure!
		c.outbox.Entries = c.outbox.Entries[:len(c.outbox.Entries)-1]
		delete(c.slots, slot)
		c.outbox.NextOp--
		return "", err
	}
	return opID, nil
}

// ComposeEpochActivate implements P9: requires this device to be an active
// entitled reader (so epoch key generation happens only on an enrolled reader),
// generates a fresh 32-byte K_epoch, wraps to every entitled reader, signs with
// the attached operator key, and durably persists to outbox.cbor BEFORE sending.
func (c *Client) ComposeEpochActivate(action string) (string, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.outbox.Halted != "" || c.outbox.Suspect {
		return "", nil, ErrFailClosed
	}
	if c.outbox.MustResolve {
		return "", nil, ErrMustResolve
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

	c.outbox.NextOp++
	opID := fmt.Sprintf("op-%d", c.outbox.NextOp)
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
			c.outbox.NextOp--
			return "", nil, err
		}
		wb, err := ldrcrypto.WrapEpochKey(epochKey, wctx)
		if err != nil {
			c.outbox.NextOp--
			return "", nil, err
		}
		wc, err := ldrcrypto.CommitWrap(wb)
		if err != nil {
			c.outbox.NextOp--
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
		c.outbox.NextOp--
		return "", nil, err
	}
	env, err := ldrcrypto.SignIntent(c.operatorKey.Signer, body)
	if err != nil {
		c.outbox.NextOp--
		return "", nil, err
	}
	dig, err := env.Digest()
	if err != nil {
		c.outbox.NextOp--
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
	c.outbox.Entries = append(c.outbox.Entries, entry)
	c.slots[slot] = opID
	if err := saveOutbox(c.outboxPath(), c.outbox); err != nil {
		c.outbox.Entries = c.outbox.Entries[:len(c.outbox.Entries)-1]
		delete(c.slots, slot)
		c.outbox.NextOp--
		return "", nil, err
	}
	return opID, epochKey, nil
}

// Send transmits the exact persisted bytes of opID over sess, settles the outbox
// entry per §5.7, and persists the result durably. Never re-signs or alters bytes!
func (c *Client) Send(ctx context.Context, sess *ldrrelay.SessionClient, opID string) (ldrrelay.SubmitReply, error) {
	c.mu.Lock()
	e := c.findOutboxLocked(opID)
	if e == nil {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, fmt.Errorf("ldrclient: unknown outbox op %q", opID)
	}
	if e.Status != ldrcore.OutPending {
		rep := ldrrelay.SubmitReply{
			Class: e.LastClass, Code: e.LastCode,
			Outcome: ldrstore.StoredOutcome{Kind: e.OutcomeKind, Reason: e.OutcomeReason, Seq: e.OutcomeSeq},
		}
		c.mu.Unlock()
		return rep, nil
	}
	if c.signsNoMoreLocked(e.SignerToken) {
		e.Status = ldrcore.OutReconcile
		_ = saveOutbox(c.outboxPath(), c.outbox)
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, ErrKeyRevoked
	}
	e.Sends++
	if err := saveOutbox(c.outboxPath(), c.outbox); err != nil {
		c.mu.Unlock()
		return ldrrelay.SubmitReply{}, err
	}
	intentBytes := bytes.Clone(e.IntentBytes)
	payloadSidecar := bytes.Clone(e.PayloadSidecar)
	wrapSidecars := make(map[[32]byte][]byte, len(e.WrapSidecars))
	for k, v := range e.WrapSidecars {
		wrapSidecars[k] = bytes.Clone(v)
	}
	c.mu.Unlock()

	rep, err := sess.Submit(ctx, intentBytes, payloadSidecar, wrapSidecars)
	if err != nil {
		return ldrrelay.SubmitReply{}, err
	}

	c.mu.Lock()
	c.settleLocked(e, rep)
	saveErr := saveOutbox(c.outboxPath(), c.outbox)
	c.mu.Unlock()
	if saveErr != nil {
		return rep, saveErr
	}
	return rep, nil
}

// ResolveAll queries every unsettled outbox intent signed by active keys over sess
// without re-sending bytes (§5.7 rules 3 & 5, G1 fix, Rule 8).
func (c *Client) ResolveAll(ctx context.Context, sess *ldrrelay.SessionClient, sessPrincipal ldrcrypto.Principal) error {
	sessTok, err := ldrrelay.PrincipalToken(sessPrincipal)
	if err != nil {
		return err
	}
	c.mu.Lock()
	var todo []*OutboxEntry
	for _, e := range c.outbox.Entries {
		if e.Status != ldrcore.OutPending && e.Status != ldrcore.OutReconcile {
			continue
		}
		if c.signsNoMoreLocked(e.SignerToken) {
			continue
		}
		// Only query operations this session principal is authorized to query.
		isReconciler := sessPrincipal.Kind == ldrcrypto.PrincipalRoot || sessPrincipal.Kind == ldrcrypto.PrincipalOperator
		if e.SignerToken != sessTok && !isReconciler {
			continue
		}
		todo = append(todo, e)
	}
	c.mu.Unlock()

	incomplete := false
	for _, e := range todo {
		c.mu.Lock()
		if c.signsNoMoreLocked(e.SignerToken) {
			c.mu.Unlock()
			continue
		}
		key := ldrstore.StoredOpKey{Generation: e.Gen, Signer: e.SignerToken, SeenSeq: e.SeenSeq, OpID: e.OpID}
		dig := e.IntentDigest
		c.mu.Unlock()

		rep, err := sess.Query(ctx, key, dig)
		if err != nil {
			incomplete = true
			continue
		}
		c.mu.Lock()
		if rep.Class == ldrcore.ClassAdmission {
			incomplete = true
			if e.Status == ldrcore.OutReconcile {
				c.mu.Unlock()
				continue
			}
		} else if e.Status == ldrcore.OutReconcile && rep.Class == ldrcore.ClassUnknown {
			c.mu.Unlock()
			continue
		}
		c.settleLocked(e, rep)
		c.mu.Unlock()
	}

	c.mu.Lock()
	if !incomplete {
		c.outbox.MustResolve = false
	}
	err = saveOutbox(c.outboxPath(), c.outbox)
	c.mu.Unlock()
	return err
}

func (c *Client) settleLocked(e *OutboxEntry, rep ldrrelay.SubmitReply) {
	e.LastClass = rep.Class
	e.LastCode = rep.Code
	e.OutcomeKind = rep.Outcome.Kind
	e.OutcomeReason = rep.Outcome.Reason
	e.OutcomeSeq = rep.Outcome.Seq

	switch rep.Class {
	case ldrcore.ClassOutcome:
		e.Status = ldrcore.OutDone
		delete(c.slots, e.Slot)
	case ldrcore.ClassRefusal:
		e.Status = ldrcore.OutClosed
		delete(c.slots, e.Slot)
		if rep.Code == "expired" || rep.Code == "unknown_anchor" {
			c.outbox.MustResolve = c.unsettledCountLocked() > 0
		}
	case ldrcore.ClassUnresolved:
		e.Status = ldrcore.OutReconcile
		if rep.Code == "history_unavailable" {
			c.outbox.Suspect = true
		} else if rep.Code == "revoked" {
			c.recordToldRevokedLocked(e.SignerToken, rep.Code)
		}
	case ldrcore.ClassMismatch:
		e.Status = ldrcore.OutReconcile
	case ldrcore.ClassAdmission:
		if !transientAdmission[rep.Code] {
			e.Status = ldrcore.OutReconcile
		}
	}
}

func (c *Client) findOutboxLocked(opID string) *OutboxEntry {
	for _, e := range c.outbox.Entries {
		if e.OpID == opID {
			return e
		}
	}
	return nil
}

func (c *Client) unsettledCountLocked() int {
	n := 0
	for _, e := range c.outbox.Entries {
		if e.Status == ldrcore.OutPending || e.Status == ldrcore.OutReconcile {
			n++
		}
	}
	return n
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

func (c *Client) signsNoMoreLocked(p string) bool {
	return c.outbox.KeyStops[p] != nil || c.revokedInRecordsLocked(p)
}

func (c *Client) recordToldRevokedLocked(p, code string) {
	if c.outbox.KeyStops[p] == nil {
		c.outbox.KeyStops[p] = &KeyStop{Key: p, Told: true, Seq: c.ckSeq, Head: c.ckHead, Code: code}
	}
	c.suspendSignerLocked(p)
}

func (c *Client) suspendSignerLocked(p string) bool {
	changed := false
	for _, e := range c.outbox.Entries {
		if e.Status == ldrcore.OutPending && e.SignerToken == p {
			e.Status = ldrcore.OutReconcile
			changed = true
		}
	}
	return changed
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
