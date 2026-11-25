package ldrclient

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

// Client directory roles distinguish pre-existing administrative directories
// from joining/enrolled member credential directories requiring complete P3
// ceremony evidence and O25 activation.
const (
	DirKindAdmin  = "admin"
	DirKindMember = "member"
)

func p256Curve() elliptic.Curve { return elliptic.P256() }

const (
	// configSchemaVersion 2 introduces required dir_kind ("admin"|"member") and
	// optional expected_join_req_digest for P3 ceremony verification. Pre-release
	// v1 config.cbor files fail closed explicitly rather than inferring authority
	// from an old Activated flag.
	configSchemaVersion = uint64(2)

	clientWALMagic   = "LDCW"
	clientWALVersion = byte(1)
	clientWALHdrSize = 10 // 4B magic + 1B ver + 1B flags + 4B len
	clientWALCRCSize = 4
	clientWALMaxBody = 1024 * 1024
)

var clientCRCTable = crc32.MakeTable(crc32.Castagnoli)

// OutboxEntry is a durably persisted intent stored strictly BEFORE first send.
type OutboxEntry struct {
	OpID           string
	Action         string
	Slot           string
	Gen            uint64
	SignerToken    string
	Principal      ldrcrypto.Principal
	SeenSeq        uint64
	SeenHead       [32]byte
	OpType         string
	IntentBytes    []byte
	IntentDigest   [32]byte
	PayloadSidecar []byte
	WrapSidecars   map[[32]byte][]byte
	Status         string // pending | done | closed | reconciliation_required
	NeedsResolve   bool   // §5.7 rule 3: must be asked about before clearing MustResolve
	Sends          uint64
	LastClass      string
	LastCode       string
	OutcomeKind    string
	OutcomeReason  string
	OutcomeSeq     uint64
}

// KeyStop is a persistent Rule 8 record of a stopped/revoked local key.
type KeyStop struct {
	Key      string
	Told     bool
	Verified bool
	Seq      uint64
	Head     [32]byte
	Code     string
}

type persistedOutbox struct {
	NextOp       uint64
	ResolveEpoch uint64
	MustResolve  bool
	Suspect      bool
	Halted       string
	Activated    bool
	KeyStops     map[string]*KeyStop
	Entries      []*OutboxEntry
}

// LocalNotice is a delivery notice derived from verified log records (§11.3).
type LocalNotice struct {
	ID         string
	Gen        uint64
	Seq        uint64
	Actor      string
	BindingGen uint64
	Kind       string
	Target     string
	Acked      bool
}

type persistedCursors struct {
	ProjectedSeq uint64
	ScannedSeq   uint64
	Rebuilds     uint64
	Notices      map[string]*LocalNotice
}

type persistedConfig struct {
	DirKind               string // DirKindAdmin or DirKindMember
	SignedDescriptor      []byte
	LineID                []byte
	DescriptorDigest      [32]byte
	GenesisAnchor         [32]byte
	ExpectedCredID        *[32]byte
	ExpectedGrant         *ldrcrypto.JoinGrant
	ExpectedJoinReqID     []byte
	ExpectedJoinReqDigest *[32]byte
}

type persistedEpochs struct {
	Keys     map[uint64][]byte
	BadWraps map[uint64]bool
}

func (c *Client) configPath() string         { return filepath.Join(c.dir, "config.cbor") }
func (c *Client) walPath() string            { return filepath.Join(c.dir, "verified.wal") }
func (c *Client) outboxPath() string         { return filepath.Join(c.dir, "outbox.cbor") }
func (c *Client) epochsPath() string         { return filepath.Join(c.dir, "epochs.cbor") }
func (c *Client) cursorsPath() string        { return filepath.Join(c.dir, "cursors.cbor") }
func (c *Client) projDir() string            { return filepath.Join(c.dir, "projection") }
func (c *Client) sidecarsDir() string        { return filepath.Join(c.dir, "sidecars") }
func (c *Client) credKeyPath() string        { return filepath.Join(c.dir, "cred.key") }
func (c *Client) adminReaderReqPath() string { return filepath.Join(c.dir, "admin-reader.req.cbor") }

func createFileExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return err
		}
	}
	if err := ldrstore.SyncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return ldrstore.SyncDir(filepath.Dir(path))
}

func checkExistingPublishTarget(path string, data []byte, allowIdentical bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !allowIdentical || !fi.Mode().IsRegular() || fi.Size() != int64(len(data)) {
		return fmt.Errorf("%w: %s", ErrOutputExists, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %s (%v)", ErrOutputExists, path, err)
	}
	defer f.Close()
	fstat, err := f.Stat()
	if err != nil || !fstat.Mode().IsRegular() || !os.SameFile(fi, fstat) {
		return fmt.Errorf("%w: %s", ErrOutputExists, path)
	}
	existing, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil || !bytes.Equal(existing, data) {
		return fmt.Errorf("%w: %s", ErrOutputExists, path)
	}
	return nil
}

// publishFileNoClobber atomically publishes data to path without replacing any
// existing destination (regular file, symlink, directory, or special file).
// When allowIdentical is true and path is already a regular file with the exact
// same bytes, publishFileNoClobber returns nil without modifying path; any other
// existing destination fails with ErrOutputExists.
func publishFileNoClobber(path string, data []byte, perm os.FileMode, allowIdentical bool) error {
	if path == "" {
		return errors.New("ldrclient: empty output path")
	}
	if err := checkExistingPublishTarget(path, data, allowIdentical); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".tmp-%s-%s", filepath.Base(path), hex.EncodeToString(rnd[:])))
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}
	if len(data) > 0 {
		if _, err := f.Write(data); err != nil {
			cleanup()
			return err
		}
	}
	if err := ldrstore.SyncFile(f); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	linkErr := os.Link(tmpPath, path)
	_ = os.Remove(tmpPath)
	if linkErr == nil {
		return ldrstore.SyncDir(dir)
	}
	if os.IsExist(linkErr) {
		if err := checkExistingPublishTarget(path, data, allowIdentical); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		return fmt.Errorf("%w: %s", ErrOutputExists, path)
	}
	if errors.Is(linkErr, syscall.ENOTSUP) || errors.Is(linkErr, syscall.EPERM) || errors.Is(linkErr, syscall.ENOSYS) {
		if err := createFileExclusive(path, data, perm); err != nil {
			if os.IsExist(err) {
				if cerr := checkExistingPublishTarget(path, data, allowIdentical); cerr == nil {
					return nil
				} else if !os.IsNotExist(cerr) {
					return cerr
				}
				return fmt.Errorf("%w: %s", ErrOutputExists, path)
			}
			return err
		}
		return nil
	}
	return linkErr
}

func (c *Client) sidecarCachePath(kind string, digest [32]byte) string {
	return filepath.Join(c.sidecarsDir(), kind+"-"+hex.EncodeToString(digest[:]))
}

func marshalConfig(cfg persistedConfig) ([]byte, error) {
	m := ldrcrypto.Map{
		{Key: "cd", Value: cfg.DescriptorDigest[:]},
		{Key: "descriptor", Value: cfg.SignedDescriptor},
		{Key: "dir_kind", Value: cfg.DirKind},
		{Key: "genesis", Value: cfg.GenesisAnchor[:]},
		{Key: "line_id", Value: cfg.LineID},
		{Key: "v", Value: configSchemaVersion},
	}
	if cfg.ExpectedCredID != nil {
		m = append(m, ldrcrypto.MapEntry{Key: "expected_cred_id", Value: cfg.ExpectedCredID[:]})
	}
	if cfg.ExpectedGrant != nil {
		caps := append([]string(nil), cfg.ExpectedGrant.Capabilities...)
		if caps == nil {
			caps = []string{}
		}
		m = append(m, ldrcrypto.MapEntry{
			Key: "expected_grant",
			Value: ldrcrypto.Map{
				{Key: "actor_limit", Value: cfg.ExpectedGrant.ActorLimit},
				{Key: "capabilities", Value: caps},
				{Key: "namespace_id", Value: cfg.ExpectedGrant.NamespaceID},
				{Key: "reader", Value: cfg.ExpectedGrant.Reader},
			},
		})
	}
	if len(cfg.ExpectedJoinReqID) > 0 {
		m = append(m, ldrcrypto.MapEntry{Key: "expected_join_req_id", Value: cfg.ExpectedJoinReqID})
	}
	if cfg.ExpectedJoinReqDigest != nil {
		m = append(m, ldrcrypto.MapEntry{Key: "expected_join_req_digest", Value: cfg.ExpectedJoinReqDigest[:]})
	}
	return ldrcrypto.MarshalCBOR(m)
}

func saveConfig(path string, cfg persistedConfig) error {
	raw, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func saveConfigCreateOnly(path string, cfg persistedConfig) error {
	raw, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	if err := createFileExclusive(path, raw, 0o600); err != nil {
		if os.IsExist(err) {
			return ErrDirInitialized
		}
		return err
	}
	return nil
}

func loadConfig(path string) (persistedConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return persistedConfig{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return persistedConfig{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return persistedConfig{}, errors.New("ldrclient: invalid config.cbor")
	}
	ver, err := ldrcrypto.MapUint(m, "v")
	if err != nil {
		return persistedConfig{}, fmt.Errorf("ldrclient: config.cbor missing version: %w", err)
	}
	if ver == 1 {
		return persistedConfig{}, errors.New("ldrclient: unsupported legacy config.cbor v1 (pre-release format break: v2 requires explicit dir_kind and P3 join_request_digest; initialize a NEW client directory and preserve existing keys and outbox from this directory)")
	}
	if ver != configSchemaVersion {
		return persistedConfig{}, fmt.Errorf("ldrclient: unsupported config.cbor version %d (want %d)", ver, configSchemaVersion)
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"cd", "descriptor", "dir_kind", "genesis", "line_id", "v"},
		"expected_cred_id", "expected_grant", "expected_join_req_digest", "expected_join_req_id"); err != nil {
		return persistedConfig{}, err
	}
	var cfg persistedConfig
	var err2 error
	if cfg.DirKind, err2 = ldrcrypto.MapString(m, "dir_kind"); err2 != nil {
		return persistedConfig{}, err2
	}
	if cfg.DirKind != DirKindAdmin && cfg.DirKind != DirKindMember {
		return persistedConfig{}, fmt.Errorf("ldrclient: invalid dir_kind %q", cfg.DirKind)
	}
	if cfg.SignedDescriptor, err2 = ldrcrypto.MapBytes(m, "descriptor"); err2 != nil {
		return persistedConfig{}, err2
	}
	if cfg.LineID, err2 = ldrcrypto.MapBytes(m, "line_id"); err2 != nil {
		return persistedConfig{}, err2
	}
	cdB, err := ldrcrypto.MapBytesLen(m, "cd", 32)
	if err != nil {
		return persistedConfig{}, err
	}
	genB, err := ldrcrypto.MapBytesLen(m, "genesis", 32)
	if err != nil {
		return persistedConfig{}, err
	}
	copy(cfg.DescriptorDigest[:], cdB)
	copy(cfg.GenesisAnchor[:], genB)
	if _, has := m["expected_cred_id"]; has {
		cb, err := ldrcrypto.MapBytesLen(m, "expected_cred_id", 32)
		if err != nil {
			return persistedConfig{}, err
		}
		var id [32]byte
		copy(id[:], cb)
		cfg.ExpectedCredID = &id
	}
	if _, has := m["expected_grant"]; has {
		gm, err := ldrcrypto.MapSubmap(m, "expected_grant")
		if err != nil {
			return persistedConfig{}, err
		}
		ns, err1 := ldrcrypto.MapString(gm, "namespace_id")
		al, err2 := ldrcrypto.MapUint(gm, "actor_limit")
		rd, err3 := ldrcrypto.MapBool(gm, "reader")
		ca, err4 := ldrcrypto.MapArray(gm, "capabilities")
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return persistedConfig{}, errors.New("ldrclient: malformed expected_grant")
		}
		caps := make([]string, len(ca))
		for i, x := range ca {
			s, ok := x.(string)
			if !ok {
				return persistedConfig{}, errors.New("ldrclient: malformed expected_grant capabilities")
			}
			caps[i] = s
		}
		cfg.ExpectedGrant = &ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: al, Reader: rd, Capabilities: caps}
	}
	if _, has := m["expected_join_req_id"]; has {
		if cfg.ExpectedJoinReqID, err = ldrcrypto.MapBytes(m, "expected_join_req_id"); err != nil {
			return persistedConfig{}, err
		}
	}
	if _, has := m["expected_join_req_digest"]; has {
		db, err := ldrcrypto.MapBytesLen(m, "expected_join_req_digest", 32)
		if err != nil {
			return persistedConfig{}, err
		}
		var d [32]byte
		copy(d[:], db)
		cfg.ExpectedJoinReqDigest = &d
	}
	return cfg, nil
}

func appendVerifiedFrameWAL(path string, fr ldrrelay.ControlFrameWire) error {
	ib := fr.IntentBytes
	if ib == nil {
		ib = []byte{}
	}
	fm := ldrcrypto.Map{
		{Key: "gen", Value: fr.Gen},
		{Key: "head", Value: fr.Head[:]},
		{Key: "intent", Value: ib},
		{Key: "op_type", Value: fr.OpType},
		{Key: "origin", Value: fr.Origin},
		{Key: "prev_head", Value: fr.PrevHead[:]},
		{Key: "seq", Value: fr.Seq},
		{Key: "seq_time", Value: fr.SeqTime},
		{Key: "v", Value: uint64(1)},
	}
	if fr.PayloadCommit != nil {
		fm = append(fm, ldrcrypto.MapEntry{Key: "payload_commit", Value: fr.PayloadCommit.ToCBORMap()})
	}
	if len(fr.WrapCommits) > 0 {
		wArr := make([]any, len(fr.WrapCommits))
		for i, wm := range fr.WrapCommits {
			wArr[i] = ldrcrypto.Map{
				{Key: "commit", Value: wm.Commit.ToCBORMap()},
				{Key: "cred_id", Value: bytes.Clone(wm.CredID[:])},
			}
		}
		fm = append(fm, ldrcrypto.MapEntry{Key: "wraps", Value: wArr})
	}
	body, err := ldrcrypto.MarshalCBORWithLimits(fm, ldrcrypto.Limits{MaxBytes: clientWALMaxBody, MaxDepth: 16, MaxItems: 8192})
	if err != nil {
		return err
	}
	buf := make([]byte, clientWALHdrSize+len(body)+clientWALCRCSize)
	copy(buf[0:4], clientWALMagic)
	buf[4] = clientWALVersion
	buf[5] = 0
	binary.BigEndian.PutUint32(buf[6:10], uint32(len(body)))
	copy(buf[10:10+len(body)], body)
	crc := crc32.Checksum(buf[:10+len(body)], clientCRCTable)
	binary.BigEndian.PutUint32(buf[10+len(body):], crc)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		return err
	}
	if err := ldrstore.SyncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// initEmptyVerifiedWAL durably creates verified.wal strictly create-only
// (O_CREATE|O_EXCL) during InitClientDir so an existing WAL is never opened or
// reused silently during initialization, and a missing verified.wal on later
// open or reconciliation is unambiguously a lost WAL.
func initEmptyVerifiedWAL(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return ErrDirInitialized
		}
		return err
	}
	if err := ldrstore.SyncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return ldrstore.SyncDir(filepath.Dir(path))
}

func loadVerifiedWAL(path string, syncFile func(*os.File) error, syncDir func(string) error) ([]ldrrelay.ControlFrameWire, error) {
	if syncFile == nil {
		syncFile = ldrstore.SyncFile
	}
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	wf, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: missing verified.wal", ldrstore.ErrCorruptWAL)
		}
		return nil, err
	}
	data, err := io.ReadAll(wf)
	if err != nil {
		_ = wf.Close()
		return nil, err
	}
	var out []ldrrelay.ControlFrameWire
	off := 0
	for off < len(data) {
		rem := len(data) - off
		if rem < clientWALHdrSize {
			// Truncated tail at EOF: safely truncate.
			if err := wf.Truncate(int64(off)); err != nil {
				_ = wf.Close()
				return nil, err
			}
			break
		}
		hdr := data[off : off+clientWALHdrSize]
		if string(hdr[0:4]) != clientWALMagic || hdr[4] != clientWALVersion || hdr[5] != 0 {
			_ = wf.Close()
			return nil, fmt.Errorf("ldrclient: corrupt verified.wal header at offset %d", off)
		}
		bodyLen := int(binary.BigEndian.Uint32(hdr[6:10]))
		if bodyLen == 0 || bodyLen > clientWALMaxBody {
			_ = wf.Close()
			return nil, fmt.Errorf("ldrclient: invalid verified.wal body length %d", bodyLen)
		}
		frameLen := clientWALHdrSize + bodyLen + clientWALCRCSize
		if off+frameLen > len(data) {
			if err := wf.Truncate(int64(off)); err != nil {
				_ = wf.Close()
				return nil, err
			}
			break
		}
		fb := data[off : off+frameLen]
		wantCRC := binary.BigEndian.Uint32(fb[clientWALHdrSize+bodyLen:])
		if crc32.Checksum(fb[:clientWALHdrSize+bodyLen], clientCRCTable) != wantCRC {
			_ = wf.Close()
			return nil, fmt.Errorf("ldrclient: verified.wal CRC32C mismatch at offset %d", off)
		}
		dec, err := ldrcrypto.UnmarshalCBOR(fb[clientWALHdrSize:clientWALHdrSize+bodyLen], ldrcrypto.Limits{MaxBytes: clientWALMaxBody, MaxDepth: 16, MaxItems: 8192})
		if err != nil {
			_ = wf.Close()
			return nil, err
		}
		m, ok := dec.(map[string]any)
		if !ok {
			_ = wf.Close()
			return nil, errors.New("ldrclient: invalid verified.wal frame body")
		}
		if err := ldrcrypto.RequireExactKeys(m,
			[]string{"gen", "head", "intent", "op_type", "origin", "prev_head", "seq", "seq_time", "v"},
			"payload_commit", "wraps"); err != nil {
			_ = wf.Close()
			return nil, fmt.Errorf("ldrclient: invalid verified.wal frame keys: %w", err)
		}
		var fr ldrrelay.ControlFrameWire
		if fr.Gen, err = ldrcrypto.MapUint(m, "gen"); err != nil {
			_ = wf.Close()
			return nil, err
		}
		if fr.Seq, err = ldrcrypto.MapUint(m, "seq"); err != nil {
			_ = wf.Close()
			return nil, err
		}
		if fr.SeqTime, err = ldrcrypto.MapUint(m, "seq_time"); err != nil {
			_ = wf.Close()
			return nil, err
		}
		if fr.Origin, err = ldrcrypto.MapString(m, "origin"); err != nil {
			_ = wf.Close()
			return nil, err
		}
		if fr.OpType, err = ldrcrypto.MapString(m, "op_type"); err != nil {
			_ = wf.Close()
			return nil, err
		}
		if fr.IntentBytes, err = ldrcrypto.MapBytes(m, "intent"); err != nil {
			_ = wf.Close()
			return nil, err
		}
		ph, err1 := ldrcrypto.MapBytesLen(m, "prev_head", 32)
		hd, err2 := ldrcrypto.MapBytesLen(m, "head", 32)
		if err1 != nil || err2 != nil {
			_ = wf.Close()
			return nil, errors.New("ldrclient: invalid verified.wal head bytes")
		}
		copy(fr.PrevHead[:], ph)
		copy(fr.Head[:], hd)
		if pcRaw, has := m["payload_commit"]; has {
			c, err := ldrcrypto.ParseCommitment(pcRaw)
			if err != nil {
				_ = wf.Close()
				return nil, err
			}
			fr.PayloadCommit = &c
		}
		if _, has := m["wraps"]; has {
			wArr, err := ldrcrypto.MapArray(m, "wraps")
			if err != nil {
				_ = wf.Close()
				return nil, err
			}
			fr.WrapCommits = make([]ldrcrypto.WrapManifestEntry, 0, len(wArr))
			for _, we := range wArr {
				wm, ok := we.(map[string]any)
				if !ok {
					_ = wf.Close()
					return nil, errors.New("ldrclient: invalid verified.wal wrap entry")
				}
				if err := ldrcrypto.RequireExactKeys(wm, []string{"commit", "cred_id"}); err != nil {
					_ = wf.Close()
					return nil, err
				}
				cidB, err := ldrcrypto.MapBytesLen(wm, "cred_id", 32)
				if err != nil {
					_ = wf.Close()
					return nil, err
				}
				cm, err := ldrcrypto.ParseCommitment(wm["commit"])
				if err != nil {
					_ = wf.Close()
					return nil, err
				}
				var cid [32]byte
				copy(cid[:], cidB)
				fr.WrapCommits = append(fr.WrapCommits, ldrcrypto.WrapManifestEntry{CredID: cid, Commit: cm})
			}
		}
		out = append(out, fr)
		off += frameLen
	}
	if err := syncFile(wf); err != nil {
		_ = wf.Close()
		return nil, fmt.Errorf("%w: verified.wal barrier sync: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := wf.Close(); err != nil {
		return nil, fmt.Errorf("%w: verified.wal close: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%w: verified.wal dir barrier sync: %v", ldrstore.ErrUncertainWrite, err)
	}
	return out, nil
}

// atomicWriteFileWithHooks distinguishes clean pre-rename failures (ErrPreWrite)
// from ambiguous post-rename directory sync failures (ErrUncertainWrite).
func atomicWriteFileWithHooks(path string, data []byte, perm os.FileMode, syncFile func(*os.File) error, syncDir func(string) error) error {
	if syncFile == nil {
		syncFile = ldrstore.SyncFile
	}
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".tmp-%s-%s", filepath.Base(path), hex.EncodeToString(rnd[:])))
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	if err := syncFile(f); err != nil {
		cleanup()
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: post-rename dir sync: %v", ldrstore.ErrUncertainWrite, err)
	}
	return nil
}

func syncOutboxBarrier(path string, syncFile func(*os.File) error, syncDir func(string) error) error {
	if syncFile == nil {
		syncFile = ldrstore.SyncFile
	}
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: open outbox for barrier: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: outbox file barrier sync: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: outbox file close: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%w: outbox dir barrier sync: %v", ldrstore.ErrUncertainWrite, err)
	}
	return nil
}

func saveOutbox(path string, ob persistedOutbox) error {
	return saveOutboxWithHooks(path, ob, nil, nil)
}

func saveOutboxCreateOnly(path string, ob persistedOutbox) error {
	raw, err := marshalOutbox(ob)
	if err != nil {
		return err
	}
	if err := createFileExclusive(path, raw, 0o600); err != nil {
		if os.IsExist(err) {
			return ErrDirInitialized
		}
		return err
	}
	return nil
}

func saveOutboxWithHooks(path string, ob persistedOutbox, syncFile func(*os.File) error, syncDir func(string) error) error {
	raw, err := marshalOutbox(ob)
	if err != nil {
		return err
	}
	return atomicWriteFileWithHooks(path, raw, 0o600, syncFile, syncDir)
}

func marshalOutbox(ob persistedOutbox) ([]byte, error) {
	stops := make([]any, 0, len(ob.KeyStops))
	stopKeys := make([]string, 0, len(ob.KeyStops))
	for k := range ob.KeyStops {
		stopKeys = append(stopKeys, k)
	}
	sort.Strings(stopKeys)
	for _, k := range stopKeys {
		ks := ob.KeyStops[k]
		stops = append(stops, ldrcrypto.Map{
			{Key: "code", Value: ks.Code},
			{Key: "head", Value: ks.Head[:]},
			{Key: "key", Value: ks.Key},
			{Key: "seq", Value: ks.Seq},
			{Key: "told", Value: ks.Told},
			{Key: "verified", Value: ks.Verified},
		})
	}
	entries := make([]any, 0, len(ob.Entries))
	for _, e := range ob.Entries {
		pCBOR, err := e.Principal.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
		}
		ps := e.PayloadSidecar
		if ps == nil {
			ps = []byte{}
		}
		wsArr := make([]any, 0, len(e.WrapSidecars))
		wIDs := make([][32]byte, 0, len(e.WrapSidecars))
		for id := range e.WrapSidecars {
			wIDs = append(wIDs, id)
		}
		sort.Slice(wIDs, func(i, j int) bool { return string(wIDs[i][:]) < string(wIDs[j][:]) })
		for _, id := range wIDs {
			wsArr = append(wsArr, ldrcrypto.Map{
				{Key: "cred_id", Value: append([]byte(nil), id[:]...)},
				{Key: "data", Value: e.WrapSidecars[id]},
			})
		}
		entries = append(entries, ldrcrypto.Map{
			{Key: "action", Value: e.Action},
			{Key: "gen", Value: e.Gen},
			{Key: "intent", Value: e.IntentBytes},
			{Key: "intent_digest", Value: e.IntentDigest[:]},
			{Key: "last_class", Value: e.LastClass},
			{Key: "last_code", Value: e.LastCode},
			{Key: "needs_resolve", Value: e.NeedsResolve},
			{Key: "op_id", Value: e.OpID},
			{Key: "op_type", Value: e.OpType},
			{Key: "outcome_kind", Value: e.OutcomeKind},
			{Key: "outcome_reason", Value: e.OutcomeReason},
			{Key: "outcome_seq", Value: e.OutcomeSeq},
			{Key: "payload", Value: ps},
			{Key: "principal", Value: pCBOR},
			{Key: "seen_head", Value: e.SeenHead[:]},
			{Key: "seen_seq", Value: e.SeenSeq},
			{Key: "sends", Value: e.Sends},
			{Key: "signer", Value: e.SignerToken},
			{Key: "slot", Value: e.Slot},
			{Key: "status", Value: e.Status},
			{Key: "wraps", Value: wsArr},
		})
	}
	raw, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "activated", Value: ob.Activated},
		{Key: "entries", Value: entries},
		{Key: "halted", Value: ob.Halted},
		{Key: "key_stops", Value: stops},
		{Key: "must_resolve", Value: ob.MustResolve},
		{Key: "next_op", Value: ob.NextOp},
		{Key: "resolve_epoch", Value: ob.ResolveEpoch},
		{Key: "suspect", Value: ob.Suspect},
		{Key: "v", Value: uint64(1)},
	}, ldrcrypto.Limits{MaxBytes: 4 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	return raw, nil
}

func loadOutbox(path string) (persistedOutbox, error) {
	ob := persistedOutbox{KeyStops: make(map[string]*KeyStop)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ob, nil
		}
		return ob, err
	}
	dec, err := ldrcrypto.UnmarshalCBOR(raw, ldrcrypto.Limits{MaxBytes: 4 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return ob, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ob, errors.New("ldrclient: invalid outbox.cbor")
	}
	ob.Activated, _ = ldrcrypto.MapBool(m, "activated")
	ob.Halted, _ = ldrcrypto.MapString(m, "halted")
	ob.MustResolve, _ = ldrcrypto.MapBool(m, "must_resolve")
	ob.NextOp, _ = ldrcrypto.MapUint(m, "next_op")
	ob.ResolveEpoch, _ = ldrcrypto.MapUint(m, "resolve_epoch")
	ob.Suspect, _ = ldrcrypto.MapBool(m, "suspect")

	if ksArr, err := ldrcrypto.MapArray(m, "key_stops"); err == nil {
		for _, elem := range ksArr {
			km, ok := elem.(map[string]any)
			if !ok {
				return ob, errors.New("ldrclient: invalid key_stop")
			}
			ks := &KeyStop{}
			ks.Key, _ = ldrcrypto.MapString(km, "key")
			ks.Code, _ = ldrcrypto.MapString(km, "code")
			ks.Seq, _ = ldrcrypto.MapUint(km, "seq")
			ks.Told, _ = ldrcrypto.MapBool(km, "told")
			ks.Verified, _ = ldrcrypto.MapBool(km, "verified")
			if hb, err := ldrcrypto.MapBytesLen(km, "head", 32); err == nil {
				copy(ks.Head[:], hb)
			}
			ob.KeyStops[ks.Key] = ks
		}
	}
	if entArr, err := ldrcrypto.MapArray(m, "entries"); err == nil {
		for _, elem := range entArr {
			em, ok := elem.(map[string]any)
			if !ok {
				return ob, errors.New("ldrclient: invalid outbox entry")
			}
			prin, err := ldrcrypto.ParsePrincipal(em["principal"])
			if err != nil {
				return ob, err
			}
			e := &OutboxEntry{Principal: prin, WrapSidecars: make(map[[32]byte][]byte)}
			e.OpID, _ = ldrcrypto.MapString(em, "op_id")
			e.Action, _ = ldrcrypto.MapString(em, "action")
			e.Slot, _ = ldrcrypto.MapString(em, "slot")
			e.Gen, _ = ldrcrypto.MapUint(em, "gen")
			e.SignerToken, _ = ldrcrypto.MapString(em, "signer")
			e.SeenSeq, _ = ldrcrypto.MapUint(em, "seen_seq")
			e.OpType, _ = ldrcrypto.MapString(em, "op_type")
			e.IntentBytes, _ = ldrcrypto.MapBytes(em, "intent")
			e.PayloadSidecar, _ = ldrcrypto.MapBytes(em, "payload")
			e.Status, _ = ldrcrypto.MapString(em, "status")
			e.NeedsResolve, _ = ldrcrypto.MapBool(em, "needs_resolve")
			e.Sends, _ = ldrcrypto.MapUint(em, "sends")
			e.LastClass, _ = ldrcrypto.MapString(em, "last_class")
			e.LastCode, _ = ldrcrypto.MapString(em, "last_code")
			e.OutcomeKind, _ = ldrcrypto.MapString(em, "outcome_kind")
			e.OutcomeReason, _ = ldrcrypto.MapString(em, "outcome_reason")
			e.OutcomeSeq, _ = ldrcrypto.MapUint(em, "outcome_seq")
			if sh, err := ldrcrypto.MapBytesLen(em, "seen_head", 32); err == nil {
				copy(e.SeenHead[:], sh)
			}
			if idg, err := ldrcrypto.MapBytesLen(em, "intent_digest", 32); err == nil {
				copy(e.IntentDigest[:], idg)
			}
			if wArr, err := ldrcrypto.MapArray(em, "wraps"); err == nil {
				for _, we := range wArr {
					wm, ok := we.(map[string]any)
					if !ok {
						continue
					}
					cidB, err1 := ldrcrypto.MapBytesLen(wm, "cred_id", 32)
					wb, err2 := ldrcrypto.MapBytes(wm, "data")
					if err1 == nil && err2 == nil {
						var cid [32]byte
						copy(cid[:], cidB)
						e.WrapSidecars[cid] = wb
					}
				}
			}
			ob.Entries = append(ob.Entries, e)
		}
	}
	return ob, nil
}

func saveEpochs(path string, ep persistedEpochs) error {
	keysArr := make([]any, 0, len(ep.Keys))
	ids := make([]uint64, 0, len(ep.Keys))
	for id := range ep.Keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		keysArr = append(keysArr, ldrcrypto.Map{
			{Key: "epoch", Value: id},
			{Key: "key", Value: ep.Keys[id]},
		})
	}
	badArr := make([]any, 0, len(ep.BadWraps))
	bIDs := make([]uint64, 0, len(ep.BadWraps))
	for id, bad := range ep.BadWraps {
		if bad {
			bIDs = append(bIDs, id)
		}
	}
	sort.Slice(bIDs, func(i, j int) bool { return bIDs[i] < bIDs[j] })
	for _, id := range bIDs {
		badArr = append(badArr, id)
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "bad_wraps", Value: badArr},
		{Key: "keys", Value: keysArr},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func loadEpochs(path string) (persistedEpochs, error) {
	ep := persistedEpochs{Keys: make(map[uint64][]byte), BadWraps: make(map[uint64]bool)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ep, nil
		}
		return ep, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ep, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ep, errors.New("ldrclient: invalid epochs.cbor")
	}
	if arr, err := ldrcrypto.MapArray(m, "keys"); err == nil {
		for _, elem := range arr {
			km, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			id, err1 := ldrcrypto.MapUint(km, "epoch")
			kb, err2 := ldrcrypto.MapBytesLen(km, "key", ldrcrypto.EpochKeySize)
			if err1 == nil && err2 == nil {
				ep.Keys[id] = kb
			}
		}
	}
	if arr, err := ldrcrypto.MapArray(m, "bad_wraps"); err == nil {
		for _, elem := range arr {
			if id, ok := elem.(uint64); ok {
				ep.BadWraps[id] = true
			}
		}
	}
	return ep, nil
}

func saveCursors(path string, cur persistedCursors) error {
	nIDs := make([]string, 0, len(cur.Notices))
	for id := range cur.Notices {
		nIDs = append(nIDs, id)
	}
	sort.Strings(nIDs)
	nArr := make([]any, 0, len(nIDs))
	for _, id := range nIDs {
		n := cur.Notices[id]
		nArr = append(nArr, ldrcrypto.Map{
			{Key: "acked", Value: n.Acked},
			{Key: "actor", Value: n.Actor},
			{Key: "binding_gen", Value: n.BindingGen},
			{Key: "gen", Value: n.Gen},
			{Key: "id", Value: n.ID},
			{Key: "kind", Value: n.Kind},
			{Key: "seq", Value: n.Seq},
			{Key: "target", Value: n.Target},
		})
	}
	raw, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "notices", Value: nArr},
		{Key: "projected_seq", Value: cur.ProjectedSeq},
		{Key: "rebuilds", Value: cur.Rebuilds},
		{Key: "scanned_seq", Value: cur.ScannedSeq},
		{Key: "v", Value: uint64(1)},
	}, ldrcrypto.Limits{MaxBytes: 2 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func loadCursors(path string) (persistedCursors, error) {
	cur := persistedCursors{Notices: make(map[string]*LocalNotice)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cur, nil
		}
		return cur, err
	}
	dec, err := ldrcrypto.UnmarshalCBOR(raw, ldrcrypto.Limits{MaxBytes: 2 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return cur, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return cur, errors.New("ldrclient: invalid cursors.cbor")
	}
	cur.ProjectedSeq, _ = ldrcrypto.MapUint(m, "projected_seq")
	cur.ScannedSeq, _ = ldrcrypto.MapUint(m, "scanned_seq")
	cur.Rebuilds, _ = ldrcrypto.MapUint(m, "rebuilds")
	if arr, err := ldrcrypto.MapArray(m, "notices"); err == nil {
		for _, elem := range arr {
			nm, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			n := &LocalNotice{}
			n.ID, _ = ldrcrypto.MapString(nm, "id")
			n.Gen, _ = ldrcrypto.MapUint(nm, "gen")
			n.Seq, _ = ldrcrypto.MapUint(nm, "seq")
			n.Actor, _ = ldrcrypto.MapString(nm, "actor")
			n.BindingGen, _ = ldrcrypto.MapUint(nm, "binding_gen")
			n.Kind, _ = ldrcrypto.MapString(nm, "kind")
			n.Target, _ = ldrcrypto.MapString(nm, "target")
			n.Acked, _ = ldrcrypto.MapBool(nm, "acked")
			cur.Notices[n.ID] = n
		}
	}
	return cur, nil
}
