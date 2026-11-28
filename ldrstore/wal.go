package ldrstore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

const (
	walMagic      = "LDRW"
	walVersion    = byte(1)
	walHeaderSize = 12 // 4B magic + 1B ver + 1B kind + 2B flags + 4B len
	walCRCSize    = 4
	walMaxBodyLen = 1024 * 1024 // 1 MiB safety cap per WAL record

	walKindCommit        byte = 1
	walKindNonCommit     byte = 2
	walKindCompact       byte = 3
	walKindCleanShutdown byte = 4
)

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// FileStore implements Store using a zero-dependency CRC32C-framed append-only
// WAL, content-addressed sidecars, and OS full-sync durability barriers under
// exclusive single-writer directory ownership (.relay.lock). Cached WAL file
// descriptors are checked against the recovery path via os.SameFile on every
// append and sync so an unlinked or replaced wal.log is detected immediately
// rather than silently acknowledging writes to an orphaned inode.
type FileStore struct {
	mu         sync.Mutex
	rootDir    string
	lockFile   *os.File
	walFiles   map[string]*os.File // hex(lineID) -> open append file
	syncFileFn func(*os.File) error
	syncDirFn  func(string) error
	closed     bool
}

// SetSyncHooks overrides the file/directory durability barriers used by
// FileStore (nil restores the default OS SyncFile / SyncDir barriers).
// Intended for fault-injection tests that independently control write
// visibility and fsync outcomes.
func (s *FileStore) SetSyncHooks(syncFile func(*os.File) error, syncDir func(string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFileFn = syncFile
	s.syncDirFn = syncDir
}

func (s *FileStore) syncFile(f *os.File) error {
	if s.syncFileFn != nil {
		return s.syncFileFn(f)
	}
	return SyncFile(f)
}

func (s *FileStore) syncDir(dir string) error {
	if s.syncDirFn != nil {
		return s.syncDirFn(dir)
	}
	return SyncDir(dir)
}

// OpenFileStore opens or initializes a FileStore at rootDir and acquires an
// exclusive OS flock so no two relay processes write the same directory.
func OpenFileStore(rootDir string) (*FileStore, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("%w: empty store directory", ErrInvalidRecord)
	}
	if err := os.MkdirAll(filepath.Join(rootDir, "lines"), 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(rootDir, ".relay.lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flockExclusive(lf); err != nil {
		_ = lf.Close()
		return nil, err
	}
	return &FileStore{
		rootDir:  rootDir,
		lockFile: lf,
		walFiles: make(map[string]*os.File),
	}, nil
}

// Close flushes and closes all open WAL handles and releases the directory lock.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var firstErr error
	for k, f := range s.walFiles {
		if err := s.syncFile(f); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(s.walFiles, k)
	}
	if s.lockFile != nil {
		_ = funlock(s.lockFile)
		if err := s.lockFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.lockFile = nil
	}
	return firstErr
}

func lineHex(lineID []byte) (string, error) {
	if len(lineID) < 16 || len(lineID) > 64 {
		return "", fmt.Errorf("%w: line_id must be 16..64 bytes", ErrInvalidRecord)
	}
	return hex.EncodeToString(lineID), nil
}

func (s *FileStore) lineDir(hexID string) string {
	return filepath.Join(s.rootDir, "lines", hexID)
}

func (s *FileStore) provisionPath(hexID string) string {
	return filepath.Join(s.lineDir(hexID), "provision.cbor")
}

func (s *FileStore) walPath(hexID string) string {
	return filepath.Join(s.lineDir(hexID), "wal.log")
}

func (s *FileStore) sidecarPath(hexID, kind string, digest [32]byte) string {
	return filepath.Join(s.lineDir(hexID), "sidecars", kind+"-"+hex.EncodeToString(digest[:]))
}

// ProvisionLine validates and atomically installs a root-signed creation descriptor.
func (s *FileStore) ProvisionLine(p ProvisionedLine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("ldrstore: store closed")
	}
	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(p.SignedDescriptor)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if !bytes.Equal(desc.LineID, p.LineID) || cd != p.DescriptorDigest || genesis != p.GenesisAnchor {
		return fmt.Errorf("%w: provisioned metadata does not match verified descriptor", ErrInvalidRecord)
	}
	hexID, err := lineHex(p.LineID)
	if err != nil {
		return err
	}
	provPath := s.provisionPath(hexID)
	if _, err := os.Stat(provPath); err == nil {
		return ErrLineExists
	}
	dir := s.lineDir(hexID)
	linesDir := filepath.Join(s.rootDir, "lines")
	sidecarsDir := filepath.Join(dir, "sidecars")
	if err := os.MkdirAll(sidecarsDir, 0o700); err != nil {
		return err
	}
	// Durably sync the parent lines/ directory (persisting the new line
	// directory entry) and subdirectories BEFORE creating wal.log and
	// installing provision.cbor.
	if err := s.syncDir(linesDir); err != nil {
		return err
	}
	if err := s.syncDir(sidecarsDir); err != nil {
		return err
	}
	// Create and durably sync the empty WAL BEFORE installing provision.cbor so
	// provision.cbor is the atomic commit point of provisioning. Once
	// provision.cbor exists, a missing wal.log is unambiguously a lost WAL
	// rather than incomplete provisioning.
	walPath := s.walPath(hexID)
	if fi, err := os.Stat(walPath); err == nil {
		if fi.Size() > 0 {
			return fmt.Errorf("%w: non-empty WAL exists without provision.cbor", ErrCorruptWAL)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	wf, err := os.OpenFile(walPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := s.syncFile(wf); err != nil {
		_ = wf.Close()
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	if err := s.syncDir(dir); err != nil {
		return err
	}

	enc, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "cd", Value: cd[:]},
		{Key: "descriptor", Value: p.SignedDescriptor},
		{Key: "genesis", Value: genesis[:]},
		{Key: "line_id", Value: p.LineID},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	if err := AtomicWriteFile(provPath, enc, 0o600); err != nil {
		return err
	}
	if err := s.syncDir(dir); err != nil {
		return err
	}
	return s.syncDir(linesDir)
}

// ListLines returns the sorted line IDs of all provisioned lines in the store.
// Empty directories or 0-byte WAL leftovers without provision.cbor represent
// incomplete provisioning and are ignored; a non-empty WAL missing its
// provision.cbor fails closed with ErrCorruptWAL.
func (s *FileStore) ListLines() ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.rootDir, "lines"))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		if _, err := os.Stat(s.provisionPath(ent.Name())); err != nil {
			if os.IsNotExist(err) {
				if fi, werr := os.Stat(s.walPath(ent.Name())); werr == nil && fi.Size() > 0 {
					return nil, fmt.Errorf("%w: non-empty WAL without provision.cbor in %q", ErrCorruptWAL, ent.Name())
				}
				continue
			}
			return nil, err
		}
		id, err := hex.DecodeString(ent.Name())
		if err != nil || len(id) < 16 || len(id) > 64 {
			return nil, fmt.Errorf("%w: invalid line directory name %q", ErrCorruptWAL, ent.Name())
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out, nil
}

func (s *FileStore) verifyWALHandleMatchesPathLocked(hexID string, f *os.File) error {
	pathInfo, err := os.Stat(s.walPath(hexID))
	if err != nil {
		_ = f.Close()
		delete(s.walFiles, hexID)
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: cached WAL path removed", ErrCorruptWAL)
		}
		return fmt.Errorf("%w: stat WAL path: %v", ErrUncertainWrite, err)
	}
	fdInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		delete(s.walFiles, hexID)
		return fmt.Errorf("%w: fstat WAL handle: %v", ErrUncertainWrite, err)
	}
	if !os.SameFile(pathInfo, fdInfo) {
		_ = f.Close()
		delete(s.walFiles, hexID)
		return fmt.Errorf("%w: cached WAL descriptor no longer matches recovery path", ErrCorruptWAL)
	}
	return nil
}

func (s *FileStore) openWALForAppendLocked(hexID string) (*os.File, error) {
	if f, ok := s.walFiles[hexID]; ok {
		if err := s.verifyWALHandleMatchesPathLocked(hexID, f); err != nil {
			return nil, err
		}
		return f, nil
	}
	if _, err := os.Stat(s.provisionPath(hexID)); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrLineNotFound
		}
		return nil, err
	}
	// Never pass O_CREATE here: a provisioned line must already have wal.log.
	f, err := os.OpenFile(s.walPath(hexID), os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: missing WAL file for provisioned line", ErrCorruptWAL)
		}
		return nil, err
	}
	s.walFiles[hexID] = f
	return f, nil
}

func verifySidecarCommitment(kind string, expected [32]byte, data []byte) error {
	switch kind {
	case SidecarPayload:
		c, err := ldrcrypto.CommitPayload(data)
		if err != nil {
			return err
		}
		if c.Digest != expected {
			return ErrCorruptSidecar
		}
		return nil
	case SidecarWrap:
		c, err := ldrcrypto.CommitWrap(data)
		if err != nil {
			return err
		}
		if c.Digest != expected {
			return ErrCorruptSidecar
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown sidecar kind %q", ErrInvalidRecord, kind)
	}
}

func (s *FileStore) writeSidecarLocked(hexID string, expected [32]byte, blob SidecarBlob) error {
	if err := verifySidecarCommitment(blob.Kind, expected, blob.Data); err != nil {
		return err
	}
	path := s.sidecarPath(hexID, blob.Kind, expected)
	if existing, err := os.ReadFile(path); err == nil {
		if err := verifySidecarCommitment(blob.Kind, expected, existing); err != nil {
			return ErrCorruptSidecar
		}
		return nil
	}
	return AtomicWriteFile(path, blob.Data, 0o600)
}

// GetSidecar reads and commitment-verifies a stored sidecar blob.
func (s *FileStore) GetSidecar(lineID []byte, kind string, digest [32]byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hexID, err := lineHex(lineID)
	if err != nil {
		return nil, err
	}
	path := s.sidecarPath(hexID, kind, digest)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrMissingSidecar
		}
		return nil, err
	}
	if err := verifySidecarCommitment(kind, digest, data); err != nil {
		return nil, err
	}
	return data, nil
}

func encodeWALFrame(kind byte, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > walMaxBodyLen {
		return nil, fmt.Errorf("%w: WAL body size %d out of bounds", ErrInvalidRecord, len(body))
	}
	buf := make([]byte, walHeaderSize+len(body)+walCRCSize)
	copy(buf[0:4], walMagic)
	buf[4] = walVersion
	buf[5] = kind
	buf[6] = 0
	buf[7] = 0
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(body)))
	copy(buf[12:12+len(body)], body)
	crc := crc32.Checksum(buf[:12+len(body)], castagnoliTable)
	binary.BigEndian.PutUint32(buf[12+len(body):], crc)
	return buf, nil
}

func (s *FileStore) appendWALLocked(hexID string, kind byte, body []byte) error {
	frame, err := encodeWALFrame(kind, body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	f, err := s.openWALForAppendLocked(hexID)
	if err != nil {
		if errors.Is(err, ErrCorruptWAL) || errors.Is(err, ErrUncertainWrite) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	if _, err := f.Write(frame); err != nil {
		_ = f.Close()
		delete(s.walFiles, hexID)
		return fmt.Errorf("%w: wal write: %v", ErrUncertainWrite, err)
	}
	if err := s.syncFile(f); err != nil {
		_ = f.Close()
		delete(s.walFiles, hexID)
		return fmt.Errorf("%w: wal sync: %v", ErrUncertainWrite, err)
	}
	if err := s.verifyWALHandleMatchesPathLocked(hexID, f); err != nil {
		return err
	}
	return nil
}

// AppendCommit durably persists all referenced sidecars FIRST, then appends and
// full-syncs one CRC32C WAL commit record.
func (s *FileStore) AppendCommit(lineID []byte, frame CommittedFrame, sidecars map[[32]byte]SidecarBlob, newFloor uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%w: store closed", ErrPreWrite)
	}
	hexID, err := lineHex(lineID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	if _, err := os.Stat(s.provisionPath(hexID)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %v", ErrPreWrite, ErrLineNotFound)
		}
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	if newFloor > ldrcrypto.MaxCounter {
		return fmt.Errorf("%w: %w: time_floor %d exceeds protocol max %d", ErrPreWrite, ErrInvalidRecord, newFloor, ldrcrypto.MaxCounter)
	}
	if frame.SeqTime > ldrcrypto.MaxCounter {
		return fmt.Errorf("%w: %w: seq_time %d exceeds protocol max %d", ErrPreWrite, ErrInvalidRecord, frame.SeqTime, ldrcrypto.MaxCounter)
	}
	// Verify and persist every referenced sidecar BEFORE writing the WAL commit.
	if frame.PayloadCommit != nil && frame.PayloadCommit.Length > 0 {
		blob, ok := sidecars[frame.PayloadCommit.Digest]
		if !ok || blob.Kind != SidecarPayload || uint64(len(blob.Data)) != frame.PayloadCommit.Length {
			return fmt.Errorf("%w: %v: missing or mismatched payload sidecar", ErrPreWrite, ErrMissingSidecar)
		}
	}
	for _, wm := range frame.WrapCommits {
		blob, ok := sidecars[wm.Commit.Digest]
		if !ok || blob.Kind != SidecarWrap || uint64(len(blob.Data)) != wm.Commit.Length {
			return fmt.Errorf("%w: %v: missing or mismatched wrap sidecar", ErrPreWrite, ErrMissingSidecar)
		}
	}
	// Deterministic write order for sidecars. Any sidecar failure occurs strictly
	// before any WAL byte is written, so it is a clean pre-write refusal.
	digests := make([][32]byte, 0, len(sidecars))
	for d := range sidecars {
		digests = append(digests, d)
	}
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i][:], digests[j][:]) < 0 })
	for _, d := range digests {
		if err := s.writeSidecarLocked(hexID, d, sidecars[d]); err != nil {
			return fmt.Errorf("%w: %v", ErrPreWrite, err)
		}
	}
	body, err := encodeCommitBody(frame, newFloor)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	return s.appendWALLocked(hexID, walKindCommit, body)
}

// AppendNonCommit durably records a rejected or noop outcome in one WAL record.
func (s *FileStore) AppendNonCommit(lineID []byte, entry HotEntry, newFloor uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%w: store closed", ErrPreWrite)
	}
	hexID, err := lineHex(lineID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	if entry.Outcome.Kind != "rejected" && entry.Outcome.Kind != "noop" {
		return fmt.Errorf("%w: %v: non-commit outcome kind %q", ErrPreWrite, ErrInvalidRecord, entry.Outcome.Kind)
	}
	if newFloor > ldrcrypto.MaxCounter {
		return fmt.Errorf("%w: %w: time_floor %d exceeds protocol max %d", ErrPreWrite, ErrInvalidRecord, newFloor, ldrcrypto.MaxCounter)
	}
	body, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "entry", Value: encodeHotEntryMap(entry)},
		{Key: "floor", Value: newFloor},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	return s.appendWALLocked(hexID, walKindNonCommit, body)
}

// AppendCompact durably retires hot entries for expired anchors.
func (s *FileStore) AppendCompact(lineID []byte, retired []StoredOpKey, newFloor uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%w: store closed", ErrPreWrite)
	}
	hexID, err := lineHex(lineID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	if newFloor > ldrcrypto.MaxCounter {
		return fmt.Errorf("%w: %w: time_floor %d exceeds protocol max %d", ErrPreWrite, ErrInvalidRecord, newFloor, ldrcrypto.MaxCounter)
	}
	keys := make([]any, len(retired))
	for i, k := range retired {
		keys[i] = encodeOpKeyMap(k)
	}
	body, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "floor", Value: newFloor},
		{Key: "retired", Value: keys},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPreWrite, err)
	}
	return s.appendWALLocked(hexID, walKindCompact, body)
}

// RecordCleanShutdown writes a clean shutdown marker with the persisted floor and wall time.
func (s *FileStore) RecordCleanShutdown(lineID []byte, floor, wallMS uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("ldrstore: store closed")
	}
	hexID, err := lineHex(lineID)
	if err != nil {
		return err
	}
	if floor > ldrcrypto.MaxCounter || wallMS > ldrcrypto.MaxCounter {
		return fmt.Errorf("%w: clean shutdown floor/wall out of domain", ErrInvalidRecord)
	}
	body, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "floor", Value: floor},
		{Key: "v", Value: uint64(1)},
		{Key: "wall_ms", Value: wallMS},
	})
	if err != nil {
		return err
	}
	return s.appendWALLocked(hexID, walKindCleanShutdown, body)
}

// SyncLine enforces a durability barrier on the provisioned line's WAL file
// and directories (preventing un-synced OS page-cache bytes from being treated
// as durable after an earlier failed sync).
func (s *FileStore) SyncLine(lineID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("ldrstore: store closed")
	}
	hexID, err := lineHex(lineID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(s.provisionPath(hexID)); err != nil {
		if os.IsNotExist(err) {
			return ErrLineNotFound
		}
		return err
	}
	if wf, ok := s.walFiles[hexID]; ok {
		if err := s.verifyWALHandleMatchesPathLocked(hexID, wf); err != nil {
			return err
		}
		if err := s.syncFile(wf); err != nil {
			_ = wf.Close()
			delete(s.walFiles, hexID)
			return fmt.Errorf("%w: wal barrier sync: %v", ErrUncertainWrite, err)
		}
		if err := s.verifyWALHandleMatchesPathLocked(hexID, wf); err != nil {
			return err
		}
	} else {
		wf, err := os.OpenFile(s.walPath(hexID), os.O_RDWR, 0o600)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: missing WAL file for provisioned line", ErrCorruptWAL)
			}
			return err
		}
		if err := s.syncFile(wf); err != nil {
			_ = wf.Close()
			return fmt.Errorf("%w: wal barrier sync: %v", ErrUncertainWrite, err)
		}
		if err := s.verifyWALHandleMatchesPathLocked(hexID, wf); err != nil {
			return err
		}
		if err := wf.Close(); err != nil {
			return fmt.Errorf("%w: wal barrier close: %v", ErrUncertainWrite, err)
		}
	}
	if err := s.syncDir(s.lineDir(hexID)); err != nil {
		return fmt.Errorf("%w: line dir barrier sync: %v", ErrUncertainWrite, err)
	}
	if err := s.syncDir(filepath.Join(s.lineDir(hexID), "sidecars")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: sidecars dir barrier sync: %v", ErrUncertainWrite, err)
	}
	return nil
}

// LoadLine scans and verifies provision.cbor, the entire CRC32C WAL, and every
// referenced sidecar commitment, then executes an explicit durability barrier
// (SyncFile + SyncDir) on the recovered WAL state before returning. Partial or
// zeroed EOF tails are truncated cleanly; a missing WAL beside provision.cbor
// or any mid-file/complete-record corruption fails closed with ErrCorruptWAL.
func (s *FileStore) LoadLine(lineID []byte) (*LineSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("ldrstore: store closed")
	}
	hexID, err := lineHex(lineID)
	if err != nil {
		return nil, err
	}
	provRaw, err := os.ReadFile(s.provisionPath(hexID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrLineNotFound
		}
		return nil, err
	}
	prov, err := decodeProvisionedLine(provRaw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(prov.LineID, lineID) {
		return nil, fmt.Errorf("%w: provision.cbor line_id mismatch", ErrCorruptWAL)
	}

	// Close any cached append handle before scanning/truncating/syncing.
	if wf, ok := s.walFiles[hexID]; ok {
		_ = wf.Close()
		delete(s.walFiles, hexID)
	}

	// Because ProvisionLine durably creates wal.log BEFORE installing
	// provision.cbor, a missing wal.log beside provision.cbor is a lost WAL
	// (never an empty line) and MUST fail closed.
	walFilePath := s.walPath(hexID)
	wf, err := os.OpenFile(walFilePath, os.O_RDWR, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: missing WAL file for provisioned line", ErrCorruptWAL)
		}
		return nil, err
	}
	data, err := io.ReadAll(wf)
	if err != nil {
		_ = wf.Close()
		return nil, err
	}

	snap := &LineSnapshot{
		Provisioned: prov,
		LogIndex:    make(map[StoredOpKey]CommittedReceipt),
		Hot:         make(map[StoredOpKey]HotEntry),
		Quota:       make(map[string]int),
	}

	offset := 0
	for offset < len(data) {
		rem := len(data) - offset
		// All-zero trailing bytes at EOF indicate a torn zero-filled tail.
		if isAllZero(data[offset:]) {
			if err := wf.Truncate(int64(offset)); err != nil {
				_ = wf.Close()
				return nil, err
			}
			snap.RecoveredTornTail = true
			break
		}
		// Partial header at EOF -> torn write tail, safely truncate.
		if rem < walHeaderSize {
			if err := wf.Truncate(int64(offset)); err != nil {
				_ = wf.Close()
				return nil, err
			}
			snap.RecoveredTornTail = true
			break
		}
		hdr := data[offset : offset+walHeaderSize]
		if string(hdr[0:4]) != walMagic || hdr[4] != walVersion || hdr[6] != 0 || hdr[7] != 0 {
			_ = wf.Close()
			return nil, fmt.Errorf("%w: invalid WAL header at offset %d", ErrCorruptWAL, offset)
		}
		kind := hdr[5]
		bodyLen := int(binary.BigEndian.Uint32(hdr[8:12]))
		if bodyLen == 0 || bodyLen > walMaxBodyLen {
			_ = wf.Close()
			return nil, fmt.Errorf("%w: invalid WAL body length %d at offset %d", ErrCorruptWAL, bodyLen, offset)
		}
		frameLen := walHeaderSize + bodyLen + walCRCSize
		// Partial body/CRC strictly at EOF -> torn write tail, safely truncate.
		if offset+frameLen > len(data) {
			if err := wf.Truncate(int64(offset)); err != nil {
				_ = wf.Close()
				return nil, err
			}
			snap.RecoveredTornTail = true
			break
		}
		frameBytes := data[offset : offset+frameLen]
		wantCRC := binary.BigEndian.Uint32(frameBytes[walHeaderSize+bodyLen:])
		gotCRC := crc32.Checksum(frameBytes[:walHeaderSize+bodyLen], castagnoliTable)
		if gotCRC != wantCRC {
			_ = wf.Close()
			return nil, fmt.Errorf("%w: CRC32C mismatch at offset %d", ErrCorruptWAL, offset)
		}
		body := frameBytes[walHeaderSize : walHeaderSize+bodyLen]
		if err := applyWALRecord(snap, kind, body); err != nil {
			_ = wf.Close()
			return nil, fmt.Errorf("%w: offset %d: %v", ErrCorruptWAL, offset, err)
		}
		offset += frameLen
	}

	// Enforce an explicit durability barrier on the recovered WAL (even when no
	// torn tail was truncated!) so un-synced page-cache bytes from an earlier
	// failed SyncFile are NEVER treated as durable on restart or reconciliation.
	if err := s.syncFile(wf); err != nil {
		_ = wf.Close()
		return nil, fmt.Errorf("%w: recovery wal sync: %v", ErrUncertainWrite, err)
	}
	if err := wf.Close(); err != nil {
		return nil, fmt.Errorf("%w: recovery wal close: %v", ErrUncertainWrite, err)
	}
	if err := s.syncDir(s.lineDir(hexID)); err != nil {
		return nil, fmt.Errorf("%w: recovery dir sync: %v", ErrUncertainWrite, err)
	}
	if err := s.syncDir(filepath.Join(s.lineDir(hexID), "sidecars")); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: recovery sidecars dir sync: %v", ErrUncertainWrite, err)
	}

	// Verify every committed frame's sidecars exist and pass commitment verification.
	for _, fr := range snap.Frames {
		if fr.PayloadCommit != nil && fr.PayloadCommit.Length > 0 {
			p := s.sidecarPath(hexID, SidecarPayload, fr.PayloadCommit.Digest)
			raw, err := os.ReadFile(p)
			if err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("%w: seq %d payload sidecar", ErrMissingSidecar, fr.Seq)
				}
				return nil, err
			}
			if err := ldrcrypto.VerifyPayloadSidecar(*fr.PayloadCommit, raw); err != nil {
				return nil, fmt.Errorf("%w: seq %d payload sidecar: %v", ErrCorruptSidecar, fr.Seq, err)
			}
		}
		for _, wm := range fr.WrapCommits {
			p := s.sidecarPath(hexID, SidecarWrap, wm.Commit.Digest)
			raw, err := os.ReadFile(p)
			if err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("%w: seq %d wrap sidecar", ErrMissingSidecar, fr.Seq)
				}
				return nil, err
			}
			if err := ldrcrypto.VerifyWrapSidecar(wm.Commit, raw); err != nil {
				return nil, fmt.Errorf("%w: seq %d wrap sidecar: %v", ErrCorruptSidecar, fr.Seq, err)
			}
		}
	}

	return snap, nil
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func applyWALRecord(snap *LineSnapshot, kind byte, body []byte) error {
	lim := ldrcrypto.Limits{MaxBytes: walMaxBodyLen, MaxDepth: 16, MaxItems: 8192}
	dec, err := ldrcrypto.UnmarshalCBOR(body, lim)
	if err != nil {
		return err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return errors.New("WAL body must be CBOR map")
	}
	v, err := ldrcrypto.MapUint(m, "v")
	if err != nil || v != 1 {
		return errors.New("unsupported WAL record version")
	}
	floor, err := ldrcrypto.MapUint(m, "floor")
	if err != nil {
		return err
	}
	if floor > ldrcrypto.MaxCounter {
		return fmt.Errorf("time_floor %d exceeds protocol max %d", floor, ldrcrypto.MaxCounter)
	}
	if floor < snap.TimeFloor {
		return fmt.Errorf("time_floor regression %d < %d", floor, snap.TimeFloor)
	}
	snap.TimeFloor = floor

	switch kind {
	case walKindCommit:
		fr, err := decodeCommitBody(m)
		if err != nil {
			return err
		}
		if floor < fr.SeqTime {
			return fmt.Errorf("commit record time_floor %d < seq_time %d", floor, fr.SeqTime)
		}
		snap.Frames = append(snap.Frames, fr)
		if fr.OpKey != nil {
			if _, exists := snap.LogIndex[*fr.OpKey]; exists {
				return fmt.Errorf("duplicate committed op_key %v", *fr.OpKey)
			}
			if _, exists := snap.Hot[*fr.OpKey]; exists {
				return fmt.Errorf("committed op_key %v collides with existing hot entry", *fr.OpKey)
			}
			snap.LogIndex[*fr.OpKey] = CommittedReceipt{Seq: fr.Seq, Digest: fr.IntentDigest}
			// line_init is not stored in hot (no anchor retirement), matching ldrcore.
			if fr.OpType != "line_init" {
				snap.Hot[*fr.OpKey] = HotEntry{
					Key:    *fr.OpKey,
					Digest: fr.IntentDigest,
					Outcome: StoredOutcome{
						Kind: "committed",
						Seq:  fr.Seq,
					},
				}
			}
		}
		return nil

	case walKindNonCommit:
		if err := ldrcrypto.RequireExactKeys(m, []string{"entry", "floor", "v"}); err != nil {
			return err
		}
		he, err := decodeHotEntry(m["entry"])
		if err != nil {
			return err
		}
		if (he.Outcome.Kind != "rejected" && he.Outcome.Kind != "noop") || he.Outcome.Seq != 0 {
			return fmt.Errorf("invalid non-commit hot entry kind=%q seq=%d", he.Outcome.Kind, he.Outcome.Seq)
		}
		if _, exists := snap.LogIndex[he.Key]; exists {
			return fmt.Errorf("non-commit op_key %v collides with committed receipt", he.Key)
		}
		if _, exists := snap.Hot[he.Key]; exists {
			return fmt.Errorf("duplicate hot op_key %v", he.Key)
		}
		snap.Hot[he.Key] = he
		snap.Quota[he.Key.Signer]++
		return nil

	case walKindCompact:
		if err := ldrcrypto.RequireExactKeys(m, []string{"floor", "retired", "v"}); err != nil {
			return err
		}
		arr, err := ldrcrypto.MapArray(m, "retired")
		if err != nil {
			return err
		}
		for _, elem := range arr {
			k, err := decodeOpKey(elem)
			if err != nil {
				return err
			}
			if prev, exists := snap.Hot[k]; exists {
				if prev.Outcome.Kind != "committed" && snap.Quota[k.Signer] > 0 {
					snap.Quota[k.Signer]--
				}
				delete(snap.Hot, k)
			}
		}
		return nil

	case walKindCleanShutdown:
		if err := ldrcrypto.RequireExactKeys(m, []string{"floor", "v", "wall_ms"}); err != nil {
			return err
		}
		wallMS, err := ldrcrypto.MapUint(m, "wall_ms")
		if err != nil {
			return err
		}
		snap.LastCleanShutdownWallMS = wallMS
		return nil

	default:
		return fmt.Errorf("unknown WAL record kind %d", kind)
	}
}

// --- Canonical CBOR encoding helpers for WAL records ---

func decodeProvisionedLine(raw []byte) (ProvisionedLine, error) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ProvisionedLine{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ProvisionedLine{}, fmt.Errorf("%w: provision.cbor must be map", ErrCorruptWAL)
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"cd", "descriptor", "genesis", "line_id", "v"}); err != nil {
		return ProvisionedLine{}, err
	}
	v, err := ldrcrypto.MapUint(m, "v")
	if err != nil || v != 1 {
		return ProvisionedLine{}, fmt.Errorf("%w: unsupported provision.cbor version", ErrCorruptWAL)
	}
	lineID, err := ldrcrypto.MapBytes(m, "line_id")
	if err != nil {
		return ProvisionedLine{}, err
	}
	descBytes, err := ldrcrypto.MapBytes(m, "descriptor")
	if err != nil {
		return ProvisionedLine{}, err
	}
	cdBytes, err := ldrcrypto.MapBytesLen(m, "cd", 32)
	if err != nil {
		return ProvisionedLine{}, err
	}
	genBytes, err := ldrcrypto.MapBytesLen(m, "genesis", 32)
	if err != nil {
		return ProvisionedLine{}, err
	}
	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(descBytes)
	if err != nil {
		return ProvisionedLine{}, fmt.Errorf("%w: descriptor verification failed: %v", ErrCorruptWAL, err)
	}
	if !bytes.Equal(desc.LineID, lineID) || !bytes.Equal(cd[:], cdBytes) || !bytes.Equal(genesis[:], genBytes) {
		return ProvisionedLine{}, fmt.Errorf("%w: provision.cbor digest mismatch", ErrCorruptWAL)
	}
	return ProvisionedLine{
		LineID:           bytes.Clone(lineID),
		SignedDescriptor: bytes.Clone(descBytes),
		DescriptorDigest: cd,
		GenesisAnchor:    genesis,
	}, nil
}

func encodeOpKeyMap(k StoredOpKey) ldrcrypto.Map {
	return ldrcrypto.Map{
		{Key: "gen", Value: k.Generation},
		{Key: "op_id", Value: k.OpID},
		{Key: "seen_seq", Value: k.SeenSeq},
		{Key: "signer", Value: k.Signer},
	}
}

func decodeOpKey(v any) (StoredOpKey, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return StoredOpKey{}, errors.New("op_key must be map")
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"gen", "op_id", "seen_seq", "signer"}); err != nil {
		return StoredOpKey{}, err
	}
	gen, err := ldrcrypto.MapUint(m, "gen")
	if err != nil {
		return StoredOpKey{}, err
	}
	opID, err := ldrcrypto.MapString(m, "op_id")
	if err != nil {
		return StoredOpKey{}, err
	}
	seenSeq, err := ldrcrypto.MapUint(m, "seen_seq")
	if err != nil {
		return StoredOpKey{}, err
	}
	signer, err := ldrcrypto.MapString(m, "signer")
	if err != nil {
		return StoredOpKey{}, err
	}
	return StoredOpKey{Generation: gen, Signer: signer, SeenSeq: seenSeq, OpID: opID}, nil
}

func encodeHotEntryMap(e HotEntry) ldrcrypto.Map {
	return ldrcrypto.Map{
		{Key: "digest", Value: bytes.Clone(e.Digest[:])},
		{Key: "key", Value: encodeOpKeyMap(e.Key)},
		{Key: "kind", Value: e.Outcome.Kind},
		{Key: "reason", Value: e.Outcome.Reason},
		{Key: "ref_gen", Value: e.Outcome.RefGen},
		{Key: "ref_seq", Value: e.Outcome.RefSeq},
		{Key: "seq", Value: e.Outcome.Seq},
	}
}

func decodeHotEntry(v any) (HotEntry, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return HotEntry{}, errors.New("hot entry must be map")
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"digest", "key", "kind", "reason", "ref_gen", "ref_seq", "seq"}); err != nil {
		return HotEntry{}, err
	}
	d, err := ldrcrypto.MapBytesLen(m, "digest", 32)
	if err != nil {
		return HotEntry{}, err
	}
	k, err := decodeOpKey(m["key"])
	if err != nil {
		return HotEntry{}, err
	}
	kind, err := ldrcrypto.MapString(m, "kind")
	if err != nil {
		return HotEntry{}, err
	}
	reason, err := ldrcrypto.MapString(m, "reason")
	if err != nil {
		return HotEntry{}, err
	}
	refGen, err := ldrcrypto.MapUint(m, "ref_gen")
	if err != nil {
		return HotEntry{}, err
	}
	refSeq, err := ldrcrypto.MapUint(m, "ref_seq")
	if err != nil {
		return HotEntry{}, err
	}
	seq, err := ldrcrypto.MapUint(m, "seq")
	if err != nil {
		return HotEntry{}, err
	}
	var dig [32]byte
	copy(dig[:], d)
	return HotEntry{
		Key:    k,
		Digest: dig,
		Outcome: StoredOutcome{
			Kind:   kind,
			Reason: reason,
			RefGen: refGen,
			RefSeq: refSeq,
			Seq:    seq,
		},
	}, nil
}

func encodeCommitBody(fr CommittedFrame, floor uint64) ([]byte, error) {
	intentBytes := fr.IntentBytes
	if intentBytes == nil {
		intentBytes = []byte{}
	}
	wraps := make([]any, len(fr.WrapCommits))
	for i, w := range fr.WrapCommits {
		wraps[i] = ldrcrypto.Map{
			{Key: "commit", Value: w.Commit.ToCBORMap()},
			{Key: "cred_id", Value: bytes.Clone(w.CredID[:])},
		}
	}
	m := ldrcrypto.Map{
		{Key: "floor", Value: floor},
		{Key: "gen", Value: fr.Gen},
		{Key: "head", Value: bytes.Clone(fr.Head[:])},
		{Key: "intent", Value: intentBytes},
		{Key: "intent_digest", Value: bytes.Clone(fr.IntentDigest[:])},
		{Key: "op_type", Value: fr.OpType},
		{Key: "origin", Value: fr.Origin},
		{Key: "prev_head", Value: bytes.Clone(fr.PrevHead[:])},
		{Key: "seq", Value: fr.Seq},
		{Key: "seq_time", Value: fr.SeqTime},
		{Key: "v", Value: uint64(1)},
		{Key: "wraps", Value: wraps},
	}
	if fr.OpKey != nil {
		m = append(m, ldrcrypto.MapEntry{Key: "op_key", Value: encodeOpKeyMap(*fr.OpKey)})
	}
	if fr.PayloadCommit != nil {
		m = append(m, ldrcrypto.MapEntry{Key: "payload_commit", Value: fr.PayloadCommit.ToCBORMap()})
	}
	return ldrcrypto.MarshalCBORWithLimits(m, ldrcrypto.Limits{MaxBytes: walMaxBodyLen, MaxDepth: 16, MaxItems: 8192})
}

func decodeCommitBody(m map[string]any) (CommittedFrame, error) {
	req := []string{"floor", "gen", "head", "intent", "intent_digest", "op_type", "origin", "prev_head", "seq", "seq_time", "v", "wraps"}
	if err := ldrcrypto.RequireExactKeys(m, req, "op_key", "payload_commit"); err != nil {
		return CommittedFrame{}, err
	}
	var fr CommittedFrame
	var err error
	if fr.Gen, err = ldrcrypto.MapUint(m, "gen"); err != nil {
		return CommittedFrame{}, err
	}
	if fr.Seq, err = ldrcrypto.MapUint(m, "seq"); err != nil {
		return CommittedFrame{}, err
	}
	if fr.SeqTime, err = ldrcrypto.MapUint(m, "seq_time"); err != nil {
		return CommittedFrame{}, err
	}
	ph, err := ldrcrypto.MapBytesLen(m, "prev_head", 32)
	if err != nil {
		return CommittedFrame{}, err
	}
	copy(fr.PrevHead[:], ph)
	hd, err := ldrcrypto.MapBytesLen(m, "head", 32)
	if err != nil {
		return CommittedFrame{}, err
	}
	copy(fr.Head[:], hd)
	if fr.Origin, err = ldrcrypto.MapString(m, "origin"); err != nil {
		return CommittedFrame{}, err
	}
	if fr.OpType, err = ldrcrypto.MapString(m, "op_type"); err != nil {
		return CommittedFrame{}, err
	}
	if fr.IntentBytes, err = ldrcrypto.MapBytes(m, "intent"); err != nil {
		return CommittedFrame{}, err
	}
	idg, err := ldrcrypto.MapBytesLen(m, "intent_digest", 32)
	if err != nil {
		return CommittedFrame{}, err
	}
	copy(fr.IntentDigest[:], idg)

	if okRaw, has := m["op_key"]; has {
		k, err := decodeOpKey(okRaw)
		if err != nil {
			return CommittedFrame{}, err
		}
		fr.OpKey = &k
	}
	if pcRaw, has := m["payload_commit"]; has {
		c, err := ldrcrypto.ParseCommitment(pcRaw)
		if err != nil {
			return CommittedFrame{}, err
		}
		fr.PayloadCommit = &c
	}
	wrapsRaw, err := ldrcrypto.MapArray(m, "wraps")
	if err != nil {
		return CommittedFrame{}, err
	}
	for _, w := range wrapsRaw {
		wm, ok := w.(map[string]any)
		if !ok {
			return CommittedFrame{}, errors.New("wrap entry must be map")
		}
		if err := ldrcrypto.RequireExactKeys(wm, []string{"commit", "cred_id"}); err != nil {
			return CommittedFrame{}, err
		}
		cidBytes, err := ldrcrypto.MapBytesLen(wm, "cred_id", 32)
		if err != nil {
			return CommittedFrame{}, err
		}
		c, err := ldrcrypto.ParseCommitment(wm["commit"])
		if err != nil {
			return CommittedFrame{}, err
		}
		var cid [32]byte
		copy(cid[:], cidBytes)
		fr.WrapCommits = append(fr.WrapCommits, ldrcrypto.WrapManifestEntry{CredID: cid, Commit: c})
	}
	return fr, nil
}
