// Package ldrstore provides the swappable durable storage boundary for LDR
// relays and its zero-dependency CRC32C-framed append-only WAL + CAS sidecar
// implementation (FileStore).
package ldrstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

var (
	ErrLineExists     = errors.New("ldrstore: line already provisioned")
	ErrLineNotFound   = errors.New("ldrstore: line not provisioned")
	ErrCorruptWAL     = errors.New("ldrstore: corrupt WAL record or invariant violation")
	ErrMissingSidecar = errors.New("ldrstore: referenced sidecar missing")
	ErrCorruptSidecar = errors.New("ldrstore: sidecar failed commitment verification")
	ErrStoreLocked    = errors.New("ldrstore: store directory is locked by another process")
	ErrInvalidRecord  = errors.New("ldrstore: invalid store record")
	// ErrPreWrite marks a clean refusal that failed strictly BEFORE any bytes
	// were written to the WAL; on-disk durable state is unchanged.
	ErrPreWrite = errors.New("ldrstore: clean pre-write refusal")
	// ErrUncertainWrite marks a WAL write or fsync failure whose on-disk
	// durability is uncertain; the caller MUST quarantine the line and
	// reconcile against validated durable state before accepting more work.
	ErrUncertainWrite = errors.New("ldrstore: uncertain WAL write or sync failure")
)

// SidecarKind distinguishes domain-separated payload vs wrap sidecar verification.
const (
	SidecarPayload = "payload"
	SidecarWrap    = "wrap"
)

// SidecarBlob carries raw sidecar bytes with their expected commitment kind.
type SidecarBlob struct {
	Kind string
	Data []byte
}

// ProvisionedLine is the immutable generation-1 bootstrap configuration
// installed by local host administration before line_init commits.
type ProvisionedLine struct {
	LineID           []byte
	SignedDescriptor []byte
	DescriptorDigest [32]byte
	GenesisAnchor    [32]byte
}

// StoredOpKey uniquely identifies a submitted operation in the store.
type StoredOpKey struct {
	Generation uint64
	Signer     string
	SeenSeq    uint64
	OpID       string
}

// CommittedReceipt is the permanent log_index entry for a committed operation.
type CommittedReceipt struct {
	Seq    uint64
	Digest [32]byte
}

// StoredOutcome is the durable outcome stored in the hot index.
type StoredOutcome struct {
	Kind   string // "committed", "rejected", "noop"
	Reason string
	RefGen uint64
	RefSeq uint64
	Seq    uint64
}

// HotEntry records one unretired operation outcome in the hot index.
type HotEntry struct {
	Key     StoredOpKey
	Digest  [32]byte
	Outcome StoredOutcome
}

// CommittedFrame is one durable log frame committed to the line's chain.
type CommittedFrame struct {
	Gen           uint64
	Seq           uint64
	SeqTime       uint64
	PrevHead      [32]byte
	Head          [32]byte
	Origin        string
	OpType        string
	IntentBytes   []byte
	IntentDigest  [32]byte
	OpKey         *StoredOpKey
	PayloadCommit *ldrcrypto.Commitment
	WrapCommits   []ldrcrypto.WrapManifestEntry
}

// LineSnapshot is the verified durable state reconstructed from disk on startup.
type LineSnapshot struct {
	Provisioned             ProvisionedLine
	Frames                  []CommittedFrame
	LogIndex                map[StoredOpKey]CommittedReceipt
	Hot                     map[StoredOpKey]HotEntry
	Quota                   map[string]int
	TimeFloor               uint64
	LastCleanShutdownWallMS uint64
	RecoveredTornTail       bool
}

// Store is the swappable persistence contract for an LDR relay backend.
// Implementations (zero-dep FileStore WAL, SQLite, or Cloudflare Durable Objects)
// MUST make every Append* call durable in one atomic step before returning nil.
type Store interface {
	ProvisionLine(p ProvisionedLine) error
	ListLines() ([][]byte, error)
	LoadLine(lineID []byte) (*LineSnapshot, error)

	// AppendCommit durably persists all referenced sidecars BEFORE committing the
	// single atomic log/hot/index/floor record.
	AppendCommit(lineID []byte, frame CommittedFrame, sidecars map[[32]byte]SidecarBlob, newFloor uint64) error

	// AppendNonCommit durably records a rejected or noop outcome in hot + quota + floor.
	AppendNonCommit(lineID []byte, entry HotEntry, newFloor uint64) error

	// AppendCompact durably removes retired hot entries and decrements their
	// non-commit quotas without ever removing permanent log_index entries.
	AppendCompact(lineID []byte, retired []StoredOpKey, newFloor uint64) error

	// RecordCleanShutdown persists a clean shutdown time marker for restart clock checks.
	RecordCleanShutdown(lineID []byte, floor, wallMS uint64) error

	// GetSidecar reads and commitment-verifies a stored sidecar blob.
	GetSidecar(lineID []byte, kind string, digest [32]byte) ([]byte, error)

	Close() error
}

// AtomicWriteFile writes data to a temporary sibling file, flushes via SyncFile,
// atomically renames into place, and flushes the parent directory.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
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
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := SyncFile(f); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return SyncDir(dir)
}
