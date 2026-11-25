package ldrstore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

func TestFileStorePreWriteSentinelsAndWALInvariants(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	defer st.Close()

	prov := makeTestProvision(t, 0x33)
	if err := st.ProvisionLine(prov); err != nil {
		t.Fatalf("ProvisionLine: %v", err)
	}

	// 1. Pre-write refusal: unknown line wraps ErrPreWrite + ErrLineNotFound.
	missingLine := bytes.Repeat([]byte{0x99}, 16)
	k1 := StoredOpKey{Generation: 1, Signer: "root:r1", SeenSeq: 0, OpID: "init-1"}
	f1 := CommittedFrame{
		Gen: 1, Seq: 1, SeqTime: 1000,
		PrevHead: prov.GenesisAnchor, Head: [32]byte{1},
		Origin: "root", OpType: "line_init",
		IntentBytes: []byte{0x01}, IntentDigest: [32]byte{0xaa},
		OpKey: &k1,
	}
	if err := st.AppendCommit(missingLine, f1, nil, 1000); !errors.Is(err, ErrPreWrite) {
		t.Fatalf("AppendCommit(missing line): got %v, want ErrPreWrite", err)
	}

	// 2. Pre-write refusal: missing sidecar wraps ErrPreWrite.
	pc, _ := ldrcrypto.CommitPayload([]byte("hello"))
	fBadSidecar := f1
	fBadSidecar.PayloadCommit = &pc
	if err := st.AppendCommit(prov.LineID, fBadSidecar, nil, 1000); !errors.Is(err, ErrPreWrite) {
		t.Fatalf("AppendCommit(missing sidecar): got %v, want ErrPreWrite", err)
	}

	// 3. Pre-write refusal: bad non-commit outcome kind wraps ErrPreWrite.
	if err := st.AppendNonCommit(prov.LineID, HotEntry{
		Key:     StoredOpKey{Generation: 1, Signer: "cred:c1", SeenSeq: 1, OpID: "bad"},
		Digest:  [32]byte{0x11},
		Outcome: StoredOutcome{Kind: "committed", Seq: 2},
	}, 1000); !errors.Is(err, ErrPreWrite) {
		t.Fatalf("AppendNonCommit(committed kind): got %v, want ErrPreWrite", err)
	}

	// 4. Clean commit succeeds after pre-write refusals.
	if err := st.AppendCommit(prov.LineID, f1, nil, 1000); err != nil {
		t.Fatalf("AppendCommit(valid after pre-write refusals): %v", err)
	}

	// 5. WAL invariant: duplicate committed OpKey fails closed on LoadLine.
	fDup := f1
	fDup.Seq = 2
	fDup.SeqTime = 2000
	fDup.PrevHead = f1.Head
	fDup.Head = [32]byte{2}
	if err := st.AppendCommit(prov.LineID, fDup, nil, 2000); err != nil {
		t.Fatalf("AppendCommit(dup): %v", err)
	}
	if _, err := st.LoadLine(prov.LineID); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("LoadLine(duplicate committed op_key): got %v, want ErrCorruptWAL", err)
	}

	// 6. WAL invariant: non-commit colliding with committed OpKey fails closed.
	dir2 := t.TempDir()
	st2, err := OpenFileStore(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.ProvisionLine(prov); err != nil {
		t.Fatal(err)
	}
	if err := st2.AppendCommit(prov.LineID, f1, nil, 1000); err != nil {
		t.Fatal(err)
	}
	if err := st2.AppendNonCommit(prov.LineID, HotEntry{
		Key:     k1,
		Digest:  [32]byte{0xbb},
		Outcome: StoredOutcome{Kind: "rejected", Reason: "conflict"},
	}, 1500); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.LoadLine(prov.LineID); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("LoadLine(non-commit colliding with commit): got %v, want ErrCorruptWAL", err)
	}

	// 7. WAL invariant: commit with floor < seq_time fails closed on LoadLine.
	dir3 := t.TempDir()
	st3, err := OpenFileStore(dir3)
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	if err := st3.ProvisionLine(prov); err != nil {
		t.Fatal(err)
	}
	if err := st3.AppendCommit(prov.LineID, f1, nil, 500); err != nil {
		t.Fatal(err)
	}
	if _, err := st3.LoadLine(prov.LineID); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("LoadLine(floor < seq_time): got %v, want ErrCorruptWAL", err)
	}

	// 8. Verify closed store returns ErrPreWrite on AppendCommit/AppendNonCommit/AppendCompact.
	hexID := hex.EncodeToString(prov.LineID)
	if _, err := os.Stat(filepath.Join(dir3, "lines", hexID, "wal.log")); err != nil {
		t.Fatal(err)
	}
	_ = st3.Close()
	if err := st3.AppendCommit(prov.LineID, f1, nil, 1000); !errors.Is(err, ErrPreWrite) {
		t.Fatalf("closed AppendCommit: got %v, want ErrPreWrite", err)
	}
	if err := st3.AppendNonCommit(prov.LineID, HotEntry{Key: k1, Outcome: StoredOutcome{Kind: "rejected", Reason: "conflict"}}, 1000); !errors.Is(err, ErrPreWrite) {
		t.Fatalf("closed AppendNonCommit: got %v, want ErrPreWrite", err)
	}
	if err := st3.AppendCompact(prov.LineID, []StoredOpKey{k1}, 1000); !errors.Is(err, ErrPreWrite) {
		t.Fatalf("closed AppendCompact: got %v, want ErrPreWrite", err)
	}
}

func TestFileStoreMissingWALVsIncompleteProvisioning(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	defer st.Close()

	// 1. Incomplete provisioning (directory + 0-byte wal.log, no provision.cbor):
	//    ListLines ignores it, LoadLine returns ErrLineNotFound, ProvisionLine succeeds.
	prov1 := makeTestProvision(t, 0x41)
	hex1 := hex.EncodeToString(prov1.LineID)
	dir1 := filepath.Join(dir, "lines", hex1)
	if err := os.MkdirAll(filepath.Join(dir1, "sidecars"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir1, "wal.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := st.ListLines()
	if err != nil || len(lines) != 0 {
		t.Fatalf("ListLines on incomplete provisioning: got lines=%d err=%v", len(lines), err)
	}
	if _, err := st.LoadLine(prov1.LineID); !errors.Is(err, ErrLineNotFound) {
		t.Fatalf("LoadLine on incomplete provisioning: got %v, want ErrLineNotFound", err)
	}
	if err := st.ProvisionLine(prov1); err != nil {
		t.Fatalf("ProvisionLine completing interrupted provision: %v", err)
	}

	// 2. Active/lost provision.cbor beside NON-EMPTY wal.log MUST fail closed.
	provBad := makeTestProvision(t, 0x42)
	hexBad := hex.EncodeToString(provBad.LineID)
	dirBad := filepath.Join(dir, "lines", hexBad)
	if err := os.MkdirAll(filepath.Join(dirBad, "sidecars"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirBad, "wal.log"), []byte("non-empty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListLines(); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("ListLines with non-empty WAL missing provision.cbor: got %v, want ErrCorruptWAL", err)
	}
	if err := st.ProvisionLine(provBad); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("ProvisionLine over non-empty WAL missing provision.cbor: got %v, want ErrCorruptWAL", err)
	}
	if err := os.RemoveAll(dirBad); err != nil {
		t.Fatal(err)
	}

	// 3. Lost WAL beside an existing provision.cbor MUST fail closed on LoadLine,
	//    SyncLine, and AppendCommit (never silently treated as empty or recreated!).
	if err := os.Remove(filepath.Join(dir1, "wal.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadLine(prov1.LineID); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("LoadLine with missing WAL beside provision.cbor: got %v, want ErrCorruptWAL", err)
	}
	if err := st.SyncLine(prov1.LineID); !errors.Is(err, ErrCorruptWAL) {
		t.Fatalf("SyncLine with missing WAL beside provision.cbor: got %v, want ErrCorruptWAL", err)
	}
	k1 := StoredOpKey{Generation: 1, Signer: "root:r1", SeenSeq: 0, OpID: "init-1"}
	f1 := CommittedFrame{
		Gen: 1, Seq: 1, SeqTime: 1000,
		PrevHead: prov1.GenesisAnchor, Head: [32]byte{1},
		Origin: "root", OpType: "line_init",
		IntentBytes: []byte{0x01}, IntentDigest: [32]byte{0xaa},
		OpKey: &k1,
	}
	err = st.AppendCommit(prov1.LineID, f1, nil, 1000)
	if !errors.Is(err, ErrCorruptWAL) || errors.Is(err, ErrPreWrite) {
		t.Fatalf("AppendCommit with lost WAL: got %v, want non-ErrPreWrite ErrCorruptWAL", err)
	}
}

func TestFileStoreIndependentReadVisibilityAndSyncBarrier(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	defer st.Close()

	prov := makeTestProvision(t, 0x43)
	if err := st.ProvisionLine(prov); err != nil {
		t.Fatal(err)
	}
	hexID := hex.EncodeToString(prov.LineID)
	walPath := filepath.Join(dir, "lines", hexID, "wal.log")

	// Commit seq 1 with normal sync succeeding.
	k1 := StoredOpKey{Generation: 1, Signer: "root:r1", SeenSeq: 0, OpID: "op-1"}
	f1 := CommittedFrame{
		Gen: 1, Seq: 1, SeqTime: 1000,
		PrevHead: prov.GenesisAnchor, Head: [32]byte{1},
		Origin: "root", OpType: "line_init",
		IntentBytes: []byte{0x01}, IntentDigest: [32]byte{0xaa},
		OpKey: &k1,
	}
	if err := st.AppendCommit(prov.LineID, f1, nil, 1000); err != nil {
		t.Fatal(err)
	}
	sizeAfter1, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}

	// Inject sync failure: f.Write still puts seq 2 bytes into the OS cache
	// (read-visible!), while SyncFile returns EIO (sync = FALSE).
	syncFail := true
	syncErr := errors.New("injected fsync EIO")
	st.SetSyncHooks(func(f *os.File) error {
		if syncFail {
			return syncErr
		}
		return SyncFile(f)
	}, nil)

	k2 := StoredOpKey{Generation: 1, Signer: "root:r1", SeenSeq: 1, OpID: "op-2"}
	f2 := CommittedFrame{
		Gen: 1, Seq: 2, SeqTime: 2000,
		PrevHead: f1.Head, Head: [32]byte{2},
		Origin: "root", OpType: "operator_key_authorize",
		IntentBytes: []byte{0x02}, IntentDigest: [32]byte{0xbb},
		OpKey: &k2,
	}
	if err := st.AppendCommit(prov.LineID, f2, nil, 2000); !errors.Is(err, ErrUncertainWrite) {
		t.Fatalf("AppendCommit with failing sync: got %v, want ErrUncertainWrite", err)
	}

	// Verify seq 2 bytes ARE independently readable in wal.log (page-cache visible),
	// yet LoadLine and SyncLine MUST fail closed while sync still fails!
	sizeAfter2, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if sizeAfter2.Size() <= sizeAfter1.Size() {
		t.Fatalf("expected seq 2 bytes to be visible in wal.log (size %d <= %d)", sizeAfter2.Size(), sizeAfter1.Size())
	}
	if _, err := st.LoadLine(prov.LineID); !errors.Is(err, ErrUncertainWrite) {
		t.Fatalf("LoadLine while sync failing: got %v, want ErrUncertainWrite", err)
	}
	if err := st.SyncLine(prov.LineID); !errors.Is(err, ErrUncertainWrite) {
		t.Fatalf("SyncLine while sync failing: got %v, want ErrUncertainWrite", err)
	}

	// Restore sync success -> LoadLine + SyncLine pass barrier and recover seq 2.
	syncFail = false
	snap, err := st.LoadLine(prov.LineID)
	if err != nil {
		t.Fatalf("LoadLine after sync restored: %v", err)
	}
	if len(snap.Frames) != 2 || snap.Frames[1].Seq != 2 {
		t.Fatalf("expected 2 recovered frames, got %d", len(snap.Frames))
	}
	if err := st.SyncLine(prov.LineID); err != nil {
		t.Fatalf("SyncLine after sync restored: %v", err)
	}
}
