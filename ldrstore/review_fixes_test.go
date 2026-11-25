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
