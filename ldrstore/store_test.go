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

func makeTestProvision(t *testing.T, lineByte byte) ProvisionedLine {
	t.Helper()
	r1, err := ldrcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ldrcrypto.GenerateECDSAP256Key()
	if err != nil {
		t.Fatal(err)
	}
	lineID := bytes.Repeat([]byte{lineByte}, 16)
	desc := ldrcrypto.CreationDescriptor{
		Version:    1,
		LineID:     lineID,
		Generation: 1,
		RootKeys:   []ldrcrypto.PublicKey{r1.PublicKey(), r2.PublicKey()},
		RelayOrigin: ldrcrypto.RelayOrigin{
			URL:            "https://127.0.0.1:8443",
			TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
			TLSPin:         bytes.Repeat([]byte{0xee}, 32),
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		},
		Profile: ldrcrypto.ProfileV1(),
	}
	signed, err := ldrcrypto.SignCreationDescriptor(r1, desc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	_, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ProvisionedLine{
		LineID:           lineID,
		SignedDescriptor: raw,
		DescriptorDigest: cd,
		GenesisAnchor:    genesis,
	}
}

func TestFileStorePersistenceCompactAndRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}

	// Second concurrent opener MUST fail with ErrStoreLocked.
	if _, err := OpenFileStore(dir); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("expected ErrStoreLocked on concurrent open, got %v", err)
	}

	prov := makeTestProvision(t, 0x11)
	if err := st.ProvisionLine(prov); err != nil {
		t.Fatalf("ProvisionLine: %v", err)
	}
	if err := st.ProvisionLine(prov); !errors.Is(err, ErrLineExists) {
		t.Fatalf("duplicate ProvisionLine: got %v, want ErrLineExists", err)
	}

	// Commit seq 1 (line_init) and seq 2 (payload-bearing) + seq 3 (wrap sidecars).
	k1 := StoredOpKey{Generation: 1, Signer: "root:r1", SeenSeq: 0, OpID: "init-1"}
	f1 := CommittedFrame{
		Gen: 1, Seq: 1, SeqTime: 1000,
		PrevHead: prov.GenesisAnchor, Head: [32]byte{1},
		Origin: "root", OpType: "line_init",
		IntentBytes: []byte{0x01}, IntentDigest: [32]byte{0xaa},
		OpKey: &k1,
	}
	if err := st.AppendCommit(prov.LineID, f1, nil, 1000); err != nil {
		t.Fatalf("AppendCommit(1): %v", err)
	}

	payloadData := []byte("encrypted-payload-sidecar-bytes")
	pCommit, err := ldrcrypto.CommitPayload(payloadData)
	if err != nil {
		t.Fatal(err)
	}
	k2 := StoredOpKey{Generation: 1, Signer: "cred:c1", SeenSeq: 1, OpID: "turn-1"}
	f2 := CommittedFrame{
		Gen: 1, Seq: 2, SeqTime: 2000,
		PrevHead: f1.Head, Head: [32]byte{2},
		Origin: "actor", OpType: "call_turn",
		IntentBytes: []byte{0x02}, IntentDigest: [32]byte{0xbb},
		OpKey: &k2, PayloadCommit: &pCommit,
	}
	if err := st.AppendCommit(prov.LineID, f2, map[[32]byte]SidecarBlob{
		pCommit.Digest: {Kind: SidecarPayload, Data: payloadData},
	}, 2000); err != nil {
		t.Fatalf("AppendCommit(2): %v", err)
	}

	wrapData := []byte("hpke-wrap-sidecar-bytes")
	wCommit, err := ldrcrypto.CommitWrap(wrapData)
	if err != nil {
		t.Fatal(err)
	}
	credID := [32]byte{0x33}
	k3 := StoredOpKey{Generation: 1, Signer: "op:o1", SeenSeq: 2, OpID: "act-1"}
	f3 := CommittedFrame{
		Gen: 1, Seq: 3, SeqTime: 3000,
		PrevHead: f2.Head, Head: [32]byte{3},
		Origin: "operator", OpType: "key_epoch_activate",
		IntentBytes: []byte{0x03}, IntentDigest: [32]byte{0xcc},
		OpKey:       &k3,
		WrapCommits: []ldrcrypto.WrapManifestEntry{{CredID: credID, Commit: wCommit}},
	}
	if err := st.AppendCommit(prov.LineID, f3, map[[32]byte]SidecarBlob{
		wCommit.Digest: {Kind: SidecarWrap, Data: wrapData},
	}, 3000); err != nil {
		t.Fatalf("AppendCommit(3): %v", err)
	}

	// Record a durable rejection, then compact k2 and the rejection.
	kRej := StoredOpKey{Generation: 1, Signer: "cred:c1", SeenSeq: 1, OpID: "bad-1"}
	if err := st.AppendNonCommit(prov.LineID, HotEntry{
		Key:     kRej,
		Digest:  [32]byte{0xdd},
		Outcome: StoredOutcome{Kind: "rejected", Reason: "conflict"},
	}, 3500); err != nil {
		t.Fatalf("AppendNonCommit: %v", err)
	}
	if err := st.AppendCompact(prov.LineID, []StoredOpKey{k2, kRej}, 700000); err != nil {
		t.Fatalf("AppendCompact: %v", err)
	}
	if err := st.RecordCleanShutdown(prov.LineID, 700000, 700123); err != nil {
		t.Fatalf("RecordCleanShutdown: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen and verify full state survived restart.
	st2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatalf("reopen OpenFileStore: %v", err)
	}
	defer st2.Close()

	lines, err := st2.ListLines()
	if err != nil || len(lines) != 1 || !bytes.Equal(lines[0], prov.LineID) {
		t.Fatalf("ListLines mismatch: %v, %v", lines, err)
	}
	snap, err := st2.LoadLine(prov.LineID)
	if err != nil {
		t.Fatalf("LoadLine: %v", err)
	}
	if snap.RecoveredTornTail {
		t.Fatalf("unexpected RecoveredTornTail on clean store")
	}
	if len(snap.Frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(snap.Frames))
	}
	if snap.TimeFloor != 700000 || snap.LastCleanShutdownWallMS != 700123 {
		t.Fatalf("floor/shutdown mismatch: %d / %d", snap.TimeFloor, snap.LastCleanShutdownWallMS)
	}
	// Permanent log_index MUST retain compacted k2!
	if rec, ok := snap.LogIndex[k2]; !ok || rec.Seq != 2 || rec.Digest != f2.IntentDigest {
		t.Fatalf("permanent log_index lost compacted commit k2: %+v, %v", rec, ok)
	}
	// Compacted hot entries MUST be gone and quota decremented back to 0.
	if _, exists := snap.Hot[k2]; exists {
		t.Fatalf("compacted k2 still in hot")
	}
	if _, exists := snap.Hot[kRej]; exists {
		t.Fatalf("compacted kRej still in hot")
	}
	if snap.Quota["cred:c1"] != 0 {
		t.Fatalf("expected quota 0 after compact, got %d", snap.Quota["cred:c1"])
	}
	// Uncompacted k3 remains in hot.
	if _, exists := snap.Hot[k3]; !exists {
		t.Fatalf("uncompacted k3 missing from hot")
	}
	// Sidecars readable & verified.
	gotPayload, err := st2.GetSidecar(prov.LineID, SidecarPayload, pCommit.Digest)
	if err != nil || !bytes.Equal(gotPayload, payloadData) {
		t.Fatalf("GetSidecar payload failed: %v", err)
	}
	gotWrap, err := st2.GetSidecar(prov.LineID, SidecarWrap, wCommit.Digest)
	if err != nil || !bytes.Equal(gotWrap, wrapData) {
		t.Fatalf("GetSidecar wrap failed: %v", err)
	}
}

func TestFileStoreTornTailRecoveryAndMidFileCorruptionFailClosed(t *testing.T) {
	prov := makeTestProvision(t, 0x22)
	hexID := hex.EncodeToString(prov.LineID)

	setupWithTwoCommits := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		st, err := OpenFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.ProvisionLine(prov); err != nil {
			t.Fatal(err)
		}
		for seq := uint64(1); seq <= 2; seq++ {
			k := StoredOpKey{Generation: 1, Signer: "root:r1", SeenSeq: seq - 1, OpID: "op"}
			if err := st.AppendCommit(prov.LineID, CommittedFrame{
				Gen: 1, Seq: seq, SeqTime: 1000 * seq,
				PrevHead: [32]byte{byte(seq - 1)}, Head: [32]byte{byte(seq)},
				Origin: "root", OpType: "line_init",
				IntentBytes: []byte{byte(seq)}, IntentDigest: [32]byte{byte(seq)},
				OpKey: &k,
			}, nil, 1000*seq); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("truncated_tail_header_recovered", func(t *testing.T) {
		dir := setupWithTwoCommits(t)
		walP := filepath.Join(dir, "lines", hexID, "wal.log")
		raw, _ := os.ReadFile(walP)
		// Append a partial 5-byte torn header.
		if err := os.WriteFile(walP, append(raw, 'L', 'D', 'R', 'W', 1), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := OpenFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		snap, err := st.LoadLine(prov.LineID)
		if err != nil {
			t.Fatalf("LoadLine failed on torn header tail: %v", err)
		}
		if !snap.RecoveredTornTail || len(snap.Frames) != 2 {
			t.Fatalf("expected RecoveredTornTail=true and 2 frames, got %v / %d", snap.RecoveredTornTail, len(snap.Frames))
		}
	})

	t.Run("truncated_tail_body_recovered", func(t *testing.T) {
		dir := setupWithTwoCommits(t)
		walP := filepath.Join(dir, "lines", hexID, "wal.log")
		raw, _ := os.ReadFile(walP)
		// Append a valid header claiming 100 bytes, followed by only 12 bytes.
		torn := make([]byte, walHeaderSize+12)
		copy(torn[0:4], walMagic)
		torn[4] = walVersion
		torn[5] = walKindCommit
		torn[11] = 100
		if err := os.WriteFile(walP, append(raw, torn...), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := OpenFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		snap, err := st.LoadLine(prov.LineID)
		if err != nil {
			t.Fatalf("LoadLine failed on torn body tail: %v", err)
		}
		if !snap.RecoveredTornTail || len(snap.Frames) != 2 {
			t.Fatalf("expected RecoveredTornTail=true and 2 frames, got %v / %d", snap.RecoveredTornTail, len(snap.Frames))
		}
	})

	t.Run("zeroed_tail_recovered", func(t *testing.T) {
		dir := setupWithTwoCommits(t)
		walP := filepath.Join(dir, "lines", hexID, "wal.log")
		raw, _ := os.ReadFile(walP)
		if err := os.WriteFile(walP, append(raw, make([]byte, 32)...), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := OpenFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		snap, err := st.LoadLine(prov.LineID)
		if err != nil {
			t.Fatalf("LoadLine failed on zeroed tail: %v", err)
		}
		if !snap.RecoveredTornTail || len(snap.Frames) != 2 {
			t.Fatalf("expected RecoveredTornTail=true and 2 frames, got %v / %d", snap.RecoveredTornTail, len(snap.Frames))
		}
	})

	t.Run("mid_file_bit_flip_fails_closed", func(t *testing.T) {
		dir := setupWithTwoCommits(t)
		walP := filepath.Join(dir, "lines", hexID, "wal.log")
		raw, _ := os.ReadFile(walP)
		// Flip 1 bit inside the first frame's CBOR body.
		raw[walHeaderSize+5] ^= 0x01
		if err := os.WriteFile(walP, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := OpenFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.LoadLine(prov.LineID); !errors.Is(err, ErrCorruptWAL) {
			t.Fatalf("expected ErrCorruptWAL on mid-file bit flip, got %v", err)
		}
	})

	t.Run("final_frame_crc_tamper_fails_closed", func(t *testing.T) {
		dir := setupWithTwoCommits(t)
		walP := filepath.Join(dir, "lines", hexID, "wal.log")
		raw, _ := os.ReadFile(walP)
		raw[len(raw)-1] ^= 0x01
		if err := os.WriteFile(walP, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := OpenFileStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.LoadLine(prov.LineID); !errors.Is(err, ErrCorruptWAL) {
			t.Fatalf("expected ErrCorruptWAL on tampered final CRC, got %v", err)
		}
	})

	t.Run("corrupt_or_missing_sidecar_fails_closed", func(t *testing.T) {
		dir := t.TempDir()
		st, _ := OpenFileStore(dir)
		_ = st.ProvisionLine(prov)
		data := []byte("sidecar-payload")
		commit, _ := ldrcrypto.CommitPayload(data)
		k := StoredOpKey{Generation: 1, Signer: "cred:c1", SeenSeq: 0, OpID: "p1"}
		if err := st.AppendCommit(prov.LineID, CommittedFrame{
			Gen: 1, Seq: 1, SeqTime: 1000, PrevHead: prov.GenesisAnchor, Head: [32]byte{1},
			Origin: "actor", OpType: "call_turn", IntentBytes: []byte{1}, IntentDigest: [32]byte{1},
			OpKey: &k, PayloadCommit: &commit,
		}, map[[32]byte]SidecarBlob{commit.Digest: {Kind: SidecarPayload, Data: data}}, 1000); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()

		// Corrupt sidecar file on disk -> ErrCorruptSidecar.
		scPath := filepath.Join(dir, "lines", hexID, "sidecars", "payload-"+hex.EncodeToString(commit.Digest[:]))
		_ = os.WriteFile(scPath, []byte("corrupted-bytes"), 0o600)
		st2, _ := OpenFileStore(dir)
		if _, err := st2.LoadLine(prov.LineID); !errors.Is(err, ErrCorruptSidecar) {
			t.Fatalf("expected ErrCorruptSidecar, got %v", err)
		}
		// Remove sidecar file -> ErrMissingSidecar.
		_ = os.Remove(scPath)
		if _, err := st2.LoadLine(prov.LineID); !errors.Is(err, ErrMissingSidecar) {
			t.Fatalf("expected ErrMissingSidecar, got %v", err)
		}
		_ = st2.Close()
	})
}
