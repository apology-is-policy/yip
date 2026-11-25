package ldrrelay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

// faultStore wraps a real ldrstore.Store so tests can:
//  1. Intercept LoadLine to return mutated LineSnapshots for Finding 1 & 2 tests.
//  2. Inject clean ErrPreWrite vs uncertain post-write ErrUncertainWrite faults
//     on AppendCommit / AppendNonCommit / AppendCompact for Finding 3 tests.
type faultStore struct {
	base ldrstore.Store

	mu              sync.Mutex
	loadMutator     func(*ldrstore.LineSnapshot) error
	commitFault     func(lineID []byte, fr ldrstore.CommittedFrame, sidecars map[[32]byte]ldrstore.SidecarBlob, floor uint64) error
	nonCommitFault  func(lineID []byte, entry ldrstore.HotEntry, floor uint64) error
	compactFault    func(lineID []byte, retired []ldrstore.StoredOpKey, floor uint64) error
	shutdownCounter int
}

func (f *faultStore) ProvisionLine(p ldrstore.ProvisionedLine) error {
	return f.base.ProvisionLine(p)
}
func (f *faultStore) ListLines() ([][]byte, error) {
	return f.base.ListLines()
}
func (f *faultStore) LoadLine(lineID []byte) (*ldrstore.LineSnapshot, error) {
	snap, err := f.base.LoadLine(lineID)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	mut := f.loadMutator
	f.mu.Unlock()
	if mut != nil {
		snap = cloneSnapshot(snap)
		if err := mut(snap); err != nil {
			return nil, err
		}
	}
	return snap, nil
}
func (f *faultStore) AppendCommit(lineID []byte, frame ldrstore.CommittedFrame, sidecars map[[32]byte]ldrstore.SidecarBlob, newFloor uint64) error {
	f.mu.Lock()
	fn := f.commitFault
	f.mu.Unlock()
	if fn != nil {
		return fn(lineID, frame, sidecars, newFloor)
	}
	return f.base.AppendCommit(lineID, frame, sidecars, newFloor)
}
func (f *faultStore) AppendNonCommit(lineID []byte, entry ldrstore.HotEntry, newFloor uint64) error {
	f.mu.Lock()
	fn := f.nonCommitFault
	f.mu.Unlock()
	if fn != nil {
		return fn(lineID, entry, newFloor)
	}
	return f.base.AppendNonCommit(lineID, entry, newFloor)
}
func (f *faultStore) AppendCompact(lineID []byte, retired []ldrstore.StoredOpKey, newFloor uint64) error {
	f.mu.Lock()
	fn := f.compactFault
	f.mu.Unlock()
	if fn != nil {
		return fn(lineID, retired, newFloor)
	}
	return f.base.AppendCompact(lineID, retired, newFloor)
}
func (f *faultStore) RecordCleanShutdown(lineID []byte, floor, wallMS uint64) error {
	f.mu.Lock()
	f.shutdownCounter++
	f.mu.Unlock()
	return f.base.RecordCleanShutdown(lineID, floor, wallMS)
}
func (f *faultStore) GetSidecar(lineID []byte, kind string, digest [32]byte) ([]byte, error) {
	return f.base.GetSidecar(lineID, kind, digest)
}
func (f *faultStore) Close() error {
	return f.base.Close()
}

func cloneSnapshot(in *ldrstore.LineSnapshot) *ldrstore.LineSnapshot {
	out := &ldrstore.LineSnapshot{
		Provisioned:             in.Provisioned,
		Frames:                  make([]ldrstore.CommittedFrame, len(in.Frames)),
		LogIndex:                make(map[ldrstore.StoredOpKey]ldrstore.CommittedReceipt, len(in.LogIndex)),
		Hot:                     make(map[ldrstore.StoredOpKey]ldrstore.HotEntry, len(in.Hot)),
		Quota:                   make(map[string]int, len(in.Quota)),
		TimeFloor:               in.TimeFloor,
		LastCleanShutdownWallMS: in.LastCleanShutdownWallMS,
		RecoveredTornTail:       in.RecoveredTornTail,
	}
	for i, fr := range in.Frames {
		c := fr
		c.IntentBytes = bytes.Clone(fr.IntentBytes)
		if fr.OpKey != nil {
			k := *fr.OpKey
			c.OpKey = &k
		}
		if fr.PayloadCommit != nil {
			pc := *fr.PayloadCommit
			c.PayloadCommit = &pc
		}
		if len(fr.WrapCommits) > 0 {
			c.WrapCommits = append([]ldrcrypto.WrapManifestEntry(nil), fr.WrapCommits...)
		}
		out.Frames[i] = c
	}
	for k, v := range in.LogIndex {
		out.LogIndex[k] = v
	}
	for k, v := range in.Hot {
		out.Hot[k] = v
	}
	for k, v := range in.Quota {
		out.Quota[k] = v
	}
	return out
}

// recomputeChainHeads updates PrevHead/Head across snap.Frames so mutated frames
// still satisfy cryptographic chain linkage — proving that startup replay
// catches admission/metadata bugs directly rather than relying on head mismatch.
func recomputeChainHeads(t *testing.T, snap *ldrstore.LineSnapshot, profDigest [32]byte) {
	t.Helper()
	prev := snap.Provisioned.GenesisAnchor
	for i := range snap.Frames {
		fr := &snap.Frames[i]
		fr.PrevHead = prev
		var err error
		if fr.Origin == ldrcore.OriginSequencer {
			fr.Head, err = ldrcrypto.AnchorChainHead(prev, profDigest, snap.Provisioned.LineID, fr.Gen, fr.Seq, fr.SeqTime)
		} else {
			fr.Head, err = ldrcrypto.ClientChainHead(prev, profDigest, snap.Provisioned.LineID, fr.Gen, fr.Seq, fr.SeqTime, fr.Origin, fr.IntentBytes)
		}
		if err != nil {
			t.Fatalf("recomputeChainHeads(seq %d): %v", fr.Seq, err)
		}
		prev = fr.Head
	}
}

type engineTestRig struct {
	dir        string
	baseStore  *ldrstore.FileStore
	fs         *faultStore
	clock      *fakeClock
	engine     *RelayEngine
	lineID     []byte
	root1      *ldrcrypto.Ed25519PrivateKey
	root2      *ldrcrypto.ECDSAP256PrivateKey
	opKey      *ldrcrypto.ECDSAP256PrivateKey
	desc       ldrcrypto.CreationDescriptor
	cd         [32]byte
	genesis    [32]byte
	profDigest [32]byte
	head1      [32]byte
	head2      [32]byte
	op2Key     ldrstore.StoredOpKey
	op2Digest  [32]byte
}

func newEngineTestRig(t *testing.T) *engineTestRig {
	t.Helper()
	dir := t.TempDir()
	st, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	fs := &faultStore{base: st}
	fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
	eng, err := NewRelayEngine(fs, DefaultClockConfig(), fc.source())
	if err != nil {
		t.Fatalf("NewRelayEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Shutdown() })

	root1, _ := ldrcrypto.GenerateEd25519Key()
	root2, _ := ldrcrypto.GenerateECDSAP256Key()
	opKey, _ := ldrcrypto.GenerateECDSAP256Key()
	lineID := bytes.Repeat([]byte{0x55}, 16)
	prof := ldrcrypto.ProfileV1()
	profDigest, _ := prof.Digest()
	desc := ldrcrypto.CreationDescriptor{
		Version:    1,
		LineID:     lineID,
		Generation: 1,
		RootKeys:   []ldrcrypto.PublicKey{root1.PublicKey(), root2.PublicKey()},
		RelayOrigin: ldrcrypto.RelayOrigin{
			URL:            "https://127.0.0.1:8443",
			TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
			TLSPin:         bytes.Repeat([]byte{0xab}, 32),
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		},
		Profile: prof,
	}
	signedDesc, err := ldrcrypto.SignCreationDescriptor(root1, desc)
	if err != nil {
		t.Fatal(err)
	}
	rawDesc, err := signedDesc.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := eng.Provision(rawDesc)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Seq 1: line_init
	root1Prin := ldrcrypto.RootPrincipal(root1.PublicKey())
	sortedRoots, _ := ldrcrypto.CanonicalRootKeys([]ldrcrypto.PublicKey{root1.PublicKey(), root2.PublicKey()})
	rk0, _ := sortedRoots[0].ToCBOR()
	rk1, _ := sortedRoots[1].ToCBOR()
	profMap, _ := prof.ToCBORMap()
	initEnv := signWireIntent(t, root1, WireIntentInput{
		ProfileDigest: profDigest, LineID: lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root1Prin,
		OpID: "init-1", OpType: "line_init",
		SeenSeq: 0, SeenHead: prov.GenesisAnchor, ValidityMS: 0,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: prov.DescriptorDigest[:]},
			{Key: "profile", Value: profMap},
			{Key: "root_keys", Value: []any{rk0, rk1}},
		},
	})
	rep1 := eng.Submit(lineID, root1Prin, initEnv.RawBytes, nil, nil)
	if rep1.Outcome.Kind != ldrcore.Committed || rep1.Outcome.Seq != 1 {
		t.Fatalf("line_init failed: %+v", rep1)
	}

	// Seq 2: operator_key_authorize
	fc.wall += 1000
	fc.mono += 1000
	root2Prin := ldrcrypto.RootPrincipal(root2.PublicKey())
	opCBOR, _ := opKey.PublicKey().ToCBOR()
	opEnv := signWireIntent(t, root2, WireIntentInput{
		ProfileDigest: profDigest, LineID: lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root2Prin,
		OpID: "auth-op-1", OpType: "operator_key_authorize",
		AuthEpoch: 0, SeenSeq: 1, SeenHead: rep1.Head, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"root_rev": 1},
		Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
	})
	rep2 := eng.Submit(lineID, root2Prin, opEnv.RawBytes, nil, nil)
	if rep2.Outcome.Kind != ldrcore.Committed || rep2.Outcome.Seq != 2 {
		t.Fatalf("operator_key_authorize failed: %+v", rep2)
	}
	op2Tok, _ := PrincipalToken(root2Prin)
	op2Dig, _ := opEnv.Digest()

	return &engineTestRig{
		dir: dir, baseStore: st, fs: fs, clock: fc, engine: eng,
		lineID: lineID, root1: root1, root2: root2, opKey: opKey,
		desc: desc, cd: prov.DescriptorDigest, genesis: prov.GenesisAnchor, profDigest: profDigest,
		head1: rep1.Head, head2: rep2.Head,
		op2Key:    ldrstore.StoredOpKey{Generation: 1, Signer: op2Tok, SeenSeq: 1, OpID: "auth-op-1"},
		op2Digest: op2Dig,
	}
}

func (rig *engineTestRig) signOp(t *testing.T, signer ldrcrypto.Signer, in WireIntentInput) (ldrcrypto.SignedIntent, ldrstore.StoredOpKey, [32]byte) {
	t.Helper()
	env := signWireIntent(t, signer, in)
	dig, err := env.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := PrincipalToken(in.Principal)
	if err != nil {
		t.Fatal(err)
	}
	return env, ldrstore.StoredOpKey{
		Generation: in.Generation,
		Signer:     tok,
		SeenSeq:    in.SeenSeq,
		OpID:       in.OpID,
	}, dig
}

// TestStartupReplayHistoricalAdmissionParity verifies Codex Finding 1:
// startup replay enforces the same historical admission invariants as live Submit.
func TestStartupReplayHistoricalAdmissionParity(t *testing.T) {
	rig := newEngineTestRig(t)

	root1Prin := ldrcrypto.RootPrincipal(rig.root1.PublicKey())
	root2Prin := ldrcrypto.RootPrincipal(rig.root2.PublicKey())
	sortedRoots, _ := ldrcrypto.CanonicalRootKeys([]ldrcrypto.PublicKey{rig.root1.PublicKey(), rig.root2.PublicKey()})
	rk0, _ := sortedRoots[0].ToCBOR()
	rk1, _ := sortedRoots[1].ToCBOR()
	profMap, _ := rig.desc.Profile.ToCBORMap()
	opCBOR, _ := rig.opKey.PublicKey().ToCBOR()

	// Control: unmodified snapshot loads cleanly.
	t.Run("baseline_clean_snapshot_succeeds", func(t *testing.T) {
		fs := &faultStore{base: rig.baseStore}
		if _, err := NewRelayEngine(fs, DefaultClockConfig(), rig.clock.source()); err != nil {
			t.Fatalf("clean replay failed: %v", err)
		}
	})

	cases := []struct {
		name   string
		mutate func(t *testing.T, snap *ldrstore.LineSnapshot)
	}{
		{
			name: "wrong_line_id_in_signed_intent",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				otherLine := bytes.Repeat([]byte{0x99}, 16)
				env, k, dig := rig.signOp(t, rig.root2, WireIntentInput{
					ProfileDigest: rig.profDigest, LineID: otherLine, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root2Prin,
					OpID: "auth-op-1", OpType: "operator_key_authorize",
					AuthEpoch: 0, SeenSeq: 1, SeenHead: rig.head1, ValidityMS: 60_000,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Expect:        ldrcrypto.ExpectMap{"root_rev": 1},
					Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
				})
				snap.Frames[1].IntentBytes = env.RawBytes
				snap.Frames[1].IntentDigest = dig
				snap.Frames[1].OpKey = &k
				snap.LogIndex[k] = ldrstore.CommittedReceipt{Seq: 2, Digest: dig}
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "wrong_profile_digest_in_signed_intent",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				badPD := rig.profDigest
				badPD[0] ^= 0xff
				env, k, dig := rig.signOp(t, rig.root2, WireIntentInput{
					ProfileDigest: badPD, LineID: rig.lineID, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root2Prin,
					OpID: "auth-op-1", OpType: "operator_key_authorize",
					AuthEpoch: 0, SeenSeq: 1, SeenHead: rig.head1, ValidityMS: 60_000,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Expect:        ldrcrypto.ExpectMap{"root_rev": 1},
					Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
				})
				snap.Frames[1].IntentBytes = env.RawBytes
				snap.Frames[1].IntentDigest = dig
				snap.Frames[1].OpKey = &k
				snap.LogIndex[k] = ldrstore.CommittedReceipt{Seq: 2, Digest: dig}
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "line_init_wrong_descriptor_digest",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				badCD := rig.cd
				badCD[0] ^= 0x01
				env, k, dig := rig.signOp(t, rig.root1, WireIntentInput{
					ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root1Prin,
					OpID: "init-1", OpType: "line_init",
					SeenSeq: 0, SeenHead: rig.genesis, ValidityMS: 0,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Fields: ldrcrypto.Map{
						{Key: "descriptor_digest", Value: badCD[:]},
						{Key: "profile", Value: profMap},
						{Key: "root_keys", Value: []any{rk0, rk1}},
					},
				})
				snap.Frames = snap.Frames[:1]
				snap.Frames[0].IntentBytes = env.RawBytes
				snap.Frames[0].IntentDigest = dig
				snap.Frames[0].OpKey = &k
				snap.LogIndex = map[ldrstore.StoredOpKey]ldrstore.CommittedReceipt{k: {Seq: 1, Digest: dig}}
				snap.Hot = map[ldrstore.StoredOpKey]ldrstore.HotEntry{}
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "line_init_wrong_seen_head",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				badGenesis := rig.genesis
				badGenesis[0] ^= 0x01
				env, k, dig := rig.signOp(t, rig.root1, WireIntentInput{
					ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root1Prin,
					OpID: "init-1", OpType: "line_init",
					SeenSeq: 0, SeenHead: badGenesis, ValidityMS: 0,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Fields: ldrcrypto.Map{
						{Key: "descriptor_digest", Value: rig.cd[:]},
						{Key: "profile", Value: profMap},
						{Key: "root_keys", Value: []any{rk0, rk1}},
					},
				})
				snap.Frames = snap.Frames[:1]
				snap.Frames[0].IntentBytes = env.RawBytes
				snap.Frames[0].IntentDigest = dig
				snap.Frames[0].OpKey = &k
				snap.LogIndex = map[ldrstore.StoredOpKey]ldrstore.CommittedReceipt{k: {Seq: 1, Digest: dig}}
				snap.Hot = map[ldrstore.StoredOpKey]ldrstore.HotEntry{}
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "line_init_wrong_root_keys",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				rogue, _ := ldrcrypto.GenerateEd25519Key()
				rogueSorted, _ := ldrcrypto.CanonicalRootKeys([]ldrcrypto.PublicKey{rig.root1.PublicKey(), rogue.PublicKey()})
				rr0, _ := rogueSorted[0].ToCBOR()
				rr1, _ := rogueSorted[1].ToCBOR()
				env, k, dig := rig.signOp(t, rig.root1, WireIntentInput{
					ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root1Prin,
					OpID: "init-1", OpType: "line_init",
					SeenSeq: 0, SeenHead: rig.genesis, ValidityMS: 0,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Fields: ldrcrypto.Map{
						{Key: "descriptor_digest", Value: rig.cd[:]},
						{Key: "profile", Value: profMap},
						{Key: "root_keys", Value: []any{rr0, rr1}},
					},
				})
				snap.Frames = snap.Frames[:1]
				snap.Frames[0].IntentBytes = env.RawBytes
				snap.Frames[0].IntentDigest = dig
				snap.Frames[0].OpKey = &k
				snap.LogIndex = map[ldrstore.StoredOpKey]ldrstore.CommittedReceipt{k: {Seq: 1, Digest: dig}}
				snap.Hot = map[ldrstore.StoredOpKey]ldrstore.HotEntry{}
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "ordinary_frame_wrong_seen_head",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				badHead := rig.head1
				badHead[0] ^= 0xff
				env, k, dig := rig.signOp(t, rig.root2, WireIntentInput{
					ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root2Prin,
					OpID: "auth-op-bad-head", OpType: "operator_key_authorize",
					AuthEpoch: 0, SeenSeq: 1, SeenHead: badHead, ValidityMS: 60_000,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Expect:        ldrcrypto.ExpectMap{"root_rev": 1},
					Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
				})
				delete(snap.LogIndex, rig.op2Key)
				delete(snap.Hot, rig.op2Key)
				snap.Frames[1].IntentBytes = env.RawBytes
				snap.Frames[1].IntentDigest = dig
				snap.Frames[1].OpKey = &k
				snap.LogIndex[k] = ldrstore.CommittedReceipt{Seq: 2, Digest: dig}
				snap.Hot[k] = ldrstore.HotEntry{Key: k, Digest: dig, Outcome: ldrstore.StoredOutcome{Kind: ldrcore.Committed, Seq: 2}}
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "ordinary_frame_expired_at_commit_time",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				// Frame 2 has ValidityMS = 60_000 anchored at Frame 1's SeqTime.
				// Move Frame 2's SeqTime 1 ms past anchorTime + 60_000 (and update floor).
				snap.Frames[1].SeqTime = snap.Frames[0].SeqTime + 60_001
				snap.TimeFloor = snap.Frames[1].SeqTime
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "duplicate_committed_op_key",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				opKey2, _ := ldrcrypto.GenerateEd25519Key()
				opCBOR2, _ := opKey2.PublicKey().ToCBOR()
				// Same (Gen, Signer, SeenSeq=1, OpID="auth-op-1") as seq 2!
				env, k, dig := rig.signOp(t, rig.root2, WireIntentInput{
					ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
					Origin: ldrcore.OriginRoot, Principal: root2Prin,
					OpID: "auth-op-1", OpType: "operator_key_authorize",
					AuthEpoch: 1, SeenSeq: 1, SeenHead: rig.head1, ValidityMS: 60_000,
					PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
					Expect:        ldrcrypto.ExpectMap{"root_rev": 2},
					Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR2}},
				})
				fr3 := ldrstore.CommittedFrame{
					Gen: 1, Seq: 3, SeqTime: snap.Frames[1].SeqTime + 1000,
					Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
					IntentBytes: env.RawBytes, IntentDigest: dig, OpKey: &k,
				}
				snap.Frames = append(snap.Frames, fr3)
				snap.TimeFloor = fr3.SeqTime
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
		{
			name: "time_anchor_carries_op_key",
			mutate: func(t *testing.T, snap *ldrstore.LineSnapshot) {
				k := ldrstore.StoredOpKey{Generation: 1, Signer: "seq", SeenSeq: 2, OpID: "bad"}
				fr3 := ldrstore.CommittedFrame{
					Gen: 1, Seq: 3, SeqTime: snap.Frames[1].SeqTime + 1000,
					Origin: ldrcore.OriginSequencer, OpType: "time_anchor",
					OpKey: &k,
				}
				snap.Frames = append(snap.Frames, fr3)
				snap.TimeFloor = fr3.SeqTime
				recomputeChainHeads(t, snap, rig.profDigest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &faultStore{
				base: rig.baseStore,
				loadMutator: func(snap *ldrstore.LineSnapshot) error {
					tc.mutate(t, snap)
					return nil
				},
			}
			_, err := NewRelayEngine(fs, DefaultClockConfig(), rig.clock.source())
			if !errors.Is(err, ldrstore.ErrCorruptWAL) {
				t.Fatalf("case %s: expected ErrCorruptWAL, got %v", tc.name, err)
			}
		})
	}
}

// TestStartupReplayWALMetadataAndIndexVerification verifies Codex Finding 2:
// startup verifies WAL metadata against IntentBytes (including real PayloadCommit
// and WrapCommits), derives permanent logIndex from verified frames, validates
// snap.Hot + quota, and preserves valid durable rejections/no-ops across restarts.
func TestStartupReplayWALMetadataAndIndexVerification(t *testing.T) {
	rig := newEngineTestRig(t)

	root2Prin := ldrcrypto.RootPrincipal(rig.root2.PublicKey())
	opPrin := ldrcrypto.OperatorPrincipal(rig.opKey.PublicKey())

	// Seq 3: credential_enroll (so we can activate epoch 1 with a real wrap sidecar
	// and commit a payload-bearing broadcast + duplicate broadcast_read for a real Noop).
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	credSig, _ := ldrcrypto.GenerateEd25519Key()
	credEnc, _ := ldrcrypto.GenerateX25519Key()
	credID, err := ldrcrypto.DeriveCredID(credSig.PublicKey(), credEnc.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	credPrin := ldrcrypto.CredentialPrincipal(credID)
	sigCBOR, _ := credSig.PublicKey().ToCBOR()
	encCBOR, _ := credEnc.PublicKey().ToCBOR()
	enrollEnv, _, _ := rig.signOp(t, rig.opKey, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "enroll-1", OpType: "credential_enroll",
		AuthEpoch: 1, SeenSeq: 2, SeenHead: rig.head2, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "cred_id", Value: credID[:]},
			{Key: "encryption_key", Value: encCBOR},
			{Key: "grant", Value: ldrcrypto.Map{
				{Key: "actor_limit", Value: uint64(2)},
				{Key: "namespace_id", Value: "ns-a"},
				{Key: "reader", Value: true},
			}},
			{Key: "join_request_digest", Value: bytes.Repeat([]byte{0x12}, 32)},
			{Key: "join_request_id", Value: []byte("jr-1")},
			{Key: "signing_key", Value: sigCBOR},
		},
	})
	repEnroll := rig.engine.Submit(rig.lineID, opPrin, enrollEnv.RawBytes, nil, nil)
	if repEnroll.Outcome.Kind != ldrcore.Committed || repEnroll.Outcome.Seq != 3 {
		t.Fatalf("credential_enroll failed: %+v", repEnroll)
	}
	head3 := repEnroll.Head

	// Seq 4: key_epoch_activate (carries a real WrapCommits entry!).
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	wrapBlob := []byte("wrapped-epoch-1-key-material")
	wrapCommit, err := ldrcrypto.CommitWrap(wrapBlob)
	if err != nil {
		t.Fatal(err)
	}
	actEnv, _, _ := rig.signOp(t, rig.opKey, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "act-1", OpType: "key_epoch_activate",
		AuthEpoch: 2, KeyEpoch: 0, SeenSeq: 3, SeenHead: head3, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"key_epoch": 0},
		Manifest:      []ldrcrypto.WrapManifestEntry{{CredID: credID, Commit: wrapCommit}},
	})
	repAct := rig.engine.Submit(rig.lineID, opPrin, actEnv.RawBytes, nil, map[[32]byte][]byte{credID: wrapBlob})
	if repAct.Outcome.Kind != ldrcore.Committed || repAct.Outcome.Seq != 4 {
		t.Fatalf("key_epoch_activate failed: %+v", repAct)
	}
	head4 := repAct.Head

	// Seq 5: actor_declare (by enrolled credential).
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	declEnv, _, _ := rig.signOp(t, credSig, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginCredential, Principal: credPrin,
		OpID: "decl-1", OpType: "actor_declare",
		AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 4, SeenHead: head4, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "actor_id", Value: "ns-a/alice"},
			{Key: "label", Value: false},
			{Key: "namespace_id", Value: "ns-a"},
		},
	})
	repDecl := rig.engine.Submit(rig.lineID, credPrin, declEnv.RawBytes, nil, nil)
	if repDecl.Outcome.Kind != ldrcore.Committed || repDecl.Outcome.Seq != 5 {
		t.Fatalf("actor_declare failed: %+v", repDecl)
	}
	head5 := repDecl.Head

	// Seq 6: broadcast_create (carries a real PayloadCommit!).
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	payloadBlob := []byte("encrypted-broadcast-body-bytes")
	payloadCommit, err := ldrcrypto.CommitPayload(payloadBlob)
	if err != nil {
		t.Fatal(err)
	}
	bcEnv, _, _ := rig.signOp(t, rig.opKey, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "bc-1", OpType: "broadcast_create",
		AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 5, SeenHead: head5, ValidityMS: 60_000,
		PayloadCommit: payloadCommit,
		Fields: ldrcrypto.Map{
			{Key: "broadcast_id", Value: "b-1"},
			{Key: "default_audience", Value: false},
			{Key: "kind", Value: "briefing"},
			{Key: "recipients", Value: []any{"ns-a/alice"}},
		},
	})
	repBC := rig.engine.Submit(rig.lineID, opPrin, bcEnv.RawBytes, payloadBlob, nil)
	if repBC.Outcome.Kind != ldrcore.Committed || repBC.Outcome.Seq != 6 {
		t.Fatalf("broadcast_create failed: %+v", repBC)
	}
	head6 := repBC.Head

	// Seq 7: broadcast_read #1 (commits receipt).
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	read1Env, _, _ := rig.signOp(t, credSig, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginActor, Principal: credPrin,
		ActorID: "ns-a/alice", BindingGen: 1,
		OpID: "br-1", OpType: "broadcast_read",
		AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 6, SeenHead: head6, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "broadcast_id", Value: "b-1"}},
	})
	repRead1 := rig.engine.Submit(rig.lineID, credPrin, read1Env.RawBytes, nil, nil)
	if repRead1.Outcome.Kind != ldrcore.Committed || repRead1.Outcome.Seq != 7 {
		t.Fatalf("broadcast_read(1) failed: %+v", repRead1)
	}
	head7 := repRead1.Head

	// Genuine durable Noop: broadcast_read #2 by the same recipient!
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	noopEnv, noopKey, noopDig := rig.signOp(t, credSig, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginActor, Principal: credPrin,
		ActorID: "ns-a/alice", BindingGen: 1,
		OpID: "br-2-noop", OpType: "broadcast_read",
		AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 7, SeenHead: head7, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "broadcast_id", Value: "b-1"}},
	})
	repNoop := rig.engine.Submit(rig.lineID, credPrin, noopEnv.RawBytes, nil, nil)
	if repNoop.Outcome.Kind != ldrcore.Noop || repNoop.Outcome.RefSeq != 7 {
		t.Fatalf("expected Noop(RefSeq=7) on second broadcast_read, got %+v", repNoop)
	}

	// Genuine durable Rejection: operator_key_authorize with stale root_rev=0.
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	otherOp, _ := ldrcrypto.GenerateEd25519Key()
	otherOpCBOR, _ := otherOp.PublicKey().ToCBOR()
	rejEnv, rejKey, rejDig := rig.signOp(t, rig.root2, WireIntentInput{
		ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root2Prin,
		OpID: "rej-stale-expect", OpType: "operator_key_authorize",
		AuthEpoch: 2, SeenSeq: 7, SeenHead: head7, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"root_rev": 0},
		Fields:        ldrcrypto.Map{{Key: "operator_key", Value: otherOpCBOR}},
	})
	repRej := rig.engine.Submit(rig.lineID, root2Prin, rejEnv.RawBytes, nil, nil)
	if repRej.Outcome.Kind != ldrcore.Rejected {
		t.Fatalf("expected Rejected, got %+v", repRej)
	}

	// Positive test: clean restart preserves both durable Rejected and Noop!
	t.Run("valid_durable_rejection_and_noop_survive_verified_restart", func(t *testing.T) {
		eng2, err := NewRelayEngine(&faultStore{base: rig.baseStore}, DefaultClockConfig(), rig.clock.source())
		if err != nil {
			t.Fatalf("restart failed: %v", err)
		}
		qRej := eng2.Query(rig.lineID, root2Prin, rejKey, rejDig)
		if qRej.Class != ldrcore.ClassOutcome || qRej.Outcome.Kind != ldrcore.Rejected || !qRej.Original {
			t.Fatalf("durable rejection lost on restart: %+v", qRej)
		}
		qNoop := eng2.Query(rig.lineID, credPrin, noopKey, noopDig)
		if qNoop.Class != ldrcore.ClassOutcome || qNoop.Outcome.Kind != ldrcore.Noop || qNoop.Outcome.RefSeq != 7 || !qNoop.Original {
			t.Fatalf("durable noop lost on restart: %+v", qNoop)
		}
	})

	cases := []struct {
		name   string
		mutate func(snap *ldrstore.LineSnapshot)
	}{
		{
			name: "frame_stored_op_key_mismatch",
			mutate: func(snap *ldrstore.LineSnapshot) {
				badKey := *snap.Frames[1].OpKey
				badKey.OpID = "tampered-op-id"
				snap.Frames[1].OpKey = &badKey
			},
		},
		{
			name: "frame_stored_intent_digest_mismatch",
			mutate: func(snap *ldrstore.LineSnapshot) {
				snap.Frames[1].IntentDigest[0] ^= 0x01
			},
		},
		{
			name: "frame_stored_op_type_mismatch",
			mutate: func(snap *ldrstore.LineSnapshot) {
				snap.Frames[1].OpType = "operator_key_revoke"
			},
		},
		{
			name: "frame_unexpected_payload_commit",
			mutate: func(snap *ldrstore.LineSnapshot) {
				c := ldrcrypto.Commitment{Length: 10, Digest: [32]byte{0xaa}}
				snap.Frames[1].PayloadCommit = &c
			},
		},
		{
			name: "frame_tampered_real_payload_commit",
			mutate: func(snap *ldrstore.LineSnapshot) {
				// Frame index 5 (seq 6) is broadcast_create with real PayloadCommit.
				snap.Frames[5].PayloadCommit.Digest[0] ^= 0xff
			},
		},
		{
			name: "frame_tampered_real_wrap_commits",
			mutate: func(snap *ldrstore.LineSnapshot) {
				// Frame index 3 (seq 4) is key_epoch_activate with real WrapCommits.
				snap.Frames[3].WrapCommits[0].Commit.Digest[0] ^= 0xff
			},
		},
		{
			name: "frame_unexpected_wrap_commits",
			mutate: func(snap *ldrstore.LineSnapshot) {
				snap.Frames[1].WrapCommits = []ldrcrypto.WrapManifestEntry{
					{CredID: [32]byte{1}, Commit: ldrcrypto.Commitment{Length: 5, Digest: [32]byte{2}}},
				}
			},
		},
		{
			name: "log_index_extra_phantom_entry",
			mutate: func(snap *ldrstore.LineSnapshot) {
				phantom := ldrstore.StoredOpKey{Generation: 1, Signer: "root:ghost", SeenSeq: 1, OpID: "ghost"}
				snap.LogIndex[phantom] = ldrstore.CommittedReceipt{Seq: 99, Digest: [32]byte{0xee}}
			},
		},
		{
			name: "log_index_missing_entry",
			mutate: func(snap *ldrstore.LineSnapshot) {
				delete(snap.LogIndex, rig.op2Key)
			},
		},
		{
			name: "log_index_wrong_seq",
			mutate: func(snap *ldrstore.LineSnapshot) {
				rec := snap.LogIndex[rig.op2Key]
				rec.Seq = 99
				snap.LogIndex[rig.op2Key] = rec
			},
		},
		{
			name: "hot_committed_entry_wrong_digest",
			mutate: func(snap *ldrstore.LineSnapshot) {
				he := snap.Hot[rig.op2Key]
				he.Digest[0] ^= 0xff
				snap.Hot[rig.op2Key] = he
			},
		},
		{
			name: "hot_contains_line_init",
			mutate: func(snap *ldrstore.LineSnapshot) {
				k1 := *snap.Frames[0].OpKey
				snap.Hot[k1] = ldrstore.HotEntry{
					Key:     k1,
					Digest:  snap.Frames[0].IntentDigest,
					Outcome: ldrstore.StoredOutcome{Kind: ldrcore.Committed, Seq: 1},
				}
			},
		},
		{
			name: "hot_non_commit_collides_with_committed",
			mutate: func(snap *ldrstore.LineSnapshot) {
				snap.Hot[rig.op2Key] = ldrstore.HotEntry{
					Key:     rig.op2Key,
					Digest:  rig.op2Digest,
					Outcome: ldrstore.StoredOutcome{Kind: ldrcore.Rejected, Reason: "conflict"},
				}
				snap.Quota[rig.op2Key.Signer]++
			},
		},
		{
			name: "hot_non_commit_nonzero_seq",
			mutate: func(snap *ldrstore.LineSnapshot) {
				he := snap.Hot[rejKey]
				he.Outcome.Seq = 9
				snap.Hot[rejKey] = he
			},
		},
		{
			name: "hot_quota_mismatch",
			mutate: func(snap *ldrstore.LineSnapshot) {
				snap.Quota[rejKey.Signer] += 5
			},
		},
		{
			name: "hot_invalid_outcome_kind",
			mutate: func(snap *ldrstore.LineSnapshot) {
				he := snap.Hot[rejKey]
				he.Outcome.Kind = "bogus_kind"
				snap.Hot[rejKey] = he
			},
		},
		{
			name: "hot_unknown_seen_seq",
			mutate: func(snap *ldrstore.LineSnapshot) {
				bad := ldrstore.StoredOpKey{Generation: 1, Signer: rejKey.Signer, SeenSeq: 999, OpID: "bad-anchor"}
				snap.Hot[bad] = ldrstore.HotEntry{
					Key:     bad,
					Digest:  [32]byte{0xde},
					Outcome: ldrstore.StoredOutcome{Kind: ldrcore.Rejected, Reason: "conflict"},
				}
				snap.Quota[bad.Signer]++
			},
		},
		{
			name: "time_floor_below_max_commit_time",
			mutate: func(snap *ldrstore.LineSnapshot) {
				snap.TimeFloor = snap.Frames[len(snap.Frames)-1].SeqTime - 1
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &faultStore{
				base: rig.baseStore,
				loadMutator: func(snap *ldrstore.LineSnapshot) error {
					tc.mutate(snap)
					return nil
				},
			}
			_, err := NewRelayEngine(fs, DefaultClockConfig(), rig.clock.source())
			if !errors.Is(err, ldrstore.ErrCorruptWAL) {
				t.Fatalf("case %s: expected ErrCorruptWAL, got %v", tc.name, err)
			}
		})
	}
}

// TestStorageErrorQuarantineAndReconcile verifies Codex Finding 3:
// clean ErrPreWrite refusals keep the line open; uncertain post-write/sync
// failures immediately quarantine the line across all operations until
// ReconcileLine reloads and verifies durable storage.
func TestStorageErrorQuarantineAndReconcile(t *testing.T) {
	makeAuthOp := func(t *testing.T, rig *engineTestRig, opID string, authEpoch, rootRev, seenSeq uint64, seenHead [32]byte) (ldrcrypto.Principal, ldrcrypto.SignedIntent, ldrstore.StoredOpKey, [32]byte) {
		t.Helper()
		root2Prin := ldrcrypto.RootPrincipal(rig.root2.PublicKey())
		extraOp, _ := ldrcrypto.GenerateEd25519Key()
		extraCBOR, _ := extraOp.PublicKey().ToCBOR()
		env, k, dig := rig.signOp(t, rig.root2, WireIntentInput{
			ProfileDigest: rig.profDigest, LineID: rig.lineID, Generation: 1,
			Origin: ldrcore.OriginRoot, Principal: root2Prin,
			OpID: opID, OpType: "operator_key_authorize",
			AuthEpoch: authEpoch, SeenSeq: seenSeq, SeenHead: seenHead, ValidityMS: 60_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Expect:        ldrcrypto.ExpectMap{"root_rev": rootRev},
			Fields:        ldrcrypto.Map{{Key: "operator_key", Value: extraCBOR}},
		})
		return root2Prin, env, k, dig
	}

	t.Run("pre_write_failure_does_not_quarantine", func(t *testing.T) {
		rig := newEngineTestRig(t)

		rig.fs.mu.Lock()
		rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
			return fmt.Errorf("%w: injected pre-write refusal", ldrstore.ErrPreWrite)
		}
		rig.fs.mu.Unlock()

		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env, _, _ := makeAuthOp(t, rig, "auth-prewrite", 1, 2, 2, rig.head2)
		rep := rig.engine.Submit(rig.lineID, root2Prin, env.RawBytes, nil, nil)
		if rep.Class != ldrcore.ClassAdmission || rep.Code != "storage_error" {
			t.Fatalf("expected admission/storage_error, got %+v", rep)
		}
		if st := rig.engine.Status()[0]; st.Quarantined {
			t.Fatalf("clean ErrPreWrite must NOT quarantine line, got %+v", st)
		}

		// Clear fault and verify retry commits cleanly without reconciliation!
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.mu.Unlock()

		repOK := rig.engine.Submit(rig.lineID, root2Prin, env.RawBytes, nil, nil)
		if repOK.Outcome.Kind != ldrcore.Committed || repOK.Outcome.Seq != 3 {
			t.Fatalf("retry after ErrPreWrite failed: %+v", repOK)
		}
	})

	t.Run("uncertain_commit_quarantines_and_reconcile_recovers_persisted_frame", func(t *testing.T) {
		rig := newEngineTestRig(t)
		opPrin := ldrcrypto.OperatorPrincipal(rig.opKey.PublicKey())

		// Simulate the exact dangerous case: WAL write landed on disk, then F_FULLFSYNC errored!
		rig.fs.mu.Lock()
		rig.fs.commitFault = func(lineID []byte, fr ldrstore.CommittedFrame, sidecars map[[32]byte]ldrstore.SidecarBlob, floor uint64) error {
			if err := rig.baseStore.AppendCommit(lineID, fr, sidecars, floor); err != nil {
				return err
			}
			return fmt.Errorf("%w: injected F_FULLFSYNC I/O error", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()

		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env, opKey, opDig := makeAuthOp(t, rig, "auth-uncertain", 1, 2, 2, rig.head2)
		rep := rig.engine.Submit(rig.lineID, root2Prin, env.RawBytes, nil, nil)
		if rep.Class != ldrcore.ClassAdmission || rep.Code != "storage_error" {
			t.Fatalf("expected storage_error, got %+v", rep)
		}

		// Line MUST be quarantined immediately!
		st := rig.engine.Status()[0]
		if !st.Quarantined || st.QuarantineReason == "" {
			t.Fatalf("expected quarantined line, got %+v", st)
		}

		// Health endpoint reports quarantined_lines=1 and ok=false.
		srv := NewRelayServer(rig.engine)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
		var health struct {
			OK               bool `json:"ok"`
			QuarantinedLines int  `json:"quarantined_lines"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
			t.Fatalf("decode health: %v", err)
		}
		if health.OK || health.QuarantinedLines != 1 {
			t.Fatalf("expected health ok=false quarantined_lines=1, got %+v", health)
		}

		// Clear disk fault, yet EVERY operation MUST keep refusing with storage_quarantined
		// until explicit ReconcileLine runs!
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.mu.Unlock()

		if r := rig.engine.Submit(rig.lineID, root2Prin, env.RawBytes, nil, nil); r.Code != "storage_quarantined" {
			t.Fatalf("Submit while quarantined: got %+v", r)
		}
		if r := rig.engine.Query(rig.lineID, root2Prin, opKey, opDig); r.Code != "storage_quarantined" {
			t.Fatalf("Query while quarantined: got %+v", r)
		}
		if r := rig.engine.AnchorRequest(rig.lineID, opPrin); r.Code != "storage_quarantined" {
			t.Fatalf("AnchorRequest while quarantined: got %+v", r)
		}
		if _, err := rig.engine.Compact(rig.lineID); err == nil || err.Error() != "storage_quarantined" {
			t.Fatalf("Compact while quarantined: got %v", err)
		}
		if _, code := rig.engine.ControlLog(rig.lineID, opPrin, 1, 10); code != "storage_quarantined" {
			t.Fatalf("ControlLog while quarantined: got %q", code)
		}
		if _, code := rig.engine.FetchSidecar(rig.lineID, opPrin, ldrstore.SidecarPayload, [32]byte{}); code != "storage_quarantined" {
			t.Fatalf("FetchSidecar while quarantined: got %q", code)
		}
		if _, _, err := rig.engine.VerifySessionPrincipal(rig.lineID, ldrcrypto.SessionAuthMessage{ProfileDigest: rig.profDigest}, nil); !errors.Is(err, ErrLineQuarantined) {
			t.Fatalf("VerifySessionPrincipal while quarantined: got %v, want ErrLineQuarantined", err)
		}

		// If durable storage fails validation during ReconcileLine, quarantine MUST stay active!
		rig.fs.mu.Lock()
		rig.fs.loadMutator = func(*ldrstore.LineSnapshot) error {
			return fmt.Errorf("%w: disk still broken", ldrstore.ErrCorruptWAL)
		}
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine on broken disk: got %v, want ErrCorruptWAL", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("line must remain quarantined after failed ReconcileLine")
		}

		// Now let ReconcileLine read the real durable WAL from disk.
		rig.fs.mu.Lock()
		rig.fs.loadMutator = nil
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine: %v", err)
		}

		// Quarantine lifted AND the commit that actually landed on disk (seq 3) was recovered!
		stAfter := rig.engine.Status()[0]
		if stAfter.Quarantined || stAfter.HeadSeq != 3 {
			t.Fatalf("expected unquarantined HeadSeq=3, got %+v", stAfter)
		}
		q := rig.engine.Query(rig.lineID, root2Prin, opKey, opDig)
		if q.Class != ldrcore.ClassOutcome || q.Outcome.Kind != ldrcore.Committed || q.Outcome.Seq != 3 || !q.Original {
			t.Fatalf("reconciled Query did not recover persisted seq 3: %+v", q)
		}

		// Subsequent commits proceed cleanly from the recovered head (seq 3 -> seq 4)!
		rig.clock.wall += 1000
		rig.clock.mono += 1000
		_, env4, _, _ := makeAuthOp(t, rig, "auth-after-reconcile", 2, 3, 3, q.Head)
		rep4 := rig.engine.Submit(rig.lineID, root2Prin, env4.RawBytes, nil, nil)
		if rep4.Outcome.Kind != ldrcore.Committed || rep4.Outcome.Seq != 4 {
			t.Fatalf("commit after ReconcileLine failed: %+v", rep4)
		}
	})

	t.Run("uncertain_non_commit_anchor_and_compact_quarantine_and_reconcile", func(t *testing.T) {
		rig := newEngineTestRig(t)
		root2Prin := ldrcrypto.RootPrincipal(rig.root2.PublicKey())
		opPrin := ldrcrypto.OperatorPrincipal(rig.opKey.PublicKey())

		// 1. Uncertain AppendNonCommit (persists then returns ErrUncertainWrite) -> quarantined -> reconciled!
		rig.fs.mu.Lock()
		rig.fs.nonCommitFault = func(lineID []byte, entry ldrstore.HotEntry, floor uint64) error {
			if err := rig.baseStore.AppendNonCommit(lineID, entry, floor); err != nil {
				return err
			}
			return fmt.Errorf("%w: non-commit sync failed", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()

		rig.clock.wall += 1000
		rig.clock.mono += 1000
		_, rejEnv, rejKey, rejDig := makeAuthOp(t, rig, "rej-uncertain", 1, 0, 2, rig.head2)
		if r := rig.engine.Submit(rig.lineID, root2Prin, rejEnv.RawBytes, nil, nil); r.Code != "storage_error" {
			t.Fatalf("expected storage_error on uncertain non-commit, got %+v", r)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantine after uncertain non-commit")
		}
		rig.fs.mu.Lock()
		rig.fs.nonCommitFault = nil
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine(non-commit): %v", err)
		}
		if q := rig.engine.Query(rig.lineID, root2Prin, rejKey, rejDig); q.Outcome.Kind != ldrcore.Rejected || !q.Original {
			t.Fatalf("reconciled Query lost persisted rejection: %+v", q)
		}

		// 2. Uncertain AnchorRequest write -> quarantined -> reconciled!
		rig.clock.wall += int64(rig.desc.Profile.FreshnessMS) + 1000
		rig.clock.mono += int64(rig.desc.Profile.FreshnessMS) + 1000
		rig.fs.mu.Lock()
		rig.fs.commitFault = func(lineID []byte, fr ldrstore.CommittedFrame, sidecars map[[32]byte]ldrstore.SidecarBlob, floor uint64) error {
			if err := rig.baseStore.AppendCommit(lineID, fr, sidecars, floor); err != nil {
				return err
			}
			return fmt.Errorf("%w: anchor sync failed", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()
		if ar := rig.engine.AnchorRequest(rig.lineID, opPrin); ar.Code != "storage_error" {
			t.Fatalf("expected storage_error on uncertain anchor, got %+v", ar)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantine after uncertain anchor write")
		}
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine(anchor): %v", err)
		}
		if st := rig.engine.Status()[0]; st.Quarantined || st.HeadSeq != 3 {
			t.Fatalf("expected unquarantined HeadSeq=3 after anchor reconcile, got %+v", st)
		}

		// 3. Uncertain Compact write -> quarantined -> reconciled!
		rig.clock.wall += int64(rig.desc.Profile.MaxValidityMS) + 10_000
		rig.clock.mono += int64(rig.desc.Profile.MaxValidityMS) + 10_000
		rig.fs.mu.Lock()
		rig.fs.compactFault = func(lineID []byte, retired []ldrstore.StoredOpKey, floor uint64) error {
			if err := rig.baseStore.AppendCompact(lineID, retired, floor); err != nil {
				return err
			}
			return fmt.Errorf("%w: compact sync failed", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()
		if _, err := rig.engine.Compact(rig.lineID); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("expected ErrUncertainWrite on compact, got %v", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantine after uncertain compact")
		}
		rig.fs.mu.Lock()
		rig.fs.compactFault = nil
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine(compact): %v", err)
		}
		if st := rig.engine.Status()[0]; st.Quarantined || st.HotEntries != 0 {
			t.Fatalf("expected unquarantined HotEntries=0 after compact reconcile, got %+v", st)
		}
	})

	t.Run("shutdown_skips_clean_marker_for_quarantined_line", func(t *testing.T) {
		rig := newEngineTestRig(t)

		rig.fs.mu.Lock()
		rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
			return fmt.Errorf("%w: disk error", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()
		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env, _, _ := makeAuthOp(t, rig, "auth-q", 1, 2, 2, rig.head2)
		_ = rig.engine.Submit(rig.lineID, root2Prin, env.RawBytes, nil, nil)
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantined line")
		}
		_ = rig.engine.Shutdown()
		rig.fs.mu.Lock()
		calls := rig.fs.shutdownCounter
		rig.fs.mu.Unlock()
		if calls != 0 {
			t.Fatalf("Shutdown wrote RecordCleanShutdown (%d times) to a quarantined line!", calls)
		}
	})
}
