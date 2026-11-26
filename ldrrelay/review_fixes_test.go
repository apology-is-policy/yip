package ldrrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

// faultStore wraps a real ldrstore.Store so tests can:
//  1. Intercept LoadLine to return mutated LineSnapshots for Finding 1 & 2 tests.
//  2. Inject clean ErrPreWrite vs uncertain post-write ErrUncertainWrite faults
//     on AppendCommit / AppendNonCommit / AppendCompact / SyncLine for Finding 3 tests.
type faultStore struct {
	base ldrstore.Store

	mu              sync.Mutex
	loadMutator     func(*ldrstore.LineSnapshot) error
	syncFault       func([]byte) error
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
func (f *faultStore) SyncLine(lineID []byte) error {
	f.mu.Lock()
	fn := f.syncFault
	f.mu.Unlock()
	if fn != nil {
		return fn(lineID)
	}
	return f.base.SyncLine(lineID)
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

// TestUncertainWriteSyncBarrierOnReconcileAndRestart verifies that quarantine
// lift and process restart BOTH require a fresh backend durability barrier
// (SyncFile/SyncDir + Store.SyncLine) even when un-synced bytes remain
// readable from the OS page cache.
func TestUncertainWriteSyncBarrierOnReconcileAndRestart(t *testing.T) {
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

	t.Run("real_filestore_read_visible_but_sync_failing_blocks_reconcile_and_restart", func(t *testing.T) {
		rig := newEngineTestRig(t)
		walPath := filepath.Join(rig.dir, "lines", hex.EncodeToString(rig.lineID), "wal.log")
		beforeInfo, err := os.Stat(walPath)
		if err != nil {
			t.Fatal(err)
		}

		// Control FileStore.SyncFile independently of write/read visibility!
		var syncMu sync.Mutex
		syncFails := true
		rig.baseStore.SetSyncHooks(func(f *os.File) error {
			syncMu.Lock()
			fail := syncFails
			syncMu.Unlock()
			if fail {
				return errors.New("injected disk flush EIO")
			}
			return ldrstore.SyncFile(f)
		}, nil)

		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env3, key3, dig3 := makeAuthOp(t, rig, "auth-real-sync-fail", 1, 2, 2, rig.head2)
		rep := rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
		if rep.Class != ldrcore.ClassAdmission || rep.Code != "storage_error" {
			t.Fatalf("expected storage_error on real sync failure, got %+v", rep)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected line quarantined after real sync failure")
		}

		// Independently verify seq 3 bytes WERE written to wal.log (read-visible = TRUE).
		afterInfo, err := os.Stat(walPath)
		if err != nil {
			t.Fatal(err)
		}
		if afterInfo.Size() <= beforeInfo.Size() {
			t.Fatalf("expected seq 3 bytes to be visible in wal.log (size %d <= %d)", afterInfo.Size(), beforeInfo.Size())
		}

		// While sync STILL fails (read-visible = TRUE, sync = FALSE):
		//  1. ReconcileLine MUST fail and KEEP quarantine active.
		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("ReconcileLine with failing sync barrier: got %v, want ErrUncertainWrite", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine MUST remain active when durability barrier fails")
		}
		//  2. Process restart (NewRelayEngine) MUST ALSO fail closed!
		if _, err := NewRelayEngine(rig.fs, DefaultClockConfig(), rig.clock.source()); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("restart NewRelayEngine with failing sync barrier: got %v, want ErrUncertainWrite", err)
		}

		// Now restore sync success (read-visible = TRUE, sync = TRUE):
		syncMu.Lock()
		syncFails = false
		syncMu.Unlock()

		// ReconcileLine passes the durability barrier, lifts quarantine, and recovers seq 3!
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine after sync restored: %v", err)
		}
		st := rig.engine.Status()[0]
		if st.Quarantined || st.HeadSeq != 3 {
			t.Fatalf("expected unquarantined HeadSeq=3, got %+v", st)
		}
		q := rig.engine.Query(rig.lineID, root2Prin, key3, dig3)
		if q.Class != ldrcore.ClassOutcome || q.Outcome.Kind != ldrcore.Committed || q.Outcome.Seq != 3 || !q.Original {
			t.Fatalf("recovered Query mismatch: %+v", q)
		}
		// Fresh restart also succeeds cleanly now that WAL is synced!
		restarted, err := NewRelayEngine(rig.fs, DefaultClockConfig(), rig.clock.source())
		if err != nil {
			t.Fatalf("restart after sync restored: %v", err)
		}
		if restarted.Status()[0].HeadSeq != 3 {
			t.Fatalf("restarted HeadSeq=%d, want 3", restarted.Status()[0].HeadSeq)
		}
	})

	t.Run("independent_store_syncline_barrier_blocks_reconcile_and_restart", func(t *testing.T) {
		rig := newEngineTestRig(t)

		// Quarantine the line with an uncertain write that DID write bytes readable by LoadLine.
		rig.fs.mu.Lock()
		rig.fs.commitFault = func(lineID []byte, fr ldrstore.CommittedFrame, sidecars map[[32]byte]ldrstore.SidecarBlob, floor uint64) error {
			if err := rig.baseStore.AppendCommit(lineID, fr, sidecars, floor); err != nil {
				return err
			}
			return fmt.Errorf("%w: ambiguous sync", ldrstore.ErrUncertainWrite)
		}
		rig.fs.syncFault = func([]byte) error {
			return fmt.Errorf("%w: SyncLine barrier failed", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()

		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env3, _, _ := makeAuthOp(t, rig, "auth-syncline-barrier", 1, 2, 2, rig.head2)
		_ = rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantined line")
		}

		// LoadLine succeeds (read-visible!), but SyncLine fails -> BOTH ReconcileLine AND restart fail!
		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("ReconcileLine with failing SyncLine: got %v, want ErrUncertainWrite", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine must stay active when SyncLine fails")
		}
		if _, err := NewRelayEngine(rig.fs, DefaultClockConfig(), rig.clock.source()); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("restart with failing SyncLine: got %v, want ErrUncertainWrite", err)
		}

		// Clear SyncLine fault -> ReconcileLine lifts quarantine cleanly.
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.syncFault = nil
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine after SyncLine restored: %v", err)
		}
		if st := rig.engine.Status()[0]; st.Quarantined || st.HeadSeq != 3 {
			t.Fatalf("expected unquarantined HeadSeq=3, got %+v", st)
		}
	})

	t.Run("torn_tail_not_visible_with_failing_sync_then_recovery", func(t *testing.T) {
		rig := newEngineTestRig(t)
		walPath := filepath.Join(rig.dir, "lines", hex.EncodeToString(rig.lineID), "wal.log")
		cleanInfo, err := os.Stat(walPath)
		if err != nil {
			t.Fatal(err)
		}

		// Simulate a torn write (partial 6-byte header) + uncertain error + failing sync.
		rig.fs.mu.Lock()
		rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
			raw, err := os.ReadFile(walPath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(walPath, append(raw, 'L', 'D', 'R', 'W', 1, 1), 0o600); err != nil {
				return err
			}
			return fmt.Errorf("%w: torn write", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()

		var syncMu sync.Mutex
		syncFails := true
		rig.baseStore.SetSyncHooks(func(f *os.File) error {
			syncMu.Lock()
			fail := syncFails
			syncMu.Unlock()
			if fail {
				return errors.New("sync still failing during torn recovery")
			}
			return ldrstore.SyncFile(f)
		}, nil)

		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env3, _, _ := makeAuthOp(t, rig, "auth-torn", 1, 2, 2, rig.head2)
		_ = rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantine after torn write")
		}
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.mu.Unlock()

		// While sync fails, torn-tail truncation cannot be durably confirmed -> stays quarantined!
		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("ReconcileLine on torn tail while sync fails: got %v, want ErrUncertainWrite", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantine to remain active while sync fails")
		}

		// Restore sync -> truncation is durably synced, quarantine lifted, WAL back to clean size, head stays at seq 2.
		syncMu.Lock()
		syncFails = false
		syncMu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine on torn tail after sync restored: %v", err)
		}
		afterInfo, err := os.Stat(walPath)
		if err != nil {
			t.Fatal(err)
		}
		if afterInfo.Size() != cleanInfo.Size() {
			t.Fatalf("expected torn tail truncated back to %d bytes, got %d", cleanInfo.Size(), afterInfo.Size())
		}
		st := rig.engine.Status()[0]
		if st.Quarantined || st.HeadSeq != 2 {
			t.Fatalf("expected unquarantined HeadSeq=2, got %+v", st)
		}

		// Also verify direct torn-tail recovery with sync succeeding reports RecoveredTornTail=true.
		rig.fs.mu.Lock()
		rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
			raw, err := os.ReadFile(walPath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(walPath, append(raw, make([]byte, 16)...), 0o600); err != nil {
				return err
			}
			return fmt.Errorf("%w: zeroed torn tail", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()
		rig.clock.wall += 1000
		rig.clock.mono += 1000
		_, env3b, _, _ := makeAuthOp(t, rig, "auth-torn-2", 1, 2, 2, rig.head2)
		_ = rig.engine.Submit(rig.lineID, root2Prin, env3b.RawBytes, nil, nil)
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.mu.Unlock()
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine on zeroed torn tail: %v", err)
		}
		if st2 := rig.engine.Status()[0]; st2.Quarantined || st2.HeadSeq != 2 || !st2.RecoveredTornTail {
			t.Fatalf("expected unquarantined HeadSeq=2 RecoveredTornTail=true, got %+v", st2)
		}
	})
}

// TestReconcileLineProtectsAcknowledgedPrefixFloorAndOutcomes verifies that
// in-process ReconcileLine fails closed and keeps quarantine if recovered
// storage rolls back the acknowledged prefix, diverges from acknowledged heads,
// regresses durable time_floor, drops/alters unexpired promised outcomes, or
// loses wal.log beside provision.cbor, while still permitting valid compaction.
func TestReconcileLineProtectsAcknowledgedPrefixFloorAndOutcomes(t *testing.T) {
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

	// Helper: advance rig to 3 acknowledged commits + 1 promised unexpired Rejection,
	// snapshot the intact 2-frame prefix BEFORE seq 3, then quarantine on seq 4.
	setupRigWithPrefixAndRejection := func(t *testing.T) (*engineTestRig, *ldrstore.LineSnapshot, ldrstore.StoredOpKey, [32]byte, [32]byte) {
		t.Helper()
		rig := newEngineTestRig(t)

		// Capture an intact, self-consistent 2-frame snapshot before seq 3!
		shortSnap, err := rig.baseStore.LoadLine(rig.lineID)
		if err != nil {
			t.Fatal(err)
		}
		shortSnap = cloneSnapshot(shortSnap)

		// Acknowledge seq 3!
		rig.clock.wall += 1000
		rig.clock.mono += 1000
		root2Prin, env3, _, _ := makeAuthOp(t, rig, "auth-seq-3", 1, 2, 2, rig.head2)
		rep3 := rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
		if rep3.Outcome.Kind != ldrcore.Committed || rep3.Outcome.Seq != 3 {
			t.Fatalf("seq 3 commit failed: %+v", rep3)
		}

		// Promise an unexpired durable Rejection (advances time_floor by +5000 ms above seq 3's SeqTime!).
		rig.clock.wall += 5000
		rig.clock.mono += 5000
		_, rejEnv, rejKey, rejDig := makeAuthOp(t, rig, "rej-promised", 2, 0, 3, rep3.Head)
		repRej := rig.engine.Submit(rig.lineID, root2Prin, rejEnv.RawBytes, nil, nil)
		if repRej.Outcome.Kind != ldrcore.Rejected {
			t.Fatalf("expected Rejected, got %+v", repRej)
		}

		// Trigger quarantine via an uncertain write fault on seq 4.
		rig.fs.mu.Lock()
		rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
			return fmt.Errorf("%w: uncertain write on seq 4", ldrstore.ErrUncertainWrite)
		}
		rig.fs.mu.Unlock()
		rig.clock.wall += 1000
		rig.clock.mono += 1000
		_, env4, _, _ := makeAuthOp(t, rig, "auth-seq-4-quarantine", 2, 3, 3, rep3.Head)
		_ = rig.engine.Submit(rig.lineID, root2Prin, env4.RawBytes, nil, nil)
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("expected quarantined line")
		}
		rig.fs.mu.Lock()
		rig.fs.commitFault = nil
		rig.fs.mu.Unlock()

		return rig, shortSnap, rejKey, rejDig, rep3.Head
	}

	t.Run("intact_but_shorter_recovered_prefix_fails_closed", func(t *testing.T) {
		rig, shortSnap, _, _, _ := setupRigWithPrefixAndRejection(t)

		// Return a completely valid, intact 2-frame snapshot (missing acknowledged seq 3!).
		rig.fs.mu.Lock()
		rig.fs.loadMutator = func(snap *ldrstore.LineSnapshot) error {
			*snap = *cloneSnapshot(shortSnap)
			return nil
		}
		rig.fs.mu.Unlock()

		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine on shorter intact prefix: got %v, want ErrCorruptWAL", err)
		}
		if st := rig.engine.Status()[0]; !st.Quarantined || st.HeadSeq != 3 {
			t.Fatalf("quarantine must remain active at HeadSeq=3, got %+v", st)
		}
	})

	t.Run("divergent_prefix_head_same_length_fails_closed", func(t *testing.T) {
		rig, _, _, _, _ := setupRigWithPrefixAndRejection(t)

		// Replace seq 3 with a DIFFERENT valid signed op (same length=3, valid signatures & chain heads!).
		_, altEnv3, altKey3, altDig3 := makeAuthOp(t, rig, "auth-seq-3-forked", 1, 2, 2, rig.head2)
		rig.fs.mu.Lock()
		rig.fs.loadMutator = func(snap *ldrstore.LineSnapshot) error {
			oldKey3 := *snap.Frames[2].OpKey
			delete(snap.LogIndex, oldKey3)
			delete(snap.Hot, oldKey3)
			snap.Frames[2].IntentBytes = altEnv3.RawBytes
			snap.Frames[2].IntentDigest = altDig3
			snap.Frames[2].OpKey = &altKey3
			snap.LogIndex[altKey3] = ldrstore.CommittedReceipt{Seq: 3, Digest: altDig3}
			snap.Hot[altKey3] = ldrstore.HotEntry{
				Key: altKey3, Digest: altDig3,
				Outcome: ldrstore.StoredOutcome{Kind: ldrcore.Committed, Seq: 3},
			}
			recomputeChainHeads(t, snap, rig.profDigest)
			return nil
		}
		rig.fs.mu.Unlock()

		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine on divergent prefix: got %v, want ErrCorruptWAL", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine must remain active on divergent prefix")
		}
	})

	t.Run("time_floor_regression_fails_closed", func(t *testing.T) {
		rig, _, _, _, _ := setupRigWithPrefixAndRejection(t)

		// Regress recovered TimeFloor below the acknowledged floor (still >= maxCommitTime
		// because the promised Rejection raised floor by +5000ms above seq 3's SeqTime!).
		rig.fs.mu.Lock()
		rig.fs.loadMutator = func(snap *ldrstore.LineSnapshot) error {
			snap.TimeFloor = snap.Frames[2].SeqTime // valid for startup, but regressed below acknowledged floor!
			return nil
		}
		rig.fs.mu.Unlock()

		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine on regressed time_floor: got %v, want ErrCorruptWAL", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine must remain active on time_floor regression")
		}
	})

	t.Run("dropped_unexpired_promised_rejection_fails_closed", func(t *testing.T) {
		rig, _, rejKey, _, _ := setupRigWithPrefixAndRejection(t)

		// Remove the unexpired promised Rejection from recovered Hot & Quota.
		rig.fs.mu.Lock()
		rig.fs.loadMutator = func(snap *ldrstore.LineSnapshot) error {
			delete(snap.Hot, rejKey)
			snap.Quota[rejKey.Signer]--
			if snap.Quota[rejKey.Signer] == 0 {
				delete(snap.Quota, rejKey.Signer)
			}
			return nil
		}
		rig.fs.mu.Unlock()

		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine on dropped unexpired promised rejection: got %v, want ErrCorruptWAL", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine must remain active when unexpired promised outcome is lost")
		}
	})

	t.Run("mutated_promised_rejection_outcome_fails_closed", func(t *testing.T) {
		rig, _, rejKey, _, _ := setupRigWithPrefixAndRejection(t)

		rig.fs.mu.Lock()
		rig.fs.loadMutator = func(snap *ldrstore.LineSnapshot) error {
			he := snap.Hot[rejKey]
			he.Outcome.Reason = "unauthorized" // changed from "conflict"!
			snap.Hot[rejKey] = he
			return nil
		}
		rig.fs.mu.Unlock()

		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine on mutated promised outcome: got %v, want ErrCorruptWAL", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine must remain active when promised outcome mutated")
		}
	})

	t.Run("valid_compaction_of_expired_outcome_allowed_on_reconcile", func(t *testing.T) {
		rig, _, rejKey, _, _ := setupRigWithPrefixAndRejection(t)
		// First lift quarantine cleanly so we can run an uncertain AppendCompact after expiry.
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("initial ReconcileLine: %v", err)
		}

		// Advance clock past MaxValidityMS so rejKey's anchor (seq 3) is strictly expired!
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

		// ReconcileLine MUST allow the validly compacted expired entries!
		if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
			t.Fatalf("ReconcileLine rejected valid expiry compaction: %v", err)
		}
		st := rig.engine.Status()[0]
		if st.Quarantined || st.HotEntries != 0 || st.CommittedOps != 3 {
			t.Fatalf("expected unquarantined HotEntries=0 CommittedOps=3, got %+v", st)
		}
		_ = rejKey
	})

	t.Run("lost_wal_beside_provision_fails_reconcile_and_restart", func(t *testing.T) {
		rig, _, _, _, _ := setupRigWithPrefixAndRejection(t)
		walPath := filepath.Join(rig.dir, "lines", hex.EncodeToString(rig.lineID), "wal.log")
		if err := os.Remove(walPath); err != nil {
			t.Fatal(err)
		}
		if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileLine with lost WAL: got %v, want ErrCorruptWAL", err)
		}
		if !rig.engine.Status()[0].Quarantined {
			t.Fatalf("quarantine must stay active when WAL is missing")
		}
		if _, err := NewRelayEngine(rig.fs, DefaultClockConfig(), rig.clock.source()); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("restart with lost WAL: got %v, want ErrCorruptWAL", err)
		}
	})

	t.Run("previously_opened_wal_unlinked_or_replaced_quarantines_live_engine", func(t *testing.T) {
		for _, mode := range []string{"unlinked", "replaced"} {
			t.Run(mode, func(t *testing.T) {
				rig := newEngineTestRig(t)
				// rig already committed seq 1 and seq 2, so FileStore holds an open cached WAL fd!
				walPath := filepath.Join(rig.dir, "lines", hex.EncodeToString(rig.lineID), "wal.log")
				if mode == "unlinked" {
					if err := os.Remove(walPath); err != nil {
						t.Fatal(err)
					}
				} else {
					orig, err := os.ReadFile(walPath)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(walPath+".new", orig, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(walPath+".new", walPath); err != nil {
						t.Fatal(err)
					}
				}

				rig.clock.wall += 1000
				rig.clock.mono += 1000
				root2Prin, env3, _, _ := makeAuthOp(t, rig, "auth-after-"+mode, 1, 2, 2, rig.head2)
				rep := rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
				if rep.Class != ldrcore.ClassAdmission || rep.Code != "storage_error" {
					t.Fatalf("mode %s: expected storage_error, got %+v", mode, rep)
				}
				if st := rig.engine.Status()[0]; !st.Quarantined {
					t.Fatalf("mode %s: live engine MUST quarantine when previously opened WAL path is %s", mode, mode)
				}
			})
		}
	})
}

// TestInitSelfSignedCertSyncFailureRecoveryAndPreservation verifies Codex Turn 28:
//   - Definite pre-link failures wrap ldrstore.ErrPreWrite; uncertain post-link
//     directory-sync failures wrap ldrstore.ErrUncertainWrite without deleting
//     published files.
//   - Both key-dir and cert-dir SyncDir failures (same directory and separate
//     directories) preserve the matching identity and recover on retry into a
//     loadable matching TLS 1.3 cert/key pair with the exact SPKI pin.
//   - Unrelated, sentinel, symlink, mismatched, or different-hosts files are
//     refused without modification.
func TestInitSelfSignedCertSyncFailureRecoveryAndPreservation(t *testing.T) {
	hosts := []string{"127.0.0.1", "localhost"}

	verifyLoadablePair := func(t *testing.T, certPath, keyPath string, wantPin [32]byte) {
		t.Helper()
		cfg, err := ServerTLSConfig(certPath, keyPath)
		if err != nil {
			t.Fatalf("ServerTLSConfig failed: %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS13 || len(cfg.Certificates) != 1 {
			t.Fatalf("unexpected ServerTLSConfig: min=%x certs=%d", cfg.MinVersion, len(cfg.Certificates))
		}
		if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
			t.Fatalf("tls.LoadX509KeyPair failed: %v", err)
		}
		rawCert, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(rawCert)
		if blk == nil {
			t.Fatalf("invalid cert PEM at %s", certPath)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		gotPin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if gotPin != wantPin {
			t.Fatalf("SPKI pin mismatch: got %x want %x", gotPin, wantPin)
		}
		for _, h := range hosts {
			if err := cert.VerifyHostname(h); err != nil {
				t.Fatalf("VerifyHostname(%q) failed: %v", h, err)
			}
		}
	}

	layouts := []struct {
		name     string
		separate bool
	}{
		{name: "same_dir", separate: false},
		{name: "separate_dirs", separate: true},
	}

	for _, layout := range layouts {
		layout := layout
		makePaths := func(t *testing.T) (certPath, keyPath string) {
			t.Helper()
			tmp := t.TempDir()
			if layout.separate {
				return filepath.Join(tmp, "certs", "server.crt"), filepath.Join(tmp, "keys", "server.key")
			}
			return filepath.Join(tmp, "tls", "server.crt"), filepath.Join(tmp, "tls", "server.key")
		}

		t.Run("key_dir_sync_failure_"+layout.name, func(t *testing.T) {
			certPath, keyPath := makePaths(t)
			keyDir := filepath.Dir(keyPath)
			failKeyDir := true
			syncDirHook := func(d string) error {
				if failKeyDir && filepath.Clean(d) == filepath.Clean(keyDir) {
					return errors.New("injected key-dir SyncDir EIO")
				}
				return ldrstore.SyncDir(d)
			}

			_, err := initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, syncDirHook)
			if !errors.Is(err, ldrstore.ErrUncertainWrite) || errors.Is(err, ldrstore.ErrPreWrite) {
				t.Fatalf("key-dir SyncDir failure: got %v, want ErrUncertainWrite (not ErrPreWrite)", err)
			}
			keyAfterFail, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatalf("expected linked keyPath to remain visible after post-link SyncDir failure: %v", err)
			}
			if _, err := os.Lstat(certPath); !os.IsNotExist(err) {
				t.Fatalf("certPath must not exist after key-dir SyncDir failure, stat err=%v", err)
			}

			// Retry while key-dir SyncDir STILL fails MUST fail closed without publishing cert or altering key!
			if _, err := initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, syncDirHook); !errors.Is(err, ldrstore.ErrUncertainWrite) {
				t.Fatalf("retry during ongoing key-dir SyncDir fault: got %v, want ErrUncertainWrite", err)
			}
			if got, _ := os.ReadFile(keyPath); !bytes.Equal(got, keyAfterFail) {
				t.Fatalf("retry during fault altered keyPath!")
			}
			if _, err := os.Lstat(certPath); !os.IsNotExist(err) {
				t.Fatalf("retry during key-dir SyncDir fault prematurely published certPath!")
			}

			// Once key-dir SyncDir recovers, retry MUST preserve the exact key identity and produce a loadable pair.
			failKeyDir = false
			pin, err := initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, syncDirHook)
			if err != nil {
				t.Fatalf("recovery retry after key-dir SyncDir fault: %v", err)
			}
			if got, _ := os.ReadFile(keyPath); !bytes.Equal(got, keyAfterFail) {
				t.Fatalf("recovery retry replaced keyPath identity!")
			}
			verifyLoadablePair(t, certPath, keyPath, pin)
		})

		t.Run("cert_dir_sync_failure_"+layout.name, func(t *testing.T) {
			certPath, keyPath := makePaths(t)
			certDir := filepath.Dir(certPath)
			failCertDir := true
			dirSyncCalls := 0
			syncDirHook := func(d string) error {
				dirSyncCalls++
				if failCertDir && filepath.Clean(d) == filepath.Clean(certDir) {
					// In same_dir layout, call #1 is keyPath's SyncDir and call #2 is certPath's SyncDir.
					if layout.separate || dirSyncCalls >= 2 {
						return errors.New("injected cert-dir SyncDir EIO")
					}
				}
				return ldrstore.SyncDir(d)
			}

			_, err := initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, syncDirHook)
			if !errors.Is(err, ldrstore.ErrUncertainWrite) || errors.Is(err, ldrstore.ErrPreWrite) {
				t.Fatalf("cert-dir SyncDir failure: got %v, want ErrUncertainWrite (not ErrPreWrite)", err)
			}
			keyAfterFail, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatalf("cert-dir SyncDir failure MUST NOT remove matching keyPath: %v", err)
			}
			certAfterFail, err := os.ReadFile(certPath)
			if err != nil {
				t.Fatalf("expected linked certPath to remain visible after post-link SyncDir failure: %v", err)
			}

			// Retry while cert-dir SyncDir STILL fails MUST fail closed while preserving both files.
			if _, err := initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, syncDirHook); !errors.Is(err, ldrstore.ErrUncertainWrite) {
				t.Fatalf("retry during ongoing cert-dir SyncDir fault: got %v, want ErrUncertainWrite", err)
			}
			if got, _ := os.ReadFile(keyPath); !bytes.Equal(got, keyAfterFail) {
				t.Fatalf("retry during cert-dir fault altered keyPath!")
			}
			if got, _ := os.ReadFile(certPath); !bytes.Equal(got, certAfterFail) {
				t.Fatalf("retry during cert-dir fault altered certPath!")
			}

			// Once cert-dir SyncDir recovers, retry MUST pass barriers, keep BOTH files byte-identical,
			// and return the exact SPKI pin for the loadable matching pair.
			failCertDir = false
			pin, err := initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, syncDirHook)
			if err != nil {
				t.Fatalf("recovery retry after cert-dir SyncDir fault: %v", err)
			}
			if got, _ := os.ReadFile(keyPath); !bytes.Equal(got, keyAfterFail) {
				t.Fatalf("recovery retry altered keyPath!")
			}
			if got, _ := os.ReadFile(certPath); !bytes.Equal(got, certAfterFail) {
				t.Fatalf("recovery retry altered certPath!")
			}
			verifyLoadablePair(t, certPath, keyPath, pin)
		})
	}

	t.Run("definite_pre_link_failures_and_recovery", func(t *testing.T) {
		// 1. Key temp SyncFile fails before os.Link -> ErrPreWrite, nothing published, retry succeeds cleanly.
		tmp := t.TempDir()
		cert1 := filepath.Join(tmp, "kpre", "server.crt")
		key1 := filepath.Join(tmp, "kpre", "server.key")
		failSyncFile := true
		_, err := initSelfSignedCertWithHooks(cert1, key1, hosts, func(f *os.File) error {
			if failSyncFile {
				return errors.New("injected key SyncFile pre-link EIO")
			}
			return ldrstore.SyncFile(f)
		}, nil)
		if !errors.Is(err, ldrstore.ErrPreWrite) || errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("key pre-link SyncFile failure: got %v, want ErrPreWrite (not ErrUncertainWrite)", err)
		}
		if _, err := os.Lstat(key1); !os.IsNotExist(err) {
			t.Fatalf("pre-link key failure published key1")
		}
		if _, err := os.Lstat(cert1); !os.IsNotExist(err) {
			t.Fatalf("pre-link key failure published cert1")
		}
		failSyncFile = false
		pin1, err := InitSelfSignedCert(cert1, key1, hosts)
		if err != nil {
			t.Fatalf("retry after pre-link key failure: %v", err)
		}
		verifyLoadablePair(t, cert1, key1, pin1)

		// 2. Key succeeds; cert temp SyncFile fails before os.Link -> ErrPreWrite, key preserved,
		//    retry keeps exact key identity and publishes matching cert!
		cert2 := filepath.Join(tmp, "cpre", "server.crt")
		key2 := filepath.Join(tmp, "cpre", "server.key")
		syncCalls := 0
		_, err = initSelfSignedCertWithHooks(cert2, key2, hosts, func(f *os.File) error {
			syncCalls++
			if syncCalls == 2 {
				return errors.New("injected cert SyncFile pre-link EIO")
			}
			return ldrstore.SyncFile(f)
		}, nil)
		if !errors.Is(err, ldrstore.ErrPreWrite) || errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("cert pre-link SyncFile failure: got %v, want ErrPreWrite (not ErrUncertainWrite)", err)
		}
		key2Bytes, err := os.ReadFile(key2)
		if err != nil {
			t.Fatalf("expected key2 preserved after cert pre-link failure: %v", err)
		}
		if _, err := os.Lstat(cert2); !os.IsNotExist(err) {
			t.Fatalf("pre-link cert failure published cert2")
		}
		pin2, err := InitSelfSignedCert(cert2, key2, hosts)
		if err != nil {
			t.Fatalf("retry after cert pre-link failure: %v", err)
		}
		if got, _ := os.ReadFile(key2); !bytes.Equal(got, key2Bytes) {
			t.Fatalf("retry after cert pre-link failure replaced key2 identity!")
		}
		verifyLoadablePair(t, cert2, key2, pin2)
	})

	t.Run("unrelated_aliasing_and_mismatched_files_preserved", func(t *testing.T) {
		tmp := t.TempDir()
		realDir := filepath.Join(tmp, "real")
		if err := os.MkdirAll(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(tmp, "link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}

		// Direct & symlink aliasing refused before creating either file.
		aliasTarget := filepath.Join(realDir, "same.pem")
		if _, err := InitSelfSignedCert(aliasTarget, aliasTarget, hosts); !errors.Is(err, ErrTLSOutputCollision) {
			t.Fatalf("direct alias: got %v, want ErrTLSOutputCollision", err)
		}
		if _, err := InitSelfSignedCert(aliasTarget, filepath.Join(linkDir, "same.pem"), hosts); !errors.Is(err, ErrTLSOutputCollision) {
			t.Fatalf("symlink alias: got %v, want ErrTLSOutputCollision", err)
		}
		if _, err := os.Lstat(aliasTarget); !os.IsNotExist(err) {
			t.Fatalf("aliasing InitSelfSignedCert created %s", aliasTarget)
		}

		// Unrelated sentinel at keyPath -> refused, sentinel untouched, cert not created.
		sentinel := []byte("UNRELATED-SENTINEL-DO-NOT-CLOBBER\n")
		sentKey := filepath.Join(tmp, "sent-key.pem")
		if err := os.WriteFile(sentKey, sentinel, 0o600); err != nil {
			t.Fatal(err)
		}
		unusedCert := filepath.Join(tmp, "unused.crt")
		if _, err := InitSelfSignedCert(unusedCert, sentKey, hosts); !errors.Is(err, ErrTLSOutputExists) {
			t.Fatalf("sentinel at keyPath: got %v, want ErrTLSOutputExists", err)
		}
		if got, _ := os.ReadFile(sentKey); !bytes.Equal(got, sentinel) {
			t.Fatalf("sentinel at keyPath was altered!")
		}
		if _, err := os.Lstat(unusedCert); !os.IsNotExist(err) {
			t.Fatalf("created cert despite sentinel at keyPath!")
		}

		// Unrelated sentinel at certPath -> refused, sentinel untouched, key not created.
		sentCert := filepath.Join(tmp, "sent-cert.pem")
		if err := os.WriteFile(sentCert, sentinel, 0o644); err != nil {
			t.Fatal(err)
		}
		unusedKey := filepath.Join(tmp, "unused.key")
		if _, err := InitSelfSignedCert(sentCert, unusedKey, hosts); !errors.Is(err, ErrTLSOutputExists) {
			t.Fatalf("sentinel at certPath: got %v, want ErrTLSOutputExists", err)
		}
		if got, _ := os.ReadFile(sentCert); !bytes.Equal(got, sentinel) {
			t.Fatalf("sentinel at certPath was altered!")
		}
		if _, err := os.Lstat(unusedKey); !os.IsNotExist(err) {
			t.Fatalf("created key despite sentinel at certPath!")
		}

		// Generate two distinct valid throwaway pairs to test symlink-to-valid-key,
		// mismatched valid key/cert, and differing hosts refusal.
		pairACert, pairAKey := filepath.Join(tmp, "a", "s.crt"), filepath.Join(tmp, "a", "s.key")
		pairBCert, pairBKey := filepath.Join(tmp, "b", "s.crt"), filepath.Join(tmp, "b", "s.key")
		if _, err := InitSelfSignedCert(pairACert, pairAKey, hosts); err != nil {
			t.Fatal(err)
		}
		if _, err := InitSelfSignedCert(pairBCert, pairBKey, hosts); err != nil {
			t.Fatal(err)
		}

		// Symlink at keyPath pointing to valid P-256 key MUST be refused (not regular).
		symKey := filepath.Join(tmp, "sym.key")
		if err := os.Symlink(pairAKey, symKey); err != nil {
			t.Fatal(err)
		}
		symCert := filepath.Join(tmp, "sym.crt")
		if _, err := InitSelfSignedCert(symCert, symKey, hosts); !errors.Is(err, ErrTLSOutputExists) {
			t.Fatalf("symlink keyPath: got %v, want ErrTLSOutputExists", err)
		}
		if _, err := os.Lstat(symCert); !os.IsNotExist(err) {
			t.Fatalf("created cert for symlink keyPath!")
		}

		// Mismatched valid key A + valid cert B MUST be refused with both files untouched.
		origKeyA, _ := os.ReadFile(pairAKey)
		origCertB, _ := os.ReadFile(pairBCert)
		if _, err := InitSelfSignedCert(pairBCert, pairAKey, hosts); !errors.Is(err, ErrTLSOutputExists) {
			t.Fatalf("mismatched valid pair: got %v, want ErrTLSOutputExists", err)
		}
		if got, _ := os.ReadFile(pairAKey); !bytes.Equal(got, origKeyA) {
			t.Fatalf("mismatched refusal altered key A!")
		}
		if got, _ := os.ReadFile(pairBCert); !bytes.Equal(got, origCertB) {
			t.Fatalf("mismatched refusal altered cert B!")
		}

		// Existing valid pair A with different hosts MUST be refused with both files untouched.
		origCertA, _ := os.ReadFile(pairACert)
		if _, err := InitSelfSignedCert(pairACert, pairAKey, []string{"127.0.0.1", "other.example"}); !errors.Is(err, ErrTLSOutputExists) {
			t.Fatalf("different hosts over valid pair: got %v, want ErrTLSOutputExists", err)
		}
		if got, _ := os.ReadFile(pairACert); !bytes.Equal(got, origCertA) {
			t.Fatalf("different-hosts refusal altered cert A!")
		}
		if got, _ := os.ReadFile(pairAKey); !bytes.Equal(got, origKeyA) {
			t.Fatalf("different-hosts refusal altered key A!")
		}
	})
}

func makeRoot2AuthOp(t *testing.T, rig *engineTestRig, opID string, authEpoch, rootRev, seenSeq uint64, seenHead [32]byte) (ldrcrypto.Principal, ldrcrypto.SignedIntent, ldrstore.StoredOpKey, [32]byte) {
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

// TestRelayEngineOutOfDomainFloorLoadAndReconcileRejected verifies Codex Turn 30 Finding 1:
// Both startup load (NewRelayEngine) and runtime reconciliation (ReconcileLine)
// reject persisted TimeFloor values exceeding ldrcore.MaxCounter (including
// MaxCounter+1, MaxInt64+1 signed-wrap boundary, and MaxUint64) with ErrCorruptWAL
// BEFORE ClockGuard conversion, and FileStore rejects writing out-of-domain floors.
func TestRelayEngineOutOfDomainFloorLoadAndReconcileRejected(t *testing.T) {
	badFloors := []struct {
		name  string
		floor uint64
	}{
		{name: "max_counter_plus_1", floor: uint64(ldrcore.MaxCounter) + 1},
		{name: "signed_wrap_max_int64_plus_1", floor: uint64(math.MaxInt64) + 1},
		{name: "max_uint64", floor: math.MaxUint64},
	}

	for _, tc := range badFloors {
		tc := tc
		t.Run("startup_and_reconcile_"+tc.name, func(t *testing.T) {
			rig := newEngineTestRig(t)

			// 1. FileStore write boundary refuses out-of-domain floors cleanly (ErrPreWrite/ErrInvalidRecord).
			if err := rig.baseStore.AppendCompact(rig.lineID, nil, tc.floor); !errors.Is(err, ldrstore.ErrPreWrite) || !errors.Is(err, ldrstore.ErrInvalidRecord) {
				t.Fatalf("%s: AppendCompact out-of-domain floor got %v, want ErrPreWrite+ErrInvalidRecord", tc.name, err)
			}
			if err := rig.baseStore.RecordCleanShutdown(rig.lineID, tc.floor, 1_700_000_000_000); !errors.Is(err, ldrstore.ErrInvalidRecord) {
				t.Fatalf("%s: RecordCleanShutdown out-of-domain floor got %v, want ErrInvalidRecord", tc.name, err)
			}

			// 2. Startup load (NewRelayEngine) MUST reject out-of-domain TimeFloor with ErrCorruptWAL.
			badStartupStore := &faultStore{
				base: rig.baseStore,
				loadMutator: func(s *ldrstore.LineSnapshot) error {
					s.TimeFloor = tc.floor
					return nil
				},
			}
			if _, err := NewRelayEngine(badStartupStore, DefaultClockConfig(), rig.clock.source()); !errors.Is(err, ldrstore.ErrCorruptWAL) {
				t.Fatalf("%s: NewRelayEngine accepted/misclassified out-of-domain floor: got %v, want ErrCorruptWAL", tc.name, err)
			}

			// 3. Quarantine the live line and inject out-of-domain TimeFloor during ReconcileLine ->
			//    MUST reject with ErrCorruptWAL and keep the line quarantined!
			rig.fs.mu.Lock()
			rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
				return fmt.Errorf("%w: injected quarantine fault", ldrstore.ErrUncertainWrite)
			}
			rig.fs.mu.Unlock()
			rig.clock.wall += 1000
			rig.clock.mono += 1000
			root2Prin, env3, _, _ := makeRoot2AuthOp(t, rig, "quar-op-"+tc.name, 1, 2, 2, rig.head2)
			rep := rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
			if rep.Class != ldrcore.ClassAdmission || rep.Code != "storage_error" {
				t.Fatalf("expected quarantine trigger storage_error, got %+v", rep)
			}
			rig.fs.mu.Lock()
			rig.fs.commitFault = nil
			rig.fs.mu.Unlock()
			if st := rig.engine.Status()[0]; !st.Quarantined {
				t.Fatalf("expected line quarantined before ReconcileLine")
			}

			rig.fs.mu.Lock()
			rig.fs.loadMutator = func(s *ldrstore.LineSnapshot) error {
				s.TimeFloor = tc.floor
				return nil
			}
			rig.fs.mu.Unlock()

			if err := rig.engine.ReconcileLine(rig.lineID); !errors.Is(err, ldrstore.ErrCorruptWAL) {
				t.Fatalf("%s: ReconcileLine with out-of-domain floor got %v, want ErrCorruptWAL", tc.name, err)
			}
			if st := rig.engine.Status()[0]; !st.Quarantined {
				t.Fatalf("%s: failed ReconcileLine cleared quarantine!", tc.name)
			}

			// Clear mutator -> genuine valid reconcile still succeeds.
			rig.fs.mu.Lock()
			rig.fs.loadMutator = nil
			rig.fs.mu.Unlock()
			if err := rig.engine.ReconcileLine(rig.lineID); err != nil {
				t.Fatalf("%s: clean ReconcileLine after mutator clear: %v", tc.name, err)
			}
		})
	}
}

// TestAdminSocketSecurityAndClockResume verifies Codex Turn 30 Finding 2 at the
// ldrrelay boundary: owner-only 0600 local Unix admin socket, refusal to clobber
// non-socket files or active sockets, explicit ConfirmClockResume wiring (refusing
// wall < floor, succeeding when wall >= floor, and never clearing storage quarantine).
func TestAdminSocketSecurityAndClockResume(t *testing.T) {
	rig := newEngineTestRig(t)
	ctx := context.Background()

	// Use a short temp dir under /tmp so macOS 104-byte Unix sun_path limit is respected.
	sockDir, err := os.MkdirTemp("/tmp", "yip-adm-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	// 1. Sentinel non-socket file MUST NOT be clobbered by StartAdminServer.
	sentinelSock := filepath.Join(sockDir, "sentinel.sock")
	sentinelBytes := []byte("KEEP-ADMIN-SENTINEL\n")
	if err := os.WriteFile(sentinelSock, sentinelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StartAdminServer(sentinelSock, rig.engine); !errors.Is(err, ErrAdminSocketConflict) {
		t.Fatalf("StartAdminServer over regular sentinel: got %v, want ErrAdminSocketConflict", err)
	}
	if got, _ := os.ReadFile(sentinelSock); !bytes.Equal(got, sentinelBytes) {
		t.Fatalf("StartAdminServer altered regular sentinel file!")
	}

	// 2. Bind real admin socket and verify owner-only 0600 permissions + active conflict check.
	sockPath := filepath.Join(sockDir, "admin.sock")
	adm, err := StartAdminServer(sockPath, rig.engine)
	if err != nil {
		t.Fatalf("StartAdminServer: %v", err)
	}
	defer adm.Close(ctx)

	fi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("Lstat admin socket: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected Unix socket mode, got %v", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("admin socket perm = %#o, want 0600", perm)
	}
	if _, err := StartAdminServer(sockPath, rig.engine); !errors.Is(err, ErrAdminSocketConflict) {
		t.Fatalf("second StartAdminServer on active socket: got %v, want ErrAdminSocketConflict", err)
	}

	// 3. Trip clock via backward jump -> AdminStatus reports untrusted, AdminClockResume refuses while wall < floor.
	rig.clock.wall -= 10_000
	rig.clock.mono += 100
	cg, ok := rig.engine.ClockGuardFor(rig.lineID)
	if !ok {
		t.Fatalf("ClockGuardFor missing")
	}
	if st := cg.Sample(); st.Trusted {
		t.Fatalf("expected backward jump to trip ClockGuard")
	}

	lines, err := AdminStatus(ctx, sockPath)
	if err != nil || len(lines) != 1 || lines[0].Clock.Trusted {
		t.Fatalf("AdminStatus while tripped: lines=%+v err=%v", lines, err)
	}
	if _, err := AdminClockResume(ctx, sockPath, rig.lineID); err == nil {
		t.Fatalf("AdminClockResume MUST refuse while wall < floor")
	}

	// 4. Also quarantine the line; once wall >= floor, AdminClockResume clears clock_uncertain
	//    but MUST NOT clear storage quarantine!
	rig.fs.mu.Lock()
	rig.fs.commitFault = func([]byte, ldrstore.CommittedFrame, map[[32]byte]ldrstore.SidecarBlob, uint64) error {
		return fmt.Errorf("%w: injected quar", ldrstore.ErrUncertainWrite)
	}
	rig.fs.mu.Unlock()
	rig.clock.wall += 15_000
	rig.clock.mono += 1000
	res, err := AdminClockResume(ctx, sockPath, rig.lineID)
	if err != nil || len(res) != 1 || !res[0].Clock.Trusted {
		t.Fatalf("AdminClockResume after wall >= floor: res=%+v err=%v", res, err)
	}
	// Trigger quarantine on next write, trip clock again, resume clock, verify quarantine remains!
	rig.clock.wall += 1000
	rig.clock.mono += 1000
	root2Prin, env3, _, _ := makeRoot2AuthOp(t, rig, "quar-clk-op", 1, 2, 2, rig.head2)
	rep := rig.engine.Submit(rig.lineID, root2Prin, env3.RawBytes, nil, nil)
	if rep.Code != "storage_error" {
		t.Fatalf("expected storage_error quarantine, got %+v", rep)
	}
	rig.fs.mu.Lock()
	rig.fs.commitFault = nil
	rig.fs.mu.Unlock()
	rig.clock.wall += 120_000 // huge forward jump with 0 mono -> trips clock
	cg.Sample()
	if cg.Status().Trusted {
		t.Fatalf("expected forward jump to trip ClockGuard")
	}
	res2, err := AdminClockResume(ctx, sockPath, nil)
	if err != nil || len(res2) != 1 || !res2[0].Clock.Trusted {
		t.Fatalf("AdminClockResume all lines: res=%+v err=%v", res2, err)
	}
	linesAfter, err := AdminStatus(ctx, sockPath)
	if err != nil || len(linesAfter) != 1 || !linesAfter[0].Quarantined || !linesAfter[0].Clock.Trusted {
		t.Fatalf("AdminClockResume MUST preserve storage quarantine while resuming clock: %+v err=%v", linesAfter, err)
	}

	// 5. Close removes the socket cleanly.
	if err := adm.Close(ctx); err != nil {
		t.Fatalf("adm.Close: %v", err)
	}
	if _, err := os.Lstat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected admin socket removed on Close, stat err=%v", err)
	}
}

// TestTransportSessionEchoBindingsAndIdleExpiry verifies Codex Turn 64:
//  1. DialSession strictly validates the full echo on both "authenticated"
//     (v, line_id, generation, session_id) and terminal "unresolved"/"revoked"
//     (also principal and server_nonce), returning an ordinary protocol error
//     (never *AuthError) on malformed or mismatched echoes.
//  2. Every authenticated session endpoint (Submit, Query, AnchorRequest
//     including zero-gen refusals, ControlLog, FetchSidecar including refusals)
//     echoes v=1 and session_gen uniformly, and verifyReplyBinding rejects
//     missing or mismatched v, session_gen, session_id, req_id, req_digest, or line_id.
//  3. validateSession enforces session idle expiry during lookup (evicting expired
//     sessions without waiting for another client's handshake sweep).
func TestTransportSessionEchoBindingsAndIdleExpiry(t *testing.T) {
	ctx := context.Background()

	startTLSHandler := func(t *testing.T, handler http.Handler) ldrcrypto.RelayOrigin {
		t.Helper()
		tlsDir := t.TempDir()
		certPath := filepath.Join(tlsDir, "server.crt")
		keyPath := filepath.Join(tlsDir, "server.key")
		pin, err := InitSelfSignedCert(certPath, keyPath, []string{"127.0.0.1", "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		srvTLS, err := ServerTLSConfig(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tlsLn := tls.NewListener(rawLn, srvTLS)
		hs := &http.Server{Handler: handler}
		go func() { _ = hs.Serve(tlsLn) }()
		t.Cleanup(func() {
			_ = hs.Close()
			_ = tlsLn.Close()
		})
		return ldrcrypto.RelayOrigin{
			URL:            "https://" + rawLn.Addr().String(),
			TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
			TLSPin:         pin[:],
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		}
	}

	t.Run("dial_session_authenticated_and_revoked_echo_validation", func(t *testing.T) {
		lineID := bytes.Repeat([]byte{0x44}, 16)
		otherLineID := bytes.Repeat([]byte{0x45}, 16)
		profDig, _ := ldrcrypto.ProfileV1().Digest()
		rootKey, err := ldrcrypto.GenerateEd25519Key()
		if err != nil {
			t.Fatal(err)
		}
		otherKey, err := ldrcrypto.GenerateEd25519Key()
		if err != nil {
			t.Fatal(err)
		}
		prin := ldrcrypto.RootPrincipal(rootKey.PublicKey())
		pCBOR, _ := prin.ToCBOR()
		otherPCBOR, _ := ldrcrypto.RootPrincipal(otherKey.PublicKey()).ToCBOR()

		sid := bytes.Repeat([]byte{0x11}, 16)
		otherSID := bytes.Repeat([]byte{0x12}, 16)
		nonce := bytes.Repeat([]byte{0x22}, 32)
		otherNonce := bytes.Repeat([]byte{0x23}, 32)

		var mu sync.Mutex
		var authReply ldrcrypto.Map

		mux := http.NewServeMux()
		mux.HandleFunc("/v1/lines/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/session/challenge") {
				writeCBOR(w, http.StatusOK, ldrcrypto.Map{
					{Key: "expires_ms", Value: uint64(time.Now().Add(time.Minute).UnixMilli())},
					{Key: "server_nonce", Value: nonce},
					{Key: "session_id", Value: sid},
					{Key: "v", Value: uint64(1)},
				})
				return
			}
			mu.Lock()
			rep := authReply
			mu.Unlock()
			writeCBOR(w, http.StatusOK, rep)
		})
		origin := startTLSHandler(t, mux)

		setReply := func(m ldrcrypto.Map) {
			mu.Lock()
			authReply = m
			mu.Unlock()
		}

		// Valid authenticated echo succeeds.
		setReply(ldrcrypto.Map{
			{Key: "class", Value: "authenticated"},
			{Key: "generation", Value: uint64(1)},
			{Key: "line_id", Value: lineID},
			{Key: "session_id", Value: sid},
			{Key: "v", Value: uint64(1)},
		})
		sc, err := DialSession(ctx, origin, lineID, profDig, 1, prin, rootKey)
		if err != nil {
			t.Fatalf("valid authenticated echo failed: %v", err)
		}
		sc.Close()

		// Malformed or mismatched authenticated echoes MUST fail with an ordinary error (not *AuthError).
		badAuthCases := map[string]ldrcrypto.Map{
			"missing_v":         {{Key: "class", Value: "authenticated"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "session_id", Value: sid}},
			"wrong_v":           {{Key: "class", Value: "authenticated"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(2)}},
			"missing_gen":       {{Key: "class", Value: "authenticated"}, {Key: "line_id", Value: lineID}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
			"wrong_gen":         {{Key: "class", Value: "authenticated"}, {Key: "generation", Value: uint64(2)}, {Key: "line_id", Value: lineID}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
			"wrong_line":        {{Key: "class", Value: "authenticated"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: otherLineID}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
			"wrong_session":     {{Key: "class", Value: "authenticated"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "session_id", Value: otherSID}, {Key: "v", Value: uint64(1)}},
			"extra_unknown_key": {{Key: "class", Value: "authenticated"}, {Key: "extra", Value: uint64(1)}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
		}
		for name, rep := range badAuthCases {
			setReply(rep)
			_, err := DialSession(ctx, origin, lineID, profDig, 1, prin, rootKey)
			if err == nil {
				t.Fatalf("authenticated case %s unexpectedly succeeded", name)
			}
			var ae *AuthError
			if errors.As(err, &ae) {
				t.Fatalf("authenticated case %s returned *AuthError (%+v), want ordinary protocol error", name, ae)
			}
		}

		// Valid full revoked echo MUST return *AuthError(unresolved/revoked).
		setReply(ldrcrypto.Map{
			{Key: "class", Value: ldrcore.ClassUnresolved},
			{Key: "code", Value: "revoked"},
			{Key: "generation", Value: uint64(1)},
			{Key: "line_id", Value: lineID},
			{Key: "principal", Value: pCBOR},
			{Key: "server_nonce", Value: nonce},
			{Key: "session_id", Value: sid},
			{Key: "v", Value: uint64(1)},
		})
		_, err = DialSession(ctx, origin, lineID, profDig, 1, prin, rootKey)
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Class != ldrcore.ClassUnresolved || ae.Code != "revoked" {
			t.Fatalf("valid revoked echo: got %v, want *AuthError(unresolved/revoked)", err)
		}

		// Missing or mismatched revoked echo fields MUST yield an ordinary protocol error
		// (NEVER *AuthError) so callers do not persist a spurious Rule 8 revocation!
		badRevokedCases := map[string]ldrcrypto.Map{
			"bare_class_code_only": {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "v", Value: uint64(1)}},
			"wrong_v":              {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "principal", Value: pCBOR}, {Key: "server_nonce", Value: nonce}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(2)}},
			"wrong_gen":            {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "generation", Value: uint64(2)}, {Key: "line_id", Value: lineID}, {Key: "principal", Value: pCBOR}, {Key: "server_nonce", Value: nonce}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
			"wrong_line":           {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: otherLineID}, {Key: "principal", Value: pCBOR}, {Key: "server_nonce", Value: nonce}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
			"wrong_session":        {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "principal", Value: pCBOR}, {Key: "server_nonce", Value: nonce}, {Key: "session_id", Value: otherSID}, {Key: "v", Value: uint64(1)}},
			"wrong_nonce":          {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "principal", Value: pCBOR}, {Key: "server_nonce", Value: otherNonce}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
			"wrong_principal":      {{Key: "class", Value: ldrcore.ClassUnresolved}, {Key: "code", Value: "revoked"}, {Key: "generation", Value: uint64(1)}, {Key: "line_id", Value: lineID}, {Key: "principal", Value: otherPCBOR}, {Key: "server_nonce", Value: nonce}, {Key: "session_id", Value: sid}, {Key: "v", Value: uint64(1)}},
		}
		for name, rep := range badRevokedCases {
			setReply(rep)
			_, err := DialSession(ctx, origin, lineID, profDig, 1, prin, rootKey)
			if err == nil {
				t.Fatalf("revoked case %s unexpectedly succeeded", name)
			}
			var gotAE *AuthError
			if errors.As(err, &gotAE) {
				t.Fatalf("revoked case %s returned *AuthError (%+v), want ordinary protocol error", name, gotAE)
			}
		}
	})

	t.Run("wire_proxy_reply_binding_mutation_across_all_endpoints", func(t *testing.T) {
		var mu sync.Mutex
		var mutateResp func(m map[string]any)
		var rs *RelayServer

		proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			rs.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			mu.Lock()
			mut := mutateResp
			mu.Unlock()
			if mut != nil && !strings.HasSuffix(r.URL.Path, "/session/challenge") && !strings.HasSuffix(r.URL.Path, "/session/auth") {
				dec, err := ldrcrypto.UnmarshalCBOR(body, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 16384})
				if err == nil {
					if m, ok := dec.(map[string]any); ok {
						mut(m)
						if enc, err := ldrcrypto.MarshalCBORWithLimits(m, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 16384}); err == nil {
							body = enc
						}
					}
				}
			}
			for k, vals := range rec.Header() {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(body)
		})

		origin := startTLSHandler(t, proxy)
		r1, _ := ldrcrypto.GenerateEd25519Key()
		r2, _ := ldrcrypto.GenerateEd25519Key()
		lineID := bytes.Repeat([]byte{0x66}, 16)
		prof := ldrcrypto.ProfileV1()
		profDig, _ := prof.Digest()
		desc := ldrcrypto.CreationDescriptor{
			Version: 1, LineID: lineID, Generation: 1,
			RootKeys:    []ldrcrypto.PublicKey{r1.PublicKey(), r2.PublicKey()},
			RelayOrigin: origin, Profile: prof,
		}
		signedDesc, err := ldrcrypto.SignCreationDescriptor(r1, desc)
		if err != nil {
			t.Fatal(err)
		}
		rawDesc, _ := signedDesc.MarshalCanonical()
		_, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(rawDesc)
		if err != nil {
			t.Fatal(err)
		}
		st, err := ldrstore.OpenFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
		eng, err := NewRelayEngine(st, DefaultClockConfig(), fc.source())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Provision(rawDesc); err != nil {
			t.Fatal(err)
		}
		rs = NewRelayServer(eng)

		r1Prin := ldrcrypto.RootPrincipal(r1.PublicKey())
		sess, err := DialSession(ctx, origin, lineID, profDig, 1, r1Prin, r1)
		if err != nil {
			t.Fatalf("DialSession via proxy: %v", err)
		}
		defer sess.Close()

		// Commit line_init cleanly first.
		sortedRoots, _ := ldrcrypto.CanonicalRootKeys(desc.RootKeys)
		r0c, _ := sortedRoots[0].ToCBOR()
		r1c, _ := sortedRoots[1].ToCBOR()
		pMap, _ := prof.ToCBORMap()
		initBody, err := BuildWireIntentBody(WireIntentInput{
			ProfileDigest: profDig, LineID: lineID, Generation: 1,
			Origin: ldrcore.OriginRoot, Principal: r1Prin,
			OpID: "proxy-init", OpType: "line_init",
			SeenSeq: 0, SeenHead: genesis, ValidityMS: 600_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields: ldrcrypto.Map{
				{Key: "descriptor_digest", Value: cd[:]},
				{Key: "profile", Value: pMap},
				{Key: "root_keys", Value: []any{r0c, r1c}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		initEnv, err := ldrcrypto.SignIntent(r1, initBody)
		if err != nil {
			t.Fatal(err)
		}
		initDig, _ := initEnv.Digest()
		r1Tok, _ := PrincipalToken(r1Prin)
		initKey := ldrstore.StoredOpKey{Generation: 1, Signer: r1Tok, SeenSeq: 0, OpID: "proxy-init"}

		if rep, err := sess.Submit(ctx, initEnv.RawBytes, nil, nil); err != nil || rep.Outcome.Kind != ldrcore.Committed {
			t.Fatalf("baseline Submit: rep=%+v err=%v", rep, err)
		}

		// Mutate session_gen (omit / wrong value) and v (wrong value) on the live wire
		// across ALL 5 authenticated endpoints (Submit, Query, AnchorRequest, ControlLog, FetchSidecar).
		wireMuts := map[string]func(map[string]any){
			"omit_session_gen":  func(m map[string]any) { delete(m, "session_gen") },
			"wrong_session_gen": func(m map[string]any) { m["session_gen"] = uint64(2) },
			"wrong_v":           func(m map[string]any) { m["v"] = uint64(2) },
		}
		for name, mut := range wireMuts {
			mu.Lock()
			mutateResp = mut
			mu.Unlock()
			if _, err := sess.Submit(ctx, initEnv.RawBytes, nil, nil); err == nil {
				t.Fatalf("Submit accepted wire mutation %s", name)
			}
			if _, err := sess.Query(ctx, initKey, initDig); err == nil {
				t.Fatalf("Query accepted wire mutation %s", name)
			}
			if _, err := sess.AnchorRequest(ctx); err == nil {
				t.Fatalf("AnchorRequest accepted wire mutation %s", name)
			}
			if _, err := sess.ControlLog(ctx, 1, 16); err == nil {
				t.Fatalf("ControlLog accepted wire mutation %s", name)
			}
			if _, err := sess.FetchSidecar(ctx, ldrstore.SidecarPayload, [32]byte{0x01}); err == nil || strings.Contains(err.Error(), "sidecar refused") {
				t.Fatalf("FetchSidecar accepted wire mutation %s (err=%v)", name, err)
			}
		}
		mu.Lock()
		mutateResp = nil
		mu.Unlock()
		if rep, err := sess.Query(ctx, initKey, initDig); err != nil || rep.Outcome.Kind != ldrcore.Committed {
			t.Fatalf("unmutated Query after proxy clear: rep=%+v err=%v", rep, err)
		}
	})

	t.Run("live_reply_binding_and_idle_expiry", func(t *testing.T) {
		fx := startRelayFixture(t)
		root2Prin := ldrcrypto.RootPrincipal(fx.root2.PublicKey())

		// Install a mutating wrapper around fx.server? Better: reuse fx's TLS cert/key on a
		// fresh RelayServer backed by fx.engine? Even cleaner: test live RelayServer via a
		// mutating httptest proxy using the EXACT desc.RelayOrigin from a fixture!
		// First test validateSession idle expiry directly on fx.server (zero other handshakes!).
		var clockMu sync.Mutex
		now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
		fx.server.setTestSessionClock(func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		}, 5*time.Minute)
		advanceServerTime := func(d time.Duration) {
			clockMu.Lock()
			now = now.Add(d)
			clockMu.Unlock()
		}

		// Authenticate root2 as the ONLY session on fx.server and commit line_init.
		sRoot2, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, root2Prin, fx.root2)
		if err != nil {
			t.Fatalf("DialSession(root2): %v", err)
		}
		defer sRoot2.Close()

		sortedRoots, _ := ldrcrypto.CanonicalRootKeys(fx.desc.RootKeys)
		r0c, _ := sortedRoots[0].ToCBOR()
		r1c, _ := sortedRoots[1].ToCBOR()
		pMap, _ := fx.desc.Profile.ToCBORMap()
		initBody, err := BuildWireIntentBody(WireIntentInput{
			ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
			Origin: ldrcore.OriginRoot, Principal: root2Prin,
			OpID: "live-idle-init", OpType: "line_init",
			SeenSeq: 0, SeenHead: fx.genesis, ValidityMS: 600_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields: ldrcrypto.Map{
				{Key: "descriptor_digest", Value: fx.cd[:]},
				{Key: "profile", Value: pMap},
				{Key: "root_keys", Value: []any{r0c, r1c}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		initEnv, err := ldrcrypto.SignIntent(fx.root2, initBody)
		if err != nil {
			t.Fatal(err)
		}
		if rep, err := sRoot2.Submit(ctx, initEnv.RawBytes, nil, nil); err != nil || rep.Outcome.Kind != ldrcore.Committed {
			t.Fatalf("line_init Submit: rep=%+v err=%v", rep, err)
		}

		// Baseline request succeeds (session_gen == 1, v == 1).
		if _, err := sRoot2.ControlLog(ctx, 1, 16); err != nil {
			t.Fatalf("ControlLog at t=0: %v", err)
		}
		// Sidecar refusal (not_found) MUST also carry valid session_gen and pass verifyReplyBinding
		// (returning the structured sidecar refusal error, not a binding mismatch!).
		if _, err := sRoot2.FetchSidecar(ctx, ldrstore.SidecarPayload, [32]byte{0x99}); err == nil || !strings.Contains(err.Error(), "sidecar refused") {
			t.Fatalf("FetchSidecar missing blob: got %v, want sidecar refused (passing reply binding)", err)
		}

		// Anchor refusal with zero outcome generation (clock_uncertain -> rep.Gen == 0)
		// MUST still pass verifyReplyBinding because session_gen == 1 is echoed separately!
		fx.clock.wall -= 10_000
		fx.clock.mono += 100
		ancRef, err := sRoot2.AnchorRequest(ctx)
		if err != nil {
			t.Fatalf("AnchorRequest clock_uncertain refusal failed reply binding: %v", err)
		}
		if ancRef.Class != ldrcore.ClassAdmission || ancRef.Code != "clock_uncertain" || ancRef.Gen != 0 {
			t.Fatalf("unexpected anchor refusal: %+v", ancRef)
		}
		// Restore clock for normal operation.
		fx.clock.wall += 15_000
		fx.clock.mono += 1000
		cg, _ := fx.engine.ClockGuardFor(fx.lineID)
		if err := cg.ConfirmResume(); err != nil {
			t.Fatalf("ConfirmResume: %v", err)
		}

		// Direct verifyReplyBinding checks: missing/wrong v, session_gen, session_id, req_id, req_digest, line_id.
		reqDig := sha256.Sum256([]byte("req-body"))
		makeGoodReply := func() map[string]any {
			return map[string]any{
				"v":           uint64(1),
				"session_gen": uint64(1),
				"session_id":  sRoot2.SessionID(),
				"req_id":      uint64(42),
				"req_digest":  reqDig[:],
				"line_id":     bytes.Clone(fx.lineID),
			}
		}
		if err := sRoot2.verifyReplyBinding(makeGoodReply(), 42, reqDig); err != nil {
			t.Fatalf("valid verifyReplyBinding failed: %v", err)
		}
		mutations := map[string]func(map[string]any){
			"missing_v":           func(m map[string]any) { delete(m, "v") },
			"wrong_v":             func(m map[string]any) { m["v"] = uint64(2) },
			"missing_session_gen": func(m map[string]any) { delete(m, "session_gen") },
			"zero_session_gen":    func(m map[string]any) { m["session_gen"] = uint64(0) },
			"wrong_session_gen":   func(m map[string]any) { m["session_gen"] = uint64(2) },
			"wrong_session_id":    func(m map[string]any) { m["session_id"] = bytes.Repeat([]byte{0xee}, 16) },
			"wrong_req_id":        func(m map[string]any) { m["req_id"] = uint64(43) },
			"wrong_req_digest":    func(m map[string]any) { m["req_digest"] = bytes.Repeat([]byte{0xdd}, 32) },
			"wrong_line_id":       func(m map[string]any) { m["line_id"] = bytes.Repeat([]byte{0xcc}, 16) },
		}
		for name, mut := range mutations {
			m := makeGoodReply()
			mut(m)
			if err := sRoot2.verifyReplyBinding(m, 42, reqDig); err == nil {
				t.Fatalf("verifyReplyBinding accepted mutated reply (%s)", name)
			}
		}

		// Idle expiry enforcement on lookup WITHOUT any other handshake/sweep:
		// 4m59s (< 5m idle limit) succeeds and refreshes lastSeen.
		advanceServerTime(4*time.Minute + 59*time.Second)
		if _, err := sRoot2.ControlLog(ctx, 1, 16); err != nil {
			t.Fatalf("ControlLog just before idle timeout failed: %v", err)
		}
		// 5m01s (> 5m idle limit) with ZERO other clients MUST reject immediately and evict the session!
		advanceServerTime(5*time.Minute + time.Second)
		if _, err := sRoot2.ControlLog(ctx, 1, 16); err == nil {
			t.Fatalf("expired idle session unexpectedly accepted ControlLog without sweep!")
		}
		// Session was evicted on lookup: even stepping server time back cannot resurrect it!
		advanceServerTime(-4 * time.Minute)
		if _, err := sRoot2.AnchorRequest(ctx); err == nil {
			t.Fatalf("evicted idle session unexpectedly resurrected on AnchorRequest!")
		}
	})
}

// TestTLSOriginSingleCAPinningAndIPv6DialAddr verifies Codex Turn 68:
//  1. pin_ca_root_pem enforces a single valid CA certificate with no extra PEM
//     material (rejecting multi-cert bundles, trailing/leading junk, and non-CA
//     leaf certs in both RelayOrigin.Validate and ClientTLSConfig) and verifies
//     live TLS 1.3 trust exclusively against that one pinned CA.
//  2. DialSession resolves default port 443 and explicit ports cleanly for
//     bracketed IPv6, IPv4, and DNS origins via net.JoinHostPort, including a
//     live TLS 1.3 handshake over IPv6 loopback ([::1]) when available.
func TestTLSOriginSingleCAPinningAndIPv6DialAddr(t *testing.T) {
	ctx := context.Background()

	mintCA := func(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	mintServerCert := func(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ips []net.IP, dns []string) (tls.Certificate, []byte) {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "relay-leaf"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  false,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses:           ips,
			DNSNames:              dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM
	}

	t.Run("single_ca_pinning_validation_and_live_tls13", func(t *testing.T) {
		caA, caAKey, caAPEM := mintCA(t, "internal-ca-A")
		caB, caBKey, caBPEM := mintCA(t, "internal-ca-B")
		leafA, leafAPEM := mintServerCert(t, caA, caAKey, []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
		leafB, _ := mintServerCert(t, caB, caBKey, []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})

		// Reject multi-CA bundle, leading text, trailing junk, non-CA leaf cert, and empty bytes.
		badPins := map[string][]byte{
			"empty":         nil,
			"multi_ca":      append(bytes.Clone(caAPEM), caBPEM...),
			"leading_text":  append([]byte("comment\n"), caAPEM...),
			"trailing_junk": append(bytes.Clone(caAPEM), []byte("extra\n")...),
			"non_ca_leaf":   leafAPEM,
		}
		for name, pin := range badPins {
			ro := ldrcrypto.RelayOrigin{
				URL:            "https://127.0.0.1:8443",
				TLSPolicy:      ldrcrypto.TLSPolicyPinCARootPEM,
				TLSPin:         pin,
				SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
			}
			if err := ro.Validate(); err == nil {
				t.Fatalf("RelayOrigin.Validate accepted %s pin_ca_root_pem", name)
			}
			if _, err := ClientTLSConfig(ro); err == nil {
				t.Fatalf("ClientTLSConfig accepted %s pin_ca_root_pem", name)
			}
		}

		// Live TLS 1.3 handshake: pinning caA trusts server presenting leafA and rejects server presenting leafB.
		serveLeaf := func(t *testing.T, leaf tls.Certificate) string {
			t.Helper()
			rawLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tlsLn := tls.NewListener(rawLn, &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{leaf},
			})
			hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})}
			go func() { _ = hs.Serve(tlsLn) }()
			t.Cleanup(func() {
				_ = hs.Close()
				_ = tlsLn.Close()
			})
			return "https://" + rawLn.Addr().String()
		}

		urlA := serveLeaf(t, leafA)
		urlB := serveLeaf(t, leafB)

		originA := ldrcrypto.RelayOrigin{
			URL:            urlA,
			TLSPolicy:      ldrcrypto.TLSPolicyPinCARootPEM,
			TLSPin:         caAPEM,
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		}
		cfgA, err := ClientTLSConfig(originA)
		if err != nil {
			t.Fatalf("ClientTLSConfig(valid single CA): %v", err)
		}
		hcA := &http.Client{Transport: &http.Transport{TLSClientConfig: cfgA}}
		defer hcA.CloseIdleConnections()
		resp, err := hcA.Get(urlA)
		if err != nil {
			t.Fatalf("TLS 1.3 GET with pinned CA A failed: %v", err)
		}
		_ = resp.Body.Close()

		// Server signed by unpinned CA B MUST be rejected when pinned to CA A.
		originB := originA
		originB.URL = urlB
		cfgB, err := ClientTLSConfig(originB)
		if err != nil {
			t.Fatal(err)
		}
		hcB := &http.Client{Transport: &http.Transport{TLSClientConfig: cfgB}}
		defer hcB.CloseIdleConnections()
		if _, err := hcB.Get(urlB); err == nil {
			t.Fatalf("pinned CA A unexpectedly accepted certificate signed by unpinned CA B!")
		}
	})

	t.Run("ipv6_default_and_explicit_port_resolution_and_dial", func(t *testing.T) {
		cases := []struct {
			rawURL string
			want   string
		}{
			{"https://[::1]", "[::1]:443"},
			{"https://[::1]:8443", "[::1]:8443"},
			{"https://[2001:db8::1]", "[2001:db8::1]:443"},
			{"https://[2001:db8::1]:9443", "[2001:db8::1]:9443"},
			{"https://127.0.0.1", "127.0.0.1:443"},
			{"https://127.0.0.1:8443", "127.0.0.1:8443"},
			{"https://relay.example.com", "relay.example.com:443"},
			{"https://relay.example.com:8443", "relay.example.com:8443"},
		}
		for _, tc := range cases {
			got, err := resolveOriginDialAddr(tc.rawURL)
			if err != nil {
				t.Fatalf("resolveOriginDialAddr(%q): %v", tc.rawURL, err)
			}
			if got != tc.want {
				t.Fatalf("resolveOriginDialAddr(%q) = %q, want %q", tc.rawURL, got, tc.want)
			}
		}

		// Verify DialSession with a bracketed IPv6 origin omitting port attempts "[::1]:443"
		// rather than failing with "missing port in address".
		r1, _ := ldrcrypto.GenerateEd25519Key()
		r2, _ := ldrcrypto.GenerateEd25519Key()
		prof := ldrcrypto.ProfileV1()
		profDig, _ := prof.Digest()
		lineID := bytes.Repeat([]byte{0x77}, 16)
		r1Prin := ldrcrypto.RootPrincipal(r1.PublicKey())

		defaultPortOrigin := ldrcrypto.RelayOrigin{
			URL:            "https://[::1]",
			TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
			TLSPin:         bytes.Repeat([]byte{0x11}, 32),
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		}
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, dialErr := DialSession(dialCtx, defaultPortOrigin, lineID, profDig, 1, r1Prin, r1)
		if dialErr != nil && strings.Contains(dialErr.Error(), "missing port in address") {
			t.Fatalf("DialSession on default-port IPv6 origin failed with missing port: %v", dialErr)
		}

		// Live end-to-end TLS 1.3 DialSession over explicit IPv6 loopback ([::1]:<port>)
		// combined with single-CA pin_ca_root_pem!
		rawLn, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable in this environment: %v", err)
		}
		ca, caKey, caPEM := mintCA(t, "ipv6-ca")
		leaf, _ := mintServerCert(t, ca, caKey, []net.IP{net.ParseIP("::1")}, nil)
		tlsLn := tls.NewListener(rawLn, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{leaf},
			NextProtos:   []string{"h2", "http/1.1"},
		})

		ipv6Origin := ldrcrypto.RelayOrigin{
			URL:            "https://" + rawLn.Addr().String(),
			TLSPolicy:      ldrcrypto.TLSPolicyPinCARootPEM,
			TLSPin:         caPEM,
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		}
		desc := ldrcrypto.CreationDescriptor{
			Version: 1, LineID: lineID, Generation: 1,
			RootKeys:    []ldrcrypto.PublicKey{r1.PublicKey(), r2.PublicKey()},
			RelayOrigin: ipv6Origin, Profile: prof,
		}
		signedDesc, err := ldrcrypto.SignCreationDescriptor(r1, desc)
		if err != nil {
			t.Fatal(err)
		}
		rawDesc, _ := signedDesc.MarshalCanonical()
		st, err := ldrstore.OpenFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
		eng, err := NewRelayEngine(st, DefaultClockConfig(), fc.source())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Provision(rawDesc); err != nil {
			t.Fatal(err)
		}
		hs := &http.Server{Handler: NewRelayServer(eng)}
		go func() { _ = hs.Serve(tlsLn) }()
		t.Cleanup(func() {
			_ = hs.Close()
			_ = tlsLn.Close()
		})

		sess, err := DialSession(ctx, ipv6Origin, lineID, profDig, 1, r1Prin, r1)
		if err != nil {
			t.Fatalf("live IPv6 explicit-port DialSession with single-CA pin failed: %v", err)
		}
		sess.Close()
	})
}
