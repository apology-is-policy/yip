package ldrclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

func signClientFrame(t *testing.T, signer ldrcrypto.Signer, prevHead [32]byte, seq, seqTime uint64, in ldrrelay.WireIntentInput) ldrrelay.ControlFrameWire {
	t.Helper()
	body, err := ldrrelay.BuildWireIntentBody(in)
	if err != nil {
		t.Fatalf("BuildWireIntentBody(%s): %v", in.OpType, err)
	}
	env, err := ldrcrypto.SignIntent(signer, body)
	if err != nil {
		t.Fatalf("SignIntent(%s): %v", in.OpType, err)
	}
	head, err := ldrcrypto.ClientChainHead(prevHead, in.ProfileDigest, in.LineID, in.Generation, seq, seqTime, in.Origin, env.RawBytes)
	if err != nil {
		t.Fatalf("ClientChainHead(%s): %v", in.OpType, err)
	}
	var pc *ldrcrypto.Commitment
	if in.PayloadCommit.Length > 0 {
		c := in.PayloadCommit
		pc = &c
	}
	return ldrrelay.ControlFrameWire{
		Gen:           in.Generation,
		Seq:           seq,
		SeqTime:       seqTime,
		PrevHead:      prevHead,
		Head:          head,
		Origin:        in.Origin,
		OpType:        in.OpType,
		IntentBytes:   env.RawBytes,
		PayloadCommit: pc,
		WrapCommits:   append([]ldrcrypto.WrapManifestEntry(nil), in.Manifest...),
	}
}

// TestClientGenesisBootstrapAndOuterFrameMetadataParity verifies Codex Slice 2 Finding 1:
// client genesis replay uses the exact same pinned bootstrap checks as the relay
// (root pair + embedded profile + descriptor digest + genesis anchor), and verifies
// outer origin, op_type, PayloadCommit, and WrapCommits against the signed body
// BEFORE persisting any frame to verified.wal.
func TestClientGenesisBootstrapAndOuterFrameMetadataParity(t *testing.T) {
	env := startTestRelay(t)
	desc, cd, genesis, profDigest := func() (ldrcrypto.CreationDescriptor, [32]byte, [32]byte, [32]byte) {
		d, c, g, _, err := ldrcrypto.VerifyCreationDescriptor(env.rawDesc)
		if err != nil {
			t.Fatal(err)
		}
		pd, _ := d.Profile.Digest()
		return d, c, g, pd
	}()

	root1Prin := ldrcrypto.RootPrincipal(env.root1.Signer.PublicKey())
	sortedRoots, _ := ldrcrypto.CanonicalRootKeys(desc.RootKeys)
	rk0, _ := sortedRoots[0].ToCBOR()
	rk1, _ := sortedRoots[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	t0 := uint64(1_700_000_000_000)

	validInitFrame := signClientFrame(t, env.root1.Signer, genesis, 1, t0, ldrrelay.WireIntentInput{
		ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root1Prin,
		OpID: "init-1", OpType: "line_init",
		SeenSeq: 0, SeenHead: genesis, ValidityMS: 0,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: cd[:]},
			{Key: "profile", Value: profMap},
			{Key: "root_keys", Value: []any{rk0, rk1}},
		},
	})

	newFreshClient := func(t *testing.T) (*Client, string) {
		t.Helper()
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindAdmin, SignedDescriptor: env.rawDesc, Activated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cl.Close() })
		return cl, dir
	}

	assertRejectedAndUnpersisted := func(t *testing.T, cl *Client, dir string, fr ldrrelay.ControlFrameWire, wantSeq uint64) {
		t.Helper()
		cl.mu.Lock()
		err := cl.verifyAndApplyFrameLocked(fr, true)
		gotSeq := cl.ckSeq
		cl.mu.Unlock()
		if err == nil {
			t.Fatalf("expected verifyAndApplyFrameLocked to fail closed, but it succeeded")
		}
		if gotSeq != wantSeq {
			t.Fatalf("checkpoint mutated on rejected frame: got %d, want %d", gotSeq, wantSeq)
		}
		frames, werr := loadVerifiedWAL(filepath.Join(dir, "verified.wal"), nil, nil)
		if werr != nil {
			t.Fatalf("loadVerifiedWAL: %v", werr)
		}
		if uint64(len(frames)) != wantSeq {
			t.Fatalf("rejected frame leaked into verified.wal: len=%d want=%d", len(frames), wantSeq)
		}
	}

	t.Run("line_init_wrong_root_keys_with_matching_descriptor_digest", func(t *testing.T) {
		cl, dir := newFreshClient(t)
		rogue, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
		badSorted, _ := ldrcrypto.CanonicalRootKeys([]ldrcrypto.PublicKey{env.root1.Signer.PublicKey(), rogue.Signer.PublicKey()})
		br0, _ := badSorted[0].ToCBOR()
		br1, _ := badSorted[1].ToCBOR()
		badInit := signClientFrame(t, env.root1.Signer, genesis, 1, t0, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginRoot, Principal: root1Prin,
			OpID: "init-bad-roots", OpType: "line_init",
			SeenSeq: 0, SeenHead: genesis, ValidityMS: 0,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields: ldrcrypto.Map{
				{Key: "descriptor_digest", Value: cd[:]}, // matches pinned cd!
				{Key: "profile", Value: profMap},
				{Key: "root_keys", Value: []any{br0, br1}}, // forged second root!
			},
		})
		assertRejectedAndUnpersisted(t, cl, dir, badInit, 0)
	})

	t.Run("line_init_wrong_embedded_profile_with_matching_descriptor_digest", func(t *testing.T) {
		cl, dir := newFreshClient(t)
		badProf := desc.Profile
		badProf.FreshnessMS += 1000 // differs from pinned descriptor profile!
		badProfMap, _ := badProf.ToCBORMap()
		badInit := signClientFrame(t, env.root1.Signer, genesis, 1, t0, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginRoot, Principal: root1Prin,
			OpID: "init-bad-prof", OpType: "line_init",
			SeenSeq: 0, SeenHead: genesis, ValidityMS: 0,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields: ldrcrypto.Map{
				{Key: "descriptor_digest", Value: cd[:]}, // matches pinned cd!
				{Key: "profile", Value: badProfMap},      // forged initial profile!
				{Key: "root_keys", Value: []any{rk0, rk1}},
			},
		})
		assertRejectedAndUnpersisted(t, cl, dir, badInit, 0)
	})

	t.Run("outer_origin_op_type_and_sidecar_metadata_mismatches_rejected_before_persist", func(t *testing.T) {
		// Build a valid sequence up through key_epoch_activate (wrap commits) and broadcast_create (payload commit).
		opKey, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
		opPrin := ldrcrypto.OperatorPrincipal(opKey.Signer.PublicKey())
		opCBOR, _ := opKey.Signer.PublicKey().ToCBOR()
		credKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		credPrin := ldrcrypto.CredentialPrincipal(credKeys.CredID)
		skC, _ := credKeys.Signing.Signer.PublicKey().ToCBOR()
		ekC, _ := credKeys.Encryption.PublicKey().ToCBOR()

		fr2 := signClientFrame(t, env.root1.Signer, validInitFrame.Head, 2, t0+1000, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginRoot, Principal: root1Prin,
			OpID: "op-auth", OpType: "operator_key_authorize",
			AuthEpoch: 0, SeenSeq: 1, SeenHead: validInitFrame.Head, ValidityMS: 60_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Expect:        ldrcrypto.ExpectMap{"root_rev": 1},
			Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
		})
		fr3 := signClientFrame(t, opKey.Signer, fr2.Head, 3, t0+2000, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginOperator, Principal: opPrin,
			OpID: "enroll-1", OpType: "credential_enroll",
			AuthEpoch: 1, SeenSeq: 2, SeenHead: fr2.Head, ValidityMS: 60_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields: ldrcrypto.Map{
				{Key: "cred_id", Value: credKeys.CredID[:]},
				{Key: "encryption_key", Value: ekC},
				{Key: "grant", Value: ldrcrypto.Map{
					{Key: "actor_limit", Value: uint64(2)},
					{Key: "namespace_id", Value: "ns-x"},
					{Key: "reader", Value: true},
				}},
				{Key: "join_request_digest", Value: bytes.Repeat([]byte{0x22}, 32)},
				{Key: "join_request_id", Value: []byte("jr-x")},
				{Key: "signing_key", Value: skC},
			},
		})
		wrapCommit, _ := ldrcrypto.CommitWrap([]byte("wrap-bytes"))
		fr4 := signClientFrame(t, opKey.Signer, fr3.Head, 4, t0+3000, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginOperator, Principal: opPrin,
			OpID: "act-1", OpType: "key_epoch_activate",
			AuthEpoch: 2, KeyEpoch: 0, SeenSeq: 3, SeenHead: fr3.Head, ValidityMS: 60_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Expect:        ldrcrypto.ExpectMap{"key_epoch": 0},
			Manifest:      []ldrcrypto.WrapManifestEntry{{CredID: credKeys.CredID, Commit: wrapCommit}},
		})
		fr5 := signClientFrame(t, credKeys.Signing.Signer, fr4.Head, 5, t0+4000, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginCredential, Principal: credPrin,
			OpID: "decl-1", OpType: "actor_declare",
			AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 4, SeenHead: fr4.Head, ValidityMS: 60_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields:        ldrcrypto.Map{{Key: "actor_id", Value: "a1"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-x"}},
		})
		payCommit, _ := ldrcrypto.CommitPayload([]byte("ciphertext-bytes"))
		fr6 := signClientFrame(t, opKey.Signer, fr5.Head, 6, t0+5000, ldrrelay.WireIntentInput{
			ProfileDigest: profDigest, LineID: env.lineID, Generation: 1,
			Origin: ldrcore.OriginOperator, Principal: opPrin,
			OpID: "bc-1", OpType: "broadcast_create",
			AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 5, SeenHead: fr5.Head, ValidityMS: 60_000,
			PayloadCommit: payCommit,
			Fields: ldrcrypto.Map{
				{Key: "broadcast_id", Value: "b1"},
				{Key: "default_audience", Value: false},
				{Key: "kind", Value: "briefing"},
				{Key: "recipients", Value: []any{"a1"}},
			},
		})

		applyPrefix := func(t *testing.T, frames ...ldrrelay.ControlFrameWire) (*Client, string) {
			t.Helper()
			cl, dir := newFreshClient(t)
			cl.mu.Lock()
			for _, f := range frames {
				if err := cl.verifyAndApplyFrameLocked(f, true); err != nil {
					cl.mu.Unlock()
					t.Fatalf("apply prefix seq %d: %v", f.Seq, err)
				}
			}
			cl.mu.Unlock()
			return cl, dir
		}

		// Mismatched outer origin
		cl, dir := applyPrefix(t, validInitFrame)
		badOrigin := fr2
		badOrigin.Origin = ldrcore.OriginOperator
		assertRejectedAndUnpersisted(t, cl, dir, badOrigin, 1)

		// Mismatched outer op_type
		cl, dir = applyPrefix(t, validInitFrame)
		badType := fr2
		badType.OpType = "operator_key_revoke"
		assertRejectedAndUnpersisted(t, cl, dir, badType, 1)

		// Mismatched / missing outer WrapCommits on key_epoch_activate
		cl, dir = applyPrefix(t, validInitFrame, fr2, fr3)
		badWraps := fr4
		badWraps.WrapCommits = nil
		assertRejectedAndUnpersisted(t, cl, dir, badWraps, 3)

		cl, dir = applyPrefix(t, validInitFrame, fr2, fr3)
		tamperedWraps := fr4
		tamperedWraps.WrapCommits = []ldrcrypto.WrapManifestEntry{{CredID: credKeys.CredID, Commit: ldrcrypto.Commitment{Length: wrapCommit.Length, Digest: [32]byte{0x99}}}}
		assertRejectedAndUnpersisted(t, cl, dir, tamperedWraps, 3)

		// Mismatched / missing outer PayloadCommit on broadcast_create
		cl, dir = applyPrefix(t, validInitFrame, fr2, fr3, fr4, fr5)
		missingPay := fr6
		missingPay.PayloadCommit = nil
		assertRejectedAndUnpersisted(t, cl, dir, missingPay, 5)

		cl, dir = applyPrefix(t, validInitFrame, fr2, fr3, fr4, fr5)
		badPay := fr6
		tamperedPC := payCommit
		tamperedPC.Digest[0] ^= 0xff
		badPay.PayloadCommit = &tamperedPC
		assertRejectedAndUnpersisted(t, cl, dir, badPay, 5)

		// Sequencer time_anchor carrying stray sidecar metadata
		cl, dir = applyPrefix(t, validInitFrame)
		ancHead, _ := ldrcrypto.AnchorChainHead(validInitFrame.Head, profDigest, env.lineID, 1, 2, t0+1000)
		badAnchor := ldrrelay.ControlFrameWire{
			Gen: 1, Seq: 2, SeqTime: t0 + 1000, PrevHead: validInitFrame.Head, Head: ancHead,
			Origin: ldrcore.OriginSequencer, OpType: "time_anchor",
			PayloadCommit: &payCommit,
		}
		assertRejectedAndUnpersisted(t, cl, dir, badAnchor, 1)

		// Clean full sequence persists with sidecar metadata and reopens cleanly!
		clOK, dirOK := applyPrefix(t, validInitFrame, fr2, fr3, fr4, fr5, fr6)
		_ = clOK.Close()
		reopened, err := OpenClient(dirOK)
		if err != nil {
			t.Fatalf("OpenClient after clean verified.wal: %v", err)
		}
		defer reopened.Close()
		if _, seq, _ := reopened.Checkpoint(); seq != 6 {
			t.Fatalf("reopened checkpoint seq=%d, want 6", seq)
		}
	})
}

// setupOnboardingFixture prepares a live TLS 1.3 relay with an initialized line,
// an authorized operator, an enrolled reader Alice (who activates epoch 1), and
// a helper to enroll additional members with explicit join_request_id & digest.
type onboardingFixture struct {
	env        *testRelayEnv
	admin      *Client
	sOp        *ldrrelay.SessionClient
	opKey      *SigningKeyMaterial
	alice      *Client
	sAlice     *ldrrelay.SessionClient
	aliceKeys  *CredentialKeyBundle
	aliceGrant ldrcrypto.JoinGrant
}

func startOnboardingFixture(t *testing.T) *onboardingFixture {
	t.Helper()
	ctx := context.Background()
	env := startTestRelay(t)

	opKey, _ := GenerateSigningKey(ldrcrypto.AlgECDSAP256)
	opCred, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	adminDir := t.TempDir()
	admin, err := InitClientDir(InitDirOptions{
		Dir: adminDir, DirKind: DirKindAdmin, SignedDescriptor: env.rawDesc, CredKeys: opCred, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	admin.AttachRootKey(env.root1)
	admin.AttachOperatorKey(opKey)

	sRoot, err := admin.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sRoot.Close() })

	desc, cd, _, _ := admin.Descriptor()
	rk0, _ := desc.RootKeys[0].ToCBOR()
	rk1, _ := desc.RootKeys[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	op1, _ := admin.ComposeAndPersist(ComposeParams{
		Action: "line_init", Origin: ldrcore.OriginRoot, OpType: "line_init",
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: cd[:]},
			{Key: "profile", Value: profMap},
			{Key: "root_keys", Value: []any{rk0, rk1}},
		},
	})
	if rep, err := admin.Send(ctx, sRoot, op1); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("line_init: %+v, err=%v", rep, err)
	}
	_, _ = admin.Sync(ctx, sRoot)

	env.tick(1000)
	opPubC, _ := opKey.Signer.PublicKey().ToCBOR()
	op2, _ := admin.ComposeAndPersist(ComposeParams{
		Action: "auth_op", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubC}},
	})
	if rep, err := admin.Send(ctx, sRoot, op2); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("auth_op: %+v, err=%v", rep, err)
	}
	_, _ = admin.Sync(ctx, sRoot)

	sOp, err := admin.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sOp.Close() })

	fx := &onboardingFixture{env: env, admin: admin, sOp: sOp, opKey: opKey}
	fx.enrollRaw(t, opCred, ldrcrypto.JoinGrant{NamespaceID: "ns-op", ActorLimit: 0, Reader: true}, bytes.Repeat([]byte{0x01}, 16), [32]byte{0x01})

	aliceKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	aliceGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-alice", ActorLimit: 4, Reader: true}
	aliceReqID, aliceReqDig := fx.enrollP3(t, aliceKeys, aliceGrant, 0x02)

	actOp, _, err := admin.ComposeEpochActivate("act-1")
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sOp, actOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("epoch_activate 1: %+v, err=%v", rep, err)
	}
	_, _ = admin.Sync(ctx, sOp)

	aliceDir := t.TempDir()
	alice, err := InitClientDir(InitDirOptions{
		Dir: aliceDir, DirKind: DirKindMember, SignedDescriptor: env.rawDesc, CredKeys: aliceKeys,
		ExpectedGrant: &aliceGrant, ExpectedJoinReq: aliceReqID, ExpectedJoinReqDigest: &aliceReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alice.Close() })
	sAlice, err := alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sAlice.Close() })
	if err := alice.VerifyEnrollmentAndActivate(ctx, sAlice); err != nil {
		t.Fatalf("alice activate: %v", err)
	}

	fx.alice = alice
	fx.sAlice = sAlice
	fx.aliceKeys = aliceKeys
	fx.aliceGrant = aliceGrant
	return fx
}

func (fx *onboardingFixture) enrollP3(t *testing.T, credKeys *CredentialKeyBundle, grant ldrcrypto.JoinGrant, reqByte byte) ([]byte, [32]byte) {
	t.Helper()
	req, err := ldrcrypto.SignJoinRequest(credKeys.Signing.Signer, ldrcrypto.JoinRequest{
		RequestID:        bytes.Repeat([]byte{reqByte}, 16),
		LineID:           fx.env.lineID,
		Generation:       1,
		DescriptorDigest: fx.env.cd,
		EncryptionKey:    credKeys.Encryption.PublicKey(),
		Grant:            grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	reqDig, err := ldrcrypto.VerifyJoinRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	fx.enrollRaw(t, credKeys, grant, req.RequestID, reqDig)
	return req.RequestID, reqDig
}

func (fx *onboardingFixture) enrollRaw(t *testing.T, credKeys *CredentialKeyBundle, grant ldrcrypto.JoinGrant, reqID []byte, reqDig [32]byte) {
	t.Helper()
	ctx := context.Background()
	fx.env.tick(500)
	_, _ = fx.admin.Sync(ctx, fx.sOp)
	skC, _ := credKeys.Signing.Signer.PublicKey().ToCBOR()
	ekC, _ := credKeys.Encryption.PublicKey().ToCBOR()
	opID, err := fx.admin.ComposeAndPersist(ComposeParams{
		Action: "enroll", Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
		Fields: ldrcrypto.Map{
			{Key: "cred_id", Value: credKeys.CredID[:]},
			{Key: "encryption_key", Value: ekC},
			{Key: "grant", Value: ldrcrypto.Map{
				{Key: "actor_limit", Value: grant.ActorLimit},
				{Key: "namespace_id", Value: grant.NamespaceID},
				{Key: "reader", Value: grant.Reader},
			}},
			{Key: "join_request_digest", Value: reqDig[:]},
			{Key: "join_request_id", Value: reqID},
			{Key: "signing_key", Value: skC},
		},
	})
	if err != nil {
		t.Fatalf("Compose(enroll): %v", err)
	}
	if rep, err := fx.admin.Send(ctx, fx.sOp, opID); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(enroll): %+v, err=%v", rep, err)
	}
	_, _ = fx.admin.Sync(ctx, fx.sOp)
}

func (fx *onboardingFixture) activateNextEpoch(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	fx.env.tick(500)
	_, _ = fx.admin.Sync(ctx, fx.sOp)
	opID, _, err := fx.admin.ComposeEpochActivate("act-next")
	if err != nil {
		t.Fatalf("ComposeEpochActivate: %v", err)
	}
	if rep, err := fx.admin.Send(ctx, fx.sOp, opID); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(epoch_activate): %+v, err=%v", rep, err)
	}
	_, _ = fx.admin.Sync(ctx, fx.sOp)
}

// TestClientO25CompleteP3CeremonyAndDirectoryDistinction verifies Codex Slice 2 Finding 2:
// joining member directories require complete P3 ceremony evidence (keys, grant,
// join_request_id, join_request_digest), VerifyEnrollmentAndActivate verifies
// the actual committed credential_enroll record against all ceremony fields, and
// pre-existing administrative directories are explicitly distinguished.
func TestClientO25CompleteP3CeremonyAndDirectoryDistinction(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	grant := ldrcrypto.JoinGrant{NamespaceID: "ns-ceremony", ActorLimit: 2, Reader: true}
	reqID, reqDig := fx.enrollP3(t, keys, grant, 0x33)
	fx.activateNextEpoch(t)

	t.Run("incomplete_joining_ceremony_evidence_rejected_at_init", func(t *testing.T) {
		badCases := []struct {
			name string
			opts InitDirOptions
		}{
			{
				name: "missing_join_req_id",
				opts: InitDirOptions{Dir: t.TempDir(), SignedDescriptor: fx.env.rawDesc, CredKeys: keys, ExpectedGrant: &grant, ExpectedJoinReqDigest: &reqDig, Activated: false},
			},
			{
				name: "missing_join_req_digest",
				opts: InitDirOptions{Dir: t.TempDir(), SignedDescriptor: fx.env.rawDesc, CredKeys: keys, ExpectedGrant: &grant, ExpectedJoinReq: reqID, Activated: false},
			},
			{
				name: "missing_expected_grant",
				opts: InitDirOptions{Dir: t.TempDir(), SignedDescriptor: fx.env.rawDesc, CredKeys: keys, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false},
			},
			{
				name: "missing_cred_keys",
				opts: InitDirOptions{Dir: t.TempDir(), SignedDescriptor: fx.env.rawDesc, ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false},
			},
			{
				name: "member_dir_cannot_start_activated",
				opts: InitDirOptions{Dir: t.TempDir(), DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys, ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: true},
			},
		}
		for _, tc := range badCases {
			if _, err := InitClientDir(tc.opts); !errors.Is(err, ErrEnrollmentCheck) {
				t.Fatalf("case %s: got %v, want ErrEnrollmentCheck", tc.name, err)
			}
		}
	})

	t.Run("admin_directory_distinguished_from_joining_member_directory", func(t *testing.T) {
		if st := fx.admin.Status(); st.DirKind != DirKindAdmin || !st.Activated {
			t.Fatalf("expected DirKindAdmin & Activated=true, got %+v", st)
		}
		if err := fx.admin.VerifyEnrollmentAndActivate(ctx, fx.sOp); !errors.Is(err, ErrEnrollmentCheck) {
			t.Fatalf("VerifyEnrollmentAndActivate on admin dir: got %v, want ErrEnrollmentCheck", err)
		}
	})

	t.Run("mismatched_join_request_id_fails_activation", func(t *testing.T) {
		wrongReqID := bytes.Repeat([]byte{0x99}, 16)
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: wrongReqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); !errors.Is(err, ErrEnrollmentCheck) {
			t.Fatalf("expected ErrEnrollmentCheck on join_request_id mismatch, got %v", err)
		}
		if cl.Status().Activated {
			t.Fatalf("client must remain unactivated on join_request_id mismatch")
		}
	})

	t.Run("mismatched_join_request_digest_fails_activation", func(t *testing.T) {
		wrongDig := reqDig
		wrongDig[0] ^= 0xff
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &wrongDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); !errors.Is(err, ErrEnrollmentCheck) {
			t.Fatalf("expected ErrEnrollmentCheck on join_request_digest mismatch, got %v", err)
		}
		if cl.Status().Activated {
			t.Fatalf("client must remain unactivated on join_request_digest mismatch")
		}
	})

	t.Run("tampered_config_missing_digest_fails_open", func(t *testing.T) {
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		cfg := cl.cfg
		_ = cl.Close()
		cfg.ExpectedJoinReqDigest = nil
		if err := saveConfig(filepath.Join(dir, "config.cbor"), cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenClient(dir); !errors.Is(err, ErrEnrollmentCheck) {
			t.Fatalf("OpenClient on member dir missing expected_join_req_digest: got %v, want ErrEnrollmentCheck", err)
		}
	})

	t.Run("complete_matching_ceremony_activates_and_reopens", func(t *testing.T) {
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); err != nil {
			t.Fatalf("VerifyEnrollmentAndActivate with complete matching ceremony: %v", err)
		}
		sess.Close()
		_ = cl.Close()
		cl2, err := OpenClient(dir)
		if err != nil {
			t.Fatalf("reopen activated member: %v", err)
		}
		defer cl2.Close()
		if !cl2.Status().Activated || cl2.Status().DirKind != DirKindMember {
			t.Fatalf("unexpected reopened status: %+v", cl2.Status())
		}
	})
}

// TestClientActivationGateBlocksPublicationAndDelivery verifies Codex Slice 2 Finding 3:
// before O25 activation passes (and after failed activation), provisional control replay
// and epoch wrap verification work, while Project, Rebuild, VerifiedRead, ReadPayload,
// ScanDelivery, DeliverableNotices, and AckNotice are strictly blocked and cannot publish
// projection files, advance delivery cursors, or expose queued notices.
func TestClientActivationGateBlocksPublicationAndDelivery(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	// Enroll Bob and activate epoch 2.
	bobKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-bob", ActorLimit: 2, Reader: true}
	bobReqID, bobReqDig := fx.enrollP3(t, bobKeys, bobGrant, 0x44)
	fx.activateNextEpoch(t)

	// Alice declares "alice" and "peer", operator moves "peer" to Bob's credential
	// so Bob's credential has a genuinely owed incoming call notice BEFORE Bob activates!
	_, _ = fx.alice.Sync(ctx, fx.sAlice)
	for _, aid := range []string{"alice", "peer"} {
		opID, err := fx.alice.ComposeAndPersist(ComposeParams{
			Action: "decl_" + aid, Origin: ldrcore.OriginCredential, OpType: "actor_declare",
			Fields: ldrcrypto.Map{{Key: "actor_id", Value: aid}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-alice"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if rep, err := fx.alice.Send(ctx, fx.sAlice, opID); err != nil || rep.Outcome.Kind != ldrcore.Committed {
			t.Fatalf("decl %s: %+v err=%v", aid, rep, err)
		}
		_, _ = fx.alice.Sync(ctx, fx.sAlice)
	}
	_, _ = fx.admin.Sync(ctx, fx.sOp)
	mvOp, err := fx.admin.ComposeAndPersist(ComposeParams{
		Action: "move_peer_to_bob", Origin: ldrcore.OriginOperator, OpType: "actor_move",
		Expect: ldrcrypto.ExpectMap{"binding_gen": 1},
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "peer"}, {Key: "to_cred", Value: bobKeys.CredID[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := fx.admin.Send(ctx, fx.sOp, mvOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("actor_move: %+v err=%v", rep, err)
	}
	_, _ = fx.alice.Sync(ctx, fx.sAlice)

	// Alice opens an encrypted call to "peer" (owned by Bob's credential).
	openOp, err := fx.alice.ComposeAndPersist(ComposeParams{
		Action: "call_peer", Origin: ldrcore.OriginActor, OpType: "call_open", ActorID: "alice",
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: "call-gated"}, {Key: "to", Value: "peer"}},
		Plaintext: []byte(`{"subject":"Gated","body":"Must not surface before activation"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	openRep, err := fx.alice.Send(ctx, fx.sAlice, openOp)
	if err != nil || openRep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("call_open: %+v err=%v", openRep, err)
	}
	callSeq := openRep.Outcome.Seq

	// 1. Bob with mismatched ceremony digest: provisional Sync + wrap verification work,
	//    activation FAILS, and ALL publication & delivery boundaries stay strictly blocked!
	wrongDig := bobReqDig
	wrongDig[0] ^= 0xaa
	badBobDir := t.TempDir()
	badBob, err := InitClientDir(InitDirOptions{
		Dir: badBobDir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: bobKeys,
		ExpectedGrant: &bobGrant, ExpectedJoinReq: bobReqID, ExpectedJoinReqDigest: &wrongDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer badBob.Close()
	sBadBob, err := badBob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sBadBob.Close()

	// Provisional control replay + wrap verification MUST still work before activation.
	if n, err := badBob.Sync(ctx, sBadBob); err != nil || n == 0 {
		t.Fatalf("provisional Sync before activation failed: n=%d err=%v", n, err)
	}
	if !badBob.HasEpochKey(2) {
		t.Fatalf("provisional wrap verification did not unwrap epoch 2 before activation")
	}

	// Activation fails on digest mismatch!
	if err := badBob.VerifyEnrollmentAndActivate(ctx, sBadBob); !errors.Is(err, ErrEnrollmentCheck) {
		t.Fatalf("expected ErrEnrollmentCheck, got %v", err)
	}

	// Publication & delivery MUST all refuse and leave zero published files / zero cursor advance!
	if err := badBob.Project(ctx, sBadBob); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("Project after failed activation: got %v, want ErrNotActivated", err)
	}
	if err := badBob.Rebuild(ctx, sBadBob); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("Rebuild after failed activation: got %v, want ErrNotActivated", err)
	}
	if _, err := badBob.VerifiedRead(ctx, sBadBob, "calls/call-gated/call"); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("VerifiedRead after failed activation: got %v, want ErrNotActivated", err)
	}
	if _, _, err := badBob.ReadPayload(ctx, sBadBob, callSeq); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("ReadPayload after failed activation: got %v, want ErrNotActivated", err)
	}
	if added, err := badBob.ScanDelivery(); !errors.Is(err, ErrNotActivated) || added != 0 {
		t.Fatalf("ScanDelivery after failed activation: added=%d err=%v, want 0/ErrNotActivated", added, err)
	}
	if notices := badBob.DeliverableNotices(); len(notices) != 0 {
		t.Fatalf("DeliverableNotices exposed notices before activation: %+v", notices)
	}
	if st := badBob.Status(); st.ProjectedSeq != 0 || st.ScannedSeq != 0 || st.Activated {
		t.Fatalf("failed activation advanced cursors or activated: %+v", st)
	}
	if _, err := os.Stat(badBob.ProjectionDir()); !os.IsNotExist(err) {
		t.Fatalf("failed activation created projection dir: err=%v", err)
	}

	// Even if cursors.cbor already had a pre-queued notice, DeliverableNotices and AckNotice
	// MUST withhold it while unactivated!
	badBob.mu.Lock()
	badBob.cursors.Notices["fake-queued"] = &LocalNotice{
		ID: "fake-queued", Gen: 1, Seq: callSeq, Actor: "peer", BindingGen: 2, Kind: "call_open", Target: "call-gated",
	}
	badBob.mu.Unlock()
	if notices := badBob.DeliverableNotices(); len(notices) != 0 {
		t.Fatalf("DeliverableNotices leaked pre-queued notice before activation: %+v", notices)
	}
	if err := badBob.AckNotice("fake-queued"); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("AckNotice before activation: got %v, want ErrNotActivated", err)
	}

	// 2. Valid Bob completes O25 activation -> projection, VerifiedRead, ReadPayload,
	//    ScanDelivery, and DeliverableNotices all work immediately!
	goodBobDir := t.TempDir()
	goodBob, err := InitClientDir(InitDirOptions{
		Dir: goodBobDir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: bobKeys,
		ExpectedGrant: &bobGrant, ExpectedJoinReq: bobReqID, ExpectedJoinReqDigest: &bobReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer goodBob.Close()
	sGoodBob, err := goodBob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sGoodBob.Close()
	if err := goodBob.VerifyEnrollmentAndActivate(ctx, sGoodBob); err != nil {
		t.Fatalf("valid Bob activation failed: %v", err)
	}
	if err := goodBob.Project(ctx, sGoodBob); err != nil {
		t.Fatalf("Project after activation failed: %v", err)
	}
	if _, err := goodBob.VerifiedRead(ctx, sGoodBob, "calls/call-gated/turn-1"); err != nil {
		t.Fatalf("VerifiedRead after activation failed: %v", err)
	}
	if added, err := goodBob.ScanDelivery(); err != nil || added != 1 {
		t.Fatalf("ScanDelivery after activation: added=%d err=%v", added, err)
	}
	if notices := goodBob.DeliverableNotices(); len(notices) != 1 || notices[0].Actor != "peer" {
		t.Fatalf("DeliverableNotices after activation: %+v", notices)
	}
}

// TestClientActivationPersistenceFailureAndAmbiguousWriteReconcile verifies Codex Slice 2 Finding 4:
// VerifyEnrollmentAndActivate publishes c.outbox.Activated ONLY after persistence succeeds,
// keeps ordinary use blocked on both clean pre-rename failures and ambiguous post-rename sync
// failures (both same-process and on reopen), and requires durable reconciliation before resuming.
func TestClientActivationPersistenceFailureAndAmbiguousWriteReconcile(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	t.Run("clean_pre_write_failure_keeps_same_process_and_reopen_unactivated", func(t *testing.T) {
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: "ns-cleanfail", ActorLimit: 2, Reader: true}
		reqID, reqDig := fx.enrollP3(t, keys, grant, 0x51)
		fx.activateNextEpoch(t)

		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		// Inject clean pre-rename failure via SyncFile on temp outbox file (removed before rename!).
		cl.SetSyncHooks(func(*os.File) error {
			return errors.New("injected temp outbox fsync EIO")
		}, nil)

		err = cl.VerifyEnrollmentAndActivate(ctx, sess)
		if !errors.Is(err, ldrstore.ErrPreWrite) {
			t.Fatalf("VerifyEnrollmentAndActivate on pre-rename failure: got %v, want ErrPreWrite", err)
		}
		// Same process MUST NOT be activated!
		if st := cl.Status(); st.Activated || st.OutboxUncertain {
			t.Fatalf("expected Activated=false OutboxUncertain=false after clean failure, got %+v", st)
		}
		if _, err := cl.ComposeAndPersist(ComposeParams{
			Action: "premature", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
			Fields: ldrcrypto.Map{{Key: "actor_id", Value: "x1"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-cleanfail"}},
		}); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("same-process Compose after failed activation: got %v, want ErrNotActivated", err)
		}
		if err := cl.Project(ctx, sess); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("same-process Project after failed activation: got %v, want ErrNotActivated", err)
		}
		if _, err := cl.ScanDelivery(); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("same-process ScanDelivery after failed activation: got %v, want ErrNotActivated", err)
		}
		_ = cl.Close()

		// Reopen MUST also see Activated=false and stay blocked!
		cl2, err := OpenClient(dir)
		if err != nil {
			t.Fatalf("reopen after clean pre-write failure: %v", err)
		}
		defer cl2.Close()
		if cl2.Status().Activated {
			t.Fatalf("reopened client unexpectedly activated after clean pre-write failure")
		}
		if _, err := cl2.ScanDelivery(); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("reopened ScanDelivery: got %v, want ErrNotActivated", err)
		}
		// Subsequent activation succeeds cleanly once disk is healthy.
		if err := cl2.VerifyEnrollmentAndActivate(ctx, sess); err != nil {
			t.Fatalf("retry activation after clean failure: %v", err)
		}
		if !cl2.Status().Activated {
			t.Fatalf("expected Activated=true after retry")
		}
	})

	t.Run("ambiguous_post_rename_sync_failure_fences_same_process_and_reopen", func(t *testing.T) {
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: "ns-ambig", ActorLimit: 2, Reader: true}
		reqID, reqDig := fx.enrollP3(t, keys, grant, 0x52)
		fx.activateNextEpoch(t)

		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		// Inject post-rename SyncDir failure: os.Rename ALREADY made outbox.cbor
		// with Activated=true visible on disk, while directory durability failed!
		var syncMu sync.Mutex
		dirSyncFails := true
		dirSyncHook := func(d string) error {
			syncMu.Lock()
			fail := dirSyncFails
			syncMu.Unlock()
			if fail {
				return errors.New("injected post-rename dir fsync EIO")
			}
			return ldrstore.SyncDir(d)
		}
		cl.SetSyncHooks(nil, dirSyncHook)

		err = cl.VerifyEnrollmentAndActivate(ctx, sess)
		if !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("VerifyEnrollmentAndActivate on post-rename dir sync failure: got %v, want ErrUncertainWrite", err)
		}
		// Verify outbox.cbor on disk IS readable with Activated=true (ambiguity!),
		// YET same-process Client MUST stay Activated=false AND OutboxUncertain=true!
		diskOB, err := loadOutbox(filepath.Join(dir, "outbox.cbor"))
		if err != nil || !diskOB.Activated {
			t.Fatalf("expected post-rename outbox.cbor to be readable with Activated=true, got %+v err=%v", diskOB, err)
		}
		if st := cl.Status(); st.Activated || !st.OutboxUncertain {
			t.Fatalf("expected Activated=false OutboxUncertain=true, got %+v", st)
		}

		// Every ordinary operation MUST stay blocked with ErrOutboxUncertain!
		if _, err := cl.ComposeAndPersist(ComposeParams{
			Action: "blocked", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
			Fields: ldrcrypto.Map{{Key: "actor_id", Value: "a1"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-ambig"}},
		}); !errors.Is(err, ErrOutboxUncertain) {
			t.Fatalf("Compose while uncertain: got %v, want ErrOutboxUncertain", err)
		}
		if err := cl.Project(ctx, sess); !errors.Is(err, ErrOutboxUncertain) {
			t.Fatalf("Project while uncertain: got %v, want ErrOutboxUncertain", err)
		}
		if _, err := cl.ScanDelivery(); !errors.Is(err, ErrOutboxUncertain) {
			t.Fatalf("ScanDelivery while uncertain: got %v, want ErrOutboxUncertain", err)
		}
		if _, err := cl.Sync(ctx, sess); !errors.Is(err, ErrOutboxUncertain) {
			t.Fatalf("Sync while uncertain: got %v, want ErrOutboxUncertain", err)
		}
		if _, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential); !errors.Is(err, ErrOutboxUncertain) {
			t.Fatalf("Dial while uncertain: got %v, want ErrOutboxUncertain", err)
		}
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); !errors.Is(err, ErrOutboxUncertain) {
			t.Fatalf("VerifyEnrollmentAndActivate while uncertain: got %v, want ErrOutboxUncertain", err)
		}
		if notices := cl.DeliverableNotices(); len(notices) != 0 {
			t.Fatalf("DeliverableNotices while uncertain: %+v", notices)
		}

		// ReconcileDurability while dirSync still fails MUST keep fence active!
		if err := cl.ReconcileDurability(); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("ReconcileDurability with failing barrier: got %v, want ErrUncertainWrite", err)
		}
		if st := cl.Status(); st.Activated || !st.OutboxUncertain {
			t.Fatalf("expected fence preserved on failed reconcile, got %+v", st)
		}

		// Reopen while dirSync STILL fails MUST fail closed (never trust un-synced Activated=true)!
		_ = cl.Close()
		if _, err := OpenClientWithSyncHooks(dir, nil, dirSyncHook); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("OpenClientWithSyncHooks while dir sync still fails: got %v, want ErrUncertainWrite", err)
		}

		// Restore dirSync -> reopen passes barrier, verifies enrollment, and activates cleanly!
		syncMu.Lock()
		dirSyncFails = false
		syncMu.Unlock()
		clReopened, err := OpenClientWithSyncHooks(dir, nil, dirSyncHook)
		if err != nil {
			t.Fatalf("OpenClient after sync barrier restored: %v", err)
		}
		defer clReopened.Close()
		if st := clReopened.Status(); !st.Activated || st.OutboxUncertain {
			t.Fatalf("expected Activated=true OutboxUncertain=false on reconciled reopen, got %+v", st)
		}
	})

	t.Run("same_process_reconcile_durability_recovers_after_sync_restored", func(t *testing.T) {
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: "ns-reconcile", ActorLimit: 2, Reader: true}
		reqID, reqDig := fx.enrollP3(t, keys, grant, 0x53)
		fx.activateNextEpoch(t)

		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		var syncMu sync.Mutex
		dirSyncFails := true
		cl.SetSyncHooks(nil, func(d string) error {
			syncMu.Lock()
			fail := dirSyncFails
			syncMu.Unlock()
			if fail {
				return errors.New("injected post-rename dir sync EIO")
			}
			return ldrstore.SyncDir(d)
		})

		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("expected ErrUncertainWrite, got %v", err)
		}
		if st := cl.Status(); st.Activated || !st.OutboxUncertain {
			t.Fatalf("expected fenced unactivated state, got %+v", st)
		}

		// Restore sync -> same-process ReconcileDurability flushes barrier and lifts fence!
		syncMu.Lock()
		dirSyncFails = false
		syncMu.Unlock()
		if err := cl.ReconcileDurability(); err != nil {
			t.Fatalf("ReconcileDurability after sync restored: %v", err)
		}
		if st := cl.Status(); !st.Activated || st.OutboxUncertain {
			t.Fatalf("expected Activated=true OutboxUncertain=false after reconcile, got %+v", st)
		}
		// Ordinary operations now work cleanly in the same process!
		if err := cl.Project(ctx, sess); err != nil {
			t.Fatalf("Project after ReconcileDurability: %v", err)
		}
		if _, err := cl.ScanDelivery(); err != nil {
			t.Fatalf("ScanDelivery after ReconcileDurability: %v", err)
		}
	})

	t.Run("reopen_rejects_forged_activated_without_verified_enrollment", func(t *testing.T) {
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: "ns-forged", ActorLimit: 2, Reader: true}
		reqID := bytes.Repeat([]byte{0x54}, 16)
		reqDig := [32]byte{0x54}
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = cl.Close()
		// Forge Activated=true directly in outbox.cbor without any verified enrollment in verified.wal!
		if err := saveOutbox(filepath.Join(dir, "outbox.cbor"), persistedOutbox{
			Activated: true,
			KeyStops:  make(map[string]*KeyStop),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenClient(dir); !errors.Is(err, ErrEnrollmentCheck) {
			t.Fatalf("OpenClient accepted forged Activated=true without verified enrollment: got %v, want ErrEnrollmentCheck", err)
		}
	})
}

// TestClientReconcileDurabilityCandidateReplayAndPrefixProtection verifies Codex Turn 10 Finding 1:
// ReconcileDurability reconstructs and verifies a candidate from durable verified.wal frames,
// compares against the previously verified head, validates activation evidence against the
// candidate (never stale in-memory state), and preserves the fence on missing or shorter WALs.
func TestClientReconcileDurabilityCandidateReplayAndPrefixProtection(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	// Helper: set up a member fenced by an ambiguous post-rename dir sync failure on activation,
	// with dirSyncHook restored to succeed afterward so we test WAL integrity directly!
	setupFencedMember := func(t *testing.T, ns string, reqByte byte) (*Client, *ldrrelay.SessionClient, string, []byte) {
		t.Helper()
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: 2, Reader: true}
		reqID, reqDig := fx.enrollP3(t, keys, grant, reqByte)
		fx.activateNextEpoch(t)

		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cl.Close() })
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sess.Close() })

		var syncMu sync.Mutex
		dirSyncFails := true
		cl.SetSyncHooks(nil, func(d string) error {
			syncMu.Lock()
			fail := dirSyncFails
			syncMu.Unlock()
			if fail {
				return errors.New("injected post-rename dir sync EIO")
			}
			return ldrstore.SyncDir(d)
		})
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); !errors.Is(err, ldrstore.ErrUncertainWrite) {
			t.Fatalf("expected ErrUncertainWrite, got %v", err)
		}
		// Restore sync so subsequent failures come strictly from WAL state!
		syncMu.Lock()
		dirSyncFails = false
		syncMu.Unlock()

		fullWAL, err := os.ReadFile(filepath.Join(dir, "verified.wal"))
		if err != nil {
			t.Fatal(err)
		}
		return cl, sess, dir, fullWAL
	}

	// rewriteWALWithPrefix rewrites verified.wal keeping only the first keepFrames valid frames.
	rewriteWALWithPrefix := func(t *testing.T, dir string, keepFrames int) {
		t.Helper()
		walPath := filepath.Join(dir, "verified.wal")
		frames, err := loadVerifiedWAL(walPath, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if keepFrames >= len(frames) {
			t.Fatalf("keepFrames=%d must be < len(frames)=%d", keepFrames, len(frames))
		}
		if err := os.Remove(walPath); err != nil {
			t.Fatal(err)
		}
		if err := initEmptyVerifiedWAL(walPath); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < keepFrames; i++ {
			if err := appendVerifiedFrameWAL(walPath, frames[i]); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("positive_control_intact_wal_lifts_fence_same_process_and_reopen", func(t *testing.T) {
		cl, _, dir, _ := setupFencedMember(t, "ns-pos-ctrl", 0x61)
		if err := cl.ReconcileDurability(); err != nil {
			t.Fatalf("positive control ReconcileDurability failed: %v", err)
		}
		if st := cl.Status(); !st.Activated || st.OutboxUncertain {
			t.Fatalf("expected Activated=true OutboxUncertain=false, got %+v", st)
		}
		_ = cl.Close()
		cl2, err := OpenClient(dir)
		if err != nil {
			t.Fatalf("positive control reopen failed: %v", err)
		}
		defer cl2.Close()
		if !cl2.Status().Activated {
			t.Fatalf("expected reopened Activated=true")
		}
	})

	t.Run("missing_verified_wal_keeps_fence_same_process_and_fails_reopen", func(t *testing.T) {
		cl, _, dir, _ := setupFencedMember(t, "ns-missing-wal", 0x62)
		if err := os.Remove(filepath.Join(dir, "verified.wal")); err != nil {
			t.Fatal(err)
		}
		// Same-process ReconcileDurability MUST fail closed and preserve fence!
		if err := cl.ReconcileDurability(); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileDurability with missing verified.wal: got %v, want ErrCorruptWAL", err)
		}
		if st := cl.Status(); st.Activated || !st.OutboxUncertain {
			t.Fatalf("fence must remain active with missing verified.wal, got %+v", st)
		}
		// Reopen MUST ALSO fail closed!
		_ = cl.Close()
		if _, err := OpenClient(dir); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("OpenClient with missing verified.wal: got %v, want ErrCorruptWAL", err)
		}
	})

	t.Run("shorter_wal_dropping_enrollment_keeps_fence_and_fails_reopen", func(t *testing.T) {
		cl, _, dir, _ := setupFencedMember(t, "ns-short-no-enroll", 0x63)
		// Keep only seq 1..2 (line_init + operator_key_authorize), dropping enrollment!
		rewriteWALWithPrefix(t, dir, 2)

		if err := cl.ReconcileDurability(); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileDurability with shorter WAL dropping enrollment: got %v, want ErrCorruptWAL", err)
		}
		if st := cl.Status(); st.Activated || !st.OutboxUncertain {
			t.Fatalf("fence must remain active on shorter WAL, got %+v", st)
		}
		// Reopen MUST ALSO fail closed (Activated=true on disk lacks verified enrollment in shorter WAL!).
		_ = cl.Close()
		if _, err := OpenClient(dir); !errors.Is(err, ErrEnrollmentCheck) {
			t.Fatalf("OpenClient with shorter WAL missing enrollment: got %v, want ErrEnrollmentCheck", err)
		}
	})

	t.Run("shorter_wal_still_containing_enrollment_but_below_checkpoint_keeps_fence", func(t *testing.T) {
		cl, _, dir, fullWAL := setupFencedMember(t, "ns-short-below-ck", 0x64)
		_, ckSeq, _ := cl.Checkpoint()
		// Truncate strictly 1 frame off the end (enrollment is earlier, epoch_activate was last!):
		// WAL is intact and still contains enrollment, yet is shorter than accepted checkpoint ckSeq!
		rewriteWALWithPrefix(t, dir, int(ckSeq-1))

		if err := cl.ReconcileDurability(); !errors.Is(err, ldrstore.ErrCorruptWAL) {
			t.Fatalf("ReconcileDurability with intact shorter WAL (%d < %d): got %v, want ErrCorruptWAL", ckSeq-1, ckSeq, err)
		}
		if st := cl.Status(); st.Activated || !st.OutboxUncertain {
			t.Fatalf("fence must remain active when durable WAL regressed below verified checkpoint, got %+v", st)
		}
		// Restoring intact WAL allows ReconcileDurability to succeed!
		if err := os.WriteFile(filepath.Join(dir, "verified.wal"), fullWAL, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cl.ReconcileDurability(); err != nil {
			t.Fatalf("ReconcileDurability after restoring intact WAL: %v", err)
		}
		if st := cl.Status(); !st.Activated || st.OutboxUncertain {
			t.Fatalf("expected clean activation after restoring intact WAL, got %+v", st)
		}
	})
}

// TestClientUnactivatedMemberBlocksAdminAttachedMutationsAndLegacyV1Config verifies
// Codex Turn 10 Finding 2 & Compatibility Note:
//   - An unactivated DirKindMember directory refuses ComposeAndPersist (even for
//     root/operator origins), ComposeEpochActivate (even with an attached operator
//     key and enrolled reader cred), Send (even for a pre-staged entry), and ResolveAll.
//   - A separate DirKindAdmin directory starts Activated=true and allows admin mutations.
//   - A legacy v1 config.cbor (without dir_kind) fails closed explicitly even when
//     outbox.cbor says Activated=true, never inferring administrative authority.
func TestClientUnactivatedMemberBlocksAdminAttachedMutationsAndLegacyV1Config(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	t.Run("unactivated_member_with_attached_root_and_operator_keys_blocks_all_mutations", func(t *testing.T) {
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: "ns-gated-admin", ActorLimit: 2, Reader: true}
		reqID, reqDig := fx.enrollP3(t, keys, grant, 0x71)
		fx.activateNextEpoch(t)

		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()

		// Attach BOTH root and operator signing keys to this provisional member directory!
		cl.AttachRootKey(fx.env.root1)
		cl.AttachOperatorKey(fx.opKey)

		// Provisional control sync succeeds (replay + wrap verification allowed before activation).
		sOp, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
		if err != nil {
			t.Fatal(err)
		}
		defer sOp.Close()
		if _, err := cl.Sync(ctx, sOp); err != nil {
			t.Fatalf("provisional Sync failed: %v", err)
		}

		// 1. ComposeAndPersist with OriginRoot MUST fail with ErrNotActivated!
		extraOp, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
		extraOpCBOR, _ := extraOp.Signer.PublicKey().ToCBOR()
		if _, err := cl.ComposeAndPersist(ComposeParams{
			Action: "root_on_unactivated_member", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
			Expect: ldrcrypto.ExpectMap{"root_rev": uint64(cl.State().Line.RootRev)},
			Fields: ldrcrypto.Map{{Key: "operator_key", Value: extraOpCBOR}},
		}); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("ComposeAndPersist(OriginRoot) on unactivated member: got %v, want ErrNotActivated", err)
		}

		// 2. ComposeAndPersist with OriginOperator MUST fail with ErrNotActivated!
		if _, err := cl.ComposeAndPersist(ComposeParams{
			Action: "op_on_unactivated_member", Origin: ldrcore.OriginOperator, OpType: "credential_revoke",
			Fields: ldrcrypto.Map{{Key: "cred_id", Value: keys.CredID[:]}},
		}); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("ComposeAndPersist(OriginOperator) on unactivated member: got %v, want ErrNotActivated", err)
		}

		// 3. ComposeEpochActivate MUST fail with ErrNotActivated even though cred IS an entitled reader!
		if _, _, err := cl.ComposeEpochActivate("epoch_on_unactivated_member"); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("ComposeEpochActivate on unactivated member: got %v, want ErrNotActivated", err)
		}

		// 4. Send MUST fail with ErrNotActivated even if an outbox entry exists in memory!
		cl.mu.Lock()
		cl.outbox.Entries = append(cl.outbox.Entries, &OutboxEntry{
			OpID: "staged-pre-act", Status: ldrcore.OutPending, SignerToken: "op:test",
		})
		cl.mu.Unlock()
		if _, err := cl.Send(ctx, sOp, "staged-pre-act"); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("Send on unactivated member: got %v, want ErrNotActivated", err)
		}
		if cl.OutboxSnapshot()[0].Sends != 0 {
			t.Fatalf("Send mutated Sends counter on unactivated member")
		}

		// 5. ResolveAll MUST fail with ErrNotActivated!
		if err := cl.ResolveAll(ctx, sOp, ldrcrypto.OperatorPrincipal(fx.opKey.Signer.PublicKey())); !errors.Is(err, ErrNotActivated) {
			t.Fatalf("ResolveAll on unactivated member: got %v, want ErrNotActivated", err)
		}
	})

	t.Run("legacy_v1_config_without_dir_kind_fails_closed_even_if_activated_true", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "sidecars"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := initEmptyVerifiedWAL(filepath.Join(dir, "verified.wal")); err != nil {
			t.Fatal(err)
		}
		// Write a pre-release v1 config.cbor (no dir_kind, v=1) paired with outbox.cbor Activated=true!
		legacyCfg, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
			{Key: "cd", Value: fx.env.cd[:]},
			{Key: "descriptor", Value: fx.env.rawDesc},
			{Key: "genesis", Value: fx.env.genesis[:]},
			{Key: "line_id", Value: fx.env.lineID},
			{Key: "v", Value: uint64(1)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := ldrstore.AtomicWriteFile(filepath.Join(dir, "config.cbor"), legacyCfg, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := saveOutbox(filepath.Join(dir, "outbox.cbor"), persistedOutbox{
			Activated: true,
			KeyStops:  make(map[string]*KeyStop),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenClient(dir); err == nil {
			t.Fatalf("OpenClient accepted legacy v1 config.cbor without dir_kind!")
		}
	})
}

// TestAdminReaderCredentialPreservationAndResume verifies Codex Turn 12 Finding 1:
//   - EnsureAdminReaderRequest creates cred.key + admin-reader.req.cbor create-only
//     on first call, safely resumes with the EXACT same keys and signed JoinRequest
//     on retry (including after a simulated --out output failure or reopen), refuses
//     conflicting namespace/alg, and refuses once the reader credential is enrolled.
//   - AttachAdminReaderKeys and EnsureAdminReaderRequest refuse silent replacement
//     of any existing cred.key, including one that cannot be decoded, and OpenClient
//     fails closed on an undecodable cred.key without touching it.
func TestAdminReaderCredentialPreservationAndResume(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	t.Run("create_resume_after_output_error_and_refuse_after_enrollment", func(t *testing.T) {
		adminDir := t.TempDir()
		adm, err := InitClientDir(InitDirOptions{
			Dir: adminDir, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, Activated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer adm.Close()

		// 1. First-time creation (ECDSA P-256) creates cred.key + admin-reader.req.cbor.
		req1, resumed1, err := adm.EnsureAdminReaderRequest("ns-admin-r", ldrcrypto.AlgECDSAP256)
		if err != nil {
			t.Fatalf("first EnsureAdminReaderRequest: %v", err)
		}
		if resumed1 {
			t.Fatalf("expected resumed=false on first creation")
		}
		origKeyBytes, err := os.ReadFile(filepath.Join(adminDir, "cred.key"))
		if err != nil {
			t.Fatalf("read cred.key: %v", err)
		}

		// 2. Simulate --out output failure (parent path is a regular file!).
		blocker := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := SaveJoinRequest(filepath.Join(blocker, "out.req.cbor"), req1); err == nil {
			t.Fatalf("expected SaveJoinRequest to fail under regular-file parent")
		}

		// 3. Retry with omitted alg ("") AND explicit matching alg -> resumes with EXACT same
		//    keys and JoinRequest, leaving cred.key byte-for-byte untouched!
		for _, retryAlg := range []string{"", ldrcrypto.AlgECDSAP256} {
			req2, resumed2, err := adm.EnsureAdminReaderRequest("ns-admin-r", retryAlg)
			if err != nil {
				t.Fatalf("retry EnsureAdminReaderRequest(alg=%q): %v", retryAlg, err)
			}
			if !resumed2 {
				t.Fatalf("expected resumed=true on retry(alg=%q)", retryAlg)
			}
			if req2.CredID != req1.CredID || !bytes.Equal(req2.RequestID, req1.RequestID) ||
				!bytes.Equal(req2.BodyBytes, req1.BodyBytes) || !bytes.Equal(req2.Sig, req1.Sig) {
				t.Fatalf("resumed request differs from original!")
			}
		}

		// 4. Close and reopen admin dir -> still resumes with the exact same request!
		if err := adm.Close(); err != nil {
			t.Fatal(err)
		}
		adm, err = OpenClient(adminDir)
		if err != nil {
			t.Fatalf("reopen adminDir: %v", err)
		}
		defer adm.Close()
		req3, resumed3, err := adm.EnsureAdminReaderRequest("ns-admin-r", "")
		if err != nil || !resumed3 || req3.CredID != req1.CredID || !bytes.Equal(req3.Sig, req1.Sig) {
			t.Fatalf("post-reopen resume mismatch: resumed=%v err=%v", resumed3, err)
		}

		// 5. Conflicting namespace or conflicting explicit alg MUST fail closed!
		if _, _, err := adm.EnsureAdminReaderRequest("ns-other", ""); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("conflicting namespace: got %v, want ErrCredentialExists", err)
		}
		if _, _, err := adm.EnsureAdminReaderRequest("ns-admin-r", ldrcrypto.AlgEd25519); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("conflicting alg: got %v, want ErrCredentialExists", err)
		}

		// 6. Enroll that exact admin reader credential and sync adminDir -> repeated
		//    EnsureAdminReaderRequest MUST fail with ErrCredentialExists!
		admCred, err := LoadCredentialKeys(filepath.Join(adminDir, "cred.key"))
		if err != nil {
			t.Fatal(err)
		}
		reqDig, err := ldrcrypto.VerifyJoinRequest(req1)
		if err != nil {
			t.Fatal(err)
		}
		fx.enrollRaw(t, admCred, req1.Grant, req1.RequestID, reqDig)
		adm.AttachOperatorKey(fx.opKey)
		sOp, err := adm.Dial(ctx, ldrcrypto.PrincipalOperator)
		if err != nil {
			t.Fatal(err)
		}
		defer sOp.Close()
		if _, err := adm.Sync(ctx, sOp); err != nil {
			t.Fatalf("sync adminDir after enrollment: %v", err)
		}
		if _, _, err := adm.EnsureAdminReaderRequest("ns-admin-r", ""); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("EnsureAdminReaderRequest after enrollment: got %v, want ErrCredentialExists", err)
		}

		// Verify original cred.key survived EVERY step byte-for-byte unchanged!
		afterKeyBytes, err := os.ReadFile(filepath.Join(adminDir, "cred.key"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(origKeyBytes, afterKeyBytes) {
			t.Fatalf("cred.key bytes changed across retries/errors/enrollment!")
		}
	})

	t.Run("attach_and_undecodable_cred_key_never_silently_replaced", func(t *testing.T) {
		// Case A: valid cred.key attached directly (no pending admin-reader.req.cbor).
		dirA := t.TempDir()
		admA, err := InitClientDir(InitDirOptions{
			Dir: dirA, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, Activated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer admA.Close()
		k1, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		k2, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		if err := admA.AttachAdminReaderKeys(k1); err != nil {
			t.Fatalf("first AttachAdminReaderKeys: %v", err)
		}
		origA, err := os.ReadFile(filepath.Join(dirA, "cred.key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := admA.AttachAdminReaderKeys(k2); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("second AttachAdminReaderKeys: got %v, want ErrCredentialExists", err)
		}
		if _, _, err := admA.EnsureAdminReaderRequest("ns-a", ""); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("EnsureAdminReaderRequest without pending req file: got %v, want ErrCredentialExists", err)
		}
		afterA, _ := os.ReadFile(filepath.Join(dirA, "cred.key"))
		if !bytes.Equal(origA, afterA) {
			t.Fatalf("AttachAdminReaderKeys/EnsureAdminReaderRequest modified existing cred.key!")
		}

		// Case B: undecodable/corrupt cred.key present on disk!
		dirB := t.TempDir()
		admB, err := InitClientDir(InitDirOptions{
			Dir: dirB, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, Activated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		corruptBytes := []byte("corrupt-undecodable-credential-material-do-not-overwrite")
		if err := os.WriteFile(filepath.Join(dirB, "cred.key"), corruptBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		// While open with c.credKeys == nil: BOTH AttachAdminReaderKeys and
		// EnsureAdminReaderRequest MUST fail with ErrCredentialExists and preserve corrupt bytes!
		if err := admB.AttachAdminReaderKeys(k2); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("AttachAdminReaderKeys over undecodable cred.key: got %v, want ErrCredentialExists", err)
		}
		if _, _, err := admB.EnsureAdminReaderRequest("ns-b", ""); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("EnsureAdminReaderRequest over undecodable cred.key: got %v, want ErrCredentialExists", err)
		}
		_ = admB.Close()
		// On reopen: OpenClient MUST fail closed (ErrKeyFile) and preserve corrupt bytes!
		if _, err := OpenClient(dirB); !errors.Is(err, ErrKeyFile) {
			t.Fatalf("OpenClient with undecodable cred.key: got %v, want ErrKeyFile", err)
		}
		gotB, err := os.ReadFile(filepath.Join(dirB, "cred.key"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(corruptBytes, gotB) {
			t.Fatalf("undecodable cred.key was modified or overwritten!")
		}
	})
}

// TestInitClientDirPreservesExistingPartialAndOpenDirectories verifies Codex Turn 12 Finding 2:
//   - InitClientDir reserves a fresh directory under exclusive .client.lock BEFORE
//     writing any artifacts, refusing already-open directories (ErrClientLocked),
//     repeated initialization of closed directories (ErrDirInitialized), partially
//     initialized directories (ErrDirInitialized), and legacy v1 directories
//     (ErrDirInitialized) without modifying existing keys, outbox, config, or WAL.
//   - Legacy v1 config error points users to a NEW client directory while preserving
//     existing keys and outbox.
func TestInitClientDirPreservesExistingPartialAndOpenDirectories(t *testing.T) {
	fx := startOnboardingFixture(t)
	ctx := context.Background()

	snapshotDirFiles := func(t *testing.T, dir string, names ...string) map[string][]byte {
		t.Helper()
		snap := make(map[string][]byte, len(names))
		for _, name := range names {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			snap[name] = b
		}
		return snap
	}
	assertSnapshotUnchanged := func(t *testing.T, dir string, snap map[string][]byte) {
		t.Helper()
		for name, want := range snap {
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("re-read %s: %v", name, err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("file %s was modified by failed InitClientDir!", name)
			}
		}
	}

	t.Run("already_open_and_closed_existing_dir_with_pending_outbox_preserved", func(t *testing.T) {
		keys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		grant := ldrcrypto.JoinGrant{NamespaceID: "ns-preserve", ActorLimit: 2, Reader: true}
		reqID, reqDig := fx.enrollP3(t, keys, grant, 0x81)
		fx.activateNextEpoch(t)

		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindMember, SignedDescriptor: fx.env.rawDesc, CredKeys: keys,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig, Activated: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			t.Fatal(err)
		}
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); err != nil {
			t.Fatal(err)
		}
		sess.Close()

		// Persist a pending outbox entry WITHOUT sending it!
		pendingOp, err := cl.ComposeAndPersist(ComposeParams{
			Action: "pending_decl", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
			Fields: ldrcrypto.Map{{Key: "actor_id", Value: "p1"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-preserve"}},
		})
		if err != nil {
			t.Fatalf("ComposeAndPersist: %v", err)
		}
		snap := snapshotDirFiles(t, dir, "cred.key", "config.cbor", "outbox.cbor", "verified.wal")

		// 1. While cl is OPEN (holding .client.lock), InitClientDir MUST fail with
		//    ErrClientLocked and leave every file 100% untouched!
		otherKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		if _, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, CredKeys: otherKeys, Activated: true,
		}); !errors.Is(err, ErrClientLocked) {
			t.Fatalf("InitClientDir on already-open dir: got %v, want ErrClientLocked", err)
		}
		assertSnapshotUnchanged(t, dir, snap)

		// 2. After closing cl, repeated InitClientDir MUST fail with ErrDirInitialized
		//    and leave cred.key, config.cbor, pending outbox.cbor, and verified.wal untouched!
		if err := cl.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := InitClientDir(InitDirOptions{
			Dir: dir, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, CredKeys: otherKeys, Activated: true,
		}); !errors.Is(err, ErrDirInitialized) {
			t.Fatalf("InitClientDir on closed existing dir: got %v, want ErrDirInitialized", err)
		}
		assertSnapshotUnchanged(t, dir, snap)

		// 3. Reopening dir still sees original CredID and pending outbox entry!
		reopened, err := OpenClient(dir)
		if err != nil {
			t.Fatalf("OpenClient after rejected re-init: %v", err)
		}
		defer reopened.Close()
		cid, ok := reopened.CredID()
		if !ok || cid != keys.CredID {
			t.Fatalf("reopened CredID mismatch: ok=%v", ok)
		}
		ob := reopened.OutboxSnapshot()
		if len(ob) != 1 || ob[0].OpID != pendingOp || ob[0].Status != ldrcore.OutPending {
			t.Fatalf("pending outbox lost after rejected re-init: %+v", ob)
		}
	})

	t.Run("partially_initialized_directories_refused_without_modification", func(t *testing.T) {
		partials := []struct {
			name    string
			file    string
			content []byte
		}{
			{name: "only_verified_wal", file: "verified.wal", content: []byte("existing-wal-marker")},
			{name: "only_cred_key", file: "cred.key", content: []byte("existing-cred-marker")},
			{name: "only_outbox", file: "outbox.cbor", content: []byte("existing-outbox-marker")},
			{name: "stray_file", file: "notes.txt", content: []byte("do-not-clobber")},
		}
		for _, tc := range partials {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				p := filepath.Join(dir, tc.file)
				if err := os.WriteFile(p, tc.content, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := InitClientDir(InitDirOptions{
					Dir: dir, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, Activated: true,
				}); !errors.Is(err, ErrDirInitialized) {
					t.Fatalf("InitClientDir on partial dir (%s): got %v, want ErrDirInitialized", tc.name, err)
				}
				got, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(tc.content, got) {
					t.Fatalf("partial dir file %s was altered!", tc.file)
				}
				for _, artifact := range []string{"config.cbor", "outbox.cbor", "verified.wal", "cred.key"} {
					if artifact == tc.file {
						continue
					}
					if _, err := os.Stat(filepath.Join(dir, artifact)); !os.IsNotExist(err) {
						t.Fatalf("failed InitClientDir unexpectedly created %s in partial dir", artifact)
					}
				}
			})
		}
	})

	t.Run("legacy_v1_dir_guides_to_new_dir_and_refuses_in_place_reinit", func(t *testing.T) {
		legacyDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(legacyDir, "sidecars"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := initEmptyVerifiedWAL(filepath.Join(legacyDir, "verified.wal")); err != nil {
			t.Fatal(err)
		}
		legacyKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		if err := SaveCredentialKeysCreateOnly(filepath.Join(legacyDir, "cred.key"), legacyKeys); err != nil {
			t.Fatal(err)
		}
		legacyCfg, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
			{Key: "cd", Value: fx.env.cd[:]},
			{Key: "descriptor", Value: fx.env.rawDesc},
			{Key: "genesis", Value: fx.env.genesis[:]},
			{Key: "line_id", Value: fx.env.lineID},
			{Key: "v", Value: uint64(1)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := ldrstore.AtomicWriteFile(filepath.Join(legacyDir, "config.cbor"), legacyCfg, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := saveOutbox(filepath.Join(legacyDir, "outbox.cbor"), persistedOutbox{
			Activated: true,
			KeyStops:  make(map[string]*KeyStop),
			Entries: []*OutboxEntry{{
				OpID: "legacy-pending-1", Action: "keep-me", Slot: "s1", Gen: 1,
				Principal: ldrcrypto.CredentialPrincipal(legacyKeys.CredID),
				Status:    ldrcore.OutPending, IntentBytes: []byte("raw"),
			}},
		}); err != nil {
			t.Fatal(err)
		}
		snap := snapshotDirFiles(t, legacyDir, "cred.key", "config.cbor", "outbox.cbor", "verified.wal")

		// 1. OpenClient rejects legacy v1 and explicitly advises initializing a NEW directory
		//    while preserving existing keys and outbox!
		_, err = OpenClient(legacyDir)
		if err == nil {
			t.Fatalf("expected OpenClient to reject legacy v1 dir")
		}
		if !strings.Contains(err.Error(), "NEW client directory") || !strings.Contains(err.Error(), "preserve existing keys and outbox") {
			t.Fatalf("legacy v1 error should direct user to a new directory and preserve keys/outbox, got: %v", err)
		}

		// 2. Attempting InitClientDir in-place on legacyDir MUST fail with ErrDirInitialized
		//    and leave legacy cred.key, config.cbor, outbox.cbor, and verified.wal untouched!
		if _, err := InitClientDir(InitDirOptions{
			Dir: legacyDir, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, Activated: true,
		}); !errors.Is(err, ErrDirInitialized) {
			t.Fatalf("InitClientDir in-place on legacy v1 dir: got %v, want ErrDirInitialized", err)
		}
		assertSnapshotUnchanged(t, legacyDir, snap)

		// 3. Initializing a fresh NEW directory succeeds cleanly.
		newDir := filepath.Join(t.TempDir(), "fresh-v2")
		fresh, err := InitClientDir(InitDirOptions{
			Dir: newDir, DirKind: DirKindAdmin, SignedDescriptor: fx.env.rawDesc, Activated: true,
		})
		if err != nil {
			t.Fatalf("InitClientDir on fresh new dir: %v", err)
		}
		_ = fresh.Close()
	})
}

// TestSaveJoinRequestNoClobberAndIdempotentRetry verifies Codex Turn 14:
// SaveJoinRequest publishes without clobbering existing destinations (sentinel
// files, conflicting requests, symlinks, directories) and treats an existing
// byte-identical regular request file as idempotent success.
func TestSaveJoinRequestNoClobberAndIdempotentRetry(t *testing.T) {
	fx := startOnboardingFixture(t)

	makeReq := func(t *testing.T, ns string, reqByte byte) ldrcrypto.JoinRequest {
		t.Helper()
		keys, err := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		if err != nil {
			t.Fatal(err)
		}
		req, err := ldrcrypto.SignJoinRequest(keys.Signing.Signer, ldrcrypto.JoinRequest{
			RequestID:        bytes.Repeat([]byte{reqByte}, 16),
			LineID:           fx.env.lineID,
			Generation:       1,
			DescriptorDigest: fx.env.cd,
			EncryptionKey:    keys.Encryption.PublicKey(),
			Grant:            ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: 0, Reader: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	req1 := makeReq(t, "ns-exp-1", 0x91)
	req2 := makeReq(t, "ns-exp-2", 0x92)

	// 1. Existing disposable sentinel regular file MUST fail with ErrOutputExists and stay intact.
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "sentinel.key")
	sentinelBytes := []byte("disposable-sentinel-must-never-be-overwritten")
	if err := os.WriteFile(sentinelPath, sentinelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveJoinRequest(sentinelPath, req1); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("SaveJoinRequest over sentinel: got %v, want ErrOutputExists", err)
	}
	gotSentinel, err := os.ReadFile(sentinelPath)
	if err != nil || !bytes.Equal(sentinelBytes, gotSentinel) {
		t.Fatalf("sentinel file was modified! err=%v", err)
	}

	// 2. Fresh regular destination publishes cleanly; exact retry succeeds idempotently;
	//    conflicting second request fails with ErrOutputExists leaving req1 untouched!
	reqPath := filepath.Join(dir, "req1.cbor")
	if err := SaveJoinRequest(reqPath, req1); err != nil {
		t.Fatalf("initial SaveJoinRequest: %v", err)
	}
	req1Bytes, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveJoinRequest(reqPath, req1); err != nil {
		t.Fatalf("exact idempotent retry SaveJoinRequest: %v", err)
	}
	afterRetryBytes, err := os.ReadFile(reqPath)
	if err != nil || !bytes.Equal(req1Bytes, afterRetryBytes) {
		t.Fatalf("exact retry altered req1.cbor!")
	}
	if err := SaveJoinRequest(reqPath, req2); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("conflicting SaveJoinRequest over req1.cbor: got %v, want ErrOutputExists", err)
	}
	afterConflictBytes, err := os.ReadFile(reqPath)
	if err != nil || !bytes.Equal(req1Bytes, afterConflictBytes) {
		t.Fatalf("conflicting SaveJoinRequest altered req1.cbor!")
	}

	// 3. Symlink destination (even pointing to byte-identical req1.cbor!) MUST fail with ErrOutputExists.
	symPath := filepath.Join(dir, "link-to-req1.cbor")
	if err := os.Symlink(reqPath, symPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveJoinRequest(symPath, req1); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("SaveJoinRequest over symlink to identical file: got %v, want ErrOutputExists", err)
	}
	if fi, err := os.Lstat(symPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink destination was altered! err=%v", err)
	}

	// 4. Directory destination MUST fail with ErrOutputExists.
	subDir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveJoinRequest(subDir, req1); !errors.Is(err, ErrOutputExists) {
		t.Fatalf("SaveJoinRequest over directory: got %v, want ErrOutputExists", err)
	}
}
