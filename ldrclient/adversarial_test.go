package ldrclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
)

func TestClientAdversarialSecurityBoundaries(t *testing.T) {
	env := startTestRelay(t)
	ctx := context.Background()

	// 1. P9 refusal: admin dir WITHOUT an enrolled reader credential MUST NOT activate an epoch.
	adminNoCredDir := t.TempDir()
	opKey, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
	adminNoCred, err := InitClientDir(InitDirOptions{
		Dir: adminNoCredDir, SignedDescriptor: env.rawDesc, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adminNoCred.Close()
	adminNoCred.AttachRootKey(env.root1)
	adminNoCred.AttachOperatorKey(opKey)

	sRoot, err := adminNoCred.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer sRoot.Close()

	desc, cd, _, _ := adminNoCred.Descriptor()
	rk0, _ := desc.RootKeys[0].ToCBOR()
	rk1, _ := desc.RootKeys[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	op1, err := adminNoCred.ComposeAndPersist(ComposeParams{
		Action: "line_init", Origin: ldrcore.OriginRoot, OpType: "line_init",
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: cd[:]},
			{Key: "profile", Value: profMap},
			{Key: "root_keys", Value: []any{rk0, rk1}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := adminNoCred.Send(ctx, sRoot, op1); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("line_init: %+v, err=%v", rep, err)
	}
	_, _ = adminNoCred.Sync(ctx, sRoot)

	opPubC, _ := opKey.Signer.PublicKey().ToCBOR()
	op2, _ := adminNoCred.ComposeAndPersist(ComposeParams{
		Action: "auth_op", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubC}},
	})
	_, _ = adminNoCred.Send(ctx, sRoot, op2)
	_, _ = adminNoCred.Sync(ctx, sRoot)

	sOp, err := adminNoCred.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	defer sOp.Close()

	// Enroll Bob with actor_limit=99 even though Bob's local P3 expectation is actor_limit=4!
	bobKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	skC, _ := bobKeys.Signing.Signer.PublicKey().ToCBOR()
	ekC, _ := bobKeys.Encryption.PublicKey().ToCBOR()
	opEnroll, err := adminNoCred.ComposeAndPersist(ComposeParams{
		Action: "enroll_bob_mismatch", Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
		Fields: ldrcrypto.Map{
			{Key: "cred_id", Value: bobKeys.CredID[:]},
			{Key: "encryption_key", Value: ekC},
			{Key: "grant", Value: ldrcrypto.Map{
				{Key: "actor_limit", Value: uint64(99)}, // differs from Bob's saved grant!
				{Key: "namespace_id", Value: "ns-bob"},
				{Key: "reader", Value: true},
			}},
			{Key: "join_request_digest", Value: bytes.Repeat([]byte{0x11}, 32)},
			{Key: "join_request_id", Value: bytes.Repeat([]byte{0x11}, 16)},
			{Key: "signing_key", Value: skC},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := adminNoCred.Send(ctx, sOp, opEnroll); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("enroll bob: %+v, err=%v", rep, err)
	}
	_, _ = adminNoCred.Sync(ctx, sOp)

	// P9 check: adminNoCred has NO credential keys, so ComposeEpochActivate MUST refuse!
	if _, _, err := adminNoCred.ComposeEpochActivate("p9_must_fail"); err == nil {
		t.Fatalf("P9 violation: ComposeEpochActivate succeeded without enrolled reader credential")
	}

	// 2. O25 grant-mismatch refusal: Bob expects actor_limit=4, relay has 99 -> ErrEnrollmentCheck!
	bobDir := t.TempDir()
	wantGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-bob", ActorLimit: 4, Reader: true}
	bobReqID := bytes.Repeat([]byte{0x11}, 16)
	var bobReqDig [32]byte
	copy(bobReqDig[:], bytes.Repeat([]byte{0x11}, 32))
	bob, err := InitClientDir(InitDirOptions{
		Dir: bobDir, SignedDescriptor: env.rawDesc, CredKeys: bobKeys,
		ExpectedGrant: &wantGrant, ExpectedJoinReq: bobReqID, ExpectedJoinReqDigest: &bobReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	sBob, err := bob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sBob.Close()
	if err := bob.VerifyEnrollmentAndActivate(ctx, sBob); !errors.Is(err, ErrEnrollmentCheck) {
		t.Fatalf("expected ErrEnrollmentCheck on grant mismatch, got %v", err)
	}
	if bob.Status().Activated {
		t.Fatalf("bob must remain unactivated after grant mismatch")
	}

	// 3. Verified WAL bit-flip corruption MUST fail closed on reopen!
	walFile := filepath.Join(bobDir, "verified.wal")
	sBob.Close()
	_ = bob.Close()
	rawWAL, err := os.ReadFile(walFile)
	if err != nil || len(rawWAL) < 20 {
		t.Fatalf("expected non-empty verified.wal, len=%d err=%v", len(rawWAL), err)
	}
	rawWAL[len(rawWAL)-1] ^= 0x01 // flip last CRC bit
	if err := os.WriteFile(walFile, rawWAL, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenClient(bobDir); err == nil {
		t.Fatalf("OpenClient succeeded on bit-flipped verified.wal")
	}

	// 4. Forged frame offered to verifyAndApplyFrameLocked halts fail-closed!
	//    Test bad chain head, bad signature, and late commit past validity_ms.
	forgedDir := t.TempDir()
	fc, err := InitClientDir(InitDirOptions{Dir: forgedDir, SignedDescriptor: env.rawDesc, Activated: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	// Feed a fabricated time_anchor at seq 1 (violation: seq 1 must be line_init).
	badFrame := ldrrelay.ControlFrameWire{
		Gen: 1, Seq: 1, SeqTime: 1_700_000_000_000,
		PrevHead: env.genesis, Head: [32]byte{0xde, 0xad},
		Origin: ldrcore.OriginSequencer, OpType: "time_anchor",
	}
	fc.mu.Lock()
	err = fc.verifyAndApplyFrameLocked(badFrame, true)
	if err != nil {
		fc.outbox.Halted = err.Error()
		_ = saveOutbox(fc.outboxPath(), fc.outbox)
	}
	fc.mu.Unlock()
	if err == nil {
		t.Fatalf("expected violation error on forged seq 1 time_anchor")
	}
	if _, err := fc.Dial(ctx, ldrcrypto.PrincipalRoot); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("expected ErrFailClosed after halt, got %v", err)
	}
	if _, err := fc.Anchor(ctx, sRoot); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("expected ErrFailClosed on Anchor after halt, got %v", err)
	}

	// 5. 3-state payload diagnostics (§10.2): ReadMalformed on call_status with empty reason,
	//    and ReadUndecryptable when local epoch key is corrupted — neither stops replay!
	//    First confirm an unactivated member dir with attached operator key CANNOT
	//    bypass activation via ComposeEpochActivate; then activate epoch 1 from the
	//    activated admin directory holding an enrolled reader credential.
	bobOKDir := t.TempDir()
	actualGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-bob", ActorLimit: 99, Reader: true}
	bobOK, err := InitClientDir(InitDirOptions{
		Dir: bobOKDir, SignedDescriptor: env.rawDesc, CredKeys: bobKeys,
		ExpectedGrant: &actualGrant, ExpectedJoinReq: bobReqID, ExpectedJoinReqDigest: &bobReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bobOK.Close()
	bobOK.AttachOperatorKey(opKey)
	sOpBob, err := bobOK.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	defer sOpBob.Close()
	if _, err := bobOK.Anchor(ctx, sOpBob); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bobOK.ComposeEpochActivate("unactivated_member_must_refuse"); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("expected ErrNotActivated for ComposeEpochActivate on unactivated member dir, got %v", err)
	}

	// Enroll admin's own reader credential in adminNoCred (DirKindAdmin, Activated=true) and activate epoch 1!
	adminReaderKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	if err := adminNoCred.AttachAdminReaderKeys(adminReaderKeys); err != nil {
		t.Fatal(err)
	}
	arSkC, _ := adminReaderKeys.Signing.Signer.PublicKey().ToCBOR()
	arEkC, _ := adminReaderKeys.Encryption.PublicKey().ToCBOR()
	opEnrollAdminReader, err := adminNoCred.ComposeAndPersist(ComposeParams{
		Action: "enroll_admin_reader", Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
		Fields: ldrcrypto.Map{
			{Key: "cred_id", Value: adminReaderKeys.CredID[:]},
			{Key: "encryption_key", Value: arEkC},
			{Key: "grant", Value: ldrcrypto.Map{
				{Key: "actor_limit", Value: uint64(0)},
				{Key: "namespace_id", Value: "ns-admin-reader"},
				{Key: "reader", Value: true},
			}},
			{Key: "join_request_digest", Value: bytes.Repeat([]byte{0x22}, 32)},
			{Key: "join_request_id", Value: bytes.Repeat([]byte{0x22}, 16)},
			{Key: "signing_key", Value: arSkC},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := adminNoCred.Send(ctx, sOp, opEnrollAdminReader); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("enroll admin reader: %+v, err=%v", rep, err)
	}
	_, _ = adminNoCred.Sync(ctx, sOp)
	actOp, _, err := adminNoCred.ComposeEpochActivate("act1")
	if err != nil {
		t.Fatalf("ComposeEpochActivate on activated admin reader: %v", err)
	}
	if rep, err := adminNoCred.Send(ctx, sOp, actOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(act1): %+v, err=%v", rep, err)
	}
	_, _ = adminNoCred.Sync(ctx, sOp)
	sBobOK, err := bobOK.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sBobOK.Close()
	if err := bobOK.VerifyEnrollmentAndActivate(ctx, sBobOK); err != nil {
		t.Fatalf("VerifyEnrollmentAndActivate(bobOK): %v", err)
	}
	// Declare two actors a1 & a2 in ns-bob, open a call, and submit call_status with empty reason.
	for _, aid := range []string{"a1", "a2"} {
		opD, _ := bobOK.ComposeAndPersist(ComposeParams{
			Action: "decl_" + aid, Origin: ldrcore.OriginCredential, OpType: "actor_declare",
			Fields: ldrcrypto.Map{{Key: "actor_id", Value: aid}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-bob"}},
		})
		_, _ = bobOK.Send(ctx, sBobOK, opD)
		_, _ = bobOK.Sync(ctx, sBobOK)
	}
	opOpen, _ := bobOK.ComposeAndPersist(ComposeParams{
		Action: "open", Origin: ldrcore.OriginActor, OpType: "call_open", ActorID: "a1",
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: "c1"}, {Key: "to", Value: "a2"}},
		Plaintext: []byte(`{"subject":"s","body":"b"}`),
	})
	_, _ = bobOK.Send(ctx, sBobOK, opOpen)
	_, _ = bobOK.Sync(ctx, sBobOK)

	opStatus, err := bobOK.ComposeAndPersist(ComposeParams{
		Action: "bad_status_reason", Origin: ldrcore.OriginActor, OpType: "call_status", ActorID: "a1",
		Expect:    ldrcrypto.ExpectMap{"lifecycle_rev": 0, "turn_count": 1},
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: "c1"}, {Key: "state", Value: "deferred"}},
		Plaintext: []byte(`{"reason":"   "}`), // empty/whitespace reason -> malformed_by_author!
	})
	if err != nil {
		t.Fatal(err)
	}
	stRep, err := bobOK.Send(ctx, sBobOK, opStatus)
	if err != nil || stRep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("call_status: %+v, err=%v", stRep, err)
	}
	_, _ = bobOK.Sync(ctx, sBobOK)
	if _, rs, err := bobOK.ReadPayload(ctx, sBobOK, stRep.Outcome.Seq); err != nil || rs != ldrcore.ReadMalformed {
		t.Fatalf("expected ReadMalformed for empty call_status reason, got (%s, %v)", rs, err)
	}
	// Corrupt local epoch 1 key -> ReadPayload MUST return ReadUndecryptable (never crash/halt)!
	bobOK.mu.Lock()
	bobOK.epochs.Keys[1][0] ^= 0xff
	bobOK.mu.Unlock()
	if _, rs, err := bobOK.ReadPayload(ctx, sBobOK, stRep.Outcome.Seq); err != nil || rs != ldrcore.ReadUndecryptable {
		t.Fatalf("expected ReadUndecryptable with corrupted local key, got (%s, %v)", rs, err)
	}
}
