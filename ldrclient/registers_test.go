package ldrclient

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

func TestClientAdvisoryRegistersActivationPersistenceReconcileAndVerification(t *testing.T) {
	env := startTestRelay(t)
	ctx := context.Background()

	// Bootstrap admin, operator, and enrolled reader credentials (op-device, alice, bob).
	adminDir := t.TempDir()
	opCredKeys, err := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	opKey, err := GenerateSigningKey(ldrcrypto.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := InitClientDir(InitDirOptions{
		Dir: adminDir, SignedDescriptor: env.rawDesc, CredKeys: opCredKeys, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	admin.AttachRootKey(env.root1)
	admin.AttachOperatorKey(opKey)

	sRoot, err := admin.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer sRoot.Close()

	desc, cd, _, _ := admin.Descriptor()
	rk0, _ := desc.RootKeys[0].ToCBOR()
	rk1, _ := desc.RootKeys[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	initOp, err := admin.ComposeAndPersist(ComposeParams{
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
	if rep, err := admin.Send(ctx, sRoot, initOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("line_init: %+v %v", rep, err)
	}
	if _, err := admin.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}

	env.tick(1000)
	opPubCBOR, _ := opKey.Signer.PublicKey().ToCBOR()
	authOp, err := admin.ComposeAndPersist(ComposeParams{
		Action: "authorize_operator", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubCBOR}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sRoot, authOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("authorize_operator: %+v %v", rep, err)
	}
	if _, err := admin.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}

	sOp, err := admin.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	defer sOp.Close()

	enrollCred := func(ns string, ck *CredentialKeyBundle, limit uint64, reqSeed byte) (ldrcrypto.JoinGrant, []byte, [32]byte) {
		grant := ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: limit, Reader: true}
		req, err := ldrcrypto.SignJoinRequest(ck.Signing.Signer, ldrcrypto.JoinRequest{
			RequestID:        bytes.Repeat([]byte{reqSeed}, 16),
			LineID:           env.lineID,
			Generation:       1,
			DescriptorDigest: cd,
			EncryptionKey:    ck.Encryption.PublicKey(),
			Grant:            grant,
		})
		if err != nil {
			t.Fatal(err)
		}
		ch, sec, err := ldrcrypto.CreateJoinChallenge(opKey.Signer.PublicKey(), req)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ldrcrypto.RespondJoinChallenge(ck.Signing.Signer, ck.Encryption, opKey.Signer.PublicKey(), req, ch)
		if err != nil {
			t.Fatal(err)
		}
		if err := ldrcrypto.VerifyJoinProof(opKey.Signer.PublicKey(), req, ch, sec, proof); err != nil {
			t.Fatal(err)
		}
		reqDig, err := ldrcrypto.VerifyJoinRequest(req)
		if err != nil {
			t.Fatal(err)
		}

		env.tick(1000)
		sigCBOR, _ := req.SigningKey.ToCBOR()
		encCBOR, _ := req.EncryptionKey.ToCBOR()
		gMap := ldrcrypto.Map{
			{Key: "actor_limit", Value: grant.ActorLimit},
			{Key: "namespace_id", Value: grant.NamespaceID},
			{Key: "reader", Value: grant.Reader},
		}
		enrOp, err := admin.ComposeAndPersist(ComposeParams{
			Action: "enroll:" + ns, Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
			Fields: ldrcrypto.Map{
				{Key: "cred_id", Value: ck.CredID[:]},
				{Key: "encryption_key", Value: encCBOR},
				{Key: "grant", Value: gMap},
				{Key: "join_request_digest", Value: reqDig[:]},
				{Key: "join_request_id", Value: req.RequestID},
				{Key: "signing_key", Value: sigCBOR},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if rep, err := admin.Send(ctx, sOp, enrOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
			t.Fatalf("enroll %s: %+v %v", ns, rep, err)
		}
		if _, err := admin.Sync(ctx, sOp); err != nil {
			t.Fatal(err)
		}
		return grant, req.RequestID, reqDig
	}

	enrollMember := func(ns string, reqSeed byte) (string, *Client) {
		ck, err := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
		if err != nil {
			t.Fatal(err)
		}
		grant, reqID, reqDig := enrollCred(ns, ck, 4, reqSeed)
		dir := t.TempDir()
		cl, err := InitClientDir(InitDirOptions{
			Dir: dir, SignedDescriptor: env.rawDesc, CredKeys: ck,
			ExpectedGrant: &grant, ExpectedJoinReq: reqID, ExpectedJoinReqDigest: &reqDig,
		})
		if err != nil {
			t.Fatal(err)
		}
		return dir, cl
	}

	enrollCred("ns-op", opCredKeys, 0, 0x30)
	aliceDir, alice := enrollMember("ns-alice", 0x31)
	_, bob := enrollMember("ns-bob", 0x32)
	defer bob.Close()

	// Activate epoch 1 for both alice and bob.
	env.tick(1000)
	epOp, _, err := admin.ComposeEpochActivate("epoch-1")
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sOp, epOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("epoch activate: %+v %v", rep, err)
	}
	if _, err := admin.Sync(ctx, sOp); err != nil {
		t.Fatal(err)
	}

	// Activate both alice and bob via O25 full replay.
	sAlice, err := alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.VerifyEnrollmentAndActivate(ctx, sAlice); err != nil {
		t.Fatalf("alice activate: %v", err)
	}
	sBob, err := bob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sBob.Close()
	if err := bob.VerifyEnrollmentAndActivate(ctx, sBob); err != nil {
		t.Fatalf("bob activate: %v", err)
	}

	// Alice declares actor "alice-1" and publishes presence twice.
	env.tick(1000)
	declOp, err := alice.ComposeAndPersist(ComposeParams{
		Action: "declare-alice", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "alice-1"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := alice.Send(ctx, sAlice, declOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("actor_declare: %+v %v", rep, err)
	}
	if _, err := alice.Sync(ctx, sAlice); err != nil {
		t.Fatal(err)
	}

	env.tick(1000)
	if rep, err := alice.PublishRegister(ctx, sAlice, "alice-1", "presence", []byte(`{"busy":"building"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister 1: rep=%+v err=%v", rep, err)
	}
	_, seqAfterFirst, _ := alice.Checkpoint()

	// Second publish reuses the SAME writer_rev (no redundant register_activate commit!).
	env.tick(1000)
	if rep, err := alice.PublishRegister(ctx, sAlice, "alice-1", "presence", []byte(`{"busy":"testing"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister 2: rep=%+v err=%v", rep, err)
	}
	_, seqAfterSecond, _ := alice.Checkpoint()
	if seqAfterSecond != seqAfterFirst {
		t.Fatalf("expected no redundant register_activate commit: seq %d -> %d", seqAfterFirst, seqAfterSecond)
	}

	// Reopen alice from disk -> persisted counter & incarnation survive reopen with zero redundant activation!
	sAlice.Close()
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	alice, err = OpenClient(aliceDir)
	if err != nil {
		t.Fatalf("OpenClient(alice): %v", err)
	}
	defer alice.Close()
	sAlice, err = alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sAlice.Close()

	env.tick(1000)
	if rep, err := alice.PublishRegister(ctx, sAlice, "alice-1", "presence", []byte(`{"busy":"reopened"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister after reopen: rep=%+v err=%v", rep, err)
	}
	_, seqAfterReopen, _ := alice.Checkpoint()
	if seqAfterReopen != seqAfterFirst {
		t.Fatalf("expected persisted register writer to avoid re-activation across reopen: seq %d -> %d", seqAfterFirst, seqAfterReopen)
	}

	// Bob syncs and reads Alice's verified decrypted presence register.
	if _, err := bob.Sync(ctx, sBob); err != nil {
		t.Fatal(err)
	}
	regs, err := bob.ReadRegisters(ctx, sBob, "presence")
	if err != nil {
		t.Fatalf("bob.ReadRegisters: %v", err)
	}
	if len(regs) != 1 || regs[0].Actor != "alice-1" || regs[0].Historical ||
		regs[0].ReadStatus != ldrcore.ReadOK || string(regs[0].Plaintext) != `{"busy":"reopened"}` ||
		regs[0].WriterRev != 1 || regs[0].Counter != 3 {
		t.Fatalf("unexpected verified register: %+v", regs)
	}

	// Fault-inject uncertain register persistence -> blocks publish until ReconcileDurability,
	// then ReconcileDurability marks counter untrusted so next publish activates writer_rev=2!
	alice.SetSyncHooks(nil, func(string) error { return errors.New("injected dir sync failure") })
	if _, err := alice.PublishRegister(ctx, sAlice, "alice-1", "presence", []byte(`{"busy":"uncertain"}`)); err == nil {
		t.Fatal("expected error on injected dir sync failure")
	}
	if _, err := alice.PublishRegister(ctx, sAlice, "alice-1", "presence", []byte(`{"busy":"blocked"}`)); !errors.Is(err, ErrRegisterUncertain) {
		t.Fatalf("expected ErrRegisterUncertain while fenced, got %v", err)
	}
	alice.SetSyncHooks(nil, nil)
	if err := alice.ReconcileDurability(); err != nil {
		t.Fatalf("ReconcileDurability: %v", err)
	}
	env.tick(1000)
	if rep, err := alice.PublishRegister(ctx, sAlice, "alice-1", "presence", []byte(`{"busy":"recovered"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister after reconcile: rep=%+v err=%v", rep, err)
	}
	if _, err := bob.Sync(ctx, sBob); err != nil {
		t.Fatal(err)
	}
	regs2, err := bob.ReadRegisters(ctx, sBob, "presence")
	if err != nil || len(regs2) != 1 || regs2[0].WriterRev != 2 || regs2[0].Counter != 1 || string(regs2[0].Plaintext) != `{"busy":"recovered"}` {
		t.Fatalf("expected fresh incarnation writer_rev=2 counter=1 after untrusted reconcile, got %+v err=%v", regs2, err)
	}

	// Revoke Alice's credential -> Bob syncs and locally computes Historical=true on Alice's cached register!
	env.tick(1000)
	if _, err := admin.Sync(ctx, sOp); err != nil {
		t.Fatal(err)
	}
	aliceCID, _ := alice.CredID()
	revOp, err := admin.ComposeAndPersist(ComposeParams{
		Action: "revoke-alice", Origin: ldrcore.OriginOperator, OpType: "credential_revoke",
		Fields: ldrcrypto.Map{{Key: "cred_id", Value: aliceCID[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sOp, revOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("revoke alice: %+v %v", rep, err)
	}
	if _, err := bob.Sync(ctx, sBob); err != nil {
		t.Fatal(err)
	}
	regsAfterRevoke, err := bob.ReadRegisters(ctx, sBob, "presence")
	if err != nil || len(regsAfterRevoke) != 1 || !regsAfterRevoke[0].Historical {
		t.Fatalf("expected local Historical=true after alice revocation, got %+v err=%v", regsAfterRevoke, err)
	}
}
