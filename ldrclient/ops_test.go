package ldrclient

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

func TestHighLevelOpsCallsDisputesBroadcastsActorsAndOpenWait(t *testing.T) {
	env := startTestRelay(t)
	ctx := context.Background()

	// Setup admin + operator + alice + bob.
	adminDir := t.TempDir()
	opCredKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	opKey, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
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

	enroll := func(ns string, ck *CredentialKeyBundle, limit uint64, seed byte) (ldrcrypto.JoinGrant, []byte, [32]byte) {
		grant := ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: limit, Reader: true}
		req, err := ldrcrypto.SignJoinRequest(ck.Signing.Signer, ldrcrypto.JoinRequest{
			RequestID: bytes.Repeat([]byte{seed}, 16), LineID: env.lineID, Generation: 1,
			DescriptorDigest: cd, EncryptionKey: ck.Encryption.PublicKey(), Grant: grant,
		})
		if err != nil {
			t.Fatal(err)
		}
		ch, sec, err := ldrcrypto.CreateJoinChallenge(opKey.Signer.PublicKey(), req)
		if err != nil {
			t.Fatal(err)
		}
		pr, err := ldrcrypto.RespondJoinChallenge(ck.Signing.Signer, ck.Encryption, opKey.Signer.PublicKey(), req, ch)
		if err != nil {
			t.Fatal(err)
		}
		if err := ldrcrypto.VerifyJoinProof(opKey.Signer.PublicKey(), req, ch, sec, pr); err != nil {
			t.Fatal(err)
		}
		reqDig, err := ldrcrypto.VerifyJoinRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		env.tick(1000)
		skC, _ := req.SigningKey.ToCBOR()
		ekC, _ := req.EncryptionKey.ToCBOR()
		enrOp, err := admin.ComposeAndPersist(ComposeParams{
			Action: "enroll:" + ns, Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
			Fields: ldrcrypto.Map{
				{Key: "cred_id", Value: ck.CredID[:]},
				{Key: "encryption_key", Value: ekC},
				{Key: "grant", Value: ldrcrypto.Map{
					{Key: "actor_limit", Value: grant.ActorLimit},
					{Key: "namespace_id", Value: grant.NamespaceID},
					{Key: "reader", Value: grant.Reader},
				}},
				{Key: "join_request_digest", Value: reqDig[:]},
				{Key: "join_request_id", Value: req.RequestID},
				{Key: "signing_key", Value: skC},
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

	enroll("ns-op", opCredKeys, 0, 0x40)
	aliceCK, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := enroll("ns-a", aliceCK, 4, 0x41)
	bg, brid, brdig := enroll("ns-b", bobCK, 4, 0x42)

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

	aliceDir := t.TempDir()
	alice, err := InitClientDir(InitDirOptions{
		Dir: aliceDir, SignedDescriptor: env.rawDesc, CredKeys: aliceCK,
		ExpectedGrant: &ag, ExpectedJoinReq: arid, ExpectedJoinReqDigest: &ardig,
	})
	if err != nil {
		t.Fatal(err)
	}
	bobDir := t.TempDir()
	bob, err := InitClientDir(InitDirOptions{
		Dir: bobDir, SignedDescriptor: env.rawDesc, CredKeys: bobCK,
		ExpectedGrant: &bg, ExpectedJoinReq: brid, ExpectedJoinReqDigest: &brdig,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()

	// Verify OpenClientWait waits for lock release cleanly and respects ctx cancellation.
	shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := OpenClientWait(shortCtx, aliceDir); !errors.Is(err, ErrClientLocked) {
		t.Fatalf("expected ErrClientLocked on timeout, got %v", err)
	}
	waitDone := make(chan *Client, 1)
	go func() {
		cl, err := OpenClientWait(ctx, aliceDir)
		if err != nil {
			t.Errorf("OpenClientWait after release: %v", err)
			return
		}
		waitDone <- cl
	}()
	time.Sleep(30 * time.Millisecond)
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	alice = <-waitDone
	defer alice.Close()

	sAlice, err := alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sAlice.Close()
	if err := alice.VerifyEnrollmentAndActivate(ctx, sAlice); err != nil {
		t.Fatal(err)
	}
	sBob, err := bob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sBob.Close()
	if err := bob.VerifyEnrollmentAndActivate(ctx, sBob); err != nil {
		t.Fatal(err)
	}

	// Declare actors via high-level SubmitActorDeclare.
	env.tick(1000)
	if _, err := alice.SubmitActorDeclare(ctx, sAlice, "alice", ""); err != nil {
		t.Fatalf("SubmitActorDeclare(alice): %v", err)
	}
	env.tick(1000)
	if err := bob.PrepareForMutation(ctx, sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.SubmitActorDeclare(ctx, sBob, "bob", ""); err != nil {
		t.Fatalf("SubmitActorDeclare(bob): %v", err)
	}
	if _, err := alice.Sync(ctx, sAlice); err != nil {
		t.Fatal(err)
	}

	// Full call lifecycle: open -> turn -> note -> attach -> dispute open/measure/resolve -> ratify -> bye/bye -> status reopen.
	env.tick(1000)
	callID := alice.NextCallID("Design Sync")
	if callID != "0001-design-sync" {
		t.Fatalf("NextCallID = %q, want 0001-design-sync", callID)
	}
	if _, err := alice.SubmitCallOpen(ctx, sAlice, "alice", "bob", callID, "Design Sync", "hello bob", "aaaa111", ""); err != nil {
		t.Fatalf("SubmitCallOpen: %v", err)
	}
	env.tick(1000)
	if err := bob.PrepareForMutation(ctx, sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	resolvedID, err := bob.ResolveCallID("bob", "")
	if err != nil || resolvedID != callID {
		t.Fatalf("ResolveCallID: got %q err=%v", resolvedID, err)
	}
	if _, err := bob.SubmitCallTurn(ctx, sBob, "bob", callID, "hi alice!", false, "bbbb222", "aaaa111"); err != nil {
		t.Fatalf("SubmitCallTurn: %v", err)
	}
	if _, err := bob.SubmitCallNote(ctx, sBob, "bob", callID, "fyi note"); err != nil {
		t.Fatalf("SubmitCallNote: %v", err)
	}
	if _, err := bob.SubmitCallAttach(ctx, sBob, "bob", callID, "plan.txt", []byte("step 1\nstep 2\n")); err != nil {
		t.Fatalf("SubmitCallAttach: %v", err)
	}
	_, dispID, err := bob.SubmitDisputeOpen(ctx, sBob, "bob", callID, "is X faster than Y?")
	if err != nil || dispID != "1" {
		t.Fatalf("SubmitDisputeOpen: dispID=%q err=%v", dispID, err)
	}
	if _, err := bob.SubmitDisputeMeasure(ctx, sBob, "bob", callID, dispID, "go test -bench=."); err != nil {
		t.Fatalf("SubmitDisputeMeasure(bob): %v", err)
	}
	env.tick(1000)
	if err := alice.PrepareForMutation(ctx, sAlice, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SubmitDisputeMeasure(ctx, sAlice, "alice", callID, dispID, "go test -bench=."); err != nil {
		t.Fatalf("SubmitDisputeMeasure(alice): %v", err)
	}
	if _, err := alice.SubmitDisputeResolve(ctx, sAlice, "alice", callID, dispID, "measured", "X is 2x faster"); err != nil {
		t.Fatalf("SubmitDisputeResolve: %v", err)
	}

	// Operator ratifies & creates a briefing broadcast to default audience.
	env.tick(1000)
	if err := admin.PrepareForMutation(ctx, sOp, ldrcrypto.PrincipalOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SubmitCallRatify(ctx, sOp, callID, "approved by human"); err != nil {
		t.Fatalf("SubmitCallRatify: %v", err)
	}
	if _, err := admin.SubmitBroadcastCreate(ctx, sOp, "b-001", "briefing", "operator", "ship phase D", nil, true); err != nil {
		t.Fatalf("SubmitBroadcastCreate: %v", err)
	}

	// Alice reads transcript, reads broadcast (idempotent on 2nd call), replies, and both say bye.
	env.tick(1000)
	if err := alice.PrepareForMutation(ctx, sAlice, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	tr, err := alice.ReadCallTranscript(ctx, sAlice, callID)
	if err != nil {
		t.Fatalf("ReadCallTranscript: %v", err)
	}
	if tr.Subject != "Design Sync" || len(tr.Turns) != 2 || len(tr.Notes) != 2 || len(tr.Attachments) != 1 ||
		string(tr.Attachments[0].Data) != "step 1\nstep 2\n" || len(tr.Disputes) != 1 || !tr.Disputes[0].Resolved ||
		tr.Disputes[0].ResolutionText != "X is 2x faster" {
		t.Fatalf("unexpected transcript: %+v", tr)
	}
	r1, err := alice.SubmitBroadcastRead(ctx, sAlice, "alice", "b-001")
	if err != nil || r1.AlreadyCommitted {
		t.Fatalf("first SubmitBroadcastRead: %+v err=%v", r1, err)
	}
	r2, err := alice.SubmitBroadcastRead(ctx, sAlice, "alice", "b-001")
	if err != nil || !r2.AlreadyCommitted {
		t.Fatalf("second SubmitBroadcastRead should be local idempotent: %+v err=%v", r2, err)
	}
	if _, err := alice.SubmitBroadcastReply(ctx, sAlice, "alice", "b-001", "acknowledged"); err != nil {
		t.Fatalf("SubmitBroadcastReply: %v", err)
	}
	bvs, err := alice.ListBroadcasts(ctx, sAlice, "alice", true)
	if err != nil || len(bvs) != 1 || bvs[0].Body != "ship phase D" || len(bvs[0].Replies) != 1 || !bvs[0].ReadByActor {
		t.Fatalf("ListBroadcasts: %+v err=%v", bvs, err)
	}

	// Bilateral bye closes the call; actor_addressing toggles default_addressed.
	if _, err := alice.SubmitCallBye(ctx, sAlice, "alice", callID); err != nil {
		t.Fatalf("SubmitCallBye(alice): %v", err)
	}
	env.tick(1000)
	if err := bob.PrepareForMutation(ctx, sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.SubmitCallBye(ctx, sBob, "bob", callID); err != nil {
		t.Fatalf("SubmitCallBye(bob): %v", err)
	}
	if bob.State().Calls[callID].Status() != "resolved" {
		t.Fatalf("expected resolved after bilateral bye, got %s", bob.State().Calls[callID].Status())
	}
	if _, err := bob.SubmitCallStatus(ctx, sBob, "bob", callID, "open", "need follow-up", ""); err != nil {
		t.Fatalf("SubmitCallStatus(open): %v", err)
	}
	if bob.State().Calls[callID].Status() != "open" {
		t.Fatalf("expected reopened call, got %s", bob.State().Calls[callID].Status())
	}
	if _, err := bob.SubmitActorAddressing(ctx, sBob, "bob", false); err != nil {
		t.Fatalf("SubmitActorAddressing(false): %v", err)
	}
	if bob.State().Line.Actors["bob"].DefaultAddressed {
		t.Fatal("expected bob default_addressed=false")
	}
}
