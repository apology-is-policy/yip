package ldrclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
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

// Turn 4 D2 Finding 1 regression:
//   - SubmitDisputeOpen MUST derive its returned dispute ID at the caller's exact
//     committed sequence even when another participant commits an intervening
//     dispute_open before the caller's post-Send Sync runs.
func TestSubmitDisputeOpenConcurrentInterveningDispute(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "alice", "ns-alice"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if err := rig.bob.PrepareForMutation(ctx, rig.sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.bob.SubmitActorDeclare(ctx, rig.sBob, "bob", "ns-bob"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if err := rig.alice.PrepareForMutation(ctx, rig.sAlice, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	callID := "0001-concurrent-disputes"
	if _, err := rig.alice.SubmitCallOpen(ctx, rig.sAlice, "alice", "bob", callID, "Race", "hello", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := rig.bob.PrepareForMutation(ctx, rig.sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}

	// Pre-compose Bob's dispute_open so the HTTP hook can submit Bob's dispute
	// right AFTER Alice's dispute_open commits on /submit and BEFORE Alice runs Sync!
	bobOpID, err := rig.bob.ComposeAndPersist(ComposeParams{
		Action:    "dispute_open:" + callID,
		Origin:    ldrcore.OriginActor,
		OpType:    "dispute_open",
		ActorID:   "bob",
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}},
		Plaintext: []byte(`{"claim":"bob intervening claim"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	var injected atomic.Bool
	var bobSendErr error
	rig.env.setHTTPHook(func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if strings.HasSuffix(r.URL.Path, "/submit") && injected.CompareAndSwap(false, true) {
			// Alice's dispute_open just committed; immediately commit Bob's dispute_open
			// BEFORE Alice's SubmitDisputeOpen runs Sync!
			rig.env.setHTTPHook(nil)
			rig.env.tick(100)
			rep, serr := rig.bob.Send(ctx, rig.sBob, bobOpID)
			if serr != nil {
				bobSendErr = serr
			} else if rep.Outcome.Kind != ldrcore.Committed {
				bobSendErr = errors.New("bob dispute_open not committed: " + rep.Outcome.Reason)
			}
		}
	})

	rig.env.tick(1000)
	res, aliceDispID, err := rig.alice.SubmitDisputeOpen(ctx, rig.sAlice, "alice", callID, "alice first claim")
	rig.env.setHTTPHook(nil)
	if err != nil {
		t.Fatalf("alice.SubmitDisputeOpen: %v", err)
	}
	if bobSendErr != nil {
		t.Fatalf("bob intervening dispute_open failed: %v", bobSendErr)
	}
	if gotCount := rig.alice.State().Calls[callID].DisputeCount; gotCount != 2 {
		t.Fatalf("expected Alice to have synced both disputes (DisputeCount=2), got %d", gotCount)
	}
	if aliceDispID != "1" {
		t.Fatalf("SubmitDisputeOpen returned %q (seq=%d), want caller's exact ID \"1\" despite intervening dispute \"2\"", aliceDispID, res.Seq)
	}
	// Verify transcript maps dispute 1 -> Alice's claim and dispute 2 -> Bob's claim.
	tr, err := rig.alice.ReadCallTranscript(ctx, rig.sAlice, callID)
	if err != nil || len(tr.Disputes) != 2 || tr.Disputes[0].Claim != "alice first claim" || tr.Disputes[1].Claim != "bob intervening claim" {
		t.Fatalf("unexpected disputes in transcript: %+v err=%v", tr, err)
	}
}

// Turn 4 D2 Finding 2 regression:
//   - Legitimate per-entry ReadNoKey / ReadUndecryptable statuses still succeed
//     in ReadCallTranscript / ListCallSummaries / ReadBroadcast / ListBroadcasts.
//   - Operational/durability errors (ErrOutboxUncertain, ErrEpochsUncertain,
//     ErrNotActivated) from ReadPayload MUST propagate as non-nil errors instead
//     of being converted to ReadUndecryptable with nil error.
func TestReadTranscriptAndListsPropagateOperationalErrors(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "alice", "ns-alice"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if err := rig.bob.PrepareForMutation(ctx, rig.sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.bob.SubmitActorDeclare(ctx, rig.sBob, "bob", "ns-bob"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if err := rig.alice.PrepareForMutation(ctx, rig.sAlice, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	callID := "0001-read-errors"
	if _, err := rig.alice.SubmitCallOpen(ctx, rig.sAlice, "alice", "bob", callID, "Epoch1 Subject", "Epoch1 Body", "", ""); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if err := rig.admin.PrepareForMutation(ctx, rig.sOp, ldrcrypto.PrincipalOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.admin.SubmitBroadcastCreate(ctx, rig.sOp, "bc-ep1", "briefing", "operator", "Epoch1 Broadcast", nil, true); err != nil {
		t.Fatal(err)
	}

	// Enroll Charlie AFTER epoch 1 and activate epoch 2 -> Charlie has NO epoch-1 key (legitimate ReadNoKey!).
	charlieCK, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	cg, crid, crdig := rig.enroll("ns-charlie", charlieCK, 2, 0x71)
	rig.env.tick(1000)
	ep2Op, _, err := rig.admin.ComposeEpochActivate("epoch-2")
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := rig.admin.Send(ctx, rig.sOp, ep2Op); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("epoch-2 activate: %+v %v", rep, err)
	}
	if _, err := rig.admin.Sync(ctx, rig.sOp); err != nil {
		t.Fatal(err)
	}

	charlieDir := t.TempDir()
	charlie, err := InitClientDir(InitDirOptions{
		Dir: charlieDir, SignedDescriptor: rig.env.rawDesc, CredKeys: charlieCK,
		ExpectedGrant: &cg, ExpectedJoinReq: crid, ExpectedJoinReqDigest: &crdig,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer charlie.Close()
	sCharlie, err := charlie.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sCharlie.Close()

	// Unactivated Charlie MUST fail with ErrNotActivated across all read/list helpers!
	if _, err := charlie.ListCallSummaries(ctx, sCharlie, "", true); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("unactivated ListCallSummaries: got %v, want ErrNotActivated", err)
	}
	if _, err := charlie.ListBroadcasts(ctx, sCharlie, "", true); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("unactivated ListBroadcasts: got %v, want ErrNotActivated", err)
	}

	if err := charlie.VerifyEnrollmentAndActivate(ctx, sCharlie); err != nil {
		t.Fatal(err)
	}

	// Activated Charlie reading epoch-1 call & broadcast MUST succeed with legitimate ReadNoKey!
	trNoKey, err := charlie.ReadCallTranscript(ctx, sCharlie, callID)
	if err != nil || len(trNoKey.Turns) != 1 || trNoKey.Turns[0].ReadStatus != ldrcore.ReadNoKey {
		t.Fatalf("expected legitimate ReadNoKey transcript for Charlie, got tr=%+v err=%v", trNoKey, err)
	}
	bvNoKey, err := charlie.ReadBroadcast(ctx, sCharlie, "", "bc-ep1")
	if err != nil || bvNoKey.ReadStatus != ldrcore.ReadNoKey {
		t.Fatalf("expected legitimate ReadNoKey broadcast for Charlie, got bv=%+v err=%v", bvNoKey, err)
	}

	// Sync Bob so Bob holds epoch-1 payloads, then fence ErrOutboxUncertain & ErrEpochsUncertain!
	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}

	// 1. ErrOutboxUncertain MUST propagate from all 4 read/list helpers!
	rig.bob.mu.Lock()
	rig.bob.outboxUncertain = true
	rig.bob.mu.Unlock()
	if _, err := rig.bob.ReadCallTranscript(ctx, rig.sBob, callID); !errors.Is(err, ErrOutboxUncertain) {
		t.Fatalf("ReadCallTranscript masked ErrOutboxUncertain: %v", err)
	}
	if _, err := rig.bob.ListCallSummaries(ctx, rig.sBob, "bob", true); !errors.Is(err, ErrOutboxUncertain) {
		t.Fatalf("ListCallSummaries masked ErrOutboxUncertain: %v", err)
	}
	if _, err := rig.bob.ReadBroadcast(ctx, rig.sBob, "bob", "bc-ep1"); !errors.Is(err, ErrOutboxUncertain) {
		t.Fatalf("ReadBroadcast masked ErrOutboxUncertain: %v", err)
	}
	if _, err := rig.bob.ListBroadcasts(ctx, rig.sBob, "bob", true); !errors.Is(err, ErrOutboxUncertain) {
		t.Fatalf("ListBroadcasts masked ErrOutboxUncertain: %v", err)
	}

	// 2. ErrEpochsUncertain MUST propagate from all 4 read/list helpers!
	rig.bob.mu.Lock()
	rig.bob.outboxUncertain = false
	rig.bob.epochsUncertain = true
	rig.bob.mu.Unlock()
	if _, err := rig.bob.ReadCallTranscript(ctx, rig.sBob, callID); !errors.Is(err, ErrEpochsUncertain) {
		t.Fatalf("ReadCallTranscript masked ErrEpochsUncertain: %v", err)
	}
	if _, err := rig.bob.ListCallSummaries(ctx, rig.sBob, "bob", true); !errors.Is(err, ErrEpochsUncertain) {
		t.Fatalf("ListCallSummaries masked ErrEpochsUncertain: %v", err)
	}
	if _, err := rig.bob.ReadBroadcast(ctx, rig.sBob, "bob", "bc-ep1"); !errors.Is(err, ErrEpochsUncertain) {
		t.Fatalf("ReadBroadcast masked ErrEpochsUncertain: %v", err)
	}
	if _, err := rig.bob.ListBroadcasts(ctx, rig.sBob, "bob", true); !errors.Is(err, ErrEpochsUncertain) {
		t.Fatalf("ListBroadcasts masked ErrEpochsUncertain: %v", err)
	}
	rig.bob.mu.Lock()
	rig.bob.epochsUncertain = false
	rig.bob.mu.Unlock()
}
