package ldrclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

type testRelayEnv struct {
	dir        string
	wallMS     int64
	monoMS     int64
	store      *ldrstore.FileStore
	engine     *ldrrelay.RelayEngine
	httpServer *http.Server
	origin     ldrcrypto.RelayOrigin
	lineID     []byte
	root1      *SigningKeyMaterial
	root2      *SigningKeyMaterial
	rawDesc    []byte
	cd         [32]byte
	genesis    [32]byte
	profDigest [32]byte
}

func startTestRelay(t *testing.T) *testRelayEnv {
	t.Helper()
	dir := t.TempDir()
	certP := filepath.Join(dir, "tls", "server.crt")
	keyP := filepath.Join(dir, "tls", "server.key")
	pin, err := ldrrelay.InitSelfSignedCert(certP, keyP, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("InitSelfSignedCert: %v", err)
	}
	tlsCfg, err := ldrrelay.ServerTLSConfig(certP, keyP)
	if err != nil {
		t.Fatal(err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)

	env := &testRelayEnv{dir: dir, wallMS: 1_700_000_000_000, monoMS: 0}
	clockSrc := func() ldrrelay.ClockSample {
		return ldrrelay.ClockSample{WallMS: env.wallMS, MonoMS: env.monoMS}
	}
	st, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), clockSrc)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: ldrrelay.NewRelayServer(eng)}
	go func() { _ = hs.Serve(tlsLn) }()

	r1, err := GenerateSigningKey(ldrcrypto.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := GenerateSigningKey(ldrcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	lineID := bytes.Repeat([]byte{0x55}, 16)
	origin := ldrcrypto.RelayOrigin{
		URL:            "https://" + rawLn.Addr().String(),
		TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
		TLSPin:         pin[:],
		SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
	}
	desc := ldrcrypto.CreationDescriptor{
		Version:     1,
		LineID:      lineID,
		Generation:  1,
		RootKeys:    []ldrcrypto.PublicKey{r1.Signer.PublicKey(), r2.Signer.PublicKey()},
		RelayOrigin: origin,
		Profile:     ldrcrypto.ProfileV1(),
	}
	signed, err := ldrcrypto.SignCreationDescriptor(r2.Signer, desc)
	if err != nil {
		t.Fatal(err)
	}
	rawDesc, err := signed.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := eng.Provision(rawDesc)
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := desc.Profile.Digest()

	env.store = st
	env.engine = eng
	env.httpServer = hs
	env.origin = origin
	env.lineID = lineID
	env.root1 = r1
	env.root2 = r2
	env.rawDesc = rawDesc
	env.cd = prov.DescriptorDigest
	env.genesis = prov.GenesisAnchor
	env.profDigest = pd

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		_ = eng.Shutdown()
	})
	return env
}

func (e *testRelayEnv) tick(ms int64) {
	e.wallMS += ms
	e.monoMS += ms
}

func TestClientEndToEndO25JoinerPersistBeforeSendProjectionDeliveryAndRule8(t *testing.T) {
	env := startTestRelay(t)
	ctx := context.Background()

	// 1. Admin client initializes line (root1 Ed25519) & authorizes operator (P-256).
	adminDir := t.TempDir()
	opCredKeys, err := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	opKey, err := GenerateSigningKey(ldrcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := InitClientDir(InitDirOptions{
		Dir: adminDir, SignedDescriptor: env.rawDesc, CredKeys: opCredKeys, Activated: true,
	})
	if err != nil {
		t.Fatalf("InitClientDir(admin): %v", err)
	}
	defer admin.Close()
	admin.AttachRootKey(env.root1)
	admin.AttachOperatorKey(opKey)

	// Concurrent second opener on same client dir MUST fail with ErrClientLocked.
	if _, err := OpenClient(adminDir); !errors.Is(err, ErrClientLocked) {
		t.Fatalf("expected ErrClientLocked on concurrent client open, got %v", err)
	}

	sRoot, err := admin.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatalf("Dial(root): %v", err)
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
		t.Fatalf("Compose(line_init): %v", err)
	}
	if rep, err := admin.Send(ctx, sRoot, initOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(line_init): %+v, err=%v", rep, err)
	}
	if _, err := admin.Sync(ctx, sRoot); err != nil {
		t.Fatalf("Sync after line_init: %v", err)
	}

	// Authorize P-256 operator key.
	env.tick(1000)
	opPubCBOR, _ := opKey.Signer.PublicKey().ToCBOR()
	authOp, err := admin.ComposeAndPersist(ComposeParams{
		Action: "authorize_operator", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubCBOR}},
	})
	if err != nil {
		t.Fatalf("Compose(operator_key_authorize): %v", err)
	}
	if rep, err := admin.Send(ctx, sRoot, authOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(operator_key_authorize): %+v, err=%v", rep, err)
	}
	if _, err := admin.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}

	// Open operator session & enroll operator's own reader device (actor_limit=0, reader=true)
	// plus Alice (cA) and Bob (cB) via full P3 key-first ceremony!
	sOp, err := admin.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatalf("Dial(operator): %v", err)
	}
	defer sOp.Close()

	enrollMember := func(name string, credKeys *CredentialKeyBundle, grant ldrcrypto.JoinGrant, reqByte byte) ([]byte, [32]byte) {
		t.Helper()
		req, err := ldrcrypto.SignJoinRequest(credKeys.Signing.Signer, ldrcrypto.JoinRequest{
			RequestID:        bytes.Repeat([]byte{reqByte}, 16),
			LineID:           env.lineID,
			Generation:       1,
			DescriptorDigest: cd,
			EncryptionKey:    credKeys.Encryption.PublicKey(),
			Grant:            grant,
		})
		if err != nil {
			t.Fatalf("SignJoinRequest(%s): %v", name, err)
		}
		ch, sec, err := ldrcrypto.CreateJoinChallenge(opKey.Signer.PublicKey(), req)
		if err != nil {
			t.Fatalf("CreateJoinChallenge(%s): %v", name, err)
		}
		pr, err := ldrcrypto.RespondJoinChallenge(credKeys.Signing.Signer, credKeys.Encryption, opKey.Signer.PublicKey(), req, ch)
		if err != nil {
			t.Fatalf("RespondJoinChallenge(%s): %v", name, err)
		}
		if err := ldrcrypto.VerifyJoinProof(opKey.Signer.PublicKey(), req, ch, sec, pr); err != nil {
			t.Fatalf("VerifyJoinProof(%s): %v", name, err)
		}
		reqDig, err := ldrcrypto.VerifyJoinRequest(req)
		if err != nil {
			t.Fatalf("VerifyJoinRequest(%s): %v", name, err)
		}
		skC, _ := req.SigningKey.ToCBOR()
		ekC, _ := req.EncryptionKey.ToCBOR()
		opID, err := admin.ComposeAndPersist(ComposeParams{
			Action: "enroll_" + name, Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
			Fields: ldrcrypto.Map{
				{Key: "cred_id", Value: req.CredID[:]},
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
			t.Fatalf("Compose(enroll %s): %v", name, err)
		}
		if rep, err := admin.Send(ctx, sOp, opID); err != nil || rep.Outcome.Kind != ldrcore.Committed {
			t.Fatalf("Send(enroll %s): %+v, err=%v", name, rep, err)
		}
		if _, err := admin.Sync(ctx, sOp); err != nil {
			t.Fatal(err)
		}
		return req.RequestID, reqDig
	}

	aliceKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	aliceGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-alice", ActorLimit: 4, Reader: true}
	bobGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-bob", ActorLimit: 4, Reader: true}

	// Operator device enrolls itself with actor_limit=0, reader=true (P9 reader generator).
	enrollMember("op-device", opCredKeys, ldrcrypto.JoinGrant{NamespaceID: "ns-op", ActorLimit: 0, Reader: true}, 0x01)
	aliceReqID, aliceReqDig := enrollMember("alice", aliceKeys, aliceGrant, 0x02)
	bobReqID, bobReqDig := enrollMember("bob", bobKeys, bobGrant, 0x03)

	// Activate epoch 1 on the enrolled operator reader (P9).
	actOp, _, err := admin.ComposeEpochActivate("activate_epoch_1")
	if err != nil {
		t.Fatalf("ComposeEpochActivate(1): %v", err)
	}
	if rep, err := admin.Send(ctx, sOp, actOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(epoch_activate 1): %+v, err=%v", rep, err)
	}
	if _, err := admin.Sync(ctx, sOp); err != nil {
		t.Fatal(err)
	}

	// 2. Alice and Bob initialize their fresh local client directories and run
	//    O25 full-replay onboarding (VerifyEnrollmentAndActivate)!
	aliceDir := t.TempDir()
	alice, err := InitClientDir(InitDirOptions{
		Dir: aliceDir, SignedDescriptor: env.rawDesc, CredKeys: aliceKeys,
		ExpectedGrant: &aliceGrant, ExpectedJoinReq: aliceReqID, ExpectedJoinReqDigest: &aliceReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Before O25 activation, ordinary credential Compose MUST fail with ErrNotActivated!
	if _, err := alice.ComposeAndPersist(ComposeParams{
		Action: "premature", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "alice"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-alice"}},
	}); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("expected ErrNotActivated before O25 verification, got %v", err)
	}

	sAlice, err := alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatalf("Dial(alice): %v", err)
	}
	if err := alice.VerifyEnrollmentAndActivate(ctx, sAlice); err != nil {
		t.Fatalf("VerifyEnrollmentAndActivate(alice): %v", err)
	}
	if !alice.HasEpochKey(1) {
		t.Fatalf("alice did not unwrap epoch 1 key during O25 onboarding")
	}

	bobDir := t.TempDir()
	bob, err := InitClientDir(InitDirOptions{
		Dir: bobDir, SignedDescriptor: env.rawDesc, CredKeys: bobKeys,
		ExpectedGrant: &bobGrant, ExpectedJoinReq: bobReqID, ExpectedJoinReqDigest: &bobReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	sBob, err := bob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatalf("Dial(bob): %v", err)
	}
	defer sBob.Close()
	if err := bob.VerifyEnrollmentAndActivate(ctx, sBob); err != nil {
		t.Fatalf("VerifyEnrollmentAndActivate(bob): %v", err)
	}

	// Declare actors alice and bob.
	declAlice, err := alice.ComposeAndPersist(ComposeParams{
		Action: "declare_alice", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "alice"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := alice.Send(ctx, sAlice, declAlice); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(decl alice): %+v, err=%v", rep, err)
	}
	declBob, err := bob.ComposeAndPersist(ComposeParams{
		Action: "declare_bob", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "bob"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-bob"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := bob.Send(ctx, sBob, declBob); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(decl bob): %+v, err=%v", rep, err)
	}
	_, _ = alice.Sync(ctx, sAlice)
	_, _ = bob.Sync(ctx, sBob)

	// 3. PERSIST-BEFORE-SEND CRASH/RESTART TEST (§5.7 rule 1 & 3):
	//    Alice composes encrypted call_open (persisted to outbox.cbor),
	//    then her process exits BEFORE sending!
	turn1Plain := []byte(`{"subject":"Phase C","body":"Persisted before first send!"}`)
	openOpID, err := alice.ComposeAndPersist(ComposeParams{
		Action: "open_call_1", Origin: ldrcore.OriginActor, OpType: "call_open",
		ActorID:   "alice",
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: "call-001"}, {Key: "to", Value: "bob"}},
		Plaintext: turn1Plain,
	})
	if err != nil {
		t.Fatalf("Compose(call_open): %v", err)
	}
	sAlice.Close()
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen Alice's client directory after simulated crash:
	// MustResolve MUST be true, blocking any new Compose until ResolveAll completes!
	alice, err = OpenClient(aliceDir)
	if err != nil {
		t.Fatalf("reopen alice: %v", err)
	}
	defer alice.Close()
	if _, err := alice.ComposeAndPersist(ComposeParams{
		Action: "blocked_by_must_resolve", Origin: ldrcore.OriginActor, OpType: "call_open",
		ActorID:   "alice",
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: "call-002"}, {Key: "to", Value: "bob"}},
		Plaintext: []byte("blocked"),
	}); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("expected ErrMustResolve after restart with unsettled outbox, got %v", err)
	}
	sAlice, err = alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer sAlice.Close()
	if err := alice.ResolveAll(ctx, sAlice, ldrcrypto.CredentialPrincipal(aliceKeys.CredID)); err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	// Now send the EXACT persisted bytes from before the crash!
	openRep, err := alice.Send(ctx, sAlice, openOpID)
	if err != nil || openRep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send persisted call_open after restart failed: %+v, err=%v", openRep, err)
	}
	callOpenSeq := openRep.Outcome.Seq

	// 4. Bob syncs, decrypts epoch-1 turn, materializes projection, checks VerifiedRead
	//    and taint rebuild, and verifies local delivery scan cursor + no resource dirs!
	if _, err := bob.Sync(ctx, sBob); err != nil {
		t.Fatal(err)
	}
	gotPT, rState, err := bob.ReadPayload(ctx, sBob, callOpenSeq)
	if err != nil || rState != ldrcore.ReadOK || !bytes.Equal(gotPT, turn1Plain) {
		t.Fatalf("bob ReadPayload: state=%s pt=%q err=%v", rState, gotPT, err)
	}
	if err := bob.Project(ctx, sBob); err != nil {
		t.Fatalf("bob Project: %v", err)
	}
	if err := bob.CheckHostLocalResourcesUntouched(); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.VerifiedRead(ctx, sBob, "calls/call-001/turn-1"); err != nil {
		t.Fatalf("VerifiedRead valid file: %v", err)
	}
	// Tamper with projected file on disk -> VerifiedRead MUST return ErrTainted!
	tamperPath := filepath.Join(bob.ProjectionDir(), "calls", "call-001", "turn-1")
	if err := os.WriteFile(tamperPath, []byte("forged local edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.VerifiedRead(ctx, sBob, "calls/call-001/turn-1"); !errors.Is(err, ErrTainted) {
		t.Fatalf("expected ErrTainted on local edit, got %v", err)
	}
	if err := bob.Rebuild(ctx, sBob); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if bob.Rebuilds() != 1 {
		t.Fatalf("expected Rebuilds()==1, got %d", bob.Rebuilds())
	}
	if _, err := bob.VerifiedRead(ctx, sBob, "calls/call-001/turn-1"); err != nil {
		t.Fatalf("VerifiedRead after Rebuild failed: %v", err)
	}

	// Local delivery scan cursor: Bob has 1 deliverable notice for call-001.
	if added, err := bob.ScanDelivery(); err != nil || added != 1 {
		t.Fatalf("ScanDelivery: added=%d err=%v", added, err)
	}
	if notices := bob.DeliverableNotices(); len(notices) != 1 || notices[0].Actor != "bob" {
		t.Fatalf("expected 1 deliverable notice for bob, got %+v", notices)
	}

	// 5. FUTURE-ONLY MEMBER CHARLIE (O3a + O25): joins AFTER epoch 1, receives epoch 2,
	//    cannot read epoch-1 turn (ReadNoKey), CAN read epoch-2 turn (ReadOK)!
	_, _ = admin.Sync(ctx, sOp)
	charlieKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	charlieGrant := ldrcrypto.JoinGrant{NamespaceID: "ns-charlie", ActorLimit: 2, Reader: true}
	charlieReqID, charlieReqDig := enrollMember("charlie", charlieKeys, charlieGrant, 0x04)

	// Operator moves actor "bob" to Charlie (binding_gen 1 -> 2) to test C2 notice withholding!
	mvOp, err := admin.ComposeAndPersist(ComposeParams{
		Action: "move_bob", Origin: ldrcore.OriginOperator, OpType: "actor_move",
		Expect: ldrcrypto.ExpectMap{"binding_gen": 1},
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "bob"}, {Key: "to_cred", Value: charlieKeys.CredID[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sOp, mvOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("actor_move failed: %+v, err=%v", rep, err)
	}
	_, _ = admin.Sync(ctx, sOp)

	// Activate epoch 2 (includes Charlie).
	act2Op, _, err := admin.ComposeEpochActivate("activate_epoch_2")
	if err != nil {
		t.Fatalf("ComposeEpochActivate(2): %v", err)
	}
	if rep, err := admin.Send(ctx, sOp, act2Op); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("Send(epoch_activate 2): %+v, err=%v", rep, err)
	}
	_, _ = admin.Sync(ctx, sOp)

	// Bob syncs the actor_move: his unacknowledged notice for binding_gen 1 MUST now be withheld (C2)!
	if _, err := bob.Sync(ctx, sBob); err != nil {
		t.Fatal(err)
	}
	if notices := bob.DeliverableNotices(); len(notices) != 0 {
		t.Fatalf("C2 violation: moved actor notice still deliverable: %+v", notices)
	}

	// Charlie runs O25 full-replay onboarding from genesis!
	charlieDir := t.TempDir()
	charlie, err := InitClientDir(InitDirOptions{
		Dir: charlieDir, SignedDescriptor: env.rawDesc, CredKeys: charlieKeys,
		ExpectedGrant: &charlieGrant, ExpectedJoinReq: charlieReqID, ExpectedJoinReqDigest: &charlieReqDig, Activated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer charlie.Close()
	sCharlie, err := charlie.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatalf("Dial(charlie): %v", err)
	}
	defer sCharlie.Close()
	if err := charlie.VerifyEnrollmentAndActivate(ctx, sCharlie); err != nil {
		t.Fatalf("VerifyEnrollmentAndActivate(charlie): %v", err)
	}
	if charlie.HasEpochKey(1) || !charlie.HasEpochKey(2) {
		t.Fatalf("future-only violation: charlie has epoch1=%v epoch2=%v", charlie.HasEpochKey(1), charlie.HasEpochKey(2))
	}
	// Charlie sees ReadNoKey on epoch-1 turn (control verified, payload uninspected).
	if _, rs, err := charlie.ReadPayload(ctx, sCharlie, callOpenSeq); err != nil || rs != ldrcore.ReadNoKey {
		t.Fatalf("expected ReadNoKey for charlie on epoch-1 turn, got (%s, %v)", rs, err)
	}
	// Charlie (now holding moved actor "bob" at binding_gen=2!) sends turn 2 under epoch 2!
	turn2Plain := []byte(`{"body":"Hello from epoch 2!"}`)
	turn2Op, err := charlie.ComposeAndPersist(ComposeParams{
		Action: "reply_turn_2", Origin: ldrcore.OriginActor, OpType: "call_turn",
		ActorID:   "bob",
		Expect:    ldrcrypto.ExpectMap{"turn_count": 1},
		Fields:    ldrcrypto.Map{{Key: "barge", Value: false}, {Key: "call_id", Value: "call-001"}},
		Plaintext: turn2Plain,
	})
	if err != nil {
		t.Fatalf("charlie Compose(call_turn): %v", err)
	}
	t2Rep, err := charlie.Send(ctx, sCharlie, turn2Op)
	if err != nil || t2Rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("charlie Send(call_turn): %+v, err=%v", t2Rep, err)
	}
	if _, err := alice.Sync(ctx, sAlice); err != nil {
		t.Fatal(err)
	}
	gotT2, rs2, err := alice.ReadPayload(ctx, sAlice, t2Rep.Outcome.Seq)
	if err != nil || rs2 != ldrcore.ReadOK || !bytes.Equal(gotT2, turn2Plain) {
		t.Fatalf("alice failed to read charlie's epoch-2 turn: state=%s pt=%q err=%v", rs2, gotT2, err)
	}

	// 6. RULE 8 PERSISTENT KEY STOP ACROSS RESTART:
	//    Operator revokes Alice; Alice learns via Sync (or Auth) -> stopped permanently!
	_, _ = admin.Sync(ctx, sOp)
	revAliceOp, err := admin.ComposeAndPersist(ComposeParams{
		Action: "revoke_alice", Origin: ldrcore.OriginOperator, OpType: "credential_revoke",
		Fields: ldrcrypto.Map{{Key: "cred_id", Value: aliceKeys.CredID[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sOp, revAliceOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("revoke alice: %+v, err=%v", rep, err)
	}
	// Alice tries to open a new session -> relay replies revoked -> Rule 8 records KeyStop durably!
	if _, err := alice.Dial(ctx, ldrcrypto.PrincipalCredential); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked for revoked alice Dial, got %v", err)
	}
	// Close and reopen Alice: stop MUST persist across restart!
	sAlice.Close()
	_ = alice.Close()
	alice2, err := OpenClient(aliceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer alice2.Close()
	if len(alice2.Stops()) != 1 {
		t.Fatalf("expected 1 persisted KeyStop after restart, got %+v", alice2.Stops())
	}
	if _, err := alice2.Dial(ctx, ldrcrypto.PrincipalCredential); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected persisted ErrKeyRevoked after restart, got %v", err)
	}
}
