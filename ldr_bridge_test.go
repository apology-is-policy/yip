package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

func TestLDRBridgeTwoWorkstationsMCPHooksLiveDeliveryAndHostLocalResources(t *testing.T) {
	// Save and restore package globals mutated by line-switching helpers.
	origActiveLine := activeLine
	origYipHome := os.Getenv("YIP_HOME")
	origYipRoot := os.Getenv("YIP_ROOT")
	origYipLDR := os.Getenv("YIP_LDR_DIR")
	t.Cleanup(func() {
		activeLine = origActiveLine
		_ = os.Setenv("YIP_HOME", origYipHome)
		_ = os.Setenv("YIP_ROOT", origYipRoot)
		_ = os.Setenv("YIP_LDR_DIR", origYipLDR)
	})
	_ = os.Unsetenv("YIP_ROOT")
	_ = os.Unsetenv("YIP_LDR_DIR")

	// 1. Start a live TLS 1.3 LDR relay.
	relayDir := t.TempDir()
	certP := filepath.Join(relayDir, "tls", "server.crt")
	keyP := filepath.Join(relayDir, "tls", "server.key")
	pin, err := ldrrelay.InitSelfSignedCert(certP, keyP, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
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
	st, err := ldrstore.OpenFileStore(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), ldrrelay.RealClockSource())
	if err != nil {
		t.Fatal(err)
	}
	rs := ldrrelay.NewRelayServer(eng)
	hs := &http.Server{Handler: rs}
	go func() { _ = hs.Serve(tlsLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		_ = eng.Shutdown()
	})

	// 2. Provision line and bootstrap admin + Alice workstation + Bob workstation.
	ctx := context.Background()
	r1, _ := ldrclient.GenerateSigningKey(ldrcrypto.AlgEd25519)
	r2, _ := ldrclient.GenerateSigningKey(ldrcrypto.AlgECDSAP256)
	opKey, _ := ldrclient.GenerateSigningKey(ldrcrypto.AlgEd25519)
	opCredKeys, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	lineID := bytes.Repeat([]byte{0x77}, 16)
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
	signedDesc, err := ldrcrypto.SignCreationDescriptor(r1.Signer, desc)
	if err != nil {
		t.Fatal(err)
	}
	rawDesc, err := signedDesc.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := eng.Provision(rawDesc)
	if err != nil {
		t.Fatal(err)
	}

	adminDir := filepath.Join(t.TempDir(), "admin")
	admin, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: adminDir, SignedDescriptor: rawDesc, CredKeys: opCredKeys, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin.AttachRootKey(r1)
	admin.AttachOperatorKey(opKey)

	sRoot, err := admin.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatal(err)
	}
	rk0, _ := desc.RootKeys[0].ToCBOR()
	rk1, _ := desc.RootKeys[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	initOp, err := admin.ComposeAndPersist(ldrclient.ComposeParams{
		Action: "line_init", Origin: ldrcore.OriginRoot, OpType: "line_init",
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: prov.DescriptorDigest[:]},
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
	opPubC, _ := opKey.Signer.PublicKey().ToCBOR()
	authOp, err := admin.ComposeAndPersist(ldrclient.ComposeParams{
		Action: "auth_op", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubC}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sRoot, authOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("auth_op: %+v %v", rep, err)
	}
	if _, err := admin.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}
	sRoot.Close()

	sOp, err := admin.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(ns string, ck *ldrclient.CredentialKeyBundle, limit uint64, seed byte) (ldrcrypto.JoinGrant, []byte, [32]byte) {
		grant := ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: limit, Reader: true}
		req, err := ldrcrypto.SignJoinRequest(ck.Signing.Signer, ldrcrypto.JoinRequest{
			RequestID: bytes.Repeat([]byte{seed}, 16), LineID: lineID, Generation: 1,
			DescriptorDigest: prov.DescriptorDigest, EncryptionKey: ck.Encryption.PublicKey(), Grant: grant,
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
		skC, _ := req.SigningKey.ToCBOR()
		ekC, _ := req.EncryptionKey.ToCBOR()
		enrOp, err := admin.ComposeAndPersist(ldrclient.ComposeParams{
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

	enroll("ns-op", opCredKeys, 0, 0x50)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := enroll("ns-alice", aliceCK, 4, 0x51)
	bg, brid, brdig := enroll("ns-bob", bobCK, 4, 0x52)

	epOp, _, err := admin.ComposeEpochActivate("ep-1")
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sOp, epOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("epoch activate: %+v %v", rep, err)
	}
	if _, err := admin.Sync(ctx, sOp); err != nil {
		t.Fatal(err)
	}

	// Activate Alice and Bob client dirs and declare actors ("alice-gemini", "bob-codex").
	aliceClientDir := filepath.Join(t.TempDir(), "alice-ldr")
	bobClientDir := filepath.Join(t.TempDir(), "bob-ldr")
	setupWorkstation := func(dir string, ck *ldrclient.CredentialKeyBundle, g ldrcrypto.JoinGrant, rid []byte, rdig [32]byte, actorID string) {
		cl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
			Dir: dir, SignedDescriptor: rawDesc, CredKeys: ck,
			ExpectedGrant: &g, ExpectedJoinReq: rid, ExpectedJoinReqDigest: &rdig,
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
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); err != nil {
			t.Fatalf("activate %s: %v", actorID, err)
		}
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			t.Fatal(err)
		}
		if _, err := cl.SubmitActorDeclare(ctx, sess, actorID, ""); err != nil {
			t.Fatalf("declare %s: %v", actorID, err)
		}
	}
	setupWorkstation(aliceClientDir, aliceCK, ag, arid, ardig, "alice-gemini")
	setupWorkstation(bobClientDir, bobCK, bg, brid, brdig, "bob-codex")

	// 3. Create two completely separate workstation YIP_HOME directories & attach LDR lines!
	aliceHome := filepath.Join(t.TempDir(), "alice-yip-home")
	bobHome := filepath.Join(t.TempDir(), "bob-yip-home")

	useAlice := func() {
		_ = os.Setenv("YIP_HOME", aliceHome)
		activeLine = "work-alice"
	}
	useBob := func() {
		_ = os.Setenv("YIP_HOME", bobHome)
		activeLine = "work-bob"
	}

	useAlice()
	if _, err := AttachLDRLine(aliceClientDir, "gemini", "alice-gemini"); err != nil {
		t.Fatalf("AttachLDRLine(alice): %v", err)
	}
	// Configure host-local resource "gpu" ONLY on Alice's workstation.
	if err := os.WriteFile(resourceConfigPath(), []byte(`{"version":1,"resources":[{"name":"gpu","description":"local GPU","machine":"alice-host"}]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	useBob()
	if _, err := AttachLDRLine(bobClientDir, "codex", "bob-codex"); err != nil {
		t.Fatalf("AttachLDRLine(bob): %v", err)
	}
	// Register a live delivery endpoint for Bob (Codex runtime) to test live wakeup over LDR!
	bobThread := "11111111-2222-3333-4444-555555555555"
	if err := RegisterEndpoint("codex", bobThread, false); err != nil {
		t.Fatalf("RegisterEndpoint(bob): %v", err)
	}

	// 4. Alice uses standard Yip MCP tools: busy, roadmap_post, roadmap_at, host-local hold, and call!
	useAlice()
	aliceSrv := &server{me: "gemini"}
	if out, err := aliceSrv.call("busy", map[string]any{"text": "building phase D"}); err != nil || !strings.Contains(out, "building phase D") {
		t.Fatalf("alice busy: out=%q err=%v", out, err)
	}
	if out, err := aliceSrv.call("roadmap_post", map[string]any{
		"arc": "LDR Rollout",
		"stations": []any{
			map[string]any{"id": "s1", "name": "Build"},
			map[string]any{"id": "s2", "name": "Verify"},
		},
		"active": "s1",
		"note":   "compiling",
	}); err != nil || !strings.Contains(out, "LDR Rollout") {
		t.Fatalf("alice roadmap_post: out=%q err=%v", out, err)
	}
	if out, err := aliceSrv.call("hold", map[string]any{"resource": "gpu", "reason": "local test run"}); err != nil || !strings.Contains(out, "HELD") {
		t.Fatalf("alice local hold(gpu): out=%q err=%v", out, err)
	}
	if out, err := aliceSrv.call("call", map[string]any{
		"peer":    "bob-codex",
		"subject": "Cross-machine test",
		"body":    "Hello from Alice workstation over TLS 1.3!",
	}); err != nil || !strings.Contains(out, "0001-cross-machine-test") {
		t.Fatalf("alice call: out=%q err=%v", out, err)
	}

	// Operator also sends an encrypted briefing broadcast to default audience.
	if err := admin.PrepareForMutation(ctx, sOp, ldrcrypto.PrincipalOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SubmitBroadcastCreate(ctx, sOp, "bc-100", "briefing", "operator", "Sync up before release", nil, true); err != nil {
		t.Fatalf("SubmitBroadcastCreate: %v", err)
	}
	sOp.Close()
	_ = admin.Close()

	// 5. Bob's workstation receives live LDR delivery wakeups, Stop-hook floor block, presence, roadmaps, call & broadcast!
	useBob()
	var delivered []string
	nSent, err := Dispatch("codex", func(_ context.Context, thread, text string) error {
		if thread != bobThread {
			t.Errorf("wrong thread %q", thread)
		}
		delivered = append(delivered, text)
		return nil
	})
	if err != nil || nSent == 0 || len(delivered) == 0 {
		t.Fatalf("expected live LDR delivery dispatch to Bob, nSent=%d delivered=%v err=%v", nSent, delivered, err)
	}
	if !strings.Contains(delivered[0], "LDR ") {
		t.Fatalf("expected LDR notice text in delivery batch, got %q", delivered[0])
	}
	// Ack the delivered notices via standard delivery_ack MCP tool and confirm LDR client acks them too!
	ep, err := readEndpoint("codex")
	if err != nil {
		t.Fatal(err)
	}
	bobSrv := &server{me: "codex"}
	for _, ev := range ep.Events {
		if _, err := bobSrv.call("delivery_ack", map[string]any{"id": ev.ID}); err != nil {
			t.Fatalf("delivery_ack(%s): %v", ev.ID, err)
		}
	}
	bobCL, err := ldrclient.OpenClientWait(ctx, bobClientDir)
	if err != nil {
		t.Fatal(err)
	}
	if rem := bobCL.DeliverableNotices(); len(rem) != 0 {
		bobCL.Close()
		t.Fatalf("expected 0 unacked LDR notices after delivery_ack, got %+v", rem)
	}
	_ = bobCL.Close()

	// Bob's Stop hook MUST block while Bob holds the floor on Alice's LDR call!
	stopRes := hookStop("codex")
	stopMap, _ := stopRes.(map[string]any)
	if stopMap == nil || stopMap["decision"] != "block" {
		t.Fatalf("expected Stop hook to block Bob while floor is Bob's, got %#v", stopRes)
	}
	// Loop guard: immediate second Stop hook with unchanged turn must NOT block again.
	if second := hookStop("codex"); second != nil {
		t.Fatalf("expected Stop hook loop guard to avoid double block, got %#v", second)
	}

	// Bob inspects presence, roadmaps, ring, reads Alice's encrypted call, replies, attaches file, opens dispute!
	if pres, err := bobSrv.call("presence", nil); err != nil || !strings.Contains(pres, "alice-gemini") || !strings.Contains(pres, "building phase D") {
		t.Fatalf("bob presence missing Alice encrypted busy: %q err=%v", pres, err)
	}
	if rms, err := bobSrv.call("roadmaps", nil); err != nil || !strings.Contains(rms, "LDR Rollout") {
		t.Fatalf("bob roadmaps missing Alice encrypted arc: %q err=%v", rms, err)
	}
	if ring, err := bobSrv.call("ring", nil); err != nil || !strings.Contains(ring, "0001-cross-machine-test") || !strings.Contains(ring, "the floor is YOURS") {
		t.Fatalf("bob ring: %q err=%v", ring, err)
	}
	if tr, err := bobSrv.call("read", map[string]any{"call": "0001-cross-machine-test"}); err != nil || !strings.Contains(tr, "Hello from Alice workstation over TLS 1.3!") {
		t.Fatalf("bob read: %q err=%v", tr, err)
	}
	if sayOut, err := bobSrv.call("say", map[string]any{"call": "0001-cross-machine-test", "body": "Loud and clear from Bob!"}); err != nil || !strings.Contains(sayOut, "turn 2 sent") {
		t.Fatalf("bob say: %q err=%v", sayOut, err)
	}
	attFile := filepath.Join(t.TempDir(), "notes.txt")
	_ = os.WriteFile(attFile, []byte("verified attachment bytes"), 0o600)
	if attOut, err := bobSrv.call("attach", map[string]any{"call": "0001-cross-machine-test", "path": attFile}); err != nil || !strings.Contains(attOut, "notes.txt") {
		t.Fatalf("bob attach: %q err=%v", attOut, err)
	}
	if bcs, err := bobSrv.call("broadcasts", nil); err != nil || !strings.Contains(bcs, "bc-100") {
		t.Fatalf("bob broadcasts: %q err=%v", bcs, err)
	}
	if bcDetail, err := bobSrv.call("broadcast_read", map[string]any{"id": "bc-100"}); err != nil || !strings.Contains(bcDetail, "Sync up before release") {
		t.Fatalf("bob broadcast_read: %q err=%v", bcDetail, err)
	}
	if _, err := bobSrv.call("broadcast_reply", map[string]any{"id": "bc-100", "body": "Ready!"}); err != nil {
		t.Fatalf("bob broadcast_reply: %v", err)
	}

	// Host-local resource isolation: Bob must NOT see Alice's local "gpu" resource!
	bobRes, err := bobSrv.call("resources", nil)
	if err != nil {
		t.Fatalf("bob resources: %v", err)
	}
	if strings.Contains(bobRes, "gpu") {
		t.Fatalf("host-local resource leaked across workstations: %q", bobRes)
	}

	// 6. Bilateral bye closes call cleanly across workstations.
	if _, err := bobSrv.call("bye", map[string]any{"call": "0001-cross-machine-test"}); err != nil {
		t.Fatalf("bob bye: %v", err)
	}
	useAlice()
	if tr, err := aliceSrv.call("read", map[string]any{"call": "0001-cross-machine-test"}); err != nil ||
		!strings.Contains(tr, "Loud and clear from Bob!") || !strings.Contains(tr, "notes.txt") {
		t.Fatalf("alice read Bob reply+attachment: %q err=%v", tr, err)
	}
	if byeOut, err := aliceSrv.call("bye", map[string]any{"call": "0001-cross-machine-test"}); err != nil || !strings.Contains(byeOut, "closed") {
		t.Fatalf("alice bye: %q err=%v", byeOut, err)
	}
	if ringAfter, err := aliceSrv.call("ring", nil); err != nil || ringAfter != "nothing ringing." {
		t.Fatalf("expected nothing ringing after close, got %q err=%v", ringAfter, err)
	}

	// Verify detach works cleanly and removes ldr.json without touching aliceClientDir.
	var detachBuf bytes.Buffer
	if err := LDRCLI([]string{"detach"}, &detachBuf); err != nil {
		t.Fatalf("LDRCLI detach: %v", err)
	}
	var detachResp map[string]any
	if err := json.Unmarshal(detachBuf.Bytes(), &detachResp); err != nil || detachResp["detached"] != true {
		t.Fatalf("unexpected detach output: %s", detachBuf.String())
	}
	if _, ok, err := loadLDRAttachment(); err != nil || ok {
		t.Fatalf("expected loadLDRAttachment=(false, nil) after detach, got ok=%v err=%v", ok, err)
	}
}

type ldrBridgeFixture struct {
	relayDir string
	rawDesc  []byte
	lineID   []byte
	provDig  [32]byte
	opKey    *ldrclient.SigningKeyMaterial
	admin    *ldrclient.Client
	sOp      *ldrrelay.SessionClient
}

func newLDRBridgeFixture(t *testing.T) *ldrBridgeFixture {
	t.Helper()
	origActiveLine := activeLine
	origYipHome := os.Getenv("YIP_HOME")
	origYipRoot := os.Getenv("YIP_ROOT")
	origYipLDR := os.Getenv("YIP_LDR_DIR")
	t.Cleanup(func() {
		activeLine = origActiveLine
		_ = os.Setenv("YIP_HOME", origYipHome)
		_ = os.Setenv("YIP_ROOT", origYipRoot)
		_ = os.Setenv("YIP_LDR_DIR", origYipLDR)
	})
	_ = os.Unsetenv("YIP_ROOT")
	_ = os.Unsetenv("YIP_LDR_DIR")

	relayDir := t.TempDir()
	certP := filepath.Join(relayDir, "tls", "server.crt")
	keyP := filepath.Join(relayDir, "tls", "server.key")
	pin, err := ldrrelay.InitSelfSignedCert(certP, keyP, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
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
	st, err := ldrstore.OpenFileStore(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), ldrrelay.RealClockSource())
	if err != nil {
		t.Fatal(err)
	}
	rs := ldrrelay.NewRelayServer(eng)
	hs := &http.Server{Handler: rs}
	go func() { _ = hs.Serve(tlsLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		_ = eng.Shutdown()
	})

	ctx := context.Background()
	r1, _ := ldrclient.GenerateSigningKey(ldrcrypto.AlgEd25519)
	r2, _ := ldrclient.GenerateSigningKey(ldrcrypto.AlgECDSAP256)
	opKey, _ := ldrclient.GenerateSigningKey(ldrcrypto.AlgEd25519)
	opCredKeys, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	lineID := make([]byte, 16)
	if _, err := rand.Read(lineID); err != nil {
		t.Fatal(err)
	}
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
	signedDesc, err := ldrcrypto.SignCreationDescriptor(r1.Signer, desc)
	if err != nil {
		t.Fatal(err)
	}
	rawDesc, err := signedDesc.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := eng.Provision(rawDesc)
	if err != nil {
		t.Fatal(err)
	}

	adminDir := filepath.Join(t.TempDir(), "admin")
	admin, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: adminDir, SignedDescriptor: rawDesc, CredKeys: opCredKeys, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin.AttachRootKey(r1)
	admin.AttachOperatorKey(opKey)

	sRoot, err := admin.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatal(err)
	}
	rk0, _ := desc.RootKeys[0].ToCBOR()
	rk1, _ := desc.RootKeys[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	initOp, err := admin.ComposeAndPersist(ldrclient.ComposeParams{
		Action: "line_init", Origin: ldrcore.OriginRoot, OpType: "line_init",
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: prov.DescriptorDigest[:]},
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
	opPubC, _ := opKey.Signer.PublicKey().ToCBOR()
	authOp, err := admin.ComposeAndPersist(ldrclient.ComposeParams{
		Action: "auth_op", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubC}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := admin.Send(ctx, sRoot, authOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("auth_op: %+v %v", rep, err)
	}
	if _, err := admin.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}
	sRoot.Close()

	sOp, err := admin.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sOp.Close()
		_ = admin.Close()
	})
	fx := &ldrBridgeFixture{
		relayDir: relayDir,
		rawDesc:  rawDesc,
		lineID:   lineID,
		provDig:  prov.DescriptorDigest,
		opKey:    opKey,
		admin:    admin,
		sOp:      sOp,
	}
	fx.enroll(t, "ns-op", opCredKeys, 0, 0x60)
	return fx
}

func (fx *ldrBridgeFixture) enroll(t *testing.T, ns string, ck *ldrclient.CredentialKeyBundle, limit uint64, seed byte) (ldrcrypto.JoinGrant, []byte, [32]byte) {
	t.Helper()
	ctx := context.Background()
	grant := ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: limit, Reader: true}
	req, err := ldrcrypto.SignJoinRequest(ck.Signing.Signer, ldrcrypto.JoinRequest{
		RequestID: bytes.Repeat([]byte{seed}, 16), LineID: fx.lineID, Generation: 1,
		DescriptorDigest: fx.provDig, EncryptionKey: ck.Encryption.PublicKey(), Grant: grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, sec, err := ldrcrypto.CreateJoinChallenge(fx.opKey.Signer.PublicKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := ldrcrypto.RespondJoinChallenge(ck.Signing.Signer, ck.Encryption, fx.opKey.Signer.PublicKey(), req, ch)
	if err != nil {
		t.Fatal(err)
	}
	if err := ldrcrypto.VerifyJoinProof(fx.opKey.Signer.PublicKey(), req, ch, sec, pr); err != nil {
		t.Fatal(err)
	}
	reqDig, err := ldrcrypto.VerifyJoinRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	skC, _ := req.SigningKey.ToCBOR()
	ekC, _ := req.EncryptionKey.ToCBOR()
	enrOp, err := fx.admin.ComposeAndPersist(ldrclient.ComposeParams{
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
	if rep, err := fx.admin.Send(ctx, fx.sOp, enrOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("enroll %s: %+v %v", ns, rep, err)
	}
	if _, err := fx.admin.Sync(ctx, fx.sOp); err != nil {
		t.Fatal(err)
	}
	return grant, req.RequestID, reqDig
}

func (fx *ldrBridgeFixture) activateEpoch(t *testing.T, action string) {
	t.Helper()
	ctx := context.Background()
	epOp, _, err := fx.admin.ComposeEpochActivate(action)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := fx.admin.Send(ctx, fx.sOp, epOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("epoch activate: %+v %v", rep, err)
	}
	if _, err := fx.admin.Sync(ctx, fx.sOp); err != nil {
		t.Fatal(err)
	}
}

func (fx *ldrBridgeFixture) setupWorkstation(t *testing.T, dir string, ck *ldrclient.CredentialKeyBundle, g ldrcrypto.JoinGrant, rid []byte, rdig [32]byte, actors ...string) {
	t.Helper()
	ctx := context.Background()
	cl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: dir, SignedDescriptor: fx.rawDesc, CredKeys: ck,
		ExpectedGrant: &g, ExpectedJoinReq: rid, ExpectedJoinReqDigest: &rdig,
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
	if err := cl.VerifyEnrollmentAndActivate(ctx, sess); err != nil {
		t.Fatalf("activate %v: %v", actors, err)
	}
	for _, actorID := range actors {
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			t.Fatal(err)
		}
		if _, err := cl.SubmitActorDeclare(ctx, sess, actorID, ""); err != nil {
			t.Fatalf("declare %s: %v", actorID, err)
		}
	}
}

func TestLDRBridgeAckDeliveryPersistsLDRFirstAndConvergesOnRetry(t *testing.T) {
	fx := newLDRBridgeFixture(t)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := fx.enroll(t, "ns-alice", aliceCK, 4, 0x61)
	bg, brid, brdig := fx.enroll(t, "ns-bob", bobCK, 4, 0x62)
	fx.activateEpoch(t, "ep-ack-1")

	aliceClientDir := filepath.Join(t.TempDir(), "alice-ldr")
	bobClientDir := filepath.Join(t.TempDir(), "bob-ldr")
	fx.setupWorkstation(t, aliceClientDir, aliceCK, ag, arid, ardig, "alice-gemini")
	fx.setupWorkstation(t, bobClientDir, bobCK, bg, brid, brdig, "bob-codex")

	aliceHome := filepath.Join(t.TempDir(), "alice-home")
	bobHome := filepath.Join(t.TempDir(), "bob-home")
	useAlice := func() { _ = os.Setenv("YIP_HOME", aliceHome); activeLine = "ack-alice" }
	useBob := func() { _ = os.Setenv("YIP_HOME", bobHome); activeLine = "ack-bob" }

	useAlice()
	if _, err := AttachLDRLine(aliceClientDir, "gemini", "alice-gemini"); err != nil {
		t.Fatal(err)
	}
	useBob()
	if _, err := AttachLDRLine(bobClientDir, "codex", "bob-codex"); err != nil {
		t.Fatal(err)
	}
	if err := RegisterEndpoint("codex", "11111111-2222-3333-4444-555555555555", false); err != nil {
		t.Fatal(err)
	}

	origTimeout := ldrAckTimeout
	ldrAckTimeout = 120 * time.Millisecond
	t.Cleanup(func() { ldrAckTimeout = origTimeout })

	dispatchOne := func(subject string) Delivery {
		t.Helper()
		useAlice()
		if _, err := (&server{me: "gemini"}).call("call", map[string]any{
			"peer": "bob-codex", "subject": subject, "body": "ping " + subject,
		}); err != nil {
			t.Fatalf("alice call %s: %v", subject, err)
		}
		useBob()
		n, err := Dispatch("codex", func(context.Context, string, string) error { return nil })
		if err != nil || n == 0 {
			t.Fatalf("dispatch %s: n=%d err=%v", subject, n, err)
		}
		ep, err := readEndpoint("codex")
		if err != nil {
			t.Fatal(err)
		}
		for i := len(ep.Events) - 1; i >= 0; i-- {
			if strings.HasPrefix(ep.Events[i].Source, "ldr:") && ep.Events[i].Status != "read" {
				return ep.Events[i]
			}
		}
		t.Fatalf("no unread ldr delivery event found after %s", subject)
		return Delivery{}
	}

	findEvent := func(id string) Delivery {
		t.Helper()
		ep, err := readEndpoint("codex")
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range ep.Events {
			if ev.ID == id {
				return ev
			}
		}
		t.Fatalf("event %s missing", id)
		return Delivery{}
	}

	// 1. Holding bobClientDir lock must fail AckDelivery AND keep endpoint event unread + LDR notice un-acked.
	ev1 := dispatchOne("lock-contention")
	held, err := ldrclient.OpenClient(bobClientDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := AckDelivery("codex", ev1.ID); err == nil {
		_ = held.Close()
		t.Fatal("expected AckDelivery to fail while LDR client directory is locked")
	}
	if got := findEvent(ev1.ID); got.Status == "read" {
		_ = held.Close()
		t.Fatalf("endpoint event marked read despite LDR ack failure: %+v", got)
	}
	if rem := held.DeliverableNotices(); len(rem) == 0 {
		_ = held.Close()
		t.Fatal("expected LDR notice to remain un-acked after failed AckDelivery")
	}
	_ = held.Close()

	// 2. Retrying AckDelivery after the lock releases converges BOTH stores cleanly.
	if err := AckDelivery("codex", ev1.ID); err != nil {
		t.Fatalf("retry AckDelivery after lock release: %v", err)
	}
	if got := findEvent(ev1.ID); got.Status != "read" {
		t.Fatalf("expected endpoint event read after retry, got %+v", got)
	}
	cl, err := ldrclient.OpenClient(bobClientDir)
	if err != nil {
		t.Fatal(err)
	}
	if rem := cl.DeliverableNotices(); len(rem) != 0 {
		_ = cl.Close()
		t.Fatalf("expected 0 un-acked LDR notices after retry, got %+v", rem)
	}
	_ = cl.Close()

	// 3. Partial-crash convergence: LDR notice already acked while endpoint.json still shows "accepted".
	ev2 := dispatchOne("partial-crash")
	_, _, ev2NoticeID, qualified := parseLDRDeliverySource(ev2.Source)
	if !qualified {
		t.Fatalf("expected line-qualified LDR delivery source, got %q", ev2.Source)
	}
	cl, err = ldrclient.OpenClient(bobClientDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.AckNotice(ev2NoticeID); err != nil {
		_ = cl.Close()
		t.Fatalf("pre-ack LDR notice: %v", err)
	}
	_ = cl.Close()
	if got := findEvent(ev2.ID); got.Status == "read" {
		t.Fatalf("expected endpoint event still unread before retry, got %+v", got)
	}
	if err := AckDelivery("codex", ev2.ID); err != nil {
		t.Fatalf("converging retry AckDelivery failed: %v", err)
	}
	if got := findEvent(ev2.ID); got.Status != "read" {
		t.Fatalf("expected endpoint event read after converging retry, got %+v", got)
	}

	// 4. Malformed ldr.json must fail AckDelivery for ldr: sources without marking endpoint read.
	ev3 := dispatchOne("broken-config")
	if err := os.WriteFile(ldrAttachmentPath(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AckDelivery("codex", ev3.ID); err == nil {
		t.Fatal("expected AckDelivery to fail when ldr.json is malformed")
	}
	if got := findEvent(ev3.ID); got.Status == "read" {
		t.Fatalf("endpoint event marked read despite malformed ldr.json: %+v", got)
	}
}

func TestLDRBridgeSharedDirectoryWaitAllowsCoresidentReply(t *testing.T) {
	fx := newLDRBridgeFixture(t)
	sharedCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	g, rid, rdig := fx.enroll(t, "ns-shared", sharedCK, 4, 0x63)
	fx.activateEpoch(t, "ep-shared-1")

	sharedClientDir := filepath.Join(t.TempDir(), "shared-ldr")
	fx.setupWorkstation(t, sharedClientDir, sharedCK, g, rid, rdig, "shared-a", "shared-b")

	sharedHome := filepath.Join(t.TempDir(), "shared-home")
	_ = os.Setenv("YIP_HOME", sharedHome)
	activeLine = "shared-line"
	if _, err := AttachLDRLine(sharedClientDir, "a", "shared-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := AttachLDRLine(sharedClientDir, "b", "shared-b"); err != nil {
		t.Fatal(err)
	}

	srvA := &server{me: "a"}
	srvB := &server{me: "b"}
	openOut, err := srvA.call("call", map[string]any{
		"peer":    "b",
		"subject": "Shared dir wait test",
		"body":    "ping from co-resident a",
	})
	if err != nil || !strings.Contains(openOut, "0001-shared-dir-wait-test") {
		t.Fatalf("a call: out=%q err=%v", openOut, err)
	}
	const callID = "0001-shared-dir-wait-test"

	type waitRes struct {
		out string
		err error
	}
	waitCh := make(chan waitRes, 1)
	go func() {
		out, werr := srvA.call("wait", map[string]any{"call": callID, "timeout_s": 10})
		waitCh <- waitRes{out: out, err: werr}
	}()

	// Give agent "a"'s wait goroutine time to complete its initial poll and enter sleep.
	time.Sleep(150 * time.Millisecond)

	// Co-resident peer "b" sharing sharedClientDir must be able to inspect ring, run Stop hook, and reply!
	ringOut, err := srvB.call("ring", nil)
	if err != nil || !strings.Contains(ringOut, callID) {
		t.Fatalf("co-resident b ring during a's wait: out=%q err=%v", ringOut, err)
	}
	stopRes := hookStop("b")
	stopMap, _ := stopRes.(map[string]any)
	if stopMap == nil || stopMap["decision"] != "block" {
		t.Fatalf("co-resident b Stop hook during a's wait: got %#v", stopRes)
	}
	sayOut, err := srvB.call("say", map[string]any{
		"call": callID,
		"body": "pong from co-resident b",
	})
	if err != nil || !strings.Contains(sayOut, "turn 2 sent") {
		t.Fatalf("co-resident b say during a's wait: out=%q err=%v", sayOut, err)
	}

	select {
	case res := <-waitCh:
		if res.err != nil {
			t.Fatalf("a wait returned error: %v", res.err)
		}
		if !strings.Contains(res.out, "shared-b replied") || !strings.Contains(res.out, "turn 2") {
			t.Fatalf("unexpected a wait output: %q", res.out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a wait did not wake promptly after co-resident b replied")
	}

	tr, err := srvA.call("read", map[string]any{"call": callID})
	if err != nil || !strings.Contains(tr, "pong from co-resident b") {
		t.Fatalf("a read after wait: out=%q err=%v", tr, err)
	}
}

func TestLDRBridgeMalformedOrUnreadableAttachmentFailsClosedPreservingLocalResources(t *testing.T) {
	fx := newLDRBridgeFixture(t)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := fx.enroll(t, "ns-alice", aliceCK, 4, 0x64)
	fx.activateEpoch(t, "ep-bad-1")

	validClientDir := filepath.Join(t.TempDir(), "valid-ldr")
	fx.setupWorkstation(t, validClientDir, aliceCK, ag, arid, ardig, "alice-gemini")

	homeDir := filepath.Join(t.TempDir(), "bad-attach-home")
	_ = os.Setenv("YIP_HOME", homeDir)
	activeLine = "bad-attach-line"
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	// Configure a host-local resource and seed a local-only call to ensure broken ldr.json
	// NEVER falls back to local calls or YIP_LDR_DIR while keeping host-local leases working.
	if err := os.WriteFile(resourceConfigPath(), []byte(`{"version":1,"resources":[{"name":"gpu","description":"local GPU","machine":"local-host"}]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decoy, err := NewCall("other", "gemini", "Local decoy call")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendTurn(decoy, "other", "should not be visible when ldr.json is broken", false); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("YIP_LDR_DIR", validClientDir)

	type brokenCase struct {
		name  string
		setup func(t *testing.T, p string)
	}
	cases := []brokenCase{
		{
			name: "malformed-json",
			setup: func(t *testing.T, p string) {
				if err := os.WriteFile(p, []byte("{not-json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown-field",
			setup: func(t *testing.T, p string) {
				if err := os.WriteFile(p, []byte(`{"version":1,"client_dir":"`+validClientDir+`","unknown":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsupported-version",
			setup: func(t *testing.T, p string) {
				if err := os.WriteFile(p, []byte(`{"version":2,"client_dir":"`+validClientDir+`"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "empty-client-dir",
			setup: func(t *testing.T, p string) {
				if err := os.WriteFile(p, []byte(`{"version":1,"client_dir":"   "}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unreadable-file",
			setup: func(t *testing.T, p string) {
				if os.Geteuid() == 0 {
					t.Skip("root ignores chmod 000")
				}
				if err := os.WriteFile(p, []byte(`{"version":1,"client_dir":"`+validClientDir+`"}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			},
		},
	}

	srv := &server{me: "gemini"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := ldrAttachmentPath()
			_ = os.Chmod(p, 0o600)
			tc.setup(t, p)
			defer func() { _ = os.Chmod(p, 0o600) }()

			if _, ok, err := loadLDRAttachment(); !ok || err == nil {
				t.Fatalf("expected loadLDRAttachment=(true, err), got ok=%v err=%v", ok, err)
			}
			if _, err := AttachLDRLine(validClientDir, "gemini", "alice-gemini"); err == nil {
				t.Fatal("expected AttachLDRLine to refuse overwriting invalid/unreadable ldr.json")
			}

			// Remote coordination tools must fail closed without falling back to YIP_LDR_DIR or local writes.
			remoteCalls := []struct {
				tool string
				args map[string]any
			}{
				{"call", map[string]any{"peer": "other", "subject": "Must fail", "body": "no local write"}},
				{"ring", nil},
				{"presence", nil},
				{"inbox", nil},
				{"broadcasts", nil},
				{"roadmaps", nil},
				{"busy", map[string]any{"text": "should fail"}},
			}
			for _, rc := range remoteCalls {
				if out, err := srv.call(rc.tool, rc.args); err == nil {
					t.Fatalf("tool %s unexpectedly succeeded with broken ldr.json: out=%q", rc.tool, out)
				}
			}
			// Verify no second local call was created by the failed `call` tool.
			localCalls, err := ListCalls()
			if err != nil {
				t.Fatal(err)
			}
			if len(localCalls) != 1 {
				t.Fatalf("expected only the seeded decoy local call, got %d", len(localCalls))
			}

			// Delivery snapshot must report ldr-config-error and NEVER surface the local decoy call.
			snap := deliverySnapshot("gemini")
			foundErr := false
			for k := range snap {
				if strings.HasPrefix(k, "ldr-config-error:") {
					foundErr = true
				}
				if strings.HasPrefix(k, "call:") || strings.HasPrefix(k, "turn:") {
					t.Fatalf("deliverySnapshot fell back to local call %q under broken ldr.json", k)
				}
			}
			if !foundErr {
				t.Fatalf("expected ldr-config-error in deliverySnapshot, got %v", snap)
			}

			// Hooks must not fall back to local calls; SessionStart surfaces the config error.
			if got := hookStop("gemini"); got != nil {
				t.Fatalf("hookStop fell back to local call under broken ldr.json: %#v", got)
			}
			if got := hookPostToolUse("gemini", hookInput{}); got != nil {
				t.Fatalf("hookPostToolUse fell back to local call under broken ldr.json: %#v", got)
			}
			startOut, _ := hookSessionStart("gemini").(map[string]any)
			hso, _ := startOut["hookSpecificOutput"].(map[string]any)
			if addCtx, _ := hso["additionalContext"].(string); !strings.Contains(addCtx, "[yip ldr] configuration error:") {
				t.Fatalf("expected SessionStart configuration error notice, got %#v", startOut)
			}

			// Host-local resource tools MUST remain fully usable even while ldr.json is broken!
			resOut, err := srv.call("resources", nil)
			if err != nil || !strings.Contains(resOut, "gpu") {
				t.Fatalf("host-local resources failed under broken ldr.json: out=%q err=%v", resOut, err)
			}
			holdOut, err := srv.call("hold", map[string]any{"resource": "gpu", "reason": "local emergency"})
			if err != nil || !strings.Contains(holdOut, "HELD") {
				t.Fatalf("host-local hold failed under broken ldr.json: out=%q err=%v", holdOut, err)
			}
			if relOut, err := srv.call("release", map[string]any{"resource": "gpu"}); err != nil || !strings.Contains(relOut, "released") {
				t.Fatalf("host-local release failed under broken ldr.json: out=%q err=%v", relOut, err)
			}
		})
	}

	// Detach removes ldr.json; unsetting YIP_LDR_DIR restores genuinely unattached (false, nil) state.
	_ = os.Chmod(ldrAttachmentPath(), 0o600)
	if err := DetachLDRLine(); err != nil {
		t.Fatal(err)
	}
	_ = os.Unsetenv("YIP_LDR_DIR")
	if _, ok, err := loadLDRAttachment(); err != nil || ok {
		t.Fatalf("expected (false, nil) after detach + unset YIP_LDR_DIR, got ok=%v err=%v", ok, err)
	}
}

func TestLDRBridgeDeliveryLineBindingAndLegacyUnqualifiedEvents(t *testing.T) {
	// Two completely independent LDR lines with distinct line_ids and identical
	// actor/sequence progression so both generate identical raw ldrclient notice IDs.
	fxA := newLDRBridgeFixture(t)
	aliceACK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobACK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	aAg, aArid, aArdig := fxA.enroll(t, "ns-alice", aliceACK, 4, 0x71)
	bAg, bArid, bArdig := fxA.enroll(t, "ns-bob", bobACK, 4, 0x72)
	fxA.activateEpoch(t, "ep-a-1")

	aliceADir := filepath.Join(t.TempDir(), "alice-a-ldr")
	bobADir := filepath.Join(t.TempDir(), "bob-a-ldr")
	fxA.setupWorkstation(t, aliceADir, aliceACK, aAg, aArid, aArdig, "alice-gemini")
	fxA.setupWorkstation(t, bobADir, bobACK, bAg, bArid, bArdig, "bob-codex")

	fxB := newLDRBridgeFixture(t)
	aliceBCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobBCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	aBg, aBrid, aBrdig := fxB.enroll(t, "ns-alice", aliceBCK, 4, 0x73)
	bBg, bBrid, bBrdig := fxB.enroll(t, "ns-bob", bobBCK, 4, 0x74)
	fxB.activateEpoch(t, "ep-b-1")

	aliceBDir := filepath.Join(t.TempDir(), "alice-b-ldr")
	bobBDir := filepath.Join(t.TempDir(), "bob-b-ldr")
	fxB.setupWorkstation(t, aliceBDir, aliceBCK, aBg, aBrid, aBrdig, "alice-gemini")
	fxB.setupWorkstation(t, bobBDir, bobBCK, bBg, bBrid, bBrdig, "bob-codex")

	aliceAHome := filepath.Join(t.TempDir(), "alice-a-home")
	aliceBHome := filepath.Join(t.TempDir(), "alice-b-home")
	// ONE shared Bob local line/endpoint that switches attachment from Line A -> Line B -> Line A.
	bobHome := filepath.Join(t.TempDir(), "bob-switch-home")

	useAliceA := func() { _ = os.Setenv("YIP_HOME", aliceAHome); activeLine = "line-a" }
	useAliceB := func() { _ = os.Setenv("YIP_HOME", aliceBHome); activeLine = "line-b" }
	useBob := func() { _ = os.Setenv("YIP_HOME", bobHome); activeLine = "bob-shared-local" }

	useAliceA()
	if _, err := AttachLDRLine(aliceADir, "gemini", "alice-gemini"); err != nil {
		t.Fatal(err)
	}
	useAliceB()
	if _, err := AttachLDRLine(aliceBDir, "gemini", "alice-gemini"); err != nil {
		t.Fatal(err)
	}

	// Attach Bob's local endpoint to Line A and register Codex delivery endpoint.
	useBob()
	if _, err := AttachLDRLine(bobADir, "codex", "bob-codex"); err != nil {
		t.Fatal(err)
	}
	if err := RegisterEndpoint("codex", "22222222-3333-4444-5555-666666666666", false); err != nil {
		t.Fatal(err)
	}

	// Alice-A opens call 0001 on Line A -> Bob receives notice evA (un-acked).
	useAliceA()
	if _, err := (&server{me: "gemini"}).call("call", map[string]any{
		"peer": "bob-codex", "subject": "Matching coords", "body": "from line A",
	}); err != nil {
		t.Fatal(err)
	}
	useBob()
	if n, err := Dispatch("codex", func(context.Context, string, string) error { return nil }); err != nil || n != 1 {
		t.Fatalf("dispatch line A: n=%d err=%v", n, err)
	}
	ep, err := readEndpoint("codex")
	if err != nil {
		t.Fatal(err)
	}
	if len(ep.Events) != 1 {
		t.Fatalf("expected 1 event after line A dispatch, got %+v", ep.Events)
	}
	evA := ep.Events[0]
	lineAHex, descAHex, rawNoticeA, qualA := parseLDRDeliverySource(evA.Source)
	if !qualA {
		t.Fatalf("expected qualified LDR source on line A, got %q", evA.Source)
	}

	// Reattach the SAME local endpoint from Line A to Line B!
	if err := DetachLDRLine(); err != nil {
		t.Fatal(err)
	}
	if _, err := AttachLDRLine(bobBDir, "codex", "bob-codex"); err != nil {
		t.Fatal(err)
	}

	// Alice-B opens call 0001 on Line B with identical sequence/actor/kind coordinates.
	useAliceB()
	if _, err := (&server{me: "gemini"}).call("call", map[string]any{
		"peer": "bob-codex", "subject": "Matching coords", "body": "from line B",
	}); err != nil {
		t.Fatal(err)
	}

	// Dispatch on Bob (now attached to Line B) MUST NOT be suppressed by Line A's ep.Known entry!
	useBob()
	if n, err := Dispatch("codex", func(context.Context, string, string) error { return nil }); err != nil || n != 1 {
		t.Fatalf("expected line B notice not suppressed by line A ep.Known: n=%d err=%v", n, err)
	}
	ep, err = readEndpoint("codex")
	if err != nil {
		t.Fatal(err)
	}
	if len(ep.Events) != 2 {
		t.Fatalf("expected 2 distinct events across line A and line B, got %+v", ep.Events)
	}
	evB := ep.Events[1]
	lineBHex, descBHex, rawNoticeB, qualB := parseLDRDeliverySource(evB.Source)
	if !qualB {
		t.Fatalf("expected qualified LDR source on line B, got %q", evB.Source)
	}
	if rawNoticeA != rawNoticeB {
		t.Fatalf("test precondition failed: expected matching raw notice coordinates, got A=%q B=%q", rawNoticeA, rawNoticeB)
	}
	if lineAHex == lineBHex && descAHex == descBHex {
		t.Fatalf("expected distinct line identity between A and B")
	}
	if evA.ID == evB.ID || evA.Source == evB.Source {
		t.Fatalf("expected distinct delivery IDs and sources across lines, got A=%+v B=%+v", evA, evB)
	}

	countUnacked := func(dir string) int {
		t.Helper()
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		return len(cl.DeliverableNotices())
	}

	// 1. Acking Line A's old event while attached to Line B MUST fail and MUST NOT ack Line B's notice!
	if err := AckDelivery("codex", evA.ID); err == nil {
		t.Fatal("expected AckDelivery(evA) to fail while attached to Line B")
	}
	if got := countUnacked(bobBDir); got != 1 {
		t.Fatalf("wrong-line ack mutated Line B notice state: unacked=%d", got)
	}
	ep, _ = readEndpoint("codex")
	if ep.Events[0].Status == "read" {
		t.Fatalf("evA was falsely marked read during wrong-line ack: %+v", ep.Events[0])
	}

	// 2. Inject a preexisting unqualified legacy event ("ldr:" + rawNoticeB): AckDelivery MUST refuse without guessing!
	legacySource := "ldr:" + rawNoticeB
	legacyID := deliveryID("codex", legacySource)
	if err := editEndpoint("codex", func(e *Endpoint) error {
		e.Known[legacySource] = true
		e.Events = append(e.Events, Delivery{
			ID: legacyID, Source: legacySource, Text: "legacy unqualified notice", Created: now(), Status: "accepted",
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := AckDelivery("codex", legacyID); err == nil {
		t.Fatal("expected AckDelivery on legacy unqualified ldr: source to fail without guessing")
	}
	if got := countUnacked(bobBDir); got != 1 {
		t.Fatalf("legacy unqualified ack mutated Line B notice state: unacked=%d", got)
	}
	ep, _ = readEndpoint("codex")
	if ep.Events[2].Status == "read" {
		t.Fatalf("legacy unqualified event falsely marked read: %+v", ep.Events[2])
	}

	// 3. Acking Line B's event while attached to Line B succeeds and leaves Line A's notice un-acked!
	if err := AckDelivery("codex", evB.ID); err != nil {
		t.Fatalf("AckDelivery(evB) on Line B failed: %v", err)
	}
	if got := countUnacked(bobBDir); got != 0 {
		t.Fatalf("expected 0 unacked notices on Line B after evB ack, got %d", got)
	}
	if got := countUnacked(bobADir); got != 1 {
		t.Fatalf("expected Line A notice to remain unacked, got %d", got)
	}

	// 4. Reattaching Line A allows AckDelivery(evA) to succeed cleanly!
	if err := DetachLDRLine(); err != nil {
		t.Fatal(err)
	}
	if _, err := AttachLDRLine(bobADir, "codex", "bob-codex"); err != nil {
		t.Fatal(err)
	}
	if err := AckDelivery("codex", evA.ID); err != nil {
		t.Fatalf("AckDelivery(evA) after reattaching Line A failed: %v", err)
	}
	if got := countUnacked(bobADir); got != 0 {
		t.Fatalf("expected 0 unacked notices on Line A after evA ack, got %d", got)
	}
}

func TestLDRBridgeCLIRoutingAndRefusalThroughActualBinary(t *testing.T) {
	// Build the actual yip CLI binary once to exercise main.go dispatch end to end.
	binPath := filepath.Join(t.TempDir(), "yip")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build yip binary failed: %v\n%s", err, string(out))
	}

	fx := newLDRBridgeFixture(t)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := fx.enroll(t, "ns-alice", aliceCK, 4, 0x75)
	bg, brid, brdig := fx.enroll(t, "ns-bob", bobCK, 4, 0x76)
	fx.activateEpoch(t, "ep-cli-1")

	aliceClientDir := filepath.Join(t.TempDir(), "alice-cli-ldr")
	bobClientDir := filepath.Join(t.TempDir(), "bob-cli-ldr")
	fx.setupWorkstation(t, aliceClientDir, aliceCK, ag, arid, ardig, "alice-gemini")
	fx.setupWorkstation(t, bobClientDir, bobCK, bg, brid, brdig, "bob-codex")

	aliceHome := filepath.Join(t.TempDir(), "alice-cli-home")
	bobHome := filepath.Join(t.TempDir(), "bob-cli-home")
	const aliceLine = "cli-alice"
	const bobLine = "cli-bob"

	_ = os.Setenv("YIP_HOME", bobHome)
	activeLine = bobLine
	if _, err := AttachLDRLine(bobClientDir, "codex", "bob-codex"); err != nil {
		t.Fatal(err)
	}

	_ = os.Setenv("YIP_HOME", aliceHome)
	activeLine = aliceLine
	if _, err := AttachLDRLine(aliceClientDir, "gemini", "alice-gemini"); err != nil {
		t.Fatal(err)
	}
	// Configure host-local resource "gpu" and seed a local decoy call involving "gemini".
	if err := os.WriteFile(resourceConfigPath(), []byte(`{"version":1,"resources":[{"name":"gpu","description":"local GPU","machine":"cli-host"}]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decoy, err := NewCall("other", "gemini", "Local decoy call")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendTurn(decoy, "other", "decoy turn 1", false); err != nil {
		t.Fatal(err)
	}

	runCLI := func(extraEnv []string, stdin string, args ...string) (string, error) {
		cmd := exec.Command(binPath, args...)
		env := make([]string, 0, len(os.Environ())+len(extraEnv)+3)
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "YIP_HOME=") || strings.HasPrefix(kv, "YIP_ROOT=") ||
				strings.HasPrefix(kv, "YIP_LINE=") || strings.HasPrefix(kv, "YIP_LDR_DIR=") ||
				strings.HasPrefix(kv, "YIP_AGENT=") {
				continue
			}
			env = append(env, kv)
		}
		env = append(env, "YIP_HOME="+aliceHome)
		env = append(env, extraEnv...)
		cmd.Env = env
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. Valid LDR attachment: CLI `call`, `note`, `calls`, `dispute`, `measure`, `roadmap` route to LDR, never the decoy!
	out, err := runCLI(nil, "hello over CLI", "--line", aliceLine, "--as", "gemini", "call", "bob-codex", "CLI note routing")
	if err != nil || !strings.Contains(out, "0001-cli-note-routing") {
		t.Fatalf("cli call: err=%v out=%q", err, out)
	}
	out, err = runCLI(nil, "verified encrypted CLI note", "--line", aliceLine, "--as", "gemini", "note", "0001-cli-note-routing")
	if err != nil || !strings.Contains(out, "note 1 left on 0001-cli-note-routing") {
		t.Fatalf("cli note with valid attachment: err=%v out=%q", err, out)
	}
	// Confirm Bob reads Alice's encrypted CLI note on the LDR relay!
	_ = os.Setenv("YIP_HOME", bobHome)
	activeLine = bobLine
	bobTr, err := (&server{me: "codex"}).call("read", map[string]any{"call": "0001-cli-note-routing"})
	if err != nil || !strings.Contains(bobTr, "verified encrypted CLI note") {
		t.Fatalf("bob failed to read Alice's LDR CLI note: err=%v tr=%q", err, bobTr)
	}
	// Confirm local decoy call received ZERO notes!
	_ = os.Setenv("YIP_HOME", aliceHome)
	activeLine = aliceLine
	if decoyNotes, err := Notes(decoy); err != nil || len(decoyNotes) != 0 {
		t.Fatalf("local decoy call mutated by LDR cli note: err=%v notes=%+v", err, decoyNotes)
	}

	// Verify `yip calls`, `yip dispute`, `yip measure`, `yip roadmap post|show` route to LDR!
	if out, err = runCLI(nil, "", "--line", aliceLine, "--as", "gemini", "calls"); err != nil ||
		!strings.Contains(out, "0001-cli-note-routing") || strings.Contains(out, "Local decoy call") {
		t.Fatalf("cli calls: err=%v out=%q", err, out)
	}
	if out, err = runCLI(nil, "", "--line", aliceLine, "--as", "gemini", "dispute", "cli factual check"); err != nil ||
		!strings.Contains(out, "opened on 0001-cli-note-routing") {
		t.Fatalf("cli dispute: err=%v out=%q", err, out)
	}
	if decoyDisputes, err := ListDisputes(decoy); err != nil || len(decoyDisputes) != 0 {
		t.Fatalf("local decoy call mutated by LDR cli dispute: err=%v disputes=%+v", err, decoyDisputes)
	}
	if out, err = runCLI(nil, "", "--line", aliceLine, "--as", "gemini", "measure", "go test ./..."); err != nil ||
		!strings.Contains(out, "recorded measurement") {
		t.Fatalf("cli measure: err=%v out=%q", err, out)
	}
	rmJSON := `{"arc":"CLI Arc","stations":[{"id":"s1","name":"One"}],"active":"s1","note":"running"}`
	if out, err = runCLI(nil, rmJSON, "--line", aliceLine, "--as", "gemini", "roadmap", "post"); err != nil ||
		!strings.Contains(out, "CLI Arc") {
		t.Fatalf("cli roadmap post: err=%v out=%q", err, out)
	}
	if out, err = runCLI(nil, "", "--line", aliceLine, "--as", "gemini", "roadmap", "show"); err != nil ||
		!strings.Contains(out, "CLI Arc") {
		t.Fatalf("cli roadmap show: err=%v out=%q", err, out)
	}

	// 2. Unsupported remote / human-only CLI operations MUST be explicitly refused on LDR-attached lines!
	refusedValid := []struct {
		name  string
		stdin string
		args  []string
	}{
		{"ratify", "human note", []string{"--line", aliceLine, "--as", "gemini", "ratify"}},
		{"broadcast", "operator broadcast", []string{"--line", aliceLine, "broadcast", "announcement", "--to", "bob-codex"}},
		{"settled", "", []string{"--line", aliceLine, "--as", "gemini", "settled", "measured"}},
		{"watch", "", []string{"--line", aliceLine, "--as", "gemini", "watch", "--once", "--timeout", "1s"}},
	}
	for _, tc := range refusedValid {
		if out, err := runCLI(nil, tc.stdin, tc.args...); err == nil {
			t.Fatalf("expected %s to be refused on LDR-attached line, succeeded with out=%q", tc.name, out)
		}
	}
	if decoyNotes, err := Notes(decoy); err != nil || len(decoyNotes) != 0 {
		t.Fatalf("refused cli ratify mutated local decoy call: err=%v notes=%+v", err, decoyNotes)
	}

	// 3. Malformed ldr.json + YIP_LDR_DIR set + local decoy call: `yip note` (and other remote CLIs) MUST fail closed!
	if err := os.WriteFile(ldrAttachmentPath(), []byte("{malformed-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	envWithFallback := []string{"YIP_LDR_DIR=" + aliceClientDir}
	if out, err := runCLI(envWithFallback, "must not land on local decoy", "--line", aliceLine, "--as", "gemini", "note"); err == nil {
		t.Fatalf("expected cli note to fail with malformed ldr.json, succeeded with out=%q", out)
	}
	if decoyNotes, err := Notes(decoy); err != nil || len(decoyNotes) != 0 {
		t.Fatalf("malformed-ldr cli note wrote to local decoy call: err=%v notes=%+v", err, decoyNotes)
	}
	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
	}{
		{"calls", "", []string{"--line", aliceLine, "--as", "gemini", "calls"}},
		{"dispute", "", []string{"--line", aliceLine, "--as", "gemini", "dispute", "bad"}},
		{"measure", "", []string{"--line", aliceLine, "--as", "gemini", "measure", "bad"}},
		{"roadmap-show", "", []string{"--line", aliceLine, "--as", "gemini", "roadmap", "show"}},
		{"ratify", "bad", []string{"--line", aliceLine, "--as", "gemini", "ratify"}},
		{"broadcast", "bad", []string{"--line", aliceLine, "broadcast", "announcement", "--to", "bob-codex"}},
		{"settled", "", []string{"--line", aliceLine, "--as", "gemini", "settled", "bad"}},
		{"watch", "", []string{"--line", aliceLine, "--as", "gemini", "watch", "--once", "--timeout", "1s"}},
	} {
		if out, err := runCLI(envWithFallback, tc.stdin, tc.args...); err == nil {
			t.Fatalf("expected %s to fail with malformed ldr.json, succeeded with out=%q", tc.name, out)
		}
	}

	// 4. Host-local resource leases STILL work via the actual CLI even while ldr.json is malformed!
	if out, err := runCLI(envWithFallback, "", "--line", aliceLine, "--as", "gemini", "resources"); err != nil || !strings.Contains(out, "gpu") {
		t.Fatalf("cli resources failed under malformed ldr.json: err=%v out=%q", err, out)
	}
	if out, err := runCLI(envWithFallback, "", "--line", aliceLine, "--as", "gemini", "hold", "gpu", "cli local gate", "--now"); err != nil || !strings.Contains(out, "HELD") {
		t.Fatalf("cli hold failed under malformed ldr.json: err=%v out=%q", err, out)
	}
	if out, err := runCLI(envWithFallback, "", "--line", aliceLine, "--as", "gemini", "release", "gpu"); err != nil || !strings.Contains(out, "released") {
		t.Fatalf("cli release failed under malformed ldr.json: err=%v out=%q", err, out)
	}
}
