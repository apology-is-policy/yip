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
	t.Run("Switchboard reads the transcript and preserves pending delivery", func(t *testing.T) {
		att, ok, err := loadLDRAttachment()
		if err != nil || !ok {
			t.Fatalf("attachment: ok=%v err=%v", ok, err)
		}
		files := []string{endpointPath("codex"), ldrCursorsPath(), filepath.Join(bobClientDir, "cursors.cbor"), filepath.Join(bobClientDir, "outbox.cbor")}
		read := func(path string) []byte {
			t.Helper()
			data, err := os.ReadFile(path)
			if os.IsNotExist(err) && path == ldrCursorsPath() {
				return nil // An unread call may have no local read cursor yet.
			}
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		before := make(map[string][]byte)
		for _, file := range files {
			before[file] = read(file)
		}
		board := loadRelayBoard(ctx, att, "", sbState{relay: &sbRelay{}})
		if board.err != "" || len(board.calls) != 1 || board.relay.VerifiedAt.IsZero() {
			t.Fatalf("board refresh: calls=%d error=%q", len(board.calls), board.err)
		}
		v := view{st: board}
		if got := strings.Join(v.styledTranscript(90, colors()), " "); !strings.Contains(got, "Hello from Alice workstation over TLS 1.3!") {
			t.Fatalf("transcript: %q", got)
		}
		if got := strings.Join(v.relayTopology(colors()), " "); !strings.Contains(got, "bob-codex") || !strings.Contains(got, "alice-gemini") {
			t.Fatalf("topology: %q", got)
		}
		for _, key := range "arbP4" {
			v.key(key)
			if v.prompt != "" || v.tab != 0 || v.flash != "Read-only relay view" {
				t.Fatalf("unexpected relay action on %q", key)
			}
		}
		// A co-resident agent holding the directory must leave the last snapshot visible.
		other, err := ldrclient.OpenClient(bobClientDir)
		if err != nil {
			t.Fatal(err)
		}
		stale := loadRelayBoard(ctx, att, board.calls[0].call.ID, board)
		other.Close()
		if stale.err == "" || stale.relay != board.relay {
			t.Fatal("failed refresh lost the last verified snapshot")
		}
		for _, file := range files {
			if !bytes.Equal(before[file], read(file)) {
				t.Fatalf("viewing the call changed %s", filepath.Base(file))
			}
		}
	})

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
	return newLDRBridgeFixtureWithLineIDLen(t, 16)
}

func newLDRBridgeFixtureWithLineIDLen(t *testing.T, lineIDLen int) *ldrBridgeFixture {
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
	lineID := make([]byte, lineIDLen)
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
	// Verify parseLDRDeliverySource accepts all supported 16..64-byte lowercase hex
	// line IDs and strictly rejects out-of-range, odd-nibble, uppercase, and legacy forms.
	var dummyCD [32]byte
	for i := range dummyCD {
		dummyCD[i] = byte(i + 1)
	}
	for _, nBytes := range []int{16, 17, 32, 64} {
		lid := bytes.Repeat([]byte{0xab}, nBytes)
		src := formatLDRDeliverySource(lid, dummyCD, "g1:s7:bob-codex:call_turn")
		gotLine, gotDesc, gotNotice, ok := parseLDRDeliverySource(src)
		if !ok || len(gotLine) != nBytes*2 || len(gotDesc) != 16 || gotNotice != "g1:s7:bob-codex:call_turn" {
			t.Fatalf("round-trip failed for %d-byte line_id: src=%q ok=%v line=%q desc=%q notice=%q",
				nBytes, src, ok, gotLine, gotDesc, gotNotice)
		}
	}
	for _, bad := range []string{
		"ldr:g1:s7:bob-codex:call_turn",                                           // legacy unqualified
		"ldr:line:" + strings.Repeat("ab", 15) + ":0102030405060708:g1:s1:a:turn", // 15 bytes (<16)
		"ldr:line:" + strings.Repeat("ab", 65) + ":0102030405060708:g1:s1:a:turn", // 65 bytes (>64)
		"ldr:line:" + strings.Repeat("a", 33) + ":0102030405060708:g1:s1:a:turn",  // odd hex length
		"ldr:line:" + strings.Repeat("AB", 16) + ":0102030405060708:g1:s1:a:turn", // uppercase hex
		"ldr:line:" + strings.Repeat("ab", 16) + ":0102030405060708:",             // empty notice ID
		"ldr:line:" + strings.Repeat("ab", 16) + ":01020304:g1:s1:a:turn",         // short desc prefix
	} {
		if _, _, _, ok := parseLDRDeliverySource(bad); ok {
			t.Fatalf("expected parseLDRDeliverySource to reject %q", bad)
		}
	}

	// Two completely independent LDR lines with distinct line_ids (16-byte Line A and
	// 64-byte Line B) and identical actor/sequence progression so both generate
	// identical raw ldrclient notice IDs while exercising longer valid line IDs in AckDelivery.
	fxA := newLDRBridgeFixtureWithLineIDLen(t, 16)
	aliceACK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobACK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	aAg, aArid, aArdig := fxA.enroll(t, "ns-alice", aliceACK, 4, 0x71)
	bAg, bArid, bArdig := fxA.enroll(t, "ns-bob", bobACK, 4, 0x72)
	fxA.activateEpoch(t, "ep-a-1")

	aliceADir := filepath.Join(t.TempDir(), "alice-a-ldr")
	bobADir := filepath.Join(t.TempDir(), "bob-a-ldr")
	fxA.setupWorkstation(t, aliceADir, aliceACK, aAg, aArid, aArdig, "alice-gemini")
	fxA.setupWorkstation(t, bobADir, bobACK, bAg, bArid, bArdig, "bob-codex")

	fxB := newLDRBridgeFixtureWithLineIDLen(t, 64)
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

func TestAttachLDRLineValidationAndActorMappingLifecycle(t *testing.T) {
	fx := newLDRBridgeFixture(t)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	unactCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := fx.enroll(t, "ns-alice", aliceCK, 4, 0x71)
	bg, brid, brdig := fx.enroll(t, "ns-bob", bobCK, 4, 0x72)
	ug, urid, urdig := fx.enroll(t, "ns-unact", unactCK, 2, 0x73)
	fx.activateEpoch(t, "ep-attach-1")

	aliceClientDir := filepath.Join(t.TempDir(), "alice-ldr")
	bobClientDir := filepath.Join(t.TempDir(), "bob-ldr")
	fx.setupWorkstation(t, aliceClientDir, aliceCK, ag, arid, ardig, "alice-codex", "reviewer")
	fx.setupWorkstation(t, bobClientDir, bobCK, bg, brid, brdig, "bob-claude")

	// Pre-activation member directory (Activated == false).
	unactDir := filepath.Join(t.TempDir(), "unactivated-ldr")
	unactCl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: unactDir, SignedDescriptor: fx.rawDesc, CredKeys: unactCK,
		ExpectedGrant: &ug, ExpectedJoinReq: urid, ExpectedJoinReqDigest: &urdig,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = unactCl.Close()

	// Admin directory without reader credential keys (CredID == "").
	bareAdminDir := filepath.Join(t.TempDir(), "bare-admin")
	bareAdminCl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: bareAdminDir, SignedDescriptor: fx.rawDesc, DirKind: ldrclient.DirKindAdmin, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = bareAdminCl.Close()

	// Enrolled & activated admin reader directory (DirKind == "admin", CredID != "", Activated == true).
	adminReaderCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	fx.enroll(t, "ns-admin-reader", adminReaderCK, 0, 0x74)
	fx.activateEpoch(t, "ep-attach-admin")
	enrolledAdminDir := filepath.Join(t.TempDir(), "enrolled-admin")
	enrolledAdminCl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: enrolledAdminDir, SignedDescriptor: fx.rawDesc, CredKeys: adminReaderCK, DirKind: ldrclient.DirKindAdmin, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = enrolledAdminCl.Close()

	home := filepath.Join(t.TempDir(), "attach-home")
	_ = os.Setenv("YIP_HOME", home)
	activeLine = "attach-hygiene"

	// 1. --actor without --as MUST fail rather than silently discarding the actor mapping.
	if _, err := AttachLDRLine(aliceClientDir, "", "alice-codex"); err == nil || !strings.Contains(err.Error(), "requires --as") {
		t.Fatalf("expected --actor without --as to fail, got: %v", err)
	}
	if err := ldrAttachCLI([]string{"--dir", aliceClientDir, "--actor", "alice-codex"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected ldrAttachCLI without --as to fail when --actor is given")
	}

	// 2. Unactivated member directory and uncredentialed admin directory MUST fail,
	// whereas an enrolled & activated admin reader directory succeeds for line observation
	// and still refuses undeclared actor mappings.
	if _, err := AttachLDRLine(unactDir, "", ""); err == nil || !strings.Contains(err.Error(), "not activated") {
		t.Fatalf("expected unactivated directory attach to fail, got: %v", err)
	}
	if _, err := AttachLDRLine(bareAdminDir, "", ""); err == nil || !strings.Contains(err.Error(), "no credential keys") {
		t.Fatalf("expected bare admin directory attach to fail, got: %v", err)
	}
	if _, err := AttachLDRLine(enrolledAdminDir, "", ""); err != nil {
		t.Fatalf("expected activated admin reader directory to attach for line observation: %v", err)
	}
	if _, err := AttachLDRLine(enrolledAdminDir, "reviewer", "alice-codex"); err == nil {
		t.Fatal("expected mapping undeclared actor onto admin reader directory to fail")
	}
	if err := DetachLDRLine(); err != nil {
		t.Fatal(err)
	}

	// 3. Mapping a seat to an undeclared actor or another workstation's credential actor MUST fail.
	if _, err := AttachLDRLine(aliceClientDir, "reviewer", "undeclared-actor"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("expected undeclared actor mapping to fail, got: %v", err)
	}
	if _, err := AttachLDRLine(aliceClientDir, "reviewer", "bob-claude"); err == nil || !strings.Contains(err.Error(), "belongs to credential") {
		t.Fatalf("expected foreign-credential actor mapping to fail, got: %v", err)
	}

	// 4. Explicit seat mapping succeeds, duplicate seat-to-same-actor fails, and re-attaching
	// the same seat without --actor clears the prior explicit mapping when seat name is a live actor.
	att, err := AttachLDRLine(aliceClientDir, "reviewer", "alice-codex")
	if err != nil {
		t.Fatalf("AttachLDRLine(reviewer -> alice-codex): %v", err)
	}
	if got := att.actorFor("reviewer"); got != "alice-codex" {
		t.Fatalf("actorFor(reviewer) = %q, want alice-codex", got)
	}
	if _, err := AttachLDRLine(aliceClientDir, "second-seat", "alice-codex"); err == nil || !strings.Contains(err.Error(), "already maps") {
		t.Fatalf("expected duplicate seat mapping to same actor to fail, got: %v", err)
	}
	att, err = AttachLDRLine(aliceClientDir, "reviewer", "")
	if err != nil {
		t.Fatalf("re-attach reviewer -> reviewer (actorID empty): %v", err)
	}
	if _, exists := att.Actors["reviewer"]; exists || att.actorFor("reviewer") != "reviewer" {
		t.Fatalf("expected stale reviewer mapping to be cleared, got Actors=%v actorFor=%q", att.Actors, att.actorFor("reviewer"))
	}

	// 5. Switching the local line to a second client directory (Credential 2) drops Credential 1's mappings!
	if _, err := AttachLDRLine(aliceClientDir, "seat-one", "alice-codex"); err != nil {
		t.Fatal(err)
	}
	att2, err := AttachLDRLine(bobClientDir, "bob-seat", "bob-claude")
	if err != nil {
		t.Fatalf("switch to bobClientDir: %v", err)
	}
	if _, leaked := att2.Actors["seat-one"]; leaked {
		t.Fatalf("switching client directories leaked previous credential's actor map: %+v", att2.Actors)
	}
	if got := att2.actorFor("bob-seat"); got != "bob-claude" {
		t.Fatalf("actorFor(bob-seat) = %q, want bob-claude", got)
	}

	// 6. InstallWith rejects invalid --ldr-dir / --ldr-actor BEFORE creating checkout or line side effects!
	cleanCheckout := filepath.Join(t.TempDir(), "clean-checkout")
	if err := os.MkdirAll(cleanCheckout, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWith(cleanCheckout, "no-side-effects", "alice-seat", false, "claude-rewake", InstallOptions{
		LDRDir:   aliceClientDir,
		LDRActor: "undeclared-actor",
	}); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("expected InstallWith with invalid --ldr-actor to fail, got: %v", err)
	}
	for _, untouched := range []string{
		filepath.Join(cleanCheckout, ".mcp.json"),
		filepath.Join(cleanCheckout, ".claude"),
		filepath.Join(lineDirFor("no-side-effects"), "members.json"),
		filepath.Join(lineDirFor("no-side-effects"), "seats.json"),
		filepath.Join(lineDirFor("no-side-effects"), "ldr.json"),
		filepath.Join(lineDirFor("no-side-effects"), "delivery", "alice-seat.json"),
	} {
		if _, err := os.Stat(untouched); !os.IsNotExist(err) {
			t.Fatalf("failed InstallWith left side effect %s (err=%v)", untouched, err)
		}
	}
}

func TestLDRBindPreservesAndGuardsActorAndUninstallPrunesMapping(t *testing.T) {
	fx := newLDRBridgeFixture(t)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := fx.enroll(t, "ns-alice-bind", aliceCK, 4, 0x81)
	bg, brid, brdig := fx.enroll(t, "ns-bob-bind", bobCK, 4, 0x82)
	fx.activateEpoch(t, "ep-bind-1")

	aliceClientDir := filepath.Join(t.TempDir(), "alice-bind-ldr")
	bobClientDir := filepath.Join(t.TempDir(), "bob-bind-ldr")
	fx.setupWorkstation(t, aliceClientDir, aliceCK, ag, arid, ardig, "alice-relay", "alice-wt2")
	fx.setupWorkstation(t, bobClientDir, bobCK, bg, brid, brdig, "bob-relay")

	aliceHome := filepath.Join(t.TempDir(), "alice-bind-home")
	bobHome := filepath.Join(t.TempDir(), "bob-bind-home")
	launchDir := filepath.Join(t.TempDir(), "alice-launch")
	wt1Dir := filepath.Join(t.TempDir(), "feature-wt")
	wt2Dir := filepath.Join(t.TempDir(), "second-wt")
	for _, d := range []string{launchDir, wt1Dir, wt2Dir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	origProcAlive := procAlive
	origAncestors := processAncestors
	t.Cleanup(func() {
		procAlive = origProcAlive
		processAncestors = origAncestors
	})
	sess1 := procID{PID: 41001, Start: "boot-s1"}
	sess2 := procID{PID: 41002, Start: "boot-s2"}
	liveProcs := map[procID]bool{sess1: true, sess2: true}
	procAlive = func(p procID) bool { return liveProcs[p] }
	activeSess := sess1
	processAncestors = func() []procID { return []procID{activeSess} }

	useAlice := func() { _ = os.Setenv("YIP_HOME", aliceHome); activeLine = "bind-alice" }
	useBob := func() { _ = os.Setenv("YIP_HOME", bobHome); activeLine = "bind-bob" }

	useAlice()
	if _, err := InstallWith(launchDir, "bind-alice", "alice-agy", false, "agy", InstallOptions{}); err != nil {
		t.Fatalf("InstallWith(alice-agy): %v", err)
	}
	if _, err := AttachLDRLine(aliceClientDir, "alice-agy", "alice-relay"); err != nil {
		t.Fatalf("AttachLDRLine(alice-agy -> alice-relay): %v", err)
	}
	if err := registerSession(sess1, "alice-agy"); err != nil {
		t.Fatal(err)
	}

	// 1. Explicit bind to an undeclared actor MUST fail without mutating members or bindings.
	conv1 := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if _, err := BindWithConv("alice-agy", sess1, conv1, wt1Dir, "undeclared-actor"); err == nil || !strings.Contains(err.Error(), "not a live actor") {
		t.Fatalf("expected bind with undeclared explicit as to fail, got: %v", err)
	}

	// 2. Default worktree bind (as == "") inherits launch seat's mapped relay actor ("alice-relay").
	res, err := BindWithConv("alice-agy", sess1, conv1, wt1Dir, "")
	if err != nil {
		t.Fatalf("BindWithConv(wt1Dir): %v", err)
	}
	if res.Name != "feature-wt" {
		t.Fatalf("bound Name = %q, want feature-wt", res.Name)
	}
	att, ok, err := loadLDRAttachment()
	if err != nil || !ok {
		t.Fatalf("loadLDRAttachment: ok=%v err=%v", ok, err)
	}
	if got := att.actorFor("feature-wt"); got != "alice-relay" {
		t.Fatalf("actorFor(feature-wt) = %q, want alice-relay", got)
	}

	// 3. A second live session cannot share "alice-relay" via default bind,
	//    and is fenced from acting as "alice-agy" while sess1 holds "alice-relay",
	//    but CAN bind wt2Dir using its own declared actor "alice-wt2"!
	if err := registerSession(sess2, "alice-agy"); err != nil {
		t.Fatal(err)
	}
	activeSess = sess2
	conv2 := "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	if _, err := BindWithConv("alice-agy", sess2, conv2, wt2Dir, ""); err == nil || !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("expected second session sharing alice-relay to fail, got: %v", err)
	}
	if _, err := (&server{me: "alice-agy"}).call("ring", nil); err == nil || !strings.Contains(err.Error(), "currently bound to worktree") {
		t.Fatalf("expected unbound second session to be fenced from alice-relay, got: %v", err)
	}
	res2, err := BindWithConv("alice-agy", sess2, conv2, wt2Dir, "alice-wt2")
	if err != nil {
		t.Fatalf("BindWithConv(wt2Dir, as=alice-wt2): %v", err)
	}
	if res2.Name != "alice-wt2" || att.actorFor("alice-wt2") != "alice-wt2" {
		t.Fatalf("unexpected second bind result: %+v actor=%q", res2, att.actorFor("alice-wt2"))
	}

	// 4. Bob opens a call to "alice-relay": delivery routes to "feature-wt" (not stolen by "alice-agy")
	//    and "feature-wt" can read & reply as "alice-relay"!
	useBob()
	if _, err := AttachLDRLine(bobClientDir, "bob-seat", "bob-relay"); err != nil {
		t.Fatal(err)
	}
	if _, err := (&server{me: "bob-seat"}).call("call", map[string]any{
		"peer":    "alice-relay",
		"subject": "Worktree bind check",
		"body":    "silver-worktree-phrase",
	}); err != nil {
		t.Fatalf("bob call to alice-relay: %v", err)
	}

	useAlice()
	activeSess = sess1
	launchSnap := ldrDeliverySnapshot(att, "alice-agy")
	wtSnap := ldrDeliverySnapshot(att, "feature-wt")
	for k := range launchSnap {
		if strings.HasPrefix(k, "ldr:") {
			t.Fatalf("launch seat alice-agy stole LDR notice %q while bound to feature-wt", k)
		}
	}
	foundWTNotice := false
	for k := range wtSnap {
		if strings.HasPrefix(k, "ldr:") {
			foundWTNotice = true
		}
	}
	if !foundWTNotice {
		t.Fatalf("bound worktree feature-wt did not receive LDR notice for alice-relay: %+v", wtSnap)
	}
	trOut, err := (&server{me: "feature-wt"}).call("read", map[string]any{"call": "0001-worktree-bind-check"})
	if err != nil || !strings.Contains(trOut, "silver-worktree-phrase") {
		t.Fatalf("feature-wt failed to read call for alice-relay: err=%v out=%q", err, trOut)
	}
	if _, err := (&server{me: "feature-wt"}).call("say", map[string]any{
		"call": "0001-worktree-bind-check",
		"body": "reply from bound worktree",
	}); err != nil {
		t.Fatalf("feature-wt failed to reply as alice-relay: %v", err)
	}

	// 4b. Reattaching the local line to a DIFFERENT client directory (bobClientDir) MUST NOT
	//     inherit feature-wt's saved live binding from aliceClientDir!
	reattached, err := AttachLDRLine(bobClientDir, "bob-local", "bob-relay")
	if err != nil {
		t.Fatalf("reattach to bobClientDir: %v", err)
	}
	if got := reattached.actorFor("feature-wt"); got == "alice-relay" {
		t.Fatalf("reattached client directory inherited previous credential's bound actor: %q", got)
	}
	if _, err := (&server{me: "feature-wt"}).call("ring", nil); err == nil || !strings.Contains(err.Error(), "previous LDR client") {
		t.Fatalf("expected stale-route bound worktree to require re-binding, got: %v", err)
	}
	// Restore aliceClientDir before testing uninstall pruning.
	if _, err := AttachLDRLine(aliceClientDir, "alice-agy", "alice-relay"); err != nil {
		t.Fatal(err)
	}

	// 5. Uninstall removes uninstalled seat's actor mapping from ldr.json while keeping others intact.
	liveProcs[sess1] = false
	liveProcs[sess2] = false
	if _, err := AttachLDRLine(aliceClientDir, "keep-seat", "alice-wt2"); err != nil {
		t.Fatal(err)
	}
	if _, err := UninstallFrom(launchDir, "alice-agy", ""); err != nil {
		t.Fatalf("UninstallFrom(alice-agy): %v", err)
	}
	afterUninstall, ok, err := loadLDRAttachment()
	if err != nil || !ok {
		t.Fatalf("loadLDRAttachment after uninstall: ok=%v err=%v", ok, err)
	}
	if _, stale := afterUninstall.Actors["alice-agy"]; stale {
		t.Fatalf("UninstallFrom left stale alice-agy mapping in ldr.json: %+v", afterUninstall.Actors)
	}
	if afterUninstall.Actors["keep-seat"] != "alice-wt2" {
		t.Fatalf("UninstallFrom clobbered unrelated seat mapping: %+v", afterUninstall.Actors)
	}
}

func TestDoctorAndDeliveryDiagnosticsWithLDRAttachment(t *testing.T) {
	fx := newLDRBridgeFixture(t)
	aliceCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	unactCK, _ := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := fx.enroll(t, "ns-alice-doc", aliceCK, 4, 0x91)
	ug, urid, urdig := fx.enroll(t, "ns-unact-doc", unactCK, 2, 0x92)
	fx.activateEpoch(t, "ep-doc-1")

	aliceClientDir := filepath.Join(t.TempDir(), "alice-doc-ldr")
	fx.setupWorkstation(t, aliceClientDir, aliceCK, ag, arid, ardig, "alice-codex")

	unactDir := filepath.Join(t.TempDir(), "unact-doc-ldr")
	unactCl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
		Dir: unactDir, SignedDescriptor: fx.rawDesc, CredKeys: unactCK,
		ExpectedGrant: &ug, ExpectedJoinReq: urid, ExpectedJoinReqDigest: &urdig,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = unactCl.Close()

	home := filepath.Join(t.TempDir(), "doc-home")
	codexHomeDir := filepath.Join(t.TempDir(), "codex-home")
	checkout := filepath.Join(t.TempDir(), "project-checkout")
	if err := os.MkdirAll(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	origCodexHome := os.Getenv("CODEX_HOME")
	origMCPList := codexMCPList
	origQueueCheck := codexQueueCheck
	origExplicitLine := doctorExplicitLine
	t.Cleanup(func() {
		_ = os.Setenv("CODEX_HOME", origCodexHome)
		codexMCPList = origMCPList
		codexQueueCheck = origQueueCheck
		doctorExplicitLine = origExplicitLine
	})
	_ = os.Setenv("YIP_HOME", home)
	_ = os.Setenv("CODEX_HOME", codexHomeDir)

	fakeYip := filepath.Join(t.TempDir(), "yip")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '" + serverVersion + "'; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(fakeYip, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	codexQueueCheck = func() error { return nil }
	codexMCPList = func(dir, profile string) ([]byte, error) {
		return json.Marshal([]map[string]any{{
			"name":    "yip",
			"enabled": true,
			"transport": map[string]any{
				"args": []string{"serve", "--codex", "--line", "project-relay", "--as", "reviewer"},
			},
		}})
	}

	// Install Codex profile "project-alice" on named line "project-relay" mapped to "alice-codex".
	if _, err := InstallWith(checkout, "project-relay", "reviewer", false, "codex", InstallOptions{
		Profile:  "project-alice",
		LDRDir:   aliceClientDir,
		LDRActor: "alice-codex",
	}); err != nil {
		t.Fatalf("InstallWith(codex profile): %v", err)
	}
	// Replace wired binary path in profile config with fakeYip matching serverVersion.
	if err := codexProfileFiles("project-alice", fakeYip, "project-relay", "reviewer", false); err != nil {
		t.Fatal(err)
	}

	// 1. Simulate running `yip doctor --runtime codex --profile project-alice` WITHOUT `--line`:
	//    activeLine starts on an unrelated directory-derived line, and CodexDoctor MUST switch
	//    activeLine to "project-relay", locate reviewer's endpoint, and verify LDR health!
	activeLine = "wrong-derived-line"
	if err := CodexDoctor(checkout, "project-alice"); err != nil {
		t.Fatalf("CodexDoctor without --line failed: %v", err)
	}
	if activeLine != "project-relay" {
		t.Fatalf("CodexDoctor resolved activeLine = %q, want project-relay", activeLine)
	}

	// 2. Passing an explicit mismatched `--line` MUST fail clearly.
	doctorExplicitLine = "other-line"
	if err := CodexDoctor(checkout, "project-alice"); err == nil || !strings.Contains(err.Error(), "configured for line") {
		t.Fatalf("expected CodexDoctor with mismatched --line to fail, got: %v", err)
	}
	doctorExplicitLine = ""

	// 3. DeliveryInbox (`yip delivery status`) preserves Endpoint JSON and embeds healthy `"ldr"` metadata.
	activeLine = "project-relay"
	rawInbox, err := DeliveryInbox("reviewer")
	if err != nil {
		t.Fatalf("DeliveryInbox(reviewer): %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(rawInbox), &parsed); err != nil {
		t.Fatalf("DeliveryInbox invalid JSON: %v\n%s", err, rawInbox)
	}
	ldrObj, _ := parsed["ldr"].(map[string]any)
	if ldrObj == nil || ldrObj["healthy"] != true || ldrObj["actor"] != "alice-codex" || ldrObj["actor_live"] != true {
		t.Fatalf("unexpected DeliveryInbox ldr payload: %+v", ldrObj)
	}

	// 4. Unactivated client directory or undeclared actor (via YIP_LDR_DIR after detach) MUST surface in
	//    CodexDoctor, DeliveryInbox, and SessionStart instead of looking like a quiet healthy line!
	if err := DetachLDRLine(); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("YIP_LDR_DIR", unactDir)
	if err := CodexDoctor(checkout, "project-alice"); err == nil || !strings.Contains(err.Error(), "not activated") {
		t.Fatalf("expected CodexDoctor to fail on unactivated YIP_LDR_DIR, got: %v", err)
	}
	rawBroken, err := DeliveryInbox("reviewer")
	if err != nil {
		t.Fatal(err)
	}
	var parsedBroken map[string]any
	if err := json.Unmarshal([]byte(rawBroken), &parsedBroken); err != nil {
		t.Fatal(err)
	}
	brokenLDR, _ := parsedBroken["ldr"].(map[string]any)
	if brokenLDR == nil || brokenLDR["healthy"] != false || !strings.Contains(brokenLDR["error"].(string), "not activated") {
		t.Fatalf("expected DeliveryInbox to surface unactivated LDR error, got: %+v", brokenLDR)
	}

	// Undeclared actor ("reviewer" on aliceClientDir when ldr.json was detached so YIP_LDR_DIR has empty Actors map):
	_ = os.Setenv("YIP_LDR_DIR", aliceClientDir)
	if err := CodexDoctor(checkout, "project-alice"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("expected CodexDoctor to catch unmapped local seat name on YIP_LDR_DIR, got: %v", err)
	}
	attEnv, ok, err := loadLDRAttachment()
	if err != nil || !ok {
		t.Fatalf("loadLDRAttachment(env): ok=%v err=%v", ok, err)
	}
	ssOut := ldrHookSessionStart(attEnv, "reviewer")
	ssJSON, _ := json.Marshal(ssOut)
	if !strings.Contains(string(ssJSON), "[yip ldr]") || !strings.Contains(string(ssJSON), "not declared") {
		t.Fatalf("expected ldrHookSessionStart to surface undeclared actor warning, got: %s", string(ssJSON))
	}
	_ = os.Unsetenv("YIP_LDR_DIR")
}



