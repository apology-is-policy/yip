package ldrclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

// TestWSTunnelLostMutationReplyAfterDurableCommitReconcilesWithUnchangedCommitCount
// exercises recovery over ws_tls13_exporter:
// drop the outer WebSocket carrier AFTER the origin relay durably commits a
// Submit (before the inner HTTP reply reaches the client), verify the old
// session fails closed, reconnect with fresh WebSocket + inner TLS 1.3 + P7,
// reconcile the original (op_id, intent_digest), and confirm the relay commit
// count stays unchanged before a subsequent mutation succeeds.
func TestWSTunnelLostMutationReplyAfterDurableCommitReconcilesWithUnchangedCommitCount(t *testing.T) {
	relayDir := t.TempDir()
	originCert := filepath.Join(relayDir, "tls", "server.crt")
	originKey := filepath.Join(relayDir, "tls", "server.key")
	originPin, err := ldrrelay.InitSelfSignedCert(originCert, originKey, []string{"origin.internal"})
	if err != nil {
		t.Fatal(err)
	}
	innerTLSCfg, err := ldrrelay.InnerTunnelServerTLSConfig(originCert, originKey)
	if err != nil {
		t.Fatal(err)
	}
	st, err := ldrstore.OpenFileStore(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), ldrrelay.RealClockSource())
	if err != nil {
		t.Fatal(err)
	}
	rs := ldrrelay.NewRelayServer(eng)

	// Simulated TLS-terminating edge proxy with programmatic connection drop.
	edgeDir := t.TempDir()
	edgeCert := filepath.Join(edgeDir, "edge.crt")
	edgeKey := filepath.Join(edgeDir, "edge.key")
	edgePin, err := ldrrelay.InitSelfSignedCert(edgeCert, edgeKey, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	edgeTLSCfg, err := ldrrelay.InnerTunnelServerTLSConfig(edgeCert, edgeKey)
	if err != nil {
		t.Fatal(err)
	}

	var dropMu sync.Mutex
	activeEdgeConns := make(map[net.Conn]struct{})
	dropAllEdge := func() {
		dropMu.Lock()
		conns := make([]net.Conn, 0, len(activeEdgeConns))
		for c := range activeEdgeConns {
			conns = append(conns, c)
		}
		dropMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}

	var dropNextSubmitReply atomic.Bool
	var dropAfterSeq atomic.Uint64
	var droppedAfterCommit atomic.Bool

	relaySeq := func() uint64 {
		statuses := eng.Status()
		if len(statuses) != 1 {
			return 0
		}
		return statuses[0].HeadSeq
	}

	// Use unmodified production NewWSTunnelServer + RelayServer. Because RelayEngine
	// commits Submit synchronously before RelayServer emits the inner TLS reply,
	// dropping the backend->client byte chunk when armed severs the carrier
	// deterministically AFTER durable commit and BEFORE the reply reaches client!
	wsTunnelSrv, err := ldrrelay.NewWSTunnelServer(rs, innerTLSCfg, "/v1/tunnel", 32)
	if err != nil {
		t.Fatal(err)
	}
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originHTTP := &http.Server{Handler: wsTunnelSrv}
	go func() { _ = originHTTP.Serve(originLn) }()

	edgeRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	edgeTLSLn := tls.NewListener(edgeRawLn, edgeTLSCfg)

	var edgeWG sync.WaitGroup
	edgeWG.Add(1)
	go func() {
		defer edgeWG.Done()
		for {
			cc, err := edgeTLSLn.Accept()
			if err != nil {
				return
			}
			edgeWG.Add(1)
			go func(clientConn net.Conn) {
				defer edgeWG.Done()
				defer clientConn.Close()
				if err := clientConn.(*tls.Conn).Handshake(); err != nil {
					return
				}
				backend, err := net.DialTimeout("tcp", originLn.Addr().String(), 5*time.Second)
				if err != nil {
					return
				}
				defer backend.Close()
				dropMu.Lock()
				activeEdgeConns[clientConn] = struct{}{}
				activeEdgeConns[backend] = struct{}{}
				dropMu.Unlock()
				defer func() {
					dropMu.Lock()
					delete(activeEdgeConns, clientConn)
					delete(activeEdgeConns, backend)
					dropMu.Unlock()
				}()

				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(backend, clientConn)
					_ = backend.Close()
					done <- struct{}{}
				}()
				go func() {
					buf := make([]byte, 32*1024)
					for {
						n, rerr := backend.Read(buf)
						if n > 0 {
							if dropNextSubmitReply.Load() && relaySeq() > dropAfterSeq.Load() && dropNextSubmitReply.Swap(false) {
								// Origin has already durably committed (HeadSeq advanced) and emitted its
								// inner TLS reply; drop the carrier BEFORE forwarding those reply bytes!
								droppedAfterCommit.Store(true)
								_ = clientConn.Close()
								_ = backend.Close()
								break
							}
							if _, werr := clientConn.Write(buf[:n]); werr != nil {
								break
							}
						}
						if rerr != nil {
							break
						}
					}
					_ = clientConn.Close()
					done <- struct{}{}
				}()
				<-done
				<-done
			}(cc)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = edgeTLSLn.Close()
		dropAllEdge()
		edgeWG.Wait()
		_ = originHTTP.Shutdown(ctx)
		_ = wsTunnelSrv.Shutdown(ctx)
		_ = eng.Shutdown()
	})

	// Provision ws_tls13_exporter line, bootstrap the admin, and enroll a credential.
	ctx := context.Background()
	r1, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
	r2, _ := GenerateSigningKey(ldrcrypto.AlgECDSAP256)
	opKey, _ := GenerateSigningKey(ldrcrypto.AlgEd25519)
	credKeys, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	lineID := bytes.Repeat([]byte{0xc3}, 16)
	origin := ldrcrypto.RelayOrigin{
		URL:             "https://" + edgeRawLn.Addr().String() + "/v1/tunnel",
		TLSPolicy:       ldrcrypto.TLSPolicyPinSPKISHA256,
		TLSPin:          originPin[:],
		SessionBinding:  ldrcrypto.SessionBindingWSTLS13Exporter,
		OuterTLSPolicy:  ldrcrypto.TLSPolicyPinSPKISHA256,
		OuterTLSPin:     edgePin[:],
		InnerServerName: "origin.internal",
	}
	desc := ldrcrypto.CreationDescriptor{
		Version: 1, LineID: lineID, Generation: 1,
		RootKeys:    []ldrcrypto.PublicKey{r1.Signer.PublicKey(), r2.Signer.PublicKey()},
		RelayOrigin: origin, Profile: ldrcrypto.ProfileV1(),
	}
	sd, err := ldrcrypto.SignCreationDescriptor(r1.Signer, desc)
	if err != nil {
		t.Fatal(err)
	}
	rawDesc, err := sd.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := eng.Provision(rawDesc)
	if err != nil {
		t.Fatal(err)
	}

	adminDir := filepath.Join(t.TempDir(), "admin")
	cl, err := InitClientDir(InitDirOptions{
		Dir: adminDir, SignedDescriptor: rawDesc, CredKeys: credKeys, Activated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	cl.AttachRootKey(r1)
	cl.AttachOperatorKey(opKey)

	sRoot, err := cl.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		t.Fatalf("Dial(root) over ws_tls13_exporter: %v", err)
	}
	rk0, _ := desc.RootKeys[0].ToCBOR()
	rk1, _ := desc.RootKeys[1].ToCBOR()
	profMap, _ := desc.Profile.ToCBORMap()
	initOp, err := cl.ComposeAndPersist(ComposeParams{
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
	if rep, err := cl.Send(ctx, sRoot, initOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("line_init: rep=%+v err=%v", rep, err)
	}
	if _, err := cl.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}
	opPubC, _ := opKey.Signer.PublicKey().ToCBOR()
	authOp, err := cl.ComposeAndPersist(ComposeParams{
		Action: "auth_op", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
		Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPubC}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := cl.Send(ctx, sRoot, authOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("auth_op: rep=%+v err=%v", rep, err)
	}
	if _, err := cl.Sync(ctx, sRoot); err != nil {
		t.Fatal(err)
	}
	sRoot.Close()

	// Dial operator session over ws_tls13_exporter, enroll the credential.
	sOp, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	grant := ldrcrypto.JoinGrant{NamespaceID: "ns-ws", ActorLimit: 4, Reader: true}
	req, _ := ldrcrypto.SignJoinRequest(credKeys.Signing.Signer, ldrcrypto.JoinRequest{
		RequestID: bytes.Repeat([]byte{0x42}, 16), LineID: lineID, Generation: 1,
		DescriptorDigest: prov.DescriptorDigest, EncryptionKey: credKeys.Encryption.PublicKey(), Grant: grant,
	})
	ch, sec, _ := ldrcrypto.CreateJoinChallenge(opKey.Signer.PublicKey(), req)
	pr, _ := ldrcrypto.RespondJoinChallenge(credKeys.Signing.Signer, credKeys.Encryption, opKey.Signer.PublicKey(), req, ch)
	if err := ldrcrypto.VerifyJoinProof(opKey.Signer.PublicKey(), req, ch, sec, pr); err != nil {
		t.Fatal(err)
	}
	reqDig, _ := ldrcrypto.VerifyJoinRequest(req)
	skC, _ := req.SigningKey.ToCBOR()
	ekC, _ := req.EncryptionKey.ToCBOR()
	enrOp, err := cl.ComposeAndPersist(ComposeParams{
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
			{Key: "join_request_id", Value: req.RequestID},
			{Key: "signing_key", Value: skC},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := cl.Send(ctx, sOp, enrOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("enroll: rep=%+v err=%v", rep, err)
	}
	if _, err := cl.Sync(ctx, sOp); err != nil {
		t.Fatal(err)
	}
	sOp.Close()

	// Now open credential session, prepare for mutation, and compose actor_declare ("ws-actor-1").
	sCred, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.PrepareForMutation(ctx, sCred, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}

	seqBefore := relaySeq()

	declare1, err := cl.ComposeAndPersist(ComposeParams{
		Action: "declare:ws-actor-1", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{
			{Key: "actor_id", Value: "ws-actor-1"},
			{Key: "label", Value: false},
			{Key: "namespace_id", Value: "ns-ws"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Arm the edge proxy to sever the WS carrier right as the post-commit Submit reply arrives!
	dropAfterSeq.Store(seqBefore)
	dropNextSubmitReply.Store(true)
	_, sendErr := cl.Send(ctx, sCred, declare1)
	if sendErr == nil {
		t.Fatal("expected Send to fail when outer WS carrier dropped before reply reached client")
	}
	if !droppedAfterCommit.Load() {
		t.Fatal("test harness did not observe post-commit reply drop")
	}

	// Verify the relay ALREADY durably committed declare1 (seqBefore + 1)!
	seqAfterDrop := relaySeq()
	if seqAfterDrop != seqBefore+1 {
		t.Fatalf("expected relay WAL to commit declare1 before drop: before=%d after=%d", seqBefore, seqAfterDrop)
	}
	// Verify client retains declare1 as unsettled (needs_resolve) and blocks the same slot before reconciliation!
	cl.mu.Lock()
	var declEntry *OutboxEntry
	for _, e := range cl.outbox.Entries {
		if e.OpID == declare1 {
			declEntry = cloneOutboxEntry(e)
		}
	}
	cl.mu.Unlock()
	if declEntry == nil || declEntry.Status != ldrcore.OutPending || !declEntry.NeedsResolve || !cl.Status().MustResolve {
		t.Fatalf("expected declare1 status %q after dropped reply, got %+v", ldrcore.OutPending, declEntry)
	}
	if _, err := cl.ComposeAndPersist(ComposeParams{
		Action: "declare:ws-actor-1", Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "ws-actor-1"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-ws"}},
	}); err == nil {
		t.Fatal("expected client to refuse re-composing busy slot while prior op is unreconciled")
	}
	// Old session MUST fail closed (never silently reconnect!).
	if _, err := sCred.AnchorRequest(ctx); err == nil {
		t.Fatal("expected dropped ws_tls13_exporter session to stay dead")
	}
	sCred.Close()

	// Reconnect with a FRESH ws_tls13_exporter WebSocket + inner TLS 1.3 + P7 session and reconcile!
	sCred2, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatalf("re-dial fresh ws_tls13_exporter session: %v", err)
	}
	defer sCred2.Close()
	if sCred.ChannelBinding() == sCred2.ChannelBinding() || bytes.Equal(sCred.SessionID(), sCred2.SessionID()) {
		t.Fatal("reconnect reused the previous channel binding or session ID")
	}
	if _, err := cl.Send(ctx, sCred2, declare1); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("send before reconciliation: got %v, want ErrMustResolve", err)
	}

	if err := cl.PrepareForMutation(ctx, sCred2, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatalf("PrepareForMutation reconciliation after dropped reply failed: %v", err)
	}
	// Reconciliation MUST settle declare1 as committed with UNCHANGED relay commit count (zero duplicate commit!)
	cl.mu.Lock()
	declEntry = nil
	for _, e := range cl.outbox.Entries {
		if e.OpID == declare1 {
			declEntry = cloneOutboxEntry(e)
		}
	}
	cl.mu.Unlock()
	if declEntry == nil || declEntry.Status != ldrcore.OutDone || declEntry.OutcomeKind != ldrcore.Committed || declEntry.OutcomeSeq != seqAfterDrop {
		t.Fatalf("expected declare1 settled as committed@%d after reconciliation, got %+v", seqAfterDrop, declEntry)
	}
	if got := relaySeq(); got != seqAfterDrop {
		t.Fatalf("reconciliation unexpectedly changed relay commit count: got %d want %d", got, seqAfterDrop)
	}
	if _, ok := cl.State().Line.Actors["ws-actor-1"]; !ok {
		t.Fatal("expected ws-actor-1 present in reconciled client state")
	}

	// Submitting a new mutation on the fresh session succeeds cleanly at seqAfterDrop + 1!
	if _, err := cl.SubmitActorDeclare(ctx, sCred2, "ws-actor-2", ""); err != nil {
		t.Fatalf("subsequent mutation after reconciliation failed: %v", err)
	}
	if got := relaySeq(); got != seqAfterDrop+1 {
		t.Fatalf("expected relay seq %d after second mutation, got %d", seqAfterDrop+1, got)
	}
}
