package ldrrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

type relayFixture struct {
	dir        string
	certPath   string
	keyPath    string
	spkiPin    [32]byte
	clock      *fakeClock
	store      *ldrstore.FileStore
	engine     *RelayEngine
	server     *RelayServer
	httpServer *http.Server
	ln         net.Listener
	origin     ldrcrypto.RelayOrigin
	lineID     []byte
	root1      *ldrcrypto.Ed25519PrivateKey
	root2      *ldrcrypto.ECDSAP256PrivateKey
	desc       ldrcrypto.CreationDescriptor
	cd         [32]byte
	genesis    [32]byte
	profDigest [32]byte
}

func startRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls", "server.crt")
	keyPath := filepath.Join(dir, "tls", "server.key")
	pin, err := InitSelfSignedCert(certPath, keyPath, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("InitSelfSignedCert: %v", err)
	}
	tlsCfg, err := ServerTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)

	fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
	st, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	eng, err := NewRelayEngine(st, DefaultClockConfig(), fc.source())
	if err != nil {
		t.Fatalf("NewRelayEngine: %v", err)
	}
	rs := NewRelayServer(eng)
	hs := &http.Server{Handler: rs}
	go func() { _ = hs.Serve(tlsLn) }()

	root1, _ := ldrcrypto.GenerateEd25519Key()
	root2, _ := ldrcrypto.GenerateECDSAP256Key()
	lineID := bytes.Repeat([]byte{0x42}, 16)
	prof := ldrcrypto.ProfileV1()
	profDigest, _ := prof.Digest()

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
		RootKeys:    []ldrcrypto.PublicKey{root1.PublicKey(), root2.PublicKey()},
		RelayOrigin: origin,
		Profile:     prof,
	}
	signedDesc, err := ldrcrypto.SignCreationDescriptor(root2, desc)
	if err != nil {
		t.Fatalf("SignCreationDescriptor: %v", err)
	}
	rawDesc, err := signedDesc.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := eng.Provision(rawDesc)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	fx := &relayFixture{
		dir: dir, certPath: certPath, keyPath: keyPath, spkiPin: pin,
		clock: fc, store: st, engine: eng, server: rs, httpServer: hs, ln: tlsLn,
		origin: origin, lineID: lineID, root1: root1, root2: root2,
		desc: desc, cd: prov.DescriptorDigest, genesis: prov.GenesisAnchor, profDigest: profDigest,
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = fx.httpServer.Shutdown(ctx)
		_ = fx.engine.Shutdown()
	})
	return fx
}

func (fx *relayFixture) restart(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = fx.httpServer.Shutdown(ctx)
	if err := fx.engine.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	tlsCfg, err := ServerTLSConfig(fx.certPath, fx.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Re-bind the exact same address/port so pinned RelayOrigin stays identical.
	addr := fx.origin.URL[len("https://"):]
	rawLn, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("re-listen %s: %v", addr, err)
	}
	fx.ln = tls.NewListener(rawLn, tlsCfg)
	st, err := ldrstore.OpenFileStore(fx.dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	eng, err := NewRelayEngine(st, DefaultClockConfig(), fx.clock.source())
	if err != nil {
		t.Fatalf("reopen engine (startup replay verification failed): %v", err)
	}
	fx.store = st
	fx.engine = eng
	fx.server = NewRelayServer(eng)
	fx.httpServer = &http.Server{Handler: fx.server}
	go func() { _ = fx.httpServer.Serve(fx.ln) }()
}

func signWireIntent(t *testing.T, signer ldrcrypto.Signer, in WireIntentInput) ldrcrypto.SignedIntent {
	t.Helper()
	body, err := BuildWireIntentBody(in)
	if err != nil {
		t.Fatalf("BuildWireIntentBody(%s): %v", in.OpType, err)
	}
	env, err := ldrcrypto.SignIntent(signer, body)
	if err != nil {
		t.Fatalf("SignIntent(%s): %v", in.OpType, err)
	}
	return env
}

func TestRelayEndToEndTLS13LifecycleSecurityAndRestart(t *testing.T) {
	fx := startRelayFixture(t)
	ctx := context.Background()

	// 0. Wrong SPKI pin MUST fail TLS handshake before any HTTP traffic.
	badOrigin := fx.origin
	badPin := bytes.Repeat([]byte{0x99}, 32)
	badOrigin.TLSPin = badPin
	if _, err := DialSession(ctx, badOrigin, fx.lineID, fx.profDigest, 1, ldrcrypto.RootPrincipal(fx.root1.PublicKey()), fx.root1); err == nil {
		t.Fatalf("DialSession succeeded with wrong SPKI pin")
	}

	// 1. Bootstrap root1 session and commit line_init (seq 1).
	root1Prin := ldrcrypto.RootPrincipal(fx.root1.PublicKey())
	sRoot1, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, root1Prin, fx.root1)
	if err != nil {
		t.Fatalf("DialSession(root1): %v", err)
	}
	defer sRoot1.Close()

	sortedRoots, _ := ldrcrypto.CanonicalRootKeys([]ldrcrypto.PublicKey{fx.root1.PublicKey(), fx.root2.PublicKey()})
	rk0, _ := sortedRoots[0].ToCBOR()
	rk1, _ := sortedRoots[1].ToCBOR()
	profMap, _ := fx.desc.Profile.ToCBORMap()
	initEnv := signWireIntent(t, fx.root1, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root1Prin,
		OpID: "init-1", OpType: "line_init",
		SeenSeq: 0, SeenHead: fx.genesis, ValidityMS: 0,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: fx.cd[:]},
			{Key: "profile", Value: profMap},
			{Key: "root_keys", Value: []any{rk0, rk1}},
		},
	})
	rep, err := sRoot1.Submit(ctx, initEnv.RawBytes, nil, nil)
	if err != nil || rep.Class != ldrcore.ClassOutcome || rep.Outcome.Kind != ldrcore.Committed || rep.Outcome.Seq != 1 {
		t.Fatalf("line_init failed: %+v, err=%v", rep, err)
	}
	head1 := rep.Head

	// 2. Root2 (ECDSA P-256!) authorizes a P-256 operator key (seq 2).
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	opKey, _ := ldrcrypto.GenerateECDSAP256Key()
	opCBOR, _ := opKey.PublicKey().ToCBOR()
	root2Prin := ldrcrypto.RootPrincipal(fx.root2.PublicKey())
	sRoot2, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, root2Prin, fx.root2)
	if err != nil {
		t.Fatalf("DialSession(root2): %v", err)
	}
	defer sRoot2.Close()

	authOpEnv := signWireIntent(t, fx.root2, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root2Prin,
		OpID: "auth-op-1", OpType: "operator_key_authorize",
		AuthEpoch: 0, SeenSeq: 1, SeenHead: head1, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"root_rev": 1},
		Fields:        ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
	})
	rep, err = sRoot2.Submit(ctx, authOpEnv.RawBytes, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed || rep.Outcome.Seq != 2 {
		t.Fatalf("operator_key_authorize failed: %+v, err=%v", rep, err)
	}
	head2 := rep.Head

	// 3. Equal 1-of-2 roots: root2 replaces root1 with fresh root3 (seq 3).
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	root3, _ := ldrcrypto.GenerateEd25519Key()
	r1CBOR, _ := fx.root1.PublicKey().ToCBOR()
	r3CBOR, _ := root3.PublicKey().ToCBOR()
	repRootEnv := signWireIntent(t, fx.root2, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: root2Prin,
		OpID: "replace-root-1", OpType: "root_member_replace",
		AuthEpoch: 1, SeenSeq: 2, SeenHead: head2, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"root_rev": 2},
		Fields: ldrcrypto.Map{
			{Key: "new_root_key", Value: r3CBOR},
			{Key: "old_root_key", Value: r1CBOR},
		},
	})
	rep, err = sRoot2.Submit(ctx, repRootEnv.RawBytes, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed || rep.Outcome.Seq != 3 {
		t.Fatalf("root_member_replace failed: %+v, err=%v", rep, err)
	}
	head3 := rep.Head

	// Replaced root1 MUST immediately receive unresolved/revoked on both its
	// existing open session (anchor/query/retry) AND on a fresh DialSession!
	if ar, err := sRoot1.AnchorRequest(ctx); err != nil || ar.Class != ldrcore.ClassUnresolved || ar.Code != "revoked" {
		t.Fatalf("replaced root1 anchor on open session: got %+v, err=%v", ar, err)
	}
	if _, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, root1Prin, fx.root1); err == nil {
		t.Fatalf("replaced root1 unexpectedly opened new session")
	} else {
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Class != ldrcore.ClassUnresolved || ae.Code != "revoked" {
			t.Fatalf("expected AuthError(unresolved/revoked), got %v", err)
		}
	}

	// 4. Operator enrolls two credentials (cA and cB), plus tests cred_id mismatch rejection.
	opPrin := ldrcrypto.OperatorPrincipal(opKey.PublicKey())
	sOp, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, opPrin, opKey)
	if err != nil {
		t.Fatalf("DialSession(op): %v", err)
	}
	defer sOp.Close()

	cASig, _ := ldrcrypto.GenerateEd25519Key()
	cAEnc, _ := ldrcrypto.GenerateX25519Key()
	cAID, _ := ldrcrypto.DeriveCredID(cASig.PublicKey(), cAEnc.PublicKey())
	cBSig, _ := ldrcrypto.GenerateEd25519Key()
	cBEnc, _ := ldrcrypto.GenerateX25519Key()
	cBID, _ := ldrcrypto.DeriveCredID(cBSig.PublicKey(), cBEnc.PublicKey())

	enrollCred := func(opID string, authEp, seenSeq uint64, seenHead [32]byte, cid [32]byte, sigPK, encPK ldrcrypto.PublicKey, ns string, reqByte byte) SubmitReply {
		skC, _ := sigPK.ToCBOR()
		ekC, _ := encPK.ToCBOR()
		env := signWireIntent(t, opKey, WireIntentInput{
			ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
			Origin: ldrcore.OriginOperator, Principal: opPrin,
			OpID: opID, OpType: "credential_enroll",
			AuthEpoch: authEp, SeenSeq: seenSeq, SeenHead: seenHead, ValidityMS: 60_000,
			PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
			Fields: ldrcrypto.Map{
				{Key: "cred_id", Value: cid[:]},
				{Key: "encryption_key", Value: ekC},
				{Key: "grant", Value: ldrcrypto.Map{
					{Key: "actor_limit", Value: uint64(4)},
					{Key: "namespace_id", Value: ns},
					{Key: "reader", Value: true},
				}},
				{Key: "join_request_digest", Value: bytes.Repeat([]byte{reqByte}, 32)},
				{Key: "join_request_id", Value: bytes.Repeat([]byte{reqByte}, 16)},
				{Key: "signing_key", Value: skC},
			},
		})
		r, err := sOp.Submit(ctx, env.RawBytes, nil, nil)
		if err != nil {
			t.Fatalf("enroll %s: %v", opID, err)
		}
		return r
	}

	// Mismatched cred_id MUST be caught cryptographically and durably rejected invalid.
	badCID := cAID
	badCID[0] ^= 0xff
	badEnroll := enrollCred("enroll-bad", 2, 3, head3, badCID, cASig.PublicKey(), cAEnc.PublicKey(), "ns-bad", 0x99)
	if badEnroll.Class != ldrcore.ClassOutcome || badEnroll.Outcome.Kind != ldrcore.Rejected || badEnroll.Outcome.Reason != "invalid" {
		t.Fatalf("mismatched cred_id should be durable rejected/invalid, got %+v", badEnroll)
	}

	// Valid enrollments for cA (seq 4) and cB (seq 5).
	repA := enrollCred("enroll-a", 2, 3, head3, cAID, cASig.PublicKey(), cAEnc.PublicKey(), "ns-a", 0x0a)
	if repA.Outcome.Kind != ldrcore.Committed || repA.Outcome.Seq != 4 {
		t.Fatalf("enroll cA failed: %+v", repA)
	}
	repB := enrollCred("enroll-b", 3, 4, repA.Head, cBID, cBSig.PublicKey(), cBEnc.PublicKey(), "ns-b", 0x0b)
	if repB.Outcome.Kind != ldrcore.Committed || repB.Outcome.Seq != 5 {
		t.Fatalf("enroll cB failed: %+v", repB)
	}
	head5 := repB.Head

	// 5. Operator activates epoch 1 with real RFC 9180 HPKE wraps (seq 6).
	epochKey, _ := ldrcrypto.GenerateEpochKey()
	rsDigest, _ := ldrcrypto.ReaderSetDigest([][32]byte{cAID, cBID})
	type rInfo struct {
		id  [32]byte
		enc *ldrcrypto.X25519PrivateKey
	}
	readers := []rInfo{{cAID, cAEnc}, {cBID, cBEnc}}
	sort.Slice(readers, func(i, j int) bool { return bytes.Compare(readers[i].id[:], readers[j].id[:]) < 0 })

	opIDBytes := []byte("act-epoch-1")
	manifest := make([]ldrcrypto.WrapManifestEntry, 0, 2)
	wraps := make(map[[32]byte][]byte, 2)
	wCtxByCred := map[[32]byte]ldrcrypto.EpochWrapContext{}
	for _, r := range readers {
		wctx := ldrcrypto.EpochWrapContext{
			LineID: fx.lineID, Generation: 1, ProfileDigest: fx.profDigest,
			NewEpoch: 1, ExpectEpoch: 0, AuthEpoch: 4,
			OpIdentityBytes: opIDBytes, RecipientCredID: r.id,
			RecipientEncKey: r.enc.PublicKey(), ReaderSetDigest: rsDigest,
		}
		wb, err := ldrcrypto.WrapEpochKey(epochKey, wctx)
		if err != nil {
			t.Fatal(err)
		}
		wc, _ := ldrcrypto.CommitWrap(wb)
		manifest = append(manifest, ldrcrypto.WrapManifestEntry{CredID: r.id, Commit: wc})
		wraps[r.id] = wb
		wCtxByCred[r.id] = wctx
	}
	actEnv := signWireIntent(t, opKey, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "act-1", OpType: "key_epoch_activate",
		AuthEpoch: 4, KeyEpoch: 0, SeenSeq: 5, SeenHead: head5, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"key_epoch": 0},
		Manifest:      manifest,
	})
	// Missing wrap sidecars on lookup miss MUST fail admission (nothing recorded!).
	missRep, err := sOp.Submit(ctx, actEnv.RawBytes, nil, nil)
	if err != nil || missRep.Class != ldrcore.ClassAdmission || missRep.Code != "missing_or_corrupt_sidecar" {
		t.Fatalf("missing wrap sidecars should fail admission, got %+v, err=%v", missRep, err)
	}
	// Now submit with complete wraps -> commits at seq 6!
	actRep, err := sOp.Submit(ctx, actEnv.RawBytes, nil, wraps)
	if err != nil || actRep.Outcome.Kind != ldrcore.Committed || actRep.Outcome.Seq != 6 {
		t.Fatalf("key_epoch_activate failed: %+v, err=%v", actRep, err)
	}
	head6 := actRep.Head

	// 6. Credentials cA and cB connect over TLS 1.3, declare actors, open call + encrypted payload!
	cAPrin := ldrcrypto.CredentialPrincipal(cAID)
	cBPrin := ldrcrypto.CredentialPrincipal(cBID)
	sA, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, cAPrin, cASig)
	if err != nil {
		t.Fatalf("DialSession(cA): %v", err)
	}
	defer sA.Close()
	sB, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, cBPrin, cBSig)
	if err != nil {
		t.Fatalf("DialSession(cB): %v", err)
	}
	defer sB.Close()

	// P7 S7: cA MUST NOT submit an intent signed by cB!
	declBEnv := signWireIntent(t, cBSig, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginCredential, Principal: cBPrin,
		OpID: "decl-b", OpType: "actor_declare",
		AuthEpoch: 4, SeenSeq: 6, SeenHead: head6, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "actor_id", Value: "bob"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-b"}},
	})
	if mism, err := sA.Submit(ctx, declBEnv.RawBytes, nil, nil); err != nil || mism.Class != ldrcore.ClassAdmission || mism.Code != "submitter_mismatch" {
		t.Fatalf("cross-principal submit should fail submitter_mismatch, got %+v, err=%v", mism, err)
	}

	declAEnv := signWireIntent(t, cASig, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginCredential, Principal: cAPrin,
		OpID: "decl-a", OpType: "actor_declare",
		AuthEpoch: 4, SeenSeq: 6, SeenHead: head6, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "actor_id", Value: "alice"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-a"}},
	})
	rDeclA, _ := sA.Submit(ctx, declAEnv.RawBytes, nil, nil)
	rDeclB, _ := sB.Submit(ctx, declBEnv.RawBytes, nil, nil)
	if rDeclA.Outcome.Seq != 7 || rDeclB.Outcome.Seq != 8 {
		t.Fatalf("actor declarations failed: A=%+v B=%+v", rDeclA, rDeclB)
	}

	// Open an encrypted call from alice -> bob (seq 9).
	callCtx := []byte("call-open-aad-context-v1")
	secretTurn := []byte("Confidential Phase B turn over pinned TLS 1.3!")
	payloadPkg, err := ldrcrypto.SealPayload(epochKey, callCtx, secretTurn)
	if err != nil {
		t.Fatal(err)
	}
	pCommit, _ := ldrcrypto.CommitPayload(payloadPkg)
	openEnv := signWireIntent(t, cASig, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginActor, Principal: cAPrin,
		ActorID: "alice", BindingGen: 1,
		OpID: "open-1", OpType: "call_open",
		AuthEpoch: 4, KeyEpoch: 1, SeenSeq: 8, SeenHead: rDeclB.Head, ValidityMS: 60_000,
		PayloadCommit: pCommit,
		Fields:        ldrcrypto.Map{{Key: "call_id", Value: "call-001"}, {Key: "to", Value: "bob"}},
	})
	openRep, err := sA.Submit(ctx, openEnv.RawBytes, payloadPkg, nil)
	if err != nil || openRep.Outcome.Kind != ldrcore.Committed || openRep.Outcome.Seq != 9 {
		t.Fatalf("call_open failed: %+v, err=%v", openRep, err)
	}

	// P5 §5.2: Retrying the EXACT signed envelope WITHOUT sidecars MUST return the original receipt!
	retryRep, err := sA.Submit(ctx, openEnv.RawBytes, nil, nil)
	if err != nil || retryRep.Class != ldrcore.ClassOutcome || !retryRep.Original || retryRep.Outcome.Seq != 9 {
		t.Fatalf("P5 sidecar-free retry failed: %+v, err=%v", retryRep, err)
	}

	// Different bytes under same (gen, signer, seen_seq=8, op_id="open-1") MUST return duplicate_mismatch!
	diffEnv := signWireIntent(t, cASig, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginActor, Principal: cAPrin,
		ActorID: "alice", BindingGen: 1,
		OpID: "open-1", OpType: "call_open",
		AuthEpoch: 4, KeyEpoch: 1, SeenSeq: 8, SeenHead: rDeclB.Head, ValidityMS: 60_000,
		PayloadCommit: pCommit,
		Fields:        ldrcrypto.Map{{Key: "call_id", Value: "call-OTHER"}, {Key: "to", Value: "bob"}},
	})
	mismRep, err := sA.Submit(ctx, diffEnv.RawBytes, payloadPkg, nil)
	if err != nil || mismRep.Class != ldrcore.ClassMismatch {
		t.Fatalf("expected duplicate_mismatch, got %+v, err=%v", mismRep, err)
	}

	// Bob fetches wrap sidecar, unwraps epoch key via HPKE, fetches payload sidecar, decrypts turn!
	var bobWrapCommit ldrcrypto.Commitment
	for _, wm := range manifest {
		if wm.CredID == cBID {
			bobWrapCommit = wm.Commit
		}
	}
	bobWrapBytes, err := sB.FetchSidecar(ctx, ldrstore.SidecarWrap, bobWrapCommit.Digest)
	if err != nil {
		t.Fatalf("FetchSidecar(wrap): %v", err)
	}
	bobEpochKey, err := ldrcrypto.UnwrapEpochKey(cBEnc, bobWrapBytes, wCtxByCred[cBID])
	if err != nil {
		t.Fatalf("UnwrapEpochKey(bob): %v", err)
	}
	fetchedPayload, err := sB.FetchSidecar(ctx, ldrstore.SidecarPayload, pCommit.Digest)
	if err != nil {
		t.Fatalf("FetchSidecar(payload): %v", err)
	}
	decryptedTurn, err := ldrcrypto.OpenPayload(bobEpochKey, callCtx, fetchedPayload)
	if err != nil || !bytes.Equal(decryptedTurn, secretTurn) {
		t.Fatalf("bob failed to decrypt turn: %q, err=%v", decryptedTurn, err)
	}

	// 7. Cross-connection session hijack MUST fail (session_id bound to TLS 1.3 cb!).
	// Send sA's session_id over sB's distinct TLS 1.3 connection.
	hijackReq := ldrcrypto.Map{
		{Key: "from_seq", Value: uint64(1)},
		{Key: "max_count", Value: uint64(10)},
		{Key: "req_id", Value: uint64(999)},
		{Key: "session_id", Value: sA.SessionID()},
		{Key: "v", Value: uint64(1)},
	}
	hijackResp, err := sB.postCBOR(ctx, "log", hijackReq)
	if err != nil {
		t.Fatalf("hijack postCBOR: %v", err)
	}
	if hijackResp["code"] != "invalid_session" {
		t.Fatalf("cross-connection session hijack was NOT blocked: %#v", hijackResp)
	}

	// 8. Demand-driven time_anchor (advance clock past FreshnessMS = 10s -> seq 10).
	fx.clock.wall += 15_000
	fx.clock.mono += 15_000
	ar, err := sA.AnchorRequest(ctx)
	if err != nil || !ar.Wrote || ar.Seq != 10 {
		t.Fatalf("expected demand-driven time_anchor at seq 10, got %+v, err=%v", ar, err)
	}

	// 9. Clock uncertainty suspends new anchors/submits while preserving historical Query!
	fx.clock.wall += 120_000 // huge forward jump with 0 mono progress!
	if uncAnchor, err := sA.AnchorRequest(ctx); err != nil || uncAnchor.Class != ldrcore.ClassAdmission || uncAnchor.Code != "clock_uncertain" {
		t.Fatalf("expected clock_uncertain on anchor, got %+v, err=%v", uncAnchor, err)
	}
	openDigest, _ := openEnv.Digest()
	cATok, _ := PrincipalToken(cAPrin)
	qRep, err := sA.Query(ctx, ldrstore.StoredOpKey{Generation: 1, Signer: cATok, SeenSeq: 8, OpID: "open-1"}, openDigest)
	if err != nil || qRep.Class != ldrcore.ClassOutcome || !qRep.Original || qRep.Outcome.Seq != 9 {
		t.Fatalf("historical Query must keep working while clock_uncertain, got %+v, err=%v", qRep, err)
	}
	// Resume clock cleanly.
	cg, _ := fx.engine.ClockGuardFor(fx.lineID)
	if err := cg.ConfirmResume(); err != nil {
		t.Fatalf("ConfirmResume: %v", err)
	}

	// 10. Compact retires expired hot entries while keeping permanent log_index!
	fx.clock.wall += 700_000
	fx.clock.mono += 700_000
	compacted, err := fx.engine.Compact(fx.lineID)
	if err != nil || compacted == 0 {
		t.Fatalf("Compact expected > 0 retired hot entries, got (%d, %v)", compacted, err)
	}
	// Close sessions before server restart.
	sRoot1.Close()
	sRoot2.Close()
	sOp.Close()
	sA.Close()
	sB.Close()

	// 11. FULL PROCESS RESTART: reopen FileStore + NewRelayEngine (verifies every frame,
	//     real Ed25519 + P-256 signature, and chain head from seq 1..10!).
	fx.restart(t)

	// Reconnect as cB, fetch full O25 control-only log (1..10), and query compacted seq 9!
	sB2, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, cBPrin, cBSig)
	if err != nil {
		t.Fatalf("DialSession(cB) after restart: %v", err)
	}
	defer sB2.Close()
	logFrames, err := sB2.ControlLog(ctx, 1, 50)
	if err != nil || len(logFrames) != 10 {
		t.Fatalf("ControlLog after restart: len=%d, err=%v", len(logFrames), err)
	}
	if logFrames[0].OpType != "line_init" || logFrames[8].OpType != "call_open" || logFrames[9].OpType != "time_anchor" {
		t.Fatalf("unexpected frame types after restart: [0]=%s [8]=%s [9]=%s", logFrames[0].OpType, logFrames[8].OpType, logFrames[9].OpType)
	}

	// Historical query by operator reconciler for compacted seq 9 STILL returns receipt after restart!
	sOp2, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, opPrin, opKey)
	if err != nil {
		t.Fatalf("DialSession(op) after restart: %v", err)
	}
	defer sOp2.Close()
	qAfter, err := sOp2.Query(ctx, ldrstore.StoredOpKey{Generation: 1, Signer: cATok, SeenSeq: 8, OpID: "open-1"}, openDigest)
	if err != nil || qAfter.Class != ldrcore.ClassOutcome || !qAfter.Original || qAfter.Outcome.Seq != 9 {
		t.Fatalf("reconciler Query after compact+restart failed: %+v, err=%v", qAfter, err)
	}

	// Verify /v1/health endpoint over TLS 1.3.
	tlsCfg, _ := ClientTLSConfig(fx.origin)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := hc.Get(fx.origin.URL + "/v1/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/health failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// Verify Engine.Status reports accurate head and line metadata.
	statuses := fx.engine.Status()
	if len(statuses) != 1 || statuses[0].LineID != hex.EncodeToString(fx.lineID) || statuses[0].HeadSeq != 10 {
		t.Fatalf("unexpected Status(): %+v", statuses)
	}

	// 12. Mid-session revocation: open session for cA, operator revokes cA,
	//     and cA's already-open session immediately receives revoked on Anchor,
	//     Query, ControlLog, and FetchSidecar!
	sA2, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, cAPrin, cASig)
	if err != nil {
		t.Fatalf("DialSession(cA) before revoke: %v", err)
	}
	defer sA2.Close()

	anBefore, err := sOp2.AnchorRequest(ctx)
	if err != nil || anBefore.Class != ldrcore.ClassOutcome {
		t.Fatalf("anchor before revoke: %+v, err=%v", anBefore, err)
	}
	revEnv := signWireIntent(t, opKey, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "rev-cA", OpType: "credential_revoke",
		AuthEpoch: 4, SeenSeq: anBefore.Seq, SeenHead: anBefore.Head, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "cred_id", Value: cAID[:]}},
	})
	revRep, err := sOp2.Submit(ctx, revEnv.RawBytes, nil, nil)
	if err != nil || revRep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("credential_revoke(cA) failed: %+v, err=%v", revRep, err)
	}
	if arRev, err := sA2.AnchorRequest(ctx); err != nil || arRev.Class != ldrcore.ClassUnresolved || arRev.Code != "revoked" {
		t.Fatalf("mid-session revoked cA anchor: got %+v, err=%v", arRev, err)
	}
	if qRev, err := sA2.Query(ctx, ldrstore.StoredOpKey{Generation: 1, Signer: cATok, SeenSeq: 8, OpID: "open-1"}, openDigest); err != nil || qRev.Class != ldrcore.ClassUnresolved || qRev.Code != "revoked" {
		t.Fatalf("mid-session revoked cA query: got %+v, err=%v", qRev, err)
	}
	if _, err := sA2.ControlLog(ctx, 1, 10); err == nil {
		t.Fatalf("mid-session revoked cA ControlLog succeeded")
	}
	if _, err := sA2.FetchSidecar(ctx, ldrstore.SidecarPayload, pCommit.Digest); err == nil {
		t.Fatalf("mid-session revoked cA FetchSidecar succeeded")
	}

	// 13. Single-use challenge replay MUST fail.
	pCBOR, _ := cBPrin.ToCBOR()
	chResp, err := sB2.postCBOR(ctx, "session/challenge", ldrcrypto.Map{
		{Key: "generation", Value: uint64(1)},
		{Key: "line_id", Value: fx.lineID},
		{Key: "principal", Value: pCBOR},
		{Key: "profile_digest", Value: fx.profDigest[:]},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sid2 := chResp["session_id"].([]byte)
	nonce2 := chResp["server_nonce"].([]byte)
	cb2 := sB2.ChannelBinding()
	sig2, err := ldrcrypto.SignSessionAuth(cBSig, ldrcrypto.SessionAuthMessage{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Principal: cBPrin, RelayOrigin: fx.origin,
		SessionID: sid2, ServerNonce: nonce2, ChannelBinding: cb2[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	authPayload := ldrcrypto.Map{
		{Key: "generation", Value: uint64(1)},
		{Key: "session_id", Value: sid2},
		{Key: "sig", Value: sig2},
		{Key: "v", Value: uint64(1)},
	}
	firstAuth, err := sB2.postCBOR(ctx, "session/auth", authPayload)
	if err != nil || firstAuth["class"] != "authenticated" {
		t.Fatalf("first challenge auth failed: %#v, err=%v", firstAuth, err)
	}
	replayAuth, err := sB2.postCBOR(ctx, "session/auth", authPayload)
	if err != nil || replayAuth["code"] != "invalid_challenge" {
		t.Fatalf("replayed single-use challenge was NOT blocked: %#v, err=%v", replayAuth, err)
	}

	// 14. Unsupported app_authenticated_session MUST fail closed until specified.
	appOrigin := fx.origin
	appOrigin.TLSPolicy = ldrcrypto.TLSPolicyWebPKI
	appOrigin.TLSPin = nil
	appOrigin.SessionBinding = ldrcrypto.SessionBindingAppAuth
	if _, err := ClientTLSConfig(appOrigin); !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatalf("expected ErrUnsupportedTransport for app_authenticated_session, got %v", err)
	}
}
