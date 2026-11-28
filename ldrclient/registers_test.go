package ldrclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

type registerTestRig struct {
	env      *testRelayEnv
	admin    *Client
	sOp      *ldrrelay.SessionClient
	opKey    *SigningKeyMaterial
	aliceDir string
	alice    *Client
	sAlice   *ldrrelay.SessionClient
	bobDir   string
	bob      *Client
	sBob     *ldrrelay.SessionClient
	enroll   func(ns string, ck *CredentialKeyBundle, limit uint64, seed byte) (ldrcrypto.JoinGrant, []byte, [32]byte)
}

func newRegisterTestRig(t *testing.T, aliceLimit, bobLimit uint64) *registerTestRig {
	t.Helper()
	env := startTestRelay(t)
	ctx := context.Background()

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
	t.Cleanup(func() { _ = admin.Close() })
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
	t.Cleanup(func() { sOp.Close() })

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

	enrollCred("ns-op", opCredKeys, 0, 0x30)
	aliceCK, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	bobCK, _ := GenerateCredentialKeys(ldrcrypto.AlgEd25519)
	ag, arid, ardig := enrollCred("ns-alice", aliceCK, aliceLimit, 0x31)
	bg, brid, brdig := enrollCred("ns-bob", bobCK, bobLimit, 0x32)

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
	if err := bob.VerifyEnrollmentAndActivate(ctx, sBob); err != nil {
		t.Fatalf("bob activate: %v", err)
	}

	rig := &registerTestRig{
		env: env, admin: admin, sOp: sOp, opKey: opKey,
		aliceDir: aliceDir, alice: alice, sAlice: sAlice,
		bobDir: bobDir, bob: bob, sBob: sBob, enroll: enrollCred,
	}
	t.Cleanup(func() {
		if rig.sAlice != nil {
			rig.sAlice.Close()
		}
		if rig.alice != nil {
			_ = rig.alice.Close()
		}
		if rig.sBob != nil {
			rig.sBob.Close()
		}
		if rig.bob != nil {
			_ = rig.bob.Close()
		}
	})
	return rig
}

func TestClientAdvisoryRegistersActivationPersistenceReconcileAndVerification(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	// Alice declares actor "alice-1" and publishes presence twice.
	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "alice-1", "ns-alice"); err != nil {
		t.Fatalf("actor_declare: %v", err)
	}

	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"busy":"building"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister 1: rep=%+v err=%v", rep, err)
	}
	_, seqAfterFirst, _ := rig.alice.Checkpoint()

	// Second publish reuses the SAME writer_rev (no redundant register_activate commit!).
	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"busy":"testing"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister 2: rep=%+v err=%v", rep, err)
	}
	_, seqAfterSecond, _ := rig.alice.Checkpoint()
	if seqAfterSecond != seqAfterFirst {
		t.Fatalf("expected no redundant register_activate commit: seq %d -> %d", seqAfterFirst, seqAfterSecond)
	}

	// Reopen alice from disk -> persisted counter & incarnation survive reopen with zero redundant activation!
	rig.sAlice.Close()
	if err := rig.alice.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	rig.alice, err = OpenClient(rig.aliceDir)
	if err != nil {
		t.Fatalf("OpenClient(alice): %v", err)
	}
	rig.sAlice, err = rig.alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}

	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"busy":"reopened"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister after reopen: rep=%+v err=%v", rep, err)
	}
	_, seqAfterReopen, _ := rig.alice.Checkpoint()
	if seqAfterReopen != seqAfterFirst {
		t.Fatalf("expected persisted register writer to avoid re-activation across reopen: seq %d -> %d", seqAfterFirst, seqAfterReopen)
	}

	// Bob syncs and reads Alice's verified decrypted presence register.
	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}
	regs, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence")
	if err != nil {
		t.Fatalf("bob.ReadRegisters: %v", err)
	}
	if len(regs) != 1 || regs[0].Actor != "alice-1" || regs[0].Historical ||
		regs[0].ReadStatus != ldrcore.ReadOK || string(regs[0].Plaintext) != `{"busy":"reopened"}` ||
		regs[0].WriterRev != 1 || regs[0].Counter != 3 {
		t.Fatalf("unexpected verified register: %+v", regs)
	}

	// Revoke Alice's credential -> Bob syncs and locally computes Historical=true on Alice's cached register!
	rig.env.tick(1000)
	if _, err := rig.admin.Sync(ctx, rig.sOp); err != nil {
		t.Fatal(err)
	}
	aliceCID, _ := rig.alice.CredID()
	if _, err := rig.admin.SubmitCredentialRevoke(ctx, rig.sOp, aliceCID); err != nil {
		t.Fatalf("revoke alice: %v", err)
	}
	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}
	regsAfterRevoke, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence")
	if err != nil || len(regsAfterRevoke) != 1 || !regsAfterRevoke[0].Historical {
		t.Fatalf("expected local Historical=true after alice revocation, got %+v err=%v", regsAfterRevoke, err)
	}
}

// Finding 1 regression:
//   - Trusted-writer fast path in EnsureRegisterActivated and signing path in
//     PublishRegister enforce local Rule 8 credential stops before signing or sending.
//   - Bound unresolved/revoked replies on PutRegister and ListRegisters durably
//     record the Rule 8 stop in outbox.cbor (surviving reopen).
//   - ReadRegisters NEVER infers revocation from an unvalidated error substring.
func TestClientRegistersRule8StopsAndValidatedRevocation(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "alice-1", "ns-alice"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"busy":"ok"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("initial PublishRegister: %+v %v", rep, err)
	}

	// 1a. Unvalidated error text containing "revoked" on ReadRegisters MUST NOT
	//     trigger ErrKeyRevoked or record a Rule 8 stop!
	rig.env.setHTTPHook(func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/register/list") {
			raw, _ := io.ReadAll(r.Body)
			dec, _ := ldrcrypto.UnmarshalCBORDefault(raw)
			m, _ := dec.(map[string]any)
			sid, _ := ldrcrypto.MapBytesLen(m, "session_id", 16)
			reqID, _ := ldrcrypto.MapUint(m, "req_id")
			reqDig := sha256.Sum256(raw)
			// Admission error (NOT unresolved/revoked) whose code contains "revoked".
			enc, _ := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
				{Key: "class", Value: ldrcore.ClassAdmission},
				{Key: "code", Value: "spurious_revoked_hint"},
				{Key: "line_id", Value: rig.env.lineID},
				{Key: "req_digest", Value: reqDig[:]},
				{Key: "req_id", Value: reqID},
				{Key: "session_gen", Value: uint64(1)},
				{Key: "session_id", Value: sid},
				{Key: "v", Value: uint64(1)},
			})
			w.Header().Set("Content-Type", "application/cbor")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(enc)
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence")
	rig.env.setHTTPHook(nil)
	if err == nil || errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("unvalidated error substring 'revoked' must not return ErrKeyRevoked, got %v", err)
	}
	if len(rig.bob.Stops()) != 0 {
		t.Fatalf("unvalidated error substring must not persist Rule 8 stop, got %+v", rig.bob.Stops())
	}

	// 1b. Revoke Alice on relay while Alice holds an existing session & trusted writer.
	rig.env.tick(1000)
	if _, err := rig.admin.Sync(ctx, rig.sOp); err != nil {
		t.Fatal(err)
	}
	aliceCID, _ := rig.alice.CredID()
	if _, err := rig.admin.SubmitCredentialRevoke(ctx, rig.sOp, aliceCID); err != nil {
		t.Fatal(err)
	}

	// Alice calls PublishRegister on the existing session -> bound unresolved/revoked reply
	// MUST return ErrKeyRevoked AND persist a durable Rule 8 stop in outbox.cbor!
	if _, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"busy":"post-revoke"}`)); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked on revoked PublishRegister, got %v", err)
	}
	if len(rig.alice.Stops()) == 0 {
		t.Fatal("expected durable Rule 8 stop recorded after validated unresolved/revoked PutRegister reply")
	}

	// With the Rule 8 stop recorded, EnsureRegisterActivated fast path, PublishRegister,
	// and ReadRegisters MUST all fail locally with ErrKeyRevoked and ZERO HTTP requests!
	var reqCount atomic.Int64
	rig.env.setHTTPHook(func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		next.ServeHTTP(w, r)
	})
	if err := rig.alice.EnsureRegisterActivated(ctx, rig.sAlice, "alice-1", "presence"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("EnsureRegisterActivated fast path ignored Rule 8 stop: %v", err)
	}
	if _, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"busy":"blocked"}`)); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("PublishRegister ignored Rule 8 stop: %v", err)
	}
	if _, err := rig.alice.ReadRegisters(ctx, rig.sAlice, "presence"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("ReadRegisters ignored Rule 8 stop: %v", err)
	}
	if got := reqCount.Load(); got != 0 {
		t.Fatalf("expected 0 HTTP requests after Rule 8 stop, got %d", got)
	}

	// Reopen Alice from disk -> Rule 8 stop persists across restart and still blocks fast path with 0 requests.
	rig.env.setHTTPHook(nil)
	if err := rig.alice.Close(); err != nil {
		t.Fatal(err)
	}
	rig.alice, err = OpenClient(rig.aliceDir)
	if err != nil {
		t.Fatal(err)
	}
	rig.env.setHTTPHook(func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		next.ServeHTTP(w, r)
	})
	if err := rig.alice.EnsureRegisterActivated(ctx, rig.sAlice, "alice-1", "presence"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("reopened EnsureRegisterActivated fast path ignored persisted Rule 8 stop: %v", err)
	}
	if got := reqCount.Load(); got != 0 {
		t.Fatalf("expected 0 HTTP requests after reopen with Rule 8 stop, got %d", got)
	}
	rig.env.setHTTPHook(nil)

	// 1c. Revoke Bob while Bob holds an existing session -> validated unresolved/revoked on
	//     ReadRegisters MUST persist a Rule 8 stop and return ErrKeyRevoked!
	bobCID, _ := rig.bob.CredID()
	rig.env.tick(1000)
	if _, err := rig.admin.SubmitCredentialRevoke(ctx, rig.sOp, bobCID); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked on validated revoked ListRegisters reply, got %v", err)
	}
	if len(rig.bob.Stops()) == 0 {
		t.Fatal("expected durable Rule 8 stop recorded after validated unresolved/revoked ListRegisters reply")
	}
}

// Finding 2 regression:
//   - Reject contradictory current-revision incarnation with ErrViolation.
//   - Reject contradictory current-revision binding_gen after actor_move with ErrViolation.
//   - Distinguish and accept genuine pre-move values and genuine superseded earlier writers
//     as Historical=true.
func TestClientRegistersIncarnationBindingGenAndSupersededValidation(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "shared-actor", "ns-alice"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "shared-actor", "presence", []byte(`{"v":1}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("alice publish 1: %+v %v", rep, err)
	}
	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}
	aliceCID, _ := rig.alice.CredID()
	bobCID, _ := rig.bob.CredID()
	epKey := rig.alice.epochs.Keys[1]

	// Helper to craft a validly signed register entry (using signer) and inject it into /register/list.
	craftEntry := func(signer ldrcrypto.Signer, cid [32]byte, bgen, wrev uint64, inc string, counter uint64, body string) ldrcrypto.Map {
		cBytes, err := ldrcrypto.RegisterPayloadContextBytes(rig.env.profDigest, rig.env.lineID, 1, "presence", "shared-actor", cid, bgen, wrev, inc, 1, counter)
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := ldrcrypto.SealPayload(epKey, cBytes, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		cm, _ := ldrcrypto.CommitPayload(pkg)
		envBytes, err := ldrcrypto.SignRegisterEnvelope(signer, ldrcrypto.RegisterEnvelope{
			Version: 1, LineID: rig.env.lineID, Generation: 1, ProfileDigest: rig.env.profDigest,
			Register: "presence", ActorID: "shared-actor", CredID: cid,
			BindingGen: bgen, WriterRev: wrev, Incarnation: inc, KeyEpoch: 1, Counter: counter,
			PayloadCommit: cm,
		})
		if err != nil {
			t.Fatal(err)
		}
		return ldrcrypto.Map{
			{Key: "accepted_at_ms", Value: uint64(rig.env.wallMS.Load())},
			{Key: "actor", Value: "shared-actor"},
			{Key: "envelope", Value: envBytes},
			{Key: "historical", Value: false}, // dishonest relay claims current!
			{Key: "payload", Value: pkg},
			{Key: "register", Value: "presence"},
		}
	}

	injectList := func(entry ldrcrypto.Map) {
		rig.env.setHTTPHook(func(next http.Handler, w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/register/list") {
				raw, _ := io.ReadAll(r.Body)
				dec, _ := ldrcrypto.UnmarshalCBORDefault(raw)
				m, _ := dec.(map[string]any)
				sid, _ := ldrcrypto.MapBytesLen(m, "session_id", 16)
				reqID, _ := ldrcrypto.MapUint(m, "req_id")
				reqDig := sha256.Sum256(raw)
				enc, _ := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
					{Key: "class", Value: "ok"},
					{Key: "entries", Value: []any{entry}},
					{Key: "has_more", Value: false},
					{Key: "line_id", Value: rig.env.lineID},
					{Key: "next_cursor", Value: ""},
					{Key: "req_digest", Value: reqDig[:]},
					{Key: "req_id", Value: reqID},
					{Key: "session_gen", Value: uint64(1)},
					{Key: "session_id", Value: sid},
					{Key: "v", Value: uint64(1)},
				})
				w.Header().Set("Content-Type", "application/cbor")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(enc)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	w1 := rig.bob.State().Line.RegisterWriters["shared-actor/presence"]

	// 2a. Contradictory current-revision incarnation (writer_rev == w1.WriterRev == 1, wrong incarnation) MUST fail!
	injectList(craftEntry(rig.alice.credKeys.Signing.Signer, aliceCID, 1, uint64(w1.WriterRev), "inc-contradictory", 99, `{"v":"forged"}`))
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrViolation) {
		t.Fatalf("expected ErrViolation for contradictory current-revision incarnation, got %v", err)
	}
	rig.env.setHTTPHook(nil)

	// 2b. Move "shared-actor" from Alice (BindingGen 1) to Bob (BindingGen 2).
	//     Committed writer w1 STILL has WriterRev=1, BindingGen=1!
	rig.env.tick(1000)
	if err := rig.admin.PrepareForMutation(ctx, rig.sOp, ldrcrypto.PrincipalOperator); err != nil {
		t.Fatal(err)
	}
	aState := rig.admin.State().Line.Actors["shared-actor"]
	moveOp, err := rig.admin.ComposeAndPersist(ComposeParams{
		Action: "move-shared-actor", Origin: ldrcore.OriginOperator, OpType: "actor_move",
		Expect: ldrcrypto.ExpectMap{"binding_gen": uint64(aState.BindingGen)},
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "shared-actor"}, {Key: "to_cred", Value: bobCID[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := rig.admin.Send(ctx, rig.sOp, moveOp); err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("actor_move: %+v %v", rep, err)
	}
	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}

	// Forged envelope naming w1.WriterRev=1 with actor's NEW BindingGen=2 (contradicting w1.BindingGen=1) MUST be rejected!
	injectList(craftEntry(rig.bob.credKeys.Signing.Signer, bobCID, 2, uint64(w1.WriterRev), w1.Incarnation, 1, `{"v":"forged-bgen"}`))
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrViolation) {
		t.Fatalf("expected ErrViolation for writer_rev contradicting committed writer BindingGen, got %v", err)
	}
	rig.env.setHTTPHook(nil)

	// 2b-extra. Wrong owning credential on same writer_rev=1 & binding_gen=1 after actor_move
	//           (Bob signs under w1.WriterRev=1, w1.BindingGen=1, w1.Incarnation, even though Alice committed w1!) MUST be rejected!
	injectList(craftEntry(rig.bob.credKeys.Signing.Signer, bobCID, 1, uint64(w1.WriterRev), w1.Incarnation, 1, `{"v":"wrong-owner-cred"}`))
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrViolation) {
		t.Fatalf("expected ErrViolation for non-activating credential on writer_rev=1 after actor_move, got %v", err)
	}
	rig.env.setHTTPHook(nil)

	// 2c. Genuine pre-move cached value on the real relay (WriterRev=1, BindingGen=1, Incarnation=w1.Incarnation
	//     while actor.BindingGen is now 2) MUST be accepted as Historical=true!
	regsPreMove, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence")
	if err != nil || len(regsPreMove) != 1 || !regsPreMove[0].Historical || string(regsPreMove[0].Plaintext) != `{"v":1}` {
		t.Fatalf("expected genuine pre-move value accepted as Historical=true, got %+v err=%v", regsPreMove, err)
	}

	// 2d. Bob activates writer_rev=2 under BindingGen=2. A relay serving the genuine superseded
	//     writer_rev=1 value (from BindingGen=1, Alice) MUST be accepted as Historical=true (NOT current and NOT ErrViolation)!
	rig.env.tick(1000)
	if err := rig.bob.PrepareForMutation(ctx, rig.sBob, ldrcrypto.PrincipalCredential); err != nil {
		t.Fatal(err)
	}
	if err := rig.bob.EnsureRegisterActivated(ctx, rig.sBob, "shared-actor", "presence"); err != nil {
		t.Fatalf("bob EnsureRegisterActivated: %v", err)
	}
	injectList(craftEntry(rig.alice.credKeys.Signing.Signer, aliceCID, 1, uint64(w1.WriterRev), w1.Incarnation, 1, `{"v":"old-writer"}`))
	regsSuperseded, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence")
	rig.env.setHTTPHook(nil)
	if err != nil || len(regsSuperseded) != 1 || !regsSuperseded[0].Historical || regsSuperseded[0].WriterRev != 1 {
		t.Fatalf("expected genuine superseded writer_rev=1 accepted as Historical=true, got %+v err=%v", regsSuperseded, err)
	}

	// 2e. Superseded writer_rev=1 with a bogus incarnation that NEVER appeared in any activation
	//     MUST be rejected with ErrViolation (never labeled historical)!
	injectList(craftEntry(rig.alice.credKeys.Signing.Signer, aliceCID, 1, uint64(w1.WriterRev), "inc-never-committed", 1, `{"v":"bogus-inc"}`))
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrViolation) {
		t.Fatalf("expected ErrViolation for bogus incarnation on superseded writer_rev=1, got %v", err)
	}
	rig.env.setHTTPHook(nil)

	// 2f. Reopen bob from disk -> regActivations rebuilds identically from verified.wal and still
	//     rejects both bogus superseded incarnation and wrong owning credential!
	rig.sBob.Close()
	if err := rig.bob.Close(); err != nil {
		t.Fatal(err)
	}
	rig.bob, err = OpenClient(rig.bobDir)
	if err != nil {
		t.Fatalf("OpenClient(bob): %v", err)
	}
	rig.sBob, err = rig.bob.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}
	injectList(craftEntry(rig.alice.credKeys.Signing.Signer, aliceCID, 1, uint64(w1.WriterRev), "inc-never-committed", 1, `{"v":"bogus-inc-reopen"}`))
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrViolation) {
		t.Fatalf("expected ErrViolation after reopen for bogus superseded incarnation, got %v", err)
	}
	injectList(craftEntry(rig.bob.credKeys.Signing.Signer, bobCID, 1, uint64(w1.WriterRev), w1.Incarnation, 1, `{"v":"wrong-owner-reopen"}`))
	if _, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence"); !errors.Is(err, ErrViolation) {
		t.Fatalf("expected ErrViolation after reopen for wrong owning credential on superseded rev, got %v", err)
	}
	rig.env.setHTTPHook(nil)
}

// Turn 4 Finding 1 regression:
//   - Pre-rename ErrPreWrite failure while recording a validated bound revoked
//     reply MUST keep the exact key stopped immediately, fence outboxUncertain,
//     carry the pending stop through ReconcileDurability, and durably persist it
//     before clearing uncertainty (surviving close+reopen).
func TestClientRegistersPreWriteRevokedStopCarriedThroughReconcile(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "alice-1", "ns-alice"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"v":1}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("initial publish: %+v %v", rep, err)
	}

	// Revoke Alice on relay while Alice still holds an active session & trusted writer.
	rig.env.tick(1000)
	if _, err := rig.admin.Sync(ctx, rig.sOp); err != nil {
		t.Fatal(err)
	}
	aliceCID, _ := rig.alice.CredID()
	if _, err := rig.admin.SubmitCredentialRevoke(ctx, rig.sOp, aliceCID); err != nil {
		t.Fatal(err)
	}

	// Inject a pre-rename ErrPreWrite failure ONLY on outbox.cbor temp file sync so
	// registers.cbor advances cleanly, PutRegister receives the real bound unresolved/revoked
	// reply, and recordValidatedRevokedStopLocked fails with ErrPreWrite!
	rig.alice.SetSyncHooks(func(f *os.File) error {
		if strings.Contains(filepath.Base(f.Name()), "outbox.cbor") {
			return errors.New("injected pre-rename outbox sync failure")
		}
		return ldrstore.SyncFile(f)
	}, nil)

	_, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"v":2}`))
	if !errors.Is(err, ldrstore.ErrPreWrite) {
		t.Fatalf("expected ErrPreWrite from failed outbox stop persist, got %v", err)
	}

	// 1. Key MUST be stopped immediately in memory AND outboxUncertain MUST be fenced!
	if stops := rig.alice.Stops(); len(stops) != 1 || !stops[0].Told {
		t.Fatalf("expected immediate Rule 8 stop in Stops() after ErrPreWrite, got %+v", stops)
	}
	if !rig.alice.Status().OutboxUncertain {
		t.Fatal("expected OutboxUncertain=true while pending Rule 8 stop awaits durable write")
	}

	// 2. Subsequent calls BEFORE reconciliation MUST refuse locally with ZERO HTTP requests!
	var reqCount atomic.Int64
	rig.env.setHTTPHook(func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		next.ServeHTTP(w, r)
	})
	if err := rig.alice.EnsureRegisterActivated(ctx, rig.sAlice, "alice-1", "presence"); err == nil {
		t.Fatal("EnsureRegisterActivated succeeded with pending Rule 8 stop")
	}
	if _, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"v":3}`)); err == nil {
		t.Fatal("PublishRegister succeeded with pending Rule 8 stop")
	}
	if _, err := rig.alice.ReadRegisters(ctx, rig.sAlice, "presence"); err == nil {
		t.Fatal("ReadRegisters succeeded with pending Rule 8 stop")
	}
	if got := reqCount.Load(); got != 0 {
		t.Fatalf("expected 0 HTTP requests while pending Rule 8 stop is fenced, got %d", got)
	}

	// 3. ReconcileDurability while outbox sync still fails MUST fail and keep stop + fence intact.
	if err := rig.alice.ReconcileDurability(); err == nil {
		t.Fatal("ReconcileDurability succeeded while outbox sync still failed")
	}
	if !rig.alice.Status().OutboxUncertain || len(rig.alice.Stops()) != 1 {
		t.Fatalf("expected stop + OutboxUncertain preserved after failed reconcile, status=%+v stops=%+v", rig.alice.Status(), rig.alice.Stops())
	}

	// 4. Restore healthy storage -> ReconcileDurability durably persists the pending stop to outbox.cbor!
	rig.alice.SetSyncHooks(nil, nil)
	if err := rig.alice.ReconcileDurability(); err != nil {
		t.Fatalf("ReconcileDurability after storage recovery: %v", err)
	}
	if rig.alice.Status().OutboxUncertain {
		t.Fatal("expected OutboxUncertain cleared after durable reconcile")
	}

	// 5. Close and reopen from disk -> stop survives on disk and still blocks with ErrKeyRevoked and 0 HTTP requests!
	if err := rig.alice.Close(); err != nil {
		t.Fatal(err)
	}
	rig.alice, err = OpenClient(rig.aliceDir)
	if err != nil {
		t.Fatalf("OpenClient after reconcile: %v", err)
	}
	if len(rig.alice.Stops()) != 1 {
		t.Fatalf("expected persisted Rule 8 stop after reopen, got %+v", rig.alice.Stops())
	}
	if err := rig.alice.EnsureRegisterActivated(ctx, rig.sAlice, "alice-1", "presence"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked on reopened fast path, got %v", err)
	}
	if _, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"v":4}`)); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked on reopened PublishRegister, got %v", err)
	}
	if _, err := rig.alice.ReadRegisters(ctx, rig.sAlice, "presence"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked on reopened ReadRegisters, got %v", err)
	}
	if got := reqCount.Load(); got != 0 {
		t.Fatalf("expected 0 HTTP requests after reopen with persisted Rule 8 stop, got %d", got)
	}
	rig.env.setHTTPHook(nil)
}

// Finding 3 regression:
//   - ReconcileDurability refuses corrupt registers.cbor (never ignores loadRegisters error).
//   - After an uncertain register write, ReconcileDurability persists TrustedCounter=false
//     BEFORE clearing registersUncertain, so an immediate close + reopen STILL forces fresh
//     register_activate re-incarnation (writer_rev 1 -> 2) rather than restoring trusted counter.
func TestClientRegistersReconcileDurabilityValidationAndReopenPersistence(t *testing.T) {
	rig := newRegisterTestRig(t, 4, 4)
	ctx := context.Background()

	rig.env.tick(1000)
	if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, "alice-1", "ns-alice"); err != nil {
		t.Fatal(err)
	}
	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"step":1}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("initial publish: %+v %v", rep, err)
	}

	// Inject uncertain post-write dir sync failure on counter advance -> sets registersUncertain=true.
	rig.alice.SetSyncHooks(nil, func(string) error { return errors.New("injected dir sync failure") })
	if _, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"step":2}`)); err == nil {
		t.Fatal("expected error on injected dir sync failure")
	}

	// ReconcileDurability MUST fail while sync is broken (cannot clear uncertainty without persisting TrustedCounter=false).
	if err := rig.alice.ReconcileDurability(); err == nil {
		t.Fatal("ReconcileDurability succeeded while dir sync failed")
	}
	if _, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"step":3}`)); !errors.Is(err, ErrRegisterUncertain) {
		t.Fatalf("expected ErrRegisterUncertain to remain set, got %v", err)
	}

	// Corrupt registers.cbor on disk -> ReconcileDurability MUST return an error (never silently ignore!).
	rig.alice.SetSyncHooks(nil, nil)
	regPath := filepath.Join(rig.aliceDir, "registers.cbor")
	origRegBytes, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regPath, []byte{0xff, 0xff, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rig.alice.ReconcileDurability(); err == nil {
		t.Fatal("ReconcileDurability ignored corrupt registers.cbor")
	}

	// Restore valid registers.cbor (which still has trusted_counter=true on disk!) and run ReconcileDurability.
	if err := os.WriteFile(regPath, origRegBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rig.alice.ReconcileDurability(); err != nil {
		t.Fatalf("ReconcileDurability: %v", err)
	}

	// IMMEDIATELY close and reopen from disk BEFORE publishing!
	// If ReconcileDurability failed to persist TrustedCounter=false, reopening would restore
	// trusted_counter=true and publish under writer_rev=1 instead of activating writer_rev=2!
	rig.sAlice.Close()
	if err := rig.alice.Close(); err != nil {
		t.Fatal(err)
	}
	rig.alice, err = OpenClient(rig.aliceDir)
	if err != nil {
		t.Fatalf("OpenClient after ReconcileDurability: %v", err)
	}
	rig.sAlice, err = rig.alice.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		t.Fatal(err)
	}

	rig.env.tick(1000)
	if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, "alice-1", "presence", []byte(`{"step":"post-reopen"}`)); err != nil || rep.Class != "ok" {
		t.Fatalf("PublishRegister after reconcile+reopen: %+v %v", rep, err)
	}
	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}
	regs, err := rig.bob.ReadRegisters(ctx, rig.sBob, "presence")
	if err != nil || len(regs) != 1 || regs[0].WriterRev != 2 || regs[0].Counter != 1 || string(regs[0].Plaintext) != `{"step":"post-reopen"}` {
		t.Fatalf("expected persisted reactivation requirement (writer_rev=2 counter=1) across reopen, got %+v err=%v", regs, err)
	}
}

// Finding 4 regression:
//   - Large register sets exceeding the 1 MiB transport frame cap (~1.35 MiB across
//     24 entries) paginate cleanly by encoded byte budget and are fully verified and
//     decrypted by Client.ReadRegisters.
func TestClientRegistersLargeMultiPageList(t *testing.T) {
	rig := newRegisterTestRig(t, 8, 4)
	ctx := context.Background()

	largeBody := bytes.Repeat([]byte("R"), 56*1024)
	regTypes := []string{"presence", "roadmap", "resource"}
	for a := 1; a <= 8; a++ {
		actor := fmt.Sprintf("bulk-%02d", a)
		rig.env.tick(100)
		if _, err := rig.alice.SubmitActorDeclare(ctx, rig.sAlice, actor, "ns-alice"); err != nil {
			t.Fatalf("declare %s: %v", actor, err)
		}
		for _, reg := range regTypes {
			rig.env.tick(100)
			if rep, err := rig.alice.PublishRegister(ctx, rig.sAlice, actor, reg, largeBody); err != nil || rep.Class != "ok" {
				t.Fatalf("PublishRegister %s/%s: %+v %v", actor, reg, rep, err)
			}
		}
	}

	if _, err := rig.bob.Sync(ctx, rig.sBob); err != nil {
		t.Fatal(err)
	}
	regs, err := rig.bob.ReadRegisters(ctx, rig.sBob, "")
	if err != nil {
		t.Fatalf("bob.ReadRegisters across >1MiB dataset: %v", err)
	}
	if len(regs) != 24 {
		t.Fatalf("expected 24 verified registers across paginated responses, got %d", len(regs))
	}
	for _, vr := range regs {
		if vr.Historical || vr.ReadStatus != ldrcore.ReadOK || !bytes.Equal(vr.Plaintext, largeBody) {
			t.Fatalf("unexpected register %s/%s: hist=%v status=%s len=%d", vr.Actor, vr.Register, vr.Historical, vr.ReadStatus, len(vr.Plaintext))
		}
	}
}
