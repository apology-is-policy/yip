package ldrrelay

import (
	"bytes"
	"context"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

func mustMarshalSignedIntent(t *testing.T, signer ldrcrypto.Signer, in WireIntentInput) []byte {
	t.Helper()
	body, err := BuildWireIntentBody(in)
	if err != nil {
		t.Fatalf("BuildWireIntentBody(%s): %v", in.OpType, err)
	}
	env, err := ldrcrypto.SignIntent(signer, body)
	if err != nil {
		t.Fatalf("SignIntent(%s): %v", in.OpType, err)
	}
	return env.RawBytes
}

func TestAdvisoryRegistersPublishListAndSection9Rules(t *testing.T) {
	fx := startRelayFixture(t)
	ctx := context.Background()

	rootPrin := ldrcrypto.RootPrincipal(fx.root1.PublicKey())
	rootSess, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, rootPrin, fx.root1)
	if err != nil {
		t.Fatalf("DialSession(root): %v", err)
	}
	defer rootSess.Close()

	rk0, _ := fx.desc.RootKeys[0].ToCBOR()
	rk1, _ := fx.desc.RootKeys[1].ToCBOR()
	profMap, _ := fx.desc.Profile.ToCBORMap()
	initRaw := mustMarshalSignedIntent(t, fx.root1, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: rootPrin,
		OpID: "op-init", OpType: "line_init", SeenSeq: 0, SeenHead: fx.genesis, PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{{Key: "descriptor_digest", Value: fx.cd[:]}, {Key: "profile", Value: profMap}, {Key: "root_keys", Value: []any{rk0, rk1}}},
	})
	rep, err := rootSess.Submit(ctx, initRaw, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("line_init: rep=%+v err=%v", rep, err)
	}
	head1 := rep.Head

	opKey, _ := ldrcrypto.GenerateEd25519Key()
	opPub, _ := opKey.PublicKey().ToCBOR()
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	authRaw := mustMarshalSignedIntent(t, fx.root1, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: rootPrin,
		OpID: "op-auth", OpType: "operator_key_authorize", SeenSeq: 1, SeenHead: head1, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(), Expect: ldrcrypto.ExpectMap{"root_rev": 1},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opPub}},
	})
	rep, err = rootSess.Submit(ctx, authRaw, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("operator_key_authorize: rep=%+v err=%v", rep, err)
	}
	head2 := rep.Head

	opPrin := ldrcrypto.OperatorPrincipal(opKey.PublicKey())
	opSess, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, opPrin, opKey)
	if err != nil {
		t.Fatalf("DialSession(op): %v", err)
	}
	defer opSess.Close()

	// Enroll credential A (reader) via P3 ceremony.
	credSig, _ := ldrcrypto.GenerateEd25519Key()
	credEnc, _ := ldrcrypto.GenerateX25519Key()
	credID, _ := ldrcrypto.DeriveCredID(credSig.PublicKey(), credEnc.PublicKey())
	grant := ldrcrypto.JoinGrant{NamespaceID: "ns-a", ActorLimit: 4, Reader: true}
	req, err := ldrcrypto.SignJoinRequest(credSig, ldrcrypto.JoinRequest{
		RequestID:        bytes.Repeat([]byte{0x11}, 16),
		LineID:           fx.lineID,
		Generation:       1,
		DescriptorDigest: fx.cd,
		EncryptionKey:    credEnc.PublicKey(),
		Grant:            grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, sec, err := ldrcrypto.CreateJoinChallenge(opKey.PublicKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ldrcrypto.RespondJoinChallenge(credSig, credEnc, opKey.PublicKey(), req, ch)
	if err != nil {
		t.Fatal(err)
	}
	if err := ldrcrypto.VerifyJoinProof(opKey.PublicKey(), req, ch, sec, proof); err != nil {
		t.Fatal(err)
	}
	reqDig, err := ldrcrypto.VerifyJoinRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	fx.clock.wall += 1000
	fx.clock.mono += 1000
	sigCBOR, _ := req.SigningKey.ToCBOR()
	encCBOR, _ := req.EncryptionKey.ToCBOR()
	grantMap := ldrcrypto.Map{
		{Key: "actor_limit", Value: grant.ActorLimit},
		{Key: "namespace_id", Value: grant.NamespaceID},
		{Key: "reader", Value: grant.Reader},
	}
	enrollRaw := mustMarshalSignedIntent(t, opKey, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "op-enroll", OpType: "credential_enroll", AuthEpoch: 1, SeenSeq: 2, SeenHead: head2, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "cred_id", Value: credID[:]},
			{Key: "encryption_key", Value: encCBOR},
			{Key: "grant", Value: grantMap},
			{Key: "join_request_digest", Value: reqDig[:]},
			{Key: "join_request_id", Value: req.RequestID},
			{Key: "signing_key", Value: sigCBOR},
		},
	})
	rep, err = opSess.Submit(ctx, enrollRaw, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("credential_enroll: rep=%+v err=%v", rep, err)
	}
	head3 := rep.Head

	// Activate key epoch 1.
	epochKey, _ := ldrcrypto.GenerateEpochKey()
	rsDig, _ := ldrcrypto.ReaderSetDigest([][32]byte{credID})
	wCtx := ldrcrypto.EpochWrapContext{
		LineID: fx.lineID, Generation: 1, ProfileDigest: fx.profDigest,
		NewEpoch: 1, ExpectEpoch: 0, AuthEpoch: 2,
		OpIdentityBytes: []byte("op-epoch1"), RecipientCredID: credID,
		RecipientEncKey: credEnc.PublicKey(), ReaderSetDigest: rsDig,
	}
	wrapBytes, err := ldrcrypto.WrapEpochKey(epochKey, wCtx)
	if err != nil {
		t.Fatal(err)
	}
	wCommit, _ := ldrcrypto.CommitWrap(wrapBytes)
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	epRaw := mustMarshalSignedIntent(t, opKey, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "op-epoch1", OpType: "key_epoch_activate", AuthEpoch: 2, SeenSeq: 3, SeenHead: head3, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Expect:        ldrcrypto.ExpectMap{"key_epoch": 0},
		Manifest:      []ldrcrypto.WrapManifestEntry{{CredID: credID, Commit: wCommit}},
	})
	rep, err = opSess.Submit(ctx, epRaw, nil, map[[32]byte][]byte{credID: wrapBytes})
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("key_epoch_activate: rep=%+v err=%v", rep, err)
	}
	head4 := rep.Head

	credPrin := ldrcrypto.CredentialPrincipal(credID)
	credSess, err := DialSession(ctx, fx.origin, fx.lineID, fx.profDigest, 1, credPrin, credSig)
	if err != nil {
		t.Fatalf("DialSession(cred): %v", err)
	}
	defer credSess.Close()

	// Declare actor "alice".
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	declRaw := mustMarshalSignedIntent(t, credSig, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginCredential, Principal: credPrin,
		OpID: "op-decl", OpType: "actor_declare", AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 4, SeenHead: head4, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "actor_id", Value: "alice"}, {Key: "label", Value: false}, {Key: "namespace_id", Value: "ns-a"}},
	})
	rep, err = credSess.Submit(ctx, declRaw, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("actor_declare: rep=%+v err=%v", rep, err)
	}
	head5 := rep.Head

	buildReg := func(reg, inc string, wrev, epoch, counter uint64, text string) ([]byte, []byte) {
		cBytes, err := ldrcrypto.RegisterPayloadContextBytes(fx.profDigest, fx.lineID, 1, reg, "alice", credID, 1, wrev, inc, epoch, counter)
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := ldrcrypto.SealPayload(epochKey, cBytes, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		cm, err := ldrcrypto.CommitPayload(pkg)
		if err != nil {
			t.Fatal(err)
		}
		env, err := ldrcrypto.SignRegisterEnvelope(credSig, ldrcrypto.RegisterEnvelope{
			Version: 1, LineID: fx.lineID, Generation: 1, ProfileDigest: fx.profDigest,
			Register: reg, ActorID: "alice", CredID: credID,
			BindingGen: 1, WriterRev: wrev, Incarnation: inc, KeyEpoch: epoch, Counter: counter,
			PayloadCommit: cm,
		})
		if err != nil {
			t.Fatal(err)
		}
		return env, pkg
	}

	// Publishing BEFORE register_activate must be rejected with no_activation.
	env0, pkg0 := buildReg("presence", "inc-1", 1, 1, 1, `{"busy":"early"}`)
	putRep, err := credSess.PutRegister(ctx, env0, pkg0)
	if err != nil || putRep.Class != ldrcore.Rejected || putRep.Code != ldrcore.RegNoActivation {
		t.Fatalf("expected no_activation before register_activate, got rep=%+v err=%v", putRep, err)
	}

	// Commit register_activate for alice/presence (writer_rev 0 -> 1, inc-1).
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	actRaw := mustMarshalSignedIntent(t, credSig, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginCredential, Principal: credPrin,
		OpID: "op-act1", OpType: "register_activate", AuthEpoch: 2, KeyEpoch: 1, SeenSeq: 5, SeenHead: head5, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(), Expect: ldrcrypto.ExpectMap{"writer_rev": 0},
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: "alice"}, {Key: "incarnation", Value: "inc-1"}, {Key: "register", Value: "presence"}},
	})
	rep, err = credSess.Submit(ctx, actRaw, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("register_activate: rep=%+v err=%v", rep, err)
	}
	head6 := rep.Head

	// Wrong incarnation under writer_rev=1 must fail.
	badIncEnv, badIncPkg := buildReg("presence", "inc-wrong", 1, 1, 1, `{"busy":"wrong"}`)
	putRep, err = credSess.PutRegister(ctx, badIncEnv, badIncPkg)
	if err != nil || putRep.Code != ldrcore.RegWrongIncarnation {
		t.Fatalf("expected wrong_incarnation, got rep=%+v err=%v", putRep, err)
	}

	// Tampered payload commitment must fail.
	tampered := bytes.Clone(pkg0)
	tampered[len(tampered)-1] ^= 0xff
	putRep, err = credSess.PutRegister(ctx, env0, tampered)
	if err != nil || putRep.Code != "commitment_mismatch" {
		t.Fatalf("expected commitment_mismatch, got rep=%+v err=%v", putRep, err)
	}

	// Valid publish counter=1 succeeds.
	putRep, err = credSess.PutRegister(ctx, env0, pkg0)
	if err != nil || putRep.Class != "ok" {
		t.Fatalf("expected ok publish, got rep=%+v err=%v", putRep, err)
	}

	// Replaying counter=1 must be rejected with stale_counter.
	putRep, err = credSess.PutRegister(ctx, env0, pkg0)
	if err != nil || putRep.Code != ldrcore.RegStaleCounter {
		t.Fatalf("expected stale_counter on replay, got rep=%+v err=%v", putRep, err)
	}

	// Advancing to counter=2 succeeds, and ListRegisters returns it as non-historical.
	env2, pkg2 := buildReg("presence", "inc-1", 1, 1, 2, `{"busy":"testing"}`)
	putRep, err = credSess.PutRegister(ctx, env2, pkg2)
	if err != nil || putRep.Class != "ok" {
		t.Fatalf("expected ok publish counter=2, got rep=%+v err=%v", putRep, err)
	}
	list, err := opSess.ListRegisters(ctx, "presence")
	if err != nil || len(list) != 1 || list[0].Historical || list[0].Actor != "alice" {
		t.Fatalf("ListRegisters(presence): list=%+v err=%v", list, err)
	}
	if listEmpty, err := opSess.ListRegisters(ctx, "roadmap"); err != nil || len(listEmpty) != 0 {
		t.Fatalf("ListRegisters(roadmap): list=%+v err=%v", listEmpty, err)
	}

	// Revoke credential A -> delayed publish refused with revoked, and cached entry becomes Historical=true!
	fx.clock.wall += 1000
	fx.clock.mono += 1000
	revRaw := mustMarshalSignedIntent(t, opKey, WireIntentInput{
		ProfileDigest: fx.profDigest, LineID: fx.lineID, Generation: 1,
		Origin: ldrcore.OriginOperator, Principal: opPrin,
		OpID: "op-rev", OpType: "credential_revoke", AuthEpoch: 2, SeenSeq: 6, SeenHead: head6, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields:        ldrcrypto.Map{{Key: "cred_id", Value: credID[:]}},
	})
	rep, err = opSess.Submit(ctx, revRaw, nil, nil)
	if err != nil || rep.Outcome.Kind != ldrcore.Committed {
		t.Fatalf("credential_revoke: rep=%+v err=%v", rep, err)
	}

	env3, pkg3 := buildReg("presence", "inc-1", 1, 1, 3, `{"busy":"after-revoke"}`)
	putRep, err = credSess.PutRegister(ctx, env3, pkg3)
	if err != nil || putRep.Class != ldrcore.ClassUnresolved || putRep.Code != "revoked" {
		t.Fatalf("expected revoked refusal after cred revoke, got rep=%+v err=%v", putRep, err)
	}
	listAfter, err := opSess.ListRegisters(ctx, "")
	if err != nil || len(listAfter) != 1 || !listAfter[0].Historical {
		t.Fatalf("expected cached register to become Historical=true after revoke, got %+v err=%v", listAfter, err)
	}
}
