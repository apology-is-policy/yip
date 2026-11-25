package ldrcrypto

import (
	"bytes"
	"errors"
	"sort"
	"testing"
)

func TestEndToEndProfileV1Workflow(t *testing.T) {
	// 1. Mixed equal 1-of-2 roots: Root A (Ed25519) + Root B (ECDSA P-256).
	rootA, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatal(err)
	}
	lineID := bytes.Repeat([]byte{0xab}, 16)
	spkiPin := bytes.Repeat([]byte{0xcd}, 32)
	prof := ProfileV1()
	profDigest, err := prof.Digest()
	if err != nil {
		t.Fatal(err)
	}

	// Reversing root_keys input order MUST produce identical canonical body, CD, and genesis.
	desc1 := CreationDescriptor{
		Version:    1,
		LineID:     lineID,
		Generation: 1,
		RootKeys:   []PublicKey{rootA.PublicKey(), rootB.PublicKey()},
		RelayOrigin: RelayOrigin{
			URL:            "https://relay.internal.example:8443",
			TLSPolicy:      TLSPolicyPinSPKISHA256,
			TLSPin:         spkiPin,
			SessionBinding: SessionBindingTLS13Exporter,
		},
		Profile: prof,
	}
	desc2 := desc1
	desc2.RootKeys = []PublicKey{rootB.PublicKey(), rootA.PublicKey()}

	body1, err := desc1.MarshalBody()
	if err != nil {
		t.Fatalf("MarshalBody(1): %v", err)
	}
	body2, err := desc2.MarshalBody()
	if err != nil {
		t.Fatalf("MarshalBody(2): %v", err)
	}
	if !bytes.Equal(body1, body2) {
		t.Fatalf("root_keys canonicalization failed across input order")
	}

	// Sign creation descriptor with P-256 Root B and verify.
	signedDesc, err := SignCreationDescriptor(rootB, desc1)
	if err != nil {
		t.Fatalf("SignCreationDescriptor: %v", err)
	}
	rawDesc, err := signedDesc.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	parsedDesc, cd, genesis, signerKey, err := VerifyCreationDescriptor(rawDesc)
	if err != nil {
		t.Fatalf("VerifyCreationDescriptor: %v", err)
	}
	if !signerKey.Equal(rootB.PublicKey()) {
		t.Fatalf("unexpected descriptor signer")
	}
	if !bytes.Equal(parsedDesc.LineID, lineID) || len(parsedDesc.RootKeys) != 2 {
		t.Fatalf("parsed descriptor mismatch")
	}

	// Non-root signer MUST be refused for descriptor signing.
	outsider, _ := GenerateEd25519Key()
	if _, err := SignCreationDescriptor(outsider, desc1); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("non-root descriptor signer accepted: %v", err)
	}

	// 2. Sign line_init intent with Ed25519 Root A; check P5 IntentDigest and chain head.
	rootAPrin, err := RootPrincipal(rootA.PublicKey()).ToCBOR()
	if err != nil {
		t.Fatal(err)
	}
	lineInitBody, err := MarshalCBOR(Map{
		{Key: "descriptor_digest", Value: cd[:]},
		{Key: "generation", Value: uint64(1)},
		{Key: "line_id", Value: lineID},
		{Key: "op_id", Value: "init-1"},
		{Key: "op_type", Value: "line_init"},
		{Key: "origin", Value: "root"},
		{Key: "payload_commit", Value: EmptyPayloadCommit().ToCBORMap()},
		{Key: "principal", Value: rootAPrin},
		{Key: "profile_digest", Value: profDigest[:]},
		{Key: "seen_head", Value: genesis[:]},
		{Key: "seen_seq", Value: uint64(0)},
		{Key: "v", Value: ProtocolVersion},
	})
	if err != nil {
		t.Fatal(err)
	}
	initEnv, err := SignIntent(rootA, lineInitBody)
	if err != nil {
		t.Fatalf("SignIntent(line_init): %v", err)
	}
	redecodedEnv, err := UnmarshalSignedIntent(initEnv.RawBytes, DefaultLimits())
	if err != nil {
		t.Fatalf("UnmarshalSignedIntent: %v", err)
	}
	if err := redecodedEnv.Verify(rootA.PublicKey()); err != nil {
		t.Fatalf("Verify(rootA): %v", err)
	}
	// Verifying with wrong key or wrong alg fails.
	if err := redecodedEnv.Verify(rootB.PublicKey()); err == nil {
		t.Fatalf("Verify accepted wrong root key")
	}
	d1, err := redecodedEnv.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Signing identical body with P-256 Root B produces a distinct P5 IntentDigest (covers sig).
	initEnvB, err := SignIntent(rootB, lineInitBody)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := initEnvB.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatalf("P5 IntentDigest did not cover signature")
	}

	head1, err := ClientChainHead(genesis, profDigest, lineID, 1, 1, 1_700_000_000_000, "root", redecodedEnv.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	head2, err := AnchorChainHead(head1, profDigest, lineID, 1, 2, 1_700_000_015_000)
	if err != nil {
		t.Fatal(err)
	}
	headRec, err := RecoveryChainHead(head2, profDigest, lineID, 2, 1, 1_700_000_020_000, redecodedEnv.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if head1 == head2 || head2 == headRec || head1 == headRec {
		t.Fatalf("chain head domain separation failed")
	}

	// 3. P3 Key-First Enrollment Ceremony with P-256 Operator and two joining readers.
	opPriv, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatal(err)
	}
	joiner1Sig, _ := GenerateEd25519Key()
	joiner1Enc, _ := GenerateX25519Key()
	joiner2Sig, _ := GenerateEd25519Key()
	joiner2Enc, _ := GenerateX25519Key()

	req1, err := SignJoinRequest(joiner1Sig, JoinRequest{
		RequestID:        bytes.Repeat([]byte{0x11}, 16),
		LineID:           lineID,
		Generation:       1,
		DescriptorDigest: cd,
		EncryptionKey:    joiner1Enc.PublicKey(),
		Grant: JoinGrant{
			NamespaceID:  "ns-workstation-a",
			ActorLimit:   4,
			Reader:       true,
			Capabilities: []string{"actor_declare", "call_open", "call_turn"},
		},
		ContextSeq:       2,
		ContextAuthEpoch: 1,
		ContextKeyEpoch:  0,
	})
	if err != nil {
		t.Fatalf("SignJoinRequest: %v", err)
	}
	ch1, secret1, err := CreateJoinChallenge(opPriv.PublicKey(), req1)
	if err != nil {
		t.Fatalf("CreateJoinChallenge: %v", err)
	}
	proof1, err := RespondJoinChallenge(joiner1Sig, joiner1Enc, opPriv.PublicKey(), req1, ch1)
	if err != nil {
		t.Fatalf("RespondJoinChallenge: %v", err)
	}
	if err := VerifyJoinProof(opPriv.PublicKey(), req1, ch1, secret1, proof1); err != nil {
		t.Fatalf("VerifyJoinProof: %v", err)
	}

	// 4. Epoch 1 activation: wrap to both readers, verify manifest, unwrap on both.
	cred1 := req1.CredID
	cred2, err := DeriveCredID(joiner2Sig.PublicKey(), joiner2Enc.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	epochKey, err := GenerateEpochKey()
	if err != nil {
		t.Fatal(err)
	}
	rsDigest, err := ReaderSetDigest([][32]byte{cred1, cred2})
	if err != nil {
		t.Fatal(err)
	}
	opIDBytes, _ := MarshalCBOR([]any{lineID, uint64(1), []any{"operator", opPriv.PublicKey().Bytes}, uint64(2), "act-1"})

	type readerInfo struct {
		id  [32]byte
		enc *X25519PrivateKey
	}
	readers := []readerInfo{{cred1, joiner1Enc}, {cred2, joiner2Enc}}
	sort.Slice(readers, func(i, j int) bool { return bytes.Compare(readers[i].id[:], readers[j].id[:]) < 0 })

	manifest := make([]WrapManifestEntry, 0, len(readers))
	sidecars := make(map[[32]byte][]byte, len(readers))
	for _, r := range readers {
		wctx := EpochWrapContext{
			LineID:          lineID,
			Generation:      1,
			ProfileDigest:   profDigest,
			NewEpoch:        1,
			ExpectEpoch:     0,
			AuthEpoch:       3,
			OpIdentityBytes: opIDBytes,
			RecipientCredID: r.id,
			RecipientEncKey: r.enc.PublicKey(),
			ReaderSetDigest: rsDigest,
		}
		wb, err := WrapEpochKey(epochKey, wctx)
		if err != nil {
			t.Fatalf("WrapEpochKey: %v", err)
		}
		commit, err := CommitWrap(wb)
		if err != nil {
			t.Fatal(err)
		}
		manifest = append(manifest, WrapManifestEntry{CredID: r.id, Commit: commit})
		sidecars[r.id] = wb

		unwrapped, err := UnwrapEpochKey(r.enc, wb, wctx)
		if err != nil {
			t.Fatalf("UnwrapEpochKey: %v", err)
		}
		if !bytes.Equal(unwrapped, epochKey) {
			t.Fatalf("unwrapped epoch key mismatch")
		}
	}
	if err := VerifyWrapManifest(manifest, sidecars); err != nil {
		t.Fatalf("VerifyWrapManifest: %v", err)
	}
	// Unsorted manifest MUST be rejected.
	reversed := []WrapManifestEntry{manifest[1], manifest[0]}
	if err := VerifyWrapManifest(reversed, sidecars); !errors.Is(err, ErrManifestMismatch) {
		t.Fatalf("unsorted wrap manifest accepted: %v", err)
	}
	// Tampered wrap sidecar MUST be rejected.
	badSidecars := map[[32]byte][]byte{
		manifest[0].CredID: append(bytes.Clone(sidecars[manifest[0].CredID]), 0x00),
		manifest[1].CredID: sidecars[manifest[1].CredID],
	}
	if err := VerifyWrapManifest(manifest, badSidecars); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("tampered wrap sidecar accepted: %v", err)
	}

	// 5. Encrypted turn payload + non-circular commitment + sidecar check.
	turnCtx, err := MarshalCBOR(Map{
		{Key: "actor_id", Value: "agent-a"},
		{Key: "binding_gen", Value: uint64(1)},
		{Key: "call_id", Value: "call-opaque-001"},
		{Key: "generation", Value: uint64(1)},
		{Key: "key_epoch", Value: uint64(1)},
		{Key: "line_id", Value: lineID},
		{Key: "op_id", Value: "turn-1"},
		{Key: "op_type", Value: "call_turn"},
		{Key: "profile_digest", Value: profDigest[:]},
		{Key: "seen_head", Value: head2[:]},
		{Key: "seen_seq", Value: uint64(2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	turnPlaintext := []byte("Ready to run verification.")
	payloadPkg, err := SealPayload(epochKey, turnCtx, turnPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	payloadCommit, err := CommitPayload(payloadPkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPayloadSidecar(payloadCommit, payloadPkg); err != nil {
		t.Fatalf("VerifyPayloadSidecar: %v", err)
	}
	if err := VerifyPayloadSidecar(payloadCommit, []byte("wrong-bytes")); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("VerifyPayloadSidecar accepted tampered payload: %v", err)
	}
	opened, err := OpenPayload(epochKey, turnCtx, payloadPkg)
	if err != nil {
		t.Fatalf("OpenPayload: %v", err)
	}
	if !bytes.Equal(opened, turnPlaintext) {
		t.Fatalf("opened turn plaintext mismatch")
	}
}

func TestRelayOriginPoliciesAndSessionAuth(t *testing.T) {
	// Verify all three TLS policies (LAN/closed-net SPKI pin, Enterprise CA pin, Public VM / Workers WebPKI)
	// and both session binding modes (tls13_exporter and app_authenticated_session).
	validOrigins := []RelayOrigin{
		{URL: "https://10.0.0.5:8443", TLSPolicy: TLSPolicyPinSPKISHA256, TLSPin: bytes.Repeat([]byte{0x01}, 32), SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://yip.corp.internal:8443", TLSPolicy: TLSPolicyPinCARootPEM, TLSPin: []byte("-----BEGIN CERTIFICATE-----..."), SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://relay.example.com", TLSPolicy: TLSPolicyWebPKI, TLSPin: nil, SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://yip-ldr.example.workers.dev", TLSPolicy: TLSPolicyWebPKI, TLSPin: nil, SessionBinding: SessionBindingAppAuth},
	}
	for i, ro := range validOrigins {
		m, err := ro.ToCBORMap()
		if err != nil {
			t.Fatalf("valid origin %d failed: %v", i, err)
		}
		raw, err := MarshalCBOR(m)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := UnmarshalCBORDefault(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRelayOrigin(dec); err != nil {
			t.Fatalf("ParseRelayOrigin(%d): %v", i, err)
		}
	}

	invalidOrigins := []RelayOrigin{
		{URL: "http://relay.local:8443", TLSPolicy: TLSPolicyWebPKI, SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://user:pass@relay.local:8443", TLSPolicy: TLSPolicyWebPKI, SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://relay.local:8443?tok=secret", TLSPolicy: TLSPolicyWebPKI, SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://relay.local:8443", TLSPolicy: TLSPolicyPinSPKISHA256, TLSPin: []byte("short"), SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://relay.local:8443", TLSPolicy: TLSPolicyWebPKI, TLSPin: []byte("must-be-empty"), SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://relay.local:8443", TLSPolicy: TLSPolicyPinCARootPEM, TLSPin: nil, SessionBinding: SessionBindingTLS13Exporter},
		{URL: "https://relay.local:8443", TLSPolicy: TLSPolicyWebPKI, SessionBinding: "bearer_token"},
	}
	for i, ro := range invalidOrigins {
		if err := ro.Validate(); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("invalid origin %d unexpectedly accepted: %v", i, err)
		}
	}

	// P7 SessionAuth and SessionRequest (Query vs AnchorRequest) separation & channel binding.
	signer, _ := GenerateEd25519Key()
	profDigest, _ := ProfileV1().Digest()
	cb := bytes.Repeat([]byte{0x99}, 32)
	authMsg := SessionAuthMessage{
		ProfileDigest:  profDigest,
		LineID:         bytes.Repeat([]byte{0x12}, 16),
		Generation:     1,
		Principal:      OperatorPrincipal(signer.PublicKey()),
		RelayOrigin:    validOrigins[0],
		SessionID:      bytes.Repeat([]byte{0x34}, 16),
		ServerNonce:    bytes.Repeat([]byte{0x56}, 32),
		ChannelBinding: cb,
	}
	authSig, err := SignSessionAuth(signer, authMsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySessionAuth(signer.PublicKey(), authMsg, authSig); err != nil {
		t.Fatalf("VerifySessionAuth: %v", err)
	}
	// Replaying session proof on a different TLS connection (different cb) MUST fail.
	otherCB := authMsg
	otherCB.ChannelBinding = bytes.Repeat([]byte{0x98}, 32)
	if err := VerifySessionAuth(signer.PublicKey(), otherCB, authSig); err == nil {
		t.Fatalf("session auth verified across different TLS channel binding")
	}

	reqMsg := SessionRequestMessage{
		LineID:         authMsg.LineID,
		Generation:     1,
		SessionID:      authMsg.SessionID,
		ChannelBinding: cb,
		ReqID:          1,
		Principal:      authMsg.Principal,
		Body:           Map{{Key: "op_id", Value: "op-1"}},
	}
	qSig, err := SignSessionRequest(signer, PurposeQuery, reqMsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySessionRequest(signer.PublicKey(), PurposeQuery, reqMsg, qSig); err != nil {
		t.Fatalf("VerifySessionRequest(query): %v", err)
	}
	// Query signature MUST NOT verify as AnchorRequest.
	if err := VerifySessionRequest(signer.PublicKey(), PurposeAnchorRequest, reqMsg, qSig); err == nil {
		t.Fatalf("query signature verified as anchor_request")
	}
}

func TestP3CeremonyTamperingRejections(t *testing.T) {
	op1, _ := GenerateEd25519Key()
	op2, _ := GenerateEd25519Key()
	jSig, _ := GenerateEd25519Key()
	jEnc, _ := GenerateX25519Key()
	otherEnc, _ := GenerateX25519Key()
	lineID := bytes.Repeat([]byte{0x77}, 16)
	cd := [32]byte{0x88}

	req, err := SignJoinRequest(jSig, JoinRequest{
		RequestID:        bytes.Repeat([]byte{0x22}, 16),
		LineID:           lineID,
		Generation:       1,
		DescriptorDigest: cd,
		EncryptionKey:    jEnc.PublicKey(),
		Grant: JoinGrant{
			NamespaceID:  "ns-dev",
			ActorLimit:   2,
			Reader:       true,
			Capabilities: []string{"actor_declare"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch, secret, err := CreateJoinChallenge(op1.PublicKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := RespondJoinChallenge(jSig, jEnc, op1.PublicKey(), req, ch)
	if err != nil {
		t.Fatal(err)
	}

	// Swapping operator key fails.
	if err := VerifyJoinProof(op2.PublicKey(), req, ch, secret, proof); err == nil {
		t.Fatalf("VerifyJoinProof accepted wrong operator key")
	}
	// Swapping grant after proof fails (changes req digest and breaks body match).
	modGrant := req
	modGrant.Grant.ActorLimit = 99
	if err := VerifyJoinProof(op1.PublicKey(), modGrant, ch, secret, proof); err == nil {
		t.Fatalf("VerifyJoinProof accepted modified grant")
	}
	// Re-signing request with different grant and reusing old proof fails.
	req2, err := SignJoinRequest(jSig, JoinRequest{
		RequestID:        req.RequestID,
		LineID:           lineID,
		Generation:       1,
		DescriptorDigest: cd,
		EncryptionKey:    jEnc.PublicKey(),
		Grant: JoinGrant{
			NamespaceID:  "ns-dev",
			ActorLimit:   99,
			Reader:       true,
			Capabilities: []string{"actor_declare"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyJoinProof(op1.PublicKey(), req2, ch, secret, proof); err == nil {
		t.Fatalf("VerifyJoinProof accepted proof from different grant request")
	}
	// Replaying proof to a fresh challenge fails.
	ch2, secret2, err := CreateJoinChallenge(op1.PublicKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyJoinProof(op1.PublicKey(), req, ch2, secret2, proof); err == nil {
		t.Fatalf("VerifyJoinProof accepted proof replayed across challenges")
	}
	// Wrong encryption key trying to answer challenge fails.
	if _, err := RespondJoinChallenge(jSig, otherEnc, op1.PublicKey(), req, ch); err == nil {
		t.Fatalf("RespondJoinChallenge succeeded with wrong encryption key")
	}
	// Wrong secret rejected.
	wrongSecret := bytes.Clone(secret)
	wrongSecret[0] ^= 0xff
	if err := VerifyJoinProof(op1.PublicKey(), req, ch, wrongSecret, proof); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("VerifyJoinProof accepted wrong secret: %v", err)
	}
}
