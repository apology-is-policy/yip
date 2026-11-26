package ldrcrypto

import (
	"bytes"
	"crypto/sha256"
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

// TestIntentDigestAndChainHeadExactRecordLimit verifies Codex Turn 44:
//   - A signed intent envelope of EXACTLY DefaultMaxBytes (512 KiB = 524288 B)
//     is accepted by SignIntent and UnmarshalSignedIntent, verified cleanly,
//     and hashable by IntentDigest, ClientChainHead, and RecoveryChainHead via
//     streaming SHA-256 (matching an explicit wide-limit reference CBOR hash).
//   - One byte over the 512 KiB wire boundary (524289 B) is rejected by both
//     SignIntent and UnmarshalSignedIntent with ErrCBORLimitExceeded.
//   - Ordinary records produce 100% unchanged SHA-256 digests identical to
//     sha256.Sum256(MarshalCBOR(preimage)).
func TestIntentDigestAndChainHeadExactRecordLimit(t *testing.T) {
	signer, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	lineID := bytes.Repeat([]byte{0x31}, 16)
	profDig, err := ProfileV1().Digest()
	if err != nil {
		t.Fatal(err)
	}
	prevHead := sha256.Sum256([]byte("prev-head"))
	wideLim := Limits{MaxBytes: 2 * 1024 * 1024, MaxDepth: DefaultMaxDepth, MaxItems: DefaultMaxItems}

	refDigest := func(t *testing.T, purpose string, fields ...any) [32]byte {
		t.Helper()
		arr := make([]any, 0, 2+len(fields))
		arr = append(arr, purpose, uint64(1))
		arr = append(arr, fields...)
		enc, err := MarshalCBORWithLimits(arr, wideLim)
		if err != nil {
			t.Fatalf("reference MarshalCBORWithLimits(%s): %v", purpose, err)
		}
		return sha256.Sum256(enc)
	}

	// 1. Ordinary record: streaming digests MUST equal sha256.Sum256(MarshalCBOR(...)) verbatim.
	smallBody, err := MarshalCBOR(Map{
		{Key: "op_id", Value: "ordinary-1"},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	smallEnv, err := SignIntent(signer, smallBody)
	if err != nil {
		t.Fatal(err)
	}
	gotSmallDig, err := smallEnv.Digest()
	if err != nil {
		t.Fatalf("smallEnv.Digest: %v", err)
	}
	wantSmallDig := refDigest(t, PurposeIntent, smallEnv.RawBytes)
	if gotSmallDig != wantSmallDig {
		t.Fatalf("ordinary IntentDigest changed: got %x want %x", gotSmallDig, wantSmallDig)
	}
	gotSmallHead, err := ClientChainHead(prevHead, profDig, lineID, 1, 7, 1_700_000_000_000, "actor", smallEnv.RawBytes)
	if err != nil {
		t.Fatalf("ordinary ClientChainHead: %v", err)
	}
	wantSmallHead := refDigest(t, PurposeChain, Map{
		{Key: "gen", Value: uint64(1)},
		{Key: "intent", Value: smallEnv.RawBytes},
		{Key: "line_id", Value: lineID},
		{Key: "origin", Value: "actor"},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profDig[:]},
		{Key: "seq", Value: uint64(7)},
		{Key: "seq_time", Value: uint64(1_700_000_000_000)},
	})
	if gotSmallHead != wantSmallHead {
		t.Fatalf("ordinary ClientChainHead changed: got %x want %x", gotSmallHead, wantSmallHead)
	}
	gotSmallRecHead, err := RecoveryChainHead(prevHead, profDig, lineID, 2, 1, 1_700_000_000_000, smallEnv.RawBytes)
	if err != nil {
		t.Fatalf("ordinary RecoveryChainHead: %v", err)
	}
	wantSmallRecHead := refDigest(t, PurposeChainRecovery, Map{
		{Key: "gen", Value: uint64(2)},
		{Key: "line_id", Value: lineID},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profDig[:]},
		{Key: "recovery", Value: smallEnv.RawBytes},
		{Key: "seq", Value: uint64(1)},
		{Key: "seq_time", Value: uint64(1_700_000_000_000)},
	})
	if gotSmallRecHead != wantSmallRecHead {
		t.Fatalf("ordinary RecoveryChainHead changed: got %x want %x", gotSmallRecHead, wantSmallRecHead)
	}

	// 2. Exact 512 KiB (DefaultMaxBytes = 524288 B) signed intent envelope:
	//    Ed25519 SignedIntent envelope overhead is 96 B:
	//      a4 (1) + "v":1 (3) + "alg":"ed25519" (12) + "sig":64B (70) + "body" key+5B hdr (10) = 96 B.
	//    Body map {"d": bstr} overhead is 8 B: a1 (1) + "d" (2) + 5B bstr hdr (5) = 8 B.
	const maxBodyLen = DefaultMaxBytes - 96
	const exactBlobLen = maxBodyLen - 8
	exactBlob := make([]byte, exactBlobLen)
	for i := range exactBlob {
		exactBlob[i] = byte((i*13 + 5) & 0xff)
	}
	exactBody, err := MarshalCBOR(Map{{Key: "d", Value: exactBlob}})
	if err != nil {
		t.Fatalf("MarshalCBOR(exactBody): %v", err)
	}
	if len(exactBody) != maxBodyLen {
		t.Fatalf("exactBody len = %d, want %d", len(exactBody), maxBodyLen)
	}
	exactEnv, err := SignIntent(signer, exactBody)
	if err != nil {
		t.Fatalf("SignIntent(exact 512KiB envelope): %v", err)
	}
	if len(exactEnv.RawBytes) != DefaultMaxBytes {
		t.Fatalf("exactEnv.RawBytes len = %d, want exact DefaultMaxBytes (%d)", len(exactEnv.RawBytes), DefaultMaxBytes)
	}

	// Exact-limit envelope MUST decode and verify under DefaultLimits().
	parsedExact, err := UnmarshalSignedIntent(exactEnv.RawBytes, DefaultLimits())
	if err != nil {
		t.Fatalf("UnmarshalSignedIntent(exact 512KiB): %v", err)
	}
	if err := parsedExact.Verify(signer.PublicKey()); err != nil {
		t.Fatalf("Verify(exact 512KiB): %v", err)
	}

	// IntentDigest, ClientChainHead, and RecoveryChainHead MUST succeed on the exact 512 KiB envelope
	// and match the exact reference canonical CBOR SHA-256 preimage!
	gotExactDig, err := parsedExact.Digest()
	if err != nil {
		t.Fatalf("IntentDigest(exact 512KiB): %v", err)
	}
	wantExactDig := refDigest(t, PurposeIntent, parsedExact.RawBytes)
	if gotExactDig != wantExactDig {
		t.Fatalf("exact 512KiB IntentDigest mismatch: got %x want %x", gotExactDig, wantExactDig)
	}

	gotExactHead, err := ClientChainHead(prevHead, profDig, lineID, 1, 9, 1_700_000_001_000, "actor", parsedExact.RawBytes)
	if err != nil {
		t.Fatalf("ClientChainHead(exact 512KiB): %v", err)
	}
	wantExactHead := refDigest(t, PurposeChain, Map{
		{Key: "gen", Value: uint64(1)},
		{Key: "intent", Value: parsedExact.RawBytes},
		{Key: "line_id", Value: lineID},
		{Key: "origin", Value: "actor"},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profDig[:]},
		{Key: "seq", Value: uint64(9)},
		{Key: "seq_time", Value: uint64(1_700_000_001_000)},
	})
	if gotExactHead != wantExactHead {
		t.Fatalf("exact 512KiB ClientChainHead mismatch: got %x want %x", gotExactHead, wantExactHead)
	}

	gotExactRecHead, err := RecoveryChainHead(prevHead, profDig, lineID, 2, 1, 1_700_000_002_000, parsedExact.RawBytes)
	if err != nil {
		t.Fatalf("RecoveryChainHead(exact 512KiB): %v", err)
	}
	wantExactRecHead := refDigest(t, PurposeChainRecovery, Map{
		{Key: "gen", Value: uint64(2)},
		{Key: "line_id", Value: lineID},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profDig[:]},
		{Key: "recovery", Value: parsedExact.RawBytes},
		{Key: "seq", Value: uint64(1)},
		{Key: "seq_time", Value: uint64(1_700_000_002_000)},
	})
	if gotExactRecHead != wantExactRecHead {
		t.Fatalf("exact 512KiB RecoveryChainHead mismatch: got %x want %x", gotExactRecHead, wantExactRecHead)
	}

	// 3. One byte over the 512 KiB wire record boundary (524289 B) MUST be rejected by both
	//    SignIntent and UnmarshalSignedIntent!
	overBody, err := MarshalCBOR(Map{{Key: "d", Value: make([]byte, exactBlobLen+1)}})
	if err != nil {
		t.Fatalf("MarshalCBOR(overBody): %v", err)
	}
	if _, err := SignIntent(signer, overBody); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("SignIntent(512KiB+1): got %v, want ErrCBORLimitExceeded", err)
	}
	overSig, err := SignDomain(signer, PurposeIntentSignatureDigest, 1, overBody)
	if err != nil {
		t.Fatal(err)
	}
	overWire, err := MarshalCBORWithLimits(Map{
		{Key: "alg", Value: AlgEd25519},
		{Key: "body", Value: overBody},
		{Key: "sig", Value: overSig},
		{Key: "v", Value: uint64(1)},
	}, wideLim)
	if err != nil {
		t.Fatal(err)
	}
	if len(overWire) != DefaultMaxBytes+1 {
		t.Fatalf("overWire len = %d, want %d", len(overWire), DefaultMaxBytes+1)
	}
	if _, err := UnmarshalSignedIntent(overWire, DefaultLimits()); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("UnmarshalSignedIntent(512KiB+1): got %v, want ErrCBORLimitExceeded", err)
	}
}

// TestRespondJoinChallengeRejectsNon32ByteSecret verifies Codex Turn 54:
// RespondJoinChallenge enforces the same 32-byte challenge secret invariant as
// CreateJoinChallenge and VerifyJoinProof, refusing validly HPKE-encrypted
// challenges whose plaintext length is not 32 bytes before signing any proof.
func TestRespondJoinChallengeRejectsNon32ByteSecret(t *testing.T) {
	op, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	jSig, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	jEnc, err := GenerateX25519Key()
	if err != nil {
		t.Fatal(err)
	}
	lineID := bytes.Repeat([]byte{0x51}, 16)
	cd := [32]byte{0x62}

	req, err := SignJoinRequest(jSig, JoinRequest{
		RequestID:        bytes.Repeat([]byte{0x73}, 16),
		LineID:           lineID,
		Generation:       1,
		DescriptorDigest: cd,
		EncryptionKey:    jEnc.PublicKey(),
		Grant: JoinGrant{
			NamespaceID: "ns-p3",
			ActorLimit:  2,
			Reader:      true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reqDig, err := VerifyJoinRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	challengeID := bytes.Repeat([]byte{0x84}, 16)
	ctxBytes, err := joinChallengeContext(req.LineID, req.Generation, req.RequestID, reqDig, op.PublicKey(), req.SigningKey, req.EncryptionKey, challengeID)
	if err != nil {
		t.Fatal(err)
	}

	craftChallenge := func(t *testing.T, secret []byte) JoinChallenge {
		t.Helper()
		enc, ct, err := HPKESealBase(req.EncryptionKey, ctxBytes, ctxBytes, secret)
		if err != nil {
			t.Fatalf("HPKESealBase(len=%d): %v", len(secret), err)
		}
		return JoinChallenge{
			ChallengeID:   challengeID,
			LineID:        req.LineID,
			Generation:    req.Generation,
			RequestID:     req.RequestID,
			RequestDigest: reqDig,
			OperatorKey:   op.PublicKey(),
			SigningKey:    req.SigningKey,
			EncryptionKey: req.EncryptionKey,
			Enc:           enc,
			Ciphertext:    ct,
		}
	}

	for _, badLen := range []int{0, 1, 16, 31, 33, 64} {
		badSecret := bytes.Repeat([]byte{0x99}, badLen)
		ch := craftChallenge(t, badSecret)
		pr, err := RespondJoinChallenge(jSig, jEnc, op.PublicKey(), req, ch)
		if !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("secret len %d: RespondJoinChallenge got %v, want ErrInvalidCeremony", badLen, err)
		}
		if len(pr.Sig) != 0 {
			t.Fatalf("secret len %d: RespondJoinChallenge returned non-empty signature on refusal", badLen)
		}
	}

	// Exact 32-byte secret MUST still succeed and pass VerifyJoinProof.
	goodSecret := bytes.Repeat([]byte{0xaa}, JoinChallengeSecretSize)
	goodCh := craftChallenge(t, goodSecret)
	pr, err := RespondJoinChallenge(jSig, jEnc, op.PublicKey(), req, goodCh)
	if err != nil {
		t.Fatalf("valid 32-byte secret RespondJoinChallenge: %v", err)
	}
	if err := VerifyJoinProof(op.PublicKey(), req, goodCh, goodSecret, pr); err != nil {
		t.Fatalf("valid 32-byte secret VerifyJoinProof: %v", err)
	}
}
