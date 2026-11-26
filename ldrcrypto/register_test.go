package ldrcrypto

import (
	"bytes"
	"testing"
)

func TestRegisterEnvelopeAndPayloadContext(t *testing.T) {
	lineID := bytes.Repeat([]byte{0x42}, 16)
	profDig, err := ProfileV1().Digest()
	if err != nil {
		t.Fatal(err)
	}
	epochKey, err := GenerateEpochKey()
	if err != nil {
		t.Fatal(err)
	}

	edSigner, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	p256Signer, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := GenerateX25519Key()
	if err != nil {
		t.Fatal(err)
	}
	credID, err := DeriveCredID(edSigner.PublicKey(), encKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		signer Signer
		other  Signer
		reg    string
	}{
		{"ed25519-presence", edSigner, p256Signer, "presence"},
		{"p256-roadmap", p256Signer, edSigner, "roadmap"},
		{"ed25519-resource", edSigner, p256Signer, "resource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctxBytes, err := RegisterPayloadContextBytes(profDig, lineID, 1, tc.reg, "alice", credID, 1, 2, "inc-1", 3, 7)
			if err != nil {
				t.Fatalf("RegisterPayloadContextBytes: %v", err)
			}
			plain := []byte(`{"tip":"abc1234","branch":"main","busy":"testing"}`)
			pkg, err := SealPayload(epochKey, ctxBytes, plain)
			if err != nil {
				t.Fatalf("SealPayload: %v", err)
			}
			commit, err := CommitPayload(pkg)
			if err != nil {
				t.Fatalf("CommitPayload: %v", err)
			}
			env := RegisterEnvelope{
				Version:       1,
				LineID:        lineID,
				Generation:    1,
				ProfileDigest: profDig,
				Register:      tc.reg,
				ActorID:       "alice",
				CredID:        credID,
				BindingGen:    1,
				WriterRev:     2,
				Incarnation:   "inc-1",
				KeyEpoch:      3,
				Counter:       7,
				PayloadCommit: commit,
			}
			raw, err := SignRegisterEnvelope(tc.signer, env)
			if err != nil {
				t.Fatalf("SignRegisterEnvelope: %v", err)
			}
			got, err := VerifyRegisterEnvelope(raw, tc.signer.PublicKey())
			if err != nil {
				t.Fatalf("VerifyRegisterEnvelope: %v", err)
			}
			if got.ActorID != "alice" || got.Register != tc.reg || got.Counter != 7 || !got.PayloadCommit.Equal(commit) {
				t.Fatalf("parsed envelope mismatch: %+v", got)
			}

			// Wrong verifier key must fail.
			if _, err := VerifyRegisterEnvelope(raw, tc.other.PublicKey()); err == nil {
				t.Fatal("VerifyRegisterEnvelope accepted wrong key")
			}

			// Tampered context must fail AEAD authentication.
			badCtx, err := RegisterPayloadContextBytes(profDig, lineID, 1, tc.reg, "alice", credID, 1, 2, "inc-1", 3, 8)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenPayload(epochKey, badCtx, pkg); err == nil {
				t.Fatal("OpenPayload accepted mismatched register counter context")
			}
			decPlain, err := OpenPayload(epochKey, ctxBytes, pkg)
			if err != nil || !bytes.Equal(decPlain, plain) {
				t.Fatalf("OpenPayload roundtrip failed: err=%v plain=%q", err, decPlain)
			}
		})
	}

	// Negative field validations.
	validCommit, _ := CommitPayload([]byte("x"))
	base := RegisterEnvelope{
		Version: 1, LineID: lineID, Generation: 1, ProfileDigest: profDig,
		Register: "presence", ActorID: "a1", CredID: credID,
		BindingGen: 1, WriterRev: 1, Incarnation: "i1", KeyEpoch: 1, Counter: 0,
		PayloadCommit: validCommit,
	}
	badCases := []struct {
		name string
		mod  func(*RegisterEnvelope)
	}{
		{"unknown_register", func(e *RegisterEnvelope) { e.Register = "secret" }},
		{"empty_actor", func(e *RegisterEnvelope) { e.ActorID = "" }},
		{"zero_binding_gen", func(e *RegisterEnvelope) { e.BindingGen = 0 }},
		{"zero_writer_rev", func(e *RegisterEnvelope) { e.WriterRev = 0 }},
		{"empty_incarnation", func(e *RegisterEnvelope) { e.Incarnation = "" }},
		{"zero_key_epoch", func(e *RegisterEnvelope) { e.KeyEpoch = 0 }},
		{"empty_payload_commit", func(e *RegisterEnvelope) { e.PayloadCommit = EmptyPayloadCommit() }},
		{"oversized_payload_commit", func(e *RegisterEnvelope) { e.PayloadCommit.Length = MaxRegisterBodyBytes + 1 }},
		{"counter_out_of_domain", func(e *RegisterEnvelope) { e.Counter = MaxCounter + 1 }},
		{"short_line_id", func(e *RegisterEnvelope) { e.LineID = []byte("short") }},
	}
	for _, bc := range badCases {
		e := base
		bc.mod(&e)
		if _, err := SignRegisterEnvelope(edSigner, e); err == nil {
			t.Fatalf("SignRegisterEnvelope accepted invalid case %s", bc.name)
		}
	}
}
