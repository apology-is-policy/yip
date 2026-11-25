package ldrcrypto

import (
	"bytes"
	"errors"
	"testing"
)

// TestHPKERFC9180AppendixA11 verifies our DHKEM(X25519, HKDF-SHA256) +
// HKDF-SHA256 key schedule, DeriveKeyPair, Encap/Decap, nonce computation,
// and AEAD seal/open byte-for-byte against official RFC 9180 Appendix A.1.1.
func TestHPKERFC9180AppendixA11(t *testing.T) {
	info := mustHex(t, "4f6465206f6e2061204772656369616e2055726e")
	ikmE := mustHex(t, "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234")
	wantPkEm := mustHex(t, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
	wantSkEm := mustHex(t, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	ikmR := mustHex(t, "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037")
	wantPkRm := mustHex(t, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
	wantSkRm := mustHex(t, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
	wantShared := mustHex(t, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
	wantKSCtx := mustHex(t, "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449")
	wantSecret := mustHex(t, "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397")
	wantKey := mustHex(t, "4531685d41d65f03dc48f6b8302c05b0")
	wantBaseNonce := mustHex(t, "56d890e5accaaf011cff4b7d")
	wantExp := mustHex(t, "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")

	skE, err := DeriveX25519KeyPair(ikmE)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair(ikmE): %v", err)
	}
	if !bytes.Equal(skE.Bytes(), wantSkEm) {
		t.Fatalf("skEm mismatch: got %x, want %x", skE.Bytes(), wantSkEm)
	}
	if !bytes.Equal(skE.PublicKey().Bytes, wantPkEm) {
		t.Fatalf("pkEm mismatch: got %x, want %x", skE.PublicKey().Bytes, wantPkEm)
	}

	skR, err := DeriveX25519KeyPair(ikmR)
	if err != nil {
		t.Fatalf("DeriveX25519KeyPair(ikmR): %v", err)
	}
	if !bytes.Equal(skR.Bytes(), wantSkRm) {
		t.Fatalf("skRm mismatch: got %x, want %x", skR.Bytes(), wantSkRm)
	}
	if !bytes.Equal(skR.PublicKey().Bytes, wantPkRm) {
		t.Fatalf("pkRm mismatch: got %x, want %x", skR.PublicKey().Bytes, wantPkRm)
	}

	sender, err := hpkeSetupBaseSenderWithKey(hpkeAEADAES128, skR.PublicKey(), skE.priv, info)
	if err != nil {
		t.Fatalf("hpkeSetupBaseSenderWithKey: %v", err)
	}
	recipient, err := hpkeSetupBaseRecipient(hpkeAEADAES128, skR, sender.enc, info)
	if err != nil {
		t.Fatalf("hpkeSetupBaseRecipient: %v", err)
	}

	for name, ctx := range map[string]*hpkeContext{"sender": sender, "recipient": recipient} {
		if !bytes.Equal(ctx.enc, wantPkEm) {
			t.Fatalf("%s enc mismatch: got %x, want %x", name, ctx.enc, wantPkEm)
		}
		if !bytes.Equal(ctx.sharedSecret, wantShared) {
			t.Fatalf("%s shared_secret mismatch: got %x, want %x", name, ctx.sharedSecret, wantShared)
		}
		if !bytes.Equal(ctx.keyScheduleContext, wantKSCtx) {
			t.Fatalf("%s key_schedule_context mismatch: got %x, want %x", name, ctx.keyScheduleContext, wantKSCtx)
		}
		if !bytes.Equal(ctx.secret, wantSecret) {
			t.Fatalf("%s secret mismatch: got %x, want %x", name, ctx.secret, wantSecret)
		}
		if !bytes.Equal(ctx.key, wantKey) {
			t.Fatalf("%s key mismatch: got %x, want %x", name, ctx.key, wantKey)
		}
		if !bytes.Equal(ctx.baseNonce, wantBaseNonce) {
			t.Fatalf("%s base_nonce mismatch: got %x, want %x", name, ctx.baseNonce, wantBaseNonce)
		}
		if !bytes.Equal(ctx.exporterSecret, wantExp) {
			t.Fatalf("%s exporter_secret mismatch: got %x, want %x", name, ctx.exporterSecret, wantExp)
		}
	}

	pt := mustHex(t, "4265617574792069732074727574682c20747275746820626561757479")
	encryptions := []struct {
		seq   uint64
		aad   string
		nonce string
		ct    string
	}{
		{0, "436f756e742d30", "56d890e5accaaf011cff4b7d", "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"},
		{1, "436f756e742d31", "56d890e5accaaf011cff4b7c", "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"},
		{2, "436f756e742d32", "56d890e5accaaf011cff4b7f", "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"},
		{4, "436f756e742d34", "56d890e5accaaf011cff4b79", "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"},
		{255, "436f756e742d323535", "56d890e5accaaf011cff4b82", "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"},
		{256, "436f756e742d323536", "56d890e5accaaf011cff4a7d", "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"},
	}

	for _, e := range encryptions {
		aad := mustHex(t, e.aad)
		wantNonce := mustHex(t, e.nonce)
		wantCT := mustHex(t, e.ct)
		if gotNonce := sender.computeNonce(e.seq); !bytes.Equal(gotNonce, wantNonce) {
			t.Fatalf("seq %d nonce mismatch: got %x, want %x", e.seq, gotNonce, wantNonce)
		}
		gotCT := sender.sealSeq(e.seq, aad, pt)
		if !bytes.Equal(gotCT, wantCT) {
			t.Fatalf("seq %d ct mismatch:\ngot:  %x\nwant: %x", e.seq, gotCT, wantCT)
		}
		gotPT, err := recipient.openSeq(e.seq, aad, gotCT)
		if err != nil {
			t.Fatalf("seq %d openSeq: %v", e.seq, err)
		}
		if !bytes.Equal(gotPT, pt) {
			t.Fatalf("seq %d pt mismatch", e.seq)
		}
	}
}

// TestHPKEAES256GCMProfileSuite checks the Profile v1 AES-256-GCM suite against
// the official RFC 9180 KEM=0x0020/KDF=0x0001/AEAD=0x0002 key derivation inputs
// plus round-trip and negative tests.
func TestHPKEAES256GCMProfileSuite(t *testing.T) {
	ikmE := mustHex(t, "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9")
	wantEnc := mustHex(t, "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256")
	ikmR := mustHex(t, "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee")
	wantSkRm := mustHex(t, "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d")
	wantPkRm := mustHex(t, "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c")
	info := mustHex(t, "4f6465206f6e2061204772656369616e2055726e")

	skE, err := DeriveX25519KeyPair(ikmE)
	if err != nil {
		t.Fatal(err)
	}
	skR, err := DeriveX25519KeyPair(ikmR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skE.PublicKey().Bytes, wantEnc) {
		t.Fatalf("AES-256-GCM vector enc mismatch: got %x, want %x", skE.PublicKey().Bytes, wantEnc)
	}
	if !bytes.Equal(skR.Bytes(), wantSkRm) || !bytes.Equal(skR.PublicKey().Bytes, wantPkRm) {
		t.Fatalf("AES-256-GCM vector recipient key mismatch")
	}

	sender, err := hpkeSetupBaseSenderWithKey(hpkeAEADAES256, skR.PublicKey(), skE.priv, info)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.key) != 32 {
		t.Fatalf("AES-256-GCM key length %d != 32", len(sender.key))
	}
	recipient, err := hpkeSetupBaseRecipient(hpkeAEADAES256, skR, sender.enc, info)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sender.key, recipient.key) || !bytes.Equal(sender.baseNonce, recipient.baseNonce) {
		t.Fatalf("sender/recipient key schedule diverged")
	}

	// Single-shot HPKESealBase / HPKEOpenBase with fresh ephemeral keys.
	pt := []byte("top-secret-epoch-key-material-32")
	aad := []byte("ldr-aad-context")
	enc1, ct1, err := HPKESealBase(skR.PublicKey(), info, aad, pt)
	if err != nil {
		t.Fatalf("HPKESealBase(1): %v", err)
	}
	enc2, ct2, err := HPKESealBase(skR.PublicKey(), info, aad, pt)
	if err != nil {
		t.Fatalf("HPKESealBase(2): %v", err)
	}
	if bytes.Equal(enc1, enc2) || bytes.Equal(ct1, ct2) {
		t.Fatalf("HPKESealBase reused ephemeral key")
	}
	got, err := HPKEOpenBase(skR, enc1, info, aad, ct1)
	if err != nil {
		t.Fatalf("HPKEOpenBase: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("HPKEOpenBase plaintext mismatch")
	}

	// Negative tests.
	otherR, _ := GenerateX25519Key()
	if _, err := HPKEOpenBase(otherR, enc1, info, aad, ct1); !errors.Is(err, ErrHPKEDecryptFailed) {
		t.Fatalf("wrong recipient succeeded: %v", err)
	}
	if _, err := HPKEOpenBase(skR, enc1, []byte("wrong-info"), aad, ct1); !errors.Is(err, ErrHPKEDecryptFailed) {
		t.Fatalf("wrong info succeeded: %v", err)
	}
	if _, err := HPKEOpenBase(skR, enc1, info, []byte("wrong-aad"), ct1); !errors.Is(err, ErrHPKEDecryptFailed) {
		t.Fatalf("wrong aad succeeded: %v", err)
	}
	badCT := bytes.Clone(ct1)
	badCT[len(badCT)-1] ^= 0x01
	if _, err := HPKEOpenBase(skR, enc1, info, aad, badCT); !errors.Is(err, ErrHPKEDecryptFailed) {
		t.Fatalf("tampered ct succeeded: %v", err)
	}
	badEnc := bytes.Clone(enc1)
	badEnc[0] ^= 0x01
	if _, err := HPKEOpenBase(skR, badEnc, info, aad, ct1); err == nil {
		t.Fatalf("tampered enc succeeded")
	}
	// All-zero low-order enc rejected as invalid key.
	if _, err := HPKEOpenBase(skR, make([]byte, 32), info, aad, ct1); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("low-order enc not rejected as ErrInvalidKey: %v", err)
	}
}

func TestEpochWrapAndUnwrap(t *testing.T) {
	sigPriv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	encPriv, err := GenerateX25519Key()
	if err != nil {
		t.Fatal(err)
	}
	credID, err := DeriveCredID(sigPriv.PublicKey(), encPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	profDigest, err := ProfileV1().Digest()
	if err != nil {
		t.Fatal(err)
	}
	rsDigest, err := ReaderSetDigest([][32]byte{credID})
	if err != nil {
		t.Fatal(err)
	}
	epochKey, err := GenerateEpochKey()
	if err != nil {
		t.Fatal(err)
	}

	ctx := EpochWrapContext{
		LineID:          bytes.Repeat([]byte{0x42}, 16),
		Generation:      1,
		ProfileDigest:   profDigest,
		NewEpoch:        1,
		ExpectEpoch:     0,
		AuthEpoch:       2,
		OpIdentityBytes: []byte("op-identity-canonical"),
		RecipientCredID: credID,
		RecipientEncKey: encPriv.PublicKey(),
		ReaderSetDigest: rsDigest,
	}

	wrapBytes, err := WrapEpochKey(epochKey, ctx)
	if err != nil {
		t.Fatalf("WrapEpochKey: %v", err)
	}
	gotKey, err := UnwrapEpochKey(encPriv, wrapBytes, ctx)
	if err != nil {
		t.Fatalf("UnwrapEpochKey: %v", err)
	}
	if !bytes.Equal(gotKey, epochKey) {
		t.Fatalf("unwrapped epoch key mismatch")
	}

	// Mutating any context field MUST break unwrap.
	mutations := []func(*EpochWrapContext){
		func(c *EpochWrapContext) { c.Generation = 2 },
		func(c *EpochWrapContext) { c.NewEpoch = 2 },
		func(c *EpochWrapContext) { c.ExpectEpoch = 1 },
		func(c *EpochWrapContext) { c.AuthEpoch = 3 },
		func(c *EpochWrapContext) { c.LineID = bytes.Repeat([]byte{0x43}, 16) },
		func(c *EpochWrapContext) { c.ProfileDigest[0] ^= 0xff },
		func(c *EpochWrapContext) { c.ReaderSetDigest[0] ^= 0xff },
		func(c *EpochWrapContext) { c.OpIdentityBytes = []byte("other-op") },
		func(c *EpochWrapContext) { c.RecipientCredID[0] ^= 0xff },
	}
	for i, mutate := range mutations {
		mod := ctx
		mutate(&mod)
		if _, err := UnwrapEpochKey(encPriv, wrapBytes, mod); !errors.Is(err, ErrHPKEDecryptFailed) {
			t.Fatalf("context mutation %d unexpectedly succeeded: %v", i, err)
		}
	}

	// Short epoch key rejected on wrap.
	if _, err := WrapEpochKey([]byte("too-short"), ctx); !errors.Is(err, ErrHPKEInvalidInput) {
		t.Fatalf("expected ErrHPKEInvalidInput for short epoch key, got %v", err)
	}
}
