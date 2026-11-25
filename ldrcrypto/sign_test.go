package ldrcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

func TestEd25519RFC8032Vectors(t *testing.T) {
	vectors := []struct {
		name string
		seed string
		pub  string
		msg  string
		sig  string
	}{
		{
			// RFC 8032 Section 7.1 TEST 1 (empty message)
			name: "RFC8032_TEST_1",
			seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			msg:  "",
			sig:  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			// RFC 8032 Section 7.1 TEST 2 (1-byte message 0x72)
			name: "RFC8032_TEST_2",
			seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			msg:  "72",
			sig:  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			priv, err := NewEd25519PrivateKeyFromSeed(mustHex(t, v.seed))
			if err != nil {
				t.Fatalf("NewEd25519PrivateKeyFromSeed: %v", err)
			}
			pub := priv.PublicKey()
			if !bytes.Equal(pub.Bytes, mustHex(t, v.pub)) {
				t.Fatalf("pub mismatch: got %x, want %s", pub.Bytes, v.pub)
			}
			if err := pub.ValidateSigningKey(); err != nil {
				t.Fatalf("ValidateSigningKey: %v", err)
			}
			msg := mustHex(t, v.msg)
			sig, err := priv.SignRaw(msg)
			if err != nil {
				t.Fatalf("SignRaw: %v", err)
			}
			if !bytes.Equal(sig, mustHex(t, v.sig)) {
				t.Fatalf("sig mismatch:\ngot:  %x\nwant: %s", sig, v.sig)
			}
			if err := VerifyRaw(pub, msg, sig); err != nil {
				t.Fatalf("VerifyRaw failed on valid RFC 8032 vector: %v", err)
			}
			// Tampered message must fail.
			if err := VerifyRaw(pub, append(bytes.Clone(msg), 0x00), sig); err == nil {
				t.Fatalf("VerifyRaw accepted modified message")
			}
			// Bit-flipped signature must fail.
			badSig := bytes.Clone(sig)
			badSig[0] ^= 0x01
			if err := VerifyRaw(pub, msg, badSig); err == nil {
				t.Fatalf("VerifyRaw accepted bit-flipped signature")
			}
		})
	}
}

func bigIntToLittleEndian32(v *big.Int) []byte {
	be := make([]byte, 32)
	v.FillBytes(be)
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = be[31-i]
	}
	return le
}

func TestEd25519StrictCanonicalAndSmallOrderRejections(t *testing.T) {
	priv, err := NewEd25519PrivateKeyFromSeed(mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	msg := []byte("strict-ed25519-test")
	sig, err := priv.SignRaw(msg)
	if err != nil {
		t.Fatal(err)
	}

	// 1. S + L malleation (RFC 8032 §8.4) MUST be rejected.
	sOrig := littleEndianToBigInt(sig[32:64])
	sPlusL := new(big.Int).Add(sOrig, ed25519L)
	malleated := bytes.Clone(sig)
	copy(malleated[32:64], bigIntToLittleEndian32(sPlusL))
	if err := VerifyRaw(pub, msg, malleated); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for S+L malleation, got %v", err)
	}

	// 2. S == L MUST be rejected.
	sigEqL := bytes.Clone(sig)
	copy(sigEqL[32:64], bigIntToLittleEndian32(ed25519L))
	if err := VerifyRaw(pub, msg, sigEqL); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for S==L, got %v", err)
	}

	// 3. All 8 small-order / torsion points on Edwards25519 MUST be rejected as
	//    both public keys A and signature R components.
	smallOrderPoints := []struct {
		name string
		hex  string
	}{
		{"order1_identity", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"order2_neg1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"order4_pos", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"order4_neg", "0000000000000000000000000000000000000000000000000000000000000080"},
		{"order8_a", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"},
		{"order8_b", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"},
		{"order8_c", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"},
		{"order8_d", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"},
	}
	for _, pt := range smallOrderPoints {
		b := mustHex(t, pt.hex)
		badPub := PublicKey{Alg: AlgEd25519, Bytes: b}
		if err := badPub.Validate(); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("small-order pubkey %s accepted: err=%v", pt.name, err)
		}
		badSigR := bytes.Clone(sig)
		copy(badSigR[:32], b)
		if err := VerifyRaw(pub, msg, badSigR); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("small-order R %s accepted: err=%v", pt.name, err)
		}
	}

	// Classic identity forgery (A = identity, R = identity, S = 0) MUST fail.
	idBytes := mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	forgerySig := make([]byte, 64)
	copy(forgerySig[:32], idBytes)
	if err := VerifyRaw(PublicKey{Alg: AlgEd25519, Bytes: idBytes}, msg, forgerySig); err == nil {
		t.Fatalf("small-order forgery accepted")
	}

	// 4. Non-canonical y >= p (y = p = 2^255-19, y = p+1) and x == -0 MUST fail.
	nonCanon := []struct {
		name string
		hex  string
	}{
		{"y_eq_p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"y_eq_p_plus_1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"x_neg_zero_at_y1", "0100000000000000000000000000000000000000000000000000000000000080"},
		{"x_neg_zero_at_ym1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"wrong_len_31", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
	}
	for _, nc := range nonCanon {
		pk := PublicKey{Alg: AlgEd25519, Bytes: mustHex(t, nc.hex)}
		if err := pk.Validate(); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("non-canonical Ed25519 key %s accepted: err=%v", nc.name, err)
		}
	}
}

func TestECDSAP256StrictLowSAndValidation(t *testing.T) {
	priv, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatalf("GenerateECDSAP256Key: %v", err)
	}
	pub := priv.PublicKey()
	if err := pub.ValidateSigningKey(); err != nil {
		t.Fatalf("ValidateSigningKey: %v", err)
	}
	if len(pub.Bytes) != ECDSAP256PublicKeySize || pub.Bytes[0] != 0x04 {
		t.Fatalf("unexpected P-256 public key format: len=%d prefix=0x%02x", len(pub.Bytes), pub.Bytes[0])
	}

	msg := []byte("ecdsa-p256-strict-low-s")
	var sampleSig []byte
	for i := 0; i < 64; i++ {
		sig, err := priv.SignRaw(msg)
		if err != nil {
			t.Fatalf("SignRaw[%d]: %v", i, err)
		}
		if len(sig) != ECDSAP256SignatureSize {
			t.Fatalf("sig len %d != 64", len(sig))
		}
		s := new(big.Int).SetBytes(sig[32:64])
		if s.Cmp(p256HalfN) > 0 {
			t.Fatalf("SignRaw emitted high-S signature")
		}
		if err := VerifyRaw(pub, msg, sig); err != nil {
			t.Fatalf("VerifyRaw[%d]: %v", i, err)
		}
		sampleSig = sig
	}

	// Construct the malleated high-S twin (r, N - s). Standard ecdsa.Verify
	// accepts it, confirming our malleation is mathematically valid, while
	// VerifyRaw MUST strictly reject it.
	r := new(big.Int).SetBytes(sampleSig[0:32])
	s := new(big.Int).SetBytes(sampleSig[32:64])
	highS := new(big.Int).Sub(p256N, s)
	ecdsaPub, err := parseECDSAP256PublicKey(pub.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(ecdsaPub, digest[:], r, highS) {
		t.Fatalf("sanity check failed: high-S twin should verify under standard ecdsa.Verify")
	}
	malleated := make([]byte, 64)
	r.FillBytes(malleated[0:32])
	highS.FillBytes(malleated[32:64])
	if err := VerifyRaw(pub, msg, malleated); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("VerifyRaw accepted high-S ECDSA signature: err=%v", err)
	}

	// Reject r=0, s=0, r=N, wrong length.
	zeroR := bytes.Clone(sampleSig)
	clear(zeroR[0:32])
	if err := VerifyRaw(pub, msg, zeroR); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("accepted r=0: %v", err)
	}
	zeroS := bytes.Clone(sampleSig)
	clear(zeroS[32:64])
	if err := VerifyRaw(pub, msg, zeroS); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("accepted s=0: %v", err)
	}
	rEqN := bytes.Clone(sampleSig)
	p256N.FillBytes(rEqN[0:32])
	if err := VerifyRaw(pub, msg, rEqN); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("accepted r=N: %v", err)
	}
	if err := VerifyRaw(pub, msg, sampleSig[:63]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("accepted truncated ECDSA sig: %v", err)
	}

	// Reject compressed SEC1, off-curve point, infinity/zero, wrong length.
	compressed := make([]byte, 33)
	compressed[0] = 0x02
	copy(compressed[1:], pub.Bytes[1:33])
	if err := (PublicKey{Alg: AlgECDSAP256, Bytes: compressed}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("accepted compressed P-256 key: %v", err)
	}
	offCurve := bytes.Clone(pub.Bytes)
	offCurve[64] ^= 0x01
	if err := (PublicKey{Alg: AlgECDSAP256, Bytes: offCurve}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("accepted off-curve P-256 key: %v", err)
	}
	allZero := make([]byte, 65)
	allZero[0] = 0x04
	if err := (PublicKey{Alg: AlgECDSAP256, Bytes: allZero}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("accepted (0,0) P-256 key: %v", err)
	}
	// Verify cross-curve confusion on private key wrapper.
	p384Priv, _ := ecdsa.GenerateKey(elliptic.P384(), bytes.NewReader(make([]byte, 128)))
	if p384Priv != nil {
		if _, err := NewECDSAP256PrivateKey(p384Priv); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("accepted P-384 private key")
		}
	}
}

func TestX25519KeyValidationAndRoleSeparation(t *testing.T) {
	xk, err := GenerateX25519Key()
	if err != nil {
		t.Fatal(err)
	}
	xpub := xk.PublicKey()
	if err := xpub.ValidateEncryptionKey(); err != nil {
		t.Fatalf("valid X25519 key rejected: %v", err)
	}
	if err := xpub.ValidateSigningKey(); !errors.Is(err, ErrKeyRoleMismatch) {
		t.Fatalf("X25519 key accepted as signing key: %v", err)
	}

	// Setting high bit 255 on a valid X25519 public key makes it non-canonical >= p.
	nonCanonHighBit := bytes.Clone(xpub.Bytes)
	nonCanonHighBit[31] |= 0x80
	if err := (PublicKey{Alg: AlgX25519, Bytes: nonCanonHighBit}).Validate(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("non-canonical X25519 high-bit key accepted: %v", err)
	}

	// Known Curve25519 low-order points and u >= p MUST be rejected.
	badX25519 := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	for _, h := range badX25519 {
		if err := (PublicKey{Alg: AlgX25519, Bytes: mustHex(t, h)}).Validate(); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("bad X25519 pubkey %s accepted: %v", h, err)
		}
	}

	// Signing key must fail ValidateEncryptionKey.
	edk, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	if err := edk.PublicKey().ValidateEncryptionKey(); !errors.Is(err, ErrKeyRoleMismatch) {
		t.Fatalf("Ed25519 key accepted as encryption key: %v", err)
	}
}

func TestSigningDomainSeparation(t *testing.T) {
	edk, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	p256k, err := GenerateECDSAP256Key()
	if err != nil {
		t.Fatal(err)
	}
	body, err := MarshalCBOR(Map{{Key: "op", Value: "call_open"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, signer := range []Signer{edk, p256k} {
		sig, err := SignDomain(signer, PurposeIntentSignatureDigest, 1, body)
		if err != nil {
			t.Fatalf("SignDomain(%s): %v", signer.PublicKey().Alg, err)
		}
		if err := VerifyDomain(signer.PublicKey(), PurposeIntentSignatureDigest, 1, body, sig); err != nil {
			t.Fatalf("VerifyDomain(%s): %v", signer.PublicKey().Alg, err)
		}
		// Cross-purpose replay MUST fail.
		if err := VerifyDomain(signer.PublicKey(), PurposeDescriptorSig, 1, body, sig); err == nil {
			t.Fatalf("cross-purpose replay accepted for %s", signer.PublicKey().Alg)
		}
		// Cross-version replay MUST fail.
		if err := VerifyDomain(signer.PublicKey(), PurposeIntentSignatureDigest, 2, body, sig); err == nil {
			t.Fatalf("cross-version replay accepted for %s", signer.PublicKey().Alg)
		}
	}
}
