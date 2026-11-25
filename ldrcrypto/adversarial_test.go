package ldrcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	mrand "math/rand"
	"testing"
)

// TestCBORCanonicalUniquenessProperty asserts the core canonical CBOR theorem:
// for any arbitrary or mutated byte slice b, UnmarshalCBORDefault(b) must never
// panic, and if it succeeds with value v, MarshalCBOR(v) MUST equal b verbatim.
func TestCBORCanonicalUniquenessProperty(t *testing.T) {
	rng := mrand.New(mrand.NewSource(20261125))

	// Seed corpus of valid canonical encodings.
	seeds := [][]byte{}
	validObjs := []any{
		uint64(0),
		uint64(23),
		uint64(24),
		uint64(255),
		uint64(256),
		uint64(65535),
		uint64(65536),
		uint64(4294967295),
		uint64(4294967296),
		MaxCounter,
		true,
		false,
		[]byte{},
		[]byte{1, 2, 3, 4, 5},
		"",
		"hello",
		[]any{uint64(1), "two", []byte{3}, true, false},
		Map{
			{Key: "a", Value: uint64(0)},
			{Key: "b", Value: []any{uint64(1), uint64(2)}},
			{Key: "aa", Value: Map{{Key: "k", Value: []byte{0xde, 0xad}}}},
		},
	}
	for _, obj := range validObjs {
		b, err := MarshalCBOR(obj)
		if err != nil {
			t.Fatalf("MarshalCBOR seed: %v", err)
		}
		seeds = append(seeds, b)
	}

	checkInvariant := func(b []byte) {
		val, err := UnmarshalCBORDefault(b)
		if err != nil {
			return
		}
		reenc, err := MarshalCBOR(val)
		if err != nil {
			t.Fatalf("accepted CBOR %x failed to re-encode: %v", b, err)
		}
		if !bytes.Equal(reenc, b) {
			t.Fatalf("NON-CANONICAL CBOR ACCEPTED!\ninput: %x\nreenc: %x\nval:   %#v", b, reenc, val)
		}
	}

	// 1. Single-byte values 0x00..0xff and all 2-byte prefixes with mutations.
	for b0 := 0; b0 <= 0xff; b0++ {
		checkInvariant([]byte{byte(b0)})
		for b1 := 0; b1 <= 0xff; b1 += 7 {
			checkInvariant([]byte{byte(b0), byte(b1)})
		}
	}

	// 2. 2000 random mutations of valid seeds (bit flips, truncations, appends, swaps).
	for i := 0; i < 2000; i++ {
		base := bytes.Clone(seeds[rng.Intn(len(seeds))])
		switch rng.Intn(5) {
		case 0: // flip 1..3 random bits
			if len(base) > 0 {
				for k := 0; k < 1+rng.Intn(3); k++ {
					pos := rng.Intn(len(base))
					base[pos] ^= byte(1 << uint(rng.Intn(8)))
				}
			}
		case 1: // truncate
			if len(base) > 0 {
				base = base[:rng.Intn(len(base))]
			}
		case 2: // append random bytes
			extra := make([]byte, 1+rng.Intn(8))
			for j := range extra {
				extra[j] = byte(rng.Intn(256))
			}
			base = append(base, extra...)
		case 3: // swap two bytes
			if len(base) >= 2 {
				a, b := rng.Intn(len(base)), rng.Intn(len(base))
				base[a], base[b] = base[b], base[a]
			}
		case 4: // purely random bytes
			base = make([]byte, 1+rng.Intn(40))
			for j := range base {
				base[j] = byte(rng.Intn(256))
			}
		}
		checkInvariant(base)
	}
}

func TestAdversarialEnvelopeAndDescriptorChecks(t *testing.T) {
	rootEd, _ := GenerateEd25519Key()
	rootP256, _ := GenerateECDSAP256Key()
	encKey, _ := GenerateX25519Key()
	lineID := bytes.Repeat([]byte{0x5a}, 16)

	// 1. CanonicalRootKeys rejects duplicates, wrong count, and non-signing keys.
	if _, err := CanonicalRootKeys([]PublicKey{rootEd.PublicKey()}); !errors.Is(err, ErrInvalidRootKeys) {
		t.Fatalf("1 root key accepted: %v", err)
	}
	if _, err := CanonicalRootKeys([]PublicKey{rootEd.PublicKey(), rootEd.PublicKey()}); !errors.Is(err, ErrInvalidRootKeys) {
		t.Fatalf("duplicate root keys accepted: %v", err)
	}
	if _, err := CanonicalRootKeys([]PublicKey{rootEd.PublicKey(), encKey.PublicKey()}); !errors.Is(err, ErrInvalidRootKeys) {
		t.Fatalf("X25519 key in root_keys accepted: %v", err)
	}

	// 2. Descriptor with P-256 root key MUST fail if Profile only enables Ed25519.
	edOnlyProfile := ProfileV1()
	edOnlyProfile.SigningAlgs = []string{AlgEd25519}
	descMismatchAlg := CreationDescriptor{
		Version:    1,
		LineID:     lineID,
		Generation: 1,
		RootKeys:   []PublicKey{rootEd.PublicKey(), rootP256.PublicKey()},
		RelayOrigin: RelayOrigin{
			URL:            "https://relay.example.com",
			TLSPolicy:      TLSPolicyWebPKI,
			SessionBinding: SessionBindingTLS13Exporter,
		},
		Profile: edOnlyProfile,
	}
	if _, err := descMismatchAlg.MarshalBody(); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("descriptor with disallowed root alg accepted: %v", err)
	}

	// 3. ParseCreationDescriptorBody MUST reject unsorted root_keys (no silent rewrite).
	sortedRoots, err := CanonicalRootKeys([]PublicKey{rootEd.PublicKey(), rootP256.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	r0, _ := sortedRoots[0].ToCBOR()
	r1, _ := sortedRoots[1].ToCBOR()
	roMap, _ := descMismatchAlg.RelayOrigin.ToCBORMap()
	profMap, _ := ProfileV1().ToCBORMap()
	unsortedBody, err := MarshalCBOR(Map{
		{Key: "generation", Value: uint64(1)},
		{Key: "line_id", Value: lineID},
		{Key: "profile", Value: profMap},
		{Key: "relay_origin", Value: roMap},
		{Key: "root_keys", Value: []any{r1, r0}}, // intentionally reversed!
		{Key: "root_threshold", Value: uint64(1)},
		{Key: "schema", Value: "ldr.creation-descriptor.v1"},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCreationDescriptorBody(unsortedBody); !errors.Is(err, ErrCBORNonCanonical) {
		t.Fatalf("unsorted root_keys in descriptor body accepted: %v", err)
	}

	// 4. SignedIntent MUST reject non-canonical nested body bytes on unmarshal.
	nonCanonBody := mustHex(t, "1800") // non-shortest uint 0
	sig, err := SignDomain(rootEd, PurposeIntentSignatureDigest, 1, nonCanonBody)
	if err != nil {
		t.Fatal(err)
	}
	badEnvBytes, err := MarshalCBOR(Map{
		{Key: "alg", Value: AlgEd25519},
		{Key: "body", Value: nonCanonBody},
		{Key: "sig", Value: sig},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalSignedIntent(badEnvBytes, DefaultLimits()); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("SignedIntent accepted non-canonical nested body: %v", err)
	}

	// 5. ECDSA P-256 ASN.1 DER signature MUST be rejected (only 64B raw low-S r||s allowed).
	msg := []byte("reject-der-format")
	d := sha256.Sum256(msg)
	derSig, err := ecdsa.SignASN1(rand.Reader, rootP256.priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRaw(rootP256.PublicKey(), msg, derSig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("ECDSA ASN.1 DER signature accepted: %v", err)
	}

	// 6. Lowest possible high-S (s = halfN + 1) MUST be rejected before curve verify.
	lowHighS := new(big.Int).Add(p256HalfN, big.NewInt(1))
	crafted := make([]byte, 64)
	crafted[31] = 1 // r = 1
	lowHighS.FillBytes(crafted[32:64])
	if err := VerifyRaw(rootP256.PublicKey(), msg, crafted); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("s = halfN+1 accepted: %v", err)
	}

	// 7. DeriveCredID rejects swapped roles.
	if _, err := DeriveCredID(encKey.PublicKey(), rootEd.PublicKey()); !errors.Is(err, ErrKeyRoleMismatch) {
		t.Fatalf("DeriveCredID accepted swapped key roles: %v", err)
	}

	// 8. ExpectMap rejects unknown expectation keys.
	badExpect := map[string]any{"not_a_real_rev": uint64(1)}
	if _, err := ParseExpectMap(badExpect); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("ParseExpectMap accepted unknown key: %v", err)
	}
}
