package ldrcrypto

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
)

func TestPayloadAEADRoundTripAndSaltUniqueness(t *testing.T) {
	epochKey, err := GenerateEpochKey()
	if err != nil {
		t.Fatal(err)
	}
	ctxBytes, err := MarshalCBOR([]any{"ldr.payload-context", uint64(1), "call_turn", uint64(7)})
	if err != nil {
		t.Fatal(err)
	}

	sizes := []int{0, 1, 64, 64 * 1024, 256 * 1024}
	for _, sz := range sizes {
		pt := make([]byte, sz)
		for i := range pt {
			pt[i] = byte((i*31 + 7) & 0xff)
		}
		pkg, err := SealPayload(epochKey, ctxBytes, pt)
		if err != nil {
			t.Fatalf("SealPayload(size=%d): %v", sz, err)
		}
		got, err := OpenPayload(epochKey, ctxBytes, pkg)
		if err != nil {
			t.Fatalf("OpenPayload(size=%d): %v", sz, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("plaintext mismatch for size=%d", sz)
		}
	}

	// Sealing identical inputs twice MUST draw distinct 32B salts and yield distinct packages.
	pkg1, err := SealPayload(epochKey, ctxBytes, []byte("same message"))
	if err != nil {
		t.Fatal(err)
	}
	pkg2, err := SealPayload(epochKey, ctxBytes, []byte("same message"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pkg1, pkg2) {
		t.Fatalf("SealPayload reused salt/ciphertext on identical inputs")
	}
}

func TestPayloadAEADGoldenVector(t *testing.T) {
	epochKey := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	salt := mustHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	ctxBytes := mustHex(t, "826b6c64722e636f6e7465787401") // ["ldr.context", 1]
	pt := []byte("Hello LDR Profile v1!")

	msgKey, nonce, err := derivePayloadKeyAndNonce(epochKey, salt, ctxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgKey) != 32 || len(nonce) != 12 {
		t.Fatalf("unexpected derived sizes: key=%d nonce=%d", len(msgKey), len(nonce))
	}

	pkg1, err := sealPayloadWithSalt(epochKey, salt, ctxBytes, pt)
	if err != nil {
		t.Fatal(err)
	}
	pkg2, err := sealPayloadWithSalt(epochKey, salt, ctxBytes, pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkg1, pkg2) {
		t.Fatalf("deterministic sealPayloadWithSalt not repeatable")
	}
	got, err := OpenPayload(epochKey, ctxBytes, pkg1)
	if err != nil {
		t.Fatalf("OpenPayload golden: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("golden plaintext mismatch: got %q, want %q", got, pt)
	}

	// Verify exact decoded CBOR structure of package.
	rawMap, err := UnmarshalCBORDefault(pkg1)
	if err != nil {
		t.Fatal(err)
	}
	m := rawMap.(map[string]any)
	if m["alg"] != AlgPayloadHKDFSHA256AES256GCM || m["v"] != uint64(1) {
		t.Fatalf("unexpected package header: %#v", m)
	}
	if !bytes.Equal(m["salt"].([]byte), salt) {
		t.Fatalf("salt mismatch")
	}
	if len(m["ct"].([]byte)) != len(pt)+PayloadTagSize {
		t.Fatalf("unexpected ct length: %d", len(m["ct"].([]byte)))
	}
}

func TestPayloadAEADNegativeRejections(t *testing.T) {
	epochKey, _ := GenerateEpochKey()
	wrongKey, _ := GenerateEpochKey()
	ctxBytes := []byte("context-bytes-v1")
	pt := []byte("confidential turn body")

	pkg, err := SealPayload(epochKey, ctxBytes, pt)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong epoch key.
	if _, err := OpenPayload(wrongKey, ctxBytes, pkg); !errors.Is(err, ErrPayloadDecryptFailed) {
		t.Fatalf("wrong key: got %v, want ErrPayloadDecryptFailed", err)
	}
	// Wrong AAD / context.
	if _, err := OpenPayload(epochKey, []byte("context-bytes-v2"), pkg); !errors.Is(err, ErrPayloadDecryptFailed) {
		t.Fatalf("wrong context: got %v, want ErrPayloadDecryptFailed", err)
	}
	// Empty context rejected upfront.
	if _, err := SealPayload(epochKey, nil, pt); !errors.Is(err, ErrPayloadInvalidInput) {
		t.Fatalf("empty context on seal: got %v", err)
	}
	if _, err := OpenPayload(epochKey, nil, pkg); !errors.Is(err, ErrPayloadInvalidInput) {
		t.Fatalf("empty context on open: got %v", err)
	}
	// Short epoch key rejected upfront.
	if _, err := SealPayload(epochKey[:16], ctxBytes, pt); !errors.Is(err, ErrPayloadInvalidInput) {
		t.Fatalf("short key on seal: got %v", err)
	}
	if _, err := OpenPayload(epochKey[:16], ctxBytes, pkg); !errors.Is(err, ErrPayloadInvalidInput) {
		t.Fatalf("short key on open: got %v", err)
	}

	// Flip a byte in salt and a byte in ct inside the CBOR package.
	dec, _ := UnmarshalCBORDefault(pkg)
	orig := dec.(map[string]any)

	badSalt := bytes.Clone(orig["salt"].([]byte))
	badSalt[0] ^= 0x80
	badSaltPkg, _ := MarshalCBOR(Map{
		{Key: "alg", Value: orig["alg"]},
		{Key: "ct", Value: orig["ct"]},
		{Key: "salt", Value: badSalt},
		{Key: "v", Value: uint64(1)},
	})
	if _, err := OpenPayload(epochKey, ctxBytes, badSaltPkg); !errors.Is(err, ErrPayloadDecryptFailed) {
		t.Fatalf("bit-flipped salt: got %v", err)
	}

	badCT := bytes.Clone(orig["ct"].([]byte))
	badCT[len(badCT)-1] ^= 0x01
	badCTPkg, _ := MarshalCBOR(Map{
		{Key: "alg", Value: orig["alg"]},
		{Key: "ct", Value: badCT},
		{Key: "salt", Value: orig["salt"]},
		{Key: "v", Value: uint64(1)},
	})
	if _, err := OpenPayload(epochKey, ctxBytes, badCTPkg); !errors.Is(err, ErrPayloadDecryptFailed) {
		t.Fatalf("bit-flipped tag: got %v", err)
	}

	// Unknown extra field in CBOR package MUST be rejected.
	extraFieldPkg, _ := MarshalCBOR(Map{
		{Key: "alg", Value: orig["alg"]},
		{Key: "ct", Value: orig["ct"]},
		{Key: "extra", Value: uint64(1)},
		{Key: "salt", Value: orig["salt"]},
		{Key: "v", Value: uint64(1)},
	})
	if _, err := OpenPayload(epochKey, ctxBytes, extraFieldPkg); !errors.Is(err, ErrCBORInvalid) {
		t.Fatalf("extra field accepted: got %v", err)
	}

	// Trailing bytes MUST be rejected.
	if _, err := OpenPayload(epochKey, ctxBytes, append(bytes.Clone(pkg), 0x00)); !errors.Is(err, ErrCBORTrailingBytes) {
		t.Fatalf("trailing byte accepted: got %v", err)
	}

	// Short ciphertext (< 16-byte GCM tag) MUST be rejected.
	shortCTPkg, _ := MarshalCBOR(Map{
		{Key: "alg", Value: AlgPayloadHKDFSHA256AES256GCM},
		{Key: "ct", Value: []byte{1, 2, 3}},
		{Key: "salt", Value: orig["salt"]},
		{Key: "v", Value: uint64(1)},
	})
	if _, err := OpenPayload(epochKey, ctxBytes, shortCTPkg); !errors.Is(err, ErrPayloadDecryptFailed) {
		t.Fatalf("short ct accepted: got %v", err)
	}
}

// TestPayloadAEADExactSizeBoundaryAndPreflight verifies Codex Turn 38:
//   - payloadPackageEncodedLen matches exact canonical CBOR package bytes across
//     all ciphertext length header width transitions (1/2/3/5-byte bstr headers).
//   - Largest accepted plaintext produces a package of exactly PayloadMaxBytes
//     and round-trips through OpenPayload cleanly.
//   - Plaintext one byte above the limit (and multi-MiB oversized inputs) are
//     rejected with ErrCBORLimitExceeded BEFORE allocating ciphertext / calling GCM.Seal.
func TestPayloadAEADExactSizeBoundaryAndPreflight(t *testing.T) {
	epochKey, err := GenerateEpochKey()
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x42}, PayloadSaltSize)
	ctxBytes := []byte("ldr.payload-size-boundary-test")

	// Exact largest plaintext fitting PayloadMaxBytes (384 KiB = 393216 B):
	// fixed overhead = 72 B, ct header (5 B for >65535), GCM tag = 16 B -> maxPT = 393123 B.
	const maxPT = PayloadMaxBytes - 72 - 5 - PayloadTagSize
	if maxPT != 393123 {
		t.Fatalf("unexpected maxPT calculation: %d", maxPT)
	}

	// Verify exact size prediction across every CBOR bstr header width transition.
	transitionLens := []int{0, 7, 8, 239, 240, 65519, 65520, maxPT}
	for _, ptLen := range transitionLens {
		wantPkgLen, err := payloadPackageEncodedLen(ptLen)
		if err != nil {
			t.Fatalf("payloadPackageEncodedLen(%d): %v", ptLen, err)
		}
		pt := make([]byte, ptLen)
		for i := range pt {
			pt[i] = byte((i*17 + 3) & 0xff)
		}
		pkg, err := sealPayloadWithSalt(epochKey, salt, ctxBytes, pt)
		if err != nil {
			t.Fatalf("sealPayloadWithSalt(len=%d): %v", ptLen, err)
		}
		if len(pkg) != wantPkgLen {
			t.Fatalf("ptLen=%d: actual pkg len %d != predicted %d", ptLen, len(pkg), wantPkgLen)
		}
		if ptLen == maxPT {
			if len(pkg) != PayloadMaxBytes {
				t.Fatalf("maxPT package len = %d, want exact PayloadMaxBytes (%d)", len(pkg), PayloadMaxBytes)
			}
			// Also verify SealPayload (with fresh CSPRNG salt) round-trips cleanly at maxPT!
			livePkg, err := SealPayload(epochKey, ctxBytes, pt)
			if err != nil {
				t.Fatalf("SealPayload(maxPT): %v", err)
			}
			if len(livePkg) != PayloadMaxBytes {
				t.Fatalf("SealPayload(maxPT) len = %d, want %d", len(livePkg), PayloadMaxBytes)
			}
			got, err := OpenPayload(epochKey, ctxBytes, livePkg)
			if err != nil {
				t.Fatalf("OpenPayload(maxPT): %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("OpenPayload(maxPT) plaintext mismatch")
			}
		}
	}

	// One byte above maxPT MUST fail with ErrCBORLimitExceeded on both SealPayload and sealPayloadWithSalt.
	overByOne := make([]byte, maxPT+1)
	if _, err := SealPayload(epochKey, ctxBytes, overByOne); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("SealPayload(maxPT+1): got %v, want ErrCBORLimitExceeded", err)
	}
	if _, err := sealPayloadWithSalt(epochKey, salt, ctxBytes, overByOne); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("sealPayloadWithSalt(maxPT+1): got %v, want ErrCBORLimitExceeded", err)
	}

	// Oversized input (2 MiB) MUST be rejected BEFORE allocating ciphertext / encrypting.
	hugePT := make([]byte, 2*1024*1024)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = SealPayload(epochKey, ctxBytes, hugePT)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("SealPayload(2MiB): got %v, want ErrCBORLimitExceeded", err)
	}
	if delta := after.TotalAlloc - before.TotalAlloc; delta > 64*1024 {
		t.Fatalf("SealPayload(2MiB) allocated %d bytes before failing size preflight (want <= 65536)", delta)
	}
}
