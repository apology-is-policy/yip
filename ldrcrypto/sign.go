package ldrcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

const (
	// Profile v1 signature and key-agreement algorithm identifiers.
	AlgEd25519    = "ed25519"
	AlgECDSAP256  = "ecdsa-p256-sha256"
	AlgX25519     = "x25519"
	AlgDigestSHA5 = "sha-512"

	Ed25519PublicKeySize   = 32
	Ed25519SignatureSize   = 64
	ECDSAP256PublicKeySize = 65
	ECDSAP256SignatureSize = 64
	X25519PublicKeySize    = 32

	PurposeIntentSignatureDigest = "ldr.intent-signature.digest"
)

var (
	ErrInvalidKey           = errors.New("ldrcrypto: invalid public or private key")
	ErrInvalidSignature     = errors.New("ldrcrypto: invalid or non-canonical signature")
	ErrUnsupportedAlgorithm = errors.New("ldrcrypto: unsupported algorithm")
	ErrKeyRoleMismatch      = errors.New("ldrcrypto: key algorithm incompatible with role")
)

// Curve constants for strict canonical Ed25519, X25519, and ECDSA P-256 checks.
var (
	// ed25519P = 2^255 - 19
	ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// ed25519L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032 §5.1)
	ed25519L = mustBigIntHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	// ed25519D = -121665 / 121666 mod p
	ed25519D = mustComputeEd25519D()
	// p256N is the order of NIST P-256 and p256HalfN = floor(N/2).
	p256N     = elliptic.P256().Params().N
	p256HalfN = new(big.Int).Rsh(new(big.Int).Set(p256N), 1)
	// x25519SmallOrderProbe is a fixed non-zero clamped X25519 private scalar
	// k = 2^254 + 8 (divisible by 8, coprime to both curve and twist prime orders).
	// Calling ECDH(pub) fails iff pub has order dividing 8 on Curve25519 or its twist.
	x25519SmallOrderProbe = mustNewX25519Probe()
)

func mustBigIntHex(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("invalid hex constant: " + h)
	}
	return v
}

func mustComputeEd25519D() *big.Int {
	num := new(big.Int).Mod(big.NewInt(-121665), ed25519P)
	den := new(big.Int).ModInverse(big.NewInt(121666), ed25519P)
	return new(big.Int).Mod(new(big.Int).Mul(num, den), ed25519P)
}

func mustNewX25519Probe() *ecdh.PrivateKey {
	var raw [32]byte
	raw[0] = 8
	raw[31] = 0x40
	k, err := ecdh.X25519().NewPrivateKey(raw[:])
	if err != nil {
		panic(err)
	}
	return k
}

// PublicKey is a normalized algorithm-tagged public key `[alg, canonical_bytes]`.
type PublicKey struct {
	Alg   string
	Bytes []byte
}

// Clone returns an independent copy of pk.
func (pk PublicKey) Clone() PublicKey {
	return PublicKey{Alg: pk.Alg, Bytes: bytes.Clone(pk.Bytes)}
}

// Equal reports whether pk and other have the exact same algorithm and bytes.
func (pk PublicKey) Equal(other PublicKey) bool {
	return pk.Alg == other.Alg && bytes.Equal(pk.Bytes, other.Bytes)
}

// Validate checks that pk uses a supported algorithm and its bytes are strictly
// canonical, on-curve, and free of small-order/torsion points.
func (pk PublicKey) Validate() error {
	switch pk.Alg {
	case AlgEd25519:
		return validateEd25519PointStrict(pk.Bytes)
	case AlgECDSAP256:
		_, err := parseECDSAP256PublicKey(pk.Bytes)
		return err
	case AlgX25519:
		_, err := parseX25519PublicKeyStrict(pk.Bytes)
		return err
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, pk.Alg)
	}
}

// ValidateSigningKey requires pk to be a valid Profile v1 signing key.
func (pk PublicKey) ValidateSigningKey() error {
	if pk.Alg != AlgEd25519 && pk.Alg != AlgECDSAP256 {
		return fmt.Errorf("%w: %q is not a signing key", ErrKeyRoleMismatch, pk.Alg)
	}
	return pk.Validate()
}

// ValidateEncryptionKey requires pk to be a valid Profile v1 X25519 encryption key.
func (pk PublicKey) ValidateEncryptionKey() error {
	if pk.Alg != AlgX25519 {
		return fmt.Errorf("%w: %q is not an encryption key", ErrKeyRoleMismatch, pk.Alg)
	}
	return pk.Validate()
}

// ToCBOR validates pk and returns `[alg, bytes]`.
func (pk PublicKey) ToCBOR() ([]any, error) {
	if err := pk.Validate(); err != nil {
		return nil, err
	}
	return []any{pk.Alg, bytes.Clone(pk.Bytes)}, nil
}

// CanonicalBytes returns the deterministic CBOR encoding of `[alg, bytes]`.
// This is the unique normalized public-key value indexed by the key registry.
func (pk PublicKey) CanonicalBytes() ([]byte, error) {
	arr, err := pk.ToCBOR()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR(arr)
}

// ParsePublicKey decodes and strictly validates `[alg, bytes]` from decoded CBOR.
func ParsePublicKey(v any) (PublicKey, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		return PublicKey{}, fmt.Errorf("%w: public key must be 2-element array [alg, bytes]", ErrInvalidKey)
	}
	alg, ok := arr[0].(string)
	if !ok {
		return PublicKey{}, fmt.Errorf("%w: public key alg must be string", ErrInvalidKey)
	}
	raw, ok := arr[1].([]byte)
	if !ok {
		return PublicKey{}, fmt.Errorf("%w: public key bytes must be bstr", ErrInvalidKey)
	}
	pk := PublicKey{Alg: alg, Bytes: bytes.Clone(raw)}
	if err := pk.Validate(); err != nil {
		return PublicKey{}, err
	}
	return pk, nil
}

// littleEndianToBigInt converts a little-endian unsigned byte slice into a *big.Int.
func littleEndianToBigInt(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(rev)
}

// decodeEd25519PointStrict validates a 32-byte compressed Edwards25519 point:
//  1. exact length 32
//  2. canonical y in [0, p-1] (rejects non-canonical y >= 2^255 - 19)
//  3. x^2 = (y^2 - 1)/(d*y^2 + 1) mod p has a square root x
//  4. if x == 0, sign bit must be 0 (RFC 8032 §5.1.3)
//  5. [8]P != (0, 1) (rejects all 8 small-order / torsion points)
func validateEd25519PointStrict(b []byte) error {
	if len(b) != Ed25519PublicKeySize {
		return fmt.Errorf("%w: ed25519 point length %d != 32", ErrInvalidKey, len(b))
	}
	signBit := (b[31] >> 7) & 1
	yBytes := bytes.Clone(b)
	yBytes[31] &^= 0x80
	y := littleEndianToBigInt(yBytes)
	if y.Cmp(ed25519P) >= 0 {
		return fmt.Errorf("%w: non-canonical ed25519 y >= p", ErrInvalidKey)
	}

	// u = y^2 - 1 mod p; v = d*y^2 + 1 mod p
	y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), ed25519P)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, ed25519P)
	v := new(big.Int).Mul(ed25519D, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, ed25519P)

	vInv := new(big.Int).ModInverse(v, ed25519P)
	if vInv == nil {
		return fmt.Errorf("%w: singular ed25519 denominator", ErrInvalidKey)
	}
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, vInv), ed25519P)
	x := new(big.Int).ModSqrt(x2, ed25519P)
	if x == nil {
		return fmt.Errorf("%w: ed25519 point not on curve", ErrInvalidKey)
	}
	if x.Sign() == 0 {
		if signBit != 0 {
			return fmt.Errorf("%w: non-canonical ed25519 x == -0", ErrInvalidKey)
		}
	} else if uint(x.Bit(0)) != uint(signBit) {
		x.Sub(ed25519P, x)
	}

	// Check [8]P != identity (0, 1) via three complete twisted-Edwards doublings.
	px, py := x, y
	for i := 0; i < 3; i++ {
		px, py = edwards25519Double(px, py)
	}
	if px.Sign() == 0 && py.Cmp(big.NewInt(1)) == 0 {
		return fmt.Errorf("%w: ed25519 small-order point rejected", ErrInvalidKey)
	}
	return nil
}

// edwards25519Double computes 2*(x, y) on -x^2 + y^2 = 1 + d*x^2*y^2 (mod p).
// Since a = -1 is square and d is non-square mod p, this formula is complete.
func edwards25519Double(x, y *big.Int) (*big.Int, *big.Int) {
	x2 := new(big.Int).Mod(new(big.Int).Mul(x, x), ed25519P)
	y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), ed25519P)
	// numX = 2*x*y; denX = y^2 - x^2 (equals 1 + d*x^2*y^2 on the curve)
	numX := new(big.Int).Mul(x, y)
	numX.Lsh(numX, 1)
	numX.Mod(numX, ed25519P)
	denX := new(big.Int).Sub(y2, x2)
	denX.Mod(denX, ed25519P)
	// numY = y^2 + x^2; denY = 2 - y^2 + x^2 (equals 1 - d*x^2*y^2 on the curve)
	numY := new(big.Int).Add(y2, x2)
	numY.Mod(numY, ed25519P)
	denY := new(big.Int).Sub(big.NewInt(2), denX)
	denY.Mod(denY, ed25519P)

	denXInv := new(big.Int).ModInverse(denX, ed25519P)
	denYInv := new(big.Int).ModInverse(denY, ed25519P)
	nx := new(big.Int).Mod(new(big.Int).Mul(numX, denXInv), ed25519P)
	ny := new(big.Int).Mod(new(big.Int).Mul(numY, denYInv), ed25519P)
	return nx, ny
}

func parseECDSAP256PublicKey(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != ECDSAP256PublicKeySize || b[0] != 0x04 {
		return nil, fmt.Errorf("%w: p256 public key must be 65-byte uncompressed SEC1", ErrInvalidKey)
	}
	// crypto/ecdh validates exact uncompressed SEC1 coordinates on NIST P-256.
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("%w: invalid p256 point: %v", ErrInvalidKey, err)
	}
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func parseX25519PublicKeyStrict(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != X25519PublicKeySize {
		return nil, fmt.Errorf("%w: x25519 public key length %d != 32", ErrInvalidKey, len(b))
	}
	// Reject non-canonical u >= 2^255 - 19 (including bit 255 set) so aliases
	// cannot slip past the permanent key registry.
	u := littleEndianToBigInt(b)
	if u.Cmp(ed25519P) >= 0 {
		return nil, fmt.Errorf("%w: non-canonical x25519 public key >= p", ErrInvalidKey)
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if _, err := x25519SmallOrderProbe.ECDH(pub); err != nil {
		return nil, fmt.Errorf("%w: x25519 small-order public key rejected", ErrInvalidKey)
	}
	return pub, nil
}

// Signer signs raw protocol messages under a Profile v1 signing key.
type Signer interface {
	PublicKey() PublicKey
	SignRaw(message []byte) ([]byte, error)
}

// Ed25519PrivateKey wraps a standard Ed25519 signing key.
type Ed25519PrivateKey struct {
	priv ed25519.PrivateKey
}

// GenerateEd25519Key generates a fresh Ed25519 signing key using crypto/rand.
func GenerateEd25519Key() (*Ed25519PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519PrivateKey{priv: priv}, nil
}

// NewEd25519PrivateKeyFromSeed constructs an Ed25519 key from a 32-byte seed.
func NewEd25519PrivateKeyFromSeed(seed []byte) (*Ed25519PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: ed25519 seed length %d != 32", ErrInvalidKey, len(seed))
	}
	return &Ed25519PrivateKey{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// PublicKey returns the normalized Ed25519 public key.
func (k *Ed25519PrivateKey) PublicKey() PublicKey {
	pub := k.priv.Public().(ed25519.PublicKey)
	return PublicKey{Alg: AlgEd25519, Bytes: bytes.Clone(pub)}
}

// SignRaw computes a canonical RFC 8032 Ed25519 signature over message.
func (k *Ed25519PrivateKey) SignRaw(message []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, message), nil
}

// ECDSAP256PrivateKey wraps a NIST P-256 signing key emitting strict low-S 64B signatures.
type ECDSAP256PrivateKey struct {
	priv *ecdsa.PrivateKey
}

// GenerateECDSAP256Key generates a fresh NIST P-256 signing key.
func GenerateECDSAP256Key() (*ECDSAP256PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDSAP256PrivateKey{priv: priv}, nil
}

// NewECDSAP256PrivateKey wraps an existing NIST P-256 *ecdsa.PrivateKey.
func NewECDSAP256PrivateKey(priv *ecdsa.PrivateKey) (*ECDSAP256PrivateKey, error) {
	if priv == nil || priv.Curve != elliptic.P256() || priv.X == nil || priv.Y == nil {
		return nil, fmt.Errorf("%w: expected NIST P-256 private key", ErrInvalidKey)
	}
	return &ECDSAP256PrivateKey{priv: priv}, nil
}

// PublicKey returns the normalized 65-byte uncompressed SEC1 P-256 public key.
func (k *ECDSAP256PrivateKey) PublicKey() PublicKey {
	out := make([]byte, ECDSAP256PublicKeySize)
	out[0] = 0x04
	k.priv.X.FillBytes(out[1:33])
	k.priv.Y.FillBytes(out[33:65])
	return PublicKey{Alg: AlgECDSAP256, Bytes: out}
}

type asn1ECDSASig struct {
	R, S *big.Int
}

// SignRaw computes a strict low-S 64-byte raw r||s ECDSA P-256 signature over SHA-256(message).
func (k *ECDSAP256PrivateKey) SignRaw(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		return nil, err
	}
	var parsed asn1ECDSASig
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("%w: malformed ASN.1 ECDSA output", ErrInvalidSignature)
	}
	if parsed.S.Cmp(p256HalfN) > 0 {
		parsed.S = new(big.Int).Sub(p256N, parsed.S)
	}
	var sig [ECDSAP256SignatureSize]byte
	parsed.R.FillBytes(sig[0:32])
	parsed.S.FillBytes(sig[32:64])
	return sig[:], nil
}

// X25519PrivateKey wraps an X25519 encryption/key-agreement private key.
type X25519PrivateKey struct {
	priv *ecdh.PrivateKey
}

// GenerateX25519Key generates a fresh X25519 private key.
func GenerateX25519Key() (*X25519PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &X25519PrivateKey{priv: priv}, nil
}

// NewX25519PrivateKey constructs an X25519 private key from 32 raw bytes.
func NewX25519PrivateKey(raw []byte) (*X25519PrivateKey, error) {
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return &X25519PrivateKey{priv: priv}, nil
}

// PublicKey returns the normalized X25519 public key.
func (k *X25519PrivateKey) PublicKey() PublicKey {
	return PublicKey{Alg: AlgX25519, Bytes: bytes.Clone(k.priv.PublicKey().Bytes())}
}

// Bytes returns a copy of the 32-byte raw private key scalar.
func (k *X25519PrivateKey) Bytes() []byte {
	return bytes.Clone(k.priv.Bytes())
}

// VerifyRaw strictly verifies sig over message under pub.
//
// For Ed25519: rejects S >= L (RFC 8032 §8.4), non-canonical R or A (y >= p,
// x == -0), off-curve points, and all 8 small-order/torsion points on A or R.
// For ECDSA P-256: requires 65-byte uncompressed SEC1 on-curve pub and 64-byte
// raw r||s with 1 <= r < N and strict low-S 1 <= s <= floor(N/2).
func VerifyRaw(pub PublicKey, message, sig []byte) error {
	switch pub.Alg {
	case AlgEd25519:
		if err := validateEd25519PointStrict(pub.Bytes); err != nil {
			return err
		}
		if len(sig) != Ed25519SignatureSize {
			return fmt.Errorf("%w: ed25519 signature length %d != 64", ErrInvalidSignature, len(sig))
		}
		// Validate canonical non-small-order R (first 32 bytes).
		if err := validateEd25519PointStrict(sig[:32]); err != nil {
			return fmt.Errorf("%w: invalid signature R: %v", ErrInvalidSignature, err)
		}
		// Enforce strict canonical scalar range 0 <= S < L (RFC 8032 §8.4).
		s := littleEndianToBigInt(sig[32:64])
		if s.Cmp(ed25519L) >= 0 {
			return fmt.Errorf("%w: ed25519 scalar S >= L", ErrInvalidSignature)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub.Bytes), message, sig) {
			return ErrInvalidSignature
		}
		return nil

	case AlgECDSAP256:
		ecdsaPub, err := parseECDSAP256PublicKey(pub.Bytes)
		if err != nil {
			return err
		}
		if len(sig) != ECDSAP256SignatureSize {
			return fmt.Errorf("%w: ecdsa p256 signature length %d != 64", ErrInvalidSignature, len(sig))
		}
		r := new(big.Int).SetBytes(sig[0:32])
		s := new(big.Int).SetBytes(sig[32:64])
		if r.Sign() <= 0 || r.Cmp(p256N) >= 0 {
			return fmt.Errorf("%w: ecdsa r out of range [1, N-1]", ErrInvalidSignature)
		}
		if s.Sign() <= 0 || s.Cmp(p256HalfN) > 0 {
			return fmt.Errorf("%w: ecdsa s fails strict low-S [1, N/2]", ErrInvalidSignature)
		}
		digest := sha256.Sum256(message)
		if !ecdsa.Verify(ecdsaPub, digest[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return fmt.Errorf("%w: %q is not a signing algorithm", ErrUnsupportedAlgorithm, pub.Alg)
	}
}

// SigningPrecommitment builds the bounded SHA-512 pre-commitment message:
//
//	Enc([purpose, version, "sha-512", uint64(len(bodyBytes)), SHA512(bodyBytes)])
//
// Keeping the signed input small and fixed-size enables hardware/platform
// signers while binding exact purpose, version, byte length, and content.
func SigningPrecommitment(purpose string, version uint64, bodyBytes []byte) ([]byte, error) {
	if purpose == "" {
		return nil, fmt.Errorf("%w: empty signing purpose", ErrCBORInvalid)
	}
	if uint64(len(bodyBytes)) > MaxCounter {
		return nil, ErrCBOROutOfDomain
	}
	sum := sha512.Sum512(bodyBytes)
	return MarshalCBOR([]any{purpose, version, AlgDigestSHA5, uint64(len(bodyBytes)), sum[:]})
}

// IntentSigningMessage returns the canonical bounded pre-commitment for signing
// an intent body B (LDR-GO-RELAY-DESIGN §5.3).
func IntentSigningMessage(bodyBytes []byte) ([]byte, error) {
	return SigningPrecommitment(PurposeIntentSignatureDigest, 1, bodyBytes)
}

// SignDomain signs bodyBytes under a distinct domain-separated pre-commitment.
func SignDomain(signer Signer, purpose string, version uint64, bodyBytes []byte) ([]byte, error) {
	if signer == nil {
		return nil, ErrInvalidKey
	}
	if err := signer.PublicKey().ValidateSigningKey(); err != nil {
		return nil, err
	}
	msg, err := SigningPrecommitment(purpose, version, bodyBytes)
	if err != nil {
		return nil, err
	}
	return signer.SignRaw(msg)
}

// VerifyDomain verifies sig over bodyBytes under the given domain-separated pre-commitment.
func VerifyDomain(pub PublicKey, purpose string, version uint64, bodyBytes, sig []byte) error {
	if err := pub.ValidateSigningKey(); err != nil {
		return err
	}
	msg, err := SigningPrecommitment(purpose, version, bodyBytes)
	if err != nil {
		return err
	}
	return VerifyRaw(pub, msg, sig)
}
