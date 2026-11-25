package ldrcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// RFC 9180 HPKE Base mode identifiers for Profile v1:
// KEM = DHKEM(X25519, HKDF-SHA256) (0x0020)
// KDF = HKDF-SHA256 (0x0001)
// AEAD = AES-256-GCM (0x0002)
const (
	hpkeModeBase   byte   = 0x00
	hpkeKEMX25519  uint16 = 0x0020
	hpkeKDFSHA256  uint16 = 0x0001
	hpkeAEADAES128 uint16 = 0x0001 // internal: used to verify RFC 9180 Appendix A.1.1 verbatim
	hpkeAEADAES256 uint16 = 0x0002 // production LDR Profile v1 AEAD
	hpkeNonceSize         = 12
	hpkeSecretSize        = 32
	hpkeVersionStr        = "HPKE-v1"

	AlgHPKEWrap = "hpke-x25519-hkdfsha256-aes256gcm"
)

var (
	ErrHPKEDecryptFailed = errors.New("ldrcrypto: hpke decryption failed")
	ErrHPKEInvalidInput  = errors.New("ldrcrypto: invalid hpke input")
)

var hpkeKEMSuiteID = []byte{'K', 'E', 'M', 0x00, 0x20}

func hpkeSuiteID(aeadID uint16) []byte {
	var out [10]byte
	copy(out[0:4], "HPKE")
	binary.BigEndian.PutUint16(out[4:6], hpkeKEMX25519)
	binary.BigEndian.PutUint16(out[6:8], hpkeKDFSHA256)
	binary.BigEndian.PutUint16(out[8:10], aeadID)
	return out[:]
}

func hpkeAEADKeySize(aeadID uint16) (int, error) {
	switch aeadID {
	case hpkeAEADAES128:
		return 16, nil
	case hpkeAEADAES256:
		return 32, nil
	default:
		return 0, fmt.Errorf("%w: unsupported HPKE AEAD 0x%04x", ErrUnsupportedAlgorithm, aeadID)
	}
}

// hpkeLabeledExtract implements RFC 9180 §4 LabeledExtract for HKDF-SHA256.
func hpkeLabeledExtract(suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := make([]byte, 0, len(hpkeVersionStr)+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, hpkeVersionStr...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(sha256.New, labeledIKM, salt)
}

// hpkeLabeledExpand implements RFC 9180 §4 LabeledExpand for HKDF-SHA256.
func hpkeLabeledExpand(suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > 0xffff {
		return nil, fmt.Errorf("%w: invalid LabeledExpand length %d", ErrHPKEInvalidInput, length)
	}
	labeledInfo := make([]byte, 0, 2+len(hpkeVersionStr)+len(suiteID)+len(label)+len(info))
	labeledInfo = binary.BigEndian.AppendUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, hpkeVersionStr...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(sha256.New, prk, string(labeledInfo), length)
}

// DeriveX25519KeyPair implements RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256).
func DeriveX25519KeyPair(ikm []byte) (*X25519PrivateKey, error) {
	if len(ikm) < 32 {
		return nil, fmt.Errorf("%w: DeriveKeyPair ikm length %d < 32", ErrHPKEInvalidInput, len(ikm))
	}
	dkpPRK, err := hpkeLabeledExtract(hpkeKEMSuiteID, nil, "dkp_prk", ikm)
	if err != nil {
		return nil, err
	}
	sk, err := hpkeLabeledExpand(hpkeKEMSuiteID, dkpPRK, "sk", nil, 32)
	if err != nil {
		return nil, err
	}
	return NewX25519PrivateKey(sk)
}

func dhkemExtractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePRK, err := hpkeLabeledExtract(hpkeKEMSuiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	return hpkeLabeledExpand(hpkeKEMSuiteID, eaePRK, "shared_secret", kemContext, hpkeSecretSize)
}

type hpkeContext struct {
	aeadID             uint16
	enc                []byte
	sharedSecret       []byte
	keyScheduleContext []byte
	secret             []byte
	key                []byte
	baseNonce          []byte
	exporterSecret     []byte
	aead               cipher.AEAD
}

func hpkeKeyScheduleBase(aeadID uint16, enc, sharedSecret, info []byte) (*hpkeContext, error) {
	nk, err := hpkeAEADKeySize(aeadID)
	if err != nil {
		return nil, err
	}
	suiteID := hpkeSuiteID(aeadID)

	pskIDHash, err := hpkeLabeledExtract(suiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, err
	}
	infoHash, err := hpkeLabeledExtract(suiteID, nil, "info_hash", info)
	if err != nil {
		return nil, err
	}
	ksCtx := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ksCtx = append(ksCtx, hpkeModeBase)
	ksCtx = append(ksCtx, pskIDHash...)
	ksCtx = append(ksCtx, infoHash...)

	secret, err := hpkeLabeledExtract(suiteID, sharedSecret, "secret", nil)
	if err != nil {
		return nil, err
	}
	key, err := hpkeLabeledExpand(suiteID, secret, "key", ksCtx, nk)
	if err != nil {
		return nil, err
	}
	baseNonce, err := hpkeLabeledExpand(suiteID, secret, "base_nonce", ksCtx, hpkeNonceSize)
	if err != nil {
		return nil, err
	}
	exporterSecret, err := hpkeLabeledExpand(suiteID, secret, "exp", ksCtx, hpkeSecretSize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &hpkeContext{
		aeadID:             aeadID,
		enc:                enc,
		sharedSecret:       sharedSecret,
		keyScheduleContext: ksCtx,
		secret:             secret,
		key:                key,
		baseNonce:          baseNonce,
		exporterSecret:     exporterSecret,
		aead:               gcm,
	}, nil
}

func (c *hpkeContext) computeNonce(seq uint64) []byte {
	nonce := bytes.Clone(c.baseNonce)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	for i := 0; i < 8; i++ {
		nonce[hpkeNonceSize-8+i] ^= seqBuf[i]
	}
	return nonce
}

func (c *hpkeContext) sealSeq(seq uint64, aad, plaintext []byte) []byte {
	return c.aead.Seal(nil, c.computeNonce(seq), plaintext, aad)
}

func (c *hpkeContext) openSeq(seq uint64, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.aead.Overhead() {
		return nil, ErrHPKEDecryptFailed
	}
	pt, err := c.aead.Open(nil, c.computeNonce(seq), ciphertext, aad)
	if err != nil {
		return nil, ErrHPKEDecryptFailed
	}
	return pt, nil
}

func hpkeSetupBaseSenderWithKey(aeadID uint16, recipientPub PublicKey, skE *ecdh.PrivateKey, info []byte) (*hpkeContext, error) {
	if err := recipientPub.ValidateEncryptionKey(); err != nil {
		return nil, err
	}
	pkR, err := parseX25519PublicKeyStrict(recipientPub.Bytes)
	if err != nil {
		return nil, err
	}
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	enc := bytes.Clone(skE.PublicKey().Bytes())
	kemContext := make([]byte, 0, 64)
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR.Bytes()...)
	sharedSecret, err := dhkemExtractAndExpand(dh, kemContext)
	if err != nil {
		return nil, err
	}
	return hpkeKeyScheduleBase(aeadID, enc, sharedSecret, info)
}

func hpkeSetupBaseRecipient(aeadID uint16, recipientPriv *X25519PrivateKey, enc, info []byte) (*hpkeContext, error) {
	if recipientPriv == nil || recipientPriv.priv == nil {
		return nil, ErrInvalidKey
	}
	pkE, err := parseX25519PublicKeyStrict(enc)
	if err != nil {
		return nil, err
	}
	dh, err := recipientPriv.priv.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	kemContext := make([]byte, 0, 64)
	kemContext = append(kemContext, pkE.Bytes()...)
	kemContext = append(kemContext, recipientPriv.priv.PublicKey().Bytes()...)
	sharedSecret, err := dhkemExtractAndExpand(dh, kemContext)
	if err != nil {
		return nil, err
	}
	return hpkeKeyScheduleBase(aeadID, bytes.Clone(enc), sharedSecret, info)
}

// HPKESealBase performs RFC 9180 single-shot Base mode encryption under
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
func HPKESealBase(recipientPub PublicKey, info, aad, plaintext []byte) (enc []byte, ciphertext []byte, err error) {
	skE, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ctx, err := hpkeSetupBaseSenderWithKey(hpkeAEADAES256, recipientPub, skE, info)
	if err != nil {
		return nil, nil, err
	}
	return ctx.enc, ctx.sealSeq(0, aad, plaintext), nil
}

// HPKEOpenBase performs RFC 9180 single-shot Base mode decryption under
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
func HPKEOpenBase(recipientPriv *X25519PrivateKey, enc, info, aad, ciphertext []byte) ([]byte, error) {
	ctx, err := hpkeSetupBaseRecipient(hpkeAEADAES256, recipientPriv, enc, info)
	if err != nil {
		return nil, err
	}
	return ctx.openSeq(0, aad, ciphertext)
}

// EpochWrapContext binds an HPKE epoch-key wrap to the full P9 activation context.
type EpochWrapContext struct {
	LineID          []byte
	Generation      uint64
	ProfileDigest   [32]byte
	NewEpoch        uint64
	ExpectEpoch     uint64
	AuthEpoch       uint64
	OpIdentityBytes []byte
	RecipientCredID [32]byte
	RecipientEncKey PublicKey
	ReaderSetDigest [32]byte
}

func (c EpochWrapContext) canonicalInfo() ([]byte, error) {
	if len(c.LineID) == 0 || len(c.OpIdentityBytes) == 0 {
		return nil, fmt.Errorf("%w: incomplete epoch wrap context", ErrHPKEInvalidInput)
	}
	if err := c.RecipientEncKey.ValidateEncryptionKey(); err != nil {
		return nil, err
	}
	ek, err := c.RecipientEncKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR([]any{
		PurposeEpochWrap,
		uint64(1),
		c.LineID,
		c.Generation,
		c.ProfileDigest[:],
		c.NewEpoch,
		c.ExpectEpoch,
		c.AuthEpoch,
		c.OpIdentityBytes,
		c.RecipientCredID[:],
		ek,
		c.ReaderSetDigest[:],
	})
}

// WrapEpochKey seals a 32-byte epoch secret to ctx.RecipientEncKey using RFC 9180
// HPKE Base mode and encodes the canonical CBOR wrap sidecar package.
func WrapEpochKey(epochKey []byte, ctx EpochWrapContext) ([]byte, error) {
	if len(epochKey) != EpochKeySize {
		return nil, fmt.Errorf("%w: epoch key length %d != %d", ErrHPKEInvalidInput, len(epochKey), EpochKeySize)
	}
	info, err := ctx.canonicalInfo()
	if err != nil {
		return nil, err
	}
	enc, ct, err := HPKESealBase(ctx.RecipientEncKey, info, info, epochKey)
	if err != nil {
		return nil, err
	}
	return MarshalCBOR(Map{
		{Key: "alg", Value: AlgHPKEWrap},
		{Key: "ct", Value: ct},
		{Key: "enc", Value: enc},
		{Key: "v", Value: uint64(1)},
	})
}

// UnwrapEpochKey validates the canonical CBOR wrap package and decrypts the
// 32-byte epoch secret using recipientPriv and the expected wrap context.
func UnwrapEpochKey(recipientPriv *X25519PrivateKey, wrapBytes []byte, ctx EpochWrapContext) ([]byte, error) {
	if recipientPriv == nil {
		return nil, ErrInvalidKey
	}
	if !recipientPriv.PublicKey().Equal(ctx.RecipientEncKey) {
		return nil, fmt.Errorf("%w: recipient key does not match wrap context", ErrInvalidKey)
	}
	info, err := ctx.canonicalInfo()
	if err != nil {
		return nil, err
	}
	decoded, err := UnmarshalCBORDefault(wrapBytes)
	if err != nil {
		return nil, err
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: wrap package must be CBOR map", ErrCBORInvalid)
	}
	if err := RequireExactKeys(m, []string{"alg", "ct", "enc", "v"}); err != nil {
		return nil, err
	}
	v, err := MapUint(m, "v")
	if err != nil || v != 1 {
		return nil, fmt.Errorf("%w: unsupported wrap package version", ErrCBORInvalid)
	}
	alg, err := MapString(m, "alg")
	if err != nil || alg != AlgHPKEWrap {
		return nil, fmt.Errorf("%w: unexpected wrap alg %q", ErrUnsupportedAlgorithm, alg)
	}
	enc, err := MapBytesLen(m, "enc", X25519PublicKeySize)
	if err != nil {
		return nil, err
	}
	ct, err := MapBytes(m, "ct")
	if err != nil {
		return nil, err
	}
	if len(ct) != EpochKeySize+PayloadTagSize {
		return nil, fmt.Errorf("%w: unexpected wrapped epoch key length %d", ErrHPKEDecryptFailed, len(ct))
	}
	pt, err := HPKEOpenBase(recipientPriv, enc, info, info, ct)
	if err != nil {
		return nil, err
	}
	if len(pt) != EpochKeySize {
		return nil, ErrHPKEDecryptFailed
	}
	return pt, nil
}
