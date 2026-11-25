package ldrcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	// Profile v1 line-payload AEAD construction (selected 2026-11-25):
	// per-message 32-byte CSPRNG salt + HKDF-SHA256 + AES-256-GCM.
	AlgPayloadHKDFSHA256AES256GCM = "hkdf-sha256-aes256gcm"
	PurposePayloadKey             = "ldr.payload-key"

	EpochKeySize     = 32
	PayloadSaltSize  = 32
	PayloadNonceSize = 12
	PayloadTagSize   = 16
	PayloadMaxBytes  = 384 * 1024
)

var (
	ErrPayloadDecryptFailed = errors.New("ldrcrypto: payload authentication or decryption failed")
	ErrPayloadInvalidInput  = errors.New("ldrcrypto: invalid payload encryption input")
)

// GenerateEpochKey draws a fresh 32-byte line epoch secret from crypto/rand.
func GenerateEpochKey() ([]byte, error) {
	k := make([]byte, EpochKeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// SealPayload encrypts plaintext under epochKey bound to contextBytes using
// a fresh 32-byte CSPRNG salt, HKDF-SHA256(epochKey, salt, Enc(["ldr.payload-key", 1, contextBytes]))
// -> (32B msg_key || 12B nonce), and AES-256-GCM(..., aad = contextBytes).
//
// Returns the canonical CBOR payload package: {"alg", "ct", "salt", "v": 1}.
func SealPayload(epochKey, contextBytes, plaintext []byte) ([]byte, error) {
	salt := make([]byte, PayloadSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return sealPayloadWithSalt(epochKey, salt, contextBytes, plaintext)
}

func derivePayloadKeyAndNonce(epochKey, salt, contextBytes []byte) (msgKey, nonce []byte, err error) {
	if len(epochKey) != EpochKeySize {
		return nil, nil, fmt.Errorf("%w: epoch key length %d != %d", ErrPayloadInvalidInput, len(epochKey), EpochKeySize)
	}
	if len(salt) != PayloadSaltSize {
		return nil, nil, fmt.Errorf("%w: salt length %d != %d", ErrPayloadInvalidInput, len(salt), PayloadSaltSize)
	}
	if len(contextBytes) == 0 {
		return nil, nil, fmt.Errorf("%w: empty payload context", ErrPayloadInvalidInput)
	}
	info, err := MarshalCBOR([]any{PurposePayloadKey, uint64(1), contextBytes})
	if err != nil {
		return nil, nil, err
	}
	okm, err := hkdf.Key(sha256.New, epochKey, salt, string(info), EpochKeySize+PayloadNonceSize)
	if err != nil {
		return nil, nil, err
	}
	return okm[:EpochKeySize], okm[EpochKeySize : EpochKeySize+PayloadNonceSize], nil
}

func sealPayloadWithSalt(epochKey, salt, contextBytes, plaintext []byte) ([]byte, error) {
	msgKey, nonce, err := derivePayloadKeyAndNonce(epochKey, salt, contextBytes)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(msgKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, contextBytes)
	pkg, err := MarshalCBOR(Map{
		{Key: "alg", Value: AlgPayloadHKDFSHA256AES256GCM},
		{Key: "ct", Value: ct},
		{Key: "salt", Value: bytes.Clone(salt)},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return nil, err
	}
	if len(pkg) > PayloadMaxBytes {
		return nil, fmt.Errorf("%w: payload package %d > %d", ErrCBORLimitExceeded, len(pkg), PayloadMaxBytes)
	}
	return pkg, nil
}

// OpenPayload strictly decodes pkgBytes, re-derives the per-message key and
// nonce from epochKey, salt, and contextBytes, and authenticates/decrypts.
func OpenPayload(epochKey, contextBytes, pkgBytes []byte) ([]byte, error) {
	if len(epochKey) != EpochKeySize {
		return nil, fmt.Errorf("%w: epoch key length %d != %d", ErrPayloadInvalidInput, len(epochKey), EpochKeySize)
	}
	if len(contextBytes) == 0 {
		return nil, fmt.Errorf("%w: empty payload context", ErrPayloadInvalidInput)
	}
	lim := DefaultLimits()
	lim.MaxBytes = PayloadMaxBytes
	decoded, err := UnmarshalCBOR(pkgBytes, lim)
	if err != nil {
		return nil, err
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: payload package must be CBOR map", ErrCBORInvalid)
	}
	if err := RequireExactKeys(m, []string{"alg", "ct", "salt", "v"}); err != nil {
		return nil, err
	}
	v, err := MapUint(m, "v")
	if err != nil || v != 1 {
		return nil, fmt.Errorf("%w: unsupported payload package version", ErrCBORInvalid)
	}
	alg, err := MapString(m, "alg")
	if err != nil || alg != AlgPayloadHKDFSHA256AES256GCM {
		return nil, fmt.Errorf("%w: unexpected payload alg %q", ErrUnsupportedAlgorithm, alg)
	}
	salt, err := MapBytesLen(m, "salt", PayloadSaltSize)
	if err != nil {
		return nil, err
	}
	ct, err := MapBytes(m, "ct")
	if err != nil {
		return nil, err
	}
	if len(ct) < PayloadTagSize {
		return nil, ErrPayloadDecryptFailed
	}
	msgKey, nonce, err := derivePayloadKeyAndNonce(epochKey, salt, contextBytes)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(msgKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, contextBytes)
	if err != nil {
		return nil, ErrPayloadDecryptFailed
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}
