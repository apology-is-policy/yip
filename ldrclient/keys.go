// Package ldrclient implements the durable local LDR client: isolated key
// custody, CRC32C-verified local log store, persist-before-send outbox with
// Rule 8 persistent key stops, O25 full-replay bootstrap and incremental sync,
// P3 key-first enrollment ceremony, P9 epoch activation, rebuildable
// projections, and local delivery scan cursors.
//
// Host-local resource leases, queues, and offers remain strictly untouched.
package ldrclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

var (
	ErrClientLocked = errors.New("ldrclient: client directory is locked by another process")
	ErrKeyFile      = errors.New("ldrclient: invalid key file")
)

// SigningKeyMaterial holds a Profile v1 signing private key (Ed25519 or ECDSA P-256).
type SigningKeyMaterial struct {
	Alg    string
	Secret []byte // 32B Ed25519 seed OR x509 ECPrivateKey DER for P-256
	Signer ldrcrypto.Signer
}

// GenerateSigningKey generates a fresh root or operator signing key.
func GenerateSigningKey(alg string) (*SigningKeyMaterial, error) {
	if alg == "" {
		alg = ldrcrypto.AlgEd25519
	}
	switch alg {
	case ldrcrypto.AlgEd25519:
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, err
		}
		k, err := ldrcrypto.NewEd25519PrivateKeyFromSeed(seed)
		if err != nil {
			return nil, err
		}
		return &SigningKeyMaterial{Alg: alg, Secret: seed, Signer: k}, nil

	case ldrcrypto.AlgECDSAP256:
		priv, err := ecdsa.GenerateKey(p256Curve(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		k, err := ldrcrypto.NewECDSAP256PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return &SigningKeyMaterial{Alg: alg, Secret: der, Signer: k}, nil

	default:
		return nil, fmt.Errorf("%w: %q", ldrcrypto.ErrUnsupportedAlgorithm, alg)
	}
}

func signingKeyFromSecret(alg string, secret []byte) (*SigningKeyMaterial, error) {
	switch alg {
	case ldrcrypto.AlgEd25519:
		k, err := ldrcrypto.NewEd25519PrivateKeyFromSeed(secret)
		if err != nil {
			return nil, err
		}
		return &SigningKeyMaterial{Alg: alg, Secret: bytes.Clone(secret), Signer: k}, nil
	case ldrcrypto.AlgECDSAP256:
		priv, err := x509.ParseECPrivateKey(secret)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
		}
		k, err := ldrcrypto.NewECDSAP256PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return &SigningKeyMaterial{Alg: alg, Secret: bytes.Clone(secret), Signer: k}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ldrcrypto.ErrUnsupportedAlgorithm, alg)
	}
}

// SaveSigningKey writes a root or operator signing key atomically with 0600 permissions.
func SaveSigningKey(path string, km *SigningKeyMaterial) error {
	if km == nil || km.Signer == nil {
		return ErrKeyFile
	}
	pubCBOR, err := km.Signer.PublicKey().ToCBOR()
	if err != nil {
		return err
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "alg", Value: km.Alg},
		{Key: "pub", Value: pubCBOR},
		{Key: "schema", Value: "ldr.signing-key.v1"},
		{Key: "secret", Value: km.Secret},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

// LoadSigningKey loads and validates a saved signing key file.
func LoadSigningKey(path string) (*SigningKeyMaterial, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: key file must be map", ErrKeyFile)
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"alg", "pub", "schema", "secret", "v"}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	schema, _ := ldrcrypto.MapString(m, "schema")
	if schema != "ldr.signing-key.v1" {
		return nil, fmt.Errorf("%w: unexpected schema %q", ErrKeyFile, schema)
	}
	alg, err := ldrcrypto.MapString(m, "alg")
	if err != nil {
		return nil, err
	}
	sec, err := ldrcrypto.MapBytes(m, "secret")
	if err != nil {
		return nil, err
	}
	pub, err := ldrcrypto.ParsePublicKey(m["pub"])
	if err != nil {
		return nil, err
	}
	km, err := signingKeyFromSecret(alg, sec)
	if err != nil {
		return nil, err
	}
	if !km.Signer.PublicKey().Equal(pub) {
		return nil, fmt.Errorf("%w: derived public key does not match stored pub", ErrKeyFile)
	}
	return km, nil
}

// SavePublicKey writes a normalized public key `[alg, bytes]` to a portable file.
func SavePublicKey(path string, pk ldrcrypto.PublicKey) error {
	raw, err := pk.CanonicalBytes()
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o644)
}

// LoadPublicKey loads either a standalone public key file OR extracts the public
// key from a saved SigningKeyMaterial file.
func LoadPublicKey(path string) (ldrcrypto.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ldrcrypto.PublicKey{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ldrcrypto.PublicKey{}, err
	}
	if arr, ok := dec.([]any); ok {
		return ldrcrypto.ParsePublicKey(arr)
	}
	if m, ok := dec.(map[string]any); ok {
		if pubRaw, has := m["pub"]; has {
			return ldrcrypto.ParsePublicKey(pubRaw)
		}
	}
	return ldrcrypto.PublicKey{}, fmt.Errorf("%w: unrecognized public key file", ErrKeyFile)
}

// CredentialKeyBundle holds a workstation credential's independently generated
// signing key, X25519 encryption key, and derived CredID (P2).
type CredentialKeyBundle struct {
	Signing    *SigningKeyMaterial
	Encryption *ldrcrypto.X25519PrivateKey
	CredID     [32]byte
}

// GenerateCredentialKeys generates independent signing and encryption keys and derives CredID.
func GenerateCredentialKeys(sigAlg string) (*CredentialKeyBundle, error) {
	sig, err := GenerateSigningKey(sigAlg)
	if err != nil {
		return nil, err
	}
	enc, err := ldrcrypto.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	cid, err := ldrcrypto.DeriveCredID(sig.Signer.PublicKey(), enc.PublicKey())
	if err != nil {
		return nil, err
	}
	return &CredentialKeyBundle{Signing: sig, Encryption: enc, CredID: cid}, nil
}

// SaveCredentialKeys writes a CredentialKeyBundle atomically with 0600 permissions.
func SaveCredentialKeys(path string, b *CredentialKeyBundle) error {
	if b == nil || b.Signing == nil || b.Encryption == nil {
		return ErrKeyFile
	}
	cid, err := ldrcrypto.DeriveCredID(b.Signing.Signer.PublicKey(), b.Encryption.PublicKey())
	if err != nil {
		return err
	}
	if cid != b.CredID {
		return fmt.Errorf("%w: cred_id mismatch", ErrKeyFile)
	}
	sigPub, err := b.Signing.Signer.PublicKey().ToCBOR()
	if err != nil {
		return err
	}
	encPub, err := b.Encryption.PublicKey().ToCBOR()
	if err != nil {
		return err
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "cred_id", Value: cid[:]},
		{Key: "enc_pub", Value: encPub},
		{Key: "enc_secret", Value: b.Encryption.Bytes()},
		{Key: "schema", Value: "ldr.credential-keys.v1"},
		{Key: "sig_alg", Value: b.Signing.Alg},
		{Key: "sig_pub", Value: sigPub},
		{Key: "sig_secret", Value: b.Signing.Secret},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

// LoadCredentialKeys loads and re-verifies a saved CredentialKeyBundle.
func LoadCredentialKeys(path string) (*CredentialKeyBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: credential key file must be map", ErrKeyFile)
	}
	req := []string{"cred_id", "enc_pub", "enc_secret", "schema", "sig_alg", "sig_pub", "sig_secret", "v"}
	if err := ldrcrypto.RequireExactKeys(m, req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	if sch, _ := ldrcrypto.MapString(m, "schema"); sch != "ldr.credential-keys.v1" {
		return nil, fmt.Errorf("%w: unexpected schema %q", ErrKeyFile, sch)
	}
	sigAlg, err := ldrcrypto.MapString(m, "sig_alg")
	if err != nil {
		return nil, err
	}
	sigSec, err := ldrcrypto.MapBytes(m, "sig_secret")
	if err != nil {
		return nil, err
	}
	encSec, err := ldrcrypto.MapBytes(m, "enc_secret")
	if err != nil {
		return nil, err
	}
	cidBytes, err := ldrcrypto.MapBytesLen(m, "cred_id", 32)
	if err != nil {
		return nil, err
	}
	sig, err := signingKeyFromSecret(sigAlg, sigSec)
	if err != nil {
		return nil, err
	}
	enc, err := ldrcrypto.NewX25519PrivateKey(encSec)
	if err != nil {
		return nil, err
	}
	derived, err := ldrcrypto.DeriveCredID(sig.Signer.PublicKey(), enc.PublicKey())
	if err != nil {
		return nil, err
	}
	var stored [32]byte
	copy(stored[:], cidBytes)
	if derived != stored {
		return nil, fmt.Errorf("%w: cred_id derivation mismatch", ErrKeyFile)
	}
	return &CredentialKeyBundle{Signing: sig, Encryption: enc, CredID: derived}, nil
}

// KeyFingerprint returns a human-readable display fingerprint (convenience
// label ONLY for out-of-band comparison; never a wire identity).
func KeyFingerprint(pk ldrcrypto.PublicKey) (string, error) {
	cb, err := pk.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cb)
	h := strings.ToUpper(hex.EncodeToString(sum[:12]))
	return fmt.Sprintf("%s-%s-%s-%s-%s-%s", h[0:4], h[4:8], h[8:12], h[12:16], h[16:20], h[20:24]), nil
}
