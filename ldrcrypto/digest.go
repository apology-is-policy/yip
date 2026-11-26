package ldrcrypto

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

const (
	PurposeCreationDescriptor = "ldr.creation-descriptor"
	PurposeGenesis            = "ldr.genesis"
	PurposeProfile            = "ldr.profile"
	PurposeCredID             = "ldr.cred-id"
	PurposeIntent             = "ldr.intent"
	PurposeChain              = "ldr.chain"
	PurposeChainAnchor        = "ldr.chain.anchor"
	PurposeChainRecovery      = "ldr.chain.recovery"
	PurposePayloadCommit      = "ldr.payload-commit"
	PurposeWrapCommit         = "ldr.wrap-commit"
	PurposeJoinRequest        = "ldr.join-request"
	PurposeJoinChallenge      = "ldr.join-challenge"
	PurposeJoinProofSecret    = "ldr.join-proof-secret"
	PurposeEpochWrap          = "ldr.epoch-wrap"
	PurposeEpochReaderSet     = "ldr.epoch-reader-set"
)

var (
	ErrCommitmentMismatch = errors.New("ldrcrypto: sidecar commitment mismatch")
	ErrInvalidRootKeys    = errors.New("ldrcrypto: invalid equal 1-of-2 root keys")
)

// DomainDigest computes SHA-256(Enc([purpose, version, fields...])) by
// streaming canonical RFC 8949 §4.2.1 CBOR directly into SHA-256.
func DomainDigest(purpose string, version uint64, fields ...any) ([32]byte, error) {
	var zero [32]byte
	if purpose == "" {
		return zero, fmt.Errorf("%w: empty digest purpose", ErrCBORInvalid)
	}
	arr := make([]any, 0, 2+len(fields))
	arr = append(arr, purpose, version)
	arr = append(arr, fields...)
	return hashCanonicalCBOR(arr)
}

// Commitment binds a sidecar's domain-separated SHA-256 digest and exact byte length.
type Commitment struct {
	Digest [32]byte
	Length uint64
}

// Equal reports whether c and other have identical digest and length.
func (c Commitment) Equal(other Commitment) bool {
	return c.Length == other.Length && c.Digest == other.Digest
}

// ToCBORMap encodes c as canonical CBOR map {"digest": bstr(32), "length": uint}.
func (c Commitment) ToCBORMap() Map {
	d := make([]byte, 32)
	copy(d, c.Digest[:])
	return Map{
		{Key: "digest", Value: d},
		{Key: "length", Value: c.Length},
	}
}

// ParseCommitment decodes a Commitment from a decoded CBOR map.
func ParseCommitment(v any) (Commitment, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Commitment{}, fmt.Errorf("%w: commitment must be map", ErrCBORInvalid)
	}
	if err := RequireExactKeys(m, []string{"digest", "length"}); err != nil {
		return Commitment{}, err
	}
	d, err := MapBytesLen(m, "digest", 32)
	if err != nil {
		return Commitment{}, err
	}
	l, err := MapUint(m, "length")
	if err != nil {
		return Commitment{}, err
	}
	var c Commitment
	copy(c.Digest[:], d)
	c.Length = l
	return c, nil
}

// CommitPayload computes the typed Commitment for an encrypted payload sidecar.
// For ciphertext-free records, pass nil or empty slice to produce EmptyPayloadCommit().
func CommitPayload(pkgBytes []byte) (Commitment, error) {
	if pkgBytes == nil {
		pkgBytes = []byte{}
	}
	if uint64(len(pkgBytes)) > MaxCounter {
		return Commitment{}, ErrCBOROutOfDomain
	}
	d, err := DomainDigest(PurposePayloadCommit, 1, pkgBytes)
	if err != nil {
		return Commitment{}, err
	}
	return Commitment{Digest: d, Length: uint64(len(pkgBytes))}, nil
}

// EmptyPayloadCommit returns the canonical commitment for a ciphertext-free record.
func EmptyPayloadCommit() Commitment {
	c, err := CommitPayload([]byte{})
	if err != nil {
		panic(err)
	}
	return c
}

// CommitWrap computes the typed Commitment for an HPKE epoch-wrap sidecar.
func CommitWrap(wrapBytes []byte) (Commitment, error) {
	if len(wrapBytes) == 0 {
		return Commitment{}, fmt.Errorf("%w: empty wrap sidecar", ErrCBORInvalid)
	}
	if uint64(len(wrapBytes)) > MaxCounter {
		return Commitment{}, ErrCBOROutOfDomain
	}
	d, err := DomainDigest(PurposeWrapCommit, 1, wrapBytes)
	if err != nil {
		return Commitment{}, err
	}
	return Commitment{Digest: d, Length: uint64(len(wrapBytes))}, nil
}

// VerifyPayloadSidecar checks that sidecar matches expected payload Commitment.
func VerifyPayloadSidecar(expected Commitment, sidecar []byte) error {
	actual, err := CommitPayload(sidecar)
	if err != nil {
		return err
	}
	if !actual.Equal(expected) {
		return fmt.Errorf("%w: payload length/digest mismatch", ErrCommitmentMismatch)
	}
	return nil
}

// VerifyWrapSidecar checks that sidecar matches expected wrap Commitment.
func VerifyWrapSidecar(expected Commitment, sidecar []byte) error {
	actual, err := CommitWrap(sidecar)
	if err != nil {
		return err
	}
	if !actual.Equal(expected) {
		return fmt.Errorf("%w: wrap length/digest mismatch", ErrCommitmentMismatch)
	}
	return nil
}

// DeriveCredID derives the immutable 32-byte credential ID from an independently
// generated signing and encryption public key pair (P2).
func DeriveCredID(sigKey, encKey PublicKey) ([32]byte, error) {
	var zero [32]byte
	if err := sigKey.ValidateSigningKey(); err != nil {
		return zero, err
	}
	if err := encKey.ValidateEncryptionKey(); err != nil {
		return zero, err
	}
	if sigKey.Equal(encKey) {
		return zero, fmt.Errorf("%w: signing and encryption keys must differ", ErrInvalidKey)
	}
	return DomainDigest(PurposeCredID, 1, sigKey.Alg, sigKey.Bytes, encKey.Alg, encKey.Bytes)
}

// CanonicalRootKeys validates and deterministically sorts the equal 1-of-2 root key set.
func CanonicalRootKeys(keys []PublicKey) ([]PublicKey, error) {
	if len(keys) != 2 {
		return nil, fmt.Errorf("%w: expected exactly 2 root keys, got %d", ErrInvalidRootKeys, len(keys))
	}
	type item struct {
		key   PublicKey
		canon []byte
	}
	items := make([]item, 2)
	for i, k := range keys {
		if err := k.ValidateSigningKey(); err != nil {
			return nil, fmt.Errorf("%w: root key %d: %v", ErrInvalidRootKeys, i, err)
		}
		cb, err := k.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		items[i] = item{key: k.Clone(), canon: cb}
	}
	if bytes.Equal(items[0].canon, items[1].canon) {
		return nil, fmt.Errorf("%w: root keys must be distinct", ErrInvalidRootKeys)
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].canon, items[j].canon) < 0
	})
	return []PublicKey{items[0].key, items[1].key}, nil
}

// DescriptorDigest computes CD = SHA-256(Enc(["ldr.creation-descriptor", 1, bodyBytes])).
func DescriptorDigest(canonicalDescBody []byte) ([32]byte, error) {
	if len(canonicalDescBody) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty descriptor body", ErrCBORInvalid)
	}
	return DomainDigest(PurposeCreationDescriptor, 1, canonicalDescBody)
}

// GenesisAnchor computes the generation-1 genesis anchor constant from line_id,
// the canonical equal 1-of-2 root key set, and the creation-descriptor digest CD.
func GenesisAnchor(lineID []byte, rootKeys []PublicKey, descDigest [32]byte) ([32]byte, error) {
	var zero [32]byte
	if len(lineID) == 0 {
		return zero, fmt.Errorf("%w: empty line_id", ErrCBORInvalid)
	}
	sorted, err := CanonicalRootKeys(rootKeys)
	if err != nil {
		return zero, err
	}
	k0, err := sorted[0].ToCBOR()
	if err != nil {
		return zero, err
	}
	k1, err := sorted[1].ToCBOR()
	if err != nil {
		return zero, err
	}
	return DomainDigest(PurposeGenesis, 1, lineID, []any{k0, k1}, descDigest[:])
}

// IntentDigest computes the P5 operation content digest over the exact signed
// envelope bytes I_bytes (including signature).
func IntentDigest(signedEnvelopeBytes []byte) ([32]byte, error) {
	if len(signedEnvelopeBytes) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty signed intent bytes", ErrCBORInvalid)
	}
	return DomainDigest(PurposeIntent, 1, signedEnvelopeBytes)
}

// ClientChainHead computes the hash-chain head for a client-origin committed record.
func ClientChainHead(prevHead, profileDigest [32]byte, lineID []byte, gen, seq, seqTime uint64, origin string, intentBytes []byte) ([32]byte, error) {
	if len(lineID) == 0 || origin == "" || len(intentBytes) == 0 {
		return [32]byte{}, fmt.Errorf("%w: missing chain frame field", ErrCBORInvalid)
	}
	frame := Map{
		{Key: "gen", Value: gen},
		{Key: "intent", Value: intentBytes},
		{Key: "line_id", Value: lineID},
		{Key: "origin", Value: origin},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profileDigest[:]},
		{Key: "seq", Value: seq},
		{Key: "seq_time", Value: seqTime},
	}
	return DomainDigest(PurposeChain, 1, frame)
}

// AnchorChainHead computes the hash-chain head for a sequencer-origin time_anchor.
func AnchorChainHead(prevHead, profileDigest [32]byte, lineID []byte, gen, seq, seqTime uint64) ([32]byte, error) {
	if len(lineID) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty line_id", ErrCBORInvalid)
	}
	frame := Map{
		{Key: "gen", Value: gen},
		{Key: "line_id", Value: lineID},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profileDigest[:]},
		{Key: "seq", Value: seq},
		{Key: "seq_time", Value: seqTime},
	}
	return DomainDigest(PurposeChainAnchor, 1, frame)
}

// RecoveryChainHead computes the hash-chain head for a generation-transition recovery frame.
func RecoveryChainHead(prevHead, profileDigest [32]byte, lineID []byte, gen, seq, seqTime uint64, recoveryEnvelopeBytes []byte) ([32]byte, error) {
	if len(lineID) == 0 || len(recoveryEnvelopeBytes) == 0 {
		return [32]byte{}, fmt.Errorf("%w: missing recovery chain field", ErrCBORInvalid)
	}
	frame := Map{
		{Key: "gen", Value: gen},
		{Key: "line_id", Value: lineID},
		{Key: "prev_head", Value: prevHead[:]},
		{Key: "profile_digest", Value: profileDigest[:]},
		{Key: "recovery", Value: recoveryEnvelopeBytes},
		{Key: "seq", Value: seq},
		{Key: "seq_time", Value: seqTime},
	}
	return DomainDigest(PurposeChainRecovery, 1, frame)
}
