package ldrcrypto

import (
	"bytes"
	"fmt"
)

const (
	// PurposeRegisterPayload domain-separates encrypted §9 advisory register
	// payload AEAD contexts from log record payload contexts.
	PurposeRegisterPayload = "ldr.register-payload"

	// MaxRegisterEnvelopeBytes bounds the encoded CBOR register envelope.
	MaxRegisterEnvelopeBytes = 8 * 1024
	// MaxRegisterBodyBytes bounds the encrypted register payload package.
	MaxRegisterBodyBytes = 64 * 1024
)

// ValidRegisterType reports whether name is one of the §9 advisory register types.
func ValidRegisterType(name string) bool {
	return name == "presence" || name == "roadmap" || name == "resource"
}

// RegisterEnvelope is a signed latest-value advisory register update outside the log (§9).
type RegisterEnvelope struct {
	Version       uint64
	LineID        []byte
	Generation    uint64
	ProfileDigest [32]byte
	Register      string
	ActorID       string
	CredID        [32]byte
	BindingGen    uint64
	WriterRev     uint64
	Incarnation   string
	KeyEpoch      uint64
	Counter       uint64
	PayloadCommit Commitment
	Sig           []byte
}

// RegisterPayloadContextBytes returns the canonical CBOR AEAD context binding a
// register ciphertext to its exact line, generation, register, actor, writer
// activation, key epoch, and monotonic counter. Domain-separated from log payloads.
func RegisterPayloadContextBytes(
	profDigest [32]byte,
	lineID []byte,
	gen uint64,
	register, actorID string,
	credID [32]byte,
	bindingGen, writerRev uint64,
	incarnation string,
	keyEpoch, counter uint64,
) ([]byte, error) {
	if len(lineID) < 16 || len(lineID) > 64 {
		return nil, fmt.Errorf("%w: register payload context invalid line_id length", ErrInvalidEnvelope)
	}
	if gen < 1 || gen > MaxCounter || !ValidRegisterType(register) || actorID == "" ||
		bindingGen < 1 || bindingGen > MaxCounter || writerRev < 1 || writerRev > MaxCounter ||
		incarnation == "" || keyEpoch < 1 || keyEpoch > MaxCounter || counter > MaxCounter {
		return nil, fmt.Errorf("%w: invalid register payload context fields", ErrInvalidEnvelope)
	}
	return MarshalCBOR([]any{
		PurposeRegisterPayload,
		uint64(1),
		bytes.Clone(profDigest[:]),
		bytes.Clone(lineID),
		gen,
		register,
		actorID,
		bytes.Clone(credID[:]),
		bindingGen,
		writerRev,
		incarnation,
		keyEpoch,
		counter,
	})
}

func (e RegisterEnvelope) validateBodyFields() error {
	if e.Version != 1 {
		return fmt.Errorf("%w: unsupported register envelope version %d", ErrInvalidEnvelope, e.Version)
	}
	if len(e.LineID) < 16 || len(e.LineID) > 64 {
		return fmt.Errorf("%w: register envelope invalid line_id length", ErrInvalidEnvelope)
	}
	if e.Generation < 1 || e.Generation > MaxCounter {
		return fmt.Errorf("%w: register envelope invalid generation", ErrInvalidEnvelope)
	}
	if !ValidRegisterType(e.Register) {
		return fmt.Errorf("%w: unknown register type %q", ErrInvalidEnvelope, e.Register)
	}
	if e.ActorID == "" || len(e.ActorID) > 128 {
		return fmt.Errorf("%w: invalid register actor_id", ErrInvalidEnvelope)
	}
	if e.BindingGen < 1 || e.BindingGen > MaxCounter {
		return fmt.Errorf("%w: invalid register binding_gen", ErrInvalidEnvelope)
	}
	if e.WriterRev < 1 || e.WriterRev > MaxCounter {
		return fmt.Errorf("%w: invalid register writer_rev", ErrInvalidEnvelope)
	}
	if e.Incarnation == "" || len(e.Incarnation) > 128 {
		return fmt.Errorf("%w: invalid register incarnation", ErrInvalidEnvelope)
	}
	if e.KeyEpoch < 1 || e.KeyEpoch > MaxCounter {
		return fmt.Errorf("%w: invalid register key_epoch", ErrInvalidEnvelope)
	}
	if e.Counter > MaxCounter {
		return fmt.Errorf("%w: register counter exceeds safe domain", ErrInvalidEnvelope)
	}
	if e.PayloadCommit.Length == 0 || e.PayloadCommit.Length > MaxRegisterBodyBytes {
		return fmt.Errorf("%w: register payload commitment length %d out of bounds", ErrInvalidEnvelope, e.PayloadCommit.Length)
	}
	return nil
}

func (e RegisterEnvelope) canonicalBodyBytes() ([]byte, error) {
	if err := e.validateBodyFields(); err != nil {
		return nil, err
	}
	return MarshalCBORWithLimits(Map{
		{Key: "actor_id", Value: e.ActorID},
		{Key: "binding_gen", Value: e.BindingGen},
		{Key: "counter", Value: e.Counter},
		{Key: "cred_id", Value: bytes.Clone(e.CredID[:])},
		{Key: "gen", Value: e.Generation},
		{Key: "incarnation", Value: e.Incarnation},
		{Key: "key_epoch", Value: e.KeyEpoch},
		{Key: "line_id", Value: bytes.Clone(e.LineID)},
		{Key: "payload_commit", Value: e.PayloadCommit.ToCBORMap()},
		{Key: "profile_digest", Value: bytes.Clone(e.ProfileDigest[:])},
		{Key: "register", Value: e.Register},
		{Key: "v", Value: uint64(1)},
		{Key: "writer_rev", Value: e.WriterRev},
	}, Limits{MaxBytes: MaxRegisterEnvelopeBytes, MaxDepth: 8, MaxItems: 64})
}

// SignRegisterEnvelope canonically encodes and signs an advisory register envelope.
func SignRegisterEnvelope(signer Signer, env RegisterEnvelope) ([]byte, error) {
	if env.Version == 0 {
		env.Version = 1
	}
	bodyBytes, err := env.canonicalBodyBytes()
	if err != nil {
		return nil, err
	}
	sig, err := SignDomain(signer, PurposeRegister, 1, bodyBytes)
	if err != nil {
		return nil, err
	}
	return MarshalCBORWithLimits(Map{
		{Key: "body", Value: bodyBytes},
		{Key: "sig", Value: sig},
		{Key: "v", Value: uint64(1)},
	}, Limits{MaxBytes: MaxRegisterEnvelopeBytes, MaxDepth: 8, MaxItems: 64})
}

// ParseRegisterEnvelope strictly decodes a signed register envelope without
// verifying the signature, returning the parsed struct and raw canonical body bytes.
func ParseRegisterEnvelope(raw []byte) (RegisterEnvelope, []byte, error) {
	lim := Limits{MaxBytes: MaxRegisterEnvelopeBytes, MaxDepth: 8, MaxItems: 64}
	topV, err := UnmarshalCBOR(raw, lim)
	if err != nil {
		return RegisterEnvelope{}, nil, err
	}
	top, ok := topV.(map[string]any)
	if !ok {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: register envelope must be map", ErrInvalidEnvelope)
	}
	if err := RequireExactKeys(top, []string{"body", "sig", "v"}); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if v, err := MapUint(top, "v"); err != nil || v != 1 {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: invalid register envelope version", ErrInvalidEnvelope)
	}
	bodyBytes, err := MapBytes(top, "body")
	if err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	sig, err := MapBytes(top, "sig")
	if err != nil || len(sig) == 0 {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: missing register envelope sig", ErrInvalidEnvelope)
	}
	bodyV, err := UnmarshalCBOR(bodyBytes, lim)
	if err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: invalid register body: %v", ErrInvalidEnvelope, err)
	}
	bm, ok := bodyV.(map[string]any)
	if !ok {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: register body must be map", ErrInvalidEnvelope)
	}
	if err := RequireExactKeys(bm, []string{
		"actor_id", "binding_gen", "counter", "cred_id", "gen",
		"incarnation", "key_epoch", "line_id", "payload_commit",
		"profile_digest", "register", "v", "writer_rev",
	}); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	var env RegisterEnvelope
	if env.Version, err = MapUint(bm, "v"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.LineID, err = MapBytes(bm, "line_id"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.Generation, err = MapUint(bm, "gen"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	pd, err := MapBytesLen(bm, "profile_digest", 32)
	if err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	copy(env.ProfileDigest[:], pd)
	if env.Register, err = MapString(bm, "register"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.ActorID, err = MapString(bm, "actor_id"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	cid, err := MapBytesLen(bm, "cred_id", 32)
	if err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	copy(env.CredID[:], cid)
	if env.BindingGen, err = MapUint(bm, "binding_gen"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.WriterRev, err = MapUint(bm, "writer_rev"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.Incarnation, err = MapString(bm, "incarnation"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.KeyEpoch, err = MapUint(bm, "key_epoch"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.Counter, err = MapUint(bm, "counter"); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if env.PayloadCommit, err = ParseCommitment(bm["payload_commit"]); err != nil {
		return RegisterEnvelope{}, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	env.Sig = bytes.Clone(sig)
	if err := env.validateBodyFields(); err != nil {
		return RegisterEnvelope{}, nil, err
	}
	return env, bytes.Clone(bodyBytes), nil
}

// VerifyRegisterEnvelope decodes raw and verifies its signature under pub.
func VerifyRegisterEnvelope(raw []byte, pub PublicKey) (RegisterEnvelope, error) {
	env, bodyBytes, err := ParseRegisterEnvelope(raw)
	if err != nil {
		return RegisterEnvelope{}, err
	}
	if err := VerifyDomain(pub, PurposeRegister, 1, bodyBytes, env.Sig); err != nil {
		return RegisterEnvelope{}, err
	}
	return env, nil
}
