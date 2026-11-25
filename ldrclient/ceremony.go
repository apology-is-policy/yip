package ldrclient

import (
	"errors"
	"os"

	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

func marshalJoinRequest(req ldrcrypto.JoinRequest) ([]byte, error) {
	if _, err := ldrcrypto.VerifyJoinRequest(req); err != nil {
		return nil, err
	}
	sk, err := req.SigningKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	ek, err := req.EncryptionKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	caps := append([]string(nil), req.Grant.Capabilities...)
	if caps == nil {
		caps = []string{}
	}
	return ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "body", Value: req.BodyBytes},
		{Key: "context_auth_epoch", Value: req.ContextAuthEpoch},
		{Key: "context_key_epoch", Value: req.ContextKeyEpoch},
		{Key: "context_seq", Value: req.ContextSeq},
		{Key: "cred_id", Value: req.CredID[:]},
		{Key: "descriptor_digest", Value: req.DescriptorDigest[:]},
		{Key: "encryption_key", Value: ek},
		{Key: "generation", Value: req.Generation},
		{Key: "grant", Value: ldrcrypto.Map{
			{Key: "actor_limit", Value: req.Grant.ActorLimit},
			{Key: "capabilities", Value: caps},
			{Key: "namespace_id", Value: req.Grant.NamespaceID},
			{Key: "reader", Value: req.Grant.Reader},
		}},
		{Key: "line_id", Value: req.LineID},
		{Key: "request_id", Value: req.RequestID},
		{Key: "schema", Value: "ldr.join-request-file.v1"},
		{Key: "sig", Value: req.Sig},
		{Key: "signing_key", Value: sk},
		{Key: "v", Value: uint64(1)},
	})
}

// SaveJoinRequest writes a signed P3 JoinRequest to path as canonical CBOR.
func SaveJoinRequest(path string, req ldrcrypto.JoinRequest) error {
	raw, err := marshalJoinRequest(req)
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o644)
}

func saveJoinRequestCreateOnly(path string, req ldrcrypto.JoinRequest) error {
	raw, err := marshalJoinRequest(req)
	if err != nil {
		return err
	}
	return createFileExclusive(path, raw, 0o600)
}

// LoadJoinRequest loads and cryptographically verifies a saved P3 JoinRequest.
func LoadJoinRequest(path string) (ldrcrypto.JoinRequest, [32]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ldrcrypto.JoinRequest{}, [32]byte{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ldrcrypto.JoinRequest{}, [32]byte{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ldrcrypto.JoinRequest{}, [32]byte{}, errors.New("ldrclient: invalid join request file")
	}
	var req ldrcrypto.JoinRequest
	req.BodyBytes, _ = ldrcrypto.MapBytes(m, "body")
	req.Sig, _ = ldrcrypto.MapBytes(m, "sig")
	req.LineID, _ = ldrcrypto.MapBytes(m, "line_id")
	req.RequestID, _ = ldrcrypto.MapBytes(m, "request_id")
	req.Generation, _ = ldrcrypto.MapUint(m, "generation")
	req.ContextSeq, _ = ldrcrypto.MapUint(m, "context_seq")
	req.ContextAuthEpoch, _ = ldrcrypto.MapUint(m, "context_auth_epoch")
	req.ContextKeyEpoch, _ = ldrcrypto.MapUint(m, "context_key_epoch")
	if cidB, err := ldrcrypto.MapBytesLen(m, "cred_id", 32); err == nil {
		copy(req.CredID[:], cidB)
	}
	if ddB, err := ldrcrypto.MapBytesLen(m, "descriptor_digest", 32); err == nil {
		copy(req.DescriptorDigest[:], ddB)
	}
	if req.SigningKey, err = ldrcrypto.ParsePublicKey(m["signing_key"]); err != nil {
		return ldrcrypto.JoinRequest{}, [32]byte{}, err
	}
	if req.EncryptionKey, err = ldrcrypto.ParsePublicKey(m["encryption_key"]); err != nil {
		return ldrcrypto.JoinRequest{}, [32]byte{}, err
	}
	gm, err := ldrcrypto.MapSubmap(m, "grant")
	if err != nil {
		return ldrcrypto.JoinRequest{}, [32]byte{}, err
	}
	req.Grant.NamespaceID, _ = ldrcrypto.MapString(gm, "namespace_id")
	req.Grant.ActorLimit, _ = ldrcrypto.MapUint(gm, "actor_limit")
	req.Grant.Reader, _ = ldrcrypto.MapBool(gm, "reader")
	if ca, err := ldrcrypto.MapArray(gm, "capabilities"); err == nil {
		for _, x := range ca {
			if s, ok := x.(string); ok {
				req.Grant.Capabilities = append(req.Grant.Capabilities, s)
			}
		}
	}
	dig, err := ldrcrypto.VerifyJoinRequest(req)
	if err != nil {
		return ldrcrypto.JoinRequest{}, [32]byte{}, err
	}
	return req, dig, nil
}

// SaveJoinChallenge writes an operator-created P3 JoinChallenge to path (never includes secret).
func SaveJoinChallenge(path string, ch ldrcrypto.JoinChallenge) error {
	opC, err := ch.OperatorKey.ToCBOR()
	if err != nil {
		return err
	}
	sigC, err := ch.SigningKey.ToCBOR()
	if err != nil {
		return err
	}
	encC, err := ch.EncryptionKey.ToCBOR()
	if err != nil {
		return err
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "challenge_id", Value: ch.ChallengeID},
		{Key: "ciphertext", Value: ch.Ciphertext},
		{Key: "enc", Value: ch.Enc},
		{Key: "encryption_key", Value: encC},
		{Key: "generation", Value: ch.Generation},
		{Key: "line_id", Value: ch.LineID},
		{Key: "operator_key", Value: opC},
		{Key: "request_digest", Value: ch.RequestDigest[:]},
		{Key: "request_id", Value: ch.RequestID},
		{Key: "schema", Value: "ldr.join-challenge-file.v1"},
		{Key: "signing_key", Value: sigC},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o644)
}

// LoadJoinChallenge reads a P3 JoinChallenge file.
func LoadJoinChallenge(path string) (ldrcrypto.JoinChallenge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ldrcrypto.JoinChallenge{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ldrcrypto.JoinChallenge{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ldrcrypto.JoinChallenge{}, errors.New("ldrclient: invalid join challenge file")
	}
	var ch ldrcrypto.JoinChallenge
	ch.ChallengeID, _ = ldrcrypto.MapBytes(m, "challenge_id")
	ch.LineID, _ = ldrcrypto.MapBytes(m, "line_id")
	ch.Generation, _ = ldrcrypto.MapUint(m, "generation")
	ch.RequestID, _ = ldrcrypto.MapBytes(m, "request_id")
	ch.Enc, _ = ldrcrypto.MapBytes(m, "enc")
	ch.Ciphertext, _ = ldrcrypto.MapBytes(m, "ciphertext")
	if rd, err := ldrcrypto.MapBytesLen(m, "request_digest", 32); err == nil {
		copy(ch.RequestDigest[:], rd)
	}
	if ch.OperatorKey, err = ldrcrypto.ParsePublicKey(m["operator_key"]); err != nil {
		return ldrcrypto.JoinChallenge{}, err
	}
	if ch.SigningKey, err = ldrcrypto.ParsePublicKey(m["signing_key"]); err != nil {
		return ldrcrypto.JoinChallenge{}, err
	}
	if ch.EncryptionKey, err = ldrcrypto.ParsePublicKey(m["encryption_key"]); err != nil {
		return ldrcrypto.JoinChallenge{}, err
	}
	return ch, nil
}

// SaveJoinProof writes a joiner's signed P3 JoinProof to path.
func SaveJoinProof(path string, pr ldrcrypto.JoinProof) error {
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "challenge_id", Value: pr.ChallengeID},
		{Key: "request_digest", Value: pr.RequestDigest[:]},
		{Key: "schema", Value: "ldr.join-proof-file.v1"},
		{Key: "secret_commit", Value: pr.SecretCommit[:]},
		{Key: "sig", Value: pr.Sig},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o644)
}

// LoadJoinProof reads a P3 JoinProof file.
func LoadJoinProof(path string) (ldrcrypto.JoinProof, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ldrcrypto.JoinProof{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ldrcrypto.JoinProof{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ldrcrypto.JoinProof{}, errors.New("ldrclient: invalid join proof file")
	}
	var pr ldrcrypto.JoinProof
	pr.ChallengeID, _ = ldrcrypto.MapBytes(m, "challenge_id")
	pr.Sig, _ = ldrcrypto.MapBytes(m, "sig")
	if rd, err := ldrcrypto.MapBytesLen(m, "request_digest", 32); err == nil {
		copy(pr.RequestDigest[:], rd)
	}
	if sc, err := ldrcrypto.MapBytesLen(m, "secret_commit", 32); err == nil {
		copy(pr.SecretCommit[:], sc)
	}
	return pr, nil
}

// SaveJoinSecret saves the operator's ephemeral 32-byte challenge secret with 0600 permissions.
func SaveJoinSecret(path string, secret []byte) error {
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "schema", Value: "ldr.join-secret-file.v1"},
		{Key: "secret", Value: secret},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

// LoadJoinSecret loads the operator's ephemeral 32-byte challenge secret.
func LoadJoinSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return nil, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return nil, errors.New("ldrclient: invalid join secret file")
	}
	return ldrcrypto.MapBytesLen(m, "secret", 32)
}
