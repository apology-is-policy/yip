package ldrclient

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

// PathsAlias reports whether paths a and b refer to the same destination,
// resolving symlinks along existing ancestor directories as well as checking
// os.SameFile when both already exist.
func PathsAlias(a, b string) (bool, error) {
	if a == "" || b == "" {
		return false, nil
	}
	if fiA, errA := os.Lstat(a); errA == nil {
		if fiB, errB := os.Lstat(b); errB == nil && os.SameFile(fiA, fiB) {
			return true, nil
		}
	}
	if fiA, errA := os.Stat(a); errA == nil {
		if fiB, errB := os.Stat(b); errB == nil && os.SameFile(fiA, fiB) {
			return true, nil
		}
	}
	ca, err := CanonicalPath(a)
	if err != nil {
		return false, err
	}
	cb, err := CanonicalPath(b)
	if err != nil {
		return false, err
	}
	return ca == cb, nil
}

// CanonicalPath resolves existing ancestors and preserves an as-yet-uncreated suffix.
func CanonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	cur := abs
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			parts := make([]string, 0, 1+len(tail))
			parts = append(parts, resolved)
			for i := len(tail) - 1; i >= 0; i-- {
				parts = append(parts, tail[i])
			}
			return filepath.Clean(filepath.Join(parts...)), nil
		}
		if !os.IsNotExist(err) {
			return abs, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// SaveCreationDescriptor verifies and publishes a signed creation descriptor
// atomically without clobbering any existing destination.
func SaveCreationDescriptor(path string, raw []byte) error {
	if _, _, _, _, err := ldrcrypto.VerifyCreationDescriptor(raw); err != nil {
		return err
	}
	return publishFileNoClobber(path, raw, 0o644, false)
}

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

// SaveJoinRequest publishes a signed P3 JoinRequest to path as canonical CBOR
// without clobbering any existing destination. If path already exists as a
// byte-identical regular file, SaveJoinRequest succeeds idempotently without
// modifying it; conflicting regular files, symlinks, and directories fail with
// ErrOutputExists.
func SaveJoinRequest(path string, req ldrcrypto.JoinRequest) error {
	raw, err := marshalJoinRequest(req)
	if err != nil {
		return err
	}
	return publishFileNoClobber(path, raw, 0o644, true)
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

func marshalJoinChallenge(ch ldrcrypto.JoinChallenge) ([]byte, error) {
	opC, err := ch.OperatorKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	sigC, err := ch.SigningKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	encC, err := ch.EncryptionKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	return ldrcrypto.MarshalCBOR(ldrcrypto.Map{
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
}

func unmarshalJoinChallenge(raw []byte) (ldrcrypto.JoinChallenge, error) {
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

// SaveJoinChallenge publishes an operator-created P3 JoinChallenge to path
// without clobbering any existing destination (never includes secret).
func SaveJoinChallenge(path string, ch ldrcrypto.JoinChallenge) error {
	raw, err := marshalJoinChallenge(ch)
	if err != nil {
		return err
	}
	return publishFileNoClobber(path, raw, 0o644, false)
}

// LoadJoinChallenge reads a P3 JoinChallenge file.
func LoadJoinChallenge(path string) (ldrcrypto.JoinChallenge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ldrcrypto.JoinChallenge{}, err
	}
	return unmarshalJoinChallenge(raw)
}

// SaveJoinProof publishes a joiner's signed P3 JoinProof to path without
// clobbering conflicting destinations (accepts an existing byte-identical regular file).
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
	return publishFileNoClobber(path, raw, 0o644, true)
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

// SaveJoinSecret publishes the operator's ephemeral 32-byte challenge secret
// with 0600 permissions without clobbering any existing destination.
func SaveJoinSecret(path string, secret []byte) error {
	if len(secret) != 32 {
		return errors.New("ldrclient: join secret must be 32 bytes")
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "schema", Value: "ldr.join-secret-file.v1"},
		{Key: "secret", Value: secret},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return publishFileNoClobber(path, raw, 0o600, false)
}

// SaveJoinSecretWithChallenge publishes the operator's 32-byte challenge secret
// along with the exact matching canonical JoinChallenge bytes (0600, non-clobbering)
// so a failed challenge-file export can be retried cleanly without regenerating
// or replacing the ceremony secret.
func SaveJoinSecretWithChallenge(path string, secret []byte, ch ldrcrypto.JoinChallenge) error {
	if len(secret) != 32 {
		return errors.New("ldrclient: join secret must be 32 bytes")
	}
	chRaw, err := marshalJoinChallenge(ch)
	if err != nil {
		return err
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "challenge", Value: chRaw},
		{Key: "schema", Value: "ldr.join-secret-file.v1"},
		{Key: "secret", Value: secret},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return publishFileNoClobber(path, raw, 0o600, false)
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

// LoadJoinSecretWithChallenge loads a regular join-secret file together with its
// embedded JoinChallenge for resuming an interrupted challenge export.
func LoadJoinSecretWithChallenge(path string) ([]byte, ldrcrypto.JoinChallenge, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, ldrcrypto.JoinChallenge{}, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ldrcrypto.JoinChallenge{}, fmt.Errorf("%w: %s is not a regular file", ErrOutputExists, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ldrcrypto.JoinChallenge{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return nil, ldrcrypto.JoinChallenge{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return nil, ldrcrypto.JoinChallenge{}, errors.New("ldrclient: invalid join secret file")
	}
	schema, _ := ldrcrypto.MapString(m, "schema")
	if schema != "ldr.join-secret-file.v1" {
		return nil, ldrcrypto.JoinChallenge{}, errors.New("ldrclient: invalid join secret schema")
	}
	sec, err := ldrcrypto.MapBytesLen(m, "secret", 32)
	if err != nil {
		return nil, ldrcrypto.JoinChallenge{}, err
	}
	chRaw, err := ldrcrypto.MapBytes(m, "challenge")
	if err != nil {
		return nil, ldrcrypto.JoinChallenge{}, errors.New("ldrclient: join secret file has no resumable challenge")
	}
	ch, err := unmarshalJoinChallenge(chRaw)
	if err != nil {
		return nil, ldrcrypto.JoinChallenge{}, err
	}
	return sec, ch, nil
}
