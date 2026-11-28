package ldrrelay

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

var (
	ErrMalformedWireIntent = errors.New("ldrrelay: malformed wire intent")
)

// KeyToken encodes a validated canonical public key `[alg, bytes]` as a unique,
// collision-free lowercase hex string suitable for ldrcore.State registries.
func KeyToken(pk ldrcrypto.PublicKey) (string, error) {
	b, err := pk.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ParseKeyToken reverses KeyToken back into a strictly validated PublicKey.
func ParseKeyToken(tok string) (ldrcrypto.PublicKey, error) {
	raw, err := hex.DecodeString(tok)
	if err != nil {
		return ldrcrypto.PublicKey{}, fmt.Errorf("%w: invalid key token hex", ldrcrypto.ErrInvalidKey)
	}
	v, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ldrcrypto.PublicKey{}, err
	}
	return ldrcrypto.ParsePublicKey(v)
}

// CredToken formats a 32-byte credential ID as lowercase hex for ldrcore.State.
func CredToken(credID [32]byte) string {
	return hex.EncodeToString(credID[:])
}

// PrincipalToken maps a tagged ldrcrypto.Principal to the exact principal
// namespace used by ldrcore ("cred:...", "op:...", "root:...").
func PrincipalToken(p ldrcrypto.Principal) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	switch p.Kind {
	case ldrcrypto.PrincipalCredential:
		return ldrcore.CredentialPrincipal(CredToken(p.CredID)), nil
	case ldrcrypto.PrincipalOperator:
		tok, err := KeyToken(*p.Key)
		if err != nil {
			return "", err
		}
		return ldrcore.OperatorPrincipal(tok), nil
	case ldrcrypto.PrincipalRoot:
		tok, err := KeyToken(*p.Key)
		if err != nil {
			return "", err
		}
		return ldrcore.RootPrincipal(tok), nil
	default:
		return "", fmt.Errorf("%w: unknown principal kind %q", ErrMalformedWireIntent, p.Kind)
	}
}

// WireIntentInput is the structured input to BuildWireIntentBody for producing
// canonical CBOR intent bodies B.
type WireIntentInput struct {
	ProfileDigest [32]byte
	LineID        []byte
	Generation    uint64
	Origin        string
	Principal     ldrcrypto.Principal
	ActorID       string // required iff Origin == "actor"
	BindingGen    uint64 // required iff Origin == "actor"
	OpID          string
	OpType        string
	AuthEpoch     uint64
	KeyEpoch      uint64
	SeenSeq       uint64
	SeenHead      [32]byte
	ValidityMS    uint64
	PayloadCommit ldrcrypto.Commitment
	Expect        ldrcrypto.ExpectMap
	Fields        ldrcrypto.Map
	Manifest      []ldrcrypto.WrapManifestEntry // present iff OpType == "key_epoch_activate"
}

// BuildWireIntentBody encodes a canonical CBOR intent body B.
func BuildWireIntentBody(in WireIntentInput) ([]byte, error) {
	prinCBOR, err := in.Principal.ToCBOR()
	if err != nil {
		return nil, err
	}
	exp := in.Expect
	if exp == nil {
		exp = ldrcrypto.ExpectMap{}
	}
	expMap, err := exp.ToCBORMap()
	if err != nil {
		return nil, err
	}
	fields := in.Fields
	if fields == nil {
		fields = ldrcrypto.Map{}
	}
	m := ldrcrypto.Map{
		{Key: "auth_epoch", Value: in.AuthEpoch},
		{Key: "expect", Value: expMap},
		{Key: "fields", Value: fields},
		{Key: "generation", Value: in.Generation},
		{Key: "key_epoch", Value: in.KeyEpoch},
		{Key: "line_id", Value: bytes.Clone(in.LineID)},
		{Key: "op_id", Value: in.OpID},
		{Key: "op_type", Value: in.OpType},
		{Key: "origin", Value: in.Origin},
		{Key: "payload_commit", Value: in.PayloadCommit.ToCBORMap()},
		{Key: "principal", Value: prinCBOR},
		{Key: "profile_digest", Value: bytes.Clone(in.ProfileDigest[:])},
		{Key: "seen_head", Value: bytes.Clone(in.SeenHead[:])},
		{Key: "seen_seq", Value: in.SeenSeq},
		{Key: "v", Value: ldrcrypto.ProtocolVersion},
		{Key: "validity_ms", Value: in.ValidityMS},
	}
	if in.Origin == ldrcore.OriginActor {
		m = append(m,
			ldrcrypto.MapEntry{Key: "actor_id", Value: in.ActorID},
			ldrcrypto.MapEntry{Key: "binding_gen", Value: in.BindingGen},
		)
	}
	if in.OpType == "key_epoch_activate" {
		mArr := make([]any, len(in.Manifest))
		for i, ent := range in.Manifest {
			mArr[i] = ldrcrypto.Map{
				{Key: "commit", Value: ent.Commit.ToCBORMap()},
				{Key: "cred_id", Value: bytes.Clone(ent.CredID[:])},
			}
		}
		m = append(m, ldrcrypto.MapEntry{Key: "manifest", Value: mArr})
	}
	return ldrcrypto.MarshalCBOR(m)
}

// DecodedIntent holds the strictly validated wire metadata and translated
// ldrcore.Record ready for admission and Apply.
type DecodedIntent struct {
	ProfileDigest    [32]byte
	LineID           []byte
	Generation       uint64
	Origin           string
	Principal        ldrcrypto.Principal
	PrincipalToken   string
	OpID             string
	OpType           string
	SeenSeq          uint64
	SeenHead         [32]byte
	ValidityMS       uint64
	PayloadCommit    ldrcrypto.Commitment
	Manifest         []ldrcrypto.WrapManifestEntry
	DescriptorDigest *[32]byte          // set on line_init
	InitProfile      *ldrcrypto.Profile // set on line_init
	Record           ldrcore.Record
}

// DecodeWireIntentBody strictly decodes canonical CBOR body bytes B, enforces
// per-type visible field allowlists, derives cred_id cryptographically (never
// trusting a sender boolean), and produces the exact ldrcore.Record.
func DecodeWireIntentBody(bodyBytes []byte, prof ldrcrypto.Profile, lim ldrcrypto.Limits) (*DecodedIntent, error) {
	v, err := ldrcrypto.UnmarshalCBOR(bodyBytes, lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: intent body must be map", ErrMalformedWireIntent)
	}
	req := []string{
		"auth_epoch", "expect", "fields", "generation", "key_epoch",
		"line_id", "op_id", "op_type", "origin", "payload_commit",
		"principal", "profile_digest", "seen_head", "seen_seq", "v", "validity_ms",
	}
	if err := ldrcrypto.RequireExactKeys(m, req, "actor_id", "binding_gen", "manifest"); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	ver, err := ldrcrypto.MapUint(m, "v")
	if err != nil || ver != ldrcrypto.ProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrMalformedWireIntent)
	}
	pdBytes, err := ldrcrypto.MapBytesLen(m, "profile_digest", 32)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	lineID, err := ldrcrypto.MapBytes(m, "line_id")
	if err != nil || len(lineID) < 16 || len(lineID) > 64 {
		return nil, fmt.Errorf("%w: invalid line_id", ErrMalformedWireIntent)
	}
	gen, err := ldrcrypto.MapUint(m, "generation")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	origin, err := ldrcrypto.MapString(m, "origin")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	prin, err := ldrcrypto.ParsePrincipal(m["principal"])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	prinTok, err := PrincipalToken(prin)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	opID, err := ldrcrypto.MapString(m, "op_id")
	if err != nil || opID == "" {
		return nil, fmt.Errorf("%w: empty op_id", ErrMalformedWireIntent)
	}
	opType, err := ldrcrypto.MapString(m, "op_type")
	if err != nil || opType == "" {
		return nil, fmt.Errorf("%w: empty op_type", ErrMalformedWireIntent)
	}
	authEpoch, err := ldrcrypto.MapUint(m, "auth_epoch")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	keyEpoch, err := ldrcrypto.MapUint(m, "key_epoch")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	seenSeq, err := ldrcrypto.MapUint(m, "seen_seq")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	shBytes, err := ldrcrypto.MapBytesLen(m, "seen_head", 32)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	validityMS, err := ldrcrypto.MapUint(m, "validity_ms")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	pCommit, err := ldrcrypto.ParseCommitment(m["payload_commit"])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	expMap, err := ldrcrypto.ParseExpectMap(m["expect"])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}
	fields, err := ldrcrypto.MapSubmap(m, "fields")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
	}

	out := &DecodedIntent{
		LineID:         bytes.Clone(lineID),
		Generation:     gen,
		Origin:         origin,
		Principal:      prin,
		PrincipalToken: prinTok,
		OpID:           opID,
		OpType:         opType,
		SeenSeq:        seenSeq,
		ValidityMS:     validityMS,
		PayloadCommit:  pCommit,
		Record: ldrcore.Record{
			Origin:     origin,
			Type:       opType,
			AuthEpoch:  int64(authEpoch),
			KeyEpoch:   int64(keyEpoch),
			ValidityMS: int64(validityMS),
			Expect:     toCoreExpect(expMap),
		},
	}
	copy(out.ProfileDigest[:], pdBytes)
	copy(out.SeenHead[:], shBytes)

	// Bind origin -> principal kind and signer fields strictly.
	_, hasActorID := m["actor_id"]
	_, hasBindingGen := m["binding_gen"]
	switch origin {
	case ldrcore.OriginActor:
		if prin.Kind != ldrcrypto.PrincipalCredential || !hasActorID || !hasBindingGen {
			return nil, fmt.Errorf("%w: actor origin requires credential principal, actor_id, and binding_gen", ErrMalformedWireIntent)
		}
		aid, err := ldrcrypto.MapString(m, "actor_id")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		bg, err := ldrcrypto.MapUint(m, "binding_gen")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		out.Record.Cred = CredToken(prin.CredID)
		out.Record.Actor = aid
		out.Record.BindingGen = int64(bg)
	case ldrcore.OriginCredential:
		if prin.Kind != ldrcrypto.PrincipalCredential || hasActorID || hasBindingGen {
			return nil, fmt.Errorf("%w: credential origin requires credential principal without actor fields", ErrMalformedWireIntent)
		}
		out.Record.Cred = CredToken(prin.CredID)
	case ldrcore.OriginOperator:
		if prin.Kind != ldrcrypto.PrincipalOperator || hasActorID || hasBindingGen {
			return nil, fmt.Errorf("%w: operator origin requires operator principal", ErrMalformedWireIntent)
		}
		tok, err := KeyToken(*prin.Key)
		if err != nil {
			return nil, err
		}
		out.Record.Operator = tok
	case ldrcore.OriginRoot:
		if prin.Kind != ldrcrypto.PrincipalRoot || hasActorID || hasBindingGen {
			return nil, fmt.Errorf("%w: root origin requires root principal", ErrMalformedWireIntent)
		}
		tok, err := KeyToken(*prin.Key)
		if err != nil {
			return nil, err
		}
		out.Record.RootKey = tok
	default:
		return nil, fmt.Errorf("%w: unsupported origin %q", ErrMalformedWireIntent, origin)
	}

	// Only key_epoch_activate may carry manifest.
	_, hasManifest := m["manifest"]
	if hasManifest && opType != "key_epoch_activate" {
		return nil, fmt.Errorf("%w: unexpected manifest on %s", ErrMalformedWireIntent, opType)
	}

	if err := decodeTypeFields(out, m, fields, prof); err != nil {
		return nil, err
	}

	// Enforce ciphertext-free vs payload-bearing commitment boundary (§6.3).
	empty := ldrcrypto.EmptyPayloadCommit()
	carriesPayload := isPayloadBearing(out.Record)
	if !carriesPayload && !pCommit.Equal(empty) {
		out.Record.UnexpectedLineCiphertext = true
	}
	if carriesPayload && pCommit.Length == 0 {
		return nil, fmt.Errorf("%w: payload-bearing %s requires non-empty payload commitment", ErrMalformedWireIntent, opType)
	}
	if pCommit.Length > prof.MaxCiphertextBytes {
		if opType == "call_attach" {
			out.Record.SizeClass = "over_inline_limit"
		} else {
			return nil, fmt.Errorf("%w: payload length %d exceeds max_ciphertext_bytes %d", ErrMalformedWireIntent, pCommit.Length, prof.MaxCiphertextBytes)
		}
	}

	return out, nil
}

func toCoreExpect(em ldrcrypto.ExpectMap) ldrcore.Expect {
	ptr := func(k string) *int64 {
		v, ok := em[k]
		if !ok {
			return nil
		}
		n := int64(v)
		return &n
	}
	return ldrcore.Expect{
		TurnCount:    ptr("turn_count"),
		LifecycleRev: ptr("lifecycle_rev"),
		MeasureRev:   ptr("measure_rev"),
		Rev:          ptr("rev"),
		AddrRev:      ptr("addr_rev"),
		BindingGen:   ptr("binding_gen"),
		AudienceRev:  ptr("audience_rev"),
		KeyEpoch:     ptr("key_epoch"),
		WriterRev:    ptr("writer_rev"),
		RootRev:      ptr("root_rev"),
	}
}

func isPayloadBearing(r ldrcore.Record) bool {
	switch r.Type {
	case "call_open", "call_turn", "call_status", "call_note", "call_ratify",
		"call_attach", "dispute_open", "dispute_measure", "dispute_resolve",
		"dispute_arbitrate", "broadcast_create", "broadcast_reply":
		return true
	case "actor_declare":
		return r.Label
	default:
		return false
	}
}

func decodeTypeFields(out *DecodedIntent, top, fields map[string]any, prof ldrcrypto.Profile) error {
	r := &out.Record
	switch out.OpType {
	case "line_init":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"descriptor_digest", "profile", "root_keys"}); err != nil {
			return fmt.Errorf("%w: line_init: %v", ErrMalformedWireIntent, err)
		}
		cdBytes, err := ldrcrypto.MapBytesLen(fields, "descriptor_digest", 32)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		var cd [32]byte
		copy(cd[:], cdBytes)
		out.DescriptorDigest = &cd
		p, err := ldrcrypto.ParseProfile(fields["profile"])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		out.InitProfile = &p
		rawRoots, err := ldrcrypto.MapArray(fields, "root_keys")
		if err != nil || len(rawRoots) != 2 {
			return fmt.Errorf("%w: line_init requires 2 root_keys", ErrMalformedWireIntent)
		}
		k0, err := ldrcrypto.ParsePublicKey(rawRoots[0])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		k1, err := ldrcrypto.ParsePublicKey(rawRoots[1])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		sorted, err := ldrcrypto.CanonicalRootKeys([]ldrcrypto.PublicKey{k0, k1})
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		t0, err := KeyToken(sorted[0])
		if err != nil {
			return err
		}
		t1, err := KeyToken(sorted[1])
		if err != nil {
			return err
		}
		r.RootKeys = []string{t0, t1}

	case "operator_key_authorize", "operator_key_revoke":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"operator_key"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		pk, err := ldrcrypto.ParsePublicKey(fields["operator_key"])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		if err := pk.ValidateSigningKey(); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		tok, err := KeyToken(pk)
		if err != nil {
			return err
		}
		r.OperatorKey = tok

	case "root_member_replace":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"new_root_key", "old_root_key"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		oldPK, err := ldrcrypto.ParsePublicKey(fields["old_root_key"])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		newPK, err := ldrcrypto.ParsePublicKey(fields["new_root_key"])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		if err := oldPK.ValidateSigningKey(); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		if err := newPK.ValidateSigningKey(); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		oldTok, err := KeyToken(oldPK)
		if err != nil {
			return err
		}
		newTok, err := KeyToken(newPK)
		if err != nil {
			return err
		}
		r.OldRootKey = oldTok
		r.NewRootKey = newTok

	case "credential_enroll":
		reqF := []string{"cred_id", "encryption_key", "grant", "join_request_digest", "join_request_id", "signing_key"}
		if err := ldrcrypto.RequireExactKeys(fields, reqF); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cidBytes, err := ldrcrypto.MapBytesLen(fields, "cred_id", 32)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		var cid [32]byte
		copy(cid[:], cidBytes)
		sigPK, err := ldrcrypto.ParsePublicKey(fields["signing_key"])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		encPK, err := ldrcrypto.ParsePublicKey(fields["encryption_key"])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		reqID, err := ldrcrypto.MapBytes(fields, "join_request_id")
		if err != nil || len(reqID) == 0 {
			return fmt.Errorf("%w: invalid join_request_id", ErrMalformedWireIntent)
		}
		reqDig, err := ldrcrypto.MapBytesLen(fields, "join_request_digest", 32)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		gm, err := ldrcrypto.MapSubmap(fields, "grant")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		if err := ldrcrypto.RequireExactKeys(gm, []string{"actor_limit", "namespace_id", "reader"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		ns, err := ldrcrypto.MapString(gm, "namespace_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		al, err := ldrcrypto.MapUint(gm, "actor_limit")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		reader, err := ldrcrypto.MapBool(gm, "reader")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}

		// Cryptographically compute cred_id derivation; never trust a boolean!
		derived, derr := ldrcrypto.DeriveCredID(sigPK, encPK)
		r.CredIDMismatch = derr != nil || derived != cid
		sigTok, err := KeyToken(sigPK)
		if err != nil {
			return err
		}
		encTok, err := KeyToken(encPK)
		if err != nil {
			return err
		}
		r.Cred = CredToken(cid)
		r.SigningKey = sigTok
		r.EncryptionKey = encTok
		r.JoinRequest = hex.EncodeToString(reqID)
		r.JoinRequestDigest = hex.EncodeToString(reqDig)
		r.Grant = &ldrcore.Grant{Namespace: ns, ActorLimit: int64(al), Reader: reader}

	case "credential_revoke":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"cred_id"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cidBytes, err := ldrcrypto.MapBytesLen(fields, "cred_id", 32)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		var cid [32]byte
		copy(cid[:], cidBytes)
		r.Cred = CredToken(cid)

	case "key_epoch_activate":
		if err := ldrcrypto.RequireExactKeys(fields, nil); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		rawMan, err := ldrcrypto.MapArray(top, "manifest")
		if err != nil {
			return fmt.Errorf("%w: key_epoch_activate requires manifest", ErrMalformedWireIntent)
		}
		man := make([]ldrcrypto.WrapManifestEntry, 0, len(rawMan))
		r.Manifest = make([]string, 0, len(rawMan))
		for i, elem := range rawMan {
			em, ok := elem.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: manifest[%d] must be map", ErrMalformedWireIntent, i)
			}
			if err := ldrcrypto.RequireExactKeys(em, []string{"commit", "cred_id"}); err != nil {
				return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
			}
			cidBytes, err := ldrcrypto.MapBytesLen(em, "cred_id", 32)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
			}
			c, err := ldrcrypto.ParseCommitment(em["commit"])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
			}
			var cid [32]byte
			copy(cid[:], cidBytes)
			man = append(man, ldrcrypto.WrapManifestEntry{CredID: cid, Commit: c})
			r.Manifest = append(r.Manifest, CredToken(cid))
		}
		// Keep manifest entries sorted by cred_id if non-empty (duplicate/order
		// errors still rejected cleanly by VerifyWrapManifest / Apply).
		out.Manifest = man

	case "actor_declare":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"actor_id", "label", "namespace_id"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		aid, err := ldrcrypto.MapString(fields, "actor_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		ns, err := ldrcrypto.MapString(fields, "namespace_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		lbl, err := ldrcrypto.MapBool(fields, "label")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Actor = aid
		r.Namespace = ns
		r.Label = lbl

	case "actor_move":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"actor_id", "to_cred"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		aid, err := ldrcrypto.MapString(fields, "actor_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		tcBytes, err := ldrcrypto.MapBytesLen(fields, "to_cred", 32)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		var tc [32]byte
		copy(tc[:], tcBytes)
		r.Actor = aid
		r.ToCred = CredToken(tc)

	case "actor_remove":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"actor_id"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		aid, err := ldrcrypto.MapString(fields, "actor_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Actor = aid

	case "actor_addressing":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"default_addressed"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		da, err := ldrcrypto.MapBool(fields, "default_addressed")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.DefaultAddressed = da

	case "register_activate":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"actor_id", "incarnation", "register"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		aid, err := ldrcrypto.MapString(fields, "actor_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		reg, err := ldrcrypto.MapString(fields, "register")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		inc, err := ldrcrypto.MapString(fields, "incarnation")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Actor = aid
		r.Register = reg
		r.Incarnation = inc

	case "call_open":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"call_id", "to"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		to, err := ldrcrypto.MapString(fields, "to")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid
		r.To = to

	case "call_turn":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"barge", "call_id"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		barge, err := ldrcrypto.MapBool(fields, "barge")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid
		r.Barge = barge

	case "call_bye", "call_note", "call_ratify", "dispute_open":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"call_id"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid

	case "call_status":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"call_id", "state"}, "related"); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		st, err := ldrcrypto.MapString(fields, "state")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid
		r.State = st
		if _, hasRel := fields["related"]; hasRel {
			rel, err := ldrcrypto.MapString(fields, "related")
			if err != nil {
				return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
			}
			r.Related = rel
		}

	case "call_attach":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"call_id", "size_class"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		sc, err := ldrcrypto.MapString(fields, "size_class")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid
		r.SizeClass = sc
		if out.PayloadCommit.Length > prof.MaxAttachmentBytes+1024 && sc == "within_inline_limit" {
			// Enforce profile inline attachment cap on visible commitment length.
			r.SizeClass = "over_inline_limit"
		}

	case "dispute_measure", "dispute_arbitrate":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"call_id", "dispute"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		disp, err := ldrcrypto.MapString(fields, "dispute")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid
		r.Dispute = disp

	case "dispute_resolve":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"call_id", "dispute", "kind"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		cid, err := ldrcrypto.MapString(fields, "call_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		disp, err := ldrcrypto.MapString(fields, "dispute")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		kind, err := ldrcrypto.MapString(fields, "kind")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Call = cid
		r.Dispute = disp
		r.Kind = kind

	case "broadcast_create":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"broadcast_id", "default_audience", "kind", "recipients"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		bid, err := ldrcrypto.MapString(fields, "broadcast_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		da, err := ldrcrypto.MapBool(fields, "default_audience")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		kind, err := ldrcrypto.MapString(fields, "kind")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		rawRec, err := ldrcrypto.MapArray(fields, "recipients")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		recips := make([]string, len(rawRec))
		for i, x := range rawRec {
			s, ok := x.(string)
			if !ok {
				return fmt.Errorf("%w: recipients[%d] must be string", ErrMalformedWireIntent, i)
			}
			recips[i] = s
		}
		r.Broadcast = bid
		r.DefaultAudience = da
		r.Kind = kind
		r.Recipients = recips

	case "broadcast_read", "broadcast_reply":
		if err := ldrcrypto.RequireExactKeys(fields, []string{"broadcast_id"}); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		bid, err := ldrcrypto.MapString(fields, "broadcast_id")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedWireIntent, err)
		}
		r.Broadcast = bid

	default:
		return fmt.Errorf("%w: unknown op_type %q", ErrMalformedWireIntent, out.OpType)
	}
	return nil
}

// sortedStringsCopy returns a sorted defensive copy (helper for manifest/status).
func sortedStringsCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
