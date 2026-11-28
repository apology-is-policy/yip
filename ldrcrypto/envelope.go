package ldrcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
)

const (
	// Protocol and schema version constants for Profile v1.
	ProtocolVersion uint64 = 1

	// Principal role tags (LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE §2).
	PrincipalCredential = "credential"
	PrincipalOperator   = "operator"
	PrincipalRoot       = "root"

	// Relay TLS server-authentication policies (LDR-GO-RELAY-DESIGN §1.2).
	TLSPolicyPinSPKISHA256 = "pin_spki_sha256"
	TLSPolicyPinCARootPEM  = "pin_ca_root_pem"
	TLSPolicyWebPKI        = "webpki"

	// Relay session-binding modes (LDR-GO-RELAY-DESIGN §2.3).
	SessionBindingTLS13Exporter   = "tls13_exporter"
	SessionBindingWSTLS13Exporter = "ws_tls13_exporter"
	SessionBindingAppAuth         = "app_authenticated_session"

	// Distinct signing purposes for non-intent signed objects.
	PurposeDescriptorSig = "ldr.creation-descriptor.sig"
	PurposeJoinReqSig    = "ldr.join-request.sig"
	PurposeJoinProofSig  = "ldr.join-proof.sig"
	PurposeSessionAuth   = "ldr.session-auth"
	PurposeQuery         = "ldr.query"
	PurposeAnchorRequest = "ldr.anchor-request"
	PurposeRegister      = "ldr.register"
)

var (
	ErrInvalidDescriptor = errors.New("ldrcrypto: invalid creation descriptor")
	ErrInvalidEnvelope   = errors.New("ldrcrypto: invalid envelope")
	ErrInvalidCeremony   = errors.New("ldrcrypto: invalid join ceremony")
	ErrManifestMismatch  = errors.New("ldrcrypto: wrap manifest mismatch")
)

// Principal is a tagged signing principal:
//
//	["credential", cred_id_bytes]
//	["operator",   [alg, pk_bytes]]
//	["root",       [alg, pk_bytes]]
type Principal struct {
	Kind   string
	CredID [32]byte
	Key    *PublicKey
}

// CredentialPrincipal constructs a tagged credential principal.
func CredentialPrincipal(credID [32]byte) Principal {
	return Principal{Kind: PrincipalCredential, CredID: credID}
}

// OperatorPrincipal constructs a tagged operator principal.
func OperatorPrincipal(key PublicKey) Principal {
	k := key.Clone()
	return Principal{Kind: PrincipalOperator, Key: &k}
}

// RootPrincipal constructs a tagged root principal.
func RootPrincipal(key PublicKey) Principal {
	k := key.Clone()
	return Principal{Kind: PrincipalRoot, Key: &k}
}

// Validate checks p's structural and key validity.
func (p Principal) Validate() error {
	switch p.Kind {
	case PrincipalCredential:
		if p.Key != nil {
			return fmt.Errorf("%w: credential principal must not carry key", ErrInvalidEnvelope)
		}
		return nil
	case PrincipalOperator, PrincipalRoot:
		if p.Key == nil {
			return fmt.Errorf("%w: %s principal requires public key", ErrInvalidEnvelope, p.Kind)
		}
		return p.Key.ValidateSigningKey()
	default:
		return fmt.Errorf("%w: unknown principal kind %q", ErrInvalidEnvelope, p.Kind)
	}
}

// Equal reports whether p and other denote the same principal.
func (p Principal) Equal(other Principal) bool {
	if p.Kind != other.Kind {
		return false
	}
	if p.Kind == PrincipalCredential {
		return p.CredID == other.CredID
	}
	if p.Key == nil || other.Key == nil {
		return false
	}
	return p.Key.Equal(*other.Key)
}

// ToCBOR converts p into its canonical 2-element CBOR array.
func (p Principal) ToCBOR() ([]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Kind == PrincipalCredential {
		id := make([]byte, 32)
		copy(id, p.CredID[:])
		return []any{p.Kind, id}, nil
	}
	k, err := p.Key.ToCBOR()
	if err != nil {
		return nil, err
	}
	return []any{p.Kind, k}, nil
}

// ParsePrincipal decodes a tagged Principal from decoded CBOR.
func ParsePrincipal(v any) (Principal, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		return Principal{}, fmt.Errorf("%w: principal must be 2-element array", ErrInvalidEnvelope)
	}
	kind, ok := arr[0].(string)
	if !ok {
		return Principal{}, fmt.Errorf("%w: principal kind must be string", ErrInvalidEnvelope)
	}
	switch kind {
	case PrincipalCredential:
		b, ok := arr[1].([]byte)
		if !ok || len(b) != 32 {
			return Principal{}, fmt.Errorf("%w: credential id must be 32 bytes", ErrInvalidEnvelope)
		}
		var id [32]byte
		copy(id[:], b)
		return CredentialPrincipal(id), nil
	case PrincipalOperator:
		pk, err := ParsePublicKey(arr[1])
		if err != nil {
			return Principal{}, err
		}
		if err := pk.ValidateSigningKey(); err != nil {
			return Principal{}, err
		}
		return OperatorPrincipal(pk), nil
	case PrincipalRoot:
		pk, err := ParsePublicKey(arr[1])
		if err != nil {
			return Principal{}, err
		}
		if err := pk.ValidateSigningKey(); err != nil {
			return Principal{}, err
		}
		return RootPrincipal(pk), nil
	default:
		return Principal{}, fmt.Errorf("%w: unknown principal kind %q", ErrInvalidEnvelope, kind)
	}
}

// RelayOrigin pins the HTTPS relay endpoint, TLS policy, and session binding mode.
//
// For SessionBindingTLS13Exporter and SessionBindingAppAuth, only the 4 base fields
// (URL, TLSPolicy, TLSPin, SessionBinding) are permitted and encoded in CBOR.
//
// For SessionBindingWSTLS13Exporter (RFC 6455 WebSocket-tunneled inner TLS 1.3):
//   - URL pins the outer HTTPS authority and explicit WebSocket upgrade path (e.g. https://relay.example.com/v1/tunnel)
//   - OuterTLSPolicy / OuterTLSPin pin outer HTTPS verification (webpki, pin_ca_root_pem, or pin_spki_sha256);
//     outer verification NEVER authenticates the origin relay
//   - InnerServerName pins the inner TLS 1.3 SNI/SAN hostname or IP literal of the origin relay
//   - TLSPolicy / TLSPin pin the origin relay's inner TLS 1.3 identity (pin_spki_sha256 or pin_ca_root_pem ONLY;
//     webpki is strictly forbidden on the inner leg)
type RelayOrigin struct {
	URL             string
	TLSPolicy       string
	TLSPin          []byte
	SessionBinding  string
	OuterTLSPolicy  string
	OuterTLSPin     []byte
	InnerServerName string
}

// ParsePinnedCARootPEM strictly parses a pin_ca_root_pem blob, requiring
// exactly one standalone valid CA X.509 certificate PEM block with no leading
// or trailing non-whitespace bytes, no PEM headers, BasicConstraintsValid+IsCA,
// and KeyUsageCertSign (when KeyUsage is specified).
func ParsePinnedCARootPEM(pemBytes []byte) (*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(pemBytes)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: pin_ca_root_pem requires a single CA certificate PEM", ErrInvalidDescriptor)
	}
	firstLine, _, hasNL := bytes.Cut(trimmed, []byte("\n"))
	if !hasNL || !bytes.Equal(bytes.TrimSuffix(firstLine, []byte("\r")), []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, fmt.Errorf("%w: pin_ca_root_pem must contain only a single CERTIFICATE PEM block", ErrInvalidDescriptor)
	}
	if bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return nil, fmt.Errorf("%w: pin_ca_root_pem must contain exactly one CERTIFICATE PEM block", ErrInvalidDescriptor)
	}
	blk, rest := pem.Decode(trimmed)
	if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
		return nil, fmt.Errorf("%w: pin_ca_root_pem must contain a single standalone CERTIFICATE PEM block", ErrInvalidDescriptor)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: pin_ca_root_pem must not contain multiple certificates or trailing data", ErrInvalidDescriptor)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: pin_ca_root_pem invalid X.509 certificate: %v", ErrInvalidDescriptor, err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("%w: pin_ca_root_pem certificate must be a CA (BasicConstraintsValid && IsCA)", ErrInvalidDescriptor)
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: pin_ca_root_pem CA certificate missing KeyUsageCertSign", ErrInvalidDescriptor)
	}
	return cert, nil
}

func validateTLSPolicyAndPin(policy string, pin []byte, allowWebPKI bool, label string) error {
	switch policy {
	case TLSPolicyPinSPKISHA256:
		if len(pin) != 32 {
			return fmt.Errorf("%w: %s pin_spki_sha256 requires 32-byte pin", ErrInvalidDescriptor, label)
		}
		return nil
	case TLSPolicyPinCARootPEM:
		if _, err := ParsePinnedCARootPEM(pin); err != nil {
			return err
		}
		return nil
	case TLSPolicyWebPKI:
		if !allowWebPKI {
			return fmt.Errorf("%w: %s webpki is forbidden; origin identity must be pinned (pin_spki_sha256 or pin_ca_root_pem)", ErrInvalidDescriptor, label)
		}
		if len(pin) != 0 {
			return fmt.Errorf("%w: %s webpki policy must have empty pin", ErrInvalidDescriptor, label)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown %s %q", ErrInvalidDescriptor, label, policy)
	}
}

func validateInnerServerName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%w: inner_server_name must be 1..253 bytes", ErrInvalidDescriptor)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("%w: inner_server_name must not contain surrounding whitespace", ErrInvalidDescriptor)
	}
	if ip := net.ParseIP(name); ip != nil {
		return nil
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("%w: invalid inner_server_name %q", ErrInvalidDescriptor, name)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: invalid inner_server_name label %q", ErrInvalidDescriptor, label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("%w: inner_server_name must be canonical lowercase DNS name or IP literal", ErrInvalidDescriptor)
			}
		}
	}
	return nil
}

// Validate checks relay_origin syntax and policy consistency.
func (r RelayOrigin) Validate() error {
	if !strings.HasPrefix(r.URL, "https://") {
		return fmt.Errorf("%w: relay URL must use https://", ErrInvalidDescriptor)
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%w: invalid relay URL", ErrInvalidDescriptor)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: relay URL must not contain credentials, query, or fragment", ErrInvalidDescriptor)
	}
	switch r.SessionBinding {
	case SessionBindingTLS13Exporter, SessionBindingAppAuth:
		if r.OuterTLSPolicy != "" || len(r.OuterTLSPin) != 0 || r.InnerServerName != "" {
			return fmt.Errorf("%w: outer/inner tunnel fields are forbidden for session_binding %q", ErrInvalidDescriptor, r.SessionBinding)
		}
		return validateTLSPolicyAndPin(r.TLSPolicy, r.TLSPin, true, "tls_policy")

	case SessionBindingWSTLS13Exporter:
		if u.ForceQuery || u.Path == "" || !strings.HasPrefix(u.Path, "/") || u.RawPath != "" || path.Clean(u.Path) != u.Path {
			return fmt.Errorf("%w: ws_tls13_exporter URL must specify a clean canonical path (e.g. /v1/tunnel)", ErrInvalidDescriptor)
		}
		if err := validateTLSPolicyAndPin(r.TLSPolicy, r.TLSPin, false, "inner tls_policy"); err != nil {
			return err
		}
		if err := validateTLSPolicyAndPin(r.OuterTLSPolicy, r.OuterTLSPin, true, "outer_tls_policy"); err != nil {
			return err
		}
		return validateInnerServerName(r.InnerServerName)

	default:
		return fmt.Errorf("%w: unknown session_binding %q", ErrInvalidDescriptor, r.SessionBinding)
	}
}

// ToCBORMap encodes r canonically.
func (r RelayOrigin) ToCBORMap() (Map, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	pin := bytes.Clone(r.TLSPin)
	if pin == nil {
		pin = []byte{}
	}
	if r.SessionBinding == SessionBindingWSTLS13Exporter {
		outerPin := bytes.Clone(r.OuterTLSPin)
		if outerPin == nil {
			outerPin = []byte{}
		}
		return Map{
			{Key: "inner_server_name", Value: r.InnerServerName},
			{Key: "outer_tls_pin", Value: outerPin},
			{Key: "outer_tls_policy", Value: r.OuterTLSPolicy},
			{Key: "session_binding", Value: r.SessionBinding},
			{Key: "tls_pin", Value: pin},
			{Key: "tls_policy", Value: r.TLSPolicy},
			{Key: "url", Value: r.URL},
		}, nil
	}
	return Map{
		{Key: "session_binding", Value: r.SessionBinding},
		{Key: "tls_pin", Value: pin},
		{Key: "tls_policy", Value: r.TLSPolicy},
		{Key: "url", Value: r.URL},
	}, nil
}

// ParseRelayOrigin decodes and validates a RelayOrigin from CBOR.
func ParseRelayOrigin(v any) (RelayOrigin, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return RelayOrigin{}, fmt.Errorf("%w: relay_origin must be map", ErrInvalidDescriptor)
	}
	sb, err := MapString(m, "session_binding")
	if err != nil {
		return RelayOrigin{}, err
	}
	if sb == SessionBindingWSTLS13Exporter {
		if err := RequireExactKeys(m, []string{
			"inner_server_name", "outer_tls_pin", "outer_tls_policy",
			"session_binding", "tls_pin", "tls_policy", "url",
		}); err != nil {
			return RelayOrigin{}, err
		}
	} else {
		if err := RequireExactKeys(m, []string{"session_binding", "tls_pin", "tls_policy", "url"}); err != nil {
			return RelayOrigin{}, err
		}
	}
	pin, err := MapBytes(m, "tls_pin")
	if err != nil {
		return RelayOrigin{}, err
	}
	pol, err := MapString(m, "tls_policy")
	if err != nil {
		return RelayOrigin{}, err
	}
	rawURL, err := MapString(m, "url")
	if err != nil {
		return RelayOrigin{}, err
	}
	ro := RelayOrigin{URL: rawURL, TLSPolicy: pol, TLSPin: bytes.Clone(pin), SessionBinding: sb}
	if sb == SessionBindingWSTLS13Exporter {
		outerPol, err := MapString(m, "outer_tls_policy")
		if err != nil {
			return RelayOrigin{}, err
		}
		outerPin, err := MapBytes(m, "outer_tls_pin")
		if err != nil {
			return RelayOrigin{}, err
		}
		innerSN, err := MapString(m, "inner_server_name")
		if err != nil {
			return RelayOrigin{}, err
		}
		ro.OuterTLSPolicy = outerPol
		ro.OuterTLSPin = bytes.Clone(outerPin)
		ro.InnerServerName = innerSN
	}
	if err := ro.Validate(); err != nil {
		return RelayOrigin{}, err
	}
	return ro, nil
}

// Profile fixes immutable generation-scoped algorithms, bounds, and timing windows.
type Profile struct {
	Version            uint64
	HashAlg            string
	SigningAlgs        []string
	KEMAlg             string
	WrapAlg            string
	PayloadAlg         string
	FreshnessMS        uint64
	MaxValidityMS      uint64
	MaxRecordBytes     uint64
	MaxCiphertextBytes uint64
	MaxPlaintextBytes  uint64
	MaxAttachmentBytes uint64
	MaxEpochMessages   uint64
	MaxEpochAgeSeconds uint64
}

// ProfileV1 returns the operator-approved Profile v1 baseline.
func ProfileV1() Profile {
	return Profile{
		Version:            1,
		HashAlg:            "sha-256",
		SigningAlgs:        []string{AlgECDSAP256, AlgEd25519},
		KEMAlg:             AlgX25519,
		WrapAlg:            AlgHPKEWrap,
		PayloadAlg:         AlgPayloadHKDFSHA256AES256GCM,
		FreshnessMS:        10_000,
		MaxValidityMS:      600_000,
		MaxRecordBytes:     512 * 1024,
		MaxCiphertextBytes: 384 * 1024,
		MaxPlaintextBytes:  64 * 1024,
		MaxAttachmentBytes: 256 * 1024,
		MaxEpochMessages:   1 << 20,
		MaxEpochAgeSeconds: 90 * 24 * 3600,
	}
}

// Validate checks that p has valid immutable profile parameters.
func (p Profile) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("%w: unsupported profile version %d", ErrInvalidDescriptor, p.Version)
	}
	if p.HashAlg != "sha-256" {
		return fmt.Errorf("%w: unsupported hash_alg %q", ErrInvalidDescriptor, p.HashAlg)
	}
	if len(p.SigningAlgs) == 0 {
		return fmt.Errorf("%w: empty signing_algs", ErrInvalidDescriptor)
	}
	for i, alg := range p.SigningAlgs {
		if alg != AlgEd25519 && alg != AlgECDSAP256 {
			return fmt.Errorf("%w: unsupported signing alg %q", ErrInvalidDescriptor, alg)
		}
		if i > 0 && p.SigningAlgs[i-1] >= alg {
			return fmt.Errorf("%w: signing_algs must be strictly sorted and unique", ErrInvalidDescriptor)
		}
	}
	if p.KEMAlg != AlgX25519 || p.WrapAlg != AlgHPKEWrap || p.PayloadAlg != AlgPayloadHKDFSHA256AES256GCM {
		return fmt.Errorf("%w: unsupported profile crypto suite", ErrInvalidDescriptor)
	}
	if p.FreshnessMS == 0 || p.MaxValidityMS < p.FreshnessMS {
		return fmt.Errorf("%w: invalid freshness/validity bounds", ErrInvalidDescriptor)
	}
	if p.MaxRecordBytes == 0 || p.MaxCiphertextBytes > p.MaxRecordBytes || p.MaxPlaintextBytes == 0 || p.MaxAttachmentBytes == 0 {
		return fmt.Errorf("%w: invalid size limits", ErrInvalidDescriptor)
	}
	if p.MaxEpochMessages == 0 || p.MaxEpochAgeSeconds == 0 {
		return fmt.Errorf("%w: invalid epoch use limits", ErrInvalidDescriptor)
	}
	return nil
}

// ToCBORMap converts p to a canonical CBOR map.
func (p Profile) ToCBORMap() (Map, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return Map{
		{Key: "freshness_ms", Value: p.FreshnessMS},
		{Key: "hash_alg", Value: p.HashAlg},
		{Key: "kem_alg", Value: p.KEMAlg},
		{Key: "max_attachment_bytes", Value: p.MaxAttachmentBytes},
		{Key: "max_ciphertext_bytes", Value: p.MaxCiphertextBytes},
		{Key: "max_epoch_age_s", Value: p.MaxEpochAgeSeconds},
		{Key: "max_epoch_messages", Value: p.MaxEpochMessages},
		{Key: "max_plaintext_bytes", Value: p.MaxPlaintextBytes},
		{Key: "max_record_bytes", Value: p.MaxRecordBytes},
		{Key: "max_validity_ms", Value: p.MaxValidityMS},
		{Key: "payload_alg", Value: p.PayloadAlg},
		{Key: "signing_algs", Value: append([]string(nil), p.SigningAlgs...)},
		{Key: "v", Value: p.Version},
		{Key: "wrap_alg", Value: p.WrapAlg},
	}, nil
}

// ParseProfile decodes and validates a Profile from a CBOR map.
func ParseProfile(v any) (Profile, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Profile{}, fmt.Errorf("%w: profile must be map", ErrInvalidDescriptor)
	}
	req := []string{
		"freshness_ms", "hash_alg", "kem_alg",
		"max_attachment_bytes", "max_ciphertext_bytes", "max_epoch_age_s",
		"max_epoch_messages", "max_plaintext_bytes", "max_record_bytes",
		"max_validity_ms", "payload_alg", "signing_algs", "v", "wrap_alg",
	}
	if err := RequireExactKeys(m, req); err != nil {
		return Profile{}, err
	}
	var p Profile
	var err error
	if p.Version, err = MapUint(m, "v"); err != nil {
		return Profile{}, err
	}
	if p.HashAlg, err = MapString(m, "hash_alg"); err != nil {
		return Profile{}, err
	}
	if p.KEMAlg, err = MapString(m, "kem_alg"); err != nil {
		return Profile{}, err
	}
	if p.WrapAlg, err = MapString(m, "wrap_alg"); err != nil {
		return Profile{}, err
	}
	if p.PayloadAlg, err = MapString(m, "payload_alg"); err != nil {
		return Profile{}, err
	}
	if p.FreshnessMS, err = MapUint(m, "freshness_ms"); err != nil {
		return Profile{}, err
	}
	if p.MaxValidityMS, err = MapUint(m, "max_validity_ms"); err != nil {
		return Profile{}, err
	}
	if p.MaxRecordBytes, err = MapUint(m, "max_record_bytes"); err != nil {
		return Profile{}, err
	}
	if p.MaxCiphertextBytes, err = MapUint(m, "max_ciphertext_bytes"); err != nil {
		return Profile{}, err
	}
	if p.MaxPlaintextBytes, err = MapUint(m, "max_plaintext_bytes"); err != nil {
		return Profile{}, err
	}
	if p.MaxAttachmentBytes, err = MapUint(m, "max_attachment_bytes"); err != nil {
		return Profile{}, err
	}
	if p.MaxEpochMessages, err = MapUint(m, "max_epoch_messages"); err != nil {
		return Profile{}, err
	}
	if p.MaxEpochAgeSeconds, err = MapUint(m, "max_epoch_age_s"); err != nil {
		return Profile{}, err
	}
	rawAlgs, err := MapArray(m, "signing_algs")
	if err != nil {
		return Profile{}, err
	}
	p.SigningAlgs = make([]string, len(rawAlgs))
	for i, a := range rawAlgs {
		s, ok := a.(string)
		if !ok {
			return Profile{}, fmt.Errorf("%w: signing_algs[%d] must be string", ErrInvalidDescriptor, i)
		}
		p.SigningAlgs[i] = s
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// Digest returns SHA-256(Enc(["ldr.profile", 1, profile_map])).
func (p Profile) Digest() ([32]byte, error) {
	pm, err := p.ToCBORMap()
	if err != nil {
		return [32]byte{}, err
	}
	return DomainDigest(PurposeProfile, 1, pm)
}

func profileAllowsSigningAlg(p Profile, alg string) bool {
	for _, a := range p.SigningAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

// CreationDescriptor is the canonical `ldr.creation-descriptor.v1` body.
type CreationDescriptor struct {
	Version     uint64
	LineID      []byte
	Generation  uint64
	RootKeys    []PublicKey // exactly 2 distinct equal roots (threshold fixed at 1)
	RelayOrigin RelayOrigin
	Profile     Profile
}

// MarshalBody encodes the canonical creation descriptor body C (normalizing RootKeys order).
func (d CreationDescriptor) MarshalBody() ([]byte, error) {
	if d.Version != 1 {
		return nil, fmt.Errorf("%w: descriptor version must be 1", ErrInvalidDescriptor)
	}
	if len(d.LineID) < 16 || len(d.LineID) > 64 {
		return nil, fmt.Errorf("%w: line_id must be 16..64 opaque bytes", ErrInvalidDescriptor)
	}
	if d.Generation != 1 {
		return nil, fmt.Errorf("%w: creation descriptor generation must be 1", ErrInvalidDescriptor)
	}
	sortedRoots, err := CanonicalRootKeys(d.RootKeys)
	if err != nil {
		return nil, err
	}
	if err := d.Profile.Validate(); err != nil {
		return nil, err
	}
	for _, rk := range sortedRoots {
		if !profileAllowsSigningAlg(d.Profile, rk.Alg) {
			return nil, fmt.Errorf("%w: root key alg %q not enabled in profile", ErrInvalidDescriptor, rk.Alg)
		}
	}
	r0, err := sortedRoots[0].ToCBOR()
	if err != nil {
		return nil, err
	}
	r1, err := sortedRoots[1].ToCBOR()
	if err != nil {
		return nil, err
	}
	roMap, err := d.RelayOrigin.ToCBORMap()
	if err != nil {
		return nil, err
	}
	profMap, err := d.Profile.ToCBORMap()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR(Map{
		{Key: "generation", Value: d.Generation},
		{Key: "line_id", Value: bytes.Clone(d.LineID)},
		{Key: "profile", Value: profMap},
		{Key: "relay_origin", Value: roMap},
		{Key: "root_keys", Value: []any{r0, r1}},
		{Key: "root_threshold", Value: uint64(1)},
		{Key: "schema", Value: "ldr.creation-descriptor.v1"},
		{Key: "v", Value: d.Version},
	})
}

// ParseCreationDescriptorBody strictly decodes a canonical creation descriptor body C.
func ParseCreationDescriptorBody(bodyBytes []byte) (CreationDescriptor, error) {
	decoded, err := UnmarshalCBORDefault(bodyBytes)
	if err != nil {
		return CreationDescriptor{}, err
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		return CreationDescriptor{}, fmt.Errorf("%w: descriptor body must be map", ErrInvalidDescriptor)
	}
	req := []string{"generation", "line_id", "profile", "relay_origin", "root_keys", "root_threshold", "schema", "v"}
	if err := RequireExactKeys(m, req); err != nil {
		return CreationDescriptor{}, err
	}
	schema, err := MapString(m, "schema")
	if err != nil || schema != "ldr.creation-descriptor.v1" {
		return CreationDescriptor{}, fmt.Errorf("%w: unexpected descriptor schema %q", ErrInvalidDescriptor, schema)
	}
	v, err := MapUint(m, "v")
	if err != nil || v != 1 {
		return CreationDescriptor{}, fmt.Errorf("%w: unsupported descriptor version", ErrInvalidDescriptor)
	}
	gen, err := MapUint(m, "generation")
	if err != nil || gen != 1 {
		return CreationDescriptor{}, fmt.Errorf("%w: creation descriptor generation must be 1", ErrInvalidDescriptor)
	}
	thresh, err := MapUint(m, "root_threshold")
	if err != nil || thresh != 1 {
		return CreationDescriptor{}, fmt.Errorf("%w: root_threshold must be 1", ErrInvalidDescriptor)
	}
	lineID, err := MapBytes(m, "line_id")
	if err != nil || len(lineID) < 16 || len(lineID) > 64 {
		return CreationDescriptor{}, fmt.Errorf("%w: invalid line_id", ErrInvalidDescriptor)
	}
	rawRoots, err := MapArray(m, "root_keys")
	if err != nil || len(rawRoots) != 2 {
		return CreationDescriptor{}, fmt.Errorf("%w: root_keys must have 2 members", ErrInvalidDescriptor)
	}
	k0, err := ParsePublicKey(rawRoots[0])
	if err != nil {
		return CreationDescriptor{}, err
	}
	k1, err := ParsePublicKey(rawRoots[1])
	if err != nil {
		return CreationDescriptor{}, err
	}
	sorted, err := CanonicalRootKeys([]PublicKey{k0, k1})
	if err != nil {
		return CreationDescriptor{}, err
	}
	// Require canonical sorted order in the encoded descriptor body (no silent rewrite).
	if !k0.Equal(sorted[0]) || !k1.Equal(sorted[1]) {
		return CreationDescriptor{}, fmt.Errorf("%w: root_keys not in canonical sorted order", ErrCBORNonCanonical)
	}
	ro, err := ParseRelayOrigin(m["relay_origin"])
	if err != nil {
		return CreationDescriptor{}, err
	}
	prof, err := ParseProfile(m["profile"])
	if err != nil {
		return CreationDescriptor{}, err
	}
	for _, rk := range sorted {
		if !profileAllowsSigningAlg(prof, rk.Alg) {
			return CreationDescriptor{}, fmt.Errorf("%w: root key alg %q not enabled in profile", ErrInvalidDescriptor, rk.Alg)
		}
	}
	return CreationDescriptor{
		Version:     v,
		LineID:      bytes.Clone(lineID),
		Generation:  gen,
		RootKeys:    sorted,
		RelayOrigin: ro,
		Profile:     prof,
	}, nil
}

// SignedCreationDescriptor carries canonical body bytes signed by one of the two initial root keys.
type SignedCreationDescriptor struct {
	BodyBytes []byte
	SignerKey PublicKey
	Sig       []byte
}

// SignCreationDescriptor builds and signs a canonical CreationDescriptor under signer,
// which must be one of the two distinct initial root keys.
func SignCreationDescriptor(signer Signer, desc CreationDescriptor) (SignedCreationDescriptor, error) {
	if signer == nil {
		return SignedCreationDescriptor{}, ErrInvalidKey
	}
	sorted, err := CanonicalRootKeys(desc.RootKeys)
	if err != nil {
		return SignedCreationDescriptor{}, err
	}
	pub := signer.PublicKey()
	if !pub.Equal(sorted[0]) && !pub.Equal(sorted[1]) {
		return SignedCreationDescriptor{}, fmt.Errorf("%w: signer is not one of the two root_keys", ErrInvalidDescriptor)
	}
	desc.RootKeys = sorted
	body, err := desc.MarshalBody()
	if err != nil {
		return SignedCreationDescriptor{}, err
	}
	sig, err := SignDomain(signer, PurposeDescriptorSig, 1, body)
	if err != nil {
		return SignedCreationDescriptor{}, err
	}
	return SignedCreationDescriptor{
		BodyBytes: body,
		SignerKey: pub,
		Sig:       sig,
	}, nil
}

// MarshalCanonical encodes the SignedCreationDescriptor as canonical CBOR.
func (s SignedCreationDescriptor) MarshalCanonical() ([]byte, error) {
	sk, err := s.SignerKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR(Map{
		{Key: "body", Value: s.BodyBytes},
		{Key: "sig", Value: s.Sig},
		{Key: "signer", Value: sk},
		{Key: "v", Value: uint64(1)},
	})
}

// VerifyCreationDescriptor strictly decodes raw canonical CBOR, verifies the
// root signature under one of the two named initial root_keys, and returns the
// parsed descriptor, its descriptor digest CD, and its genesis anchor.
func VerifyCreationDescriptor(raw []byte) (desc CreationDescriptor, cd [32]byte, genesis [32]byte, signerKey PublicKey, err error) {
	decoded, err := UnmarshalCBORDefault(raw)
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		return desc, cd, genesis, signerKey, fmt.Errorf("%w: signed descriptor must be map", ErrInvalidDescriptor)
	}
	if err := RequireExactKeys(m, []string{"body", "sig", "signer", "v"}); err != nil {
		return desc, cd, genesis, signerKey, err
	}
	v, err := MapUint(m, "v")
	if err != nil || v != 1 {
		return desc, cd, genesis, signerKey, fmt.Errorf("%w: unsupported signed descriptor version", ErrInvalidDescriptor)
	}
	body, err := MapBytes(m, "body")
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	sig, err := MapBytes(m, "sig")
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	signerKey, err = ParsePublicKey(m["signer"])
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	desc, err = ParseCreationDescriptorBody(body)
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	if !signerKey.Equal(desc.RootKeys[0]) && !signerKey.Equal(desc.RootKeys[1]) {
		return desc, cd, genesis, signerKey, fmt.Errorf("%w: descriptor signer not in root_keys", ErrInvalidDescriptor)
	}
	if err := VerifyDomain(signerKey, PurposeDescriptorSig, 1, body, sig); err != nil {
		return desc, cd, genesis, signerKey, err
	}
	cd, err = DescriptorDigest(body)
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	genesis, err = GenesisAnchor(desc.LineID, desc.RootKeys, cd)
	if err != nil {
		return desc, cd, genesis, signerKey, err
	}
	return desc, cd, genesis, signerKey, nil
}

// Allowed expect keys (LDR-STATE-MACHINE §5.1, §5.8, A.4 V6).
var allowedExpectKeys = map[string]struct{}{
	"root_rev":      {},
	"key_epoch":     {},
	"binding_gen":   {},
	"addr_rev":      {},
	"writer_rev":    {},
	"turn_count":    {},
	"lifecycle_rev": {},
	"rev":           {},
	"measure_rev":   {},
	"audience_rev":  {},
}

// ExpectMap preserves the exact distinction between an absent expectation and
// an explicit expectation of 0 (Appendix A Q10 / P6).
type ExpectMap map[string]uint64

// ToCBORMap converts e to a canonical CBOR map, validating all keys and bounds.
func (e ExpectMap) ToCBORMap() (Map, error) {
	out := make(Map, 0, len(e))
	for k, v := range e {
		if _, ok := allowedExpectKeys[k]; !ok {
			return nil, fmt.Errorf("%w: unknown expect key %q", ErrInvalidEnvelope, k)
		}
		if v > MaxCounter {
			return nil, fmt.Errorf("%w: expect.%s=%d", ErrCBOROutOfDomain, k, v)
		}
		out = append(out, MapEntry{Key: k, Value: v})
	}
	return out, nil
}

// ParseExpectMap decodes an ExpectMap from CBOR, rejecting unknown keys and
// preserving absent vs explicit zero faithfully.
func ParseExpectMap(v any) (ExpectMap, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: expect must be CBOR map", ErrInvalidEnvelope)
	}
	out := make(ExpectMap, len(m))
	for k, rawVal := range m {
		if _, ok := allowedExpectKeys[k]; !ok {
			return nil, fmt.Errorf("%w: unknown expect key %q", ErrInvalidEnvelope, k)
		}
		n, ok := rawVal.(uint64)
		if !ok {
			return nil, fmt.Errorf("%w: expect.%s must be uint", ErrInvalidEnvelope, k)
		}
		out[k] = n
	}
	return out, nil
}

// SignedIntent is the P5 canonical signed intent envelope I containing exact
// body_bytes, alg, and signature (never embedding payload sidecar bytes).
type SignedIntent struct {
	BodyBytes []byte
	Alg       string
	Sig       []byte
	RawBytes  []byte // exact canonical wire bytes I_bytes when marshaled/unmarshaled
}

// SignIntent signs canonical bodyBytes using IntentSigningMessage (bounded SHA-512
// pre-commitment) and produces the immutable canonical SignedIntent I.
func SignIntent(signer Signer, bodyBytes []byte) (SignedIntent, error) {
	if signer == nil {
		return SignedIntent{}, ErrInvalidKey
	}
	if len(bodyBytes) == 0 {
		return SignedIntent{}, fmt.Errorf("%w: empty intent body", ErrInvalidEnvelope)
	}
	// Ensure bodyBytes itself is valid canonical CBOR before signing.
	if _, err := UnmarshalCBORDefault(bodyBytes); err != nil {
		return SignedIntent{}, fmt.Errorf("%w: body is not valid canonical CBOR: %v", ErrInvalidEnvelope, err)
	}
	pub := signer.PublicKey()
	if err := pub.ValidateSigningKey(); err != nil {
		return SignedIntent{}, err
	}
	sig, err := SignDomain(signer, PurposeIntentSignatureDigest, 1, bodyBytes)
	if err != nil {
		return SignedIntent{}, err
	}
	env := SignedIntent{
		BodyBytes: bytes.Clone(bodyBytes),
		Alg:       pub.Alg,
		Sig:       sig,
	}
	raw, err := MarshalCBOR(Map{
		{Key: "alg", Value: env.Alg},
		{Key: "body", Value: env.BodyBytes},
		{Key: "sig", Value: env.Sig},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return SignedIntent{}, err
	}
	env.RawBytes = raw
	return env, nil
}

// UnmarshalSignedIntent strictly decodes a SignedIntent envelope I from raw bytes,
// keeping RawBytes verbatim for P5 IntentDigest computation.
func UnmarshalSignedIntent(raw []byte, lim Limits) (SignedIntent, error) {
	decoded, err := UnmarshalCBOR(raw, lim)
	if err != nil {
		return SignedIntent{}, err
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		return SignedIntent{}, fmt.Errorf("%w: signed intent must be map", ErrInvalidEnvelope)
	}
	if err := RequireExactKeys(m, []string{"alg", "body", "sig", "v"}); err != nil {
		return SignedIntent{}, err
	}
	v, err := MapUint(m, "v")
	if err != nil || v != 1 {
		return SignedIntent{}, fmt.Errorf("%w: unsupported signed intent version", ErrInvalidEnvelope)
	}
	alg, err := MapString(m, "alg")
	if err != nil {
		return SignedIntent{}, err
	}
	if alg != AlgEd25519 && alg != AlgECDSAP256 {
		return SignedIntent{}, fmt.Errorf("%w: unsupported intent alg %q", ErrUnsupportedAlgorithm, alg)
	}
	body, err := MapBytes(m, "body")
	if err != nil || len(body) == 0 {
		return SignedIntent{}, fmt.Errorf("%w: empty intent body", ErrInvalidEnvelope)
	}
	// Verify nested body bytes are also strictly canonical CBOR.
	if _, err := UnmarshalCBOR(body, lim); err != nil {
		return SignedIntent{}, fmt.Errorf("%w: non-canonical intent body: %v", ErrInvalidEnvelope, err)
	}
	sig, err := MapBytes(m, "sig")
	if err != nil {
		return SignedIntent{}, err
	}
	return SignedIntent{
		BodyBytes: bytes.Clone(body),
		Alg:       alg,
		Sig:       bytes.Clone(sig),
		RawBytes:  bytes.Clone(raw),
	}, nil
}

// Verify checks that s.Alg matches pub.Alg and that s.Sig is a strictly canonical
// valid signature over IntentSigningMessage(s.BodyBytes).
func (s SignedIntent) Verify(pub PublicKey) error {
	if err := pub.ValidateSigningKey(); err != nil {
		return err
	}
	if s.Alg != pub.Alg {
		return fmt.Errorf("%w: envelope alg %q != signer key alg %q", ErrInvalidSignature, s.Alg, pub.Alg)
	}
	return VerifyDomain(pub, PurposeIntentSignatureDigest, 1, s.BodyBytes, s.Sig)
}

// Digest returns the P5 operation content digest over the exact signed envelope bytes.
func (s SignedIntent) Digest() ([32]byte, error) {
	if len(s.RawBytes) == 0 {
		return [32]byte{}, fmt.Errorf("%w: SignedIntent missing RawBytes", ErrInvalidEnvelope)
	}
	return IntentDigest(s.RawBytes)
}

// WrapManifestEntry pairs an entitled reader's cred_id with its wrap sidecar commitment.
type WrapManifestEntry struct {
	CredID [32]byte
	Commit Commitment
}

// ReaderSetDigest computes the deterministic digest of the sorted entitled reader cred_ids.
func ReaderSetDigest(credIDs [][32]byte) ([32]byte, error) {
	if len(credIDs) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty reader set", ErrManifestMismatch)
	}
	cp := make([][]byte, len(credIDs))
	for i, id := range credIDs {
		b := make([]byte, 32)
		copy(b, id[:])
		cp[i] = b
	}
	sort.Slice(cp, func(i, j int) bool { return bytes.Compare(cp[i], cp[j]) < 0 })
	for i := 1; i < len(cp); i++ {
		if bytes.Equal(cp[i-1], cp[i]) {
			return [32]byte{}, fmt.Errorf("%w: duplicate cred_id in reader set", ErrManifestMismatch)
		}
	}
	arr := make([]any, len(cp))
	for i, b := range cp {
		arr[i] = b
	}
	return DomainDigest(PurposeEpochReaderSet, 1, arr)
}

// VerifyWrapManifest verifies that manifest is strictly sorted by cred_id, non-empty,
// contains no duplicates, and that sidecars supplies the exact committed bytes for
// every entry (with no missing or extraneous sidecars).
func VerifyWrapManifest(manifest []WrapManifestEntry, sidecars map[[32]byte][]byte) error {
	if len(manifest) == 0 {
		return fmt.Errorf("%w: empty wrap manifest", ErrManifestMismatch)
	}
	if len(sidecars) != len(manifest) {
		return fmt.Errorf("%w: sidecar count %d != manifest count %d", ErrManifestMismatch, len(sidecars), len(manifest))
	}
	for i, ent := range manifest {
		if i > 0 {
			cmp := bytes.Compare(manifest[i-1].CredID[:], ent.CredID[:])
			if cmp == 0 {
				return fmt.Errorf("%w: duplicate cred_id in manifest", ErrManifestMismatch)
			}
			if cmp > 0 {
				return fmt.Errorf("%w: manifest not sorted by cred_id", ErrManifestMismatch)
			}
		}
		raw, ok := sidecars[ent.CredID]
		if !ok {
			return fmt.Errorf("%w: missing wrap sidecar for cred_id %x", ErrManifestMismatch, ent.CredID[:8])
		}
		if err := VerifyWrapSidecar(ent.Commit, raw); err != nil {
			return err
		}
	}
	return nil
}

// --- P3 Key-First Enrollment Ceremony ---

// JoinGrant specifies the exact namespace, capacity, reader flag, and capabilities requested.
type JoinGrant struct {
	NamespaceID  string
	ActorLimit   uint64
	Reader       bool
	Capabilities []string
}

// Validate checks grant structure and requires strictly sorted unique capabilities.
func (g JoinGrant) Validate() error {
	if g.NamespaceID == "" {
		return fmt.Errorf("%w: empty namespace_id", ErrInvalidCeremony)
	}
	if g.ActorLimit > MaxCounter {
		return ErrCBOROutOfDomain
	}
	for i, capStr := range g.Capabilities {
		if capStr == "" {
			return fmt.Errorf("%w: empty capability", ErrInvalidCeremony)
		}
		if i > 0 && g.Capabilities[i-1] >= capStr {
			return fmt.Errorf("%w: capabilities must be sorted and unique", ErrInvalidCeremony)
		}
	}
	return nil
}

func (g JoinGrant) toCBORMap() (Map, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	caps := append([]string(nil), g.Capabilities...)
	if caps == nil {
		caps = []string{}
	}
	return Map{
		{Key: "actor_limit", Value: g.ActorLimit},
		{Key: "capabilities", Value: caps},
		{Key: "namespace_id", Value: g.NamespaceID},
		{Key: "reader", Value: g.Reader},
	}, nil
}

// JoinRequest is the joiner-signed P3 enrollment request.
type JoinRequest struct {
	RequestID        []byte
	LineID           []byte
	Generation       uint64
	DescriptorDigest [32]byte
	SigningKey       PublicKey
	EncryptionKey    PublicKey
	CredID           [32]byte
	Grant            JoinGrant
	ContextSeq       uint64
	ContextAuthEpoch uint64
	ContextKeyEpoch  uint64
	BodyBytes        []byte
	Sig              []byte
}

func (r JoinRequest) canonicalBody() ([]byte, error) {
	if len(r.RequestID) < 16 || len(r.RequestID) > 64 {
		return nil, fmt.Errorf("%w: request_id must be 16..64 bytes", ErrInvalidCeremony)
	}
	if len(r.LineID) < 16 || len(r.LineID) > 64 {
		return nil, fmt.Errorf("%w: line_id must be 16..64 bytes", ErrInvalidCeremony)
	}
	if r.Generation == 0 {
		return nil, fmt.Errorf("%w: generation must be >= 1", ErrInvalidCeremony)
	}
	derived, err := DeriveCredID(r.SigningKey, r.EncryptionKey)
	if err != nil {
		return nil, err
	}
	if derived != r.CredID {
		return nil, fmt.Errorf("%w: cred_id does not match signing/encryption keys", ErrInvalidCeremony)
	}
	sk, err := r.SigningKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	ek, err := r.EncryptionKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	gm, err := r.Grant.toCBORMap()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR(Map{
		{Key: "context_auth_epoch", Value: r.ContextAuthEpoch},
		{Key: "context_key_epoch", Value: r.ContextKeyEpoch},
		{Key: "context_seq", Value: r.ContextSeq},
		{Key: "cred_id", Value: bytes.Clone(r.CredID[:])},
		{Key: "descriptor_digest", Value: bytes.Clone(r.DescriptorDigest[:])},
		{Key: "encryption_key", Value: ek},
		{Key: "generation", Value: r.Generation},
		{Key: "grant", Value: gm},
		{Key: "line_id", Value: bytes.Clone(r.LineID)},
		{Key: "request_id", Value: bytes.Clone(r.RequestID)},
		{Key: "signing_key", Value: sk},
		{Key: "v", Value: uint64(1)},
	})
}

// SignJoinRequest derives CredID, builds canonical BodyBytes, and signs the P3 JoinRequest.
func SignJoinRequest(joinerSig Signer, req JoinRequest) (JoinRequest, error) {
	if joinerSig == nil {
		return JoinRequest{}, ErrInvalidKey
	}
	req.SigningKey = joinerSig.PublicKey()
	derived, err := DeriveCredID(req.SigningKey, req.EncryptionKey)
	if err != nil {
		return JoinRequest{}, err
	}
	req.CredID = derived
	body, err := req.canonicalBody()
	if err != nil {
		return JoinRequest{}, err
	}
	sig, err := SignDomain(joinerSig, PurposeJoinReqSig, 1, body)
	if err != nil {
		return JoinRequest{}, err
	}
	req.BodyBytes = body
	req.Sig = sig
	return req, nil
}

// VerifyJoinRequest checks cred_id derivation, exact canonical body match, and joiner signature.
func VerifyJoinRequest(req JoinRequest) ([32]byte, error) {
	var zero [32]byte
	expectedBody, err := req.canonicalBody()
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(req.BodyBytes, expectedBody) {
		return zero, fmt.Errorf("%w: join request body mismatch", ErrInvalidCeremony)
	}
	if err := VerifyDomain(req.SigningKey, PurposeJoinReqSig, 1, req.BodyBytes, req.Sig); err != nil {
		return zero, err
	}
	return DomainDigest(PurposeJoinRequest, 1, req.BodyBytes, req.Sig)
}

// JoinChallenge is the operator's HPKE-encrypted possession challenge for the joiner's encryption key.
type JoinChallenge struct {
	ChallengeID   []byte
	LineID        []byte
	Generation    uint64
	RequestID     []byte
	RequestDigest [32]byte
	OperatorKey   PublicKey
	SigningKey    PublicKey
	EncryptionKey PublicKey
	Enc           []byte
	Ciphertext    []byte
}

func joinChallengeContext(lineID []byte, gen uint64, reqID []byte, reqDigest [32]byte, opKey, sigKey, encKey PublicKey, challengeID []byte) ([]byte, error) {
	if len(challengeID) < 16 || len(challengeID) > 64 {
		return nil, fmt.Errorf("%w: challenge_id must be 16..64 bytes", ErrInvalidCeremony)
	}
	if err := opKey.ValidateSigningKey(); err != nil {
		return nil, err
	}
	if err := sigKey.ValidateSigningKey(); err != nil {
		return nil, err
	}
	if err := encKey.ValidateEncryptionKey(); err != nil {
		return nil, err
	}
	opCBOR, err := opKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	sigCBOR, err := sigKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	encCBOR, err := encKey.ToCBOR()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR([]any{
		PurposeJoinChallenge,
		uint64(1),
		lineID,
		gen,
		reqID,
		reqDigest[:],
		opCBOR,
		sigCBOR,
		encCBOR,
		challengeID,
	})
}

// JoinChallengeSecretSize is the fixed 32-byte length of the P3 challenge secret.
const JoinChallengeSecretSize = 32

// CreateJoinChallenge verifies req, draws a fresh 32-byte secret and 16-byte challenge ID,
// and HPKE-encrypts the secret to req.EncryptionKey bound to the complete P3 ceremony context.
// The raw secret is returned to the operator caller to retain locally and never placed in the challenge.
func CreateJoinChallenge(operatorKey PublicKey, req JoinRequest) (challenge JoinChallenge, secret []byte, err error) {
	reqDigest, err := VerifyJoinRequest(req)
	if err != nil {
		return JoinChallenge{}, nil, err
	}
	challengeID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, challengeID); err != nil {
		return JoinChallenge{}, nil, err
	}
	secret = make([]byte, JoinChallengeSecretSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return JoinChallenge{}, nil, err
	}
	ctxBytes, err := joinChallengeContext(req.LineID, req.Generation, req.RequestID, reqDigest, operatorKey, req.SigningKey, req.EncryptionKey, challengeID)
	if err != nil {
		return JoinChallenge{}, nil, err
	}
	enc, ct, err := HPKESealBase(req.EncryptionKey, ctxBytes, ctxBytes, secret)
	if err != nil {
		return JoinChallenge{}, nil, err
	}
	challenge = JoinChallenge{
		ChallengeID:   challengeID,
		LineID:        bytes.Clone(req.LineID),
		Generation:    req.Generation,
		RequestID:     bytes.Clone(req.RequestID),
		RequestDigest: reqDigest,
		OperatorKey:   operatorKey.Clone(),
		SigningKey:    req.SigningKey.Clone(),
		EncryptionKey: req.EncryptionKey.Clone(),
		Enc:           enc,
		Ciphertext:    ct,
	}
	return challenge, secret, nil
}

// JoinProof proves possession of both the joiner's encryption key (via secret commitment)
// and signing key (via strict signature over the full ceremony transcript).
type JoinProof struct {
	ChallengeID   []byte
	RequestDigest [32]byte
	SecretCommit  [32]byte
	Sig           []byte
}

func joinProofTranscript(ctxBytes []byte, secretCommit [32]byte) ([]byte, error) {
	return MarshalCBOR(Map{
		{Key: "context", Value: ctxBytes},
		{Key: "secret_commit", Value: secretCommit[:]},
		{Key: "v", Value: uint64(1)},
	})
}

// RespondJoinChallenge decrypts the operator's HPKE challenge using joinerEncPriv,
// computes a domain-separated commitment to the decrypted secret, and signs the
// full ceremony transcript with joinerSig.
func RespondJoinChallenge(joinerSig Signer, joinerEncPriv *X25519PrivateKey, expectedOpKey PublicKey, req JoinRequest, ch JoinChallenge) (JoinProof, error) {
	if joinerSig == nil || joinerEncPriv == nil {
		return JoinProof{}, ErrInvalidKey
	}
	reqDigest, err := VerifyJoinRequest(req)
	if err != nil {
		return JoinProof{}, err
	}
	if !joinerSig.PublicKey().Equal(req.SigningKey) || !joinerEncPriv.PublicKey().Equal(req.EncryptionKey) {
		return JoinProof{}, fmt.Errorf("%w: joiner keys do not match join request", ErrInvalidCeremony)
	}
	if !bytes.Equal(ch.LineID, req.LineID) || ch.Generation != req.Generation ||
		!bytes.Equal(ch.RequestID, req.RequestID) || ch.RequestDigest != reqDigest ||
		!ch.OperatorKey.Equal(expectedOpKey) ||
		!ch.SigningKey.Equal(req.SigningKey) || !ch.EncryptionKey.Equal(req.EncryptionKey) {
		return JoinProof{}, fmt.Errorf("%w: challenge context mismatch", ErrInvalidCeremony)
	}
	ctxBytes, err := joinChallengeContext(req.LineID, req.Generation, req.RequestID, reqDigest, expectedOpKey, req.SigningKey, req.EncryptionKey, ch.ChallengeID)
	if err != nil {
		return JoinProof{}, err
	}
	if len(ch.Ciphertext) != JoinChallengeSecretSize+PayloadTagSize {
		return JoinProof{}, fmt.Errorf("%w: challenge ciphertext length %d != %d", ErrInvalidCeremony, len(ch.Ciphertext), JoinChallengeSecretSize+PayloadTagSize)
	}
	secret, err := HPKEOpenBase(joinerEncPriv, ch.Enc, ctxBytes, ctxBytes, ch.Ciphertext)
	if err != nil {
		return JoinProof{}, err
	}
	if len(secret) != JoinChallengeSecretSize {
		return JoinProof{}, fmt.Errorf("%w: decrypted challenge secret length %d != %d", ErrInvalidCeremony, len(secret), JoinChallengeSecretSize)
	}
	secretCommit, err := DomainDigest(PurposeJoinProofSecret, 1, ctxBytes, secret)
	if err != nil {
		return JoinProof{}, err
	}
	transcript, err := joinProofTranscript(ctxBytes, secretCommit)
	if err != nil {
		return JoinProof{}, err
	}
	sig, err := SignDomain(joinerSig, PurposeJoinProofSig, 1, transcript)
	if err != nil {
		return JoinProof{}, err
	}
	return JoinProof{
		ChallengeID:   bytes.Clone(ch.ChallengeID),
		RequestDigest: reqDigest,
		SecretCommit:  secretCommit,
		Sig:           sig,
	}, nil
}

// VerifyJoinProof checks all P3 ceremony bindings against the operator's saved
// request, challenge, and independently generated secret.
func VerifyJoinProof(operatorKey PublicKey, req JoinRequest, ch JoinChallenge, expectedSecret []byte, proof JoinProof) error {
	if len(expectedSecret) != JoinChallengeSecretSize {
		return fmt.Errorf("%w: invalid expected secret length", ErrInvalidCeremony)
	}
	reqDigest, err := VerifyJoinRequest(req)
	if err != nil {
		return err
	}
	if !bytes.Equal(ch.LineID, req.LineID) || ch.Generation != req.Generation ||
		!bytes.Equal(ch.RequestID, req.RequestID) || ch.RequestDigest != reqDigest ||
		!ch.OperatorKey.Equal(operatorKey) ||
		!ch.SigningKey.Equal(req.SigningKey) || !ch.EncryptionKey.Equal(req.EncryptionKey) {
		return fmt.Errorf("%w: challenge does not match join request", ErrInvalidCeremony)
	}
	if !bytes.Equal(proof.ChallengeID, ch.ChallengeID) || proof.RequestDigest != reqDigest {
		return fmt.Errorf("%w: proof does not match challenge/request", ErrInvalidCeremony)
	}
	ctxBytes, err := joinChallengeContext(req.LineID, req.Generation, req.RequestID, reqDigest, operatorKey, req.SigningKey, req.EncryptionKey, ch.ChallengeID)
	if err != nil {
		return err
	}
	wantCommit, err := DomainDigest(PurposeJoinProofSecret, 1, ctxBytes, expectedSecret)
	if err != nil {
		return err
	}
	if proof.SecretCommit != wantCommit {
		return fmt.Errorf("%w: decrypted challenge secret commitment mismatch", ErrInvalidCeremony)
	}
	transcript, err := joinProofTranscript(ctxBytes, proof.SecretCommit)
	if err != nil {
		return err
	}
	return VerifyDomain(req.SigningKey, PurposeJoinProofSig, 1, transcript, proof.Sig)
}

// --- P7 Authenticated Session / Query / Anchor-Request Signing ---

// SessionAuthMessage builds the canonical body signed to bind a session challenge
// to a TLS 1.3 channel binding value (RFC 9266) or app session token.
type SessionAuthMessage struct {
	ProfileDigest  [32]byte
	LineID         []byte
	Generation     uint64
	Principal      Principal
	RelayOrigin    RelayOrigin
	SessionID      []byte
	ServerNonce    []byte
	ChannelBinding []byte
}

func (m SessionAuthMessage) canonicalBytes() ([]byte, error) {
	if len(m.LineID) == 0 || len(m.SessionID) == 0 || len(m.ServerNonce) != 32 || len(m.ChannelBinding) != 32 {
		return nil, fmt.Errorf("%w: invalid session auth fields", ErrInvalidEnvelope)
	}
	pCBOR, err := m.Principal.ToCBOR()
	if err != nil {
		return nil, err
	}
	roMap, err := m.RelayOrigin.ToCBORMap()
	if err != nil {
		return nil, err
	}
	return MarshalCBOR(Map{
		{Key: "channel_binding", Value: m.ChannelBinding},
		{Key: "generation", Value: m.Generation},
		{Key: "line_id", Value: m.LineID},
		{Key: "principal", Value: pCBOR},
		{Key: "profile_digest", Value: m.ProfileDigest[:]},
		{Key: "relay_origin", Value: roMap},
		{Key: "server_nonce", Value: m.ServerNonce},
		{Key: "session_id", Value: m.SessionID},
		{Key: "v", Value: uint64(1)},
	})
}

// SignSessionAuth signs a P7 session challenge proof.
func SignSessionAuth(signer Signer, m SessionAuthMessage) ([]byte, error) {
	body, err := m.canonicalBytes()
	if err != nil {
		return nil, err
	}
	return SignDomain(signer, PurposeSessionAuth, 1, body)
}

// VerifySessionAuth verifies a P7 session challenge proof under pub.
func VerifySessionAuth(pub PublicKey, m SessionAuthMessage, sig []byte) error {
	body, err := m.canonicalBytes()
	if err != nil {
		return err
	}
	return VerifyDomain(pub, PurposeSessionAuth, 1, body, sig)
}

// SessionRequestMessage binds a query or anchor_request to an active session.
type SessionRequestMessage struct {
	LineID         []byte
	Generation     uint64
	SessionID      []byte
	ChannelBinding []byte
	ReqID          uint64
	Principal      Principal
	Body           Map
}

func (m SessionRequestMessage) canonicalBytes() ([]byte, error) {
	if len(m.LineID) == 0 || len(m.SessionID) == 0 || len(m.ChannelBinding) != 32 || m.ReqID == 0 {
		return nil, fmt.Errorf("%w: invalid session request fields", ErrInvalidEnvelope)
	}
	pCBOR, err := m.Principal.ToCBOR()
	if err != nil {
		return nil, err
	}
	body := m.Body
	if body == nil {
		body = Map{}
	}
	return MarshalCBOR(Map{
		{Key: "body", Value: body},
		{Key: "channel_binding", Value: m.ChannelBinding},
		{Key: "generation", Value: m.Generation},
		{Key: "line_id", Value: m.LineID},
		{Key: "principal", Value: pCBOR},
		{Key: "req_id", Value: m.ReqID},
		{Key: "session_id", Value: m.SessionID},
		{Key: "v", Value: uint64(1)},
	})
}

// SignSessionRequest signs a P7 query (PurposeQuery) or anchor request (PurposeAnchorRequest).
func SignSessionRequest(signer Signer, purpose string, m SessionRequestMessage) ([]byte, error) {
	if purpose != PurposeQuery && purpose != PurposeAnchorRequest {
		return nil, fmt.Errorf("%w: invalid session request purpose %q", ErrInvalidEnvelope, purpose)
	}
	body, err := m.canonicalBytes()
	if err != nil {
		return nil, err
	}
	return SignDomain(signer, purpose, 1, body)
}

// VerifySessionRequest verifies a P7 query or anchor request signature under pub.
func VerifySessionRequest(pub PublicKey, purpose string, m SessionRequestMessage, sig []byte) error {
	if purpose != PurposeQuery && purpose != PurposeAnchorRequest {
		return fmt.Errorf("%w: invalid session request purpose %q", ErrInvalidEnvelope, purpose)
	}
	body, err := m.canonicalBytes()
	if err != nil {
		return err
	}
	return VerifyDomain(pub, purpose, 1, body, sig)
}
