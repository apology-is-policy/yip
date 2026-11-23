package ldrcore

// Record is the sequencer-visible part of one record, in the semantic field
// names the conformance vectors use. Payloads, signatures and wraps are not
// modelled: a Record reaches Apply only after decode, signature verification
// and admission have passed (stages 1 to 4 of the spec), or, for a
// sequencer-origin record, over its typed verification path.
type Record struct {
	Origin string `json:"origin"`
	Type   string `json:"type"`

	// Signer. For actor and credential origin, Cred signs; for actor origin
	// it signs on behalf of Actor at BindingGen. For operator origin,
	// Operator signs. On credential_enroll and credential_revoke, Cred is the
	// target, and on credential-origin and actor_move records Actor is the
	// target.
	Cred       string `json:"cred,omitempty"`
	Actor      string `json:"actor,omitempty"`
	BindingGen int64  `json:"binding_gen,omitempty"`
	Operator   string `json:"operator,omitempty"`

	AuthEpoch  int64 `json:"auth_epoch"`
	KeyEpoch   int64 `json:"key_epoch"`
	ValidityMS int64 `json:"validity_ms,omitempty"`

	Expect Expect `json:"expect"`

	// A type declared ciphertext-free that nevertheless carries line-scope
	// ciphertext is syntactically invalid.
	UnexpectedLineCiphertext bool `json:"unexpected_line_ciphertext,omitempty"`

	// Calls.
	Call      string `json:"call,omitempty"`
	To        string `json:"to,omitempty"`
	Barge     bool   `json:"barge,omitempty"`
	State     string `json:"state,omitempty"`
	Related   string `json:"related,omitempty"`
	SizeClass string `json:"size_class,omitempty"`
	Dispute   string `json:"dispute,omitempty"`
	Kind      string `json:"kind,omitempty"`

	// Broadcasts.
	Broadcast       string   `json:"broadcast,omitempty"`
	Recipients      []string `json:"recipients,omitempty"`
	DefaultAudience bool     `json:"default_audience,omitempty"`

	// Identity and membership.
	Namespace        string   `json:"namespace,omitempty"`
	Label            bool     `json:"label,omitempty"`
	DefaultAddressed bool     `json:"default_addressed,omitempty"`
	ToCred           string   `json:"to_cred,omitempty"`
	Grant            *Grant   `json:"grant,omitempty"`
	Manifest         []string `json:"manifest,omitempty"`
	OperatorKey      string   `json:"operator_key,omitempty"`

	// Enrollment. JoinRequest is the join request's identifier and
	// JoinRequestDigest the digest of the request the joiner signed; the
	// sequencer reserves the first and only carries the second. SigningKey
	// and EncryptionKey are the credential's two public keys, as opaque
	// strings: each stands for an algorithm identifier and that algorithm's
	// one accepted public encoding.
	JoinRequest       string `json:"join_request,omitempty"`
	JoinRequestDigest string `json:"join_request_digest,omitempty"`
	SigningKey        string `json:"signing_key,omitempty"`
	EncryptionKey     string `json:"encryption_key,omitempty"`
	// CredIDMismatch says that Cred is not the derivation of the two keys.
	// The derivation is a hash, and this package computes none: like a
	// signature, the fact is stated instead of checked. It is a premise of
	// the model and never a field on the wire. An implementation computes
	// the derivation and takes no sender's word for it.
	CredIDMismatch bool `json:"cred_id_mismatch,omitempty"`

	// RootKey is the root public key a line_init names.
	RootKey string `json:"root_key,omitempty"`

	// Registers.
	Register    string `json:"register,omitempty"`
	Incarnation string `json:"incarnation,omitempty"`
}

// Clone returns a deep copy: no pointer or slice in the result is shared
// with r.
func (r Record) Clone() Record {
	out := r
	out.Recipients = append([]string(nil), r.Recipients...)
	out.Manifest = append([]string(nil), r.Manifest...)
	if r.Recipients == nil {
		out.Recipients = nil
	}
	if r.Manifest == nil {
		out.Manifest = nil
	}
	if r.Grant != nil {
		g := *r.Grant
		out.Grant = &g
	}
	out.Expect = r.Expect.clone()
	return out
}

func (e Expect) clone() Expect {
	dup := func(p *int64) *int64 {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	return Expect{
		TurnCount: dup(e.TurnCount), LifecycleRev: dup(e.LifecycleRev), MeasureRev: dup(e.MeasureRev),
		Rev: dup(e.Rev), AddrRev: dup(e.AddrRev), BindingGen: dup(e.BindingGen), AudienceRev: dup(e.AudienceRev),
		KeyEpoch: dup(e.KeyEpoch), WriterRev: dup(e.WriterRev), RootRev: dup(e.RootRev),
	}
}

// Grant is what enrollment gives a credential.
type Grant struct {
	Namespace  string `json:"namespace"`
	ActorLimit int64  `json:"actor_limit"`
	Reader     bool   `json:"reader"`
}

// Expect holds the object versions the signer acted on. A nil field means the
// signer did not state it; a record type that requires one treats its absence
// as syntactically invalid.
type Expect struct {
	TurnCount    *int64 `json:"turn_count,omitempty"`
	LifecycleRev *int64 `json:"lifecycle_rev,omitempty"`
	MeasureRev   *int64 `json:"measure_rev,omitempty"`
	Rev          *int64 `json:"rev,omitempty"`
	AddrRev      *int64 `json:"addr_rev,omitempty"`
	BindingGen   *int64 `json:"binding_gen,omitempty"`
	AudienceRev  *int64 `json:"audience_rev,omitempty"`
	KeyEpoch     *int64 `json:"key_epoch,omitempty"`
	WriterRev    *int64 `json:"writer_rev,omitempty"`
	RootRev      *int64 `json:"root_rev,omitempty"`
}

// Profile is the protocol profile of one generation. Its values are fixed for
// the generation; the numbers in the vectors file are provisional policy
// candidates, not measured thresholds.
type Profile struct {
	FreshnessMS   int64
	ValidityMaxMS int64
	// StateCommit makes every chain frame commit to the state its record
	// produced (commit.go). It is an exploration of one possible answer to an
	// open question, how a new member comes by its starting state (spec
	// section 13, O25), and nobody has chosen it. With the field unset the
	// chain is exactly what it was.
	StateCommit bool
}

// Outcome kinds.
const (
	Committed = "committed"
	Rejected  = "rejected"
	Noop      = "noop"
	// Violation is a sequencer-assigned value that no honest sequencer
	// produces. A replaying client stops and reports it. It is evidence
	// against the sequencer, not a rejection of the intent a record carries.
	Violation = "violation"
)

// Outcome is the result of applying one record.
type Outcome struct {
	Kind   string
	Reason string // set when Kind is Rejected
	// RefSeq names the record that already established the state, when Kind
	// is Noop and the state records which one it was. Zero means the state
	// does not record it.
	RefSeq int64
}

// Record origins.
const (
	OriginActor      = "actor"
	OriginCredential = "credential"
	OriginOperator   = "operator"
	OriginRoot       = "root"
	OriginSequencer  = "sequencer"
)

// recordOrigin is the one origin each phase-1 record type may have.
// recovery_generation is absent on purpose: its effect is a rebuild from a
// base, which is not a transition of this function.
var recordOrigin = map[string]string{
	"line_init":              OriginRoot,
	"operator_key_authorize": OriginRoot,
	"operator_key_revoke":    OriginRoot,
	"credential_enroll":      OriginOperator,
	"credential_revoke":      OriginOperator,
	"key_epoch_activate":     OriginOperator,
	"actor_declare":          OriginCredential,
	"actor_move":             OriginOperator,
	"actor_remove":           OriginCredential,
	"actor_addressing":       OriginActor,
	"register_activate":      OriginCredential,
	"call_open":              OriginActor,
	"call_turn":              OriginActor,
	"call_bye":               OriginActor,
	"call_status":            OriginActor,
	"call_note":              OriginActor,
	"call_ratify":            OriginOperator,
	"call_attach":            OriginActor,
	"dispute_open":           OriginActor,
	"dispute_measure":        OriginActor,
	"dispute_resolve":        OriginActor,
	"dispute_arbitrate":      OriginOperator,
	"broadcast_create":       OriginOperator,
	"broadcast_read":         OriginActor,
	"broadcast_reply":        OriginActor,
	"time_anchor":            OriginSequencer,
}

// payloadBearing lists the types that always carry line-scope ciphertext
// (spec section 6.3). actor_declare carries it only when it has a label.
var payloadBearing = map[string]bool{
	"call_open":         true,
	"call_turn":         true,
	"call_status":       true,
	"call_note":         true,
	"call_ratify":       true,
	"call_attach":       true,
	"dispute_open":      true,
	"dispute_measure":   true,
	"dispute_resolve":   true,
	"dispute_arbitrate": true,
	"broadcast_create":  true,
	"broadcast_reply":   true,
}

func (r *Record) carriesLineCiphertext() bool {
	return payloadBearing[r.Type] || (r.Type == "actor_declare" && r.Label)
}

var (
	lifecycleStates = map[string]bool{"open": true, "resolved": true, "deferred": true, "archived": true, "linked": true}
	broadcastKinds  = map[string]bool{"announcement": true, "regroup": true, "briefing": true}
	registerTypes   = map[string]bool{"presence": true, "roadmap": true, "resource": true}
	sizeClasses     = map[string]bool{"within_inline_limit": true, "over_inline_limit": true}
)
