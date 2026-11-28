package ldrcore

import (
	"maps"
	"slices"
)

// MaxCounter bounds every counter, sequence number and time in a State. It is
// 2^53-1, the safe-integer limit for a consumer that reads numbers as 64-bit
// binary floating point. That is an interoperability bound for such
// consumers, not a guarantee about every JSON implementation: a wire decoder
// must still reject fractions and out-of-domain values before any lossy
// conversion, and this package has no wire decoder. A counter never wraps: a
// record that would push one past MaxCounter is rejected as exhausted and
// changes nothing.
const MaxCounter int64 = 1<<53 - 1

// State is the semantic state the transition function reads and writes:
// sections 6.1, 7.1 and 8 of docs/LDR-STATE-MACHINE.md. Field names are the
// stable semantic names the conformance vectors use. They are not wire names.
type State struct {
	Line       Line                  `json:"line"`
	Calls      map[string]*Call      `json:"calls"`
	Broadcasts map[string]*Broadcast `json:"broadcasts"`
}

// Line is membership, key and identity state. Generation 0 means no line
// exists yet: only line_init can commit against it.
type Line struct {
	Generation int64 `json:"generation"`
	HeadSeq    int64 `json:"head_seq"`
	HeadTime   int64 `json:"head_time"`
	// RootKeys is the line's active equal 1-of-2 root public key set, initially
	// fixed by line_init and updated only by root_member_replace. Like every
	// key in a State each entry is an opaque string standing for an algorithm
	// identifier and that algorithm's one accepted public encoding.
	RootKeys        []string                   `json:"root_keys"`
	RootRev         int64                      `json:"root_rev"`
	AuthEpoch       int64                      `json:"auth_epoch"`
	AudienceRev     int64                      `json:"audience_rev"`
	KeyEpoch        int64                      `json:"key_epoch"`
	RekeyPending    bool                       `json:"rekey_pending"`
	CallCount       int64                      `json:"call_count"`
	Operators       []string                   `json:"operators"`
	Credentials     map[string]*Credential     `json:"credentials"`
	Readers         map[int64][]string         `json:"readers"`
	Tombstones      Tombstones                 `json:"tombstones"`
	Actors          map[string]*Actor          `json:"actors"`
	RegisterWriters map[string]*RegisterWriter `json:"register_writers"`
}

// Credential is an enrolled isolation domain, its two public keys and its
// grants. The credential's identifier is derived from the two keys, and
// neither key is ever replaced. In phase 1 a namespace has exactly one
// declaration owner. A revoked credential keeps its entry for good: the entry
// is what reserves its keys and its namespace.
type Credential struct {
	SigningKey    string `json:"signing_key"`
	EncryptionKey string `json:"encryption_key"`
	Namespace     string `json:"namespace"`
	ActorLimit    int64  `json:"actor_limit"`
	Reader        bool   `json:"reader"`
	Revoked       bool   `json:"revoked"`
}

// Tombstones are identifiers that must never be used again. OperatorKeys
// holds every operator key that was authorized and then revoked, and RootKeys
// holds every root key that was active and then replaced: each is what tells a
// revoked or replaced key from one that never held the role. Calls and
// Broadcasts hold identifiers created in a discarded recovery tail so they
// cannot collide with new objects in a later generation.
type Tombstones struct {
	Creds        []string `json:"creds"`
	Actors       []string `json:"actors"`
	JoinRequests []string `json:"join_requests"`
	OperatorKeys []string `json:"operator_keys"`
	RootKeys     []string `json:"root_keys"`
	Calls        []string `json:"calls"`
	Broadcasts   []string `json:"broadcasts"`
}

// Actor is an immutable identity inside one namespace, bound to one
// credential at a time.
type Actor struct {
	Namespace        string `json:"namespace"`
	Cred             string `json:"cred"`
	BindingGen       int64  `json:"binding_gen"`
	AddrRev          int64  `json:"addr_rev"`
	DefaultAddressed bool   `json:"default_addressed"`
	Live             bool   `json:"live"`
}

// RegisterWriter is the activation state of one advisory register of one
// actor. BindingGen is the binding generation that made the activation.
type RegisterWriter struct {
	WriterRev   int64    `json:"writer_rev"`
	Incarnation string   `json:"incarnation"`
	BindingGen  int64    `json:"binding_gen"`
	Used        []string `json:"used"`
}

// Call is a two-party conversation. Floor and status are derived, not stored.
type Call struct {
	CallNo       int64               `json:"call_no"`
	From         string              `json:"from"`
	To           string              `json:"to"`
	TurnCount    int64               `json:"turn_count"`
	LastTurnFrom string              `json:"last_turn_from"`
	Lifecycle    string              `json:"lifecycle"`
	LifecycleRev int64               `json:"lifecycle_rev"`
	Byes         []string            `json:"byes"`
	Links        []string            `json:"links"`
	NoteCount    int64               `json:"note_count"`
	AttachCount  int64               `json:"attach_count"`
	DisputeCount int64               `json:"dispute_count"`
	Disputes     map[string]*Dispute `json:"disputes"`
}

// Dispute is one disagreement on a call.
type Dispute struct {
	OpenedBy   string           `json:"opened_by"`
	Rev        int64            `json:"rev"`
	MeasureRev map[string]int64 `json:"measure_rev"`
	Resolved   bool             `json:"resolved"`
	Resolution *Resolution      `json:"resolution,omitempty"`
}

// Resolution records how a dispute ended and who said so. Kind "measured" is
// the signer's attributed assertion; it never means a test ran or passed.
type Resolution struct {
	Kind string `json:"kind"`
	By   string `json:"by"`
}

// Broadcast is an operator message with an immutable recipient snapshot.
type Broadcast struct {
	Kind            string             `json:"kind"`
	Recipients      []string           `json:"recipients"`
	DefaultAudience bool               `json:"default_audience"`
	Receipts        map[string]Receipt `json:"receipts"`
	ReplyCount      map[string]int64   `json:"reply_count"`
}

// Receipt names the generation-qualified coordinate (ReadGen, ReadSeq) that
// first recorded a recipient's read.
type Receipt struct {
	ReadGen int64 `json:"read_gen"`
	ReadSeq int64 `json:"read_seq"`
}

// Involves reports whether actor is one of the call's two participants.
func (c *Call) Involves(actor string) bool { return actor == c.From || actor == c.To }

// Floor is the participant who did not write the last turn.
func (c *Call) Floor() string {
	if c.LastTurnFrom == c.From {
		return c.To
	}
	return c.From
}

// Status is the lifecycle, or "resolved" when the lifecycle is open and both
// participants have a standing bye.
func (c *Call) Status() string {
	if c.Lifecycle != "open" {
		return c.Lifecycle
	}
	if slices.Contains(c.Byes, c.From) && slices.Contains(c.Byes, c.To) {
		return "resolved"
	}
	return "open"
}

// EntitledReaders is the set a new key epoch must be distributed to: enrolled,
// unrevoked credentials that hold the reader capability. Sorted.
func (l *Line) EntitledReaders() []string {
	var out []string
	for id, c := range l.Credentials {
		if c.Reader && !c.Revoked {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// DefaultAudience is the set a default-audience broadcast must name: live
// actors that have not left the default audience. Sorted.
func (l *Line) DefaultAudience() []string {
	var out []string
	for id, a := range l.Actors {
		if a.Live && a.DefaultAddressed {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// keyUsed reports whether a public key has ever held a role on this line: an
// active or replaced root key, an operator key that is or was authorized, or
// either key of a credential that is or was enrolled. Such a key is reserved
// for life. It never takes a second role and never returns to its first. The
// registry is derived, not stored: nothing that feeds it is ever deleted from
// a State.
func (l *Line) keyUsed(k string) bool {
	if slices.Contains(l.RootKeys, k) || slices.Contains(l.Tombstones.RootKeys, k) ||
		slices.Contains(l.Operators, k) || slices.Contains(l.Tombstones.OperatorKeys, k) {
		return true
	}
	for _, c := range l.Credentials {
		if c.SigningKey == k || c.EncryptionKey == k {
			return true
		}
	}
	return false
}

// liveInNamespace counts live actors in a namespace, whichever credential
// currently holds them.
func (l *Line) liveInNamespace(ns string) int64 {
	var n int64
	for _, a := range l.Actors {
		if a.Live && a.Namespace == ns {
			n++
		}
	}
	return n
}

// Clone returns a deep copy. Apply works on a clone so that a rejected record
// can never leave a partial effect behind.
func (s State) Clone() State {
	out := State{Line: s.Line.clone()}
	out.Calls = make(map[string]*Call, len(s.Calls))
	for id, c := range s.Calls {
		cc := *c
		cc.Byes = slices.Clone(c.Byes)
		cc.Links = slices.Clone(c.Links)
		cc.Disputes = make(map[string]*Dispute, len(c.Disputes))
		for did, d := range c.Disputes {
			dd := *d
			dd.MeasureRev = maps.Clone(d.MeasureRev)
			if d.Resolution != nil {
				r := *d.Resolution
				dd.Resolution = &r
			}
			cc.Disputes[did] = &dd
		}
		out.Calls[id] = &cc
	}
	out.Broadcasts = make(map[string]*Broadcast, len(s.Broadcasts))
	for id, b := range s.Broadcasts {
		bb := *b
		bb.Recipients = slices.Clone(b.Recipients)
		bb.Receipts = maps.Clone(b.Receipts)
		bb.ReplyCount = maps.Clone(b.ReplyCount)
		out.Broadcasts[id] = &bb
	}
	return out
}

func (l Line) clone() Line {
	out := l
	out.RootKeys = slices.Clone(l.RootKeys)
	out.Operators = slices.Clone(l.Operators)
	out.Credentials = make(map[string]*Credential, len(l.Credentials))
	for id, c := range l.Credentials {
		cc := *c
		out.Credentials[id] = &cc
	}
	out.Readers = make(map[int64][]string, len(l.Readers))
	for e, r := range l.Readers {
		out.Readers[e] = slices.Clone(r)
	}
	out.Tombstones = Tombstones{
		Creds:        slices.Clone(l.Tombstones.Creds),
		Actors:       slices.Clone(l.Tombstones.Actors),
		JoinRequests: slices.Clone(l.Tombstones.JoinRequests),
		OperatorKeys: slices.Clone(l.Tombstones.OperatorKeys),
		RootKeys:     slices.Clone(l.Tombstones.RootKeys),
		Calls:        slices.Clone(l.Tombstones.Calls),
		Broadcasts:   slices.Clone(l.Tombstones.Broadcasts),
	}
	out.Actors = make(map[string]*Actor, len(l.Actors))
	for id, a := range l.Actors {
		aa := *a
		out.Actors[id] = &aa
	}
	out.RegisterWriters = make(map[string]*RegisterWriter, len(l.RegisterWriters))
	for id, w := range l.RegisterWriters {
		ww := *w
		ww.Used = slices.Clone(w.Used)
		out.RegisterWriters[id] = &ww
	}
	return out
}

// Canon returns a copy in canonical form: every set sorted, and no nil slice
// or map, so two states that mean the same thing compare equal.
func (s State) Canon() State {
	out := s.Clone()
	l := &out.Line
	l.RootKeys = canonSet(l.RootKeys)
	l.Operators = canonSet(l.Operators)
	l.Tombstones.Creds = canonSet(l.Tombstones.Creds)
	l.Tombstones.Actors = canonSet(l.Tombstones.Actors)
	l.Tombstones.JoinRequests = canonSet(l.Tombstones.JoinRequests)
	l.Tombstones.OperatorKeys = canonSet(l.Tombstones.OperatorKeys)
	l.Tombstones.RootKeys = canonSet(l.Tombstones.RootKeys)
	l.Tombstones.Calls = canonSet(l.Tombstones.Calls)
	l.Tombstones.Broadcasts = canonSet(l.Tombstones.Broadcasts)
	for e, r := range l.Readers {
		l.Readers[e] = canonSet(r)
	}
	for _, w := range l.RegisterWriters {
		w.Used = canonSet(w.Used)
	}
	for _, c := range out.Calls {
		c.Byes = canonSet(c.Byes)
		c.Links = canonSet(c.Links)
		for _, d := range c.Disputes {
			if d.MeasureRev == nil {
				d.MeasureRev = map[string]int64{}
			}
		}
	}
	for _, b := range out.Broadcasts {
		b.Recipients = canonSet(b.Recipients)
		if b.Receipts == nil {
			b.Receipts = map[string]Receipt{}
		}
		if b.ReplyCount == nil {
			b.ReplyCount = map[string]int64{}
		}
	}
	return out
}

func canonSet(s []string) []string {
	out := slices.Clone(s)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// addToSet returns s with v added, sorted, without duplicates.
func addToSet(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	out := append(slices.Clone(s), v)
	slices.Sort(out)
	return out
}

// sameSet reports whether a and b hold the same members. Neither may contain
// duplicates; callers check that separately.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func hasDuplicates(s []string) bool {
	x := slices.Clone(s)
	slices.Sort(x)
	return len(slices.Compact(x)) != len(s)
}
