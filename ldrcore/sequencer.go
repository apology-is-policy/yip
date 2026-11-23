package ldrcore

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
)

// Sequencer is an in-memory model of the shell around Apply: operation
// identity and dedup, admission versus durable outcome, the retry lookup of
// spec section 5.5, anchor resolution, validity, anchor-scoped retirement,
// the rejection quota, the time floor and demand-driven time anchors.
//
// It is a model for running the specification's scenario traces. It is not a
// relay. It has no transport, no sessions, no storage and no cryptography:
//
//   - A signature is the boolean Intent.SignatureOK.
//   - The chain head is a non-cryptographic stand-in (FNV), good only for
//     telling two histories apart. It is not the chain construction.
//   - The clock is injected. Every call is handed a reading and whether the
//     deployment considers it trustworthy; the model reads no real clock and
//     invents no threshold for detecting a fault.
//   - "Persisted in one atomic step" is trivially true of a struct in memory.
//
// A Sequencer is not safe for concurrent use. The spec requires admission and
// outcome decisions for one operation identity to be serialized; here every
// call is.
type Sequencer struct {
	LineID string
	prof   Profile
	// QuotaMax bounds each signer's durable rejection and no-op entries.
	QuotaMax int
	// Overloaded makes every submission an admission error. It is a fault
	// injected by a test, standing for any transient refusal.
	Overloaded bool

	gen         int64
	genStartSeq int64 // first sequence number of the current generation
	state       State
	log         []Entry             // records committed by this model, oldest first
	heads       map[int64]string    // chain head after each known sequence number
	times       map[int64]int64     // seq_time of each known sequence number
	logIndex    map[OpKey]OpReceipt // committed operations, including retained earlier generations
	hot         map[OpKey]hotEntry
	quota       map[string]int
	floor       int64
}

// OpReceipt is what the log index keeps for a committed operation: where it
// committed and the digest of its bytes.
type OpReceipt struct {
	Seq    int64
	Digest string
}

// Entry is one committed record as the log holds it.
type Entry struct {
	Seq     int64
	SeqTime int64
	Head    string
	Key     OpKey // zero for a sequencer-origin record
	Digest  string
	Record  Record
	// Payload travelled with the intent. The sequencer stores and serves it
	// and never reads it.
	Payload Payload
}

// Payload stands for the encrypted payload that travels with an intent. No
// decision of Submit or Apply depends on it. Its fields are facts a reader
// could discover only by trying to decrypt; they are stated up front because
// this package has no cryptography. The epoch a payload claims is the
// record's visible KeyEpoch.
type Payload struct {
	// Forged is ciphertext that fails authentication under the key of the
	// epoch the record names.
	Forged bool
	// Malformed is plaintext that authenticates and then breaks a rule only a
	// reader can check, such as an empty reason where one is required.
	Malformed bool
}

// OpKey is the operation identity of spec section 5.1, without the line. An
// op_id is unique only within its anchor, so the same OpID under a later
// SeenSeq is a different operation.
type OpKey struct {
	Generation int64
	Signer     string
	SeenSeq    int64
	OpID       string
}

// Intent is what a client submits. Digest stands for a digest of the exact
// signed bytes: two intents with the same Digest are the same bytes.
type Intent struct {
	LineID      string
	Generation  int64
	OpID        string
	SeenSeq     int64
	SeenHead    string
	ValidityMS  int64
	Digest      string
	SignatureOK bool
	Record      Record
	// Payload is carried into the log untouched. Digest is taken to cover it.
	Payload Payload
}

// Clock is one reading of the sequencer's clock, as the deployment reports
// it. Trusted is false when the deployment has detected a discontinuity or
// cannot vouch for the reading.
type Clock struct {
	Now     int64
	Trusted bool
}

// At is a trusted clock reading.
func At(now int64) Clock { return Clock{Now: now, Trusted: true} }

type hotEntry struct {
	digest  string
	outcome Outcome
	seq     int64 // for a commit
}

// Answer classes. They promise different things and must not be confused.
const (
	// ClassOutcome is the one durable outcome of an admitted operation.
	ClassOutcome = "outcome"
	// ClassRefusal is definitive without an index entry: the operation did
	// not commit and never can in this generation.
	ClassRefusal = "refusal"
	// ClassUnresolved resolves nothing: whether the operation committed
	// earlier is not established, and it is never grounds to repeat it.
	ClassUnresolved = "unresolved"
	// ClassAdmission is transport-level. Nothing is recorded and nothing is
	// promised.
	ClassAdmission = "admission_error"
	// ClassMismatch is different bytes under an identity that already has an
	// outcome. The original stands.
	ClassMismatch = "duplicate_mismatch"
	// ClassUnknown answers a query that found no outcome while the operation
	// could still be admitted. It is not a cancellation and not evidence of
	// non-commit; the query evaluated nothing, reserved nothing and used no
	// quota.
	ClassUnknown = "outcome_unknown"
)

// Answer is what a submission, resubmission or query is told.
type Answer struct {
	Class string
	// Outcome is set for ClassOutcome.
	Outcome Outcome
	// Seq is the sequence number of a committed operation.
	Seq int64
	// Code names a refusal, an unresolved refusal or an admission error.
	Code string
	// Original is true when the answer is an outcome recorded earlier and
	// returned by lookup. A user-facing result must say so: identical bytes
	// are never re-evaluated against current state.
	Original bool
}

// NewSequencer returns a sequencer for an empty log. The profile is fixed for
// the generation.
func NewSequencer(lineID string, prof Profile) *Sequencer {
	return &Sequencer{
		LineID:   lineID,
		prof:     prof,
		QuotaMax: 64,
		heads:    map[int64]string{0: "genesis:" + lineID},
		times:    map[int64]int64{},
		logIndex: map[OpKey]OpReceipt{},
		hot:      map[OpKey]hotEntry{},
		quota:    map[string]int{},
	}
}

// State returns a copy of the current state.
func (q *Sequencer) State() State { return q.state.Clone() }

// Log returns a deep copy of the records this model committed. Nothing the
// caller does to the result can reach the sequencer's own log.
func (q *Sequencer) Log() []Entry {
	out := make([]Entry, len(q.log))
	for i, e := range q.log {
		e.Record = e.Record.Clone()
		out[i] = e
	}
	return out
}

// Head returns the current sequence number and chain head.
func (q *Sequencer) Head() (int64, string) {
	return q.state.Line.HeadSeq, q.heads[q.state.Line.HeadSeq]
}

// HeadAt returns the chain head recorded at seq, if this history knows it.
func (q *Sequencer) HeadAt(seq int64) (string, bool) {
	h, ok := q.heads[seq]
	return h, ok
}

// Generation returns the current generation.
func (q *Sequencer) Generation() int64 { return q.gen }

// TimeFloor returns the persisted time floor.
func (q *Sequencer) TimeFloor() int64 { return q.floor }

// HotEntries returns how many durable outcomes the hot index holds.
func (q *Sequencer) HotEntries() int { return len(q.hot) }

// signerOf names the key that signs a record, in a namespace that keeps
// credentials, operator keys and the root apart.
func signerOf(r *Record) string {
	switch r.Origin {
	case OriginActor, OriginCredential:
		return "cred:" + r.Cred
	case OriginOperator:
		return "op:" + r.Operator
	case OriginRoot:
		return "root"
	}
	return ""
}

// CredentialPrincipal names a credential as a principal, for queries and
// anchor requests.
func CredentialPrincipal(id string) string { return "cred:" + id }

// OperatorPrincipal names an operator key as a principal.
func OperatorPrincipal(id string) string { return "op:" + id }

// Root is the root principal.
const Root = "root"

// Standings of a principal.
const (
	standingActive = iota // may submit, query and request anchors
	// standingRevoked is a credential that was revoked, or an operator key
	// that was authorized and then revoked. The state keeps a tombstone for
	// both, so the key is told that it is revoked and nothing more: not
	// whether an earlier operation of its committed.
	standingRevoked
	// standingNever is a key that never held the role it claims: a credential
	// that was never enrolled, an operator key that was never authorized.
	standingNever
)

// standing is judged for a principal whose possession of the key is already
// established: by the signature on a submission, or by the authenticated
// session a query or an anchor request arrives on. Neither is modelled beyond
// a boolean and a premise.
func (q *Sequencer) standing(principal string) int {
	l := &q.state.Line
	switch {
	case principal == Root:
		return standingActive
	case len(principal) > 5 && principal[:5] == "cred:":
		c := l.Credentials[principal[5:]]
		switch {
		case c == nil:
			return standingNever
		case c.Revoked:
			return standingRevoked
		}
		return standingActive
	case len(principal) > 3 && principal[:3] == "op:":
		switch k := principal[3:]; {
		case slices.Contains(l.Operators, k):
			return standingActive
		case slices.Contains(l.Tombstones.OperatorKeys, k):
			return standingRevoked
		}
	}
	return standingNever
}

// access turns a standing into the answer a refused principal gets.
func access(standing int) (Answer, bool) {
	switch standing {
	case standingActive:
		return Answer{}, true
	case standingRevoked:
		return unresolved("revoked"), false
	}
	return admission("unknown_signer"), false
}

// tick takes the evaluation time from the injected clock. No evaluation uses
// a time below the floor, and the floor advances with every evaluation. An
// untrusted or out-of-domain reading suspends evaluation.
func (q *Sequencer) tick(c Clock) (int64, bool) {
	if !c.Trusted || c.Now < 0 || c.Now > MaxCounter {
		return 0, false
	}
	t := max(c.Now, q.floor)
	q.floor = t
	return t, true
}

func (q *Sequencer) seqTime(seq int64) int64 { return q.times[seq] }

// retired reports whether the identity space of anchor seq is retired:
// nothing anchored there can be admitted any more, whatever its bytes and
// whatever validity it claims. The comparison is strict.
func (q *Sequencer) retired(seq int64) bool {
	return q.floor > q.seqTime(seq)+q.prof.ValidityMaxMS
}

func refusal(code string) Answer    { return Answer{Class: ClassRefusal, Code: code} }
func unresolved(code string) Answer { return Answer{Class: ClassUnresolved, Code: code} }
func admission(code string) Answer  { return Answer{Class: ClassAdmission, Code: code} }

// lookup is steps 1 to 4 of the retry lookup: outcomes already recorded, and
// operations of an earlier generation. It needs no clock, so it still answers
// while evaluation is suspended.
func (q *Sequencer) lookup(key OpKey, digest string) (Answer, bool) {
	if a, found := q.recorded(key, digest); found {
		return a, true
	}
	switch {
	case key.Generation < q.gen:
		// Not in the history this generation retained. It has no effect now,
		// and it may have committed in a discarded tail.
		return unresolved("abandoned"), true
	case key.Generation > q.gen:
		return unresolved("history_unavailable"), true
	}
	return Answer{}, false
}

// recorded finds an outcome already held for exactly this identity, in the
// hot index or the log index.
func (q *Sequencer) recorded(key OpKey, digest string) (Answer, bool) {
	if e, ok := q.hot[key]; ok {
		if e.digest != digest {
			return Answer{Class: ClassMismatch}, true
		}
		return Answer{Class: ClassOutcome, Outcome: e.outcome, Seq: e.seq, Original: true}, true
	}
	if r, ok := q.logIndex[key]; ok {
		if r.Digest != digest {
			return Answer{Class: ClassMismatch}, true
		}
		return Answer{Class: ClassOutcome, Outcome: Outcome{Kind: Committed}, Seq: r.Seq, Original: true}, true
	}
	return Answer{}, false
}

// Submit handles a submission or a resubmission of the same bytes.
func (q *Sequencer) Submit(in Intent, c Clock) Answer {
	// Stages 1 and 2 are premises here: decoding is assumed, and the
	// signature is a boolean.
	if q.Overloaded {
		return admission("overloaded")
	}
	if in.LineID != q.LineID {
		return admission("wrong_line")
	}
	if !in.SignatureOK {
		return admission("bad_signature")
	}
	if in.ValidityMS < 0 || in.SeenSeq < 0 || in.OpID == "" || in.Digest == "" {
		return admission("malformed")
	}
	signer := signerOf(&in.Record)
	if signer == "" {
		return admission("malformed")
	}

	// line_init is the bootstrap exception: no prior checkpoint, no validity.
	if in.Record.Type == "line_init" {
		return q.submitLineInit(in, signer, c)
	}
	if q.gen == 0 {
		return admission("no_line")
	}

	// Authorization to learn an outcome comes before any lookup. A revoked
	// key is refused, including for its own earlier receipts, and the refusal
	// says nothing about whether the operation committed.
	if a, ok := access(q.standing(signer)); !ok {
		return a
	}

	key := OpKey{Generation: in.Generation, Signer: signer, SeenSeq: in.SeenSeq, OpID: in.OpID}
	if a, found := q.lookup(key, in.Digest); found {
		return a
	}

	// Everything from here needs sequencer time.
	t, ok := q.tick(c)
	if !ok {
		return admission("clock_uncertain")
	}

	// Resolve the anchor before computing expiry: an unknown or ahead-of-head
	// reference has no accepted seq_time.
	if in.SeenSeq > q.state.Line.HeadSeq {
		return unresolved("history_unavailable")
	}
	// An intent of this generation cannot anchor before the generation began.
	if h, known := q.heads[in.SeenSeq]; in.SeenSeq < q.genStartSeq || !known || h != in.SeenHead {
		return refusal("unknown_anchor")
	}
	// The deadline is inclusive, and a claim above the maximum buys nothing.
	if t > q.seqTime(in.SeenSeq)+min(in.ValidityMS, q.prof.ValidityMaxMS) {
		return refusal("expired")
	}

	// Admitted. From here the operation gets exactly one durable outcome,
	// unless it would be a rejection or no-op and the signer's quota is full.
	rec := in.Record
	rec.ValidityMS = in.ValidityMS
	next, out := Apply(q.state, rec, t, q.prof)
	switch out.Kind {
	case Committed:
		q.commit(next, Entry{Key: key, Digest: in.Digest, Record: rec, Payload: in.Payload}, t)
		seq := q.state.Line.HeadSeq
		q.logIndex[key] = OpReceipt{Seq: seq, Digest: in.Digest}
		q.hot[key] = hotEntry{digest: in.Digest, outcome: out, seq: seq}
		return Answer{Class: ClassOutcome, Outcome: out, Seq: seq}
	case Rejected, Noop:
		// The evaluation is discarded when the quota is full, so nothing was
		// promised and a later retry is evaluated afresh. A commit is never
		// blocked by the rejection quota.
		if q.quota[signer] >= q.QuotaMax {
			return admission("quota")
		}
		q.quota[signer]++
		q.hot[key] = hotEntry{digest: in.Digest, outcome: out}
		return Answer{Class: ClassOutcome, Outcome: out}
	}
	// Apply reports a violation only for something no honest sequencer
	// produces. Reaching it here means the model itself is wrong.
	panic(fmt.Sprintf("ldrcore: Apply returned %q for an admitted intent of type %s", out.Kind, rec.Type))
}

func (q *Sequencer) submitLineInit(in Intent, signer string, c Clock) Answer {
	key := OpKey{Generation: in.Generation, Signer: signer, SeenSeq: in.SeenSeq, OpID: in.OpID}
	// A retry of the line_init that created this line gets its receipt, and
	// changed bytes under that identity are a mismatch. Only a recorded
	// outcome is looked up here: before the line exists there is no current
	// generation to compare the intent's against.
	if a, found := q.recorded(key, in.Digest); found {
		return a
	}
	if q.gen != 0 {
		// A line exists. Another line_init can never commit into this log,
		// and it has no anchor whose retirement could bound an index entry,
		// so this is a definitive refusal without one.
		return refusal("line_exists")
	}

	// The bootstrap context. line_init is exempt from validity, not from
	// saying what it is: it creates generation 1 and anchors on genesis.
	// A client that names a later generation or a sequence number this empty
	// log has never had is ahead of this relay, exactly as in the ordinary
	// case, and learns nothing about what happened elsewhere.
	if in.Generation < 1 {
		return admission("malformed")
	}
	if in.Generation != 1 || in.SeenSeq > 0 {
		return unresolved("history_unavailable")
	}
	if in.SeenHead != q.heads[0] {
		return refusal("unknown_anchor")
	}
	t, ok := q.tick(c)
	if !ok {
		return admission("clock_uncertain")
	}
	next, out := Apply(q.state, in.Record, t, q.prof)
	if out.Kind != Committed {
		// Apply refused the input itself: wrong origin, malformed, and so
		// on. That is not evidence that a line exists. With no line there is
		// nowhere to hold a durable outcome, so nothing is recorded and
		// nothing is promised.
		return admission("invalid_bootstrap")
	}
	q.gen, q.genStartSeq = 1, 1
	q.commit(next, Entry{Key: key, Digest: in.Digest, Record: in.Record}, t)
	q.logIndex[key] = OpReceipt{Seq: 1, Digest: in.Digest}
	return Answer{Class: ClassOutcome, Outcome: out, Seq: 1}
}

// commit appends one record and adopts the state Apply returned.
func (q *Sequencer) commit(next State, e Entry, t int64) {
	e.Seq = next.Line.HeadSeq
	e.SeqTime = t
	// The log owns its records: the caller keeps the pointers and slices of
	// the intent it submitted, and must not be able to change history.
	e.Record = e.Record.Clone()
	e.Head = chainHead(q.heads[e.Seq-1], e.Seq, t, e.Record.Type, e.Digest)
	q.log = append(q.log, e)
	q.heads[e.Seq] = e.Head
	q.times[e.Seq] = t
	q.state = next
}

// chainHead is a stand-in for the chain commitment. It is FNV, which is not a
// cryptographic hash: it exists so that two different histories have
// different heads in a test. It says nothing about the real construction.
func chainHead(prev string, seq, t int64, typ, digest string) string {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%d|%d|%s|%s", prev, seq, t, typ, digest)
	return fmt.Sprintf("%016x", h.Sum64())
}

// AnchorRequest is the demand-driven time anchor of spec section 4.2. It is
// not an intent: it has no operation identity, no outcome and no validity,
// and it grants nothing. It returns the head the requester should anchor on,
// and whether a time_anchor record was written to produce it.
func (q *Sequencer) AnchorRequest(principal string, c Clock) (seq int64, head string, wrote bool, a Answer) {
	if q.Overloaded {
		return 0, "", false, admission("overloaded")
	}
	if q.gen == 0 {
		return 0, "", false, admission("no_line")
	}
	// Authorization is re-checked here, inside the same step as the append.
	// A session authenticated before a revocation is not enough.
	switch q.standing(principal) {
	case standingRevoked:
		// A key that has shown possession, and that the state holds a
		// tombstone for, is told that it is revoked, as on a submission or a
		// query. That is all it gets: no anchor, no record, no outcome.
		return 0, "", false, unresolved("revoked")
	case standingNever:
		// A key that never held the role is not told even that.
		return 0, "", false, admission("not_authorized")
	}
	t, ok := q.tick(c)
	if !ok {
		return 0, "", false, admission("clock_uncertain")
	}
	if t-q.state.Line.HeadTime > q.prof.FreshnessMS {
		next, out := Apply(q.state, Record{Origin: OriginSequencer, Type: "time_anchor"}, t, q.prof)
		if out.Kind != Committed {
			// The sequence space is exhausted; there is nowhere to put one.
			return 0, "", false, admission("exhausted")
		}
		q.commit(next, Entry{Record: Record{Origin: OriginSequencer, Type: "time_anchor"}}, t)
		wrote = true
	}
	seq, head = q.Head()
	return seq, head, wrote, Answer{}
}

// Query answers an authorized question about an operation without its bytes:
// the signer asking about its own operation, or an operator or the root
// reconciling history by naming the operation and its digest. It never
// evaluates anything and never changes sequencer state, the time floor
// included.
//
// A recorded outcome is returned whatever the clock says: that is the
// historical receipt lookup that keeps working while time is uncertain.
// Anything that depends on time does not. Saying "expired" needs the anchor to
// have retired, and although the saved floor that shows it was established
// earlier, this model takes the conservative rule: while the clock is not
// trusted it does not say so, exactly as Submit would not.
func (q *Sequencer) Query(principal string, key OpKey, digest string, c Clock) Answer {
	if a, ok := access(q.standing(principal)); !ok {
		return a
	}
	reconciler := principal == Root || (len(principal) > 3 && principal[:3] == "op:")
	if principal != key.Signer && !reconciler {
		// Refused before any index lookup.
		return admission("not_authorized")
	}
	if a, found := q.lookup(key, digest); found {
		return a
	}
	// Nothing is recorded for an operation of this generation. Every answer
	// from here depends on sequencer time.
	if !c.Trusted || c.Now < 0 || c.Now > MaxCounter {
		return admission("clock_uncertain")
	}
	if key.SeenSeq > q.state.Line.HeadSeq {
		return unresolved("history_unavailable")
	}
	if _, known := q.heads[key.SeenSeq]; key.SeenSeq < q.genStartSeq || !known {
		return refusal("unknown_anchor")
	}
	// Once the anchor has retired, a miss in a complete index establishes
	// that the operation never committed, under the trusted clock and
	// complete history this model has. Before that it establishes nothing.
	if q.retired(key.SeenSeq) {
		return refusal("expired")
	}
	return Answer{Class: ClassUnknown, Code: "outcome_unknown"}
}

// Compact discards the hot entries of every retired anchor, rejections
// included, and returns how many it discarded. It never runs on an intent's
// own deadline, and it does nothing while sequencer time is uncertain.
// Committed operations stay findable through the log index.
func (q *Sequencer) Compact(c Clock) int {
	if _, ok := q.tick(c); !ok {
		return 0
	}
	n := 0
	for key, e := range q.hot {
		if key.Generation == q.gen && !q.retired(key.SeenSeq) {
			continue
		}
		if e.outcome.Kind != Committed {
			q.quota[key.Signer]--
		}
		delete(q.hot, key)
		n++
	}
	return n
}

// PostRecoveryFixture is a stipulated starting point after a generation
// change. It exists so that the retry lookup of spec section 5.5 can be
// exercised for operations of an earlier generation, and for nothing else.
//
// This package does not model recovery. How a log is rolled back, how later
// revocations and tombstones are carried across, whether sequence numbers
// restart, and what authorizes any of it are unresolved and are not this
// package's to decide. A fixture simply asserts the result: this generation,
// this state, this head, and these earlier operations whose receipts were
// retained. Every earlier operation not listed is treated as unavailable.
type PostRecoveryFixture struct {
	Generation int64
	// State is the state at the first record of the generation.
	State State
	// Head is the chain head at State.Line.HeadSeq.
	Head string
	// Retained holds the operations of earlier generations whose receipts
	// survived.
	Retained map[OpKey]OpReceipt
	// Reconciled is an external premise: membership, keys and tombstones in
	// State were reconciled by whatever recovery procedure produced it. The
	// model cannot check that and does not try.
	Reconciled bool
}

// ErrNotReconciled is returned when a fixture is offered without its premise.
var ErrNotReconciled = errors.New("ldrcore: a post-recovery fixture needs the external premise that its security state was reconciled")

// NewSequencerFromFixture installs a post-recovery fixture. It refuses one
// that does not carry the reconciliation premise. Refusing is not a recovery
// gate and certifies nothing about a fixture that does carry it.
func NewSequencerFromFixture(lineID string, prof Profile, fx PostRecoveryFixture) (*Sequencer, error) {
	if !fx.Reconciled {
		return nil, ErrNotReconciled
	}
	if fx.Generation < 2 || fx.State.Line.Generation != fx.Generation {
		return nil, fmt.Errorf("fixture generation %d does not match its state's generation %d", fx.Generation, fx.State.Line.Generation)
	}
	if bad := fx.State.CheckInvariants(); len(bad) > 0 {
		return nil, fmt.Errorf("fixture state is not coherent: %v", bad)
	}
	q := NewSequencer(lineID, prof)
	q.gen = fx.Generation
	q.state = fx.State.Clone()
	q.genStartSeq = q.state.Line.HeadSeq
	q.heads = map[int64]string{q.state.Line.HeadSeq: fx.Head}
	q.times = map[int64]int64{q.state.Line.HeadSeq: q.state.Line.HeadTime}
	q.floor = q.state.Line.HeadTime
	for key, r := range fx.Retained {
		if key.Generation >= fx.Generation {
			return nil, fmt.Errorf("retained operation %v is not from an earlier generation", key)
		}
		q.logIndex[key] = r
	}
	return q, nil
}

// Replay derives the state a log produces, the way a client would: it applies
// each record in order and insists that Apply commits it. A log that does not
// replay was not produced by an honest sequencer.
//
// It replays a log that begins at genesis. It does not model a generation
// change.
func Replay(log []Entry, prof Profile) (State, error) {
	var s State
	for i, e := range log {
		if e.Seq != int64(i)+1 {
			return State{}, fmt.Errorf("entry %d has sequence number %d", i, e.Seq)
		}
		next, out := Apply(s, e.Record, e.SeqTime, prof)
		if out.Kind != Committed {
			return State{}, fmt.Errorf("record %d (%s) does not commit on replay: %s %s", e.Seq, e.Record.Type, out.Kind, out.Reason)
		}
		s = next
	}
	return s, nil
}
