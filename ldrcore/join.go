package ldrcore

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
)

// Join is a model of a first bootstrap from an operator-endorsed state
// commitment: the third route for the open question of spec section 13, O25,
// described at the top of commit.go. It follows the acceptance sequence Codex
// set out when it reviewed the idea (call 0003, turn 25). It is an
// exploration. Nobody has chosen it, and Codex's P4 is unchanged.
//
// What a successful Join establishes, and under what it rests:
//
//   - The operator the joiner pinned signed this joiner's enrollment over a
//     head, and the state the joiner starts from is the state that head
//     commits to. The joiner has not replayed the records before that head:
//     the state is an endorsed prefix, not a verified one.
//   - Every record from that head to the head the relay named was verified
//     here: linkage, signature, generation, the head it was signed over, its
//     deadline, that its operation identity had not committed before, its
//     outcome and its state commitment.
//   - For the last three of those the joiner needs something from before the
//     endorsed head: the heads a later record may name, with their times, and
//     the operation identities a later record may repeat. It opens the chain
//     backwards from the endorsed head as far as either can matter (the live
//     window, openWindow) and replays none of it.
//   - The enrollment is on the chain the pinned relay served, the credential
//     is still entitled at the head the relay named, and, for a reader, a key
//     epoch includes it.
//
// What it rests on, none of which this package can check:
//
//   - The relay handed to Join is the one the joiner pinned, and that pin
//     reached the joiner independently of the enrolling operator's device.
//     If the device that enrolls the joiner also tells it where the relay
//     is, that device alone can do everything the operator and the relay can
//     do together.
//   - The pinned operator's device verified every record up to the head it
//     signed over, as ReplayVerified does, and derived the state there. The
//     client model does under a profile that commits state: Client.Sync runs
//     the same frame verification as this file and stops at a frame that
//     fails it, and a client that has stopped signs nothing. A signer that
//     checked less would be endorsing whatever the relay served it.
//
// What it does not establish:
//
//   - Anything about the records before the endorsed head. The operator's
//     key and the relay together can commit to a state holding actions that
//     no honest member signed, and Join accepts it; replay from genesis
//     would not (ReplayVerified, and the tests that compare the two). The
//     live window is opened, not replayed, and is worth what the endorsement
//     is worth.
//   - Freshness against a relay that withholds records or serves a fork.
//   - That the relay's bookkeeping was honest where it left no record: an
//     index of committed operations says nothing about a rejection or a
//     no-op that was never logged.
//
// Not modelled: the ceremony that produces the pin, the root-signed evidence
// of the operator's authorization that Codex's draft also requires, transfer
// in chunks, a bound on the length of the suffix, a device that had already
// accepted a checkpoint, and a generation change.

// JoinPin is what a joining device fixed before it was handed any state: the
// line, the profile and the root key from the creation descriptor, the
// enrolling operator's key, and its own request. How each reaches the device
// is the ceremony's business and a premise here.
type JoinPin struct {
	LineID     string
	Generation int64
	Profile    Profile
	RootKey    string
	// Operator is the key of the operator the joiner expects to enroll it.
	Operator string

	// The joiner's own request.
	Cred              string
	SigningKey        string
	EncryptionKey     string
	Grant             Grant
	JoinRequest       string
	JoinRequestDigest string

	// MaxSnapshotBytes is the joiner's budget for an encoded state. Zero
	// means DefaultSnapshotBudget.
	MaxSnapshotBytes int
	// MaxWindowRecords is the joiner's budget for the live window before the
	// endorsed head, in records. Zero means DefaultWindowBudget. A window
	// over the budget is refused whole; it is never cut short.
	MaxWindowRecords int
	// OnEndorserRevoked is the policy for an endorsing operator whose key is
	// revoked after the enrollment committed and before the join is accepted.
	OnEndorserRevoked int
}

// DefaultSnapshotBudget and DefaultWindowBudget are the budgets used when a
// pin sets none. The numbers are arbitrary.
const (
	DefaultSnapshotBudget = 1 << 20
	DefaultWindowBudget   = 1 << 12
)

// ErrWindowTooLarge: the live window before the endorsed head holds more
// records than the joiner's budget. Nothing was accepted.
var ErrWindowTooLarge = errors.New("ldrcore: the live window before the endorsed head is larger than the budget")

// Policies for JoinPin.OnEndorserRevoked.
const (
	// EndorserRevokedStop refuses the join, as P4 does for its detached
	// attestation. It is the zero value: nothing is relaxed without being
	// asked for.
	EndorserRevokedStop = iota
	// EndorserRevokedAccept accepts the join and records the revocation in
	// the provenance. The reasoning is that a committed enrollment, unlike a
	// detached attestation, has a position in the log: it committed while
	// its signer was authorized. That holds under the same trust in the
	// relay's ordering as everything else here. It shows nothing about when
	// the key was really compromised.
	EndorserRevokedAccept
)

// JoinRelay is what a joiner asks of the relay it pinned. A Sequencer is one.
type JoinRelay interface {
	// AnchorRequest names a fresh head to an enrolled credential (spec 4.2).
	AnchorRequest(principal string, c Clock) (seq int64, head string, wrote bool, a Answer)
	// Enrollment returns the committed record that enrolled cred.
	Enrollment(cred string) (Entry, bool)
	// Entries returns the committed records from..to, both included.
	Entries(from, to int64) []Entry
}

// SnapshotSource supplies the encoded state after a record. Anyone may be
// one: the relay, the enrolling device, another member. What it supplies is
// believed only as far as the endorsed commitment covers it.
type SnapshotSource interface {
	SnapshotAt(seq int64) ([]byte, bool)
}

// Joined is an accepted starting point. Nothing of it exists until every
// check has passed.
type Joined struct {
	State State
	// Seq and Head are the accepted checkpoint: the head the relay named.
	Seq  int64
	Head string
	Provenance
}

// Provenance records what an accepted starting point rests on. It is kept
// with the state: a state that was endorsed is not a state that was replayed.
type Provenance struct {
	// Operator is the pinned operator whose enrollment endorsed the state.
	Operator string
	// EndorsedSeq and EndorsedHead are the head that operator signed over.
	// Nothing at or before it was replayed by this joiner.
	EndorsedSeq  int64
	EndorsedHead string
	// WindowSeq is the oldest record of the live window: from there to
	// EndorsedSeq the joiner opened each frame under the endorsed head and
	// replayed none.
	WindowSeq int64
	// EnrollSeq is where the enrollment committed.
	EnrollSeq int64
	// EndorserRevokedAt is the record that revoked the endorsing operator's
	// key after the enrollment committed, or zero.
	EndorserRevokedAt int64
}

// JoinError says why a join did not finish. Nothing was accepted, and no
// other state, enrollment or relay is taken in place of the one that failed.
type JoinError struct {
	// Pending is true when nothing offered contradicts the pin and something
	// needed is not there yet: no commit, no snapshot, no key epoch. The same
	// join may be tried again later. When it is false, something offered is
	// wrong, and trying again with the same evidence gives the same answer.
	Pending bool
	Reason  string
	// Err is the underlying error, when there is one.
	Err error
}

func (e *JoinError) Error() string {
	kind := "refused"
	if e.Pending {
		kind = "pending"
	}
	return "ldrcore: join " + kind + ": " + e.Reason
}

func (e *JoinError) Unwrap() error { return e.Err }

func joinPending(format string, a ...any) error {
	return &JoinError{Pending: true, Reason: fmt.Sprintf(format, a...)}
}

func joinRefused(format string, a ...any) error {
	return &JoinError{Reason: fmt.Sprintf(format, a...)}
}

// JoinPending reports whether err is a join that may be tried again.
func JoinPending(err error) bool {
	var je *JoinError
	return errors.As(err, &je) && je.Pending
}

// Join runs a first bootstrap for the credential in pin, against the relay
// the joiner pinned and a snapshot from anyone.
func Join(pin JoinPin, relay JoinRelay, snaps SnapshotSource, clk Clock) (*Joined, error) {
	prof := pin.Profile
	if !prof.StateCommit {
		return nil, joinRefused("the pinned profile does not commit state, so there is nothing to check a snapshot against")
	}
	budget := pin.MaxSnapshotBytes
	if budget == 0 {
		budget = DefaultSnapshotBudget
	}

	// A fresh head, named by the pinned relay to this credential. The relay
	// checks membership here; the joiner checks it again below, on the
	// records.
	fseq, fhead, _, ans := relay.AnchorRequest(CredentialPrincipal(pin.Cred), clk)
	switch {
	case ans.Class == ClassUnresolved && ans.Code == "revoked":
		return nil, joinRefused("the relay says this credential is revoked")
	case ans.Class != "":
		return nil, joinPending("the relay named no head: %s %s", ans.Class, ans.Code)
	}

	// The enrollment, as the relay committed it. Only this record is taken
	// as the endorsement: a later record of the same operator is not.
	en, ok := relay.Enrollment(pin.Cred)
	if !ok {
		return nil, joinPending("the relay holds no enrollment of this credential")
	}
	if err := pin.checkEnrollment(en); err != nil {
		return nil, err
	}
	at := en.Key.SeenSeq
	if at < 1 || at >= en.Seq || en.Seq > fseq {
		return nil, joinRefused("the enrollment at %d, signed over the head at %d, does not fit under the head the relay named at %d",
			en.Seq, at, fseq)
	}

	// Every record from the endorsed head to the named one.
	run := relay.Entries(at, fseq)
	if int64(len(run)) != fseq-at+1 {
		return nil, joinPending("the relay supplied %d of the %d records between the endorsed head and the head it named",
			len(run), fseq-at+1)
	}

	// The frame that opens the head the operator signed over. Its record is
	// the last of the endorsed prefix: it is opened with the live window
	// below, and it is not replayed.
	frame := run[0]
	if frame.Seq != at || frame.StateDigest == "" || frameHead(&frame) != en.SeenHead {
		return nil, joinRefused("the frame offered at %d does not open the head the operator signed over", at)
	}

	// The snapshot is believed only because that frame commits to it. The
	// commitment is checked on the bytes before any of them is decoded.
	enc, ok := snaps.SnapshotAt(at)
	if !ok {
		return nil, joinPending("no snapshot of the endorsed head at %d was supplied; no other state is taken in its place", at)
	}
	if len(enc) > budget {
		return nil, &JoinError{Reason: "the snapshot is over this joiner's budget", Err: ErrSnapshotTooLarge}
	}
	if digestEncoded(pin.LineID, prof, enc) != frame.StateDigest {
		return nil, joinRefused("the snapshot is not the state the endorsed head commits to")
	}
	state, err := DecodeState(enc, budget)
	if err != nil {
		return nil, &JoinError{Reason: "the endorsed head commits to bytes that are not a coherent state", Err: err}
	}
	l := &state.Line
	switch {
	case l.Generation != pin.Generation || l.HeadSeq != at || l.HeadTime != frame.SeqTime:
		return nil, joinRefused("the snapshot is a state of another coordinate than the endorsed head")
	case l.RootKey != pin.RootKey:
		return nil, joinRefused("the snapshot names another root key than the one pinned")
	case !slices.Contains(l.Operators, pin.Operator):
		return nil, joinRefused("the pinned operator is not authorized in the endorsed state")
	}

	// What the records after the endorsed head may refer back to.
	ctx, from, err := openWindow(&pin, relay, frame, en.SeenHead)
	if err != nil {
		return nil, err
	}

	// Replay to the named head. The candidate stays in local variables until
	// the last check has passed. A record anchored before the window is
	// refused by the frame verification: the window reaches back to the
	// oldest head that anything after the endorsed one could have been
	// admitted on.
	prov := Provenance{Operator: pin.Operator, EndorsedSeq: at, EndorsedHead: en.SeenHead, WindowSeq: from, EnrollSeq: en.Seq}
	head := en.SeenHead
	for _, e := range run[1:] {
		next, err := verifyFrame(pin.LineID, prof, state, head, ctx, e)
		if err != nil {
			return nil, &JoinError{Reason: "the records after the endorsed head do not verify", Err: err}
		}
		if e.Seq == en.Seq && !reflect.DeepEqual(e, en) {
			return nil, joinRefused("the record at %d is not the enrollment the relay showed", e.Seq)
		}
		if e.Seq > en.Seq && prov.EndorserRevokedAt == 0 && !slices.Contains(next.Line.Operators, pin.Operator) {
			prov.EndorserRevokedAt = e.Seq
		}
		state, head = next, e.Head
		ctx.record(&e, head)
	}
	// The count and the numbering were checked above, so the last record is
	// the one numbered fseq. What is left is whether it has the head named.
	if head != fhead {
		return nil, joinRefused("the records supplied do not reach the head the relay named")
	}

	// Still entitled at that head, to exactly what was requested.
	c := state.Line.Credentials[pin.Cred]
	switch {
	case c == nil:
		return nil, joinRefused("the verified records do not enroll this credential")
	case c.Revoked:
		return nil, joinRefused("this credential was revoked before the join was accepted")
	case c.SigningKey != pin.SigningKey || c.EncryptionKey != pin.EncryptionKey ||
		c.Namespace != pin.Grant.Namespace || c.ActorLimit != pin.Grant.ActorLimit || c.Reader != pin.Grant.Reader:
		return nil, joinRefused("the credential in the verified state is not what this device requested")
	}
	if prov.EndorserRevokedAt != 0 && pin.OnEndorserRevoked != EndorserRevokedAccept {
		return nil, joinRefused("the endorsing operator's key was revoked at %d, after the enrollment committed at %d, and this pin does not accept an endorsement on its position in the log",
			prov.EndorserRevokedAt, en.Seq)
	}
	if pin.Grant.Reader && !readsSomeEpoch(&state.Line, pin.Cred) {
		return nil, joinPending("no key epoch includes this credential yet")
	}

	return &Joined{State: state.Clone(), Seq: fseq, Head: fhead, Provenance: prov}, nil
}

// openWindow opens the chain backwards from the frame of the endorsed head,
// as far as anything in it can matter to a record after that head: a head
// such a record may name, with its seq_time, or an operation identity it may
// repeat. Nothing after the endorsed head can have been admitted on an anchor
// stamped more than the maximum validity before the endorsed head (spec 5.3),
// and an identity is tied to its anchor, so the window ends at the first
// frame older than that, or at genesis. Its length is set by recorded times
// and the profile, never by a guess at how busy the line was.
//
// Opening is not replay. Each frame is checked to hash to the head that the
// frame after it names, which makes its number, its time and the digest of
// its bytes as good as the endorsed head. No outcome is re-derived, and the
// window says nothing more about those records than the endorsement does.
//
// In this model a frame's digest is an opaque name for the signed bytes, so
// what ties an operation identity to its frame is the signature stand-in, and
// it is checked here for that reason. With real bytes the digest ties them,
// and whether a joiner also verifies the window's signatures is a separate
// choice. That two different signed records never share a digest is the
// premise stated at Intent.
//
// It returns the context for verifying the records after the endorsed head,
// and the number of the oldest record it opened.
func openWindow(pin *JoinPin, relay JoinRelay, frame Entry, head string) (*signedContext, int64, error) {
	budget := pin.MaxWindowRecords
	if budget == 0 {
		budget = DefaultWindowBudget
	}
	oldest := frame.SeqTime - pin.Profile.ValidityMaxMS
	ctx := newSignedContext()
	e := frame
	for n := 1; ; n++ {
		// The type is under the head and the origin is not, and a type has one
		// origin. Without this a relay could show a member's record as its own
		// and keep the identity out of the index.
		if e.Record.Origin != recordOrigin[e.Record.Type] {
			return nil, 0, joinRefused("the record at %d, in the live window, is a %s of %s origin", e.Seq, e.Record.Type, e.Record.Origin)
		}
		if e.Record.Origin != OriginSequencer && !signedBy(&e, signerOf(&e.Record)) {
			return nil, 0, joinRefused("the record at %d, in the live window, is not what its signer signed", e.Seq)
		}
		ctx.record(&e, head)
		switch {
		case e.SeqTime < oldest:
			// Too old to be named by anything after the endorsed head, and so
			// is everything before it: the window is complete.
			return ctx, e.Seq, nil
		case e.Seq == 1:
			if e.Prev != genesisHead(pin.LineID) {
				return nil, 0, joinRefused("the first record does not stand on this line's genesis")
			}
			return ctx, 1, nil
		case n >= budget:
			// A budget below one, which no joiner means, opens nothing.
			return nil, 0, &JoinError{Reason: "the live window before the endorsed head is over this joiner's budget", Err: ErrWindowTooLarge}
		}
		older := relay.Entries(e.Seq-1, e.Seq-1)
		if len(older) != 1 {
			return nil, 0, joinPending("the relay did not supply the record at %d, which the live window before the endorsed head needs; nothing is taken in its place", e.Seq-1)
		}
		p := older[0]
		if p.Seq != e.Seq-1 || frameHead(&p) != e.Prev {
			return nil, 0, joinRefused("the record offered at %d does not open the head before the record at %d", e.Seq-1, e.Seq)
		}
		head, e = e.Prev, p
	}
}

// checkEnrollment compares the committed enrollment with the pin: the
// operator, its signature, and the joiner's own request.
func (pin *JoinPin) checkEnrollment(en Entry) error {
	r := &en.Record
	op := OperatorPrincipal(pin.Operator)
	switch {
	case r.Type != "credential_enroll" || r.Origin != OriginOperator:
		return joinRefused("the record offered as the enrollment is a %s of %s origin", r.Type, r.Origin)
	case r.Operator != pin.Operator:
		return joinRefused("the enrollment names another operator than the one pinned")
	case !signedBy(&en, op):
		return joinRefused("the enrollment does not carry the pinned operator's signature")
	case en.Key.Generation != pin.Generation:
		return joinRefused("the enrollment was signed for another generation")
	case r.Cred != pin.Cred || r.SigningKey != pin.SigningKey || r.EncryptionKey != pin.EncryptionKey:
		return joinRefused("the enrollment is not for the keys this device requested")
	case r.JoinRequest != pin.JoinRequest || r.JoinRequestDigest != pin.JoinRequestDigest:
		return joinRefused("the enrollment answers another join request")
	case r.Grant == nil || *r.Grant != pin.Grant:
		return joinRefused("the enrollment grants something other than what this device requested")
	}
	return nil
}

// readsSomeEpoch reports whether a key epoch's manifest names cred.
func readsSomeEpoch(l *Line, cred string) bool {
	for _, readers := range l.Readers {
		if slices.Contains(readers, cred) {
			return true
		}
	}
	return false
}
