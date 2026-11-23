package ldrcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
)

// State commitment. This file and join.go are an exploration, not a rule of
// the specification.
//
// The open question is how a new member comes by its starting state (spec
// section 13, O25). Codex's draft proposes that the enrolling operator's
// device attests that state in a separate signed statement (its P4); the
// alternative it names is replaying every control record from genesis. The
// third route explored here was proposed on call 0003, turn 24, and reviewed
// by Codex in turn 25:
//
//   - every chain frame also commits to the state its record produced, so a
//     head stands for a state and not only for a sequence of bytes;
//   - every signed intent already names the head its signer had verified, so
//     the operator's signature on an enrollment endorses the state at that
//     head, with no separate statement;
//   - a joiner checks a snapshot against that commitment and replays every
//     record after it (join.go).
//
// The exploration is switched on by Profile.StateCommit. With it off, nothing
// in this file is reached and the chain is what it was.
//
// What stands in, as everywhere in this package:
//
//   - The encoding is Go's JSON of the canonical form of a State. It is
//     deterministic, which is all the model needs. It is not a proposal for
//     the normative encoding, which would have to fix ordering, optional
//     fields, numeric bounds and versioning for every implementation.
//   - The digest is FNV, not a cryptographic hash: an attacker can find
//     collisions in it at will, and no test here relies on it for more than
//     telling two encodings apart.
//
// A State holds the coordinate of its head (generation, sequence number,
// time) and not the head itself, so the digest of a state never covers the
// head that covers it.

// EncodeState returns the stand-in canonical encoding of a state.
func EncodeState(s State) []byte {
	b, err := json.Marshal(s.Canon())
	if err != nil {
		// A State holds only strings, integers, booleans and maps and slices
		// of them. Failing to encode one is a defect in this package.
		panic("ldrcore: a state does not encode: " + err.Error())
	}
	return b
}

// digestEncoded is the commitment to an encoded state. It is bound to the
// line and to the profile; the generation and the coordinate are inside the
// encoding.
func digestEncoded(lineID string, prof Profile, enc []byte) string {
	h := fnv.New64a()
	fmt.Fprintf(h, "ldr.state|%s|%d|%d|%d|", lineID, prof.FreshnessMS, prof.ValidityMaxMS, len(enc))
	h.Write(enc)
	return fmt.Sprintf("%016x", h.Sum64())
}

// StateDigest is the commitment to a state.
func StateDigest(lineID string, prof Profile, s State) string {
	return digestEncoded(lineID, prof, EncodeState(s))
}

// signatureOf stands for a signature by principal over the signed part of e:
// the record, the operation identity, the head named and the digest of the
// exact bytes. It is no signature: anyone can compute it. What it gives the
// model is that a signed field cannot be changed afterwards without the
// change showing.
func signatureOf(principal string, e *Entry) string {
	rec, err := json.Marshal(e.Record)
	if err != nil {
		panic("ldrcore: a record does not encode: " + err.Error())
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "ldr.sig|%d|%s|%d|%s|%s|%s|",
		e.Key.Generation, e.Key.Signer, e.Key.SeenSeq, e.Key.OpID, e.SeenHead, e.Digest)
	h.Write(rec)
	// The principal is carried in the value itself.
	return fmt.Sprintf("%s/%016x", principal, h.Sum64())
}

// signedBy reports whether e carries the signature of principal over its
// signed part as it now stands.
func signedBy(e *Entry, principal string) bool {
	return principal != "" && e.Sig == signatureOf(principal, e)
}

// Errors of DecodeState.
var (
	// ErrSnapshotTooLarge: the encoding is over the budget the caller set.
	// Nothing was decoded.
	ErrSnapshotTooLarge = errors.New("ldrcore: the encoded state is larger than the budget")
	// ErrSnapshotEncoding: the bytes are not the canonical encoding of a
	// coherent state.
	ErrSnapshotEncoding = errors.New("ldrcore: the bytes are not the canonical encoding of a coherent state")
)

// DecodeState decodes an encoded state of at most maxBytes. It accepts only
// the one canonical encoding of a coherent state. One comparison does most of
// that: the decoded state, encoded again, must give back exactly the bytes
// offered. An unknown field, a missing field, a set out of order, a
// duplicate, white space and trailing bytes all fail it. A missing tombstone
// list is a missing field; a list with entries removed is a different state,
// which only the commitment can tell from the right one.
func DecodeState(enc []byte, maxBytes int) (State, error) {
	if len(enc) > maxBytes {
		return State{}, fmt.Errorf("%w: %d bytes, budget %d", ErrSnapshotTooLarge, len(enc), maxBytes)
	}
	var s State
	if err := json.Unmarshal(enc, &s); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrSnapshotEncoding, err)
	}
	// JSON lets a null stand where an object belongs. No state has one, and
	// nothing below may be handed one.
	if s.hasNullObject() {
		return State{}, fmt.Errorf("%w: a null where an object belongs", ErrSnapshotEncoding)
	}
	if !bytes.Equal(EncodeState(s), enc) {
		return State{}, fmt.Errorf("%w: not in canonical form", ErrSnapshotEncoding)
	}
	// Canonical bytes can still encode a state no line can reach.
	if bad := s.CheckInvariants(); len(bad) > 0 {
		return State{}, fmt.Errorf("%w: %v", ErrSnapshotEncoding, bad)
	}
	return s, nil
}

// hasNullObject reports whether a decoded state holds a nil where one of its
// objects belongs. A dispute's resolution is the one object that may be
// absent.
func (s *State) hasNullObject() bool {
	for _, c := range s.Line.Credentials {
		if c == nil {
			return true
		}
	}
	for _, a := range s.Line.Actors {
		if a == nil {
			return true
		}
	}
	for _, w := range s.Line.RegisterWriters {
		if w == nil {
			return true
		}
	}
	for _, c := range s.Calls {
		if c == nil {
			return true
		}
		for _, d := range c.Disputes {
			if d == nil {
				return true
			}
		}
	}
	for _, b := range s.Broadcasts {
		if b == nil {
			return true
		}
	}
	return false
}

// SnapshotAt returns the encoded state after the record at seq, if this
// sequencer commits state and holds it. The copy is the caller's.
func (q *Sequencer) SnapshotAt(seq int64) ([]byte, bool) {
	enc, ok := q.snaps[seq]
	if !ok {
		return nil, false
	}
	return bytes.Clone(enc), true
}

// Entries returns deep copies of the committed records from..to, both
// included, as far as this sequencer's log holds them.
func (q *Sequencer) Entries(from, to int64) []Entry {
	var out []Entry
	for _, e := range q.log {
		if e.Seq >= from && e.Seq <= to {
			e.Record = e.Record.Clone()
			out = append(out, e)
		}
	}
	return out
}

// Enrollment returns the committed record that enrolled cred, if there is
// one. A credential identifier is enrolled at most once (spec section 6.2).
func (q *Sequencer) Enrollment(cred string) (Entry, bool) {
	for _, e := range q.log {
		if e.Record.Type == "credential_enroll" && e.Record.Cred == cred {
			e.Record = e.Record.Clone()
			return e, true
		}
	}
	return Entry{}, false
}

// ReplayVerified is full replay as a member holding the whole log would do
// it, with the checks Replay leaves to its caller: every frame links onto the
// one before; every signed record carries the signature of the principal it
// names, for this generation, over a head that is on this chain, and
// committed within its deadline under an operation identity that had not
// committed before; every record commits; and, where the profile commits
// state, every frame commits to the state derived here. It returns the state
// and the head it reached.
//
// It exists to be compared with Join. It replays a log that begins at
// genesis and does not model a generation change.
func ReplayVerified(lineID string, log []Entry, prof Profile) (State, string, error) {
	var s State
	head := genesisHead(lineID)
	ctx := newSignedContext()
	for _, e := range log {
		next, err := verifyFrame(lineID, prof, s, head, ctx, e)
		if err != nil {
			return State{}, "", err
		}
		s, head = next, e.Head
		ctx.record(&e, head)
	}
	return s, head, nil
}

// signedContext is what verifying a signed record needs besides the state and
// the head before it: the heads a record may name, each with its seq_time,
// and the operation identities that have committed. Apply does not see these.
// They belong to admission (spec 5.2, 5.3, 5.5), and a verifier that left
// them out would take whatever a relay chose to admit. Codex's probe of the
// first version of this file showed exactly that (call 0003, turn 27).
//
// It keeps everything it is given. A verifier that runs for long would drop
// what has retired: an anchor older than the head by more than the maximum
// validity can be named by nothing that is still admissible, and the
// identities under it can no longer be repeated.
type signedContext struct {
	anchors map[int64]anchor
	ops     map[OpKey]int64
}

// anchor is a head a signer may have named, with the seq_time recorded there.
type anchor struct {
	head string
	time int64
}

func newSignedContext() *signedContext {
	return &signedContext{anchors: map[int64]anchor{}, ops: map[OpKey]int64{}}
}

// record takes in a frame whose head is established: verified, or opened
// under a head that is (join.go).
func (x *signedContext) record(e *Entry, head string) {
	x.anchors[e.Seq] = anchor{head: head, time: e.SeqTime}
	if e.Record.Origin != OriginSequencer {
		x.ops[e.Key] = e.Seq
	}
}

// admitted re-checks, from recorded values alone, what admission decided
// when a signed record committed. The times are the relay's own: this shows
// that they are consistent with the record, not that they are true.
func (x *signedContext) admitted(lineID string, e *Entry) error {
	// One operation identity commits once, whether or not the bytes are the
	// same. A retry of committed bytes is answered with the original outcome
	// and appends nothing (spec 5.5).
	if at, again := x.ops[e.Key]; again {
		return fmt.Errorf("record %d (%s) repeats the operation identity that committed at %d", e.Seq, e.Record.Type, at)
	}
	if e.Record.Type == "line_init" {
		// The bootstrap exception: signed over genesis, exempt from validity.
		// It commits only as the first record, where the one sequence number
		// it can name is zero.
		if e.SeenHead != genesisHead(lineID) {
			return fmt.Errorf("record %d (line_init) is not signed over genesis", e.Seq)
		}
		return nil
	}
	a, held := x.anchors[e.Key.SeenSeq]
	switch {
	case !held:
		// Genesis is never held: only line_init is signed over it.
		return fmt.Errorf("record %d (%s) is anchored at %d, which is not a head this verifier holds", e.Seq, e.Record.Type, e.Key.SeenSeq)
	case a.head != e.SeenHead:
		// Evidence of divergent histories (spec 5.2).
		return fmt.Errorf("record %d was signed over a head that is not on this chain", e.Seq)
	case e.SeqTime-a.time > e.Record.ValidityMS:
		// The deadline is inclusive (spec 5.3). It is compared with the time
		// the record committed, never with the time of this replay: a record
		// that committed in time verifies for ever. A validity above the
		// maximum does not commit at all, which Apply checks.
		return fmt.Errorf("record %d (%s) committed %d ms after its anchor at %d, with a validity of %d ms",
			e.Seq, e.Record.Type, e.SeqTime-a.time, e.Key.SeenSeq, e.Record.ValidityMS)
	}
	return nil
}

// verifyFrame checks one frame against the state and the head before it and
// against what ctx holds, and returns the state after it. It changes nothing:
// the caller takes the frame into ctx once it has accepted it. It is the step
// Join, ReplayVerified and a member under a profile that commits state share.
func verifyFrame(lineID string, prof Profile, s State, head string, ctx *signedContext, e Entry) (State, error) {
	if e.Seq != s.Line.HeadSeq+1 {
		return State{}, fmt.Errorf("a record numbered %d follows the record numbered %d", e.Seq, s.Line.HeadSeq)
	}
	if e.Prev != head {
		return State{}, fmt.Errorf("record %d does not name the head before it", e.Seq)
	}
	if frameHead(&e) != e.Head {
		return State{}, fmt.Errorf("record %d does not chain onto the head before it", e.Seq)
	}
	signed := e.Record.Origin != OriginSequencer
	if !signed {
		if e.Sig != "" || e.SeenHead != "" || e.Key != (OpKey{}) {
			return State{}, fmt.Errorf("record %d is sequencer-origin and carries a signer's fields", e.Seq)
		}
	} else {
		signer := signerOf(&e.Record)
		if !signedBy(&e, signer) {
			return State{}, fmt.Errorf("record %d (%s) does not carry the signature of %q", e.Seq, e.Record.Type, signer)
		}
		if e.Key.Signer != signer || e.Key.SeenSeq >= e.Seq || e.Key.SeenSeq < 0 {
			return State{}, fmt.Errorf("record %d (%s) has an operation identity that does not fit it", e.Seq, e.Record.Type)
		}
		if err := ctx.admitted(lineID, &e); err != nil {
			return State{}, err
		}
	}
	next, out := Apply(s, e.Record, e.SeqTime, prof)
	if out.Kind != Committed {
		return State{}, fmt.Errorf("record %d (%s) does not commit on replay: %s %s", e.Seq, e.Record.Type, out.Kind, out.Reason)
	}
	// The generation is compared after the record is applied, because
	// line_init names the generation it creates.
	if signed && e.Key.Generation != next.Line.Generation {
		return State{}, fmt.Errorf("record %d (%s) was signed for another generation", e.Seq, e.Record.Type)
	}
	switch {
	case prof.StateCommit && StateDigest(lineID, prof, next) != e.StateDigest:
		return State{}, fmt.Errorf("record %d commits to a different state than the one derived", e.Seq)
	case !prof.StateCommit && e.StateDigest != "":
		return State{}, fmt.Errorf("record %d carries a state digest that this profile does not define", e.Seq)
	}
	return next, nil
}
