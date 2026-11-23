package ldrcore

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These tests exercise the state-commitment exploration (commit.go, join.go):
// one possible answer to the open question of how a new member comes by its
// starting state (spec section 13, O25). The attack cases are the ones Codex
// listed when it reviewed the idea (call 0003, turn 25). Two of them are
// expected to succeed: they mark where this route's trust ends, and they are
// named as limits.
//
// A signature is a computed stand-in here (Entry.Sig, signatureOf). It binds
// the signed fields, so a changed field shows, but anyone can compute it. A
// test that builds a frame by hand may compute it for a principal only if
// the party it plays holds that principal's key, or if the bytes are ones
// the principal really signed. Each such test says which.

// commitProfile is testProfile with state commitment switched on.
var commitProfile = Profile{FreshnessMS: testProfile.FreshnessMS, ValidityMaxMS: testProfile.ValidityMaxMS, StateCommit: true}

func activate(expect int64, readers ...string) Record {
	return Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", Manifest: readers,
		Expect: Expect{KeyEpoch: ptr(expect)}}
}

func revokeOperator(key string, rootRev int64) Record {
	return Record{Origin: OriginRoot, Type: "operator_key_revoke", OperatorKey: key, Expect: Expect{RootRev: ptr(rootRev)}}
}

// pinFor is what a device that asked to be enrolled as cred, by op1, holds
// before it is handed anything. It matches the enroll helper.
func pinFor(cred, ns, jr string) JoinPin {
	return JoinPin{
		LineID: "L", Generation: 1, Profile: commitProfile, RootKey: "rootK", Operator: "op1",
		Cred: cred, SigningKey: "sk-" + cred, EncryptionKey: "ek-" + cred,
		Grant:       Grant{Namespace: ns, ActorLimit: 4, Reader: true},
		JoinRequest: jr, JoinRequestDigest: "digest-" + jr,
	}
}

var pinC = pinFor("credC", "nsC", "jr3")

// joinLine is the twelve-record line under commitProfile, on which op1 has
// then enrolled credC, signing over the head at 12, and activated a key
// epoch that includes it. Fourteen records.
func joinLine(t *testing.T) *env {
	t.Helper()
	e := newLineWith(t, commitProfile)
	if _, seq := e.commit(enroll("credC", "nsC", "jr3")); seq != 13 {
		t.Fatalf("the enrollment committed at %d, want 13", seq)
	}
	e.commit(activate(2, "credA", "credB", "credC"))
	return e
}

func mustJoin(t *testing.T, pin JoinPin, relay JoinRelay, snaps SnapshotSource, now int64) *Joined {
	t.Helper()
	j, err := Join(pin, relay, snaps, At(now))
	if err != nil {
		t.Fatalf("the join did not finish: %v", err)
	}
	return j
}

func joinErr(t *testing.T, pin JoinPin, relay JoinRelay, snaps SnapshotSource, now int64) *JoinError {
	t.Helper()
	j, err := Join(pin, relay, snaps, At(now))
	var je *JoinError
	if !errors.As(err, &je) || j != nil {
		t.Fatalf("the join returned %v and %v, want a JoinError and nothing accepted", j, err)
	}
	return je
}

func wantRefused(t *testing.T, je *JoinError, part string) {
	t.Helper()
	text := je.Reason
	if je.Err != nil {
		text += ": " + je.Err.Error()
	}
	if je.Pending || !strings.Contains(text, part) {
		t.Fatalf("got %q (pending %v), want a refusal mentioning %q", text, je.Pending, part)
	}
}

func wantPending(t *testing.T, je *JoinError, part string) {
	t.Helper()
	if !je.Pending || !strings.Contains(je.Reason, part) {
		t.Fatalf("got %q (pending %v), want pending, mentioning %q", je.Reason, je.Pending, part)
	}
}

// snapshots is a snapshot source that is not the relay: whoever hands the
// joiner a state.
type snapshots map[int64][]byte

func (s snapshots) SnapshotAt(seq int64) ([]byte, bool) {
	b, ok := s[seq]
	return b, ok
}

// forger builds frames the way a party that is not bound by the rules can.
// It chooses each record, who signed it, and the state it claims the record
// produced. It answers a joiner as a relay and as a snapshot source.
type forger struct {
	t       *testing.T
	entries []Entry
	snaps   snapshots
	state   State
	head    string
	n       int
	// named, when set, is the head it names instead of its last one.
	named string
	// shown, when set, is what it shows as the enrollment.
	shown *Entry
	// withhold is how many of its last records it leaves out of Entries.
	withhold int
}

// forgeFrom starts a chain at an invented frame that commits to s. The frame
// claims to be the record numbered s.Line.HeadSeq. Before it stands one more
// invented frame, old enough to end the live window a joiner opens.
func forgeFrom(t *testing.T, s State) *forger {
	t.Helper()
	f := &forger{t: t, snaps: snapshots{}, head: "invented"}
	f.stale(s.Line.HeadSeq-1, s.Line.HeadTime)
	f.push(Entry{Seq: s.Line.HeadSeq, SeqTime: s.Line.HeadTime,
		Record: Record{Origin: OriginSequencer, Type: "time_anchor"}}, s, "")
	return f
}

// stale appends a frame numbered seq and stamped more than the maximum
// validity before the time given: a frame nothing later can name. It commits
// to no state anyone will ask for.
func (f *forger) stale(seq, before int64) {
	e := Entry{Seq: seq, SeqTime: before - commitProfile.ValidityMaxMS - 1, Prev: f.head,
		Record: Record{Origin: OriginSequencer, Type: "time_anchor"}, StateDigest: "0000000000000000"}
	e.Head = frameHead(&e)
	f.entries = append(f.entries, e)
	f.head = e.Head
}

// forgeOnto continues a real chain: entries are real records ending in the
// state s.
func forgeOnto(t *testing.T, entries []Entry, s State) *forger {
	t.Helper()
	return &forger{t: t, snaps: snapshots{}, entries: entries, state: s, head: entries[len(entries)-1].Head}
}

// at returns the forger's frame numbered seq, to be read or changed.
func (f *forger) at(seq int64) *Entry {
	f.t.Helper()
	for i := range f.entries {
		if f.entries[i].Seq == seq {
			return &f.entries[i]
		}
	}
	f.t.Fatalf("the forger has no frame numbered %d", seq)
	return nil
}

// frame appends an intent a member really signed, committed at the time
// given. The bytes are the member's own; the frame, its time and the state it
// claims are the forger's.
func (f *forger) frame(in Intent, at int64) Entry {
	f.t.Helper()
	rec := in.Record.Clone()
	rec.ValidityMS = in.ValidityMS
	next, out := Apply(f.state, rec, at, commitProfile)
	if out.Kind != Committed {
		f.t.Fatalf("the member's %s does not commit where the forger puts it: %s %s", rec.Type, out.Kind, out.Reason)
	}
	return f.push(Entry{Seq: next.Line.HeadSeq, SeqTime: at, Record: rec, SeenHead: in.SeenHead, Key: keyOf(in),
		Digest: in.Digest}, next, signerOf(&rec))
}

// push appends a frame that claims next as its state. edit, if given, runs
// before anything is signed or hashed, so a test can make the frame say
// something else. by, if not empty, is the principal that then signs the
// entry as it stands: the party the forger plays must hold that key, or the
// bytes must be ones that principal really signed. With by empty the entry
// keeps whatever signature it came with.
func (f *forger) push(e Entry, next State, by string, edit ...func(*Entry)) Entry {
	enc := EncodeState(next)
	e.Prev = f.head
	e.StateDigest = digestEncoded("L", commitProfile, enc)
	for _, fn := range edit {
		fn(&e)
	}
	if by != "" {
		e.Sig = signatureOf(by, &e)
	}
	e.Head = frameHead(&e)
	f.snaps[e.Seq] = enc
	f.entries = append(f.entries, e)
	f.state, f.head = next, e.Head
	return e
}

// sign appends r as an intent signed over the forger's current head, with
// the state the rules give, one millisecond after the record before it. by
// is the principal whose key signs, after edit has run; empty means the
// entry carries no signature.
func (f *forger) sign(r Record, by string, edit ...func(*Entry)) Entry {
	f.t.Helper()
	l := f.state.Line
	r.AuthEpoch, r.KeyEpoch, r.ValidityMS = l.AuthEpoch, l.KeyEpoch, testValidity
	if a := l.Actors[r.Actor]; r.Origin == OriginActor && a != nil {
		r.Cred, r.BindingGen = a.Cred, a.BindingGen
	}
	at := l.HeadTime + 1
	next, out := Apply(f.state, r, at, commitProfile)
	if out.Kind != Committed {
		f.t.Fatalf("the forger's %s does not commit: %s %s", r.Type, out.Kind, out.Reason)
	}
	f.n++
	return f.push(Entry{Seq: next.Line.HeadSeq, SeqTime: at, Record: r, SeenHead: f.head,
		Key:    OpKey{Generation: 1, Signer: signerOf(&r), SeenSeq: l.HeadSeq, OpID: fmt.Sprintf("f%d", f.n)},
		Digest: fmt.Sprintf("fd%d", f.n)}, next, by, edit...)
}

func (f *forger) AnchorRequest(string, Clock) (int64, string, bool, Answer) {
	last := f.entries[len(f.entries)-1]
	if f.named != "" {
		return last.Seq, f.named, false, Answer{}
	}
	return last.Seq, last.Head, false, Answer{}
}

func (f *forger) Enrollment(cred string) (Entry, bool) {
	if f.shown != nil {
		return *f.shown, true
	}
	for _, e := range f.entries {
		if e.Record.Type == "credential_enroll" && e.Record.Cred == cred {
			return e, true
		}
	}
	return Entry{}, false
}

func (f *forger) Entries(from, to int64) []Entry {
	var out []Entry
	held := f.entries[:len(f.entries)-f.withhold]
	for i := range held {
		if held[i].Seq >= from && held[i].Seq <= to {
			out = append(out, held[i])
		}
	}
	return out
}

func (f *forger) SnapshotAt(seq int64) ([]byte, bool) { return f.snaps.SnapshotAt(seq) }

// headNamer is a relay that names its head to anyone, whatever its state says
// about them.
type headNamer struct{ *Sequencer }

func (h headNamer) AnchorRequest(string, Clock) (int64, string, bool, Answer) {
	seq, head := h.Head()
	return seq, head, false, Answer{}
}

// relink recomputes Prev and Head from index i on, as a relay that changed a
// frame and built on it consistently would.
func relink(log []Entry, i int) {
	for ; i < len(log); i++ {
		if i > 0 {
			log[i].Prev = log[i-1].Head
		}
		log[i].Head = frameHead(&log[i])
	}
}

func TestStateCommitment(t *testing.T) {
	t.Run("with the switch off the chain is what it was", func(t *testing.T) {
		e := newLine(t)
		prev := genesisHead("L")
		for _, en := range e.q.Log() {
			if en.StateDigest != "" {
				t.Fatalf("record %d carries a state digest", en.Seq)
			}
			if want := chainHead(prev, en.Seq, en.SeqTime, en.Record.Type, en.Digest); en.Head != want || en.Prev != prev {
				t.Fatalf("record %d: head %s over %s, want %s over %s", en.Seq, en.Head, en.Prev, want, prev)
			}
			prev = en.Head
		}
		if _, ok := e.q.SnapshotAt(12); ok {
			t.Fatal("a sequencer that commits no state keeps snapshots")
		}
	})

	t.Run("every frame commits to the state after it", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		var s State
		for _, en := range e.q.Log() {
			next, out := Apply(s, en.Record, en.SeqTime, commitProfile)
			if out.Kind != Committed {
				t.Fatalf("record %d does not replay", en.Seq)
			}
			if en.StateDigest == "" || en.StateDigest != StateDigest("L", commitProfile, next) {
				t.Fatalf("record %d commits to %q, not to the state after it", en.Seq, en.StateDigest)
			}
			enc, ok := e.q.SnapshotAt(en.Seq)
			if !ok {
				t.Fatalf("no snapshot at %d", en.Seq)
			}
			got, err := DecodeState(enc, DefaultSnapshotBudget)
			if err != nil {
				t.Fatalf("the snapshot at %d does not decode: %v", en.Seq, err)
			}
			if d := diff(got, next); len(d) > 0 {
				t.Fatalf("the snapshot at %d is another state: %v", en.Seq, d)
			}
			// The head covers the digest.
			other := en
			other.StateDigest = "0000000000000000"
			if frameHead(&other) == en.Head {
				t.Fatalf("the head at %d does not depend on the state digest", en.Seq)
			}
			s = next
		}
		got, head, err := ReplayVerified("L", e.q.Log(), commitProfile)
		if err != nil {
			t.Fatalf("the log does not replay with its commitments: %v", err)
		}
		if _, want := e.q.Head(); head != want || len(diff(got, e.q.State())) > 0 {
			t.Fatal("verified replay ends somewhere else than the sequencer")
		}
	})

	t.Run("the digest is bound to the line and the profile", func(t *testing.T) {
		s := newLineWith(t, commitProfile).q.State()
		d := StateDigest("L", commitProfile, s)
		longer := commitProfile
		longer.ValidityMaxMS++
		if d == StateDigest("M", commitProfile, s) || d == StateDigest("L", longer, s) {
			t.Fatal("the same digest stands for a state on another line or under another profile")
		}
	})

	t.Run("a member stops at a frame that commits to another state", func(t *testing.T) {
		// A relay that derives something else at record 11 and builds on it
		// consistently. The member cannot say who is right; it stops, and
		// has no checkpoint there to sign over.
		log := newLineWith(t, commitProfile).q.Log()
		log[10].StateDigest = "feedfacefeedface"
		relink(log, 10)
		c := NewClient("L", "credA", commitProfile)
		var v *ViolationError
		if err := c.Sync(log); !errors.As(err, &v) || v.Seq != 11 || !strings.Contains(v.Reason, "different state") {
			t.Fatalf("got %v, want a violation at 11 about the state", err)
		}
		if ck, _ := c.Checkpoint(); ck != 10 || c.Halted() == "" {
			t.Fatalf("checkpoint %d, halted %q: want 10 and stopped", ck, c.Halted())
		}
		if _, _, err := ReplayVerified("L", log, commitProfile); err == nil {
			t.Fatal("verified replay accepts the same log")
		}
	})

	t.Run("a member under the other profile refuses the chain", func(t *testing.T) {
		with, without := newLineWith(t, commitProfile).q.Log(), newLine(t).q.Log()
		var v *ViolationError
		if err := NewClient("L", "credA", testProfile).Sync(with); !errors.As(err, &v) || v.Seq != 1 ||
			!strings.Contains(v.Reason, "does not define") {
			t.Fatalf("a profile without commitments took a frame that carries one: %v", err)
		}
		if err := NewClient("L", "credA", commitProfile).Sync(without); !errors.As(err, &v) || v.Seq != 1 {
			t.Fatalf("a profile with commitments took a frame that carries none: %v", err)
		}
	})
}

func TestStateEncoding(t *testing.T) {
	e := newLineWith(t, commitProfile)
	e.commit(revoke("credB"))
	s := e.q.State()
	enc := EncodeState(s)

	got, err := DecodeState(enc, len(enc))
	if err != nil {
		t.Fatalf("the encoding does not decode: %v", err)
	}
	if d := diff(got, s); len(d) > 0 || !bytes.Equal(EncodeState(got), enc) {
		t.Fatalf("the encoding does not round-trip: %v", d)
	}
	if _, err := DecodeState(enc, len(enc)-1); !errors.Is(err, ErrSnapshotTooLarge) {
		t.Fatalf("one byte over the budget: %v", err)
	}

	swap := func(old, new string) []byte {
		t.Helper()
		out := bytes.Replace(enc, []byte(old), []byte(new), 1)
		if bytes.Equal(out, enc) {
			t.Fatalf("the encoding does not contain %s", old)
		}
		return out
	}
	refused := map[string][]byte{
		"bytes after the state":              append(bytes.Clone(enc), []byte("{}")...),
		"white space":                        append(bytes.Clone(enc), ' '),
		"an unknown field":                   swap(`{"line":`, `{"extra":1,"line":`),
		"a missing tombstone set":            swap(`,"operator_keys":[]`, ``),
		"a set out of order":                 swap(`"join_requests":["jr1","jr2"]`, `"join_requests":["jr2","jr1"]`),
		"a set with a duplicate":             swap(`"join_requests":["jr1","jr2"]`, `"join_requests":["jr1","jr1","jr2"]`),
		"a counter out of domain":            swap(`"root_rev":2`, `"root_rev":-1`),
		"a number that is not an integer":    swap(`"root_rev":2`, `"root_rev":2.0`),
		"a revocation without its tombstone": swap(`"creds":["credB"]`, `"creds":[]`),
		"half a state":                       enc[:len(enc)/2],
		"nothing":                            nil,
	}
	for name, b := range refused {
		if _, err := DecodeState(b, DefaultSnapshotBudget); !errors.Is(err, ErrSnapshotEncoding) {
			t.Errorf("%s: got %v, want ErrSnapshotEncoding", name, err)
		}
	}

	// A tombstone removed where no invariant ties it to anything is a
	// coherent state. Only the commitment tells it from the right one.
	fewer := swap(`"join_requests":["jr1","jr2"]`, `"join_requests":["jr2"]`)
	if _, err := DecodeState(fewer, DefaultSnapshotBudget); err != nil {
		t.Fatalf("a state with one tombstone fewer does not decode: %v", err)
	}
	if digestEncoded("L", commitProfile, fewer) == digestEncoded("L", commitProfile, enc) {
		t.Fatal("the commitment does not tell a state from the same state with a tombstone removed")
	}
}

func TestJoin(t *testing.T) {
	t.Run("an enrolled credential starts from the endorsed state", func(t *testing.T) {
		e := joinLine(t)
		j := mustJoin(t, pinC, e.q, e.q, e.now)
		seq, head := e.q.Head()
		if j.Seq != seq || j.Head != head || seq != 14 {
			t.Fatalf("accepted checkpoint %d %s, want %d %s", j.Seq, j.Head, seq, head)
		}
		if d := diff(j.State, e.q.State()); len(d) > 0 {
			t.Fatalf("the accepted state is not the line's: %v", d)
		}
		head12, known := e.q.HeadAt(12)
		// The line is younger than the maximum validity, so the live window
		// reaches back to its first record.
		want := Provenance{Operator: "op1", EndorsedSeq: 12, EndorsedHead: head12, WindowSeq: 1, EnrollSeq: 13}
		if !known || j.Provenance != want {
			t.Fatalf("provenance %+v, want %+v", j.Provenance, want)
		}
		// The same state a member that replayed everything holds.
		full, fullHead, err := ReplayVerified("L", e.q.Log(), commitProfile)
		if err != nil || fullHead != j.Head || len(diff(j.State, full)) > 0 {
			t.Fatalf("full replay disagrees with the join: %v", err)
		}
	})

	t.Run("the relay names a fresh head and the joiner verifies up to it", func(t *testing.T) {
		e := joinLine(t)
		e.now += commitProfile.FreshnessMS + 1
		j := mustJoin(t, pinC, e.q, e.q, e.now)
		last := e.q.Log()[14]
		if j.Seq != 15 || last.Record.Type != "time_anchor" || j.Head != last.Head {
			t.Fatalf("accepted at %d; the relay's last record is a %s at %d", j.Seq, last.Record.Type, last.Seq)
		}
	})

	t.Run("records between the endorsed head and the enrollment are replayed", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		early := e.intent(note("a1")) // signed over the head at 12, sent late
		e.commit(note("b1"))          // 13
		en := e.intent(enroll("credC", "nsC", "jr3"))
		if en.SeenSeq != 13 {
			t.Fatalf("the enrollment is signed over %d, want 13", en.SeenSeq)
		}
		// 14 is anchored before the endorsed head. The joiner checks the head
		// it names, and its deadline, against the live window.
		e.wantOutcome(e.submit(early), Committed, "", false)
		e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credB", Namespace: "nsB", Actor: "b2"})
		e.commit(activate(2, "credA", "credB")) // 16: an epoch change before the enrollment
		e.now++
		e.wantOutcome(e.submit(en), Committed, "", false) // 17
		e.commit(activate(3, "credA", "credB", "credC"))

		j := mustJoin(t, pinC, e.q, e.q, e.now)
		head13, _ := e.q.HeadAt(13)
		want := Provenance{Operator: "op1", EndorsedSeq: 13, EndorsedHead: head13, WindowSeq: 1, EnrollSeq: 17}
		if j.Provenance != want || j.Seq != 18 {
			t.Fatalf("provenance %+v at %d, want %+v at 18", j.Provenance, j.Seq, want)
		}
		if d := diff(j.State, e.q.State()); len(d) > 0 {
			t.Fatalf("the accepted state is not the line's: %v", d)
		}
	})

	t.Run("a credential that reads nothing needs no key epoch", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		r := enroll("credC", "nsC", "jr3")
		r.Grant.Reader = false
		e.commit(r)
		pin := pinC
		pin.Grant.Reader = false
		if j := mustJoin(t, pin, e.q, e.q, e.now); j.Seq != 13 {
			t.Fatalf("accepted at %d, want 13", j.Seq)
		}
	})

	t.Run("pending, never a substitute", func(t *testing.T) {
		// Not enrolled: the operator invented a commit the relay never made.
		e := newLineWith(t, commitProfile)
		wantPending(t, joinErr(t, pinC, e.q, e.q, e.now), "named no head")

		// Enrolled, no key epoch for it yet.
		e.commit(enroll("credC", "nsC", "jr3"))
		wantPending(t, joinErr(t, pinC, e.q, e.q, e.now), "no key epoch")

		// No snapshot of the endorsed head. The relay's later snapshots are
		// not taken in its place.
		e.commit(activate(2, "credA", "credB", "credC"))
		wantPending(t, joinErr(t, pinC, e.q, snapshots{}, e.now), "no snapshot of the endorsed head")
		later, _ := e.q.SnapshotAt(13)
		wantRefused(t, joinErr(t, pinC, e.q, snapshots{12: later}, e.now), "not the state the endorsed head commits to")

		// The relay cannot evaluate: nothing is named.
		if je := joinErr(t, pinC, e.q, e.q, -1); !je.Pending {
			t.Fatalf("an untrusted clock at the relay: %v", je)
		}
		mustJoin(t, pinC, e.q, e.q, e.now)
	})

	t.Run("the enrollment must be the one this device asked for", func(t *testing.T) {
		e := joinLine(t)
		cases := map[string]struct {
			edit func(*JoinPin)
			part string
		}{
			"another operator":               {func(p *JoinPin) { p.Operator = "op2" }, "another operator"},
			"another signing key":            {func(p *JoinPin) { p.SigningKey = "sk-other" }, "keys this device requested"},
			"another encryption key":         {func(p *JoinPin) { p.EncryptionKey = "ek-other" }, "keys this device requested"},
			"another join request":           {func(p *JoinPin) { p.JoinRequest = "jr9" }, "another join request"},
			"another request digest":         {func(p *JoinPin) { p.JoinRequestDigest = "digest-jr9" }, "another join request"},
			"another namespace":              {func(p *JoinPin) { p.Grant.Namespace = "nsX" }, "grants something other"},
			"another actor limit":            {func(p *JoinPin) { p.Grant.ActorLimit = 5 }, "grants something other"},
			"no reader grant":                {func(p *JoinPin) { p.Grant.Reader = false }, "grants something other"},
			"another generation":             {func(p *JoinPin) { p.Generation = 2 }, "another generation"},
			"another root key":               {func(p *JoinPin) { p.RootKey = "rootX" }, "another root key"},
			"another line":                   {func(p *JoinPin) { p.LineID = "M" }, "not the state the endorsed head commits to"},
			"a profile that commits nothing": {func(p *JoinPin) { p.Profile = testProfile }, "does not commit state"},
		}
		for name, c := range cases {
			pin := pinC
			c.edit(&pin)
			je := joinErr(t, pin, e.q, e.q, e.now)
			if je.Pending || !strings.Contains(je.Reason, c.part) {
				t.Errorf("%s: got %q (pending %v), want a refusal mentioning %q", name, je.Reason, je.Pending, c.part)
			}
		}
	})

	t.Run("a snapshot is believed only as far as the endorsed head commits to it", func(t *testing.T) {
		e := joinLine(t)
		real, _ := e.q.SnapshotAt(12)

		// The enrolling operator's device hands over another state for the
		// head it really signed over: one more turn on c1, which nobody took.
		s, err := DecodeState(real, DefaultSnapshotBudget)
		if err != nil {
			t.Fatal(err)
		}
		s.Calls["c1"].TurnCount++
		s.Calls["c1"].LastTurnFrom = "a1"
		wantRefused(t, joinErr(t, pinC, e.q, snapshots{12: EncodeState(s)}, e.now), "not the state the endorsed head commits to")

		// Bytes changed on the way.
		bent := bytes.Clone(real)
		bent[len(bent)/2] ^= 1
		wantRefused(t, joinErr(t, pinC, e.q, snapshots{12: bent}, e.now), "not the state the endorsed head commits to")

		// A state over the joiner's budget is refused before it is looked at.
		small := pinC
		small.MaxSnapshotBytes = len(real) - 1
		je := joinErr(t, small, e.q, e.q, e.now)
		wantRefused(t, je, "over this joiner's budget")
		if !errors.Is(je, ErrSnapshotTooLarge) {
			t.Fatalf("over budget: %v", je)
		}
		small.MaxSnapshotBytes = len(real)
		mustJoin(t, small, e.q, e.q, e.now)
	})

	t.Run("a revoked joiner is not accepted", func(t *testing.T) {
		e := joinLine(t)
		e.commit(revoke("credC"))
		wantRefused(t, joinErr(t, pinC, e.q, e.q, e.now), "relay says this credential is revoked")
		// A relay that names a head all the same: the records say it too.
		wantRefused(t, joinErr(t, pinC, headNamer{e.q}, e.q, e.now), "revoked before the join was accepted")
	})

	t.Run("an endorser revoked after the enrollment committed is a stated policy", func(t *testing.T) {
		e := joinLine(t)
		_, at := e.commit(revokeOperator("op1", 2))
		wantRefused(t, joinErr(t, pinC, e.q, e.q, e.now), "revoked at 15, after the enrollment committed at 13")

		// Later records do not move the position the provenance records.
		e.commit(note("a1"))
		ordered := pinC
		ordered.OnEndorserRevoked = EndorserRevokedAccept
		j := mustJoin(t, ordered, e.q, e.q, e.now)
		if j.EndorserRevokedAt != at || at != 15 || j.Seq != 16 {
			t.Fatalf("the provenance records a revocation at %d, want %d, accepted at %d", j.EndorserRevokedAt, at, j.Seq)
		}
	})

	t.Run("an endorser revoked before the enrollment commits endorses nothing", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		in := e.intent(enroll("credC", "nsC", "jr3")) // op1 signs over the head at 12
		e.commit(revokeOperator("op1", 2))            // 13
		e.now++
		e.want(e.submit(in), ClassUnresolved, "revoked")
		wantPending(t, joinErr(t, pinC, e.q, e.q, e.now), "named no head")

		// A relay that commits the enrollment regardless. It holds no key:
		// the enrollment is the operator's own bytes, and the state it claims
		// is one the rules do not give.
		f := forgeOnto(t, e.q.Log(), e.q.State())
		forced := e.q.State()
		forced.Line.Credentials["credC"] = &Credential{SigningKey: "sk-credC", EncryptionKey: "ek-credC", Namespace: "nsC", ActorLimit: 4}
		forced.Line.Tombstones.JoinRequests = addToSet(forced.Line.Tombstones.JoinRequests, "jr3")
		forced.Line.HeadSeq, forced.Line.HeadTime = 14, e.now
		rec := in.Record
		rec.ValidityMS = in.ValidityMS
		f.push(Entry{Seq: 14, SeqTime: e.now, Record: rec, SeenHead: in.SeenHead, Key: keyOf(in), Digest: in.Digest}, forced, "op:op1")
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "does not commit on replay")
	})
}

// TestJoinAgainstADishonestRelay: the operator's device is honest and its key
// is safe; the relay is not bound by the rules and holds no member's key.
func TestJoinAgainstADishonestRelay(t *testing.T) {
	// start gives a forger the real log: the enrollment is at 13 and the key
	// epoch at 14.
	start := func(t *testing.T) (*env, *forger) {
		e := joinLine(t)
		return e, forgeOnto(t, e.q.Log(), e.q.State())
	}

	t.Run("it cannot put another state under the head the operator signed over", func(t *testing.T) {
		e := joinLine(t)
		real := e.q.Entries(12, 14)
		// The real record at 12 under the relay's own commitment, to a state
		// of its choosing, with the real enrollment after it. The relay
		// supplies the matching snapshot itself.
		enc, _ := e.q.SnapshotAt(12)
		other, err := DecodeState(enc, DefaultSnapshotBudget)
		if err != nil {
			t.Fatal(err)
		}
		other.Calls["c1"].TurnCount++
		other.Calls["c1"].LastTurnFrom = "a1"
		g := &forger{t: t, snaps: snapshots{}, head: real[0].Prev}
		g.push(real[0], other, "")
		g.entries = append(g.entries, real[1:]...)
		wantRefused(t, joinErr(t, pinC, g, g, e.now), "does not open the head the operator signed over")
	})

	t.Run("it cannot add a record no member signed", func(t *testing.T) {
		e, f := start(t)
		// A turn by a1, which the relay cannot sign.
		f.sign(turn("a1", 2), "")
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "does not carry the signature")
	})

	t.Run("it cannot commit to a state the records do not give", func(t *testing.T) {
		e, f := start(t)
		f.sign(note("a1"), "cred:credA", func(en *Entry) { en.StateDigest = "feedfacefeedface" })
		// The note is real in this test's premise; only the commitment is the
		// relay's own.
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "commits to a different state")
	})

	t.Run("it cannot show a record signed over another history", func(t *testing.T) {
		e, f := start(t)
		f.sign(note("a1"), "cred:credA", func(en *Entry) { en.SeenHead = "0123456789abcdef" })
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "signed over a head that is not on this chain")
	})

	t.Run("it cannot name a head its records do not reach", func(t *testing.T) {
		e, f := start(t)
		f.named = "0123456789abcdef"
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "do not reach the head the relay named")
		f.named = ""
		f.withhold = 1
		wantPending(t, joinErr(t, pinC, f, e.q, e.now), "supplied 2 of the 3 records")
	})

	t.Run("it cannot show one enrollment and commit another", func(t *testing.T) {
		// The operator signed the same enrollment twice, which gives two
		// different sets of bytes (spec 5.1). The relay committed one and
		// shows the other. Both signatures are the operator's own.
		e, f := start(t)
		shown := *f.at(13)
		shown.Digest = "another-copy"
		shown.Sig = signatureOf("op:op1", &shown)
		f.shown = &shown
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "is not the enrollment the relay showed")
	})

	t.Run("it cannot point the operator's endorsement at another head", func(t *testing.T) {
		// The real enrollment, altered to name a frame of the relay's own
		// making. The head named is a signed field.
		e := joinLine(t)
		enc, _ := e.q.SnapshotAt(12)
		other, err := DecodeState(enc, DefaultSnapshotBudget)
		if err != nil {
			t.Fatal(err)
		}
		other.Calls["c1"].TurnCount++
		other.Calls["c1"].LastTurnFrom = "a1"
		g := forgeFrom(t, other)
		moved, _ := e.q.Enrollment("credC")
		moved.SeenHead = g.head
		next, out := Apply(other, moved.Record, moved.SeqTime, commitProfile)
		if out.Kind != Committed {
			t.Fatalf("the enrollment does not apply to the relay's state: %s %s", out.Kind, out.Reason)
		}
		g.push(moved, next, "")
		wantRefused(t, joinErr(t, pinC, g, g, e.now), "does not carry the pinned operator's signature")
	})

	t.Run("it cannot alter a record a member signed", func(t *testing.T) {
		// The key epoch's manifest, changed after the operator signed it. The
		// frame's head does not cover the record's fields in this model; the
		// signature does.
		e, f := start(t)
		f.at(14).Record.Manifest = []string{"credA", "credC"}
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "record 14 (key_epoch_activate) does not carry the signature")
		// The same for each part of its operation identity.
		for name, alter := range map[string]func(*OpKey){
			"op_id":      func(k *OpKey) { k.OpID = "another" },
			"generation": func(k *OpKey) { k.Generation = 2 },
			"seen_seq":   func(k *OpKey) { k.SeenSeq = 12 },
			"signer":     func(k *OpKey) { k.Signer = "op:op2" },
		} {
			_, g := start(t)
			alter(&g.at(14).Key)
			je := joinErr(t, pinC, g, e.q, e.now)
			if je.Pending || je.Err == nil || !strings.Contains(je.Err.Error(), "record 14 (key_epoch_activate) does not carry the signature") {
				t.Errorf("%s altered: %v", name, je)
			}
		}
	})

	t.Run("it cannot enroll a joiner the operator did not", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.sign(enroll("credC", "nsC", "jr3"), "") // no operator key
		wantRefused(t, joinErr(t, pinC, f, e.q, e.now), "does not carry the pinned operator's signature")
	})
}

// TestJoinTrustLimits holds the two cases Join cannot refuse. They pass when
// the attack succeeds.
func TestJoinTrustLimits(t *testing.T) {
	// fabricate is what a party holding op1's key can build with no relay at
	// all: a state of its choosing, a frame committing to it, an enrollment
	// of credC signed over that frame's head, and a key epoch. Here the
	// state is the line's own at 12 with one more turn on c1, by a1, which
	// a1 never took.
	fabricate := func(t *testing.T) (*env, *forger) {
		e := newLineWith(t, commitProfile)
		invented := e.q.State()
		invented.Calls["c1"].TurnCount = 3
		invented.Calls["c1"].LastTurnFrom = "a1"
		f := forgeFrom(t, invented)
		f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		return e, f
	}

	t.Run("the operator's key and the relay together", func(t *testing.T) {
		// The attacker holds op1's key and is the relay the joiner pinned.
		e, f := fabricate(t)
		j := mustJoin(t, pinC, f, f, e.now)
		if c := j.State.Calls["c1"]; c.TurnCount != 3 || c.LastTurnFrom != "a1" {
			t.Fatalf("the joiner did not take the invented turn: %+v", c)
		}
		if real := e.q.State().Calls["c1"]; real.TurnCount != 2 {
			t.Fatalf("the real call has %d turns", real.TurnCount)
		}

		// Replay from genesis is not taken in by the same two parties. To
		// give that state a history they need a1's turn, and they cannot
		// sign it.
		h := forgeOnto(t, e.q.Log(), e.q.State())
		h.sign(turn("a1", 2), "op:op1") // the only key they hold
		h.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		h.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		if _, _, err := ReplayVerified("L", h.entries, commitProfile); err == nil ||
			!strings.Contains(err.Error(), "record 13 (call_turn) does not carry the signature") {
			t.Fatalf("replay from genesis: %v, want a refusal at the invented turn", err)
		}
		// The joiner does not take that history either, though it replays
		// nothing at or before the endorsed head. The invented turn is in the
		// live window, where the joiner checks that each record is what its
		// signer signed. That costs the two parties nothing: they put the
		// invented state under a record of their own instead, as above.
		wantRefused(t, joinErr(t, pinC, h, h, e.now), "record at 13, in the live window, is not what its signer signed")
		// One record later it is inside what the joiner replays, and the
		// joiner refuses it there.
		k := forgeOnto(t, e.q.Log(), e.q.State())
		k.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		k.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		k.sign(turn("a1", 2), "op:op1")
		wantRefused(t, joinErr(t, pinC, k, e.q, e.now), "record 15 (call_turn) does not carry the signature")
	})

	t.Run("the enrolling device also says where the relay is", func(t *testing.T) {
		// The relay is honest and never saw this enrollment. The attacker
		// holds op1's key only. A joiner that asks the real relay accepts
		// nothing.
		e, f := fabricate(t)
		wantPending(t, joinErr(t, pinC, e.q, f, e.now), "named no head")
		// A joiner that took the relay's address from the enrolling device
		// is asking the attacker. Nothing in what it receives differs from
		// the case above.
		if j := mustJoin(t, pinC, f, f, e.now); j.State.Calls["c1"].TurnCount != 3 {
			t.Fatal("the joiner did not take the invented state")
		}
	})
}
