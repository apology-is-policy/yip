package ldrcore

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

// These tests execute the scenario traces of docs/LDR-CONFORMANCE-VECTORS.json
// that the sequencer model can reach. Each is registered under its trace ID
// in traceTests, and TestTraceCoverageLabels checks that table against the
// labels in the file.

var testProfile = Profile{FreshnessMS: 10000, ValidityMaxMS: 600000}

const testValidity = 60000

type env struct {
	t   *testing.T
	q   *Sequencer
	now int64
	n   int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{t: t, q: NewSequencer("L", testProfile), now: 1000000}
}

// intent builds an intent for r anchored on the current head, filling the
// epochs and the binding from current state so a test states only what it is
// about. A test that wants a stale value sets it on the returned intent.
func (e *env) intent(r Record) Intent {
	l := e.q.State().Line
	r.AuthEpoch, r.KeyEpoch = l.AuthEpoch, l.KeyEpoch
	if r.Origin == OriginActor {
		if a := l.Actors[r.Actor]; a != nil {
			r.Cred, r.BindingGen = a.Cred, a.BindingGen
		}
	}
	seq, head := e.q.Head()
	e.n++
	gen := e.q.Generation()
	if gen == 0 {
		gen = 1 // line_init names the generation it creates
	}
	return Intent{LineID: "L", Generation: gen, OpID: fmt.Sprintf("o%d", e.n), SeenSeq: seq, SeenHead: head,
		ValidityMS: testValidity, Digest: fmt.Sprintf("d%d", e.n), SignatureOK: true, Record: r}
}

func keyOf(in Intent) OpKey {
	return OpKey{Generation: in.Generation, Signer: signerOf(&in.Record), SeenSeq: in.SeenSeq, OpID: in.OpID}
}

func (e *env) submit(in Intent) Answer { return e.q.Submit(in, At(e.now)) }

// commit submits r one millisecond later and requires it to commit.
func (e *env) commit(r Record) (Intent, int64) {
	e.t.Helper()
	e.now++
	in := e.intent(r)
	a := e.submit(in)
	if a.Class != ClassOutcome || a.Outcome.Kind != Committed {
		e.t.Fatalf("%s: got %s, want committed", r.Type, showAnswer(a))
	}
	return in, a.Seq
}

func showAnswer(a Answer) string {
	switch a.Class {
	case ClassOutcome:
		s := describe(a.Outcome.Kind, a.Outcome.Reason)
		if a.Outcome.Kind == Committed {
			s += fmt.Sprintf(" at seq %d", a.Seq)
		}
		if a.Original {
			s += " (original)"
		}
		return s
	case ClassMismatch:
		return ClassMismatch
	}
	return a.Class + " " + a.Code
}

func (e *env) wantOutcome(a Answer, kind, reason string, original bool) {
	e.t.Helper()
	if a.Class != ClassOutcome || a.Outcome.Kind != kind || a.Outcome.Reason != reason || a.Original != original {
		want := describe(kind, reason)
		if original {
			want += " (original)"
		}
		e.t.Fatalf("got %s, want %s", showAnswer(a), want)
	}
}

func (e *env) want(a Answer, class, code string) {
	e.t.Helper()
	if a.Class != class || a.Code != code {
		e.t.Fatalf("got %s, want %s %s", showAnswer(a), class, code)
	}
}

// checkReplay is the client's view: replaying the log from genesis must give
// exactly the state the sequencer holds, and that state must be coherent.
func (e *env) checkReplay() {
	e.t.Helper()
	got, err := Replay(e.q.Log(), testProfile)
	if err != nil {
		e.t.Fatalf("the log does not replay: %v", err)
	}
	if d := diff(got, e.q.State()); len(d) > 0 {
		e.t.Fatalf("replaying the log gives a different state:\n  %v", d)
	}
	if bad := e.q.State().CheckInvariants(); len(bad) > 0 {
		e.t.Fatalf("the sequencer's state is not coherent: %v", bad)
	}
	var last int64
	for _, entry := range e.q.Log() {
		if entry.SeqTime < last {
			e.t.Fatalf("seq_time decreases at seq %d", entry.SeqTime)
		}
		last = entry.SeqTime
	}
}

func actorRec(typ, actor string) Record { return Record{Origin: OriginActor, Type: typ, Actor: actor} }

func turn(actor string, count int64) Record {
	r := actorRec("call_turn", actor)
	r.Call, r.Expect.TurnCount = "c1", ptr(count)
	return r
}

func bye(actor string, turns, lifecycle int64) Record {
	r := actorRec("call_bye", actor)
	r.Call, r.Expect.TurnCount, r.Expect.LifecycleRev = "c1", ptr(turns), ptr(lifecycle)
	return r
}

func note(actor string) Record {
	r := actorRec("call_note", actor)
	r.Call = "c1"
	return r
}

func reopen(actor string, lifecycle, turns int64) Record {
	r := actorRec("call_status", actor)
	r.Call, r.State, r.Expect.LifecycleRev, r.Expect.TurnCount = "c1", "open", ptr(lifecycle), ptr(turns)
	return r
}

func enroll(cred, ns, jr string) Record {
	return Record{Origin: OriginOperator, Type: "credential_enroll", Operator: "op1", Cred: cred, JoinRequest: jr,
		Grant: &Grant{Namespace: ns, ActorLimit: 4, Reader: true}}
}

func revoke(cred string) Record {
	return Record{Origin: OriginOperator, Type: "credential_revoke", Operator: "op1", Cred: cred}
}

// newLine builds a small line entirely through the sequencer, from line_init:
// operator op1; credentials credA (actors a1, a2) and credB (actor b1), both
// readers of key epoch 2; call c1 from a1 to b1 with two turns, so the floor
// is a1's; and broadcast bc1 to a1 and b1. Twelve records.
func newLine(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.commit(Record{Origin: OriginRoot, Type: "line_init"})
	e.commit(Record{Origin: OriginRoot, Type: "operator_key_authorize", OperatorKey: "op1", Expect: Expect{RootRev: ptr(1)}})
	e.commit(enroll("credA", "nsA", "jr1"))
	e.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", Manifest: []string{"credA"}, Expect: Expect{KeyEpoch: ptr(0)}})
	e.commit(enroll("credB", "nsB", "jr2"))
	e.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", Manifest: []string{"credA", "credB"}, Expect: Expect{KeyEpoch: ptr(1)}})
	for _, a := range []struct{ cred, ns, id string }{{"credA", "nsA", "a1"}, {"credA", "nsA", "a2"}, {"credB", "nsB", "b1"}} {
		e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: a.cred, Namespace: a.ns, Actor: a.id})
	}
	open := actorRec("call_open", "a1")
	open.Call, open.To = "c1", "b1"
	e.commit(open)
	e.commit(turn("b1", 1))
	e.commit(Record{Origin: OriginOperator, Type: "broadcast_create", Operator: "op1", Broadcast: "bc1", Kind: "briefing", Recipients: []string{"a1", "b1"}})
	if seq, _ := e.q.Head(); seq != 12 {
		t.Fatalf("base line has %d records, want 12", seq)
	}
	e.checkReplay()
	return e
}

// closeCall leaves c1 with both byes standing, so its status is resolved.
func (e *env) closeCall() {
	e.t.Helper()
	e.commit(bye("a1", 2, 0))
	e.commit(bye("b1", 2, 0))
}

// retire moves the clock just past the retirement of the anchor at seq and
// compacts.
func (e *env) retire(seq int64) int {
	e.t.Helper()
	e.now = e.q.seqTime(seq) + testProfile.ValidityMaxMS + 1
	return e.q.Compact(At(e.now))
}

var traceTests = map[string]func(*testing.T){
	"T01": func(t *testing.T) { // identical retry
		e := newLine(t)
		in, seq := e.commit(turn("a1", 2))
		logLen := len(e.q.Log())
		e.wantOutcome(e.submit(in), Committed, "", true)
		if a := e.submit(in); a.Seq != seq || len(e.q.Log()) != logLen {
			t.Fatalf("a retry committed again: seq %d, log %d -> %d", a.Seq, logLen, len(e.q.Log()))
		}
		e.checkReplay()
	},
	"T02": func(t *testing.T) { // same identity, different bytes
		e := newLine(t)
		in, _ := e.commit(turn("a1", 2))
		other := in
		other.Digest = "different-bytes"
		e.want(e.submit(other), ClassMismatch, "")
		if n := e.retire(in.SeenSeq); n == 0 || e.q.HotEntries() != 0 {
			t.Fatalf("compaction left %d hot entries after discarding %d", e.q.HotEntries(), n)
		}
		// The log index keeps committed operations, so the mismatch survives.
		e.want(e.submit(other), ClassMismatch, "")
		e.checkReplay()
	},
	"T03": func(t *testing.T) { // a rejection is stable; a new operation is not bound by it
		e := newLine(t)
		e.closeCall()
		rejected := e.intent(turn("a1", 2))
		e.wantOutcome(e.submit(rejected), Rejected, "not_open", false)
		e.commit(reopen("b1", 0, 2))
		if s := e.q.State().Calls["c1"]; s.Status() != "open" || s.Floor() != "a1" || s.TurnCount != 2 {
			t.Fatalf("after the reopen: status %s, floor %s, turns %d", s.Status(), s.Floor(), s.TurnCount)
		}
		// A fresh evaluation of the same fields would now commit. The same
		// bytes are never evaluated afresh.
		e.wantOutcome(e.submit(rejected), Rejected, "not_open", true)
		e.commit(turn("a1", 2))
		e.checkReplay()
	},
	"T04": func(t *testing.T) { // commit, lost receipt, retry after the anchor retires
		e := newLine(t)
		in, seq := e.commit(turn("a1", 2))
		e.retire(in.SeenSeq)
		a := e.submit(in)
		e.wantOutcome(a, Committed, "", true)
		if a.Seq != seq {
			t.Fatalf("receipt from the log index names seq %d, want %d", a.Seq, seq)
		}
	},
	"T05": func(t *testing.T) { // never arrived, retried after validity
		e := newLine(t)
		late := e.intent(turn("a1", 2))
		hot := e.q.HotEntries()
		e.now += testValidity + 1
		e.want(e.submit(late), ClassRefusal, "expired")
		if e.q.HotEntries() != hot {
			t.Fatalf("an expired refusal left an index entry: %d hot entries, was %d", e.q.HotEntries(), hot)
		}
		// A deliberately new intent needs a fresh anchor on a quiet line.
		if _, _, wrote, a := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); a.Class != "" || !wrote {
			t.Fatalf("anchor request: wrote=%v %s", wrote, showAnswer(a))
		}
		e.commit(turn("a1", 2))
		e.checkReplay()
	},
	"T06": func(t *testing.T) { // an admission error promises nothing
		e := newLine(t)
		in := e.intent(turn("a1", 2))
		hot := e.q.HotEntries()
		e.q.Overloaded = true
		e.want(e.submit(in), ClassAdmission, "overloaded")
		if e.q.HotEntries() != hot {
			t.Fatal("an admission error left an index entry")
		}
		e.q.Overloaded = false
		e.wantOutcome(e.submit(in), Committed, "", false)
		e.wantOutcome(e.q.Query(CredentialPrincipal("credA"), keyOf(in), in.Digest, At(e.now)), Committed, "", true)
		e.checkReplay()
	},
	"T07": func(t *testing.T) { // quiet line: anchor before writing
		e := newLine(t)
		stale := e.intent(turn("a1", 2))
		e.now += 3600000
		e.want(e.submit(stale), ClassRefusal, "expired")
		head, _ := e.q.Head()
		seq, _, wrote, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now))
		if !wrote || seq != head+1 || e.q.Log()[seq-1].SeqTime != e.now {
			t.Fatalf("anchor: wrote=%v seq=%d", wrote, seq)
		}
		fresh := e.intent(turn("a1", 2))
		e.now += 2000
		e.wantOutcome(e.submit(fresh), Committed, "", false)
		e.checkReplay()
	},
	"T08": func(t *testing.T) { // anchor requests coalesce
		e := newLine(t)
		e.now += 20000
		first, _, wrote, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now))
		if !wrote {
			t.Fatal("no anchor written for a head older than F")
		}
		again, _, wrote, _ := e.q.AnchorRequest(CredentialPrincipal("credB"), At(e.now+3000))
		if wrote || again != first {
			t.Fatalf("a second request inside F wrote=%v and named seq %d, want %d", wrote, again, first)
		}
		e.now += 20000
		x, _, w1, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now))
		y, _, w2, _ := e.q.AnchorRequest(CredentialPrincipal("credB"), At(e.now))
		if !w1 || w2 || x != y || x != first+1 {
			t.Fatalf("two requests at once: wrote %v,%v named %d,%d", w1, w2, x, y)
		}
		e.checkReplay()
	},
	"T09": func(t *testing.T) { // a later anchor does not extend an old intent
		e := newLine(t)
		held := e.intent(turn("a1", 2))
		e.now += 3600000
		if _, _, wrote, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); !wrote {
			t.Fatal("no anchor written")
		}
		e.now += 1000
		e.want(e.submit(held), ClassRefusal, "expired")
	},
	"T10": func(t *testing.T) { // an operator can anchor a line with no active credential
		e := newLine(t)
		e.commit(revoke("credA"))
		e.commit(revoke("credB"))
		e.now += 3600000
		if _, _, wrote, a := e.q.AnchorRequest(OperatorPrincipal("op1"), At(e.now)); !wrote {
			t.Fatalf("the operator's anchor request was not served: %s", showAnswer(a))
		}
		e.commit(enroll("credC", "nsC", "jr3"))
		e.checkReplay()
	},
	"T11": func(t *testing.T) { // requester authorization is re-checked at the append
		e := newLine(t)
		e.commit(revoke("credB"))
		e.now += 3600000
		logLen := len(e.q.Log())
		if _, _, wrote, a := e.q.AnchorRequest(CredentialPrincipal("credB"), At(e.now)); wrote || a.Code != "not_authorized" || len(e.q.Log()) != logLen {
			t.Fatalf("a revoked requester: wrote=%v %s", wrote, showAnswer(a))
		}
	},
	"T12": func(t *testing.T) { // anchor at an occupied sequence with the wrong head
		e := newLine(t)
		in := e.intent(turn("a1", 2))
		in.SeenSeq, in.SeenHead = 10, "not-the-head-at-10"
		hot := e.q.HotEntries()
		e.want(e.submit(in), ClassRefusal, "unknown_anchor")
		if e.q.HotEntries() != hot {
			t.Fatal("unknown_anchor left an index entry")
		}
	},
	"T13": func(t *testing.T) { // anchor ahead of the sequencer (relay side only)
		e := newLine(t)
		in := e.intent(turn("a1", 2))
		in.SeenSeq, in.SeenHead = 45, "a-head-this-relay-has-never-seen"
		e.want(e.submit(in), ClassUnresolved, "history_unavailable")
	},
	"T14": func(t *testing.T) { // an intent anchored before a divergence is admissible on both branches
		x, y := newLine(t), newLine(t)
		if _, hx := x.q.Head(); func() bool { _, hy := y.q.Head(); return hx != hy }() {
			t.Fatal("two identical histories have different heads")
		}
		shared := x.intent(note("b1")) // anchored at seq 12, before the fork
		x.commit(turn("a1", 2))
		y.commit(note("a1"))
		if hx, _ := x.q.HeadAt(13); func() bool { hy, _ := y.q.HeadAt(13); return hx == hy }() {
			t.Fatal("divergent histories share a head")
		}
		x.now, y.now = x.now+1, y.now+1
		x.wantOutcome(x.submit(shared), Committed, "", false)
		y.wantOutcome(y.submit(shared), Committed, "", false) // no detection is claimed
		onX := x.intent(note("a1"))                           // anchored on x's seq 14
		y.want(y.submit(onX), ClassRefusal, "unknown_anchor") // evidence of divergent histories
	},
	"T15": func(t *testing.T) { // generation change, from a stipulated post-recovery fixture
		base := newLine(t)
		st := base.q.State()
		st.Line.Generation = 2
		kept := OpKey{Generation: 1, Signer: "cred:credA", SeenSeq: 9, OpID: "kept"}
		lost := OpKey{Generation: 1, Signer: "cred:credA", SeenSeq: 11, OpID: "lost"}
		q, err := NewSequencerFromFixture("L", testProfile, PostRecoveryFixture{
			Generation: 2, State: st, Head: "head-of-generation-2", Reconciled: true,
			Retained: map[OpKey]OpReceipt{kept: {Seq: 10, Digest: "kept-bytes"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		e := &env{t: t, q: q, now: st.Line.HeadTime + 1}
		old := func(k OpKey, digest string) Intent {
			return Intent{LineID: "L", Generation: 1, OpID: k.OpID, SeenSeq: k.SeenSeq, SeenHead: "old", ValidityMS: testValidity,
				Digest: digest, SignatureOK: true, Record: Record{Origin: OriginActor, Type: "call_note", Cred: "credA", Actor: "a1", Call: "c1"}}
		}
		a := e.submit(old(kept, "kept-bytes"))
		e.wantOutcome(a, Committed, "", true)
		if a.Seq != 10 {
			t.Fatalf("retained receipt names seq %d, want 10", a.Seq)
		}
		e.want(e.submit(old(kept, "other-bytes")), ClassMismatch, "")
		e.want(e.submit(old(lost, "lost-bytes")), ClassUnresolved, "abandoned")
		e.want(e.q.Query(OperatorPrincipal("op1"), lost, "lost-bytes", At(e.now)), ClassUnresolved, "abandoned")
		// An intent of the new generation anchors on its first record, not before.
		early := e.intent(note("a1"))
		early.SeenSeq, early.SeenHead = st.Line.HeadSeq-1, "old"
		e.want(e.submit(early), ClassRefusal, "unknown_anchor")
		e.commit(note("a1"))
	},
	"T16": func(t *testing.T) { // sequencer clock faults
		e := newLine(t)
		done, _ := e.commit(note("a1"))

		// A detected jump is a discontinuity, not elapsed time.
		pending := e.intent(note("b1"))
		floor := e.q.TimeFloor()
		jumped := Clock{Now: e.now + 86400000, Trusted: false}
		if a := e.q.Submit(pending, jumped); a.Class != ClassAdmission || a.Code != "clock_uncertain" {
			t.Fatalf("under an untrusted clock: %s", showAnswer(a))
		}
		if e.q.Compact(jumped) != 0 || e.q.TimeFloor() != floor {
			t.Fatal("an untrusted clock compacted or moved the time floor")
		}
		// An authorized historical receipt lookup still answers.
		if a := e.q.Submit(done, jumped); a.Class != ClassOutcome || a.Outcome.Kind != Committed || !a.Original {
			t.Fatalf("receipt lookup under an untrusted clock: %s", showAnswer(a))
		}
		// Nothing was expired by the jump: the pending intent still commits.
		e.wantOutcome(e.submit(pending), Committed, "", false)

		// An undetected freeze: nothing expires by time, and time never goes back.
		for i := 0; i < 5; i++ {
			e.wantOutcome(e.submit(e.intent(note("a1"))), Committed, "", false)
		}

		// A restart with a clock below the floor evaluates at the floor.
		short := e.intent(note("b1"))
		short.ValidityMS = 1000
		anchorTime := e.q.seqTime(short.SeenSeq)
		e.q.Compact(At(anchorTime + 2000)) // any evaluation moves the floor
		if a := e.q.Submit(short, At(anchorTime+500)); a.Class != ClassRefusal || a.Code != "expired" {
			t.Fatalf("a regressed clock re-admitted an intent: %s", showAnswer(a))
		}
		if e.q.TimeFloor() != anchorTime+2000 {
			t.Fatalf("the time floor moved to %d", e.q.TimeFloor())
		}

		// A legitimately elapsed day is simply time: an old intent expires.
		old := e.intent(note("a1"))
		e.now = e.q.TimeFloor() + 86400000
		e.want(e.submit(old), ClassRefusal, "expired")
		e.checkReplay()
	},
	"T17": func(t *testing.T) { // receipts after revocation
		e := newLine(t)
		in, seq := e.commit(note("b1"))
		e.commit(revoke("credB"))
		e.want(e.submit(in), ClassUnresolved, "revoked")
		e.want(e.q.Query(CredentialPrincipal("credB"), keyOf(in), in.Digest, At(e.now)), ClassUnresolved, "revoked")
		a := e.q.Query(OperatorPrincipal("op1"), keyOf(in), in.Digest, At(e.now))
		e.wantOutcome(a, Committed, "", true)
		if a.Seq != seq {
			t.Fatalf("reconciled receipt names seq %d, want %d", a.Seq, seq)
		}
	},
	"T18": func(t *testing.T) { // a new intent from a revoked credential
		e := newLine(t)
		e.commit(revoke("credB"))
		in := e.intent(note("b1"))
		in.Record.Cred, in.Record.BindingGen = "credB", 1
		hot := e.q.HotEntries()
		e.want(e.submit(in), ClassUnresolved, "revoked")
		if e.q.HotEntries() != hot {
			t.Fatal("a revoked signer's intent left an index entry")
		}
	},
	"T19": func(t *testing.T) { // preconditions apply to new evaluations only
		e := newLine(t)
		in, seq := e.commit(turn("a1", 2))
		e.commit(enroll("credC", "nsC", "jr3")) // auth_epoch moves on
		a := e.submit(in)
		e.wantOutcome(a, Committed, "", true)
		if a.Seq != seq {
			t.Fatalf("got seq %d, want %d", a.Seq, seq)
		}
	},
	"T28": func(t *testing.T) { // no fixture is installed without the reconciliation premise
		st := newLine(t).q.State()
		st.Line.Generation = 2
		_, err := NewSequencerFromFixture("L", testProfile, PostRecoveryFixture{Generation: 2, State: st, Head: "h"})
		if !errors.Is(err, ErrNotReconciled) {
			t.Fatalf("got %v, want ErrNotReconciled", err)
		}
	},
	"T30": func(t *testing.T) { // a call opened to an actor that is declared a moment later
		e := newLine(t)
		open := actorRec("call_open", "a1")
		open.Call, open.To = "c7", "a3"
		early := e.intent(open)
		e.wantOutcome(e.submit(early), Rejected, "unknown_target", false)
		authEpoch := e.q.State().Line.AuthEpoch
		e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credA", Namespace: "nsA", Actor: "a3"})
		if e.q.State().Line.AuthEpoch != authEpoch {
			t.Fatal("actor_declare changed auth_epoch")
		}
		// The earlier intent keeps its outcome; it is never retried on its own.
		e.wantOutcome(e.submit(early), Rejected, "unknown_target", true)
		e.commit(open)
		e.checkReplay()
	},
	"T32": func(t *testing.T) { // hot and cold lookup of a rejected operation
		e := newLine(t)
		e.closeCall()
		in := e.intent(turn("a1", 2))
		e.wantOutcome(e.submit(in), Rejected, "not_open", false)
		logLen := len(e.q.Log())
		e.wantOutcome(e.q.Query(CredentialPrincipal("credA"), keyOf(in), in.Digest, At(e.now)), Rejected, "not_open", true)
		e.want(e.q.Query(CredentialPrincipal("credB"), keyOf(in), in.Digest, At(e.now)), ClassAdmission, "not_authorized")
		e.retire(in.SeenSeq)
		// The reason is gone; the fact that it never committed is not.
		e.want(e.q.Query(CredentialPrincipal("credA"), keyOf(in), in.Digest, At(e.now)), ClassRefusal, "expired")
		e.want(e.submit(in), ClassRefusal, "expired")
		if len(e.q.Log()) != logLen {
			t.Fatal("a rejection entered the log")
		}
	},
	"T33": func(t *testing.T) { // rejection quota and duplicate admission
		e := newLine(t)
		e.q.QuotaMax = 2
		first := e.intent(turn("a1", 1)) // stale count: conflict
		e.wantOutcome(e.submit(first), Rejected, "conflict", false)
		e.wantOutcome(e.submit(e.intent(turn("a1", 1))), Rejected, "conflict", false)
		hot := e.q.HotEntries()
		blocked := e.intent(turn("a1", 1))
		e.want(e.submit(blocked), ClassAdmission, "quota")
		if e.q.HotEntries() != hot {
			t.Fatal("a quota refusal left an index entry")
		}
		// Dedup lookup comes before the quota check.
		e.wantOutcome(e.submit(first), Rejected, "conflict", true)
		// A commit is never blocked by the rejection quota.
		e.commit(turn("a1", 2))
		// Two copies of one undecided intent: one evaluation, one entry.
		e.q.QuotaMax = 3
		e.wantOutcome(e.submit(blocked), Rejected, "conflict", false)
		e.wantOutcome(e.submit(blocked), Rejected, "conflict", true)
		if e.q.HotEntries() != hot+2 { // the commit, and one entry for both copies
			t.Fatalf("hot entries: %d, want %d", e.q.HotEntries(), hot+2)
		}
	},
	"T34": func(t *testing.T) { // the time floor survives a lost refusal
		e := newLine(t)
		in := e.intent(turn("a1", 2))
		in.ValidityMS = 1000
		anchor := e.q.seqTime(in.SeenSeq)
		if a := e.q.Submit(in, At(anchor+5000)); a.Code != "expired" {
			t.Fatalf("got %s, want expired", showAnswer(a))
		}
		if e.q.TimeFloor() != anchor+5000 {
			t.Fatalf("time floor is %d, want %d", e.q.TimeFloor(), anchor+5000)
		}
		// The reply is lost and the sequencer restarts reading an earlier time.
		if a := e.q.Submit(in, At(anchor+500)); a.Code != "expired" {
			t.Fatalf("after the restart: %s, want expired", showAnswer(a))
		}
		if a := e.q.Submit(in, Clock{Now: anchor + 500, Trusted: false}); a.Code != "clock_uncertain" {
			t.Fatalf("with an untrusted clock: %s, want clock_uncertain", showAnswer(a))
		}
		if len(e.q.Log()) != 12 || e.q.TimeFloor() != anchor+5000 {
			t.Fatal("the intent was admitted, or the floor moved back")
		}
	},
	"T38": func(t *testing.T) { // an op_id cannot be reused with different bytes after compaction
		e := newLine(t)
		e.closeCall()
		in := e.intent(turn("a1", 2))
		e.wantOutcome(e.submit(in), Rejected, "not_open", false)
		changed := in
		changed.Digest = "different-bytes"
		e.want(e.submit(changed), ClassMismatch, "")

		// The rejected intent's own deadline is not the trigger. Past it, but
		// before the anchor retires, nothing is discarded, and bytes that
		// claim the full maximum validity under the same identity are still
		// a mismatch rather than a new operation. This is the hole a
		// per-intent retention rule would leave.
		anchor := e.q.seqTime(in.SeenSeq)
		longer := changed
		longer.ValidityMS = testProfile.ValidityMaxMS
		// Compaction may discard entries of earlier anchors here, which have
		// retired; what matters is that this anchor's entry survives, up to
		// and including the last instant at which a maximum-validity intent
		// anchored there is still admissible.
		for _, at := range []int64{anchor + testValidity + 1, anchor + testProfile.ValidityMaxMS} {
			e.now = at
			e.q.Compact(At(e.now))
			e.want(e.submit(longer), ClassMismatch, "")
		}

		if e.retire(in.SeenSeq) == 0 {
			t.Fatal("nothing was compacted")
		}
		e.want(e.submit(in), ClassRefusal, "expired")
		e.want(e.submit(changed), ClassRefusal, "expired") // not evaluated as new
		// The same op_id under a fresh anchor is a different operation.
		if _, _, wrote, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); !wrote {
			t.Fatal("no anchor written")
		}
		e.commit(reopen("b1", 0, 2))
		again := e.intent(turn("a1", 2))
		again.OpID, again.Digest = in.OpID, "different-bytes"
		if keyOf(again) == keyOf(in) {
			t.Fatal("a fresh anchor did not change the operation identity")
		}
		e.now++
		e.wantOutcome(e.submit(again), Committed, "", false)
		e.checkReplay()
	},
	"T39": func(t *testing.T) { // a larger validity claim cannot revive a retired anchor
		e := newLine(t)
		e.closeCall()
		in := e.intent(turn("a1", 2))
		e.wantOutcome(e.submit(in), Rejected, "not_open", false)
		e.retire(in.SeenSeq)
		revive := in
		revive.Digest, revive.ValidityMS = "different-bytes", 3600000
		e.now = e.q.seqTime(in.SeenSeq) + 900000
		e.want(e.submit(revive), ClassRefusal, "expired") // the deadline uses min(claimed, maximum)

		// The boundary is inclusive.
		seq, _, _, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now))
		anchor := e.q.seqTime(seq)
		onTime, late := e.intent(note("a1")), e.intent(note("b1"))
		if a := e.q.Submit(onTime, At(anchor+testValidity)); a.Outcome.Kind != Committed {
			t.Fatalf("exactly at the deadline: %s, want committed", showAnswer(a))
		}
		if a := e.q.Submit(late, At(anchor+testValidity+1)); a.Code != "expired" {
			t.Fatalf("one past the deadline: %s, want expired", showAnswer(a))
		}
		e.checkReplay()
	},
}

func TestTraces(t *testing.T) {
	for id, run := range traceTests {
		t.Run(id, run)
	}
}

// A query that finds nothing while the operation could still be admitted is
// not a cancellation: it evaluates nothing, reserves nothing, uses no quota,
// and a later submission of the bytes still commits.
func TestQueryIsNotCancellation(t *testing.T) {
	e := newLine(t)
	in := e.intent(turn("a1", 2))
	hot, logLen := e.q.HotEntries(), len(e.q.Log())
	for _, who := range []string{CredentialPrincipal("credA"), OperatorPrincipal("op1"), Root} {
		e.want(e.q.Query(who, keyOf(in), in.Digest, At(e.now)), ClassUnknown, "outcome_unknown")
	}
	if e.q.HotEntries() != hot || len(e.q.Log()) != logLen {
		t.Fatal("a query changed sequencer state")
	}
	e.wantOutcome(e.submit(in), Committed, "", false)
	e.wantOutcome(e.q.Query(Root, keyOf(in), in.Digest, At(e.now)), Committed, "", true)
	e.want(e.q.Query(Root, keyOf(in), "other-bytes", At(e.now)), ClassMismatch, "")
}

// An operator key outside the active set gets an access refusal that
// establishes nothing: the state keeps no history of operator keys, so the
// model cannot tell a revoked key from one that never existed. An
// independently authorized principal can still reconcile its history.
func TestInactiveOperatorKeyEstablishesNothing(t *testing.T) {
	e := newLine(t)
	in, seq := e.commit(enroll("credC", "nsC", "jr3"))
	e.commit(Record{Origin: OriginRoot, Type: "operator_key_revoke", OperatorKey: "op1", Expect: Expect{RootRev: ptr(2)}})
	e.want(e.submit(in), ClassAdmission, "not_authorized")
	never := e.intent(Record{Origin: OriginOperator, Type: "credential_revoke", Operator: "op9", Cred: "credC"})
	e.want(e.submit(never), ClassAdmission, "not_authorized") // indistinguishable, by design
	a := e.q.Query(Root, keyOf(in), in.Digest, At(e.now))
	e.wantOutcome(a, Committed, "", true)
	if a.Seq != seq {
		t.Fatalf("got seq %d, want %d", a.Seq, seq)
	}
}

// Admission refusals that must not be confused with outcomes.
func TestAdmissionRefusals(t *testing.T) {
	e := newLine(t)
	base := e.intent(turn("a1", 2))
	hot := e.q.HotEntries()
	for code, mutate := range map[string]func(*Intent){
		"wrong_line":     func(in *Intent) { in.LineID = "another-line" },
		"bad_signature":  func(in *Intent) { in.SignatureOK = false },
		"malformed":      func(in *Intent) { in.OpID = "" },
		"unknown_signer": func(in *Intent) { in.Record.Cred = "credZ" },
	} {
		in := base
		mutate(&in)
		if code == "unknown_signer" {
			in.Record.Origin = OriginCredential // so the signer is the credential named
		}
		e.want(e.submit(in), ClassAdmission, code)
	}
	if e.q.HotEntries() != hot {
		t.Fatal("an admission refusal left an index entry")
	}
	empty := newEnv(t)
	empty.want(empty.submit(empty.intent(note("a1"))), ClassAdmission, "no_line")
	// An ordinary intent cannot anchor on genesis: a generation's first
	// anchorable point is its first record.
	onGenesis := base
	onGenesis.OpID, onGenesis.SeenSeq = "on-genesis", 0
	onGenesis.SeenHead, _ = e.q.HeadAt(0)
	e.want(e.submit(onGenesis), ClassRefusal, "unknown_anchor")
	// A claim above the maximum validity is admitted only within the maximum,
	// and is then durably invalid: the shell hands the claim to Apply.
	greedy := e.intent(note("a1"))
	greedy.ValidityMS = testProfile.ValidityMaxMS + 1
	e.wantOutcome(e.submit(greedy), Rejected, "invalid", false)
	hot++
	// A second line_init is refused definitively and changes nothing.
	e.want(e.submit(e.intent(Record{Origin: OriginRoot, Type: "line_init"})), ClassRefusal, "line_exists")
	e.wantOutcome(e.submit(base), Committed, "", false)
}

// TestSequencerRandomWalk drives the model with a seeded stream of
// submissions, resubmissions, changed-bytes resubmissions, queries, anchor
// requests, clock movement, clock faults and compaction, and checks what must
// hold whatever the order:
//
//   - the log replays to exactly the sequencer's state, which is coherent;
//   - sequencer time and the time floor never decrease;
//   - an operation identity never gets two different outcomes, a committed
//     one stays committed at the same sequence number forever, and a
//     non-commit may only decay to "expired" once its anchor has retired;
//   - different bytes under an identity that has an outcome never commit.
func TestSequencerRandomWalk(t *testing.T) {
	steps := 20000
	if raceEnabled {
		steps = 2500
	}
	for _, seed := range []int64{1, 2, 3} {
		rng := rand.New(rand.NewSource(seed))
		e := newLine(t)
		type seen struct {
			in     Intent
			answer Answer
		}
		var sent []seen
		floor := e.q.TimeFloor()
		counts := map[string]int{}

		records := func() Record {
			st := e.q.State()
			c := st.Calls["c1"]
			switch rng.Intn(9) {
			case 0:
				return note("a1")
			case 1:
				return note("b1")
			case 2:
				return turn(c.Floor(), c.TurnCount)
			case 3:
				return turn("a1", c.TurnCount-int64(rng.Intn(2))) // sometimes stale, sometimes out of turn
			case 4:
				return bye([]string{"a1", "b1"}[rng.Intn(2)], c.TurnCount, c.LifecycleRev)
			case 5:
				return reopen("b1", c.LifecycleRev, c.TurnCount)
			case 6:
				r := actorRec("broadcast_read", []string{"a1", "b1", "a2"}[rng.Intn(3)])
				r.Broadcast = "bc1"
				return r
			case 7:
				r := actorRec("actor_addressing", "a2")
				r.DefaultAddressed, r.Expect.AddrRev = rng.Intn(2) == 0, ptr(st.Line.Actors["a2"].AddrRev)
				return r
			}
			r := actorRec("call_attach", "a1")
			r.Call, r.SizeClass = "c1", []string{"within_inline_limit", "over_inline_limit"}[rng.Intn(2)]
			return r
		}

		for i := 0; i < steps; i++ {
			clock := At(e.now)
			if rng.Intn(40) == 0 {
				clock.Trusted = false // a detected fault
			}
			switch op := rng.Intn(20); {
			case op < 8: // a new intent
				in := e.intent(records())
				if rng.Intn(6) == 0 {
					in.ValidityMS = int64(rng.Intn(3000))
				}
				a := e.q.Submit(in, clock)
				sent = append(sent, seen{in, a})
				counts[a.Class+" "+a.Code+a.Outcome.Kind]++
			case op < 13 && len(sent) > 0: // resubmit, sometimes with changed bytes
				k := rng.Intn(len(sent))
				in, was := sent[k].in, sent[k].answer
				changed := rng.Intn(4) == 0
				if changed {
					in.Digest += "-changed"
				}
				a := e.q.Submit(in, clock)
				counts["re:"+a.Class+" "+a.Code+a.Outcome.Kind]++
				switch {
				case changed:
					if a.Class == ClassOutcome && a.Outcome.Kind == Committed && was.Class == ClassOutcome {
						t.Fatalf("seed %d step %d: changed bytes committed under an identity that already had outcome %s", seed, i, showAnswer(was))
					}
					if a.Class == ClassOutcome && was.Class != ClassOutcome {
						// The original was never admitted, so the changed bytes are the
						// first to be; remember them as this identity's bytes.
						sent[k] = seen{in, a}
					}
				case was.Class == ClassOutcome && was.Outcome.Kind == Committed:
					if a.Class != ClassOutcome || a.Outcome.Kind != Committed || a.Seq != was.Seq {
						t.Fatalf("seed %d step %d: a committed operation answered %s, was %s", seed, i, showAnswer(a), showAnswer(was))
					}
				case was.Class == ClassOutcome: // a rejection or a no-op
					same := a.Class == ClassOutcome && a.Outcome == was.Outcome
					decayed := a.Class == ClassRefusal && a.Code == "expired" && e.q.retired(in.SeenSeq)
					// Once its entry is compacted, a non-commit needs sequencer time
					// to be answered at all; with an untrusted clock the model can
					// only say that it promises nothing.
					silent := a.Class == ClassAdmission && a.Code == "clock_uncertain" && !clock.Trusted
					if !same && !decayed && !silent {
						t.Fatalf("seed %d step %d: %s became %s", seed, i, showAnswer(was), showAnswer(a))
					}
				default:
					// Never admitted before. It may be admitted now; remember what it got.
					sent[k].answer = a
				}
			case op < 15 && len(sent) > 0: // a query evaluates nothing
				k := rng.Intn(len(sent))
				in, was := sent[k].in, sent[k].answer
				hot, logLen := e.q.HotEntries(), len(e.q.Log())
				before := e.q.TimeFloor()
				a := e.q.Query(Root, keyOf(in), in.Digest, clock)
				if e.q.HotEntries() != hot || len(e.q.Log()) != logLen || e.q.TimeFloor() != before {
					t.Fatalf("seed %d step %d: a query changed sequencer state", seed, i)
				}
				if was.Class == ClassOutcome && was.Outcome.Kind == Committed && (a.Outcome.Kind != Committed || a.Seq != was.Seq) {
					t.Fatalf("seed %d step %d: query of a committed operation answered %s", seed, i, showAnswer(a))
				}
			case op < 17:
				e.q.AnchorRequest([]string{CredentialPrincipal("credA"), OperatorPrincipal("op1"), Root}[rng.Intn(3)], clock)
			case op < 18:
				e.q.Compact(clock)
			default: // time passes: usually a little, sometimes past a deadline or a retirement
				e.now += []int64{1, 50, 4000, 15000, 70000, 700000}[rng.Intn(6)]
				if rng.Intn(30) == 0 {
					e.now -= 5000 // a clock that reads earlier than before
				}
			}
			if f := e.q.TimeFloor(); f < floor {
				t.Fatalf("seed %d step %d: the time floor went from %d to %d", seed, i, floor, f)
			} else {
				floor = f
			}
			if i%500 == 0 {
				e.checkReplay()
			}
		}
		e.checkReplay()
		if !raceEnabled {
			for _, must := range []string{"outcome committed", "outcome rejected", "outcome noop", "refusal expired", "admission_error clock_uncertain", "re:duplicate_mismatch ", "re:outcome committed"} {
				if counts[must] == 0 {
					t.Errorf("seed %d: the walk never produced %q: %v", seed, must, counts)
				}
			}
		}
		if seed == 1 {
			t.Logf("seed 1: %d records committed; answers: %v", len(e.q.Log()), counts)
		}
	}
}

// Two sequencers given the same inputs at the same times are identical.
func TestSequencerIsDeterministic(t *testing.T) {
	a, b := newLine(t), newLine(t)
	if !reflect.DeepEqual(a.q.Log(), b.q.Log()) || !reflect.DeepEqual(a.q.State(), b.q.State()) {
		t.Fatal("the same inputs produced different logs or states")
	}
}

// Compaction returns quota for the rejections it discards, and only for
// those: a discarded commit never counted against the quota.
func TestQuotaAcrossCompaction(t *testing.T) {
	e := newLine(t)
	e.q.QuotaMax = 1
	stale := func() Intent { return e.intent(turn("a1", 1)) }
	e.wantOutcome(e.submit(stale()), Rejected, "conflict", false)
	for i := 0; i < 3; i++ {
		e.commit(note("a1")) // commits by the same signer
	}
	e.want(e.submit(stale()), ClassAdmission, "quota")

	head, _ := e.q.Head()
	if e.retire(head) == 0 {
		t.Fatal("nothing was compacted")
	}
	if _, _, wrote, _ := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); !wrote {
		t.Fatal("no anchor written")
	}
	// The one rejection's quota came back, and no more than that.
	e.wantOutcome(e.submit(stale()), Rejected, "conflict", false)
	e.want(e.submit(stale()), ClassAdmission, "quota")
}

// The vectors file labels every trace with how far a Go test re-enacts it.
// Those labels must match what this package actually runs.
func TestTraceCoverageLabels(t *testing.T) {
	f := loadVectors(t)
	applyOnly := map[string]bool{
		"TestTraceNewMemberIsFutureOnly": true, "TestTraceTwoTurnsRace": true,
		"TestTraceLastNamespaceSlot": true, "TestTraceRegisterWriterAcrossMove": true,
	}
	byScope := map[string]int{}
	for _, tr := range f.Traces {
		byScope[tr.Run.Scope]++
		_, executed := traceTests[tr.ID]
		switch tr.Run.Scope {
		case "sequencer model":
			if !executed || tr.Run.Test != "TestTraces/"+tr.ID {
				t.Errorf("%s is labelled as run by %q, but no such trace test exists", tr.ID, tr.Run.Test)
			}
		case "apply-only part":
			if executed || !applyOnly[tr.Run.Test] {
				t.Errorf("%s is labelled apply-only by %q", tr.ID, tr.Run.Test)
			}
		case "not executed":
			if executed || tr.Run.Test != "" || tr.Run.Limits == "" {
				t.Errorf("%s is labelled not executed, but has a test or no stated reason", tr.ID)
			}
		default:
			t.Errorf("%s has unknown run scope %q", tr.ID, tr.Run.Scope)
		}
	}
	if !reflect.DeepEqual(byScope, f.Coverage.TracesByScope) {
		t.Errorf("file says %v traces by scope; found %v", f.Coverage.TracesByScope, byScope)
	}
	if byScope["sequencer model"] != len(traceTests) {
		t.Errorf("%d trace tests exist, %d traces are labelled as run by one", len(traceTests), byScope["sequencer model"])
	}
}

// The four tests below are the focused checks for the defects Codex's probes
// found in the first version of the sequencer model (docs/LDR-SEQUENCER-REVIEW.md).

// The bootstrap is exempt from validity, not from its context: line_init
// creates generation 1 and anchors on genesis, and an input Apply refuses is
// not evidence that a line exists.
func TestBootstrapContext(t *testing.T) {
	e := newEnv(t)
	genesis, _ := e.q.HeadAt(0)
	init := func(mutate func(*Intent)) Intent {
		in := e.intent(Record{Origin: OriginRoot, Type: "line_init"})
		mutate(&in)
		return in
	}
	e.want(e.submit(init(func(in *Intent) { in.Generation = 7 })), ClassUnresolved, "history_unavailable")
	e.want(e.submit(init(func(in *Intent) { in.SeenSeq, in.SeenHead = 55, "unrelated" })), ClassUnresolved, "history_unavailable")
	e.want(e.submit(init(func(in *Intent) { in.SeenHead = "not-genesis" })), ClassRefusal, "unknown_anchor")
	e.want(e.submit(init(func(in *Intent) { in.Generation = 0 })), ClassAdmission, "malformed")
	// An invalid first init is refused as invalid, never as "line exists".
	e.want(e.submit(init(func(in *Intent) { in.Record.UnexpectedLineCiphertext = true })), ClassAdmission, "invalid_bootstrap")
	e.want(e.submit(init(func(in *Intent) { in.Record.Origin = OriginOperator; in.Record.Operator = "op1" })), ClassAdmission, "invalid_bootstrap")
	if e.q.Generation() != 0 || len(e.q.Log()) != 0 || e.q.HotEntries() != 0 {
		t.Fatal("a refused bootstrap left state behind")
	}

	// Nothing above was recorded, so a valid line_init still commits.
	good := init(func(in *Intent) {})
	if good.SeenSeq != 0 || good.SeenHead != genesis || good.Generation != 1 {
		t.Fatalf("test intent is not a genesis-anchored generation-1 intent: %+v", good)
	}
	e.wantOutcome(e.submit(good), Committed, "", false)
	// After the line exists: retry and mismatch lookup first, then the refusal.
	e.wantOutcome(e.submit(good), Committed, "", true)
	changed := good
	changed.Digest = "different-bytes"
	e.want(e.submit(changed), ClassMismatch, "")
	other := init(func(in *Intent) { in.Generation, in.SeenSeq, in.SeenHead = 1, 0, genesis })
	e.want(e.submit(other), ClassRefusal, "line_exists")
	e.checkReplay()
}

// The log owns its records. Neither the intent a caller submitted nor the
// copy Log returns shares a pointer or a slice with it.
func TestCommittedRecordsDoNotAlias(t *testing.T) {
	e := newEnv(t)
	e.commit(Record{Origin: OriginRoot, Type: "line_init"})
	rootRev := int64(1)
	authorize := Record{Origin: OriginRoot, Type: "operator_key_authorize", OperatorKey: "op1", Expect: Expect{RootRev: &rootRev}}
	e.commit(authorize)
	grant := &Grant{Namespace: "nsA", ActorLimit: 4, Reader: true}
	e.commit(Record{Origin: OriginOperator, Type: "credential_enroll", Operator: "op1", Cred: "credA", JoinRequest: "jr1", Grant: grant})
	manifest := []string{"credA"}
	e.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", Manifest: manifest, Expect: Expect{KeyEpoch: ptr(0)}})
	e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credA", Namespace: "nsA", Actor: "a1"})
	recipients := []string{"a1"}
	e.commit(Record{Origin: OriginOperator, Type: "broadcast_create", Operator: "op1", Broadcast: "bc1", Kind: "briefing", Recipients: recipients})
	e.checkReplay()

	// The caller scribbles on everything it still holds.
	rootRev, grant.Namespace, grant.ActorLimit, manifest[0], recipients[0] = 99, "nsEvil", 0, "credEvil", "zz"
	e.checkReplay()

	// And on everything Log handed back.
	got := e.q.Log()
	*got[1].Record.Expect.RootRev = 77
	got[2].Record.Grant.Namespace = "nsEvil"
	got[3].Record.Manifest[0] = "credEvil"
	got[5].Record.Recipients[0] = "zz"
	got[0].Record.Type = "tampered"
	e.checkReplay()
	if again := e.q.Log(); *again[1].Record.Expect.RootRev != 1 || again[2].Record.Grant.Namespace != "nsA" ||
		again[3].Record.Manifest[0] != "credA" || again[5].Record.Recipients[0] != "a1" || again[0].Record.Type != "line_init" {
		t.Fatal("the sequencer's log was changed through a returned copy")
	}
}

// Query and Submit agree about an untrusted clock. A recorded outcome is
// still returned; anything that needs time is not, and a query never moves
// the time floor.
func TestQueryRespectsClockTrust(t *testing.T) {
	e := newLine(t)
	done, seq := e.commit(note("a1"))
	e.closeCall()
	gone := e.intent(turn("a1", 2))
	e.wantOutcome(e.submit(gone), Rejected, "not_open", false)
	pending := e.intent(note("b1"))
	e.retire(gone.SeenSeq) // the rejection's entry is compacted
	floor := e.q.TimeFloor()

	untrusted := Clock{Now: e.now, Trusted: false}
	signer := CredentialPrincipal("credA")
	// The compacted rejection: both entry points decline to speak about time.
	e.want(e.q.Submit(gone, untrusted), ClassAdmission, "clock_uncertain")
	e.want(e.q.Query(signer, keyOf(gone), gone.Digest, untrusted), ClassAdmission, "clock_uncertain")
	// An operation with no record at all: likewise.
	e.want(e.q.Query(CredentialPrincipal("credB"), keyOf(pending), pending.Digest, untrusted), ClassAdmission, "clock_uncertain")
	// A committed receipt is still answered.
	a := e.q.Query(signer, keyOf(done), done.Digest, untrusted)
	e.wantOutcome(a, Committed, "", true)
	if a.Seq != seq {
		t.Fatalf("got seq %d, want %d", a.Seq, seq)
	}
	// With a trusted clock the same query says what it could not say before.
	e.want(e.q.Query(signer, keyOf(gone), gone.Digest, At(e.now)), ClassRefusal, "expired")
	if e.q.TimeFloor() != floor {
		t.Fatalf("a query moved the time floor from %d to %d", floor, e.q.TimeFloor())
	}
	// A query with a trusted clock far in the future must not move it either,
	// nor may it call an unretired anchor expired on the strength of a reading
	// it does not persist.
	fresh := e.intent(note("a1"))
	if _, _, wrote, _ := e.q.AnchorRequest(signer, At(e.now)); !wrote {
		t.Fatal("no anchor written")
	}
	fresh = e.intent(note("a1"))
	e.want(e.q.Query(signer, keyOf(fresh), fresh.Digest, At(e.now+10*testProfile.ValidityMaxMS)), ClassUnknown, "outcome_unknown")
	if e.q.TimeFloor() != e.now {
		t.Fatalf("a query moved the time floor to %d", e.q.TimeFloor())
	}
	e.now++
	e.wantOutcome(e.submit(fresh), Committed, "", false)
}
