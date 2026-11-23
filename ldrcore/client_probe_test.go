package ldrcore

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// These tests exist because Codex's independent probe of the client model
// (call 0003, turns 11 and 13, 2026-11-23) found two defects that the
// author's tests and mutation check had both missed, and proposed a rule the
// spec did not have. Codex's probes are not copied here. These are the
// author's tests of the author's fixes.
//
// Traces T43 to T47 of the vectors file are re-enacted here and registered
// with the other client traces.

func init() {
	for id, fn := range map[string]func(*testing.T){
		"T43": traceT43, "T44": traceT44, "T45": traceT45, "T46": traceT46, "T47": traceT47,
	} {
		clientTraceTests[id] = fn
	}
}

func moveActor(actor, to string, bindingGen int64) Record {
	return Record{Origin: OriginOperator, Type: "actor_move", Operator: "op1", Actor: actor, ToCred: to,
		Expect: Expect{BindingGen: ptr(bindingGen)}}
}

var (
	activatePresence = Record{Origin: OriginCredential, Type: "register_activate", Actor: "a2", Register: "presence",
		Incarnation: "i1", Expect: Expect{WriterRev: ptr(0)}}
	declareA9 = Record{Origin: OriginCredential, Type: "actor_declare", Namespace: "nsA", Actor: "a9"}
	ratifyC1  = Record{Origin: OriginOperator, Type: "call_ratify", Call: "c1"}
)

// suspendedTurn returns a client whose turn awaits reconciliation after a
// relay that does not know it refused it. With second, another intent is
// stored that has never been sent or asked about.
func suspendedTurn(t *testing.T, second bool) (*env, *Client, string) {
	t.Helper()
	e := newLine(t)
	ca := e.client("credA")
	id, err := ca.Compose("turn", turn("a1", 2), Payload{})
	if err != nil {
		t.Fatal(err)
	}
	if second {
		if _, err := ca.Compose("activate", activatePresence, Payload{}); err != nil {
			t.Fatal(err)
		}
	}
	stranger := newEnv(t)
	stranger.commit(lineInit())
	a, _ := ca.Send(stranger.q, id, At(e.now))
	e.want(a, ClassAdmission, "unknown_signer")
	return e, ca, id
}

// operatorAsks is the operator's query about a stored intent, by identity
// and digest, at the relay the client had verified.
func operatorAsks(e *env, c *Client, id string) Answer {
	in := stored(c, id).Intent
	return e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
}

// wantSlotHeld requires an intent to await reconciliation in its own slot.
func wantSlotHeld(t *testing.T, c *Client, id string) {
	t.Helper()
	o := stored(c, id)
	if o.Status != OutReconcile || c.out.slots[o.Slot] != id {
		t.Fatalf("intent %s: status %s, slot held by %q; want it awaiting reconciliation in its own slot",
			id, o.Status, c.out.slots[o.Slot])
	}
}

// wantKeyRefused requires Compose to refuse r because its key has stopped,
// and not because a rollback is suspected.
func wantKeyRefused(t *testing.T, c *Client, name string, r Record) {
	t.Helper()
	_, err := c.Compose(name, r, Payload{})
	if !errors.Is(err, ErrKeyRevoked) || errors.Is(err, ErrFailClosed) {
		t.Fatalf("%s: %v, want ErrKeyRevoked", name, err)
	}
}

// queuedNote returns credB's client with one unacknowledged notice for b1.
func queuedNote(t *testing.T) (*env, *Client, string) {
	t.Helper()
	e := newLine(t)
	cb := e.client("credB")
	_, seq := e.commit(note("a1"))
	e.sync(cb)
	id := fmt.Sprintf("g1-s%d-b1", seq)
	if n, ok := hasNotice(cb.Notices(), id); !ok || n.BindingGen != 1 {
		t.Fatalf("the notice was not queued under binding generation 1: %+v", n)
	}
	return e, cb, id
}

// wantWithheld requires a notice to be held back and still unacknowledged.
func wantWithheld(t *testing.T, c *Client, id string, attempts int) {
	t.Helper()
	if n, ok := hasNotice(c.Deliver(), id); ok {
		t.Fatalf("handed over: %+v", n)
	}
	n, ok := hasNotice(c.Withheld(), id)
	if !ok || n.Acked || n.Attempts != attempts {
		t.Fatalf("withheld notice %+v (found %v), want unacknowledged with %d attempts", n, ok, attempts)
	}
	if n, ok := hasNotice(c.Notices(), id); !ok || n.Acked {
		t.Fatalf("the queue's record of it: %+v (found %v)", n, ok)
	}
}

// T43: an answer obtained by another principal settles an intent as the
// client's own would. This is finding C1.
func traceT43(t *testing.T) {
	e, ca, id := suspendedTurn(t, true)
	wantSlotHeld(t, ca, id)

	e.retire(stored(ca, id).Intent.SeenSeq)
	got := operatorAsks(e, ca, id)
	e.want(got, ClassRefusal, "expired")
	if err := ca.Reconciled(id, got); err != nil {
		t.Fatal(err)
	}
	if o := stored(ca, id); o.Status != OutClosed || o.Result.Code != "expired" {
		t.Fatalf("the reconciled intent: %+v", o)
	}

	if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("composing with an intent never asked about: %v, want ErrMustResolve", err)
	}
	ca.ResolveAll(e.q, At(e.now))
	if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); err != nil {
		t.Fatalf("composing after the resolve: %v", err)
	}
}

func TestReconciledSettlesAsTheClientsOwnAnswerWould(t *testing.T) {
	t.Run("with nothing else unsettled it frees the slot and demands nothing", func(t *testing.T) {
		e, ca, id := suspendedTurn(t, false)
		e.retire(stored(ca, id).Intent.SeenSeq)
		if err := ca.Reconciled(id, operatorAsks(e, ca, id)); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); err != nil {
			t.Fatalf("composing after the only intent was reconciled: %v", err)
		}
	})

	t.Run("an outcome settles it and is not a stale-checkpoint signal", func(t *testing.T) {
		e, ca, id := suspendedTurn(t, true)
		e.wantOutcome(e.submit(stored(ca, id).Intent), Committed, "", false)
		got := operatorAsks(e, ca, id)
		if got.Class != ClassOutcome {
			t.Fatalf("the operator's query: %s", showAnswer(got))
		}
		if err := ca.Reconciled(id, got); err != nil {
			t.Fatal(err)
		}
		if o := stored(ca, id); o.Status != OutDone || o.Sends != 1 {
			t.Fatalf("the reconciled intent: %+v", o)
		}
		if _, err := ca.Compose("note", noteOn("a1", "c1"), Payload{}); err != nil {
			t.Fatalf("composing after an outcome was recorded: %v", err)
		}
	})
}

// T44: a queued notice is checked again when it is handed over. This is
// finding C2.
func traceT44(t *testing.T) {
	e, cb, first := queuedNote(t)

	// The operator moves b1 to credA.
	e.commit(moveActor("b1", "credA", 1))
	e.sync(cb)
	wantWithheld(t, cb, first, 0)

	// The new host owes nothing for a record older than the move, whether it
	// replays the line in one piece or record by record.
	ca := NewClient("L", "credA", testProfile)
	e.sync(ca)
	step := NewClient("L", "credA", testProfile)
	for i := range e.q.Log() {
		if err := step.Run(e.q.Log()[:i+1]); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]*Client{"in one piece": ca, "record by record": step} {
		if n, ok := hasNotice(c.Notices(), first); ok {
			t.Fatalf("replayed %s, the new host queued %+v", name, n)
		}
	}

	// A record after the move is owed on the new host, under the new binding.
	_, seq := e.commit(note("a1"))
	e.sync(ca)
	e.sync(cb)
	second := fmt.Sprintf("g1-s%d-b1", seq)
	if n, ok := hasNotice(ca.Deliver(), second); !ok || n.BindingGen != 2 {
		t.Fatalf("the new host's notice for the later record: %+v (found %v)", n, ok)
	}
	if n, ok := hasNotice(cb.Notices(), second); ok {
		t.Fatalf("the old host queued a notice for a record after the move: %+v", n)
	}

	// Moved back, b1 has a third binding. Its first is not revived.
	e.commit(moveActor("b1", "credB", 2))
	_, seq = e.commit(note("a1"))
	e.sync(cb)
	third := fmt.Sprintf("g1-s%d-b1", seq)
	if n, ok := hasNotice(cb.Deliver(), third); !ok || n.BindingGen != 3 {
		t.Fatalf("the notice under the third binding: %+v (found %v)", n, ok)
	}
	wantWithheld(t, cb, first, 0)

	// Removed, b1 is handed nothing more. What it was handed stays on record.
	e.commit(Record{Origin: OriginCredential, Type: "actor_remove", Cred: "credB", Actor: "b1", Expect: Expect{BindingGen: ptr(3)}})
	e.sync(cb)
	if got := cb.Deliver(); len(got) != 0 {
		t.Fatalf("handed to a removed actor: %v", got)
	}
	wantWithheld(t, cb, first, 0)
	// The third was handed over twice while b1 was live: once above, and once
	// by the delivery that checked the first.
	wantWithheld(t, cb, third, 2)
}

func TestDeliveryIsDecidedAgainAtHandoff(t *testing.T) {
	t.Run("a record is judged in the state it produced", func(t *testing.T) {
		// Before the record that opens it, the call has no participants.
		e := newLine(t)
		cb := e.client("credB")
		_, seq := e.commit(openCall("a1", "b1", "c2"))
		e.sync(cb)
		if n, ok := hasNotice(cb.Deliver(), fmt.Sprintf("g1-s%d-b1", seq)); !ok || n.Kind != "call_open" {
			t.Fatalf("the notice for the new call: %+v (found %v)", n, ok)
		}
	})

	t.Run("a queued notice is withheld once its actor is removed", func(t *testing.T) {
		e, cb, id := queuedNote(t)
		e.commit(removeActor("credB", "b1"))
		e.sync(cb)
		wantWithheld(t, cb, id, 0)
	})

	t.Run("a revoked credential's notices are withheld", func(t *testing.T) {
		e, cb, id := queuedNote(t)
		e.commit(revoke("credB"))
		e.sync(cb)
		wantWithheld(t, cb, id, 0)
	})

	t.Run("what a record owes does not depend on when the client scanned", func(t *testing.T) {
		e, early, id := queuedNote(t)
		e.commit(removeActor("credB", "b1"))
		e.sync(early)
		// This client takes the note and the removal in before it scans once.
		late := NewClient("L", "credB", testProfile)
		e.sync(late)
		a, _ := hasNotice(early.Notices(), id)
		b, ok := hasNotice(late.Notices(), id)
		if !ok || !reflect.DeepEqual(a, b) {
			t.Fatalf("scanned before the removal: %+v\nscanned after it: %+v (found %v)", a, b, ok)
		}
		if got := late.Deliver(); len(got) != 0 {
			t.Fatalf("handed to a removed actor: %v", got)
		}
	})

	t.Run("a record after the removal owes the actor nothing", func(t *testing.T) {
		e, cb, _ := queuedNote(t)
		e.commit(removeActor("credB", "b1"))
		_, seq := e.commit(note("a1"))
		e.sync(cb)
		if n, ok := hasNotice(cb.Notices(), fmt.Sprintf("g1-s%d-b1", seq)); ok {
			t.Fatalf("queued for a removed actor: %+v", n)
		}
	})

	t.Run("a paused actor's notice is held back, not withheld", func(t *testing.T) {
		_, cb, id := queuedNote(t)
		cb.Pause("b1")
		if got := cb.Deliver(); len(got) != 0 {
			t.Fatalf("handed to a paused actor: %v", got)
		}
		if n, ok := hasNotice(cb.Withheld(), id); ok {
			t.Fatalf("a paused actor's notice is reported as withheld: %+v", n)
		}
	})

	t.Run("an acknowledged notice is not reported as withheld", func(t *testing.T) {
		e, cb, id := queuedNote(t)
		cb.Deliver()
		cb.Ack(id)
		e.commit(removeActor("credB", "b1"))
		e.sync(cb)
		if got := cb.Withheld(); len(got) != 0 {
			t.Fatalf("withheld: %v", got)
		}
	})
}

// T45: a key that is told it is revoked signs and sends nothing more, and
// the device's other key goes on. The rule is Codex's proposal.
func traceT45(t *testing.T) {
	e := newLine(t)
	ca := e.client("credA")
	ca.OperatorKey = "op1"
	done, _ := ca.Compose("note", noteOn("a1", "c1"), Payload{})
	a, _ := ca.Send(e.q, done, At(e.now))
	e.wantOutcome(a, Committed, "", false)
	sent, _ := ca.Compose("turn", turn("a1", 2), Payload{})
	unsent, _ := ca.Compose("activate", activatePresence, Payload{})
	asOperator, err := ca.Compose("ratify", ratifyC1, Payload{})
	if err != nil {
		t.Fatal(err)
	}
	e.commit(revoke("credA"))

	// The client has not taken its revocation in. The relay tells it.
	a, _ = ca.Send(e.q, sent, At(e.now))
	e.want(a, ClassUnresolved, "revoked")
	if got := ca.Stopped(); !reflect.DeepEqual(got, []string{"cred:credA"}) {
		t.Fatalf("stopped keys: %v", got)
	}
	// What the key had already settled stays settled.
	if o := stored(ca, done); o.Status != OutDone {
		t.Fatalf("the intent that had committed: %+v", o)
	}
	// Every intent the key signed keeps its slot and awaits reconciliation,
	// the one never sent included. Nothing is sent under the key again.
	wantSlotHeld(t, ca, sent)
	wantSlotHeld(t, ca, unsent)
	ca.Send(e.q, sent, At(e.now))
	ca.Send(e.q, unsent, At(e.now))
	if stored(ca, sent).Sends != 1 || stored(ca, unsent).Sends != 0 {
		t.Fatalf("sends under a revoked key: %d and %d", stored(ca, sent).Sends, stored(ca, unsent).Sends)
	}
	if got := stored(ca, unsent).Result; got != (Answer{}) {
		t.Fatalf("the unsent intent was given an answer it never received: %+v", got)
	}

	// It signs nothing more, for itself or for its actors. That is not a
	// suspected rollback.
	wantKeyRefused(t, ca, "a credential record", declareA9)
	wantKeyRefused(t, ca, "an actor record", noteOn("a2", "c1"))

	// The operator key on the same device is another principal.
	if o := stored(ca, asOperator); o.Status != OutPending {
		t.Fatalf("the operator's intent: %+v", o)
	}
	if a, _ := ca.Send(e.q, asOperator, At(e.now)); a.Class != ClassOutcome {
		t.Fatalf("sending the operator's intent: %s", showAnswer(a))
	}
	if _, err := ca.Compose("revoke credB", revoke("credB"), Payload{}); err != nil {
		t.Fatalf("composing with the operator key: %v", err)
	}

	// A principal that is still authorized reconciles the stopped key's
	// intents. Settling them does not lift the stop.
	for _, id := range []string{sent, unsent} {
		if got := operatorAsks(e, ca, id); got.Class != ClassUnknown {
			t.Fatalf("the operator's query before the anchor retired: %s", showAnswer(got))
		}
	}
	e.retire(stored(ca, sent).Intent.SeenSeq)
	for _, id := range []string{sent, unsent} {
		got := operatorAsks(e, ca, id)
		e.want(got, ClassRefusal, "expired")
		if err := ca.Reconciled(id, got); err != nil || stored(ca, id).Status != OutClosed {
			t.Fatalf("reconciling %s: err %v, %+v", id, err, stored(ca, id))
		}
	}
	ca.ResolveAll(e.q, At(e.now))
	wantKeyRefused(t, ca, "a credential record after reconciliation", declareA9)
}

// T46: a stopped key asks nothing, and does not hold back another key. It
// also covers the other two ways a key learns that it is revoked.
func traceT46(t *testing.T) {
	e := newLine(t)
	ca := e.client("credA")
	ca.OperatorKey = "op1"
	anchoring, verifying := e.client("credA"), e.client("credA")
	first, _ := ca.Compose("turn", turn("a1", 2), Payload{})
	second, _ := ca.Compose("activate", activatePresence, Payload{})
	held, _ := verifying.Compose("activate", activatePresence, Payload{})
	e.commit(revoke("credA"))

	// After a restart nothing is composed before stored intents are asked
	// about, whichever key the new record would need.
	if err := ca.Restart(); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Compose("ratify", ratifyC1, Payload{}); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("composing after a restart: %v, want ErrMustResolve", err)
	}

	// The first query is answered revoked, and the key stops. The second
	// intent is not asked about, and no answer is made up for it.
	ca.ResolveAll(e.q, At(e.now))
	if o := stored(ca, first); o.Status != OutReconcile || o.Result.Code != "revoked" || o.Sends != 0 {
		t.Fatalf("the first intent after the pass: %+v", o)
	}
	wantSlotHeld(t, ca, second)
	if got := stored(ca, second).Result; got != (Answer{}) {
		t.Fatalf("the second intent was asked about under a stopped key: %+v", got)
	}

	// The pass is complete: the stopped key's intents do not hold back op1.
	if _, err := ca.Compose("ratify", ratifyC1, Payload{}); err != nil {
		t.Fatalf("composing as the operator after the pass: %v", err)
	}
	wantKeyRefused(t, ca, "a credential record", declareA9)

	// Another restart, another pass: nothing is asked as credA, and nothing
	// about its intents changes.
	before := []OutboxEntry{stored(ca, first), stored(ca, second)}
	if err := ca.Restart(); err != nil {
		t.Fatal(err)
	}
	ca.ResolveAll(e.q, At(e.now))
	if after := []OutboxEntry{stored(ca, first), stored(ca, second)}; !reflect.DeepEqual(before, after) {
		t.Fatalf("a stopped key's intents changed:\n before %+v\n after  %+v", before, after)
	}
	if _, err := ca.Compose("revoke credB", revoke("credB"), Payload{}); err != nil {
		t.Fatalf("composing as the operator after the second pass: %v", err)
	}

	// A refused anchor request that says revoked stops the key as well.
	if err := anchoring.Anchor(e.q, At(e.now)); err == nil {
		t.Fatal("a revoked credential's anchor request returned no error")
	}
	if got := anchoring.Stops(); len(got) != 1 || !got[0].Told || got[0].Verified || got[0].Answer.Code != "revoked" {
		t.Fatalf("after the refused anchor request: %+v", got)
	}
	wantKeyRefused(t, anchoring, "a credential record", declareA9)

	// So does verifying the revocation in the records, without being told.
	e.sync(verifying)
	if got := verifying.Stops(); len(got) != 1 || got[0].Told || !got[0].Verified || got[0].Key != "cred:credA" {
		t.Fatalf("after verifying the revocation: %+v", got)
	}
	wantSlotHeld(t, verifying, held)
	verifying.Send(e.q, held, At(e.now))
	if stored(verifying, held).Sends != 0 {
		t.Fatal("an intent of a revoked key was sent")
	}
	wantKeyRefused(t, verifying, "a credential record", declareA9)
	wantKeyRefused(t, verifying, "an actor record", noteOn("a2", "c1"))

	// A refusal for any other reason stops nothing.
	other := newLine(t)
	unrevoked := other.client("credA")
	if err := unrevoked.Anchor(other.q, Clock{Now: other.now, Trusted: false}); err == nil {
		t.Fatal("an anchor request under an untrusted clock returned no error")
	}
	if got := unrevoked.Stopped(); len(got) != 0 {
		t.Fatalf("stopped keys after an admission error: %v", got)
	}
}

// T47: a stop stands when the records the client verifies show no
// revocation. The answer and the checkpoint are kept, and the difference is
// reported, not judged.
func traceT47(t *testing.T) {
	e := newLine(t)
	ca := e.client("credA")
	id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
	ckSeq, ckHead := ca.Checkpoint()

	// Premise: a relay holding the same line, with a revocation of credA
	// that the relay this client had verified does not have.
	fork := newLine(t)
	fork.commit(revoke("credA"))
	a, _ := ca.Send(fork.q, id, At(fork.now))
	e.want(a, ClassUnresolved, "revoked")
	told := KeyStop{Key: "cred:credA", Told: true, Answer: a, Seq: ckSeq, Head: ckHead}
	if got := ca.Stops(); !reflect.DeepEqual(got, []KeyStop{told}) {
		t.Fatalf("after being told: %+v", got)
	}

	// The turn's bytes had reached the first relay and committed there. The
	// client takes in its further records. None revokes credA.
	e.wantOutcome(e.submit(stored(ca, id).Intent), Committed, "", false)
	e.commit(note("b1"))
	e.sync(ca)
	if got := ca.Stops(); !reflect.DeepEqual(got, []KeyStop{told}) {
		t.Fatalf("after verifying records without a revocation: %+v", got)
	}
	// The stop stands, and it is still not a suspected rollback.
	wantKeyRefused(t, ca, "a credential record", declareA9)

	// A second answer does not replace the evidence of the first.
	ca.toldRevoked("cred:credA", Answer{Class: ClassUnresolved, Code: "revoked", Seq: 99})
	if got := ca.Stops(); !reflect.DeepEqual(got, []KeyStop{told}) {
		t.Fatalf("after a second answer: %+v", got)
	}

	// The stopped credential requests no anchor, even from the relay it had
	// verified, which has no revocation and would serve it. This is finding
	// C3: the stop is the client's and does not depend on one relay's state.
	e.now += testProfile.FreshnessMS + 1
	logLen := len(e.q.Log())
	if err := ca.Anchor(e.q, At(e.now)); !errors.Is(err, ErrKeyRevoked) || len(e.q.Log()) != logLen {
		t.Fatalf("a stopped credential's anchor request: err %v, relay log %d -> %d; want ErrKeyRevoked and no request",
			err, logLen, len(e.q.Log()))
	}
	if got := ca.Stops(); !reflect.DeepEqual(got, []KeyStop{told}) {
		t.Fatalf("after the refused request: %+v", got)
	}

	// An old outcome, obtained by an authorized principal, settles the
	// intent. It is no reason to resume.
	got := operatorAsks(e, ca, id)
	if got.Class != ClassOutcome {
		t.Fatalf("the operator's query: %s", showAnswer(got))
	}
	if err := ca.Reconciled(id, got); err != nil || stored(ca, id).Status != OutDone {
		t.Fatalf("reconciling: err %v, %+v", err, stored(ca, id))
	}
	wantKeyRefused(t, ca, "a credential record after the outcome", declareA9)

	// If the revocation is verified later, the report says so, and the
	// evidence of the earlier answer is unchanged.
	e.commit(revoke("credA"))
	e.sync(ca)
	told.Verified = true
	if got := ca.Stops(); !reflect.DeepEqual(got, []KeyStop{told}) {
		t.Fatalf("after verifying the revocation: %+v", got)
	}
}

func TestARevokedKeySignsNothingMore(t *testing.T) {
	t.Run("an operator key stops alone", func(t *testing.T) {
		for _, how := range []string{"told", "verified"} {
			e := newLine(t)
			ca := e.client("credA")
			ca.OperatorKey = "op1"
			asOperator, _ := ca.Compose("revoke credB", revoke("credB"), Payload{})
			asCred, _ := ca.Compose("activate", activatePresence, Payload{})
			e.commit(Record{Origin: OriginRoot, Type: "operator_key_revoke", OperatorKey: "op1",
				Expect: Expect{RootRev: ptr(e.q.State().Line.RootRev)}})
			if how == "told" {
				a, _ := ca.Send(e.q, asOperator, At(e.now))
				e.want(a, ClassUnresolved, "revoked")
			} else {
				e.sync(ca)
			}
			if got := ca.Stopped(); !reflect.DeepEqual(got, []string{"op:op1"}) {
				t.Fatalf("%s: stopped keys: %v", how, got)
			}
			wantSlotHeld(t, ca, asOperator)
			wantKeyRefused(t, ca, how+": an operator record", ratifyC1)
			// The credential is untouched: its stored intent is still pending,
			// it is still asked about, and it composes.
			ca.ResolveAll(e.q, At(e.now))
			if o := stored(ca, asCred); o.Status != OutPending || o.Result.Class != ClassUnknown {
				t.Fatalf("%s: the credential's intent: %+v", how, o)
			}
			if _, err := ca.Compose("note", noteOn("a1", "c1"), Payload{}); err != nil {
				t.Fatalf("%s: composing as the credential: %v", how, err)
			}
		}
	})
}
