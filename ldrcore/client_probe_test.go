package ldrcore

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// These tests exist because Codex's independent probe of the client model
// (call 0003, turn 11, 2026-11-23) found two defects that the author's tests
// and mutation check had both missed, and proposed a rule the spec did not
// have. Codex's probes are not copied here. These are the author's tests of
// the author's fixes.

func moveActor(actor, to string, bindingGen int64) Record {
	return Record{Origin: OriginOperator, Type: "actor_move", Operator: "op1", Actor: actor, ToCred: to,
		Expect: Expect{BindingGen: ptr(bindingGen)}}
}

var activatePresence = Record{Origin: OriginCredential, Type: "register_activate", Actor: "a2", Register: "presence",
	Incarnation: "i1", Expect: Expect{WriterRev: ptr(0)}}

// Finding C1: an answer obtained by another principal settled an intent
// without the stale-checkpoint guard of the client's own answers.
func TestReconciledSettlesAsTheClientsOwnAnswerWould(t *testing.T) {
	// suspended returns a client whose turn awaits reconciliation after a
	// relay that does not know it refused it. With second, another intent is
	// stored that has never been sent or asked about.
	suspended := func(t *testing.T, second bool) (*env, *Client, string) {
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
	// expiredFor is the operator's query for the intent once its anchor has
	// retired: a definitive refusal that names a stale checkpoint.
	expiredFor := func(e *env, ca *Client, id string) Answer {
		e.t.Helper()
		in := stored(ca, id).Intent
		e.retire(in.SeenSeq)
		a := e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
		e.want(a, ClassRefusal, "expired")
		return a
	}

	t.Run("a stale-checkpoint refusal forces a resolve while another intent is unsettled", func(t *testing.T) {
		e, ca, id := suspended(t, true)
		if err := ca.Reconciled(id, expiredFor(e, ca, id)); err != nil {
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
	})

	t.Run("with nothing else unsettled it frees the slot and demands nothing", func(t *testing.T) {
		e, ca, id := suspended(t, false)
		if err := ca.Reconciled(id, expiredFor(e, ca, id)); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); err != nil {
			t.Fatalf("composing after the only intent was reconciled: %v", err)
		}
	})

	t.Run("an outcome settles it and is not a stale-checkpoint signal", func(t *testing.T) {
		e, ca, id := suspended(t, true)
		in := stored(ca, id).Intent
		e.wantOutcome(e.submit(in), Committed, "", false)
		got := e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
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

// Finding C2: eligibility for a local notice was decided when it was queued
// and never again, and what was queued depended on when the client scanned.
func TestDeliveryIsDecidedAgainAtHandoff(t *testing.T) {
	// queued returns credB's client with one unacknowledged notice for b1.
	queued := func(t *testing.T) (*env, *Client, string) {
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
	// withheld requires the notice to be held back and still unacknowledged.
	withheld := func(t *testing.T, c *Client, id string, attempts int) {
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
		e, cb, id := queued(t)
		e.commit(removeActor("credB", "b1"))
		e.sync(cb)
		withheld(t, cb, id, 0)
	})

	t.Run("a notice already handed over once is withheld the same way", func(t *testing.T) {
		e, cb, id := queued(t)
		if _, ok := hasNotice(cb.Deliver(), id); !ok {
			t.Fatal("not handed over while the actor was live")
		}
		e.commit(removeActor("credB", "b1"))
		e.sync(cb)
		withheld(t, cb, id, 1)
	})

	t.Run("a revoked credential's notices are withheld", func(t *testing.T) {
		e, cb, id := queued(t)
		e.commit(revoke("credB"))
		e.sync(cb)
		withheld(t, cb, id, 0)
	})

	t.Run("a move leaves the notice on the old host and owes none on the new", func(t *testing.T) {
		e, cb, id := queued(t)
		e.commit(moveActor("b1", "credA", 1))
		e.sync(cb)
		withheld(t, cb, id, 0)

		// The new host owes nothing for a record older than the move, whether
		// it replays the line in one piece or record by record.
		batch := NewClient("L", "credA", testProfile)
		e.sync(batch)
		step := NewClient("L", "credA", testProfile)
		for i := range e.q.Log() {
			if err := step.Run(e.q.Log()[:i+1]); err != nil {
				t.Fatal(err)
			}
		}
		for name, c := range map[string]*Client{"in one piece": batch, "record by record": step} {
			if n, ok := hasNotice(c.Notices(), id); ok {
				t.Errorf("replayed %s, the new host queued %+v", name, n)
			}
		}

		// A record after the move is owed on the new host, under the new binding.
		_, seq := e.commit(note("a1"))
		e.sync(batch)
		e.sync(cb)
		later := fmt.Sprintf("g1-s%d-b1", seq)
		if n, ok := hasNotice(batch.Deliver(), later); !ok || n.BindingGen != 2 {
			t.Fatalf("the new host's notice for the later record: %+v (found %v)", n, ok)
		}
		if n, ok := hasNotice(cb.Notices(), later); ok {
			t.Fatalf("the old host queued a notice for a record after the move: %+v", n)
		}
	})

	t.Run("moving back does not revive the notices of the earlier binding", func(t *testing.T) {
		e, cb, id := queued(t)
		e.commit(moveActor("b1", "credA", 1))
		e.commit(moveActor("b1", "credB", 2))
		e.sync(cb)
		withheld(t, cb, id, 0)
		_, seq := e.commit(note("a1"))
		e.sync(cb)
		later := fmt.Sprintf("g1-s%d-b1", seq)
		if n, ok := hasNotice(cb.Deliver(), later); !ok || n.BindingGen != 3 {
			t.Fatalf("the notice under the new binding: %+v (found %v)", n, ok)
		}
		withheld(t, cb, id, 0)
	})

	t.Run("what a record owes does not depend on when the client scanned", func(t *testing.T) {
		e, early, id := queued(t)
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
		e, cb, _ := queued(t)
		e.commit(removeActor("credB", "b1"))
		_, seq := e.commit(note("a1"))
		e.sync(cb)
		if n, ok := hasNotice(cb.Notices(), fmt.Sprintf("g1-s%d-b1", seq)); ok {
			t.Fatalf("queued for a removed actor: %+v", n)
		}
	})

	t.Run("a paused actor's notice is held back, not withheld", func(t *testing.T) {
		_, cb, id := queued(t)
		cb.Pause("b1")
		if got := cb.Deliver(); len(got) != 0 {
			t.Fatalf("handed to a paused actor: %v", got)
		}
		if n, ok := hasNotice(cb.Withheld(), id); ok {
			t.Fatalf("a paused actor's notice is reported as withheld: %+v", n)
		}
	})

	t.Run("an acknowledged notice is not reported as withheld", func(t *testing.T) {
		e, cb, id := queued(t)
		cb.Deliver()
		cb.Ack(id)
		e.commit(removeActor("credB", "b1"))
		e.sync(cb)
		if got := cb.Withheld(); len(got) != 0 {
			t.Fatalf("withheld: %v", got)
		}
	})
}

// The rule Codex proposed for a key that learns it is revoked. The spec had
// none, and the model let such a client go on composing.
func TestARevokedKeySignsNothingMore(t *testing.T) {
	slotHeld := func(t *testing.T, c *Client, id string) {
		t.Helper()
		o := stored(c, id)
		if o.Status != OutReconcile || c.out.slots[o.Slot] != id {
			t.Fatalf("intent %s: status %s, slot held by %q; want it awaiting reconciliation in its own slot",
				id, o.Status, c.out.slots[o.Slot])
		}
	}
	refused := func(t *testing.T, c *Client, name string, r Record) {
		t.Helper()
		_, err := c.Compose(name, r, Payload{})
		if !errors.Is(err, ErrKeyRevoked) || errors.Is(err, ErrFailClosed) {
			t.Fatalf("%s: %v, want ErrKeyRevoked", name, err)
		}
	}
	declare := Record{Origin: OriginCredential, Type: "actor_declare", Namespace: "nsA", Actor: "a9"}

	t.Run("told it is revoked, a credential stops and its other key goes on", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		ca.OperatorKey = "op1"
		done, _ := ca.Compose("note", noteOn("a1", "c1"), Payload{})
		a, _ := ca.Send(e.q, done, At(e.now))
		e.wantOutcome(a, Committed, "", false)
		sent, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		unsent, _ := ca.Compose("activate", activatePresence, Payload{})
		asOperator, err := ca.Compose("ratify", Record{Origin: OriginOperator, Type: "call_ratify", Call: "c1"}, Payload{})
		if err != nil {
			t.Fatal(err)
		}
		e.commit(revoke("credA"))
		// The client has not replayed its revocation. The relay tells it.
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
		slotHeld(t, ca, sent)
		slotHeld(t, ca, unsent)
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
		refused(t, ca, "a credential record", declare)
		refused(t, ca, "an actor record", noteOn("a2", "c1"))

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
			in := stored(ca, id).Intent
			if got := e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now)); got.Class != ClassUnknown {
				t.Fatalf("the operator's query before the anchor retired: %s", showAnswer(got))
			}
		}
		in := stored(ca, sent).Intent
		e.retire(in.SeenSeq)
		for _, id := range []string{sent, unsent} {
			in := stored(ca, id).Intent
			got := e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
			e.want(got, ClassRefusal, "expired")
			if err := ca.Reconciled(id, got); err != nil || stored(ca, id).Status != OutClosed {
				t.Fatalf("reconciling %s: err %v, %+v", id, err, stored(ca, id))
			}
		}
		ca.ResolveAll(e.q, At(e.now))
		refused(t, ca, "a credential record after reconciliation", declare)
	})

	t.Run("verifying its own revocation stops a credential the same way", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		id, _ := ca.Compose("activate", activatePresence, Payload{})
		e.commit(revoke("credA"))
		e.sync(ca)
		if got := ca.Stopped(); !reflect.DeepEqual(got, []string{"cred:credA"}) {
			t.Fatalf("stopped keys: %v", got)
		}
		slotHeld(t, ca, id)
		ca.Send(e.q, id, At(e.now))
		if stored(ca, id).Sends != 0 {
			t.Fatal("an intent of a revoked key was sent")
		}
		refused(t, ca, "a credential record", declare)
		refused(t, ca, "an actor record", noteOn("a2", "c1"))
	})

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
			slotHeld(t, ca, asOperator)
			refused(t, ca, how+": an operator record", Record{Origin: OriginOperator, Type: "call_ratify", Call: "c1"})
			// The credential is untouched: its stored intent is still pending,
			// and it composes.
			if o := stored(ca, asCred); o.Status != OutPending {
				t.Fatalf("%s: the credential's intent: %+v", how, o)
			}
			if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); err != nil {
				t.Fatalf("%s: composing as the credential: %v", how, err)
			}
		}
	})

	t.Run("a query answered revoked stops the key", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		e.commit(revoke("credA"))
		ca.ResolveAll(e.q, At(e.now))
		if o := stored(ca, id); o.Status != OutReconcile || o.Result.Code != "revoked" || o.Sends != 0 {
			t.Fatalf("the intent after the query: %+v", o)
		}
		refused(t, ca, "a credential record", declare)
	})

	// The relay model refuses a revoked key's anchor request with an admission
	// error that does not say why. The client cannot take that for `revoked`.
	t.Run("a refused anchor request stops no key", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		e.commit(revoke("credA"))
		if err := ca.Anchor(e.q, At(e.now)); err == nil {
			t.Fatal("the anchor request returned no error")
		}
		if got := ca.Stopped(); len(got) != 0 || stored(ca, id).Status != OutPending {
			t.Fatalf("stopped keys %v, intent %+v", got, stored(ca, id))
		}
	})
}
