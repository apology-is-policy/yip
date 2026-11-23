package ldrcore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These tests exist because a mutation check of client.go and outbox.go on
// 2026-11-23 found single-rule breaks that no test caught. Each subtest pins
// one of them. They are the author's tests of the author's code.

func removeActor(cred, actor string) Record {
	return Record{Origin: OriginCredential, Type: "actor_remove", Cred: cred, Actor: actor, Expect: Expect{BindingGen: ptr(1)}}
}

// rolledBack returns a relay holding only the first n records of e's line.
func rolledBack(t *testing.T, e *env, n int) *Sequencer {
	t.Helper()
	q := NewSequencer("L", testProfile)
	for _, entry := range e.q.Log()[:n] {
		in := Intent{LineID: "L", Generation: entry.Key.Generation, OpID: entry.Key.OpID, SeenSeq: entry.Key.SeenSeq,
			ValidityMS: testValidity, Digest: entry.Digest, SignatureOK: true, Record: entry.Record}
		in.SeenHead, _ = q.HeadAt(in.SeenSeq)
		if a := q.Submit(in, At(entry.SeqTime)); a.Class != ClassOutcome {
			t.Fatalf("rebuilding the rolled-back relay: %s", showAnswer(a))
		}
	}
	return q
}

func TestClientStoreAndReaderRules(t *testing.T) {
	t.Run("the store shares no memory with the records it was handed", func(t *testing.T) {
		e := newLine(t)
		c := NewClient("L", "credB", testProfile)
		log := e.q.Log()
		if err := c.Run(log); err != nil {
			t.Fatal(err)
		}
		const path = "broadcasts/bc1/broadcast"
		want := c.Files()[path]
		if !strings.Contains(want, "recipients=a1,b1\n") {
			t.Fatalf("the broadcast file:\n%s", want)
		}
		log[11].Record.Recipients[0] = "zz"
		if err := c.Rebuild(); err != nil {
			t.Fatal(err)
		}
		if got := c.Files()[path]; got != want {
			t.Fatalf("changing the caller's record changed the store:\n%s", got)
		}
	})

	t.Run("broadcasts and actors have views that follow the store", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		const bview, aview = "broadcasts/bc1/view", "actors/a2/view"
		if got, err := cb.ReadFile(bview); err != nil || !strings.Contains(got, "receipt.b1=pending\n") {
			t.Fatalf("the broadcast's view before it is read (%v):\n%s", err, got)
		}
		a2 := e.q.State().Line.Actors["a2"]
		if got, err := cb.ReadFile(aview); err != nil || !strings.Contains(got, fmt.Sprintf("addr_rev=%d\n", a2.AddrRev)) {
			t.Fatalf("the actor's view before its addressing changes (%v):\n%s", err, got)
		}
		read := actorRec("broadcast_read", "b1")
		read.Broadcast = "bc1"
		_, readSeq := e.commit(read)
		addressed := !a2.DefaultAddressed
		addr := actorRec("actor_addressing", "a2")
		addr.DefaultAddressed, addr.Expect.AddrRev = addressed, ptr(a2.AddrRev)
		_, addrSeq := e.commit(addr)
		e.sync(cb)
		got, err := cb.ReadFile(bview)
		if err != nil || !strings.HasPrefix(got, fmt.Sprintf("derived_seq=%d\n", readSeq)) ||
			!strings.Contains(got, fmt.Sprintf("receipt.b1=%d\n", readSeq)) {
			t.Fatalf("the broadcast's view after the read (%v):\n%s", err, got)
		}
		got, err = cb.ReadFile(aview)
		if err != nil || !strings.HasPrefix(got, fmt.Sprintf("derived_seq=%d\n", addrSeq)) ||
			!strings.Contains(got, fmt.Sprintf("addr_rev=%d\n", a2.AddrRev+1)) ||
			!strings.Contains(got, fmt.Sprintf("default_addressed=%t\n", addressed)) {
			t.Fatalf("the actor's view after the change (%v):\n%s", err, got)
		}
	})

	t.Run("reader states are decided in order", func(t *testing.T) {
		e := newLine(t)
		forged := e.commitP(turn("a1", 2), Payload{Forged: true})
		malformed := e.commitP(turn("b1", 3), Payload{Malformed: true})
		both := e.commitP(turn("a1", 4), Payload{Forged: true, Malformed: true})
		log := e.q.Log()
		at := func(seq int64) Entry { return log[seq-1] }

		cb := e.client("credB")
		// A record with no line ciphertext has nothing to read, key or no key.
		if got := cb.ReaderState(at(3)); got != ReadNone {
			t.Errorf("an enrollment record reads as %s, want %s", got, ReadNone)
		}
		if got := cb.ReaderState(at(both)); got != ReadUndecryptable {
			t.Errorf("a payload that does not authenticate reads as %s; nothing about its plaintext is known", got)
		}
		if got := cb.ReaderState(at(malformed)); got != ReadMalformed {
			t.Errorf("an authenticated malformed payload reads as %s", got)
		}
		// Under wrong local key material the plaintext was never authenticated,
		// so the writer cannot be said to have malformed it.
		cb.CorruptKey(2)
		if got := cb.ReaderState(at(malformed)); got != ReadUndecryptable {
			t.Errorf("a malformed payload under a wrong local key reads as %s", got)
		}

		// Without a key the payload is not inspected at all.
		nokey := e.client("credB")
		nokey.FailWrap(2)
		for _, seq := range []int64{forged, malformed, both} {
			if got := nokey.ReaderState(at(seq)); got != ReadNoKey {
				t.Errorf("seq %d without a key reads as %s, want %s", seq, got, ReadNoKey)
			}
		}
	})
}

func TestProjectionWriteRules(t *testing.T) {
	// measured returns credB's client on a line where a1 has opened a dispute
	// on c1, and a function that commits a1's next measurement.
	measured := func(t *testing.T) (*env, *Client, func(rev int64) int64) {
		e := newLine(t)
		open := actorRec("dispute_open", "a1")
		open.Call = "c1"
		e.commit(open)
		cb := e.client("credB")
		return e, cb, func(rev int64) int64 {
			m := actorRec("dispute_measure", "a1")
			m.Call, m.Dispute, m.Expect.MeasureRev = "c1", "1", ptr(rev)
			_, s := e.commit(m)
			return s
		}
	}
	const measure = "calls/c1/dispute-1/measure-a1"

	t.Run("a differing immutable file taints the projection, which is rebuilt", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		_, seq := e.commit(turn("a1", 2))
		cb.EditFile(turnFileAt(3), "type=call_turn\nnot what the store holds\n")
		e.sync(cb)
		if cb.Rebuilds() != 1 {
			t.Fatalf("%d rebuilds, want 1", cb.Rebuilds())
		}
		if got, err := cb.ReadFile(turnFileAt(3)); err != nil || !strings.Contains(got, fmt.Sprintf("seq=%d\n", seq)) {
			t.Fatalf("the turn file after the rebuild (%v):\n%s", err, got)
		}
	})

	t.Run("a view is replaced only by a higher one, and a read still refuses it", func(t *testing.T) {
		e, cb, next := measured(t)
		first := next(0)
		e.commit(note("a1")) // so the store's checkpoint is past the tag below
		foreign := fmt.Sprintf("derived_seq=%d\nnot what the store holds\n", first+1)
		cb.EditFile(measure, foreign)
		e.sync(cb)
		if cb.Rebuilds() != 0 || cb.Files()[measure] != foreign {
			t.Fatalf("%d rebuilds; the higher view was replaced by a lower one:\n%s", cb.Rebuilds(), cb.Files()[measure])
		}
		if _, err := cb.ReadFile(measure); !errors.Is(err, ErrTainted) {
			t.Fatalf("reading it: %v, want ErrTainted", err)
		}
	})

	t.Run("a view with the same tag and other content taints the projection", func(t *testing.T) {
		e, cb, next := measured(t)
		seq := next(0)
		cb.Fault = FaultAfterFileWrite
		if err := cb.Run(e.q.Log()); !errors.Is(err, ErrCrashed) {
			t.Fatalf("the client did not die after writing the file: %v", err)
		}
		written := cb.Files()[measure]
		if !strings.HasPrefix(written, fmt.Sprintf("derived_seq=%d\n", seq)) {
			t.Fatalf("the view before the edit:\n%s", written)
		}
		cb.EditFile(measure, fmt.Sprintf("derived_seq=%d\nnot what the store holds\n", seq))
		if err := cb.Restart(); err != nil {
			t.Fatal(err)
		}
		if cb.Rebuilds() != 1 || cb.Files()[measure] != written {
			t.Fatalf("%d rebuilds, want 1, and the view restored:\n%s", cb.Rebuilds(), cb.Files()[measure])
		}
	})

	t.Run("a view that cannot be read taints the projection", func(t *testing.T) {
		e, cb, next := measured(t)
		next(0)
		e.sync(cb)
		cb.EditFile(measure, "not a view at all\n")
		second := next(1)
		e.sync(cb)
		if cb.Rebuilds() != 1 {
			t.Fatalf("%d rebuilds, want 1", cb.Rebuilds())
		}
		if got := cb.Files()[measure]; !strings.HasPrefix(got, fmt.Sprintf("derived_seq=%d\n", second)) {
			t.Fatalf("the view after the rebuild:\n%s", got)
		}
	})

	t.Run("a file the projection has not written yet is not yet projected", func(t *testing.T) {
		_, cb := crashAt41(t, FaultBeforeProjection)
		if _, err := cb.ReadFile(turnFile); !errors.Is(err, ErrNotProjected) {
			t.Fatalf("reading it: %v, want ErrNotProjected", err)
		}
	})
}

func turnFileAt(n int) string { return fmt.Sprintf("calls/c1/turn-%d", n) }

func TestDeliveryRules(t *testing.T) {
	t.Run("a sender is not notified of its own record", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		e.commit(turn("a1", 2))
		e.sync(ca)
		if got := ca.Deliver(); len(got) != 0 {
			t.Fatalf("a1's own turn was delivered to its credential: %v", got)
		}
	})

	t.Run("an actor that is no longer live is not notified", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		e.commit(removeActor("credB", "b1"))
		e.commit(note("a1"))
		e.sync(cb)
		if got := cb.Deliver(); len(got) != 0 {
			t.Fatalf("a removed actor was notified: %v", got)
		}
	})

	t.Run("an operator's record on a call notifies both participants", func(t *testing.T) {
		e := newLine(t)
		ca, cb := e.client("credA"), e.client("credB")
		_, seq := e.commit(Record{Origin: OriginOperator, Type: "call_ratify", Operator: "op1", Call: "c1"})
		e.sync(ca)
		e.sync(cb)
		if _, ok := hasNotice(ca.Deliver(), fmt.Sprintf("g1-s%d-a1", seq)); !ok {
			t.Error("a1 was not notified of the ratification")
		}
		if _, ok := hasNotice(cb.Deliver(), fmt.Sprintf("g1-s%d-b1", seq)); !ok {
			t.Error("b1 was not notified of the ratification")
		}
	})

	t.Run("a rescan does not replace a notice that is already queued", func(t *testing.T) {
		_, cb := crashAt41(t, FaultAfterEnqueue)
		// The notice is durable. A runtime takes it and acknowledges it before
		// the scan cursor has moved.
		if _, ok := hasNotice(cb.Deliver(), turnNotice); !ok {
			t.Fatal("the queued notice was not delivered")
		}
		cb.Ack(turnNotice)
		if err := cb.Restart(); err != nil {
			t.Fatal(err)
		}
		if got := cb.Deliver(); len(got) != 0 {
			t.Fatalf("the rescan brought back an acknowledged notice: %v", got)
		}
		if n, _ := hasNotice(cb.Notices(), turnNotice); !n.Acked || n.Attempts != 1 {
			t.Fatalf("the notice after the rescan: %+v", n)
		}
	})
}

func TestOutboxRules(t *testing.T) {
	setup := func(t *testing.T) (*env, *Client) {
		e := newLine(t)
		return e, e.client("credA")
	}
	activate := Record{Origin: OriginCredential, Type: "register_activate", Actor: "a2", Register: "presence",
		Incarnation: "i1", Expect: Expect{WriterRev: ptr(0)}}

	t.Run("an actor that is no longer live does not sign", func(t *testing.T) {
		e, ca := setup(t)
		e.commit(removeActor("credA", "a2"))
		e.sync(ca)
		if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrNotSigner) {
			t.Fatalf("composing for a removed actor: %v, want ErrNotSigner", err)
		}
	})

	t.Run("an operator record is signed only with the operator key the device holds", func(t *testing.T) {
		_, ca := setup(t)
		unnamed := Record{Origin: OriginOperator, Type: "credential_revoke", Cred: "credB"}
		if _, err := ca.Compose("revoke", unnamed, Payload{}); !errors.Is(err, ErrNotSigner) {
			t.Fatalf("a device with no operator key: %v, want ErrNotSigner", err)
		}
		ca.OperatorKey = "op1"
		other := unnamed
		other.Operator = "op2"
		if _, err := ca.Compose("revoke", other, Payload{}); !errors.Is(err, ErrNotSigner) {
			t.Fatalf("a record that names another operator key: %v, want ErrNotSigner", err)
		}
		id, err := ca.Compose("revoke", unnamed, Payload{})
		if err != nil || stored(ca, id).Intent.Record.Operator != "op1" {
			t.Fatalf("with its own key: err %v, signed as %q", err, stored(ca, id).Intent.Record.Operator)
		}
	})

	t.Run("every record of one actor on one call shares a slot", func(t *testing.T) {
		_, ca := setup(t)
		if _, err := ca.Compose("turn", turn("a1", 2), Payload{}); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("note", noteOn("a1", "c1"), Payload{}); !errors.Is(err, ErrSlotBusy) {
			t.Fatalf("a note while a turn on the same call is unresolved: %v, want ErrSlotBusy", err)
		}
	})

	t.Run("the stored intent shares no memory with the caller's record", func(t *testing.T) {
		_, ca := setup(t)
		r := turn("a1", 2)
		id, err := ca.Compose("turn", r, Payload{})
		if err != nil {
			t.Fatal(err)
		}
		*r.Expect.TurnCount = 99
		if got := *stored(ca, id).Intent.Record.Expect.TurnCount; got != 2 {
			t.Fatalf("the stored intent now expects turn count %d", got)
		}
	})

	t.Run("an intent that was never stored cannot be sent", func(t *testing.T) {
		e, ca := setup(t)
		if _, err := ca.Send(e.q, "credA-99", At(e.now)); err == nil {
			t.Fatal("sending an unknown intent returned no error")
		}
	})

	t.Run("unknown_anchor closes the intent and forces a resolve", func(t *testing.T) {
		e := newLine(t)
		e.commit(note("a1"))
		ca := e.client("credA")
		// A relay whose line of the same name differs at the client's checkpoint.
		fork := newLine(t)
		fork.now += 5
		fork.commit(note("a1"))
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		if _, err := ca.Compose("activate", activate, Payload{}); err != nil {
			t.Fatal(err)
		}
		a, _ := ca.Send(fork.q, id, At(fork.now))
		e.want(a, ClassRefusal, "unknown_anchor")
		if stored(ca, id).Status != OutClosed {
			t.Fatal("a definitive refusal must close the intent")
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); !errors.Is(err, ErrMustResolve) {
			t.Fatalf("composing after unknown_anchor with another intent stored: %v, want ErrMustResolve", err)
		}
	})

	t.Run("only history_unavailable raises the suspicion of a rollback", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		e.commit(revoke("credA"))
		a, _ := ca.Send(e.q, id, At(e.now))
		e.want(a, ClassUnresolved, "revoked")
		// This client has not yet replayed its own revocation. Its key signs
		// nothing more (client_probe_test.go), but that is the key stopping,
		// not a suspected rollback.
		if _, err := ca.Compose("activate", activate, Payload{}); !errors.Is(err, ErrKeyRevoked) || errors.Is(err, ErrFailClosed) {
			t.Fatalf("composing after revoked: %v, want ErrKeyRevoked", err)
		}
	})

	t.Run("a suspected rollback is cleared only from outside", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		a, _ := ca.Send(rolledBack(t, e, 8), id, At(e.now))
		e.want(a, ClassUnresolved, "history_unavailable")
		if _, err := ca.Compose("activate", activate, Payload{}); !errors.Is(err, ErrFailClosed) {
			t.Fatalf("composing while a rollback is suspected: %v, want ErrFailClosed", err)
		}
		// Asking again does not clear it.
		ca.ResolveAll(e.q, At(e.now))
		if _, err := ca.Compose("activate", activate, Payload{}); !errors.Is(err, ErrFailClosed) {
			t.Fatalf("composing after a query: %v, want ErrFailClosed", err)
		}
		ca.ClearSuspicion()
		if _, err := ca.Compose("activate", activate, Payload{}); err != nil {
			t.Fatalf("composing after the suspicion was cleared: %v", err)
		}
	})

	t.Run("other bytes under the same identity leave the intent to be reconciled", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		other := stored(ca, id).Intent
		other.Digest = "other bytes under the same identity"
		e.wantOutcome(e.submit(other), Committed, "", false)
		a, _ := ca.Send(e.q, id, At(e.now))
		if a.Class != ClassMismatch {
			t.Fatalf("got %s, want a mismatch", showAnswer(a))
		}
		if o := stored(ca, id); o.Status != OutReconcile {
			t.Fatalf("%+v, want reconciliation-required", o)
		}
		ca.Send(e.q, id, At(e.now))
		if stored(ca, id).Sends != 1 {
			t.Fatal("it was sent again")
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); !errors.Is(err, ErrSlotBusy) {
			t.Fatalf("its slot: %v, want ErrSlotBusy", err)
		}
	})

	t.Run("resolving asks about unsettled intents only, and may settle one awaiting reconciliation", func(t *testing.T) {
		e, ca := setup(t)
		done, _ := ca.Compose("activate", activate, Payload{})
		a, _ := ca.Send(e.q, done, At(e.now))
		e.wantOutcome(a, Committed, "", false)
		e.sync(ca)

		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		stranger := newEnv(t)
		stranger.commit(lineInit())
		a, _ = ca.Send(stranger.q, id, At(e.now))
		e.want(a, ClassAdmission, "unknown_signer")

		// A restart with nothing pending still asks before composing.
		if err := ca.Restart(); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrMustResolve) {
			t.Fatalf("composing after a restart: %v, want ErrMustResolve", err)
		}
		// A relay that cannot say anything while its clock is uncertain
		// teaches nothing, and the reason stored with the intent stands.
		ca.ResolveAll(e.q, Clock{Now: e.now, Trusted: false})
		if o := stored(ca, id); o.Status != OutReconcile || o.Result.Code != "unknown_signer" {
			t.Fatalf("the unreconciled intent after an admission error on the query: %+v", o)
		}
		ca.ResolveAll(e.q, At(e.now))
		// The settled intent was not asked about again.
		if o := stored(ca, done); o.Status != OutDone || o.Result.Original {
			t.Fatalf("the settled intent after resolving: %+v", o)
		}
		// The relay has no outcome for the other. That teaches nothing: it
		// still awaits reconciliation, for the reason it had, and is not sent.
		if o := stored(ca, id); o.Status != OutReconcile || o.Result.Code != "unknown_signer" {
			t.Fatalf("the unreconciled intent after a query with no outcome: %+v", o)
		}
		ca.Send(e.q, id, At(e.now))
		if stored(ca, id).Sends != 1 {
			t.Fatal("it was sent again")
		}
		// Once its anchor has retired, the same query is definitive.
		e.retire(stored(ca, id).Intent.SeenSeq)
		ca.ResolveAll(e.q, At(e.now))
		if o := stored(ca, id); o.Status != OutClosed || o.Result.Code != "expired" {
			t.Fatalf("after its anchor retired: %+v", o)
		}
		if err := ca.Anchor(e.q, At(e.now)); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); err != nil {
			t.Fatalf("its slot after the query settled it: %v", err)
		}
	})

	t.Run("only an intent awaiting reconciliation can be reconciled", func(t *testing.T) {
		_, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		committed := Answer{Class: ClassOutcome, Outcome: Outcome{Kind: Committed}}
		if err := ca.Reconciled(id, committed); err == nil || stored(ca, id).Status != OutPending {
			t.Fatalf("reconciling a pending intent: err %v, %+v", err, stored(ca, id))
		}
	})

	t.Run("a refused anchor request is reported", func(t *testing.T) {
		e, ca := setup(t)
		e.commit(revoke("credA"))
		if err := ca.Anchor(e.q, At(e.now)); err == nil {
			t.Fatal("a revoked credential's anchor request returned no error")
		}
	})
}
