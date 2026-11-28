package ldrcore

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// These tests execute the scenario traces that concern the agent's own
// machine, against the client model. Each is registered under its trace ID
// in clientTraceTests, and TestTraceCoverageLabels checks that table against
// the labels in the vectors file.

// commitP is commit with a payload attached.
func (e *env) commitP(r Record, p Payload) int64 {
	e.t.Helper()
	e.now++
	in := e.intent(r)
	in.Payload = p
	a := e.submit(in)
	if a.Class != ClassOutcome || a.Outcome.Kind != Committed {
		e.t.Fatalf("%s: got %s, want committed", r.Type, showAnswer(a))
	}
	return a.Seq
}

// padTo adds notes by a1 on c1 until the head is exactly seq.
func (e *env) padTo(seq int64) {
	e.t.Helper()
	for {
		head, _ := e.q.Head()
		if head == seq {
			return
		}
		if head > seq {
			e.t.Fatalf("head is already %d, past %d", head, seq)
		}
		e.commit(note("a1"))
	}
}

// sync runs the client's ordinary loop over the sequencer's log and requires
// its verified state to be exactly the sequencer's.
func (e *env) sync(c *Client) {
	e.t.Helper()
	if err := c.Run(e.q.Log()); err != nil {
		e.t.Fatalf("client %s: %v", c.Cred, err)
	}
	if d := diff(c.State(), e.q.State()); len(d) > 0 {
		e.t.Fatalf("client %s derived a different state:\n  %v", c.Cred, d)
	}
}

// client returns a client for cred that has replayed the line from genesis
// and acknowledged every notice so far.
func (e *env) client(cred string) *Client {
	e.t.Helper()
	c := NewClient("L", cred, testProfile)
	e.sync(c)
	for _, n := range c.Deliver() {
		c.Ack(n.ID)
	}
	return c
}

func noteOn(actor, call string) Record {
	r := actorRec("call_note", actor)
	r.Call = call
	return r
}

func openCall(from, to, call string) Record {
	r := actorRec("call_open", from)
	r.Call, r.To = call, to
	return r
}

func hasNotice(ns []Notice, id string) (Notice, bool) {
	for _, n := range ns {
		if n.ID == id {
			return n, true
		}
	}
	return Notice{}, false
}

// crashAt41 builds the situation three traces share: credB's client is
// caught up at seq 40, a1's turn commits at seq 41, and the client dies at
// the named point while taking it in.
func crashAt41(t *testing.T, fault string) (*env, *Client) {
	t.Helper()
	e := newLine(t)
	e.padTo(40)
	cb := e.client("credB")
	if _, seq := e.commit(turn("a1", 2)); seq != 41 {
		t.Fatalf("the turn committed at seq %d, want 41", seq)
	}
	cb.Fault = fault
	if err := cb.Run(e.q.Log()); !errors.Is(err, ErrCrashed) {
		t.Fatalf("the client did not die at %s: %v", fault, err)
	}
	if ck, _ := cb.Checkpoint(); ck != 41 {
		t.Fatalf("the record is not in the verified store: checkpoint %d", ck)
	}
	return e, cb
}

const turnFile, turnNotice = "calls/c1/turn-3", "g1-s41-b1"

var clientTraceTests = map[string]func(*testing.T){
	"T22": func(t *testing.T) { // crash between log-store commit and projection
		e := newLine(t)
		e.padTo(40)
		cb := e.client("credB")
		before := len(cb.Files())
		e.commit(turn("a1", 2))
		cb.Fault = FaultBeforeProjection
		if err := cb.Run(e.q.Log()); !errors.Is(err, ErrCrashed) {
			t.Fatalf("the client did not die before projecting: %v", err)
		}
		if ck, _ := cb.Checkpoint(); ck != 41 || cb.ProjectedSeq() != 40 {
			t.Fatalf("checkpoint %d, projected_seq %d; want 41 and 40", ck, cb.ProjectedSeq())
		}
		if _, ok := cb.Files()[turnFile]; ok {
			t.Fatal("the turn file exists before anything was projected")
		}

		if err := cb.Restart(); err != nil {
			t.Fatal(err)
		}
		files := cb.Files()
		if _, ok := files[turnFile]; !ok || cb.ProjectedSeq() != 41 {
			t.Fatalf("projection did not resume from 41: projected_seq %d", cb.ProjectedSeq())
		}
		if len(files) != before+1 || cb.Rebuilds() != 0 {
			t.Fatalf("%d files after, %d before, %d rebuilds; want exactly one new file and no rebuild",
				len(files), before, cb.Rebuilds())
		}

		// The notice is found by the scan cursor, under its stable ID.
		got := cb.Deliver()
		if len(got) != 1 || got[0].ID != turnNotice || cb.ScannedSeq() != 41 {
			t.Fatalf("delivered %v with the scan cursor at %d; want exactly %s", got, cb.ScannedSeq(), turnNotice)
		}
	},

	"T23": func(t *testing.T) { // a locally edited projection file has no authority
		e := newLine(t)
		cb := e.client("credB")
		cb.MarkSeen("b1", "c1")
		const path = "calls/c1/turn-2"
		orig, err := cb.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		floor, status, unread := cb.Floor("c1"), cb.Status("c1"), cb.Unread("b1", "c1")
		if floor != "a1" || status != "open" || unread != 0 {
			t.Fatalf("before the edit: floor %s, status %s, unread %d", floor, status, unread)
		}

		// b1 wrote turn 2. Make it look as if the peer, a1, did, and add a
		// turn that was never committed.
		cb.EditFile(path, strings.Replace(orig, "from=b1", "from=a1", 1))
		cb.EditFile(turnFile, "type=call_turn\ncall=c1\nfrom=a1\nturn=3\n")
		if f, s, u := cb.Floor("c1"), cb.Status("c1"), cb.Unread("b1", "c1"); f != floor || s != status || u != unread {
			t.Fatalf("after the edit: floor %s, status %s, unread %d", f, s, u)
		}
		// The edit is caught at the read, not at some later rebuild.
		if _, err := cb.ReadFile(path); !errors.Is(err, ErrTainted) {
			t.Fatalf("reading the edited file: %v, want ErrTainted", err)
		}
		if _, err := cb.ReadFile(turnFile); !errors.Is(err, ErrNoAuthority) {
			t.Fatalf("reading a file the store never defined: %v, want ErrNoAuthority", err)
		}

		if err := cb.Rebuild(); err != nil {
			t.Fatal(err)
		}
		files := cb.Files()
		if files[path] != orig {
			t.Fatal("the rebuild did not restore the file from the verified store")
		}
		if _, ok := files[turnFile]; ok {
			t.Fatal("the rebuild kept a file the store never defined")
		}
		if _, err := cb.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	},

	"T24": func(t *testing.T) { // three unreadable states, and replay continues past each
		e := newEnv(t)
		e.commit(lineInit())
		e.commit(Record{Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK1", OperatorKey: "op1", Expect: Expect{RootRev: ptr(1)}})
		e.commit(enroll("credA", "nsA", "jr1"))
		e.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", Manifest: []string{"credA"}, Expect: Expect{KeyEpoch: ptr(0)}})
		e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credA", Namespace: "nsA", Actor: "a1"})
		e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credA", Namespace: "nsA", Actor: "a2"})
		e.commit(openCall("a1", "a2", "cX")) // under epoch 1, before credB exists
		e.commit(enroll("credB", "nsB", "jr2"))
		e.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", Manifest: []string{"credA", "credB"}, Expect: Expect{KeyEpoch: ptr(1)}})
		e.commit(Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credB", Namespace: "nsB", Actor: "b1"})
		e.commit(openCall("a1", "b1", "c1"))
		e.commitP(turn("b1", 1), Payload{Forged: true})
		st := actorRec("call_status", "a1")
		st.Call, st.State, st.Expect.LifecycleRev, st.Expect.TurnCount = "c1", "deferred", ptr(0), ptr(2)
		statusSeq := e.commitP(st, Payload{Malformed: true})
		_, noteSeq := e.commit(note("a1"))

		// credB replays the whole line. sync requires its state to equal the
		// sequencer's, so every record after an unreadable one was applied.
		cb := e.client("credB")
		files := cb.Files()
		for path, want := range map[string]string{
			"calls/cX/turn-1": "body=" + ReadNoKey,
			"calls/c1/turn-2": "body=" + ReadUndecryptable,
			fmt.Sprintf("calls/c1/status-%d", statusSeq): "reason=" + ReadMalformed,
			fmt.Sprintf("calls/c1/note-%d", noteSeq):     "body=" + ReadOK,
		} {
			if !strings.Contains(files[path], want+"\n") {
				t.Errorf("%s does not say %s:\n%s", path, want, files[path])
			}
		}
		if cb.State().Calls["cX"] == nil {
			t.Error("the control record of a call this reader cannot read was not applied")
		}
		if cb.Status("c1") != "deferred" {
			t.Errorf("the lifecycle change with a malformed reason did not stand: status %s", cb.Status("c1"))
		}
		if cb.Halted() != "" {
			t.Errorf("an unreadable payload stopped replay: %s", cb.Halted())
		}

		// Wrong local key material is indistinguishable from bad ciphertext,
		// so the reader state cannot name the writer as the one at fault.
		ca := e.client("credA")
		ca.CorruptKey(2)
		if err := ca.Rebuild(); err != nil {
			t.Fatal(err)
		}
		if got := ca.Files()["calls/c1/turn-1"]; !strings.Contains(got, "body="+ReadUndecryptable+"\n") {
			t.Errorf("a good payload under a wrong local key reads as:\n%s", got)
		}
	},

	"T27": func(t *testing.T) { // outbox single-flight is client discipline
		e := newLine(t)
		e.commit(openCall("a2", "b1", "c2"))
		e.commit(openCall("a1", "a2", "c5"))
		ca := e.client("credA")
		send := func(id string) Answer {
			t.Helper()
			e.now++
			a, err := ca.Send(e.q, id, At(e.now))
			if err != nil {
				t.Fatal(err)
			}
			return a
		}

		first, err := ca.Compose("first note on c1", noteOn("a1", "c1"), Payload{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("second note on c1", noteOn("a1", "c1"), Payload{}); !errors.Is(err, ErrSlotBusy) {
			t.Fatalf("a second intent in slot (a1, c1): %v, want ErrSlotBusy", err)
		}
		if n := len(ca.Outbox()); n != 1 {
			t.Fatalf("%d intents were built, want 1", n)
		}

		// a2 is a different actor on the same credential.
		id, err := ca.Compose("a2 notes c2", noteOn("a2", "c2"), Payload{})
		if err != nil {
			t.Fatalf("slot (a2, c2) is separate: %v", err)
		}
		e.wantOutcome(send(id), Committed, "", false)

		// Both actors of credA take part in c5.
		if _, err := ca.Compose("a1 notes c5", noteOn("a1", "c5"), Payload{}); err != nil {
			t.Fatal(err)
		}
		id, err = ca.Compose("a2 notes c5", noteOn("a2", "c5"), Payload{})
		if err != nil {
			t.Fatalf("slot (a2, c5) is separate from (a1, c5): %v", err)
		}
		e.wantOutcome(send(id), Committed, "", false)
		for _, o := range ca.Outbox() {
			if o.Intent.Record.Cred != "credA" {
				t.Fatalf("%s is signed by %q, want credA", o.ID, o.Intent.Record.Cred)
			}
		}

		// The first note resolves; asking again is a new operation.
		e.wantOutcome(send(first), Committed, "", false)
		again, err := ca.Compose("another note on c1", noteOn("a1", "c1"), Payload{})
		if err != nil || again == first {
			t.Fatalf("after the first note resolved: id %q, err %v", again, err)
		}
		e.wantOutcome(send(again), Committed, "", false)
		if n := e.q.State().Calls["c1"].NoteCount; n != 2 {
			t.Fatalf("c1 has %d notes, want 2", n)
		}
		e.checkReplay()
	},

	"T29": func(t *testing.T) { // a local delivery pause does not change a broadcast's audience
		e := newLine(t)
		cb := e.client("credB")
		rev := e.q.State().Line.AudienceRev
		cb.Pause("b1")
		if len(cb.Outbox()) != 0 || e.q.State().Line.AudienceRev != rev {
			t.Fatal("pausing local delivery reached the line")
		}
		st := e.q.State()
		audience := st.Line.DefaultAudience()
		_, seq := e.commit(Record{Origin: OriginOperator, Type: "broadcast_create", Operator: "op1", Broadcast: "bc2",
			Kind: "announcement", Recipients: audience, DefaultAudience: true, Expect: Expect{AudienceRev: ptr(rev)}})
		if got := e.q.State().Broadcasts["bc2"].Recipients; !reflect.DeepEqual(canonSet(got), []string{"a1", "a2", "b1"}) {
			t.Fatalf("the snapshot is %v; b1 must remain in it", got)
		}
		// The notice waits locally and is handed over when the pause ends.
		e.sync(cb)
		id := fmt.Sprintf("g1-s%d-b1", seq)
		if _, ok := hasNotice(cb.Notices(), id); !ok || len(cb.Deliver()) != 0 {
			t.Fatal("while paused, the notice must be queued and not delivered")
		}
		cb.Resume("b1")
		if _, ok := hasNotice(cb.Deliver(), id); !ok {
			t.Fatal("the notice was not delivered after the pause ended")
		}
	},

	"T35": func(t *testing.T) { // crash after projecting a file and before the projection cursor advances
		_, cb := crashAt41(t, FaultAfterFileWrite)
		written, ok := cb.Files()[turnFile]
		if !ok || cb.ProjectedSeq() != 40 {
			t.Fatalf("file exists: %t, projected_seq %d; want the file and 40", ok, cb.ProjectedSeq())
		}
		n := len(cb.Files())

		if err := cb.Restart(); err != nil {
			t.Fatal(err)
		}
		files := cb.Files()
		if cb.ProjectedSeq() != 41 || files[turnFile] != written || len(files) != n {
			t.Fatalf("projected_seq %d, %d files (was %d)", cb.ProjectedSeq(), len(files), n)
		}
		if cb.Rebuilds() != 0 {
			t.Fatal("an existing byte-identical file was treated as corruption")
		}
	},

	"T36": func(t *testing.T) { // crash after a notice is enqueued and before the scan cursor advances
		_, cb := crashAt41(t, FaultAfterEnqueue)
		if _, ok := hasNotice(cb.Notices(), turnNotice); !ok || cb.ScannedSeq() != 40 {
			t.Fatalf("notice queued: %t, scan cursor %d; want the notice and 40", ok, cb.ScannedSeq())
		}

		if err := cb.Restart(); err != nil {
			t.Fatal(err)
		}
		var at41 []Notice
		for _, n := range cb.Notices() {
			if n.Seq == 41 {
				at41 = append(at41, n)
			}
		}
		if len(at41) != 1 || at41[0].ID != turnNotice || cb.ScannedSeq() != 41 {
			t.Fatalf("after the rescan: %v, scan cursor %d; want the one notice under the same ID", at41, cb.ScannedSeq())
		}
		// At least once: it is handed over again until acknowledged, always
		// under the same ID. Exactly-once to a runtime is not claimed.
		cb.Deliver()
		got, _ := hasNotice(cb.Deliver(), turnNotice)
		if got.Attempts != 2 {
			t.Fatalf("%d attempts under one ID, want 2", got.Attempts)
		}
		cb.Ack(turnNotice)
		if len(cb.Deliver()) != 0 {
			t.Fatal("an acknowledged notice was delivered again")
		}
	},

	"T42": func(t *testing.T) { // a relay that refuses the signer: no reason to send again, no evidence of non-commit
		e := newLine(t)
		ca := e.client("credA")
		id, err := ca.Compose("note", noteOn("a1", "c1"), Payload{})
		if err != nil {
			t.Fatal(err)
		}
		e.q.Overloaded = true
		a, _ := ca.Send(e.q, id, At(e.now))
		e.want(a, ClassAdmission, "overloaded")
		if stored(ca, id).Status != OutPending {
			t.Fatal("an overload must leave the intent pending")
		}
		e.q.Overloaded = false

		// A relay that has a line called L and has never heard of credA.
		stranger := newEnv(t)
		stranger.commit(lineInit())
		a, _ = ca.Send(stranger.q, id, At(e.now))
		e.want(a, ClassAdmission, "unknown_signer")
		if o := stored(ca, id); o.Status != OutReconcile || o.Sends != 2 {
			t.Fatalf("after the refusal of the signer: %+v", o)
		}
		// It is not sent again, to that relay or to the one the client knows.
		logLen := len(e.q.Log())
		ca.Send(stranger.q, id, At(e.now))
		ca.Send(e.q, id, At(e.now))
		if stored(ca, id).Sends != 2 || len(e.q.Log()) != logLen {
			t.Fatal("an intent awaiting reconciliation was sent again")
		}
		if _, err := ca.Compose("another note", noteOn("a1", "c1"), Payload{}); !errors.Is(err, ErrSlotBusy) {
			t.Fatalf("its slot while unreconciled: %v, want ErrSlotBusy", err)
		}

		// The operator asks the relay the client had verified. While the
		// anchor is live the answer settles nothing; once it has retired, a
		// miss is definitive.
		in := stored(ca, id).Intent
		got := e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
		e.want(got, ClassUnknown, "outcome_unknown")
		if err := ca.Reconciled(id, got); err == nil {
			t.Fatal("outcome_unknown must not settle an intent")
		}
		e.retire(in.SeenSeq)
		got = e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
		e.want(got, ClassRefusal, "expired")
		if err := ca.Reconciled(id, got); err != nil || stored(ca, id).Status != OutClosed {
			t.Fatalf("after reconciliation: err %v, %+v", err, stored(ca, id))
		}
		if err := ca.Anchor(e.q, At(e.now)); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("another note", noteOn("a1", "c1"), Payload{}); err != nil {
			t.Fatalf("the slot after reconciliation: %v", err)
		}
	},
}

// stored returns the outbox entry with the given ID.
func stored(c *Client, id string) OutboxEntry {
	for _, o := range c.Outbox() {
		if o.ID == id {
			return o
		}
	}
	return OutboxEntry{}
}

func TestClientTraces(t *testing.T) {
	for id, fn := range clientTraceTests {
		t.Run(id, fn)
	}
}

// A fault at any point, any number of times, must leave the client where a
// client that never crashed would be: the same verified state, the same
// files, the same notices.
func TestClientCrashAnywhere(t *testing.T) {
	faults := []string{"", FaultBeforeProjection, FaultAfterFileWrite, FaultAfterEnqueue}
	for seed := int64(1); seed <= 3; seed++ {
		rng := rand.New(rand.NewSource(seed))
		e := newLine(t)
		ca, cb := NewClient("L", "credA", testProfile), NewClient("L", "credB", testProfile)
		floor := "a1"
		turns := int64(2)
		for step := 0; step < 300; step++ {
			switch rng.Intn(4) {
			case 0:
				e.commit(turn(floor, turns))
				turns++
				if floor == "a1" {
					floor = "b1"
				} else {
					floor = "a1"
				}
			case 1:
				e.commit(note([]string{"a1", "b1"}[rng.Intn(2)]))
			case 2:
				e.commit(Record{Origin: OriginOperator, Type: "broadcast_create", Operator: "op1",
					Broadcast: fmt.Sprintf("r%d-%d", seed, step), Kind: "announcement", Recipients: []string{"a1", "a2", "b1"}})
			case 3:
				e.now += 20000 // let an anchor be due
				if _, _, _, a := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); a.Class != "" {
					t.Fatalf("anchor request: %s", showAnswer(a))
				}
			}
			for _, c := range []*Client{ca, cb} {
				if rng.Intn(3) == 0 {
					continue // this client lags
				}
				c.Fault = faults[rng.Intn(len(faults))]
				err := c.Run(e.q.Log())
				for errors.Is(err, ErrCrashed) {
					c.Fault = faults[rng.Intn(len(faults))]
					err = c.Catchup() // what a restart does, possibly dying again
				}
				if err != nil {
					t.Fatalf("seed %d step %d: %v", seed, step, err)
				}
				if c.ProjectedSeq() > mustSeq(c) || c.ScannedSeq() > mustSeq(c) {
					t.Fatalf("seed %d step %d: a cursor is ahead of the checkpoint", seed, step)
				}
			}
		}
		for _, c := range []*Client{ca, cb} {
			c.Fault = ""
			e.sync(c)
			fresh := NewClient("L", c.Cred, testProfile)
			e.sync(fresh)
			if !reflect.DeepEqual(c.Files(), fresh.Files()) {
				t.Errorf("seed %d: %s's files differ from a client that never crashed", seed, c.Cred)
			}
			if !reflect.DeepEqual(noticeIDs(c), noticeIDs(fresh)) {
				t.Errorf("seed %d: %s's notices differ from a client that never crashed", seed, c.Cred)
			}
			if c.Rebuilds() != 0 {
				t.Errorf("seed %d: %s rebuilt its projection %d times; a crash alone must never taint it", seed, c.Cred, c.Rebuilds())
			}
			for path := range c.Files() {
				if _, err := c.ReadFile(path); err != nil {
					t.Errorf("seed %d: %s: verified read of %s: %v", seed, c.Cred, path, err)
				}
			}
		}
	}
}

func mustSeq(c *Client) int64 {
	seq, _ := c.Checkpoint()
	return seq
}

func noticeIDs(c *Client) []string {
	var out []string
	for _, n := range c.Notices() {
		out = append(out, n.ID)
	}
	return out
}

// A client stops at the first thing no honest sequencer produces, keeps what
// it had verified, and signs nothing afterwards.
func TestClientStopsAtAViolation(t *testing.T) {
	cases := map[string]func(log []Entry) []Entry{
		"a head that does not chain": func(log []Entry) []Entry {
			log[12].Head = "0000000000000000"
			return log
		},
		"a record that cannot commit on replay": func(log []Entry) []Entry {
			// The same turn again, chained correctly: it conflicts.
			dup := log[12]
			dup.Seq, dup.SeqTime = 14, log[12].SeqTime+1
			dup.Head = chainHead(log[12].Head, dup.Seq, dup.SeqTime, dup.Record.Type, dup.Digest)
			return append(log, dup)
		},
		"a time anchor inside the freshness window": func(log []Entry) []Entry {
			a := Entry{Seq: 14, SeqTime: log[12].SeqTime + 1, Record: Record{Origin: OriginSequencer, Type: "time_anchor"}}
			a.Head = chainHead(log[12].Head, a.Seq, a.SeqTime, a.Record.Type, a.Digest)
			return append(log, a)
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLine(t)
			cb := e.client("credB")
			e.commit(turn("a1", 2)) // seq 13
			err := cb.Sync(corrupt(e.q.Log()))
			var v *ViolationError
			if !errors.As(err, &v) {
				t.Fatalf("got %v, want a violation", err)
			}
			if cb.Halted() == "" {
				t.Fatal("the client did not stop")
			}
			if seq, _ := cb.Checkpoint(); seq < 12 || seq > 13 {
				t.Fatalf("the checkpoint is %d; it must hold what was verified and nothing after", seq)
			}
			if _, err := cb.Compose("a note", noteOn("b1", "c1"), Payload{}); !errors.Is(err, ErrFailClosed) {
				t.Fatalf("composing after a violation: %v, want ErrFailClosed", err)
			}
			if err := cb.Sync(e.q.Log()); err == nil {
				t.Fatal("a stopped client took in more records")
			}
		})
	}

	t.Run("a different record at a verified sequence number", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		log := e.q.Log()
		log[5].Head = "ffffffffffffffff"
		var v *ViolationError
		if err := cb.Sync(log); !errors.As(err, &v) || v.Seq != 6 {
			t.Fatalf("got %v, want a violation at seq 6", err)
		}
	})

	t.Run("a gap is not a verdict", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		e.commit(turn("a1", 2))
		e.commit(turn("b1", 3))
		if err := cb.Sync(e.q.Log()[13:]); err == nil || cb.Halted() != "" {
			t.Fatalf("a record offered out of order: err %v, halted %q; want an error and no halt", err, cb.Halted())
		}
		e.sync(cb)
	})
}

// Views carry the sequence number they were derived from, are replaced only
// by a higher one, and are verified at the read like any other file.
func TestProjectionViews(t *testing.T) {
	e := newLine(t)
	cb := e.client("credB")
	const view = "calls/c1/view"
	before, err := cb.ReadFile(view)
	if err != nil || !strings.Contains(before, "turn_count=2\n") {
		t.Fatalf("view before the turn (%v):\n%s", err, before)
	}

	// The store is ahead of the projection: the old view is stale, not wrong.
	_, seq := e.commit(turn("a1", 2))
	if err := cb.Sync(e.q.Log()); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.ReadFile(view); !errors.Is(err, ErrNotProjected) {
		t.Fatalf("reading a view the projection has not caught up to: %v, want ErrNotProjected", err)
	}
	if cb.Floor("c1") != "b1" {
		t.Fatal("verified state must already show the new floor")
	}
	if err := cb.Catchup(); err != nil {
		t.Fatal(err)
	}
	after, err := cb.ReadFile(view)
	if err != nil || !strings.HasPrefix(after, fmt.Sprintf("derived_gen=1\nderived_seq=%d\n", seq)) || !strings.Contains(after, "floor=b1\n") {
		t.Fatalf("view after the turn (%v):\n%s", err, after)
	}

	// An older view never replaces a newer one, and one that claims to be
	// newer than the store taints the projection.
	cb.EditFile(view, before)
	if _, err := cb.ReadFile(view); !errors.Is(err, ErrTainted) {
		t.Fatalf("an old view put back by hand: %v, want ErrTainted", err)
	}
	cb.EditFile(view, strings.Replace(after, fmt.Sprintf("derived_seq=%d", seq), "derived_seq=999", 1))
	e.commit(turn("b1", 3))
	e.sync(cb)
	if cb.Rebuilds() != 1 {
		t.Fatalf("%d rebuilds, want 1: a view from beyond the store must taint the projection", cb.Rebuilds())
	}
	if got, err := cb.ReadFile(view); err != nil || !strings.Contains(got, "turn_count=4\n") {
		t.Fatalf("view after the rebuild (%v):\n%s", err, got)
	}

	// Two measurements by one actor: the latest wins, and re-projecting the
	// older record does not bring it back.
	open := actorRec("dispute_open", "a1")
	open.Call = "c1"
	e.commit(open)
	measure := func(rev int64) int64 {
		m := actorRec("dispute_measure", "a1")
		m.Call, m.Dispute, m.Expect.MeasureRev = "c1", "1", ptr(rev)
		_, s := e.commit(m)
		return s
	}
	measure(0)
	second := measure(1)
	e.sync(cb)
	if err := cb.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got := cb.Files()["calls/c1/dispute-1/measure-a1"]; !strings.HasPrefix(got, fmt.Sprintf("derived_gen=1\nderived_seq=%d\n", second)) {
		t.Fatalf("the measurement view is not the latest:\n%s", got)
	}
}

// The outbox rules that no trace exercises.
func TestOutboxDiscipline(t *testing.T) {
	setup := func(t *testing.T) (*env, *Client) {
		e := newLine(t)
		return e, e.client("credA")
	}
	entry := func(c *Client, id string) OutboxEntry {
		for _, o := range c.Outbox() {
			if o.ID == id {
				return o
			}
		}
		return OutboxEntry{}
	}

	t.Run("an admission error settles nothing and the same bytes go again", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		digest := entry(ca, id).Intent.Digest
		e.q.Overloaded = true
		a, _ := ca.Send(e.q, id, At(e.now))
		e.want(a, ClassAdmission, "overloaded")
		if entry(ca, id).Status != OutPending {
			t.Fatal("an admission error must leave the intent pending")
		}
		e.q.Overloaded = false
		a, _ = ca.Send(e.q, id, At(e.now))
		e.wantOutcome(a, Committed, "", false)
		if o := entry(ca, id); o.Sends != 2 || o.Intent.Digest != digest || o.Status != OutDone || o.Action != "turn" {
			t.Fatalf("after the retry: %+v", o)
		}
		// A settled intent is never sent again.
		a, _ = ca.Send(e.q, id, At(e.now))
		if entry(ca, id).Sends != 2 || a.Outcome.Kind != Committed {
			t.Fatal("a settled intent was sent again")
		}
	})

	t.Run("an admission error that can pass leaves the intent pending", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 1), Payload{}) // a stale count: it will be rejected
		e.q.QuotaMax = 0
		a, _ := ca.Send(e.q, id, At(e.now))
		e.want(a, ClassAdmission, "quota")
		if entry(ca, id).Status != OutPending {
			t.Fatal("a full quota must leave the intent pending")
		}
		a, _ = ca.Send(e.q, id, Clock{Now: e.now, Trusted: false})
		e.want(a, ClassAdmission, "clock_uncertain")
		if entry(ca, id).Status != OutPending {
			t.Fatal("an uncertain clock must leave the intent pending")
		}
		e.q.QuotaMax = 64
		a, _ = ca.Send(e.q, id, At(e.now))
		e.wantOutcome(a, Rejected, "conflict", false)
		if o := entry(ca, id); o.Status != OutDone || o.Sends != 3 {
			t.Fatalf("after the third send: %+v", o)
		}
	})

	t.Run("an admission error that waiting does not remove suspends sending", func(t *testing.T) {
		for code, relay := range map[string]*Sequencer{
			"no_line":    NewSequencer("L", testProfile),
			"wrong_line": NewSequencer("M", testProfile),
		} {
			e, ca := setup(t)
			id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
			a, _ := ca.Send(relay, id, At(e.now))
			e.want(a, ClassAdmission, code)
			if o := entry(ca, id); o.Status != OutReconcile {
				t.Fatalf("%s: %+v, want reconciliation-required", code, o)
			}
			// It is not closed: an admission error is not evidence of non-commit.
			if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); !errors.Is(err, ErrSlotBusy) {
				t.Fatalf("%s: the slot: %v, want ErrSlotBusy", code, err)
			}
			// The cause may be corrected, but nothing here sends on its own:
			// offered the right relay, the client still does not send.
			if a, _ := ca.Send(e.q, id, At(e.now)); a.Class != ClassAdmission || entry(ca, id).Sends != 1 {
				t.Fatalf("%s: a suspended intent was sent again: %+v, sends %d", code, a, entry(ca, id).Sends)
			}
			// A query that finds no outcome settles nothing and frees nothing.
			in := entry(ca, id).Intent
			unknown := e.q.Query(signerOf(&in.Record), opKey(in), in.Digest, At(e.now))
			if err := ca.Reconciled(id, unknown); err == nil || entry(ca, id).Status != OutReconcile {
				t.Fatalf("%s: %s %s settled the intent: %+v", code, unknown.Class, unknown.Code, entry(ca, id))
			}
		}
	})

	t.Run("an admission code the client does not know suspends sending", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		ca.settle(ca.out.find(id), Answer{Class: ClassAdmission, Code: "a_code_from_a_later_relay"})
		if o := entry(ca, id); o.Status != OutReconcile {
			t.Fatalf("%+v, want reconciliation-required", o)
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); !errors.Is(err, ErrSlotBusy) {
			t.Fatalf("the slot: %v, want ErrSlotBusy", err)
		}
		if a, _ := ca.Send(e.q, id, At(e.now)); a.Code != "a_code_from_a_later_relay" || entry(ca, id).Sends != 0 {
			t.Fatalf("a suspended intent was sent: %+v, sends %d", a, entry(ca, id).Sends)
		}
	})

	t.Run("after a restart nothing is composed before stored intents are asked about", func(t *testing.T) {
		e, ca := setup(t)
		sent, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		held, _ := ca.Compose("note on c1 by a2 is not possible; a2 declares nothing", Record{Origin: OriginCredential,
			Type: "register_activate", Actor: "a2", Register: "presence", Incarnation: "i1", Expect: Expect{WriterRev: ptr(0)}}, Payload{})
		// The turn commits, and the answer is lost with the process.
		in := entry(ca, sent).Intent
		e.wantOutcome(e.submit(in), Committed, "", false)
		if err := ca.Restart(); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrMustResolve) {
			t.Fatalf("composing before resolving: %v, want ErrMustResolve", err)
		}
		ca.ResolveAll(e.q, At(e.now))
		if o := entry(ca, sent); o.Status != OutDone || !o.Result.Original || o.Sends != 0 {
			t.Fatalf("the committed turn after the query: %+v", o)
		}
		// The relay has no outcome for the one never sent. That is not a
		// cancellation: it stays pending and still holds its slot.
		if o := entry(ca, held); o.Status != OutPending || o.Result.Class != ClassUnknown {
			t.Fatalf("the unsent intent after the query: %+v", o)
		}
		if _, err := ca.Compose("again", Record{Origin: OriginCredential, Type: "register_activate", Actor: "a2",
			Register: "presence", Incarnation: "i2", Expect: Expect{WriterRev: ptr(0)}}, Payload{}); !errors.Is(err, ErrSlotBusy) {
			t.Fatalf("its slot after the query: %v, want ErrSlotBusy", err)
		}
	})

	t.Run("an expired intent is closed and forces a resolve", func(t *testing.T) {
		e, ca := setup(t)
		late, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		other, _ := ca.Compose("note", noteOn("a2", "c1"), Payload{})
		e.now += testValidity + 1000
		a, _ := ca.Send(e.q, late, At(e.now))
		e.want(a, ClassRefusal, "expired")
		if entry(ca, late).Status != OutClosed {
			t.Fatal("a definitive refusal must close the intent")
		}
		if _, err := ca.Compose("turn again", turn("a1", 2), Payload{}); !errors.Is(err, ErrMustResolve) {
			t.Fatalf("composing after a stale-checkpoint refusal: %v, want ErrMustResolve", err)
		}
		_ = other
		ca.ResolveAll(e.q, At(e.now))
		// The slot is free again: a deliberately new intent, with a new op_id.
		if err := ca.Anchor(e.q, At(e.now)); err != nil {
			t.Fatal(err)
		}
		fresh, err := ca.Compose("turn again", turn("a1", 2), Payload{})
		if err != nil || fresh == late {
			t.Fatalf("a new intent after the refusal: id %q, err %v", fresh, err)
		}
		a, _ = ca.Send(e.q, fresh, At(e.now))
		e.wantOutcome(a, Committed, "", false)
	})

	t.Run("a refusal that resolves nothing is never resubmitted", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		e.commit(revoke("credA"))
		a, _ := ca.Send(e.q, id, At(e.now))
		e.want(a, ClassUnresolved, "revoked")
		if entry(ca, id).Status != OutReconcile {
			t.Fatal("revoked must mark the intent reconciliation-required")
		}
		ca.Send(e.q, id, At(e.now))
		if entry(ca, id).Sends != 1 {
			t.Fatal("a reconciliation-required intent was sent again")
		}
		if err := ca.Reconciled(id, Answer{Class: ClassUnknown}); err == nil {
			t.Fatal("outcome_unknown must not settle an intent")
		}
		// The operator reconciles by naming the operation and its digest.
		in := entry(ca, id).Intent
		got := e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
		if got.Class != ClassUnknown {
			t.Fatalf("the operator's query: %s", showAnswer(got))
		}
		e.retire(in.SeenSeq)
		got = e.q.Query(OperatorPrincipal("op1"), opKey(in), in.Digest, At(e.now))
		e.want(got, ClassRefusal, "expired")
		if err := ca.Reconciled(id, got); err != nil || entry(ca, id).Status != OutClosed {
			t.Fatalf("after reconciliation: err %v, %+v", err, entry(ca, id))
		}
	})

	t.Run("history the relay does not have stops the client", func(t *testing.T) {
		e, ca := setup(t)
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		// A relay that was rolled back to an earlier point of the same line.
		old := newLine(t)
		old.q = NewSequencer("L", testProfile)
		for _, entry := range e.q.Log()[:8] {
			in := Intent{LineID: "L", Generation: entry.Key.Generation, OpID: entry.Key.OpID, SeenSeq: entry.Key.SeenSeq,
				ValidityMS: testValidity, Digest: entry.Digest, SignatureOK: true, Record: entry.Record}
			in.SeenHead, _ = old.q.HeadAt(in.SeenSeq)
			if a := old.q.Submit(in, At(entry.SeqTime)); a.Class != ClassOutcome {
				t.Fatalf("rebuilding the rolled-back relay: %s", showAnswer(a))
			}
		}
		a, _ := ca.Send(old.q, id, At(e.now))
		e.want(a, ClassUnresolved, "history_unavailable")
		if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrFailClosed) {
			t.Fatalf("composing while a rollback is suspected: %v, want ErrFailClosed", err)
		}
	})

	t.Run("a client signs only for what it holds", func(t *testing.T) {
		e, ca := setup(t)
		for name, r := range map[string]Record{
			"an actor bound to another credential": noteOn("b1", "c1"),
			"another credential":                   {Origin: OriginCredential, Type: "actor_declare", Cred: "credB", Namespace: "nsB", Actor: "b9"},
			"an operator key it does not hold":     revoke("credB"),
			"a root key it does not hold":          {Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK1", OperatorKey: "op2", Expect: Expect{RootRev: ptr(2)}},
		} {
			if _, err := ca.Compose(name, r, Payload{}); !errors.Is(err, ErrNotSigner) {
				t.Errorf("%s: %v, want ErrNotSigner", name, err)
			}
		}
		if len(ca.Outbox()) != 0 {
			t.Fatal("a refused compose stored an intent")
		}
		_ = e
	})
}

// A client that holds a root key and an operator key can bring a line up from
// nothing through its own outbox, anchoring only on what it has verified.
func TestClientBootstrapsALine(t *testing.T) {
	e := newEnv(t)
	c := NewClient("L", "credA", testProfile)
	c.RootKey, c.OperatorKey = "rootK1", "op1"
	do := func(r Record) {
		t.Helper()
		id, err := c.Compose(r.Type, r, Payload{})
		if err != nil {
			t.Fatalf("%s: %v", r.Type, err)
		}
		e.now++
		a, _ := c.Send(e.q, id, At(e.now))
		e.wantOutcome(a, Committed, "", false)
		e.sync(c)
	}
	if _, err := c.Compose("too early", Record{Origin: OriginRoot, Type: "operator_key_authorize", OperatorKey: "op1",
		Expect: Expect{RootRev: ptr(1)}}, Payload{}); !errors.Is(err, ErrNoLine) {
		t.Fatalf("an ordinary intent with nothing to anchor on: %v, want ErrNoLine", err)
	}
	do(lineInit())
	if _, err := c.Compose("other root", Record{Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK2",
		OperatorKey: "op1", Expect: Expect{RootRev: ptr(1)}}, Payload{}); !errors.Is(err, ErrNotSigner) {
		t.Fatalf("signing as the other root key: %v, want ErrNotSigner", err)
	}
	do(Record{Origin: OriginRoot, Type: "operator_key_authorize", OperatorKey: "op1", Expect: Expect{RootRev: ptr(1)}})
	do(enroll("credA", "nsA", "jr1"))
	if c.HasKey(1) {
		t.Fatal("a key for an epoch that does not exist")
	}
	do(Record{Origin: OriginOperator, Type: "key_epoch_activate", Manifest: []string{"credA"}, Expect: Expect{KeyEpoch: ptr(0)}})
	do(Record{Origin: OriginCredential, Type: "actor_declare", Namespace: "nsA", Actor: "a1"})
	do(Record{Origin: OriginCredential, Type: "actor_declare", Namespace: "nsA", Actor: "a2"})
	do(openCall("a1", "a2", "c1"))
	if !c.HasKey(1) || c.Floor("c1") != "a2" {
		t.Fatalf("after bootstrap: has key %t, floor %s", c.HasKey(1), c.Floor("c1"))
	}
	// A manifest names it and its wrap does not verify: it holds no key.
	c.FailWrap(1)
	if c.HasKey(1) {
		t.Fatal("a wrap that did not verify still gave a key")
	}
	e.checkReplay()
}
