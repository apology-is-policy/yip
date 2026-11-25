package ldrcore

import (
	"errors"
	"strings"
	"testing"
)

// These tests cover the five defects Gemini's independent probe found at
// claude/ldr commit 2062b74 (G1-G5), plus the normative section 11.2 replay
// checks (J1-J3 under the ordinary profile) and anchor-retirement pruning in
// signedContext. Traces T48 to T50 are registered with the client traces.

func init() {
	for id, fn := range map[string]func(*testing.T){
		"T48": traceT48, "T49": traceT49, "T50": traceT50,
	} {
		clientTraceTests[id] = fn
	}
}

// T48: an admission error during ResolveAll does not complete the resolve pass
// (finding G1).
func traceT48(t *testing.T) {
	e := newLine(t)
	ca := e.client("credA")

	committed, err := ca.Compose("turn", turn("a1", 2), Payload{})
	if err != nil {
		t.Fatal(err)
	}
	uncommitted, err := ca.Compose("activate", activatePresence, Payload{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Restart(); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("after restart: got %v, want ErrMustResolve", err)
	}

	// Untrusted clock: both queries fail with clock_uncertain. Pass is incomplete.
	ca.ResolveAll(e.q, Clock{Now: e.now, Trusted: false})
	if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("after clock_uncertain on all queries: got %v, want ErrMustResolve", err)
	}

	// Even if one intent is committed in logIndex (answerable without the clock)
	// while the other still gets clock_uncertain, the pass stays incomplete.
	e.wantOutcome(e.submit(stored(ca, committed).Intent), Committed, "", false)
	ca.ResolveAll(e.q, Clock{Now: e.now, Trusted: false})
	if o := stored(ca, committed); o.Status != OutDone {
		t.Fatalf("committed intent after query: %+v", o)
	}
	if o := stored(ca, uncommitted); o.Status != OutPending || o.Result.Code != "clock_uncertain" {
		t.Fatalf("uncommitted intent after untrusted query: %+v", o)
	}
	if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); !errors.Is(err, ErrMustResolve) {
		t.Fatalf("after partial clock_uncertain pass: got %v, want ErrMustResolve", err)
	}

	// Once the clock is trusted, ResolveAll gets a non-admission answer for
	// every active unsettled intent and completes the pass.
	ca.ResolveAll(e.q, At(e.now))
	if _, err := ca.Compose("note", noteOn("a2", "c1"), Payload{}); err != nil {
		t.Fatalf("after completed resolve pass: %v", err)
	}
}

// T49: a halted or rollback-suspecting client requests no anchor (finding G2).
func traceT49(t *testing.T) {
	t.Run("halted client makes no anchor request", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		bad := e.q.Log()
		bad[5].Head = "ffffffffffffffff"
		if err := ca.Sync(bad); err == nil || ca.Halted() == "" {
			t.Fatalf("expected halt, got err=%v halted=%q", err, ca.Halted())
		}
		e.now += testProfile.FreshnessMS + 1
		before := len(e.q.Log())
		if err := ca.Anchor(e.q, At(e.now)); !errors.Is(err, ErrFailClosed) || len(e.q.Log()) != before {
			t.Fatalf("halted client Anchor: err=%v, log %d->%d; want ErrFailClosed and no request", err, before, len(e.q.Log()))
		}
	})

	t.Run("rollback-suspecting client makes no anchor request until cleared", func(t *testing.T) {
		e := newLine(t)
		ca := e.client("credA")
		id, _ := ca.Compose("turn", turn("a1", 2), Payload{})
		a, _ := ca.Send(rolledBack(t, e, 8), id, At(e.now))
		e.want(a, ClassUnresolved, "history_unavailable")

		e.now += testProfile.FreshnessMS + 1
		before := len(e.q.Log())
		if err := ca.Anchor(e.q, At(e.now)); !errors.Is(err, ErrFailClosed) || len(e.q.Log()) != before {
			t.Fatalf("suspect client Anchor: err=%v, log %d->%d; want ErrFailClosed and no request", err, before, len(e.q.Log()))
		}

		ca.ClearSuspicion()
		if err := ca.Anchor(e.q, At(e.now)); err != nil || len(e.q.Log()) != before+1 {
			t.Fatalf("after ClearSuspicion: err=%v, log %d->%d; want nil and one time_anchor", err, before, len(e.q.Log()))
		}
	})
}

// T50: ordinary-profile replay enforces signed-context rules (J1-J3) and
// prunes retired anchors from signedContext (spec 11.2).
func traceT50(t *testing.T) {
	// makeEntry builds a validly chained plain-profile frame (no StateCommit).
	makePlain := func(t *testing.T, e *env, r Record, seenSeq int64, seenHead, opID string, gen int64, at int64) Entry {
		t.Helper()
		s := e.q.State()
		l := s.Line
		r.AuthEpoch, r.KeyEpoch = l.AuthEpoch, l.KeyEpoch
		if r.ValidityMS == 0 {
			r.ValidityMS = testValidity
		}
		if a := l.Actors[r.Actor]; r.Origin == OriginActor && a != nil {
			r.Cred, r.BindingGen = a.Cred, a.BindingGen
		}
		next, out := Apply(s, r, at, testProfile)
		if out.Kind != Committed {
			t.Fatalf("helper Apply(%s): %s %s", r.Type, out.Kind, out.Reason)
		}
		_, prevHead := e.q.Head()
		en := Entry{
			Seq:      next.Line.HeadSeq,
			SeqTime:  at,
			Prev:     prevHead,
			SeenHead: seenHead,
			Key:      OpKey{Generation: gen, Signer: signerOf(&r), SeenSeq: seenSeq, OpID: opID},
			Digest:   "d:" + opID,
			Record:   r,
		}
		en.Head = frameHead(&en)
		return en
	}

	t.Run("J1 wrong generation rejected on ordinary replay", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		seq, head := e.q.Head()
		bad := makePlain(t, e, note("a1"), seq, head, "g2-op", 2, e.q.State().Line.HeadTime+1)
		var v *ViolationError
		if err := cb.Sync([]Entry{bad}); !errors.As(err, &v) || !strings.Contains(v.Reason, "another generation") {
			t.Fatalf("got %v, want ViolationError mentioning another generation", err)
		}
	})

	t.Run("J2 expired deadline rejected on ordinary replay", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		seq, head := e.q.Head()
		r := note("a1")
		r.ValidityMS = 1
		bad := makePlain(t, e, r, seq, head, "late-op", 1, e.q.State().Line.HeadTime+2)
		var v *ViolationError
		if err := cb.Sync([]Entry{bad}); !errors.As(err, &v) || !strings.Contains(v.Reason, "committed 2 ms after its anchor") {
			t.Fatalf("got %v, want ViolationError mentioning deadline", err)
		}
	})

	t.Run("J3 duplicate committed operation identity rejected on ordinary replay", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		in, _ := e.commit(note("a1"))
		e.sync(cb)
		dup := makePlain(t, e, in.Record, in.SeenSeq, in.SeenHead, in.OpID, in.Generation, e.q.State().Line.HeadTime+1)
		var v *ViolationError
		if err := cb.Sync([]Entry{dup}); !errors.As(err, &v) || !strings.Contains(v.Reason, "repeats the operation identity") {
			t.Fatalf("got %v, want ViolationError mentioning repeated identity", err)
		}
	})

	t.Run("off-chain anchor head rejected on ordinary replay", func(t *testing.T) {
		e := newLine(t)
		cb := e.client("credB")
		seq, _ := e.q.Head()
		bad := makePlain(t, e, note("a1"), seq, "0123456789abcdef", "fork-op", 1, e.q.State().Line.HeadTime+1)
		var v *ViolationError
		if err := cb.Sync([]Entry{bad}); !errors.As(err, &v) || !strings.Contains(v.Reason, "not on this chain") {
			t.Fatalf("got %v, want ViolationError mentioning off-chain head", err)
		}
	})

	t.Run("retired anchors and their identities are pruned and still refused", func(t *testing.T) {
		e := newLine(t)
		in, _ := e.commit(note("a1")) // seq 13, anchored at 12
		cb := e.client("credB")
		if _, held := cb.signed.anchors[12]; !held {
			t.Fatal("anchor 12 must be held before retirement")
		}
		if _, held := cb.signed.ops[opKey(in)]; !held {
			t.Fatal("op at seq 13 must be indexed before anchor 12 retires")
		}

		// Advance past anchor 12's retirement and commit a time anchor.
		e.now = e.q.State().Line.HeadTime + testProfile.ValidityMaxMS + 1
		if _, _, wrote, a := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); !wrote || a.Class != "" {
			t.Fatalf("anchor request failed: wrote=%v %s", wrote, showAnswer(a))
		}
		e.sync(cb)

		if _, held := cb.signed.anchors[12]; held {
			t.Fatal("retired anchor 12 was not pruned from signedContext")
		}
		if _, held := cb.signed.ops[opKey(in)]; held {
			t.Fatal("retired op identity under anchor 12 was not pruned from signedContext")
		}

		// Replaying the retired op or any new record anchored at 12 is still refused.
		late := makePlain(t, e, in.Record, in.SeenSeq, in.SeenHead, in.OpID, in.Generation, e.now+1)
		var v *ViolationError
		if err := cb.Sync([]Entry{late}); !errors.As(err, &v) || !strings.Contains(v.Reason, "not a head this verifier holds") {
			t.Fatalf("late record on pruned anchor: got %v, want ViolationError", err)
		}
	})
}

// TestGeminiProbeRegressions verifies that G3, G4 and G5 from Gemini's
// independent probe of 2062b74 are closed.
func TestGeminiProbeRegressions(t *testing.T) {
	t.Run("G3 openWindow rejects non-monotonic timestamp", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		s := e.q.State()
		enc := EncodeState(s)
		f := &forger{t: t, snaps: snapshots{12: enc}, state: s, head: "invented"}
		f.stale(10, s.Line.HeadTime)
		future := Entry{
			Seq: 11, SeqTime: s.Line.HeadTime + 5000, Prev: f.head,
			Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: "0000000000000000",
		}
		future.Head = frameHead(&future)
		f.entries = append(f.entries, future)
		f.head = future.Head
		e12 := Entry{
			Seq: 12, SeqTime: s.Line.HeadTime, Prev: f.head,
			Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: digestEncoded("L", commitProfile, enc),
		}
		e12.Head = frameHead(&e12)
		f.entries = append(f.entries, e12)
		f.head = e12.Head
		f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		wantRefused(t, joinErr(t, pinC, f, f, e.now), "stamped later than record 12")
	})

	t.Run("G3 openWindow rejects missing StateDigest on prior frame", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		s := e.q.State()
		enc := EncodeState(s)
		f := &forger{t: t, snaps: snapshots{12: enc}, state: s, head: "invented"}
		bad11 := Entry{
			Seq: 11, SeqTime: s.Line.HeadTime - commitProfile.ValidityMaxMS - 1, Prev: f.head,
			Record: Record{Origin: OriginSequencer, Type: "time_anchor"},
		}
		bad11.Head = frameHead(&bad11)
		f.entries = append(f.entries, bad11)
		f.head = bad11.Head
		e12 := Entry{
			Seq: 12, SeqTime: s.Line.HeadTime, Prev: f.head,
			Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: digestEncoded("L", commitProfile, enc),
		}
		e12.Head = frameHead(&e12)
		f.entries = append(f.entries, e12)
		f.head = e12.Head
		f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		wantRefused(t, joinErr(t, pinC, f, f, e.now), "carries no state commitment")
	})

	t.Run("G3 openWindow rejects sequencer signer fields in live window", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		s := e.q.State()
		enc := EncodeState(s)
		f := &forger{t: t, snaps: snapshots{12: enc}, state: s, head: "invented"}
		bad11 := Entry{
			Seq: 11, SeqTime: s.Line.HeadTime - commitProfile.ValidityMaxMS - 1, Prev: f.head,
			Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: "0000000000000000",
			Sig:         "forged",
		}
		bad11.Head = frameHead(&bad11)
		f.entries = append(f.entries, bad11)
		f.head = bad11.Head
		e12 := Entry{
			Seq: 12, SeqTime: s.Line.HeadTime, Prev: f.head,
			Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: digestEncoded("L", commitProfile, enc),
		}
		e12.Head = frameHead(&e12)
		f.entries = append(f.entries, e12)
		f.head = e12.Head
		f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		wantRefused(t, joinErr(t, pinC, f, f, e.now), "sequencer-origin and carries a signer's fields")
	})

	t.Run("G3 openWindow rejects negative budget and non-line_init at seq 1", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		s := e.q.State()
		s.Line.HeadSeq = 1
		enc := EncodeState(s)
		f := &forger{t: t, snaps: snapshots{1: enc}, state: s, head: genesisHead("L")}
		e1 := Entry{
			Seq: 1, SeqTime: s.Line.HeadTime, Prev: genesisHead("L"),
			Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: digestEncoded("L", commitProfile, enc),
		}
		e1.Head = frameHead(&e1)
		f.entries = append(f.entries, e1)
		f.head = e1.Head
		f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")

		neg := pinC
		neg.MaxWindowRecords = -1
		je := joinErr(t, neg, f, f, e.now)
		wantRefused(t, je, "over this joiner's budget")
		if !errors.Is(je, ErrWindowTooLarge) {
			t.Fatalf("negative budget: got %v, want ErrWindowTooLarge", je)
		}

		// With a valid budget, seq 1 not being line_init is still refused.
		wantRefused(t, joinErr(t, pinC, f, f, e.now), "first record of the line is time_anchor, not line_init")
	})

	t.Run("G4 verifyFrame rejects negative line_init validity, empty OpID/Digest, and time_anchor Digest", func(t *testing.T) {
		log := newLineWith(t, commitProfile).q.Log()
		log[0].Record.ValidityMS = -5
		log[0].Sig = signatureOf(Root, &log[0])
		if _, _, err := ReplayVerified("L", log, commitProfile); err == nil || !strings.Contains(err.Error(), "rejected invalid") {
			t.Fatalf("negative line_init validity: got %v", err)
		}

		e := joinLine(t)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.OpID = "" })
		if _, _, err := ReplayVerified("L", f.entries, commitProfile); err == nil || !strings.Contains(err.Error(), "operation identity that does not fit") {
			t.Fatalf("empty OpID: got %v", err)
		}

		f2 := forgeOnto(t, e.q.Log(), e.q.State())
		f2.sign(note("a1"), "cred:credA", func(en *Entry) { en.Digest = "" })
		if _, _, err := ReplayVerified("L", f2.entries, commitProfile); err == nil || !strings.Contains(err.Error(), "operation identity that does not fit") {
			t.Fatalf("empty Digest: got %v", err)
		}

		f3 := forgeOnto(t, e.q.Log(), e.q.State())
		f3.anchor(func(en *Entry) { en.Digest = "unexpected-digest" })
		if _, _, err := ReplayVerified("L", f3.entries, commitProfile); err == nil || !strings.Contains(err.Error(), "sequencer-origin and carries a signer's fields") {
			t.Fatalf("non-empty time_anchor Digest: got %v", err)
		}
	})

	t.Run("G5 DecodeState rejects unreachable snapshot states", func(t *testing.T) {
		base := newLineWith(t, commitProfile).q.State()
		cases := map[string]func(*State){
			"root_rev zero in generation 1": func(s *State) {
				s.Line.RootRev = 0
			},
			"key_epoch 0 with rekey_pending false": func(s *State) {
				s.Line.KeyEpoch = 0
				s.Line.Readers = map[int64][]string{}
				s.Line.RekeyPending = false
			},
			"unknown register type in RegisterWriters": func(s *State) {
				s.Line.RegisterWriters["a1/not_a_register"] = &RegisterWriter{
					WriterRev: 1, Incarnation: "inc1", BindingGen: 1, Used: []string{"inc1"},
				}
			},
			"empty Readers for active epoch": func(s *State) {
				s.Line.Readers[1] = []string{}
			},
			"empty Readers map with active key_epoch": func(s *State) {
				s.Line.Readers = map[int64][]string{}
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				s := base.Clone()
				mutate(&s)
				if _, err := DecodeState(EncodeState(s), DefaultSnapshotBudget); !errors.Is(err, ErrSnapshotEncoding) {
					t.Fatalf("%s: got %v, want ErrSnapshotEncoding", name, err)
				}
			})
		}
	})
}
