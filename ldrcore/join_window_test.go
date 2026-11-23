package ldrcore

import (
	"errors"
	"strings"
	"testing"
)

// These tests cover what Codex's probe of the first version of the
// exploration found (call 0003, turn 27): three checks that neither verifier
// made, and a premise about the endorsing device that nothing exercised.
//
// The three checks are things admission decides and Apply never sees: the
// generation an intent was signed for, its deadline, and whether its
// operation identity had already committed. A verifier that only re-derives
// outcomes takes whatever a relay chose to admit. In each test here the
// members and the operator are honest and the relay holds no key: what it
// commits are bytes a member really signed, in a place or at a time where an
// honest relay would not have put them.
//
// See join_test.go for the helpers and for what a hand-built frame may claim.

// bothRefuse wants the same refusal from replay from genesis and from a join
// of pin against the forger, with the snapshot taken from the honest line.
func bothRefuse(t *testing.T, pin JoinPin, e *env, f *forger, part string) {
	t.Helper()
	if _, _, err := ReplayVerified("L", f.entries, commitProfile); err == nil || !strings.Contains(err.Error(), part) {
		t.Errorf("replay from genesis: got %v, want a refusal mentioning %q", err, part)
	}
	wantRefused(t, joinErr(t, pin, f, e.q, e.now), part)
}

func TestWhatAdmissionDecidedIsCheckedAgain(t *testing.T) {
	// start is the fourteen-record line with credC enrolled at 13, the real
	// log in a relay's hands, and the time of the head.
	start := func(t *testing.T) (*env, *forger, int64) {
		e := joinLine(t)
		return e, forgeOnto(t, e.q.Log(), e.q.State()), e.q.State().Line.HeadTime
	}

	t.Run("a record signed for another generation", func(t *testing.T) {
		// a1 signed this note for a generation 2. The relay commits it into
		// generation 1.
		e, f, _ := start(t)
		f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.Generation = 2 })
		bothRefuse(t, pinC, e, f, "record 15 (call_note) was signed for another generation")
	})

	t.Run("a record committed after its deadline", func(t *testing.T) {
		e, f, head := start(t)
		in := e.intent(note("a1")) // signed over the head at 14
		in.ValidityMS = 1

		// At its deadline it is admissible: the boundary is inclusive.
		f.frame(in, head+1)
		if _, _, err := ReplayVerified("L", f.entries, commitProfile); err != nil {
			t.Fatalf("replay from genesis refuses a record committed at its deadline: %v", err)
		}
		if j := mustJoin(t, pinC, f, e.q, e.now); j.Seq != 15 {
			t.Fatalf("accepted at %d, want 15", j.Seq)
		}

		// One millisecond later it is not, and an honest relay says so.
		_, late, _ := start(t)
		late.frame(in, head+2)
		bothRefuse(t, pinC, e, late, "record 15 (call_note) committed 2 ms after its anchor at 14, with a validity of 1 ms")
		e.now = head + 2
		e.want(e.submit(in), ClassRefusal, "expired")
	})

	t.Run("one signed operation committed twice", func(t *testing.T) {
		e, f, head := start(t)
		in := e.intent(note("a1"))
		first := f.frame(in, head+1)
		again := f.frame(in, head+2)
		if first.Sig != again.Sig || first.Key != again.Key || first.Digest != again.Digest {
			t.Fatal("the second frame does not carry the same signed bytes as the first")
		}
		if got, was := f.state.Calls["c1"].NoteCount, e.q.State().Calls["c1"].NoteCount; got != was+2 {
			t.Fatalf("the relay's state counts %d notes after %d, want two more", got, was)
		}
		bothRefuse(t, pinC, e, f, "record 16 (call_note) repeats the operation identity that committed at 15")
	})

	t.Run("one operation identity under two sets of bytes", func(t *testing.T) {
		// a1 signed the same intent twice, which gives different bytes under
		// one identity (spec 5.1). The relay commits both.
		e, f, head := start(t)
		in := e.intent(note("a1"))
		f.frame(in, head+1)
		in.Digest = "signed-again"
		f.frame(in, head+2)
		bothRefuse(t, pinC, e, f, "record 16 (call_note) repeats the operation identity that committed at 15")
	})

	t.Run("a line_init that is not signed over genesis", func(t *testing.T) {
		log := newLineWith(t, commitProfile).q.Log()
		log[0].SeenHead = "0123456789abcdef"
		log[0].Sig = signatureOf(Root, &log[0]) // as the root would have signed it
		if _, _, err := ReplayVerified("L", log, commitProfile); err == nil ||
			!strings.Contains(err.Error(), "record 1 (line_init) is not signed over genesis") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a later record signed over genesis", func(t *testing.T) {
		// Only line_init anchors on genesis.
		log := newLineWith(t, commitProfile).q.Log()
		log[1].Key.SeenSeq, log[1].SeenHead = 0, genesisHead("L")
		log[1].Sig = signatureOf(Root, &log[1])
		if _, _, err := ReplayVerified("L", log, commitProfile); err == nil ||
			!strings.Contains(err.Error(), "record 2 (operator_key_authorize) is anchored at 0, which is not a head this verifier holds") {
			t.Fatalf("got %v", err)
		}
	})
}

// since is a relay that serves no record numbered below from.
type since struct {
	JoinRelay
	from int64
}

func (r since) Entries(from, to int64) []Entry { return r.JoinRelay.Entries(max(from, r.from), to) }

// TestTheLiveWindow: what a joiner needs from before the endorsed head, and
// what a relay that holds no key can and cannot do with it.
func TestTheLiveWindow(t *testing.T) {
	// A joiner that reads nothing needs no key epoch, so these lines end at
	// the enrollment.
	pin := pinC
	pin.Grant.Reader = false
	enrollC := func() Record {
		r := enroll("credC", "nsC", "jr3")
		r.Grant.Reader = false
		return r
	}

	// noted is the twelve-record line with two notes after it, and an
	// enrollment of credC that op1 has signed over the head at 14 and not
	// yet sent.
	noted := func(t *testing.T) (e *env, note13, en Intent) {
		e = newLineWith(t, commitProfile)
		note13, _ = e.commit(note("a1")) // 13
		e.commit(note("b1"))             // 14
		e.now++
		return e, note13, e.intent(enrollC())
	}
	// replayed is that line in the hands of a relay that commits the note at
	// 13 a second time, at 15, before the enrollment at 16. The note is
	// anchored at 12 and well within its deadline.
	replayed := func(t *testing.T) (*env, *forger) {
		e, note13, en := noted(t)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.frame(note13, e.now)
		f.frame(en, e.now)
		return e, f
	}

	t.Run("an operation that committed before the endorsed head is not committed again after it", func(t *testing.T) {
		e, f := replayed(t)
		bothRefuse(t, pin, e, f, "record 15 (call_note) repeats the operation identity that committed at 13")
		// Without the relay's extra record the same line is joined.
		h, _, en := noted(t)
		h.wantOutcome(h.submit(en), Committed, "", false)
		if j := mustJoin(t, pin, h.q, h.q, h.now); j.EndorsedSeq != 14 || j.WindowSeq != 1 || j.Seq != 15 {
			t.Fatalf("provenance %+v at %d", j.Provenance, j.Seq)
		}
	})

	t.Run("it cannot hide that operation by calling its record the sequencer's", func(t *testing.T) {
		// The type is under the head. The origin is not.
		e, f := replayed(t)
		f.at(13).Record.Origin = OriginSequencer
		wantRefused(t, joinErr(t, pin, f, e.q, e.now), "record at 13, in the live window, is a call_note of sequencer origin")
	})

	t.Run("it cannot give that operation another identity", func(t *testing.T) {
		e, f := replayed(t)
		f.at(13).Key.OpID = "another"
		wantRefused(t, joinErr(t, pin, f, e.q, e.now), "record at 13, in the live window, is not what its signer signed")
	})

	t.Run("it cannot end the window early by making a record look old", func(t *testing.T) {
		// Stamped long ago, the record at 14 would end the window before the
		// note at 13 is reached. Its time is under the head the record after
		// it names, whether or not the relay recomputes the frame's own head.
		for _, rehash := range []bool{false, true} {
			e, f := replayed(t)
			old := f.at(13)
			old.SeqTime -= commitProfile.ValidityMaxMS + 1
			if rehash {
				old.Head = frameHead(old)
			}
			wantRefused(t, joinErr(t, pin, f, e.q, e.now), "record offered at 13 does not open the head before the record at 14")
		}
	})

	t.Run("a window the relay does not supply is waited for", func(t *testing.T) {
		e := joinLine(t)
		wantPending(t, joinErr(t, pinC, since{e.q, 12}, e.q, e.now), "did not supply the record at 11")
		wantPending(t, joinErr(t, pinC, since{e.q, 2}, e.q, e.now), "did not supply the record at 1")
		mustJoin(t, pinC, since{e.q, 1}, e.q, e.now)
	})

	t.Run("a window over the joiner's budget is refused whole", func(t *testing.T) {
		e := joinLine(t)
		small := pinC
		small.MaxWindowRecords = 11 // the window is the twelve records up to the endorsed head
		je := joinErr(t, small, e.q, e.q, e.now)
		wantRefused(t, je, "over this joiner's budget")
		if !errors.Is(je, ErrWindowTooLarge) {
			t.Fatalf("over budget: %v", je)
		}
		small.MaxWindowRecords = 12
		mustJoin(t, small, e.q, e.q, e.now)
		// A budget below one is no way to ask for an unbounded window.
		small.MaxWindowRecords = -1
		if je := joinErr(t, small, e.q, e.q, e.now); !errors.Is(je, ErrWindowTooLarge) {
			t.Fatalf("a negative budget: %v", je)
		}
	})

	// aged is the twelve-record line, a note at 13, then more than the
	// maximum validity with nothing committed, a time anchor at 14, and an
	// enrollment of credC that op1 has signed over that anchor and not yet
	// sent. a1 signed two notes long ago and never sent them: one over the
	// head at 12, one over the head at 13.
	aged := func(t *testing.T) (e *env, over12, over13, en Intent) {
		e = newLineWith(t, commitProfile)
		over12 = e.intent(note("a1"))
		e.commit(note("b1")) // 13
		over13 = e.intent(note("a1"))
		e.now += commitProfile.ValidityMaxMS + 1000
		if seq, _, wrote, a := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); !wrote || seq != 14 || a.Class != "" {
			t.Fatalf("no time anchor at 14: seq %d, wrote %v, %s", seq, wrote, showAnswer(a))
		}
		e.now++
		return e, over12, over13, e.intent(enrollC())
	}

	t.Run("the window ends at the first record too old to be named", func(t *testing.T) {
		e, _, _, en := aged(t)
		e.wantOutcome(e.submit(en), Committed, "", false) // 15
		j := mustJoin(t, pin, e.q, e.q, e.now)
		if j.EndorsedSeq != 14 || j.WindowSeq != 13 || j.Seq != 15 {
			t.Fatalf("provenance %+v at %d, want the window to end at 13", j.Provenance, j.Seq)
		}
		// The joiner asked for nothing older.
		mustJoin(t, pin, since{e.q, 13}, e.q, e.now)
	})

	t.Run("a head exactly the maximum validity before the endorsed one can still be named", func(t *testing.T) {
		// The note at 13 is stamped exactly the maximum validity before the
		// time anchor at 14. An intent signed over 13 with the maximum
		// validity is admissible at that instant, so the window must hold 13
		// as a head and go on to the record before it.
		e := newLineWith(t, commitProfile)
		e.commit(note("b1")) // 13
		over13 := e.intent(note("a1"))
		over13.ValidityMS = commitProfile.ValidityMaxMS
		e.now += commitProfile.ValidityMaxMS
		if seq, _, wrote, a := e.q.AnchorRequest(CredentialPrincipal("credA"), At(e.now)); !wrote || seq != 14 || a.Class != "" {
			t.Fatalf("no time anchor at 14: seq %d, wrote %v, %s", seq, wrote, showAnswer(a))
		}
		en := e.intent(enrollC())
		e.wantOutcome(e.submit(over13), Committed, "", false) // 15, at its deadline
		e.now++
		e.wantOutcome(e.submit(en), Committed, "", false) // 16
		j := mustJoin(t, pin, e.q, e.q, e.now)
		if j.EndorsedSeq != 14 || j.WindowSeq != 12 || j.Seq != 16 {
			t.Fatalf("provenance %+v at %d, want the window to end at 12", j.Provenance, j.Seq)
		}
	})

	t.Run("a record anchored before the window was not admissible", func(t *testing.T) {
		// The relay commits the old note signed over 12, which the window
		// does not reach. Replay from genesis holds that head and refuses the
		// note on its deadline.
		e, over12, _, en := aged(t)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.frame(over12, e.now)
		f.frame(en, e.now)
		wantRefused(t, joinErr(t, pin, f, e.q, e.now), "record 15 (call_note) is anchored at 12, which is not a head this verifier holds")
		if _, _, err := ReplayVerified("L", f.entries, commitProfile); err == nil ||
			!strings.Contains(err.Error(), "record 15 (call_note) committed 601002 ms after its anchor at 12") {
			t.Fatalf("replay from genesis: %v, want a refusal on the deadline", err)
		}
	})

	t.Run("a record anchored on the window's oldest record is past its deadline", func(t *testing.T) {
		e, _, over13, en := aged(t)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.frame(over13, e.now)
		f.frame(en, e.now)
		bothRefuse(t, pin, e, f, "record 15 (call_note) committed 601001 ms after its anchor at 13")
	})

	t.Run("a member that was shown another history before the endorsed head", func(t *testing.T) {
		// a1 signed a note over a head at 13 that is not this chain's. The
		// joiner starts at 14 and still sees it (spec 5.2).
		e, _, en := noted(t)
		forked := e.intent(note("a1"))
		forked.SeenSeq, forked.SeenHead = 13, "0123456789abcdef"
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.frame(forked, e.now)
		f.frame(en, e.now)
		bothRefuse(t, pin, e, f, "record 15 was signed over a head that is not on this chain")
	})
}

// TestAnEndorsingDeviceVerifiesWhatItSignsOver: the join rests on the pinned
// operator's device having verified everything up to the head it signs over.
// Under a profile that commits state the client model does, and a client that
// has stopped signs nothing.
func TestAnEndorsingDeviceVerifiesWhatItSignsOver(t *testing.T) {
	// The device is op1's: a member's client that also holds the operator key.
	device := func() *Client {
		c := NewClient("L", "credA", commitProfile)
		c.OperatorKey = "op1"
		return c
	}

	t.Run("an honest device and an honest relay", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		d := device()
		send := func(action string, r Record) {
			t.Helper()
			if err := d.Sync(e.q.Log()); err != nil {
				t.Fatalf("the device does not verify the line: %v", err)
			}
			id, err := d.Compose(action, r, Payload{})
			if err != nil {
				t.Fatalf("%s: %v", action, err)
			}
			e.now++
			a, err := d.Send(e.q, id, At(e.now))
			if err != nil {
				t.Fatalf("%s: %v", action, err)
			}
			e.wantOutcome(a, Committed, "", false)
		}
		send("enroll credC", enroll("credC", "nsC", "jr3"))
		send("give credC the key", activate(2, "credA", "credB", "credC"))
		j := mustJoin(t, pinC, e.q, e.q, e.now)
		if j.EndorsedSeq != 12 || j.EnrollSeq != 13 || j.Seq != 14 {
			t.Fatalf("provenance %+v at %d", j.Provenance, j.Seq)
		}
	})

	// In each case the relay serves the real twelve records and then
	// something an honest relay would not have committed. The device stops
	// before it, and signs no enrollment over it.
	cases := map[string]struct {
		build func(e *env, f *forger)
		bad   int64
		part  string
	}{
		"a record no member signed": {func(e *env, f *forger) {
			f.sign(note("a1"), "")
		}, 13, "does not carry the signature"},
		"a record committed twice": {func(e *env, f *forger) {
			in := e.intent(note("a1"))
			f.frame(in, e.now+1)
			f.frame(in, e.now+2)
		}, 14, "repeats the operation identity that committed at 13"},
		"a record committed after its deadline": {func(e *env, f *forger) {
			in := e.intent(note("a1"))
			in.ValidityMS = 1
			f.frame(in, e.now+2)
		}, 13, "committed 2 ms after its anchor"},
		"a record signed for another generation": {func(e *env, f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.Generation = 2 })
		}, 13, "signed for another generation"},
		"a record signed over another history": {func(e *env, f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.SeenHead = "0123456789abcdef" })
		}, 13, "signed over a head that is not on this chain"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLineWith(t, commitProfile)
			f := forgeOnto(t, e.q.Log(), e.q.State())
			c.build(e, f)
			d := device()
			var v *ViolationError
			if err := d.Sync(f.entries); !errors.As(err, &v) || v.Seq != c.bad || !strings.Contains(v.Reason, c.part) {
				t.Fatalf("got %v, want a violation at %d mentioning %q", err, c.bad, c.part)
			}
			if ck, _ := d.Checkpoint(); ck != c.bad-1 || d.Halted() == "" {
				t.Fatalf("checkpoint %d, halted %q: want %d and stopped", ck, d.Halted(), c.bad-1)
			}
			if _, err := d.Compose("enroll credC", enroll("credC", "nsC", "jr3"), Payload{}); !errors.Is(err, ErrFailClosed) {
				t.Fatalf("the stopped device composed an enrollment: %v", err)
			}
		})
	}

	t.Run("the ordinary client model takes a signature as a premise", func(t *testing.T) {
		// Under the profile that commits no state, the client model checks
		// linkage and outcomes and nothing of the signed context (client.go).
		// The same unsigned note is taken. That is the model's stated
		// premise, and no joiner rests on such a client's signature.
		e := newLine(t)
		log := e.q.Log()
		s := e.q.State()
		r := note("a1")
		r.Cred, r.BindingGen = "credA", s.Line.Actors["a1"].BindingGen
		r.AuthEpoch, r.KeyEpoch, r.ValidityMS = s.Line.AuthEpoch, s.Line.KeyEpoch, testValidity
		next, out := Apply(s, r, s.Line.HeadTime+1, testProfile)
		if out.Kind != Committed {
			t.Fatalf("the note does not apply: %s %s", out.Kind, out.Reason)
		}
		en := Entry{Seq: next.Line.HeadSeq, SeqTime: next.Line.HeadTime, Record: r, Prev: log[11].Head, SeenHead: log[11].Head,
			Key: OpKey{Generation: 1, Signer: "cred:credA", SeenSeq: 12, OpID: "invented"}, Digest: "invented"}
		en.Head = frameHead(&en)
		c := NewClient("L", "credB", testProfile)
		if err := c.Sync(append(log, en)); err != nil {
			t.Fatalf("the ordinary client refused it: %v", err)
		}
		if ck, _ := c.Checkpoint(); ck != 13 {
			t.Fatalf("checkpoint %d, want 13", ck)
		}
	})
}
