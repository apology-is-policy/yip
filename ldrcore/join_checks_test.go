package ldrcore

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// These tests take the checks of Join and of the frame verification one at a
// time. See join_test.go for the helpers and for what a hand-built frame is
// allowed to claim.

// forgeFrame starts a chain at one hand-built frame: numbered seq, stamped
// at, committing to enc, which the forger also supplies as the snapshot. s is
// the state the forger goes on from. Before the frame stands one that is old
// enough to end the live window.
func forgeFrame(t *testing.T, s State, seq, at int64, enc []byte) *forger {
	t.Helper()
	f := &forger{t: t, snaps: snapshots{seq: enc}, state: s, head: "invented"}
	f.stale(seq-1, at)
	e := Entry{Seq: seq, SeqTime: at, Prev: f.head, Record: Record{Origin: OriginSequencer, Type: "time_anchor"},
		StateDigest: digestEncoded("L", commitProfile, enc)}
	e.Head = frameHead(&e)
	f.entries, f.head = append(f.entries, e), e.Head
	return f
}

// anchor appends a time anchor far enough after the last record to be legal.
func (f *forger) anchor(edit ...func(*Entry)) Entry {
	f.t.Helper()
	r := Record{Origin: OriginSequencer, Type: "time_anchor"}
	at := f.state.Line.HeadTime + commitProfile.FreshnessMS + 1
	next, out := Apply(f.state, r, at, commitProfile)
	if out.Kind != Committed {
		f.t.Fatalf("the forger's time anchor does not commit: %s", out.Kind)
	}
	return f.push(Entry{Seq: next.Line.HeadSeq, SeqTime: at, Record: r}, next, "", edit...)
}

func TestStatesThatMeanTheSameEncodeTheSame(t *testing.T) {
	s := newLineWith(t, commitProfile).q.State()
	other := s.Clone()
	other.Line.Tombstones.JoinRequests = []string{"jr2", "jr1"} // the same set, in another order
	other.Calls["c1"].Byes = []string{}                         // empty, where s has none
	other.Line.Tombstones.OperatorKeys = nil
	if !bytes.Equal(EncodeState(s), EncodeState(other)) {
		t.Fatal("two representations of one state have two encodings")
	}
	if StateDigest("L", commitProfile, s) != StateDigest("L", commitProfile, other) {
		t.Fatal("two representations of one state have two digests")
	}
}

// TestANullIsNotAnObject: bytes that are valid JSON and put a null where a
// state has an object must be refused, and must not bring the decoder down.
func TestANullIsNotAnObject(t *testing.T) {
	e := newLineWith(t, commitProfile)
	e.commit(Record{Origin: OriginCredential, Type: "register_activate", Cred: "credA", Actor: "a1", Register: "presence",
		Incarnation: "inc1", Expect: Expect{WriterRev: ptr(0)}})
	enc := EncodeState(e.q.State())
	for _, object := range []string{`"credA":`, `"a1":`, `"a1/presence":`, `"c1":`, `"bc1":`} {
		at := bytes.Index(enc, []byte(object+"{"))
		if at < 0 {
			t.Fatalf("the encoding has no object under %s", object)
		}
		// Replace the object under this key by null.
		depth, end := 0, at+len(object)
		for i := end; i < len(enc); i++ {
			if enc[i] == '{' {
				depth++
			} else if enc[i] == '}' {
				depth--
				if depth == 0 {
					end = i + 1
					break
				}
			}
		}
		bad := append(append(bytes.Clone(enc[:at+len(object)]), []byte("null")...), enc[end:]...)
		if _, err := DecodeState(bad, DefaultSnapshotBudget); !errors.Is(err, ErrSnapshotEncoding) {
			t.Errorf("a null under %s: got %v, want ErrSnapshotEncoding", object, err)
		}
	}
	// A dispute, inside a call.
	bad := bytes.Replace(enc, []byte(`"disputes":{}`), []byte(`"disputes":{"1":null}`), 1)
	if _, err := DecodeState(bad, DefaultSnapshotBudget); bytes.Equal(bad, enc) || !errors.Is(err, ErrSnapshotEncoding) {
		t.Errorf("a null dispute: got %v, want ErrSnapshotEncoding", err)
	}
}

// TestAMemberLinksOntoItsOwnHead: a frame that names another predecessor,
// and whose head is right for that predecessor, does not follow the head the
// member verified.
func TestAMemberLinksOntoItsOwnHead(t *testing.T) {
	for name, tc := range map[string]struct {
		prof Profile
		part string
	}{
		"committing state": {commitProfile, "does not name the head before it"},
		"plain":            {testProfile, "does not chain"},
	} {
		log := newLineWith(t, tc.prof).q.Log()
		log[10].Prev = "0123456789abcdef"
		log[10].Head = frameHead(&log[10])
		c := NewClient("L", "credA", tc.prof)
		var v *ViolationError
		if err := c.Sync(log); !errors.As(err, &v) || v.Seq != 11 || !strings.Contains(v.Reason, tc.part) {
			t.Errorf("%s: got %v, want a violation at 11", name, err)
		}
		if ck, _ := c.Checkpoint(); ck != 10 {
			t.Errorf("%s: checkpoint %d, want 10", name, ck)
		}
	}
}

func TestWhatTheSequencerHandsOutIsTheCallers(t *testing.T) {
	e := joinLine(t)
	if got := e.q.Entries(12, 13); len(got) != 2 || got[0].Seq != 12 || got[1].Seq != 13 {
		t.Fatalf("Entries(12, 13) returned %d records", len(got))
	}
	if got := e.q.Entries(14, 99); len(got) != 1 || got[0].Seq != 14 {
		t.Fatalf("Entries(14, 99) returned %d records", len(got))
	}
	snap, _ := e.q.SnapshotAt(12)
	clear(snap)
	en, _ := e.q.Enrollment("credC")
	en.Record.Grant.Namespace = "changed"
	es := e.q.Entries(12, 14)
	es[1].Record.Grant.ActorLimit = 99
	es[2].Record.Manifest[0] = "changed"

	again, _ := e.q.Enrollment("credC")
	if g := again.Record.Grant; g.Namespace != "nsC" || g.ActorLimit != 4 {
		t.Fatalf("a caller changed the sequencer's enrollment record: %+v", g)
	}
	mustJoin(t, pinC, e.q, e.q, e.now)
}

func TestJoinOnAnHonestRelay(t *testing.T) {
	t.Run("an operator endorses nothing at a head where it was not one", func(t *testing.T) {
		// op2 signs an enrollment over the head at 12, where only op1 is an
		// operator, guessing the authorization epoch that its own
		// authorization will produce. The root then authorizes it and the
		// enrollment commits: the relay judges the signer at commit.
		e := newLineWith(t, commitProfile)
		r := enroll("credC", "nsC", "jr3")
		r.Operator = "op2"
		in := e.intent(r)
		in.Record.AuthEpoch++
		e.commit(Record{Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK1", OperatorKey: "op2", Expect: Expect{RootRev: ptr(2)}})
		e.now++
		e.wantOutcome(e.submit(in), Committed, "", false)
		e.commit(activate(2, "credA", "credB", "credC"))

		pin := pinC
		pin.Operator = "op2"
		wantRefused(t, joinErr(t, pin, e.q, e.q, e.now), "not authorized in the endorsed state")
	})

	t.Run("a relay that names a head for a credential it never enrolled", func(t *testing.T) {
		e := newLineWith(t, commitProfile)
		_, err := Join(pinC, headNamer{e.q}, e.q, At(e.now))
		if !JoinPending(err) {
			t.Fatalf("got %v, want pending", err)
		}
		wantPending(t, joinErr(t, pinC, headNamer{e.q}, e.q, e.now), "holds no enrollment")
		if JoinPending(nil) || JoinPending(joinRefused("x")) {
			t.Fatal("JoinPending is true of something that is not pending")
		}
	})
}

// TestFrameVerification: a relay that holds no key, serving real records and
// then one frame of its own making. In each case the record in that frame is
// taken to be a member's real bytes; what the relay made is the frame.
func TestFrameVerification(t *testing.T) {
	cases := map[string]struct {
		build func(f *forger)
		part  string
	}{
		"a frame built on another head": {func(f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Prev = "0123456789abcdef" })
		}, "does not name the head before it"},
		"a head the frame does not hash to": {func(f *forger) {
			f.sign(note("a1"), "cred:credA")
			f.entries[len(f.entries)-1].Head = "0123456789abcdef"
		}, "does not chain onto the head before it"},
		"a time anchor with a signer": {func(f *forger) {
			f.anchor(func(en *Entry) { en.Sig = signatureOf("cred:credA", en) })
		}, "sequencer-origin and carries a signer's fields"},
		"a time anchor with an operation identity": {func(f *forger) {
			f.anchor(func(en *Entry) { en.Key = OpKey{Generation: 1, Signer: "cred:credA", OpID: "x"} })
		}, "sequencer-origin and carries a signer's fields"},
		"a time anchor that names a head": {func(f *forger) {
			f.anchor(func(en *Entry) { en.SeenHead = "0123456789abcdef" })
		}, "sequencer-origin and carries a signer's fields"},
		"an operation identity of another signer": {func(f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.Signer = "cred:credB" })
		}, "operation identity that does not fit"},
		"a record signed over its own position": {func(f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.SeenSeq = en.Seq })
		}, "operation identity that does not fit"},
		"a record signed over a negative position": {func(f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.SeenSeq = -1 })
		}, "operation identity that does not fit"},
		"a record signed for another generation": {func(f *forger) {
			f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Key.Generation = 2 })
		}, "signed for another generation"},
		"a time anchor too soon after the record before it": {func(f *forger) {
			next := f.state.Clone()
			next.Line.HeadSeq++
			next.Line.HeadTime++
			f.push(Entry{Seq: next.Line.HeadSeq, SeqTime: next.Line.HeadTime,
				Record: Record{Origin: OriginSequencer, Type: "time_anchor"}}, next, "")
		}, "does not commit on replay"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := joinLine(t)
			f := forgeOnto(t, e.q.Log(), e.q.State())
			c.build(f)
			wantRefused(t, joinErr(t, pinC, f, e.q, e.now), c.part)
		})
	}

	t.Run("a sequence number skipped", func(t *testing.T) {
		// Fifteen records, the last of them numbered 16.
		e := joinLine(t)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.sign(note("a1"), "cred:credA", func(en *Entry) { en.Seq = 16 })
		wantPending(t, joinErr(t, pinC, f, e.q, e.now), "supplied 4 of the 5 records")
		wantRefused(t, joinErr(t, pinC, misnumbering{f}, e.q, e.now), "numbered 16 follows the record numbered 14")
	})

	t.Run("a legal time anchor is taken", func(t *testing.T) {
		e := joinLine(t)
		f := forgeOnto(t, e.q.Log(), e.q.State())
		f.anchor()
		if j := mustJoin(t, pinC, f, e.q, e.now); j.Seq != 15 {
			t.Fatalf("accepted at %d, want 15", j.Seq)
		}
	})

	t.Run("replay from genesis applies the same checks", func(t *testing.T) {
		with, without := newLineWith(t, commitProfile).q.Log(), newLine(t).q.Log()
		if _, _, err := ReplayVerified("L", with, testProfile); err == nil {
			t.Fatal("a profile without commitments replayed frames that carry them")
		}
		if _, _, err := ReplayVerified("L", without, commitProfile); err == nil {
			t.Fatal("a profile with commitments replayed frames that carry none")
		}
		if _, _, err := ReplayVerified("L", without, testProfile); err != nil {
			t.Fatalf("the plain chain does not replay: %v", err)
		}
		if _, _, err := ReplayVerified("M", with, commitProfile); err == nil {
			t.Fatal("a log replayed as another line's")
		}
		if _, _, err := ReplayVerified("L", with[1:], commitProfile); err == nil {
			t.Fatal("a log replayed without its first record")
		}
		// A signed field changed after the fact shows as a bad signature.
		with[8].SeenHead = "0123456789abcdef"
		if _, _, err := ReplayVerified("L", with, commitProfile); err == nil || !strings.Contains(err.Error(), "record 9 (actor_declare) does not carry the signature") {
			t.Fatalf("a record altered after it was signed: %v", err)
		}
		// The same record as its signer would have made it, had the signer
		// been shown another history: the signature is good and the head it
		// names is not on this chain.
		with[8].Sig = signatureOf(signerOf(&with[8].Record), &with[8])
		if _, _, err := ReplayVerified("L", with, commitProfile); err == nil || !strings.Contains(err.Error(), "record 9 was signed over a head that is not on this chain") {
			t.Fatalf("a record signed over another history: %v", err)
		}
	})
}

// TestJoinBindsTheTwoTogether: checks that hold even against a party that has
// the pinned operator's key and is the relay the joiner asks. Its state is
// the real one at 12; what it gets wrong is the wrapping.
func TestJoinBindsTheTwoTogether(t *testing.T) {
	real := func(t *testing.T) (State, int64) {
		e := newLineWith(t, commitProfile)
		return e.q.State(), e.now
	}
	enrollC := func(f *forger, edit ...func(*Entry)) {
		f.sign(enroll("credC", "nsC", "jr3"), "op:op1", edit...)
	}

	t.Run("the two together, getting it right", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		enrollC(f)
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		mustJoin(t, pinC, f, f, now)
	})

	t.Run("bytes that are not the canonical encoding of a state", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime, append(EncodeState(s), ' '))
		enrollC(f)
		wantRefused(t, joinErr(t, pinC, f, f, now), "not a coherent state")
	})

	t.Run("a state numbered otherwise than its frame", func(t *testing.T) {
		s, now := real(t)
		s.Line.HeadSeq = 11
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		enrollC(f, func(en *Entry) { en.Seq, en.Key.SeenSeq = 13, 12 })
		wantRefused(t, joinErr(t, pinC, f, f, now), "another coordinate")
	})

	t.Run("a state stamped otherwise than its frame", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime-1, EncodeState(s))
		enrollC(f)
		wantRefused(t, joinErr(t, pinC, f, f, now), "another coordinate")
	})

	t.Run("a state of another generation", func(t *testing.T) {
		s, now := real(t)
		s.Line.Generation = 2
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		enrollC(f)
		wantRefused(t, joinErr(t, pinC, f, f, now), "another coordinate")
	})

	t.Run("an enrollment signed over its own position, or over none", func(t *testing.T) {
		for _, seen := range []int64{13, 14, 0, -1} {
			s, now := real(t)
			f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
			enrollC(f, func(en *Entry) { en.Key.SeenSeq = seen })
			wantRefused(t, joinErr(t, pinC, f, f, now), "does not fit under the head the relay named")
		}
	})

	t.Run("a head named from before the enrollment", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		first := *f.at(12)
		enrollC(f)
		wantRefused(t, joinErr(t, pinC, earlier{f, first}, f, now), "does not fit under the head the relay named")
	})

	t.Run("another record shown as the enrollment", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		enrollC(f)
		shown := f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		f.shown = &shown
		wantRefused(t, joinErr(t, pinC, f, f, now), "offered as the enrollment is a key_epoch_activate")
	})

	t.Run("a frame numbered otherwise than the head the enrollment names", func(t *testing.T) {
		// The frame says 11, the state in it says 12, and the enrollment is
		// signed over "the head at 12".
		s, now := real(t)
		f := forgeFrame(t, s, 11, s.Line.HeadTime, EncodeState(s))
		enrollC(f)
		wantRefused(t, joinErr(t, pinC, everything{f}, snapshots{12: EncodeState(s)}, now),
			"does not open the head the operator signed over")
	})

	t.Run("an enrollment of another credential with this device's keys", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		r := enroll("credC", "nsC", "jr3")
		r.Cred = "credX"
		shown := f.sign(r, "op:op1")
		f.shown = &shown
		wantRefused(t, joinErr(t, pinC, f, f, now), "not for the keys this device requested")
	})

	t.Run("an enrollment shown with other bytes than were signed", func(t *testing.T) {
		s, now := real(t)
		f := forgeFrame(t, s, 12, s.Line.HeadTime, EncodeState(s))
		shown := f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
		shown.Digest = "other-bytes"
		f.shown = &shown
		wantRefused(t, joinErr(t, pinC, f, f, now), "does not carry the pinned operator's signature")
	})

	t.Run("a frame without a commitment at the endorsed head", func(t *testing.T) {
		s, now := real(t)
		e0 := Entry{Seq: 12, SeqTime: s.Line.HeadTime, Prev: "invented", Record: Record{Origin: OriginSequencer, Type: "time_anchor"}}
		e0.Head = frameHead(&e0)
		f := &forger{t: t, snaps: snapshots{12: EncodeState(s)}, entries: []Entry{e0}, state: s, head: e0.Head}
		enrollC(f)
		wantRefused(t, joinErr(t, pinC, f, f, now), "does not open the head the operator signed over")
	})

	t.Run("a frame in the live window under another number than its place", func(t *testing.T) {
		// The frame before the endorsed one hashes to the head it should and
		// says it is record 10.
		s, now := real(t)
		enc := EncodeState(s)
		f := &forger{t: t, snaps: snapshots{12: enc}, state: s, head: "invented"}
		f.stale(10, s.Line.HeadTime)
		e := Entry{Seq: 12, SeqTime: s.Line.HeadTime, Prev: f.head, Record: Record{Origin: OriginSequencer, Type: "time_anchor"},
			StateDigest: digestEncoded("L", commitProfile, enc)}
		e.Head = frameHead(&e)
		f.entries, f.head = append(f.entries, e), e.Head
		enrollC(f)
		f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
		wantPending(t, joinErr(t, pinC, f, f, now), "did not supply the record at 11")
		wantRefused(t, joinErr(t, pinC, misplaced{f, 11, *f.at(10)}, f, now),
			"record offered at 11 does not open the head before the record at 12")
	})

	t.Run("a first record that does not stand on genesis", func(t *testing.T) {
		// A chain that claims to begin at record 1 and is built on something
		// other than this line's genesis. The frames before 12 commit to
		// nothing anyone asks for; the joiner opens them and replays none.
		_, now := real(t)
		f := chainOf(t, "invented", 12)
		wantRefused(t, joinErr(t, pinC, f, f, now), "first record does not stand on this line's genesis")
		g := chainOf(t, genesisHead("L"), 12)
		if j := mustJoin(t, pinC, g, g, now); j.WindowSeq != 1 {
			t.Fatalf("the window was opened back to %d, want 1", j.WindowSeq)
		}
	})

	t.Run("a live window longer than the default budget", func(t *testing.T) {
		_, now := real(t)
		fits := chainOf(t, genesisHead("L"), DefaultWindowBudget)
		if j := mustJoin(t, pinC, fits, fits, now); j.WindowSeq != 1 || j.EndorsedSeq != DefaultWindowBudget {
			t.Fatalf("provenance %+v", j.Provenance)
		}
		over := chainOf(t, genesisHead("L"), DefaultWindowBudget+1)
		je := joinErr(t, pinC, over, over, now)
		if je.Pending || !errors.Is(je, ErrWindowTooLarge) {
			t.Fatalf("got %v, want the window refused as too large", je)
		}
	})
}

// chainOf is a chain of n frames built on prev, all stamped alike, of which
// only the last commits to a state anyone asks for: the real state of the
// twelve-record line, renumbered n. On it op1 enrolls credC and activates a
// key epoch. A party holding op1's key can build it with no relay at all.
func chainOf(t *testing.T, prev string, n int64) *forger {
	t.Helper()
	s := newLineWith(t, commitProfile).q.State()
	s.Line.HeadSeq = n
	f := &forger{t: t, snaps: snapshots{n: EncodeState(s)}, state: s, head: prev}
	for seq := int64(1); seq <= n; seq++ {
		var e Entry
		if seq == 1 {
			e = Entry{
				Seq: 1, SeqTime: s.Line.HeadTime, Prev: f.head, SeenHead: prev,
				Key:         OpKey{Generation: 1, Signer: RootPrincipal("rootK1"), SeenSeq: 0, OpID: "init"},
				Digest:      "init",
				Record:      lineInit(),
				StateDigest: "0000000000000000",
			}
			e.Sig = signatureOf(RootPrincipal("rootK1"), &e)
		} else {
			e = Entry{
				Seq: seq, SeqTime: s.Line.HeadTime, Prev: f.head,
				Record:      Record{Origin: OriginSequencer, Type: "time_anchor"},
				StateDigest: "0000000000000000",
			}
		}
		if seq == n {
			e.StateDigest = StateDigest("L", commitProfile, s)
		}
		e.Head = frameHead(&e)
		f.entries, f.head = append(f.entries, e), e.Head
	}
	f.sign(enroll("credC", "nsC", "jr3"), "op:op1")
	f.sign(activate(2, "credA", "credB", "credC"), "op:op1")
	return f
}

// misnumbering is a relay that counts its records and hands them over by
// position, whatever number each one claims. Its log begins at record 1.
type misnumbering struct{ *forger }

func (r misnumbering) AnchorRequest(string, Clock) (int64, string, bool, Answer) {
	return int64(len(r.entries)), r.head, false, Answer{}
}

func (r misnumbering) Entries(from, to int64) []Entry {
	return r.entries[from-1 : min(to, int64(len(r.entries)))]
}

// misplaced is a relay that, asked for the one record at a given number,
// hands over another.
type misplaced struct {
	*forger
	at   int64
	give Entry
}

func (r misplaced) Entries(from, to int64) []Entry {
	if from == r.at && to == r.at {
		return []Entry{r.give}
	}
	return r.forger.Entries(from, to)
}

// everything is a relay that hands over all its records from its invented
// frame on, whatever range it is asked for. The frame before that one only
// ends the live window.
type everything struct{ *forger }

func (r everything) Entries(int64, int64) []Entry { return r.entries[1:] }

// earlier is a relay that names an older head than its last.
type earlier struct {
	*forger
	at Entry
}

func (r earlier) AnchorRequest(string, Clock) (int64, string, bool, Answer) {
	return r.at.Seq, r.at.Head, false, Answer{}
}
