package ldrcore

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

var knownReasons = map[string]bool{
	"invalid": true, "too_large": true, "unauthorized": true, "conflict": true,
	"unknown_target": true, "rekey_pending": true, "not_open": true, "not_floor": true,
	"exhausted": true,
}

// TestHostileRecords feeds Apply records it was never meant to accept: every
// record type under every origin, signed by known, unknown and empty
// credentials, actors and operators, aimed at existing, missing and empty
// targets, with expectations present or absent.
//
// The precondition ladder runs checks in rung order, and a later check may
// dereference what an earlier rung established. That is only sound if every
// builder registers its existence checks on the right rung. This test is the
// evidence for that: a mistake shows up as a panic here, which fails the
// test. Apply does not recover from panics and must not need to.
//
// It also asserts the properties that hold for any input at all: Apply never
// modifies its argument, anything but a commit returns the argument unchanged,
// and a commit returns a coherent state exactly one sequence number later.
func TestHostileRecords(t *testing.T) {
	f := loadVectors(t)
	prof := Profile{FreshnessMS: f.Profile.FreshnessMS, ValidityMaxMS: f.Profile.ValidityMaxMS}

	types := []string{"no_such_type", "recovery_generation"}
	for typ := range recordOrigin {
		types = append(types, typ)
	}
	sort.Strings(types)
	origins := []string{OriginActor, OriginCredential, OriginOperator, OriginRoot, OriginSequencer, "bogus"}
	creds := []string{"credA", "credB", "credZ", ""}
	actors := []string{"a1", "a2", "b1", "zz", ""}
	operators := []string{"op1", "op9"}
	// One knob moves every target field together: existing, missing, empty.
	targets := []struct {
		call, related, to, dispute, broadcast, toCred, namespace, register, key, sk, ek string
		rootKey, oldRoot, newRoot                                                       string
		rootKeys                                                                        []string
	}{
		{"c1", "c2", "b1", "1", "bc1", "credB", "nsA", "presence", "op1", "skA", "ekB", "rootK1", "rootK2", "rootK9", []string{"rootK1", "rootK2"}},
		{"c9", "c9", "zz", "9", "bc9", "credZ", "nsZ", "bogus", "op9", "skZ", "ekZ", "rootK9", "rootK9", "op1", []string{"rootK9"}},
		{},
	}
	zero, one, two, three := int64(0), int64(1), int64(2), int64(3)
	expects := []Expect{
		{},
		// The values line_basic actually holds, so that checks behind the
		// expectation rung (not_open, not_floor) are reachable.
		{TurnCount: &two, LifecycleRev: &zero, MeasureRev: &zero, Rev: &two, AddrRev: &one, BindingGen: &one, AudienceRev: &three, KeyEpoch: &two, WriterRev: &zero, RootRev: &one},
		{TurnCount: &zero, LifecycleRev: &zero, MeasureRev: &zero, Rev: &zero, AddrRev: &zero, BindingGen: &zero, AudienceRev: &zero, KeyEpoch: &zero, WriterRev: &zero, RootRev: &zero},
		{TurnCount: &one, LifecycleRev: &one, MeasureRev: &one, Rev: &one, AddrRev: &one, BindingGen: &one, AudienceRev: &one, KeyEpoch: &one, WriterRev: &one, RootRev: &one},
	}

	// Clone once first: a decoded state has nil maps where Clone has empty
	// ones, and the comparisons below are exact, not canonical.
	var starts []State
	for _, fixture := range []string{"line_basic", "dispute_resolved", "a2_moved_with_writer", "three_creds_b_revoked", "empty_log"} {
		starts = append(starts, decodeState(t, f.fixture(t, fixture, 0)).Clone())
	}
	// One more start, produced by Apply itself: a1 has already read bc1, so a
	// second read by a1 is the no-op the fixtures above cannot reach.
	starts = append(starts, mustCommit(t, starts[0], Record{Origin: OriginActor, Type: "broadcast_read",
		Cred: "credA", Actor: "a1", BindingGen: 1, AuthEpoch: 3, KeyEpoch: 2, Broadcast: "bc1"}, 1005000, prof))

	// And one where the line's counters sit at the top of their domain, so
	// that anything able to commit would have to wrap one.
	top := starts[0].Clone()
	top.Line.HeadSeq, top.Line.RootRev, top.Line.AuthEpoch = MaxCounter, MaxCounter, MaxCounter
	top.Line.AudienceRev, top.Line.KeyEpoch, top.Line.CallCount = MaxCounter, MaxCounter, MaxCounter
	for _, c := range top.Calls {
		c.NoteCount, c.AttachCount, c.LifecycleRev = MaxCounter, MaxCounter, MaxCounter
	}
	if bad := top.CheckInvariants(); len(bad) > 0 {
		t.Fatalf("the top-of-domain start is not coherent: %v", bad)
	}
	starts = append(starts, top)

	outcomes := map[string]int{}
	reasons := map[string]int{}
	// The race detector has nothing to find in a single-goroutine pure
	// function and makes this loop about ten times slower, so under it every
	// stride-th record is run. The full product runs in an ordinary test.
	n, stride := 0, 1
	if raceEnabled {
		stride = 8
	}
	for _, before := range starts {
		snapshot := before.Clone()
		for _, typ := range types {
			for _, origin := range origins {
				for _, cred := range creds {
					for _, actor := range actors {
						for _, op := range operators {
							for ti, tg := range targets {
								for ei, ex := range expects {
									// The size class rides on two of the combinations with
									// existing targets, rather than tripling the whole product.
									size := ""
									if ti == 0 && ei == 0 {
										size = "over_inline_limit"
									} else if ti == 0 && ei == 2 {
										size = "bogus"
									}
									n++
									if n%stride != 0 {
										continue
									}
									r := Record{
										SizeClass: size,
										Origin:    origin, Type: typ, Cred: cred, Actor: actor, BindingGen: 1, Operator: op,
										AuthEpoch: before.Line.AuthEpoch, KeyEpoch: before.Line.KeyEpoch, Expect: ex,
										Call: tg.call, Related: tg.related, To: tg.to, Dispute: tg.dispute, Broadcast: tg.broadcast,
										ToCred: tg.toCred, Namespace: tg.namespace, Register: tg.register, OperatorKey: tg.key,
										State: "linked", Kind: "withdrawn", Incarnation: "z9", JoinRequest: "jr9", JoinRequestDigest: "jd9",
										SigningKey: tg.sk, EncryptionKey: tg.ek,
										RootKey: tg.rootKey, RootKeys: tg.rootKeys, OldRootKey: tg.oldRoot, NewRootKey: tg.newRoot,
										Recipients: []string{tg.to}, Manifest: []string{cred},
										Grant: &Grant{Namespace: tg.namespace, ActorLimit: 1},
									}
									got, out := applyOrFail(t, before, r, prof)
									outcomes[out.Kind]++

									if !reflect.DeepEqual(before, snapshot) {
										t.Fatalf("Apply modified its input for %s", show(r))
									}
									switch out.Kind {
									case Committed:
										if got.Line.HeadSeq != before.Line.HeadSeq+1 {
											t.Fatalf("commit did not advance the head by one for %s", show(r))
										}
										if bad := got.CheckInvariants(); len(bad) > 0 {
											t.Fatalf("commit produced an incoherent state for %s:\n  %v", show(r), bad)
										}
									case Rejected:
										if !knownReasons[out.Reason] {
											t.Fatalf("unknown rejection reason %q for %s", out.Reason, show(r))
										}
										reasons[out.Reason]++
										fallthrough
									case Noop, Violation:
										if !reflect.DeepEqual(got, before) {
											t.Fatalf("%s returned a changed state for %s", out.Kind, show(r))
										}
									default:
										t.Fatalf("unknown outcome %q for %s", out.Kind, show(r))
									}
									// With the sequence space used up, nothing commits.
									if before.Line.HeadSeq >= MaxCounter && out.Kind == Committed {
										t.Fatalf("committed past the last sequence number for %s", show(r))
									}
									// An empty log accepts line_init and nothing else.
									if before.Line.Generation == 0 && typ != "line_init" && out.Kind != Violation {
										t.Fatalf("empty log: got %s for %s, want violation", out.Kind, show(r))
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// The generator must reach every kind of outcome, or it is not exercising
	// the ladder at all.
	for _, kind := range []string{Committed, Rejected, Noop, Violation} {
		if outcomes[kind] == 0 && !raceEnabled {
			t.Errorf("no generated record produced outcome %s: %v", kind, outcomes)
		}
	}
	if !raceEnabled {
		for reason := range knownReasons {
			if reasons[reason] == 0 {
				t.Errorf("no generated record was rejected %s: %v", reason, reasons)
			}
		}
	}
	t.Logf("outcomes over generated records: %v", outcomes)
	t.Logf("rejection reasons: %v", reasons)
}

func applyOrFail(t *testing.T, s State, r Record, p Profile) (State, Outcome) {
	t.Helper()
	defer func() {
		if x := recover(); x != nil {
			t.Fatalf("Apply panicked (%v) for %s", x, show(r))
		}
	}()
	return Apply(s, r, s.Line.HeadTime+p.FreshnessMS+1, p)
}

func show(r Record) string {
	b, _ := json.Marshal(r)
	return string(b)
}
