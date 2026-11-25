package ldrcore

import (
	"errors"
	"reflect"
	"testing"
)

// These tests cover Draft v8 equal 1-of-2 roots (2026-11-25 operator decision
// on O26): two distinct active root keys provisioned at line_init, tagged
// root principals ("root:<key>"), root_member_replace, replaced-root
// tombstones, sequencer standing/reconciliation (T51), and Rule 8 client stop
// behavior when a held root key is replaced (T52).

func init() {
	traceTests["T51"] = traceT51
	clientTraceTests["T52"] = traceT52
}

// T51: equal 1-of-2 root replacement, replaced-root refusal, surviving/new
// root reconciliation, and concurrent root race.
func traceT51(t *testing.T) {
	e := newEnv(t)
	initIn, initSeq := e.commit(lineInit())
	if initSeq != 1 {
		t.Fatalf("line_init seq = %d, want 1", initSeq)
	}

	// Both provisioned roots have equal authority: rootK1 authorizes op1,
	// rootK2 authorizes op2.
	authOp1, authOp1Seq := e.commit(Record{
		Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK1",
		OperatorKey: "op1", Expect: Expect{RootRev: ptr(1)},
	})
	e.commit(Record{
		Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK2",
		OperatorKey: "op2", Expect: Expect{RootRev: ptr(2)},
	})
	// rootK1 signs an intent before being replaced, never sent yet.
	unsent := e.intent(Record{
		Origin: OriginRoot, Type: "operator_key_revoke", RootKey: "rootK1",
		OperatorKey: "op2", Expect: Expect{RootRev: ptr(3)},
	})

	// rootK2 replaces rootK1 with rootK3.
	e.commit(Record{
		Origin: OriginRoot, Type: "root_member_replace", RootKey: "rootK2",
		OldRootKey: "rootK1", NewRootKey: "rootK3", Expect: Expect{RootRev: ptr(3)},
	})
	st := e.q.State().Line
	if !reflect.DeepEqual(st.RootKeys, []string{"rootK2", "rootK3"}) {
		t.Fatalf("active roots after replace: %v, want [rootK2 rootK3]", st.RootKeys)
	}
	if !reflect.DeepEqual(st.Tombstones.RootKeys, []string{"rootK1"}) {
		t.Fatalf("root tombstones after replace: %v, want [rootK1]", st.Tombstones.RootKeys)
	}
	if st.RootRev != 4 || st.AuthEpoch != 3 {
		t.Fatalf("counters after replace: root_rev=%d auth_epoch=%d, want 4 and 3", st.RootRev, st.AuthEpoch)
	}

	hot, logLen := e.q.HotEntries(), len(e.q.Log())

	// Replaced rootK1 is refused with unresolved/revoked on submit (including
	// retry of its committed op and of its original line_init), query, and
	// anchor request, writing nothing.
	e.want(e.submit(authOp1), ClassUnresolved, "revoked")
	e.want(e.submit(initIn), ClassUnresolved, "revoked")
	e.want(e.submit(unsent), ClassUnresolved, "revoked")
	e.want(e.q.Query(RootPrincipal("rootK1"), keyOf(authOp1), authOp1.Digest, At(e.now)), ClassUnresolved, "revoked")
	if _, _, wrote, a := e.q.AnchorRequest(RootPrincipal("rootK1"), At(e.now+3600000)); wrote || a != unresolved("revoked") {
		t.Fatalf("replaced root anchor request: %s, wrote=%t", showAnswer(a), wrote)
	}

	// A key that was never a root gets an admission error, never "revoked".
	never := e.intent(Record{
		Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK9",
		OperatorKey: "op3", Expect: Expect{RootRev: ptr(4)},
	})
	e.want(e.submit(never), ClassAdmission, "unknown_signer")
	e.want(e.q.Query(RootPrincipal("rootK9"), keyOf(authOp1), authOp1.Digest, At(e.now)), ClassAdmission, "unknown_signer")
	if _, _, wrote, a := e.q.AnchorRequest(RootPrincipal("rootK9"), At(e.now+3600000)); wrote || a != admission("not_authorized") {
		t.Fatalf("never-root anchor request: %s, wrote=%t", showAnswer(a), wrote)
	}
	if e.q.HotEntries() != hot || len(e.q.Log()) != logLen {
		t.Fatal("refused root requests altered sequencer state")
	}

	// Surviving rootK2 and newly installed rootK3 reconcile rootK1's history
	// (both its operator authorization and line_init); rootK1 stays recorded
	// as the historical signer.
	for _, who := range []string{RootPrincipal("rootK2"), RootPrincipal("rootK3"), OperatorPrincipal("op1")} {
		a := e.q.Query(who, keyOf(authOp1), authOp1.Digest, At(e.now))
		e.wantOutcome(a, Committed, "", true)
		if a.Seq != authOp1Seq || keyOf(authOp1).Signer != RootPrincipal("rootK1") {
			t.Fatalf("%s reconciled seq=%d signer=%s", who, a.Seq, keyOf(authOp1).Signer)
		}
		li := e.q.Query(who, keyOf(initIn), initIn.Digest, At(e.now))
		e.wantOutcome(li, Committed, "", true)
		if li.Seq != initSeq {
			t.Fatalf("%s reconciled line_init seq=%d, want %d", who, li.Seq, initSeq)
		}
	}
	e.want(e.q.Query(RootPrincipal("rootK3"), keyOf(unsent), unsent.Digest, At(e.now)), ClassUnknown, "outcome_unknown")

	// Replaced rootK1 cannot be reintroduced as root, operator, or credential.
	reintro := e.intent(Record{
		Origin: OriginRoot, Type: "root_member_replace", RootKey: "rootK2",
		OldRootKey: "rootK3", NewRootKey: "rootK1", Expect: Expect{RootRev: ptr(4)},
	})
	e.wantOutcome(e.submit(reintro), Rejected, "conflict", false)

	// Concurrent root race at root_rev=4: rootK2 and rootK3 each attempt to
	// authorize a different operator key; first commit wins, second gets conflict.
	raceA := e.intent(Record{
		Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK2",
		OperatorKey: "op3", Expect: Expect{RootRev: ptr(4)},
	})
	raceB := e.intent(Record{
		Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK3",
		OperatorKey: "op4", Expect: Expect{RootRev: ptr(4)},
	})
	e.now++
	e.wantOutcome(e.submit(raceA), Committed, "", false)
	e.now++
	e.wantOutcome(e.submit(raceB), Rejected, "conflict", false)

	// Mutual replacement race at root_rev=5: rootK3 replaces rootK2 first;
	// rootK2's in-flight attempt to replace rootK3 is answered revoked.
	repK2 := e.intent(Record{
		Origin: OriginRoot, Type: "root_member_replace", RootKey: "rootK3",
		OldRootKey: "rootK2", NewRootKey: "rootK4", Expect: Expect{RootRev: ptr(5)},
	})
	repK3 := e.intent(Record{
		Origin: OriginRoot, Type: "root_member_replace", RootKey: "rootK2",
		OldRootKey: "rootK3", NewRootKey: "rootK5", Expect: Expect{RootRev: ptr(5)},
	})
	e.now++
	e.wantOutcome(e.submit(repK2), Committed, "", false)
	e.now++
	e.want(e.submit(repK3), ClassUnresolved, "revoked")
	if got := e.q.State().Line.RootKeys; !reflect.DeepEqual(got, []string{"rootK3", "rootK4"}) {
		t.Fatalf("final active roots: %v, want [rootK3 rootK4]", got)
	}
	if got := e.q.State().Line.Tombstones.RootKeys; !reflect.DeepEqual(got, []string{"rootK1", "rootK2"}) {
		t.Fatalf("final root tombstones: %v, want [rootK1 rootK2]", got)
	}
	e.checkReplay()
}

// T52: Rule 8 stopped-key behavior when a device's held root key is replaced.
func traceT52(t *testing.T) {
	for _, how := range []string{"told", "verified"} {
		t.Run(how, func(t *testing.T) {
			e := newLine(t)
			ca := e.client("credA")
			ca.OperatorKey = "op1"
			ca.RootKey = "rootK1"

			asRoot, err := ca.Compose("authorize op2", Record{
				Origin: OriginRoot, Type: "operator_key_authorize",
				OperatorKey: "op2", Expect: Expect{RootRev: ptr(e.q.State().Line.RootRev)},
			}, Payload{})
			if err != nil {
				t.Fatalf("compose root: %v", err)
			}
			asCred, err := ca.Compose("activate", activatePresence, Payload{})
			if err != nil {
				t.Fatalf("compose cred: %v", err)
			}

			// Elsewhere rootK2 replaces rootK1 with rootK3.
			e.commit(Record{
				Origin: OriginRoot, Type: "root_member_replace", RootKey: "rootK2",
				OldRootKey: "rootK1", NewRootKey: "rootK3", Expect: Expect{RootRev: ptr(e.q.State().Line.RootRev)},
			})

			if how == "told" {
				a, err := ca.Send(e.q, asRoot, At(e.now))
				if err != nil {
					t.Fatalf("send root: %v", err)
				}
				e.want(a, ClassUnresolved, "revoked")
			} else {
				e.sync(ca)
			}

			if got := ca.Stopped(); !reflect.DeepEqual(got, []string{RootPrincipal("rootK1")}) {
				t.Fatalf("%s: stopped keys = %v, want [%s]", how, got, RootPrincipal("rootK1"))
			}
			wantSlotHeld(t, ca, asRoot)
			if how == "verified" && stored(ca, asRoot).Sends != 0 {
				t.Fatal("verified stop sent the root intent")
			}

			// Further root composition is refused with ErrKeyRevoked.
			if _, err := ca.Compose("authorize op3", Record{
				Origin: OriginRoot, Type: "operator_key_authorize",
				OperatorKey: "op3", Expect: Expect{RootRev: ptr(e.q.State().Line.RootRev)},
			}, Payload{}); !errors.Is(err, ErrKeyRevoked) {
				t.Fatalf("%s: compose after root stop: got %v, want ErrKeyRevoked", how, err)
			}

			// Restart + ResolveAll: root:rootK1 asks nothing, does not hold back
			// credA or op1, and credA + op1 continue working normally.
			if err := ca.Restart(); err != nil {
				t.Fatal(err)
			}
			ca.ResolveAll(e.q, At(e.now))
			if o := stored(ca, asCred); o.Status != OutPending || o.Result.Class != ClassUnknown {
				t.Fatalf("%s: cred intent after resolve: %+v", how, o)
			}
			if _, err := ca.Compose("note", noteOn("a1", "c1"), Payload{}); err != nil {
				t.Fatalf("%s: cred compose blocked by stopped root: %v", how, err)
			}
			if _, err := ca.Compose("ratify", ratifyC1, Payload{}); err != nil {
				t.Fatalf("%s: operator compose blocked by stopped root: %v", how, err)
			}

			// Once the anchor retires, surviving/new rootK3 reconciles the
			// replaced root's intent and settles its slot; rootK1 stays stopped.
			e.retire(stored(ca, asRoot).Intent.SeenSeq)
			ans := e.q.Query(RootPrincipal("rootK3"), opKey(stored(ca, asRoot).Intent), stored(ca, asRoot).Intent.Digest, At(e.now))
			e.want(ans, ClassRefusal, "expired")
			if err := ca.Reconciled(asRoot, ans); err != nil {
				t.Fatalf("%s: Reconciled: %v", how, err)
			}
			if o := stored(ca, asRoot); o.Status != OutClosed {
				t.Fatalf("%s: root intent after reconciliation: %+v", how, o)
			}
			// Settling with expired triggered the stale-checkpoint resolve
			// guard (C1) because other intents are still stored; resolving them
			// clears mustResolve, and rootK1 remains permanently stopped.
			ca.ResolveAll(e.q, At(e.now))
			if _, err := ca.Compose("authorize op4", Record{
				Origin: OriginRoot, Type: "operator_key_authorize",
				OperatorKey: "op4", Expect: Expect{RootRev: ptr(e.q.State().Line.RootRev)},
			}, Payload{}); !errors.Is(err, ErrKeyRevoked) {
				t.Fatalf("%s: root resumed after settlement: %v", how, err)
			}
		})
	}
}

// TestEqualRootInvariants verifies CheckInvariants / DecodeState on malformed
// root-set and root-tombstone states.
func TestEqualRootInvariants(t *testing.T) {
	base := newLineWith(t, commitProfile).q.State()
	cases := map[string]func(*State){
		"only one active root key": func(s *State) {
			s.Line.RootKeys = []string{"rootK1"}
		},
		"three active root keys": func(s *State) {
			s.Line.RootKeys = []string{"rootK1", "rootK2", "rootK3"}
		},
		"duplicate active root key": func(s *State) {
			s.Line.RootKeys = []string{"rootK1", "rootK1"}
		},
		"active root also in root tombstones": func(s *State) {
			s.Line.Tombstones.RootKeys = []string{"rootK1"}
		},
		"replaced root reused as operator key": func(s *State) {
			s.Line.Tombstones.RootKeys = []string{"op1"}
		},
		"empty root key": func(s *State) {
			s.Line.RootKeys = []string{"", "rootK1"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := base.Clone()
			mutate(&s)
			if bad := s.CheckInvariants(); len(bad) == 0 {
				t.Fatalf("%s: CheckInvariants reported no violation", name)
			}
			if _, err := DecodeState(EncodeState(s), DefaultSnapshotBudget); !errors.Is(err, ErrSnapshotEncoding) {
				t.Fatalf("%s: DecodeState got %v, want ErrSnapshotEncoding", name, err)
			}
		})
	}
}
