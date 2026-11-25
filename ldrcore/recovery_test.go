package ldrcore

import (
	"errors"
	"strings"
	"testing"
)

// These tests execute the generation-transition and rollback-recovery traces
// T53-T58 (docs/LDR-RECOVERY.md, O23-B sequence reset with (gen, seq)
// coordinates, full cross-generation replay, fail-closed tail reconciliation,
// and discarded call/broadcast tombstoning).

func init() {
	traceTests["T53"] = traceT53
	traceTests["T55"] = traceT55
	traceTests["T56"] = traceT56
	traceTests["T58"] = traceT58
	clientTraceTests["T54"] = traceT54
	clientTraceTests["T57"] = traceT57
}

// rollbackScenario builds a generation-1 line through seq 12 (base), records a
// committed operation at base (noteAtBase), then commits security and object
// records in a tail (13..18):
//
//	13: revoke credB
//	14: call_open cTail (by a1 to a2)
//	15: broadcast_create bcTail (by op1 to a1)
//	16: rootK2 replaces rootK1 with rootK3
//	17: rootK2 revokes op1
//	18: rootK3 authorizes op2
//
// Returns the full live env, the rolled-back Sequencer at seq 12, the verified
// witness tail (13..18), and intents committed at/after base.
func rollbackScenario(t *testing.T) (full *env, rb *Sequencer, witnessTail []Entry, atBase, inTail Intent) {
	t.Helper()
	full = newLine(t)
	atBase, baseSeq := full.commit(note("a1")) // seq 13 = base
	if baseSeq != 13 {
		t.Fatalf("baseSeq = %d, want 13", baseSeq)
	}
	// Record a broadcast read by a1 at seq 14 so we have a gen-1 receipt at (1,14) <= base.
	br := actorRec("broadcast_read", "a1")
	br.Broadcast = "bc1"
	_, baseSeq = full.commit(br) // seq 14 = base
	if baseSeq != 14 {
		t.Fatalf("baseSeq after broadcast_read = %d, want 14", baseSeq)
	}

	// Tail records 15..20 (will be discarded by rollback to 14).
	inTail, _ = full.commit(revoke("credB"))                                                                                                                                                       // 15
	full.commit(activate(2, "credA"))                                                                                                                                                              // 16 (clear rekey_pending so cTail/bcTail commit)
	full.commit(openCall("a1", "a2", "cTail"))                                                                                                                                                     // 17
	full.commit(Record{Origin: OriginOperator, Type: "broadcast_create", Operator: "op1", Broadcast: "bcTail", Kind: "regroup", Recipients: []string{"a1"}})                                       // 18
	full.commit(Record{Origin: OriginRoot, Type: "root_member_replace", RootKey: "rootK2", OldRootKey: "rootK1", NewRootKey: "rootK3", Expect: Expect{RootRev: ptr(full.q.State().Line.RootRev)}}) // 19
	full.commit(Record{Origin: OriginRoot, Type: "operator_key_revoke", RootKey: "rootK2", OperatorKey: "op1", Expect: Expect{RootRev: ptr(full.q.State().Line.RootRev)}})                         // 20

	var err error
	rb, err = full.q.RollbackTo(baseSeq)
	if err != nil {
		t.Fatalf("RollbackTo(%d): %v", baseSeq, err)
	}
	witnessTail = full.q.Log()[baseSeq:]
	return full, rb, witnessTail, atBase, inTail
}

// T53: reconciled rollback recovery with sequence reset to 1, carried security
// tombstones, retained vs abandoned gen-1 receipts, discarded call/broadcast
// ID tombstones, and full cross-generation replay.
func traceT53(t *testing.T) {
	full, rb, tail, atBase, inTail := rollbackScenario(t)
	baseSeq, baseHead := rb.Head()
	rec, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, full.q.State().Line.HeadSeq, tail, "rootK2", testProfile, "https://relay.internal:8443")
	if err != nil {
		t.Fatalf("BuildRecoveryFromWitness: %v", err)
	}
	recTime := full.now + 100
	a := rb.CommitRecovery(rec, "rec-1", "rec-digest-1", At(recTime))
	if a.Class != ClassOutcome || a.Outcome.Kind != Committed || a.Seq != 1 {
		t.Fatalf("CommitRecovery: got %s, want committed at seq 1", showAnswer(a))
	}
	if rb.Generation() != 2 {
		t.Fatalf("generation = %d, want 2", rb.Generation())
	}
	st := rb.State()
	if st.Line.HeadSeq != 1 || !st.Line.RekeyPending {
		t.Fatalf("after recovery: head_seq=%d rekey_pending=%v", st.Line.HeadSeq, st.Line.RekeyPending)
	}
	if !st.Line.Credentials["credB"].Revoked || st.Line.Actors["b1"].Live {
		t.Fatal("credB revocation did not survive recovery")
	}
	if len(st.Line.Operators) != 0 || !contains(st.Line.Tombstones.OperatorKeys, "op1") {
		t.Fatalf("op1 revocation did not survive recovery: ops=%v tomb=%v", st.Line.Operators, st.Line.Tombstones.OperatorKeys)
	}
	if !contains(st.Line.Tombstones.RootKeys, "rootK1") || contains(st.Line.RootKeys, "rootK1") {
		t.Fatalf("rootK1 replacement did not survive recovery: roots=%v tomb=%v", st.Line.RootKeys, st.Line.Tombstones.RootKeys)
	}
	if !contains(st.Line.Tombstones.Calls, "cTail") || !contains(st.Line.Tombstones.Broadcasts, "bcTail") {
		t.Fatalf("discarded call/broadcast tombstones missing: calls=%v broadcasts=%v", st.Line.Tombstones.Calls, st.Line.Tombstones.Broadcasts)
	}

	// Gen-1 receipt at <= baseSeq returns its original receipt; discarded tail
	// op returns unresolved/abandoned (never expired).
	gotBase := rb.Query(RootPrincipal("rootK2"), keyOf(atBase), atBase.Digest, At(recTime))
	if gotBase.Class != ClassOutcome || gotBase.Outcome.Kind != Committed || gotBase.Seq != 13 || !gotBase.Original {
		t.Fatalf("gen-1 retained receipt: %s", showAnswer(gotBase))
	}
	gotTail := rb.Query(RootPrincipal("rootK2"), keyOf(inTail), inTail.Digest, At(recTime+testProfile.ValidityMaxMS+1000))
	if gotTail.Class != ClassUnresolved || gotTail.Code != "abandoned" {
		t.Fatalf("gen-1 discarded tail query: got %s, want unresolved abandoned", showAnswer(gotTail))
	}
	// Replaced rootK1 is still revoked in gen 2.
	if r := rb.Query(RootPrincipal("rootK1"), keyOf(atBase), atBase.Digest, At(recTime)); r.Class != ClassUnresolved || r.Code != "revoked" {
		t.Fatalf("replaced rootK1 in gen 2: got %s, want unresolved revoked", showAnswer(r))
	}

	// Authorize a fresh operator op2 and activate a gen-2 key epoch, then
	// verify discarded call_id cTail and broadcast_id bcTail are rejected conflict.
	e2 := &env{t: t, q: rb, now: recTime}
	e2.commit(Record{Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK3", OperatorKey: "op2", Expect: Expect{RootRev: ptr(rb.State().Line.RootRev)}})
	e2.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op2", Manifest: []string{"credA"}, Expect: Expect{KeyEpoch: ptr(rb.State().Line.KeyEpoch)}})

	reopenCall := e2.intent(openCall("a1", "a2", "cTail"))
	e2.wantOutcome(e2.submit(reopenCall), Rejected, "conflict", false)
	reopenBC := e2.intent(Record{Origin: OriginOperator, Type: "broadcast_create", Operator: "op2", Broadcast: "bcTail", Kind: "regroup", Recipients: []string{"a1"}})
	e2.wantOutcome(e2.submit(reopenBC), Rejected, "conflict", false)

	// Full cross-generation replay from genesis matches sequencer state exactly!
	gotState, gotHead, err := ReplayVerifiedFull("L", rb.FullLog(), testProfile)
	if err != nil {
		t.Fatalf("ReplayVerifiedFull: %v", err)
	}
	_, wantHead := rb.Head()
	if gotHead != wantHead || len(diff(gotState, rb.State())) > 0 {
		t.Fatalf("full cross-generation replay diverged: head %s!=%s diff=%v", gotHead, wantHead, diff(gotState, rb.State()))
	}
	_ = baseSeq
}

// T54: incomplete reconciliation caught fail-closed by a client that witnessed
// the discarded tail.
func traceT54(t *testing.T) {
	cases := map[string]struct {
		omit func(*RecoveryRecord)
		part string
	}{
		"omitted credential_revoke": {
			func(r *RecoveryRecord) { r.RevokedCreds = nil },
			"revocation of credential credB",
		},
		"omitted operator_key_revoke": {
			func(r *RecoveryRecord) { r.RevokedOperators = nil },
			"revocation of operator key op1",
		},
		"omitted root_member_replace": {
			func(r *RecoveryRecord) {
				r.ActiveRootKeys = nil
				r.ReconciledTombstones.RootKeys = nil
			},
			"replacement of root key rootK1",
		},
		"omitted discarded call_id tombstone": {
			func(r *RecoveryRecord) { r.ReconciledTombstones.Calls = nil },
			"discarded call tombstone cTail",
		},
		"omitted discarded broadcast_id tombstone": {
			func(r *RecoveryRecord) { r.ReconciledTombstones.Broadcasts = nil },
			"discarded broadcast tombstone bcTail",
		},
		"regressed auth_epoch floor": {
			func(r *RecoveryRecord) { r.AuthEpochFloor = 0 },
			"auth_epoch progress",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			full, rb, tail, _, _ := rollbackScenario(t)
			// credA witnessed the complete generation-1 log including the tail.
			ca := full.client("credA")

			_, baseHead := rb.Head()
			rec, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, full.q.State().Line.HeadSeq, tail, "rootK2", testProfile, "")
			if err != nil {
				t.Fatal(err)
			}
			tc.omit(&rec)

			a := rb.CommitRecovery(rec, "rec-bad", "rec-bad-d", At(full.now+100))
			if a.Class != ClassOutcome || a.Outcome.Kind != Committed {
				t.Fatalf("incomplete recovery did not commit at rolled-back relay: %s", showAnswer(a))
			}
			var v *ViolationError
			err = ca.Sync(rb.Log())
			if !errors.As(err, &v) || !strings.Contains(v.Reason, tc.part) {
				t.Fatalf("witness client Sync: got %v, want ViolationError mentioning %q", err, tc.part)
			}
			if ca.Halted() == "" || ca.Generation() != 1 {
				t.Fatalf("client did not fail closed: gen=%d halted=%q", ca.Generation(), ca.Halted())
			}
			if _, err := ca.Compose("note", note("a1"), Payload{}); !errors.Is(err, ErrFailClosed) {
				t.Fatalf("halted client composed: %v", err)
			}
		})
	}
}

// T55: replay, wrong prior_generation, wrong base_head, replaced-root signer,
// and mismatch protection on recovery_generation.
func traceT55(t *testing.T) {
	full, rb, tail, _, _ := rollbackScenario(t)
	_, baseHead := rb.Head()
	rec, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, full.q.State().Line.HeadSeq, tail, "rootK2", testProfile, "")
	if err != nil {
		t.Fatal(err)
	}

	// Wrong prior_generation -> refused.
	badPrior := rec
	badPrior.PriorGeneration = 2
	badPrior.Generation = 3
	if a := rb.CommitRecovery(badPrior, "bad-prior", "d-prior", At(full.now+10)); a.Class != ClassRefusal || a.Code != "wrong_generation" {
		t.Fatalf("wrong prior_generation: %s", showAnswer(a))
	}

	// Wrong base_head -> refused unknown_anchor.
	badHead := rec
	badHead.BaseHead = "0123456789abcdef"
	if a := rb.CommitRecovery(badHead, "bad-head", "d-head", At(full.now+10)); a.Class != ClassRefusal || a.Code != "unknown_anchor" {
		t.Fatalf("wrong base_head: %s", showAnswer(a))
	}

	// Replaced rootK1 cannot sign recovery_generation that tombstones rootK1.
	badSigner := rec
	badSigner.RootKey = "rootK1"
	if a := rb.CommitRecovery(badSigner, "bad-signer", "d-signer", At(full.now+10)); a.Class != ClassRefusal || a.Code != "invalid_recovery" {
		t.Fatalf("replaced root signing recovery: %s", showAnswer(a))
	}

	// Valid commit succeeds at (2,1).
	okAns := rb.CommitRecovery(rec, "rec-ok", "d-ok", At(full.now+100))
	if okAns.Class != ClassOutcome || okAns.Outcome.Kind != Committed || okAns.Seq != 1 {
		t.Fatalf("valid CommitRecovery: %s", showAnswer(okAns))
	}
	// Identical retry returns original receipt; changed bytes under same opID mismatch.
	retry := rb.CommitRecovery(rec, "rec-ok", "d-ok", At(full.now+101))
	if retry.Class != ClassOutcome || !retry.Original || retry.Seq != 1 {
		t.Fatalf("identical recovery retry: %s", showAnswer(retry))
	}
	mismatch := rb.CommitRecovery(rec, "rec-ok", "d-other", At(full.now+102))
	if mismatch.Class != ClassMismatch {
		t.Fatalf("recovery mismatch: %s", showAnswer(mismatch))
	}
	// A distinct recovery_generation naming prior_generation 1 cannot apply twice.
	again := rb.CommitRecovery(rec, "rec-second", "d-second", At(full.now+103))
	if again.Class != ClassRefusal || again.Code != "wrong_generation" {
		t.Fatalf("second recovery for gen 1: %s", showAnswer(again))
	}
}

// T56: mandatory rekey gate and register generation invalidation after recovery.
func traceT56(t *testing.T) {
	full := newLine(t)
	// Activate presence writer for a1 in gen 1 and publish counter 1.
	full.commit(Record{Origin: OriginCredential, Type: "register_activate", Cred: "credA", Actor: "a1", Register: "presence", Incarnation: "i1", Expect: Expect{WriterRev: ptr(0)}})
	regs := NewRegisters("L")
	v1 := RegisterValue{
		LineID: "L", Generation: 1, Register: "presence", Actor: "a1", Cred: "credA",
		BindingGen: 1, WriterRev: 1, Incarnation: "i1", KeyEpoch: 2, Counter: 1, SignatureOK: true,
	}
	if reason := regs.Publish(full.q.State(), v1, full.now); reason != "" {
		t.Fatalf("gen-1 publish: %s", reason)
	}
	baseSeq, _ := full.q.Head()
	full.commit(revoke("credB")) // discarded tail
	rb, err := full.q.RollbackTo(baseSeq)
	if err != nil {
		t.Fatal(err)
	}
	_, baseHead := rb.Head()
	rec, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, full.q.State().Line.HeadSeq, full.q.Log()[baseSeq:], "rootK1", testProfile, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := rb.CommitRecovery(rec, "rec-56", "d-56", At(full.now+100)); a.Outcome.Kind != Committed {
		t.Fatalf("CommitRecovery: %s", showAnswer(a))
	}

	// Gen-1 cached register value is now historical, and gen-1 updates are rejected wrong_line.
	if !regs.Historical(rb.State(), "a1", "presence") {
		t.Fatal("gen-1 register value was not marked historical after recovery")
	}
	v1Next := v1
	v1Next.Counter = 2
	if reason := regs.Publish(rb.State(), v1Next, full.now+101); reason != RegWrongLine {
		t.Fatalf("gen-1 register publish in gen 2: got %q, want %q", reason, RegWrongLine)
	}

	// Payload-bearing turn and gen-2 register publish are both blocked by rekey_pending.
	e2 := &env{t: t, q: rb, now: full.now + 100}
	e2.wantOutcome(e2.submit(e2.intent(turn("a1", 2))), Rejected, "rekey_pending", false)
	v2 := v1
	v2.Generation = 2
	v2.Counter = 2
	if reason := regs.Publish(rb.State(), v2, e2.now); reason != RegRekeyPending {
		t.Fatalf("gen-2 register publish while rekey_pending: got %q, want %q", reason, RegRekeyPending)
	}

	// Activating a key epoch that still lists revoked credB fails invalid;
	// activating with only reconciled entitled readers (credA) clears the gate.
	badAct := e2.intent(activate(rb.State().Line.KeyEpoch, "credA", "credB"))
	e2.wantOutcome(e2.submit(badAct), Rejected, "invalid", false)
	e2.commit(activate(rb.State().Line.KeyEpoch, "credA"))
	e2.commit(turn("a1", 2))

	// Fresh register activation in gen 2 with fresh incarnation succeeds and publishes.
	e2.commit(Record{Origin: OriginCredential, Type: "register_activate", Cred: "credA", Actor: "a1", Register: "presence", Incarnation: "i2", Expect: Expect{WriterRev: ptr(1)}})
	v2Fresh := RegisterValue{
		LineID: "L", Generation: 2, Register: "presence", Actor: "a1", Cred: "credA",
		BindingGen: 1, WriterRev: 2, Incarnation: "i2", KeyEpoch: rb.State().Line.KeyEpoch, Counter: 1, SignatureOK: true,
	}
	if reason := regs.Publish(rb.State(), v2Fresh, e2.now); reason != "" {
		t.Fatalf("gen-2 register publish after activation: %s", reason)
	}
}

// T57: generation-qualified broadcast receipts, projection view tags
// ((2,2) > (1,20)), archived discarded tail, withheld gen-1 notices, abandoned
// gen-1 outbox intents, and Rule 8 key-stop persistence across recovery.
func traceT57(t *testing.T) {
	full, rb, tail, _, _ := rollbackScenario(t)
	// Sync credA through the full gen-1 log (seq 20), leaving a gen-1 notice
	// unacknowledged and holding an unsettled gen-1 outbox intent + stopped op1.
	ca := NewClient("L", "credA", testProfile)
	ca.OperatorKey = "op1"
	if err := ca.Run(full.q.Log()); err != nil {
		t.Fatal(err)
	}
	// op1 was revoked at seq 20, so Rule 8 stopped op:op1.
	if len(ca.Stopped()) != 1 || ca.Stopped()[0] != OperatorPrincipal("op1") {
		t.Fatalf("before recovery: stopped=%v, want [op:op1]", ca.Stopped())
	}
	// Compose an unsettled gen-1 intent as credA before recovery.
	gen1Intent, err := ca.Compose("gen1-note", note("a1"), Payload{})
	if err != nil {
		t.Fatalf("compose gen1 intent: %v", err)
	}
	// Confirm bc1 view carries the gen-1 receipt at (1,14) and c1 view is tagged (1,13).
	bviewBefore, err := ca.ReadFile("broadcasts/bc1/view")
	if err != nil || !strings.Contains(bviewBefore, "receipt.a1=g1-s14\n") {
		t.Fatalf("bc1 view before recovery (%v):\n%s", err, bviewBefore)
	}

	// Commit reconciled recovery at (2,1) and a gen-2 turn on c1 at (2,4).
	_, baseHead := rb.Head()
	rec, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, full.q.State().Line.HeadSeq, tail, "rootK2", testProfile, "")
	if err != nil {
		t.Fatal(err)
	}
	recTime := full.now + 100
	if a := rb.CommitRecovery(rec, "rec-57", "d-57", At(recTime)); a.Outcome.Kind != Committed {
		t.Fatalf("CommitRecovery: %s", showAnswer(a))
	}
	e2 := &env{t: t, q: rb, now: recTime}
	e2.commit(Record{Origin: OriginRoot, Type: "operator_key_authorize", RootKey: "rootK3", OperatorKey: "op2", Expect: Expect{RootRev: ptr(rb.State().Line.RootRev)}})
	e2.commit(Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op2", Manifest: []string{"credA"}, Expect: Expect{KeyEpoch: ptr(rb.State().Line.KeyEpoch)}})
	_, turnSeq := e2.commit(turn("a1", 2)) // (2,4)

	// Client transitions smoothly from (1,20) through (2,1)..(2,4).
	if err := ca.Run(rb.Log()); err != nil {
		t.Fatalf("client Run across recovery: %v", err)
	}
	if ca.Generation() != 2 {
		t.Fatalf("client generation = %d, want 2", ca.Generation())
	}
	// Discarded tail (15..20 = 6 entries) is archived forensically.
	if got := len(ca.ArchivedTail()); got != len(tail) {
		t.Fatalf("archived tail len = %d, want %d", got, len(tail))
	}
	// Gen-1 broadcast receipt (1,14) survived cleanly into gen 2.
	if rc := ca.State().Broadcasts["bc1"].Receipts["a1"]; rc.ReadGen != 1 || rc.ReadSeq != 14 {
		t.Fatalf("gen-1 receipt after recovery: %+v, want {1 14}", rc)
	}
	// Projection view for c1 was replaced cleanly by (2, turnSeq) > (1, 13) with 0 rebuilds.
	c1View, err := ca.ReadFile("calls/c1/view")
	if err != nil || !strings.HasPrefix(c1View, "derived_gen=2\nderived_seq=4\n") || !strings.Contains(c1View, "turn_count=3\n") {
		t.Fatalf("c1 view after recovery (turnSeq=%d, err=%v):\n%s", turnSeq, err, c1View)
	}
	if ca.Rebuilds() != 0 {
		t.Fatalf("expected clean view superseding without rebuild, got %d rebuilds", ca.Rebuilds())
	}
	// Gen-1 unsettled intent is marked reconciliation_required (never auto-sent).
	if o := stored(ca, gen1Intent); o.Status != OutReconcile || o.Sends != 0 {
		t.Fatalf("gen-1 outbox intent after recovery: %+v", o)
	}
	// Rule 8 stop on op1 persists across recovery.
	if len(ca.Stopped()) != 1 || ca.Stopped()[0] != OperatorPrincipal("op1") {
		t.Fatalf("stopped keys after recovery: %v", ca.Stopped())
	}
	// Any unacknowledged gen-1 notices are withheld in gen 2.
	if delivered := ca.Deliver(); len(delivered) != 0 {
		t.Fatalf("gen-1 notices delivered in gen 2: %+v", delivered)
	}
	// A brand-new client joining in gen 2 replays FullLog from genesis cleanly.
	fresh := NewClient("L", "credA", testProfile)
	if err := fresh.Run(rb.FullLog()); err != nil {
		t.Fatalf("fresh client full cross-generation replay: %v", err)
	}
	if len(diff(fresh.State(), rb.State())) > 0 {
		t.Fatalf("fresh client state diverges from sequencer: %v", diff(fresh.State(), rb.State()))
	}
}

// T58: unreconcilable loss fails closed when witness evidence for a rollback
// gap is missing or disconnected from base_head.
func traceT58(t *testing.T) {
	full, rb, tail, _, _ := rollbackScenario(t)
	_, baseHead := rb.Head()
	knownTail := full.q.State().Line.HeadSeq

	// Missing witness tail for a known rollback gap (14 -> 20): fails closed.
	if _, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, knownTail, nil, "rootK2", testProfile, ""); !errors.Is(err, ErrUnreconcilableLoss) {
		t.Fatalf("missing witness tail: got %v, want ErrUnreconcilableLoss", err)
	}
	// Truncated witness tail (missing last record): fails closed.
	if _, err := BuildRecoveryFromWitness(rb.State(), baseHead, testProfile, knownTail, tail[:len(tail)-1], "rootK2", testProfile, ""); !errors.Is(err, ErrUnreconcilableLoss) {
		t.Fatalf("truncated witness tail: got %v, want ErrUnreconcilableLoss", err)
	}
	// Disconnected witness tail (wrong base head): fails closed.
	if _, err := BuildRecoveryFromWitness(rb.State(), "wrong-head", testProfile, knownTail, tail, "rootK2", testProfile, ""); !errors.Is(err, ErrUnreconcilableLoss) {
		t.Fatalf("disconnected witness tail: got %v, want ErrUnreconcilableLoss", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
