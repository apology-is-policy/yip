package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func resTestRoot(t *testing.T) {
	t.Helper()
	t.Setenv("YIP_ROOT", t.TempDir())
}

// The whole scheme rests on this: two agents asking at once, exactly one wins.
// A read-then-write acquire would let both through, so this is the test that
// would fail if anyone "simplified" atomicCreate into a check plus a write.
func TestAcquireIsExclusive(t *testing.T) {
	resTestRoot(t)
	got1, _, _, err := TryAcquire("mac", "main", "first", time.Hour, nil)
	if err != nil || !got1 {
		t.Fatalf("first acquire should win: got=%v err=%v", got1, err)
	}
	got2, cur, pos, err := TryAcquire("mac", "aux", "second", time.Hour, nil)
	if err != nil {
		t.Fatalf("second acquire errored: %v", err)
	}
	if got2 {
		t.Fatal("BOTH agents hold the lease -- mutual exclusion is broken")
	}
	if cur.Holder != "main" {
		t.Fatalf("holder should be main, got %q", cur.Holder)
	}
	if pos != 1 {
		t.Fatalf("loser should be queued at 1, got %d", pos)
	}
}

// A holder re-asking must renew rather than fail, or a long job cannot extend
// its TTL without a release/acquire gap a peer could win.
func TestReacquireRenews(t *testing.T) {
	resTestRoot(t)
	if got, _, _, _ := TryAcquire("mac", "main", "a", time.Hour, nil); !got {
		t.Fatal("setup acquire failed")
	}
	got, cur, _, err := TryAcquire("mac", "main", "b", 2*time.Hour, []int{7})
	if err != nil || !got {
		t.Fatalf("holder re-acquire should renew: got=%v err=%v", got, err)
	}
	if cur.Reason != "b" || cur.TTLSecs != int(2*time.Hour/time.Second) {
		t.Fatalf("renew did not update reason/ttl: %+v", cur)
	}
}

// Release is the ONLY thing that ends a claim, so it must refuse a non-holder.
// If anyone may end a claim, the holder's word stops being authoritative and
// the scheme degrades to the advisory flag it replaces.
func TestReleaseRefusesNonHolder(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "mine", time.Hour, nil)
	if _, err := Release("mac", "aux"); err == nil {
		t.Fatal("aux released a lease it does not hold")
	}
	if l, ok := LoadLease("mac"); !ok || l.Holder != "main" {
		t.Fatal("lease damaged by a refused release")
	}
	if _, err := Release("mac", "main"); err != nil {
		t.Fatalf("holder could not release: %v", err)
	}
	if _, ok := LoadLease("mac"); ok {
		t.Fatal("lease survived its own release")
	}
}

// FIFO, and specifically: an unheld resource is NOT free-for-all. Without the
// head-of-queue check, whoever polls at the right instant wins and an early
// waiter can starve behind latecomers.
func TestQueueIsFIFO(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "holding", time.Hour, nil)
	TryAcquire("mac", "aux", "second", time.Hour, nil)  // queues first
	time.Sleep(1100 * time.Millisecond)                 // RFC3339 is second-granular
	TryAcquire("mac", "vault", "third", time.Hour, nil) // queues second
	if q := Queue("mac"); len(q) != 2 || q[0].Agent != "aux" || q[1].Agent != "vault" {
		t.Fatalf("queue order wrong: %+v", q)
	}
	Release("mac", "main")
	// vault must NOT be able to jump aux even though it asks first.
	if got, _, _, _ := TryAcquire("mac", "vault", "third", time.Hour, nil); got {
		t.Fatal("vault jumped the queue ahead of aux")
	}
	if got, _, _, _ := TryAcquire("mac", "aux", "second", time.Hour, nil); !got {
		t.Fatal("aux was at the head and did not get it")
	}
}

// An expired lease is not an open one. Stealing a LIVE lease must be refused,
// and stealing an expired one must be recorded -- a silent reclaim would
// recreate the bug this whole file exists to close, with a timer attached.
func TestStealOnlyWhenExpiredAndIsRecorded(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "live work", time.Hour, nil)
	if _, err := Steal("mac", "aux", "impatient"); err == nil {
		t.Fatal("stole a live lease")
	}
	// Expire it by hand: TTL is wall-clock, so backdate Since.
	l, _ := LoadLease("mac")
	l.Since = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	l.TTLSecs = 60
	b, _ := json.MarshalIndent(l, "", "  ")
	os.WriteFile(leasePath("mac"), b, 0o644)

	if _, err := Steal("mac", "aux", ""); err == nil {
		t.Fatal("stole without a reason -- an unexplained reclaim is indistinguishable from a breach")
	}
	nl, err := Steal("mac", "aux", "main dead 2h, needed for the gate")
	if err != nil {
		t.Fatalf("could not steal an expired lease: %v", err)
	}
	if nl.Holder != "aux" || nl.StolenFrom != "main" || nl.StealWhy == "" {
		t.Fatalf("steal not recorded: %+v", nl)
	}
}

// Expiry must be wall-clock, never heartbeat. Guarding it here because the
// "obvious" improvement -- reclaim when the holder stops beating -- would steal
// a machine out from under a live 40-minute gate, whose holder legitimately
// does not beat while blocked in one long call.
func TestExpiryIsWallClockNotHeartbeat(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "long gate", time.Hour, nil)
	l, _ := LoadLease("mac")
	if l.Expired() {
		t.Fatal("fresh lease reported expired")
	}
	// No beat is written anywhere in this test; the lease must still be held.
	if _, ok := LoadLease("mac"); !ok {
		t.Fatal("lease vanished without a heartbeat")
	}
	if got, _, _, _ := TryAcquire("mac", "aux", "opportunist", time.Hour, nil); got {
		t.Fatal("a silent holder lost its lease -- heartbeat leaked into expiry")
	}
}

func TestUnknownResourceRefused(t *testing.T) {
	resTestRoot(t)
	if _, _, _, err := TryAcquire("laptop", "main", "x", time.Hour, nil); err == nil {
		t.Fatal("acquired an unknown resource")
	}
}

// THE REAL EXCLUSIVITY TEST. The sequential one above cannot reach the
// compare-and-set: TryAcquire returns at the "held by someone else" branch long
// before it links, so replacing atomicCreate with a clobbering write left it
// green. Measured -- the sabotage passed, which is the finding.
//
// Only genuine concurrency exercises the window between the LoadLease check and
// the create, and that window is exactly what atomicCreate closes.
func TestAcquireIsExclusiveUnderRace(t *testing.T) {
	resTestRoot(t)
	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := []string{}
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		agent := fmt.Sprintf("a%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them all at once
			if got, _, _, _ := TryAcquire("mac", agent, "race", time.Hour, nil); got {
				mu.Lock()
				winners = append(winners, agent)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(winners) != 1 {
		t.Fatalf("expected exactly ONE winner, got %d: %v -- mutual exclusion is broken", len(winners), winners)
	}
	l, ok := LoadLease("mac")
	if !ok || l.Holder != winners[0] {
		t.Fatalf("lease holder %q disagrees with the winner %v", l.Holder, winners)
	}
}
