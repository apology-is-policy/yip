package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A pid that is verified dead: a child that has exited and been reaped.
func deadPid(t *testing.T) int {
	t.Helper()
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		t.Fatalf("could not run a child: %v", err)
	}
	return c.Process.Pid
}

// writeExpired plants a lease of holder whose TTL ran out `over` ago.
func writeExpired(t *testing.T, holder string, over time.Duration, pids []int, runners []Runner) {
	t.Helper()
	if err := ensureResourceDirs("mac"); err != nil {
		t.Fatal(err)
	}
	l := Lease{Resource: "mac", Holder: holder, Reason: "a gate that ended", TTLSecs: 60,
		Since: time.Now().Add(-over - time.Minute).UTC().Format(time.RFC3339), Pids: pids, Runners: runners}
	b, _ := json.Marshal(l)
	if err := os.WriteFile(leasePath("mac"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	offerMu.Lock()
	offerRefused = map[string]time.Time{}
	offerMu.Unlock()
}

func deadRunner(t *testing.T) ([]int, []Runner) {
	host, _ := os.Hostname()
	p := deadPid(t)
	return []int{p}, []Runner{{Host: host, PID: p, Start: "Thu Jan 1 00:00:00 1970"}}
}

// The rule itself: past the grace, with every registered runner verified dead,
// the head of the queue gets the machine -- and it is on the record that it
// came from an expired lease, with the evidence, and the old holder is told.
func TestExpiredLeasePassesToQueueHeadAfterGrace(t *testing.T) {
	resTestRoot(t)
	pids, runners := deadRunner(t)
	writeExpired(t, "a", 2*time.Hour, pids, runners)
	got, cur, _, err := TryAcquire("mac", "b", "next gate", time.Hour, nil)
	if err != nil || !got {
		t.Fatalf("the queue head did not get an offerable lease: got=%v err=%v", got, err)
	}
	if cur.Holder != "b" || cur.StolenFrom != "a" || !strings.Contains(cur.StealWhy, "all 1 registered are verified dead") {
		t.Fatalf("the takeover is not on the lease: %+v", cur)
	}
	if l, _ := LoadLease("mac"); l.Holder != "b" || l.Reason != "next gate" {
		t.Fatalf("lease on disk: %+v", l)
	}
	ev := ResourceEvents("mac")
	if len(ev) != 1 || !strings.HasPrefix(ev[0].Action, "expired lease passed to the queue: ") ||
		ev[0].Previous.Holder != "a" || len(ev[0].Evidence) != 1 || !strings.Contains(ev[0].Evidence[0], "dead") {
		t.Fatalf("no event with the evidence: %+v", ev)
	}
	if n := RecoveryNotices("a"); len(n) != 1 || !strings.Contains(n[0], "expired lease passed to the queue") {
		t.Fatalf("the old holder is not told: %v", n)
	}
	if len(Queue("mac")) != 0 {
		t.Fatalf("the taker is still queued: %+v", Queue("mac"))
	}
}

// A lease that registered nothing has nothing alive: the grace is all it gets.
func TestExpiredLeaseWithNoRunnerPassesAfterGrace(t *testing.T) {
	resTestRoot(t)
	writeExpired(t, "a", 11*time.Minute, nil, nil)
	got, cur, _, err := TryAcquire("mac", "b", "next", time.Hour, nil)
	if err != nil || !got || !strings.Contains(cur.StealWhy, "none was registered") {
		t.Fatalf("got=%v err=%v lease=%+v", got, err, cur)
	}
}

// Inside the grace the lease is its holder's, dead runners or not.
func TestExpiredLeaseIsKeptInsideTheGrace(t *testing.T) {
	resTestRoot(t)
	pids, runners := deadRunner(t)
	writeExpired(t, "a", 9*time.Minute, pids, runners)
	got, cur, pos, err := TryAcquire("mac", "b", "next", time.Hour, nil)
	if err != nil || got || cur.Holder != "a" || pos != 1 {
		t.Fatalf("a lease 9m past its TTL changed hands: got=%v err=%v cur=%+v pos=%d", got, err, cur, pos)
	}
	if len(ResourceEvents("mac")) != 0 {
		t.Fatal("a refused ask wrote an event")
	}
}

// Alive, unknown and unidentified runners each keep the lease, however long
// past its TTL: not seeing a runner die is not seeing it dead.
func TestExpiredLeaseIsKeptWhileARunnerMayLive(t *testing.T) {
	host, _ := os.Hostname()
	alive, err := runnerStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		pids    []int
		runners []Runner
	}{
		"alive":        {[]int{os.Getpid()}, []Runner{{Host: host, PID: os.Getpid(), Start: alive}}},
		"unknown":      {[]int{os.Getpid()}, []Runner{{Host: host, PID: os.Getpid(), Start: ""}}},
		"other host":   {[]int{os.Getpid()}, []Runner{{Host: host + ".elsewhere", PID: os.Getpid(), Start: alive}}},
		"unidentified": {[]int{os.Getpid()}, nil},
	} {
		resTestRoot(t)
		writeExpired(t, "a", 5*time.Hour, c.pids, c.runners)
		got, cur, _, err := TryAcquire("mac", "b", "next", time.Hour, nil)
		if err != nil || got || cur.Holder != "a" {
			t.Fatalf("%s runner: the lease changed hands: got=%v err=%v cur=%+v", name, got, err, cur)
		}
	}
}

// Only the head of the queue is offered it; a later asker waits its turn.
func TestExpiredLeasePassesInQueueOrder(t *testing.T) {
	resTestRoot(t)
	if got, _, _, _ := TryAcquire("mac", "a", "gate", time.Hour, nil); !got {
		t.Fatal("setup")
	}
	// Queue order is by arrival, then by name: b then c on both counts.
	if got, _, pos, _ := TryAcquire("mac", "b", "first in line", time.Hour, nil); got || pos != 1 {
		t.Fatal("b should queue first")
	}
	pids, runners := deadRunner(t)
	writeExpired(t, "a", time.Hour, pids, runners)
	if got, cur, pos, _ := TryAcquire("mac", "c", "second in line", time.Hour, nil); got || cur.Holder != "a" || pos != 2 {
		t.Fatalf("c jumped the queue: got=%v cur=%+v pos=%d", got, cur, pos)
	}
	if got, cur, _, err := TryAcquire("mac", "b", "first in line", time.Hour, nil); !got || err != nil || cur.StolenFrom != "a" {
		t.Fatalf("the head was not served: got=%v err=%v cur=%+v", got, err, cur)
	}
}

// A holder who is alive and late renews, and that ends the matter: nothing is
// taken, and a waiter who had been offered the lease keeps its place for the
// release instead of finding its two-minute window long gone.
func TestRenewalWithdrawsTheOfferAndKeepsTheWaiter(t *testing.T) {
	resTestRoot(t)
	if got, _, _, _ := TryAcquire("mac", "a", "gate", time.Hour, nil); !got {
		t.Fatal("setup")
	}
	if got, _, _, err := Request("mac", "b", "next", time.Hour, nil); got || err != nil {
		t.Fatal("b should queue", got, err)
	}
	writeExpired(t, "a", time.Hour, nil, nil)
	if err := advanceOffers("mac"); err != nil {
		t.Fatal(err)
	}
	q, _ := loadRequest("mac", "b")
	if q.Offered == "" {
		t.Fatal("an offerable lease was not offered to the head")
	}
	if got, cur, _, err := TryAcquire("mac", "a", "gate, still going", time.Hour, nil); !got || err != nil || cur.Expired() {
		t.Fatalf("the holder could not renew: got=%v err=%v cur=%+v", got, err, cur)
	}
	if q, _ = loadRequest("mac", "b"); q.Offered != "" {
		t.Fatalf("the offer outlived the renewal: %+v", q)
	}
	if got, cur, _, _ := Request("mac", "b", "next", time.Hour, nil); got || cur.Holder != "a" {
		t.Fatalf("a renewed lease changed hands: %+v", cur)
	}
	if _, err := Release("mac", "a"); err != nil {
		t.Fatal(err)
	}
	if head := Queue("mac"); len(head) == 0 || head[0].Agent != "b" {
		t.Fatalf("the waiter lost its place: %+v", head)
	}
	if q, _ = loadRequest("mac", "b"); q.Offered == "" {
		t.Fatal("the release did not offer the head afresh")
	}
	if got, cur, _, err := Request("mac", "b", "next", time.Hour, nil); !got || err != nil || cur.StolenFrom != "" {
		t.Fatalf("b did not get the released machine as an ordinary lease: got=%v err=%v cur=%+v", got, err, cur)
	}
}

// An offer overtaken by a held lease (here the holder registered a live
// runner without renewing) must not cost the waiter its place at the release.
func TestReleaseOffersTheHeadAfresh(t *testing.T) {
	resTestRoot(t)
	if got, _, _, _ := TryAcquire("mac", "a", "gate", time.Hour, nil); !got {
		t.Fatal("setup")
	}
	if got, _, _, err := Request("mac", "b", "next", time.Hour, nil); got || err != nil {
		t.Fatal("b should queue", got, err)
	}
	writeExpired(t, "a", time.Hour, nil, nil)
	if err := advanceOffers("mac"); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	alive, _ := runnerStart(os.Getpid())
	writeExpired(t, "a", time.Hour, []int{os.Getpid()}, []Runner{{Host: host, PID: os.Getpid(), Start: alive}})
	q, _ := loadRequest("mac", "b")
	if q.Offered == "" {
		t.Fatal("an offerable lease was not offered to the head")
	}
	q.Offered = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	saveRequest("mac", q)
	if got, cur, _, _ := Request("mac", "b", "next", time.Hour, nil); got || cur.Holder != "a" {
		t.Fatalf("a lease with a live runner changed hands: %+v", cur)
	}
	if _, err := Release("mac", "a"); err != nil {
		t.Fatal(err)
	}
	if head := Queue("mac"); len(head) == 0 || head[0].Agent != "b" {
		t.Fatalf("the waiter lost its place: %+v", head)
	}
	if q, _ = loadRequest("mac", "b"); q.Offered == "" || time.Since(mustTime(t, q.Offered)) > time.Minute {
		t.Fatalf("the release did not offer the head afresh: %+v", q)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// What a waiter is told about an expired lease says which of the three it is.
func TestExpiryOutlookNamesWhatHappensNext(t *testing.T) {
	resTestRoot(t)
	host, _ := os.Hostname()
	alive, _ := runnerStart(os.Getpid())
	for want, l := range map[string]Lease{
		"is not passed on":        {Resource: "mac", Holder: "a", TTLSecs: 60, Since: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), Pids: []int{os.Getpid()}, Runners: []Runner{{Host: host, PID: os.Getpid(), Start: alive}}},
		"unless they renew":       {Resource: "mac", Holder: "a", TTLSecs: 60, Since: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)},
		"when the head next asks": {Resource: "mac", Holder: "a", TTLSecs: 60, Since: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
	} {
		if got := l.expiryOutlook(); !strings.Contains(got, want) {
			t.Fatalf("outlook %q does not say %q", got, want)
		}
	}
}
