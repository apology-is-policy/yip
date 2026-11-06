package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenewalStartsAtRenewal(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "build", time.Minute, nil)
	l, _ := LoadLease("mac")
	l.Since = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	b, _ := json.Marshal(l)
	os.WriteFile(leasePath("mac"), b, 0600)
	got, l, _, e := TryAcquire("mac", "main", "still building", time.Minute, nil)
	if e != nil || !got || l.Remaining() < 55*time.Second {
		t.Fatalf("renewal did not buy a fresh duration: %+v %v", l, e)
	}
}
func TestDurableRequestCancellationAndOffer(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "build", time.Hour, nil)
	got, _, _, e := Request("mac", "astra", "tests", time.Minute, nil)
	if got || e != nil {
		t.Fatal(got, e)
	}
	q, _ := loadRequest("mac", "astra")
	id := q.ID
	q.Seen = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	saveRequest("mac", q)
	if len(Queue("mac")) != 1 {
		t.Fatal("durable request lost to legacy heartbeat timeout")
	}
	Request("mac", "astra", "tests", time.Minute, nil)
	q, _ = loadRequest("mac", "astra")
	if q.ID != id {
		t.Fatal("renew replaced request identity")
	}
	Release("mac", "main")
	q, _ = loadRequest("mac", "astra")
	if q.Offered == "" {
		t.Fatal("release did not offer head")
	}
	q.Offered = time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339)
	saveRequest("mac", q)
	got, _, _, e = Request("mac", "aux", "next", time.Minute, nil)
	if !got || e != nil {
		t.Fatal("missed offer blocked next", got, e)
	}
	h, _ := QueueHistory("mac")
	if !strings.Contains(h, "offer-expired") {
		t.Fatal(h)
	}
	Request("mac", "corona", "queued", time.Minute, nil)
	if e := CancelRequest("mac", "corona"); e != nil {
		t.Fatal(e)
	}
	if l, _ := LoadLease("mac"); l.Holder != "aux" {
		t.Fatal("cancel changed another lease")
	}
	h, _ = QueueHistory("mac")
	if !strings.Contains(h, "cancelled") {
		t.Fatal(h)
	}
}
func TestExpiredRequestRejoinsAtTail(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "build", time.Hour, nil)
	Request("mac", "a", "old", time.Minute, nil)
	q, _ := loadRequest("mac", "a")
	q.Expires = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	saveRequest("mac", q)
	Request("mac", "b", "waiting", time.Minute, nil)
	Request("mac", "a", "returned", time.Minute, nil)
	qs := Queue("mac")
	if len(qs) != 2 || qs[0].Agent != "b" {
		t.Fatalf("expired waiter jumped queue: %+v", qs)
	}
}

func TestLegacyQueueAdoptionGetsStableIdentityWithoutReordering(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "main", "build", time.Hour, nil)
	TryAcquire("mac", "astra", "legacy waiter", time.Minute, nil)
	before, ok := loadRequest("mac", "astra")
	if !ok || before.ID != "" {
		t.Fatal("not a legacy entry", before)
	}
	got, _, pos, err := Request("mac", "astra", "durable waiter", time.Minute, nil)
	if got || pos != 1 || err != nil {
		t.Fatal(got, pos, err)
	}
	after, _ := loadRequest("mac", "astra")
	if after.ID == "" || after.Since != before.Since {
		t.Fatal("identity or position lost", before, after)
	}
	Request("mac", "astra", "same request", time.Minute, nil)
	again, _ := loadRequest("mac", "astra")
	if again.ID != after.ID {
		t.Fatal("identity changed", after, again)
	}
	CancelRequest("mac", "astra")
	history, _ := QueueHistory("mac")
	if !strings.Contains(history, after.ID+" astra cancelled") {
		t.Fatal(history)
	}
}
func TestLifecycleDoesNotResolveByAge(t *testing.T) {
	tmpLine(t)
	c, e := NewCall("a", "b", "old question")
	if e != nil {
		t.Fatal(e)
	}
	AppendTurn(c, "a", "please decide", false)
	files, _ := filepath.Glob(filepath.Join(c.Dir(), "turns", "*.md"))
	b, _ := os.ReadFile(files[0])
	b = []byte(strings.ReplaceAll(string(b), now(), time.Now().Add(-72*time.Hour).UTC().Format(time.RFC3339)))
	os.WriteFile(files[0], b, 0600)
	turns, _ := Turns(c)
	if CallStatus(c, turns) != "stale" || IsClosed(c) {
		t.Fatal("old request incorrectly resolved")
	}
	rings, _ := RingFor("b")
	if len(rings) != 0 {
		t.Fatal("stale floor still blocks")
	}
	digest, _ := Inbox("b", true)
	if !strings.Contains(digest, "unresolved") {
		t.Fatal(digest)
	}
	if e := SetCallStatus(c, "b", "open", "resume this decision", ""); e != nil {
		t.Fatal(e)
	}
	turns, _ = Turns(c)
	if CallStatus(c, turns) != "open" {
		t.Fatal("explicit reopen did not activate old call")
	}
	if e := SetCallStatus(c, "b", "archived", "retain for later", ""); e != nil {
		t.Fatal(e)
	}
	if CallStatus(c, turns) != "archived" || IsClosed(c) {
		t.Fatal("archive resolved request")
	}
}
func TestNotesReadParityAndNoStopObligation(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("a", "b", "FYI")
	AppendTurn(c, "a", "request", false)
	AppendTurn(c, "b", "answer", false)
	SetCallStatus(c, "a", "resolved", "answered", "")
	AppendNote(c, "b", AuthorAgent, "a useful follow-up")
	inbox, _ := Inbox("a", false)
	if !strings.Contains(inbox, "1 notes unread") {
		t.Fatal(inbox)
	}
	if got := hookStop("a"); got != nil {
		t.Fatal("note made a stop obligation", got)
	}
	out, e := (&server{me: "a"}).call("read", map[string]any{"call": c.ID})
	if e != nil || !strings.Contains(out, "a useful follow-up") {
		t.Fatal(out, e)
	}
	n, _ := NoteUnseen(c, "a")
	if n != 0 {
		t.Fatal("read didn't acknowledge notes")
	}
}
func TestRetireKeepsHistoryAndCanUndo(t *testing.T) {
	tmpLine(t)
	SetBusy("a", "working", nil)
	Retire("a", true)
	out, _ := presenceText("", "b")
	if strings.Contains(out, "a:") {
		t.Fatal(out)
	}
	if _, ok := LoadPresence("a"); !ok {
		t.Fatal("retire deleted history")
	}
	Retire("a", false)
	out, _ = presenceText("", "b")
	if !strings.Contains(out, "a:") {
		t.Fatal(out)
	}
}
func TestRecoveryRejectsAliveOrUnknownRunners(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "a", "test", time.Hour, []int{os.Getpid()})
	l, _ := LoadLease("mac")
	l.Since = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	b, _ := json.Marshal(l)
	os.WriteFile(leasePath("mac"), b, 0600)
	if _, e := Steal("mac", "b", "controller silent"); e == nil {
		t.Fatal("stole from live runner")
	}
	l.Runners[0].Start = ""
	b, _ = json.Marshal(l)
	os.WriteFile(leasePath("mac"), b, 0600)
	if _, e := Steal("mac", "b", "unknown identity"); e == nil {
		t.Fatal("stole with unknown runner")
	}
}

func TestMalformedLeaseFailsClosed(t *testing.T) {
	resTestRoot(t)
	if err := ensureResourceDirs("mac"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leasePath("mac"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, held := LoadLease("mac"); !held {
		t.Fatal("unreadable lease reported free")
	}
	if got, _, _, err := TryAcquire("mac", "a", "test", time.Minute, nil); got || err == nil {
		t.Fatal("corrupt lease not rejected", got, err)
	}
	if _, err := Steal("mac", "a", "corrupt state"); err == nil {
		t.Fatal("overwrote corrupt lease")
	}
	b, _ := os.ReadFile(leasePath("mac"))
	if string(b) != "broken" {
		t.Fatal("changed corrupt state")
	}
}

func TestRepeatedReleaseIsVisibleBetweenWatchPolls(t *testing.T) {
	resTestRoot(t)
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"a", "b", "c"} {
		if _, _, _, err := Request("mac", who, "test", time.Minute, nil); err != nil {
			t.Fatal(err)
		}
	}
	before := watchSnapshot("c")
	if _, err := Release("mac", "a"); err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := Request("mac", "b", "test", time.Minute, nil); !got || err != nil {
		t.Fatal(got, err)
	}
	if _, err := Release("mac", "b"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for k, v := range watchSnapshot("c") {
		if strings.HasPrefix(k, "resource-event:") {
			if _, ok := before[k]; !ok {
				n++
				if !strings.Contains(v, " released by ") {
					t.Fatalf("a holder's release must read as done, not as a request: %q", v)
				}
			}
		}
	}
	if n != 2 {
		t.Fatalf("missed a release between polls: %d", n)
	}
}

func resourceEventKeys(me string) int {
	n := 0
	for k := range watchSnapshot(me) {
		if strings.HasPrefix(k, "resource-event:") {
			n++
		}
	}
	return n
}

func TestReleaseReachesOnlyThoseQueuedForTheResource(t *testing.T) {
	resTestRoot(t)
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"a", "b"} {
		if _, _, _, err := Request("mac", who, "test", time.Minute, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Release("mac", "a"); err != nil {
		t.Fatal(err)
	}
	if n := resourceEventKeys("b"); n != 1 {
		t.Fatalf("CONTROL: the agent queued for it should see the release: %d", n)
	}
	if n := resourceEventKeys("bystander"); n != 0 {
		t.Fatalf("an agent not queued for it should not be woken: %d", n)
	}
	if n := resourceEventKeys("a"); n != 0 {
		t.Fatalf("the agent that released it should not be told: %d", n)
	}

	// Joining the queue later must not replay what happened before it.
	if _, _, _, err := Request("mac", "late", "test", time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	q, ok := loadRequest("mac", "late")
	if !ok {
		t.Fatal("no request for the late joiner")
	}
	q.Since = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := saveRequest("mac", q); err != nil {
		t.Fatal(err)
	}
	if n := resourceEventKeys("late"); n != 0 {
		t.Fatalf("a late joiner should not see earlier events: %d", n)
	}
}

func TestResourceEventConcerns(t *testing.T) {
	e := ResourceEvent{By: "x", At: "2026-01-01T00:00:10Z", Previous: Lease{Holder: "a"}}
	queue := []QueueEntry{
		{Agent: "early", Since: "2026-01-01T00:00:09Z"},
		{Agent: "same", Since: "2026-01-01T00:00:10Z"},
		{Agent: "late", Since: "2026-01-01T00:00:11Z"},
	}
	for me, want := range map[string]bool{
		"x": false, "a": true, "early": true, "same": true, "late": false, "other": false,
	} {
		if got := resourceEventConcerns(e, me, queue); got != want {
			t.Errorf("%s: got %v, want %v", me, got, want)
		}
	}
	// One's own act on one's own lease is still not news.
	self := ResourceEvent{By: "a", At: e.At, Previous: Lease{Holder: "a"}}
	if resourceEventConcerns(self, "a", nil) {
		t.Error("an agent's own release concerns it")
	}
}

func TestRecoveryPersistsPeerNoticeAndPriorLease(t *testing.T) {
	resTestRoot(t)
	TryAcquire("mac", "a", "original purpose", time.Minute, nil)
	l, _ := LoadLease("mac")
	l.Since = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	b, _ := json.Marshal(l)
	os.WriteFile(leasePath("mac"), b, 0600)
	if _, err := Steal("mac", "b", "operator confirmed abandoned work; no registered runners"); err != nil {
		t.Fatal(err)
	}
	events := ResourceEvents("mac")
	if len(events) != 1 || events[0].Previous.Reason != "original purpose" {
		t.Fatal(events)
	}
	if notices := RecoveryNotices("a"); len(notices) != 1 || !strings.Contains(notices[0], "recovery requested") {
		t.Fatal(notices)
	}
}

func TestReopenRearmsStopGuardOnce(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("a", "b", "decision")
	AppendTurn(c, "a", "please decide", false)
	if hookStop("b") == nil {
		t.Fatal("no first obligation")
	}
	if hookStop("b") != nil {
		t.Fatal("loop guard missing")
	}
	SetCallStatus(c, "b", "deferred", "later", "")
	if hookStop("b") != nil {
		t.Fatal("deferred call blocked")
	}
	SetCallStatus(c, "a", "open", "ready now", "")
	if hookStop("b") == nil {
		t.Fatal("reopen not visible")
	}
	if hookStop("b") != nil {
		t.Fatal("reopen loops")
	}
}
