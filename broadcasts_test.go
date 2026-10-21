package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestBroadcastResponsesPreserveFloorsAndResources(t *testing.T) {
	seedBroadcastMembers(t)
	c, _ := NewCall("a", "b", "existing")
	AppendTurn(c, "a", "question", false)
	turns, _ := Turns(c)
	floor := FloorHolder(c, turns)
	TryAcquire("mac", "a", "gate", time.Hour, nil)
	leaseBefore, _ := os.ReadFile(leasePath("mac"))
	b, e := CreateBroadcast("operator", "briefing", "progress and blockers", []string{"a", "b"})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(BroadcastInbox("b", false), "reply requested") {
		t.Fatal("request missing")
	}
	if _, e = ReadBroadcast(b.ID, "c"); e == nil {
		t.Fatal("unaddressed read")
	}
	if _, e = ReadBroadcast(b.ID, "b"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(BroadcastInbox("b", false), "reply requested") {
		t.Fatal("read resolved response")
	}
	if e = ReplyBroadcast(b.ID, "b", "gate running; checkpoint in ten minutes"); e != nil {
		t.Fatal(e)
	}
	if BroadcastInbox("b", false) != "" {
		t.Fatal("answered request still pending")
	}
	if !strings.Contains(BroadcastInbox("a", false), "reply requested") {
		t.Fatal("one reply resolved another recipient")
	}
	after, _ := Turns(c)
	leaseAfter, _ := os.ReadFile(leasePath("mac"))
	if len(after) != len(turns) || FloorHolder(c, after) != floor || string(leaseBefore) != string(leaseAfter) {
		t.Fatal("broadcast changed floors or lease")
	}
}
func TestBroadcastDefaultAudienceExcludesPausedAndRetired(t *testing.T) {
	seedBroadcastMembers(t)
	RegisterEndpoint("b", testThread, false)
	PauseEndpoint("b", true)
	Retire("c", true)
	got := BroadcastRecipients()
	if len(got) != 1 || got[0] != "a" {
		t.Fatal(got)
	}
	b, e := CreateBroadcast("operator", "announcement", "FYI", got)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(BroadcastInbox("a", false), "reply requested") {
		t.Fatal("announcement demands reply")
	}
	PauseEndpoint("b", false)
	Retire("c", false)
	if b.hasRecipient("b") || b.hasRecipient("c") {
		t.Fatal("audience changed")
	}
}
func TestBroadcastComposePreviewDraftAndReplies(t *testing.T) {
	seedBroadcastMembers(t)
	v := &view{by: "operator", st: loadState()}
	v.key('b')
	v.input = []rune("a,b")
	v.submit()
	v.input = []rune("briefing")
	v.submit()
	v.input = []rune("progress please \x1b[31m")
	v.submit()
	bs, _ := ListBroadcasts()
	if len(bs) != 0 {
		t.Fatal("sent before confirmation")
	}
	v.frameLines(24, 80)
	v.key(27)
	if v.broadcast == nil || v.broadcast.Body == "" {
		t.Fatal("lost draft on escape/resize")
	}
	v.key('b')
	v.submit()
	v.submit()
	v.submit()
	v.input = []rune("SEND")
	v.submit()
	bs, _ = ListBroadcasts()
	if len(bs) != 1 {
		t.Fatal(bs, v.flash)
	}
	ReplyBroadcast(bs[0].ID, "b", "working on it")
	rendered := strings.Join(v.broadcastLines(65, palette{}), "\n")
	if !strings.Contains(rendered, "working on it") || !strings.Contains(rendered, "response pending") || strings.Contains(rendered, "\x1b") {
		t.Fatal(rendered)
	}
}

func TestCancelledBroadcastDoesNotCaptureRatification(t *testing.T) {
	seedBroadcastMembers(t)
	c, _ := NewCall("a", "b", "question")
	AppendTurn(c, "a", "question", false)
	v := &view{by: "operator", st: loadState()}
	v.key('b')
	v.key(27)
	v.key('r')
	v.input = []rune("operator note")
	v.submit()
	notes, _ := Notes(c)
	if len(notes) != 1 || strings.TrimSpace(notes[0].Body) != "operator note" {
		t.Fatal("draft intercepted another operator action", notes, v.flash)
	}
}
