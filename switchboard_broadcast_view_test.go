package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBroadcastConversationRailAndTranscript(t *testing.T) {
	seedBroadcastMembers(t)
	b, err := CreateBroadcast("operator", "regroup", "Regroup now\nDetails with 界 and \033]52;c;hidden\a", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if err = ReplyBroadcast(b.ID, "b", "The build is complete."); err != nil {
		t.Fatal(err)
	}
	v := &view{st: loadState()}
	if len(v.st.calls) != 1 || v.selectedConversation().broadcast == nil || v.selectedCall() != nil {
		t.Fatal("broadcast must be selectable but never a call mutation target")
	}
	p := palette{enabled: true, violet: "\033[35m", cyan: "\033[36m", amber: "\033[33m", green: "\033[32m", muted: "\033[90m"}
	rail := strings.Join(v.callRail(60, p), "\n")
	if !strings.Contains(rail, "BROADCAST / regroup") || !strings.Contains(rail, "1/2 read") || !strings.Contains(rail, p.violet) {
		t.Fatal(rail)
	}
	for _, render := range []string{strings.Join(v.styledTranscript(60, p), "\n"), strings.Join(v.broadcastLines(60, p), "\n")} {
		for _, want := range []string{p.violet, p.cyan, p.amber, "REPLY", "response pending", "The build is complete."} {
			if !strings.Contains(render, want) {
				t.Fatalf("missing %q in %s", want, render)
			}
		}
		if strings.Contains(render, "\033]52") || strings.Contains(render, "hidden") {
			t.Fatal("terminal injection")
		}
	}
	before, _ := os.ReadFile(receiptPath(b.ID, "a"))
	for _, size := range [][2]int{{160, 44}, {110, 32}, {80, 24}, {40, 10}} {
		for _, tab := range []int{0, 3} {
			v.tab = tab
			for _, row := range v.frameLines(size[1], size[0]) {
				if plainWidth(row) > size[0] {
					t.Fatal("overflow")
				}
			}
		}
	}
	after, _ := os.ReadFile(receiptPath(b.ID, "a"))
	if string(before) != string(after) {
		t.Fatal("observer marked receipt read")
	}
	v.key('r')
	if v.prompt != "" {
		t.Fatal("ratification accepted on broadcast")
	}
	v.key('a')
	if v.prompt != "" {
		t.Fatal("arbitration accepted on broadcast")
	}
	c, _ := NewCall("a", "b", "New call")
	v.refresh(loadState())
	if v.selectedConversation().broadcast == nil || v.selectedConversation().broadcast.ID != b.ID {
		t.Fatal("broadcast selection lost on refresh")
	}
	for i, item := range v.st.calls {
		if item.call.ID == c.ID {
			v.sel = i
		}
	}
	v.frameLines(44, 160)
	v.tab = 3
	var index int
	for i, item := range v.st.calls {
		if item.broadcast != nil {
			index = i
		}
	}
	v.mouse(sbMouse{x: 3, y: v.panes.top + 2 + 3*index})
	if v.tab != 0 || v.selectedConversation().broadcast == nil {
		t.Fatal("rail click did not open broadcast")
	}
	v.tab = 2
	v.frameLines(24, 80)
	v.railScroll = 0
	v.mouse(sbMouse{x: v.panes.centerX + 3, y: v.panes.top + 2 + 3*index})
	if v.tab != 0 || v.selectedConversation().broadcast == nil {
		t.Fatal("narrow list click did not open broadcast")
	}
	mono := strings.Join(v.styledTranscript(60, palette{}), "\n")
	if strings.Contains(mono, "\033") {
		t.Fatal("monochrome transcript has escapes")
	}
}

func TestDispatchWatchLivenessAndExclusiveOwner(t *testing.T) {
	seedBroadcastMembers(t)
	if err := RegisterEndpoint("a", testThread, false); err != nil {
		t.Fatal(err)
	}
	if dispatchWatchAlive("a") || !strings.Contains(EndpointStatus("a"), "dispatcher stopped") {
		t.Fatal("registration presented as active")
	}
	release, err := beginDispatchWatch("a")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if !dispatchWatchAlive("a") || !strings.Contains(EndpointStatus("a"), "dispatcher running") {
		t.Fatal("owner not detected")
	}
	if another, err := beginDispatchWatch("a"); err == nil {
		another()
		t.Fatal("duplicate owner allowed")
	}
	release()
	if dispatchWatchAlive("a") || !strings.Contains(EndpointStatus("a"), "dispatcher stopped") {
		t.Fatal("stale lock claims liveness")
	}
}

// Regression for the operator's fully answered regroup: completion must not
// bury its mouse-selectable row below open, stale and archived call history.
func TestCompletedBroadcastStaysVisibleAboveCallHistory(t *testing.T) {
	seedBroadcastMembers(t)
	for i := 0; i < 20; i++ {
		if _, err := NewCall("a", "b", "Old conversation"); err != nil {
			t.Fatal(err)
		}
	}
	b, err := CreateBroadcast("operator", "regroup", "Completed briefing", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range b.Recipients {
		if err := ReplyBroadcast(b.ID, a, "Reported."); err != nil {
			t.Fatal(err)
		}
	}
	st := loadState()
	if len(st.calls) != 21 || st.calls[0].broadcast == nil || st.calls[0].broadcast.ID != b.ID || st.calls[0].status != "resolved" {
		t.Fatal("completed broadcast buried below call history")
	}
	v := &view{st: st, sel: 1, tab: 3}
	v.frameLines(24, 160)
	if !strings.Contains(strings.Join(v.callRail(25, palette{})[:5], "\n"), "BROADCAST / regroup") {
		t.Fatal("broadcast missing from first rail item")
	}
	v.mouse(sbMouse{x: 3, y: v.panes.top + 2})
	if v.tab != 0 || v.selectedConversation().broadcast == nil || v.selectedConversation().broadcast.ID != b.ID {
		t.Fatal("mouse failed to open completed broadcast")
	}
	if !strings.Contains(strings.Join(v.styledTranscript(60, palette{}), "\n"), "2/2 read · 2 replied") {
		t.Fatal("completed replies not displayed")
	}
	// New broadcasts also sort ahead of completed ones by their own activity,
	// while refresh preserves the operator's selected transcript.
	newer, err := CreateBroadcast("operator", "announcement", "New bulletin", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	newer.At = "2099-01-01T00:00:00Z"
	if err := writeState(filepath.Join(broadcastDir(), newer.ID+".json"), newer); err != nil {
		t.Fatal(err)
	}
	next := loadState()
	if next.calls[0].broadcast.ID != newer.ID {
		t.Fatal("broadcast activity order wrong")
	}
	v.refresh(next)
	if v.selectedConversation().broadcast.ID != b.ID {
		t.Fatal("selected completed briefing moved to newer broadcast")
	}
}
