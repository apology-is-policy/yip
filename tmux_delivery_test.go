package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTmuxRequiresExplicitIdleAndCannotUseCodexDispatcher(t *testing.T) {
	tmpLine(t)
	target := &TmuxTarget{Socket: "/fixture/socket", Pane: "%1", PID: 123, Start: "fixture", Runtime: "claude"}
	ep := Endpoint{Version: 1, Agent: "a", Runtime: "tmux", Thread: "%1", Tmux: target, Known: map[string]bool{}}
	if e := writeState(endpointPath("a"), ep); e != nil {
		t.Fatal(e)
	}
	if e := DeliveryCLI([]string{"dispatch-tmux"}, "a"); e == nil {
		t.Fatal("missing idle assertion")
	}
	called := false
	if _, e := Dispatch("a", func(context.Context, string, string) error { called = true; return nil }); e == nil || called {
		t.Fatal("cross transport dispatch", e, called)
	}
	if e := RegisterChannel("a", false); e == nil {
		t.Fatal("replaced tmux endpoint")
	}
}
func TestTmuxRejectsUnsafeTargetBeforeInvokingTools(t *testing.T) {
	for _, pane := range []string{"main", "%1;touch /tmp/no", "-t", "%1\n"} {
		if _, e := inspectTmux(context.Background(), "/fixture/socket", pane); e == nil {
			t.Fatal(pane)
		}
	}
	path := filepath.Join(t.TempDir(), "file")
	os.WriteFile(path, []byte("not socket"), 0600)
	if _, e := inspectTmux(context.Background(), path, "%1"); e == nil {
		t.Fatal("regular file accepted")
	}
}
