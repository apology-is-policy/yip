package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise serveIO itself: replacing the MCP process must start dispatch even
// if the resumed, idle chat never issues another tools/call. The fake queue
// captures literal argv; it cannot contact a real Codex chat.
func TestCodexMCPRestartDeliversBeforeFirstToolCall(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	unlock, err := codexSessionLock("b", threadA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bindCodexSession("b", threadA, "/original", time.Now()); err != nil {
		unlock()
		t.Fatal(err)
	}
	c, err := NewCall("a", "b", "resume regression")
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	if _, err := AppendTurn(c, "a", "first message", false); err != nil {
		unlock()
		t.Fatal(err)
	}
	if _, err := Dispatch("b", func(context.Context, string, string) error { return nil }); err != nil {
		unlock()
		t.Fatal(err)
	}
	before, _ := readEndpoint("b")
	unlock() // the original MCP process exits, retaining its binding/receipts
	if _, err := AppendNote(c, "a", AuthorAgent, "arrived during restart"); err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	argsPath := filepath.Join(bin, "queue-args")
	t.Setenv("YIP_TEST_QUEUE_ARGS", argsPath)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$YIP_TEST_QUEUE_ARGS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	input, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- serveIO("b", serveCodex, input, io.Discard) }()
	t.Cleanup(func() {
		_ = writer.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("MCP recovery did not stop on EOF")
		}
		_ = input.Close()
		if dispatchWatchAlive("b") || codexSessionAlive("b", threadA) {
			t.Error("MCP shutdown left a delivery lock held")
		}
	})
	// No tool call, and no thread ID in initialize.
	if _, err := io.WriteString(writer, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ep, err := readEndpoint("b")
		if err == nil && len(ep.Events) == len(before.Events)+1 && ep.Events[len(ep.Events)-1].Status == "accepted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement MCP did not deliver before tools/call", ep, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil || !strings.HasPrefix(string(args), "queue\n--thread\n"+threadA+"\n--message\nYip coordination notices") || strings.Contains(string(args), " CALL ") {
		t.Fatal("wrong destination/argv or replayed original call", string(args), err)
	}
	ep, _ := readEndpoint("b")
	if ep.Thread != before.Thread || ep.BoundAt != before.BoundAt || ep.Cwd != before.Cwd || ep.Binding != before.Binding {
		t.Fatal("recovery rewrote session ownership", ep)
	}
	for i, d := range ep.Events {
		if len(d.Attempts) != 1 || (i < len(before.Events) && d.Attempt != before.Events[i].Attempt) {
			t.Fatal("recovery retried an existing attempt", d)
		}
	}
	if codexSessionAlive("b", threadA) || !pushReachable("b") || !strings.Contains(EndpointStatus("b"), "dispatcher running") {
		t.Fatal("recovery must report dispatcher reachability without claiming a session lock", EndpointStatus("b"))
	}
}

func TestCodexRecoveryHonorsOwnershipPauseAndRebind(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	var targets []string
	send := func(_ context.Context, thread, _ string) error { targets = append(targets, thread); return nil }
	s := &server{me: "b", codexMode: true, started: time.Now(), codexSend: send}
	other := &server{me: "b", codexMode: true, started: time.Now(), codexSend: send}
	t.Cleanup(s.stopCodexRecovery)
	t.Cleanup(other.stopCodexRecovery)
	tick := func(s *server) {
		t.Helper()
		if err := s.codexTick(); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := NewCall("a", "b", "recovery ownership")
	AppendTurn(c, "a", "pending", false)
	tick(s)
	if len(targets) != 0 || dispatchWatchAlive("b") {
		t.Fatal("unbound endpoint recovered")
	}
	if err := RegisterEndpoint("b", threadA, false); err != nil {
		t.Fatal(err)
	}
	tick(s)
	if len(targets) != 0 || dispatchWatchAlive("b") {
		t.Fatal("manual registration silently started automatic recovery")
	}
	unlock, err := codexSessionLock("b", threadA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bindCodexSession("b", threadA, "", time.Now()); err != nil {
		unlock()
		t.Fatal(err)
	}
	tick(s)
	if len(targets) != 0 || dispatchWatchAlive("b") {
		unlock()
		t.Fatal("recovery competed with a live bound session")
	}
	unlock()
	if err := PauseEndpoint("b", true); err != nil {
		t.Fatal(err)
	}
	tick(s)
	if len(targets) != 0 || dispatchWatchAlive("b") {
		t.Fatal("paused endpoint recovered")
	}
	PauseEndpoint("b", false)
	if err := Retire("b", true); err != nil {
		t.Fatal(err)
	}
	tick(s)
	if len(targets) != 0 || dispatchWatchAlive("b") {
		t.Fatal("retired endpoint recovered")
	}
	Retire("b", false)
	tick(s)
	if len(targets) != 1 || targets[0] != threadA || !dispatchWatchAlive("b") {
		t.Fatal("did not recover saved session", targets)
	}
	AppendNote(c, "a", AuthorAgent, "only one recovery poller")
	tick(other)
	if len(targets) != 1 || other.codexRecoveryRelease != nil {
		t.Fatal("two recovery watchers ran", targets)
	}
	tick(s)
	if len(targets) != 2 {
		t.Fatal("recovery owner did not deliver", targets)
	}
	if res, err := bindCodexSession("b", threadB, "", other.started); err != nil || res.Bound {
		t.Fatal("older session displaced a binding with active recovery", res, err)
	}
	// A genuinely newer session takes over. Old notices are never replayed.
	other.started = time.Now()
	if note := other.observeCodexThread(threadB); !strings.Contains(note, "Delivery connected") {
		t.Fatal(note)
	}
	t.Cleanup(other.codexRelease)
	tick(s)
	if dispatchWatchAlive("b") || s.codexThread != "" {
		t.Fatal("recovery failed to yield or claimed a thread")
	}
	AppendNote(c, "a", AuthorAgent, "new session only")
	tick(other)
	if strings.Join(targets, ",") != threadA+","+threadA+","+threadB {
		t.Fatal("wrong destination or duplicate", targets)
	}
}

func TestCodexRecoveryLeavesInvalidAndOtherRuntimeEndpointsUntouched(t *testing.T) {
	for _, content := range []string{
		"broken",
		`{"version":1,"agent":"b","runtime":"codex","binding":"session","thread":"not-a-thread","known":{}}`,
		`{"version":1,"agent":"b","runtime":"claude-channels","binding":"session","thread":"other-session","known":{}}`,
	} {
		t.Run(content, func(t *testing.T) {
			seedBroadcastMembers(t)
			if err := os.MkdirAll(filepath.Dir(endpointPath("b")), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(endpointPath("b"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			s := &server{me: "b", codexSend: func(context.Context, string, string) error {
				t.Fatal("dispatched an invalid or other-runtime endpoint")
				return nil
			}}
			t.Cleanup(s.stopCodexRecovery)
			if err := s.codexTick(); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(endpointPath("b"))
			if string(got) != content || dispatchWatchAlive("b") {
				t.Fatal("recovery changed or claimed endpoint", string(got))
			}
		})
	}
}
