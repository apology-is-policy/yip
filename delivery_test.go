package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testThread = "00000000-0000-4000-8000-000000000001"

func seedBroadcastMembers(t *testing.T) {
	t.Helper()
	tmpLine(t)
	if e := SaveMembers(Members{Members: map[string]string{"/fixture/a": "a", "/fixture/b": "b", "/fixture/c": "c"}}); e != nil {
		t.Fatal(e)
	}
}
func TestStateTransactionsAcrossProcesses(t *testing.T) {
	if mode := os.Getenv("YIP_STATE_TEST_CHILD"); mode != "" {
		c := &Call{ID: "fixture"}
		for i := 0; i < 40; i++ {
			if e := UpdateAgentState(c, "a", func(s *AgentState) {
				if mode == "seen" {
					s.Seen++
				} else {
					s.SeenNotes++
				}
			}); e != nil {
				t.Fatal(e)
			}
		}
		return
	}
	tmpLine(t)
	var cmds []*exec.Cmd
	for _, mode := range []string{"seen", "seen", "notes", "notes"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStateTransactionsAcrossProcesses$")
		cmd.Env = append(os.Environ(), "YIP_STATE_TEST_CHILD="+mode)
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		cmds = append(cmds, cmd)
	}
	for _, cmd := range cmds {
		if e := cmd.Wait(); e != nil {
			t.Fatal(e)
		}
	}
	c := &Call{ID: "fixture"}
	s := LoadAgentState(c, "a")
	if s.Seen != 80 || s.SeenNotes != 80 {
		t.Fatal("lost concurrent cursor updates", s)
	}
	if e := SaveAgentState(c, "a", AgentState{NotifiedAt: 9}); e != nil {
		t.Fatal(e)
	}
	s = LoadAgentState(c, "a")
	if s.Seen != 80 || s.SeenNotes != 80 || s.NotifiedAt != 9 {
		t.Fatal("stale snapshot erased state", s)
	}
}
func TestCorruptStateCannotBeOverwritten(t *testing.T) {
	tmpLine(t)
	c := &Call{ID: "fixture"}
	if e := SaveAgentState(c, "a", AgentState{Seen: 3}); e != nil {
		t.Fatal(e)
	}
	p := agentStatePath(c, "a")
	os.WriteFile(p, []byte("broken"), 0600)
	if e := SaveAgentState(c, "a", AgentState{Seen: 9}); e == nil {
		t.Fatal("overwrote corruption")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "broken" {
		t.Fatal(string(b))
	}
	os.WriteFile(presencePath("a"), []byte("broken"), 0600)
	if e := Beat("a", "read"); e == nil {
		t.Fatal("beat overwrote corruption")
	}
}
func TestPresenceAndHookTransactions(t *testing.T) {
	tmpLine(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if e := Beat("a", "read"); e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			if e := SetBusy("a", "gate", []int{42}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	p, _ := LoadPresence("a")
	if p.Busy != "gate" || p.LastTool != "read" || len(p.Pids) != 1 {
		t.Fatal(p)
	}
	if e := SetBusy("a", "", nil); e != nil {
		t.Fatal(e)
	}
	p, _ = LoadPresence("a")
	if p.Busy != "" || p.LastTool != "read" {
		t.Fatal(p)
	}
	c, _ := NewCall("a", "b", "question")
	AppendTurn(c, "a", "answer please", false)
	var blocks atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if hookStop("b") != nil {
				blocks.Add(1)
			}
		}()
	}
	wg.Wait()
	if blocks.Load() != 1 {
		t.Fatal("duplicate Stop continuation", blocks.Load())
	}
}
func TestDurableDeliveryPauseAckAndNoDuplicate(t *testing.T) {
	seedBroadcastMembers(t)
	if e := RegisterEndpoint("b", testThread, false); e != nil {
		t.Fatal(e)
	}
	b, e := CreateBroadcast("operator", "briefing", "status please", []string{"b"})
	if e != nil {
		t.Fatal(e)
	}
	sends := 0
	send := func(_ context.Context, thread, text string) error {
		sends++
		if thread != testThread || !strings.Contains(text, b.ID) {
			t.Error(thread, text)
		}
		return nil
	}
	PauseEndpoint("b", true)
	if n, e := Dispatch("b", send); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	ep, _ := readEndpoint("b")
	if len(ep.Events) != 1 || ep.Events[0].Status != "pending" {
		t.Fatal(ep)
	}
	if e := RegisterEndpoint("b", testThread, true); e != nil {
		t.Fatal(e)
	}
	ep, _ = readEndpoint("b")
	if !ep.Paused {
		t.Fatal("reinstall unpaused endpoint")
	}
	PauseEndpoint("b", false)
	if n, e := Dispatch("b", send); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if n, e := Dispatch("b", send); e != nil || n != 0 {
		t.Fatal("resent accepted event", n, e)
	}
	ep, _ = readEndpoint("b")
	if e := AckDelivery("b", ep.Events[0].ID); e != nil {
		t.Fatal(e)
	}
	ep, _ = readEndpoint("b")
	if ep.Events[0].Status != "read" || sends != 1 {
		t.Fatal(ep, sends)
	}
	if e := AckDelivery("a", ep.Events[0].ID); e == nil {
		t.Fatal("other recipient acknowledged")
	}
}
func TestAmbiguousDeliveryRequiresExplicitRetry(t *testing.T) {
	seedBroadcastMembers(t)
	RegisterEndpoint("b", testThread, false)
	CreateBroadcast("operator", "announcement", "note", []string{"b"})
	sends := 0
	send := func(context.Context, string, string) error {
		sends++
		return errors.New("transport lost after possible acceptance")
	}
	if _, e := Dispatch("b", send); e == nil {
		t.Fatal("error lost")
	}
	ep, _ := readEndpoint("b")
	id := ep.Events[0].ID
	if ep.Events[0].Status != "unknown" {
		t.Fatal(ep)
	}
	Dispatch("b", send)
	if sends != 1 {
		t.Fatal("automatic retry")
	}
	if e := RetryDelivery("b", id); e != nil {
		t.Fatal(e)
	}
	// Simulate a crash after the attempt was persisted and before receipt save.
	editEndpoint("b", func(ep *Endpoint) error { ep.Events[0].Status = "sending"; return nil })
	Dispatch("b", send)
	if sends != 1 {
		t.Fatal("replayed crash attempt")
	}
	ep, _ = readEndpoint("b")
	if ep.Events[0].Status != "unknown" {
		t.Fatal(ep)
	}
	RetryDelivery("b", id)
	Dispatch("b", func(context.Context, string, string) error { sends++; return nil })
	if sends != 2 {
		t.Fatal(sends)
	}
}
func TestCompetingDispatchersAndRetirement(t *testing.T) {
	seedBroadcastMembers(t)
	RegisterEndpoint("b", testThread, false)
	CreateBroadcast("operator", "announcement", "hello", []string{"b"})
	var sent atomic.Int32
	var wg sync.WaitGroup
	send := func(context.Context, string, string) error { sent.Add(1); return nil }
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := Dispatch("b", send); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if sent.Load() != 1 {
		t.Fatal("duplicate dispatch", sent.Load())
	}
	CreateBroadcast("operator", "regroup", "next checkpoint", []string{"b"})
	Retire("b", true)
	if n, e := Dispatch("b", send); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	if sent.Load() != 1 {
		t.Fatal("woke retired session")
	}
}
func TestSourceReplayAndCorruptEndpoint(t *testing.T) {
	seedBroadcastMembers(t)
	c, _ := NewCall("a", "b", "before registration")
	AppendTurn(c, "a", "opening", false)
	RegisterEndpoint("b", testThread, false)
	n, e := Dispatch("b", func(context.Context, string, string) error { t.Fatal("replayed baseline"); return nil })
	if n != 0 || e != nil {
		t.Fatal(n, e)
	}
	AppendNote(c, "a", AuthorAgent, "after registration")
	n, e = Dispatch("b", func(context.Context, string, string) error { return nil })
	if n != 1 || e != nil {
		t.Fatal(n, e)
	}
	os.WriteFile(endpointPath("b"), []byte("broken"), 0600)
	if _, e = Dispatch("b", func(context.Context, string, string) error { t.Fatal("sent from corrupt endpoint"); return nil }); e == nil {
		t.Fatal("corruption ignored")
	}
}
func TestCodexTransportUsesLiteralArguments(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$YIP_TEST_ARG_LOG\"\n"
	os.WriteFile(filepath.Join(dir, "codex"), []byte(script), 0700)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("YIP_TEST_ARG_LOG", log)
	msg := "$(echo not-executed) `literal` ' quote\nsecond line"
	if e := codexSender(context.Background(), testThread, msg); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(log)
	want := "queue\n--thread\n" + testThread + "\n--message\n" + msg + "\n"
	if string(b) != want {
		t.Fatalf("argument corruption: %q", b)
	}
}
func TestCodexHookOutputContracts(t *testing.T) {
	stop := codexHookOutput("stop", map[string]any{"decision": "block", "reason": "reply", "terminalSequence": "bad", "hookSpecificOutput": map[string]any{"hookEventName": "Stop"}})
	b, _ := json.Marshal(stop)
	if string(b) != `{"decision":"block","reason":"reply"}` {
		t.Fatal(string(b))
	}
	post := codexHookOutput("posttooluse", map[string]any{"terminalSequence": "bad", "hookSpecificOutput": map[string]any{"hookEventName": "PostToolUse", "additionalContext": "notice"}})
	b, _ = json.Marshal(post)
	if strings.Contains(string(b), "terminalSequence") || !strings.Contains(string(b), "PostToolUse") {
		t.Fatal(string(b))
	}
}
func TestCodexInstallPreservesConfigAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".codex"), 0700)
	config := filepath.Join(root, ".codex", "config.toml")
	hooks := filepath.Join(root, ".codex", "hooks.json")
	old := "model = \"example\"\n[mcp_servers.other]\ncommand = \"other\"\n"
	os.WriteFile(config, []byte(old), 0600)
	os.WriteFile(hooks, []byte(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo keep"}]}]}}`), 0600)
	for i := 0; i < 2; i++ {
		if e := codexFiles(root, "/tmp/path with 'quote/yip", "test-line", "a", false); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := os.ReadFile(config)
	if !strings.HasPrefix(string(b), old) || strings.Count(string(b), "[mcp_servers.yip]") != 1 {
		t.Fatal(string(b))
	}
	m, _ := readJSON(hooks)
	h := m["hooks"].(map[string]any)
	if len(h["Stop"].([]any)) != 2 {
		t.Fatal(h)
	}
	backup, _ := os.ReadFile(config + ".yip-backup")
	if string(backup) != old {
		t.Fatal("backup changed")
	}
	if e := codexFiles(root, "", "", "", true); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(config)
	if strings.Contains(string(b), "mcp_servers.yip") || !strings.Contains(string(b), "mcp_servers.other") {
		t.Fatal(string(b))
	}
	m, _ = readJSON(hooks)
	h = m["hooks"].(map[string]any)
	if len(h["Stop"].([]any)) != 1 {
		t.Fatal(h)
	}
	if _, e := codexConfig("[mcp_servers.\"yip\"]\ncommand='private'\n", "bin", "line", "a", false); e == nil {
		t.Fatal("overwrote unmanaged server")
	}
}

func TestMixedHookGroupsPreserveOtherHandlers(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".codex")
	os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, "hooks.json")
	data := `{"hooks":{"Stop":[{"matcher":"keep-matcher","hooks":[{"type":"command","command":"echo keep"},{"type":"command","command":"old-yip # yip-line-hook"}]}]}}`
	os.WriteFile(path, []byte(data), 0600)
	if e := codexFiles(root, "/tmp/yip", "test", "a", false); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "echo keep") || !strings.Contains(string(b), "keep-matcher") || strings.Contains(string(b), "old-yip") {
		t.Fatal(string(b))
	}
}
func TestRetryRetainsAttemptHistory(t *testing.T) {
	seedBroadcastMembers(t)
	RegisterEndpoint("b", testThread, false)
	CreateBroadcast("operator", "announcement", "note", []string{"b"})
	Dispatch("b", func(context.Context, string, string) error { return errors.New("uncertain") })
	ep, _ := readEndpoint("b")
	id := ep.Events[0].ID
	RetryDelivery("b", id)
	Dispatch("b", func(context.Context, string, string) error { return nil })
	ep, _ = readEndpoint("b")
	attempts := ep.Events[0].Attempts
	if len(attempts) != 2 || attempts[0].Status != "unknown" || attempts[1].Status != "accepted" || attempts[0].ID == attempts[1].ID {
		t.Fatal(attempts)
	}
}
func TestDeliveryOfferDoesNotClaimResource(t *testing.T) {
	seedBroadcastMembers(t)
	TryAcquire("mac", "a", "gate", 60*60*1e9, nil)
	Request("mac", "b", "next", 60*60*1e9, nil)
	RegisterEndpoint("b", testThread, false)
	Release("mac", "a")
	n, e := Dispatch("b", func(_ context.Context, _ string, text string) error {
		if !strings.Contains(text, "inspect current lease") {
			t.Fatal(text)
		}
		return nil
	})
	if e != nil || n == 0 {
		t.Fatal(n, e)
	}
	if _, held := LoadLease("mac"); held {
		t.Fatal("delivery acquired resource")
	}
	q, _ := loadRequest("mac", "b")
	if q.Offered == "" {
		t.Fatal("offer missing")
	}
}

func TestRetirementSerializesWithDispatch(t *testing.T) {
	seedBroadcastMembers(t)
	RegisterEndpoint("b", testThread, false)
	CreateBroadcast("operator", "announcement", "first", []string{"b"})
	entered, finish := make(chan struct{}), make(chan struct{})
	dispatched := make(chan error, 1)
	go func() {
		_, err := Dispatch("b", func(context.Context, string, string) error { close(entered); <-finish; return nil })
		dispatched <- err
	}()
	<-entered
	retired := make(chan error, 1)
	go func() { retired <- Retire("b", true) }()
	select {
	case err := <-retired:
		close(finish)
		t.Fatalf("retirement returned during active send: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(finish)
	if err := <-dispatched; err != nil {
		t.Fatal(err)
	}
	if err := <-retired; err != nil {
		t.Fatal(err)
	}
	CreateBroadcast("operator", "announcement", "second", []string{"b"})
	n, err := Dispatch("b", func(context.Context, string, string) error { t.Fatal("sent after retirement"); return nil })
	if err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
