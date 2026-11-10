package main

// claude-rewake: one waiter per identity, a wake is exit 2 with the notices on
// stderr, an orphaned waiter sends nothing, and the generated hooks name their
// identity and line so they can never resolve a different, empty line.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func always() bool { return true }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRewakeWakesOnceAndFencesASecondWaiter(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureEndpoint("a", "claude-rewake"); err != nil {
		t.Fatal(err)
	}
	if pushReachable("a") || !strings.Contains(EndpointStatus("a"), "not armed") {
		t.Fatal("unarmed session reported reachable", EndpointStatus("a"))
	}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- RunRewake("a", 10*time.Second, "session-1", &stderr, always, 20*time.Millisecond) }()
	waitFor(t, "waiter armed", func() bool { return rewakeArmed("a") })
	if !pushReachable("a") || !peerReachable("a") || !strings.Contains(EndpointStatus("a"), "armed;") {
		t.Fatal("armed waiter not reported", EndpointStatus("a"))
	}
	// The Stop of every turn starts another waiter; it must not stack.
	start := time.Now()
	if code := RunRewake("a", 10*time.Second, "session-1", &bytes.Buffer{}, always, 20*time.Millisecond); code != 0 || time.Since(start) > time.Second {
		t.Fatal("second waiter armed", code, time.Since(start))
	}
	// One source record = one event, so the batch is deterministic.
	b, err := CreateBroadcast("operator", "briefing", "status please", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 2 {
			t.Fatal("wake exit code", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never woke")
	}
	if out := stderr.String(); !strings.Contains(out, "Yip coordination notices") || !strings.Contains(out, b.ID) {
		t.Fatal(out)
	}
	ep, _ := readEndpoint("a")
	if ep.Thread != "session-1" || len(ep.Events) != 1 || ep.Events[0].Status != "sent" {
		t.Fatal(ep)
	}
	if rewakeArmed("a") {
		t.Fatal("lock kept after exit")
	}
	// Nothing new: a quiet window ends with exit 0 and resends nothing.
	if code := RunRewake("a", 100*time.Millisecond, "session-1", &stderr, always, 20*time.Millisecond); code != 0 {
		t.Fatal("resent", code)
	}
}

func TestPostToolUseIsQuietOnlyWhileAWaiterIsArmed(t *testing.T) {
	seedBroadcastMembers(t)
	ensureEndpoint("a", "claude-rewake")
	c, _ := NewCall("b", "a", "review please")
	AppendTurn(c, "b", "the diff", false)
	unlock, err := holdLock(rewakeLockPath("a")) // stands in for an armed waiter
	if err != nil {
		t.Fatal(err)
	}
	// The roadmap nudge is not a delivered notice: it still speaks while armed.
	v := hookPostToolUse("a", hookInput{})
	if b, _ := json.Marshal(v); !strings.Contains(string(b), "roadmap") || strings.Contains(string(b), c.ID) {
		t.Fatal("armed hook should carry only the roadmap nudge", string(b))
	}
	// With the nudge satisfied, it says nothing at all.
	if _, err := PostRoadmap("a", Roadmap{Arc: "x", Stations: []RoadmapStation{{Name: "s"}}}); err != nil {
		t.Fatal(err)
	}
	if v := hookPostToolUse("a", hookInput{}); v != nil {
		t.Fatal("hook repeated what the armed waiter delivers", v)
	}
	if st := LoadAgentState(c, "a"); st.NotifiedAt != 0 {
		t.Fatal("suppressed hook consumed its cursor", st)
	}
	unlock()
	if v := hookPostToolUse("a", hookInput{}); v == nil {
		t.Fatal("hook stayed quiet after the waiter's window ended")
	}
}

func TestOrphanedRewakeWaiterLeavesNoticesPending(t *testing.T) {
	seedBroadcastMembers(t)
	ensureEndpoint("a", "claude-rewake")
	c, _ := NewCall("b", "a", "while nobody listens")
	AppendTurn(c, "b", "hello", false)
	var checks atomic.Int32
	gone := func() bool { return checks.Add(1) == 0 } // the session already exited
	if code := RunRewake("a", time.Second, "", &bytes.Buffer{}, gone, 10*time.Millisecond); code != 0 {
		t.Fatal(code)
	}
	ep, _ := readEndpoint("a")
	for _, d := range ep.Events {
		if d.Status != "pending" {
			t.Fatal("orphaned waiter marked a notice", d.Status)
		}
	}
	var stderr bytes.Buffer
	if code := RunRewake("a", time.Second, "", &stderr, always, 10*time.Millisecond); code != 2 || !strings.Contains(stderr.String(), c.ID) {
		t.Fatal("live waiter did not deliver what the orphan left", code, stderr.String())
	}
}

func TestRewakeRespectsRuntimePauseAndRetirement(t *testing.T) {
	seedBroadcastMembers(t)
	ensureCodexEndpoint("b")
	start := time.Now()
	if code := RunRewake("b", 5*time.Second, "", &bytes.Buffer{}, always, 10*time.Millisecond); code != 0 || time.Since(start) > time.Second {
		t.Fatal("waited on a Codex endpoint", code)
	}
	if code := RunRewake("nobody", time.Second, "", &bytes.Buffer{}, always, 10*time.Millisecond); code != 0 {
		t.Fatal(code)
	}
	ensureEndpoint("a", "claude-rewake")
	PauseEndpoint("a", true)
	c, _ := NewCall("b", "a", "paused")
	AppendTurn(c, "b", "x", false)
	if code := RunRewake("a", 150*time.Millisecond, "", &bytes.Buffer{}, always, 20*time.Millisecond); code != 0 {
		t.Fatal("woke a paused endpoint", code)
	}
	if pushReachable("a") {
		t.Fatal("paused endpoint reachable")
	}
	PauseEndpoint("a", false)
	Retire("a", true)
	if code := RunRewake("a", 150*time.Millisecond, "", &bytes.Buffer{}, always, 20*time.Millisecond); code != 0 {
		t.Fatal("woke a retired identity", code)
	}
}

func readHooksFile(t *testing.T, path string) map[string][]map[string]any {
	t.Helper()
	m, err := readJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]map[string]any{}
	hooks, _ := m["hooks"].(map[string]any)
	for ev, groups := range hooks {
		for _, g := range groups.([]any) {
			for _, h := range g.(map[string]any)["hooks"].([]any) {
				out[ev] = append(out[ev], h.(map[string]any))
			}
		}
	}
	return out
}

func TestClaudeRewakeInstallWritesNamedHooksAndABackgroundWaiter(t *testing.T) {
	dir := seatFixture(t)
	if _, err := InstallWith(dir, "work", "claude", true, "claude-rewake", InstallOptions{WakeWindow: 30 * time.Second}); err == nil {
		t.Fatal("wake window shorter than its margin accepted")
	}
	if _, err := InstallWith(dir, "work", "claude", true, "claude-rewake", InstallOptions{WakeWindow: 2 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	hooks := readHooksFile(t, filepath.Join(dir, ".claude", "settings.local.json"))
	if len(hooks["PostToolUse"]) != 1 || len(hooks["Stop"]) != 2 || len(hooks["SessionStart"]) != 2 {
		t.Fatal(hooks)
	}
	for _, ev := range []string{"PostToolUse", "Stop", "SessionStart"} {
		sync := hooks[ev][0]
		cmd, _ := sync["command"].(string)
		if !strings.Contains(cmd, "--line 'work' --as 'claude'") || sync["asyncRewake"] != nil {
			t.Fatal(ev, sync)
		}
	}
	for _, ev := range []string{"Stop", "SessionStart"} {
		w := hooks[ev][1]
		cmd, _ := w["command"].(string)
		if w["asyncRewake"] != true || w["timeout"] != float64(7200) || !strings.Contains(cmd, "|| exec ") ||
			!strings.Contains(cmd, " hook rewake ") || !strings.Contains(cmd, "--for 1h59m0s") || !strings.Contains(cmd, "--as 'claude'") {
			t.Fatal(ev, w)
		}
		if binFromHookCmd(cmd) == "" {
			t.Fatal("doctor cannot read the binary back from", cmd)
		}
	}
	m, _ := readJSON(filepath.Join(dir, ".mcp.json"))
	args, _ := json.Marshal(m["mcpServers"].(map[string]any)["yip"].(map[string]any)["args"])
	if string(args) != `["serve","--as","claude","--line","work"]` {
		t.Fatal(string(args))
	}
	if ep, err := readEndpoint("claude"); err != nil || ep.Runtime != "claude-rewake" {
		t.Fatal(ep, err)
	}
	if _, in := hookInstalled(checkoutRoot(dir)); !strings.Contains(strings.Join(in, " "), "(3/3) + rewake (2/2)") {
		t.Fatal(in)
	}
	// Reinstalling as plain hooks removes the waiter; uninstall removes all.
	if _, err := InstallWith(dir, "work", "claude", true, "claude", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if hooks = readHooksFile(t, filepath.Join(dir, ".claude", "settings.local.json")); len(hooks["Stop"]) != 1 {
		t.Fatal("rewake waiter survived a runtime change", hooks)
	}
	if err := UninstallWith(dir, "", ""); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(dir, ".claude", "settings.local.json")) {
		b, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.local.json"))
		t.Fatal("hooks left behind", string(b))
	}
}

func TestEveryClaudeRuntimeNamesItsLine(t *testing.T) {
	for _, runtime := range []string{"claude", "claude-channels"} {
		t.Run(runtime, func(t *testing.T) {
			dir := seatFixture(t)
			if _, err := InstallWith(dir, "strategies", "claude", true, runtime, InstallOptions{}); err != nil {
				t.Fatal(err)
			}
			for ev, handlers := range readHooksFile(t, filepath.Join(dir, ".claude", "settings.local.json")) {
				for _, h := range handlers {
					if cmd, _ := h["command"].(string); !strings.Contains(cmd, "--line 'strategies' --as 'claude'") {
						t.Fatal(ev, cmd)
					}
				}
			}
			m, _ := readJSON(filepath.Join(dir, ".mcp.json"))
			args, _ := json.Marshal(m["mcpServers"].(map[string]any)["yip"].(map[string]any)["args"])
			if !strings.Contains(string(args), `"--line","strategies"`) || !strings.Contains(string(args), `"claude"`) {
				t.Fatal(string(args))
			}
		})
	}
}

func TestWaitHoldsForAnIdlePeerYipCanWake(t *testing.T) {
	seedBroadcastMembers(t)
	c, _ := NewCall("a", "b", "review")
	AppendTurn(c, "a", "please", false)
	s := &server{me: "a"}
	// b has never been active and nothing can reach it: return at once.
	out, err := s.call("wait", map[string]any{"call": c.ID, "timeout_s": float64(1)})
	if err != nil || !strings.HasPrefix(out, "not waiting") {
		t.Fatal(out, err)
	}
	// b is an idle Codex chat that is bound and live: worth waiting for.
	ensureCodexEndpoint("b")
	unlock, _ := codexSessionLock("b", threadA)
	defer unlock()
	bindCodexSession("b", threadA, "", time.Now())
	out, err = s.call("wait", map[string]any{"call": c.ID, "timeout_s": float64(1)})
	if err != nil || !strings.HasPrefix(out, "no reply within") {
		t.Fatal("wait gave up on a reachable peer:", out, err)
	}
	c2, _ := NewCall("a", "b", "second")
	reply, _ := s.call("call", map[string]any{"peer": "b", "subject": "third", "body": "x"})
	_ = c2
	if !strings.Contains(reply, "Yip is delivering this to it now") {
		t.Fatal(reply)
	}
}
