package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	agyConvA = "11111111-1111-4111-8111-111111111111"
	agyConvB = "22222222-2222-4222-8222-222222222222"
)

func runAgyHook(t *testing.T, event, as, stdinJSON string) map[string]any {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	_, _ = inW.WriteString(stdinJSON)
	inW.Close()
	RunHookRuntime(event, as, "agy")
	os.Stdin, os.Stdout = oldIn, oldOut
	outW.Close()
	b, _ := io.ReadAll(outR)
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(b), &m); err != nil {
		t.Fatalf("agy hook %s did not emit valid JSON: %q (%v)", event, string(b), err)
	}
	return m
}

func TestAgyInstallPluginValidatesAndUninstalls(t *testing.T) {
	tmpLine(t)
	dir := t.TempDir()
	// Keep an unrelated file under .agents/ to ensure uninstall leaves it untouched.
	unrelated := filepath.Join(dir, ".agents", "notes.txt")
	if err := os.MkdirAll(filepath.Dir(unrelated), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := InstallWith(dir, "v2", "gemini", false, "agy", InstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Agent != "gemini" || res.Seat != "" {
		t.Fatalf("unexpected install result: %+v", res)
	}
	pluginDir := agyPluginDir(checkoutRoot(dir))
	for _, rel := range []string{"plugin.json", "mcp_config.json", "hooks.json", filepath.Join("rules", "AGENTS.md")} {
		if _, err := os.Stat(filepath.Join(pluginDir, rel)); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
	if agyPluginAgent(checkoutRoot(dir)) != "gemini" {
		t.Fatalf("agyPluginAgent = %q, want gemini", agyPluginAgent(checkoutRoot(dir)))
	}
	ep, err := readEndpoint("gemini")
	if err != nil || ep.Runtime != "agy" || ep.Thread != "" {
		t.Fatalf("unexpected agy endpoint: %+v err=%v", ep, err)
	}

	// Validate with the real `agy plugin validate` when agy is installed.
	if _, err := exec.LookPath("agy"); err == nil {
		out, verr := exec.Command("agy", "plugin", "validate", pluginDir).CombinedOutput()
		if verr != nil {
			t.Fatalf("real agy plugin validate failed: %v\n%s", verr, string(out))
		}
	}

	// Second agy identity in the same checkout must refuse rather than clobbering.
	if _, err := InstallWith(dir, "v2", "gemini2", false, "agy", InstallOptions{Seat: true}); err == nil {
		t.Fatal("expected refusal when installing a second agy identity into the same plugin dir")
	}

	// Reinstall same identity is idempotent.
	res2, err := InstallWith(dir, "v2", "gemini", false, "agy", InstallOptions{})
	if err != nil || !res2.Reinstall {
		t.Fatalf("idempotent reinstall failed: %+v err=%v", res2, err)
	}

	// Uninstall removes .agents/plugins/yip/ and preserves unrelated .agents/ files.
	if err := UninstallWith(dir, "gemini", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		t.Fatalf("plugin dir still exists after uninstall: %v", err)
	}
	if b, err := os.ReadFile(unrelated); err != nil || string(b) != "keep me\n" {
		t.Fatalf("unrelated file damaged: %q err=%v", string(b), err)
	}
}

func TestAgySeatBesideClaudeAndInstallOrder(t *testing.T) {
	// Order 1: Claude owns the checkout, then Antigravity joins as a seat automatically.
	t.Run("claude-then-agy", func(t *testing.T) {
		tmpLine(t)
		dir := t.TempDir()
		if _, err := InstallWith(dir, "v2", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
			t.Fatal(err)
		}
		res, err := InstallWith(dir, "v2", "gemini", false, "agy", InstallOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Seat == "" || !strings.Contains(res.Seat, "agy seat") {
			t.Fatalf("expected agy seat, got %+v", res)
		}
		if LoadMembers().AgentAt(checkoutRoot(dir)) != "claude" {
			t.Fatal("claude lost path membership")
		}
		if _, ok := LoadSeats().Seats["gemini"]; !ok {
			t.Fatal("gemini missing from seats")
		}

		// Inside an agy shell (ANTIGRAVITY_CONVERSATION_ID set), unregistered
		// session must NOT silently impersonate Claude's path member.
		t.Setenv("YIP_AGENT", "")
		t.Setenv("CODEX_THREAD_ID", "")
		t.Setenv("ANTIGRAVITY_CONVERSATION_ID", agyConvA)
		fakeProcs(t, []procID{{PID: 9999, Start: "1"}})
		if me, err := WhoAmI("", dir); err == nil {
			t.Fatalf("unbound agy shell impersonated %q", me)
		}

		// Once registered with launch="gemini", agy shell resolves to "gemini".
		fakeProcs(t, []procID{{PID: 9000, Start: "1"}, sessionA})
		if err := registerSession(sessionA, "gemini"); err != nil {
			t.Fatal(err)
		}
		// Keep sessionA alive in procAlive for identityFor.
		procAlive = func(p procID) bool { return p == sessionA }
		if me, err := WhoAmI("", dir); err != nil || me != "gemini" {
			t.Fatalf("registered agy seat shell resolved to %q err=%v, want gemini", me, err)
		}
	})

	// Order 2: Antigravity installs first, then Claude installs and moves Antigravity to a seat.
	t.Run("agy-then-claude", func(t *testing.T) {
		tmpLine(t)
		dir := t.TempDir()
		if _, err := InstallWith(dir, "v2", "gemini", false, "agy", InstallOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := InstallWith(dir, "v2", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
			t.Fatal(err)
		}
		if LoadMembers().AgentAt(checkoutRoot(dir)) != "claude" {
			t.Fatal("claude did not become path member")
		}
		seat, ok := LoadSeats().Seats["gemini"]
		if !ok || seat.Runtime != "agy" {
			t.Fatalf("gemini was not moved to an agy seat: %+v ok=%v", seat, ok)
		}
	})
}

func TestAgyHookContracts(t *testing.T) {
	tmpLine(t)
	dir := t.TempDir()
	if _, err := InstallWith(dir, "v2", "gemini", false, "agy", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	fakeProcs(t, []procID{sessionA}, sessionA)

	// SessionStart injects systemMessage with listen nudge.
	out := runAgyHook(t, "sessionstart", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`","hookEventName":"SessionStart"}`)
	steps, _ := out["injectSteps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("expected 1 injectStep on SessionStart, got %v", out)
	}
	sm := steps[0].(map[string]any)["systemMessage"].(map[string]any)["systemMessage"].(string)
	if !strings.Contains(sm, "delivery listen --runtime agy") {
		t.Fatalf("SessionStart nudge missing delivery listen command: %s", sm)
	}

	// Open a call from peer to gemini.
	c, err := NewCall("claude", "gemini", "compiler question")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendTurn(c, "claude", "check the lowering pass", false); err != nil {
		t.Fatal(err)
	}

	// PostToolUse heartbeats with toolCall.name and ALWAYS emits `{}`.
	post := runAgyHook(t, "posttooluse", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`","toolCall":{"id":"t1","name":"read_file"}}`)
	if len(post) != 0 {
		t.Fatalf("PostToolUse must emit {}, got %v", post)
	}
	if p, ok := LoadPresence("gemini"); !ok || p.LastTool != "read_file" {
		t.Fatalf("PostToolUse did not beat with toolCall.name: %+v ok=%v", p, ok)
	}

	// PreInvocation delivers mid-turn notices via injectSteps when listener is NOT live.
	pre := runAgyHook(t, "preinvocation", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`"}`)
	steps, _ = pre["injectSteps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("PreInvocation did not inject notice: %v", pre)
	}
	sm = steps[0].(map[string]any)["systemMessage"].(map[string]any)["systemMessage"].(string)
	if !strings.Contains(sm, c.ID) {
		t.Fatalf("PreInvocation notice missing call ID %s: %s", c.ID, sm)
	}

	// Second PreInvocation with nothing new emits `{}`.
	pre2 := runAgyHook(t, "preinvocation", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`"}`)
	if len(pre2) != 0 {
		t.Fatalf("expected quiet second PreInvocation, got %v", pre2)
	}

	// Stop on USER_CANCELED or ERROR does NOT block.
	for _, reason := range []string{"USER_CANCELED", "ERROR", "MAX_INVOCATIONS"} {
		st := runAgyHook(t, "stop", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`","terminationReason":"`+reason+`"}`)
		if len(st) != 0 {
			t.Fatalf("Stop blocked on %s: %v", reason, st)
		}
	}

	// Stop on NO_TOOL_CALL returns {"decision":"continue","reason":...} once, then guards against looping.
	st := runAgyHook(t, "stop", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`","terminationReason":"NO_TOOL_CALL"}`)
	if st["decision"] != "continue" || !strings.Contains(st["reason"].(string), c.ID) {
		t.Fatalf("Stop did not continue with call ID: %v", st)
	}
	st2 := runAgyHook(t, "stop", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`","terminationReason":"NO_TOOL_CALL"}`)
	if len(st2) != 0 {
		t.Fatalf("Stop looped on unchanged obligation: %v", st2)
	}

	// While a live agy listener holds its lock, PreInvocation suppresses routine notices without advancing NotifiedAt.
	unlock, err := agySessionLock("gemini", agyConvA)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := bindAgySession("gemini", agyConvA, dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	c2, _ := NewCall("claude", "gemini", "second call")
	_, _ = AppendTurn(c2, "claude", "another turn", false)
	preLive := runAgyHook(t, "preinvocation", "gemini", `{"conversationId":"`+agyConvA+`","cwd":"`+dir+`"}`)
	if steps, ok := preLive["injectSteps"].([]any); ok && len(steps) > 0 {
		msg := steps[0].(map[string]any)["systemMessage"].(map[string]any)["systemMessage"].(string)
		if strings.Contains(msg, c2.ID) {
			t.Fatalf("PreInvocation repeated notice while live agy listener was active: %s", msg)
		}
	}
	if LoadAgentState(c2, "gemini").NotifiedAt != 0 {
		t.Fatal("PreInvocation advanced NotifiedAt while live agy push was active")
	}
}

func TestAgyLiveDeliveryAndDynamicWorktreeBind(t *testing.T) {
	tmpLine(t)
	launchDir := t.TempDir()
	wtA := filepath.Join(t.TempDir(), "wt-alpha")
	wtB := filepath.Join(t.TempDir(), "wt-beta")
	for _, d := range []string{wtA, wtB} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := InstallWith(launchDir, "v2", "gemini", false, "agy", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := SaveMembers(Members{Line: activeLine, Members: map[string]string{
		checkoutRoot(launchDir): "gemini",
		"/fixture/claude":       "claude",
	}}); err != nil {
		t.Fatal(err)
	}

	// Two independent agy sessions started from the same shared launch folder.
	// Use a thread-safe ancestor hook driven by goroutine-local lookup? Since
	// processAncestors is package-global, test sequential bind transitions and
	// concurrent delivery isolation deterministically.
	// Simulate real agy 1.5.14 process layout: MCP server runs under a helper
	// PID (mcpHelper) while hooks and `delivery listen` run under agyParent.
	// Bindings carry the shared conversation UUID so all three stay in sync.
	mcpHelper := procID{PID: 4300, Start: "19"}
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB, mcpHelper)
	var aliveA atomic.Bool
	aliveA.Store(true)
	procAlive = func(p procID) bool {
		if p == sessionA {
			return aliveA.Load()
		}
		return p == sessionB || p == mcpHelper
	}

	// Subagent MCP call must be refused from calling bind.
	var mcpOut bytes.Buffer
	subReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bind","arguments":{"worktree":"` + wtA + `"},"_meta":{"antigravity.google/conversation_id":"` + agyConvB + `","antigravity.google/root_conversation_id":"` + agyConvA + `"}}}` + "\n"
	srv := &server{me: "gemini", launch: "gemini", session: mcpHelper, agyMode: true, enc: json.NewEncoder(&mcpOut)}
	var rpc rpcReq
	if err := json.Unmarshal([]byte(subReq), &rpc); err != nil {
		t.Fatal(err)
	}
	srv.handle(&rpc)
	if !strings.Contains(mcpOut.String(), "not a subagent") {
		t.Fatalf("subagent was not refused bind: %s", mcpOut.String())
	}

	// Main conversation of sessionA binds wt-alpha via MCP server (different parent PID from listener!).
	mcpOut.Reset()
	bindReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bind","arguments":{"worktree":"` + wtA + `"},"_meta":{"antigravity.google/conversation_id":"` + agyConvA + `","antigravity.google/root_conversation_id":"` + agyConvA + `"}}}` + "\n"
	if err := json.Unmarshal([]byte(bindReq), &rpc); err != nil {
		t.Fatal(err)
	}
	srv.handle(&rpc)
	if srv.me != "wt-alpha" || !strings.Contains(mcpOut.String(), "You are now wt-alpha") {
		t.Fatalf("sessionA bind failed: out=%q me=%q", mcpOut.String(), srv.me)
	}
	// sessionB binds wt-beta with its own conversation UUID (even on the same helper PID!).
	resB, err := BindWithConv("gemini", mcpHelper, agyConvB, wtB, "")
	if err != nil || resB.Name != "wt-beta" {
		t.Fatalf("sessionB bind failed: %+v err=%v", resB, err)
	}
	// Cross-conversation fencing: convB cannot act as wt-alpha.
	if _, err := identityForConv("wt-alpha", true, agyConvB); err == nil {
		t.Fatal("convB was allowed to act as convA's bound worktree wt-alpha")
	}

	// Start RunAgyListen for sessionA (bound to wt-alpha).
	var mu sync.Mutex
	var delivered []struct{ conv, text string }
	fakeSend := func(_ context.Context, conv, text string) error {
		mu.Lock()
		delivered = append(delivered, struct{ conv, text string }{conv, text})
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var listenOut bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- RunAgyListen(ctx, "gemini", agyConvA, wtA, fakeSend, 15*time.Millisecond, &listenOut)
	}()

	waitFor(t, "wt-alpha listener live", func() bool { return pushReachable("wt-alpha") })
	if pushReachable("gemini") {
		t.Fatal("bound sessionA listener should not claim launch identity gemini")
	}

	// Call wt-alpha from claude -> delivered to agyConvA and marked accepted.
	cA, err := NewCall("claude", "wt-alpha", "lower ir")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendTurn(cA, "claude", "please check phi nodes", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "notice delivered to convA", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, d := range delivered {
			if d.conv == agyConvA && strings.Contains(d.text, cA.ID) {
				return true
			}
		}
		return false
	})

	// Call wt-beta -> must NOT be delivered to sessionA's convA.
	cB, _ := NewCall("claude", "wt-beta", "for beta only")
	_, _ = AppendTurn(cB, "claude", "beta work", false)
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	for _, d := range delivered {
		if strings.Contains(d.text, cB.ID) {
			mu.Unlock()
			t.Fatalf("sessionA received wt-beta's notice: %+v", d)
		}
	}
	mu.Unlock()

	// Dynamic unbind back to launch folder: listener automatically switches from wt-alpha to gemini.
	if _, err := BindWithConv("gemini", mcpHelper, agyConvA, launchDir, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "listener followed unbind to gemini", func() bool {
		return pushReachable("gemini") && !pushReachable("wt-alpha")
	})

	// Session exit stops listener cleanly without consuming pending notices.
	aliveA.Store(false)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener returned error on session exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit when its parent session ended")
	}
	if pushReachable("gemini") {
		t.Fatal("lock not released after listener exit")
	}
}

func TestAgySenderRejectsJSONErrorOnZeroExit(t *testing.T) {
	tmp := t.TempDir()
	fakeBin := filepath.Join(tmp, "agentapi")
	script := "#!/bin/sh\necho '{\"response\":{},\"error\":\"rpc error: code = Unavailable\"}'\nexit 0\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldFind := findAgentAPI
	t.Cleanup(func() { findAgentAPI = oldFind })
	findAgentAPI = func() (string, error) { return fakeBin, nil }

	err := agySender(context.Background(), agyConvA, "hello")
	if err == nil || !strings.Contains(err.Error(), "Unavailable") {
		t.Fatalf("expected error from JSON error field on exit 0, got %v", err)
	}

	okScript := "#!/bin/sh\necho '{\"response\":{\"sendMessage\":{\"recipientId\":\"'$3'\"}}}'\nexit 0\n"
	if err := os.WriteFile(fakeBin, []byte(okScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := agySender(context.Background(), agyConvA, "hello"); err != nil {
		t.Fatalf("expected success on valid response, got %v", err)
	}
}

func TestAgyDoctorAndTmuxTarget(t *testing.T) {
	tmpLine(t)
	dir := t.TempDir()
	if _, err := InstallWith(dir, "v2", "gemini", false, "agy", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	// Replace wired binary path with a small executable matching serverVersion.
	fakeYip := filepath.Join(t.TempDir(), "yip")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '" + serverVersion + "'; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(fakeYip, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := agyFiles(checkoutRoot(dir), fakeYip, "v2", "gemini", false); err != nil {
		t.Fatal(err)
	}
	oldVal, oldFind := agyValidatePlugin, findAgentAPI
	t.Cleanup(func() { agyValidatePlugin, findAgentAPI = oldVal, oldFind })
	agyValidatePlugin = func(string) ([]byte, error) { return []byte(`{"errors":[]}`), nil }
	findAgentAPI = func() (string, error) { return "/fake/agentapi", nil }

	if err := AgyDoctor(dir); err != nil {
		t.Fatalf("AgyDoctor failed on valid install: %v", err)
	}

	if !validTmuxTarget(&TmuxTarget{Socket: "/tmp/s", Pane: "%1", PID: 123, Start: "Mon", Runtime: "agy"}) {
		t.Fatal("validTmuxTarget rejected agy")
	}
}
