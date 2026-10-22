package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func channelFixture(t *testing.T) (string, func()) {
	t.Helper()
	seedBroadcastMembers(t)
	if e := RegisterChannel("a", false); e != nil {
		t.Fatal(e)
	}
	unlock, e := channelOwner("a")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(unlock)
	if e = beginChannel("a", "session-one"); e != nil {
		t.Fatal(e)
	}
	return "session-one", unlock
}
func channelSend(agent, session string, fail bool) (int, error) {
	return dispatchEndpoint(agent, "claude-channels", session, func(context.Context, string, string) error {
		if fail {
			return errors.New("write failed")
		}
		return nil
	})
}
func TestChannelProbeGatesNoticesAndRejectsWrongConnection(t *testing.T) {
	session, _ := channelFixture(t)
	if e := editEndpoint("a", func(ep *Endpoint) error {
		ep.Events = append(ep.Events, Delivery{ID: "notice", Source: "fixture", Text: "hello", Status: "pending"})
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ep, _ := readEndpoint("a")
	if e := acknowledgeChannel("a", session, ep.ChannelProbe); e == nil {
		t.Fatal("acknowledged unsent probe")
	}
	n, e := channelSend("a", session, false)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	ep, _ = readEndpoint("a")
	if ep.Events[0].Status != "sent" || ep.Events[1].Status != "pending" {
		t.Fatal(ep)
	}
	if e := AckDelivery("a", ep.ChannelProbe); e == nil {
		t.Fatal("ordinary ack certified a probe")
	}
	if e := acknowledgeChannel("a", "other-session", ep.ChannelProbe); e == nil {
		t.Fatal("wrong session certified channel")
	}
	if _, e := (&server{me: "a"}).call("channel_ack", map[string]any{"id": ep.ChannelProbe}); e == nil {
		t.Fatal("CLI certified channel")
	}
	if e := acknowledgeChannel("a", session, ep.ChannelProbe); e != nil {
		t.Fatal(e)
	}
	if !channelPreferred("a") {
		t.Fatal("verified owner not preferred")
	}
	n, e = channelSend("a", session, false)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	n, e = channelSend("a", session, false)
	if e != nil || n != 0 {
		t.Fatal("duplicate", n, e)
	}
	if e := AckDelivery("a", "notice"); e != nil {
		t.Fatal(e)
	}
}
func TestChannelRestartFencesOldProbeAndPreservesHistory(t *testing.T) {
	session, _ := channelFixture(t)
	channelSend("a", session, false)
	old, _ := readEndpoint("a")
	if e := beginChannel("a", "session-two"); e != nil {
		t.Fatal(e)
	}
	if e := acknowledgeChannel("a", session, old.ChannelProbe); e == nil {
		t.Fatal("old session ack")
	}
	if _, e := channelSend("a", session, false); e == nil {
		t.Fatal("old session send")
	}
	n, e := channelSend("a", "session-two", false)
	if n != 1 || e != nil {
		t.Fatal(n, e)
	}
	ep, _ := readEndpoint("a")
	if len(ep.Events) != 2 || len(ep.Events[0].Attempts) != 1 || ep.ChannelReady {
		t.Fatal(ep)
	}
	if e := acknowledgeChannel("a", "session-two", ep.ChannelProbe); e != nil {
		t.Fatal(e)
	}
	endChannel("a", session) // stale cleanup cannot clear new readiness
	ep, _ = readEndpoint("a")
	if !ep.ChannelReady {
		t.Fatal("stale cleanup")
	}
	endChannel("a", "session-two")
	if channelPreferred("a") {
		t.Fatal("disconnected still preferred")
	}
}
func TestChannelUnknownSendIsNeverAutomaticallyRetried(t *testing.T) {
	session, _ := channelFixture(t)
	n, e := channelSend("a", session, true)
	if n != 1 || e == nil {
		t.Fatal(n, e)
	}
	n, e = channelSend("a", session, false)
	if n != 0 || e != nil {
		t.Fatal(n, e)
	}
	ep, _ := readEndpoint("a")
	if ep.Events[0].Status != "unknown" {
		t.Fatal(ep)
	}
	if e = RetryDelivery("a", ep.ChannelProbe); e != nil {
		t.Fatal(e)
	}
	n, e = channelSend("a", session, false)
	if n != 1 || e != nil {
		t.Fatal(n, e)
	}
	ep, _ = readEndpoint("a")
	if len(ep.Events[0].Attempts) != 2 {
		t.Fatal(ep)
	}
}
func TestChannelPauseRetireAndOwnerFencing(t *testing.T) {
	session, _ := channelFixture(t)
	if release, e := channelOwner("a"); e == nil {
		release()
		t.Fatal("duplicate owner")
	}
	if e := PauseEndpoint("a", true); e != nil {
		t.Fatal(e)
	}
	if n, e := channelSend("a", session, false); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	PauseEndpoint("a", false)
	Retire("a", true)
	if n, e := channelSend("a", session, false); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	Retire("a", false)
	if n, e := channelSend("a", session, false); n != 1 || e != nil {
		t.Fatal(n, e)
	}
}
func TestChannelRegistrationCannotReplaceCodexOrCorruption(t *testing.T) {
	seedBroadcastMembers(t)
	if e := RegisterEndpoint("a", testThread, false); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(endpointPath("a"))
	if e := RegisterChannel("a", false); e == nil {
		t.Fatal("replaced Codex")
	}
	after, _ := os.ReadFile(endpointPath("a"))
	if !bytes.Equal(before, after) {
		t.Fatal("changed Codex")
	}
	os.WriteFile(endpointPath("b"), []byte("null"), 0600)
	if e := RegisterChannel("b", false); e == nil {
		t.Fatal("erased corrupt state")
	}
	if e := RegisterChannel("../x", false); e == nil {
		t.Fatal("unsafe identity")
	}
}
func TestChannelAndCodexDispatchCannotCross(t *testing.T) {
	session, _ := channelFixture(t)
	called := false
	if _, e := Dispatch("a", func(context.Context, string, string) error { called = true; return nil }); e == nil || called {
		t.Fatal(e, called)
	}
	if _, e := channelSend("a", session, false); e != nil {
		t.Fatal(e)
	}
}
func TestChannelMCPNegotiationAndOutputSerialization(t *testing.T) {
	var buf bytes.Buffer
	s := &server{enc: json.NewEncoder(&buf), channelMode: true}
	s.handle(&rpcReq{ID: json.RawMessage("1"), Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2026-07-28"}`)})
	var first map[string]any
	if e := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &first); e != nil {
		t.Fatal(e)
	}
	result := first["result"].(map[string]any)
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatal(result)
	}
	caps := result["capabilities"].(map[string]any)
	if _, ok := caps["experimental"].(map[string]any)["claude/channel"]; !ok {
		t.Fatal(caps)
	}
	buf.Reset()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				s.writeFrame(map[string]any{"jsonrpc": "2.0", "method": "notifications/claude/channel", "params": map[string]any{"content": strings.Repeat("x", 3000)}})
			}
		}()
	}
	wg.Wait()
	dec := json.NewDecoder(&buf)
	count := 0
	for {
		var frame map[string]any
		e := dec.Decode(&frame)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		count++
	}
	if count != 600 {
		t.Fatal(count)
	}
}
func TestChannelInstallMergesConfig(t *testing.T) {
	seedBroadcastMembers(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"other":{"command":"untouched"}}}`), 0600)
	if e := configureChannel(root, "/test/yip", "line", "a"); e != nil {
		t.Fatal(e)
	}
	m, e := readJSON(filepath.Join(root, ".mcp.json"))
	if e != nil {
		t.Fatal(e)
	}
	servers := m["mcpServers"].(map[string]any)
	if servers["other"].(map[string]any)["command"] != "untouched" {
		t.Fatal(m)
	}
	a := servers["yip"].(map[string]any)["args"].([]any)
	if len(a) != 6 || a[1] != "--channels" || a[3] != "a" || a[5] != "line" {
		t.Fatal(a)
	}
}
func TestHelpIsReadOnlyAndContainsEveryToolSchema(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-exist")
	t.Setenv("YIP_ROOT", root)
	for _, flag := range []string{"--help", "--help-agents"} {
		var b bytes.Buffer
		if !printHelp([]string{flag}, &b) {
			t.Fatal(flag)
		}
		for _, word := range []string{"channel_ack", "broadcast_reply", "resource", "tmux"} {
			if !strings.Contains(b.String(), word) {
				t.Fatal(flag, word)
			}
		}
		if flag == "--help-agents" {
			for _, tool := range tools() {
				if !strings.Contains(b.String(), `"name": "`+tool.Name+`"`) {
					t.Fatal(tool.Name)
				}
			}
		}
	}
	if _, e := os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("help touched state", e)
	}
}
func TestChannelPreferredDoesNotConsumeHookCursors(t *testing.T) {
	session, _ := channelFixture(t)
	c, e := NewCall("b", "a", "pending question")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = AppendTurn(c, "b", "please answer", false); e != nil {
		t.Fatal(e)
	}
	channelSend("a", session, false)
	ep, _ := readEndpoint("a")
	acknowledgeChannel("a", session, ep.ChannelProbe)
	if v := hookPostToolUse("a", hookInput{}); v != nil {
		t.Fatal(v)
	}
	if st := LoadAgentState(c, "a"); st.NotifiedAt != 0 {
		t.Fatal("channel hook consumed cursor", st)
	}
	endChannel("a", session)
	if channelPreferred("a") {
		t.Fatal("fallback suppressed after exit")
	}
	if v := hookPostToolUse("a", hookInput{}); v == nil {
		t.Fatal("hook fallback lost pending call")
	}
}
