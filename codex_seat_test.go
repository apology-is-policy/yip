package main

// Seats and Codex live delivery. The load-bearing tests are the co-location
// one (installing a second agent in a checkout must never re-point the first
// agent's path-resolved identity) and the newest-wins binding (a superseded
// session must go passive, never double-deliver, and never steal back).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const threadA = "01a1b037-0000-7000-8000-00000000000a"
const threadB = "01a1b037-0000-7000-8000-00000000000b"

// seatFixture isolates every path an install touches and restores the
// process-global active line afterwards.
func seatFixture(t *testing.T) string {
	t.Helper()
	tmpLine(t)
	t.Setenv("YIP_HOME", t.TempDir())
	t.Setenv("CODEX_HOME", t.TempDir())
	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("YIP_AGENT", "")
	prev, prevList := activeLine, codexMCPList
	t.Cleanup(func() { activeLine, codexMCPList = prev, prevList })
	// Never ask a real Codex from tests; individual tests stub an answer.
	codexMCPList = func(string, string) ([]byte, error) { return nil, errors.New("no codex in tests") }
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func codexBlockOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _, err := codexManagedBlock(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func TestCoLocatedCodexBecomesSeatAndNeverEvictsTheMember(t *testing.T) {
	dir := seatFixture(t)
	if _, err := InstallWith(dir, "t", "main", true, "claude", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := InstallWith(dir, "t", "reviewer", false, "codex", InstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Seat == "" || !strings.Contains(strings.Join(res.Notes, " "), "main") {
		t.Fatalf("co-located Codex install not reported as a seat: %+v", res)
	}
	root := checkoutRoot(dir)
	if a := LoadMembers().AgentAt(root); a != "main" {
		t.Fatalf("path member re-pointed to %q", a)
	}
	// What Claude's hooks and `serve` resolve to: still main.
	if me, err := WhoAmI("", dir); err != nil || me != "main" {
		t.Fatal(me, err)
	}
	if s := LoadSeats().Seats["reviewer"]; s.Workdir != root || s.Runtime != "codex" || s.Profile != "" {
		t.Fatal(s)
	}
	if names := strings.Join(LineNames(), ","); names != "main,reviewer" {
		t.Fatal(names)
	}
	block := codexBlockOf(t, filepath.Join(dir, ".codex", "config.toml"))
	if codexBlockAgent(block) != "reviewer" || !strings.Contains(block, `"serve", "--codex"`) || !strings.Contains(block, `env_vars = ["CODEX_HOME"]`) {
		t.Fatal(block)
	}
	ep, err := readEndpoint("reviewer")
	if err != nil || ep.Runtime != "codex" || ep.Thread != "" {
		t.Fatal("install did not create an unbound Codex endpoint", ep, err)
	}
	// Reinstalling the seat is idempotent and still leaves main alone.
	if res, err = InstallWith(dir, "t", "reviewer", false, "codex", InstallOptions{}); err != nil || !res.Reinstall {
		t.Fatal(res, err)
	}
	// A second Claude identity cannot share a path-resolved checkout.
	if _, err := InstallWith(dir, "t", "other", true, "claude", InstallOptions{}); err == nil || !strings.Contains(err.Error(), "own worktree") {
		t.Fatal("second Claude identity accepted", err)
	}
	// Nor can a second Codex identity take over the single .codex/ layer.
	if _, err := InstallWith(dir, "t", "reviewer2", false, "codex", InstallOptions{}); err == nil || !strings.Contains(err.Error(), "--profile") {
		t.Fatal("second Codex identity replaced the seat's config", err)
	}
	if _, ok := LoadSeats().Seats["reviewer2"]; ok {
		t.Fatal("failed install recorded a seat")
	}
	// Broadcast audiences include the seat.
	if !contains(BroadcastRecipients(), "reviewer") {
		t.Fatal(BroadcastRecipients())
	}
}

func TestSeatConversionAndNarrowUninstall(t *testing.T) {
	dir := seatFixture(t)
	root := checkoutRoot(dir)
	// Codex first, as the path member (the pre-seat layout).
	if _, err := InstallWith(dir, "t", "reviewer", false, "codex", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	// Explicit conversion frees the path.
	res, err := InstallWith(dir, "t", "reviewer", false, "codex", InstallOptions{Seat: true})
	if err != nil || !strings.Contains(strings.Join(res.Notes, " "), "now a seat") {
		t.Fatal(res, err)
	}
	if LoadMembers().AgentAt(root) != "" {
		t.Fatal("conversion kept the path membership")
	}
	if _, err := InstallWith(dir, "t", "main", true, "claude", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := UninstallWith(dir, "nobody", ""); err == nil {
		t.Fatal("uninstalled an identity that is not here")
	}
	if err := UninstallWith(dir, "reviewer", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadSeats().Seats["reviewer"]; ok {
		t.Fatal("seat kept")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".codex", "config.toml")); strings.Contains(string(b), codexBegin) {
		t.Fatal("seat config kept")
	}
	if LoadMembers().AgentAt(root) != "main" || !fileExists(filepath.Join(dir, ".mcp.json")) {
		t.Fatal("narrow uninstall removed the member")
	}
	if err := UninstallWith(dir, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(LineNames()) != 0 {
		t.Fatal(LineNames())
	}
}

// Codex installed first, then Claude: the order must not matter.
func TestClaudeInstallMovesACodexOwnerToASeat(t *testing.T) {
	dir := seatFixture(t)
	root := checkoutRoot(dir)
	if _, err := InstallWith(dir, "t", "codex", false, "codex", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if LoadMembers().AgentAt(root) != "codex" {
		t.Fatal("fixture: codex should own the unowned folder")
	}
	res, err := InstallWith(dir, "t", "claude", true, "claude-rewake", InstallOptions{})
	if err != nil {
		t.Fatal("Claude refused a folder owned by a Codex agent:", err)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "now a Codex seat") {
		t.Fatal(res.Notes)
	}
	if LoadMembers().AgentAt(root) != "claude" {
		t.Fatal("Claude did not become the member")
	}
	if s := LoadSeats().Seats["codex"]; s.Workdir != root || s.Runtime != "codex" {
		t.Fatal("codex not seated beside claude", s)
	}
	// Its Codex config was untouched and still names it.
	if codexBlockAgent(codexBlockOf(t, filepath.Join(dir, ".codex", "config.toml"))) != "codex" {
		t.Fatal("codex config changed")
	}
	// Re-running the Codex install now just refreshes the seat.
	if res, err := InstallWith(dir, "t", "codex", false, "codex", InstallOptions{}); err != nil || !res.Reinstall {
		t.Fatal(res, err)
	}
	// A Claude owner is never moved: a second Claude identity is refused.
	if _, err := InstallWith(dir, "t", "other", true, "claude", InstallOptions{}); err == nil || !strings.Contains(err.Error(), "own worktree") {
		t.Fatal("second Claude identity accepted", err)
	}
}

// A registration left in another folder is removed by name from anywhere,
// including when that folder is gone; then the intended install succeeds.
func TestUninstallByNameRemovesALeftoverElsewhere(t *testing.T) {
	launch := seatFixture(t)
	old, _ := filepath.EvalSymlinks(t.TempDir())
	if _, err := InstallWith(old, "t", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := InstallWith(launch, "t", "claude", true, "claude-rewake", InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "yip uninstall --as claude --line t") {
		t.Fatal("error does not say how to recover:", err)
	}
	where, err := UninstallFrom(launch, "claude", "")
	if err != nil || where != checkoutRoot(old) {
		t.Fatal(where, err)
	}
	if fileExists(filepath.Join(old, ".mcp.json")) {
		t.Fatal("left the old folder's config")
	}
	if _, err := InstallWith(launch, "t", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	// A registration whose folder no longer exists can be removed too.
	gone := filepath.Join(t.TempDir(), "deleted")
	os.MkdirAll(gone, 0o755)
	if _, err := InstallWith(gone, "t", "ghost", true, "claude", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(gone)
	if _, err := UninstallFrom(launch, "ghost", ""); err != nil {
		t.Fatal(err)
	}
	if fileExists(gone) || contains(LineNames(), "ghost") {
		t.Fatal("ghost kept, or its folder recreated")
	}
	if !contains(LineNames(), "claude") {
		t.Fatal("removing ghost touched claude")
	}
	if _, err := UninstallFrom(launch, "nobody", ""); err == nil {
		t.Fatal("removed an identity that is not on the line")
	}
}

// One folder reached under two spellings is one checkout.
func TestAnotherSpellingOfTheSameFolderIsTheSameCheckout(t *testing.T) {
	dir := seatFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skip("cannot create a symlink here:", err)
	}
	// Record the folder under a spelling EvalSymlinks will not produce, as a
	// case variant on a case-insensitive disk would be.
	if _, err := InstallWith(dir, "t", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	m := LoadMembers()
	m.Members = map[string]string{alias: "claude"}
	SaveMembers(m)
	if _, err := InstallWith(dir, "t", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
		t.Fatal("same folder under another spelling treated as a second checkout:", err)
	}
	if got := LoadMembers().Members; len(got) != 1 || got[alias] != "claude" {
		t.Fatal("registration duplicated instead of reused", got)
	}
	if me, err := WhoAmI("", dir); err != nil || me != "claude" {
		t.Fatal(me, err)
	}
	if err := UninstallWith(dir, "", ""); err != nil || len(LoadMembers().Members) != 0 {
		t.Fatal("uninstall missed the other spelling", err, LoadMembers().Members)
	}
}

// Uninstall must leave the line the folder joined, not the one derived from it.
func TestLinesHostingFindsTheJoinedLine(t *testing.T) {
	dir := seatFixture(t)
	t.Setenv("YIP_ROOT", "") // resolve lines under YIP_HOME, as a real install does
	root := checkoutRoot(dir)
	if _, err := InstallWith(dir, "strategies", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWith(dir, "strategies", "codex", false, "codex", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(linesHosting(root), ","); got != "strategies" {
		t.Fatal("lines hosting the folder:", got)
	}
	derived, _ := resolveLine(root)
	if derived == "strategies" {
		t.Fatal("fixture: the derived line should differ from --line")
	}
	activeLine = "strategies"
	if err := UninstallWith(dir, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(linesHosting(root)) != 0 {
		t.Fatal("membership left behind", linesHosting(root))
	}
}

func TestProfileSeatLivesOnlyInItsProfileLayer(t *testing.T) {
	dir := seatFixture(t)
	if _, err := InstallWith(dir, "t", "", false, "codex", InstallOptions{Profile: "yip-reviewer"}); err == nil {
		t.Fatal("profile seat without an explicit name")
	}
	if _, err := InstallWith(dir, "t", "main", false, "claude", InstallOptions{Profile: "x"}); err == nil {
		t.Fatal("Claude profile seat accepted")
	}
	res, err := InstallWith(dir, "t", "reviewer", false, "codex", InstallOptions{Profile: "yip-reviewer"})
	if err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(dir, ".codex")) {
		t.Fatal("profile seat wrote into the checkout")
	}
	if LoadMembers().AgentAt(checkoutRoot(dir)) != "" {
		t.Fatal("profile seat became the path member")
	}
	if s := LoadSeats().Seats["reviewer"]; s.Profile != "yip-reviewer" || s.Workdir != "" {
		t.Fatal(s)
	}
	path := codexProfilePath("yip-reviewer")
	if res.McpPath != path {
		t.Fatal(res.McpPath)
	}
	block := codexBlockOf(t, path)
	for _, ev := range codexHookEvents {
		if strings.Count(block, "[[hooks."+ev+".hooks]]") != 1 {
			t.Fatal(ev, block)
		}
	}
	if !strings.Contains(block, "--as 'reviewer'") || !strings.Contains(block, `"--codex"`) {
		t.Fatal(block)
	}
	// One profile serves one identity.
	if _, err := InstallWith(dir, "t", "second", false, "codex", InstallOptions{Profile: "yip-reviewer"}); err == nil {
		t.Fatal("second identity took over the profile")
	}
	// A profile that already has its own hooks is not merged into.
	os.WriteFile(codexProfilePath("busy"), []byte("[[hooks.Stop]]\n"), 0600)
	if _, err := InstallWith(dir, "t", "third", false, "codex", InstallOptions{Profile: "busy"}); err == nil {
		t.Fatal("merged into a profile with unmanaged hooks")
	}
	// Names stay unique across members and seats.
	if _, err := InstallWith(dir, "t", "reviewer", true, "claude", InstallOptions{}); err == nil {
		t.Fatal("member took a seat's name")
	}
	if err := UninstallWith("", "", "yip-reviewer"); err != nil {
		t.Fatal(err)
	}
	if fileExists(path) {
		t.Fatal("Yip-only profile file left behind")
	}
	if _, ok := LoadSeats().Seats["reviewer"]; ok {
		t.Fatal("seat kept")
	}
}

func TestCodexBindingNewestSessionWinsAndSupersededIsPassive(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("a", "b", "review please")
	AppendTurn(c, "a", "diff attached", false)
	// Unbound: notices wait as pending; an external dispatcher sends nothing.
	if n, err := Dispatch("b", func(context.Context, string, string) error { t.Fatal("sent while unbound"); return nil }); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	var sentTo []string
	send := func(_ context.Context, thread, _ string) error { sentTo = append(sentTo, thread); return nil }

	startA := time.Now()
	unlockA, err := codexSessionLock("b", threadA)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockA()
	if _, err := codexSessionLock("b", threadA); err == nil {
		t.Fatal("two servers for one thread")
	}
	if res, err := bindCodexSession("b", threadA, "/work/a", startA); err != nil || !res.Bound || res.Previous != "" {
		t.Fatal(res, err)
	}
	// A new call is two events (call + its first turn), sent as one batch.
	if n, err := dispatchEndpoint("b", "codex", threadA, send); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if !strings.Contains(EndpointStatus("b"), "session live") {
		t.Fatal(EndpointStatus("b"))
	}

	// A newer session binds and takes over; the earlier accepted notice is
	// reported, not resent.
	time.Sleep(2 * time.Millisecond)
	unlockB, err := codexSessionLock("b", threadB)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bindCodexSession("b", threadB, "/work/b", time.Now())
	if err != nil || !res.Bound || res.Previous != threadA || res.Unread != 2 {
		t.Fatal(res, err)
	}
	if _, err := dispatchEndpoint("b", "codex", threadA, send); err != errNotOwner {
		t.Fatal("superseded session still dispatches", err)
	}
	// The older live session must not steal it back while B lives.
	if res, err := bindCodexSession("b", threadA, "/work/a", startA); err != nil || res.Bound {
		t.Fatal("superseded session rebound over a newer live one", res, err)
	}
	AppendNote(c, "a", AuthorAgent, "one more thing")
	if n, err := dispatchEndpoint("b", "codex", threadB, send); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	// B goes away: A may take over again, and only new notices go to A.
	unlockB()
	if res, err := bindCodexSession("b", threadA, "/work/a", startA); err != nil || !res.Bound || res.Previous != threadB {
		t.Fatal(res, err)
	}
	if n, err := dispatchEndpoint("b", "codex", threadA, send); n != 0 || err != nil {
		t.Fatal("rebinding resent earlier notices", n, err)
	}
	if strings.Join(sentTo, ",") != threadA+","+threadB {
		t.Fatal(sentTo)
	}
	ep, _ := readEndpoint("b")
	if ep.Cwd != "/work/a" || ep.Binding != "session" {
		t.Fatal(ep)
	}
	unlockA()
	if !strings.Contains(EndpointStatus("b"), "session closed") || !strings.Contains(EndpointStatus("b"), "dispatcher stopped") {
		t.Fatal(EndpointStatus("b"))
	}
}

func TestCodexBindingRefusesOtherRuntimesAndCorruption(t *testing.T) {
	seedBroadcastMembers(t)
	if err := RegisterChannel("a", false); err != nil {
		t.Fatal(err)
	}
	if _, err := bindCodexSession("a", threadA, "", time.Now()); err == nil {
		t.Fatal("Codex bound over a Channels endpoint")
	}
	// Install still succeeds, keeps the Channels record, and says why push is off.
	if warning, err := ensureCodexEndpoint("a"); err != nil || !strings.Contains(warning, "distinct --as") {
		t.Fatal("Codex install over a Channels endpoint", warning, err)
	}
	if ep, _ := readEndpoint("a"); ep.Runtime != "claude-channels" {
		t.Fatal("Channels record converted", ep.Runtime)
	}
	os.WriteFile(endpointPath("c"), []byte("broken"), 0600)
	if _, err := bindCodexSession("c", threadA, "", time.Now()); err == nil {
		t.Fatal("bound over corruption")
	}
	if b, _ := os.ReadFile(endpointPath("c")); string(b) != "broken" {
		t.Fatal("corruption overwritten")
	}
	if _, err := bindCodexSession("b", "not-a-uuid", "", time.Now()); err == nil {
		t.Fatal("invalid thread accepted")
	}
}

func TestManualRegistrationRespectsLiveBindingAndInstallBaseline(t *testing.T) {
	seedBroadcastMembers(t)
	c, _ := NewCall("a", "b", "before install")
	AppendTurn(c, "a", "history", false)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	// First manual registration of an install-created endpoint can replay.
	if err := RegisterEndpoint("b", threadA, true); err != nil {
		t.Fatal(err)
	}
	ep, _ := readEndpoint("b")
	if len(ep.Events) == 0 || ep.Binding != "manual" {
		t.Fatal("replay lost on install-created endpoint", ep)
	}
	// A live session binding cannot be moved by hand.
	unlock, _ := codexSessionLock("b", threadB)
	if res, err := bindCodexSession("b", threadB, "", time.Now()); err != nil || !res.Bound {
		t.Fatal(res, err)
	}
	if err := RegisterEndpoint("b", threadA, false); err == nil {
		t.Fatal("manual registration moved a live binding")
	}
	unlock()
	if err := RegisterEndpoint("b", threadA, false); err != nil {
		t.Fatal("closed session's binding could not be moved", err)
	}
	ep, _ = readEndpoint("b")
	if ep.Thread != threadA || ep.Binding != "manual" {
		t.Fatal(ep)
	}
}

func TestMCPBindsFromMetaThreadIDOnce(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	var sent []string
	s := &server{me: "b", enc: json.NewEncoder(&buf), codexMode: true, started: time.Now(), cwd: "/work",
		codexSend: func(_ context.Context, thread, text string) error { sent = append(sent, thread+" "+text); return nil }}
	t.Cleanup(func() {
		if s.codexRelease != nil {
			s.codexRelease()
		}
	})
	s.handle(&rpcReq{ID: json.RawMessage("1"), Method: "initialize", Params: json.RawMessage(`{}`)})
	var init struct {
		Result map[string]any `json:"result"`
	}
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &init)
	instructions, _ := init.Result["instructions"].(string)
	if head := instructions[:min(512, len(instructions))]; !strings.Contains(head, "You are b") || !strings.Contains(head, "ring tool") || !strings.Contains(head, "delivery_ack") {
		t.Fatal("first 512 characters lack identity/binding/ack:", head)
	}
	call := func(id, thread string) string {
		buf.Reset()
		s.handle(&rpcReq{ID: json.RawMessage(id), Method: "tools/call", Params: json.RawMessage(`{"name":"ring","arguments":{},"_meta":{"threadId":"` + thread + `","progressToken":1}}`)})
		return buf.String()
	}
	if out := call("2", threadA); !strings.Contains(out, "Delivery connected") {
		t.Fatal(out)
	}
	if out := call("3", threadA); strings.Contains(out, "Delivery connected") {
		t.Fatal("bind note repeated", out)
	}
	// One server serves one thread; a different ID later is ignored.
	call("4", threadB)
	if ep, _ := readEndpoint("b"); ep.Thread != threadA || ep.Cwd != "/work" || !codexSessionAlive("b", threadA) {
		t.Fatal(ep)
	}
	c, _ := NewCall("a", "b", "please review")
	AppendTurn(c, "a", "the diff", false)
	if err := s.codexTick(); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || !strings.HasPrefix(sent[0], threadA+" Yip coordination notices") {
		t.Fatal(sent)
	}
	// A non-Codex server ignores _meta entirely.
	plain := &server{me: "a", enc: json.NewEncoder(&buf)}
	if note := plain.observeCodexThread(threadB); note != "" {
		t.Fatal(note)
	}
}

func TestCodexServerRetriesLockContentionAndPassiveTickDoesNotWrite(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	// A previous server for the same thread is still exiting (a reload).
	old, err := codexSessionLock("b", threadA)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{me: "b", codexMode: true, started: time.Now(), codexSend: func(context.Context, string, string) error { return nil }}
	t.Cleanup(func() {
		if s.codexRelease != nil {
			s.codexRelease()
		}
	})
	if note := s.observeCodexThread(threadA); note != "" || s.codexThread != "" {
		t.Fatal("bound while another server held the thread", note)
	}
	old()
	if note := s.observeCodexThread(threadA); !strings.Contains(note, "Delivery connected") {
		t.Fatal("lock contention was sticky", note)
	}
	// A newer live session supersedes s; s's ticks must not rewrite state.
	time.Sleep(2 * time.Millisecond)
	newer, _ := codexSessionLock("b", threadB)
	defer newer()
	if res, err := bindCodexSession("b", threadB, "", time.Now()); err != nil || !res.Bound {
		t.Fatal(res, err)
	}
	before, _ := os.ReadFile(endpointPath("b"))
	for i := 0; i < 3; i++ {
		if err := s.codexTick(); err != nil {
			t.Fatal(err)
		}
	}
	if after, _ := os.ReadFile(endpointPath("b")); !bytes.Equal(before, after) {
		t.Fatal("passive server rewrote the endpoint")
	}
}

func TestWhoAmIInsideACodexShellUsesTheBindingNotThePath(t *testing.T) {
	dir := seatFixture(t)
	InstallWith(dir, "t", "main", true, "claude", InstallOptions{})
	InstallWith(dir, "t", "reviewer", false, "codex", InstallOptions{})
	unlock, _ := codexSessionLock("reviewer", threadA)
	defer unlock()
	if _, err := bindCodexSession("reviewer", threadA, dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_THREAD_ID", threadA)
	if me, err := WhoAmI("", dir); err != nil || me != "reviewer" {
		t.Fatal(me, err)
	}
	if me, _ := WhoAmI("main", dir); me != "main" {
		t.Fatal("explicit --as lost")
	}
	// An unbound Codex chat in a shared checkout must not become main.
	t.Setenv("CODEX_THREAD_ID", threadB)
	if me, err := WhoAmI("", dir); err == nil || !strings.Contains(err.Error(), "--as") {
		t.Fatal("unbound Codex shell resolved to", me)
	}
	t.Setenv("CODEX_THREAD_ID", "")
	if me, _ := WhoAmI("", dir); me != "main" {
		t.Fatal(me)
	}
}

func TestCodexSessionStartNudgesUntilThisSessionIsBound(t *testing.T) {
	seedBroadcastMembers(t)
	if _, err := ensureCodexEndpoint("b"); err != nil {
		t.Fatal(err)
	}
	if n := codexBindNudge("b", threadA); !strings.Contains(n, "ring") {
		t.Fatal(n)
	}
	unlock, _ := codexSessionLock("b", threadA)
	defer unlock()
	bindCodexSession("b", threadA, "", time.Now())
	if n := codexBindNudge("b", threadA); n != "" {
		t.Fatal("bound session nudged", n)
	}
	if n := codexBindNudge("b", threadB); n == "" {
		t.Fatal("other session not nudged")
	}
	out := codexHookOutput("sessionstart", withContext(hookSessionStart("b"), "SessionStart", "[yip] nudge"))
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), "[yip] nudge") || !strings.Contains(string(b), `"hookEventName":"SessionStart"`) {
		t.Fatal(string(b))
	}
	if n := codexBindNudge("a", threadA); n != "" {
		t.Fatal("non-Codex identity nudged", n)
	}
}

func TestReadOnlyToolsAreAnnotated(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range tools() {
		seen[tool.Name] = true
		ro, _ := tool.Annotations["readOnlyHint"].(bool)
		if ro != readOnlyTools[tool.Name] {
			t.Fatal(tool.Name, tool.Annotations)
		}
	}
	for name := range readOnlyTools {
		if !seen[name] {
			t.Fatal("annotation names a missing tool:", name)
		}
	}
}

// Writing .codex/ is not Codex loading it: install and doctor ask Codex.
func TestCodexLoadCheckExplainsUntrustedAndDisabled(t *testing.T) {
	dir := seatFixture(t)
	answer := `[]`
	codexMCPList = func(got, profile string) ([]byte, error) {
		if got != dir || profile != "" {
			t.Errorf("asked Codex about %q (profile %q), want %q", got, profile, dir)
		}
		return []byte(answer), nil
	}
	res, err := InstallWith(dir, "t", "codex", false, "codex", InstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(res.Notes, " ")
	if !strings.Contains(notes, "NOT LOADED YET") || !strings.Contains(notes, "trust_level = \"trusted\"") || !strings.Contains(notes, dir) {
		t.Fatal("untrusted folder not reported at install:", notes)
	}
	answer = `[{"name":"yip","enabled":true,"disabled_reason":null,"transport":{"args":["serve","--codex","--line","t","--as","codex"]}}]`
	if ok, why, err := codexLoadsYip(dir, "", "codex"); !ok || err != nil {
		t.Fatal(why, err)
	}
	if ok, why, _ := codexLoadsYip(dir, "", "other"); ok || !strings.Contains(why, `"codex", not "other"`) {
		t.Fatal(why)
	}
	answer = `[{"name":"yip","enabled":false,"disabled_reason":"not allowed by requirements","transport":{"args":[]}}]`
	if ok, why, _ := codexLoadsYip(dir, "", "codex"); ok || !strings.Contains(why, "not allowed by requirements") {
		t.Fatal("policy-disabled server not explained:", why)
	}
	codexMCPList = func(string, string) ([]byte, error) { return nil, errors.New("codex: command not found") }
	if res, _ := InstallWith(dir, "t", "codex", false, "codex", InstallOptions{}); strings.Contains(strings.Join(res.Notes, " "), "NOT LOADED") {
		t.Fatal("claimed not-loaded without being able to ask Codex")
	}
}

// A Codex chat, unbound, in a Claude-owned folder must not answer as Claude.
func TestUnboundCodexShellNeverAnswersAsTheClaudeMember(t *testing.T) {
	dir := seatFixture(t)
	if _, err := InstallWith(dir, "t", "claude", true, "claude-rewake", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_THREAD_ID", threadB)
	if me, err := WhoAmI("", dir); err == nil {
		t.Fatal("unbound Codex shell answered as", me)
	}
	if me, _ := WhoAmI("claude", dir); me != "claude" {
		t.Fatal("explicit --as lost")
	}
	t.Setenv("CODEX_THREAD_ID", "")
	if me, _ := WhoAmI("", dir); me != "claude" {
		t.Fatal(me)
	}
}

// A bare CLI command in a checkout that joined a named line uses that line.
func TestJoinedLineFindsANamedLineButPrefersTheDerivedOne(t *testing.T) {
	dir := seatFixture(t)
	t.Setenv("YIP_ROOT", "")
	root := checkoutRoot(dir)
	derived, _ := resolveLine(root)
	if got := joinedLine(root, derived); got != "" {
		t.Fatal("unjoined checkout resolved to", got)
	}
	if _, err := InstallWith(dir, "cannae", "paullus", true, "claude", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := joinedLine(root, derived); got != "cannae" {
		t.Fatal("named line not found:", got)
	}
	// Also on the derived line (worktree sharing): derived wins.
	activeLine = derived
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	SaveMembers(Members{Line: derived, Members: map[string]string{root: "paullus"}})
	if got := joinedLine(root, derived); got != derived {
		t.Fatal("derived line not preferred:", got)
	}
	// Two named lines and not the derived one: ambiguous, keep the default.
	activeLine = derived
	SaveMembers(Members{Line: derived, Members: map[string]string{}})
	activeLine = "other"
	EnsureRoot()
	SaveMembers(Members{Line: "other", Members: map[string]string{root: "paullus"}})
	if got := joinedLine(root, derived); got != "" {
		t.Fatal("ambiguous lines resolved to", got)
	}
}
