package main

// bind: a Claude session answers as its worktree's identity -- only that
// session, only in place of the identity it started as, never two sessions
// for one name -- and the waiter armed under the old name steps aside.

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	sessionA = procID{PID: 4100, Start: "17"}
	sessionB = procID{PID: 4200, Start: "18"}
)

// fakeProcs stands in for the process table: caller is the calling process's
// ancestry, live the processes that exist -- Claude sessions, all of them;
// any other ancestor is a shell.
func fakeProcs(t *testing.T, caller []procID, live ...procID) {
	t.Helper()
	oldAnc, oldAlive, oldExe := processAncestors, procAlive, procExe
	t.Cleanup(func() { processAncestors, procAlive, procExe = oldAnc, oldAlive, oldExe })
	processAncestors = func() []procID { return caller }
	procExe = func(pid int) string {
		for _, l := range live {
			if l.PID == pid {
				return "/opt/claude/bin/claude"
			}
		}
		return "/bin/sh"
	}
	procAlive = func(p procID) bool {
		for _, l := range live {
			if l == p {
				return true
			}
		}
		return false
	}
}

// seedSharedLaunch: one launch folder, "claude", on the rewake runtime, plus a
// peer b; returns the launch folder and a fresh worktree named name.
func seedSharedLaunch(t *testing.T, name string) (launchDir, worktree string) {
	t.Helper()
	tmpLine(t)
	launchDir, worktree = t.TempDir(), filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(worktree, 0o755); err != nil {
		t.Fatal(err)
	}
	launchDir, _ = filepath.EvalSymlinks(launchDir)
	worktree, _ = filepath.EvalSymlinks(worktree)
	if err := SaveMembers(Members{Members: map[string]string{launchDir: "claude", "/fixture/b": "b"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureEndpoint("claude", "claude-rewake"); err != nil {
		t.Fatal(err)
	}
	return launchDir, worktree
}

func whoami(t *testing.T, as string) string {
	t.Helper()
	me, err := WhoAmI(as, "")
	if err != nil {
		t.Fatal(err)
	}
	return me
}

func TestBindAnswersAsTheWorktreeOnlyInItsOwnSession(t *testing.T) {
	_, wt := seedSharedLaunch(t, "Repo-WT-Review")
	fakeProcs(t, []procID{{PID: 9000, Start: "1"}, sessionA}, sessionA, sessionB)
	res, err := Bind("claude", sessionA, wt, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "repo-wt-review" || !res.Joined || res.Worktree != wt {
		t.Fatal(res)
	}
	if LoadMembers().AgentAt(wt) != "repo-wt-review" {
		t.Fatal("worktree did not join as a path member", LoadMembers())
	}
	if ep, err := readEndpoint("repo-wt-review"); err != nil || ep.Runtime != "claude-rewake" {
		t.Fatal("bound identity has no rewake endpoint", ep, err)
	}
	if me := whoami(t, "claude"); me != "repo-wt-review" {
		t.Fatal("bound session still answers as", me)
	}
	if me := whoami(t, "b"); me != "b" {
		t.Fatal("an explicit other identity was replaced:", me)
	}
	// Every other session started from the folder is still "claude" -- even
	// one whose pid the kernel reused from the bound session.
	for _, other := range []procID{sessionB, {PID: sessionA.PID, Start: "99"}} {
		processAncestors = func() []procID { return []procID{other} }
		if me := whoami(t, "claude"); me != "claude" {
			t.Fatal("an unbound session answers as", me, other)
		}
	}
}

func TestTwoLiveSessionsCannotBindOneWorktree(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionB, wt, ""); err == nil || !strings.Contains(err.Error(), "another live Claude session") {
		t.Fatal("second live session took the name:", err)
	}
	// Once the holder has exited, the worktree's name is free to take over.
	procAlive = func(p procID) bool { return p == sessionB }
	if _, err := Bind("claude", sessionB, wt, ""); err != nil {
		t.Fatal(err)
	}
	if b, ok := liveBinding("wt"); !ok || b.Session != sessionB {
		t.Fatal(b, ok)
	}
}

func TestRebindMovesAndTheLaunchFolderEndsTheBinding(t *testing.T) {
	launchDir, wt1 := seedSharedLaunch(t, "wt-one")
	wt2 := filepath.Join(filepath.Dir(wt1), "wt-two")
	if err := os.Mkdir(wt2, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeProcs(t, []procID{sessionA}, sessionA)
	for _, wt := range []string{wt1, wt2} {
		if _, err := Bind("claude", sessionA, wt, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := liveBinding("wt-one"); ok {
		t.Fatal("rebinding left the first worktree bound")
	}
	if me := whoami(t, "claude"); me != "wt-two" {
		t.Fatal(me)
	}
	res, err := Bind("claude", sessionA, launchDir, "")
	if err != nil || res.Name != "claude" || !strings.Contains(res.text("claude"), "as claude again") {
		t.Fatal(res, err)
	}
	if me := whoami(t, "claude"); me != "claude" {
		t.Fatal("binding the launch folder did not end the binding:", me)
	}
}

func TestBindNamesAndRefusals(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA)
	if _, err := Bind("claude", sessionA, "relative/wt", ""); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, "b"); err == nil || !strings.Contains(err.Error(), "already belongs") {
		t.Fatal("joined under a name another checkout owns:", err)
	}
	if res, err := Bind("claude", sessionA, wt, "reviewer"); err != nil || res.Name != "reviewer" {
		t.Fatal(res, err)
	}
	// Once on the line, the worktree keeps its recorded name.
	if _, err := Bind("claude", sessionA, wt, "other"); err == nil || !strings.Contains(err.Error(), `as "reviewer"`) {
		t.Fatal(err)
	}
}

func TestBindNeedsTheRewakeRuntime(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA)
	if err := os.Remove(endpointPath("claude")); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureEndpoint("claude", "claude-channels"); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err == nil || !strings.Contains(err.Error(), "claude-rewake runtime") {
		t.Fatal("bound a Channels identity:", err)
	}
	// Hooks-only (no push delivery at all) binds, and gets no endpoint.
	if err := os.Remove(endpointPath("claude")); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	if endpointExists("wt") {
		t.Fatal("hooks-only identity grew a push endpoint")
	}
}

func TestBindAcceptsAWindowsPathUnderWSL(t *testing.T) {
	_, wt := seedSharedLaunch(t, "Strategies-wt-x")
	fakeProcs(t, nil, sessionA)
	old := wslPath
	t.Cleanup(func() { wslPath = old })
	wslPath = func(p string) (string, error) {
		if p != `C:\projects\Strategies-wt-x` {
			t.Fatal("asked to convert", p)
		}
		return wt, nil
	}
	res, err := Bind("claude", sessionA, `C:\projects\Strategies-wt-x`, "")
	if err != nil || res.Worktree != wt || res.Name != "strategies-wt-x" {
		t.Fatal(res, err)
	}
}

func TestServerBindSwitchesItsIdentity(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	s := &server{me: "claude", launch: "claude"}
	out, err := s.call("bind", map[string]any{"worktree": wt})
	if err != nil || s.me != "wt" || !strings.Contains(out, "You are now wt") {
		t.Fatal(out, err, s.me)
	}
	// A restarted MCP server of the same session finds the binding again.
	if fresh := (&server{me: "claude", launch: "claude"}); func() string { _, _ = fresh.call("ring", nil); return fresh.me }() != "wt" {
		t.Fatal("restarted server lost the binding")
	}
	// Channels and Codex connections keep the name they started with.
	if _, err := (&server{me: "claude"}).call("bind", map[string]any{"worktree": wt}); err == nil {
		t.Fatal("a non-Claude connection bound")
	}
}

func TestRewakeWaiterStepsAsideWhenItsSessionBinds(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	alive := rewakeAlive(os.Getppid(), "claude", "claude")
	if !alive() {
		t.Fatal("waiter of an unbound session reported gone")
	}
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	if alive() {
		t.Fatal("waiter kept answering for the name its session left")
	}
	old, _ := NewCall("b", "claude", "for the folder's identity")
	AppendTurn(old, "b", "hello", false)
	start := time.Now()
	if code := RunRewake("claude", 5*time.Second, "", &bytes.Buffer{}, alive, 10*time.Millisecond); code != 0 || time.Since(start) > time.Second {
		t.Fatal("stale waiter woke its session", code)
	}
	ep, _ := readEndpoint("claude")
	for _, d := range ep.Events {
		if d.Status != "pending" {
			t.Fatal("stale waiter consumed a notice", d)
		}
	}
	// The waiter armed for the bound identity is woken by its calls.
	c, _ := NewCall("b", "wt", "review please")
	AppendTurn(c, "b", "the diff", false)
	var stderr bytes.Buffer
	if code := RunRewake("wt", 5*time.Second, "", &stderr, rewakeAlive(os.Getppid(), "claude", "wt"), 10*time.Millisecond); code != 2 || !strings.Contains(stderr.String(), c.ID) {
		t.Fatal("bound waiter did not wake", code, stderr.String())
	}
}

func TestProcStatReadsTheRealProcessTree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bind reads /proc")
	}
	ppid, start, ok := procStat(os.Getpid())
	if !ok || ppid != os.Getppid() || start == "" {
		t.Fatal(ppid, start, ok)
	}
	anc := processAncestors()
	if len(anc) == 0 || anc[0].PID != os.Getppid() || !procAlive(anc[0]) {
		t.Fatal(anc)
	}
	if procAlive(procID{PID: anc[0].PID, Start: anc[0].Start + "0"}) {
		t.Fatal("a reused pid passed for the original process")
	}
}

func TestGitTipReadsAWorktreeThisHostsGitCannotOpen(t *testing.T) {
	tmpLine(t)
	base := t.TempDir()
	common := filepath.Join(base, "repo", ".git")
	gitdir := filepath.Join(common, "worktrees", "wt")
	wt := filepath.Join(base, "wt")
	for _, d := range []string{gitdir, filepath.Join(common, "refs", "heads", "feature"), wt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// What Windows git writes, as WSL sees it: a C:/ gitdir Linux git rejects.
	write(filepath.Join(wt, ".git"), "gitdir: C:/repo/.git/worktrees/wt\n")
	write(filepath.Join(gitdir, "HEAD"), "ref: refs/heads/feature/x\n")
	write(filepath.Join(gitdir, "commondir"), "../..\n")
	old := wslPath
	t.Cleanup(func() { wslPath = old })
	wslPath = func(p string) (string, error) {
		return filepath.Join(base, strings.TrimPrefix(filepath.ToSlash(p), "C:/")), nil
	}
	if err := SaveMembers(Members{Members: map[string]string{wt: "wt"}}); err != nil {
		t.Fatal(err)
	}
	const sha = "60e708c47c6d1f0a2b3c4d5e6f708192a3b4c5d6"
	loose := filepath.Join(common, "refs", "heads", "feature", "x")
	write(loose, sha+"\n")
	if got, br := GitTip("wt"); got != "60e708c" || br != "feature/x" {
		t.Fatal("loose ref:", got, br)
	}
	if err := os.Remove(loose); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(common, "packed-refs"), "# pack-refs with: peeled fully-peeled sorted\n"+sha+" refs/heads/feature/x\n")
	if got, br := GitTip("wt"); got != "60e708c" || br != "feature/x" {
		t.Fatal("packed ref:", got, br)
	}
	write(filepath.Join(gitdir, "HEAD"), sha+"\n")
	if got, br := GitTip("wt"); got != "60e708c" || br != "HEAD" {
		t.Fatal("detached:", got, br)
	}
}

// Review findings (cross-provider review, 2026-11-20): one regression each.

func TestBindCannotLandBetweenAWaitersCheckAndItsDispatch(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	c, _ := NewCall("b", "claude", "for the folder")
	AppendTurn(c, "b", "hello", false)
	// Hold the endpoint so the waiter stops inside dispatch, past its check.
	unlockEP, err := fileGuard(endpointPath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	var checked atomic.Bool
	alive := func() bool { me, err := boundIdentity("claude"); checked.Store(true); return err == nil && me == "claude" }
	done := make(chan int, 1)
	go func() { done <- RunRewake("claude", 5*time.Second, "", &bytes.Buffer{}, alive, 10*time.Millisecond) }()
	waitFor(t, "waiter past its identity check", checked.Load)
	bound := make(chan error, 1)
	go func() { _, err := Bind("claude", sessionA, wt, ""); bound <- err }()
	select {
	case err := <-bound:
		t.Fatal("bind committed while a waiter was between its check and its dispatch", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlockEP()
	if code := <-done; code != 2 {
		t.Fatal("the waiter checked first, so it delivers to the session it checked", code)
	}
	if err := <-bound; err != nil {
		t.Fatal(err)
	}
}

func TestAWaiterTakesOverFromOneLeavingTheName(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionB}, sessionB)
	if _, err := Bind("claude", sessionB, wt, ""); err != nil {
		t.Fatal(err)
	}
	// The previous binder's waiter still holds the name for up to one poll --
	// even one from the same conversation, resumed in a new process.
	if err := writeState(rewakeOwnerPath("wt"), sessionA); err != nil {
		t.Fatal(err)
	}
	if err := editEndpoint("wt", func(ep *Endpoint) error { ep.Thread = "session-B"; return nil }); err != nil {
		t.Fatal(err)
	}
	stale, err := holdLock(rewakeLockPath("wt"))
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- RunRewake("wt", 5*time.Second, "session-B", &stderr, always, 40*time.Millisecond) }()
	time.Sleep(60 * time.Millisecond)
	stale()
	waitFor(t, "new waiter armed", func() bool {
		var held procID
		return rewakeArmed("wt") && readState(rewakeOwnerPath("wt"), &held) == nil && held == sessionB
	})
	c, _ := NewCall("b", "wt", "review please")
	AppendTurn(c, "b", "the diff", false)
	if code := <-done; code != 2 || !strings.Contains(stderr.String(), c.ID) {
		t.Fatal("the session that took the name was not armed", code, stderr.String())
	}
}

func TestAHandOffIsNotRefusedWhileTheOldWaiterLingers(t *testing.T) {
	launchDir, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	lingering, err := holdLock(rewakeLockPath("wt")) // A's waiter, up to a poll
	if err != nil {
		t.Fatal(err)
	}
	defer lingering()
	if _, err := Bind("claude", sessionA, launchDir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal("own rebind refused:", err)
	}
	if _, err := Bind("claude", sessionA, launchDir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionB, wt, ""); err != nil {
		t.Fatal("hand-off to another session refused:", err)
	}
}

func TestAnUnboundSessionStartedInsideABoundOneIsItsOwn(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt-outer")
	inner := procID{PID: 4300, Start: "19"}
	fakeProcs(t, []procID{sessionA}, sessionA, inner)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	// `claude -p` run from A's shell: its hooks and server see A above it.
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, inner, {PID: 8, Start: "1"}, sessionA} }
	if me := whoami(t, "claude"); me != "claude" {
		t.Fatal("unbound inner session answered as", me)
	}
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, sessionA} }
	if me := whoami(t, "claude"); me != "wt-outer" {
		t.Fatal("A's own shell answered as", me)
	}
}

func TestAnUnreadableBindingsFileFailsClosed(t *testing.T) {
	seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	if err := os.WriteFile(bindingsPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if me, err := WhoAmI("claude", ""); err == nil {
		t.Fatal("resolved an identity past a corrupt bindings file:", me)
	}
	if _, err := (&server{me: "claude", launch: "claude"}).call("busy", map[string]any{"text": "x"}); err == nil {
		t.Fatal("a tool acted under the launch name past a corrupt bindings file")
	}
	if rewakeAlive(os.Getppid(), "claude", "claude")() {
		t.Fatal("a waiter kept dispatching past a corrupt bindings file")
	}
}

func TestBindSaysWhatItLeavesBehind(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	if got, _, _, err := TryAcquire("mac", "claude", "a build", time.Hour, nil); err != nil || !got {
		t.Fatal(got, err)
	}
	c, _ := NewCall("b", "claude", "question")
	AppendTurn(c, "b", "are you there?", false)
	res, err := Bind("claude", sessionA, wt, "")
	if err != nil {
		t.Fatal(err)
	}
	out := res.text("claude")
	if !strings.Contains(out, "claude holds mac") || !strings.Contains(out, "owes a reply on "+c.ID) {
		t.Fatal(out)
	}
}

func TestPresenceReusesARecentHEAD(t *testing.T) {
	tmpLine(t)
	wt := t.TempDir()
	write := func(head string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+filepath.Join(wt, "g")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(wt, "g"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wt, "g", "HEAD"), []byte(head+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveMembers(Members{Members: map[string]string{wt: "wt"}}); err != nil {
		t.Fatal(err)
	}
	write("1111111111111111111111111111111111111111")
	if err := Beat("wt", "x"); err != nil {
		t.Fatal(err)
	}
	write("2222222222222222222222222222222222222222")
	if err := Beat("wt", "y"); err != nil {
		t.Fatal(err)
	}
	if p, _ := LoadPresence("wt"); p.Tip != "1111111" || p.LastTool != "y" {
		t.Fatal("beat re-measured HEAD within the reuse window", p)
	}
	if sha, _ := GitTip("wt"); sha != "2222222" {
		t.Fatal("stamps must still measure:", sha)
	}
}

func TestTheNearestBoundSessionWins(t *testing.T) {
	launchDir, wt1 := seedSharedLaunch(t, "wt-one")
	_ = launchDir
	wt2 := filepath.Join(filepath.Dir(wt1), "wt-two")
	if err := os.Mkdir(wt2, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeProcs(t, nil, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionB, wt2, ""); err != nil {
		t.Fatal(err)
	}
	// B was started from inside A: B's processes have both as ancestors.
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, sessionB, sessionA} }
	for i := 0; i < 50; i++ {
		if me := whoami(t, "claude"); me != "wt-two" {
			t.Fatal("inner session answered as", me)
		}
	}
	processAncestors = func() []procID { return []procID{sessionA} }
	if me := whoami(t, "claude"); me != "wt-one" {
		t.Fatal(me)
	}
}

func TestOnlyTheMCPToolBindsAndItBindsItsParent(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionB, sessionA}, sessionA, sessionB)
	t.Setenv("CLAUDE_PID", "4100") // inherited from outer session A: ignored
	if s, err := claudeSession(); err != nil || s != sessionB {
		t.Fatal("server bound", s, err)
	}
	// A shell command cannot tell which name its session started as.
	if _, err := (&server{me: "claude", launch: "claude", cli: true}).call("bind", map[string]any{"worktree": wt}); err == nil {
		t.Fatal("yip api bound")
	}
}

func TestAFailedBindLeavesTheIdentityUnchanged(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	if err := os.MkdirAll(filepath.Dir(endpointPath("wt")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(endpointPath("wt"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err == nil {
		t.Fatal("bind over a corrupt endpoint succeeded")
	}
	if me := whoami(t, "claude"); me != "claude" || LoadMembers().AgentAt(wt) != "" {
		t.Fatal("a failed bind committed:", me, LoadMembers())
	}
}

func TestBindingsFromAnEarlierBootBindNobody(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB)
	stale := Bindings{Version: 1, Boot: "an-earlier-boot", Bindings: map[string]Binding{
		"wt": {Session: sessionA, Launch: "claude", Worktree: wt, Bound: now()},
	}}
	if err := writeState(bindingsPath(), stale); err != nil {
		t.Fatal(err)
	}
	if me := whoami(t, "claude"); me != "claude" {
		t.Fatal("a reused pid and start time from an earlier boot answered as", me)
	}
	if _, err := Bind("claude", sessionB, wt, ""); err != nil {
		t.Fatal(err)
	}
}
