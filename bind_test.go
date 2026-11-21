package main

// bind: a Claude session answers as its worktree's identity -- only that
// session, only in place of the identity it started as, never two sessions
// for one name -- and the waiter armed under the old name steps aside.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
// ancestry, live the processes that exist -- Claude sessions, all of them,
// registered as their Yip MCP server would; any other ancestor is a shell.
func fakeProcs(t *testing.T, caller []procID, live ...procID) {
	t.Helper()
	oldAnc, oldAlive := processAncestors, procAlive
	t.Cleanup(func() { processAncestors, procAlive = oldAnc, oldAlive })
	processAncestors = func() []procID { return caller }
	procAlive = func(p procID) bool {
		for _, l := range live {
			if l == p {
				return true
			}
		}
		return false
	}
	for _, l := range live {
		if err := registerSession(l, "claude"); err != nil {
			t.Fatal(err)
		}
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
	if b, ok, _ := liveBinding("wt"); !ok || b.Session != sessionB {
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
	if _, ok, _ := liveBinding("wt-one"); ok {
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
	s := &server{me: "claude", launch: "claude", session: sessionA}
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
	alive := rewakeAlive(os.Getppid(), sessionA, "claude", "claude")
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
	if code := RunRewake("wt", 5*time.Second, "", &stderr, rewakeAlive(os.Getppid(), sessionA, "claude", "wt"), 10*time.Millisecond); code != 2 || !strings.Contains(stderr.String(), c.ID) {
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
	alive := func() bool {
		me, err := boundIdentity("claude")
		checked.Store(true)
		return err == nil && me == "claude"
	}
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
	if rewakeAlive(os.Getppid(), sessionA, "claude", "claude")() {
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
	// Beating keeps the heartbeat fresh, not the measurement: once the tip
	// is a minute old, the next beat measures, however busy the agent is.
	if err := updateJSON(presencePath("wt"), func(p *Presence) error {
		p.TipAt = time.Now().Add(-61 * time.Second).UTC().Format(time.RFC3339)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Beat("wt", "z"); err != nil {
		t.Fatal(err)
	}
	if p, _ := LoadPresence("wt"); p.Tip != "2222222" {
		t.Fatal("an active agent's presence never re-measured HEAD", p)
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

func TestOnlyTheMCPToolBindsAndOnlyForTheSessionThatStartedIt(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionB, sessionA}, sessionA, sessionB)
	t.Setenv("CLAUDE_PID", "4100") // inherited from outer session A: ignored
	if p := parentSession(); p != sessionB {
		t.Fatal("server's session", p)
	}
	// A shell command cannot tell which name its session started as.
	if _, err := (&server{me: "claude", launch: "claude", cli: true}).call("bind", map[string]any{"worktree": wt}); err == nil {
		t.Fatal("yip api bound")
	}
	// A server orphaned by its session must not bind whatever adopted it.
	orphan := &server{me: "claude", launch: "claude", session: procID{PID: 4400, Start: "20"}}
	if _, err := orphan.call("bind", map[string]any{"worktree": wt}); err == nil || !strings.Contains(err.Error(), "has exited") {
		t.Fatal("an orphaned server bound:", err)
	}
}

func TestTheWalkStopsAtTheNearestRegisteredSession(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	inner := procID{PID: 4300, Start: "19"}
	node := procID{PID: 77, Start: "5"} // any other program, e.g. an interpreter
	fakeProcs(t, []procID{sessionA}, sessionA, inner)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, node, sessionA} }
	if me := whoami(t, "claude"); me != "wt" {
		t.Fatal("an unregistered ancestor stopped the walk:", me)
	}
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, inner, node, sessionA} }
	if me := whoami(t, "claude"); me != "claude" {
		t.Fatal("a registered session inside A answered as A's name:", me)
	}
	// Sessions that exited, or ran in another boot, are forgotten.
	procAlive = func(p procID) bool { return p == sessionA }
	stale := sessionRecord{Session: procID{PID: 4500, Start: "21"}, Boot: "an-earlier-boot", Launch: "claude"}
	if err := writeState(sessionPath(stale.Session), stale); err != nil {
		t.Fatal(err)
	}
	if err := registerSession(sessionA, "claude"); err != nil {
		t.Fatal(err)
	}
	if isRegistered(inner) || fileExists(sessionPath(stale.Session)) || !isRegistered(sessionA) {
		t.Fatal("registry kept exited or earlier-boot sessions")
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

// Review round 3 (Codex call 0006, prosecutor run 2): one regression each.

func TestRebindSaysWhatItLeavesWithTheNameItLeaves(t *testing.T) {
	launchDir, wt1 := seedSharedLaunch(t, "wt-one")
	wt2 := filepath.Join(filepath.Dir(wt1), "wt-two")
	if err := os.Mkdir(wt2, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeProcs(t, []procID{sessionA}, sessionA)
	if _, err := Bind("claude", sessionA, wt1, ""); err != nil {
		t.Fatal(err)
	}
	if got, _, _, err := TryAcquire("mac", "wt-one", "a build", time.Hour, nil); err != nil || !got {
		t.Fatal(got, err)
	}
	c, _ := NewCall("b", "wt-one", "question")
	AppendTurn(c, "b", "still there?", false)
	res, err := Bind("claude", sessionA, wt2, "")
	if err != nil {
		t.Fatal(err)
	}
	out := res.text("claude")
	if !strings.Contains(out, "wt-one holds mac") || !strings.Contains(out, "bind "+wt1+" again") || !strings.Contains(out, "wt-one owes a reply on "+c.ID) {
		t.Fatal("rebind was silent about what wt-one keeps:", out)
	}
	c2, _ := NewCall("b", "wt-two", "another")
	AppendTurn(c2, "b", "and you?", false)
	res, err = Bind("claude", sessionA, launchDir, "")
	if err != nil || !strings.Contains(res.text("claude"), "wt-two owes a reply on "+c2.ID) {
		t.Fatal("unbind was silent about what wt-two keeps:", res, err)
	}
}

func TestAContenderReadsTheCurrentHoldersOwner(t *testing.T) {
	seedSharedLaunch(t, "wt")
	// A stale owner record names the contender; a new holder is mid-claim:
	// it has the lock and has not yet recorded itself.
	if err := writeState(rewakeOwnerPath("claude"), sessionA); err != nil {
		t.Fatal(err)
	}
	guard, err := fileGuard(rewakeOwnerPath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := holdLock(rewakeLockPath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	got := make(chan procID, 1)
	go func() { _, held, _ := claimRewake("claude", sessionA); got <- held }()
	select {
	case held := <-got:
		t.Fatal("contender read the owner while a claim was in progress:", held)
	case <-time.After(100 * time.Millisecond):
	}
	if err := writeState(rewakeOwnerPath("claude"), sessionB); err != nil {
		t.Fatal(err)
	}
	guard()
	if held := <-got; held != sessionB {
		t.Fatal("contender saw a stale owner:", held)
	}
}

func TestAShellInAnotherSessionsBoundFolderIsRefused(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt-one")
	t.Setenv("YIP_AGENT", "")
	t.Setenv("CODEX_THREAD_ID", "") // run from inside Codex, it would name a Codex chat
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	if me, err := WhoAmI("", wt); err != nil || me != "wt-one" {
		t.Fatal("the bound session's own shell:", me, err)
	}
	processAncestors = func() []procID { return []procID{sessionB} }
	if me, err := WhoAmI("", wt); err == nil {
		t.Fatal("another session's shell in the bound folder answered as", me)
	}
	// B started inside A: A is an ancestor, but B is the nearest session.
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, sessionB, sessionA} }
	if me, err := WhoAmI("", wt); err == nil {
		t.Fatal("a session nested in the binder answered as its worktree:", me)
	}
	if me, err := WhoAmI("wt-one", wt); err == nil {
		t.Fatal("another Claude session took a bound name with --as:", me)
	}
	// A person at a terminal (no Claude session above) may name it outright.
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}} }
	if me, err := WhoAmI("wt-one", wt); err != nil || me != "wt-one" {
		t.Fatal("an explicit --as outside any session:", me, err)
	}
}

func TestWatchStopsWhenItsSessionRebinds(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	still := func() bool { cur, err := boundIdentity("claude"); return err == nil && cur == "claude" }
	done := make(chan error, 1)
	go func() { done <- Watch("claude", still, 10*time.Millisecond, 5*time.Second, false, false) }()
	time.Sleep(30 * time.Millisecond)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errWatchIdentity) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch kept streaming the name its session left")
	}
}

// Review round 4 (Codex call 0007): one regression each.

func TestHookSessionFindsClaudeThroughTheHookShell(t *testing.T) {
	seedSharedLaunch(t, "wt")
	shell := procID{PID: 50, Start: "3"}
	fakeProcs(t, []procID{shell, sessionB, sessionA}, sessionA, sessionB)
	old := procCmdline
	t.Cleanup(func() { procCmdline = old })
	procCmdline = func(pid int) string {
		if pid == shell.PID {
			return "/bin/sh\x00-c\x00[ ! -x yip ] || yip hook sessionstart --as claude  # yip-line-hook"
		}
		return "claude"
	}
	if p := hookSession(); p != sessionB {
		t.Fatal("hook through its shell:", p)
	}
	processAncestors = func() []procID { return []procID{sessionB, sessionA} } // exec'd
	if p := hookSession(); p != sessionB {
		t.Fatal("exec'd hook:", p)
	}
}

// runHook runs a hook as Claude would: input on stdin, output from stdout.
func runHook(t *testing.T, event string, in string) string {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	_, _ = inW.WriteString(in)
	inW.Close()
	RunHookRuntime(event, "claude", "claude")
	os.Stdin, os.Stdout = oldIn, oldOut
	outW.Close()
	b, _ := io.ReadAll(outR)
	return string(b)
}

func TestSessionStartRegistersItsSessionBeforeResolving(t *testing.T) {
	launchDir, wt := seedSharedLaunch(t, "outer-wt")
	shell := procID{PID: 50, Start: "3"}
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("b", "outer-wt", "for A")
	AppendTurn(c, "b", "your turn", false)
	// B starts inside A; its MCP server has not registered it yet.
	if err := os.Remove(sessionPath(sessionB)); err != nil {
		t.Fatal(err)
	}
	processAncestors = func() []procID { return []procID{shell, sessionB, sessionA} }
	old := procCmdline
	t.Cleanup(func() { procCmdline = old })
	procCmdline = func(pid int) string {
		if pid == shell.PID {
			return "/bin/sh\x00-c\x00yip hook sessionstart  # yip-line-hook"
		}
		return "claude"
	}
	out := runHook(t, "sessionstart", `{"cwd":"`+launchDir+`","hook_event_name":"SessionStart","source":"startup"}`)
	if strings.Contains(out, c.ID) {
		t.Fatal("a nested session was told the outer session's business:", out)
	}
	if !isRegistered(sessionB) {
		t.Fatal("SessionStart did not register its session")
	}
}

func TestAFailedRegistrationRefusesToActAndABadRecordIsABoundary(t *testing.T) {
	_, wt := seedSharedLaunch(t, "outer-wt")
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	// An unreadable record still marks B as a session: do not cross it.
	if err := os.WriteFile(sessionPath(sessionB), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	processAncestors = func() []procID { return []procID{sessionB, sessionA} }
	if me := whoami(t, "claude"); me != "claude" {
		t.Fatal("crossed an unreadable session record into", me)
	}
	// A server that could not register refuses to act at all.
	if err := os.Remove(sessionPath(sessionB)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessionsDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sessionsDir(), 0o755) })
	s := &server{me: "claude"}
	s.startClaude("claude")
	if s.regErr == nil {
		t.Skip("registry directory still writable (running as root?)")
	}
	if out, err := s.call("busy", map[string]any{"text": "inner B's work"}); err == nil {
		t.Fatal("an unregistered session acted:", out)
	}
}

// Review round 5 (prosecutor run 3 on 336ea49): one regression each.

func TestStopMeasuresTheLastCommitOfATurn(t *testing.T) {
	tmpLine(t)
	wt := t.TempDir()
	head := func(sha string) {
		t.Helper()
		_ = os.MkdirAll(filepath.Join(wt, "g"), 0o755)
		if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+filepath.Join(wt, "g")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wt, "g", "HEAD"), []byte(sha+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveMembers(Members{Members: map[string]string{wt: "wt"}}); err != nil {
		t.Fatal(err)
	}
	head("1111111111111111111111111111111111111111")
	_ = Beat("wt", "a")
	head("2222222222222222222222222222222222222222") // committed within the window
	_ = Beat("wt", "b")
	hookStop("wt") // the turn ends; the session goes idle
	if p, _ := LoadPresence("wt"); p.Tip != "2222222" {
		t.Fatal("idle presence hides the turn's last commit:", p.Tip)
	}
	// A measurement stamped in the future (clock stepped back) is stale.
	_ = updateJSON(presencePath("wt"), func(p *Presence) error {
		p.TipAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		return nil
	})
	head("3333333333333333333333333333333333333333")
	_ = Beat("wt", "c")
	if p, _ := LoadPresence("wt"); p.Tip != "3333333" {
		t.Fatal("a future TipAt was trusted:", p.Tip)
	}
}

func TestNativeAndBoundSessionsCannotShareAName(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	native := procID{PID: 4700, Start: "23"}
	fakeProcs(t, []procID{sessionA}, sessionA, native)
	if err := os.Remove(sessionPath(native)); err != nil {
		t.Fatal(err)
	}
	if err := registerSession(native, "wt"); err != nil { // started inside wt
		t.Fatal(err)
	}
	m := LoadMembers()
	m.Members[wt] = "wt"
	if err := SaveMembers(m); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err == nil || !strings.Contains(err.Error(), "answers to wt") {
		t.Fatal("bound a name a live native session answers to:", err)
	}
	// The other order: bound first, then a session is started inside wt.
	procAlive = func(p procID) bool { return p == sessionA }
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	late := procID{PID: 4800, Start: "24"}
	procAlive = func(p procID) bool { return p == sessionA || p == late }
	if err := registerSession(late, "wt"); err != nil {
		t.Fatal(err)
	}
	processAncestors = func() []procID { return []procID{late} }
	if me, err := identityFor("wt", true); err == nil {
		t.Fatal("a session started inside a bound worktree answered as", me)
	}
}

func TestReleasingTheWaiterClearsItsOwner(t *testing.T) {
	seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	release, _, err := claimRewake("claude", sessionA)
	if err != nil {
		t.Fatal(err)
	}
	release()
	// A peer's lockHeld probe holds the lock for an instant; the owner is
	// empty, so a claimant colliding with it retries instead of giving up.
	probe, err := holdLock(rewakeLockPath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	_, held, err := claimRewake("claude", sessionA)
	probe()
	if err == nil || held != (procID{}) {
		t.Fatal("owner not cleared on release:", held, err)
	}
}

func TestPruningJudgesOnlyItsOwnNamespace(t *testing.T) {
	seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA)
	elsewhere := sessionRecord{Session: procID{PID: 4900, Start: "25"}, Boot: bootID(), NS: "pid:[1]", Launch: "claude"}
	mine := sessionRecord{Session: procID{PID: 5000, Start: "26"}, Boot: bootID(), NS: pidNS(), Launch: "claude"}
	for _, r := range []sessionRecord{elsewhere, mine} {
		if err := writeState(sessionPath(r.Session), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := registerSession(sessionA, "claude"); err != nil {
		t.Fatal(err)
	}
	if !fileExists(sessionPath(elsewhere.Session)) || fileExists(sessionPath(mine.Session)) {
		t.Fatal("pruned by the wrong namespace's view of liveness")
	}
	old := bootID
	t.Cleanup(func() { bootID = old })
	bootID = func() string { return "" }
	if err := writeState(sessionPath(mine.Session), mine); err != nil {
		t.Fatal(err)
	}
	_ = registerSession(sessionA, "claude")
	if !fileExists(sessionPath(mine.Session)) {
		t.Fatal("pruned without knowing the boot")
	}
}

func TestWatchDoesNotLeakTheOldNamesEventsInTheBindPoll(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	c, _ := NewCall("b", "claude", "for the folder")
	var calls atomic.Int32
	still := func() bool {
		cur, err := identityFor("claude", true)
		if calls.Add(1) == 1 { // the bind lands just after this check passes
			AppendTurn(c, "b", "hello", false)
			if _, err := Bind("claude", sessionA, wt, ""); err != nil {
				t.Error(err)
			}
		}
		return err == nil && cur == "claude"
	}
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := Watch("claude", still, 10*time.Millisecond, 2*time.Second, true, false)
	os.Stdout = old
	w.Close()
	out, _ := io.ReadAll(r)
	if !errors.Is(err, errWatchIdentity) || strings.Contains(string(out), c.ID) {
		t.Fatal("the bind poll let the old name's event out:", err, string(out))
	}
}

// Review round 6 (Codex call 0008 on e1fe176): one regression each.

func TestAPromptMentioningTheMarkerIsNotAHookShell(t *testing.T) {
	if isHookShell("claude\x00-p\x00why does # yip-line-hook appear?") {
		t.Fatal("a Claude prompt passed for a hook shell")
	}
	if !isHookShell("/bin/sh\x00-c\x00[ ! -x yip ] || yip hook stop  # yip-line-hook") {
		t.Fatal("the real hook shell was not recognised")
	}
	seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionB, sessionA}, sessionA, sessionB) // exec'd hook under B
	old := procCmdline
	t.Cleanup(func() { procCmdline = old })
	procCmdline = func(int) string { return "claude\x00-p\x00# yip-line-hook" }
	if p := hookSession(); p != sessionB {
		t.Fatal("skipped a Claude process whose prompt mentions the marker:", p)
	}
}

func TestAnotherNamespacesRecordIsNotALocalBoundary(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	shell := procID{PID: 60, Start: "4"}
	fakeProcs(t, []procID{shell, sessionA}, sessionA)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	// A registrar in another pid namespace recorded a session whose numbers
	// happen to match this shell.
	foreign := sessionRecord{Session: shell, Boot: bootID(), NS: "pid:[999]", Launch: "other"}
	if err := writeState(filepath.Join(sessionsDir(), "60-4-999.json"), foreign); err != nil {
		t.Fatal(err)
	}
	if me := whoami(t, "claude"); me != "wt" {
		t.Fatal("a foreign namespace's record stopped the walk:", me)
	}
	procAlive = func(p procID) bool { return p == sessionA || p == shell } // same numbers, live here
	if _, found, _ := answeringTo("other", procID{}, Bindings{}); found {
		t.Fatal("a foreign namespace's record counted as a live local session")
	}
}

func TestBindJudgesWhoAnswersToTheNameNow(t *testing.T) {
	launchDir, wt := seedSharedLaunch(t, "wt")
	late := procID{PID: 4800, Start: "24"}
	fakeProcs(t, nil, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	// A session started inside wt after the bind is fenced, not answering:
	// it does not veto the binder binding again.
	procAlive = func(p procID) bool { return p == sessionA || p == sessionB || p == late }
	if err := registerSession(late, "wt"); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal("the binder's repeat bind was refused:", err)
	}
	// A bound away from claude, so claude's folder is free for B (launched
	// as "other") -- were no other session answering to claude.
	if err := os.Remove(sessionPath(sessionB)); err != nil {
		t.Fatal(err)
	}
	if err := registerSession(sessionB, "other"); err != nil {
		t.Fatal(err)
	}
	if res, err := Bind("other", sessionB, launchDir, ""); err != nil || res.Name != "claude" {
		t.Fatal("a vacated launch name stayed reserved:", res, err)
	}
}

func TestAnOlderMeasurementNeverReplacesANewerOne(t *testing.T) {
	newer, older := time.Now(), time.Now().Add(-time.Second)
	p := &Presence{}
	setTip(p, "2222222", "main", newer) // the Stop's final measurement
	setTip(p, "1111111", "main", older) // a beat that measured earlier publishes late
	if p.Tip != "2222222" {
		t.Fatal("an in-flight older beat overwrote the final HEAD:", p.Tip)
	}
}

// Review round 7 (prosecutor run 4 on e1fe176): one regression each.

func TestPresenceMeasurementIsBoundedAndNeverEmpty(t *testing.T) {
	seedSharedLaunch(t, "wt")
	old := tipFunc
	t.Cleanup(func() { tipFunc = old })
	tipFunc = func(string) (string, string) { return "1111111", "main" }
	if err := MeasureTip("claude"); err != nil {
		t.Fatal(err)
	}
	tipFunc = func(string) (string, string) { return "", "main" } // a branch, no SHA
	_ = MeasureTip("claude")
	if p, _ := LoadPresence("claude"); p.Tip != "1111111" {
		t.Fatal("a branch without a SHA replaced the last good HEAD:", p.Tip)
	}
	c, _ := NewCall("b", "claude", "owed")
	AppendTurn(c, "b", "reply please", false)
	// A stalled filesystem: the Stop hook still decides within the budget,
	// and the last good HEAD stays.
	tipFunc = func(string) (string, string) { time.Sleep(3 * time.Second); return "2222222", "main" }
	start := time.Now()
	decision := hookStop("claude")
	if took := time.Since(start); took > tipBudget+500*time.Millisecond {
		t.Fatal("Stop waited on a stalled measurement:", took)
	}
	if b, _ := json.Marshal(decision); !strings.Contains(string(b), "block") {
		t.Fatal("Stop lost its block decision:", string(b))
	}
	tipFunc = func(string) (string, string) { return "", "" } // nothing found
	_ = MeasureTip("claude")
	if p, _ := LoadPresence("claude"); p.Tip != "1111111" {
		t.Fatal("a stalled or empty measurement replaced the last good HEAD:", p.Tip)
	}
}

func TestTheWaiterMeasuresPresenceWhileItRuns(t *testing.T) {
	seedSharedLaunch(t, "wt")
	old := tipFunc
	t.Cleanup(func() { tipFunc = old })
	tipFunc = func(string) (string, string) { return "3333333", "main" }
	// A turn ended by an interrupt runs no Stop; the armed waiter measures.
	RunRewake("claude", 100*time.Millisecond, "", &bytes.Buffer{}, always, 10*time.Millisecond)
	if p, _ := LoadPresence("claude"); p.Tip != "3333333" {
		t.Fatal("the waiter left presence unmeasured:", p.Tip)
	}
}

func TestEveryHookRegistersItsSessionFirst(t *testing.T) {
	launchDir, wt := seedSharedLaunch(t, "outer-wt")
	shell := procID{PID: 50, Start: "3"}
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("b", "outer-wt", "for A")
	AppendTurn(c, "b", "your turn", false)
	// B started inside A before this binary registered it (or registration
	// failed at its SessionStart): its PostToolUse hook must not answer as A.
	if err := os.Remove(sessionPath(sessionB)); err != nil {
		t.Fatal(err)
	}
	processAncestors = func() []procID { return []procID{shell, sessionB, sessionA} }
	old := procCmdline
	t.Cleanup(func() { procCmdline = old })
	procCmdline = func(pid int) string {
		if pid == shell.PID {
			return "/bin/sh\x00-c\x00yip hook posttooluse  # yip-line-hook"
		}
		return "claude"
	}
	out := runHook(t, "posttooluse", `{"cwd":"`+launchDir+`","hook_event_name":"PostToolUse","tool_name":"Bash"}`)
	if strings.Contains(out, c.ID) || !isRegistered(sessionB) {
		t.Fatal("an unregistered session's hook answered as the outer session:", out)
	}
}

func TestASessionWhoseLaunchNameIsFencedCanStillBind(t *testing.T) {
	launchDir, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA, sessionB)
	// B, launched as "other", bound claude's folder: claude is now B's.
	if err := os.Remove(sessionPath(sessionB)); err != nil {
		t.Fatal(err)
	}
	if err := registerSession(sessionB, "other"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sessionPath(sessionA)); err != nil {
		t.Fatal(err)
	}
	procAlive = func(p procID) bool { return p == sessionB }
	if _, err := Bind("other", sessionB, launchDir, ""); err != nil {
		t.Fatal(err)
	}
	procAlive = func(p procID) bool { return p == sessionA || p == sessionB }
	if err := registerSession(sessionA, "claude"); err != nil {
		t.Fatal(err)
	}
	s := &server{me: "claude", launch: "claude", session: sessionA}
	if _, err := s.call("busy", map[string]any{"text": "x"}); err == nil {
		t.Fatal("a fenced session acted as claude")
	}
	if out, err := s.call("bind", map[string]any{"worktree": wt}); err != nil {
		t.Fatal("a fenced session could not bind its way out:", err, out)
	}
}

func TestBindRefusesWhatItCannotFenceOrRead(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA)
	if _, err := ensureEndpoint("wt", "claude-channels"); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err == nil || !strings.Contains(err.Error(), "delivered through claude-channels") {
		t.Fatal("bound a worktree delivered through Channels:", err)
	}
	if err := os.Remove(endpointPath("wt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionsDir(), "1-1-0.json"), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err == nil || !strings.Contains(err.Error(), "cannot tell who answers") {
		t.Fatal("bound past an unreadable registry record:", err)
	}
}

func TestRegistrationRecoversOnceTheFaultIsFixed(t *testing.T) {
	seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	if err := os.Remove(sessionPath(sessionA)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessionsDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	s := &server{me: "claude"}
	s.startClaude("claude")
	_ = os.Chmod(sessionsDir(), 0o755)
	if s.regErr == nil {
		t.Skip("registry directory still writable (running as root?)")
	}
	if _, err := s.call("busy", map[string]any{"text": "x"}); err != nil {
		t.Fatal("registration did not recover once the fault was fixed:", err)
	}
}

func TestTakingOverANameReportsItsUnacknowledgedNotices(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, nil, sessionA, sessionB)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("b", "wt", "for the first binder")
	AppendTurn(c, "b", "hello", false)
	RunRewake("wt", time.Second, "", &bytes.Buffer{}, always, 10*time.Millisecond) // sent, never acked
	procAlive = func(p procID) bool { return p == sessionB }                       // the first binder exits
	res, err := Bind("claude", sessionB, wt, "")
	if err != nil || !strings.Contains(res.text("claude"), "never acknowledged") {
		t.Fatal("takeover was silent about the earlier session's notices:", res, err)
	}
}

// Review round 8 (Codex call 0009 on 15ed0fe): one regression each.

func TestStalledPresenceWorkDoesNotPileUp(t *testing.T) {
	seedSharedLaunch(t, "wt")
	oldF, oldB := tipFunc, tipBudget
	release := make(chan struct{})
	t.Cleanup(func() { close(release); tipFunc, tipBudget = oldF, oldB })
	tipBudget = 30 * time.Millisecond
	var running atomic.Int32
	tipFunc = func(string) (string, string) { running.Add(1); <-release; running.Add(-1); return "", "" }
	for i := 0; i < 5; i++ {
		if _, _, _, ok := measureTip("claude"); ok {
			t.Fatal("a stalled measurement reported success")
		}
	}
	if n := running.Load(); n != 1 {
		t.Fatal("stalled measurements piled up:", n)
	}
}

func TestStopDecidesWithinBudgetEvenWhenPresenceIsLocked(t *testing.T) {
	seedSharedLaunch(t, "wt")
	oldF, oldB := tipFunc, tipBudget
	t.Cleanup(func() { tipFunc, tipBudget = oldF, oldB })
	tipBudget = 100 * time.Millisecond
	tipFunc = func(string) (string, string) { return "1111111", "main" }
	c, _ := NewCall("b", "claude", "owed")
	AppendTurn(c, "b", "reply please", false)
	held, err := fileGuard(presencePath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	// The publish outlives Stop by design; let it finish before the line's
	// directory goes. Captured first: the job leaves the map before done.
	t.Cleanup(func() {
		job, running := tipJobs.Load(Root() + "|publish:claude")
		held()
		if running {
			<-job.(*tipJob).done
		}
	})
	start := time.Now()
	decision := hookStop("claude")
	if took := time.Since(start); took > tipBudget+500*time.Millisecond {
		t.Fatal("Stop waited on the presence lock:", took)
	}
	if b, _ := json.Marshal(decision); !strings.Contains(string(b), "block") {
		t.Fatal("Stop lost its block decision:", string(b))
	}
}

// Review round 9 (Codex call 0010 on 77d150c): one regression each.

func TestALockHolderNeverLeavesANestedSessionUnregistered(t *testing.T) {
	_, wt := seedSharedLaunch(t, "outer-wt")
	inner := procID{PID: 5200, Start: "28"}
	fakeProcs(t, []procID{sessionA}, sessionA)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	stuck, err := fileGuard(filepath.Join(sessionsDir(), "registry")) // a stalled registrar
	if err != nil {
		t.Fatal(err)
	}
	defer stuck()
	procAlive = func(p procID) bool { return p == sessionA || p == inner }
	processAncestors = func() []procID { return []procID{inner, sessionA} }
	s := &server{me: "claude"}
	s.startClaude("claude")
	if s.regErr != nil {
		t.Fatal("the nested session was left unregistered:", s.regErr)
	}
	// Its first shell command, before any of its hooks has run.
	processAncestors = func() []procID { return []procID{{PID: 9, Start: "1"}, inner, sessionA} }
	if me := whoami(t, "claude"); me != "claude" {
		t.Fatal("the nested session's CLI answered as the outer binding:", me)
	}
}

func TestRecordsOfDifferentBootsNeverShareAFile(t *testing.T) {
	seedSharedLaunch(t, "wt")
	p := procID{PID: 5300, Start: "29"}
	old := bootID
	t.Cleanup(func() { bootID = old })
	bootID = func() string { return "boot-1" }
	earlier := sessionPath(p)
	bootID = func() string { return "boot-2" }
	if sessionPath(p) == earlier {
		t.Fatal("a prune reading the earlier boot's record could remove this boot's:", earlier)
	}
}

func TestAJoinedMeasurementKeepsItsOwnTime(t *testing.T) {
	seedSharedLaunch(t, "wt")
	oldF, oldB := tipFunc, tipBudget
	t.Cleanup(func() { tipFunc, tipBudget = oldF, oldB })
	release := make(chan struct{})
	var calls atomic.Int32
	tipFunc = func(string) (string, string) { calls.Add(1); <-release; return "1111111", "main" }
	tipBudget = 30 * time.Millisecond
	_ = SetBusy("claude", "first", nil) // times out; its measurement runs on
	// Meanwhile another process measures and publishes a newer HEAD.
	if err := updateJSON(presencePath("claude"), func(p *Presence) error { setTip(p, "2222222", "main", time.Now()); return nil }); err != nil {
		t.Fatal(err)
	}
	tipBudget = 2 * time.Second
	done := make(chan error, 1)
	go func() { done <- SetBusy("claude", "second", nil) }()
	time.Sleep(50 * time.Millisecond) // the second caller joins the run in flight
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatal("the second caller did not join the run in flight:", n)
	}
	if p, _ := LoadPresence("claude"); p.Tip != "2222222" {
		t.Fatal("a joined older sample overwrote a newer HEAD:", p.Tip)
	}
}

// Review round 10 (prosecutor run 5 on 15ed0fe): one regression each.

func TestAFailedMeasurementWaitsOutTheReuseWindow(t *testing.T) {
	seedSharedLaunch(t, "wt")
	old := tipFunc
	t.Cleanup(func() { tipFunc = old })
	var calls atomic.Int32
	tipFunc = func(string) (string, string) { calls.Add(1); return "", "" } // ran out, or found nothing
	for i := 0; i < 3; i++ {
		if err := Beat("claude", "tool"); err != nil {
			t.Fatal(err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatal("every beat measured again after a failed measurement:", n)
	}
	if err := updateJSON(presencePath("claude"), func(p *Presence) error {
		p.TipTried = time.Now().Add(-2 * presenceTipReuse).UTC().Format(time.RFC3339Nano)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = Beat("claude", "tool")
	if n := calls.Load(); n != 2 {
		t.Fatal("never measured again once the window passed:", n)
	}
}

func TestChannelsAndCodexConnectionsAreRefusedABoundName(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	t.Setenv("YIP_HOME", t.TempDir())
	t.Setenv("CODEX_HOME", t.TempDir())
	prev := activeLine
	t.Cleanup(func() { activeLine = prev })
	fakeProcs(t, []procID{sessionA}, sessionA) // plain hooks: no launch endpoint
	if err := os.Remove(endpointPath("claude")); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWith(wt, activeLine, "", true, "claude-channels", InstallOptions{}); err == nil || !strings.Contains(err.Error(), "could not be fenced") {
		t.Fatal("installed Channels under a bound name:", err)
	}
	if err := serveIO("wt", serveChannels, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), "bound by another") {
		t.Fatal("a Channels server started under a bound name:", err)
	}
	s := &server{me: "wt", codexMode: true}
	if out, err := s.call("presence", map[string]any{}); err == nil {
		t.Fatal("a Codex connection acted as a bound name:", out)
	}
}

func TestABrokenRegistryDoesNotSilenceALineWithoutBindings(t *testing.T) {
	seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	if err := os.RemoveAll(sessionsDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionsDir(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("b", "claude", "owed")
	AppendTurn(c, "b", "reply please", false)
	if out := runHook(t, "stop", `{"session_id":"s"}`); !strings.Contains(out, "block") {
		t.Fatal("Stop stopped enforcing an owed reply:", out)
	}
	s := &server{me: "claude"}
	s.startClaude("claude")
	if s.regErr == nil {
		t.Fatal("fixture: registration did not fail")
	}
	if out, err := s.call("presence", map[string]any{}); err != nil {
		t.Fatal("every tool refused on a line nobody bound:", err, out)
	}
	inR, inW, _ := os.Pipe()
	oldIn, oldErr := os.Stdin, os.Stderr
	t.Cleanup(func() { os.Stdin, os.Stderr = oldIn, oldErr })
	os.Stdin, os.Stderr = inR, nil
	_, _ = inW.WriteString(`{"session_id":"s"}`)
	inW.Close()
	if code := RunRewakeHook("claude", time.Second); code != 2 {
		t.Fatal("the rewake waiter did not arm on a line nobody bound:", code)
	}
}

func TestAStampIsBoundedAndNeverAnOlderRunsSample(t *testing.T) {
	seedSharedLaunch(t, "wt")
	oldF, oldB := tipFunc, tipBudget
	t.Cleanup(func() { tipFunc, tipBudget = oldF, oldB })
	release := make(chan struct{})
	tipFunc = func(string) (string, string) { <-release; return "1111111", "main" }
	tipFunc = func(string) (string, string) { return "1111111", "main" }
	if turn := renderTurn(1, "claude", "b", "x", false); !strings.Contains(turn, "\ntip: 1111111") || !strings.Contains(turn, "\npeer-tip: 1111111") {
		t.Fatal("a turn was stamped outside the bounded measurement:", turn)
	}
	tipFunc = func(string) (string, string) { <-release; return "1111111", "main" }
	tipBudget = 50 * time.Millisecond
	start := time.Now()
	if sha, _ := stampTip("claude"); sha != "" {
		t.Fatal("a timed-out stamp reported a HEAD:", sha)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatal("a stamp waited on a stalled measurement:", took)
	}
	tipBudget = 2 * time.Second
	done := make(chan string, 1)
	go func() { sha, _ := stampTip("claude"); done <- sha }()
	time.Sleep(50 * time.Millisecond) // joins the stalled run, begun before it asked
	close(release)
	if sha := <-done; sha != "" {
		t.Fatal("stamped with a sample begun before the message:", sha)
	}
}

// Review round 11 (Codex call 0010 on 96b325d): one regression each.

func TestTheCLIOfABoundSessionIsNotTakenForAConnection(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{{PID: 9, Start: "1"}, sessionA}, sessionA)
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	me := whoami(t, "claude")
	if out, err := (&server{me: me}).call("presence", map[string]any{}); me != "wt" || err != nil {
		t.Fatal("the binder's own CLI was refused its name:", me, err, out)
	}
}

func TestAnUnregisteredWaiterStopsOnceAnybodyBinds(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	inner := procID{PID: 5400, Start: "30"}
	fakeProcs(t, []procID{inner, sessionA}, sessionA)
	procAlive = func(p procID) bool { return p == sessionA || p == inner }
	if err := os.Chmod(sessionsDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sessionsDir(), 0o755) })
	if registerSession(inner, "wt") == nil {
		t.Skip("registry directory still writable (running as root?)")
	}
	alive := rewakeAlive(os.Getppid(), inner, "wt", "wt") // started inside wt
	if !alive() {
		t.Fatal("fixture: the waiter did not arm on a line nobody bound")
	}
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	if alive() {
		t.Fatal("an unregistered session's waiter kept answering once a binding appeared")
	}
}

func TestAnUnregisteredSessionCannotCreateTheFirstBinding(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	fakeProcs(t, []procID{sessionA}, sessionA)
	if err := os.Remove(sessionPath(sessionA)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessionsDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sessionsDir(), 0o755) })
	s := &server{me: "claude"}
	s.startClaude("claude")
	if s.regErr == nil {
		t.Skip("registry directory still writable (running as root?)")
	}
	if out, err := s.call("bind", map[string]any{"worktree": wt}); err == nil || anyLiveBinding() {
		t.Fatal("an unregistered session bound:", out)
	}
}

func TestConnectionsFailClosedOnAnUnreadableBindingsFile(t *testing.T) {
	_, wt := seedSharedLaunch(t, "wt")
	t.Setenv("YIP_HOME", t.TempDir())
	t.Setenv("CODEX_HOME", t.TempDir())
	prev := activeLine
	t.Cleanup(func() { activeLine = prev })
	if err := os.WriteFile(bindingsPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := (&server{me: "claude", channelMode: true}).call("presence", map[string]any{}); err == nil {
		t.Fatal("a Channels connection acted past a corrupt bindings file:", out)
	}
	if err := serveIO("claude", serveCodex, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("a Codex server started past a corrupt bindings file")
	}
	if _, err := InstallWith(wt, activeLine, "wt", true, "claude-channels", InstallOptions{}); err == nil {
		t.Fatal("installed Channels past a corrupt bindings file")
	}
}

// Review round 12 (Codex call 0010 on 7c57374): one regression each.

// crossTheFirstBind runs act in unregistered session B while A commits the
// line's first live binding, between B's "nobody is bound" check and its
// identity resolution.
func crossTheFirstBind(t *testing.T, act func()) {
	t.Helper()
	_, wt := seedSharedLaunch(t, "wt")
	inner := procID{PID: 5500, Start: "31"}
	gone := procID{PID: 5600, Start: "32"}
	fakeProcs(t, []procID{inner, sessionA}, sessionA)
	if err := writeState(bindingsPath(), Bindings{Version: 1, Boot: bootID(), Bindings: map[string]Binding{"old": {Session: gone, Launch: "claude"}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sessionsDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sessionsDir(), 0o755) })
	if registerSession(inner, "claude") == nil {
		t.Skip("registry directory still writable (running as root?)")
	}
	reached, proceed := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	procAlive = func(p procID) bool {
		if p == gone && first.CompareAndSwap(false, true) {
			close(reached)
			<-proceed
		}
		return p == sessionA || p == inner
	}
	done := make(chan struct{})
	go func() { act(); close(done) }()
	<-reached
	if _, err := Bind("claude", sessionA, wt, ""); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	<-done
	if p, ok := LoadPresence("wt"); ok {
		t.Fatal("an unregistered session acted as the name another bound meanwhile:", p)
	}
}

func TestAnUnregisteredToolCannotCrossTheFirstBind(t *testing.T) {
	var s *server
	crossTheFirstBind(t, func() {
		s = &server{me: "claude"}
		s.launch, s.session, s.regErr = "claude", procID{PID: 5500, Start: "31"}, errors.New("unwritable")
		_, _ = s.call("busy", map[string]any{"text": "B's work"})
	})
}

func TestAnUnregisteredHookCannotCrossTheFirstBind(t *testing.T) {
	crossTheFirstBind(t, func() { runHook(t, "posttooluse", `{"tool_name":"Edit"}`) })
}
