package main

// Claude rewake: waking an idle Claude session with nothing but hooks.
//
// Claude Code's `asyncRewake` command hooks run in the background, and one
// that exits with code 2 "wakes Claude immediately even when the session is
// idle", showing its stderr as a system reminder (code.claude.com/docs/en/
// hooks). That is the whole transport: no development channel, no tmux, no
// keystrokes into a terminal that might be showing a permission dialog.
//
// `yip hook rewake` is that hook. Installed on SessionStart and Stop, it is
// armed whenever the session starts or finishes a turn, and:
//   - holds a per-identity kernel lock; a second waiter exits at once, so the
//     Stop of every turn does not stack another process;
//   - reads the same durable delivery records as Codex and Channels, marks a
//     batch sent, prints it to stderr and exits 2;
//   - exits 0 (shows nothing) at its deadline, which sits inside the hook's
//     own timeout -- Claude enforces that timeout on rewake hooks -- or as soon
//     as its parent session has gone, so a waiter orphaned by an exited Claude
//     never marks notices sent into nowhere.
//
// It is not a subscription. After a quiet window the session is unarmed until
// it next starts or ends a turn, when the ordinary hooks also report what
// arrived. Status says which it is.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const defaultWakeWindow = 4 * time.Hour

// The waiter stops this long before Claude's hook timeout would kill it, so
// the end of a window is always a clean exit 0 rather than a killed sender.
const rewakeMargin = time.Minute

func rewakeLockPath(agent string) string {
	return filepath.Join(Root(), "delivery", agent+".rewake.lock")
}

func rewakeOwnerPath(agent string) string {
	return filepath.Join(Root(), "delivery", agent+".rewake.owner")
}

func rewakeArmed(agent string) bool {
	return validComponent(agent) && lockHeld(rewakeLockPath(agent))
}

func rewakeStatus(agent string) string {
	if rewakeArmed(agent) {
		return "Claude rewake armed; an idle session wakes on new notices"
	}
	return "Claude rewake not armed; notices wait for its next turn (re-arms when a turn starts or ends)"
}

// rewakeHookEntry is the background handler the claude-rewake runtime adds
// to SessionStart and Stop.
func rewakeHookEntry(bin, line, agent string, window time.Duration) map[string]any {
	wait := window - rewakeMargin
	command := fmt.Sprintf("[ ! -x %s ] || exec %s hook rewake --runtime claude-rewake --line %s --as %s --for %s  %s",
		bin, bin, shellQuote(line), shellQuote(agent), wait, hookMarker)
	return map[string]any{
		"type":    "command",
		"command": command,
		// exec above makes this process Claude's direct child, which is what
		// lets the waiter notice the session exiting.
		"asyncRewake": true,
		"timeout":     int(window / time.Second),
	}
}

// RunRewake is the body of `yip hook rewake`; it returns the exit code.
// parentAlive reports whether the session that started the waiter still runs.
func RunRewake(agent string, wait time.Duration, session string, stderr io.Writer, parentAlive func() bool, interval time.Duration) int {
	ep, err := readEndpoint(agent)
	if err != nil || ep.Runtime != "claude-rewake" {
		return 0
	}
	// The waiter's owner is the Claude process that ran the hook -- not the
	// conversation, which a resumed session (a new process) shares.
	var owner procID
	if anc := processAncestors(); len(anc) > 0 {
		owner = anc[0]
	}
	unlock, held, err := claimRewake(agent, owner)
	// Armed already. By this process (every Stop re-arms): nothing to do. By
	// another, which may be leaving this name -- it rebound, unbound or exited
	// -- and steps aside within a poll: wait a few polls to take over, or this
	// session would sit unarmed until its next turn.
	for retry := time.Now().Add(3 * interval); err != nil; unlock, held, err = claimRewake(agent, owner) {
		if held == owner || !time.Now().Before(retry) {
			return 0
		}
		time.Sleep(interval / 4)
	}
	defer unlock()
	if session != "" && session != ep.Thread {
		_ = editEndpoint(agent, func(ep *Endpoint) error { ep.Thread = session; return nil })
	}
	deadline := time.Now().Add(wait)
	for {
		// Checked and dispatched under the bindings guard: a bind cannot land
		// between "still this session's identity" and "notices marked sent".
		unlockB, err := fileGuard(bindingsPath())
		if err != nil {
			return 0
		}
		if !parentAlive() {
			unlockB()
			return 0 // nobody to wake: leave notices pending
		}
		var message string
		n, err := dispatchEndpoint(agent, "claude-rewake", "", func(_ context.Context, _ string, text string) error {
			message = text
			return nil
		})
		unlockB()
		if err != nil {
			return 0
		}
		if n > 0 {
			fmt.Fprintln(stderr, message)
			return 2
		}
		if !time.Now().Before(deadline) {
			return 0
		}
		time.Sleep(interval)
	}
}

// claimRewake takes the identity's waiter lock and records owner as its
// holder, or reports the holder -- under one guard, so an owner read while
// the lock is held always names the process holding it.
func claimRewake(agent string, owner procID) (unlock func(), held procID, err error) {
	guard, err := fileGuard(rewakeOwnerPath(agent))
	if err != nil {
		return nil, procID{}, err
	}
	defer guard()
	if unlock, err = holdLock(rewakeLockPath(agent)); err != nil {
		_ = readState(rewakeOwnerPath(agent), &held)
		return nil, held, err
	}
	if err = writeState(rewakeOwnerPath(agent), owner); err != nil {
		unlock()
		return nil, procID{}, err
	}
	return unlock, owner, nil
}

// RunRewakeHook wires RunRewake to the process: stdin carries Claude's hook
// input, stderr becomes the system reminder, and the parent is the session.
func RunRewakeHook(override string, wait time.Duration) int {
	in := readHookInput()
	launch, err := launchIdentity(override, in.Cwd)
	if err != nil {
		return 0
	}
	if _, err := os.Stat(Root()); err != nil {
		return 0
	}
	_ = registerSession(parentSession(), launch) // exec'd: the parent is the session
	me, err := boundIdentity(launch)
	if err != nil {
		return 0
	}
	if wait <= 0 || wait > 24*time.Hour {
		wait = defaultWakeWindow - rewakeMargin
	}
	return RunRewake(me, wait, in.SessionID, os.Stderr, rewakeAlive(os.Getppid(), launch, me), 2*time.Second)
}

// rewakeAlive: the session that started the waiter still runs AND still
// answers as me. One that binds (or unbinds) mid-window has stopped being me:
// the waiter steps aside, leaving notices pending, so the session's next turn
// arms a waiter for the identity it answers to now.
func rewakeAlive(ppid int, launch, me string) func() bool {
	return func() bool {
		cur, err := boundIdentity(launch)
		return ppid > 1 && os.Getppid() == ppid && err == nil && cur == me
	}
}

// pushReachable: would a notice for agent reach a running session now?
func pushReachable(agent string) bool {
	ep, err := readEndpoint(agent)
	if err != nil || ep.Paused || Retired(agent) {
		return false
	}
	switch ep.Runtime {
	case "claude-channels":
		return channelPreferred(agent)
	case "codex":
		return codexBindingAlive(ep)
	case "claude-rewake":
		return rewakeArmed(agent)
	}
	return false
}

// peerReachable: recently active, or connected for push delivery. A Codex
// reviewer idle for an hour is still reachable when its chat is bound.
func peerReachable(agent string) bool {
	p, _ := LoadPresence(agent)
	return p.Live() || pushReachable(agent)
}
