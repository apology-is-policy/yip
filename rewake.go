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
	unlock, err := holdLock(rewakeLockPath(agent))
	if err != nil {
		return 0 // another waiter is armed for this identity
	}
	defer unlock()
	if session != "" && session != ep.Thread {
		_ = editEndpoint(agent, func(ep *Endpoint) error { ep.Thread = session; return nil })
	}
	deadline := time.Now().Add(wait)
	for {
		if !parentAlive() {
			return 0 // nobody to wake: leave notices pending
		}
		var message string
		n, err := dispatchEndpoint(agent, "claude-rewake", "", func(_ context.Context, _ string, text string) error {
			message = text
			return nil
		})
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

// RunRewakeHook wires RunRewake to the process: stdin carries Claude's hook
// input, stderr becomes the system reminder, and the parent is the session.
func RunRewakeHook(override string, wait time.Duration) int {
	in := readHookInput()
	me, err := WhoAmI(override, in.Cwd)
	if err != nil {
		return 0
	}
	if _, err := os.Stat(Root()); err != nil {
		return 0
	}
	if wait <= 0 || wait > 24*time.Hour {
		wait = defaultWakeWindow - rewakeMargin
	}
	ppid := os.Getppid()
	alive := func() bool { return ppid > 1 && os.Getppid() == ppid }
	return RunRewake(me, wait, in.SessionID, os.Stderr, alive, 2*time.Second)
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
