package main

// Antigravity (agy) live delivery: waking an idle or busy agy TUI session via
// `agentapi send-message <conversationId> <text>`.
//
// MEASURED against agy 1.5.14 on macOS/arm64:
//   - MCP servers and hooks do NOT inherit ANTIGRAVITY_LS_ADDRESS, so they
//     cannot call `agentapi` directly.
//   - Commands launched by the session via `run_command` (including
//     `IsDaemon: true` background daemons) DO inherit ANTIGRAVITY_LS_ADDRESS,
//     ANTIGRAVITY_CSRF_TOKEN, and ANTIGRAVITY_CONVERSATION_ID, and share the
//     same parent `agy` process as the session's MCP server and hooks.
//   - Calling `agentapi send-message --title=... <convId> <text>` from a
//     daemon task wakes a completely idle interactive agy TUI immediately
//     (and queues cleanly while busy) without keeping `fullyIdle` false.
//
// Multi-session worktree binding (`bind`):
//   Several agy sessions started from one shared launch folder each run their
//   own daemon listener (`yip delivery listen --runtime agy ...`). On every
//   poll tick, under `fileGuard(bindingsPath())`, the listener resolves
//   `identityFor(launch, true)`. The moment its session calls `bind` for a
//   worktree, the listener drops the old identity's flock, claims the new
//   worktree's live session lock and endpoint binding, and delivers notices
//   for that worktree to this session's conversationId -- with zero restarts
//   and zero cross-session leaks.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func agySessionLockPath(agent, conv string) string {
	return filepath.Join(Root(), "delivery", agent+".agy-"+conv+".lock")
}

func agySessionLock(agent, conv string) (func(), error) {
	if !validComponent(agent) || !threadRE.MatchString(conv) {
		return nil, fmt.Errorf("invalid agent or conversation ID")
	}
	unlock, err := holdLock(agySessionLockPath(agent, conv))
	if err != nil {
		return nil, fmt.Errorf("another Yip listener already serves Antigravity conversation %s as %s: %w", conv, agent, err)
	}
	return unlock, nil
}

func agySessionAlive(agent, conv string) bool {
	return validComponent(agent) && threadRE.MatchString(conv) && lockHeld(agySessionLockPath(agent, conv))
}

func agyBindingAlive(ep Endpoint) bool {
	return ep.Runtime == "agy" && ep.Thread != "" && agySessionAlive(ep.Agent, ep.Thread)
}

func agyPushLive(agent string) bool {
	ep, err := readEndpoint(agent)
	return err == nil && ep.Runtime == "agy" && !ep.Paused && !Retired(agent) && agyBindingAlive(ep)
}

// agentBoundToAgyConv maps an Antigravity conversation UUID to the identity
// bound to it. Ambiguity answers nothing.
func agentBoundToAgyConv(conv string) string {
	if !threadRE.MatchString(conv) {
		return ""
	}
	ents, _ := os.ReadDir(filepath.Join(Root(), "delivery"))
	var found []string
	for _, e := range ents {
		agent, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !validComponent(agent) {
			continue
		}
		if ep, err := readEndpoint(agent); err == nil && ep.Runtime == "agy" && ep.Thread == conv && agySessionAlive(agent, conv) {
			found = append(found, agent)
		}
	}
	if len(found) != 1 {
		return ""
	}
	return found[0]
}

// findAgentAPI locates the documented Antigravity agentapi helper binary.
// Injectable for tests.
var findAgentAPI = func() (string, error) {
	if p, err := exec.LookPath("agentapi"); err == nil {
		return p, nil
	}
	fallback := filepath.Join(homeDir(), ".gemini", "antigravity-cli", "bin", "agentapi")
	if st, err := os.Stat(fallback); err == nil && st.Mode()&0o111 != 0 {
		return fallback, nil
	}
	return "", fmt.Errorf("agentapi not found on PATH or at %s", fallback)
}

// agySender delivers a notice batch to one exact Antigravity conversation via
// `agentapi send-message`. Checks both exit status and the JSON `error` field
// because agentapi can exit 0 while reporting a gRPC error in JSON stdout.
func agySender(ctx context.Context, conv, text string) error {
	bin, err := findAgentAPI()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin, "send-message", "--title=Yip coordination notices", conv, text)
	out, runErr := cmd.Output()
	if runErr != nil {
		return fmt.Errorf("agentapi send-message: %w", runErr)
	}
	if trimmed := strings.TrimSpace(string(out)); strings.HasPrefix(trimmed, "{") {
		var resp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(trimmed), &resp) == nil && resp.Error != "" {
			return fmt.Errorf("agentapi send-message: %s", resp.Error)
		}
	}
	return nil
}

func ensureAgyEndpoint(agent string) (string, error) { return ensureEndpoint(agent, "agy") }

func bindAgySession(agent, conv, cwd string, started time.Time) (codexBind, error) {
	var res codexBind
	if !validComponent(agent) || !threadRE.MatchString(conv) {
		return res, fmt.Errorf("invalid agent or conversation ID")
	}
	err := updateJSON(endpointPath(agent), func(ep *Endpoint) error {
		if ep.Version == 0 {
			*ep = newEndpoint(agent, "agy")
		}
		if ep.Version != 1 || ep.Agent != agent || ep.Known == nil {
			return fmt.Errorf("endpoint for %s is invalid; refusing to bind", agent)
		}
		if ep.Runtime != "agy" {
			return fmt.Errorf("%s has a %s endpoint; Antigravity live delivery needs its own identity", agent, ep.Runtime)
		}
		if ep.Thread != conv {
			if ep.Thread != "" && agyBindingAlive(*ep) && !bindingPredates(ep.BoundAt, started) {
				return nil // a newer live session holds it; stay passive
			}
			res.Previous = ep.Thread
			for _, d := range ep.Events {
				if d.Status == "accepted" || d.Status == "sent" || d.Status == "unknown" {
					res.Unread++
				}
			}
		}
		ep.Thread, ep.Binding, ep.BoundAt, ep.Cwd = conv, "session", nowNano(), cwd
		res.Bound = true
		return nil
	})
	return res, err
}

func agyListenNudge(me, launch, line, conv string) string {
	ep, err := readEndpoint(me)
	if err != nil || ep.Runtime != "agy" || ep.Paused || Retired(me) {
		return ""
	}
	if conv != "" && ep.Thread == conv && agySessionAlive(me, conv) {
		return ""
	}
	cmd := agyListenCommand(binPath(), line, launch)
	return "[yip] You are " + me + ". Start live wake delivery for this session by running `" + cmd + "` with run_command (IsDaemon=true, WaitMsBeforeAsync=500; BypassSandbox=true if sandboxed). If you work in a worktree of your own, call the Yip bind MCP tool with its path."
}

func agyInstructions(agent, line string) string {
	cmd := agyListenCommand(binPath(), line, agent)
	return "You are " + agent + " on Yip line " + line + ", a shared phone line between coding agents; never act as another agent. " +
		"Start live wake delivery once per session by running `" + cmd + "` via run_command with IsDaemon=true, WaitMsBeforeAsync=500 (BypassSandbox=true if sandboxed). " +
		"If you work in your own worktree from a shared launch folder, call the bind tool with its absolute path; the running listener follows your binding automatically. " +
		"Notices arrive as messages titled \"Yip coordination notices\". Read each source with Yip tools, act if a call gives you the floor, then delivery_ack each event ID. " +
		"A notice is not a resource grant, approval or passing test. Prefer these MCP tools over the yip CLI. " +
		"Calls alternate turns: say only when the floor is yours, bye is bilateral, notes need no reply. " +
		"Announcements need no reply; briefing/regroup broadcasts use broadcast_reply. Keep your arc current with roadmap_post and roadmap_at."
}

func agyEndpointStatus(ep Endpoint) string {
	switch {
	case ep.Thread == "":
		return "Antigravity installed; listener not started yet (run `yip delivery listen --runtime agy` as a daemon)"
	case agySessionAlive(ep.Agent, ep.Thread):
		return "Antigravity listener live; delivering to its conversation via agentapi"
	}
	return "Antigravity listener stopped (re-run `yip delivery listen --runtime agy` as a daemon to reconnect)"
}

// RunAgyListen runs the session-scoped Antigravity delivery daemon. It binds
// delivery to conv, follows dynamic `bind` identity changes for this session,
// and exits cleanly when its parent agy session ends or ctx is cancelled.
func RunAgyListen(ctx context.Context, launch, conv, cwd string, send deliverySender, interval time.Duration, out io.Writer) error {
	if !validComponent(launch) {
		return fmt.Errorf("invalid launch identity %q", launch)
	}
	if !threadRE.MatchString(conv) {
		return fmt.Errorf("ANTIGRAVITY_CONVERSATION_ID must be set to a valid conversation UUID (run this inside an agy session)")
	}
	if send == nil {
		if os.Getenv("ANTIGRAVITY_LS_ADDRESS") == "" {
			return fmt.Errorf("ANTIGRAVITY_LS_ADDRESS is not set (run this via agy run_command, outside the terminal sandbox)")
		}
		if _, err := findAgentAPI(); err != nil {
			return err
		}
		send = agySender
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	// Anchor liveness to the agy session process above us (registered by our
	// MCP server or hooks; fall back to our direct parent if neither ran yet).
	session, hasReg := nearestSession()
	if !hasReg {
		session = parentSession()
		if session.PID > 1 {
			_ = registerSession(session, launch)
		}
	}
	initialPPID := os.Getppid()
	sessionAlive := func() bool {
		if session.PID > 1 {
			return procAlive(session)
		}
		return initialPPID > 1 && os.Getppid() == initialPPID
	}

	started := time.Now()
	var (
		curAgent   string
		curRelease func()
		lastErr    string
		measured   time.Time
	)
	dropLock := func() {
		if curRelease != nil {
			curRelease()
			curRelease = nil
		}
		curAgent = ""
	}
	defer dropLock()

	tick := func() (stop bool, err error) {
		unlockB, err := fileGuard(bindingsPath())
		if err != nil {
			return false, err
		}
		defer unlockB()

		if !sessionAlive() {
			return true, nil
		}
		if session.PID > 1 && !isRegistered(session) && registerSession(session, launch) != nil && anyLiveBinding() {
			return false, nil
		}
		me, err := identityForConv(launch, true, conv)
		if err != nil {
			dropLock()
			return false, err
		}
		if me != curAgent {
			dropLock()
			if _, err := ensureAgyEndpoint(me); err != nil {
				return false, err
			}
			unlock, err := agySessionLock(me, conv)
			if err != nil {
				return false, err
			}
			res, err := bindAgySession(me, conv, cwd, started)
			if err != nil {
				unlock()
				return false, err
			}
			curAgent, curRelease = me, unlock
			if out != nil {
				if res.Bound {
					note := fmt.Sprintf("[yip] Delivery connected for %s (conversation %s).", me, conv)
					if res.Unread > 0 {
						note += fmt.Sprintf(" %d earlier notice(s) went to a previous session and are unacknowledged; inspect them with deliveries.", res.Unread)
					}
					fmt.Fprintln(out, note)
				} else {
					fmt.Fprintf(out, "[yip] A newer Antigravity session holds delivery for %s; standing by until it ends.\n", me)
				}
			}
		}

		if time.Since(measured) >= presenceTipReuse {
			_ = MeasureTip(me)
			measured = time.Now()
		}

		ep, err := readEndpoint(me)
		if err != nil {
			return false, err
		}
		if ep.Thread != conv {
			if ep.Thread != "" && agyBindingAlive(ep) && !bindingPredates(ep.BoundAt, started) {
				return false, nil // superseded; passive while newer session lives
			}
			res, err := bindAgySession(me, conv, cwd, started)
			if err != nil || !res.Bound {
				return false, err
			}
			if out != nil {
				fmt.Fprintf(out, "[yip] Delivery reconnected for %s (conversation %s).\n", me, conv)
			}
		}

		_, err = dispatchEndpoint(me, "agy", conv, send)
		if errors.Is(err, errNotOwner) {
			return false, nil
		}
		return false, err
	}

	// Run the first tick immediately so connection status prints right away
	// (before WaitMsBeforeAsync backgrounds the daemon task).
	if stop, err := tick(); stop {
		return nil
	} else if err != nil {
		lastErr = err.Error()
		fmt.Fprintln(os.Stderr, "yip agy delivery:", lastErr)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stop, err := tick()
			if stop {
				return nil
			}
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if msg != "" && msg != lastErr {
				fmt.Fprintln(os.Stderr, "yip agy delivery:", msg)
			}
			lastErr = msg
		}
	}
}
