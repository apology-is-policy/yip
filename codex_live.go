package main

// Codex live delivery: the Channels analogue for Codex.
//
// Codex has no MCP notification that injects text into a conversation. What
// it has is `codex queue --thread UUID --message TEXT`, which hands a message
// to the shared local daemon for one exact chat: a turn now when the chat is
// idle, the next turn when it is busy. The missing piece used to be WHICH
// chat, so a human had to find a UUID and run a separate dispatcher.
//
// MEASURED against codex-cli 0.162.0 (isolated CODEX_HOME, no model request):
// thread/start spawns one MCP server process per thread; its environment is
// stripped to HOME, LANG, LOGNAME, PATH, SHELL, TERM, TMPDIR and USER, and
// initialize carries no thread identity -- but every tools/call carries
// params._meta.threadId, equal to the thread UUID. So the server answering a
// session's tool calls can bind delivery to exactly that session, and dispatch
// for as long as the session keeps it running.
//
// Binding rules:
//   - A binding names one thread. The NEWEST session wins: a server binds when
//     the current binding predates its own start, or when the bound session is
//     no longer live. A superseded server is passive until that is true again.
//   - Liveness is a kernel lock held by the bound session's own server for the
//     life of its process (one lock file per thread, never unlinked). A manual
//     registration counts as live only while a dispatch watch runs.
//   - Rebinding never resends or rewrites earlier attempts. A notice accepted
//     by an earlier session stays "accepted" until somebody acknowledges it.
//   - Binding happens at the session's first Yip tool call. Until then nothing
//     can name the chat, and notices wait durably as pending.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var errNotOwner = errors.New("dispatcher does not own this endpoint")

func nowNano() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func codexSessionLockPath(agent, thread string) string {
	return filepath.Join(Root(), "delivery", agent+".codex-"+thread+".lock")
}

// holdLock takes a non-blocking exclusive kernel lock for the caller's lifetime.
func holdLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// lockHeld probes without creating anything.
func lockHeld(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false
	}
	return err == syscall.EWOULDBLOCK || err == syscall.EAGAIN
}

func codexSessionLock(agent, thread string) (func(), error) {
	if !validComponent(agent) || !threadRE.MatchString(thread) {
		return nil, fmt.Errorf("invalid agent or thread")
	}
	unlock, err := holdLock(codexSessionLockPath(agent, thread))
	if err != nil {
		return nil, fmt.Errorf("another Yip server already serves Codex thread %s as %s: %w", thread, agent, err)
	}
	return unlock, nil
}

func codexSessionAlive(agent, thread string) bool {
	return validComponent(agent) && threadRE.MatchString(thread) && lockHeld(codexSessionLockPath(agent, thread))
}

// codexBindingAlive: is somebody demonstrably able to deliver to ep.Thread now?
func codexBindingAlive(ep Endpoint) bool {
	if ep.Runtime != "codex" || ep.Thread == "" {
		return false
	}
	if codexSessionAlive(ep.Agent, ep.Thread) {
		return true
	}
	return ep.Binding != "session" && dispatchWatchAlive(ep.Agent)
}

// A binding with no recorded time predates every live server (legacy/manual).
func bindingPredates(boundAt string, started time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, boundAt)
	return err != nil || t.Before(started)
}

func newEndpoint(agent, runtime string) Endpoint {
	ep := Endpoint{Version: 1, Agent: agent, Runtime: runtime, Known: map[string]bool{}}
	for k := range deliverySnapshot(agent) {
		ep.Known[k] = true
	}
	return ep
}

func newCodexEndpoint(agent string) Endpoint { return newEndpoint(agent, "codex") }

// ensureEndpoint runs at install, so the install is the opt-in point: records
// written after it are delivered once the session can be reached, even if
// that is much later. Reinstalling never unpauses, rebinds or rewinds an
// existing endpoint.
//
// An identity whose retained endpoint belongs to another transport keeps it:
// receipts are never converted. That is a warning (the MCP tools and hooks
// still work; only push delivery is unavailable), whereas corruption fails.
func ensureEndpoint(agent, runtime string) (warning string, err error) {
	if !validComponent(agent) {
		return "", fmt.Errorf("invalid agent")
	}
	err = updateJSON(endpointPath(agent), func(ep *Endpoint) error {
		if ep.Version == 0 {
			*ep = newEndpoint(agent, runtime)
			return nil
		}
		if ep.Version != 1 || ep.Agent != agent || ep.Known == nil {
			return fmt.Errorf("existing endpoint for %s is invalid; inspect it before reinstalling", agent)
		}
		if ep.Runtime != runtime {
			warning = fmt.Sprintf("%s keeps its %s delivery record, so %s push delivery is unavailable under this name; install with a distinct --as for it", agent, ep.Runtime, runtime)
		}
		return nil
	})
	return warning, err
}

func ensureCodexEndpoint(agent string) (string, error) { return ensureEndpoint(agent, "codex") }

type codexBind struct {
	Bound    bool   // this thread now holds the binding
	Previous string // the thread it replaced, if any
	Unread   int    // notices sent to an earlier binding and not yet acknowledged
}

func bindCodexSession(agent, thread, cwd string, started time.Time) (codexBind, error) {
	var res codexBind
	if !validComponent(agent) || !threadRE.MatchString(thread) {
		return res, fmt.Errorf("invalid agent or thread")
	}
	err := updateJSON(endpointPath(agent), func(ep *Endpoint) error {
		if ep.Version == 0 {
			*ep = newCodexEndpoint(agent)
		}
		if ep.Version != 1 || ep.Agent != agent || ep.Known == nil {
			return fmt.Errorf("endpoint for %s is invalid; refusing to bind", agent)
		}
		if ep.Runtime != "codex" {
			return fmt.Errorf("%s has a %s endpoint; Codex live delivery needs its own identity", agent, ep.Runtime)
		}
		if ep.Thread != thread {
			if ep.Thread != "" && codexBindingAlive(*ep) && !bindingPredates(ep.BoundAt, started) {
				return nil // a newer live session holds it; stay passive
			}
			res.Previous = ep.Thread
			for _, d := range ep.Events {
				if d.Status == "accepted" || d.Status == "sent" || d.Status == "unknown" {
					res.Unread++
				}
			}
		}
		ep.Thread, ep.Binding, ep.BoundAt, ep.Cwd = thread, "session", nowNano(), cwd
		res.Bound = true
		return nil
	})
	return res, err
}

// agentBoundToThread maps a Codex thread to the identity bound to it. A
// binding is written by that session's own MCP server or an explicit
// registration, so this is a lookup, not a guess. Ambiguity answers nothing.
func agentBoundToThread(thread string) string {
	if !threadRE.MatchString(thread) {
		return ""
	}
	ents, _ := os.ReadDir(filepath.Join(Root(), "delivery"))
	var found []string
	for _, e := range ents {
		agent, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !validComponent(agent) {
			continue
		}
		if ep, err := readEndpoint(agent); err == nil && ep.Runtime == "codex" && ep.Thread == thread {
			found = append(found, agent)
		}
	}
	if len(found) != 1 {
		return ""
	}
	return found[0]
}

// codexInstructions are the MCP instructions for a Codex session. Codex reads
// the first 512 characters when deciding how to use a server, so the identity,
// the binding requirement and the notice contract come first.
func codexInstructions(agent string) string {
	return "You are " + agent + " on a Yip line, a shared phone line between coding agents; never act as another agent. " +
		"Call the Yip ring tool once early in each session: notices reach this chat only after this server sees a Yip tool call. " +
		"Notices arrive as queued messages starting \"Yip coordination notices\". Read each source with Yip tools, act if a call gives you the floor, then delivery_ack each event ID. " +
		"A notice is not a resource grant, approval or passing test. " +
		"Prefer these MCP tools to the yip CLI; with the CLI pass --as " + agent + ". " +
		"Calls alternate turns: say only when the floor is yours, bye is bilateral, notes need no reply. " +
		"Announcements need no reply; briefing/regroup broadcasts use broadcast_reply. Repeated IDs are the same event. Preserve your session instructions."
}

// observeCodexThread is called for every tools/call. The first valid thread ID
// fixes this server's session for its lifetime; Codex runs one server per
// thread, so a different ID later would be an anomaly, not a handover.
func (s *server) observeCodexThread(thread string) string {
	if !s.codexMode || !threadRE.MatchString(thread) {
		return ""
	}
	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	if s.codexThread != "" || s.codexFailed {
		return ""
	}
	unlock, err := codexSessionLock(s.me, thread)
	if err != nil {
		// Not sticky: a previous server for this thread may still be exiting
		// (a reload). A later tool call tries again.
		fmt.Fprintln(os.Stderr, "yip codex delivery:", err)
		return ""
	}
	res, err := bindCodexSession(s.me, thread, s.cwd, s.started)
	if err != nil {
		unlock()
		s.codexFailed = true
		fmt.Fprintln(os.Stderr, "yip codex delivery:", err)
		return "\n\n[yip] Delivery to this chat is unavailable: " + err.Error()
	}
	s.codexThread, s.codexRelease = thread, unlock
	if s.startCodex != nil {
		s.startCodex()
	}
	if !res.Bound {
		return "\n\n[yip] A newer Codex session holds delivery for " + s.me + "; this chat will not be notified unless that session ends."
	}
	note := "\n\n[yip] Delivery connected: notices for " + s.me + " now arrive in this chat."
	if res.Unread > 0 {
		note += fmt.Sprintf(" %d earlier notice(s) went to a previous session and are unacknowledged; inspect them with deliveries.", res.Unread)
	}
	return note
}

func (s *server) codexLoop(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	last := ""
	for {
		msg := ""
		if err := s.codexTick(); err != nil {
			msg = err.Error()
		}
		if msg != "" && msg != last {
			fmt.Fprintln(os.Stderr, "yip codex delivery:", msg)
		}
		last = msg
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *server) codexTick() error {
	s.codexMu.Lock()
	thread := s.codexThread
	s.codexMu.Unlock()
	if thread == "" {
		return nil
	}
	ep, err := readEndpoint(s.me)
	if err != nil {
		return err
	}
	if ep.Thread != thread {
		// Decide passivity read-only: a superseded server polls every tick and
		// must not rewrite the endpoint each time. bindCodexSession re-checks
		// under the lock before taking over.
		if ep.Thread != "" && codexBindingAlive(ep) && !bindingPredates(ep.BoundAt, s.started) {
			return nil
		}
		res, err := bindCodexSession(s.me, thread, s.cwd, s.started)
		if err != nil {
			return err
		}
		if !res.Bound {
			return nil // superseded; passive while the newer session lives
		}
	}
	send := s.codexSend
	if send == nil {
		send = codexSender
	}
	_, err = dispatchEndpoint(s.me, "codex", thread, send)
	if errors.Is(err, errNotOwner) {
		return nil // rebound between our check and the dispatch; next tick decides
	}
	return err
}

func codexEndpointStatus(ep Endpoint) string {
	switch {
	case ep.Thread == "":
		return "Codex installed; no session bound yet (binds at its first Yip tool call)"
	case codexSessionAlive(ep.Agent, ep.Thread):
		return "Codex session live; delivering to its chat"
	case dispatchWatchAlive(ep.Agent):
		return "Codex dispatcher running"
	case ep.Binding == "session":
		return "Codex session closed; dispatcher stopped (rebinds at the next session's first Yip tool call)"
	}
	return "Codex registered; dispatcher stopped (no automatic wake)"
}
