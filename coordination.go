package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// New agent operations use the same dispatch from MCP and `yip api`.
func coordinationTools() []toolDef {
	return []toolDef{
		{Name: "steal", Description: "Explicit expired-lease recovery. Requires a recorded reason, all registered runners verified dead, and peer notification. Alive or unknown runners require holder/operator coordination. Never kills jobs.", InputSchema: obj(map[string]any{"resource": str("Resource"), "reason": str("Recovery evidence and reason")}, "resource", "reason")},
		{Name: "inbox", Description: "Compact call/notes digest; stale calls stay unresolved without blocking. all includes history.", InputSchema: obj(map[string]any{"all": yesno("Include stale and resolved history")})},
		{Name: "call_status", Description: "Explicitly resolve, defer, archive, reopen (open) or link a call. Reason is durable; archive does not resolve. Notes are FYIs and never need this just to avoid a reply.", InputSchema: obj(map[string]any{"call": str("Call id"), "state": str("open, resolved, deferred, archived, linked"), "reason": str("Why"), "related": str("Other call for linked")}, "call", "state", "reason")},
		{Name: "request", Description: "Nonblocking durable resource request; returns HELD only after acquisition, otherwise queues for 24h. Watch for changes, then call again to claim. An available queue head has a 2m offer window. No permission to work while queued. Requires upgraded resource clients.", InputSchema: obj(map[string]any{"resource": str("mac or pi"), "reason": str("Purpose"), "ttl_s": num("Lease duration, default 2h"), "pids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}}, "resource", "reason")},
		{Name: "cancel_request", Description: "Cancel only your queued interest, never a held lease.", InputSchema: obj(map[string]any{"resource": str("Resource")}, "resource")},
		{Name: "queue_history", Description: "Resource request state including served, cancelled and expired entries.", InputSchema: obj(map[string]any{"resource": str("Resource")}, "resource")},
		{Name: "lease_update", Description: "Update your held lease's phase and exact runner registrations. This does not renew it. Pass every current runner PID; observation failure is unknown, not dead.", InputSchema: obj(map[string]any{"resource": str("Resource"), "phase": str("Current phase"), "pids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}}, "resource", "phase", "pids")},
		{Name: "retire", Description: "Retire your identity from default presence views; undo=true restores it. No history is deleted.", InputSchema: obj(map[string]any{"undo": yesno("Reactivate")})},
	}
}
func coordinationCall(me, name string, a map[string]any) (string, bool, error) {
	switch name {
	case "steal":
		l, e := Steal(argStr(a, "resource"), me, argStr(a, "reason"))
		if e != nil {
			return "", true, e
		}
		return fmt.Sprintf("HELD: %s recovered from %s. Prior lease and recovery evidence are retained; peer notice is in inbox/watch. No jobs were stopped.", l.Resource, l.StolenFrom), true, nil
	case "inbox":
		s, e := Inbox(me, argBool(a, "all"))
		return s, true, e
	case "call_status":
		c, e := ResolveCall(argStr(a, "call"), me)
		if e != nil {
			return "", true, e
		}
		e = SetCallStatus(c, me, argStr(a, "state"), argStr(a, "reason"), argStr(a, "related"))
		return "call state recorded", true, e
	case "retire":
		return "retirement updated", true, Retire(me, !argBool(a, "undo"))
	case "request":
		n, why := argStr(a, "resource"), argStr(a, "reason")
		if strings.TrimSpace(why) == "" {
			return "", true, fmt.Errorf("reason required")
		}
		got, l, pos, e := Request(n, me, why, time.Duration(argInt(a, "ttl_s", 7200))*time.Second, argInts(a, "pids"))
		if e != nil {
			return "", true, e
		}
		if got {
			return fmt.Sprintf("HELD: %s by %s; %s remaining", n, me, span(l.Remaining())), true, nil
		}
		return fmt.Sprintf("QUEUED: %s position %d. No lease granted. Use watch; request again when offered. Durable request expires after 24h; available offer lasts 2m. cancel_request withdraws.", n, pos), true, nil
	case "cancel_request":
		return "request cancelled (lease unchanged)", true, CancelRequest(argStr(a, "resource"), me)
	case "queue_history":
		s, e := QueueHistory(argStr(a, "resource"))
		return s, true, e
	case "lease_update":
		n := argStr(a, "resource")
		if err := validatePids(argInts(a, "pids")); err != nil {
			return "", true, err
		}
		unlock, e := resourceGuard(n)
		if e != nil {
			return "", true, e
		}
		defer unlock()
		l, ok, readErr := readLease(n)
		if readErr != nil {
			return "", true, readErr
		}
		if !ok || l.Holder != me {
			return "", true, fmt.Errorf("you do not hold %s", n)
		}
		l.Phase = argStr(a, "phase")
		l.Pids = argInts(a, "pids")
		l.Runners = captureRunners(l.Pids)
		b, _ := json.MarshalIndent(l, "", "  ")
		e = atomicReplace(leasePath(n), append(b, '\n'))
		return "phase and runners updated", true, e
	}
	return "", false, nil
}

// OS locks cover resource read/modify/write intervals, not waits. Kernel-owned
// flock is released on crash; an agent cannot strand an on-disk lock marker.
func resourceGuard(name string) (func(), error) {
	if _, ok := KnownResource(name); !ok {
		return nil, fmt.Errorf("unknown resource %q", name)
	}
	if err := ensureResourceDirs(name); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(resourcesDir(), name+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

type Runner struct {
	Host  string `json:"host"`
	PID   int    `json:"pid"`
	Start string `json:"start"`
}

func runnerStart(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "lstart=")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	b, e := cmd.Output()
	if e != nil {
		return "", e
	}
	s := strings.Join(strings.Fields(string(b)), " ")
	if s == "" {
		return "", fmt.Errorf("missing start time")
	}
	return s, nil
}
func captureRunners(pids []int) []Runner {
	host, _ := os.Hostname()
	var r []Runner
	for _, p := range pids {
		start, _ := runnerStart(p)
		r = append(r, Runner{host, p, start})
	}
	return r
}
func runnerStatus(r Runner) string {
	host, err := os.Hostname()
	if err != nil || host != r.Host || r.PID <= 0 || r.Start == "" {
		return "unknown"
	}
	if e := syscall.Kill(r.PID, 0); e == syscall.ESRCH {
		return "dead"
	} else if e != nil {
		return "unknown"
	}
	start, e := runnerStart(r.PID)
	if e != nil {
		return "unknown"
	}
	if start != r.Start {
		return "dead (PID reused)"
	}
	return "alive"
}
func diskText(path string) string {
	if path == "" {
		path = "."
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "disk: unknown"
	}
	return fmt.Sprintf("disk: %.1f GiB available at %s", float64(st.Bavail)*float64(st.Bsize)/(1<<30), path)
}

// Limit synchronous identity probes and reject ambiguous process-group inputs.
func validatePids(pids []int) error {
	if len(pids) > 16 {
		return fmt.Errorf("at most 16 runner PIDs may be registered")
	}
	seen := map[int]bool{}
	for _, p := range pids {
		if p <= 0 || seen[p] {
			return fmt.Errorf("runner PIDs must be positive and unique")
		}
		seen[p] = true
	}
	return nil
}
