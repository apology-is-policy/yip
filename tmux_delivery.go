package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type TmuxTarget struct {
	Socket  string `json:"socket"`
	Pane    string `json:"pane"`
	PID     int    `json:"pid"`
	Start   string `json:"start"`
	Runtime string `json:"runtime"`
}

var paneRE = regexp.MustCompile(`^%[0-9]+$`)

func validTmuxTarget(t *TmuxTarget) bool {
	return t != nil && filepath.IsAbs(t.Socket) && paneRE.MatchString(t.Pane) && t.PID > 0 && t.Start != "" && (t.Runtime == "claude" || t.Runtime == "codex")
}
func inspectTmux(ctx context.Context, socket, pane string) (TmuxTarget, error) {
	t := TmuxTarget{Socket: socket, Pane: pane}
	if !filepath.IsAbs(socket) || !paneRE.MatchString(pane) {
		return t, fmt.Errorf("require absolute socket path and exact %%pane ID")
	}
	st, e := os.Stat(socket)
	if e != nil {
		return t, e
	}
	if st.Mode()&os.ModeSocket == 0 {
		return t, fmt.Errorf("tmux socket is not a socket")
	}
	out, e := exec.CommandContext(ctx, "tmux", "-S", socket, "display-message", "-p", "-t", pane, "#{pane_id}\t#{pane_pid}\t#{pane_current_command}\t#{pane_dead}\t#{pane_in_mode}").Output()
	if e != nil {
		return t, fmt.Errorf("inspect tmux pane: %w", e)
	}
	fields := strings.Split(strings.TrimSpace(string(out)), "\t")
	if len(fields) != 5 || fields[0] != pane || fields[3] != "0" || fields[4] != "0" {
		return t, fmt.Errorf("pane missing, dead or in a terminal mode")
	}
	t.PID, e = strconv.Atoi(fields[1])
	if e != nil {
		return t, e
	}
	t.Runtime = fields[2]
	if t.Runtime != "claude" && t.Runtime != "codex" {
		return t, fmt.Errorf("pane must directly run claude or codex")
	}
	comm, e := exec.CommandContext(ctx, "ps", "-p", fields[1], "-o", "comm=").Output()
	if e != nil {
		return t, e
	}
	if filepath.Base(strings.TrimSpace(string(comm))) != t.Runtime {
		return t, fmt.Errorf("pane PID is a shell/wrapper; start pane with exec claude or exec codex")
	}
	t.Start, e = runnerStart(t.PID)
	return t, e
}
func RegisterTmux(agent, socket, pane string, replay bool) error {
	if !validComponent(agent) {
		return fmt.Errorf("invalid agent")
	}
	canonical, e := filepath.EvalSymlinks(socket)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target, e := inspectTmux(ctx, canonical, pane)
	if e != nil {
		return e
	}
	return updateJSON(endpointPath(agent), func(ep *Endpoint) error {
		if ep.Version != 0 {
			if ep.Version != 1 || ep.Agent != agent || ep.Runtime != "tmux" || !validTmuxTarget(ep.Tmux) || *ep.Tmux != target {
				return fmt.Errorf("existing endpoint differs; use a distinct identity and preserve its receipts")
			}
			return nil
		}
		*ep = Endpoint{Version: 1, Agent: agent, Runtime: "tmux", Thread: target.Pane, Tmux: &target, Known: map[string]bool{}}
		if replay {
			reconcileEndpoint(ep)
		} else {
			for k := range deliverySnapshot(agent) {
				ep.Known[k] = true
			}
		}
		return nil
	})
}
func tmuxSender(target TmuxTarget) deliverySender {
	return func(ctx context.Context, _ string, text string) error {
		current, e := inspectTmux(ctx, target.Socket, target.Pane)
		if e != nil {
			return e
		}
		if current != target {
			return fmt.Errorf("tmux pane/process identity changed; refusing keys")
		}
		// Literal text, no shell interpolation and no terminal control bytes. Sending
		// Enter is separate; any partial outcome remains unknown, never auto-retried.
		text = strings.Join(strings.Fields(terminalText(text)), " ")
		if e = exec.CommandContext(ctx, "tmux", "-S", target.Socket, "send-keys", "-t", target.Pane, "-l", "--", text).Run(); e != nil {
			return e
		}
		current, e = inspectTmux(ctx, target.Socket, target.Pane)
		if e != nil {
			return e
		}
		if current != target {
			return fmt.Errorf("pane changed after text write; inspect manually")
		}
		return exec.CommandContext(ctx, "tmux", "-S", target.Socket, "send-keys", "-t", target.Pane, "Enter").Run()
	}
}
func DispatchTmux(agent string) (int, error) {
	ep, e := readEndpoint(agent)
	if e != nil {
		return 0, e
	}
	if ep.Runtime != "tmux" || !validTmuxTarget(ep.Tmux) {
		return 0, fmt.Errorf("no tmux endpoint")
	}
	return dispatchEndpoint(agent, "tmux", "", tmuxSender(*ep.Tmux))
}
