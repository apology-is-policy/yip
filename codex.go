package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const codexBegin = "# BEGIN YIP MANAGED MCP\n"
const codexEnd = "# END YIP MANAGED MCP\n"

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// The shared Codex daemon may predate the invoking terminal and has its own
// environment. Bind the installation's actual state paths in both transports.
func codexStatePaths() (string, string) {
	root, home := Root(), yipHome()
	if absolute, err := filepath.Abs(root); err == nil {
		root = absolute
	}
	if absolute, err := filepath.Abs(home); err == nil {
		home = absolute
	}
	return root, home
}
func codexConfig(existing, bin, line, agent string, remove bool) (string, error) {
	start := strings.Index(existing, codexBegin)
	if start >= 0 {
		end := strings.Index(existing[start:], codexEnd)
		if end < 0 {
			return "", fmt.Errorf("incomplete Yip config block; refusing to overwrite")
		}
		existing = existing[:start] + existing[start+end+len(codexEnd):]
	}
	if strings.Contains(existing, codexBegin) || strings.Contains(existing, codexEnd) {
		return "", fmt.Errorf("duplicate or incomplete Yip config blocks")
	}
	// Without a TOML parser, conservatively refuse any unmanaged Yip reference,
	// including quoted/dotted or inline tables. Never append a conflicting table.
	if !remove && strings.Contains(strings.ToLower(existing), "yip") {
		return "", fmt.Errorf("unmanaged Yip reference in Codex config; reconcile it explicitly first")
	}
	if remove {
		return existing, nil
	}
	stateRoot, stateHome := codexStatePaths()
	block := fmt.Sprintf("%s[mcp_servers.yip]\ncommand = %s\nargs = [\"serve\", \"--line\", %s, \"--as\", %s]\nenv = { YIP_ROOT = %s, YIP_HOME = %s }\n%s", codexBegin, strconv.Quote(bin), strconv.Quote(line), strconv.Quote(agent), strconv.Quote(stateRoot), strconv.Quote(stateHome), codexEnd)
	return strings.TrimRight(existing, "\n") + "\n\n" + block, nil
}
func codexFiles(root, bin, line, agent string, remove bool) error {
	dir := filepath.Join(root, ".codex")
	unlock, err := fileGuard(filepath.Join(dir, "yip-install"))
	if err != nil {
		return err
	}
	defer unlock()
	configPath, hookPath := filepath.Join(dir, "config.toml"), filepath.Join(dir, "hooks.json")
	old, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if remove && !strings.Contains(string(old), codexBegin) {
		return nil
	}
	config, err := codexConfig(string(old), bin, line, agent, remove)
	if err != nil {
		return err
	}
	m, err := readJSON(hookPath)
	if err != nil {
		return err
	}
	hooks, ok := m["hooks"].(map[string]any)
	if m["hooks"] != nil && !ok {
		return fmt.Errorf("hooks must be an object")
	}
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, event := range []string{"SessionStart", "PostToolUse", "Stop"} {
		groups := dropYipHandlers(hooks[event])
		if !remove {
			stateRoot, stateHome := codexStatePaths()
			command := "env " + shellQuote("YIP_ROOT="+stateRoot) + " " + shellQuote("YIP_HOME="+stateHome) + " " + shellQuote(bin) + " hook " + strings.ToLower(event) + " --runtime codex --line " + shellQuote(line) + " --as " + shellQuote(agent) + " " + hookMarker
			groups = append(groups, map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}})
		}
		if len(groups) > 0 {
			hooks[event] = groups
		} else {
			delete(hooks, event)
		}
	}
	m["hooks"] = hooks
	// Retain an exact pre-install backup for each source before changing either.
	for _, path := range []string{configPath, hookPath} {
		data, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		backup := path + ".yip-backup"
		if e = atomicCreate(backup, data); e != nil && !os.IsExist(e) {
			return e
		}
	}
	if err = atomicReplace(configPath, []byte(config)); err != nil {
		return err
	}
	if err = writeJSON(hookPath, m); err != nil {
		if restoreErr := atomicReplace(configPath, old); restoreErr != nil {
			return fmt.Errorf("hooks: %v; restoring config: %v", err, restoreErr)
		}
		return err
	}
	return nil
}
func codexHookOutput(event string, output any) any {
	m, ok := output.(map[string]any)
	if !ok {
		return nil
	}
	if strings.EqualFold(event, "stop") {
		if m["decision"] == "block" {
			return map[string]any{"decision": "block", "reason": m["reason"]}
		}
		return nil
	}
	h, ok := m["hookSpecificOutput"].(map[string]any)
	if !ok {
		return nil
	}
	return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": h["hookEventName"], "additionalContext": h["additionalContext"]}}
}
func CodexDoctor(root string) error {
	root = checkoutRoot(root)
	config, err := os.ReadFile(filepath.Join(root, ".codex", "config.toml"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(config), codexBegin) || !strings.Contains(string(config), codexEnd) {
		return fmt.Errorf("Yip Codex MCP block missing")
	}
	start := strings.Index(string(config), codexBegin) + len(codexBegin)
	end := strings.Index(string(config)[start:], codexEnd)
	if end < 0 {
		return fmt.Errorf("incomplete Yip Codex block")
	}
	var bin string
	for _, line := range strings.Split(string(config)[start:start+end], "\n") {
		if strings.HasPrefix(line, "command = ") {
			bin, err = strconv.Unquote(strings.TrimPrefix(line, "command = "))
			if err != nil {
				return err
			}
		}
	}
	if bin == "" {
		return fmt.Errorf("Yip binary missing from Codex block")
	}
	if ok, detail := BinRuns(bin); !ok {
		return fmt.Errorf("wired Yip binary does not run: %s", detail)
	}
	if version := BinVersion(bin); version != serverVersion {
		return fmt.Errorf("wired Yip version %q differs from this binary %q", version, serverVersion)
	}
	m, err := readJSON(filepath.Join(root, ".codex", "hooks.json"))
	if err != nil {
		return err
	}
	hooks, _ := m["hooks"].(map[string]any)
	for _, ev := range []string{"SessionStart", "PostToolUse", "Stop"} {
		groups, _ := hooks[ev].([]any)
		n := 0
		for _, g := range groups {
			if isYipGroup(g) {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%s has %d Yip registrations, expected 1", ev, n)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = exec.CommandContext(ctx, "codex", "queue", "--help").Run(); err != nil {
		return fmt.Errorf("Codex queue unavailable: %w", err)
	}
	fmt.Println("Codex MCP and hook registrations present; queue command available. Review hook trust in /hooks. This does not prove runtime delivery or receipt.")
	return nil
}

// Preserve unrelated handlers even when they share a matcher group with Yip.
func dropYipHandlers(existing any) []any {
	groups, _ := existing.([]any)
	var out []any
	for _, item := range groups {
		group, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		handlers, ok := group["hooks"].([]any)
		if !ok {
			out = append(out, item)
			continue
		}
		var keep []any
		for _, h := range handlers {
			hm, _ := h.(map[string]any)
			command, _ := hm["command"].(string)
			if !strings.Contains(command, hookMarker) {
				keep = append(keep, h)
			}
		}
		if len(keep) > 0 {
			clone := map[string]any{}
			for k, v := range group {
				clone[k] = v
			}
			clone["hooks"] = keep
			out = append(out, clone)
		}
	}
	return out
}
