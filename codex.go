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

var codexHookEvents = []string{"SessionStart", "PostToolUse", "Stop"}

func codexHookCommand(bin, line, agent, event string) string {
	stateRoot, stateHome := codexStatePaths()
	return "env " + shellQuote("YIP_ROOT="+stateRoot) + " " + shellQuote("YIP_HOME="+stateHome) + " " + shellQuote(bin) + " hook " + strings.ToLower(event) + " --runtime codex --line " + shellQuote(line) + " --as " + shellQuote(agent) + " " + hookMarker
}

// codexManagedBlock splits a config into its managed Yip block and the rest.
func codexManagedBlock(content string) (block, rest string, err error) {
	start := strings.Index(content, codexBegin)
	if start < 0 {
		rest = content
	} else {
		end := strings.Index(content[start:], codexEnd)
		if end < 0 {
			return "", "", fmt.Errorf("incomplete Yip config block; refusing to overwrite")
		}
		block = content[start+len(codexBegin) : start+end]
		rest = content[:start] + content[start+end+len(codexEnd):]
	}
	if strings.Contains(rest, codexBegin) || strings.Contains(rest, codexEnd) {
		return "", "", fmt.Errorf("duplicate or incomplete Yip config blocks")
	}
	return block, rest, nil
}

// codexBlockAgent reads back the identity a managed block serves ("" if none).
func codexBlockAgent(block string) string {
	for _, line := range strings.Split(block, "\n") {
		list, ok := strings.CutPrefix(line, "args = [")
		if !ok {
			continue
		}
		var args []string
		for list = strings.TrimSpace(list); strings.HasPrefix(list, `"`); {
			q, err := strconv.QuotedPrefix(list)
			if err != nil {
				return ""
			}
			v, _ := strconv.Unquote(q)
			args = append(args, v)
			list = strings.TrimLeft(list[len(q):], ", ")
		}
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "--as" {
				return args[i+1]
			}
		}
	}
	return ""
}

// codexConfig merges the managed block. inlineHooks puts the lifecycle hooks
// in the same block -- needed for a profile layer, which has no hooks.json of
// its own (the one beside it belongs to the user layer and every session).
func codexConfig(existing, bin, line, agent string, remove bool, inlineHooks ...bool) (string, error) {
	old, rest, err := codexManagedBlock(existing)
	if err != nil {
		return "", err
	}
	// Without a TOML parser, conservatively refuse any unmanaged Yip reference,
	// including quoted/dotted or inline tables. Never append a conflicting table.
	if !remove && strings.Contains(strings.ToLower(rest), "yip") {
		return "", fmt.Errorf("unmanaged Yip reference in Codex config; reconcile it explicitly first")
	}
	if remove {
		return rest, nil
	}
	// One config layer serves one identity. Replacing another agent's block
	// would silently move that agent's session onto this name.
	if owner := codexBlockAgent(old); owner != "" && owner != agent {
		return "", fmt.Errorf("this Codex config already serves %q; give %q its own profile (--profile NAME) or uninstall %q first", owner, agent, owner)
	}
	hooks := len(inlineHooks) > 0 && inlineHooks[0]
	if hooks && strings.Contains(strings.ToLower(rest), "hooks") {
		return "", fmt.Errorf("this Codex profile already defines hooks; use a dedicated profile for the Yip seat")
	}
	stateRoot, stateHome := codexStatePaths()
	var b strings.Builder
	b.WriteString(codexBegin)
	fmt.Fprintf(&b, "[mcp_servers.yip]\ncommand = %s\nargs = [\"serve\", \"--codex\", \"--line\", %s, \"--as\", %s]\nenv = { YIP_ROOT = %s, YIP_HOME = %s }\n", strconv.Quote(bin), strconv.Quote(line), strconv.Quote(agent), strconv.Quote(stateRoot), strconv.Quote(stateHome))
	// The daemon spawns this server with a stripped environment. Forward a
	// custom CODEX_HOME so `codex queue` reaches the same daemon as the session.
	b.WriteString("env_vars = [\"CODEX_HOME\"]\n")
	if hooks {
		for _, event := range codexHookEvents {
			fmt.Fprintf(&b, "\n[[hooks.%s]]\n[[hooks.%s.hooks]]\ntype = \"command\"\ncommand = %s\n", event, event, strconv.Quote(codexHookCommand(bin, line, agent, event)))
		}
	}
	b.WriteString(codexEnd)
	return strings.TrimRight(rest, "\n") + "\n\n" + b.String(), nil
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
	if remove && agent != "" {
		if block, _, e := codexManagedBlock(string(old)); e == nil {
			if owner := codexBlockAgent(block); owner != "" && owner != agent {
				return fmt.Errorf("%s serves %q, not %q", configPath, owner, agent)
			}
		}
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
	for _, event := range codexHookEvents {
		groups := dropYipHandlers(hooks[event])
		if !remove {
			groups = append(groups, map[string]any{"hooks": []any{map[string]any{"type": "command", "command": codexHookCommand(bin, line, agent, event)}}})
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

// codexHome is where Codex keeps user config and profile layers.
func codexHome() string {
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return v
	}
	return filepath.Join(homeDir(), ".codex")
}

func codexProfilePath(profile string) string {
	return filepath.Join(codexHome(), profile+".config.toml")
}

// codexProfileFiles writes a seat into a Codex profile layer
// ($CODEX_HOME/NAME.config.toml), loaded by `codex -p NAME` from any
// directory. MEASURED on codex-cli 0.162.0: a profile layer contributes both
// its [mcp_servers] and inline [[hooks.*]] to a runtime session.
func codexProfileFiles(profile, bin, line, agent string, remove bool) error {
	if !validComponent(profile) {
		return fmt.Errorf("profile name must be letters, digits, - or _")
	}
	unlock, err := fileGuard(filepath.Join(codexHome(), "yip-install"))
	if err != nil {
		return err
	}
	defer unlock()
	path := codexProfilePath(profile)
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if remove && !strings.Contains(string(old), codexBegin) {
		return nil
	}
	if remove && agent != "" {
		if block, _, e := codexManagedBlock(string(old)); e == nil {
			if owner := codexBlockAgent(block); owner != "" && owner != agent {
				return fmt.Errorf("profile %s serves %q, not %q", profile, owner, agent)
			}
		}
	}
	config, err := codexConfig(string(old), bin, line, agent, remove, true)
	if err != nil {
		return err
	}
	if len(old) > 0 {
		if e := atomicCreate(path+".yip-backup", old); e != nil && !os.IsExist(e) {
			return e
		}
	}
	if remove && strings.TrimSpace(config) == "" {
		return os.Remove(path)
	}
	return atomicReplace(path, []byte(config))
}

// CodexDoctor checks one Codex config layer: a checkout's .codex/ (hooks in
// hooks.json) or, with profile set, $CODEX_HOME/PROFILE.config.toml (hooks
// inline). It reports the identity's delivery state; it cannot prove receipt.
func CodexDoctor(root, profile string) error {
	configPath, inline := filepath.Join(checkoutRoot(root), ".codex", "config.toml"), false
	if profile != "" {
		configPath, inline = codexProfilePath(profile), true
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	block, _, err := codexManagedBlock(string(config))
	if err != nil {
		return err
	}
	if block == "" {
		return fmt.Errorf("Yip Codex MCP block missing from %s", configPath)
	}
	var bin string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(line, "command = ") {
			bin, err = strconv.Unquote(strings.TrimPrefix(line, "command = "))
			if err != nil {
				return err
			}
			break
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
	if !strings.Contains(block, `"serve", "--codex"`) {
		return fmt.Errorf("Codex block predates live delivery; re-run yip install --runtime codex, then restart Codex")
	}
	for _, ev := range codexHookEvents {
		n := 0
		if inline {
			n = strings.Count(block, "[[hooks."+ev+".hooks]]")
		} else {
			m, err := readJSON(filepath.Join(filepath.Dir(configPath), "hooks.json"))
			if err != nil {
				return err
			}
			hooks, _ := m["hooks"].(map[string]any)
			groups, _ := hooks[ev].([]any)
			for _, g := range groups {
				if isYipGroup(g) {
					n++
				}
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
	agent := codexBlockAgent(block)
	fmt.Printf("Codex MCP and hook registrations present for %s in %s; queue command available.\n", agent, configPath)
	fmt.Printf("delivery: %s\n", EndpointStatus(agent))
	fmt.Println("Review hook trust in /hooks. This does not prove runtime delivery or receipt: verify that the intended chat receives and acknowledges a notice.")
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
