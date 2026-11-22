package main

// Antigravity CLI/TUI (agy) integration: workspace plugin (.agents/plugins/yip/),
// lifecycle hooks, MCP server configuration, and doctor checks.
//
// MEASURED against agy 1.5.14 on macOS/arm64:
//   - A native workspace plugin at <checkout>/.agents/plugins/yip/ bundles
//     plugin.json, mcp_config.json, hooks.json, and rules/AGENTS.md cleanly
//     without modifying global ~/.gemini/config/ files or colliding with
//     .claude/ or .codex/.
//   - Both the stdio MCP server and every hook process are spawned directly by
//     the agy process (shared parent PID), so session-boundary registration
//     and worktree `bind` work identically to Claude.
//   - Hooks use camelCase protojson on stdin (conversationId, cwd, toolCall,
//     terminationReason, continuationActive, fullyIdle).
//   - PostToolUse expects `{}` only and cannot inject context; mid-turn
//     notices belong in PreInvocation via `injectSteps`, and Stop uses
//     `{"decision":"continue","reason":"..."}`.
//   - MCP tools/call carries `_meta["antigravity.google/conversation_id"]` and
//     `_meta["antigravity.google/root_conversation_id"]`.
//   - MCP servers and hooks do NOT receive ANTIGRAVITY_LS_ADDRESS; agent
//     commands (`run_command`, including `IsDaemon: true`) DO receive it and
//     can run `agentapi send-message <conversationId> <text>`, which wakes
//     even a completely idle interactive agy TUI.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const agyPluginName = "yip"

var agyHookEvents = []string{"SessionStart", "PreInvocation", "PostToolUse", "Stop"}

var agyEagerTools = []string{
	"ring", "call", "say", "read", "wait", "bye", "note", "inbox",
	"presence", "busy", "resources", "hold", "release", "bind",
	"deliveries", "delivery_ack", "broadcasts", "broadcast_read",
	"broadcast_reply", "roadmap_post", "roadmap_at",
}

func agyPluginDir(root string) string {
	return filepath.Join(root, ".agents", "plugins", agyPluginName)
}

// agyHookCommand runs yip with exec so the hook process is agy's direct child
// (preserving process-tree session registration), guarded on binary presence.
func agyHookCommand(bin, line, agent, event string) string {
	stateRoot, stateHome := codexStatePaths()
	return fmt.Sprintf("[ ! -x %s ] || YIP_ROOT=%s YIP_HOME=%s exec %s hook %s --runtime agy --line %s --as %s  %s",
		shellQuote(bin), shellQuote(stateRoot), shellQuote(stateHome), shellQuote(bin),
		strings.ToLower(event), shellQuote(line), shellQuote(agent), hookMarker)
}

// agyListenCommand formats a prefix-matchable command string for the daemon
// listener so Antigravity's "Always Allow" prefix matching works smoothly.
func agyListenCommand(bin, line, agent string) string {
	cmdBin := bin
	if strings.ContainsAny(bin, " \t'\"\\$") {
		cmdBin = shellQuote(bin)
	}
	return fmt.Sprintf("%s delivery listen --runtime agy --line %s --as %s", cmdBin, line, agent)
}

// agyPluginAgent reads back the identity a checkout's .agents/plugins/yip/
// plugin serves ("" if none).
func agyPluginAgent(root string) string {
	m, err := readJSON(filepath.Join(agyPluginDir(root), "mcp_config.json"))
	if err != nil {
		return ""
	}
	servers, _ := m["mcpServers"].(map[string]any)
	yipSrv, _ := servers["yip"].(map[string]any)
	args, _ := yipSrv["args"].([]any)
	for i := 0; i+1 < len(args); i++ {
		if s, _ := args[i].(string); s == "--as" {
			name, _ := args[i+1].(string)
			return name
		}
	}
	return ""
}

// isAgyIdentity reports whether agent is demonstrably an Antigravity agent --
// by its delivery record or by this checkout's .agents/plugins/yip/ plugin.
func isAgyIdentity(agent, root string) bool {
	if ep, err := readEndpoint(agent); err == nil && ep.Runtime == "agy" {
		return true
	}
	return agyPluginAgent(root) == agent
}

func agyRulesText(bin, line, agent string) string {
	listenCmd := agyListenCommand(bin, line, agent)
	return fmt.Sprintf(`# Yip Coordination (%s on line %s)

You are **%s** on Yip line **%s**, a shared phone line between coding agents. Never act as another agent.

- **Prefer Yip MCP tools** over the `+"`yip`"+` CLI (the terminal sandbox may block CLI access to `+"`~/.yip`"+`). If using the CLI, pass `+"`--as %s --line %s`"+`.
- **Connect live idle wakeups once per session**: run `+"`%s`"+` via `+"`run_command`"+` with `+"`IsDaemon: true`"+` and `+"`WaitMsBeforeAsync: 500`"+` (request `+"`BypassSandbox: true`"+` if sandboxed). Once connected, Yip notices wake this session via `+"`agentapi`"+` even when idle.
- **Working in your own worktree from a shared launch folder**: once your worktree exists, call the Yip `+"`bind`"+` MCP tool with its absolute path (and again after a restart or resume). The running `+"`delivery listen`"+` daemon automatically follows your binding.
- **Notice contract**: notices arrive as messages titled `+"`Yip coordination notices`"+`. Read the authoritative source via Yip tools, act if a call gives you the floor, then call `+"`delivery_ack`"+` for each event ID. A notice is not a resource grant, verified approval, or passing test.
- **Protocol**: calls alternate turns (`+"`say`"+` only when the floor is yours, `+"`bye`"+` is bilateral, `+"`note`"+` needs no reply). Announcements need no reply; briefing/regroup broadcasts use `+"`broadcast_reply`"+`. Keep your arc current with `+"`roadmap_post`"+` / `+"`roadmap_at`"+`.
`, agent, line, agent, line, agent, line, listenCmd)
}

func agyFiles(root, bin, line, agent string, remove bool) error {
	agentsDir := filepath.Join(root, ".agents")
	if remove {
		if _, err := os.Stat(agyPluginDir(root)); os.IsNotExist(err) {
			return nil
		}
	}
	unlock, err := fileGuard(filepath.Join(agentsDir, "yip-install"))
	if err != nil {
		return err
	}
	defer unlock()

	pluginDir := agyPluginDir(root)
	if remove {
		if agent != "" {
			if owner := agyPluginAgent(root); owner != "" && owner != agent {
				return fmt.Errorf("%s serves %q, not %q", pluginDir, owner, agent)
			}
		}
		if err := os.RemoveAll(pluginDir); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	if owner := agyPluginAgent(root); owner != "" && owner != agent {
		return fmt.Errorf("this Antigravity plugin (%s) already serves %q; uninstall %q first or use a separate checkout", pluginDir, owner, owner)
	}

	stateRoot, stateHome := codexStatePaths()
	eager := map[string]any{}
	for _, t := range agyEagerTools {
		eager[t] = map[string]any{"eager": true}
	}

	pluginJSON := map[string]any{
		"name":    agyPluginName,
		"version": "1.0.0",
	}
	mcpJSON := map[string]any{
		"mcpServers": map[string]any{
			"yip": map[string]any{
				"command": bin,
				"args":    []any{"serve", "--agy", "--line", line, "--as", agent},
				"env": map[string]any{
					"YIP_ROOT": stateRoot,
					"YIP_HOME": stateHome,
				},
				"tools": eager,
			},
		},
	}
	hooksJSON := map[string]any{
		"yip": map[string]any{
			"SessionStart": []any{
				map[string]any{"type": "command", "command": agyHookCommand(bin, line, agent, "SessionStart"), "timeout": 15},
			},
			"PreInvocation": []any{
				map[string]any{"type": "command", "command": agyHookCommand(bin, line, agent, "PreInvocation"), "timeout": 15},
			},
			"PostToolUse": []any{
				map[string]any{
					"matcher": "*",
					"hooks": []any{
						map[string]any{"type": "command", "command": agyHookCommand(bin, line, agent, "PostToolUse"), "timeout": 15},
					},
				},
			},
			"Stop": []any{
				map[string]any{"type": "command", "command": agyHookCommand(bin, line, agent, "Stop"), "timeout": 15},
			},
		},
	}

	if err := writeJSON(filepath.Join(pluginDir, "plugin.json"), pluginJSON); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(pluginDir, "mcp_config.json"), mcpJSON); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(pluginDir, "hooks.json"), hooksJSON); err != nil {
		return err
	}
	rulesPath := filepath.Join(pluginDir, "rules", "AGENTS.md")
	if err := os.MkdirAll(filepath.Dir(rulesPath), 0o755); err != nil {
		return err
	}
	return atomicReplace(rulesPath, []byte(agyRulesText(bin, line, agent)))
}

// agyHookOutput translates Yip's internal hook result to Antigravity's
// protojson hook output contract. Antigravity expects valid JSON on stdout,
// so "no action" emits `{}`.
func agyHookOutput(event string, output any) any {
	ev := strings.ToLower(event)
	if ev == "posttooluse" {
		return map[string]any{}
	}
	m, ok := output.(map[string]any)
	if !ok || m == nil {
		return map[string]any{}
	}
	if ev == "stop" {
		if m["decision"] == "block" {
			return map[string]any{"decision": "continue", "reason": m["reason"]}
		}
		return map[string]any{}
	}
	h, ok := m["hookSpecificOutput"].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	text, _ := h["additionalContext"].(string)
	if text == "" {
		return map[string]any{}
	}
	return map[string]any{
		"injectSteps": []any{
			map[string]any{
				"systemMessage": map[string]any{
					"systemMessage": text,
				},
			},
		},
	}
}

// agyValidatePlugin asks `agy plugin validate --json` to check the plugin
// directory. Injectable so unit tests do not require agy on PATH.
var agyValidatePlugin = func(pluginDir string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "agy", "plugin", "validate", "--json", pluginDir).CombinedOutput()
}

// AgyDoctor verifies the workspace Antigravity plugin, wired binary/version,
// hook registrations, agentapi availability, and delivery status.
func AgyDoctor(root string) error {
	pluginDir := agyPluginDir(checkoutRoot(root))
	if _, err := os.Stat(filepath.Join(pluginDir, "plugin.json")); err != nil {
		return fmt.Errorf("Antigravity plugin missing at %s (run `yip install --runtime agy`): %w", pluginDir, err)
	}
	mcpMap, err := readJSON(filepath.Join(pluginDir, "mcp_config.json"))
	if err != nil {
		return err
	}
	servers, _ := mcpMap["mcpServers"].(map[string]any)
	yipSrv, ok := servers["yip"].(map[string]any)
	if !ok {
		return fmt.Errorf("Yip MCP server entry missing from %s", filepath.Join(pluginDir, "mcp_config.json"))
	}
	bin, _ := yipSrv["command"].(string)
	if bin == "" {
		return fmt.Errorf("Yip binary missing from Antigravity mcp_config.json")
	}
	if ok, detail := BinRuns(bin); !ok {
		return fmt.Errorf("wired Yip binary does not run: %s", detail)
	}
	if version := BinVersion(bin); version != serverVersion {
		return fmt.Errorf("wired Yip version %q differs from this binary %q", version, serverVersion)
	}
	rawArgs, _ := yipSrv["args"].([]any)
	var args []string
	for _, a := range rawArgs {
		if s, ok := a.(string); ok {
			args = append(args, s)
		}
	}
	hasAgyFlag := false
	agent := ""
	pluginLine := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--agy" {
			hasAgyFlag = true
		}
		if args[i] == "--as" && i+1 < len(args) {
			agent = args[i+1]
		}
		if args[i] == "--line" && i+1 < len(args) {
			pluginLine = args[i+1]
		}
	}
	if !hasAgyFlag || agent == "" {
		return fmt.Errorf("Antigravity MCP args incomplete (expected `serve --agy ... --as NAME`); re-run yip install --runtime agy")
	}
	if pluginLine != "" && os.Getenv("YIP_ROOT") == "" {
		activeLine = slugify(pluginLine)
	}

	hookMap, err := readJSON(filepath.Join(pluginDir, "hooks.json"))
	if err != nil {
		return err
	}
	yipHooks, ok := hookMap["yip"].(map[string]any)
	if !ok {
		return fmt.Errorf("yip hook group missing from %s", filepath.Join(pluginDir, "hooks.json"))
	}
	for _, ev := range agyHookEvents {
		arr, _ := yipHooks[ev].([]any)
		n := 0
		if ev == "PostToolUse" {
			for _, g := range arr {
				if isYipGroup(g) {
					n++
				}
			}
		} else {
			for _, item := range arr {
				hm, _ := item.(map[string]any)
				if cmd, _ := hm["command"].(string); strings.Contains(cmd, hookMarker) {
					n++
				}
			}
		}
		if n != 1 {
			return fmt.Errorf("%s has %d Yip registrations in %s, expected 1", ev, n, filepath.Join(pluginDir, "hooks.json"))
		}
	}

	if out, verr := agyValidatePlugin(pluginDir); verr != nil {
		// Distinguish "agy not on PATH" from an actual plugin schema error.
		var ee *exec.Error
		if !isExecNotFound(verr, &ee) {
			return fmt.Errorf("agy plugin validate failed: %v\n%s", verr, strings.TrimSpace(string(out)))
		}
		fmt.Println("note: `agy` not found on PATH; skipped `agy plugin validate`")
	}

	agentapiBin, err := findAgentAPI()
	if err != nil {
		return fmt.Errorf("agentapi unavailable: %w", err)
	}
	fmt.Printf("Antigravity plugin valid for %s in %s; agentapi found at %s.\n", agent, pluginDir, agentapiBin)
	fmt.Printf("delivery: %s\n", EndpointStatus(agent))
	if b, ok, _ := liveBinding(agent); ok {
		fmt.Printf("bound: %s is currently answered by session pid %d (launched as %s)\n", agent, b.Session.PID, b.Launch)
	}
	fmt.Println("Trust this folder in agy and start the daemon listener (`yip delivery listen --runtime agy ...`) with IsDaemon=true to receive idle wakeups.")
	return nil
}

func isExecNotFound(err error, target **exec.Error) bool {
	if ee, ok := err.(*exec.Error); ok {
		*target = ee
		return true
	}
	return false
}
