package main

// #include "bridge.h"
// #include <stdlib.h>
import "C"

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unsafe"
)

// Each field becomes exactly one argv value (or a checkbox, positional
// argument or stdin body). No shell interprets operator input.
type formField struct {
	label, flag      string
	optional, toggle bool
	path             bool
}

func field(label, flag string) formField { return formField{label: label, flag: flag} }
func optional(label, flag string) formField {
	return formField{label: label, flag: flag, optional: true}
}
func pathField(label, flag string) formField {
	return formField{label: label, flag: flag, path: true}
}
func optionalPath(label, flag string) formField {
	return formField{label: label, flag: flag, optional: true, path: true}
}
func toggle(label, flag string) formField {
	return formField{label: label, flag: flag, optional: true, toggle: true}
}

type boardAction struct {
	group, label, command string
	fields                []formField
}

func form(group, label, command string, fields ...formField) boardAction {
	return boardAction{group, label, command, fields}
}

var clientDir = pathField("Client directory", "--dir")
var adminDir = pathField("Operator client directory", "--dir")
var relayDir = pathField("Relay data directory", "--dir")
var descriptor = pathField("Signed descriptor file", "--descriptor")
var digest = field("Trusted descriptor fingerprint", "--expect")
var operatorKey = pathField("Operator key file", "--operator-key")
var requestFile = pathField("Join request file", "--request")
var challengeFile = pathField("Challenge file", "--challenge")
var runtimeField = field("Runtime", "--runtime")
var lineField = field("Local line", "--line")
var profileField = optional("Profile", "--profile")
var seatField = optional("Seat name", "--as")
var actorField = field("Actor", "--actor")
var byField = optional("Attribution", "--by")
var rootKey = pathField("Root key file", "--root-key")
var callID = field("Call ID", "--call")
var fromActor = field("Sending actor", "--from")
var message = field("Message", "--body")
var dispute = field("Dispute ID", "--dispute")
var actions = []boardAction{
	form("Connect to relay", "Inspect signed descriptor", "ldr inspect", descriptor),
	form("Connect to relay", "Verify relay connection", "ldr inspect --probe", descriptor, digest),
	form("Connect to relay", "Create workstation request", "ldr join request", descriptor, digest, clientDir, field("Workstation namespace", "--namespace"), optional("Actor limit", "--actor-limit"), toggle("Receive encrypted content", "--reader"), pathField("Save request to", "--out")),
	form("Connect to relay", "Prove workstation keys", "ldr join prove", clientDir, pathField("Trusted operator public key", "--operator-pub"), requestFile, challengeFile, pathField("Save proof to", "--out")),
	form("Connect to relay", "Activate workstation", "ldr join activate", clientDir),
	form("Connect to relay", "Declare actor", "ldr actor declare", clientDir, actorField),
	form("Connect to relay", "Remove actor", "ldr actor remove", clientDir, actorField),
	form("Connect to relay", "Attach local line", "ldr attach", clientDir, lineField, seatField, optional("Relay actor", "--actor")),
	form("Connect to relay", "Detach local line", "ldr detach", lineField),
	form("Enroll workstation", "Inspect signed request", "ldr join inspect", requestFile),
	form("Enroll workstation", "Issue challenge", "ldr join challenge", operatorKey, requestFile, field("Reviewed request digest", "--expect-request"), field("Verified signing fingerprint", "--expect-signing"), field("Verified encryption fingerprint", "--expect-encryption"), pathField("Save challenge to", "--out-challenge"), pathField("Keep secret in local file", "--out-secret")),
	form("Enroll workstation", "Enroll verified workstation", "ldr join enroll", adminDir, operatorKey, requestFile, challengeFile, pathField("Local challenge secret file", "--secret"), pathField("Workstation proof file", "--proof")),
	form("Enroll workstation", "Activate reader epoch", "ldr epoch activate", adminDir, operatorKey),
	form("Enroll workstation", "Revoke credential", "ldr join revoke", adminDir, operatorKey, field("Credential ID", "--cred-id")),
	form("Create a Line", "Create a Line", "switchboard --create-line", field("Line name", "")),
	form("Add Agent", "Add Agent", "@agent", lineField, field("Provider", ""), field("Agent name", ""), field("Attachment", ""), optional("Worktree path", ""), optional("Profile name", ""), toggle("Checkout-local Claude settings", "--local")),
	form("Manage Lines", "View another line", "@line", lineField),
	form("Manage Agents", "Remove agent", "uninstall", lineField, field("Agent name", "--as"), profileField),
	form("Diagnostics", "Run Doctor", "doctor", runtimeField, profileField, optional("Line", "--line")),
	form("Diagnostics", "Re-probe overdue local endpoints", "switchboard --reprobe", lineField, byField),
	form("Client tools", "Client status", "ldr status", clientDir),
	form("Client tools", "Sync client", "ldr sync", clientDir),
	form("Client tools", "List actors", "ldr actor list", clientDir),
	form("Client tools", "Set actor addressing", "ldr actor addressing", clientDir, actorField, field("Default addressing (true/false)", "--default")),
	form("Client tools", "List registers", "ldr register list", clientDir, optional("Register", "--register")),
	form("Client tools", "Update actor register", "ldr register put", clientDir, actorField, field("Register", "--register"), message),
	form("Relay calls", "List calls", "ldr call list", clientDir, optional("Actor", "--actor"), toggle("Include all", "--all")),
	form("Relay calls", "Read call", "ldr call read", clientDir, callID),
	form("Relay calls", "Open call", "ldr call open", clientDir, fromActor, field("Recipient", "--to"), callID, field("Subject", "--subject"), message),
	form("Relay calls", "Send turn", "ldr call say", clientDir, fromActor, callID, message, toggle("Barge", "--barge")),
	form("Relay calls", "Say bye", "ldr call bye", clientDir, fromActor, callID),
	form("Relay calls", "Add actor note", "ldr call note", clientDir, fromActor, callID, message),
	form("Relay calls", "Set call status", "ldr call status", clientDir, fromActor, callID, field("State", "--state"), optional("Reason", "--reason"), optional("Related call", "--related")),
	form("Relay calls", "Attach file", "ldr call attach", clientDir, fromActor, callID, pathField("Attachment file", "--path")),
	form("Relay calls", "Ratify as operator", "ldr call ratify", adminDir, operatorKey, callID, message),
	form("Relay calls", "Record dispute", "ldr call dispute", clientDir, fromActor, callID, field("Claim", "--claim")),
	form("Relay calls", "Record measurement", "ldr call measure", clientDir, fromActor, callID, dispute, field("Command", "--cmd")),
	form("Relay calls", "Resolve dispute", "ldr call resolve", clientDir, fromActor, callID, dispute, field("Kind", "--kind"), field("Detail", "--detail")),
	form("Relay broadcasts", "List broadcasts", "ldr broadcast list", clientDir, optional("Actor", "--actor"), toggle("Include all", "--all")),
	form("Relay broadcasts", "Read broadcast", "ldr broadcast read", clientDir, actorField, field("Broadcast ID", "--id")),
	form("Relay broadcasts", "Reply to broadcast", "ldr broadcast reply", clientDir, actorField, field("Broadcast ID", "--id"), message),
	form("Resources", "Inspect resource configuration", "config show"),
	form("Resources", "Initialize resource configuration", "config init", toggle("All line clients have restarted", "--clients-restarted")),
	form("Resources", "Migrate resource configuration", "config migrate", toggle("All line clients have restarted", "--clients-restarted")),
	form("Resources", "Validate configuration", "config validate", pathField("Configuration file", "")),
	form("Resources", "Apply configuration", "config apply", pathField("Configuration file", ""), toggle("All line clients have restarted", "--clients-restarted")),
	form("Host a line", "Generate relay certificate", "relay init", relayDir, field("Certificate hostnames", "--hosts")),
	form("Host a line", "Provision signed line", "relay provision", relayDir, descriptor),
	form("Host a line", "Serve in this terminal", "@serve", relayDir, optional("Direct listen address or off", "--listen"), optional("Tunnel loopback address or Unix socket", "--tunnel-listen"), optional("Tunnel path", "--tunnel-path"), optionalPath("TLS certificate file", "--cert"), optionalPath("TLS private key file", "--key"), optional("Tunnel capacity", "--max-tunnels"), optional("Authentication concurrency", "--max-auth"), optional("Per-line admission limit", "--max-per-line")),
	form("Host a line", "Inspect live relay", "relay clock status", relayDir),
	form("Host a line", "Inspect offline store", "relay status", relayDir),
	form("Host a line", "Resume relay clock", "relay clock resume", relayDir, field("Hosted line ID", "--line-id")),
	form("Host a line", "Monitor local admin socket", "@monitor", pathField("Relay admin socket path", "--admin-sock")),
	form("Line administration", "Generate signing key", "ldr root keygen", pathField("Private key output file", "--out"), pathField("Public key output file", "--pub"), optional("Algorithm", "--alg")),
	form("Line administration", "Sign line descriptor", "ldr root descriptor", pathField("First root public key file", "--root1"), pathField("Second root public key file", "--root2"), pathField("Root signing key file", "--signer"), field("Relay HTTPS URL", "--url"), field("TLS policy", "--tls-policy"), optionalPath("SPKI pin or CA file", "--tls-pin"), optional("Session binding", "--session-binding"), optional("Inner server name", "--inner-server-name"), optional("Outer TLS policy", "--outer-tls-policy"), optionalPath("Outer pin or CA file", "--outer-tls-pin"), pathField("Save descriptor to", "--out")),
	form("Line administration", "Create operator reader request", "ldr root reader-request", adminDir, field("Namespace", "--namespace"), pathField("Save request to", "--out")),
	form("Line administration", "Replace root key", "ldr root replace-root", adminDir, rootKey, pathField("Old root public key file", "--old-root-pub"), pathField("New root public key file", "--new-root-pub")),
	form("Line administration", "Initialize provisioned line", "ldr root init-line", adminDir, descriptor, rootKey),
	form("Line administration", "Authorize operator", "ldr root authorize-operator", adminDir, rootKey, pathField("Operator public key", "--operator-pub")),
	form("Line administration", "Revoke operator", "ldr root revoke-operator", adminDir, rootKey, pathField("Operator public key", "--operator-pub")),
	form("Broadcasts", "Send local briefing", "broadcast briefing", lineField, byField, field("Recipients (comma-separated)", "--to"), field("Message", "@stdin")),
	form("Broadcasts", "Send local announcement", "broadcast announcement", lineField, byField, field("Recipients (comma-separated)", "--to"), field("Message", "@stdin")),
	form("Broadcasts", "Send local regroup", "broadcast regroup", lineField, byField, field("Recipients (comma-separated)", "--to"), field("Message", "@stdin")),
	form("Broadcasts", "Send relay broadcast", "ldr broadcast create", adminDir, operatorKey, field("Kind", "--kind"), field("Recipients (comma-separated)", "--to"), byField, field("Message", "--body")),
	form("Calls", "Add human note", "ratify", lineField, field("Call ID", ""), byField, field("Message", "@stdin")),
	form("Calls", "Add signed human note", "ldr call ratify", adminDir, operatorKey, field("Call ID", "--call"), field("Message", "--body")),
	form("Calls", "Arbitrate local dispute", "switchboard --arbitrate", lineField, field("Call ID", "--call"), field("Dispute ID", "--dispute"), byField, field("Resolution", "@stdin")),
}

// Resolve the setup choices before invoking install in the requested checkout.
func agentArguments(values []string) ([]string, string, error) {
	line, provider, agent, mode := strings.TrimSpace(values[0]), values[1], strings.TrimSpace(values[2]), values[3]
	if line == "" || agent == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(agent, "-") {
		return nil, "", fmt.Errorf("enter a line and an agent name")
	}
	switch provider {
	case "codex", "agy", "claude", "claude-channels", "claude-rewake":
	default:
		return nil, "", fmt.Errorf("choose a provider")
	}
	args := []string{"install", "--line", line, "--as", agent, "--runtime", provider}
	switch mode {
	case "Worktree", "New worktree":
		if mode == "New worktree" && strings.TrimSpace(values[4]) == "" {
			return nil, "", fmt.Errorf("enter a new worktree path")
		}
	case "Shared seat":
		if provider != "codex" && provider != "agy" {
			return nil, "", fmt.Errorf("shared seats require Codex or Antigravity")
		}
		args = append(args, "--seat")
	case "Codex profile":
		if provider != "codex" || strings.TrimSpace(values[5]) == "" || strings.HasPrefix(values[5], "-") {
			return nil, "", fmt.Errorf("choose Codex and enter a profile name")
		}
		args = append(args, "--profile", strings.TrimSpace(values[5]))
	default:
		return nil, "", fmt.Errorf("choose an attachment")
	}
	if strings.HasPrefix(provider, "claude") && values[6] != "" {
		args = append(args, "--local")
	}
	return args, "", nil
}

func expandHomePath(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[2:]), nil
}

func installBoardAgent(ctx context.Context, yip, dir string, args, values []string) (string, error) {
	path := strings.TrimSpace(values[4])
	if path != "" && values[3] != "Codex profile" {
		var err error
		path, err = expandHomePath(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
		if values[3] == "New worktree" {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return "", fmt.Errorf("choose an unused worktree path")
			}
			output, err := runAction(ctx, "git", dir, []string{"worktree", "add", "--", path}, "")
			if err != nil {
				return output, err
			}
		}
		dir = path
	}
	msg, err := runAction(ctx, yip, dir, args, "")
	if err != nil && values[3] == "New worktree" {
		msg += "\nWorktree created at " + dir + ". Select Worktree to retry installation there."
	}
	return msg, err
}

func cstrings(values ...string) ([]*C.char, func()) {
	out := make([]*C.char, len(values))
	for i, s := range values {
		out[i] = C.CString(s)
	}
	return out, func() {
		for _, p := range out {
			C.free(unsafe.Pointer(p))
		}
	}
}
func registerActions() {
	for _, a := range actions {
		v, free := cstrings(a.group, a.label)
		C.board_action(v[0], v[1])
		free()
		for _, f := range a.fields {
			label := f.label
			if f.optional && !f.toggle {
				label += " (optional)"
			}
			s, free := cstrings(label)
			var checkbox C.int
			if f.toggle {
				checkbox = 1
			}
			C.board_field(s[0], checkbox)
			free()
		}
	}
}
func (a boardAction) arguments(values []string) (args []string, body string, err error) {
	if len(values) != len(a.fields) {
		return nil, "", fmt.Errorf("invalid field count")
	}
	if a.command == "@agent" {
		return agentArguments(values)
	}
	args = strings.Fields(a.command)
	for i, f := range a.fields {
		v := strings.TrimSpace(values[i])
		if v == "" {
			if f.flag == "--by" && os.Getenv("YIP_SWITCHBOARD_BY") != "" {
				args = append(args, f.flag, os.Getenv("YIP_SWITCHBOARD_BY"))
				continue
			}
			if f.optional {
				continue
			}
			return nil, "", fmt.Errorf("Enter %s", f.label)
		}
		if f.toggle {
			args = append(args, f.flag)
			continue
		}
		if f.flag == "@stdin" {
			body = values[i]
			continue
		}
		if strings.HasPrefix(v, "--") {
			return nil, "", fmt.Errorf("%s cannot begin with --", f.label)
		}
		if f.path {
			v, err = expandHomePath(v)
		} else if f.flag == "--tunnel-listen" && strings.HasPrefix(v, "unix:~/") {
			var path string
			path, err = expandHomePath(strings.TrimPrefix(v, "unix:"))
			v = "unix:" + path
		}
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", f.label, err)
		}
		if f.flag != "" {
			args = append(args, f.flag)
		}
		args = append(args, v)
	}
	return args, body, nil
}

// Keep the process draining output after the display budget is consumed.
type displayOutput struct {
	strings.Builder
	truncated bool
}

func (w *displayOutput) Write(b []byte) (int, error) {
	n := min(len(b), 65536-w.Len())
	_, _ = w.Builder.Write(b[:n])
	if n < len(b) {
		w.truncated = true
	}
	return len(b), nil
}
func runAction(ctx context.Context, yip, dir string, args []string, body string) (string, error) {
	cmd := exec.CommandContext(ctx, yip, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(body)
	var out displayOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	msg := strings.Map(func(r rune) rune {
		if r == '\n' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, out.String())
	if out.truncated {
		msg += "\nOutput truncated."
	}
	return strings.TrimSpace(msg), err
}
func actionStatus(message string, busy, failed bool) {
	text, free := cstrings(terminalCells(message))
	defer free()
	var state C.int
	if busy {
		state = 1
	}
	if failed {
		state = 2
	}
	C.board_result(text[0], state)
}
