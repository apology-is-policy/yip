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
}

func field(label, flag string) formField { return formField{label: label, flag: flag} }
func optional(label, flag string) formField {
	return formField{label: label, flag: flag, optional: true}
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

var clientDir = field("Client directory", "--dir")
var adminDir = field("Operator client directory", "--dir")
var relayDir = field("Relay data directory", "--dir")
var descriptor = field("Signed descriptor file", "--descriptor")
var digest = field("Trusted descriptor fingerprint", "--expect")
var operatorKey = field("Operator key file", "--operator-key")
var requestFile = field("Join request file", "--request")
var challengeFile = field("Challenge file", "--challenge")
var runtimeField = field("Runtime", "--runtime")
var lineField = field("Local line", "--line")
var profileField = optional("Profile", "--profile")
var seatField = optional("Seat name", "--as")
var actorField = field("Actor", "--actor")
var byField = optional("Attribution", "--by")
var rootKey = field("Root key file", "--root-key")
var actions = []boardAction{
	form("Connect to relay", "Inspect signed descriptor", "ldr inspect", descriptor),
	form("Connect to relay", "Verify relay connection", "ldr inspect --probe", descriptor, digest),
	form("Connect to relay", "Create workstation request", "ldr join request", descriptor, digest, clientDir, field("Workstation namespace", "--namespace"), optional("Actor limit", "--actor-limit"), toggle("Receive encrypted content", "--reader"), field("Save request to", "--out")),
	form("Connect to relay", "Prove workstation keys", "ldr join prove", clientDir, field("Trusted operator public key", "--operator-pub"), requestFile, challengeFile, field("Save proof to", "--out")),
	form("Connect to relay", "Activate workstation", "ldr join activate", clientDir),
	form("Connect to relay", "Declare actor", "ldr actor declare", clientDir, actorField),
	form("Connect to relay", "Remove actor", "ldr actor remove", clientDir, actorField),
	form("Connect to relay", "Attach local line", "ldr attach", clientDir, lineField, seatField, optional("Relay actor", "--actor")),
	form("Connect to relay", "Detach local line", "ldr detach", lineField),
	form("Enroll workstation", "Issue challenge", "ldr join challenge", operatorKey, requestFile, field("Verified signing fingerprint", "--expect-signing"), field("Verified encryption fingerprint", "--expect-encryption"), field("Save challenge to", "--out-challenge"), field("Keep secret in local file", "--out-secret")),
	form("Enroll workstation", "Enroll verified workstation", "ldr join enroll", adminDir, operatorKey, requestFile, challengeFile, field("Local challenge secret file", "--secret"), field("Workstation proof file", "--proof")),
	form("Enroll workstation", "Activate reader epoch", "ldr epoch activate", adminDir, operatorKey),
	form("Enroll workstation", "Revoke credential", "ldr join revoke", adminDir, operatorKey, field("Credential ID", "--cred-id")),
	form("Lines and seats", "View another line", "@line", lineField),
	form("Lines and seats", "Inspect seats and profiles", "line", lineField),
	form("Lines and seats", "Install line or seat", "install", lineField, runtimeField, seatField, profileField, toggle("Use a shared seat", "--seat"), toggle("Local checkout settings", "--local")),
	form("Lines and seats", "Remove seat or profile", "uninstall", lineField, field("Seat name", "--as"), runtimeField, profileField),
	form("Diagnostics", "Run Doctor", "doctor", runtimeField, profileField, optional("Line", "--line")),
	form("Diagnostics", "Re-probe overdue local endpoints", "switchboard --reprobe", byField),
	form("Diagnostics", "Client status", "ldr status", clientDir),
	form("Diagnostics", "Sync client", "ldr sync", clientDir),
	form("Resources", "Inspect resource configuration", "config show"),
	form("Resources", "Initialize resource configuration", "config init", toggle("All line clients have restarted", "--clients-restarted")),
	form("Resources", "Migrate resource configuration", "config migrate", toggle("All line clients have restarted", "--clients-restarted")),
	form("Resources", "Validate configuration", "config validate", field("Configuration file", "")),
	form("Resources", "Apply configuration", "config apply", field("Configuration file", ""), toggle("All line clients have restarted", "--clients-restarted")),
	form("Host a line", "Generate relay certificate", "relay init", relayDir, field("Certificate hostnames", "--hosts")),
	form("Host a line", "Provision signed line", "relay provision", relayDir, descriptor),
	form("Host a line", "Serve in this terminal", "@serve", relayDir, optional("Direct listen address or off", "--listen"), optional("Tunnel loopback address or Unix socket", "--tunnel-listen"), optional("Tunnel path", "--tunnel-path"), optional("TLS certificate file", "--cert"), optional("TLS private key file", "--key"), optional("Tunnel capacity", "--max-tunnels"), optional("Authentication concurrency", "--max-auth"), optional("Per-line admission limit", "--max-per-line")),
	form("Host a line", "Inspect live relay", "relay clock status", relayDir),
	form("Host a line", "Inspect offline store", "relay status", relayDir),
	form("Host a line", "Resume relay clock", "relay clock resume", relayDir, field("Hosted line ID", "--line-id")),
	form("Host a line", "Monitor local admin socket", "@monitor", field("Relay admin socket path", "--admin-sock")),
	form("Line administration", "Generate signing key", "ldr root keygen", field("Private key output file", "--out"), field("Public key output file", "--pub"), optional("Algorithm", "--alg")),
	form("Line administration", "Sign line descriptor", "ldr root descriptor", field("First root public key file", "--root1"), field("Second root public key file", "--root2"), field("Root signing key file", "--signer"), field("Relay HTTPS URL", "--url"), field("TLS policy", "--tls-policy"), optional("SPKI pin or CA file", "--tls-pin"), optional("Session binding", "--session-binding"), optional("Inner server name", "--inner-server-name"), optional("Outer TLS policy", "--outer-tls-policy"), optional("Outer pin or CA file", "--outer-tls-pin"), field("Save descriptor to", "--out")),
	form("Line administration", "Create operator reader request", "ldr root reader-request", adminDir, field("Namespace", "--namespace"), field("Save request to", "--out")),
	form("Line administration", "Replace root key", "ldr root replace-root", adminDir, rootKey, field("Old root public key file", "--old-root-pub"), field("New root public key file", "--new-root-pub")),
	form("Line administration", "Initialize provisioned line", "ldr root init-line", adminDir, descriptor, rootKey),
	form("Line administration", "Authorize operator", "ldr root authorize-operator", adminDir, rootKey, field("Operator public key", "--operator-pub")),
	form("Line administration", "Revoke operator", "ldr root revoke-operator", adminDir, rootKey, field("Operator public key", "--operator-pub")),
	form("Broadcasts", "Send local briefing", "broadcast briefing", byField, field("Recipients (comma-separated)", "--to"), field("Message", "@stdin")),
	form("Broadcasts", "Send local announcement", "broadcast announcement", byField, field("Recipients (comma-separated)", "--to"), field("Message", "@stdin")),
	form("Broadcasts", "Send local regroup", "broadcast regroup", byField, field("Recipients (comma-separated)", "--to"), field("Message", "@stdin")),
	form("Broadcasts", "Send relay broadcast", "ldr broadcast create", adminDir, operatorKey, field("Kind", "--kind"), field("Recipients (comma-separated)", "--to"), byField, field("Message", "--body")),
	form("Calls", "Add human note", "ratify", field("Call ID", ""), byField, field("Message", "@stdin")),
	form("Calls", "Add signed human note", "ldr call ratify", adminDir, operatorKey, field("Call ID", "--call"), field("Message", "--body")),
	form("Calls", "Arbitrate local dispute", "switchboard --arbitrate", field("Call ID", "--call"), field("Dispute ID", "--dispute"), byField, field("Resolution", "@stdin")),
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
		if strings.HasPrefix(v, "~/") {
			home, e := os.UserHomeDir()
			if e == nil && (f.flag == "--dir" || strings.Contains(strings.ToLower(f.label), "file") || strings.Contains(f.label, "Save ") || f.flag == "--out") {
				v = filepath.Join(home, v[2:])
			}
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
