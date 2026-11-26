package main

import (
	"reflect"
	"testing"
)

func TestEnrollmentFormPassesTrustedFingerprintsAsValues(t *testing.T) {
	for _, a := range actions {
		if a.command != "ldr join challenge" {
			continue
		}
		values := []string{"/credentials/operator key", "join.req", "sig-fingerprint", "enc-fingerprint", "challenge", "secret"}
		args, _, err := a.arguments(values)
		want := []string{"ldr", "join", "challenge", "--operator-key", values[0], "--request", values[1], "--expect-signing", values[2], "--expect-encryption", values[3], "--out-challenge", values[4], "--out-secret", values[5]}
		if err != nil || !reflect.DeepEqual(args, want) {
			t.Fatalf("challenge: %q, %v", args, err)
		}
		values[2] = ""
		if _, _, err := a.arguments(values); err == nil {
			t.Fatal("missing trust comparison accepted")
		}
		return
	}
	t.Fatal("missing enrollment form")
}

func TestAgentSetupRespectsProviderAndAttachment(t *testing.T) {
	values := []string{"garden", "codex", "reviewer", "Codex profile", "", "review-desk", ""}
	args, _, err := agentArguments(values)
	if err != nil || !reflect.DeepEqual(args, []string{"install", "--line", "garden", "--as", "reviewer", "--runtime", "codex", "--profile", "review-desk"}) {
		t.Fatalf("profile install: %q %v", args, err)
	}
	values[1] = "claude"
	if _, _, err = agentArguments(values); err == nil {
		t.Fatal("Claude profile accepted")
	}
	values[3] = "New worktree"
	values[5] = ""
	if _, _, err = agentArguments(values); err == nil {
		t.Fatal("empty new worktree path accepted")
	}
	values[3] = "Shared seat"
	values[1] = "agy"
	args, _, err = agentArguments(values)
	if err != nil || args[len(args)-1] != "--seat" {
		t.Fatalf("shared seat: %q %v", args, err)
	}
}
