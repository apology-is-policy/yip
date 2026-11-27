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
		values := []string{"/credentials/operator key", "join.req", "reviewed-digest", "sig-fingerprint", "enc-fingerprint", "challenge", "secret"}
		args, _, err := a.arguments(values)
		want := []string{"ldr", "join", "challenge", "--operator-key", values[0], "--request", values[1], "--expect-request", values[2], "--expect-signing", values[3], "--expect-encryption", values[4], "--out-challenge", values[5], "--out-secret", values[6]}
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

func TestActionArgumentsExpandFilesystemFieldsOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, tt := range []struct{ action, flag, input, want string }{
		{"Prove workstation keys", "--operator-pub", "~/key dir/op.pub", home + "/key dir/op.pub"},
		{"Authorize operator", "--operator-pub", "~/op.pub", home + "/op.pub"},
		{"Monitor local admin socket", "--admin-sock", "~/admin.sock", home + "/admin.sock"},
		{"Serve in this terminal", "--tunnel-listen", "unix:~/relay.sock", "unix:" + home + "/relay.sock"},
		{"Serve in this terminal", "--tunnel-listen", "127.0.0.1:8080", "127.0.0.1:8080"},
		{"Open call", "--body", "~/literal", "~/literal"},
	} {
		t.Run(tt.action+"/"+tt.flag, func(t *testing.T) {
			for _, a := range actions {
				if a.label != tt.action {
					continue
				}
				values := make([]string, len(a.fields))
				for i, f := range a.fields {
					if f.flag == tt.flag {
						values[i] = tt.input
					} else if !f.optional {
						values[i] = "fixture"
					}
				}
				args, _, err := a.arguments(values)
				if err != nil {
					t.Fatal(err)
				}
				for i, arg := range args {
					if arg == tt.flag && i+1 < len(args) && args[i+1] == tt.want {
						return
					}
				}
				t.Fatalf("missing %q = %q in %q", tt.flag, tt.want, args)
			}
			t.Fatal("missing form")
		})
	}
}
