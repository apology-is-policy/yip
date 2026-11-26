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
