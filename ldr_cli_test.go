package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

func TestLDRCLIEndToEndOverTLS13(t *testing.T) {
	tmp := t.TempDir()
	relayDir := filepath.Join(tmp, "relay")
	keysDir := filepath.Join(tmp, "keys")
	rootDir := filepath.Join(tmp, "root-client")
	aliceDir := filepath.Join(tmp, "alice-client")
	bobDir := filepath.Join(tmp, "bob-client")

	runRelay := func(args ...string) map[string]any {
		t.Helper()
		var buf bytes.Buffer
		if err := RelayCLI(args, &buf); err != nil {
			t.Fatalf("RelayCLI(%v): %v", args, err)
		}
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("RelayCLI(%v) JSON %q: %v", args, buf.String(), err)
		}
		return m
	}
	runLDR := func(args ...string) map[string]any {
		t.Helper()
		var buf bytes.Buffer
		if err := LDRCLI(args, &buf); err != nil {
			t.Fatalf("LDRCLI(%v): %v", args, err)
		}
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("LDRCLI(%v) JSON %q: %v", args, buf.String(), err)
		}
		return m
	}

	// 1. Initialize relay TLS 1.3 cert & get SPKI pin.
	initOut := runRelay("init", "--dir", relayDir, "--hosts", "127.0.0.1,localhost")
	pinHex := initOut["pin_spki_sha256"].(string)

	// Bind localhost ephemeral port for live TLS 1.3 relay.
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayURL := "https://" + rawLn.Addr().String()

	// 2. Generate equal 1-of-2 roots (Ed25519 + ECDSA P-256!) and P-256 operator key.
	r1Key := filepath.Join(keysDir, "root1.key")
	r2Key := filepath.Join(keysDir, "root2.key")
	opKey := filepath.Join(keysDir, "op.key")
	opPub := filepath.Join(keysDir, "op.pub")
	runLDR("root", "keygen", "--out", r1Key, "--alg", "ed25519")
	runLDR("root", "keygen", "--out", r2Key, "--alg", "ecdsa-p256-sha256")
	runLDR("root", "keygen", "--out", opKey, "--pub", opPub, "--alg", "ecdsa-p256-sha256")

	// 3. Create root-signed descriptor and provision relay locally.
	descFile := filepath.Join(tmp, "line.desc.cbor")
	runLDR("root", "descriptor",
		"--line-id", "auto",
		"--root1", r1Key, "--root2", r2Key,
		"--url", relayURL,
		"--tls-policy", "pin_spki_sha256", "--tls-pin", pinHex,
		"--signer", r2Key,
		"--out", descFile,
	)
	runRelay("provision", "--dir", relayDir, "--descriptor", descFile)

	// Start live TLS 1.3 relay server backed by the provisioned FileStore.
	tlsCfg, err := ldrrelay.ServerTLSConfig(initOut["cert"].(string), initOut["key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ldrstore.OpenFileStore(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: ldrrelay.NewRelayServer(eng)}
	go func() { _ = hs.Serve(tls.NewListener(rawLn, tlsCfg)) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		_ = eng.Shutdown()
	})

	// 4. Root initializes line & authorizes operator.
	runLDR("root", "init-line", "--dir", rootDir, "--descriptor", descFile, "--root-key", r1Key)
	runLDR("root", "authorize-operator", "--dir", rootDir, "--root-key", r2Key, "--operator-pub", opPub)

	// 5. Full P3 key-first ceremony for Alice (reader) and Bob (reader).
	p3Enroll := func(name, clientDir, ns string) {
		reqF := filepath.Join(tmp, name+".req.cbor")
		chF := filepath.Join(tmp, name+".ch.cbor")
		secF := filepath.Join(tmp, name+".sec.cbor")
		prF := filepath.Join(tmp, name+".proof.cbor")
		runLDR("join", "request", "--dir", clientDir, "--descriptor", descFile, "--namespace", ns, "--actor-limit", "2", "--reader", "--out", reqF)
		runLDR("join", "challenge", "--operator-key", opKey, "--request", reqF, "--out-challenge", chF, "--out-secret", secF)
		runLDR("join", "prove", "--dir", clientDir, "--operator-pub", opPub, "--request", reqF, "--challenge", chF, "--out", prF)
		runLDR("join", "enroll", "--dir", rootDir, "--operator-key", opKey, "--request", reqF, "--challenge", chF, "--secret", secF, "--proof", prF)
	}
	p3Enroll("alice", aliceDir, "ns-alice")
	p3Enroll("bob", bobDir, "ns-bob")

	// 6. P9 epoch activation runs on enrolled reader Alice's dir with operator key!
	runLDR("epoch", "activate", "--dir", aliceDir, "--operator-key", opKey)

	// 6b. Before O25 activation, `yip ldr sync --project` and `--scan` MUST fail
	//     with ErrNotActivated, while plain provisional `sync` succeeds and exposes
	//     zero deliverable notices!
	var unactBuf bytes.Buffer
	if err := LDRCLI([]string{"sync", "--dir", bobDir, "--project"}, &unactBuf); err == nil {
		t.Fatalf("expected `yip ldr sync --project` to fail before activation")
	}
	if err := LDRCLI([]string{"sync", "--dir", bobDir, "--scan"}, &unactBuf); err == nil {
		t.Fatalf("expected `yip ldr sync --scan` to fail before activation")
	}
	provSync := runLDR("sync", "--dir", bobDir)
	if provSync["deliverable"] != nil {
		t.Fatalf("expected nil deliverable notices before activation, got %+v", provSync["deliverable"])
	}

	// 7. Alice and Bob complete O25 full-replay activation, declare actors, and exchange an encrypted call!
	runLDR("join", "activate", "--dir", aliceDir)
	runLDR("join", "activate", "--dir", bobDir)
	runLDR("actor", "declare", "--dir", aliceDir, "--actor", "alice")
	runLDR("actor", "declare", "--dir", bobDir, "--actor", "bob")
	runLDR("call", "open", "--dir", aliceDir, "--from", "alice", "--to", "bob", "--call", "call-cli-1", "--subject", "Hello", "--body", "End-to-end CLI encrypted turn")

	// 8. Bob syncs with --project --scan, verifies deliverable notice & replies!
	syncOut := runLDR("sync", "--dir", bobDir, "--project", "--scan")
	if n := int(syncOut["notices_added"].(float64)); n != 1 {
		t.Fatalf("expected 1 notice scanned for bob, got %v", syncOut)
	}
	runLDR("call", "say", "--dir", bobDir, "--from", "bob", "--call", "call-cli-1", "--body", "Reply from Bob!")
	stOut := runLDR("status", "--dir", bobDir)
	stMap := stOut["status"].(map[string]any)
	if !stMap["activated"].(bool) || int(stMap["key_epoch"].(float64)) != 1 {
		t.Fatalf("unexpected final bob status: %+v", stOut)
	}
}
