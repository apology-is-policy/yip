package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
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

	// 5. Enroll an admin reader credential inside the activated rootDir (P9) plus
	//    full P3 key-first ceremonies for joining members Alice and Bob.
	//    Also verify admin reader-request preserves cred.key across an --out write
	//    failure, resumes cleanly with the exact same cred_id/request_id, and
	//    refuses replacement after enrollment!
	opReqF := filepath.Join(tmp, "admin-reader.req.cbor")
	opChF := filepath.Join(tmp, "admin-reader.ch.cbor")
	opSecF := filepath.Join(tmp, "admin-reader.sec.cbor")
	opPrF := filepath.Join(tmp, "admin-reader.proof.cbor")

	badParent := filepath.Join(tmp, "not-a-directory")
	if err := os.WriteFile(badParent, []byte("blocker"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errOutBuf bytes.Buffer
	if err := LDRCLI([]string{"root", "reader-request", "--dir", rootDir, "--namespace", "ns-admin", "--out", filepath.Join(badParent, "req.cbor")}, &errOutBuf); err == nil {
		t.Fatalf("expected `yip ldr root reader-request` to fail when --out parent is a regular file")
	}
	rootCredBefore, err := os.ReadFile(filepath.Join(rootDir, "cred.key"))
	if err != nil {
		t.Fatalf("expected cred.key persisted on first reader-request before --out failure: %v", err)
	}

	// Conflicting existing destinations (disposable sentinel AND rootDir/cred.key itself)
	// MUST be refused without clobbering either the sentinel or cred.key!
	sentinelPath := filepath.Join(tmp, "disposable-sentinel.txt")
	sentinelBytes := []byte("cli-disposable-sentinel-do-not-overwrite")
	if err := os.WriteFile(sentinelPath, sentinelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LDRCLI([]string{"root", "reader-request", "--dir", rootDir, "--namespace", "ns-admin", "--out", sentinelPath}, &errOutBuf); err == nil {
		t.Fatalf("expected `yip ldr root reader-request` to refuse existing sentinel destination")
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || !bytes.Equal(sentinelBytes, got) {
		t.Fatalf("`yip ldr root reader-request` clobbered disposable sentinel!")
	}
	if err := LDRCLI([]string{"root", "reader-request", "--dir", rootDir, "--namespace", "ns-admin", "--out", filepath.Join(rootDir, "cred.key")}, &errOutBuf); err == nil {
		t.Fatalf("expected `yip ldr root reader-request` to refuse overwriting rootDir/cred.key")
	}
	if got, err := os.ReadFile(filepath.Join(rootDir, "cred.key")); err != nil || !bytes.Equal(rootCredBefore, got) {
		t.Fatalf("`yip ldr root reader-request` clobbered rootDir/cred.key!")
	}

	resumedReq := runLDR("root", "reader-request", "--dir", rootDir, "--namespace", "ns-admin", "--out", opReqF)
	if !resumedReq["resumed"].(bool) {
		t.Fatalf("expected resumed `yip ldr root reader-request` after --out errors, got %+v", resumedReq)
	}
	opReqBytes, err := os.ReadFile(opReqF)
	if err != nil {
		t.Fatal(err)
	}
	// Exact retry to the SAME --out before enrollment succeeds idempotently!
	exactRetry := runLDR("root", "reader-request", "--dir", rootDir, "--namespace", "ns-admin", "--out", opReqF)
	if !exactRetry["resumed"].(bool) || exactRetry["cred_id"] != resumedReq["cred_id"] || exactRetry["request_id"] != resumedReq["request_id"] {
		t.Fatalf("exact retry mismatch: got %+v, want %+v", exactRetry, resumedReq)
	}
	if got, err := os.ReadFile(opReqF); err != nil || !bytes.Equal(opReqBytes, got) {
		t.Fatalf("exact retry altered opReqF!")
	}
	rootCredResumed, err := os.ReadFile(filepath.Join(rootDir, "cred.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootCredBefore, rootCredResumed) {
		t.Fatalf("`yip ldr root reader-request` resume overwrote cred.key!")
	}
	runLDR("join", "challenge", "--operator-key", opKey, "--request", opReqF, "--out-challenge", opChF, "--out-secret", opSecF)
	runLDR("join", "prove", "--dir", rootDir, "--operator-pub", opPub, "--request", opReqF, "--challenge", opChF, "--out", opPrF)
	runLDR("join", "enroll", "--dir", rootDir, "--operator-key", opKey, "--request", opReqF, "--challenge", opChF, "--secret", opSecF, "--proof", opPrF)

	// After enrollment, repeating `yip ldr root reader-request` MUST fail without touching cred.key!
	var repeatReqBuf bytes.Buffer
	if err := LDRCLI([]string{"root", "reader-request", "--dir", rootDir, "--namespace", "ns-admin", "--out", filepath.Join(tmp, "dup.req.cbor")}, &repeatReqBuf); err == nil {
		t.Fatalf("expected repeated `yip ldr root reader-request` after enrollment to fail")
	}
	rootCredAfter, err := os.ReadFile(filepath.Join(rootDir, "cred.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootCredBefore, rootCredAfter) {
		t.Fatalf("repeated `yip ldr root reader-request` altered enrolled cred.key!")
	}

	// Repeated `yip ldr root init-line` against existing rootDir MUST fail without modifying files!
	var reinitBuf bytes.Buffer
	if err := LDRCLI([]string{"root", "init-line", "--dir", rootDir, "--descriptor", descFile, "--root-key", r1Key}, &reinitBuf); err == nil {
		t.Fatalf("expected repeated `yip ldr root init-line` on existing rootDir to fail")
	}
	if got, err := os.ReadFile(filepath.Join(rootDir, "cred.key")); err != nil || !bytes.Equal(rootCredBefore, got) {
		t.Fatalf("failed `yip ldr root init-line` altered rootDir/cred.key!")
	}

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
	// `yip ldr join request` MUST refuse an existing disposable sentinel without
	// clobbering it or initializing the target dir, and MUST refuse overwriting
	// cred.key even if --out points inside a newly initialized dir!
	unusedJoinDir := filepath.Join(tmp, "unused-join-dir")
	var joinSentinelBuf bytes.Buffer
	if err := LDRCLI([]string{"join", "request", "--dir", unusedJoinDir, "--descriptor", descFile, "--namespace", "ns-unused", "--actor-limit", "2", "--reader", "--out", sentinelPath}, &joinSentinelBuf); err == nil {
		t.Fatalf("expected `yip ldr join request` to refuse existing sentinel destination")
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || !bytes.Equal(sentinelBytes, got) {
		t.Fatalf("`yip ldr join request` clobbered disposable sentinel!")
	}
	if _, err := os.Stat(unusedJoinDir); !os.IsNotExist(err) {
		t.Fatalf("failed `yip ldr join request` created target dir %s", unusedJoinDir)
	}
	selfCollisionDir := filepath.Join(tmp, "self-collision-join-dir")
	if err := LDRCLI([]string{"join", "request", "--dir", selfCollisionDir, "--descriptor", descFile, "--namespace", "ns-self", "--actor-limit", "2", "--reader", "--out", filepath.Join(selfCollisionDir, "cred.key")}, &joinSentinelBuf); err == nil {
		t.Fatalf("expected `yip ldr join request` with --out <dir>/cred.key to refuse clobbering cred.key")
	}
	if _, err := ldrclient.LoadCredentialKeys(filepath.Join(selfCollisionDir, "cred.key")); err != nil {
		t.Fatalf("`yip ldr join request` corrupted newly created cred.key: %v", err)
	}

	p3Enroll("alice", aliceDir, "ns-alice")
	p3Enroll("bob", bobDir, "ns-bob")

	// Repeated `yip ldr join request` against already-initialized aliceDir MUST fail
	// without overwriting aliceDir/cred.key!
	aliceCredBefore, err := os.ReadFile(filepath.Join(aliceDir, "cred.key"))
	if err != nil {
		t.Fatal(err)
	}
	var dupJoinBuf bytes.Buffer
	if err := LDRCLI([]string{"join", "request", "--dir", aliceDir, "--descriptor", descFile, "--namespace", "ns-alice", "--actor-limit", "2", "--reader", "--out", filepath.Join(tmp, "dup-alice.req.cbor")}, &dupJoinBuf); err == nil {
		t.Fatalf("expected repeated `yip ldr join request` on existing aliceDir to fail")
	}
	if got, err := os.ReadFile(filepath.Join(aliceDir, "cred.key")); err != nil || !bytes.Equal(aliceCredBefore, got) {
		t.Fatalf("failed `yip ldr join request` altered aliceDir/cred.key!")
	}

	// 6. Unactivated member directory aliceDir MUST NOT activate an epoch even with operator key!
	//    P9 epoch activation runs on the activated admin directory rootDir holding an enrolled reader.
	var badEpochBuf bytes.Buffer
	if err := LDRCLI([]string{"epoch", "activate", "--dir", aliceDir, "--operator-key", opKey}, &badEpochBuf); err == nil {
		t.Fatalf("expected `yip ldr epoch activate` to refuse on unactivated member dir aliceDir")
	}
	runLDR("epoch", "activate", "--dir", rootDir, "--operator-key", opKey)

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
