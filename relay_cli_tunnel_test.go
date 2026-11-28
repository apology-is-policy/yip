package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
)

func TestRelayServeTunnelListenLoopbackUnixSocketAndCLIDescriptor(t *testing.T) {
	// 1. Non-loopback plaintext --tunnel-listen MUST be refused!
	for _, bad := range []string{"0.0.0.0:8080", "[::]:8080", ":8080", "192.0.2.10:8080", "unix:"} {
		if _, _, err := validateTunnelListen(bad); err == nil {
			t.Fatalf("validateTunnelListen(%q) unexpectedly accepted", bad)
		}
	}
	for _, good := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "unix:/tmp/yip-test.sock"} {
		if _, _, err := validateTunnelListen(good); err != nil {
			t.Fatalf("validateTunnelListen(%q) unexpectedly rejected: %v", good, err)
		}
	}

	// 2. Initialize relay cert for dedicated inner server name "relay-origin.internal"
	//    and build a ws_tls13_exporter descriptor via `yip ldr root descriptor`.
	work := t.TempDir()
	relayDir := filepath.Join(work, "relay")
	var initBuf bytes.Buffer
	if err := RelayCLI([]string{"init", "--dir", relayDir, "--hosts", "relay-origin.internal"}, &initBuf); err != nil {
		t.Fatalf("relay init: %v", err)
	}
	var initResp struct {
		Pin string `json:"pin_spki_sha256"`
	}
	if err := json.Unmarshal(initBuf.Bytes(), &initResp); err != nil || len(initResp.Pin) != 64 {
		t.Fatalf("unexpected relay init output: %s", initBuf.String())
	}

	// Start a simulated outer TLS edge proxy pointing to an owner-only Unix domain socket!
	// Use /tmp short path for macOS 104-char sun_path limit.
	sockDir, err := os.MkdirTemp("/tmp", "yip-ws-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "t.sock")

	existingPath := filepath.Join(sockDir, "live.sock")
	existing, err := net.Listen("unix", existingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	probeCtx, stopProbe := context.WithTimeout(context.Background(), time.Second)
	defer stopProbe()
	if err := runRelayServe(probeCtx, relayServeOpts{
		Dir: relayDir, Listen: "off", TunnelListen: "unix:" + existingPath,
		AdminSock: filepath.Join(sockDir, "probe.sock"), ClockCfg: ldrrelay.DefaultClockConfig(),
	}, io.Discard); err == nil {
		t.Fatal("tunnel listener replaced an existing socket")
	}
	probe, err := net.DialTimeout("unix", existingPath, time.Second)
	if err != nil {
		t.Fatalf("existing socket no longer reachable: %v", err)
	}
	_ = probe.Close()

	edgeDir := filepath.Join(work, "edge")
	edgeCert := filepath.Join(edgeDir, "edge.crt")
	edgeKey := filepath.Join(edgeDir, "edge.key")
	edgePin, err := ldrrelay.InitSelfSignedCert(edgeCert, edgeKey, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	edgeTLSCfg, err := ldrrelay.InnerTunnelServerTLSConfig(edgeCert, edgeKey)
	if err != nil {
		t.Fatal(err)
	}
	edgeRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	edgeTLSLn := tls.NewListener(edgeRawLn, edgeTLSCfg)
	t.Cleanup(func() { _ = edgeTLSLn.Close() })
	go func() {
		for {
			cc, err := edgeTLSLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				be, err := net.DialTimeout("unix", sockPath, 5*time.Second)
				if err != nil {
					return
				}
				defer be.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(be, c); _ = be.Close(); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, be); _ = c.Close(); done <- struct{}{} }()
				<-done
				<-done
			}(cc)
		}
	}()

	// Generate two roots + ws_tls13_exporter descriptor through LDRCLI!
	r1Key := filepath.Join(work, "r1.key")
	r1Pub := filepath.Join(work, "r1.pub")
	r2Key := filepath.Join(work, "r2.key")
	r2Pub := filepath.Join(work, "r2.pub")
	if err := LDRCLI([]string{"root", "keygen", "--out", r1Key, "--pub", r1Pub}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := LDRCLI([]string{"root", "keygen", "--out", r2Key, "--pub", r2Pub}, io.Discard); err != nil {
		t.Fatal(err)
	}

	descPath := filepath.Join(work, "line.desc.cbor")
	var descBuf bytes.Buffer
	if err := LDRCLI([]string{
		"root", "descriptor",
		"--root1", r1Pub, "--root2", r2Pub, "--signer", r1Key,
		"--session-binding", ldrcrypto.SessionBindingWSTLS13Exporter,
		"--url", "https://" + edgeRawLn.Addr().String() + "/v1/tunnel",
		"--outer-tls-policy", ldrcrypto.TLSPolicyPinSPKISHA256,
		"--outer-tls-pin", hex.EncodeToString(edgePin[:]),
		"--inner-server-name", "relay-origin.internal",
		"--tls-policy", ldrcrypto.TLSPolicyPinSPKISHA256,
		"--tls-pin", initResp.Pin,
		"--out", descPath,
	}, &descBuf); err != nil {
		t.Fatalf("root descriptor ws_tls13_exporter: %v", err)
	}
	var descOut struct {
		LineID string `json:"line_id"`
	}
	if err := json.Unmarshal(descBuf.Bytes(), &descOut); err != nil || descOut.LineID == "" {
		t.Fatalf("unexpected descriptor output: %s", descBuf.String())
	}

	// Provision on relay!
	if err := RelayCLI([]string{"provision", "--dir", relayDir, "--descriptor", descPath}, io.Discard); err != nil {
		t.Fatalf("relay provision: %v", err)
	}

	// Start relay with --listen off and --tunnel-listen unix:<sockPath>!
	serveCtx, cancelServe := context.WithCancel(context.Background())
	readyCh := make(chan relayServeReady, 1)
	serveErrCh := make(chan error, 1)
	var serveOut bytes.Buffer
	go func() {
		serveErrCh <- runRelayServe(serveCtx, relayServeOpts{
			Dir:          relayDir,
			Listen:       "off",
			TunnelListen: "unix:" + sockPath,
			TunnelPath:   "/v1/tunnel",
			AdminSock:    filepath.Join(sockDir, "a.sock"),
			ClockCfg:     ldrrelay.DefaultClockConfig(),
			ReadyCh:      readyCh,
		}, &serveOut)
	}()

	select {
	case rdy := <-readyCh:
		if rdy.ListenAddr != "" || !strings.HasPrefix(rdy.TunnelAddr, "unix:") {
			t.Fatalf("unexpected ready state: %+v", rdy)
		}
	case err := <-serveErrCh:
		t.Fatalf("runRelayServe exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runRelayServe")
	}

	// Confirm Unix socket is owner-only (0600)!
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat tunnel socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected tunnel socket mode 0600, got %o", perm)
	}

	// Run real `yip ldr root init-line` through the edge proxy -> Unix socket -> inner TLS 1.3!
	adminDir := filepath.Join(work, "admin")
	if err := LDRCLI([]string{"root", "init-line", "--dir", adminDir, "--descriptor", descPath, "--root-key", r1Key}, io.Discard); err != nil {
		t.Fatalf("root init-line over ws_tls13_exporter unix socket: %v", err)
	}
	cl, err := ldrclient.OpenClient(adminDir)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Status().CheckpointSeq != 1 {
		_ = cl.Close()
		t.Fatalf("expected checkpoint seq 1 after init-line, got %+v", cl.Status())
	}
	_ = cl.Close()

	// Shutdown cleanly and confirm Unix socket file is removed!
	cancelServe()
	if err := <-serveErrCh; err != nil {
		t.Fatalf("runRelayServe shutdown error: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected tunnel socket cleaned up on shutdown, stat err=%v", err)
	}
}
