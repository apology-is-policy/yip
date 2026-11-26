package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

const relayUsage = `yip relay -- operator-hosted Long Distance Relay (TLS 1.3 + CRC32C WAL).

  yip relay init --dir <data_dir> [--hosts 127.0.0.1,localhost]
      Generate TLS 1.3 self-signed server certificate/key and print pin_spki_sha256.

  yip relay provision --dir <data_dir> --descriptor <file.cbor>
      Verify and atomically provision a root-signed creation descriptor locally.

  yip relay status --dir <data_dir>
      Verify stored WAL/sidecars and print JSON status of provisioned lines.

  yip relay serve --dir <data_dir> [--listen <addr|off>] [--tunnel-listen <loopback|unix:/path>] [--tunnel-path </v1/tunnel>] [--max-tunnels N] [--max-auth N] [--max-per-line N] [--cert <file>] [--key <file>] [--admin-sock <path>]
      Run the TLS 1.3 LDR relay server (direct and/or WS-tunneled inner TLS 1.3 behind an edge proxy) and local owner-only admin socket until SIGINT/SIGTERM.

  yip relay clock status [--dir <data_dir>] [--admin-sock <path>]
      Query live line and clock-guard status from a running relay via its local admin socket.

  yip relay clock resume [--dir <data_dir>] [--admin-sock <path>] [--line <hex>]
      Explicitly confirm host wall clock synchronization and resume a running relay's ClockGuard.
`

// RelayCLI dispatches `yip relay <init|provision|serve|status|clock>`.
func RelayCLI(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(out, relayUsage)
		return nil
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		return relayCLIInit(rest, out)
	case "provision":
		return relayCLIProvision(rest, out)
	case "status":
		return relayCLIStatus(rest, out)
	case "serve":
		return relayCLIServe(rest, out)
	case "clock":
		return relayCLIClock(rest, out)
	default:
		return fmt.Errorf("unknown relay subcommand %q\n\n%s", sub, relayUsage)
	}
}

func relayCLIInit(args []string, out io.Writer) error {
	var dir, hostsCSV string
	args, dir = takeFlag(args, "--dir", "")
	args, hostsCSV = takeFlag(args, "--hosts", "127.0.0.1,localhost")
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}
	if dir == "" {
		return errors.New("relay init requires --dir <data_dir>")
	}
	var hosts []string
	for _, h := range strings.Split(hostsCSV, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	certPath := filepath.Join(dir, "tls", "server.crt")
	keyPath := filepath.Join(dir, "tls", "server.key")
	pin, err := ldrrelay.InitSelfSignedCert(certPath, keyPath, hosts)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"cert":            certPath,
		"key":             keyPath,
		"hosts":           hosts,
		"tls_policy":      "pin_spki_sha256",
		"pin_spki_sha256": hex.EncodeToString(pin[:]),
	})
}

func relayCLIProvision(args []string, out io.Writer) error {
	var dir, descPath string
	args, dir = takeFlag(args, "--dir", "")
	args, descPath = takeFlag(args, "--descriptor", "")
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}
	if dir == "" || descPath == "" {
		return errors.New("relay provision requires --dir <data_dir> and --descriptor <file.cbor>")
	}
	raw, err := os.ReadFile(descPath)
	if err != nil {
		return err
	}
	st, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), nil)
	if err != nil {
		return err
	}
	prov, err := eng.Provision(raw)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"line_id":           hex.EncodeToString(prov.LineID),
		"descriptor_digest": hex.EncodeToString(prov.DescriptorDigest[:]),
		"genesis_anchor":    hex.EncodeToString(prov.GenesisAnchor[:]),
	})
}

func relayCLIStatus(args []string, out io.Writer) error {
	var dir string
	args, dir = takeFlag(args, "--dir", "")
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}
	if dir == "" {
		return errors.New("relay status requires --dir <data_dir>")
	}
	st, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"dir":   dir,
		"lines": eng.Status(),
	})
}

type relayServeOpts struct {
	MaxTunnels, MaxAuth, MaxPerLine int
	Dir                             string
	Listen                          string // direct TLS 1.3 listen addr, or "off" when TunnelListen is set
	TunnelListen                    string // optional loopback TCP (127.0.0.1:port, [::1]:port, localhost:port) or unix:/path
	TunnelPath                      string // optional WebSocket upgrade path (default /v1/tunnel)
	CertPath                        string
	KeyPath                         string
	AdminSock                       string
	ClockCfg                        ldrrelay.ClockConfig
	NowFn                           ldrrelay.ClockSource
	ReadyCh                         chan<- relayServeReady
}

type relayServeReady struct {
	ListenAddr string
	TunnelAddr string
	AdminSock  string
	Engine     *ldrrelay.RelayEngine
}

func validateTunnelListen(addr string) (network, cleanAddr string, err error) {
	if strings.HasPrefix(addr, "unix:") {
		p := strings.TrimSpace(strings.TrimPrefix(addr, "unix:"))
		if p == "" {
			return "", "", errors.New("relay serve --tunnel-listen unix: requires a socket path")
		}
		return "unix", p, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", "", fmt.Errorf("relay serve --tunnel-listen %q must be loopback host:port or unix:/path", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return "tcp", net.JoinHostPort("127.0.0.1", port), nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", "", fmt.Errorf("relay serve --tunnel-listen %q refused: plaintext edge-tunnel listener must bind a loopback address or owner-only unix: socket", addr)
	}
	return "tcp", addr, nil
}

func relayCLIServe(args []string, out io.Writer) error {
	var dir, listenAddr, tunnelListen, tunnelPath, certPath, keyPath, adminSock string
	args, dir = takeFlag(args, "--dir", "")
	args, listenAddr = takeFlag(args, "--listen", "127.0.0.1:8443")
	args, tunnelListen = takeFlag(args, "--tunnel-listen", "")
	args, tunnelPath = takeFlag(args, "--tunnel-path", "/v1/tunnel")
	args, certPath = takeFlag(args, "--cert", "")
	args, keyPath = takeFlag(args, "--key", "")
	args, adminSock = takeFlag(args, "--admin-sock", "")
	var limits [3]int
	for i, flag := range []string{"--max-tunnels", "--max-auth", "--max-per-line"} {
		var raw string
		args, raw = takeFlag(args, flag, "")
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 4096 {
			return fmt.Errorf("%s requires 1..4096", flag)
		}
		limits[i] = n
	}
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runRelayServe(ctx, relayServeOpts{
		Dir: dir, MaxTunnels: limits[0], MaxAuth: limits[1], MaxPerLine: limits[2],
		Listen:       listenAddr,
		TunnelListen: tunnelListen,
		TunnelPath:   tunnelPath,
		CertPath:     certPath,
		KeyPath:      keyPath,
		AdminSock:    adminSock,
		ClockCfg:     ldrrelay.DefaultClockConfig(),
	}, out)
}

func runRelayServe(ctx context.Context, opts relayServeOpts, out io.Writer) error {
	if opts.Dir == "" {
		return errors.New("relay serve requires --dir <data_dir>")
	}
	listenAddr := strings.TrimSpace(opts.Listen)
	tunnelListen := strings.TrimSpace(opts.TunnelListen)
	if strings.EqualFold(listenAddr, "off") || strings.EqualFold(listenAddr, "none") {
		if tunnelListen == "" {
			return errors.New("relay serve --listen off requires --tunnel-listen")
		}
		listenAddr = ""
	}
	if listenAddr == "" && tunnelListen == "" {
		listenAddr = "127.0.0.1:8443"
	}
	var tunnelNet, tunnelCleanAddr string
	if tunnelListen != "" {
		var err error
		tunnelNet, tunnelCleanAddr, err = validateTunnelListen(tunnelListen)
		if err != nil {
			return err
		}
	}
	certPath := opts.CertPath
	if certPath == "" {
		certPath = filepath.Join(opts.Dir, "tls", "server.crt")
	}
	keyPath := opts.KeyPath
	if keyPath == "" {
		keyPath = filepath.Join(opts.Dir, "tls", "server.key")
	}
	adminSock := opts.AdminSock
	if adminSock == "" {
		adminSock = ldrrelay.DefaultAdminSocketPath(opts.Dir)
	}
	tlsCfg, err := ldrrelay.ServerTLSConfig(certPath, keyPath)
	if err != nil {
		return err
	}
	st, err := ldrstore.OpenFileStore(opts.Dir)
	if err != nil {
		return err
	}
	eng, err := ldrrelay.NewRelayEngine(st, opts.ClockCfg, opts.NowFn)
	if err != nil {
		_ = st.Close()
		return err
	}
	relaySrv := ldrrelay.NewRelayServer(eng)
	if opts.MaxAuth <= 0 {
		opts.MaxAuth = 64
	}
	if opts.MaxPerLine <= 0 {
		opts.MaxPerLine = 256
	}
	relaySrv.ConfigureAdmission(opts.MaxAuth, opts.MaxPerLine)
	adminSrv, err := ldrrelay.StartAdminServer(adminSock, eng, relaySrv.AdmissionStatus)
	if err != nil {
		_ = eng.Shutdown()
		return err
	}

	var (
		directSrv  *http.Server
		directLn   net.Listener
		directAddr string
		tunnelSrv  *http.Server
		tunnelWS   *ldrrelay.WSTunnelServer
		tunnelLn   net.Listener
		tunnelAddr string
	)
	cleanupPreStart := func() {
		if directLn != nil {
			_ = directLn.Close()
		}
		if tunnelLn != nil {
			_ = tunnelLn.Close()
		}
		if tunnelWS != nil {
			_ = tunnelWS.Shutdown(context.Background())
		}
		_ = adminSrv.Close(context.Background())
		_ = eng.Shutdown()
	}

	if listenAddr != "" {
		rawLn, err := net.Listen("tcp", listenAddr)
		if err != nil {
			cleanupPreStart()
			return err
		}
		directLn = tls.NewListener(rawLn, tlsCfg)
		directAddr = rawLn.Addr().String()
		directSrv = &http.Server{
			Addr:              listenAddr,
			ReadTimeout:       30 * time.Second,
			Handler:           relaySrv,
			ReadHeaderTimeout: 10 * time.Second,
		}
		relaySrv.TrackConnections(directSrv)
	}

	if tunnelListen != "" {
		tunnelPath := opts.TunnelPath
		if tunnelPath == "" {
			tunnelPath = "/v1/tunnel"
		}
		wsSrv, err := ldrrelay.NewWSTunnelServer(relaySrv, tlsCfg, tunnelPath, opts.MaxTunnels)
		if err != nil {
			cleanupPreStart()
			return err
		}
		tunnelWS = wsSrv
		if tunnelNet == "unix" {
			if err := os.MkdirAll(filepath.Dir(tunnelCleanAddr), 0o700); err != nil {
				cleanupPreStart()
				return err
			}
			ln, err := net.Listen("unix", tunnelCleanAddr)
			if err != nil {
				cleanupPreStart()
				return err
			}
			if err := os.Chmod(tunnelCleanAddr, 0o600); err != nil {
				_ = ln.Close()
				cleanupPreStart()
				return err
			}
			tunnelLn = ln
			tunnelAddr = "unix:" + tunnelCleanAddr
		} else {
			ln, err := net.Listen("tcp", tunnelCleanAddr)
			if err != nil {
				cleanupPreStart()
				return err
			}
			tunnelLn = ln
			tunnelAddr = ln.Addr().String()
		}
		tunnelSrv = &http.Server{
			Handler:           tunnelWS,
			MaxHeaderBytes:    8192,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	// Periodic 1s clock-guard sampler for drift/freeze detection during idle stretches.
	sampleCtx, stopSample := context.WithCancel(ctx)
	defer stopSample()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-sampleCtx.Done():
				return
			case <-ticker.C:
				for _, st := range eng.Status() {
					id, err := hex.DecodeString(st.LineID)
					if err == nil {
						if cg, ok := eng.ClockGuardFor(id); ok {
							cg.Sample()
						}
					}
				}
			}
		}
	}()

	errCh := make(chan error, 2)
	if directSrv != nil {
		go func() {
			if err := directSrv.Serve(directLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		fmt.Fprintf(out, "yip relay listening on https://%s (direct TLS 1.3, dir=%s, admin=%s)\n", directAddr, opts.Dir, adminSock)
	}
	if tunnelSrv != nil {
		go func() {
			if err := tunnelSrv.Serve(tunnelLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		fmt.Fprintf(out, "yip relay ws-tunnel listening on %s (inner TLS 1.3, path=%s, dir=%s, admin=%s)\n", tunnelAddr, opts.TunnelPath, opts.Dir, adminSock)
	}

	if opts.ReadyCh != nil {
		opts.ReadyCh <- relayServeReady{
			ListenAddr: directAddr,
			TunnelAddr: tunnelAddr,
			AdminSock:  adminSock,
			Engine:     eng,
		}
	}

	shutdownAll := func() error {
		stopSample()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if directSrv != nil {
			_ = directSrv.Shutdown(shutCtx)
		}
		if tunnelSrv != nil {
			_ = tunnelSrv.Shutdown(shutCtx)
		}
		if tunnelWS != nil {
			_ = tunnelWS.Shutdown(shutCtx)
		}
		_ = adminSrv.Close(shutCtx)
		return eng.Shutdown()
	}

	select {
	case <-ctx.Done():
		return shutdownAll()
	case err := <-errCh:
		_ = shutdownAll()
		return err
	}
}

func relayCLIClock(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yip relay clock <status|resume> [--dir <data_dir>] [--admin-sock <path>] [--line <hex>]")
	}
	sub, rest := args[0], args[1:]
	var dir, adminSock, lineHex string
	rest, dir = takeFlag(rest, "--dir", "")
	rest, adminSock = takeFlag(rest, "--admin-sock", "")
	if sub == "resume" {
		rest, lineHex = takeFlag(rest, "--line", "")
		rest, lineHex = takeFlag(rest, "--line-id", lineHex)
	}
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}
	if adminSock == "" {
		if dir == "" {
			return fmt.Errorf("relay clock %s requires --dir <data_dir> or --admin-sock <path>", sub)
		}
		adminSock = ldrrelay.DefaultAdminSocketPath(dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch sub {
	case "status":
		status, err := ldrrelay.ReadAdminStatus(ctx, adminSock)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"admin_sock": adminSock,
			"lines":      status.Lines, "admission": status.Admission,
		})

	case "resume":
		var lineID []byte
		if lineHex != "" {
			var err error
			lineID, err = hex.DecodeString(strings.TrimSpace(lineHex))
			if err != nil || len(lineID) != 16 {
				return errors.New("relay clock resume --line must be 32 hex chars (16 bytes)")
			}
		}
		results, resumeErr := ldrrelay.AdminClockResume(ctx, adminSock, lineID)
		_ = json.NewEncoder(out).Encode(map[string]any{
			"admin_sock": adminSock,
			"ok":         resumeErr == nil,
			"results":    results,
		})
		return resumeErr

	default:
		return fmt.Errorf("unknown relay clock subcommand %q (expected status or resume)", sub)
	}
}
