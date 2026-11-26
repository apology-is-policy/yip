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

  yip relay serve --dir <data_dir> --listen <addr> [--cert <file>] [--key <file>] [--admin-sock <path>]
      Run the TLS 1.3 LDR relay server and local owner-only admin socket until SIGINT/SIGTERM.

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
	Dir       string
	Listen    string
	CertPath  string
	KeyPath   string
	AdminSock string
	ClockCfg  ldrrelay.ClockConfig
	NowFn     ldrrelay.ClockSource
	ReadyCh   chan<- relayServeReady
}

type relayServeReady struct {
	ListenAddr string
	AdminSock  string
	Engine     *ldrrelay.RelayEngine
}

func relayCLIServe(args []string, out io.Writer) error {
	var dir, listenAddr, certPath, keyPath, adminSock string
	args, dir = takeFlag(args, "--dir", "")
	args, listenAddr = takeFlag(args, "--listen", "127.0.0.1:8443")
	args, certPath = takeFlag(args, "--cert", "")
	args, keyPath = takeFlag(args, "--key", "")
	args, adminSock = takeFlag(args, "--admin-sock", "")
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runRelayServe(ctx, relayServeOpts{
		Dir:       dir,
		Listen:    listenAddr,
		CertPath:  certPath,
		KeyPath:   keyPath,
		AdminSock: adminSock,
		ClockCfg:  ldrrelay.DefaultClockConfig(),
	}, out)
}

func runRelayServe(ctx context.Context, opts relayServeOpts, out io.Writer) error {
	if opts.Dir == "" {
		return errors.New("relay serve requires --dir <data_dir>")
	}
	listenAddr := opts.Listen
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8443"
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
	adminSrv, err := ldrrelay.StartAdminServer(adminSock, eng)
	if err != nil {
		_ = eng.Shutdown()
		return err
	}
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           ldrrelay.NewRelayServer(eng),
		ReadHeaderTimeout: 10 * time.Second,
	}
	rawLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = adminSrv.Close(context.Background())
		_ = eng.Shutdown()
		return err
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)

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

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	fmt.Fprintf(out, "yip relay listening on https://%s (TLS 1.3, dir=%s, admin=%s)\n", rawLn.Addr().String(), opts.Dir, adminSock)
	if opts.ReadyCh != nil {
		opts.ReadyCh <- relayServeReady{
			ListenAddr: rawLn.Addr().String(),
			AdminSock:  adminSock,
			Engine:     eng,
		}
	}

	select {
	case <-ctx.Done():
		stopSample()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = adminSrv.Close(shutCtx)
		return eng.Shutdown()
	case err := <-errCh:
		stopSample()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = adminSrv.Close(shutCtx)
		_ = eng.Shutdown()
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
		lines, err := ldrrelay.AdminStatus(ctx, adminSock)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"admin_sock": adminSock,
			"lines":      lines,
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
