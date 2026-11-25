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

  yip relay serve --dir <data_dir> --listen <addr> [--cert <file>] [--key <file>]
      Run the TLS 1.3 LDR relay server until SIGINT/SIGTERM.
`

// RelayCLI dispatches `yip relay <init|provision|serve|status>`.
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

func relayCLIServe(args []string, out io.Writer) error {
	var dir, listenAddr, certPath, keyPath string
	args, dir = takeFlag(args, "--dir", "")
	args, listenAddr = takeFlag(args, "--listen", "127.0.0.1:8443")
	args, certPath = takeFlag(args, "--cert", "")
	args, keyPath = takeFlag(args, "--key", "")
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}
	if dir == "" {
		return errors.New("relay serve requires --dir <data_dir>")
	}
	if certPath == "" {
		certPath = filepath.Join(dir, "tls", "server.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(dir, "tls", "server.key")
	}
	tlsCfg, err := ldrrelay.ServerTLSConfig(certPath, keyPath)
	if err != nil {
		return err
	}
	st, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		return err
	}
	eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), nil)
	if err != nil {
		_ = st.Close()
		return err
	}
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           ldrrelay.NewRelayServer(eng),
		ReadHeaderTimeout: 10 * time.Second,
	}
	rawLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = eng.Shutdown()
		return err
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodic 1s clock-guard sampler for drift/freeze detection during idle stretches.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
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

	fmt.Fprintf(out, "yip relay listening on https://%s (TLS 1.3, dir=%s)\n", rawLn.Addr().String(), dir)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return eng.Shutdown()
	case err := <-errCh:
		_ = eng.Shutdown()
		return err
	}
}
