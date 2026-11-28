package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

// Each call reopens every directory as a fresh CLI/Switchboard process would.
func TestWizardTwoWorkstations(t *testing.T) {
	base := t.TempDir()
	path := func(parts ...string) string { return filepath.Join(append([]string{base}, parts...)...) }
	wizard := func(ok bool, role, step string, args ...string) string {
		t.Helper()
		var out bytes.Buffer
		err := LDRCLI(append([]string{"wizard", step, "--workspace", path(role)}, args...), &out)
		if (err == nil) != ok {
			t.Fatalf("%s/%s: %v (%s)", role, step, err, out.String())
		}
		return out.String()
	}
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := LDRCLI(args, &out); err != nil {
			t.Fatalf("%s: %v", args[0], err)
		}
		return out.String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wizard(true, "host", "host", "--url", "https://"+ln.Addr().String())
	for range 2 {
		wizard(true, "operator", "prepare", "--in", path("host", "share", "host.yip"))
		wizard(true, "host", "provision", "--in", path("operator", "share", "line.desc.cbor"))
	}
	dir := path("host", "relay")
	cfg, err := ldrrelay.ServerTLSConfig(filepath.Join(dir, "tls", "server.crt"), filepath.Join(dir, "tls", "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := ldrstore.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, err := ldrrelay.NewRelayEngine(store, ldrrelay.DefaultClockConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, e := os.ReadFile(path("operator", "share", "line.desc.cbor"))
	if e != nil {
		t.Fatal(e)
	}
	desc, _, _, _, e := ldrcrypto.VerifyCreationDescriptor(raw)
	if e != nil {
		t.Fatal(e)
	}
	principal := ldrcrypto.RootPrincipal(desc.RootKeys[0])
	token, e := ldrrelay.PrincipalToken(principal)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []ldrstore.StoredOpKey{{Generation: 1, SeenSeq: 1, Signer: token}, {Generation: 2, Signer: token}, {Generation: 1, Signer: "other"}} {
		if reply := engine.Query(desc.LineID, principal, key, [32]byte{}); reply.Class != ldrcore.ClassAdmission {
			t.Fatalf("unexpected bootstrap query result: %v", reply)
		}
	}
	var interruptSubmit atomic.Int32
	relay := ldrrelay.NewRelayServer(engine)
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/submit") && interruptSubmit.Load() > 0 && interruptSubmit.Add(-1) == 0 {
			http.Error(w, "fixture interrupted before delivery", http.StatusServiceUnavailable)
			return
		}
		relay.ServeHTTP(w, r)
	})}
	go server.Serve(tls.NewListener(ln, cfg))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	interruptSubmit.Store(1)
	wizard(false, "operator", "initialize")
	wizard(true, "operator", "initialize")
	wizard(true, "operator", "initialize")
	op := path("operator", "custody", "operator.key")
	admin := path("operator", "admin")
	for _, name := range []string{"alice", "bob"} {
		invitation := name + "-invitation"
		share := func(work, file string) string { return path(work, "share", file) }
		wizard(true, invitation, "invite", "--admin-dir", admin, "--operator-key", op, "--namespace", name)
		f := share(invitation, "invitation.yip")
		if name == "alice" {
			var inv wizardInvitation
			if e := wizardLoad(f, &inv); e != nil {
				t.Fatal(e)
			}
			inv.Limit++
			if e := wizardRecord(path("changed.yip"), inv); e != nil {
				t.Fatal(e)
			}
			wizard(false, name, "join", "--in", path("changed.yip"))
		}
		msg := wizard(true, name, "join", "--in", f)
		if !strings.Contains(msg, name) {
			t.Fatal(msg)
		}
		if name == "bob" {
			wizard(false, invitation, "review", "--in", share("alice", "request.cbor"))
			wizard(false, name, "join", "--in", share("alice-invitation", "invitation.yip"))
		}
		if got := wizard(true, name, "join", "--in", f); got != msg {
			t.Fatal("reopening changed the request")
		}
		_, d, e := ldrclient.LoadJoinRequest(share(name, "request.cbor"))
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(wizard(true, invitation, "review", "--in", share(name, "request.cbor")), wizardCode(d)) {
			t.Fatal("different review code")
		}
		wizard(false, invitation, "approve", "--code", "incorrect")
		for range 2 {
			wizard(true, invitation, "approve", "--code", wizardCode(d))
		}
		wizard(false, name, "activate")
		if name == "bob" {
			wizard(false, name, "prove", "--in", share("alice-invitation", "challenge.cbor"))
		}
		wizard(true, name, "prove", "--in", share(invitation, "challenge.cbor"))
		if name == "bob" {
			wizard(false, invitation, "admit", "--in", share("alice", "proof.cbor"))
		}
		if name == "alice" {
			interruptSubmit.Store(1)
		} else {
			interruptSubmit.Store(2)
		}
		wizard(false, invitation, "admit", "--in", share(name, "proof.cbor"))
		for range 2 {
			wizard(true, invitation, "admit", "--in", share(name, "proof.cbor"))
			wizard(true, name, "activate")
		}
		run("actor", "declare", "--dir", path(name, "client"), "--actor", name)
	}
	// A synced, authenticated transfer folder carries all four public files.
	// Its completion marker cannot activate a provisional workstation.
	exchange := path("exchange")
	wizard(true, "auto-invite", "invite", "--setup", path("operator"), "--namespace", "charlie", "--no-reader")
	offer := func(code string) string {
		t.Helper()
		return wizard(true, "auto-invite", "exchange-invite", "--exchange", exchange, "--code", code)
	}
	join := func() string { t.Helper(); return wizard(true, "charlie", "exchange-join", "--exchange", exchange) }
	offer("")
	join()
	_, digest, e := ldrclient.LoadJoinRequest(filepath.Join(exchange, "request.cbor"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(offer(""), wizardCode(digest)) {
		t.Fatal("expected operator review before approval")
	}
	wizard(false, "auto-invite", "exchange-invite", "--exchange", exchange, "--code", "wrong")
	offer(wizardCode(digest))
	join()
	if err := os.WriteFile(filepath.Join(exchange, "enrolled.txt"), []byte(fmt.Sprintf("%x\n", digest)), 0600); err != nil {
		t.Fatal(err)
	}
	wizard(false, "charlie", "exchange-join", "--exchange", exchange)
	offer("")
	if !strings.Contains(join(), "verified checkpoint") {
		t.Fatal("exchange did not activate")
	}
	wizard(false, "charlie", "exchange-join", "--exchange", path("charlie", "share"))
	cl, err := ldrclient.OpenClient(admin)
	if err != nil {
		t.Fatal(err)
	}
	s := cl.Status()
	cl.Close()
	if s.KeyEpoch != 4 {
		t.Fatalf("duplicate rotation: epoch %d", s.KeyEpoch)
	}
	run("call", "open", "--dir", path("alice", "client"), "--from", "alice", "--to", "bob", "--call", "onboarding", "--body", "Hello from Alice")
	if result := run("sync", "--dir", path("bob", "client"), "--project", "--scan"); !strings.Contains(result, `"notices_added":1`) {
		t.Fatalf("recipient delivery: %s", result)
	}
	run("call", "say", "--dir", path("bob", "client"), "--from", "bob", "--call", "onboarding", "--body", "Hello back")
	if result := run("call", "read", "--dir", path("alice", "client"), "--actor", "alice", "--call", "onboarding"); !strings.Contains(result, "Hello back") {
		t.Fatalf("recipient transcript: %s", result)
	}
	for _, role := range []string{"operator", "host", "alice", "bob", "alice-invitation", "bob-invitation"} {
		entries, e := os.ReadDir(path(role, "share"))
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			switch entry.Name() {
			case ".tmp", "line.desc.cbor", "host.yip", "invitation.yip", "request.cbor", "proof.cbor", "challenge.cbor":
			default:
				t.Fatalf("unexpected export: %s", entry.Name())
			}
		}
	}
}

func TestWizardTunnelCustody(t *testing.T) {
	base := t.TempDir()
	host := filepath.Join(base, "edge-host")
	setup := filepath.Join(base, "operator")
	run := func(step, workspace string, args ...string) error {
		return wizardCLI(append([]string{step, "--workspace", workspace}, args...), io.Discard)
	}
	url := "https://relay.example.org/v1/tunnel"
	if err := run("host", host, "--url", url, "--tunnel"); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(host, "share", "host.yip")
	alias := filepath.Join(base, "export-view")
	if err := os.Symlink(filepath.Join(host, "share"), alias); err != nil {
		t.Fatal(err)
	}
	if err := run("prepare", setup, "--in", bundle, "--root-a", filepath.Join(alias, "custody.key")); err == nil {
		t.Fatal("accepted export folder for secret key")
	}
	rootKey := filepath.Join(base, "offline", "root.key")
	if err := run("prepare", setup, "--in", bundle, "--root-a", rootKey); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(setup, "share", "line.desc.cbor")
	b, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	d, _, _, _, err := ldrcrypto.VerifyCreationDescriptor(b)
	if err != nil {
		t.Fatal(err)
	}
	o := d.RelayOrigin
	if o.URL != url || o.InnerServerName != "relay.example.org" || o.OuterTLSPolicy != ldrcrypto.TLSPolicyWebPKI || o.SessionBinding != ldrcrypto.SessionBindingWSTLS13Exporter {
		t.Fatalf("unexpected tunnel origin: %+v", o)
	}
	if err = run("provision", host, "--in", signed); err != nil {
		t.Fatal(err)
	}
	var h wizardHost
	if err = wizardLoad(bundle, &h); err != nil {
		t.Fatal(err)
	}
	args := h.serveArgs("data", "")
	if !slices.Equal(args, []string{"serve", "--dir", "data", "--listen", "off", "--tunnel-listen", "127.0.0.1:8080", "--tunnel-path", "/v1/tunnel"}) {
		t.Fatal(args)
	}
	if err = os.Rename(rootKey, rootKey+".offline"); err != nil {
		t.Fatal(err)
	}
	if err = run("prepare", setup, "--in", bundle, "--root-a", rootKey); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(rootKey); !os.IsNotExist(err) {
		t.Fatal("replaced a root that had been moved offline")
	}
}
