package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

type wizardHost struct {
	Version int    `json:"version"`
	URL     string `json:"url"`
	Pin     string `json:"pin_spki_sha256"`
	Tunnel  bool   `json:"websocket_tunnel"`
}

func (h wizardHost) origin() (ldrcrypto.RelayOrigin, error) {
	pin, err := hex.DecodeString(h.Pin)
	o := ldrcrypto.RelayOrigin{URL: h.URL, TLSPin: pin, TLSPolicy: ldrcrypto.TLSPolicyPinSPKISHA256, SessionBinding: ldrcrypto.SessionBindingTLS13Exporter}
	if err != nil || h.Version != 1 {
		return o, errors.New("invalid relay host identity")
	}
	u, err := url.Parse(h.URL)
	if err != nil {
		return o, err
	}
	if h.Tunnel {
		o.SessionBinding = ldrcrypto.SessionBindingWSTLS13Exporter
		o.InnerServerName = u.Hostname()
		o.OuterTLSPolicy = ldrcrypto.TLSPolicyWebPKI
	} else if u.Path != "" && u.Path != "/" {
		return o, errors.New("use an HTTPS origin without a path for a direct relay, or select WebSocket tunnel")
	}
	return o, o.Validate()
}

func (h wizardHost) serveArgs(dir, override string) []string {
	u, _ := url.Parse(h.URL)
	if h.Tunnel {
		if override == "" {
			override = "127.0.0.1:8080"
		}
		return []string{"serve", "--dir", dir, "--listen", "off", "--tunnel-listen", override, "--tunnel-path", u.Path}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	host := ""
	if u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback() {
		host = u.Hostname()
	}
	if override == "" {
		override = net.JoinHostPort(host, port)
	}
	return []string{"serve", "--dir", dir, "--listen", override}
}

type wizardCustody struct{ RootA, RootB, Operator string }

func (w wizardArgs) setup() (string, error) {
	switch w.step {
	case "host":
		h := wizardHost{Version: 1, URL: w.url, Tunnel: w.tunnel, Pin: strings.Repeat("00", 32)}
		if _, err := h.origin(); err != nil {
			return "", err
		}
		u, _ := url.Parse(w.url)
		dir := w.path("relay")
		pin, err := ldrrelay.InitSelfSignedCert(filepath.Join(dir, "tls", "server.crt"), filepath.Join(dir, "tls", "server.key"), []string{u.Hostname()})
		if err != nil {
			return "", err
		}
		h.Pin = hex.EncodeToString(pin[:])
		if err = wizardRecord(w.path("host.yip"), h); err != nil {
			return "", err
		}
		dst := w.shared("host.yip")
		if err = wizardCopy(w.path("host.yip"), dst); err != nil {
			return "", err
		}
		return fmt.Sprintf("Send %s to the operator through an authenticated channel. It identifies %s. The TLS private key stays on this host.", dst, h.URL), nil
	case "provision":
		var h wizardHost
		if err := wizardLoad(w.path("host.yip"), &h); err != nil {
			return "", err
		}
		o, err := h.origin()
		if err != nil {
			return "", err
		}
		raw, err := wizardRead(w.input)
		if err != nil {
			return "", err
		}
		d, cd, _, _, err := ldrcrypto.VerifyCreationDescriptor(raw)
		if err != nil {
			return "", err
		}
		got := d.RelayOrigin
		if got.URL != o.URL || got.SessionBinding != o.SessionBinding || got.TLSPolicy != o.TLSPolicy ||
			!bytes.Equal(got.TLSPin, o.TLSPin) || got.InnerServerName != o.InnerServerName ||
			got.OuterTLSPolicy != o.OuterTLSPolicy || !bytes.Equal(got.OuterTLSPin, o.OuterTLSPin) {
			return "", errors.New("the signed line names another relay identity")
		}
		if err = wizardSave(w.path("line.desc.cbor"), raw); err != nil {
			return "", err
		}
		dir := w.path("relay")
		st, err := ldrstore.OpenFileStore(dir)
		if err != nil {
			return "", err
		}
		defer st.Close()
		eng, err := ldrrelay.NewRelayEngine(st, ldrrelay.DefaultClockConfig(), nil)
		if err != nil {
			return "", err
		}
		if _, current, _, found := eng.LineDescriptor(d.LineID); found {
			if current != cd {
				return "", errors.New("this line ID is already provisioned with another descriptor")
			}
		} else if _, err = eng.Provision(raw); err != nil {
			return "", err
		}
		if err = wizardSave(w.path("provisioned"), cd[:]); err != nil {
			return "", err
		}
		parts := []string{"yip", "relay"}
		for _, a := range h.serveArgs(dir, "") {
			parts = append(parts, shellQuote(a))
		}
		next := "Start the relay under your service manager or in a second terminal."
		if h.Tunnel {
			next += " Route the public WebSocket path to HTTP on 127.0.0.1:8080."
		}
		return fmt.Sprintf("Provisioned line %x. %s\n%s\nThen choose Initialize line on the operator workstation.", d.LineID, next, strings.Join(parts, " ")), nil
	case "prepare":
		return w.prepare()
	default:
		return w.initialize()
	}
}

func (w wizardArgs) keyPath(path, name string) (string, error) {
	if path == "" {
		return w.path(filepath.Join("custody", name+".key")), nil
	}
	p, err := ldrclient.CanonicalPath(path)
	if err != nil {
		return "", err
	}
	if err = wizardPrivateLocation(p); err != nil {
		return "", err
	}
	if wizardContains(w.workspace, p) {
		return "", errors.New("choose an external key path or leave it empty for the private custody directory")
	}
	return p, nil
}

func wizardKey(path, pubFile string) (ldrcrypto.PublicKey, error) {
	var zero ldrcrypto.PublicKey
	saved, err := wizardExists(pubFile)
	if err != nil {
		return zero, err
	}
	if saved {
		// A removed offline root must never be regenerated on a retry.
		return ldrclient.LoadPublicKey(pubFile)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return zero, err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = wizardLDR("root", "keygen", "--out", path); err != nil {
			return zero, err
		}
	} else if err != nil {
		return zero, err
	} else if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return zero, fmt.Errorf("expected a private regular key file at %s", path)
	}
	km, err := ldrclient.LoadSigningKey(path)
	if err != nil {
		return zero, err
	}
	pk := km.Signer.PublicKey()
	b, err := pk.CanonicalBytes()
	if err != nil {
		return zero, err
	}
	return pk, wizardSave(pubFile, b)
}

func (w wizardArgs) prepare() (string, error) {
	var h wizardHost
	if err := wizardLoad(w.input, &h); err != nil {
		return "", err
	}
	origin, err := h.origin()
	if err != nil {
		return "", err
	}
	if err = wizardRecord(w.path("host.yip"), h); err != nil {
		return "", err
	}
	a, err := w.keyPath(w.rootA, "root-a")
	if err != nil {
		return "", err
	}
	b, err := w.keyPath(w.rootB, "root-b")
	if err != nil {
		return "", err
	}
	op, err := w.keyPath(w.operator, "operator")
	if err != nil {
		return "", err
	}
	custody := wizardCustody{a, b, op}
	for _, pair := range [][2]string{{a, b}, {a, op}, {b, op}} {
		alias, e := ldrclient.PathsAlias(pair[0], pair[1])
		if e != nil {
			return "", e
		}
		if alias {
			return "", errors.New("choose three distinct signing keys")
		}
	}
	if err = wizardRecord(w.path("custody.json"), custody); err != nil {
		return "", err
	}
	pkA, err := wizardKey(a, w.path("root-a.pub"))
	if err != nil {
		return "", err
	}
	pkB, err := wizardKey(b, w.path("root-b.pub"))
	if err != nil {
		return "", err
	}
	pkOp, err := wizardKey(op, w.path("operator.pub"))
	if err != nil {
		return "", err
	}
	if pkA.Equal(pkB) || pkA.Equal(pkOp) || pkB.Equal(pkOp) {
		return "", errors.New("both roots and the operator must have distinct keys")
	}
	path := w.path("line.desc.cbor")
	ok, err := wizardExists(path)
	if err != nil {
		return "", err
	}
	if !ok {
		args := []string{"root", "descriptor", "--root1", w.path("root-a.pub"), "--root2", w.path("root-b.pub"), "--signer", a, "--url", origin.URL, "--tls-pin", h.Pin, "--out", path}
		if h.Tunnel {
			args = append(args, "--session-binding", origin.SessionBinding, "--inner-server-name", origin.InnerServerName, "--outer-tls-policy", origin.OuterTLSPolicy)
		}
		if err = wizardLDR(args...); err != nil {
			return "", err
		}
	}
	dst := w.shared("line.desc.cbor")
	if err = wizardCopy(path, dst); err != nil {
		return "", err
	}
	return fmt.Sprintf("Send %s to the relay host for provisioning. Then start the relay.\nFirst root: %s\nSecond root: %s\nDaily operator key: %s\nKeep the first root available for Initialize line. Store the two roots separately afterward.", dst, a, b, op), nil
}

func (w wizardArgs) initialize() (string, error) {
	var custody wizardCustody
	if err := wizardLoad(w.path("custody.json"), &custody); err != nil {
		return "", err
	}
	raw, err := wizardRead(w.path("line.desc.cbor"))
	if err != nil {
		return "", err
	}
	dir := w.path("admin")
	auth := wizardAuthority{dir, custody.Operator}
	if err = wizardInitDir(dir, func(tmp string) error {
		cl, e := ldrclient.InitClientDir(ldrclient.InitDirOptions{Dir: tmp, DirKind: ldrclient.DirKindAdmin, SignedDescriptor: raw, Activated: true})
		if e == nil {
			cl.Close()
		}
		return e
	}); err != nil {
		return "", err
	}
	op, err := ldrclient.LoadSigningKey(custody.Operator)
	if err != nil {
		return "", err
	}
	opPub, err := ldrclient.LoadPublicKey(w.path("operator.pub"))
	if err != nil || !op.Signer.PublicKey().Equal(opPub) {
		return "", errors.New("operator key differs from the saved setup")
	}
	if ok, e := wizardExists(w.path("operator-authorized")); e != nil {
		return "", e
	} else if !ok {
		root, e := ldrclient.LoadSigningKey(custody.RootA)
		if e != nil {
			return "", e
		}
		cl, e := ldrclient.OpenClient(dir)
		if e != nil {
			return "", e
		}
		if !bytes.Equal(raw, cl.SignedDescriptor()) {
			cl.Close()
			return "", errors.New("administrator pinned a different descriptor")
		}
		tok, e := ldrrelay.KeyToken(opPub)
		if e != nil {
			cl.Close()
			return "", e
		}
		_, cd, _, _ := cl.Descriptor()
		initAction := fmt.Sprintf("wizard-init:%x", cd)
		authorizeAction := "wizard-authorize:" + tok
		line, e := wizardAnchor(cl, root, true, initAction, authorizeAction)
		if e == nil && line.Generation == 0 {
			e = ldrInitializeClient(cl, root, io.Discard, initAction)
		}
		cl.Close()
		if e != nil {
			return "", e
		}
		if !slices.Contains(line.Operators, tok) {
			if e = ldrRootAction([]string{"authorize-operator", "--dir", dir, "--root-key", custody.RootA, "--operator-pub", w.path("operator.pub")}, io.Discard, authorizeAction); e != nil {
				return "", e
			}
		}
		if e = wizardSave(w.path("operator-authorized"), []byte(tok)); e != nil {
			return "", e
		}
	}
	reqPath := w.path("admin-request.cbor")
	ok, err := wizardExists(reqPath)
	if err != nil {
		return "", err
	}
	if !ok {
		if err = wizardLDR("root", "reader-request", "--dir", dir, "--namespace", "relay-operator", "--out", reqPath); err != nil {
			return "", err
		}
	}
	_, dig, err := ldrclient.LoadJoinRequest(reqPath)
	if err != nil {
		return "", err
	}
	if err = w.challenge(custody.Operator, reqPath, dig); err != nil {
		return "", err
	}
	proof := w.path("admin-proof.cbor")
	ok, err = wizardExists(proof)
	if err != nil {
		return "", err
	}
	if !ok {
		if err = wizardLDR("join", "prove", "--dir", dir, "--operator-pub", w.path("operator.pub"), "--request", reqPath, "--challenge", w.path("challenge.cbor"), "--out", proof); err != nil {
			return "", err
		}
	}
	if err = w.enroll(auth, reqPath, proof); err != nil {
		return "", err
	}
	return fmt.Sprintf("Line ready. Put each root key in its chosen offline location. Either root can recover authority.\nFor Invite a workstation, use operator client %s and signing key %s.", dir, custody.Operator), nil
}
