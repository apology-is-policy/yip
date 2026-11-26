package ldrrelay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

const tlsExporterLabel = "EXPORTER-Channel-Binding"

var (
	ErrTLSVersionRejected   = errors.New("ldrrelay: TLS 1.3 required")
	ErrTLSPinMismatch       = errors.New("ldrrelay: TLS SPKI pin mismatch")
	ErrUnsupportedTransport = errors.New("ldrrelay: session_binding mode not yet supported by client")
	ErrTLSOutputExists      = errors.New("ldrrelay: TLS output already exists")
	ErrTLSOutputCollision   = errors.New("ldrrelay: cert and key paths must not alias")
)

// InitSelfSignedCert generates an ECDSA P-256 self-signed server certificate
// with explicit IP and DNS SANs, publishes keyPath (0600) and certPath (0644)
// atomically without clobbering unrelated files, and returns the 32-byte
// SHA-256(SPKI) pin for pin_spki_sha256. Interrupted initializations (such as
// post-link directory sync failures or second-output write failures) are
// recoverable on retry while preserving the matching key/cert identity. When
// keyPath already exists without certPath, any existing regular standalone
// ECDSA P-256 "EC PRIVATE KEY" PEM file is accepted by format (preserving its
// bytes unchanged, without asserting provenance that a prior relay init
// created it) to mint the matching certificate at certPath.
func InitSelfSignedCert(certPath, keyPath string, hosts []string) ([32]byte, error) {
	return initSelfSignedCertWithHooks(certPath, keyPath, hosts, nil, nil)
}

func initSelfSignedCertWithHooks(
	certPath, keyPath string,
	hosts []string,
	syncFile func(*os.File) error,
	syncDir func(string) error,
) ([32]byte, error) {
	var zero [32]byte
	if certPath == "" || keyPath == "" {
		return zero, errors.New("ldrrelay: empty cert or key path")
	}
	wantIPs, wantDNS, err := parseTLSHosts(hosts)
	if err != nil {
		return zero, err
	}
	alias, err := tlsPathsAlias(certPath, keyPath)
	if err != nil {
		return zero, err
	}
	if alias {
		return zero, ErrTLSOutputCollision
	}

	_, keyStatErr := os.Lstat(keyPath)
	keyExists := false
	if keyStatErr == nil {
		keyExists = true
	} else if !os.IsNotExist(keyStatErr) {
		return zero, keyStatErr
	}

	_, certStatErr := os.Lstat(certPath)
	certExists := false
	if certStatErr == nil {
		certExists = true
	} else if !os.IsNotExist(certStatErr) {
		return zero, certStatErr
	}

	switch {
	case !keyExists && !certExists:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return zero, err
		}
		keyDER, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return zero, err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		certPEM, spkiPin, err := mintRelaySelfSignedCert(priv, wantIPs, wantDNS)
		if err != nil {
			return zero, err
		}
		if err := publishFileCreateOnlyWithHooks(keyPath, keyPEM, 0o600, syncFile, syncDir); err != nil {
			return zero, err
		}
		if err := publishFileCreateOnlyWithHooks(certPath, certPEM, 0o644, syncFile, syncDir); err != nil {
			// Preserve keyPath on both pre-link and post-link failures so retry
			// can recover the exact matching identity without creating an orphan cert.
			return zero, err
		}
		return spkiPin, nil

	case keyExists && !certExists:
		// Recover when keyPath exists without certPath (e.g., key-dir SyncDir
		// failed or certPath write failed pre-link). Accepts an existing regular
		// standalone ECDSA P-256 PEM key by format (preserving its bytes without
		// establishing prior relay-init provenance) and mints a matching cert.
		priv, _, err := loadExistingRelayKey(keyPath)
		if err != nil {
			return zero, fmt.Errorf("%w: %s: %v", ErrTLSOutputExists, keyPath, err)
		}
		if err := syncTLSFileAndDir(keyPath, syncFile, syncDir); err != nil {
			return zero, err
		}
		certPEM, spkiPin, err := mintRelaySelfSignedCert(priv, wantIPs, wantDNS)
		if err != nil {
			return zero, err
		}
		if err := publishFileCreateOnlyWithHooks(certPath, certPEM, 0o644, syncFile, syncDir); err != nil {
			return zero, err
		}
		return spkiPin, nil

	case !keyExists && certExists:
		// Cannot reconstruct a private key from an existing certificate; refuse
		// without touching certPath or creating keyPath.
		return zero, fmt.Errorf("%w: %s exists without matching key %s", ErrTLSOutputExists, certPath, keyPath)

	default:
		// Both keyPath and certPath exist. Allow recovery ONLY when both are
		// regular files forming a valid, matching, currently valid self-signed
		// relay pair for the exact requested hosts, and only after passing
		// durability barriers on both files and their parent directories.
		priv, keyRaw, err := loadExistingRelayKey(keyPath)
		if err != nil {
			return zero, fmt.Errorf("%w: %s: %v", ErrTLSOutputExists, keyPath, err)
		}
		cert, certRaw, err := loadExistingRelayCert(certPath)
		if err != nil {
			return zero, fmt.Errorf("%w: %s: %v", ErrTLSOutputExists, certPath, err)
		}
		spkiPin, err := verifyExistingRelayPair(cert, certRaw, priv, keyRaw, wantIPs, wantDNS)
		if err != nil {
			return zero, fmt.Errorf("%w: %v", ErrTLSOutputExists, err)
		}
		if err := syncTLSFileAndDir(keyPath, syncFile, syncDir); err != nil {
			return zero, err
		}
		if err := syncTLSFileAndDir(certPath, syncFile, syncDir); err != nil {
			return zero, err
		}
		return spkiPin, nil
	}
}

func parseTLSHosts(hosts []string) ([]net.IP, []string, error) {
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}
	seenIP := make(map[string]net.IP)
	seenDNS := make(map[string]struct{})
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				ip = append(net.IP(nil), ip4...)
			} else {
				ip = append(net.IP(nil), ip.To16()...)
			}
			seenIP[string(ip.To16())] = ip
		} else {
			seenDNS[strings.ToLower(h)] = struct{}{}
		}
	}
	ips := make([]net.IP, 0, len(seenIP))
	for _, ip := range seenIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i].To16(), ips[j].To16()) < 0
	})
	dns := make([]string, 0, len(seenDNS))
	for d := range seenDNS {
		dns = append(dns, d)
	}
	sort.Strings(dns)
	if len(ips) == 0 && len(dns) == 0 {
		return nil, nil, errors.New("ldrrelay: at least one valid IP or DNS host required")
	}
	return ips, dns, nil
}

func mintRelaySelfSignedCert(priv *ecdsa.PrivateKey, ips []net.IP, dns []string) ([]byte, [32]byte, error) {
	var zero [32]byte
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, zero, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "yip-ldr-relay",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, zero, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, zero, err
	}
	spkiPin := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, spkiPin, nil
}

func loadExistingRelayKey(path string) (*ecdsa.PrivateKey, []byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	blk, rest := pem.Decode(raw)
	if blk == nil || len(bytes.TrimSpace(rest)) != 0 || blk.Type != "EC PRIVATE KEY" || len(blk.Headers) != 0 {
		return nil, nil, errors.New("not a standalone EC PRIVATE KEY PEM file")
	}
	priv, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if priv.Curve != elliptic.P256() {
		return nil, nil, errors.New("existing key is not ECDSA P-256")
	}
	return priv, raw, nil
}

func loadExistingRelayCert(path string) (*x509.Certificate, []byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	blk, rest := pem.Decode(raw)
	if blk == nil || len(bytes.TrimSpace(rest)) != 0 || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
		return nil, nil, errors.New("not a standalone CERTIFICATE PEM file")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, raw, nil
}

func verifyExistingRelayPair(
	cert *x509.Certificate,
	certRaw []byte,
	priv *ecdsa.PrivateKey,
	keyRaw []byte,
	wantIPs []net.IP,
	wantDNS []string,
) ([32]byte, error) {
	var zero [32]byte
	if cert.Subject.CommonName != "yip-ldr-relay" || cert.Issuer.CommonName != "yip-ldr-relay" {
		return zero, errors.New("certificate is not a yip-ldr-relay self-signed cert")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return zero, errors.New("certificate basic constraints do not match relay leaf cert")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return zero, errors.New("certificate key usage does not match relay server cert")
	}
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return zero, errors.New("existing certificate is expired or not yet valid")
	}
	if !priv.PublicKey.Equal(cert.PublicKey) {
		return zero, errors.New("existing certificate public key does not match private key")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return zero, fmt.Errorf("existing certificate self-signature invalid: %v", err)
	}
	if _, err := tls.X509KeyPair(certRaw, keyRaw); err != nil {
		return zero, fmt.Errorf("existing cert/key pair not loadable: %v", err)
	}
	gotIPs, gotDNS := canonicalCertSANs(cert)
	if len(gotIPs) != len(wantIPs) || len(gotDNS) != len(wantDNS) {
		return zero, errors.New("existing certificate SANs do not match requested hosts")
	}
	for i := range wantIPs {
		if !bytes.Equal(gotIPs[i].To16(), wantIPs[i].To16()) {
			return zero, errors.New("existing certificate IP SANs do not match requested hosts")
		}
	}
	for i := range wantDNS {
		if gotDNS[i] != wantDNS[i] {
			return zero, errors.New("existing certificate DNS SANs do not match requested hosts")
		}
	}
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo), nil
}

func canonicalCertSANs(cert *x509.Certificate) ([]net.IP, []string) {
	seenIP := make(map[string]net.IP, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		if ip4 := ip.To4(); ip4 != nil {
			ip = append(net.IP(nil), ip4...)
		} else {
			ip = append(net.IP(nil), ip.To16()...)
		}
		seenIP[string(ip.To16())] = ip
	}
	ips := make([]net.IP, 0, len(seenIP))
	for _, ip := range seenIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i].To16(), ips[j].To16()) < 0
	})
	seenDNS := make(map[string]struct{}, len(cert.DNSNames))
	for _, d := range cert.DNSNames {
		seenDNS[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	dns := make([]string, 0, len(seenDNS))
	for d := range seenDNS {
		dns = append(dns, d)
	}
	sort.Strings(dns)
	return ips, dns
}

func syncTLSFileAndDir(path string, syncFile func(*os.File) error, syncDir func(string) error) error {
	if syncFile == nil {
		syncFile = ldrstore.SyncFile
	}
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		f, err = os.Open(path)
		if err != nil {
			return fmt.Errorf("%w: open %s for durability barrier: %v", ldrstore.ErrUncertainWrite, path, err)
		}
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: sync file %s: %v", ldrstore.ErrUncertainWrite, path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: close file %s: %v", ldrstore.ErrUncertainWrite, path, err)
	}
	dir := filepath.Dir(path)
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: sync dir %s: %v", ldrstore.ErrUncertainWrite, dir, err)
	}
	return nil
}

func tlsPathsAlias(a, b string) (bool, error) {
	if fiA, errA := os.Lstat(a); errA == nil {
		if fiB, errB := os.Lstat(b); errB == nil && os.SameFile(fiA, fiB) {
			return true, nil
		}
	}
	if fiA, errA := os.Stat(a); errA == nil {
		if fiB, errB := os.Stat(b); errB == nil && os.SameFile(fiA, fiB) {
			return true, nil
		}
	}
	ca, err := canonicalTLSPath(a)
	if err != nil {
		return false, err
	}
	cb, err := canonicalTLSPath(b)
	if err != nil {
		return false, err
	}
	return ca == cb, nil
}

func canonicalTLSPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	cur := abs
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			parts := make([]string, 0, 1+len(tail))
			parts = append(parts, resolved)
			for i := len(tail) - 1; i >= 0; i-- {
				parts = append(parts, tail[i])
			}
			return filepath.Clean(filepath.Join(parts...)), nil
		}
		if !os.IsNotExist(err) {
			return abs, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func publishFileCreateOnlyWithHooks(
	path string,
	data []byte,
	perm os.FileMode,
	syncFile func(*os.File) error,
	syncDir func(string) error,
) error {
	if syncFile == nil {
		syncFile = ldrstore.SyncFile
	}
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: mkdir %s: %v", ldrstore.ErrPreWrite, dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tls.tmp.*")
	if err != nil {
		return fmt.Errorf("%w: create temp in %s: %v", ldrstore.ErrPreWrite, dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: chmod temp %s: %v", ldrstore.ErrPreWrite, tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: write temp %s: %v", ldrstore.ErrPreWrite, tmpPath, err)
	}
	if err := syncFile(tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: sync temp %s: %v", ldrstore.ErrPreWrite, tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: close temp %s: %v", ldrstore.ErrPreWrite, tmpPath, err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("%w: link %s: %v", ldrstore.ErrPreWrite, path, err)
	}
	// Past os.Link: path is now published on disk and MUST NOT be unlinked.
	cleanup = false
	rmErr := os.Remove(tmpPath)
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: post-link dir sync %s: %v", ldrstore.ErrUncertainWrite, dir, err)
	}
	if rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("%w: remove temp %s: %v", ldrstore.ErrUncertainWrite, tmpPath, rmErr)
	}
	return nil
}

// ServerTLSConfig loads a cert/key pair and enforces TLS 1.3 minimum.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// ClientTLSConfig builds a strict TLS 1.3 client configuration matching the
// creation descriptor's pinned relay_origin TLS policy.
func ClientTLSConfig(origin ldrcrypto.RelayOrigin) (*tls.Config, error) {
	if err := origin.Validate(); err != nil {
		return nil, err
	}
	if origin.SessionBinding != ldrcrypto.SessionBindingTLS13Exporter {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTransport, origin.SessionBinding)
	}
	u, err := url.Parse(origin.URL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()

	switch origin.TLSPolicy {
	case ldrcrypto.TLSPolicyPinSPKISHA256:
		wantPin := append([]byte(nil), origin.TLSPin...)
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         host,
			InsecureSkipVerify: true, // strictly verified by VerifyConnection below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if cs.Version != tls.VersionTLS13 {
					return ErrTLSVersionRejected
				}
				if len(cs.PeerCertificates) == 0 {
					return ErrTLSPinMismatch
				}
				leaf := cs.PeerCertificates[0]
				now := time.Now()
				if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
					return errors.New("ldrrelay: pinned server certificate expired or not yet valid")
				}
				if err := leaf.VerifyHostname(host); err != nil {
					return fmt.Errorf("ldrrelay: pinned server hostname mismatch: %w", err)
				}
				got := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(got[:], wantPin) != 1 {
					return ErrTLSPinMismatch
				}
				return nil
			},
		}, nil

	case ldrcrypto.TLSPolicyPinCARootPEM:
		caCert, err := ldrcrypto.ParsePinnedCARootPEM(origin.TLSPin)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: host,
			RootCAs:    pool,
		}, nil

	case ldrcrypto.TLSPolicyWebPKI:
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: host,
		}, nil

	default:
		return nil, fmt.Errorf("ldrrelay: unsupported tls_policy %q", origin.TLSPolicy)
	}
}

// ExportTLSChannelBinding derives the 32-byte RFC 9266 tls-exporter channel
// binding value from a TLS 1.3 connection state. Fails closed on TLS < 1.3.
func ExportTLSChannelBinding(cs tls.ConnectionState) ([32]byte, error) {
	var zero [32]byte
	if cs.Version != tls.VersionTLS13 {
		return zero, ErrTLSVersionRejected
	}
	raw, err := cs.ExportKeyingMaterial(tlsExporterLabel, nil, 32)
	if err != nil {
		return zero, fmt.Errorf("ldrrelay: tls-exporter failed: %w", err)
	}
	if len(raw) != 32 {
		return zero, errors.New("ldrrelay: unexpected tls-exporter length")
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}
