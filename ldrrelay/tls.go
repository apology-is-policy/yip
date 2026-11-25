package ldrrelay

import (
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
)

// InitSelfSignedCert generates an ECDSA P-256 self-signed server certificate
// with explicit IP and DNS SANs, writes certPath (0644) and keyPath (0600)
// atomically, and returns the 32-byte SHA-256(SPKI) pin for pin_spki_sha256.
func InitSelfSignedCert(certPath, keyPath string, hosts []string) ([32]byte, error) {
	var zero [32]byte
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "localhost"}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return zero, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return zero, err
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
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.IPAddresses) == 0 && len(tmpl.DNSNames) == 0 {
		return zero, errors.New("ldrrelay: at least one valid IP or DNS host required")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return zero, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return zero, err
	}
	spkiPin := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return zero, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := ldrstore.AtomicWriteFile(certPath, certPEM, 0o644); err != nil {
		return zero, err
	}
	if err := ldrstore.AtomicWriteFile(keyPath, keyPEM, 0o600); err != nil {
		return zero, err
	}
	return spkiPin, nil
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
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(origin.TLSPin) {
			return nil, errors.New("ldrrelay: pin_ca_root_pem contained no valid PEM certificates")
		}
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
