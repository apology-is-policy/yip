package ldrrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

// startSimulatedEdgeWSProxy starts a TLS-terminating edge proxy (simulating
// Cloudflare Tunnel / nginx / Caddy) that accepts outer HTTPS WebSocket upgrades
// on outerTLS and forwards the raw HTTP/1.1 WebSocket byte stream to a loopback
// plaintext origin backend (originNetwork, originAddr). Optional hooks let tests
// inspect outer TLS exporter bytes or inject carrier drops mid-stream.
type simEdgeProxy struct {
	addr       string
	spkiPin    [32]byte
	outerCBsMu sync.Mutex
	outerCBs   [][32]byte
	dropAllMu  sync.Mutex
	active     map[net.Conn]struct{}
	closeFn    func()
}

func (p *simEdgeProxy) DropActiveConnections() {
	p.dropAllMu.Lock()
	conns := make([]net.Conn, 0, len(p.active))
	for c := range p.active {
		conns = append(conns, c)
	}
	p.dropAllMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *simEdgeProxy) LastOuterCB() ([32]byte, bool) {
	p.outerCBsMu.Lock()
	defer p.outerCBsMu.Unlock()
	if len(p.outerCBs) == 0 {
		return [32]byte{}, false
	}
	return p.outerCBs[len(p.outerCBs)-1], true
}

func startSimulatedEdgeWSProxy(t *testing.T, outerHosts []string, originNetwork, originAddr string) *simEdgeProxy {
	t.Helper()
	edgeDir := t.TempDir()
	certP := filepath.Join(edgeDir, "edge.crt")
	keyP := filepath.Join(edgeDir, "edge.key")
	pin, err := InitSelfSignedCert(certP, keyP, outerHosts)
	if err != nil {
		t.Fatal(err)
	}
	edgeTLS, err := InnerTunnelServerTLSConfig(certP, keyP)
	if err != nil {
		t.Fatal(err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(rawLn, edgeTLS)

	p := &simEdgeProxy{
		addr:    rawLn.Addr().String(),
		spkiPin: pin,
		active:  make(map[net.Conn]struct{}),
	}
	track := func(c net.Conn) {
		p.dropAllMu.Lock()
		p.active[c] = struct{}{}
		p.dropAllMu.Unlock()
	}
	untrack := func(c net.Conn) {
		p.dropAllMu.Lock()
		delete(p.active, c)
		p.dropAllMu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			clientConn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(cc net.Conn) {
				defer wg.Done()
				defer cc.Close()
				tc := cc.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				if cb, err := ExportTLSChannelBinding(tc.ConnectionState()); err == nil {
					p.outerCBsMu.Lock()
					p.outerCBs = append(p.outerCBs, cb)
					p.outerCBsMu.Unlock()
				}
				// Plaintext hop from edge proxy to loopback / Unix origin listener
				// (exactly what cloudflared / nginx does after terminating outer TLS).
				backend, err := net.DialTimeout(originNetwork, originAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer backend.Close()
				track(cc)
				track(backend)
				defer untrack(cc)
				defer untrack(backend)

				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(backend, cc)
					_ = backend.Close()
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(cc, backend)
					_ = cc.Close()
					done <- struct{}{}
				}()
				<-done
				<-done
			}(clientConn)
		}
	}()

	p.closeFn = func() {
		_ = tlsLn.Close()
		p.DropActiveConnections()
		wg.Wait()
	}
	t.Cleanup(p.closeFn)
	return p
}

// writeRawWSFrame writes a raw RFC 6455 frame for low-level framing/adversarial tests.
func writeRawWSFrame(w io.Writer, fin bool, rsv byte, opcode byte, masked bool, maskKey [4]byte, payload []byte) error {
	var hdr [14]byte
	b0 := (rsv & 0x70) | (opcode & 0x0F)
	if fin {
		b0 |= 0x80
	}
	hdr[0] = b0
	nHdr := 2
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	plen := len(payload)
	switch {
	case plen <= 125:
		hdr[1] = maskBit | byte(plen)
	case plen <= 65535:
		hdr[1] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(plen))
		nHdr = 4
	default:
		hdr[1] = maskBit | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(plen))
		nHdr = 10
	}
	if masked {
		copy(hdr[nHdr:nHdr+4], maskKey[:])
		nHdr += 4
	}
	buf := make([]byte, nHdr+plen)
	copy(buf[:nHdr], hdr[:nHdr])
	copy(buf[nHdr:], payload)
	if masked {
		for i := 0; i < plen; i++ {
			buf[nHdr+i] ^= maskKey[i&3]
		}
	}
	_, err := w.Write(buf)
	return err
}

func TestWSTunnelCarrierFramingFragmentationControlFramesAndLimits(t *testing.T) {
	// 1. Ordered byte stream across >wsWriteChunkSize (128 KiB) with odd read/write boundaries.
	t.Run("ordered-stream-large-transfer", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		srvCh := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				srvCh <- c
			}
		}()
		cRaw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		sRaw := <-srvCh

		clientWS := newWSConn(cRaw, bufio.NewReader(cRaw), true, 25*time.Millisecond, nil)
		serverWS := newWSConn(sRaw, bufio.NewReader(sRaw), false, 0, nil)
		defer clientWS.Close()
		defer serverWS.Close()

		want := make([]byte, 128*1024+777)
		if _, err := io.ReadFull(rand.Reader, want); err != nil {
			t.Fatal(err)
		}
		errCh := make(chan error, 1)
		go func() {
			// Write in irregular chunks independent of frame/TLS record boundaries.
			for off := 0; off < len(want); {
				step := 4111
				if off+step > len(want) {
					step = len(want) - off
				}
				if _, err := clientWS.Write(want[off : off+step]); err != nil {
					errCh <- err
					return
				}
				off += step
			}
			errCh <- nil
		}()

		got := make([]byte, len(want))
		off := 0
		for off < len(got) {
			step := 1319
			if off+step > len(got) {
				step = len(got) - off
			}
			n, err := serverWS.Read(got[off : off+step])
			if err != nil {
				t.Fatalf("serverWS.Read at %d: %v", off, err)
			}
			off += n
		}
		if err := <-errCh; err != nil {
			t.Fatalf("clientWS.Write: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("byte stream mismatch across wsConn transfer")
		}
		// Clean shutdown yields EOF on peer.
		if err := clientWS.Close(); err != nil {
			t.Fatalf("clientWS.Close: %v", err)
		}
		var b [1]byte
		if _, err := serverWS.Read(b[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF after peer Close, got %v", err)
		}
	})

	// 2. Fragmented binary message with interleaved Ping & Pong control frames.
	t.Run("fragmented-with-interleaved-ping-pong", func(t *testing.T) {
		cRaw, sRaw := net.Pipe()
		defer cRaw.Close()
		defer sRaw.Close()
		serverWS := newWSConn(sRaw, bufio.NewReader(sRaw), false, 0, nil)
		defer serverWS.Close()

		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		pongCh := make(chan []byte, 1)
		go func() {
			// Send fragmented binary message: "hello " + Ping("beat") + "world" + Pong("ok") + "!"
			_ = writeRawWSFrame(cRaw, false, 0, wsOpBinary, true, mask, []byte("hello "))
			_ = writeRawWSFrame(cRaw, true, 0, wsOpPing, true, mask, []byte("beat"))
			// Read the server's Pong response right away so net.Pipe doesn't block!
			br := bufio.NewReader(cRaw)
			var hdr [2]byte
			if _, err := io.ReadFull(br, hdr[:]); err == nil && (hdr[0]&0x0F) == wsOpPong && (hdr[1]&0x80) == 0 {
				plen := int(hdr[1] & 0x7F)
				pb := make([]byte, plen)
				_, _ = io.ReadFull(br, pb)
				pongCh <- pb
			}
			_ = writeRawWSFrame(cRaw, false, 0, wsOpContinuation, true, mask, []byte("world"))
			_ = writeRawWSFrame(cRaw, true, 0, wsOpPong, true, mask, []byte("ok"))
			_ = writeRawWSFrame(cRaw, true, 0, wsOpContinuation, true, mask, []byte("!"))
		}()

		got := make([]byte, len("hello world!"))
		if _, err := io.ReadFull(serverWS, got); err != nil {
			t.Fatalf("ReadFull fragmented stream: %v", err)
		}
		if string(got) != "hello world!" {
			t.Fatalf("reassembled=%q want=%q", string(got), "hello world!")
		}
		select {
		case pb := <-pongCh:
			if string(pb) != "beat" {
				t.Fatalf("pong payload=%q want=beat", string(pb))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for server Pong reply to interleaved Ping")
		}
	})

	// 3. Deadlines propagate to underlying connection.
	t.Run("read-deadline", func(t *testing.T) {
		cRaw, sRaw := net.Pipe()
		defer cRaw.Close()
		defer sRaw.Close()
		serverWS := newWSConn(sRaw, bufio.NewReader(sRaw), false, 0, nil)
		defer serverWS.Close()
		_ = serverWS.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		var buf [8]byte
		_, err := serverWS.Read(buf[:])
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("expected timeout error from SetReadDeadline, got %v", err)
		}
	})

	// 4. Protocol violations fail closed (RSV bits, unmasked client, masked server, text opcode, fragmented control, oversized payload).
	violations := []struct {
		name     string
		isClient bool
		send     func(w io.Writer)
	}{
		{"rsv-bits-set", false, func(w io.Writer) {
			_ = writeRawWSFrame(w, true, 0x40, wsOpBinary, true, [4]byte{1, 2, 3, 4}, []byte("x"))
		}},
		{"unmasked-client-frame", false, func(w io.Writer) {
			_ = writeRawWSFrame(w, true, 0, wsOpBinary, false, [4]byte{}, []byte("x"))
		}},
		{"masked-server-frame", true, func(w io.Writer) {
			_ = writeRawWSFrame(w, true, 0, wsOpBinary, true, [4]byte{1, 2, 3, 4}, []byte("x"))
		}},
		{"text-frame-rejected", false, func(w io.Writer) {
			_ = writeRawWSFrame(w, true, 0, wsOpText, true, [4]byte{1, 2, 3, 4}, []byte("hi"))
		}},
		{"unexpected-continuation", false, func(w io.Writer) {
			_ = writeRawWSFrame(w, true, 0, wsOpContinuation, true, [4]byte{1, 2, 3, 4}, []byte("hi"))
		}},
		{"fragmented-ping", false, func(w io.Writer) {
			_ = writeRawWSFrame(w, false, 0, wsOpPing, true, [4]byte{1, 2, 3, 4}, []byte("hi"))
		}},
		{"oversized-control", false, func(w io.Writer) {
			_ = writeRawWSFrame(w, true, 0, wsOpPing, true, [4]byte{1, 2, 3, 4}, make([]byte, 126))
		}},
		{"oversized-data-frame", false, func(w io.Writer) {
			// Write only header claiming wsMaxFramePayload+1 bytes so receiver rejects immediately.
			var hdr [14]byte
			hdr[0] = 0x80 | wsOpBinary
			hdr[1] = 0x80 | 127
			binary.BigEndian.PutUint64(hdr[2:10], uint64(wsMaxFramePayload+1))
			_, _ = w.Write(hdr[:14])
		}},
	}
	for _, tc := range violations {
		t.Run(tc.name, func(t *testing.T) {
			cRaw, sRaw := net.Pipe()
			defer cRaw.Close()
			defer sRaw.Close()
			wc := newWSConn(sRaw, bufio.NewReader(sRaw), tc.isClient, 0, nil)
			defer wc.Close()
			go func() {
				tc.send(cRaw)
				// Drain any close frame so failProtocol doesn't stall on net.Pipe.
				_, _ = io.Copy(io.Discard, cRaw)
			}()
			var buf [16]byte
			_, err := wc.Read(buf[:])
			if !errors.Is(err, ErrWSProtocol) {
				t.Fatalf("expected ErrWSProtocol for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestWSTunnelReadAndWriteDeadlines(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	// The first header byte is available immediately; the rest arrives after timeout.
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{0x82}), raw))
	wc := newWSConn(raw, reader, true, 0, nil)
	defer wc.Close()
	if err := wc.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := wc.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle read returned %v", err)
	}
	if _, err := wc.Write(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked write returned %v", err)
	}
	if err := wc.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = peer.Write([]byte{1, 42})
		_, _ = io.Copy(io.Discard, peer)
	}()
	if _, err := io.ReadFull(wc, b[:]); err != nil || b[0] != 42 {
		t.Fatalf("read after resetting deadline: %v, %v", b, err)
	}
}

func TestWSTunnelFragmentedMessageLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra bool
	}{{"exact limit", false}, {"one byte over", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var wire bytes.Buffer
			chunk := make([]byte, wsMaxFramePayload)
			for n := 0; n < wsMaxMessagePayload; n += len(chunk) {
				op := byte(wsOpContinuation)
				if n == 0 {
					op = wsOpBinary
				}
				fin := !tc.extra && n+len(chunk) == wsMaxMessagePayload
				if err := writeRawWSFrame(&wire, fin, 0, op, false, [4]byte{}, chunk); err != nil {
					t.Fatal(err)
				}
			}
			op := byte(wsOpBinary)
			if tc.extra {
				op = wsOpContinuation
			}
			if err := writeRawWSFrame(&wire, true, 0, op, false, [4]byte{}, []byte{1}); err != nil {
				t.Fatal(err)
			}
			raw, peer := net.Pipe()
			defer peer.Close()
			go io.Copy(io.Discard, peer)
			wc := newWSConn(raw, bufio.NewReader(&wire), true, 0, nil)
			defer wc.Close()
			total, err := io.Copy(io.Discard, wc)
			if tc.extra {
				if total != wsMaxMessagePayload || !errors.Is(err, ErrWSProtocol) {
					t.Fatalf("read %d, error %v", total, err)
				}
			} else if total != wsMaxMessagePayload+1 || err != nil {
				t.Fatalf("read %d, error %v", total, err)
			}
		})
	}
}

func TestWSTunnelUpgradeValidationRejectsRedirectsExtensionsAndBadAccept(t *testing.T) {
	dir := t.TempDir()
	certP := filepath.Join(dir, "outer.crt")
	keyP := filepath.Join(dir, "outer.key")
	pin, err := InitSelfSignedCert(certP, keyP, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, err := InnerTunnelServerTLSConfig(certP, keyP)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		resp func(secKey string) string
	}{
		{"redirect-302", func(string) string {
			return "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/other\r\nContent-Length: 0\r\n\r\n"
		}},
		{"http-200", func(string) string {
			return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		}},
		{"bad-accept", func(string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid==\r\n\r\n"
		}},
		{"extensions-negotiated", func(k string) string {
			return fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n", computeWSAccept(k))
		}},
		{"unexpected-subprotocol", func(k string) string {
			return fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: custom\r\n\r\n", computeWSAccept(k))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tlsLn := tls.NewListener(rawLn, srvTLS)
			defer tlsLn.Close()
			go func() {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_, _ = io.WriteString(c, tc.resp(req.Header.Get("Sec-WebSocket-Key")))
			}()

			origin := ldrcrypto.RelayOrigin{
				URL:             "https://" + rawLn.Addr().String() + "/v1/tunnel",
				TLSPolicy:       ldrcrypto.TLSPolicyPinSPKISHA256,
				TLSPin:          bytes.Repeat([]byte{0x11}, 32),
				SessionBinding:  ldrcrypto.SessionBindingWSTLS13Exporter,
				OuterTLSPolicy:  ldrcrypto.TLSPolicyPinSPKISHA256,
				OuterTLSPin:     pin[:],
				InnerServerName: "origin.internal",
			}
			outerCfg, err := ClientOuterTLSConfig(origin)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := DialWSTunnel(ctx, origin.URL, outerCfg)
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, ErrWSTunnelRejected) {
				t.Fatalf("expected ErrWSTunnelRejected for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestWSTunnelEndToEndThroughEdgeProxyExporterPinCarrierAndIdleExpiry(t *testing.T) {
	// 1. Start origin Go relay with BOTH a direct TLS 1.3 listener AND a loopback
	//    plaintext /v1/tunnel WebSocket listener sharing the SAME RelayEngine + RelayServer.
	relayDir := t.TempDir()
	originCert := filepath.Join(relayDir, "tls", "server.crt")
	originKey := filepath.Join(relayDir, "tls", "server.key")
	originPin, err := InitSelfSignedCert(originCert, originKey, []string{"origin.internal", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	directTLSCfg, err := ServerTLSConfig(originCert, originKey)
	if err != nil {
		t.Fatal(err)
	}
	innerTunnelTLSCfg, err := InnerTunnelServerTLSConfig(originCert, originKey)
	if err != nil {
		t.Fatal(err)
	}

	st, err := ldrstore.OpenFileStore(relayDir)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewRelayEngine(st, DefaultClockConfig(), RealClockSource())
	if err != nil {
		t.Fatal(err)
	}
	rs := NewRelayServer(eng)

	// Direct TLS 1.3 listener
	directRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	directSrv := &http.Server{Handler: rs}
	go func() { _ = directSrv.Serve(tls.NewListener(directRawLn, directTLSCfg)) }()

	// Loopback plaintext WS tunnel listener -> inner TLS 1.3 server
	wsTunnelSrv, err := NewWSTunnelServer(rs, innerTunnelTLSCfg, "/v1/tunnel", 32)
	if err != nil {
		t.Fatal(err)
	}
	tunnelLoopbackLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tunnelHTTPSrv := &http.Server{Handler: wsTunnelSrv}
	go func() { _ = tunnelHTTPSrv.Serve(tunnelLoopbackLn) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = directSrv.Shutdown(ctx)
		_ = tunnelHTTPSrv.Shutdown(ctx)
		_ = wsTunnelSrv.Shutdown(ctx)
		_ = eng.Shutdown()
	})

	// 2. Start simulated TLS-terminating edge proxy (distinct outer cert/SPKI!) pointing at loopback WS listener.
	edge := startSimulatedEdgeWSProxy(t, []string{"127.0.0.1"}, "tcp", tunnelLoopbackLn.Addr().String())
	if edge.spkiPin == originPin {
		t.Fatal("edge and origin pins must differ")
	}

	// 3. Provision TWO lines on the same relay:
	//    - tunLine: ws_tls13_exporter (pinned to edge outer SPKI + origin inner SPKI & "origin.internal")
	//    - dirLine: tls13_exporter (pinned directly to directRawLn + origin SPKI)
	r1, _ := ldrcrypto.GenerateEd25519Key()
	r2, _ := ldrcrypto.GenerateECDSAP256Key()
	tunLineID := bytes.Repeat([]byte{0xa1}, 16)
	dirLineID := bytes.Repeat([]byte{0xb2}, 16)

	tunOrigin := ldrcrypto.RelayOrigin{
		URL:             "https://" + edge.addr + "/v1/tunnel",
		TLSPolicy:       ldrcrypto.TLSPolicyPinSPKISHA256,
		TLSPin:          originPin[:],
		SessionBinding:  ldrcrypto.SessionBindingWSTLS13Exporter,
		OuterTLSPolicy:  ldrcrypto.TLSPolicyPinSPKISHA256,
		OuterTLSPin:     edge.spkiPin[:],
		InnerServerName: "origin.internal",
	}
	dirOrigin := ldrcrypto.RelayOrigin{
		URL:            "https://" + directRawLn.Addr().String(),
		TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
		TLSPin:         originPin[:],
		SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
	}

	provision := func(lineID []byte, ro ldrcrypto.RelayOrigin) (ldrcrypto.CreationDescriptor, ldrstore.ProvisionedLine, [32]byte) {
		desc := ldrcrypto.CreationDescriptor{
			Version: 1, LineID: lineID, Generation: 1,
			RootKeys:    []ldrcrypto.PublicKey{r1.PublicKey(), r2.PublicKey()},
			RelayOrigin: ro, Profile: ldrcrypto.ProfileV1(),
		}
		sd, err := ldrcrypto.SignCreationDescriptor(r1, desc)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := sd.MarshalCanonical()
		if err != nil {
			t.Fatal(err)
		}
		prov, err := eng.Provision(raw)
		if err != nil {
			t.Fatal(err)
		}
		profDig, _ := desc.Profile.Digest()
		return desc, prov, profDig
	}

	tunDesc, tunProv, profDig := provision(tunLineID, tunOrigin)
	_, _, _ = provision(dirLineID, dirOrigin)
	rootPrin := ldrcrypto.RootPrincipal(r1.PublicKey())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 4. Positive end-to-end test: dial ws_tls13_exporter through the TLS-terminating edge proxy!
	sess, err := DialSession(ctx, tunOrigin, tunLineID, profDig, 1, rootPrin, r1)
	if err != nil {
		t.Fatalf("DialSession(ws_tls13_exporter): %v", err)
	}
	defer sess.Close()

	// Verify IDENTICAL inner RFC 9266 tls-exporter channel binding at client and origin relay,
	// AND confirm it is DIFFERENT from the outer edge TLS connection's exporter!
	sidHex := hex.EncodeToString(sess.SessionID())
	rs.mu.Lock()
	srvSess := rs.sessions[sidHex]
	rs.mu.Unlock()
	if srvSess == nil {
		t.Fatal("origin RelayServer missing authenticated session")
	}
	if srvSess.cb != sess.ChannelBinding() {
		t.Fatalf("inner exporter mismatch: client=%x server=%x", sess.ChannelBinding(), srvSess.cb)
	}
	if outerCB, ok := edge.LastOuterCB(); !ok || outerCB == sess.ChannelBinding() {
		t.Fatalf("inner exporter must differ from outer edge TLS exporter (ok=%v)", ok)
	}

	// Execute real line_init + AnchorRequest + ControlLog over the inner TLS 1.3 session!
	sortedRoots, err := ldrcrypto.CanonicalRootKeys(tunDesc.RootKeys)
	if err != nil {
		t.Fatal(err)
	}
	rk0, _ := sortedRoots[0].ToCBOR()
	rk1, _ := sortedRoots[1].ToCBOR()
	profMap, _ := tunDesc.Profile.ToCBORMap()
	body, err := BuildWireIntentBody(WireIntentInput{
		ProfileDigest: profDig, LineID: tunLineID, Generation: 1,
		Origin: ldrcore.OriginRoot, Principal: rootPrin,
		OpID: "ws-init-1", OpType: "line_init",
		SeenSeq: 0, SeenHead: tunProv.GenesisAnchor, ValidityMS: 60_000,
		PayloadCommit: ldrcrypto.EmptyPayloadCommit(),
		Fields: ldrcrypto.Map{
			{Key: "descriptor_digest", Value: tunProv.DescriptorDigest[:]},
			{Key: "profile", Value: profMap},
			{Key: "root_keys", Value: []any{rk0, rk1}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signedInit, err := ldrcrypto.SignIntent(r1, body)
	if err != nil {
		t.Fatal(err)
	}
	subRep, err := sess.Submit(ctx, signedInit.RawBytes, nil, nil)
	if err != nil || subRep.Outcome.Kind != ldrcore.Committed || subRep.Outcome.Seq != 1 {
		t.Fatalf("ws tunnel line_init failed: rep=%+v err=%v", subRep, err)
	}
	ancRep, err := sess.AnchorRequest(ctx)
	if err != nil || ancRep.Class != ldrcore.ClassOutcome || ancRep.Seq != 1 {
		t.Fatalf("ws tunnel AnchorRequest failed: rep=%+v err=%v", ancRep, err)
	}
	frames, err := sess.ControlLog(ctx, 1, 10)
	if err != nil || len(frames) != 1 || frames[0].Seq != 1 {
		t.Fatalf("ws tunnel ControlLog failed: frames=%d err=%v", len(frames), err)
	}

	// 5. Wrong origin pin behind a VALID outer HTTPS connection MUST be rejected!
	badPinOrigin := tunOrigin
	badPinOrigin.TLSPin = bytes.Repeat([]byte{0xff}, 32)
	if badSess, err := DialSession(ctx, badPinOrigin, tunLineID, profDig, 1, rootPrin, r1); !errors.Is(err, ErrTLSPinMismatch) {
		if badSess != nil {
			badSess.Close()
		}
		t.Fatalf("expected ErrTLSPinMismatch for wrong origin pin behind valid outer TLS, got %v", err)
	}

	// 6. Wrong inner_server_name behind a VALID outer HTTPS connection MUST be rejected!
	badSNOrigin := tunOrigin
	badSNOrigin.InnerServerName = "wrong-origin.internal"
	if badSess, err := DialSession(ctx, badSNOrigin, tunLineID, profDig, 1, rootPrin, r1); err == nil {
		badSess.Close()
		t.Fatal("expected inner hostname verification failure behind valid outer TLS")
	}

	// 7. Wrong carrier rejection (per-line strict enforcement via ConnContext):
	//    (a) Calling the direct tls13_exporter line over /v1/tunnel MUST fail with wrong_carrier!
	tunToDirectLine := tunOrigin
	if badSess, err := DialSession(ctx, tunToDirectLine, dirLineID, profDig, 1, rootPrin, r1); err == nil || !strings.Contains(err.Error(), "wrong_carrier") {
		if badSess != nil {
			badSess.Close()
		}
		t.Fatalf("expected wrong_carrier when calling tls13_exporter line over WS tunnel, got %v", err)
	}
	//    (b) Calling the ws_tls13_exporter line over direct TLS MUST fail with wrong_carrier!
	dirToTunnelLine := dirOrigin
	if badSess, err := DialSession(ctx, dirToTunnelLine, tunLineID, profDig, 1, rootPrin, r1); err == nil || !strings.Contains(err.Error(), "wrong_carrier") {
		if badSess != nil {
			badSess.Close()
		}
		t.Fatalf("expected wrong_carrier when calling ws_tls13_exporter line over direct TLS, got %v", err)
	}

	// 8. Carrier reset ends inner TLS & P7 session (client MUST NOT silently reconnect!).
	edge.DropActiveConnections()
	if _, err := sess.AnchorRequest(ctx); err == nil {
		t.Fatal("expected AnchorRequest to fail closed after outer WS carrier reset")
	}

	// 9. Heartbeats maintain carrier liveness ONLY, never extending P7 session idle timeout!
	var fakeNow atomic.Int64
	baseNow := time.Now()
	fakeNow.Store(baseNow.UnixNano())
	rs.setTestSessionClock(func() time.Time { return time.Unix(0, fakeNow.Load()) }, 50*time.Millisecond)
	defer rs.setTestSessionClock(nil, 0)

	sess2, err := DialSession(ctx, tunOrigin, tunLineID, profDig, 1, rootPrin, r1)
	if err != nil {
		t.Fatalf("re-dial ws_tls13_exporter: %v", err)
	}
	defer sess2.Close()
	// Advance server session clock past idle timeout while WS carrier remains open.
	fakeNow.Store(baseNow.Add(5 * time.Second).UnixNano())
	if _, err := sess2.AnchorRequest(ctx); err == nil {
		t.Fatal("expected expired P7 session to fail even with live WS carrier")
	}
}
