package ldrrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	wsGUID                = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxFramePayload     = 256 * 1024 // 256 KiB per WS frame (TLS 1.3 records are <=16 KiB + overhead)
	wsMaxMessagePayload   = 1 << 20
	wsWriteChunkSize      = 32 * 1024 // 32 KiB per outgoing binary WS frame
	wsMaxControlPayload   = 125       // RFC 6455 §5.5 strict control frame limit
	wsMaxHandshakeBytes   = 8 * 1024  // bounded HTTP/1.1 Upgrade header exchange
	wsDefaultMaxConns     = 512
	wsDefaultPingInterval = 30 * time.Second
	wsDefaultHandshakeTTL = 15 * time.Second

	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

var (
	// ErrWSTunnelRejected is returned when an HTTP/1.1 WebSocket upgrade fails
	// validation (non-101, redirect, extensions negotiated, bad accept key, etc.).
	ErrWSTunnelRejected = errors.New("ldrrelay: websocket tunnel upgrade rejected")
	// ErrWSProtocol is returned on RFC 6455 framing or masking violations.
	ErrWSProtocol = errors.New("ldrrelay: websocket protocol violation")
)

func computeWSAccept(key string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, key)
	_, _ = io.WriteString(h, wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func headerHasToken(vals []string, want string) bool {
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), want) {
				return true
			}
		}
	}
	return false
}

// handshakeLimitReader enforces a strict byte cap while parsing HTTP Upgrade
// headers, then disables the cap once switched to the WebSocket byte stream
// without dropping any bytes already buffered in bufio.Reader.
type handshakeLimitReader struct {
	r       io.Reader
	rem     int64
	limited bool
}

func (l *handshakeLimitReader) Read(p []byte) (int, error) {
	if !l.limited {
		return l.r.Read(p)
	}
	if l.rem <= 0 {
		return 0, fmt.Errorf("%w: handshake response exceeded %d bytes", ErrWSTunnelRejected, wsMaxHandshakeBytes)
	}
	if int64(len(p)) > l.rem {
		p = p[:l.rem]
	}
	n, err := l.r.Read(p)
	l.rem -= int64(n)
	return n, err
}

// DialWSTunnel opens an outer TLS 1.3 HTTP/1.1 WebSocket tunnel to rawURL
// (zero redirects, zero compression/extensions) and returns a net.Conn carrying
// RFC 6455 binary messages as an ordered byte stream.
func DialWSTunnel(ctx context.Context, rawURL string, outerTLSCfg *tls.Config) (net.Conn, error) {
	return dialWSTunnelWithPing(ctx, rawURL, outerTLSCfg, wsDefaultPingInterval)
}

func dialWSTunnelWithPing(ctx context.Context, rawURL string, outerTLSCfg *tls.Config, pingInterval time.Duration) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: invalid outer tunnel URL", ErrWSTunnelRejected)
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") || u.RawPath != "" || path.Clean(u.Path) != u.Path || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.ForceQuery {
		return nil, fmt.Errorf("%w: outer tunnel URL requires a clean canonical path with no query or fragment", ErrWSTunnelRejected)
	}
	addr, err := resolveOriginDialAddr(rawURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, wsDefaultHandshakeTTL)
	defer cancel()
	if outerTLSCfg == nil {
		return nil, errors.New("ldrrelay: outer TLS configuration required")
	}
	cfg := outerTLSCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{"http/1.1"} // explicit HTTP/1.1 Upgrade on outer leg

	rawConn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := rawConn.(*tls.Conn); !ok || tc.ConnectionState().Version != tls.VersionTLS13 {
		_ = rawConn.Close()
		return nil, ErrTLSVersionRejected
	}

	deadline, _ := ctx.Deadline()
	_ = rawConn.SetDeadline(deadline)
	stopCancel := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stopCancel()

	var keyBytes [16]byte
	if _, err := io.ReadFull(rand.Reader, keyBytes[:]); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	secKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", u.EscapedPath())
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", u.Host)
	reqBuf.WriteString("Upgrade: websocket\r\n")
	reqBuf.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Key: %s\r\n", secKey)
	reqBuf.WriteString("Sec-WebSocket-Version: 13\r\n")
	reqBuf.WriteString("\r\n")
	if _, err := rawConn.Write(reqBuf.Bytes()); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	hlr := &handshakeLimitReader{r: rawConn, rem: wsMaxHandshakeBytes, limited: true}
	br := bufio.NewReaderSize(hlr, 4096)
	dummyReq, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	resp, err := http.ReadResponse(br, dummyReq)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("%w: %v", ErrWSTunnelRejected, err)
	}
	// Reject redirects, errors, extensions, subprotocols, and bad accept digests.
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Proto != "HTTP/1.1" {
		_ = rawConn.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: unexpected HTTP status %d", ErrWSTunnelRejected, resp.StatusCode)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "websocket") ||
		!headerHasToken(resp.Header.Values("Connection"), "upgrade") {
		_ = rawConn.Close()
		return nil, fmt.Errorf("%w: missing Upgrade/Connection headers", ErrWSTunnelRejected)
	}
	if len(resp.Header.Values("Sec-WebSocket-Accept")) != 1 || resp.Header.Get("Sec-WebSocket-Accept") != computeWSAccept(secKey) {
		_ = rawConn.Close()
		return nil, fmt.Errorf("%w: Sec-WebSocket-Accept mismatch", ErrWSTunnelRejected)
	}
	if len(resp.Header.Values("Sec-WebSocket-Extensions")) != 0 {
		_ = rawConn.Close()
		return nil, fmt.Errorf("%w: websocket extensions/compression are forbidden", ErrWSTunnelRejected)
	}
	if len(resp.Header.Values("Sec-WebSocket-Protocol")) != 0 {
		_ = rawConn.Close()
		return nil, fmt.Errorf("%w: unexpected websocket subprotocol", ErrWSTunnelRejected)
	}

	if !stopCancel() {
		return nil, ctx.Err()
	}
	hlr.limited = false
	_ = rawConn.SetDeadline(time.Time{})

	wc := newWSConn(rawConn, br, true, pingInterval, nil)
	return wc, nil
}

// wsConn adapts an RFC 6455 binary WebSocket stream to net.Conn.
// Binary messages are treated as an ordered byte stream completely independent
// of inner TLS record boundaries, handling fragmentation, interleaved control
// frames (Ping/Pong/Close), strict masking, deadlines, backpressure, and clean shutdown.
type wsConn struct {
	raw      net.Conn
	br       *bufio.Reader
	isClient bool

	readMu       sync.Mutex
	rRem         int64
	rMasked      bool
	rMask        [4]byte
	rMaskOff     int
	inFrag       bool
	messageBytes int64

	writeMu sync.Mutex

	closing   atomic.Bool
	closeOnce sync.Once
	stopCh    chan struct{}
	pingDone  chan struct{}
	onClose   func()
}

func newWSConn(raw net.Conn, br *bufio.Reader, isClient bool, pingInterval time.Duration, onClose func()) *wsConn {
	c := &wsConn{
		raw:      raw,
		br:       br,
		isClient: isClient,
		stopCh:   make(chan struct{}),
		pingDone: make(chan struct{}),
		onClose:  onClose,
	}
	if pingInterval > 0 {
		go c.pingLoop(pingInterval)
	} else {
		close(c.pingDone)
	}
	return c
}

func (c *wsConn) pingLoop(interval time.Duration) {
	defer close(c.pingDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var seq uint64
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			seq++
			var payload [8]byte
			binary.BigEndian.PutUint64(payload[:], seq)
			if err := c.writeControl(wsOpPing, payload[:]); err != nil {
				return
			}
		}
	}
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.rRem > 0 {
			toRead := len(p)
			if int64(toRead) > c.rRem {
				toRead = int(c.rRem)
			}
			n, err := c.br.Read(p[:toRead])
			if n > 0 {
				if c.rMasked {
					for i := 0; i < n; i++ {
						p[i] ^= c.rMask[(c.rMaskOff+i)&3]
					}
					c.rMaskOff = (c.rMaskOff + n) & 3
				}
				c.rRem -= int64(n)
			}
			return n, err
		}

		// Read next RFC 6455 frame header.
		// Keep incomplete headers buffered so reads can resume after a deadline.
		hdr, err := c.br.Peek(2)
		if err != nil {
			return 0, err
		}
		fin := (hdr[0] & 0x80) != 0
		rsv := hdr[0] & 0x70
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		len7 := hdr[1] & 0x7F

		if rsv != 0 {
			c.failProtocol(1002)
			return 0, fmt.Errorf("%w: non-zero RSV bits (extensions disabled)", ErrWSProtocol)
		}
		// RFC 6455 §5.1: client->server MUST be masked; server->client MUST be unmasked.
		if c.isClient && masked {
			c.failProtocol(1002)
			return 0, fmt.Errorf("%w: server sent masked frame", ErrWSProtocol)
		}
		if !c.isClient && !masked {
			c.failProtocol(1002)
			return 0, fmt.Errorf("%w: client sent unmasked frame", ErrWSProtocol)
		}

		headerLen := 2
		switch len7 {
		case 126:
			headerLen += 2
		case 127:
			headerLen += 8
		}
		if masked {
			headerLen += 4
		}
		header, err := c.br.Peek(headerLen)
		if err != nil {
			return 0, err
		}
		payloadLen := int64(len7)
		switch len7 {
		case 126:
			payloadLen = int64(binary.BigEndian.Uint16(header[2:4]))
		case 127:
			payloadLen = int64(binary.BigEndian.Uint64(header[2:10]))
		}
		if (len7 == 126 && payloadLen < 126) || (len7 == 127 && payloadLen <= 65535) {
			c.failProtocol(1002)
			return 0, fmt.Errorf("%w: invalid extended frame length", ErrWSProtocol)
		}
		var maskKey [4]byte
		if masked {
			copy(maskKey[:], header[headerLen-4:])
		}

		// Control frames (0x8..0xF): MUST have FIN=1, len<=125, may interleave mid-fragment.
		if opcode >= 0x8 {
			if !fin || payloadLen > wsMaxControlPayload {
				c.failProtocol(1002)
				return 0, fmt.Errorf("%w: invalid control frame (fin=%v len=%d)", ErrWSProtocol, fin, payloadLen)
			}
			size := headerLen + int(payloadLen)
			frame, err := c.br.Peek(size)
			if err != nil {
				return 0, err
			}
			ctrl := bytes.Clone(frame[headerLen:])
			_, _ = c.br.Discard(size)
			if masked {
				for i := range ctrl {
					ctrl[i] ^= maskKey[i&3]
				}
			}

			switch opcode {
			case wsOpPing:
				if err := c.writeControl(wsOpPong, ctrl); err != nil {
					return 0, err
				}
			case wsOpPong:
				// Heartbeat response; carrier liveness only.
			case wsOpClose:
				// Validate optional close payload length per RFC 6455 §5.5.1 (0 or >=2).
				if len(ctrl) == 1 {
					c.failProtocol(1002)
					return 0, fmt.Errorf("%w: 1-byte close frame", ErrWSProtocol)
				}
				if len(ctrl) >= 2 {
					code := binary.BigEndian.Uint16(ctrl)
					if !(code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006 || code >= 3000 && code <= 4999) {
						c.failProtocol(1002)
						return 0, fmt.Errorf("%w: invalid close status", ErrWSProtocol)
					}
					if !utf8.Valid(ctrl[2:]) {
						c.failProtocol(1007)
						return 0, fmt.Errorf("%w: invalid close reason", ErrWSProtocol)
					}
				}
				_ = c.closeWithPayload(ctrl)
				return 0, io.EOF
			default:
				c.failProtocol(1002)
				return 0, fmt.Errorf("%w: unknown control opcode 0x%x", ErrWSProtocol, opcode)
			}
			continue
		}

		// Data frames (0x0..0x7): only binary byte stream + continuations are allowed.
		if payloadLen > wsMaxFramePayload {
			c.failProtocol(1009)
			return 0, fmt.Errorf("%w: frame payload %d exceeds cap %d", ErrWSProtocol, payloadLen, wsMaxFramePayload)
		}
		if !c.inFrag {
			if opcode != wsOpBinary {
				c.failProtocol(1003)
				return 0, fmt.Errorf("%w: expected binary frame (0x2), got 0x%x", ErrWSProtocol, opcode)
			}
			if !fin {
				c.inFrag = true
			}
		} else {
			if opcode != wsOpContinuation {
				c.failProtocol(1002)
				return 0, fmt.Errorf("%w: expected continuation frame (0x0), got 0x%x", ErrWSProtocol, opcode)
			}
			if fin {
				c.inFrag = false
			}
		}

		c.messageBytes += payloadLen
		if c.messageBytes > wsMaxMessagePayload {
			c.failProtocol(1009)
			return 0, fmt.Errorf("%w: fragmented message exceeds cap", ErrWSProtocol)
		}
		if fin {
			c.messageBytes = 0
		}
		_, _ = c.br.Discard(headerLen)
		if payloadLen == 0 {
			continue
		}
		c.rRem = payloadLen
		c.rMasked = masked
		c.rMask = maskKey
		c.rMaskOff = 0
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	total := 0
	for total < len(p) {
		chunk := p[total:]
		if len(chunk) > wsWriteChunkSize {
			chunk = chunk[:wsWriteChunkSize]
		}
		if err := c.writeFrameLocked(true, wsOpBinary, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

func (c *wsConn) writeControl(opcode byte, payload []byte) error {
	if len(payload) > wsMaxControlPayload {
		return fmt.Errorf("%w: control payload too large", ErrWSProtocol)
	}
	if c.closing.Load() {
		return net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closing.Load() {
		return net.ErrClosed
	}
	return c.writeFrameLocked(true, opcode, payload)
}

func (c *wsConn) writeFrameLocked(fin bool, opcode byte, payload []byte) error {
	var hdr [14]byte
	b0 := opcode & 0x0F
	if fin {
		b0 |= 0x80
	}
	hdr[0] = b0
	nHdr := 2
	maskBit := byte(0)
	if c.isClient {
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
	var maskKey [4]byte
	if c.isClient {
		if _, err := io.ReadFull(rand.Reader, maskKey[:]); err != nil {
			return err
		}
		copy(hdr[nHdr:nHdr+4], maskKey[:])
		nHdr += 4
	}
	// Assemble contiguous frame buffer so one Write passes cleanly through raw conn.
	frame := make([]byte, nHdr+plen)
	copy(frame[:nHdr], hdr[:nHdr])
	copy(frame[nHdr:], payload)
	if c.isClient {
		for i := 0; i < plen; i++ {
			frame[nHdr+i] ^= maskKey[i&3]
		}
	}
	n, err := c.raw.Write(frame)
	if n != len(frame) && err == nil {
		err = io.ErrShortWrite
	}
	if n > 0 && n < len(frame) {
		// A retry cannot reconstruct a partially transmitted frame.
		_ = c.raw.Close()
	}
	return err
}

func (c *wsConn) failProtocol(code uint16) {
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], code)
	_ = c.closeWithPayload(body[:])
}

func (c *wsConn) Close() error {
	return c.closeWithPayload([]byte{0x03, 0xe8}) // normal closure (1000)
}

func (c *wsConn) closeWithPayload(payload []byte) error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		close(c.stopCh)
		if c.writeMu.TryLock() {
			_ = c.raw.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_ = c.writeFrameLocked(true, wsOpClose, payload)
			c.writeMu.Unlock()
		}
		closeErr = c.raw.Close()
		<-c.pingDone
		if c.onClose != nil {
			c.onClose()
		}
	})
	return closeErr
}

func (c *wsConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// wsTunnelListener feeds accepted RFC 6455 wsConn carriers into an inner TLS 1.3
// tls.Listener + HTTP/1.1 http.Server.
type wsTunnelListener struct {
	addr   net.Addr
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once

	mu     sync.Mutex
	active map[*wsConn]struct{}
}

func newWSTunnelListener(addr net.Addr) *wsTunnelListener {
	return &wsTunnelListener{
		addr:   addr,
		accept: make(chan net.Conn, 64),
		closed: make(chan struct{}),
		active: make(map[*wsConn]struct{}),
	}
}

func (l *wsTunnelListener) enqueue(c *wsConn) bool {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		return false
	default:
		l.active[c] = struct{}{}
	}
	l.mu.Unlock()

	select {
	case l.accept <- c:
		return true
	case <-l.closed:
		l.remove(c)
		return false
	}
}

func (l *wsTunnelListener) remove(c *wsConn) {
	l.mu.Lock()
	delete(l.active, c)
	l.mu.Unlock()
}

func (l *wsTunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *wsTunnelListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.mu.Lock()
		conns := make([]*wsConn, 0, len(l.active))
		for c := range l.active {
			conns = append(conns, c)
		}
		l.mu.Unlock()
		var closed sync.WaitGroup
		for _, c := range conns {
			closed.Go(func() { _ = c.Close() })
		}
		closed.Wait()
	})
	return nil
}

func (l *wsTunnelListener) Addr() net.Addr { return l.addr }

type wsVirtualAddr string

func (a wsVirtualAddr) Network() string { return "ws-tunnel" }
func (a wsVirtualAddr) String() string  { return string(a) }

// WSTunnelServer accepts HTTP/1.1 WebSocket upgrades on tunnelPath (intended for
// loopback or owner-only Unix domain socket listeners behind an edge TLS proxy),
// terminates inner TLS 1.3 directly inside the origin relay, tags every inner
// request context with WithWSTunnelCarrier, and serves RelayServer over HTTP/1.1.
type WSTunnelServer struct {
	relay      *RelayServer
	tunnelPath string
	sem        chan struct{}
	wsLn       *wsTunnelListener
	innerSrv   *http.Server
	innerDone  chan struct{}
	shutOnce   sync.Once
}

// NewWSTunnelServer creates and starts the inner TLS 1.3 + HTTP/1.1 server fed by
// accepted WebSocket upgrade connections. innerTLSCfg MUST carry the origin relay's
// server certificate; MinVersion TLS 1.3 and NextProtos ["http/1.1"] are enforced.
func NewWSTunnelServer(relaySrv *RelayServer, innerTLSCfg *tls.Config, tunnelPath string, maxConns int) (*WSTunnelServer, error) {
	if relaySrv == nil || innerTLSCfg == nil {
		return nil, errors.New("ldrrelay: relay server and inner TLS config required")
	}
	if tunnelPath == "" {
		tunnelPath = "/v1/tunnel"
	}
	if !strings.HasPrefix(tunnelPath, "/") || path.Clean(tunnelPath) != tunnelPath {
		return nil, fmt.Errorf("ldrrelay: invalid tunnel path %q", tunnelPath)
	}
	if maxConns <= 0 {
		maxConns = wsDefaultMaxConns
	}
	cfg := innerTLSCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{"http/1.1"} // match inner HTTP/1.1 server ALPN strictly

	wsLn := newWSTunnelListener(wsVirtualAddr(tunnelPath))
	innerSrv := &http.Server{
		Handler:           relaySrv,
		IdleTimeout:       sessionIdleTimeout,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){}, // explicit HTTP/1.1 only
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return WithWSTunnelCarrier(ctx)
		},
	}
	relaySrv.TrackConnections(innerSrv)
	ts := &WSTunnelServer{relay: relaySrv,
		tunnelPath: tunnelPath,
		sem:        make(chan struct{}, maxConns),
		wsLn:       wsLn,
		innerSrv:   innerSrv,
		innerDone:  make(chan struct{}),
	}
	go func() {
		defer close(ts.innerDone)
		_ = innerSrv.Serve(tls.NewListener(wsLn, cfg))
	}()
	return ts, nil
}

// ServeHTTP handles HTTP/1.1 WebSocket Upgrade requests on tunnelPath.
func (ts *WSTunnelServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != ts.tunnelPath || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		http.Error(w, "http/1.1 upgrade required", http.StatusUpgradeRequired)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") ||
		!headerHasToken(r.Header.Values("Connection"), "upgrade") ||
		strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")) != "13" {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Sec-WebSocket-Key")) != 1 {
		http.Error(w, "invalid websocket upgrade request", http.StatusBadRequest)
		return
	}
	secKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	rawKey, err := base64.StdEncoding.DecodeString(secKey)
	if err != nil || len(rawKey) != 16 {
		http.Error(w, "invalid Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	select {
	case ts.sem <- struct{}{}:
	default:
		ts.relay.overload.Add(1)
		http.Error(w, "too many tunnel connections", http.StatusServiceUnavailable)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		<-ts.sem
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	rawConn, rw, err := hj.Hijack()
	if err != nil {
		<-ts.sem
		return
	}

	// Never negotiate extensions/compression (omit Sec-WebSocket-Extensions).
	var resp bytes.Buffer
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.WriteString("Upgrade: websocket\r\n")
	resp.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&resp, "Sec-WebSocket-Accept: %s\r\n", computeWSAccept(secKey))
	resp.WriteString("\r\n")
	_ = rawConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := rw.Write(resp.Bytes()); err != nil {
		_ = rawConn.Close()
		<-ts.sem
		return
	}
	if err := rw.Flush(); err != nil {
		_ = rawConn.Close()
		<-ts.sem
		return
	}
	_ = rawConn.SetDeadline(time.Time{})

	ts.relay.tunnels.Add(1)
	var wc *wsConn
	wc = newWSConn(rawConn, rw.Reader, false, 0, func() {
		ts.relay.tunnels.Add(-1)
		ts.wsLn.remove(wc)
		<-ts.sem
	})
	if !ts.wsLn.enqueue(wc) {
		_ = wc.Close()
	}
}

// Shutdown cleanly closes the tunnel listener, active WebSocket connections,
// and the inner TLS 1.3 HTTP/1.1 server.
func (ts *WSTunnelServer) Shutdown(ctx context.Context) error {
	var err error
	ts.shutOnce.Do(func() {
		_ = ts.wsLn.Close()
		err = ts.innerSrv.Shutdown(ctx)
		<-ts.innerDone
	})
	return err
}
