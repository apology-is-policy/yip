package ldrrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

type carrierKind int

const (
	carrierDirect   carrierKind = iota // default for direct TLS 1.3 listeners
	carrierWSTunnel                    // set ONLY via trusted WS tunnel inner http.Server ConnContext
)

type carrierCtxKey struct{}

// WithWSTunnelCarrier marks a connection context as arriving via the trusted
// WebSocket-tunneled inner TLS 1.3 listener (never inferred from HTTP headers).
func WithWSTunnelCarrier(ctx context.Context) context.Context {
	return context.WithValue(ctx, carrierCtxKey{}, carrierWSTunnel)
}

func requestCarrier(r *http.Request) carrierKind {
	if v, ok := r.Context().Value(carrierCtxKey{}).(carrierKind); ok {
		return v
	}
	return carrierDirect
}

const (
	maxHTTPBodyBytes     = 1024 * 1024 // 1 MiB transport frame cap
	challengeTTL         = 30 * time.Second
	maxPendingChallenges = 4096
	maxActiveSessions    = 4096
	sessionIdleTimeout   = 30 * time.Minute
)

type pendingChallenge struct {
	lineID      []byte
	principal   ldrcrypto.Principal
	serverNonce [32]byte
	cb          [32]byte
	expiresAt   time.Time
}

type activeSession struct {
	sessionID []byte
	lineID    []byte
	gen       uint64
	principal ldrcrypto.Principal
	cb        [32]byte
	lastReqID uint64
	lastSeen  time.Time
}

// RelayServer exposes RelayEngine over TLS 1.3 with RFC 9266 tls-exporter
// channel-bound authenticated sessions (P7).
type RelayServer struct {
	engine *RelayEngine

	mu              sync.Mutex
	pending         map[string]pendingChallenge // hex(session_id)
	sessions        map[string]*activeSession   // hex(session_id)
	nowFn           func() time.Time            // nil defaults to time.Now (test hook)
	idleTimeout     time.Duration               // <=0 defaults to sessionIdleTimeout
	maxRegPageBytes uint64                      // 0 defaults to MaxRegisterPageBytes
	mux             *http.ServeMux
}

// NewRelayServer creates an HTTP handler serving the LDR v1 relay API.
func NewRelayServer(engine *RelayEngine) *RelayServer {
	s := &RelayServer{
		engine:      engine,
		pending:     make(map[string]pendingChallenge),
		sessions:    make(map[string]*activeSession),
		idleTimeout: sessionIdleTimeout,
		mux:         http.NewServeMux(),
	}
	s.mux.HandleFunc("/v1/health", s.handleHealth)
	s.mux.HandleFunc("/v1/lines/", s.handleLine)
	return s
}

func (s *RelayServer) now() time.Time {
	s.mu.Lock()
	fn := s.nowFn
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return time.Now()
}

func (s *RelayServer) idleLimitLocked() time.Duration {
	if s.idleTimeout > 0 {
		return s.idleTimeout
	}
	return sessionIdleTimeout
}

func (s *RelayServer) isSessionExpiredLocked(as *activeSession, now time.Time) bool {
	return now.Sub(as.lastSeen) > s.idleLimitLocked()
}

// setTestSessionClock overrides the server session clock and idle timeout for
// deterministic unit testing without wall-clock sleeps.
func (s *RelayServer) setTestSessionClock(nowFn func() time.Time, idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nowFn = nowFn
	if idle > 0 {
		s.idleTimeout = idle
	} else {
		s.idleTimeout = sessionIdleTimeout
	}
}

// SetMaxRegisterPageBytes overrides the encoded CBOR byte budget per
// /register/list page (0 restores MaxRegisterPageBytes; capped at MaxRegisterPageBytes).
func (s *RelayServer) SetMaxRegisterPageBytes(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > MaxRegisterPageBytes {
		n = MaxRegisterPageBytes
	}
	s.maxRegPageBytes = n
}

func (s *RelayServer) registerPageByteCap() uint64 {
	s.mu.Lock()
	n := s.maxRegPageBytes
	s.mu.Unlock()
	if n == 0 || n > MaxRegisterPageBytes {
		return MaxRegisterPageBytes
	}
	return n
}

// ServeHTTP satisfies http.Handler. Every line endpoint requires TLS 1.3.
func (s *RelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *RelayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses := s.engine.Status()
	clockOK := true
	quarantined := 0
	for _, st := range statuses {
		if !st.Clock.Trusted {
			clockOK = false
		}
		if st.Quarantined {
			quarantined++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                quarantined == 0,
		"clock_trusted":     clockOK,
		"lines":             len(statuses),
		"quarantined_lines": quarantined,
	})
}

func (s *RelayServer) handleLine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil {
		http.Error(w, "tls 1.3 required", http.StatusUpgradeRequired)
		return
	}
	cb, err := ExportTLSChannelBinding(*r.TLS)
	if err != nil {
		http.Error(w, "tls 1.3 channel binding failed", http.StatusUpgradeRequired)
		return
	}

	// Parse /v1/lines/<hex_line_id>/<endpoint...>
	path := strings.TrimPrefix(r.URL.Path, "/v1/lines/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	lineID, err := hex.DecodeString(parts[0])
	if err != nil || len(lineID) < 16 || len(lineID) > 64 {
		http.Error(w, "invalid line id", http.StatusBadRequest)
		return
	}
	endpoint := parts[1]

	// Enforce per-line transport carrier binding from trusted listener ConnContext
	// and verified CreationDescriptor — never from HTTP headers, with no fallback.
	desc, _, _, exists := s.engine.LineDescriptor(lineID)
	carrier := requestCarrier(r)
	var rejectStatus int
	var rejectCode string
	switch {
	case !exists:
		rejectStatus, rejectCode = http.StatusNotFound, "wrong_line"
	case desc.RelayOrigin.SessionBinding == ldrcrypto.SessionBindingTLS13Exporter:
		if carrier != carrierDirect {
			rejectStatus, rejectCode = http.StatusMisdirectedRequest, "wrong_carrier"
		}
	case desc.RelayOrigin.SessionBinding == ldrcrypto.SessionBindingWSTLS13Exporter:
		if carrier != carrierWSTunnel {
			rejectStatus, rejectCode = http.StatusMisdirectedRequest, "wrong_carrier"
		}
	default:
		rejectStatus, rejectCode = http.StatusNotImplemented, "unsupported_transport"
	}
	if rejectStatus != 0 {
		if endpoint == "session/challenge" {
			writeCBOR(w, rejectStatus, ldrcrypto.Map{{Key: "error", Value: rejectCode}, {Key: "v", Value: uint64(1)}})
		} else {
			writeCBOR(w, rejectStatus, ldrcrypto.Map{
				{Key: "class", Value: ldrcore.ClassAdmission},
				{Key: "code", Value: rejectCode},
				{Key: "v", Value: uint64(1)},
			})
		}
		return
	}

	body, err := readBoundedBody(w, r, maxHTTPBodyBytes)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	reqDigest := sha256.Sum256(body)

	switch endpoint {
	case "session/challenge":
		s.handleChallenge(w, lineID, cb, body)
	case "session/auth":
		s.handleAuth(w, lineID, cb, body)
	case "submit":
		s.handleSubmit(w, lineID, cb, body, reqDigest)
	case "query":
		s.handleQuery(w, lineID, cb, body, reqDigest)
	case "anchor":
		s.handleAnchor(w, lineID, cb, body, reqDigest)
	case "log":
		s.handleLog(w, lineID, cb, body, reqDigest)
	case "sidecar":
		s.handleSidecar(w, lineID, cb, body, reqDigest)
	case "register/put":
		s.handleRegisterPut(w, lineID, cb, body, reqDigest)
	case "register/list":
		s.handleRegisterList(w, lineID, cb, body, reqDigest)
	default:
		http.NotFound(w, r)
	}
}

func readBoundedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func writeCBOR(w http.ResponseWriter, status int, m ldrcrypto.Map) {
	enc, err := ldrcrypto.MarshalCBORWithLimits(m, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 16384})
	if err != nil {
		http.Error(w, "internal encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	_, _ = w.Write(enc)
}

func (s *RelayServer) sweepLocked(now time.Time) {
	for k, pc := range s.pending {
		if now.After(pc.expiresAt) {
			delete(s.pending, k)
		}
	}
	for k, as := range s.sessions {
		if s.isSessionExpiredLocked(as, now) {
			delete(s.sessions, k)
		}
	}
}

func (s *RelayServer) handleChallenge(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"generation", "line_id", "principal", "profile_digest", "v"}); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if reqGen, err := ldrcrypto.MapUint(m, "generation"); err != nil || reqGen < 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	reqLine, err := ldrcrypto.MapBytes(m, "line_id")
	if err != nil || !bytes.Equal(reqLine, lineID) {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "wrong_line"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, err := ldrcrypto.ParsePrincipal(m["principal"])
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	_, _, profDigest, exists := s.engine.LineDescriptor(lineID)
	if !exists {
		writeCBOR(w, http.StatusNotFound, ldrcrypto.Map{{Key: "error", Value: "wrong_line"}, {Key: "v", Value: uint64(1)}})
		return
	}
	pd, err := ldrcrypto.MapBytesLen(m, "profile_digest", 32)
	if err != nil || !bytes.Equal(pd, profDigest[:]) {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "error", Value: "wrong_profile"}, {Key: "v", Value: uint64(1)}})
		return
	}

	var sid [16]byte
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, sid[:]); err != nil {
		http.Error(w, "rng failure", http.StatusInternalServerError)
		return
	}
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		http.Error(w, "rng failure", http.StatusInternalServerError)
		return
	}
	now := s.now()
	exp := now.Add(challengeTTL)

	s.mu.Lock()
	s.sweepLocked(now)
	if len(s.pending) >= maxPendingChallenges {
		s.mu.Unlock()
		writeCBOR(w, http.StatusTooManyRequests, ldrcrypto.Map{{Key: "error", Value: "overloaded"}, {Key: "v", Value: uint64(1)}})
		return
	}
	s.pending[hex.EncodeToString(sid[:])] = pendingChallenge{
		lineID:      bytes.Clone(lineID),
		principal:   prin,
		serverNonce: nonce,
		cb:          cb,
		expiresAt:   exp,
	}
	s.mu.Unlock()

	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "expires_ms", Value: uint64(exp.UnixMilli())},
		{Key: "server_nonce", Value: nonce[:]},
		{Key: "session_id", Value: sid[:]},
		{Key: "v", Value: uint64(1)},
	})
}

func (s *RelayServer) handleAuth(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"generation", "session_id", "sig", "v"}); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err := ldrcrypto.MapBytesLen(m, "session_id", 16)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	gen, err := ldrcrypto.MapUint(m, "generation")
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sig, err := ldrcrypto.MapBytes(m, "sig")
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}

	sidHex := hex.EncodeToString(sid)
	now := s.now()
	s.mu.Lock()
	pc, found := s.pending[sidHex]
	// Burn challenge immediately on first attempt (single-use!).
	delete(s.pending, sidHex)
	s.mu.Unlock()

	if !found || now.After(pc.expiresAt) || !bytes.Equal(pc.lineID, lineID) || pc.cb != cb {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_challenge"}, {Key: "v", Value: uint64(1)}})
		return
	}

	desc, _, profDigest, exists := s.engine.LineDescriptor(lineID)
	if !exists {
		writeCBOR(w, http.StatusNotFound, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "wrong_line"}, {Key: "v", Value: uint64(1)}})
		return
	}
	authMsg := ldrcrypto.SessionAuthMessage{
		ProfileDigest:  profDigest,
		LineID:         lineID,
		Generation:     gen,
		Principal:      pc.principal,
		RelayOrigin:    desc.RelayOrigin,
		SessionID:      sid,
		ServerNonce:    pc.serverNonce[:],
		ChannelBinding: cb[:],
	}
	stg, curGen, err := s.engine.VerifySessionPrincipal(lineID, authMsg, sig)
	if err != nil {
		if errors.Is(err, ErrLineQuarantined) {
			writeCBOR(w, http.StatusServiceUnavailable, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "storage_quarantined"}, {Key: "v", Value: uint64(1)}})
			return
		}
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "unknown_signer"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if stg == standingRevoked {
		// Key possession proven for a tombstoned/revoked key: return bound revoked answer, grant NO session.
		pCBOR, _ := pc.principal.ToCBOR()
		writeCBOR(w, http.StatusForbidden, ldrcrypto.Map{
			{Key: "class", Value: ldrcore.ClassUnresolved},
			{Key: "code", Value: "revoked"},
			{Key: "generation", Value: curGen},
			{Key: "line_id", Value: lineID},
			{Key: "principal", Value: pCBOR},
			{Key: "server_nonce", Value: pc.serverNonce[:]},
			{Key: "session_id", Value: sid},
			{Key: "v", Value: uint64(1)},
		})
		return
	}

	s.mu.Lock()
	s.sweepLocked(now)
	if len(s.sessions) >= maxActiveSessions {
		s.mu.Unlock()
		writeCBOR(w, http.StatusTooManyRequests, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "overloaded"}, {Key: "v", Value: uint64(1)}})
		return
	}
	s.sessions[sidHex] = &activeSession{
		sessionID: bytes.Clone(sid),
		lineID:    bytes.Clone(lineID),
		gen:       curGen,
		principal: pc.principal,
		cb:        cb,
		lastSeen:  now,
	}
	s.mu.Unlock()

	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "class", Value: "authenticated"},
		{Key: "generation", Value: curGen},
		{Key: "line_id", Value: lineID},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
	})
}

func (s *RelayServer) validateSession(sid []byte, lineID []byte, cb [32]byte, reqID uint64, requireMonotonic bool) (ldrcrypto.Principal, uint64, bool) {
	sidHex := hex.EncodeToString(sid)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sidHex]
	if !ok {
		return ldrcrypto.Principal{}, 0, false
	}
	if s.isSessionExpiredLocked(sess, now) {
		delete(s.sessions, sidHex)
		return ldrcrypto.Principal{}, 0, false
	}
	if !bytes.Equal(sess.lineID, lineID) || sess.cb != cb {
		return ldrcrypto.Principal{}, 0, false
	}
	if requireMonotonic {
		if reqID == 0 || reqID <= sess.lastReqID {
			return ldrcrypto.Principal{}, 0, false
		}
		sess.lastReqID = reqID
	}
	sess.lastSeen = now
	return sess.principal, sess.gen, true
}

func (s *RelayServer) handleSubmit(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBOR(body, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 8192})
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"intent", "req_id", "session_id", "v"}, "payload", "wraps"); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err := ldrcrypto.MapBytesLen(m, "session_id", 16)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	reqID, err := ldrcrypto.MapUint(m, "req_id")
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	intentBytes, err := ldrcrypto.MapBytes(m, "intent")
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	var payload []byte
	if _, has := m["payload"]; has {
		payload, err = ldrcrypto.MapBytes(m, "payload")
		if err != nil {
			writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
			return
		}
	}
	var wraps map[[32]byte][]byte
	if _, has := m["wraps"]; has {
		wArr, err := ldrcrypto.MapArray(m, "wraps")
		if err != nil {
			writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
			return
		}
		wraps = make(map[[32]byte][]byte, len(wArr))
		for _, elem := range wArr {
			em, ok := elem.(map[string]any)
			if !ok {
				writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
				return
			}
			cidB, err1 := ldrcrypto.MapBytesLen(em, "cred_id", 32)
			wb, err2 := ldrcrypto.MapBytes(em, "data")
			if err1 != nil || err2 != nil {
				writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
				return
			}
			var cid [32]byte
			copy(cid[:], cidB)
			wraps[cid] = wb
		}
	}

	rep := s.engine.Submit(lineID, prin, intentBytes, payload, wraps)
	writeCBOR(w, http.StatusOK, encodeSubmitReply(lineID, gen, sid, reqID, reqDigest, rep))
}

func (s *RelayServer) handleQuery(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	req := []string{"intent_digest", "op_gen", "op_id", "op_seen_seq", "op_signer", "req_id", "session_id", "sig", "v"}
	if err := ldrcrypto.RequireExactKeys(m, req); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err := ldrcrypto.MapBytesLen(m, "session_id", 16)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	reqID, err := ldrcrypto.MapUint(m, "req_id")
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	opGen, err1 := ldrcrypto.MapUint(m, "op_gen")
	opSigner, err2 := ldrcrypto.MapString(m, "op_signer")
	opSeenSeq, err3 := ldrcrypto.MapUint(m, "op_seen_seq")
	opID, err4 := ldrcrypto.MapString(m, "op_id")
	idgBytes, err5 := ldrcrypto.MapBytesLen(m, "intent_digest", 32)
	sig, err6 := ldrcrypto.MapBytes(m, "sig")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	// Verify signed query request bound to session + cb + req_id (P7).
	pubKey, _, exists := s.engine.ResolvePrincipalKey(lineID, prin)
	if !exists {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "unknown_signer"}, {Key: "v", Value: uint64(1)}})
		return
	}
	reqMsg := ldrcrypto.SessionRequestMessage{
		LineID: lineID, Generation: gen, SessionID: sid, ChannelBinding: cb[:], ReqID: reqID, Principal: prin,
		Body: ldrcrypto.Map{
			{Key: "intent_digest", Value: idgBytes},
			{Key: "op_gen", Value: opGen},
			{Key: "op_id", Value: opID},
			{Key: "op_seen_seq", Value: opSeenSeq},
			{Key: "op_signer", Value: opSigner},
		},
	}
	if err := ldrcrypto.VerifySessionRequest(pubKey, ldrcrypto.PurposeQuery, reqMsg, sig); err != nil {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "bad_signature"}, {Key: "v", Value: uint64(1)}})
		return
	}
	var idg [32]byte
	copy(idg[:], idgBytes)
	rep := s.engine.Query(lineID, prin, ldrstore.StoredOpKey{
		Generation: opGen, Signer: opSigner, SeenSeq: opSeenSeq, OpID: opID,
	}, idg)
	writeCBOR(w, http.StatusOK, encodeSubmitReply(lineID, gen, sid, reqID, reqDigest, rep))
}

func (s *RelayServer) handleAnchor(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"req_id", "session_id", "sig", "v"}); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err1 := ldrcrypto.MapBytesLen(m, "session_id", 16)
	reqID, err2 := ldrcrypto.MapUint(m, "req_id")
	sig, err3 := ldrcrypto.MapBytes(m, "sig")
	if err1 != nil || err2 != nil || err3 != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	pubKey, _, exists := s.engine.ResolvePrincipalKey(lineID, prin)
	if !exists {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "unknown_signer"}, {Key: "v", Value: uint64(1)}})
		return
	}
	reqMsg := ldrcrypto.SessionRequestMessage{
		LineID: lineID, Generation: gen, SessionID: sid, ChannelBinding: cb[:], ReqID: reqID, Principal: prin,
		Body: ldrcrypto.Map{},
	}
	if err := ldrcrypto.VerifySessionRequest(pubKey, ldrcrypto.PurposeAnchorRequest, reqMsg, sig); err != nil {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "bad_signature"}, {Key: "v", Value: uint64(1)}})
		return
	}
	rep := s.engine.AnchorRequest(lineID, prin)
	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "class", Value: rep.Class},
		{Key: "code", Value: rep.Code},
		{Key: "gen", Value: rep.Gen},
		{Key: "head", Value: rep.Head[:]},
		{Key: "line_id", Value: lineID},
		{Key: "req_digest", Value: reqDigest[:]},
		{Key: "req_id", Value: reqID},
		{Key: "seq", Value: rep.Seq},
		{Key: "seq_time", Value: rep.SeqTime},
		{Key: "session_gen", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
		{Key: "wrote", Value: rep.Wrote},
	})
}

func (s *RelayServer) handleLog(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"from_seq", "max_count", "req_id", "session_id", "v"}); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err1 := ldrcrypto.MapBytesLen(m, "session_id", 16)
	reqID, err2 := ldrcrypto.MapUint(m, "req_id")
	fromSeq, err3 := ldrcrypto.MapUint(m, "from_seq")
	maxCount, err4 := ldrcrypto.MapUint(m, "max_count")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	frames, errCode := s.engine.ControlLog(lineID, prin, fromSeq, maxCount)
	if errCode != "" {
		cls := ldrcore.ClassAdmission
		if errCode == "revoked" {
			cls = ldrcore.ClassUnresolved
		}
		writeCBOR(w, http.StatusForbidden, ldrcrypto.Map{
			{Key: "class", Value: cls},
			{Key: "code", Value: errCode},
			{Key: "line_id", Value: lineID},
			{Key: "req_digest", Value: reqDigest[:]},
			{Key: "req_id", Value: reqID},
			{Key: "session_gen", Value: gen},
			{Key: "session_id", Value: sid},
			{Key: "v", Value: uint64(1)},
		})
		return
	}
	arr := make([]any, len(frames))
	for i, fr := range frames {
		ib := fr.IntentBytes
		if ib == nil {
			ib = []byte{}
		}
		fm := ldrcrypto.Map{
			{Key: "gen", Value: fr.Gen},
			{Key: "head", Value: fr.Head[:]},
			{Key: "intent", Value: ib},
			{Key: "op_type", Value: fr.OpType},
			{Key: "origin", Value: fr.Origin},
			{Key: "prev_head", Value: fr.PrevHead[:]},
			{Key: "seq", Value: fr.Seq},
			{Key: "seq_time", Value: fr.SeqTime},
		}
		if fr.PayloadCommit != nil {
			fm = append(fm, ldrcrypto.MapEntry{Key: "payload_commit", Value: fr.PayloadCommit.ToCBORMap()})
		}
		if len(fr.WrapCommits) > 0 {
			wArr := make([]any, len(fr.WrapCommits))
			for j, wm := range fr.WrapCommits {
				wArr[j] = ldrcrypto.Map{
					{Key: "commit", Value: wm.Commit.ToCBORMap()},
					{Key: "cred_id", Value: bytes.Clone(wm.CredID[:])},
				}
			}
			fm = append(fm, ldrcrypto.MapEntry{Key: "wraps", Value: wArr})
		}
		arr[i] = fm
	}
	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "class", Value: "ok"},
		{Key: "frames", Value: arr},
		{Key: "gen", Value: gen},
		{Key: "line_id", Value: lineID},
		{Key: "req_digest", Value: reqDigest[:]},
		{Key: "req_id", Value: reqID},
		{Key: "session_gen", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
	})
}

func (s *RelayServer) handleSidecar(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"digest", "kind", "req_id", "session_id", "v"}); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err1 := ldrcrypto.MapBytesLen(m, "session_id", 16)
	reqID, err2 := ldrcrypto.MapUint(m, "req_id")
	kind, err3 := ldrcrypto.MapString(m, "kind")
	digB, err4 := ldrcrypto.MapBytesLen(m, "digest", 32)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	var dig [32]byte
	copy(dig[:], digB)
	data, errCode := s.engine.FetchSidecar(lineID, prin, kind, dig)
	if errCode != "" {
		cls := ldrcore.ClassAdmission
		if errCode == "revoked" {
			cls = ldrcore.ClassUnresolved
		}
		writeCBOR(w, http.StatusNotFound, ldrcrypto.Map{
			{Key: "class", Value: cls},
			{Key: "code", Value: errCode},
			{Key: "line_id", Value: lineID},
			{Key: "req_digest", Value: reqDigest[:]},
			{Key: "req_id", Value: reqID},
			{Key: "session_gen", Value: gen},
			{Key: "session_id", Value: sid},
			{Key: "v", Value: uint64(1)},
		})
		return
	}
	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "class", Value: "ok"},
		{Key: "data", Value: data},
		{Key: "line_id", Value: lineID},
		{Key: "req_digest", Value: reqDigest[:]},
		{Key: "req_id", Value: reqID},
		{Key: "session_gen", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
	})
}

func encodeSubmitReply(lineID []byte, gen uint64, sid []byte, reqID uint64, reqDigest [32]byte, rep SubmitReply) ldrcrypto.Map {
	return ldrcrypto.Map{
		{Key: "class", Value: rep.Class},
		{Key: "code", Value: rep.Code},
		{Key: "gen", Value: gen},
		{Key: "head", Value: rep.Head[:]},
		{Key: "line_id", Value: lineID},
		{Key: "original", Value: rep.Original},
		{Key: "outcome_kind", Value: rep.Outcome.Kind},
		{Key: "outcome_reason", Value: rep.Outcome.Reason},
		{Key: "outcome_ref_gen", Value: rep.Outcome.RefGen},
		{Key: "outcome_ref_seq", Value: rep.Outcome.RefSeq},
		{Key: "outcome_seq", Value: rep.Outcome.Seq},
		{Key: "req_digest", Value: reqDigest[:]},
		{Key: "req_id", Value: reqID},
		{Key: "seq_time", Value: rep.SeqTime},
		{Key: "session_gen", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
	}
}

// --- Pinned TLS 1.3 Channel-Bound SessionClient (for relay transport & e2e tests) ---

// SessionClient binds one authenticated session to a single pinned TLS 1.3
// connection (direct or WebSocket-tunneled inner TLS 1.3) and fails closed if
// the connection drops or redirects are attempted.
type SessionClient struct {
	origin     ldrcrypto.RelayOrigin
	reqBaseURL string
	lineID     []byte
	lineHex    string
	profDigest [32]byte
	principal  ldrcrypto.Principal
	signer     ldrcrypto.Signer

	httpClient *http.Client
	transport  *http.Transport
	closeConn  func()
	cb         [32]byte
	sessionID  []byte
	gen        uint64
	nextReqID  uint64
	mu         sync.Mutex
}

func formatHostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func resolveOriginDialAddr(originURL string) (string, error) {
	u, err := url.Parse(originURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("ldrrelay: relay origin URL missing host")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), nil
}

// DialSession opens a pinned TLS 1.3 connection to origin (directly for
// tls13_exporter, or over an outer HTTPS HTTP/1.1 WebSocket tunnel with pinned
// inner TLS 1.3 for ws_tls13_exporter), exports RFC 9266 tls-exporter channel
// binding from the origin-terminated TLS 1.3 connection, runs the single-use
// challenge/auth handshake, and returns an authenticated SessionClient.
func DialSession(ctx context.Context, origin ldrcrypto.RelayOrigin, lineID []byte, profDigest [32]byte, gen uint64, principal ldrcrypto.Principal, signer ldrcrypto.Signer) (*SessionClient, error) {
	innerTLSCfg, err := ClientTLSConfig(origin)
	if err != nil {
		return nil, err
	}

	var outerTLSCfg *tls.Config
	var reqBaseURL string
	var forceH2 bool
	var dialAddr string

	switch origin.SessionBinding {
	case ldrcrypto.SessionBindingTLS13Exporter:
		innerTLSCfg.NextProtos = []string{"h2", "http/1.1"}
		dialAddr, err = resolveOriginDialAddr(origin.URL)
		if err != nil {
			return nil, err
		}
		reqBaseURL = strings.TrimRight(origin.URL, "/")
		forceH2 = true

	case ldrcrypto.SessionBindingWSTLS13Exporter:
		outerTLSCfg, err = ClientOuterTLSConfig(origin)
		if err != nil {
			return nil, err
		}
		innerTLSCfg.NextProtos = []string{"http/1.1"}
		reqBaseURL = "https://" + formatHostForURL(origin.InnerServerName)
		forceH2 = false

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTransport, origin.SessionBinding)
	}

	var dialMu sync.Mutex
	var dialedOnce bool
	var capturedCB [32]byte
	var activeConn net.Conn
	handshakeCtx, cancelHandshake := context.WithCancel(ctx)
	defer cancelHandshake()

	tr := &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   forceH2,
		DialTLSContext: func(dctx context.Context, network, _ string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			if dialedOnce {
				// Never silently reconnect a bound session onto a new TLS handshake!
				return nil, errors.New("ldrrelay: TLS session connection dropped; re-authentication required")
			}
			// net/http detaches its dial context from the request. Preserve the
			// caller's cancellation throughout both handshakes.
			dialCtx, cancelDial := context.WithCancel(dctx)
			stop := context.AfterFunc(handshakeCtx, cancelDial)
			defer stop()
			defer cancelDial()
			var tc *tls.Conn
			if origin.SessionBinding == ldrcrypto.SessionBindingWSTLS13Exporter {
				tunnelCtx, cancel := context.WithTimeout(dialCtx, wsDefaultHandshakeTTL)
				defer cancel()
				wsConn, err := DialWSTunnel(tunnelCtx, origin.URL, outerTLSCfg)
				if err != nil {
					return nil, err
				}
				tc = tls.Client(wsConn, innerTLSCfg)
				if err := tc.HandshakeContext(tunnelCtx); err != nil {
					_ = tc.Close()
					_ = wsConn.Close()
					return nil, err
				}
			} else {
				dialer := &tls.Dialer{Config: innerTLSCfg}
				conn, err := dialer.DialContext(dialCtx, network, dialAddr)
				if err != nil {
					return nil, err
				}
				tc = conn.(*tls.Conn)
			}
			cb, err := ExportTLSChannelBinding(tc.ConnectionState())
			if err != nil {
				_ = tc.Close()
				return nil, err
			}
			capturedCB = cb
			activeConn = tc
			dialedOnce = true
			return tc, nil
		},
	}
	if !forceH2 {
		// Explicitly serve HTTP/1.1 inside inner ws_tls13_exporter tunnel matching inner ALPN.
		tr.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	}

	hc := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("ldrrelay: HTTP redirects are forbidden")
		},
	}

	sc := &SessionClient{
		origin:     origin,
		reqBaseURL: reqBaseURL,
		lineID:     bytes.Clone(lineID),
		lineHex:    hex.EncodeToString(lineID),
		profDigest: profDigest,
		principal:  principal,
		signer:     signer,
		httpClient: hc,
		transport:  tr,
		closeConn: func() {
			cancelHandshake()
			dialMu.Lock()
			c := activeConn
			activeConn = nil
			dialMu.Unlock()
			if c != nil {
				_ = c.Close()
			}
		},
		gen: gen,
	}

	// Step 1: request single-use challenge over the pinned TLS 1.3 connection.
	pCBOR, err := principal.ToCBOR()
	if err != nil {
		sc.Close()
		return nil, err
	}
	chResp, err := sc.postCBOR(ctx, "session/challenge", ldrcrypto.Map{
		{Key: "generation", Value: gen},
		{Key: "line_id", Value: lineID},
		{Key: "principal", Value: pCBOR},
		{Key: "profile_digest", Value: profDigest[:]},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		sc.Close()
		return nil, err
	}
	if v, err := ldrcrypto.MapUint(chResp, "v"); err != nil || v != 1 {
		sc.Close()
		return nil, errors.New("ldrrelay: malformed challenge reply version")
	}
	if errStr, ok := chResp["error"].(string); ok {
		sc.Close()
		return nil, fmt.Errorf("ldrrelay: challenge refused: %s", errStr)
	}
	if err := ldrcrypto.RequireExactKeys(chResp, []string{"expires_ms", "server_nonce", "session_id", "v"}); err != nil {
		sc.Close()
		return nil, fmt.Errorf("ldrrelay: malformed challenge reply: %w", err)
	}
	if exp, err := ldrcrypto.MapUint(chResp, "expires_ms"); err != nil || exp == 0 {
		sc.Close()
		return nil, errors.New("ldrrelay: malformed challenge reply expires_ms")
	}
	sid, err := ldrcrypto.MapBytesLen(chResp, "session_id", 16)
	if err != nil {
		sc.Close()
		return nil, err
	}
	nonce, err := ldrcrypto.MapBytesLen(chResp, "server_nonce", 32)
	if err != nil {
		sc.Close()
		return nil, err
	}

	dialMu.Lock()
	sc.cb = capturedCB
	dialMu.Unlock()

	// Step 2: sign session proof binding cb, server_nonce, session_id, relay_origin, line, gen, principal.
	authMsg := ldrcrypto.SessionAuthMessage{
		ProfileDigest:  profDigest,
		LineID:         lineID,
		Generation:     gen,
		Principal:      principal,
		RelayOrigin:    origin,
		SessionID:      sid,
		ServerNonce:    nonce,
		ChannelBinding: sc.cb[:],
	}
	sig, err := ldrcrypto.SignSessionAuth(signer, authMsg)
	if err != nil {
		sc.Close()
		return nil, err
	}
	authResp, err := sc.postCBOR(ctx, "session/auth", ldrcrypto.Map{
		{Key: "generation", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "sig", Value: sig},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		sc.Close()
		return nil, err
	}
	if err := validateAuthReply(authResp, lineID, gen, sid, nonce, principal); err != nil {
		sc.Close()
		return nil, err
	}
	sc.sessionID = bytes.Clone(sid)
	return sc, nil
}

func principalsEqual(a, b ldrcrypto.Principal) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == ldrcrypto.PrincipalCredential {
		return a.CredID == b.CredID
	}
	return a.Key != nil && b.Key != nil && a.Key.Equal(*b.Key)
}

// validateAuthReply strictly verifies session/auth responses before accepting
// authentication OR returning a terminal *AuthError (e.g. unresolved/revoked,
// which callers persist as a durable Rule 8 stop). Malformed or mismatched
// echoes always return an ordinary protocol error, never *AuthError.
func validateAuthReply(authResp map[string]any, lineID []byte, gen uint64, sid, nonce []byte, principal ldrcrypto.Principal) error {
	if v, err := ldrcrypto.MapUint(authResp, "v"); err != nil || v != 1 {
		return errors.New("ldrrelay: malformed auth reply version")
	}
	cls, err := ldrcrypto.MapString(authResp, "class")
	if err != nil || cls == "" {
		return errors.New("ldrrelay: malformed auth reply class")
	}
	switch cls {
	case "authenticated":
		if err := ldrcrypto.RequireExactKeys(authResp, []string{"class", "generation", "line_id", "session_id", "v"}); err != nil {
			return fmt.Errorf("ldrrelay: malformed authenticated reply: %w", err)
		}
		if gotGen, err := ldrcrypto.MapUint(authResp, "generation"); err != nil || gotGen != gen {
			return errors.New("ldrrelay: authenticated reply generation mismatch")
		}
		if gotLine, err := ldrcrypto.MapBytes(authResp, "line_id"); err != nil || !bytes.Equal(gotLine, lineID) {
			return errors.New("ldrrelay: authenticated reply line_id mismatch")
		}
		if gotSID, err := ldrcrypto.MapBytesLen(authResp, "session_id", 16); err != nil || !bytes.Equal(gotSID, sid) {
			return errors.New("ldrrelay: authenticated reply session_id mismatch")
		}
		return nil

	default:
		code, err := ldrcrypto.MapString(authResp, "code")
		if err != nil || code == "" {
			return errors.New("ldrrelay: malformed auth refusal reply code")
		}
		if cls == ldrcore.ClassUnresolved && code == "revoked" {
			if err := ldrcrypto.RequireExactKeys(authResp, []string{
				"class", "code", "generation", "line_id", "principal", "server_nonce", "session_id", "v",
			}); err != nil {
				return fmt.Errorf("ldrrelay: malformed revoked auth reply: %w", err)
			}
			if gotGen, err := ldrcrypto.MapUint(authResp, "generation"); err != nil || gotGen != gen {
				return errors.New("ldrrelay: revoked auth reply generation mismatch")
			}
			if gotLine, err := ldrcrypto.MapBytes(authResp, "line_id"); err != nil || !bytes.Equal(gotLine, lineID) {
				return errors.New("ldrrelay: revoked auth reply line_id mismatch")
			}
			if gotSID, err := ldrcrypto.MapBytesLen(authResp, "session_id", 16); err != nil || !bytes.Equal(gotSID, sid) {
				return errors.New("ldrrelay: revoked auth reply session_id mismatch")
			}
			if gotNonce, err := ldrcrypto.MapBytesLen(authResp, "server_nonce", 32); err != nil || !bytes.Equal(gotNonce, nonce) {
				return errors.New("ldrrelay: revoked auth reply server_nonce mismatch")
			}
			gotPrin, err := ldrcrypto.ParsePrincipal(authResp["principal"])
			if err != nil || !principalsEqual(gotPrin, principal) {
				return errors.New("ldrrelay: revoked auth reply principal mismatch")
			}
		}
		return &AuthError{Class: cls, Code: code}
	}
}

// AuthError reports a relay authentication refusal (including terminal revoked).
type AuthError struct {
	Class string
	Code  string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("ldrrelay: auth refused (%s / %s)", e.Class, e.Code)
}

// Close closes the underlying TLS 1.3 connection (and outer WebSocket tunnel, if any).
func (c *SessionClient) Close() {
	c.transport.CloseIdleConnections()
	if c.closeConn != nil {
		c.closeConn()
	}
}

// SessionID returns the authenticated session ID.
func (c *SessionClient) SessionID() []byte { return bytes.Clone(c.sessionID) }

// Principal returns the authenticated principal bound to this session.
func (c *SessionClient) Principal() ldrcrypto.Principal { return c.principal }

// ChannelBinding returns the 32-byte RFC 9266 tls-exporter channel binding value.
func (c *SessionClient) ChannelBinding() [32]byte { return c.cb }

func (c *SessionClient) postRawCBOR(ctx context.Context, endpoint string, raw []byte) (map[string]any, error) {
	reqURL := c.reqBaseURL + "/v1/lines/" + c.lineHex + "/" + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(respBytes) > maxHTTPBodyBytes {
		return nil, errors.New("ldrrelay: response exceeds transport bound")
	}
	dec, err := ldrcrypto.UnmarshalCBOR(respBytes, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 16384})
	if err != nil {
		return nil, fmt.Errorf("ldrrelay: non-cbor response (status %d): %w", resp.StatusCode, err)
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return nil, errors.New("ldrrelay: response must be CBOR map")
	}
	return m, nil
}

func (c *SessionClient) postCBOR(ctx context.Context, endpoint string, body ldrcrypto.Map) (map[string]any, error) {
	raw, err := ldrcrypto.MarshalCBORWithLimits(body, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 16384})
	if err != nil {
		return nil, err
	}
	return c.postRawCBOR(ctx, endpoint, raw)
}

func (c *SessionClient) verifyReplyBinding(m map[string]any, reqID uint64, reqDigest [32]byte) error {
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		return errors.New("ldrrelay: reply version mismatch")
	}
	if sg, err := ldrcrypto.MapUint(m, "session_gen"); err != nil || sg != c.gen {
		return errors.New("ldrrelay: reply session_gen mismatch")
	}
	if sid, err := ldrcrypto.MapBytesLen(m, "session_id", 16); err != nil || !bytes.Equal(sid, c.sessionID) {
		return errors.New("ldrrelay: reply session_id mismatch")
	}
	if rid, err := ldrcrypto.MapUint(m, "req_id"); err != nil || rid != reqID {
		return errors.New("ldrrelay: reply req_id mismatch")
	}
	if rd, err := ldrcrypto.MapBytesLen(m, "req_digest", 32); err != nil || !bytes.Equal(rd, reqDigest[:]) {
		return errors.New("ldrrelay: reply req_digest mismatch")
	}
	if lid, err := ldrcrypto.MapBytes(m, "line_id"); err != nil || !bytes.Equal(lid, c.lineID) {
		return errors.New("ldrrelay: reply line_id mismatch")
	}
	return nil
}

// Submit sends a signed intent (and optional payload/wrap sidecars) over the bound session.
func (c *SessionClient) Submit(ctx context.Context, intentBytes, payloadSidecar []byte, wrapSidecars map[[32]byte][]byte) (SubmitReply, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	reqMap := ldrcrypto.Map{
		{Key: "intent", Value: intentBytes},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "v", Value: uint64(1)},
	}
	if len(payloadSidecar) > 0 {
		reqMap = append(reqMap, ldrcrypto.MapEntry{Key: "payload", Value: payloadSidecar})
	}
	if len(wrapSidecars) > 0 {
		ids := make([][32]byte, 0, len(wrapSidecars))
		for cid := range wrapSidecars {
			ids = append(ids, cid)
		}
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				if bytes.Compare(ids[j][:], ids[i][:]) < 0 {
					ids[i], ids[j] = ids[j], ids[i]
				}
			}
		}
		wArr := make([]any, 0, len(ids))
		for _, cid := range ids {
			wArr = append(wArr, ldrcrypto.Map{
				{Key: "cred_id", Value: bytes.Clone(cid[:])},
				{Key: "data", Value: wrapSidecars[cid]},
			})
		}
		reqMap = append(reqMap, ldrcrypto.MapEntry{Key: "wraps", Value: wArr})
	}
	rawReq, err := ldrcrypto.MarshalCBORWithLimits(reqMap, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 16384})
	if err != nil {
		return SubmitReply{}, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "submit", rawReq)
	if err != nil {
		return SubmitReply{}, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return SubmitReply{}, err
	}
	return decodeSubmitReply(resp)
}

// AnchorRequest requests a fresh anchor over the bound TLS 1.3 session.
func (c *SessionClient) AnchorRequest(ctx context.Context) (AnchorReply, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	reqMsg := ldrcrypto.SessionRequestMessage{
		LineID: c.lineID, Generation: c.gen, SessionID: c.sessionID,
		ChannelBinding: c.cb[:], ReqID: reqID, Principal: c.principal,
		Body: ldrcrypto.Map{},
	}
	sig, err := ldrcrypto.SignSessionRequest(c.signer, ldrcrypto.PurposeAnchorRequest, reqMsg)
	if err != nil {
		return AnchorReply{}, err
	}
	reqMap := ldrcrypto.Map{
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "sig", Value: sig},
		{Key: "v", Value: uint64(1)},
	}
	rawReq, err := ldrcrypto.MarshalCBOR(reqMap)
	if err != nil {
		return AnchorReply{}, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "anchor", rawReq)
	if err != nil {
		return AnchorReply{}, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return AnchorReply{}, err
	}
	var out AnchorReply
	out.Class, _ = ldrcrypto.MapString(resp, "class")
	out.Code, _ = ldrcrypto.MapString(resp, "code")
	out.Gen, _ = ldrcrypto.MapUint(resp, "gen")
	out.Seq, _ = ldrcrypto.MapUint(resp, "seq")
	out.SeqTime, _ = ldrcrypto.MapUint(resp, "seq_time")
	out.Wrote, _ = ldrcrypto.MapBool(resp, "wrote")
	if hb, err := ldrcrypto.MapBytesLen(resp, "head", 32); err == nil {
		copy(out.Head[:], hb)
	}
	return out, nil
}

// Query performs a signed P7 outcome query over the bound session.
func (c *SessionClient) Query(ctx context.Context, key ldrstore.StoredOpKey, intentDigest [32]byte) (SubmitReply, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	reqMsg := ldrcrypto.SessionRequestMessage{
		LineID: c.lineID, Generation: c.gen, SessionID: c.sessionID,
		ChannelBinding: c.cb[:], ReqID: reqID, Principal: c.principal,
		Body: ldrcrypto.Map{
			{Key: "intent_digest", Value: intentDigest[:]},
			{Key: "op_gen", Value: key.Generation},
			{Key: "op_id", Value: key.OpID},
			{Key: "op_seen_seq", Value: key.SeenSeq},
			{Key: "op_signer", Value: key.Signer},
		},
	}
	sig, err := ldrcrypto.SignSessionRequest(c.signer, ldrcrypto.PurposeQuery, reqMsg)
	if err != nil {
		return SubmitReply{}, err
	}
	reqMap := ldrcrypto.Map{
		{Key: "intent_digest", Value: intentDigest[:]},
		{Key: "op_gen", Value: key.Generation},
		{Key: "op_id", Value: key.OpID},
		{Key: "op_seen_seq", Value: key.SeenSeq},
		{Key: "op_signer", Value: key.Signer},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "sig", Value: sig},
		{Key: "v", Value: uint64(1)},
	}
	rawReq, err := ldrcrypto.MarshalCBOR(reqMap)
	if err != nil {
		return SubmitReply{}, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "query", rawReq)
	if err != nil {
		return SubmitReply{}, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return SubmitReply{}, err
	}
	return decodeSubmitReply(resp)
}

// ControlLog fetches a page of control-only frames (O25 full replay).
func (c *SessionClient) ControlLog(ctx context.Context, fromSeq, maxCount uint64) ([]ControlFrameWire, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	reqMap := ldrcrypto.Map{
		{Key: "from_seq", Value: fromSeq},
		{Key: "max_count", Value: maxCount},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "v", Value: uint64(1)},
	}
	rawReq, err := ldrcrypto.MarshalCBOR(reqMap)
	if err != nil {
		return nil, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "log", rawReq)
	if err != nil {
		return nil, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return nil, err
	}
	cls, _ := ldrcrypto.MapString(resp, "class")
	if cls != "ok" {
		code, _ := ldrcrypto.MapString(resp, "code")
		return nil, fmt.Errorf("ldrrelay: log fetch refused (%s / %s)", cls, code)
	}
	arr, err := ldrcrypto.MapArray(resp, "frames")
	if err != nil {
		return nil, err
	}
	out := make([]ControlFrameWire, 0, len(arr))
	for _, elem := range arr {
		fm, ok := elem.(map[string]any)
		if !ok {
			return nil, errors.New("ldrrelay: invalid control frame element")
		}
		if err := ldrcrypto.RequireExactKeys(fm,
			[]string{"gen", "head", "intent", "op_type", "origin", "prev_head", "seq", "seq_time"},
			"payload_commit", "wraps"); err != nil {
			return nil, fmt.Errorf("ldrrelay: invalid control frame keys: %w", err)
		}
		var fr ControlFrameWire
		var err error
		if fr.Gen, err = ldrcrypto.MapUint(fm, "gen"); err != nil {
			return nil, err
		}
		if fr.Seq, err = ldrcrypto.MapUint(fm, "seq"); err != nil {
			return nil, err
		}
		if fr.SeqTime, err = ldrcrypto.MapUint(fm, "seq_time"); err != nil {
			return nil, err
		}
		if fr.Origin, err = ldrcrypto.MapString(fm, "origin"); err != nil {
			return nil, err
		}
		if fr.OpType, err = ldrcrypto.MapString(fm, "op_type"); err != nil {
			return nil, err
		}
		if fr.IntentBytes, err = ldrcrypto.MapBytes(fm, "intent"); err != nil {
			return nil, err
		}
		ph, err := ldrcrypto.MapBytesLen(fm, "prev_head", 32)
		if err != nil {
			return nil, err
		}
		copy(fr.PrevHead[:], ph)
		hd, err := ldrcrypto.MapBytesLen(fm, "head", 32)
		if err != nil {
			return nil, err
		}
		copy(fr.Head[:], hd)
		if pcRaw, has := fm["payload_commit"]; has {
			c, err := ldrcrypto.ParseCommitment(pcRaw)
			if err != nil {
				return nil, err
			}
			fr.PayloadCommit = &c
		}
		if _, has := fm["wraps"]; has {
			wArr, err := ldrcrypto.MapArray(fm, "wraps")
			if err != nil {
				return nil, err
			}
			fr.WrapCommits = make([]ldrcrypto.WrapManifestEntry, 0, len(wArr))
			for _, we := range wArr {
				wm, ok := we.(map[string]any)
				if !ok {
					return nil, errors.New("ldrrelay: invalid wrap entry in control frame")
				}
				if err := ldrcrypto.RequireExactKeys(wm, []string{"commit", "cred_id"}); err != nil {
					return nil, err
				}
				cidB, err := ldrcrypto.MapBytesLen(wm, "cred_id", 32)
				if err != nil {
					return nil, err
				}
				cm, err := ldrcrypto.ParseCommitment(wm["commit"])
				if err != nil {
					return nil, err
				}
				var cid [32]byte
				copy(cid[:], cidB)
				fr.WrapCommits = append(fr.WrapCommits, ldrcrypto.WrapManifestEntry{CredID: cid, Commit: cm})
			}
		}
		out = append(out, fr)
	}
	return out, nil
}

// FetchSidecar retrieves a stored sidecar blob by kind and commitment digest.
func (c *SessionClient) FetchSidecar(ctx context.Context, kind string, digest [32]byte) ([]byte, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	reqMap := ldrcrypto.Map{
		{Key: "digest", Value: digest[:]},
		{Key: "kind", Value: kind},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "v", Value: uint64(1)},
	}
	rawReq, err := ldrcrypto.MarshalCBOR(reqMap)
	if err != nil {
		return nil, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "sidecar", rawReq)
	if err != nil {
		return nil, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return nil, err
	}
	cls, _ := ldrcrypto.MapString(resp, "class")
	if cls != "ok" {
		code, _ := ldrcrypto.MapString(resp, "code")
		return nil, fmt.Errorf("ldrrelay: sidecar refused (%s / %s)", cls, code)
	}
	return ldrcrypto.MapBytes(resp, "data")
}

func decodeSubmitReply(m map[string]any) (SubmitReply, error) {
	var out SubmitReply
	var err error
	if out.Class, err = ldrcrypto.MapString(m, "class"); err != nil {
		return SubmitReply{}, err
	}
	out.Code, _ = ldrcrypto.MapString(m, "code")
	out.Original, _ = ldrcrypto.MapBool(m, "original")
	out.SeqTime, _ = ldrcrypto.MapUint(m, "seq_time")
	out.Outcome.Kind, _ = ldrcrypto.MapString(m, "outcome_kind")
	out.Outcome.Reason, _ = ldrcrypto.MapString(m, "outcome_reason")
	out.Outcome.RefGen, _ = ldrcrypto.MapUint(m, "outcome_ref_gen")
	out.Outcome.RefSeq, _ = ldrcrypto.MapUint(m, "outcome_ref_seq")
	out.Outcome.Seq, _ = ldrcrypto.MapUint(m, "outcome_seq")
	if hb, err := ldrcrypto.MapBytesLen(m, "head", 32); err == nil {
		copy(out.Head[:], hb)
	}
	return out, nil
}
