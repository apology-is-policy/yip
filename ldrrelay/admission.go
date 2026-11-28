package ldrrelay

import (
	"bytes"
	"context"
	"net"
	"net/http"
)

type AdmissionStatus struct {
	Tunnels    int64  `json:"active_tunnels"`
	Handshakes int    `json:"in_flight_auth"`
	Pending    int    `json:"pending_challenges"`
	Sessions   int    `json:"active_sessions"`
	Overload   uint64 `json:"overload_rejections"`
}

// ConfigureAdmission sets budgets before starting listeners.
func (s *RelayServer) ConfigureAdmission(auth, perLine int) {
	s.authSlots = make(chan struct{}, auth)
	s.perLine = perLine
}
func (s *RelayServer) AdmissionStatus() AdmissionStatus {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	return AdmissionStatus{s.tunnels.Load(), len(s.authSlots), len(s.pending), len(s.sessions), s.overload.Load()}
}
func (s *RelayServer) pendingFullLocked(line []byte) bool {
	if len(s.pending) >= maxPendingChallenges {
		return true
	}
	if len(s.pending) < s.perLine {
		return false
	}
	count := 0
	for _, p := range s.pending {
		if bytes.Equal(p.lineID, line) {
			count++
		}
	}
	return count >= s.perLine
}
func (s *RelayServer) sessionsFullLocked(line []byte) bool {
	if len(s.sessions) >= maxActiveSessions {
		return true
	}
	if len(s.sessions) < s.perLine {
		return false
	}
	count := 0
	for _, p := range s.sessions {
		if bytes.Equal(p.lineID, line) {
			count++
		}
	}
	return count >= s.perLine
}

type connectionKey struct{}

// Challenges and sessions are bound to one TLS connection. Drop their slots
// when that connection closes, including clients that disconnect without logout.
func (s *RelayServer) TrackConnections(server *http.Server) {
	previous := server.ConnContext
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if previous != nil {
			ctx = previous(ctx, c)
		}
		return context.WithValue(ctx, connectionKey{}, c)
	}
	server.ConnState = func(c net.Conn, state http.ConnState) {
		if state != http.StateClosed {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		ids := s.byConn[c]
		delete(s.byConn, c)
		for id := range ids {
			delete(s.pending, id)
			delete(s.sessions, id)
		}
	}
}

func (s *RelayServer) rememberLocked(conn net.Conn, id string) {
	if conn == nil {
		return
	}
	if s.byConn[conn] == nil {
		s.byConn[conn] = make(map[string]struct{})
	}
	s.byConn[conn][id] = struct{}{}
}

func (s *RelayServer) forgetLocked(conn net.Conn, id string) {
	if conn == nil {
		return
	}
	ids := s.byConn[conn]
	delete(ids, id)
	if len(ids) == 0 {
		delete(s.byConn, conn)
	}
}
