package ldrrelay

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPerLineAdmissionAndConnectionCleanup(t *testing.T) {
	s := NewRelayServer(nil)
	s.ConfigureAdmission(2, 1)
	httpServer := new(http.Server)
	s.TrackConnections(httpServer)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn := httpServer.ConnContext(context.Background(), a).Value(connectionKey{}).(net.Conn)
	line := []byte("one")
	s.pending["p"] = pendingChallenge{conn: conn, lineID: line, expiresAt: time.Now().Add(time.Minute)}
	s.sessions["s"] = &activeSession{conn: conn, lineID: line, lastSeen: time.Now()}
	s.rememberLocked(conn, "p")
	s.rememberLocked(conn, "s")
	if !s.pendingFullLocked(line) || !s.sessionsFullLocked(line) || s.pendingFullLocked([]byte("two")) || s.sessionsFullLocked([]byte("two")) {
		t.Fatal("admission budget did not isolate the two lines")
	}
	if st := s.AdmissionStatus(); st.Pending != 1 || st.Sessions != 1 {
		t.Fatal(st)
	}
	httpServer.ConnState(a, http.StateClosed)
	if st := s.AdmissionStatus(); st.Pending != 0 || st.Sessions != 0 || len(s.byConn) != 0 {
		t.Fatal(st)
	}
}
