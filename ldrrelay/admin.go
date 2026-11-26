package ldrrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apology-is-policy/yip/ldrstore"
)

const (
	adminMaxBodyBytes = 4096
	adminTimeout      = 5 * time.Second
)

var (
	ErrAdminSocketConflict = errors.New("ldrrelay: admin socket path conflict")
)

// DefaultAdminSocketPath returns the default local Unix admin socket path
// inside the relay's data directory.
func DefaultAdminSocketPath(dataDir string) string {
	return filepath.Join(dataDir, "admin.sock")
}

// AdminServer exposes local host-administrator controls (such as explicit
// clock resume under LDR-GO-RELAY-DESIGN §4.1) strictly over an owner-only
// (0600) Unix domain socket — never on any network interface.
type AdminServer struct {
	sockPath string
	sockInfo os.FileInfo
	ln       net.Listener
	srv      *http.Server
	engine   *RelayEngine

	closeOnce sync.Once
	done      chan struct{}
}

// StartAdminServer binds an owner-only (0600) local Unix domain socket at
// sockPath and serves local operator control endpoints for engine.
// It refuses to replace any non-socket file or an already-active socket.
func StartAdminServer(sockPath string, engine *RelayEngine) (*AdminServer, error) {
	if sockPath == "" {
		return nil, errors.New("ldrrelay: empty admin socket path")
	}
	if engine == nil {
		return nil, errors.New("ldrrelay: nil relay engine")
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(sockPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%w: %s exists and is not a Unix socket", ErrAdminSocketConflict, sockPath)
		}
		// Probe whether another live admin server owns this socket before
		// removing a stale socket file left by an unclean exit.
		if conn, dialErr := net.DialTimeout("unix", sockPath, 150*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: %s is already active", ErrAdminSocketConflict, sockPath)
		}
		if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("ldrrelay: listen local admin socket %s: %w (hint: pass a shorter --admin-sock path if directory path exceeds OS sun_path limit)", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("ldrrelay: chmod 0600 admin socket %s: %w", sockPath, err)
	}
	fi, err := os.Lstat(sockPath)
	if err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, err
	}

	as := &AdminServer{
		sockPath: sockPath,
		sockInfo: fi,
		ln:       ln,
		engine:   engine,
		done:     make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/status", as.handleStatus)
	mux.HandleFunc("/admin/v1/clock/resume", as.handleClockResume)
	as.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: adminTimeout,
	}
	go func() {
		defer close(as.done)
		_ = as.srv.Serve(ln)
	}()
	return as, nil
}

// SocketPath returns the bound local Unix socket path.
func (a *AdminServer) SocketPath() string {
	return a.sockPath
}

// Close gracefully stops the local admin server and removes its socket file
// only if the pathname still points to the same socket inode.
func (a *AdminServer) Close(ctx context.Context) error {
	var retErr error
	a.closeOnce.Do(func() {
		if ctx == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), adminTimeout)
			defer cancel()
		}
		retErr = a.srv.Shutdown(ctx)
		_ = a.ln.Close()
		<-a.done
		if cur, err := os.Lstat(a.sockPath); err == nil && a.sockInfo != nil && os.SameFile(cur, a.sockInfo) {
			_ = os.Remove(a.sockPath)
		}
	})
	return retErr
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"lines": a.engine.Status(),
	})
}

type adminClockResumeRequest struct {
	LineID string `json:"line_id,omitempty"`
}

type adminClockResumeResponse struct {
	OK      bool                `json:"ok"`
	Results []ClockResumeResult `json:"results,omitempty"`
	Error   string              `json:"error,omitempty"`
}

func (a *AdminServer) handleClockResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, adminMaxBodyBytes+1))
	if err != nil {
		writeAdminJSON(w, http.StatusBadRequest, adminClockResumeResponse{OK: false, Error: err.Error()})
		return
	}
	if len(raw) > adminMaxBodyBytes {
		writeAdminJSON(w, http.StatusRequestEntityTooLarge, adminClockResumeResponse{OK: false, Error: "request body too large"})
		return
	}
	var req adminClockResumeRequest
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			writeAdminJSON(w, http.StatusBadRequest, adminClockResumeResponse{OK: false, Error: "invalid JSON request"})
			return
		}
	}

	req.LineID = strings.TrimSpace(req.LineID)
	if req.LineID != "" {
		lineID, err := hex.DecodeString(req.LineID)
		if err != nil || len(lineID) != 16 {
			writeAdminJSON(w, http.StatusBadRequest, adminClockResumeResponse{OK: false, Error: "line_id must be 32 hex chars (16 bytes)"})
			return
		}
		st, err := a.engine.ConfirmClockResume(lineID)
		if errors.Is(err, ldrstore.ErrLineNotFound) {
			writeAdminJSON(w, http.StatusNotFound, adminClockResumeResponse{OK: false, Error: err.Error()})
			return
		}
		res := ClockResumeResult{LineID: hex.EncodeToString(lineID), Clock: st}
		if err != nil {
			res.Error = err.Error()
			writeAdminJSON(w, http.StatusConflict, adminClockResumeResponse{
				OK:      false,
				Results: []ClockResumeResult{res},
				Error:   err.Error(),
			})
			return
		}
		writeAdminJSON(w, http.StatusOK, adminClockResumeResponse{
			OK:      true,
			Results: []ClockResumeResult{res},
		})
		return
	}

	results, err := a.engine.ConfirmAllClockResumes()
	if err != nil {
		writeAdminJSON(w, http.StatusConflict, adminClockResumeResponse{
			OK:      false,
			Results: results,
			Error:   err.Error(),
		})
		return
	}
	writeAdminJSON(w, http.StatusOK, adminClockResumeResponse{
		OK:      true,
		Results: results,
	})
}

func writeAdminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newAdminHTTPClient(sockPath string) *http.Client {
	dialer := &net.Dialer{Timeout: adminTimeout}
	return &http.Client{
		Timeout: adminTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", sockPath)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("ldrrelay: admin client refuses redirects")
		},
	}
}

// AdminStatus queries the live status of a running relay via its local admin socket.
func AdminStatus(ctx context.Context, sockPath string) ([]LineStatus, error) {
	if sockPath == "" {
		return nil, errors.New("ldrrelay: empty admin socket path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://relay.local/admin/v1/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := newAdminHTTPClient(sockPath).Do(req)
	if err != nil {
		return nil, fmt.Errorf("ldrrelay: connect local admin socket %s: %w", sockPath, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ldrrelay: admin status HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Lines []LineStatus `json:"lines"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Lines, nil
}

// AdminClockResume sends an explicit operator clock-resume confirmation to the
// running relay's live ClockGuard over its local Unix admin socket. If lineID
// is empty, all provisioned lines on the running relay are resumed.
func AdminClockResume(ctx context.Context, sockPath string, lineID []byte) ([]ClockResumeResult, error) {
	if sockPath == "" {
		return nil, errors.New("ldrrelay: empty admin socket path")
	}
	var bodyReq adminClockResumeRequest
	if len(lineID) > 0 {
		bodyReq.LineID = hex.EncodeToString(lineID)
	}
	payload, err := json.Marshal(bodyReq)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://relay.local/admin/v1/clock/resume", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := newAdminHTTPClient(sockPath).Do(req)
	if err != nil {
		return nil, fmt.Errorf("ldrrelay: connect local admin socket %s: %w", sockPath, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out adminClockResumeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ldrrelay: admin clock resume HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if resp.StatusCode != http.StatusOK || !out.OK {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return out.Results, fmt.Errorf("ldrrelay: clock resume refused: %s", msg)
	}
	return out.Results, nil
}
