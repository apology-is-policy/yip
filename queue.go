package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const requestLifetime = 24 * time.Hour
const requestOfferWindow = 2 * time.Minute

func requestID() string {
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func loadRequest(name, agent string) (QueueEntry, bool) {
	var q QueueEntry
	b, e := os.ReadFile(queuePath(name, agent))
	if e != nil {
		return q, false
	}
	if json.Unmarshal(b, &q) != nil {
		return q, false
	}
	return q, true
}
func saveRequest(name string, q QueueEntry) error {
	b, _ := json.MarshalIndent(q, "", "  ")
	return atomicReplace(queuePath(name, q.Agent), append(b, '\n'))
}
func archiveRequest(name string, q QueueEntry, state string) error {
	if q.ID == "" {
		q.ID = requestID()
	}
	q.State = state
	dir := filepath.Join(resourcesDir(), name+".history")
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(q, "", "  ")
	if e := atomicCreate(filepath.Join(dir, q.ID+"-"+state+".json"), append(b, '\n')); e != nil && !os.IsExist(e) {
		return e
	}
	return nil
}
func finishRequest(name, agent, state string) error {
	q, ok := loadRequest(name, agent)
	if !ok {
		return nil
	}
	if e := archiveRequest(name, q, state); e != nil {
		return e
	}
	e := os.Remove(queuePath(name, agent))
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
func CancelRequest(name, agent string) error {
	unlock, e := resourceGuard(name)
	if e != nil {
		return e
	}
	defer unlock()
	return finishRequest(name, agent, "cancelled")
}
func QueueHistory(name string) (string, error) {
	if _, ok := KnownResource(name); !ok {
		return "", fmt.Errorf("unknown resource")
	}
	files, _ := filepath.Glob(filepath.Join(resourcesDir(), name+".history", "*.json"))
	files2, _ := filepath.Glob(filepath.Join(queueDir(name), "*.json"))
	files = append(files, files2...)
	var rows []string
	for _, f := range files {
		var q QueueEntry
		b, e := os.ReadFile(f)
		if e != nil || json.Unmarshal(b, &q) != nil {
			continue
		}
		state := q.State
		if state == "" {
			state = "queued"
		}
		if state == "queued" && q.stale() {
			state = "expired"
		}
		rows = append(rows, fmt.Sprintf("%s %s %s %s %s", q.Since, q.ID, q.Agent, state, q.Reason))
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n"), nil
}

// Called only under resourceGuard. Offer expiry relinquishes queued interest,
// never a lease. Reads do not renew requests or manufacture agent activity.
func advanceOffers(name string) error {
	if _, held := LoadLease(name); held {
		return nil
	}
	for {
		q := Queue(name)
		if len(q) == 0 {
			return nil
		}
		head := q[0]
		if head.Expires == "" {
			return nil
		} // legacy client's own 15m window
		if head.Offered == "" {
			head.Offered = now()
			return saveRequest(name, head)
		}
		t, e := time.Parse(time.RFC3339, head.Offered)
		if e != nil || time.Since(t) < requestOfferWindow {
			return nil
		}
		if e := finishRequest(name, head.Agent, "offer-expired"); e != nil {
			return e
		}
	}
}
func Request(name, agent, reason string, ttl time.Duration, pids []int) (bool, Lease, int, error) {
	if err := validatePids(pids); err != nil {
		return false, Lease{}, 0, err
	}
	unlock, e := resourceGuard(name)
	if e != nil {
		return false, Lease{}, 0, e
	}
	if e = advanceOffers(name); e != nil {
		unlock()
		return false, Lease{}, 0, e
	}
	l, held, readErr := readLease(name)
	if readErr != nil {
		unlock()
		return false, Lease{}, 0, readErr
	}
	if held && l.Holder == agent {
		unlock()
		return TryAcquire(name, agent, reason, ttl, pids)
	}
	q, ok := loadRequest(name, agent)
	if !ok || q.stale() {
		if ok {
			if e := archiveRequest(name, q, "expired"); e != nil {
				unlock()
				return false, Lease{}, 0, e
			}
		}
		q = QueueEntry{ID: requestID(), Agent: agent, Since: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	q.Reason = reason
	q.Seen = now()
	q.Expires = time.Now().Add(requestLifetime).UTC().Format(time.RFC3339)
	q.State = "queued"
	e = saveRequest(name, q)
	unlock()
	if e != nil {
		return false, Lease{}, 0, e
	}
	return TryAcquire(name, agent, reason, ttl, pids)
}
