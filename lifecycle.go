package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Lifecycle events are append-only testimony. Archiving never resolves a
// question, and an old floor is not a perpetual demand for another reply.
type CallEvent struct {
	ID      string `json:"id"`
	By      string `json:"by"`
	At      string `json:"at"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Related string `json:"related,omitempty"`
}

const callStaleAfter = 48 * time.Hour

func CallEvents(c *Call) []CallEvent {
	files, _ := filepath.Glob(filepath.Join(c.Dir(), "events", "*.json"))
	sort.Strings(files)
	var out []CallEvent
	for _, f := range files {
		var e CallEvent
		b, err := os.ReadFile(f)
		if err == nil && json.Unmarshal(b, &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
func CallStatus(c *Call, turns []Turn) string {
	state := "open"
	reopened := ""
	for _, e := range CallEvents(c) {
		if e.State != "linked" {
			state = e.State
			if e.State == "open" {
				reopened = e.At
			}
		}
	}
	if state != "open" {
		return state
	}
	if IsClosed(c) {
		return "resolved"
	}
	at := c.Opened
	if len(turns) > 0 {
		at = turns[len(turns)-1].At
	}
	if reopened > at {
		at = reopened
	}
	t, err := time.Parse(time.RFC3339, at)
	if err == nil && time.Since(t) > callStaleAfter {
		return "stale"
	}
	return "open"
}
func SetCallStatus(c *Call, me, state, reason, related string) error {
	if !c.Involves(me) {
		return fmt.Errorf("not a participant")
	}
	switch state {
	case "open", "resolved", "deferred", "archived", "linked":
	default:
		return fmt.Errorf("state must be open, resolved, deferred, archived or linked")
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("a reason is required; it stays in the transcript")
	}
	if state == "linked" {
		other, err := ResolveCall(related, me)
		if err != nil {
			return err
		}
		if other.ID == c.ID {
			return fmt.Errorf("cannot link a call to itself")
		}
		related = other.ID
	}
	dir := filepath.Join(c.Dir(), "events")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for i := 0; i < 16; i++ {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		id := fmt.Sprintf("%06d", len(files)+1)
		e := CallEvent{id, me, now(), state, reason, related}
		b, _ := json.MarshalIndent(e, "", "  ")
		err := atomicCreate(filepath.Join(dir, id+".json"), append(b, '\n'))
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if state == "open" {
			ClearByes(c)
		}
		return nil
	}
	return fmt.Errorf("lifecycle event contention")
}
func NoteUnseen(c *Call, me string) (int, int) {
	notes, _ := Notes(c)
	st := LoadAgentState(c, me)
	n, last := 0, 0
	for _, note := range notes {
		last = note.N
		if note.N > st.SeenNotes && note.From != me {
			n++
		}
	}
	return n, last
}
func MarkNotesSeen(c *Call, me string, last int) {
	st := LoadAgentState(c, me)
	if last > st.SeenNotes {
		st.SeenNotes = last
		_ = SaveAgentState(c, me, st)
	}
}
func Inbox(me string, all bool) (string, error) {
	calls, err := ListCalls()
	if err != nil {
		return "", err
	}
	out := RecoveryNotices(me)
	for _, c := range calls {
		if !c.Involves(me) {
			continue
		}
		turns, _ := Turns(c)
		state := CallStatus(c, turns)
		st := LoadAgentState(c, me)
		nt := 0
		for _, t := range turns {
			if t.N > st.Seen && t.From != me {
				nt++
			}
		}
		nn, _ := NoteUnseen(c, me)
		if !all && state != "open" && nt == 0 && nn == 0 {
			continue
		}
		obligation := "no reply due"
		if state == "open" && FloorHolder(c, turns) == me {
			obligation = "reply due"
		} else if state != "resolved" && state != "open" {
			obligation = "unresolved; not blocking"
		}
		out = append(out, fmt.Sprintf("%s [%s] %s | %d turns, %d notes unread | %s\n  %s", c.ID, state, c.Peer(me), nt, nn, obligation, c.Subject))
	}
	if len(out) == 0 {
		return "inbox clear (use all=true for history)", nil
	}
	return strings.Join(out, "\n"), nil
}
func retirePath(me string) string { return filepath.Join(presenceDir(), me+".retired") }
func Retired(me string) bool      { _, e := os.Stat(retirePath(me)); return e == nil }
func Retire(me string, retired bool) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	if retired {
		return atomicReplace(retirePath(me), []byte(now()+"\n"))
	}
	err := os.Remove(retirePath(me))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Notes are visible once per new note but never enter the stop-hook obligation
// set. A read acknowledges them; notification alone does not mark them read.
func NoteNotices(me string) []string {
	calls, _ := ListCalls()
	var out []string
	for _, c := range calls {
		if !c.Involves(me) {
			continue
		}
		st := LoadAgentState(c, me)
		notes, _ := Notes(c)
		count, last := 0, st.NotesNotified
		for _, n := range notes {
			if n.N > st.NotesNotified && n.N > st.SeenNotes && n.From != me {
				count++
			}
			if n.N > last {
				last = n.N
			}
		}
		if count > 0 {
			out = append(out, fmt.Sprintf("%s: %d new note(s), no reply owed; read or inbox.", c.ID, count))
		}
		if last > st.NotesNotified {
			st.NotesNotified = last
			_ = SaveAgentState(c, me, st)
		}
	}
	return out
}
