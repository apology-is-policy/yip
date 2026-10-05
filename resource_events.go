package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// An intent is persisted before a destructive transition. It is evidence of
// the request, not a grant: consumers must inspect the current lease before
// starting work. Keeping these events makes release/reacquire/release visible
// even when both transitions happen between watcher polls.
type ResourceEvent struct {
	ID       string   `json:"id"`
	At       string   `json:"at"`
	By       string   `json:"by"`
	Action   string   `json:"action"`
	Previous Lease    `json:"previous"`
	Evidence []string `json:"runner_evidence,omitempty"`
}

func recordResourceEvent(name, by, action string, previous Lease, runners []Runner) error {
	dir := filepath.Join(resourcesDir(), name+".events")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	e := ResourceEvent{ID: requestID(), At: now(), By: by, Action: action, Previous: previous}
	for _, r := range runners {
		e.Evidence = append(e.Evidence, fmt.Sprintf("%s pid %d start %s: %s", r.Host, r.PID, r.Start, runnerStatus(r)))
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return atomicCreate(filepath.Join(dir, e.ID+".json"), append(b, '\n'))
}

func ResourceEvents(name string) []ResourceEvent {
	files, _ := filepath.Glob(filepath.Join(resourcesDir(), name+".events", "*.json"))
	var out []ResourceEvent
	for _, f := range files {
		b, err := os.ReadFile(f)
		var e ResourceEvent
		if err == nil && json.Unmarshal(b, &e) == nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At == out[j].At {
			return out[i].ID < out[j].ID
		}
		return out[i].At < out[j].At
	})
	return out
}

func RecoveryNotices(me string) []string {
	var out []string
	for _, r := range knownResources {
		for _, e := range ResourceEvents(r.Name) {
			if e.Previous.Holder == me && e.By != me {
				out = append(out, fmt.Sprintf("RESOURCE %s %s: %s by %s; previous owner %s. Inspect resources; event is not a grant.", r.Name, e.At, e.Action, e.By, me))
			}
		}
	}
	return out
}

// Hooks deliver each peer recovery notice once; inbox retains its durable
// history. Notification is advisory and never creates a stop obligation.
func FreshRecoveryNotices(me string) []string {
	var out []string
	dir := filepath.Join(presenceDir(), me+".resource-notices")
	if os.MkdirAll(dir, 0755) != nil {
		return nil
	}
	for _, r := range knownResources {
		for _, e := range ResourceEvents(r.Name) {
			if e.Previous.Holder != me || e.By == me {
				continue
			}
			marker := filepath.Join(dir, e.ID)
			if _, err := os.Stat(marker); err == nil {
				continue
			}
			line := fmt.Sprintf("%s: %s by %s. Prior lease/evidence retained; inspect resources before further work.", r.Name, e.Action, e.By)
			if err := atomicCreate(marker, []byte(now()+"\n")); err == nil {
				out = append(out, line)
			}
		}
	}
	return out
}
