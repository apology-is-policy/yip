package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Broadcast struct {
	ID         string   `json:"id"`
	At         string   `json:"at"`
	By         string   `json:"by"` // attribution, not authenticated operator approval
	Kind       string   `json:"kind"`
	Body       string   `json:"body"`
	Recipients []string `json:"recipients"`
}
type BroadcastReply struct {
	At   string `json:"at"`
	Body string `json:"body"`
}
type BroadcastReceipt struct {
	ReadAt   string           `json:"read_at,omitempty"`
	Notified bool             `json:"notified,omitempty"`
	Replies  []BroadcastReply `json:"replies,omitempty"`
}

func broadcastDir() string { return filepath.Join(Root(), "broadcasts") }
func (b Broadcast) hasRecipient(agent string) bool {
	for _, a := range b.Recipients {
		if a == agent {
			return true
		}
	}
	return false
}
func BroadcastRecipients() []string {
	var out []string
	for _, a := range LoadMembers().Names() {
		if Retired(a) {
			continue
		}
		if endpointExists(a) {
			ep, err := readEndpoint(a)
			if err != nil || ep.Paused {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}
func CreateBroadcast(by, kind, body string, recipients []string) (*Broadcast, error) {
	if kind != "announcement" && kind != "regroup" && kind != "briefing" {
		return nil, fmt.Errorf("kind must be announcement, regroup or briefing")
	}
	if strings.TrimSpace(by) == "" || strings.TrimSpace(body) == "" || len(body) > 64*1024 {
		return nil, fmt.Errorf("sender and body required (body limit 64 KiB)")
	}
	known := LoadMembers().Names()
	set := map[string]bool{}
	for _, a := range recipients {
		if !validComponent(a) {
			return nil, fmt.Errorf("invalid recipient %q", a)
		}
		found := false
		for _, k := range known {
			if k == a {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("%s is not a line member", a)
		}
		set[a] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("select at least one recipient")
	}
	recipients = nil
	for a := range set {
		recipients = append(recipients, a)
	}
	sort.Strings(recipients)
	b := &Broadcast{ID: requestID(), At: now(), By: by, Kind: kind, Body: body, Recipients: recipients}
	if err := os.MkdirAll(broadcastDir(), 0700); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	// This single immutable record is also the delivery intent for every recipient.
	if err = atomicCreate(filepath.Join(broadcastDir(), b.ID+".json"), append(data, '\n')); err != nil {
		return nil, err
	}
	d, err := os.Open(broadcastDir())
	if err != nil {
		return b, err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return b, err
	}
	return b, nil
}
func ListBroadcasts() ([]Broadcast, error) {
	files, err := filepath.Glob(filepath.Join(broadcastDir(), "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Broadcast
	for _, f := range files {
		var b Broadcast
		if err = readState(f, &b); err != nil {
			return nil, err
		}
		if !validComponent(b.ID) {
			return nil, fmt.Errorf("invalid broadcast ID in %s", f)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
func ListBroadcastsQuiet() []Broadcast { b, _ := ListBroadcasts(); return b }
func loadBroadcast(id string) (Broadcast, error) {
	var b Broadcast
	if !validComponent(id) {
		return b, fmt.Errorf("invalid broadcast ID")
	}
	err := readState(filepath.Join(broadcastDir(), id+".json"), &b)
	if err == nil && b.ID != id {
		err = fmt.Errorf("broadcast not found")
	}
	return b, err
}
func receiptPath(id, agent string) string {
	return filepath.Join(broadcastDir(), id+".receipts", agent+".json")
}
func broadcastReceipt(id, agent string) (BroadcastReceipt, error) {
	var r BroadcastReceipt
	if !validComponent(id) || !validComponent(agent) {
		return r, fmt.Errorf("invalid receipt identity")
	}
	err := readState(receiptPath(id, agent), &r)
	return r, err
}
func ReadBroadcast(id, agent string) (string, error) {
	if !validComponent(agent) {
		return "", fmt.Errorf("invalid recipient")
	}
	b, err := loadBroadcast(id)
	if err != nil {
		return "", err
	}
	if !b.hasRecipient(agent) {
		return "", fmt.Errorf("not a recipient")
	}
	err = updateJSON(receiptPath(id, agent), func(r *BroadcastReceipt) error { r.ReadAt = now(); return nil })
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s [%s] attributed to %s at %s\nRecipients: %s\n%s", b.ID, b.Kind, b.By, b.At, strings.Join(b.Recipients, ", "), b.Body), nil
}
func ReplyBroadcast(id, agent, body string) error {
	if !validComponent(agent) {
		return fmt.Errorf("invalid recipient")
	}
	b, err := loadBroadcast(id)
	if err != nil {
		return err
	}
	if !b.hasRecipient(agent) {
		return fmt.Errorf("not a recipient")
	}
	if strings.TrimSpace(body) == "" || len(body) > 64*1024 {
		return fmt.Errorf("nonempty reply required (limit 64 KiB)")
	}
	return updateJSON(receiptPath(id, agent), func(r *BroadcastReceipt) error {
		r.ReadAt = now()
		r.Replies = append(r.Replies, BroadcastReply{At: now(), Body: body})
		return nil
	})
}
func BroadcastInbox(agent string, all bool) string {
	var lines []string
	for _, b := range ListBroadcastsQuiet() {
		if !b.hasRecipient(agent) {
			continue
		}
		r, err := broadcastReceipt(b.ID, agent)
		if err != nil {
			lines = append(lines, "broadcast receipt unreadable: "+b.ID)
			continue
		}
		due := b.Kind != "announcement" && len(r.Replies) == 0
		if !all && r.ReadAt != "" && !due {
			continue
		}
		state := "unread"
		if r.ReadAt != "" {
			state = "read"
		}
		if due {
			state += "; reply requested"
		}
		lines = append(lines, fmt.Sprintf("BROADCAST %s [%s, %s] attributed to %s: %s", b.ID, b.Kind, state, b.By, firstLine(b.Body)))
	}
	return strings.Join(lines, "\n")
}
func BroadcastNotices(agent string) []string {
	if !validComponent(agent) {
		return nil
	}
	var out []string
	for _, b := range ListBroadcastsQuiet() {
		if !b.hasRecipient(agent) {
			continue
		}
		fresh := false
		err := updateJSON(receiptPath(b.ID, agent), func(r *BroadcastReceipt) error {
			if !r.Notified && r.ReadAt == "" {
				fresh = true
				r.Notified = true
			}
			return nil
		})
		if err == nil && fresh {
			out = append(out, fmt.Sprintf("broadcast %s [%s] from %s; use broadcast_read and respond if requested", b.ID, b.Kind, b.By))
		}
	}
	return out
}
func BroadcastCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("broadcast announcement|regroup|briefing [--to a,b] [--by NAME] < body; broadcast list")
	}
	if args[0] == "list" {
		b, e := ListBroadcasts()
		if e != nil {
			return e
		}
		raw, _ := json.MarshalIndent(b, "", "  ")
		fmt.Println(string(raw))
		return nil
	}
	kind := args[0]
	args = args[1:]
	var to, by string
	args, to = takeFlag(args, "--to", "")
	args, by = takeFlag(args, "--by", os.Getenv("USER"))
	if len(args) > 0 {
		return fmt.Errorf("unknown broadcast arguments")
	}
	if by == "" {
		by = "operator"
	}
	recipients := BroadcastRecipients()
	if to != "" {
		recipients = strings.Split(to, ",")
	}
	b, e := CreateBroadcast(by, kind, stdinBody(), recipients)
	if b != nil {
		fmt.Printf("broadcast %s exists for %s; delivery requires an enabled adapter or inbox read\n", b.ID, strings.Join(b.Recipients, ", "))
		if e != nil {
			fmt.Println("Durability confirmation failed; inspect this ID before retrying.")
		}
	}
	return e
}
