package main

import (
	"fmt"
	"sort"
	"strings"
)

type broadcastDraft struct {
	Kind       string
	Recipients []string
	Body       string
	Stage      string
}

func (v *view) startBroadcast() {
	v.broadcastComposing = true
	if v.broadcast == nil {
		v.broadcast = &broadcastDraft{Kind: "announcement", Recipients: BroadcastRecipients()}
	}
	v.tab = 3
	v.scroll = 0
	v.follow = false
	v.broadcast.Stage = "recipients"
	v.prompt = "broadcast recipients (comma separated)>"
	v.input = []rune(strings.Join(v.broadcast.Recipients, ","))
}
func (v *view) submitBroadcast(text string) {
	d := v.broadcast
	if d == nil {
		return
	}
	switch d.Stage {
	case "recipients":
		names := strings.Split(text, ",")
		known := LoadMembers().Names()
		seen := map[string]bool{}
		var recipients []string
		for _, name := range names {
			name = strings.TrimSpace(name)
			found := false
			for _, k := range known {
				if k == name {
					found = true
				}
			}
			if !found || !validComponent(name) {
				v.flash = "unknown recipient: " + name
				return
			}
			if !seen[name] {
				recipients = append(recipients, name)
				seen[name] = true
			}
		}
		d.Recipients = recipients
		d.Stage = "kind"
		v.prompt = "kind: announcement, regroup, briefing>"
		v.input = []rune(d.Kind)
	case "kind":
		if text != "announcement" && text != "regroup" && text != "briefing" {
			v.flash = "choose announcement, regroup or briefing"
			return
		}
		d.Kind = text
		d.Stage = "body"
		v.prompt = "broadcast text>"
		v.input = []rune(d.Body)
	case "body":
		if text == "" {
			v.flash = "body required"
			return
		}
		d.Body = text
		d.Stage = "confirm"
		v.prompt = "review (arrows scroll); type SEND (Esc keeps draft)>"
		v.input = nil
		v.scroll = 0
	case "confirm":
		if text != "SEND" {
			v.flash = "not sent; type SEND or Esc to keep draft"
			return
		}
		b, err := CreateBroadcast(v.by, d.Kind, d.Body, d.Recipients)
		if err != nil {
			if b != nil {
				v.flash = "broadcast " + b.ID + " exists; durability uncertain, inspect before retry"
				v.prompt = ""
				v.input = nil
				v.broadcast = nil
				v.broadcastComposing = false
				return
			}
			v.flash = "broadcast FAILED: " + err.Error()
			return
		}
		v.flash = "recorded broadcast " + b.ID + "; see individual delivery and replies"
		v.prompt = ""
		v.input = nil
		v.broadcast = nil
		v.broadcastComposing = false
	}
}

// Receipts summarize each recipient separately; a read does not imply a reply.
func broadcastProgress(b *Broadcast) string {
	read, replied := 0, 0
	for _, a := range b.Recipients {
		r, err := broadcastReceipt(b.ID, a)
		if err == nil && r.ReadAt != "" {
			read++
		}
		if err == nil && len(r.Replies) > 0 {
			replied++
		}
	}
	if b.Kind == "announcement" {
		return fmt.Sprintf("%d/%d read", read, len(b.Recipients))
	}
	return fmt.Sprintf("%d/%d read · %d replied", read, len(b.Recipients), replied)
}

func broadcastTranscript(b *Broadcast, w int, p palette) []string {
	out := []string{p.text(p.violet, "● "+b.By) + p.text(p.muted, "   "+shortTime(b.At)+"  BROADCAST / "+strings.ToUpper(b.Kind)), p.text(p.muted, "#"+b.ID)}
	body := func(text string) {
		for _, l := range wrap(terminalText(text), max(8, w-2)) {
			out = append(out, p.text(p.line, "│ ")+l)
		}
	}
	label := func(style, text string) {
		for _, l := range wrap(terminalText(text), max(8, w)) {
			out = append(out, p.text(style, l))
		}
	}
	body(b.Body)
	out = append(out, "")
	label(p.violet, "RECIPIENTS · "+broadcastProgress(b))
	for _, a := range b.Recipients {
		r, err := broadcastReceipt(b.ID, a)
		state, color := "unread", p.amber
		if r.ReadAt != "" {
			state, color = "read", p.green
		}
		if b.Kind != "announcement" && len(r.Replies) == 0 {
			state += "; response pending"
			color = p.amber
		}
		if err != nil {
			state, color = "receipt unreadable", p.red
		}
		label(color, "● "+a+" · "+state)
		delivery := EndpointStatus(a)
		if ep, e := readEndpoint(a); e == nil {
			for _, d := range ep.Events {
				if d.Source == "broadcast:"+b.ID {
					delivery += "; " + d.Status
				}
			}
		}
		label(p.muted, "  "+delivery)
	}
	out = append(out, "")
	var replies []sbEntry
	for _, a := range b.Recipients {
		r, err := broadcastReceipt(b.ID, a)
		if err != nil {
			continue
		}
		for _, reply := range r.Replies {
			replies = append(replies, sbEntry{from: a, at: reply.At, body: reply.Body})
		}
	}
	sort.SliceStable(replies, func(i, j int) bool { return replies[i].at < replies[j].at })
	for _, reply := range replies {
		out = append(out, p.text(p.cyan, "● "+reply.from)+p.text(p.muted, "   "+shortTime(reply.at)+"  REPLY"))
		body(reply.body)
		out = append(out, "")
	}
	return out
}

func (v *view) broadcastLines(w int, p palette) []string {
	var out []string
	add := func(style, s string) {
		for _, l := range wrap(terminalText(s), max(8, w)) {
			out = append(out, p.text(style, l))
		}
	}
	if v.broadcast != nil {
		d := v.broadcast
		add(p.violet, "DRAFT / "+d.Kind+" / attributed to "+v.by)
		add(p.muted, "Recipients are fixed at send. Enabled dispatchers may wake them; inbox remains available.")
		for _, a := range d.Recipients {
			add(p.amber, a+": "+EndpointStatus(a))
		}
		add(p.ink, d.Body)
		add(p.muted, "No resource transfer or worker cancellation. Attribution is not verified approval.")
		add("", "")
	}
	add(p.violet, "BROADCASTS / b compose or resume draft")
	bs, err := ListBroadcasts()
	if err != nil {
		add(p.red, err.Error())
		return out
	}
	for i := len(bs) - 1; i >= 0; i-- {
		out = append(out, "")
		out = append(out, broadcastTranscript(&bs[i], w, p)...)
	}
	return out
}
