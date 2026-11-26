package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
)

const sbRelayKeys = "1 chat · 2 relay · 3 calls · 5 topology · n/p select · j/k scroll · q quit"

type sbRelay struct {
	ldrclient.CallObservation
	endpoints []string
}

func loadRelayBoard(ctx context.Context, att LDRAttachment, selected string, previous sbState) sbState {
	// An attachment can be removed or replaced while the terminal is open.
	current, ok, err := loadLDRAttachment()
	if err != nil {
		return sbState{relay: &sbRelay{}, err: err.Error()}
	}
	if !ok || current.ClientDir != att.ClientDir {
		return sbState{relay: &sbRelay{}, err: "Line attachment changed. Reopen Switchboard."}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	snapshot, err := ldrclient.ObserveCalls(ctx, att.ClientDir, selected, &previous.relay.CallObservation)
	if err != nil {
		if previous.relay.VerifiedAt.IsZero() || (snapshot.Status.LineID != "" &&
			(snapshot.Status.LineID != previous.relay.Status.LineID || snapshot.Status.CredID != previous.relay.Status.CredID)) {
			previous = sbState{relay: &sbRelay{CallObservation: snapshot}}
		}
		previous.err = err.Error()
		return previous
	}

	r := &sbRelay{CallObservation: snapshot}
	for _, local := range LineNames() {
		ep, err := readEndpoint(local)
		r.endpoints = append(r.endpoints, current.actorFor(local)+" · "+endpointStatusFrom(local, ep, err))
	}
	st := sbState{relay: r}
	for _, summary := range snapshot.Calls {
		sc := &sbCall{
			call:  &Call{ID: summary.ID, Subject: summary.Subject, From: summary.From, To: summary.To, Opened: fmtMS(summary.OpenedMS)},
			floor: summary.Floor, status: summary.Status, closed: summary.Status == "resolved",
			lastAt: fmtMS(summary.LastTimeMS),
		}
		if tr := snapshot.Transcript; tr != nil && tr.ID == summary.ID {
			sc.entries = relayBoardEntries(tr)
		}
		st.calls = append(st.calls, sc)
	}
	return st
}

func relayBoardEntries(tr *ldrclient.CallTranscript) []sbEntry {
	// Relay sequences also order entries recorded within the same millisecond.
	type item struct {
		seq   uint64
		entry sbEntry
	}
	var items []item
	add := func(seq, ms uint64, kind, from, body string, n int) {
		items = append(items, item{seq, sbEntry{kind, from, fmtMS(ms), body, n}})
	}
	for _, t := range tr.Turns {
		kind := "TURN"
		if t.Barge {
			kind = "BARGE"
		}
		add(t.Seq, t.SeqTimeMS, kind, t.From, t.Body, t.Number)
	}
	for _, n := range tr.Notes {
		kind := "NOTE"
		if n.Kind == "human" {
			kind = "HUMAN"
		}
		add(n.Seq, n.SeqTimeMS, kind, n.From, n.Body, n.Number)
	}
	for _, e := range tr.Events {
		add(e.Seq, e.SeqTimeMS, "STATE", e.By, strings.TrimSpace(e.State+" "+e.Reason), int(e.Seq))
	}
	for _, a := range tr.Attachments {
		label := a.Name
		if label == "" {
			label = a.ReadStatus
		}
		add(a.Seq, a.SeqTimeMS, "ATTACHMENT", a.From, label, int(a.Seq))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	entries := make([]sbEntry, 0, len(items))
	for _, it := range items {
		entries = append(entries, it.entry)
	}
	return entries
}

func (v *view) relayDashboard(w int, p palette) []string {
	r := v.st.relay
	out := []string{p.text(p.cyan, "RELAY STATUS")}
	add := func(s string) { out = append(out, wrap(terminalText(s), w)...) }
	if r.Origin.URL != "" {
		add(r.Origin.URL)
		add(r.Origin.SessionBinding)
	}
	if v.st.err != "" {
		add("Refresh failed")
		add(v.st.err)
	}
	if r.VerifiedAt.IsZero() {
		if v.st.err == "" {
			add("Connecting…")
		}
		return out
	}
	add("Last verified " + r.VerifiedAt.Local().Format("15:04:05 MST"))
	add(fmt.Sprintf("Checkpoint %d · epoch %d", r.Status.CheckpointSeq, r.Status.KeyEpoch))
	add("Line " + r.Status.LineID)
	if len(r.endpoints) > 0 {
		out = append(out, "", p.text(p.cyan, "LOCAL DELIVERY"))
		for _, e := range r.endpoints {
			add(e)
		}
	}
	return out
}

func (v *view) relayTopology() []string {
	r := v.st.relay
	if r.VerifiedAt.IsZero() {
		return []string{"Awaiting verified line state"}
	}
	out := []string{terminalText(r.Origin.URL), "└─ Line " + r.Status.LineID}
	sc := v.selectedCall()
	for i, cred := range r.Credentials {
		branch, indent := "├─ ", "│  "
		if i == len(r.Credentials)-1 {
			branch, indent = "└─ ", "   "
		}
		label := fmt.Sprintf("%s · %s", cred.Namespace, cred.ID[:min(12, len(cred.ID))])
		if cred.ID == r.Status.CredID {
			label += " · this client"
		}
		if cred.Revoked {
			label += " · revoked"
		}
		out = append(out, terminalText("   "+branch+label))
		var actors []string
		for _, a := range r.Actors {
			if a.Cred != cred.ID {
				continue
			}
			name := a.ID
			if !a.Live {
				name += " · retired"
			}
			if sc != nil && (a.ID == sc.call.From || a.ID == sc.call.To) {
				name += " · selected call"
			}
			actors = append(actors, name)
		}
		for j, name := range actors {
			twig := "├─ "
			if j == len(actors)-1 {
				twig = "└─ "
			}
			out = append(out, terminalText("   "+indent+twig+name))
		}
	}
	return out
}
