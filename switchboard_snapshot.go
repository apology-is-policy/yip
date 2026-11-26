package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrrelay"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type switchboardSnapshot struct {
	Lines                                      []string
	Line                                       string
	Error                                      string
	TranscriptID                               string
	Transcript                                 string
	Calls                                      []switchboardCall
	Overview                                   []string
	Topology                                   []string
	Health, Broadcasts, Roadmaps               []string
	HealthInks, BroadcastInks, RoadmapInks     string
	TranscriptInks, OverviewInks, TopologyInks string
}

type switchboardCall struct {
	ID, Subject, Status, Floor, Participants, Route, Progress string
}

func serveSwitchboardSnapshots(ctx context.Context, in io.Reader, out io.Writer) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	loader := &sbLoader{}
	state := sbState{}
	var lastDir string
	requests, responses := json.NewDecoder(in), json.NewEncoder(out)
	for {
		var raw json.RawMessage
		var req struct {
			Selected string
			ldrclient.ObservationViews
			Health bool
		}
		if err := requests.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(raw) > 0 && raw[0] == '"' {
			if err := json.Unmarshal(raw, &req.Selected); err != nil {
				return err
			}
		} else if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		selected := req.Selected
		att, remote, err := loadLDRAttachment()
		if err != nil {
			state = sbState{}
			lastDir = ""
			if err := responses.Encode(switchboardSnapshot{Line: activeLine, Error: err.Error()}); err != nil {
				return err
			}
			continue
		}
		if att.ClientDir != lastDir {
			state = sbState{}
			loader = &sbLoader{}
			lastDir = att.ClientDir
		}
		if remote {
			if state.relay == nil {
				state.relay = &sbRelay{}
			}
			state = loadRelayViews(ctx, att, selected, state, req.ObservationViews)
		} else {
			state = loader.load()
		}
		snap := makeSwitchboardSnapshot(state, selected, req.ObservationViews)
		snap.Lines = []string{activeLine}
		if os.Getenv("YIP_ROOT") == "" {
			entries, _ := os.ReadDir(filepath.Join(yipHome(), "lines"))
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != activeLine {
					snap.Lines = append(snap.Lines, entry.Name())
				}
			}
			slices.Sort(snap.Lines)
		}

		if socket := os.Getenv("YIP_RELAY_ADMIN_SOCKET"); req.Health && socket != "" {
			probe, stop := context.WithTimeout(ctx, 2*time.Second)
			admin, e := ldrrelay.ReadAdminStatus(probe, socket)
			stop()
			snap.Health = append(snap.Health, "", "Relay host · local admin socket")
			if e != nil {
				snap.Health = append(snap.Health, e.Error())
				snap.HealthInks += strings.Repeat(" ", len(snap.Health)-1-len(snap.HealthInks)) + "r"
			} else if st := admin.Admission; st != nil {
				snap.Health = append(snap.Health, fmt.Sprintf("Active tunnels %d · authenticating %d", st.Tunnels, st.Handshakes), fmt.Sprintf("Pending challenges %d · sessions %d", st.Pending, st.Sessions), fmt.Sprintf("Overload rejections %d", st.Overload))
			} else {
				snap.Health = append(snap.Health, "Admission counters unavailable")
			}
			if admin != nil {
				for _, line := range admin.Lines {
					state := "Clock trusted"
					if !line.Clock.Trusted {
						state = "Clock uncertain · " + line.Clock.UncertainReason
					}
					if line.Quarantined {
						state += " · Quarantined: " + line.QuarantineReason
					}
					snap.Health = append(snap.Health, fmt.Sprintf("Line %s · seq %d · %s", line.LineID, line.HeadSeq, state))
				}
			}
		}
		if err := responses.Encode(snap); err != nil {
			return err
		}
	}
}

func makeSwitchboardSnapshot(state sbState, selected string, views ldrclient.ObservationViews) switchboardSnapshot {
	snapshot := switchboardSnapshot{Line: activeLine, Error: state.err}
	view := &view{st: state}
	route := "Local call"
	if state.relay != nil {
		route = "Long-distance call"
	}
	for i, call := range state.calls {
		participants := call.call.From + " ⇄ " + call.call.To
		kind := route
		floor := call.floor
		if call.closed || call.status == "resolved" || call.status == "archived" {
			floor = ""
		}
		if call.broadcast != nil {
			participants = fmt.Sprintf("%s → %d recipients", call.broadcast.By, len(call.broadcast.Recipients))
			kind = "Broadcast · " + call.broadcast.Kind
		}
		snapshot.Calls = append(snapshot.Calls, switchboardCall{
			ID: call.call.ID, Subject: terminalText(call.call.Subject), Status: call.status, Floor: floor, Participants: participants, Route: kind, Progress: call.progress(),
		})
		if call.call.ID == selected {
			view.sel = i
		}
	}
	p := switchboardPalette()
	if call := view.selectedConversation(); call != nil {
		var transcript, inks strings.Builder
		if call.broadcast != nil {
			rows, tones := snapshotLines(broadcastTranscript(call, 160, p), p)
			transcript.WriteString(strings.Join(rows, "\n"))
			inks.WriteString(tones)
		} else {
			for _, entry := range call.entries {
				header := terminalText(entry.from + " · " + entry.kind)
				if entry.n > 0 {
					header += fmt.Sprintf(" #%d", entry.n)
				}
				if stamp := strings.TrimSpace(shortTime(entry.at)); stamp != "" {
					header += " · " + stamp
				}
				ink := byte('b')
				switch {
				case entry.kind == "BARGE":
					ink = 'r'
				case entry.kind == "HUMAN" || entry.kind == "STATE":
					ink = 'y'
				case entry.kind == "TURN" && entry.from == call.call.To:
					ink = 'g'
				}
				body := terminalText(entry.body)
				transcript.WriteString(header + "\n" + body)
				inks.WriteByte(ink)
				inks.WriteString(strings.Repeat(" ", strings.Count(body, "\n")+2))
				transcript.WriteString("\n\n")
			}
		}
		snapshot.TranscriptInks = inks.String()
		snapshot.TranscriptID = call.call.ID
		snapshot.Transcript = strings.TrimRight(transcript.String(), "\n")
	}
	snapshot.Overview, snapshot.OverviewInks = snapshotLines(view.dashboard(33, p), p)
	if state.relay == nil {
		snapshot.Topology = []string{"Local line · " + activeLine}
		for i, member := range state.members {
			branch := "├─ "
			if i == len(state.members)-1 {
				branch = "└─ "
			}
			snapshot.Topology = append(snapshot.Topology, branch+member)
		}
		snapshot.Health = []string{"Local line · " + activeLine, "No relay attachment"}
		if views.Broadcasts {
			for _, call := range state.calls {
				if call.broadcast != nil {
					rows, inks := snapshotLines(broadcastTranscript(call, 65, p), p)
					snapshot.Broadcasts = append(snapshot.Broadcasts, rows...)
					snapshot.BroadcastInks += inks
				}
			}
		}
		if views.Roadmaps {
			snapshot.Roadmaps, snapshot.RoadmapInks = snapshotLines(view.mapLines(65, p), p)
		}
	} else {
		snapshot.Topology, snapshot.TopologyInks = snapshotLines(view.relayTopology(p), p)
		r := state.relay
		snapshot.Health, snapshot.HealthInks = snapshotLines(view.relayDashboard(65, p), p)
		stage := r.Stage
		if stage != "" {
			snapshot.Health = append([]string{stage}, snapshot.Health...)
			shade := "g"
			if state.err != "" {
				shade = "r"
			}
			snapshot.HealthInks = shade + snapshot.HealthInks
		}
		for _, b := range r.Broadcasts {
			snapshot.Broadcasts = append(snapshot.Broadcasts, b.Kind+" · "+b.By+" · "+b.ID, b.Body, "Recipients: "+strings.Join(b.Recipients, ", "))
			for _, rep := range b.Replies {
				snapshot.Broadcasts = append(snapshot.Broadcasts, rep.From+" · "+rep.Body)
			}
		}
		if views.Roadmaps {
			snapshot.Roadmaps = strings.Split(formatLDRRoadmaps(r.Roadmaps, ""), "\n")
		}
		if r.BroadcastError != "" {
			snapshot.Broadcasts = append(snapshot.Broadcasts, r.BroadcastError)
		}
		if r.RoadmapError != "" {
			snapshot.Roadmaps = append(snapshot.Roadmaps, r.RoadmapError)
		}
	}

	return snapshot
}

// Preserve the status renderer’s semantic accents while sending only plain text over the stream.
// Each byte describes one logical row; ordinary text uses the default foreground.
func snapshotLines(rows []string, p palette) ([]string, string) {
	var inks strings.Builder
	for i, row := range rows {
		ink := byte(' ')
		switch {
		case strings.Contains(row, p.red):
			ink = 'r'
		case strings.Contains(row, p.amber):
			ink = 'y'
		case strings.Contains(row, p.green):
			ink = 'g'
		case strings.Contains(row, p.cyan), strings.Contains(row, p.violet):
			ink = 'b'
		}
		inks.WriteByte(ink)
		rows[i] = terminalText(row)
	}
	return rows, inks.String()
}
