package main

import (
	"fmt"
	"strings"
)

// The map screen: every agent's arc as a transit line, with the station it is at lit up. It is built for a
// glance, so the line comes first, then the one sentence on where the agent is, and the full list of
// stations only for the line in focus.

// A clickable place in the map's flat lines. A hit with station -1 is the agent's block as a whole.
type sbMapHit struct {
	line, x0, x1 int
	agent        string
	station      int
}

const (
	mapMinSlot = 7  // below this a label is unreadable, so the line is drawn upright instead
	mapMaxSlot = 22 // a short line stays a line rather than stretching across a wide screen
)

func stationStyle(status string, p palette) string {
	switch status {
	case stationActive:
		return p.amber
	case stationPassed:
		return p.green
	}
	return p.muted
}

// The one thing on the screen that must not be missed. Reverse video survives any palette, and with no
// colour at all the glyph and the NOW line still say it.
func mapActiveLabel(s string, p palette) string {
	if !p.enabled {
		return terminalText(s)
	}
	return "\033[1m\033[7m" + p.amber + terminalText(s) + sgrReset + p.bg + p.ink
}

func (v *view) roadmapFocus() string {
	for _, r := range v.st.roadmaps {
		if r.Agent == v.mapFocus {
			return r.Agent
		}
	}
	if len(v.st.roadmaps) > 0 {
		return v.st.roadmaps[0].Agent
	}
	return ""
}

func (v *view) mapCycle(step int) {
	n := len(v.st.roadmaps)
	if n == 0 {
		return
	}
	at := 0
	focus := v.roadmapFocus()
	for i, r := range v.st.roadmaps {
		if r.Agent == focus {
			at = i
		}
	}
	v.mapFocus = v.st.roadmaps[(at+step+n)%n].Agent
	v.mapPicked = -1
}

// line and x are in the map's own lines, past the scroll and the pane's margin.
func (v *view) mapClick(line, x int) {
	for _, h := range v.mapHits {
		if h.line == line && x >= h.x0 && x < h.x1 && h.station >= 0 {
			v.mapFocus, v.mapPicked = h.agent, h.station
			return
		}
	}
	for _, h := range v.mapHits {
		if h.line == line && h.station < 0 {
			v.mapFocus, v.mapPicked = h.agent, -1
			return
		}
	}
}

// roadmapOneLine is the side panel's glance at an agent's line, on every other screen.
func (v *view) roadmapOneLine(agent string) string {
	for _, r := range v.st.roadmaps {
		if r.Agent != agent {
			continue
		}
		if s, ok := activeStation(r); ok {
			return "◉ " + terminalText(s.Name) + " · " + terminalText(r.Arc)
		}
		if r.Done {
			return "● finished · " + terminalText(r.Arc)
		}
		return "○ not started · " + terminalText(r.Arc)
	}
	return ""
}

func mapAge(r Roadmap, p palette) (string, string) {
	age := roadmapAge(r)
	text := "updated " + span(age) + " ago"
	switch {
	case age >= roadmapAbandonedTime:
		return text + " · may not be true", p.red
	case age >= roadmapStaleAfter:
		return text + " · getting old", p.amber
	}
	return text, p.muted
}

func (v *view) mapLines(w int, p palette) []string {
	v.mapHits = v.mapHits[:0]
	w = max(20, w)
	if len(v.st.roadmaps) == 0 {
		return []string{
			"",
			p.text(p.cyan, "No lines on the map yet."),
			"",
			p.text(p.muted, "An agent posts its arc with roadmap_post, or yip roadmap post, and moves its marker with roadmap_at."),
		}
	}
	focus := v.roadmapFocus()
	var out []string
	var focused *Roadmap
	for i := range v.st.roadmaps {
		r := v.st.roadmaps[i]
		if r.Agent == focus {
			focused = &v.st.roadmaps[i]
		}
		out = append(out, v.mapBlock(r, w, p, len(out), r.Agent == focus)...)
		out = append(out, "")
	}
	if focused != nil {
		out = append(out, v.mapLegend(*focused, w, p, len(out))...)
	}
	return out
}

func atMostTwoLines(ls []string, w int) []string {
	if len(ls) <= 2 {
		return ls
	}
	return []string{ls[0], fitCells(strings.TrimRight(ls[1], " "), max(1, w-1), false) + "…"}
}

func (v *view) mapBlock(r Roadmap, w int, p palette, base int, focused bool) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	hit := func(x0, x1, station int) {
		v.mapHits = append(v.mapHits, sbMapHit{line: base + len(out), x0: x0, x1: x1, agent: r.Agent, station: station})
	}
	shown := compactRoadmap(r, roadmapShownMax)

	mark := "  "
	if focused {
		mark = "▸ "
	}
	age, ageStyle := mapAge(r, p)
	left := mark + r.Agent + "  " + r.Arc
	room := max(1, w-plainWidth(age)-1)
	hit(0, w, -1)
	add(fitCells(p.text(p.cyan, trunc(terminalText(left), room)), room, true) + " " + p.text(ageStyle, age))
	if r.Description != "" {
		for _, l := range atMostTwoLines(wrap(r.Description, max(8, w-2)), max(8, w-2)) {
			hit(0, w, -1)
			add("  " + p.text(p.muted, l))
		}
	}

	var mains []int
	for i, s := range shown {
		if s.Detour == "" {
			mains = append(mains, i)
		}
	}
	slot := 0
	if len(mains) > 0 {
		slot = min(mapMaxSlot, (w-2)/len(mains))
	}
	pulse := motionEnabled() && v.frame%2 == 1
	if slot < mapMinSlot {
		for i, s := range shown {
			indent := "  "
			if s.Detour != "" {
				indent = "    ┗ "
			}
			name := p.text(stationStyle(s.Status, p), s.Name)
			if s.Status == stationActive {
				name = mapActiveLabel(s.Name, p)
			}
			hit(0, w, i)
			add(indent + p.text(stationStyle(s.Status, p), stationGlyph(s.Status, s.Folded > 0, pulse)) + " " + name)
		}
	} else {
		// The rail. A stretch is solid once it has been travelled.
		var rail strings.Builder
		rail.WriteString("  ")
		for k, i := range mains {
			s := shown[i]
			rail.WriteString(p.text(stationStyle(s.Status, p), stationGlyph(s.Status, s.Folded > 0, pulse)))
			if k == len(mains)-1 {
				break
			}
			next := shown[mains[k+1]]
			if next.Status == stationPassed || next.Status == stationActive {
				rail.WriteString(p.text(p.green, strings.Repeat("━", slot-1)))
			} else {
				rail.WriteString(p.text(p.line, strings.Repeat("┄", slot-1)))
			}
		}
		for k, i := range mains {
			hit(2+k*slot, 2+(k+1)*slot, i)
		}
		add(rail.String())

		// The names, in up to two rows under their stations.
		rows := [2][]string{}
		for _, i := range mains {
			ls := wrap(shown[i].Name, slot-1)
			a, b := "", ""
			if len(ls) > 0 {
				a = ls[0]
			}
			if len(ls) > 1 {
				b = ls[1]
			}
			if len(ls) > 2 {
				b = trunc(b+"…", slot-1)
			}
			rows[0], rows[1] = append(rows[0], strings.TrimRight(a, " ")), append(rows[1], strings.TrimRight(b, " "))
		}
		for row := 0; row < 2; row++ {
			any := false
			var b strings.Builder
			b.WriteString("  ")
			for k, i := range mains {
				text := rows[row][k]
				any = any || text != ""
				styled := p.text(stationStyle(shown[i].Status, p), text)
				if shown[i].Status == stationActive && text != "" {
					styled = mapActiveLabel(text, p)
				}
				if shown[i].Status == stationPassed && text != "" {
					styled = p.text(p.ink, text)
				}
				b.WriteString(fitCells(styled, slot, true))
			}
			if any {
				for k, i := range mains {
					hit(2+k*slot, 2+(k+1)*slot, i)
				}
				add(b.String())
			}
		}

		// Each detour hangs from its station, as far along the line as that station is.
		for k, i := range mains {
			var line strings.Builder
			x := 2 + k*slot
			line.WriteString(strings.Repeat(" ", x))
			line.WriteString(p.text(p.violet, "┗━"))
			x += 2
			any := false
			for j := i + 1; j < len(shown) && shown[j].Detour != ""; j++ {
				s := shown[j]
				name := terminalText(s.Name)
				label := p.text(stationStyle(s.Status, p), stationGlyph(s.Status, s.Folded > 0, pulse)) + " "
				if s.Status == stationActive {
					label += mapActiveLabel(name, p)
				} else {
					label += p.text(stationStyle(s.Status, p), name)
				}
				line.WriteString(" " + label + " " + p.text(p.violet, "━"))
				width := 1 + 2 + plainWidth(name) + 2
				hit(x, x+width, j)
				x += width
				any = true
			}
			if any {
				line.WriteString(p.text(p.violet, "┛"))
				add(fitCells(line.String(), w, false))
			}
		}
	}

	// Where the agent is, in words.
	now, nowStyle := "NOT STARTED", p.muted
	text := ""
	if s, ok := activeStation(r); ok {
		now, nowStyle = "NOW", p.amber
		text = s.Name
		if s.Description != "" {
			text += ": " + s.Description
		}
	}
	if r.Done {
		now, nowStyle = "FINISHED", p.green
	}
	if r.Note != "" {
		if text != "" {
			text += " -- "
		}
		text += r.Note
	}
	ls := atMostTwoLines(wrap(text, max(8, w-len(now)-4)), max(8, w-len(now)-4))
	if len(ls) == 0 {
		ls = []string{""}
	}
	for i, l := range ls {
		head := strings.Repeat(" ", len(now))
		if i == 0 {
			head = now
		}
		hit(0, w, -1)
		add("  " + p.text(nowStyle, head) + "  " + p.text(p.ink, l))
	}
	return out
}

// The stations of the line in focus, each with its description. Unfolded where the map folded is not
// wanted: the list matches the drawn line, and a fold names what it holds.
func (v *view) mapLegend(r Roadmap, w int, p palette, base int) []string {
	var out []string
	head := fmt.Sprintf("STATIONS · %s · %s", r.Agent, r.Arc)
	out = append(out, p.text(p.violet, trunc(terminalText(head), w)))
	shown := compactRoadmap(r, roadmapShownMax)
	for i, s := range shown {
		indent := "  "
		if s.Detour != "" {
			indent = "    ┗ "
		}
		style := stationStyle(s.Status, p)
		name := p.text(style, s.Name)
		if s.Status == stationActive {
			name = mapActiveLabel(s.Name, p)
		}
		picked := v.mapPicked == i && v.mapFocus == r.Agent
		lead := indent + p.text(style, stationGlyph(s.Status, s.Folded > 0, false)) + " "
		if picked {
			lead = "▸" + lead[1:]
		}
		v.mapHits = append(v.mapHits, sbMapHit{line: base + len(out), x0: 0, x1: w, agent: r.Agent, station: i})
		out = append(out, lead+name)
		if s.Description != "" {
			text := p.muted
			if picked {
				text = p.ink
			}
			for _, l := range wrap(s.Description, max(8, w-plainWidth(indent)-2)) {
				v.mapHits = append(v.mapHits, sbMapHit{line: base + len(out), x0: 0, x1: w, agent: r.Agent, station: i})
				out = append(out, strings.Repeat(" ", plainWidth(indent)+2)+p.text(text, l))
			}
		}
	}
	return out
}
