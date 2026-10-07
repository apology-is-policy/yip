package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type palette struct {
	bg, ink, muted, line, cyan, green, amber, red, violet, selected string
	enabled                                                         bool
}

func colors() palette {
	if _, ok := os.LookupEnv("NO_COLOR"); ok || os.Getenv("TERM") == "dumb" {
		return palette{}
	}
	return palette{bg: "\033[48;5;234m", ink: "\033[38;5;255m", muted: "\033[38;5;248m", line: "\033[38;5;239m", cyan: "\033[38;5;117m", green: "\033[38;5;114m", amber: "\033[38;5;222m", red: "\033[38;5;210m", violet: "\033[38;5;183m", selected: "\033[48;5;237m", enabled: true}
}
func (p palette) text(style, s string) string {
	return style + strings.ReplaceAll(terminalText(s), "\n", " ") + sgrReset + p.bg + p.ink
}
func (p palette) tag(style, s string) string { return p.text(style, " "+s+" ") }
func motionEnabled() bool                    { return colors().enabled && os.Getenv("YIP_REDUCED_MOTION") == "" }
func (v *view) activityGlyph() string {
	if !motionEnabled() {
		return "●"
	}
	return []string{"●", "◉", "●", "·"}[v.frame%4]
}
func (v *view) frameLines(rows, cols int) []string {
	if rows < 1 || cols < 1 {
		return nil
	}
	p := colors()
	v.panes = paneLayout(rows, cols)
	var out []string
	put := func(s string) {
		if len(out) < rows {
			out = append(out, p.bg+p.ink+fitCells(s, cols, true)+sgrReset)
		}
	}
	if cols < 40 || rows < 10 {
		put(p.text(p.cyan, "YIP / SWITCHBOARD"))
		put("Terminal too small for the live panels.")
		put("Resize to at least 40 × 10. q exits.")
		for len(out) < rows {
			put("")
		}
		return out
	}
	open, stale := 0, 0
	for _, c := range v.st.calls {
		if c.status == "open" {
			open++
		} else if c.status == "stale" {
			stale++
		}
	}
	name := activeLine
	if name == "" {
		name = "local line"
	}
	header := p.text(p.cyan, "  ╭─ YIP ") + p.text(p.ink, "/ SWITCHBOARD")
	right := fmt.Sprintf("%s  %d active · %d stale  ", name, open, stale)
	put(fitCells(header, max(1, cols-plainWidth(right)), true) + p.text(p.muted, right))
	put(p.text(p.line, "  ╰"+strings.Repeat("─", max(0, cols-5))) + p.text(p.cyan, "╮"))
	sc := v.selectedCall()
	title := "No conversations yet"
	detail := "Calls will appear here as the line becomes active."
	if sc != nil {
		title = sc.call.Subject
		detail = fmt.Sprintf("%s  ⇄  %s    %s    #%s", sc.call.From, sc.call.To, strings.ToUpper(sc.status), strings.SplitN(sc.call.ID, "-", 2)[0])
	}
	put("  " + p.text(p.ink, title))
	put("  " + p.text(p.muted, detail))
	put("")
	bodyH := v.panes.height
	railW, sideW, centerW := v.panes.railW, v.panes.sideW, v.panes.centerW
	transcript := v.styledTranscript(max(8, centerW-4), p)
	if v.tab == 1 {
		transcript = v.dashboard(centerW-4, p)
	}
	if v.tab == 2 {
		transcript = v.callRail(centerW-4, p)
	}
	if v.follow && v.tab == 0 {
		v.scroll = max(0, len(transcript)-bodyH+1)
	}
	v.scroll = min(max(0, v.scroll), max(0, len(transcript)-bodyH))
	side := v.dashboard(sideW-2, p)
	rail := v.callRail(railW-2, p)
	v.panes.centerLen, v.panes.sideLen = len(transcript), len(side)
	v.panes.railLen = 2 + 3*len(v.st.calls)
	v.railScroll = min(max(0, v.railScroll), max(0, v.panes.railLen-bodyH))
	v.sideScroll = min(max(0, v.sideScroll), max(0, len(side)-bodyH))
	centerScroll := v.scroll
	if v.tab == 2 {
		centerScroll = v.railScroll
	}
	for i := 0; i < bodyH; i++ {
		l := ""
		if i+centerScroll < len(transcript) {
			l = transcript[i+centerScroll]
		}
		line := ""
		if railW > 0 {
			r := ""
			if i+v.railScroll < len(rail) {
				r = rail[i+v.railScroll]
			}
			line = fitCells(r, railW, true) + p.text(p.line, "│ ")
		}
		line += fitCells("  "+l, centerW, true)
		if sideW > 0 {
			r := ""
			if i+v.sideScroll < len(side) {
				r = side[i+v.sideScroll]
			}
			line += p.text(p.line, "│ ") + fitCells(r, sideW, true)
		}
		put(line)
	}
	put(p.text(p.line, "  "+strings.Repeat("─", max(0, cols-4))))
	if v.prompt != "" {
		prompt := trunc(terminalText(v.prompt), max(8, cols/2))
		typed := tailCells(terminalText(string(v.input)), max(1, cols-plainWidth(prompt)-5))
		put("  " + p.text(p.violet, prompt) + " " + typed + p.text(p.cyan, "▏"))
	} else {
		help := "  click call · wheel over pane · tab/n next · p prev · j/k scroll · f follow · 1 chat 2 desk 3 calls · r ratify · a arbitrate · q quit"
		if cols < 125 {
			help = "  1 chat 2 desk 3 calls · r ratify · a arbitrate · ? help · q quit"
		}
		if v.flash != "" {
			help = "  " + v.flash
		}
		put(p.text(p.muted, help))
	}
	for len(out) < rows {
		put("")
	}
	return out
}
func (v *view) styledTranscript(w int, p palette) []string {
	sc := v.selectedCall()
	if sc == nil {
		return []string{"", p.text(p.cyan, "A quiet line."), "", p.text(p.muted, "Open a call to begin a conversation.")}
	}
	var out []string
	for _, e := range sc.entries {
		color := p.cyan
		switch e.kind {
		case "NOTE":
			color = p.muted
		case "HUMAN":
			color = p.violet
		case "BARGE":
			color = p.red
		case "STATE":
			color = p.amber
		}
		out = append(out, p.text(color, "● "+e.from)+p.text(p.muted, fmt.Sprintf("   %s  %s #%d", shortTime(e.at), e.kind, e.n)))
		for _, l := range wrap(terminalText(e.body), max(8, w-2)) {
			out = append(out, p.text(p.line, "│ ")+l)
		}
		out = append(out, "")
	}
	if len(out) == 0 {
		out = []string{p.text(p.muted, "No messages yet.")}
	}
	return out
}
func (v *view) callRail(w int, p palette) []string {
	if w < 1 {
		return nil
	}
	out := []string{p.text(p.muted, "CONVERSATIONS"), ""}
	for i := range v.st.calls {
		c := v.st.calls[i]
		marker := "○"
		color := p.muted
		if c.status == "open" {
			marker = "●"
			color = p.cyan
		}
		if c.status == "stale" {
			color = p.amber
		}
		bg := ""
		if i == v.sel {
			bg = p.selected
			marker = "▸"
		}
		floor := "  → floor: " + c.floor
		if c.closed || c.status == "resolved" || c.status == "archived" {
			floor = "  — " + c.status
		} else if c.floor == "" {
			floor = "  — no floor"
		}
		out = append(out, p.text(bg+color, fitCells(marker+" "+c.call.From+" / "+c.call.To, w, true)), p.text(bg+p.ink, fitCells("  "+trunc(terminalText(c.call.Subject), max(4, w-2)), w, true)), p.text(bg+p.amber, fitCells(terminalText(floor), w, true)))
	}
	return out
}
func (v *view) dashboard(w int, p palette) []string {
	if w < 8 {
		return nil
	}
	out := []string{}
	if sc := v.selectedCall(); sc != nil && len(sc.disputes) > 0 {
		out = append(out, p.text(p.violet, "DECISIONS · a arbitrate"))
		out = append(out, v.disputeLines(w)...)
		out = append(out, "")
	}
	out = append(out, p.text(p.muted, "SHARED MACHINES"), "")
	for _, r := range v.st.resources {
		l := r.lease
		color, label := p.green, "AVAILABLE"
		if r.held {
			color, label = p.amber, "HELD · "+l.Holder
		}
		if r.held && l.Expired() {
			color, label = p.red, "EXPIRED · "+l.Holder
		}
		out = append(out, p.text(color, "◆ "+strings.ToUpper(r.name)+"  "+label))
		if r.held {
			out = append(out, p.text(p.muted, "  "+span(l.Remaining())+" remaining"))
			ratio := 1.0 - float64(l.Remaining())/float64(time.Duration(l.TTLSecs)*time.Second)
			if ratio < 0 {
				ratio = 0
			}
			if ratio > 1 {
				ratio = 1
			}
			n := max(4, w-3)
			filled := int(float64(n) * ratio)
			out = append(out, "  "+p.text(color, strings.Repeat("━", filled))+p.text(p.line, strings.Repeat("─", n-filled)))
			why := l.Phase
			if why == "" {
				why = l.Reason
			}
			ls := wrap(terminalText(why), w-3)
			if len(ls) > 3 {
				ls = append(ls[:2], trunc(ls[2], w-4)+"…")
			}
			for _, line := range ls {
				out = append(out, "  "+p.text(p.muted, line))
			}
			for _, s := range r.runners {
				out = append(out, "  "+p.text(p.muted, s))
			}
		}
		for i, q := range r.queue {
			out = append(out, p.text(p.amber, fmt.Sprintf("  ↳ %d %s · %s", i+1, q.Agent, span(time.Since(q.sinceTime())))))
		}
		out = append(out, "")
	}
	out = append(out, p.text(p.muted, "ON THE LINE"), "")
	for _, a := range v.st.members {
		if Retired(a) {
			continue
		}
		pr, ok := v.st.presence[a]
		status := "quiet"
		color := p.muted
		if ok && pr.Live() {
			status = "recent contact"
			color = p.green
		}
		glyph := "○"
		if ok && pr.Live() {
			glyph = v.activityGlyph()
		}
		out = append(out, p.text(color, glyph+" "+a)+p.text(p.muted, "  "+status))
		if ok {
			out = append(out, "  "+p.text(p.muted, trunc(pr.Branch+" · "+pr.Tip, w-2)))
			if pr.Busy != "" {
				out = append(out, "  "+p.text(p.muted, trunc(terminalText(pr.Busy), w-2)))
			}
		}
		out = append(out, "")
	}
	out = append(out, p.text(p.muted, trunc(v.st.disk, w)))
	return out
}
