package main

// `yip switchboard` -- the human's seat, as a live view.
//
// The CLI already gave the human two verbs (`ratify`, `settled`). What it did
// not give them was a way to WATCH: to see an exchange as it happens, notice a
// dispute reaching ESCALATE, and act on it without first reconstructing the
// state from three commands. That is what this is.
//
// THE ONE RULE IT MUST NOT BREAK:
//
//	An assertion must stay expensive. Everything else should be cheap.
//
// So there is deliberately NO key here that speaks as an agent. The floor is
// what makes an assertion expensive, and a switchboard that let anyone fire off
// a quick turn would be exactly the fast lane that rule exists to prevent. The
// only two things this can WRITE are the two things that are the human's alone:
//
//	r  ratify   -- a note authored by the human (AppendNote, kind: human)
//	a  arbitrate -- a resolution on a dispute (Resolution{Kind: "human"})
//
// Everything else is observation.
//
// It is hand-rolled ANSI over `stty` rather than a TUI framework, which keeps
// the repo's zero dependencies. That is not asceticism: this is three panes and
// a prompt, and the alternative was taking the first dependency this program
// has ever had in order to get raw mode and a box drawing routine.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ----------------------------------------------------------------- terminal

// tty owns the terminal's mode. The saved string is whatever `stty -g` reported
// BEFORE we touched anything, so restore puts back exactly what was there
// rather than a guess like `sane` -- the user's own settings survive.
type tty struct {
	f     *os.File
	saved string
	rows  int
	cols  int
}

func openTTY() (*tty, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no terminal: %v (the switchboard needs one)", err)
	}
	t := &tty{f: f, rows: 24, cols: 80}
	saved, err := t.stty("-g")
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot read terminal mode: %v", err)
	}
	t.saved = strings.TrimSpace(saved)
	if _, err := t.stty("raw", "-echo"); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot enter raw mode: %v", err)
	}
	t.readSize()
	return t, nil
}

func (t *tty) stty(args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = t.f // portable: macOS uses -f, Linux -F, but both read stdin
	out, err := cmd.Output()
	return string(out), err
}

func (t *tty) readSize() {
	out, err := t.stty("size")
	if err != nil {
		return
	}
	var r, c int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "%d %d", &r, &c); err == nil && r > 0 && c > 0 {
		t.rows, t.cols = r, c
	}
}

// restore must be safe to call twice: it runs from a defer AND from the signal
// path, and a terminal left raw is the worst way to exit.
func (t *tty) restore() {
	if t.f == nil {
		return
	}
	if t.saved != "" {
		_, _ = t.stty(t.saved)
		t.saved = ""
	}
	fmt.Fprint(t.f, escMouseOff+escShowCursor+escAltOff)
	t.f.Close()
	t.f = nil
}

const (
	escAltOn      = "\033[?1049h"
	escAltOff     = "\033[?1049l"
	escHideCursor = "\033[?25l"
	escShowCursor = "\033[?25h"
	escMouseOn    = "\033[?1000h\033[?1006h"
	escMouseOff   = "\033[?1006l\033[?1000l"
	escClearLine  = "\033[K"
	sgrReset      = "\033[0m"
	sgrBold       = "\033[1m"
	sgrDim        = "\033[2m"
	sgrRev        = "\033[7m"
)

// ------------------------------------------------------------------- state

type sbEntry struct {
	kind string // TURN | NOTE | HUMAN
	from string
	at   string
	body string
	n    int
}

type sbDispute struct {
	d      *Dispute
	status string
	ms     map[string]Measurement
	done   bool
}

type sbCall struct {
	call     *Call
	entries  []sbEntry
	floor    string
	closed   bool
	disputes []*sbDispute
	status   string
	lastAt   string
}

type sbResource struct {
	name    string
	lease   Lease
	held    bool
	queue   []QueueEntry
	runners []string
}

type sbState struct {
	resources []sbResource
	disk      string
	calls     []*sbCall
	members   []string
	presence  map[string]Presence
	err       string
}

// mergeEntries interleaves turns and notes into one transcript.
//
// Turns and notes are numbered INDEPENDENTLY -- there is a turn 3 and a note 3
// and they are unrelated -- so neither number can order the other. The
// timestamp is the only thing that puts them in the order they actually
// happened, which is the whole job of a transcript.
//
// Timestamps are RFC3339 at second granularity, so a turn and a note written in
// the same second compare EQUAL. The sort is stable and turns are appended
// first, so a tie shows the turn above the note. That is a real case, not a
// theoretical one: an agent that speaks and then immediately notes lands both
// in one second.
//
// Pure, so the ordering can be tested without a terminal or a clock.
func mergeEntries(turns []Turn, notes []Note) []sbEntry {
	var out []sbEntry
	for _, t := range turns {
		k := "TURN"
		if t.Barge {
			k = "BARGE"
		}
		out = append(out, sbEntry{k, t.From, t.At, t.Body, t.N})
	}
	for _, n := range notes {
		k := "NOTE"
		if n.Kind == AuthorHuman {
			k = "HUMAN"
		}
		out = append(out, sbEntry{k, n.From, n.At, n.Body, n.N})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at < out[j].at })
	return out
}

func loadState() sbState {
	st := sbState{presence: map[string]Presence{}}
	m := LoadMembers()
	st.members = m.Names()
	for _, a := range st.members {
		if p, ok := LoadPresence(a); ok {
			st.presence[a] = p
		}
	}
	calls, err := ListCalls()
	if err != nil {
		st.err = err.Error()
		return st
	}
	for _, c := range calls {
		sc := &sbCall{call: c, closed: IsClosed(c)}
		turns, _ := Turns(c)
		notes, _ := Notes(c)
		sc.floor = FloorHolder(c, turns)
		sc.status = CallStatus(c, turns)
		sc.entries = mergeEntries(turns, notes)
		for _, e := range CallEvents(c) {
			sc.entries = append(sc.entries, sbEntry{kind: "STATE", from: e.By, at: e.At, body: e.State + ": " + e.Reason, n: 0})
		}
		sort.SliceStable(sc.entries, func(i, j int) bool { return sc.entries[i].at < sc.entries[j].at })
		if n := len(sc.entries); n > 0 {
			sc.lastAt = sc.entries[n-1].at
		}
		ds, _ := ListDisputes(c)
		for _, d := range ds {
			_, done := DisputeResolution(c, d)
			sc.disputes = append(sc.disputes, &sbDispute{d: d, status: DisputeStatus(c, d), ms: Measurements(c, d), done: done})
		}
		st.calls = append(st.calls, sc)
	}
	// Most recently active first: the call a watching human cares about is the
	// one that just moved, not the one with the lowest id.
	sort.SliceStable(st.calls, func(i, j int) bool {
		rank := func(c *sbCall) int {
			switch c.status {
			case "open":
				return 0
			case "deferred":
				return 1
			case "stale":
				return 2
			case "archived":
				return 3
			default:
				return 4
			}
		}
		if rank(st.calls[i]) != rank(st.calls[j]) {
			return rank(st.calls[i]) < rank(st.calls[j])
		}
		return st.calls[i].lastAt > st.calls[j].lastAt
	})
	for _, r := range knownResources {
		l, held := LoadLease(r.Name)
		sr := sbResource{name: r.Name, lease: l, held: held, queue: Queue(r.Name)}
		for _, runner := range l.Runners {
			sr.runners = append(sr.runners, fmt.Sprintf("pid %d %s", runner.PID, runnerStatus(runner)))
		}
		st.resources = append(st.resources, sr)
	}
	path, _ := os.Getwd()
	st.disk = diskText(path)
	return st
}

// -------------------------------------------------------------------- view

type view struct {
	t          *tty
	by         string
	st         sbState
	sel        int // selected call
	selD       int // selected dispute within that call
	scroll     int
	railScroll int
	sideScroll int
	panes      sbLayout // geometry and content lengths of the last displayed frame
	follow     bool
	prompt     string // non-empty => input mode
	input      []rune
	flash      string
	quitting   bool
	frame      int
	tab        int
}

func wrap(s string, w int) []string {
	if w < 1 {
		w = 1
	}
	var out []string
	for _, line := range strings.Split(strings.TrimRight(terminalText(s), "\n"), "\n") {
		r := []rune(line)
		if len(r) == 0 {
			out = append(out, "")
			continue
		}
		for start := 0; start < len(r); {
			used, end, lastSpace := 0, start, -1
			for end < len(r) && used+cellWidth(r[end]) <= w {
				used += cellWidth(r[end])
				if r[end] == ' ' {
					lastSpace = end
				}
				end++
			}
			if end == start {
				start++
				continue
			}
			if end < len(r) && lastSpace > start {
				end = lastSpace + 1
			}
			out = append(out, string(r[start:end]))
			start = end
		}
	}
	return out
}

func trunc(s string, w int) string {
	if plainWidth(s) <= w {
		return s
	}
	if w <= 1 {
		return fitCells(s, w, false)
	}
	return fitCells(s, w-1, false) + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shortTime(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return "     "
	}
	return t.Local().Format("15:04")
}

// transcriptLines renders the selected call to flat lines so scrolling is a
// window over a slice and cannot disagree with what is drawn.
func (v *view) transcriptLines(w int) []string {
	if v.sel >= len(v.st.calls) {
		return []string{"", "  no calls on this line yet."}
	}
	sc := v.st.calls[v.sel]
	var out []string
	for _, e := range sc.entries {
		style, tag := sgrReset, e.kind
		switch e.kind {
		case "HUMAN":
			style, tag = sgrBold, "HUMAN"
		case "NOTE":
			style = sgrDim
		case "BARGE":
			style = sgrBold
		}
		out = append(out, fmt.Sprintf("%s%-5s %s %-6s%s %s#%d%s",
			style, tag, shortTime(e.at), e.from, sgrReset, sgrDim, e.n, sgrReset))
		for _, l := range wrap(e.body, w-4) {
			out = append(out, "    "+l)
		}
		out = append(out, "")
	}
	if len(out) == 0 {
		out = []string{"", "  (no turns yet)"}
	}
	return out
}

func (v *view) presenceLines(w int) []string {
	var out []string
	for _, a := range v.st.members {
		p, ok := v.st.presence[a]
		if !ok {
			out = append(out, trunc(fmt.Sprintf(" %-6s %s(never seen)%s", a, sgrDim, sgrReset), w+len(sgrDim)+len(sgrReset)))
			continue
		}
		state := sgrDim + "idle" + sgrReset
		if p.Live() {
			state = "LIVE"
		}
		out = append(out, fmt.Sprintf(" %-6s %s %-7s %s", a, state, describeAge(p.Age()), trunc(p.Tip+" "+p.Branch, max(4, w-26))))
		if p.Busy != "" {
			out = append(out, fmt.Sprintf("   %sbusy: %s%s", sgrDim, trunc(p.Busy, max(4, w-10)), sgrReset))
		}
	}
	if len(out) == 0 {
		out = []string{" (nobody on this line yet)"}
	}
	return out
}

func (v *view) disputeLines(w int) []string {
	if v.sel >= len(v.st.calls) {
		return nil
	}
	ds := v.st.calls[v.sel].disputes
	if len(ds) == 0 {
		return []string{" " + sgrDim + "(no disputes)" + sgrReset}
	}
	var out []string
	for i, sd := range ds {
		mark := "  "
		pre, post := "", ""
		if i == v.selD {
			mark, pre, post = "> ", sgrRev, sgrReset
		}
		// Show the NUMBER and the claim, not the id -- the id is
		// "001-is-the-switchboard-worth-building", i.e. the number plus a
		// slug OF THE CLAIM, so printing both spends the pane twice on the
		// same words and truncates the readable copy down to nothing.
		num, _, _ := strings.Cut(sd.d.ID, "-")
		out = append(out, fmt.Sprintf("%s%s%s  %s%s", pre, mark, num, trunc(terminalText(sd.d.Claim), max(4, w-8)), post))
		// The status line is the whole value of the mechanism -- it is the only
		// thing that says "this one needs a person" -- so it is never elided.
		head := strings.SplitN(sd.status, " -- ", 2)[0]
		style := sgrDim
		if strings.HasPrefix(head, "ESCALATE") {
			style = sgrBold
		}
		out = append(out, fmt.Sprintf("    %s%s%s", style, trunc(terminalText(head), w-6), sgrReset))
	}
	return out
}

// resourceLines is the right half of the main pane: who holds each machine and
// who is queued behind them.
//
// Read live rather than through loadState because this is the panel whose whole
// value is being current -- the operator looks at it to answer "is anybody
// blocked right now", and a cached answer to that is worse than none. Two small
// file reads per frame.
func (v *view) resourceLines(w int) []string {
	var out []string
	add := func(s string) { out = append(out, trunc(s, w)) }
	for _, r := range knownResources {
		l, held := LoadLease(r.Name)
		q := Queue(r.Name)
		switch {
		case !held:
			add(sgrBold + r.Name + sgrReset + " " + sgrDim + "free" + sgrReset)
		case l.Expired():
			add(sgrBold + r.Name + sgrReset + " " + sgrBold + "EXPIRED" + sgrReset + " " + l.Holder)
			add("  " + sgrDim + "ttl gone " + span(-l.Remaining()) + " -- still not free" + sgrReset)
		default:
			add(sgrBold + r.Name + sgrReset + " " + l.Holder + " " + sgrDim + span(l.Remaining()) + " left" + sgrReset)
		}
		if held && l.Reason != "" {
			for _, ln := range wrap(l.Reason, max(4, w-2)) {
				add("  " + sgrDim + ln + sgrReset)
			}
		}
		if l.StolenFrom != "" {
			add("  " + sgrBold + "STOLEN from " + l.StolenFrom + sgrReset)
		}
		for i, e := range q {
			add(fmt.Sprintf("  %s%d. %s waiting %s%s", sgrDim, i+1, e.Agent, span(time.Since(e.sinceTime())), sgrReset))
		}
		add("")
	}
	if len(out) == 0 {
		add(sgrDim + "no resources" + sgrReset)
	}
	return out
}

// render builds the WHOLE frame into one buffer and writes it once. Positioning
// each row and clearing to end-of-line means there is never a clear-then-draw
// gap, so no flicker and no partial frame.
func (v *view) render() {
	var b bytes.Buffer
	for row, line := range v.frameLines(v.t.rows, v.t.cols) {
		if !colors().enabled {
			line = stripSGR(line)
		}
		fmt.Fprintf(&b, "\033[%d;1H%s%s", row+1, line, escClearLine)
	}
	fmt.Fprint(v.t.f, b.String())
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// padVisible pads to a visible width, ignoring SGR escapes -- otherwise the
// column separator drifts by however many bytes of colour a row happens to
// carry, which is invisible in a unit test and obvious on screen.
func padVisible(s string, w int) string { return fitCells(s, w, true) }

// ------------------------------------------------------------------- input

func (v *view) selectedCall() *sbCall {
	if v.sel >= 0 && v.sel < len(v.st.calls) {
		return v.st.calls[v.sel]
	}
	return nil
}

func (v *view) submit() {
	text := strings.TrimSpace(string(v.input))
	kind := v.prompt
	v.prompt, v.input = "", nil
	if text == "" {
		v.flash = "cancelled (empty)"
		return
	}
	sc := v.selectedCall()
	if sc == nil {
		v.flash = "no call selected"
		return
	}
	switch {
	case strings.HasPrefix(kind, "ratify"):
		n, err := AppendNote(sc.call, v.by, AuthorHuman, text)
		if err != nil {
			v.flash = "ratify FAILED: " + err.Error()
			return
		}
		v.flash = fmt.Sprintf("ratified as note #%d (authored by %s)", n, v.by)
	case strings.HasPrefix(kind, "arbitrate"):
		if v.selD >= len(sc.disputes) {
			v.flash = "no dispute selected"
			return
		}
		d := sc.disputes[v.selD].d
		err := SetResolution(sc.call, d, Resolution{By: v.by, Kind: "human", Detail: text, At: now()})
		if err != nil {
			v.flash = "arbitrate FAILED: " + err.Error()
			return
		}
		v.flash = "resolved " + d.ID + " (human)"
	}
}

func (v *view) key(k rune) {
	if v.prompt != "" {
		switch k {
		case '\r', '\n':
			v.submit()
		case 27: // ESC
			v.prompt, v.input, v.flash = "", nil, "cancelled"
		case 127, 8:
			if len(v.input) > 0 {
				v.input = v.input[:len(v.input)-1]
			}
		default:
			if k >= 32 {
				v.input = append(v.input, k)
			}
		}
		return
	}
	v.flash = ""
	switch k {
	case '?':
		v.flash = "click a call · wheel over a pane · tab/n next · p prev · j/k scroll · g top G end · f follow · r ratify a arbitrate"
	case '1', '2', '3':
		v.tab = int(k - '1')
		v.scroll = 0
	case 'p':
		if len(v.st.calls) > 0 {
			v.sel = (v.sel + len(v.st.calls) - 1) % len(v.st.calls)
			v.scroll = 0
			v.selD = 0
			v.revealCall()
		}
	case 'q', 3: // q or Ctrl-C
		v.quitting = true
	case 'j':
		if v.tab == 2 {
			v.railScroll++
		} else {
			v.scroll++
		}
		v.follow = false
	case 'k':
		if v.tab == 2 {
			v.railScroll = max(0, v.railScroll-1)
		} else if v.scroll > 0 {
			v.scroll--
		}
		v.follow = false
	case 'g':
		v.scroll, v.follow = 0, false
		if v.tab == 2 {
			v.railScroll = 0
		}
	case 'G':
		v.follow = true
		if v.tab == 2 {
			v.railScroll = max(0, 2+3*len(v.st.calls)-v.panes.height)
		}
	case 'f':
		v.follow = !v.follow
	case '\t', 'n':
		if len(v.st.calls) > 0 {
			v.sel = (v.sel + 1) % len(v.st.calls)
			v.scroll, v.selD = 0, 0
			v.follow = true
			v.revealCall()
		}
	case 'd':
		if sc := v.selectedCall(); sc != nil && len(sc.disputes) > 0 {
			v.selD = (v.selD + 1) % len(sc.disputes)
		}
	case 'r':
		if v.selectedCall() == nil {
			v.flash = "no call to ratify into"
			return
		}
		v.prompt = "ratify as " + v.by + ">"
	case 'a':
		sc := v.selectedCall()
		if sc == nil || v.selD >= len(sc.disputes) {
			v.flash = "no dispute selected -- press d to pick one"
			return
		}
		v.prompt = "arbitrate " + sc.disputes[v.selD].d.ID + ">"
	}
}

// ------------------------------------------------------------------- driver

func Switchboard(by string) error {
	if by == "" {
		by = os.Getenv("USER")
	}
	if by == "" {
		by = "human"
	}
	if err := EnsureRoot(); err != nil {
		return err
	}
	t, err := openTTY()
	if err != nil {
		return err
	}
	// A terminal left in raw mode is the worst way to exit, so restore is wired
	// to both normal exit and the signal path, which returns through this defer.
	defer t.restore()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
	defer signal.Stop(sigs)

	fmt.Fprint(t.f, escAltOn+escHideCursor+escMouseOn)

	v := &view{t: t, by: by, follow: true, st: loadState()}
	v.render()

	keys := make(chan rune, 64)
	go func() {
		reader := bufio.NewReader(t.f)
		for {
			r, _, err := reader.ReadRune()
			if err != nil {
				close(keys)
				return
			}
			keys <- r
		}
	}()

	tick := time.NewTicker(time.Second)
	var decoder sbInputDecoder
	escapeTimer := time.NewTimer(time.Hour)
	escapeTimer.Stop()
	defer escapeTimer.Stop()
	defer tick.Stop()

	for !v.quitting {
		select {
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			events := decoder.feed(k)
			for _, event := range events {
				v.handleInput(event)
			}
			if !escapeTimer.Stop() {
				select {
				case <-escapeTimer.C:
				default:
				}
			}
			if decoder.loneEscape() {
				escapeTimer.Reset(100 * time.Millisecond)
			}
			if len(events) > 0 {
				v.render()
			}
		case <-escapeTimer.C:
			if decoder.loneEscape() {
				decoder = sbInputDecoder{}
				v.key(27)
				v.render()
			}
		case <-tick.C:
			v.refresh(loadState())
			v.frame++
			v.render()
		case s := <-sigs:
			if s == syscall.SIGWINCH {
				t.readSize()
				v.render()
				continue
			}
			return nil
		}
	}
	return nil
}

// parseSwitchboardArgs pulls --by out of the tail.
func parseSwitchboardArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--by" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--by=") {
			return strings.TrimPrefix(args[i], "--by=")
		}
	}
	return ""
}

// Preserve the identity, including while a human is typing a decision.
func (v *view) refresh(next sbState) {
	id := ""
	if sc := v.selectedCall(); sc != nil {
		id = sc.call.ID
	}
	v.st = next
	for i, c := range next.calls {
		if c.call.ID == id {
			moved := v.sel != i
			v.sel = i
			if moved {
				v.revealCall()
			}
			return
		}
	}
	v.sel = 0
	v.selD = 0
	v.revealCall()
	if id != "" && v.prompt != "" {
		v.prompt = ""
		v.input = nil
		v.flash = "selected call disappeared; input cancelled"
	}
}
