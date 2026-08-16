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
	if t.saved != "" {
		_, _ = t.stty(t.saved)
		t.saved = ""
	}
	fmt.Fprint(t.f, escShowCursor+escAltOff)
	t.f.Close()
}

const (
	escAltOn      = "\033[?1049h"
	escAltOff     = "\033[?1049l"
	escHideCursor = "\033[?25l"
	escShowCursor = "\033[?25h"
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
	lastAt   string
}

type sbState struct {
	calls    []*sbCall
	members  []string
	presence map[string]Presence
	err      string
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
		sc.entries = mergeEntries(turns, notes)
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
		if st.calls[i].closed != st.calls[j].closed {
			return !st.calls[i].closed
		}
		return st.calls[i].lastAt > st.calls[j].lastAt
	})
	return st
}

// -------------------------------------------------------------------- view

type view struct {
	t        *tty
	by       string
	st       sbState
	sel      int // selected call
	selD     int // selected dispute within that call
	scroll   int
	follow   bool
	prompt   string // non-empty => input mode
	input    []rune
	flash    string
	quitting bool
}

func wrap(s string, w int) []string {
	if w < 8 {
		w = 8
	}
	var out []string
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		r := []rune(line)
		if len(r) == 0 {
			out = append(out, "")
			continue
		}
		for len(r) > w {
			cut := w
			// Prefer a space near the edge so words survive; fall back to a
			// hard cut, because a long unbroken token must not stall the loop.
			for i := w; i > w*2/3; i-- {
				if r[i] == ' ' {
					cut = i
					break
				}
			}
			out = append(out, string(r[:cut]))
			r = r[cut:]
			for len(r) > 0 && r[0] == ' ' {
				r = r[1:]
			}
		}
		out = append(out, string(r))
	}
	return out
}

func trunc(s string, w int) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w <= 1 {
		return string(r[:max(0, w)])
	}
	return string(r[:w-1]) + "…"
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
		out = append(out, fmt.Sprintf("%s%s%s  %s%s", pre, mark, num, trunc(sd.d.Claim, max(4, w-8)), post))
		// The status line is the whole value of the mechanism -- it is the only
		// thing that says "this one needs a person" -- so it is never elided.
		head := strings.SplitN(sd.status, " -- ", 2)[0]
		style := sgrDim
		if strings.HasPrefix(head, "ESCALATE") {
			style = sgrBold
		}
		out = append(out, fmt.Sprintf("    %s%s%s", style, trunc(head, w-6), sgrReset))
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
	rows, cols := v.t.rows, v.t.cols
	var b bytes.Buffer
	row := 1
	put := func(s string) {
		if row > rows {
			return
		}
		fmt.Fprintf(&b, "\033[%d;1H%s%s", row, s, escClearLine)
		row++
	}
	rule := func(label string) {
		put(sgrDim + trunc(label+" "+strings.Repeat("─", max(0, cols-len(label)-2)), cols) + sgrReset)
	}

	// header
	title := "yip switchboard"
	if v.sel < len(v.st.calls) {
		sc := v.st.calls[v.sel]
		state := "floor:" + sc.floor
		if sc.closed {
			state = "CLOSED"
		}
		title = fmt.Sprintf("%s  %s  [%s]  (%d/%d)", sc.call.ID, sc.call.Subject, state, v.sel+1, len(v.st.calls))
	}
	put(sgrRev + trunc(" "+title+strings.Repeat(" ", cols), cols) + sgrReset)

	bottomH := 8
	if rows < 20 {
		bottomH = 5
	}
	transH := rows - 1 /*header*/ - 1 /*rule*/ - bottomH - 1 /*footer*/
	if transH < 3 {
		transH = 3
	}

	// The main pane splits vertically: transcript left, shared machines right.
	// The resource panel earns a permanent seat rather than a keystroke because
	// the question it answers -- is a peer blocked on something I am holding --
	// is one the operator needs ambiently, and would never think to ask.
	resW := cols / 3
	if resW > 40 {
		resW = 40
	}
	if resW < 18 || cols < 60 {
		resW = 0 // too narrow to split; transcript takes the whole width
	}
	transW := cols - 1
	if resW > 0 {
		transW = cols - resW - 3
	}

	lines := v.transcriptLines(transW)
	if v.follow {
		v.scroll = max(0, len(lines)-transH)
	}
	if v.scroll > max(0, len(lines)-1) {
		v.scroll = max(0, len(lines)-1)
	}
	var res []string
	if resW > 0 {
		res = v.resourceLines(resW)
	}
	for i := 0; i < transH; i++ {
		idx := v.scroll + i
		l := ""
		if idx < len(lines) {
			l = lines[idx]
		}
		if resW == 0 {
			put(l)
			continue
		}
		r := ""
		if i < len(res) {
			r = res[i]
		}
		put(padVisible(l, transW) + sgrDim + "│" + sgrReset + " " + r)
	}

	rule("─ presence ── disputes ")

	// Two columns, rendered as one string per row so a single write does the
	// whole frame.
	lw := cols/2 - 1
	if lw < 20 {
		lw = cols - 1
	}
	left, right := v.presenceLines(lw), v.disputeLines(cols-lw-3)
	for i := 0; i < bottomH; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		put(padVisible(l, lw) + sgrDim + "│" + sgrReset + " " + r)
	}

	// footer: prompt when the human is typing, otherwise the key map
	if v.prompt != "" {
		put(sgrBold + v.prompt + sgrReset + " " + string(v.input) + "█")
	} else {
		help := " [r]atify  [a]rbitrate  [d]ispute-sel  [f]ollow " + onOff(v.follow) +
			"  [tab]call  [jk]scroll  [q]uit"
		if v.flash != "" {
			help = " " + v.flash
		}
		put(sgrDim + trunc(help, cols-1) + sgrReset)
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
func padVisible(s string, w int) string {
	vis, inEsc := 0, false
	var out []rune
	for _, r := range s {
		switch {
		case r == '\033':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			if vis >= w {
				continue
			}
			vis++
		}
		out = append(out, r)
	}
	return string(out) + strings.Repeat(" ", max(0, w-vis))
}

// ------------------------------------------------------------------- input

func (v *view) selectedCall() *sbCall {
	if v.sel < len(v.st.calls) {
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
	case 'q', 3: // q or Ctrl-C
		v.quitting = true
	case 'j':
		v.scroll++
		v.follow = false
	case 'k':
		if v.scroll > 0 {
			v.scroll--
		}
		v.follow = false
	case 'g':
		v.scroll, v.follow = 0, false
	case 'G':
		v.follow = true
	case 'f':
		v.follow = !v.follow
	case '\t', 'n':
		if len(v.st.calls) > 0 {
			v.sel = (v.sel + 1) % len(v.st.calls)
			v.scroll, v.selD = 0, 0
			v.follow = true
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
	// to BOTH the normal path and a signal. os.Exit skips defers, so the signal
	// path has to restore for itself.
	defer t.restore()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)

	fmt.Fprint(t.f, escAltOn+escHideCursor)

	v := &view{t: t, by: by, follow: true, st: loadState()}
	v.render()

	keys := make(chan rune, 64)
	go func() {
		buf := make([]byte, 16)
		for {
			n, err := t.f.Read(buf)
			if err != nil || n == 0 {
				close(keys)
				return
			}
			for i := 0; i < n; i++ {
				// Arrow keys arrive as ESC [ A..D. Map them onto the same
				// handlers as jk so both work without a second code path.
				if buf[i] == 27 && i+2 < n && buf[i+1] == '[' {
					switch buf[i+2] {
					case 'A':
						keys <- 'k'
					case 'B':
						keys <- 'j'
					}
					i += 2
					continue
				}
				keys <- rune(buf[i])
			}
		}
	}()

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for !v.quitting {
		select {
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			v.key(k)
			v.render()
		case <-tick.C:
			v.st = loadState()
			if v.sel >= len(v.st.calls) {
				v.sel = 0
			}
			v.render()
		case s := <-sigs:
			if s == syscall.SIGWINCH {
				t.readSize()
				v.render()
				continue
			}
			t.restore()
			os.Exit(0)
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
