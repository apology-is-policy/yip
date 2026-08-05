package main

// Tests for the switchboard's logic. The terminal layer is deliberately thin
// (open, size, raw, restore) and cannot be driven headlessly; everything below
// it is pure or file-backed, and that is where the bugs actually are.
//
// The load-bearing test here is TestSwitchboardCannotSpeakAsAnAgent. The rest
// check behaviour; that one checks the RULE.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tmpLine(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("YIP_ROOT", dir)
	if err := EnsureRoot(); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
}

// --------------------------------------------------------------- pure bits

func TestPadVisibleIgnoresEscapes(t *testing.T) {
	// The column separator sits at a fixed offset. If padding counted the bytes
	// of an SGR sequence, a coloured row would push the separator left by
	// however much colour it happened to carry -- invisible to a naive test and
	// glaring on screen.
	plain := padVisible("abc", 10)
	if len(plain) != 10 {
		t.Fatalf("plain: want width 10, got %d (%q)", len(plain), plain)
	}
	coloured := padVisible(sgrBold+"abc"+sgrReset, 10)
	if got := visibleWidth(coloured); got != 10 {
		t.Fatalf("coloured: want visible width 10, got %d (%q)", got, coloured)
	}
	if !strings.Contains(coloured, sgrBold) {
		t.Fatalf("padding dropped the escape: %q", coloured)
	}
}

// visibleWidth is the test's own independent counter. Reusing padVisible's
// scanner would make this assert that the function agrees with itself.
func visibleWidth(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case r == '\033':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			n++
		}
	}
	return n
}

func TestWrapTerminatesOnUnbrokenToken(t *testing.T) {
	// A long token with no space must be hard-cut. A word-boundary-only search
	// would find none and loop forever, which in a render loop is a hang, not
	// a wrong pixel.
	long := strings.Repeat("x", 200)
	lines := wrap(long, 20)
	if len(lines) < 10 {
		t.Fatalf("want the token split across lines, got %d", len(lines))
	}
	for i, l := range lines {
		if len([]rune(l)) > 20 {
			t.Fatalf("line %d is %d wide, over 20: %q", i, len([]rune(l)), l)
		}
	}
	if joined := strings.Join(lines, ""); joined != long {
		t.Fatalf("wrap lost or added content: %d chars in, %d out", len(long), len(joined))
	}
}

func TestTruncIsRuneSafe(t *testing.T) {
	// Byte slicing a multi-byte rune emits a replacement character and corrupts
	// the rest of the line.
	got := trunc("héllo wörld", 7)
	if len([]rune(got)) != 7 {
		t.Fatalf("want 7 runes, got %d (%q)", len([]rune(got)), got)
	}
	if strings.Contains(got, "�") {
		t.Fatalf("trunc split a rune: %q", got)
	}
	if trunc("short", 99) != "short" {
		t.Fatalf("trunc altered a string that fits")
	}
}

func TestMergeEntriesOrdersByTimeNotNumber(t *testing.T) {
	// Turn 2 happened AFTER note 1, and note numbering is independent, so a
	// merge that trusted either number would interleave them wrongly.
	turns := []Turn{
		{N: 1, From: "aux", At: "2026-08-05T10:00:00Z", Body: "first turn"},
		{N: 2, From: "main", At: "2026-08-05T10:00:30Z", Body: "second turn"},
	}
	notes := []Note{
		{N: 1, From: "main", Kind: AuthorAgent, At: "2026-08-05T10:00:10Z", Body: "a note"},
		{N: 2, From: "michal", Kind: AuthorHuman, At: "2026-08-05T10:00:40Z", Body: "approved"},
	}
	got := mergeEntries(turns, notes)
	want := []string{"TURN", "NOTE", "TURN", "HUMAN"}
	if len(got) != len(want) {
		t.Fatalf("want %d entries, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].kind != want[i] {
			t.Fatalf("entry %d: want %s, got %s (%q)", i, want[i], got[i].kind, got[i].body)
		}
	}
}

func TestMergeEntriesTieShowsTurnFirst(t *testing.T) {
	// Same second is a real case: speak, then note. Documented tie-break.
	at := "2026-08-05T10:00:00Z"
	got := mergeEntries(
		[]Turn{{N: 1, From: "aux", At: at, Body: "t"}},
		[]Note{{N: 1, From: "aux", Kind: AuthorAgent, At: at, Body: "n"}},
	)
	if got[0].kind != "TURN" || got[1].kind != "NOTE" {
		t.Fatalf("tie-break changed: got %s then %s", got[0].kind, got[1].kind)
	}
}

// ------------------------------------------------------- the rule it enforces

// TestSwitchboardCannotSpeakAsAnAgent is the reason this file exists.
//
// The switchboard must not become a fast lane for assertions -- the floor is
// what makes an assertion expensive, and that expense is what catches things.
// So no key may write a TURN. This drives every printable key (plus Enter, ESC
// and Backspace) through the input handler and asserts the turn count is
// unchanged afterwards.
//
// It fails the moment somebody adds a convenient `s`-for-say, which is exactly
// the change that would look harmless in review.
func TestSwitchboardCannotSpeakAsAnAgent(t *testing.T) {
	tmpLine(t)
	c, err := NewCall("aux", "main", "the rule")
	if err != nil {
		t.Fatalf("NewCall: %v", err)
	}
	if _, err := AppendTurn(c, "aux", "opening turn", false); err != nil {
		t.Fatalf("AppendTurn: %v", err)
	}
	before, _ := Turns(c)

	v := &view{by: "michal", st: loadState(), follow: true}
	for k := rune(32); k < 127; k++ {
		v.key(k)
		v.key('\r') // commit anything that opened a prompt
		v.key(27)   // and cancel anything still open
	}
	v.key('\t')
	v.key(8)

	after, _ := Turns(c)
	if len(after) != len(before) {
		t.Fatalf("a key wrote a TURN: %d -> %d. The switchboard must never speak as an agent.",
			len(before), len(after))
	}
}

// ------------------------------------------------------------ the two writes

func TestRatifyWritesAHumanNote(t *testing.T) {
	tmpLine(t)
	c, err := NewCall("aux", "main", "ratify path")
	if err != nil {
		t.Fatalf("NewCall: %v", err)
	}
	v := &view{by: "michal", st: loadState(), follow: true}

	v.key('r')
	if v.prompt == "" {
		t.Fatal("r did not open the ratify prompt")
	}
	for _, r := range "approved: renumber to 104/105" {
		v.key(r)
	}
	v.key('\r')

	notes, _ := Notes(c)
	if len(notes) != 1 {
		t.Fatalf("want 1 note, got %d (flash: %q)", len(notes), v.flash)
	}
	if notes[0].Kind != AuthorHuman {
		t.Fatalf("want kind human, got %q -- an agent-authored note here would defeat the seat", notes[0].Kind)
	}
	if notes[0].From != "michal" {
		t.Fatalf("want author michal, got %q", notes[0].From)
	}
	if !strings.Contains(notes[0].Body, "104/105") {
		t.Fatalf("body not recorded: %q", notes[0].Body)
	}
	// A ratification is a NOTE, so it must not have taken the floor.
	turns, _ := Turns(c)
	if len(turns) != 0 {
		t.Fatalf("ratify wrote a turn (%d) -- it must be a note", len(turns))
	}
}

func TestRatifyEscapeCancelsAndWritesNothing(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("aux", "main", "cancel path")
	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('r')
	for _, r := range "half-typed thought" {
		v.key(r)
	}
	v.key(27) // ESC
	if v.prompt != "" {
		t.Fatal("ESC left the prompt open")
	}
	if notes, _ := Notes(c); len(notes) != 0 {
		t.Fatalf("ESC still wrote %d note(s)", len(notes))
	}
}

func TestRatifyEmptyBodyWritesNothing(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("aux", "main", "empty path")
	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('r')
	v.key(' ')
	v.key('\r')
	if notes, _ := Notes(c); len(notes) != 0 {
		t.Fatalf("a whitespace-only ratification was recorded (%d)", len(notes))
	}
}

func TestArbitrateResolvesTheSelectedDispute(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("aux", "main", "arbitrate path")
	d1, _ := NewDispute(c, "aux", "first claim")
	d2, _ := NewDispute(c, "aux", "second claim")

	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('d') // move selection off the first
	if v.selD != 1 {
		t.Fatalf("d did not move the dispute selection: %d", v.selD)
	}
	v.key('a')
	if v.prompt == "" {
		t.Fatal("a did not open the arbitrate prompt")
	}
	for _, r := range "not worth building" {
		v.key(r)
	}
	v.key('\r')

	if _, done := DisputeResolution(c, d2); !done {
		t.Fatalf("the SELECTED dispute was not resolved (flash: %q)", v.flash)
	}
	if _, done := DisputeResolution(c, d1); done {
		t.Fatal("arbitrate resolved the WRONG dispute -- selection is not respected")
	}
	r, _ := DisputeResolution(c, d2)
	if r.Kind != "human" || r.By != "michal" {
		t.Fatalf("want a human resolution by michal, got %+v", r)
	}
}

func TestArbitrateWithNoDisputeIsRefused(t *testing.T) {
	tmpLine(t)
	NewCall("aux", "main", "no disputes")
	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('a')
	if v.prompt != "" {
		t.Fatal("arbitrate opened a prompt with no dispute to resolve")
	}
	if v.flash == "" {
		t.Fatal("arbitrate refused silently -- the human gets no feedback")
	}
}

// ------------------------------------------------------------------ backspace

func TestBackspaceEditsThePrompt(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("aux", "main", "editing")
	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('r')
	for _, r := range "okay!!" {
		v.key(r)
	}
	v.key(127)
	v.key(127)
	v.key('\r')
	notes, _ := Notes(c)
	if len(notes) != 1 || strings.TrimSpace(notes[0].Body) != "okay" {
		t.Fatalf("backspace did not edit: %q", notes[0].Body)
	}
}

// ------------------------------------------------------------- state loading

func TestLoadStateOrdersActiveCallsFirst(t *testing.T) {
	tmpLine(t)
	old, _ := NewCall("aux", "main", "older and closed")
	AppendTurn(old, "aux", "x", false)
	SetBye(old, "aux")
	SetBye(old, "main")

	fresh, _ := NewCall("aux", "main", "the live one")
	AppendTurn(fresh, "aux", "y", false)

	st := loadState()
	if len(st.calls) != 2 {
		t.Fatalf("want 2 calls, got %d", len(st.calls))
	}
	if st.calls[0].call.ID != fresh.ID {
		t.Fatalf("a closed call sorted above a live one: %s first", st.calls[0].call.ID)
	}
	if !st.calls[1].closed {
		t.Fatal("the closed call is not reported closed")
	}
}

func TestTranscriptLinesSurviveAnEmptyCall(t *testing.T) {
	tmpLine(t)
	NewCall("aux", "main", "nothing said yet")
	v := &view{by: "michal", st: loadState(), follow: true}
	if got := v.transcriptLines(60); len(got) == 0 {
		t.Fatal("an empty call rendered zero lines")
	}
	// And with no calls at all.
	v2 := &view{by: "michal", st: sbState{}, follow: true}
	if got := v2.transcriptLines(60); len(got) == 0 {
		t.Fatal("an empty line rendered zero lines")
	}
}

// ------------------------------------------------------------------ frames

// renderTo draws one frame into a file and returns it. The terminal layer is
// just an *os.File, so pointing it at a temp file gives the closest thing to a
// screenshot that runs without a terminal -- and a render panic would take the
// switchboard down mid-use, which no other test here would catch.
func renderTo(t *testing.T, v *view, rows, cols int) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "frame")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer f.Close()
	v.t = &tty{f: f, rows: rows, cols: cols}
	v.render()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return string(b)
}

func TestRenderDrawsTheWholeFrame(t *testing.T) {
	tmpLine(t)
	c, _ := NewCall("aux", "main", "the merge instruction")
	AppendTurn(c, "aux", "here is the plan", false)
	AppendNote(c, "michal", AuthorHuman, "approved: renumber to 104/105")
	d, _ := NewDispute(c, "aux", "is this worth building")
	SetMeasurement(c, d, "aux", "none")
	SetMeasurement(c, d, "main", "none")

	v := &view{by: "michal", st: loadState(), follow: true}
	frame := renderTo(t, v, 24, 100)

	for _, want := range []string{
		"the merge instruction", // header carries the call
		"approved: renumber",    // the human turn is in the transcript
		"presence",              // the bottom rule
		"ESCALATE",              // the status that says a person is needed
		"[r]atify",              // the key map
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("frame is missing %q", want)
		}
	}
	// Every row is positioned explicitly, so the frame must address all 24.
	if n := strings.Count(frame, "\033["); n < 24 {
		t.Fatalf("frame addressed %d rows, want at least 24", n)
	}
}

func TestRenderSurvivesATinyTerminal(t *testing.T) {
	// strings.Repeat panics on a negative count and several widths here are
	// derived by subtraction, so a narrow window is a real crash risk rather
	// than a cosmetic one. A panic mid-session leaves the terminal raw.
	tmpLine(t)
	c, _ := NewCall("aux", "main", "a subject much longer than the window")
	AppendTurn(c, "aux", strings.Repeat("word ", 200), false)
	NewDispute(c, "aux", "a claim that will not fit either")

	for _, sz := range [][2]int{{24, 80}, {10, 40}, {6, 20}, {4, 10}, {3, 4}, {1, 1}} {
		v := &view{by: "michal", st: loadState(), follow: true}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("render panicked at %dx%d: %v", sz[0], sz[1], r)
				}
			}()
			renderTo(t, v, sz[0], sz[1])
		}()
	}
}

func TestPromptReplacesTheKeyMap(t *testing.T) {
	tmpLine(t)
	NewCall("aux", "main", "prompting")
	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('r')
	frame := renderTo(t, v, 24, 80)
	if !strings.Contains(frame, "ratify as michal") {
		t.Fatal("the prompt is not shown while typing")
	}
	if strings.Contains(frame, "[r]atify") {
		t.Fatal("the key map is still drawn under an open prompt")
	}
}

func TestNoCallMeansNoWrite(t *testing.T) {
	tmpLine(t)
	v := &view{by: "michal", st: loadState(), follow: true}
	v.key('r')
	v.key('a')
	if v.prompt != "" {
		t.Fatal("opened a prompt with no call selected")
	}
	ents, _ := os.ReadDir(filepath.Join(Root(), "calls"))
	if len(ents) != 0 {
		t.Fatalf("keys created something out of nothing: %d entries", len(ents))
	}
}
