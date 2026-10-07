package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func demoView() *view {
	stamp := time.Now().UTC().Format(time.RFC3339)
	c := &Call{ID: "0165-the-next-version-of-yip", Subject: "A clearer line between agents", From: "astra", To: "main", Opened: stamp}
	v := &view{follow: false, st: sbState{calls: []*sbCall{{call: c, status: "open", floor: "main", entries: []sbEntry{
		{kind: "TURN", from: "astra", at: stamp, n: 1, body: "The new switchboard is ready for review.\n\nDurable queues survive compaction. The inbox separates active decisions from old conversations, and resource ownership remains explicit."},
		{kind: "NOTE", from: "aux", at: stamp, n: 1, body: "The host checks are complete. Keep notes lightweight; they never need a reply."},
		{kind: "HUMAN", from: "operator", at: stamp, n: 2, body: "This is the direction. Keep going."},
	}}}, members: []string{"astra", "main", "aux", "corona"}, presence: map[string]Presence{
		"astra":  {Beat: stamp, Branch: "switchboard", Tip: "a3f92d1", Busy: "Refining the terminal interface"},
		"main":   {Beat: stamp, Branch: "signal7-land", Tip: "bb2f284", Busy: "SMP verification · row 4 of 5"},
		"aux":    {Beat: stamp, Branch: "aux-3", Tip: "4630aef", Busy: "Haul transport checks"},
		"corona": {Beat: stamp, Branch: "async-memory", Tip: "5ff62b7", Busy: "Service lifecycle review"},
	}, resources: []sbResource{
		{name: "mac", held: true, lease: Lease{Holder: "main", Since: time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339), TTLSecs: 3600, Phase: "SMP verification · row 4 of 5"}, queue: []QueueEntry{{Agent: "corona", Since: stamp}, {Agent: "astra", Since: stamp}}},
		{name: "pi"},
	}, disk: "disk: 42.7 GiB available"}}
	for _, sample := range []struct{ subject, status, from, to string }{
		{"Signal delivery / final gate", "open", "main", "aux"},
		{"Async service ownership", "open", "corona", "astra"},
		{"Haul transport evidence", "deferred", "aux", "main"},
		{"Registry lifetime checkpoint", "resolved", "astra", "main"},
	} {
		v.st.calls = append(v.st.calls, &sbCall{call: &Call{ID: sample.subject, Subject: sample.subject, From: sample.from, To: sample.to}, status: sample.status})
	}
	return v
}
func TestFrameFitsAndSanitizes(t *testing.T) {
	tmpLine(t)
	v := demoView()
	v.st.calls[0].entries[0].body = "untrusted \033]52;c;hidden\a title\033[2J界e\u0301"
	for _, size := range [][2]int{{160, 44}, {110, 32}, {80, 24}, {40, 10}, {20, 6}} {
		lines := v.frameLines(size[1], size[0])
		if len(lines) != size[1] {
			t.Fatal(size, len(lines))
		}
		for _, l := range lines {
			if strings.Contains(l, "\033]") || strings.Contains(l, "\033[2J") {
				t.Fatal("terminal controls escaped")
			}
			if plainWidth(l) > size[0] {
				t.Fatalf("overflow %v %d %q", size, plainWidth(l), l)
			}
		}
	}
}
func TestTerminalTextDropsControls(t *testing.T) {
	s := terminalText("hello\033]52;c;secret\a!\033[2J\x00")
	if s != "hello!" {
		t.Fatal(s)
	}
	if plainWidth(fitCells("\033[31m界a\033[0m", 2, true)) != 2 {
		t.Fatal("wide cell clipping")
	}
}
func TestFrameMonochromeAndStatic(t *testing.T) {
	tmpLine(t)
	t.Setenv("NO_COLOR", "1")
	if motionEnabled() {
		t.Fatal("motion on without color")
	}
	v := demoView()
	for _, l := range v.frameLines(24, 80) {
		if strings.Contains(stripSGR(l), "\033") {
			t.Fatal("escape in plain frame")
		}
	}
}

func TestRefreshKeepsHumanDecisionOnItsCall(t *testing.T) {
	tmpLine(t)
	first, _ := NewCall("a", "b", "first")
	second, _ := NewCall("a", "b", "second")
	v := &view{by: "operator", st: sbState{calls: []*sbCall{{call: first}, {call: second}}}}
	v.key('r')
	for _, r := range "approved" {
		v.key(r)
	}
	v.refresh(sbState{calls: []*sbCall{{call: second}, {call: first}}})
	v.key('\r')
	notes, _ := Notes(first)
	wrong, _ := Notes(second)
	if len(notes) != 1 || len(wrong) != 0 {
		t.Fatal("decision moved with list index", notes, wrong)
	}
	v.key('r')
	v.key('x')
	v.refresh(sbState{})
	if v.prompt != "" || len(v.input) != 0 {
		t.Fatal("orphaned decision input survived")
	}
}

func TestDeskIsScrollableOnWideAndNarrowTerminals(t *testing.T) {
	tmpLine(t)
	for _, w := range []int{80, 160} {
		v := demoView()
		v.key('2')
		v.key('j')
		v.scroll = 1000
		frame := strings.Join(v.frameLines(24, w), "\n")
		if !strings.Contains(frame, "42.7 GiB") {
			t.Fatalf("desk tail unreachable at width %d", w)
		}
	}
}

// Optional evidence captures use a synthetic line, never the operator's state.
func TestSwitchboardCapture(t *testing.T) {
	dir := os.Getenv("YIP_CAPTURE_DIR")
	if dir == "" {
		t.Skip("capture not requested")
	}
	tmpLine(t)
	os.MkdirAll(dir, 0755)
	v := demoView()
	for _, sz := range [][2]int{{160, 44}, {110, 32}, {80, 24}} {
		var b strings.Builder
		for _, l := range v.frameLines(sz[1], sz[0]) {
			b.WriteString(l)
			b.WriteString("\n")
		}
		if err := os.WriteFile(filepath.Join(dir, fmtSize(sz)+".ansi"), []byte(b.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
func fmtSize(s [2]int) string { return strings.Join([]string{itoa(s[0]), itoa(s[1])}, "x") }
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
