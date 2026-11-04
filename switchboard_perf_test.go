package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
)

// What every frame is built on must not change while it gets faster: these are the implementations it
// replaced, kept as the oracle.
func fitCellsOracle(s string, w int, pad bool) string {
	if w <= 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	r := []rune(s)
	clipped := false
	for i := 0; i < len(r); i++ {
		if r[i] == 27 && i+1 < len(r) && r[i+1] == '[' {
			j := i + 2
			for j < len(r) && ((r[j] >= '0' && r[j] <= '9') || r[j] == ';') {
				j++
			}
			if j < len(r) && r[j] == 'm' {
				b.WriteString(string(r[i : j+1]))
				i = j
				continue
			}
		}
		n := cellWidth(r[i])
		if used+n > w {
			clipped = true
			continue
		}
		if clipped {
			continue
		}
		b.WriteRune(r[i])
		used += n
	}
	if pad && used < w {
		b.WriteString(strings.Repeat(" ", w-used))
	}
	return b.String()
}

func randomTerminalString(rng *rand.Rand) string {
	pieces := []string{"a", "word ", "\033[1m", "\033[38;5;117m", "\033[0m", "\033[", "\033[12", "\033]52;c;x\007", "●", "━", "│", "日本", "é", "é", "‮", "\t", "\n", "\x7f", "\xff", "\xc3", "‍", "️", "🙂", "\x01", "~"}
	var b strings.Builder
	for i := rng.Intn(24); i > 0; i-- {
		b.WriteString(pieces[rng.Intn(len(pieces))])
	}
	return b.String()
}

func TestFastPathsMatchTheirOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 200000; i++ {
		s := randomTerminalString(rng)
		w, pad := rng.Intn(30)-1, rng.Intn(2) == 0
		if got, want := fitCells(s, w, pad), fitCellsOracle(s, w, pad); got != want {
			t.Fatalf("fitCells(%q, %d, %v) = %q, want %q", s, w, pad, got, want)
		}
	}
	for r := rune(0); r < 0x3000; r++ {
		fast := cellWidth(r)
		slow := 1
		switch {
		case isZeroWidthForTest(r):
			slow = 0
		case r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a || r >= 0x2e80):
			slow = 2
		}
		if fast != slow {
			t.Fatalf("cellWidth(%U) = %d, want %d", r, fast, slow)
		}
	}
	// The clean path must not pass anything the slow path would have changed.
	for c := 0; c < 256; c++ {
		s := "a" + string([]byte{byte(c)}) + "b"
		if got := terminalText(s); strings.ContainsAny(got, "\033\007\t\x7f") {
			t.Fatalf("terminalText(%q) = %q", s, got)
		}
	}
}

func TestPaintingNeverTouchesTheDisk(t *testing.T) {
	t.Setenv("YIP_ROOT", t.TempDir())
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("a", "b", "question")
	AppendTurn(c, "a", "first", false)
	seedBroadcastMembers(t)
	b, err := CreateBroadcast("op", "briefing", "Report in", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReplyBroadcast(b.ID, "a", "reported"); err != nil {
		t.Fatal(err)
	}
	if _, err := PostRoadmap("a", Roadmap{Arc: "x", Active: "s", Stations: []RoadmapStation{{ID: "s", Name: "s"}}}); err != nil {
		t.Fatal(err)
	}
	st := loadState()
	frames := func() []string {
		var out []string
		for tab := 0; tab < 5; tab++ {
			for sel := range st.calls {
				v := &view{st: st, sel: sel, tab: tab, mapPicked: -1}
				out = append(out, v.frameLines(30, 160)...)
			}
		}
		return out
	}
	before := frames()
	root := os.Getenv("YIP_ROOT")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	after := frames()
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatal("a frame changed when the state directory went away: painting read the disk")
	}
	if !strings.Contains(strings.Join(before, "\n"), "reported") {
		t.Fatal("the control: the broadcast's reply should be on screen")
	}
}

// The cache may only ever save reading: after every kind of write it must agree with a fresh read.
func TestLoaderAgreesWithAFreshReadAfterEveryWrite(t *testing.T) {
	t.Setenv("YIP_ROOT", t.TempDir())
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	seedBroadcastMembers(t)
	summary := func(st sbState) string {
		var b strings.Builder
		for _, c := range st.calls {
			fmt.Fprintf(&b, "%s|%s|%s|%v|%d|%s", c.call.ID, c.status, c.floor, c.closed, len(c.entries), c.lastAt)
			for _, e := range c.entries {
				fmt.Fprintf(&b, "|%s:%s", e.kind, e.body)
			}
			for _, d := range c.disputes {
				fmt.Fprintf(&b, "|D %s %s %v %d", d.d.ID, d.status, d.done, len(d.ms))
			}
			b.WriteByte('\n')
		}
		return b.String()
	}
	loader := &sbLoader{}
	c, err := NewCall("a", "b", "first")
	if err != nil {
		t.Fatal(err)
	}
	loader.load()
	steps := []struct {
		name string
		do   func() error
	}{
		{"a turn", func() error { _, e := AppendTurn(c, "a", "hello", false); return e }},
		{"a second turn", func() error { _, e := AppendTurn(c, "b", "hi", false); return e }},
		{"a note", func() error { _, e := AppendNote(c, "a", AuthorAgent, "fyi"); return e }},
		{"a bye", func() error { return SetBye(c, "a") }},
		{"the other bye", func() error { return SetBye(c, "b") }},
		{"a status", func() error { return SetCallStatus(c, "a", "open", "again", "") }},
		{"a dispute", func() error { _, e := NewDispute(c, "a", "the claim"); return e }},
		{"a measurement", func() error {
			ds, _ := ListDisputes(c)
			return SetMeasurement(c, ds[0], "a", "true")
		}},
		{"a resolution", func() error {
			ds, _ := ListDisputes(c)
			return SetResolution(c, ds[0], Resolution{By: "op", Kind: "human", Detail: "done", At: now()})
		}},
		{"a new call", func() error { _, e := NewCall("b", "a", "second"); return e }},
	}
	for _, s := range steps {
		time.Sleep(5 * time.Millisecond) // a filesystem clock has a grain; the full reload covers finer
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		got, want := summary(loader.load()), summary(loadState())
		if got != want {
			t.Fatalf("after %s the cached read differs:\n%s\nfresh:\n%s", s.name, got, want)
		}
	}
	// And a cached call is really not re-read: the point of all this.
	first := loader.calls[c.ID]
	loader.load()
	if loader.calls[c.ID] != first {
		t.Fatal("an unchanged call was read again")
	}
}

func TestSnapshotsDoNotShareWhatTheyChange(t *testing.T) {
	t.Setenv("YIP_ROOT", t.TempDir())
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCall("a", "b", "x"); err != nil {
		t.Fatal(err)
	}
	loader := &sbLoader{}
	one, two := loader.load(), loader.load()
	if one.calls[0] == two.calls[0] {
		t.Fatal("the view and the loader share a call; the loader runs on its own goroutine")
	}
}

func TestBroadcastsSinkAsNewerCallsArrive(t *testing.T) {
	call := func(id, status, at string) *sbCall {
		return &sbCall{call: &Call{ID: id}, status: status, lastAt: at}
	}
	bc := func(id, at string) *sbCall {
		return &sbCall{call: &Call{ID: id}, broadcast: &Broadcast{ID: id}, status: "open", lastAt: at}
	}
	ids := func(cs []*sbCall) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.call.ID)
		}
		return strings.Join(out, " ")
	}
	t1, t2, t3, t4, t5 := "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", "2026-11-03T00:00:00Z", "2026-11-04T00:00:00Z", "2026-11-05T00:00:00Z"
	got := ids(orderConversations(
		[]*sbCall{call("old-open", "open", t1), call("new-open", "open", t4), call("stale", "stale", t2), call("resolved", "resolved", t5)},
		[]*sbCall{bc("b-mid", t3), bc("b-old", t1)},
	))
	// A newer call stands above a broadcast. Only an older one stays below it.
	if want := "new-open b-mid old-open stale resolved b-old"; got != want {
		t.Fatalf("order %q, want %q", got, want)
	}
	// A fresh broadcast still heads the list until something newer happens.
	got = ids(orderConversations([]*sbCall{call("c", "open", t1)}, []*sbCall{bc("fresh", t5)}))
	if got != "fresh c" {
		t.Fatalf("order %q", got)
	}
	// And a same-second tie goes to the call.
	got = ids(orderConversations([]*sbCall{call("c", "open", t1)}, []*sbCall{bc("b", t1)}))
	if got != "c b" {
		t.Fatalf("order %q", got)
	}
}

func TestRenderWritesOnlyWhatChanged(t *testing.T) {
	t.Setenv("YIP_ROOT", t.TempDir())
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
	c, _ := NewCall("a", "b", "question")
	for i := 0; i < 40; i++ {
		AppendTurn(c, "a", fmt.Sprintf("line %d", i), false)
		AppendTurn(c, "b", "reply", false)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	v := &view{st: loadState(), t: &tty{f: w, rows: 24, cols: 100}}
	read := func() int {
		w.SetWriteDeadline(time.Time{})
		r.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := make([]byte, 1<<20)
		n, _ := r.Read(buf)
		return n
	}
	v.render()
	full := read()
	if full == 0 {
		t.Fatal("the first frame wrote nothing")
	}
	v.render()
	if n := read(); n != 0 {
		t.Fatalf("an unchanged frame wrote %d bytes", n)
	}
	v.scroll = 3
	v.render()
	scrolled := read()
	if scrolled == 0 || scrolled >= full {
		t.Fatalf("a scroll wrote %d of a %d byte frame", scrolled, full)
	}
	v.key(12)
	v.render()
	if n := read(); n < full/2 {
		t.Fatalf("Ctrl-L wrote %d of a %d byte frame", n, full)
	}
}

func BenchmarkFrameWhileScrolling(b *testing.B) {
	b.Setenv("YIP_ROOT", b.TempDir())
	if err := EnsureRoot(); err != nil {
		b.Fatal(err)
	}
	c, _ := NewCall("a", "b", "question")
	for i := 0; i < 200; i++ {
		AppendTurn(c, "a", strings.Repeat("some words in a turn ", 12), false)
	}
	for i := 0; i < 280; i++ {
		NewCall("a", "b", fmt.Sprintf("call %d", i))
	}
	v := &view{st: loadState(), sel: 0}
	for i := 0; i < b.N; i++ {
		v.scroll = i % 200
		v.frameLines(50, 200)
	}
}

func isZeroWidthForTest(r rune) bool {
	if r == 0x200d || r == 0xfe0f {
		return true
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r)
}
