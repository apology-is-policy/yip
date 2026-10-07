package main

import (
	"fmt"
	"strings"
	"testing"
)

func feedInput(v *view, s string) {
	var d sbInputDecoder
	for _, r := range s {
		for _, e := range d.feed(r) {
			v.handleInput(e)
		}
	}
}

func longMouseView(t *testing.T, cols int) *view {
	t.Helper()
	tmpLine(t)
	v := demoView()
	for i := 0; i < 20; i++ {
		v.st.calls = append(v.st.calls, &sbCall{call: &Call{ID: fmt.Sprint(i), From: "a", To: "b", Subject: fmt.Sprint("Call ", i)}, floor: "b", status: "open"})
	}
	v.st.calls[0].entries[0].body = strings.Repeat("A long message.\n", 100)
	v.frameLines(24, cols)
	return v
}

func TestSGRMouseDecoderAndKeyboard(t *testing.T) {
	var d sbInputDecoder
	var events []sbInput
	// One rune at a time: packets can arrive across multiple terminal reads.
	for _, r := range "\033[<65;130;9M\033[<0;4;8m\033[A界" {
		events = append(events, d.feed(r)...)
	}
	if len(events) != 4 {
		t.Fatalf("events: %+v", events)
	}
	m := events[0].mouse
	if m == nil || m.button != 65 || m.x != 129 || m.y != 8 || m.release {
		t.Fatalf("wheel: %+v", m)
	}
	if events[1].mouse == nil || !events[1].mouse.release {
		t.Fatal("release lost")
	}
	if !events[2].arrow || events[2].key != 'k' || events[3].key != '界' {
		t.Fatal("keyboard changed")
	}
	for _, bad := range []string{"\033[<0;0;8M", "\033[<0;2M", "\033[<0;-1;8M", "\033[<0;999999999999999999999;8M", "\033[" + strings.Repeat("1", 100) + "M", "\033[200~"} {
		for _, r := range bad {
			if e := d.feed(r); len(e) > 0 {
				t.Fatalf("bad packet became input: %q %+v", bad, e)
			}
		}
		if e := d.feed('x'); len(e) != 1 || e[0].key != 'x' {
			t.Fatal("decoder did not recover")
		}
	}
}

func TestMouseScrollTargetsOnlyPaneUnderPointer(t *testing.T) {
	v := longMouseView(t, 160)
	v.follow = true
	v.frameLines(24, 160)
	chat := v.scroll
	feedInput(v, "\033[<65;4;10M")
	if v.railScroll != 3 || v.sideScroll != 0 || v.scroll != chat || !v.follow {
		t.Fatal("rail wheel moved chat or disabled follow")
	}
	feedInput(v, "\033[<65;150;10M")
	if v.sideScroll != 3 || v.railScroll != 3 || v.scroll != chat || !v.follow {
		t.Fatal("side wheel moved another pane")
	}
	feedInput(v, "\033[<64;60;10M")
	if v.scroll != chat-3 || v.follow {
		t.Fatal("chat wheel failed to suspend follow")
	}
	for i := 0; i < 100; i++ {
		feedInput(v, "\033[<65;150;10M")
	}
	v.frameLines(24, 160)
	if v.sideScroll != v.panes.sideLen-v.panes.height {
		t.Fatal("side bottom not clamped")
	}
	for i := 0; i < 100; i++ {
		feedInput(v, "\033[<64;150;10M")
	}
	if v.sideScroll != 0 {
		t.Fatal("side top not clamped")
	}
}

func TestMouseSelectsVisibleCallAfterScrollAndResize(t *testing.T) {
	v := longMouseView(t, 160)
	feedInput(v, "\033[<65;4;10M") // offset 3: row 7 shows the second call
	v.frameLines(24, 160)
	feedInput(v, "\033[<0;4;8M")
	if v.sel != 1 || v.selD != 0 || !v.follow {
		t.Fatalf("selected %d, want 1", v.sel)
	}
	// Narrow screens expose the same scrollable/clickable list with key 3.
	v.key('3')
	v.frameLines(24, 80)
	feedInput(v, "\033[<0;4;11M")
	if v.sel != 2 || v.tab != 0 {
		t.Fatalf("narrow selection: %d tab %d", v.sel, v.tab)
	}
	v.frameLines(24, 160)
	before := v.sel
	for _, packet := range []string{"\033[<0;28;8M", "\033[<0;4;1M", "\033[<0;4;24M", "\033[<0;4;8m", "\033[<32;4;8M"} {
		feedInput(v, packet)
	}
	if v.sel != before {
		t.Fatal("border, release or motion selected a call")
	}
	v.frameLines(6, 20)
	feedInput(v, "\033[<0;4;8M")
	if v.sel != before {
		t.Fatal("tiny terminal has a hit target")
	}
}

func TestMouseCannotRetargetOrPolluteHumanPrompt(t *testing.T) {
	tmpLine(t)
	a, _ := NewCall("a", "b", "first")
	b, _ := NewCall("a", "b", "second")
	v := &view{by: "operator", st: sbState{calls: []*sbCall{{call: a}, {call: b}}}}
	v.frameLines(24, 160)
	v.key('r')
	v.key('界')
	feedInput(v, "\033[<0;4;11M\033[<65;150;10M\033[B")
	if v.sel != 0 || string(v.input) != "界" || v.prompt == "" || v.sideScroll != 0 {
		t.Fatal("mouse/arrow affected prompt")
	}
	v.key('\r')
	notes, _ := Notes(a)
	wrong, _ := Notes(b)
	if len(notes) != 1 || strings.TrimSpace(notes[0].Body) != "界" || len(wrong) != 0 {
		t.Fatal("wrong decision destination or text")
	}
	for _, c := range []*Call{a, b} {
		turns, _ := Turns(c)
		if len(turns) != 0 {
			t.Fatal("mouse wrote an agent turn")
		}
	}
}

func TestFloorLabelsAndKeyboardReveal(t *testing.T) {
	v := longMouseView(t, 160)
	frame := strings.Join(v.frameLines(24, 160), "\n")
	if !strings.Contains(stripSGR(frame), "→ floor: main") {
		t.Fatal("floor missing")
	}
	v.st.calls[0].closed = true
	v.st.calls[0].status = "resolved"
	rail := strings.Join(v.callRail(25, colors()), "\n")
	if strings.Contains(stripSGR(rail), "floor: main") || !strings.Contains(stripSGR(rail), "— resolved") {
		t.Fatal("closed call claims a floor")
	}
	for i := 0; i < 18; i++ {
		v.key('n')
		v.frameLines(24, 160)
	}
	if v.sel != 18 || 2+3*v.sel < v.railScroll || 2+3*v.sel+2 >= v.railScroll+v.panes.height {
		t.Fatal("keyboard selection scrolled out of view")
	}
}
