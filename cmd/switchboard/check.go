package main

// #include "bridge.h"
import "C"

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
)

func check() error {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		return err
	}
	defer screen.Fini()
	screen.SetSize(90, 25)
	initBoard()
	defer C.board_close()

	draw := func(in input) string {
		frame(screen, in, 50*time.Millisecond)
		var text strings.Builder
		width, height := screen.Size()
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				r, _, _, n := screen.GetContent(x, y)
				text.WriteRune(r)
				x += max(0, n-1)
			}
			text.WriteByte('\n')
		}
		return text.String()
	}
	idle := input{x: -1, y: -1}
	initial := draw(idle)
	for _, label := range []string{"Switchboard", "View", "Calls", "Transcript", "copper lantern finch", "╔", "║", "╚", "╝"} {
		if !strings.Contains(initial, label) {
			return fmt.Errorf("missing %q in prototype frame\n%s", label, initial)
		}
	}
	rows := strings.Split(initial, "\n")
	const leftEdge, leftEnd, rightEdge, rightEnd = 1, 29, 31, 88
	for y := 3; y < 23; y++ {
		row := []rune(rows[y])
		if row[0] != ' ' || row[89] != ' ' || row[30] != ' ' {
			return fmt.Errorf("expected a one-cell gutter on row %d", y)
		}
		for _, x := range []int{leftEdge, leftEnd, rightEdge, rightEnd} {
			if row[x] != '║' {
				return fmt.Errorf("missing side at (%d,%d)\n%s", x, y, initial)
			}
		}
	}
	for _, bounds := range [][2]int{{leftEdge, leftEnd}, {rightEdge, rightEnd}} {
		start, end := bounds[0], bounds[1]
		top, bottom := []rune(rows[2]), []rune(rows[23])
		if !strings.HasPrefix(string(top[start:end+1]), "╔═╡█╞══╡") || top[end] != '╗' ||
			string(bottom[start:end+1]) != "╚"+strings.Repeat("═", end-start-1)+"╝" {
			return fmt.Errorf("incorrect frame caps\n%s", initial)
		}
	}
	checkInk := func(x, y int, want int32) error {
		_, _, style, _ := screen.GetContent(x, y)
		fg, _, _ := style.Decompose()
		if fg != tcell.NewHexColor(want) {
			return fmt.Errorf("foreground at (%d,%d) is #%06x, want #%06x", x, y, fg.Hex(), want)
		}
		return nil
	}
	// Color assertions read the final tcell cells, after ImTUI palette conversion.
	for _, ink := range []struct {
		row  int
		name string
		rgb  int32
	}{{6, "codex-peer", 0x99d5fb}, {8, "codex", 0x75fb4c}} {
		at := strings.Index(rows[ink.row], ink.name)
		if at < 0 {
			return fmt.Errorf("missing speaker %s", ink.name)
		}
		if err := checkInk(len([]rune(rows[ink.row][:at])), ink.row, ink.rgb); err != nil {
			return err
		}
	}
	background := func(x, y int) tcell.Color {
		_, _, style, _ := screen.GetContent(x, y)
		_, bg, _ := style.Decompose()
		return bg
	}
	for _, y := range []int{3, 11, 22} {
		for _, x := range []int{leftEdge, rightEdge} {
			if background(x-1, y) == background(x, y) || background(x, y) != background(x+1, y) {
				return fmt.Errorf("pane background is offset at column %d, row %d", x, y)
			}
		}
	}
	if strings.Contains(draw(input{x: -1, y: -1, toggleChat: true}), "copper lantern finch") {
		return fmt.Errorf("collapsed pane still renders transcript")
	}
	draw(input{x: -1, y: -1, toggleChat: true})
	// The third call is the Unicode fixture.
	draw(input{x: 7, y: 14})
	draw(input{x: 7, y: 14, down: true})
	unicodeFrame := draw(input{x: 7, y: 14})
	for _, label := range []string{"Příliš žluťoučký kůň", "界", "東京", "🐦"} {
		if !strings.Contains(unicodeFrame, label) {
			return fmt.Errorf("missing %q in Unicode fixture\n%s", label, unicodeFrame)
		}
	}
	click := func(x, y int) string {
		draw(input{x: x, y: y})
		draw(input{x: x, y: y, down: true})
		return draw(input{x: x, y: y})
	}
	drag := func(x, y, toX, toY int) string {
		draw(input{x: x, y: y})
		draw(input{x: x, y: y, down: true})
		draw(input{x: toX, y: toY, down: true})
		return draw(input{x: toX, y: toY})
	}
	menuX := strings.Index(rows[0], "Switchboard")
	if menuX < 0 || strings.TrimSpace(rows[1]) != "" || background(60, 0) == background(60, 1) || background(60, 1) != background(0, 24) {
		return fmt.Errorf("expected a one-row menu\n%s", initial)
	}
	if err := checkInk(menuX, 0, 0xffff97); err != nil {
		return err
	}
	opened := click(menuX+1, 0)
	if menuX < 0 || !strings.Contains(opened, "Quit") {
		return fmt.Errorf("Switchboard menu did not open\n%s", opened)
	}
	for y, row := range strings.Split(opened, "\n") {
		if x := strings.Index(row, "Quit"); x >= 0 {
			if err := checkInk(len([]rune(row[:x])), y, 0xea3323); err != nil {
				return err
			}
			break
		}
	}
	click(86, 0)
	draw(idle)
	if err := checkInk(4, 2, 0x5f5f84); err != nil {
		return err
	}
	draw(input{x: 4, y: 2})
	if err := checkInk(4, 2, 0x73adf9); err != nil {
		return err
	}
	draw(input{x: 4, y: 2, down: true})
	if err := checkInk(4, 2, 0x0f87fa); err != nil {
		return err
	}
	draw(input{x: 4, y: 2})
	collapsed := draw(idle)
	if strings.Contains(collapsed, "Idle wake trial") {
		return fmt.Errorf("title-bar button did not collapse the Calls pane\n%s", collapsed)
	}
	for i := 0; i < 6; i++ {
		draw(idle)
	}
	click(4, 2)
	for i := 0; i < 6; i++ {
		draw(idle)
	}
	moved := drag(8, 2, 11, 3)
	if strings.Index(strings.Split(moved, "\n")[3], "Calls") < 0 {
		return fmt.Errorf("drag did not move the Calls pane\n%s", moved)
	}
	resized := drag(32, 24, 39, 24)
	if strings.IndexRune(strings.Split(resized, "\n")[3], '╗') <= strings.IndexRune(strings.Split(moved, "\n")[3], '╗') {
		return fmt.Errorf("resize did not widen the Calls frame\n%s", resized)
	}
	screen.SetSize(110, 32)
	if enlarged := draw(idle); !strings.Contains(enlarged, "Transcript") || []rune(strings.Split(enlarged, "\n")[30])[108] != '╝' {
		return fmt.Errorf("terminal resize lost the transcript or its outer gutters\n%s", enlarged)
	}
	C.board_close()
	initBoard()
	screen.SetSize(124, 32)
	live := boardSnapshot{
		Line: "test-live-line", TranscriptID: "first", Transcript: "test-peer · TURN #12 · 12:00\nLive transcript with 東京", TranscriptInks: "g ",
		Calls:    []callSnapshot{{ID: "first", Subject: "First live call", Participants: "test-peer ⇄ another-peer", Status: "open", Floor: "test-peer", Route: "Local call"}, {ID: "second", Subject: "Second live call", Participants: "other ⇄ test-peer", Status: "resolved", Route: "Local call"}},
		Overview: []string{"Checkpoint 71"}, OverviewInks: "b", Topology: []string{"Actor topology"},
	}
	applySnapshot(live, "")
	liveFrame := draw(idle)
	for _, label := range []string{"› First live call", "☏ Second live call", "│ test-peer ⇄ another-peer", "│ open · Floor: test-peer", "│ Local call", "Live transcript with 東京", "Line status", "Checkpoint 71"} {
		if !strings.Contains(liveFrame, label) {
			return fmt.Errorf("missing %q from live snapshot frame\n%s", label, liveFrame)
		}
	}
	// Body text should line up with the transcript divider above it.
	liveRows := strings.Split(liveFrame, "\n")
	messageAt := strings.Index(liveRows[9], "test-peer · TURN")
	if messageAt < 0 {
		return fmt.Errorf("missing first message beneath divider")
	}
	start := len([]rune(liveRows[9][:messageAt]))
	rule := []rune(liveRows[8])
	if rule[start] != '─' || rule[start-1] == '─' {
		return fmt.Errorf("transcript body begins at %d, out of line with its divider\n%s", start, liveFrame)
	}
	for label, want := range map[string]int32{
		"test-peer · TURN #12": 0x75fb4c, "Checkpoint 71": 0x99d5fb,
		"Floor: test-peer": 0x75fb4c, "test-peer ⇄ another-peer": 0x99d5fb,
	} {
		found := false
		for y, row := range strings.Split(liveFrame, "\n") {
			if offset := strings.Index(row, label); offset >= 0 {
				if err := checkInk(len([]rune(row[:offset])), y, want); err != nil {
					return err
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing styled field %q", label)
		}
	}
	for y, row := range strings.Split(liveFrame, "\n") {
		if x := strings.Index(row, "Second live call"); x >= 0 {
			click(len([]rune(row[:x]))+1, y)
			break
		}
	}
	if int(C.board_selected()) != 1 {
		return fmt.Errorf("could not select second live call")
	}
	switched := draw(idle)
	if !strings.Contains(switched, "☏ First live call") || !strings.Contains(switched, "› Second live call") {
		return fmt.Errorf("call markers did not follow selection")
	}
	// Deliver the selected call's full history after the click, as the live stream does.
	// Check following to the tail across a width change, then switching back to a short call.
	live.TranscriptID = "second"
	live.Transcript = strings.Repeat("An ordinary wrapped message from the other workstation. ", 2400) +
		"\n\nLast entry 東京"
	applySnapshot(live, "second")
	for _, width := range []int{124, 80, 150} {
		screen.SetSize(width, 32)
		draw(idle)
		if rendered := draw(idle); !strings.Contains(rendered, "Last entry 東京") {
			return fmt.Errorf("follow lost the long transcript tail at width %d", width)
		}
	}
	// The header and both corners of the bottom frame stay fixed as the body scrolls.
	beforeWheel := draw(idle)
	wheel := input{x: 65, y: 18, wheel: 5}
	draw(wheel)
	afterWheel := draw(idle)
	beforeRows, afterRows := strings.Split(beforeWheel, "\n"), strings.Split(afterWheel, "\n")
	for y := 2; y <= 8; y++ {
		if beforeRows[y] != afterRows[y] {
			return fmt.Errorf("transcript header moved at row %d", y)
		}
	}
	if !strings.Contains(beforeRows[30], "╚"+strings.Repeat("═", 150-36-38-4)+"╝") || beforeRows[30] != afterRows[30] {
		return fmt.Errorf("damaged transcript bottom edge: %s", afterRows[30])
	}
	if strings.Contains(afterWheel, "Last entry 東京") {
		return fmt.Errorf("wheel did not scroll the conversation")
	}
	// The SHF-style button keeps its label; its adjacent lamp tracks following.
	followRow := afterRows[7]
	labelOffset := strings.Index(followRow, "Follow")
	if labelOffset < 0 {
		return fmt.Errorf("missing Follow button")
	}
	lampOffset := strings.LastIndex(followRow[:labelOffset], "█")
	if lampOffset < 0 {
		return fmt.Errorf("missing Follow lamp")
	}
	lampX := len([]rune(followRow[:lampOffset]))
	buttonX := len([]rune(followRow[:labelOffset])) + 1
	if background(lampX+1, 7) != background(buttonX, 7) || background(lampX-1, 7) == background(buttonX, 7) {
		return fmt.Errorf("Follow button does not meet its lamp")
	}
	if err := checkInk(lampX, 7, 0xea3323); err != nil {
		return err
	}
	live.Transcript += "\nNewest follow check"
	applySnapshot(live, "second")
	draw(idle)
	if paused := draw(idle); strings.Contains(paused, "Newest follow check") {
		return fmt.Errorf("scrolling up did not pause following")
	}
	draw(input{x: 65, y: 18, wheel: -1})
	if err := checkInk(lampX, 7, 0xea3323); err != nil {
		return err
	}
	draw(input{x: 65, y: 18, wheel: -20})
	if err := checkInk(lampX, 7, 0x75fb4c); err != nil {
		return err
	}
	live.Transcript += "\nAutomatic follow resumed"
	applySnapshot(live, "second")
	draw(idle)
	if resumed := draw(idle); !strings.Contains(resumed, "Automatic follow resumed") {
		return fmt.Errorf("scrolling to the bottom did not resume following")
	}
	click(buttonX, 7)
	live.Transcript += strings.Repeat("\nManual pause check", 40) + "\nManual resume check"
	applySnapshot(live, "second")
	draw(idle)
	if paused := draw(idle); strings.Contains(paused, "Manual resume check") {
		return fmt.Errorf("manual pause at the bottom was overridden")
	}
	if err := checkInk(lampX, 7, 0xea3323); err != nil {
		return err
	}
	click(buttonX, 7)
	if resumed := draw(idle); !strings.Contains(resumed, "Manual resume check") {
		return fmt.Errorf("Follow button did not resume at the newest entry")
	}
	if err := checkInk(lampX, 7, 0x75fb4c); err != nil {
		return err
	}
	click(9, 6)
	if int(C.board_selected()) != 0 {
		return fmt.Errorf("could not return to the first live call")
	}
	live.TranscriptID, live.Transcript = "first", "Short transcript again"
	applySnapshot(live, "first")
	draw(idle)
	if rendered := draw(idle); !strings.Contains(rendered, live.Transcript) {
		return fmt.Errorf("switching from the long call lost the short transcript")
	}
	live.Calls[0], live.Calls[1] = live.Calls[1], live.Calls[0]
	if selected := applySnapshot(live, "second"); selected != "second" || int(C.board_selected()) != 0 {
		return fmt.Errorf("live refresh lost selection across reorder")
	}
	live.Health = []string{"Verified relay checkpoint"}
	live.Topology = []string{"Workstation topology"}
	live.Broadcasts = []string{"Operator briefing"}
	live.Roadmaps = []string{"Station one"}
	applySnapshot(live, "second")
	for i, want := range []string{"Workstation topology", "Verified relay checkpoint", "Operator briefing", "Station one", "Inspect signed descriptor"} {
		C.board_toggle_view(C.int(i))
		draw(idle)
		if !strings.Contains(draw(idle), want) {
			return fmt.Errorf("window %d did not show %q", i, want)
		}
		C.board_toggle_view(C.int(i))
		draw(idle)
	}
	fmt.Println("Switchboard views, ImTUI palette, minimizer states, one-row menu, frame spacing, drag, resize, selection and Unicode verified")
	return nil
}
