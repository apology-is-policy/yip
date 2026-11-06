package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func seedMapLine(t *testing.T) {
	t.Helper()
	t.Setenv("YIP_ROOT", t.TempDir())
	if err := EnsureRoot(); err != nil {
		t.Fatal(err)
	}
}

func line(names ...string) []RoadmapStation {
	var out []RoadmapStation
	for _, n := range names {
		out = append(out, RoadmapStation{Name: n, Description: "about " + n})
	}
	return out
}

func TestRoadmapRefusals(t *testing.T) {
	seedMapLine(t)
	long := strings.Repeat("x", 500)
	var many []string
	for i := 0; i < roadmapPostedMax+1; i++ {
		many = append(many, fmt.Sprintf("s%d", i))
	}
	for what, r := range map[string]Roadmap{
		"no arc":         {Stations: line("a")},
		"no stations":    {Arc: "x"},
		"blank station":  {Arc: "x", Stations: line(" ")},
		"long name":      {Arc: "x", Stations: line(long)},
		"too many":       {Arc: "x", Stations: line(many...)},
		"same id":        {Arc: "x", Stations: line("a", "a")},
		"unknown active": {Arc: "x", Stations: line("a"), Active: "b"},
		"unknown detour": {Arc: "x", Stations: []RoadmapStation{{Name: "a"}, {Name: "b", Detour: "c"}}},
		"detour of a detour": {Arc: "x", Stations: []RoadmapStation{
			{Name: "a"}, {Name: "b", Detour: "a"}, {Name: "c", Detour: "b"}}},
		"bad state": {Arc: "x", Stations: []RoadmapStation{{Name: "a", State: "active"}}},
	} {
		if _, err := PostRoadmap("aux", r); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	if _, ok, _ := LoadRoadmap("aux"); ok {
		t.Fatal("a refused post left a file")
	}
	if _, err := PostRoadmap("../evil", Roadmap{Arc: "x", Stations: line("a")}); err == nil {
		t.Fatal("a path in an agent name was accepted")
	}
}

func TestStationStatesAndTheMarker(t *testing.T) {
	seedMapLine(t)
	r, err := PostRoadmap("aux", Roadmap{Arc: "arc", Active: "b", Stations: []RoadmapStation{
		{Name: "a"}, {Name: "a side", Detour: "a"}, {Name: "b"}, {Name: "b one", Detour: "b"}, {Name: "b two", Detour: "b"}, {Name: "c"}, {Name: "d", State: "skipped"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := func(r Roadmap, exp ...string) {
		t.Helper()
		got := stationStates(r)
		if strings.Join(got, " ") != strings.Join(exp, " ") {
			t.Fatalf("states %v, want %v", got, exp)
		}
	}
	// A detour behind the marker that nobody took reads as not taken, never as travelled.
	want(r, stationPassed, stationSkipped, stationActive, stationAhead, stationAhead, stationAhead, stationSkipped)

	// On a detour: its main station is behind, the earlier stop done, the later ahead.
	if r, err = MoveRoadmap("aux", "b two", "note", false); err != nil {
		t.Fatal(err)
	}
	want(r, stationPassed, stationSkipped, stationPassed, stationPassed, stationActive, stationAhead, stationSkipped)
	if r.Note != "note" {
		t.Fatal("note not kept")
	}
	// Leaving the detour marks it done, so it stays travelled once it is behind.
	if r, err = MoveRoadmap("aux", "c", "", false); err != nil {
		t.Fatal(err)
	}
	want(r, stationPassed, stationSkipped, stationPassed, stationPassed, stationPassed, stationActive, stationSkipped)
	if r.Note != "" {
		t.Fatal("a move without a note kept the old one")
	}
	// Staying put is allowed: omitting the station keeps the marker.
	if r, err = MoveRoadmap("aux", "", "still here", false); err != nil || r.Active != "c" || r.Note != "still here" {
		t.Fatal(err, r.Active, r.Note)
	}
	if _, err = MoveRoadmap("aux", "nowhere", "", false); err == nil || !strings.Contains(err.Error(), "a-side") {
		t.Fatalf("an unknown station should name the real ones: %v", err)
	}
	if r, err = MoveRoadmap("aux", "", "", true); err != nil || !r.Done || r.Active != "" {
		t.Fatal(err, r.Done, r.Active)
	}
	for _, s := range stationStates(r) {
		if s == stationActive || s == stationAhead {
			t.Fatalf("a finished arc still has %s", s)
		}
	}
	if _, err = MoveRoadmap("corona", "a", "", false); err == nil {
		t.Fatal("moved a marker on a roadmap never posted")
	}
}

// The fold's promises, over many shapes: never more than the limit, nothing lost, the order kept, and
// the places a glance is for always there.
func TestCompactRoadmapProperties(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for trial := 0; trial < 4000; trial++ {
		nMain := 1 + rng.Intn(40)
		var st []RoadmapStation
		var mainNames []string
		for i := 0; i < nMain; i++ {
			name := fmt.Sprintf("m%d", i)
			mainNames = append(mainNames, name)
			st = append(st, RoadmapStation{ID: name, Name: name})
			if rng.Intn(4) == 0 {
				for d := 0; d < 1+rng.Intn(9); d++ {
					dn := fmt.Sprintf("m%d-d%d", i, d)
					st = append(st, RoadmapStation{ID: dn, Name: dn, Detour: name})
				}
			}
		}
		r := Roadmap{Agent: "a", Arc: "x", Stations: st}
		switch rng.Intn(10) {
		case 0:
			r.Done = true
		case 1:
		default:
			r.Active = st[rng.Intn(len(st))].ID
		}
		shown := compactRoadmap(r, roadmapShownMax)
		if len(shown) > roadmapShownMax {
			t.Fatalf("trial %d: %d points from %d stations (active %q)", trial, len(shown), len(st), r.Active)
		}
		total, sawActive := 0, false
		last := -1
		pos := map[string]int{}
		for i, s := range st {
			pos[s.Name] = i
		}
		for _, s := range shown {
			if s.Folded > 0 {
				total += s.Folded
				if len(s.Members) != s.Folded {
					t.Fatalf("trial %d: a fold of %d names %d", trial, s.Folded, len(s.Members))
				}
				continue
			}
			total++
			if s.ID == r.Active {
				sawActive = true
			}
			if p := pos[s.Name]; p < last {
				t.Fatalf("trial %d: order changed at %s", trial, s.Name)
			} else {
				last = p
			}
		}
		if total != len(st) {
			t.Fatalf("trial %d: %d stations accounted for of %d", trial, total, len(st))
		}
		if r.Active != "" && !sawActive {
			t.Fatalf("trial %d: the active station %q was folded away", trial, r.Active)
		}
		if shown[0].Name != mainNames[0] {
			t.Fatalf("trial %d: the start is gone: %s", trial, shown[0].Name)
		}
		var end string
		for _, s := range shown {
			if s.Detour == "" {
				end = s.Name
			}
		}
		if end != mainNames[len(mainNames)-1] {
			t.Fatalf("trial %d: the end is gone: %s", trial, end)
		}
	}
}

func TestCompactLeavesAShortLineAlone(t *testing.T) {
	var names []string
	for i := 0; i < roadmapShownMax; i++ {
		names = append(names, fmt.Sprintf("s%d", i))
	}
	r := Roadmap{Arc: "x", Active: "s5", Stations: line(names...)}
	for i := range r.Stations {
		r.Stations[i].ID = r.Stations[i].Name
	}
	shown := compactRoadmap(r, roadmapShownMax)
	for _, s := range shown {
		if s.Folded > 0 {
			t.Fatal("twelve stations were folded")
		}
	}
	r.Stations = append(r.Stations, RoadmapStation{ID: "s12", Name: "s12"})
	folds := 0
	for _, s := range compactRoadmap(r, roadmapShownMax) {
		if s.Folded > 0 {
			folds++
		}
	}
	if folds == 0 {
		t.Fatal("thirteen stations were not folded")
	}
}

func mapView(t *testing.T) *view {
	t.Helper()
	seedMapLine(t)
	_, err := PostRoadmap("aux", Roadmap{Arc: "Thread model", Description: "One line about the arc.", Active: "c8", Note: "lease running", Stations: []RoadmapStation{
		{Name: "C4", Description: "thread-directed notes"},
		{Name: "11c", Description: "a native table"},
		{Name: "pins", Detour: "11c", Description: "two stale pins", State: "done"},
		{ID: "c8", Name: "C8a", Description: "the torpor key"},
		{Name: "C10"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PostRoadmap("main", Roadmap{Arc: "Boosty", Stations: line("one", "two")}); err != nil {
		t.Fatal(err)
	}
	return &view{by: "op", st: loadState(), mapPicked: -1}
}

func TestMapScreenShowsTheLineAndTheMarker(t *testing.T) {
	v := mapView(t)
	v.key('5')
	if v.tab != 4 {
		t.Fatal("5 did not open the map")
	}
	rows := v.frameLines(40, 160)
	if v.panes.centerW != 160 || v.panes.railW != 0 || v.panes.sideW != 0 {
		t.Fatalf("the map should have the whole width: %+v", v.panes)
	}
	text := terminalTextLines(rows)
	for _, want := range []string{"Thread model", "One line about the arc.", "C4", "11c", "C8a", "C10", "NOW", "the torpor key", "lease running", "Boosty", "NOT STARTED", "◉", "●", "○", "┗━", "pins"} {
		if !strings.Contains(text, want) {
			t.Errorf("the map lost %q", want)
		}
	}
	lit := "\033[1m\033[7m"
	joined := strings.Join(rows, "\n")
	if colors().enabled && !strings.Contains(joined, lit) {
		t.Error("the active station is not lit")
	}
	for i, r := range rows {
		if w := plainWidth(r); w > 160 {
			t.Fatalf("row %d is %d cells on a 160 terminal", i, w)
		}
	}
}

func terminalTextLines(rows []string) string { return stripSGR(strings.Join(rows, "\n")) }

func TestMapDrawsUprightWhenNarrow(t *testing.T) {
	v := mapView(t)
	var many []string
	for i := 0; i < 12; i++ {
		many = append(many, fmt.Sprintf("station %d", i))
	}
	if _, err := PostRoadmap("aux", Roadmap{Arc: "long", Active: "station-3", Stations: line(many...)}); err != nil {
		t.Fatal(err)
	}
	v.refresh(loadState())
	v.tab = 4
	for _, cols := range []int{40, 60, 85, 200} {
		rows := v.frameLines(30, cols)
		for i, r := range rows {
			if w := plainWidth(r); w > cols {
				t.Fatalf("%d cols: row %d is %d cells", cols, i, w)
			}
		}
		if !strings.Contains(terminalTextLines(rows), "NOW") {
			t.Fatalf("%d cols: no NOW line", cols)
		}
	}
}

func TestMapTextCannotReachTheTerminal(t *testing.T) {
	seedMapLine(t)
	evil := "x\033]52;c;aGVsbG8=\007y\033[2Jz"
	if _, err := PostRoadmap("aux", Roadmap{Arc: evil, Description: evil, Active: "a", Note: evil,
		Stations: []RoadmapStation{{ID: "a", Name: evil, Description: evil}}}); err != nil {
		t.Fatal(err)
	}
	check := func(mode string) {
		t.Helper()
		v := &view{by: "op", st: loadState(), tab: 4, mapPicked: -1}
		out := strings.Join(v.frameLines(30, 120), "")
		for _, bad := range []string{"\033]", "\033[2J", "\007"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s: %q reached the frame", mode, bad)
			}
		}
		if !strings.Contains(stripSGR(out), "xyz") {
			t.Fatalf("%s: the text itself was lost", mode)
		}
	}
	t.Setenv("TERM", "xterm-256color")
	os.Unsetenv("NO_COLOR")
	check("colour")
	t.Setenv("NO_COLOR", "1")
	check("no colour")
	s, _ := RoadmapText("aux")
	if strings.ContainsAny(s, "\033\007") {
		t.Fatal("control bytes in the plain form")
	}
}

func TestMapFocusAndClick(t *testing.T) {
	v := mapView(t)
	v.key('5')
	v.frameLines(40, 160)
	if v.roadmapFocus() != "aux" {
		t.Fatal("focus should start on the first line")
	}
	v.key('n')
	v.frameLines(40, 160)
	if v.roadmapFocus() != "main" {
		t.Fatal("n did not move the focus")
	}
	if !strings.Contains(terminalTextLines(v.frameLines(40, 160)), "STATIONS · main") {
		t.Fatal("the list did not follow the focus")
	}
	v.key('p')
	v.frameLines(40, 160)
	// Click C8a on the rail: find its hit, and click through the real geometry.
	var h *sbMapHit
	shown := compactRoadmap(v.st.roadmaps[0], roadmapShownMax)
	for i := range v.mapHits {
		x := v.mapHits[i]
		if x.agent == "aux" && x.station >= 0 && shown[x.station].Name == "C8a" {
			h = &x
			break
		}
	}
	if h == nil {
		t.Fatal("no hit box for C8a")
	}
	v.mouse(sbMouse{x: v.panes.centerX + 2 + h.x0, y: v.panes.top + h.line})
	if v.mapPicked != h.station || v.mapFocus != "aux" {
		t.Fatalf("clicking C8a picked %d", v.mapPicked)
	}
	if !strings.Contains(terminalTextLines(v.frameLines(40, 160)), "▸") {
		t.Fatal("the picked station is not marked")
	}
	// The row right below a header is the rail, so a click on a header proves which row the geometry
	// reached: it focuses the line and picks no station.
	var head *sbMapHit
	for i := range v.mapHits {
		if x := v.mapHits[i]; x.agent == "main" && x.station == -1 {
			head = &x
			break
		}
	}
	if head == nil {
		t.Fatal("no hit box for main's header")
	}
	v.mouse(sbMouse{x: v.panes.centerX + 2 + 2, y: v.panes.top + head.line})
	if v.mapFocus != "main" || v.mapPicked != -1 {
		t.Fatalf("a click on main's header gave focus %q, station %d", v.mapFocus, v.mapPicked)
	}
}

func TestMapIsSafeWithNothingPostedAndHidesTheRetired(t *testing.T) {
	seedMapLine(t)
	v := &view{by: "op", st: loadState(), tab: 4, mapPicked: -1}
	if !strings.Contains(terminalTextLines(v.frameLines(30, 100)), "No lines on the map yet") {
		t.Fatal("an empty map should say so")
	}
	v.key('n')
	v.mouse(sbMouse{x: 5, y: 7})
	if _, err := PostRoadmap("gone", Roadmap{Arc: "x", Stations: line("a")}); err != nil {
		t.Fatal(err)
	}
	if err := Retire("gone", true); err != nil {
		t.Fatal(err)
	}
	if len(ListRoadmaps()) != 0 {
		t.Fatal("a retired agent is still on the map")
	}
}

func TestDashboardGlance(t *testing.T) {
	v := mapView(t)
	if got := v.roadmapOneLine("aux"); !strings.Contains(got, "C8a") || !strings.Contains(got, "Thread model") {
		t.Fatalf("glance %q", got)
	}
	if got := v.roadmapOneLine("nobody"); got != "" {
		t.Fatalf("glance for no roadmap: %q", got)
	}
}

func TestToolsWriteOnlyTheCallersLine(t *testing.T) {
	seedMapLine(t)
	args := map[string]any{"arc": "x", "active": "a", "stations": []any{
		map[string]any{"name": "a", "description": "first"},
		map[string]any{"name": "b"},
	}}
	out, handled, err := coordinationCall("aux", "roadmap_post", args)
	if err != nil || !handled || !strings.Contains(out, "at a") {
		t.Fatal(out, handled, err)
	}
	if _, ok, _ := LoadRoadmap("corona"); ok {
		t.Fatal("wrote someone else's line")
	}
	if out, _, err = coordinationCall("aux", "roadmap_at", map[string]any{"station": "b", "note": "n"}); err != nil || !strings.Contains(out, "at b") {
		t.Fatal(out, err)
	}
	if out, _, err = coordinationCall("corona", "roadmaps", map[string]any{"agent": "aux"}); err != nil || !strings.Contains(out, "first") {
		t.Fatal(out, err)
	}
	bad := map[string]any{"arc": "x", "stations": []any{map[string]any{"name": "a", "colour": "red"}}}
	if _, _, err = coordinationCall("aux", "roadmap_post", bad); err == nil {
		t.Fatal("an unknown field was silently dropped")
	}
	if _, _, err = coordinationCall("aux", "roadmap_clear", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := LoadRoadmap("aux"); ok {
		t.Fatal("not cleared")
	}
}

func TestToolsAreAdvertised(t *testing.T) {
	names := map[string]bool{}
	for _, d := range tools() {
		names[d.Name] = true
	}
	for _, n := range []string{"roadmap_post", "roadmap_at", "roadmaps", "roadmap_clear"} {
		if !names[n] {
			t.Errorf("%s is not advertised", n)
		}
	}
}

func TestNudgeIsRareAndStopsWhenKept(t *testing.T) {
	seedMapLine(t)
	if roadmapNudge("aux") == "" {
		t.Fatal("no roadmap: the first call should nudge")
	}
	if roadmapNudge("aux") != "" {
		t.Fatal("nudged twice in a row")
	}
	if err := os.Remove(roadmapNudgePath("aux")); err != nil {
		t.Fatal(err)
	}
	if _, err := PostRoadmap("aux", Roadmap{Arc: "x", Stations: line("a")}); err != nil {
		t.Fatal(err)
	}
	if roadmapNudge("aux") != "" {
		t.Fatal("a fresh roadmap was nudged")
	}
}
