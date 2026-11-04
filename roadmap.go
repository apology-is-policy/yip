package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// A roadmap is an agent's own statement of where it stands on its arc: a line of stations from start to
// end, with detours, and the one it is at. It exists so a person can look instead of asking. So it is
// observation only: it grants nothing, wakes nobody and rings nobody. An agent writes only its own.
//
// What was posted is kept whole. Folding it to roadmapShownMax happens when it is read, so a long arc
// loses nothing and an agent never has to do the folding itself.

const (
	roadmapShownMax      = 12
	roadmapPostedMax     = 64
	roadmapArcMax        = 80
	roadmapTextMax       = 600
	roadmapNameMax       = 40
	roadmapStationDesc   = 400
	roadmapNoteMax       = 240
	roadmapNudgeAfter    = 2 * time.Hour
	roadmapStaleAfter    = 6 * time.Hour
	roadmapAbandonedTime = 24 * time.Hour
)

// Where a station stands. A station's own state wins over its position: the line is a plan, and work does
// not always land in order.
const (
	stationPassed  = "passed"
	stationActive  = "active"
	stationAhead   = "ahead"
	stationSkipped = "skipped"
)

type RoadmapStation struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	State       string `json:"state,omitempty"`  // done, skipped or todo; empty means "by position"
	Detour      string `json:"detour,omitempty"` // the main-line station this branches from
}

type Roadmap struct {
	Agent       string           `json:"agent"`
	Arc         string           `json:"arc"`
	Description string           `json:"description,omitempty"`
	Stations    []RoadmapStation `json:"stations"`
	Active      string           `json:"active,omitempty"`
	Done        bool             `json:"done,omitempty"`
	Note        string           `json:"note,omitempty"`
	At          string           `json:"at"`
}

func roadmapDir() string               { return filepath.Join(Root(), "roadmaps") }
func roadmapPath(agent string) string  { return filepath.Join(roadmapDir(), agent+".json") }
func roadmapNudgePath(a string) string { return filepath.Join(roadmapDir(), a+".nudged") }

func tooLong(what, s string, limit int) error {
	if utf8.RuneCountInString(s) > limit {
		return fmt.Errorf("%s is over %d characters", what, limit)
	}
	return nil
}

// findStation matches an id exactly, then a name without regard to case. A name two stations share is
// refused here, so a marker can never land on a station the agent did not mean.
func findStation(stations []RoadmapStation, key string) (int, error) {
	key = strings.TrimSpace(key)
	for i := range stations {
		if stations[i].ID == key {
			return i, nil
		}
	}
	found := -1
	for i := range stations {
		if strings.EqualFold(stations[i].Name, key) {
			if found >= 0 {
				return -1, fmt.Errorf("two stations are named %q: use an id", key)
			}
			found = i
		}
	}
	if found >= 0 {
		return found, nil
	}
	ids := make([]string, 0, len(stations))
	for i := range stations {
		ids = append(ids, stations[i].ID)
	}
	return -1, fmt.Errorf("no station %q on this roadmap; it has: %s", key, strings.Join(ids, ", "))
}

func normalizeRoadmap(r *Roadmap) error {
	r.Arc = strings.TrimSpace(r.Arc)
	if r.Arc == "" {
		return fmt.Errorf("a roadmap needs its arc's name")
	}
	if err := tooLong("the arc's name", r.Arc, roadmapArcMax); err != nil {
		return err
	}
	if err := tooLong("the arc's description", r.Description, roadmapTextMax); err != nil {
		return err
	}
	if err := tooLong("the note", r.Note, roadmapNoteMax); err != nil {
		return err
	}
	if len(r.Stations) == 0 {
		return fmt.Errorf("a roadmap needs at least one station")
	}
	if len(r.Stations) > roadmapPostedMax {
		return fmt.Errorf("%d stations is over the %d a roadmap can hold; twelve are shown, and a longer line is folded for you", len(r.Stations), roadmapPostedMax)
	}
	seen := map[string]bool{}
	for i := range r.Stations {
		s := &r.Stations[i]
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" {
			return fmt.Errorf("station %d has no name", i+1)
		}
		if err := tooLong("station "+s.Name+"'s name", s.Name, roadmapNameMax); err != nil {
			return err
		}
		if err := tooLong("station "+s.Name+"'s description", s.Description, roadmapStationDesc); err != nil {
			return err
		}
		if s.ID = strings.TrimSpace(s.ID); s.ID == "" {
			s.ID = slugify(s.Name)
		}
		if s.ID == "" {
			s.ID = fmt.Sprintf("s%d", i+1)
		}
		if seen[s.ID] {
			return fmt.Errorf("two stations have the id %q", s.ID)
		}
		seen[s.ID] = true
		switch s.State {
		case "", "done", "skipped", "todo":
		default:
			return fmt.Errorf("station %s: state %q is not one of done, skipped, todo; the active station is named by active", s.Name, s.State)
		}
	}
	for i := range r.Stations {
		s := &r.Stations[i]
		if s.Detour == "" {
			continue
		}
		j, err := findStation(r.Stations, s.Detour)
		if err != nil {
			return fmt.Errorf("station %s's detour: %v", s.Name, err)
		}
		if r.Stations[j].Detour != "" {
			return fmt.Errorf("station %s branches from %s, which is itself a detour; a detour leaves the main line", s.Name, r.Stations[j].Name)
		}
		s.Detour = r.Stations[j].ID
	}
	if r.Active != "" {
		i, err := findStation(r.Stations, r.Active)
		if err != nil {
			return fmt.Errorf("active: %v", err)
		}
		if r.Stations[i].State == "skipped" {
			return fmt.Errorf("active: %s is marked skipped", r.Stations[i].Name)
		}
		r.Active = r.Stations[i].ID
	}
	return nil
}

func saveRoadmap(r Roadmap) error {
	if err := os.MkdirAll(roadmapDir(), 0o755); err != nil {
		return err
	}
	return writeState(roadmapPath(r.Agent), r)
}

// PostRoadmap replaces the agent's roadmap.
func PostRoadmap(agent string, r Roadmap) (Roadmap, error) {
	if !validComponent(agent) {
		return r, fmt.Errorf("invalid agent name")
	}
	r.Agent, r.At = agent, now()
	if err := normalizeRoadmap(&r); err != nil {
		return r, err
	}
	return r, saveRoadmap(r)
}

func LoadRoadmap(agent string) (Roadmap, bool, error) {
	var r Roadmap
	if !validComponent(agent) {
		return r, false, fmt.Errorf("invalid agent name")
	}
	if _, err := os.Stat(roadmapPath(agent)); err != nil {
		if os.IsNotExist(err) {
			return r, false, nil
		}
		return r, false, err
	}
	if err := readState(roadmapPath(agent), &r); err != nil {
		return r, false, err
	}
	return r, true, nil
}

// MoveRoadmap moves the marker: the cheap call that keeps a posted line true. Arriving at a station a
// second time is allowed and refreshes the time, which is how an agent says "still here".
//
// A detour's stations are marked done as the marker leaves them, because a detour behind the marker that
// nobody marked reads as a branch not taken, and this one was.
func MoveRoadmap(agent, station, note string, done bool) (Roadmap, error) {
	r, ok, err := LoadRoadmap(agent)
	if err != nil {
		return r, err
	}
	if !ok {
		return r, fmt.Errorf("no roadmap posted yet: use roadmap_post first")
	}
	if err := tooLong("the note", note, roadmapNoteMax); err != nil {
		return r, err
	}
	next := r.Active
	if station != "" {
		i, err := findStation(r.Stations, station)
		if err != nil {
			return r, err
		}
		if r.Stations[i].State == "skipped" {
			r.Stations[i].State = ""
		}
		next = r.Stations[i].ID
	}
	if prev, err := findStation(r.Stations, r.Active); r.Active != "" && err == nil && r.Stations[prev].ID != next {
		if p := &r.Stations[prev]; p.Detour != "" {
			p.State = "done"
		}
	}
	if n, err := findStation(r.Stations, next); next != "" && err == nil {
		// Reaching a station that was finished out of order opens it again.
		if r.Stations[n].State == "done" {
			r.Stations[n].State = ""
		}
		if d := r.Stations[n].Detour; d != "" {
			for i := 0; i < n; i++ {
				if r.Stations[i].Detour == d && r.Stations[i].State == "" {
					r.Stations[i].State = "done"
				}
			}
		}
	}
	r.Active, r.Done = next, done
	if done {
		r.Active = ""
	}
	r.Note, r.At = note, now()
	return r, saveRoadmap(r)
}

func ClearRoadmap(agent string) error {
	if !validComponent(agent) {
		return fmt.Errorf("invalid agent name")
	}
	err := os.Remove(roadmapPath(agent))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ListRoadmaps is every posted roadmap of an agent still on the line. A file that will not parse is left
// out here and reported by `yip roadmap show`.
func ListRoadmaps() []Roadmap {
	files, _ := filepath.Glob(filepath.Join(roadmapDir(), "*.json"))
	var out []Roadmap
	for _, f := range files {
		var r Roadmap
		if readState(f, &r) != nil || r.Agent == "" || len(r.Stations) == 0 || Retired(r.Agent) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Agent < out[j].Agent })
	return out
}

// anchorOf is the main-line position the marker stands at: the active station, or the main station its
// detour left from. -1 means the line has not been started.
func anchorOf(r Roadmap, mains []int) int {
	if r.Done {
		return len(mains)
	}
	if r.Active == "" {
		return -1
	}
	key := r.Active
	for _, s := range r.Stations {
		if s.ID == r.Active && s.Detour != "" {
			key = s.Detour
		}
	}
	for pos, i := range mains {
		if r.Stations[i].ID == key {
			return pos
		}
	}
	return -1
}

func roadmapMains(r Roadmap) []int {
	var mains []int
	for i, s := range r.Stations {
		if s.Detour == "" {
			mains = append(mains, i)
		}
	}
	return mains
}

// stationStates says where each station stands.
func stationStates(r Roadmap) []string {
	mains := roadmapMains(r)
	anchor := anchorOf(r, mains)
	pos := map[string]int{}
	for p, i := range mains {
		pos[r.Stations[i].ID] = p
	}
	activeIdx := -1
	for i, s := range r.Stations {
		if s.ID == r.Active {
			activeIdx = i
		}
	}
	activeOnDetour := activeIdx >= 0 && r.Stations[activeIdx].Detour != ""
	out := make([]string, len(r.Stations))
	for i, s := range r.Stations {
		switch s.State {
		case "done":
			out[i] = stationPassed
			continue
		case "skipped":
			out[i] = stationSkipped
			continue
		case "todo":
			out[i] = stationAhead
			continue
		}
		if i == activeIdx {
			out[i] = stationActive
			continue
		}
		if s.Detour == "" {
			if pos[s.ID] <= anchor {
				out[i] = stationPassed
			} else {
				out[i] = stationAhead
			}
			continue
		}
		// A detour behind the marker that nobody marked done is a branch not taken.
		p := pos[s.Detour]
		switch {
		case p > anchor:
			out[i] = stationAhead
		case p < anchor:
			out[i] = stationSkipped
		case activeOnDetour && r.Stations[activeIdx].Detour == s.Detour && i < activeIdx:
			out[i] = stationPassed
		default:
			out[i] = stationAhead
		}
	}
	return out
}

// shownStation is one point on the drawn line: a station, or a fold standing in for several.
type shownStation struct {
	RoadmapStation
	Status  string
	Folded  int      // how many stations this stands for, 0 for a real station
	Members []string // their names
}

func foldOf(stations []RoadmapStation, states []string, idx []int, detourOf string) shownStation {
	f := shownStation{Folded: len(idx), Status: stationAhead}
	f.Detour = detourOf
	passed := true
	for _, i := range idx {
		f.Members = append(f.Members, stations[i].Name)
		if states[i] == stationActive {
			f.Status = stationActive
		}
		if states[i] != stationPassed && states[i] != stationSkipped {
			passed = false
		}
	}
	if passed {
		f.Status = stationPassed
	}
	unit := "stops"
	if len(idx) == 1 {
		unit = "stop"
	}
	f.Name = fmt.Sprintf("+%d %s", len(idx), unit)
	f.Description = strings.Join(f.Members, ", ")
	return f
}

// compactRoadmap folds a line to at most limit points, keeping what a glance is for: the start, the end,
// where the agent is, and the stops either side, leaning ahead since the road matters more than the
// history. Stations between kept ones fold into one point, so nothing silently vanishes: every station
// is shown or counted in a fold.
//
// The limit holds because the kept skeleton is bounded: first, anchor, last and the two folds between
// them are 5 points, the anchor's detours are at most 5, and each of the two other kept stations
// contributes at most 1 detour point. The rest is added only while it fits.
func compactRoadmap(r Roadmap, limit int) []shownStation {
	if limit < roadmapShownMax {
		limit = roadmapShownMax
	}
	states := stationStates(r)
	mains := roadmapMains(r)
	detours := map[string][]int{}
	for i, s := range r.Stations {
		if s.Detour != "" {
			detours[s.Detour] = append(detours[s.Detour], i)
		}
	}
	real := func(i int) shownStation { return shownStation{RoadmapStation: r.Stations[i], Status: states[i]} }
	if len(mains) == 0 {
		return nil
	}
	anchor := anchorOf(r, mains)
	if anchor < 0 {
		anchor = 0
	}
	if anchor >= len(mains) {
		anchor = len(mains) - 1
	}
	const anchorDetourMax = 5

	keep := make([]bool, len(mains))
	keep[0], keep[anchor], keep[len(mains)-1] = true, true, true
	size := func() int {
		n, gap := 0, false
		for pos, i := range mains {
			if !keep[pos] {
				if !gap {
					n++
				}
				gap = true
				continue
			}
			gap = false
			n++
			d := len(detours[r.Stations[i].ID])
			if pos == anchor {
				n += min(d, anchorDetourMax)
			} else if d > 0 {
				n++
			}
		}
		return n
	}
	try := func(pos int) {
		if pos < 0 || pos >= len(mains) || keep[pos] {
			return
		}
		keep[pos] = true
		if size() > limit {
			keep[pos] = false
		}
	}
	for ahead, behind := anchor+1, anchor-1; ahead < len(mains) || behind >= 0; {
		try(ahead)
		ahead++
		try(ahead)
		ahead++
		try(behind)
		behind--
	}

	var out []shownStation
	var run []int
	flush := func() {
		if len(run) > 0 {
			out = append(out, foldOf(r.Stations, states, run, ""))
			run = nil
		}
	}
	for pos, i := range mains {
		id := r.Stations[i].ID
		if !keep[pos] {
			run = append(run, i)
			run = append(run, detours[id]...)
			continue
		}
		flush()
		out = append(out, real(i))
		ds := detours[id]
		switch {
		case len(ds) == 0:
		case pos == anchor:
			out = append(out, anchorDetours(r, states, ds, id, anchorDetourMax)...)
		case len(ds) == 1:
			out = append(out, real(ds[0]))
		default:
			out = append(out, foldOf(r.Stations, states, ds, id))
		}
	}
	flush()
	return out
}

// anchorDetours shows the detour the agent is on, folding what will not fit either side of it.
func anchorDetours(r Roadmap, states []string, ds []int, main string, budget int) []shownStation {
	real := func(i int) shownStation { return shownStation{RoadmapStation: r.Stations[i], Status: states[i]} }
	var out []shownStation
	if len(ds) <= budget {
		for _, i := range ds {
			out = append(out, real(i))
		}
		return out
	}
	at := 0
	for p, i := range ds {
		if states[i] == stationActive {
			at = p
		}
	}
	from, to := max(0, at-1), min(len(ds), at+2)
	for to-from < budget-2 && (from > 0 || to < len(ds)) {
		if to < len(ds) {
			to++
		} else {
			from--
		}
	}
	if from == 1 {
		from = 0
	}
	if to == len(ds)-1 {
		to = len(ds)
	}
	if from > 0 {
		out = append(out, foldOf(r.Stations, states, ds[:from], main))
	}
	for _, i := range ds[from:to] {
		out = append(out, real(i))
	}
	if to < len(ds) {
		out = append(out, foldOf(r.Stations, states, ds[to:], main))
	}
	return out
}

func roadmapAge(r Roadmap) time.Duration {
	t, err := time.Parse(time.RFC3339, r.At)
	if err != nil {
		return 0
	}
	return time.Since(t)
}

func activeStation(r Roadmap) (RoadmapStation, bool) {
	for _, s := range r.Stations {
		if s.ID == r.Active {
			return s, true
		}
	}
	return RoadmapStation{}, false
}

// RoadmapSummary is what a post or a move answers with, so an agent sees the fold it caused.
func RoadmapSummary(r Roadmap) string {
	shown := compactRoadmap(r, roadmapShownMax)
	folded := 0
	for _, s := range shown {
		if s.Folded > 0 {
			folded++
		}
	}
	where := "not started"
	if s, ok := activeStation(r); ok {
		where = "at " + s.Name
	}
	if r.Done {
		where = "finished"
	}
	text := fmt.Sprintf("%s: %s, %s; %d stations", r.Agent, r.Arc, where, len(r.Stations))
	if folded > 0 {
		text += fmt.Sprintf(", drawn as %d points with %d folds", len(shown), folded)
	}
	return text + "."
}

// RoadmapText is the plain form, for agents and for `yip roadmap show`.
func RoadmapText(agent string) (string, error) {
	var rs []Roadmap
	if agent != "" {
		r, ok, err := LoadRoadmap(agent)
		if err != nil {
			return "", err
		}
		if !ok {
			return agent + " has no roadmap posted.", nil
		}
		rs = []Roadmap{r}
	} else {
		rs = ListRoadmaps()
	}
	if len(rs) == 0 {
		return "No roadmaps posted on this line.", nil
	}
	var b strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&b, "%s  %s  (updated %s ago)\n", r.Agent, r.Arc, span(roadmapAge(r)))
		if r.Description != "" {
			fmt.Fprintf(&b, "  %s\n", r.Description)
		}
		for _, s := range compactRoadmap(r, roadmapShownMax) {
			indent := "  "
			if s.Detour != "" {
				indent = "    \\ "
			}
			fmt.Fprintf(&b, "%s%s %s", indent, stationGlyph(s.Status, s.Folded > 0, false), s.Name)
			if s.Description != "" {
				fmt.Fprintf(&b, " -- %s", s.Description)
			}
			b.WriteByte('\n')
		}
		if r.Note != "" {
			fmt.Fprintf(&b, "  note: %s\n", r.Note)
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(terminalText(b.String()), "\n"), nil
}

// roadmapNudge is one line every roadmapNudgeAfter while an agent's map is missing or old. A field whose
// upkeep is nobody's step stays unkept, and the person glancing at it cannot tell. Quiet otherwise.
func roadmapNudge(agent string) string {
	r, ok, err := LoadRoadmap(agent)
	if err != nil {
		return ""
	}
	if ok && roadmapAge(r) < roadmapNudgeAfter {
		return ""
	}
	if fi, err := os.Stat(roadmapNudgePath(agent)); err == nil && time.Since(fi.ModTime()) < roadmapNudgeAfter {
		return ""
	}
	if os.MkdirAll(roadmapDir(), 0o755) != nil || atomicReplace(roadmapNudgePath(agent), []byte(now()+"\n")) != nil {
		return ""
	}
	if !ok {
		return "You have no roadmap posted, so the operator cannot see where you are: roadmap_post your arc (or yip roadmap post; see yip help)."
	}
	return fmt.Sprintf("Your roadmap (%s) was last updated %s ago. If the marker is still true, roadmap_at (or yip roadmap at) says so; if not, move it.", terminalText(r.Arc), span(roadmapAge(r)))
}

// RoadmapCLI is `yip roadmap post|at|show|clear`.
func RoadmapCLI(args []string, me string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: yip roadmap post [--file path] | at <station> [--note text] [--done] | show [agent] | clear")
	}
	switch args[0] {
	case "post":
		rest, path := takeFlag(args[1:], "--file", "")
		if len(rest) > 0 {
			return fmt.Errorf("usage: yip roadmap post [--file path] (JSON on stdin without --file)")
		}
		f := os.Stdin
		if path != "" {
			var err error
			if f, err = os.Open(path); err != nil {
				return err
			}
			defer f.Close()
		}
		var r Roadmap
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return fmt.Errorf("roadmap JSON: %v", err)
		}
		out, err := PostRoadmap(me, r)
		if err != nil {
			return err
		}
		fmt.Println(RoadmapSummary(out))
		return nil
	case "at":
		rest, note := takeFlag(args[1:], "--note", "")
		done := false
		var station []string
		for _, a := range rest {
			if a == "--done" {
				done = true
			} else {
				station = append(station, a)
			}
		}
		out, err := MoveRoadmap(me, strings.Join(station, " "), note, done)
		if err != nil {
			return err
		}
		fmt.Println(RoadmapSummary(out))
		return nil
	case "show":
		agent := ""
		if len(args) > 1 {
			agent = args[1]
		}
		text, err := RoadmapText(agent)
		if err != nil {
			return err
		}
		fmt.Println(text)
		return nil
	case "clear":
		if err := ClearRoadmap(me); err != nil {
			return err
		}
		fmt.Println("roadmap cleared.")
		return nil
	}
	return fmt.Errorf("unknown roadmap command %q", args[0])
}

func stationGlyph(status string, folded, pulse bool) string {
	switch {
	case folded:
		return "⋯"
	case status == stationActive && pulse:
		return "◎"
	case status == stationActive:
		return "◉"
	case status == stationPassed:
		return "●"
	case status == stationSkipped:
		return "⊘"
	}
	return "○"
}

func roadmapTools() []toolDef {
	station := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id":          str("Short stable key, used by roadmap_at. Defaults from the name."),
			"name":        str("Short label, under the station on the map. Up to 40 characters; a dozen words is too long."),
			"description": str("What this station is. Shown when the station is the current one, and in the station list."),
			"detour":      str("Set on a detour station: the id or name of the main-line station it branches from."),
			"state":       str("Only to override position: done, skipped or todo."),
		},
		"required": []string{"name"},
	}
	return []toolDef{
		{
			Name: "roadmap_post",
			Description: "Post your arc as a line of stations, start to end, replacing your last one. The operator reads this on the switchboard's map to see where you are without asking. " +
				"Post the whole road: twelve points are drawn, and a longer line is folded around your position for you. Post once when an arc starts or changes shape; move the marker with roadmap_at. This grants nothing and notifies nobody.",
			InputSchema: obj(map[string]any{
				"arc":         str("The arc's name"),
				"description": str("What the arc is for, in a sentence or two"),
				"stations":    map[string]any{"type": "array", "items": station, "description": "In order, start to end. A detour station goes after the station it branches from."},
				"active":      str("The id or name of the station you are at. Omit if not started."),
				"note":        str("Optional: one line on what is happening at this station now"),
			}, "arc", "stations"),
		},
		{
			Name: "roadmap_at",
			Description: "Move your marker to a station, and say what is happening there. Do this on reaching a station, and at a resting point, even if you have not moved: the map shows how long ago you last said so. " +
				"Omit station to stay where you are. done: true finishes the arc.",
			InputSchema: obj(map[string]any{
				"station": str("The id or name of the station; omit to stay"),
				"note":    str("One line on what is happening now; replaces the last note"),
				"done":    yesno("The arc is finished"),
			}),
		},
		{
			Name:        "roadmaps",
			Description: "Read where agents are on their arcs: one agent's roadmap, or everyone's. Usually cheaper than asking them.",
			InputSchema: obj(map[string]any{"agent": str("Omit for everyone")}),
		},
		{
			Name:        "roadmap_clear",
			Description: "Take your line off the map, when you have no arc to show.",
			InputSchema: obj(map[string]any{}),
		},
	}
}

// doRoadmap answers the roadmap tools. The agent is always the caller: no tool writes another's line.
func doRoadmap(me, name string, a map[string]any) (string, error) {
	switch name {
	case "roadmap_post":
		r := Roadmap{Arc: argStr(a, "arc"), Description: argStr(a, "description"), Active: argStr(a, "active"), Note: argStr(a, "note")}
		raw, err := json.Marshal(a["stations"])
		if err != nil {
			return "", err
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r.Stations); err != nil {
			return "", fmt.Errorf("stations: %v", err)
		}
		out, err := PostRoadmap(me, r)
		if err != nil {
			return "", err
		}
		return RoadmapSummary(out), nil
	case "roadmap_at":
		out, err := MoveRoadmap(me, argStr(a, "station"), argStr(a, "note"), argBool(a, "done"))
		if err != nil {
			return "", err
		}
		return RoadmapSummary(out), nil
	case "roadmaps":
		return RoadmapText(argStr(a, "agent"))
	case "roadmap_clear":
		if err := ClearRoadmap(me); err != nil {
			return "", err
		}
		return "roadmap cleared.", nil
	}
	return "", fmt.Errorf("unknown roadmap tool %q", name)
}
