package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Snapshots for the switchboard. A line holds thousands of small files and almost none of them change
// between ticks, so a call is re-read only when its directories say something moved. Every writer here
// goes through a rename (atomicReplace), and a rename touches the directory's mtime, which is what
// callSig reads.
//
// The whole line is re-read every sbFullReloadEvery snapshots anyway: a coarse filesystem clock can hide
// two writes inside one tick, and that should cost seconds of staleness, not a wrong screen until restart.
const sbFullReloadEvery = 30

// What a broadcast looks like right now. Rendering reads this and never the disk.
type sbBroadcast struct {
	receipts map[string]BroadcastReceipt
	bad      map[string]bool
	delivery map[string]string
	progress string
}

type sbCallCache struct {
	sig    string
	call   *Call
	turns  []Turn
	events []CallEvent
	closed bool
	sc     sbCall
}

type sbEndpointCache struct {
	mod      time.Time
	size     int64
	ep       Endpoint
	err      error
	bySource map[string][]string
}

type sbLoader struct {
	calls     map[string]*sbCallCache
	endpoints map[string]*sbEndpointCache
	loads     int
}

// loadState is one uncached snapshot.
func loadState() sbState { return (&sbLoader{}).load() }

func callSig(dir string) string {
	var b strings.Builder
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%d;", fi.ModTime().UnixNano())
		} else {
			b.WriteString("-;")
		}
	}
	add(dir)
	add(filepath.Join(dir, "turns"))
	add(filepath.Join(dir, "notes"))
	add(filepath.Join(dir, "events"))
	disputes := filepath.Join(dir, "disputes")
	add(disputes)
	if ents, err := os.ReadDir(disputes); err == nil {
		for _, e := range ents {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				add(filepath.Join(disputes, e.Name()))
			}
		}
	}
	return b.String()
}

func readCallCache(id, sig string) *sbCallCache {
	c, err := LoadCall(id)
	if err != nil {
		return nil
	}
	cc := &sbCallCache{sig: sig, call: c, closed: IsClosed(c), events: CallEvents(c)}
	cc.turns, _ = Turns(c)
	notes, _ := Notes(c)
	sc := sbCall{call: c, closed: cc.closed, sig: sig, floor: FloorHolder(c, cc.turns)}
	sc.entries = mergeEntries(cc.turns, notes)
	for _, e := range cc.events {
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
	cc.sc = sc
	return cc
}

func (l *sbLoader) endpoint(agent string) *sbEndpointCache {
	fi, statErr := os.Stat(endpointPath(agent))
	if e := l.endpoints[agent]; e != nil && statErr == nil && e.mod.Equal(fi.ModTime()) && e.size == fi.Size() {
		return e
	}
	e := &sbEndpointCache{bySource: map[string][]string{}}
	if statErr == nil {
		e.mod, e.size = fi.ModTime(), fi.Size()
	}
	e.ep, e.err = readEndpoint(agent)
	if e.err == nil {
		for _, d := range e.ep.Events {
			e.bySource[d.Source] = append(e.bySource[d.Source], d.Status)
		}
	}
	l.endpoints[agent] = e
	return e
}

func (l *sbLoader) broadcastCall(b *Broadcast) *sbCall {
	bv := &sbBroadcast{receipts: map[string]BroadcastReceipt{}, bad: map[string]bool{}, delivery: map[string]string{}}
	sc := &sbCall{broadcast: b, bview: bv, call: &Call{ID: "broadcast:" + b.ID, From: b.By, To: "broadcast", Subject: firstLine(b.Body)}, status: "resolved", lastAt: b.At}
	read, replied := 0, 0
	for _, a := range b.Recipients {
		r, e := broadcastReceipt(b.ID, a)
		bv.receipts[a] = r
		if e != nil {
			bv.bad[a] = true
		} else {
			if r.ReadAt != "" {
				read++
			}
			if len(r.Replies) > 0 {
				replied++
			}
		}
		if e != nil || r.ReadAt == "" || (b.Kind != "announcement" && len(r.Replies) == 0) {
			sc.status = "open"
		}
		for _, reply := range r.Replies {
			if reply.At > sc.lastAt {
				sc.lastAt = reply.At
			}
		}
		ep := l.endpoint(a)
		delivery := endpointStatusFrom(a, ep.ep, ep.err)
		for _, status := range ep.bySource["broadcast:"+b.ID] {
			delivery += "; " + status
		}
		bv.delivery[a] = delivery
	}
	bv.progress = fmt.Sprintf("%d/%d read · %d replied", read, len(b.Recipients), replied)
	if b.Kind == "announcement" {
		bv.progress = fmt.Sprintf("%d/%d read", read, len(b.Recipients))
	}
	return sc
}

// A conversation's place in the list. Calls sort by status, then by activity. A broadcast has no place in
// that order, so it takes its place by age: it stands above the first call older than it, and every newer
// call pushes it further down.
func callRank(c *sbCall) int {
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

func orderConversations(calls, broadcasts []*sbCall) []*sbCall {
	sort.SliceStable(calls, func(i, j int) bool {
		if ri, rj := callRank(calls[i]), callRank(calls[j]); ri != rj {
			return ri < rj
		}
		return calls[i].lastAt > calls[j].lastAt
	})
	sort.SliceStable(broadcasts, func(i, j int) bool { return broadcasts[i].lastAt > broadcasts[j].lastAt })
	active := func(c *sbCall) string {
		if c.lastAt != "" {
			return c.lastAt
		}
		return c.call.Opened
	}
	out := make([]*sbCall, 0, len(calls)+len(broadcasts))
	i, j := 0, 0
	for i < len(calls) || j < len(broadcasts) {
		if j < len(broadcasts) && (i >= len(calls) || broadcasts[j].lastAt > active(calls[i])) {
			out = append(out, broadcasts[j])
			j++
		} else {
			out = append(out, calls[i])
			i++
		}
	}
	return out
}

func (l *sbLoader) load() sbState {
	if l.calls == nil {
		l.calls = map[string]*sbCallCache{}
		l.endpoints = map[string]*sbEndpointCache{}
	}
	l.loads++
	full := l.loads%sbFullReloadEvery == 0

	st := sbState{presence: map[string]Presence{}, endpoints: map[string]string{}, retired: map[string]bool{}}
	m := LoadMembers()
	st.members = m.Names()
	for _, a := range st.members {
		st.retired[a] = Retired(a)
		if p, ok := LoadPresence(a); ok {
			st.presence[a] = p
		}
		ep := l.endpoint(a)
		st.endpoints[a] = endpointStatusFrom(a, ep.ep, ep.err)
	}
	ents, err := os.ReadDir(callsDir())
	if err != nil && !os.IsNotExist(err) {
		st.err = err.Error()
		return st
	}
	seen := map[string]bool{}
	var calls []*sbCall
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		id := e.Name()
		// The signature comes first: a write that lands during the read moves it, so the next load
		// reads the call again and never keeps a half-new copy under the newer signature.
		sig := callSig(filepath.Join(callsDir(), id))
		cc := l.calls[id]
		if cc == nil || cc.sig != sig || full {
			if cc = readCallCache(id, sig); cc == nil {
				delete(l.calls, id)
				continue
			}
			l.calls[id] = cc
		}
		seen[id] = true
		// The view still holds the last snapshot's pointers, so each snapshot gets its own copies.
		sc := cc.sc
		sc.status = callStatusFrom(cc.call, cc.turns, cc.events, cc.closed)
		calls = append(calls, &sc)
	}
	for id := range l.calls {
		if !seen[id] {
			delete(l.calls, id)
		}
	}
	var broadcasts []*sbCall
	bs, err := ListBroadcasts()
	if err != nil {
		st.err = err.Error()
	}
	for i := range bs {
		broadcasts = append(broadcasts, l.broadcastCall(&bs[i]))
	}
	st.calls = orderConversations(calls, broadcasts)
	st.roadmaps = ListRoadmaps()
	for _, r := range resourceList() {
		lease, held := LoadLease(r.Name)
		sr := sbResource{name: r.Name, lease: lease, held: held, queue: Queue(r.Name)}
		for _, runner := range lease.Runners {
			sr.runners = append(sr.runners, fmt.Sprintf("pid %d %s", runner.PID, runnerStatus(runner)))
		}
		st.resources = append(st.resources, sr)
	}
	path, _ := os.Getwd()
	st.disk = diskText(path)
	return st
}
