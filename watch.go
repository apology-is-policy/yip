package main

// `yip watch` -- an event stream, so nobody has to poll in bash.
//
// Before this, an agent that wanted to know when a peer OPENED a call had no
// primitive for it: wait() needs a call that already exists. The observed
// workaround was a hand-rolled 15-second shell loop, which is both unbounded
// and invisible.
//
// This is the shape the agent harness already wants: one line of stdout per
// event, consumed by a persistent monitor. The agent is not blocked while it
// waits and pays nothing to be idle -- the peer's write is what wakes it.
//
//	Monitor(command: "yip watch", persistent: true)   # every event
//	Bash(run_in_background: true, "yip watch --once") # just the next one
//
// It also closes the one row the README called irreducible: "idle, owing
// nothing, human silent -> one word". An idle agent with a monitor armed is
// reachable by its peer without the human saying anything.
//
// A watcher never reports its OWN writes. Being woken by your own turn is
// worse than useless -- it trains you to ignore the stream.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type watchEvent struct {
	key  string // stable identity, so an event is reported exactly once
	line string
}

// snapshot enumerates everything currently visible to this agent. Events are
// the set difference between two snapshots, which means a missed poll cannot
// drop an event -- it just arrives one interval later.
func watchSnapshot(me string) map[string]string {
	out := map[string]string{}
	calls, err := ListCalls()
	if err != nil {
		return out
	}
	for _, c := range calls {
		if !c.Involves(c.Peer(me)) || !c.Involves(me) {
			continue
		}
		turns, _ := Turns(c)

		if c.From != me {
			out["call:"+c.ID] = fmt.Sprintf("CALL   %s  %s -> %s  %q", c.ID, c.From, c.To, c.Subject)
		}
		for _, t := range turns {
			if t.From == me {
				continue
			}
			floor := FloorHolder(c, turns)
			mark := ""
			if t.Barge {
				mark = " !!BARGE"
			}
			out[fmt.Sprintf("turn:%s:%d", c.ID, t.N)] =
				fmt.Sprintf("TURN   %s  #%d from %s  floor:%s%s", c.ID, t.N, t.From, floor, mark)
		}
		notes, _ := Notes(c)
		for _, n := range notes {
			if n.From == me && n.Kind == AuthorAgent {
				continue
			}
			kind := "NOTE  "
			if n.Kind == AuthorHuman {
				kind = "HUMAN "
			}
			out[fmt.Sprintf("note:%s:%d", c.ID, n.N)] =
				fmt.Sprintf("%s %s  #%d from %s  %s", kind, c.ID, n.N, n.From, firstLine(n.Body))
		}
		if peer := c.Peer(me); HasBye(c, peer) {
			out["bye:"+c.ID+":"+peer] = fmt.Sprintf("BYE    %s  from %s", c.ID, peer)
		}
		if IsClosed(c) {
			out["closed:"+c.ID] = fmt.Sprintf("CLOSED %s", c.ID)
		}
		for _, d := range ListDisputesQuiet(c) {
			st := DisputeStatus(c, d)
			// Status is part of the key on purpose: a dispute changing state
			// (a measurement arriving, agreement reached) is itself the event
			// worth waking for.
			out[fmt.Sprintf("dispute:%s:%s:%s", c.ID, d.ID, st)] =
				fmt.Sprintf("DISPUTE %s  %s  -- %s", c.ID, d.ID, st)
		}
	}
	return out
}

func ListDisputesQuiet(c *Call) []*Dispute {
	d, _ := ListDisputes(c)
	return d
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 72 {
		s = s[:69] + "..."
	}
	return s
}

// Watch emits one line per new event. replay=true reports what is already
// there before streaming (useful for a switchboard attaching mid-conversation);
// the default reports only what happens from now on, so arming a monitor does
// not dump history at you.
//
// deadline BOUNDS the wait. This is not optional politeness: --once with
// nothing to report would otherwise spin forever, which is precisely the
// unbounded-waiter hazard this command exists to remove. A tool that fixes
// somebody's 15-second poll loop by introducing an infinite one has done
// nothing. Zero means genuinely forever, which is correct ONLY for a
// persistent monitor that something else will stop.
//
// Exit codes are load-bearing for the --once shape: 0 means an event arrived,
// 3 means the deadline passed with nothing. A caller that cannot tell those
// apart will read silence as success.
func Watch(me string, interval, deadline time.Duration, once, replay bool) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	seen := map[string]bool{}
	if !replay {
		for k := range watchSnapshot(me) {
			seen[k] = true
		}
	}
	var until time.Time
	if deadline > 0 {
		until = time.Now().Add(deadline)
	}
	for {
		var fresh []watchEvent
		for k, line := range watchSnapshot(me) {
			if !seen[k] {
				seen[k] = true
				fresh = append(fresh, watchEvent{k, line})
			}
		}
		sort.Slice(fresh, func(i, j int) bool { return fresh[i].key < fresh[j].key })
		for _, e := range fresh {
			fmt.Println(e.line)
		}
		// Unbuffered: os.Stdout is not wrapped, so each Println is a write and
		// the consumer sees it immediately. A buffered writer here would hold
		// events until the buffer filled, which for a low-rate stream means
		// never -- the exact silent-failure the monitor docs warn about.
		if once && len(fresh) > 0 {
			return nil
		}
		if !until.IsZero() && !time.Now().Before(until) {
			return errWatchDeadline
		}
		time.Sleep(interval)
	}
}

// errWatchDeadline is distinguishable from a real failure so a caller can tell
// "nothing happened" from "the watch broke".
var errWatchDeadline = &watchTimeout{}

type watchTimeout struct{}

func (*watchTimeout) Error() string { return "watch: deadline passed with no event" }

// WatchOnceExisting is the "is anything waiting for me right now" check, for a
// switchboard or a session opening cold. It never blocks.
func WatchNow(me string) []string {
	var lines []string
	for _, l := range watchSnapshot(me) {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	return lines
}

func watchRootExists() bool {
	st, err := os.Stat(filepath.Join(Root(), "calls"))
	return err == nil && st.IsDir()
}
