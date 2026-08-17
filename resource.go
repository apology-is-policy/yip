package main

// Resource leases -- the missing testimony.
//
// WHY THIS EXISTS. Three agents share one 8-core Mac and one Pi, and the
// question "is this machine free?" turned out to have NO local answer. On
// 2026-08-16 all three of us wrote waiters for it and all three were wrong:
// one watched only QEMU (blind to a cargo build), one used `setsid` and died
// instantly on macOS so "nothing running" was vacuously true, and the third --
// hardened past both of those to require zero QEMU AND zero builds AND low
// load -- fired into a GAP BETWEEN a peer's build and its boot, and took the
// cores out from under a running control.
//
// That last one is the important failure, because adding axes could never have
// fixed it. A machine between phases is IDENTICAL to an idle machine on every
// dimension a machine exposes: no processes, no load, nothing. The difference
// is INTENT, and intent is not on the machine. So no detector can settle it,
// at any sensitivity -- only a statement from whoever knows can. That is what a
// lease is: testimony, where every previous attempt was measurement.
//
// TWO DESIGN CONSEQUENCES, both learned the hard way, both load-bearing:
//
//  1. LEASES DO NOT EXPIRE ON HEARTBEAT. The obvious design -- reclaim when the
//     holder stops beating -- is wrong here, and wrong in the direction that
//     destroys work. A beat is written per TOOL CALL, not per unit of work, so
//     an agent running a 40-minute gate in one blocking call goes silent for
//     40 minutes while very much holding the machine. Measured: a peer's beat
//     read "36m ago" with a 40-boot SMP gate mid-flight. Heartbeat expiry would
//     have handed their cores away at minute 3. Expiry is therefore WALL-CLOCK
//     only, from a TTL the holder chooses, and it is a backstop against a dead
//     agent rather than a normal path.
//
//  2. AN EXPIRED LEASE IS NOT AN OPEN ONE. It has to be taken deliberately, by
//     `steal`, which records who did it and why. A lease that silently evaporates
//     recreates the original bug with a timer attached.
//
// WHAT THIS DELIBERATELY DOES NOT DO: it grants no licence to kill a peer's
// processes. Holding a resource means nobody else STARTS; it does not mean
// anything already running is a trespasser. On the day this was designed the
// host carried a `caffeinate` that one agent attributed to "a FOURTH session
// no agent had registered", and a QEMU that neither active agent could account
// for. The fourth session turned out to be that agent's OWN claude (`--resume
// aux_gfx` is aux's conversation) -- the census had no control, and the
// control was its own identity. That correction sharpens the point rather
// than weakening it: "in violation" is an inference, and the inferences were
// wrong all day, from both sides. The costs are also wildly asymmetric:
// killing a peer's gate at boot 39 of 40 destroys 40 minutes AND the
// evidence, while tolerating a freeloader costs some wall clock. So: report,
// notify, escalate -- see ViolationAdvice.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ------------------------------------------------------------------ registry

// Resource is a thing exactly one agent may hold at a time.
//
// THE UNIT IS A PHYSICAL MACHINE, not a tool or a workload, and that is the
// correction that makes the whole scheme work. The first cut of this list had
// "QEMU" and "CPU" as separate entries, which would have let two agents hold
// two locks and saturate one set of cores while the protocol told both of them
// they were fine -- the original bug, with a blessing. QEMU is not a resource,
// it is a CONSUMER of one: TCG is a pure CPU emulator, an HVF guest runs real
// vCPU threads, and `cargo build -j` / TLC / a sanitizer build each saturate
// every core. They are one contention class because they contend for one thing.
type Resource struct {
	Name string
	Desc string
}

var knownResources = []Resource{
	{
		Name: "mac",
		Desc: "the 8-core dev Mac -- ONE class covering builds, TLC, sanitizers, " +
			"QEMU/HVF guests and the SMP gate. Includes the `thyla-gl` Parallels VM, " +
			"whose 4 vCPUs are carved out of these same 8 cores rather than being " +
			"separate hardware.",
	},
	{
		Name: "pi",
		Desc: "thyla-pi -- ARM64/KVM/V3D. Exclusive by necessity as well as by " +
			"protocol: 4 GB RAM means one 2048 MiB guest at a time, and QEMU there " +
			"is single-flight.",
	},
}

func KnownResource(name string) (Resource, bool) {
	for _, r := range knownResources {
		if r.Name == name {
			return r, true
		}
	}
	return Resource{}, false
}

func ResourceNames() []string {
	out := make([]string, 0, len(knownResources))
	for _, r := range knownResources {
		out = append(out, r.Name)
	}
	return out
}

// ------------------------------------------------------------------- layout

func resourcesDir() string { return filepath.Join(Root(), "resources") }

func leasePath(name string) string { return filepath.Join(resourcesDir(), name+".lease") }
func queueDir(name string) string  { return filepath.Join(resourcesDir(), name+".queue") }
func queuePath(name, agent string) string {
	return filepath.Join(queueDir(name), agent+".json")
}

func ensureResourceDirs(name string) error {
	for _, d := range []string{resourcesDir(), queueDir(name)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// -------------------------------------------------------------------- lease

type Lease struct {
	Resource string `json:"resource"`
	Holder   string `json:"holder"`
	Reason   string `json:"reason"`
	Since    string `json:"since"`
	TTLSecs  int    `json:"ttl_secs"`
	Pids     []int  `json:"pids,omitempty"`
	// StolenFrom records a reclaim so it can never look like an ordinary
	// acquire in the log. An expired lease taken silently would be the
	// original bug with a timer on it.
	StolenFrom string `json:"stolen_from,omitempty"`
	StealWhy   string `json:"steal_why,omitempty"`
}

const (
	defaultTTL = 2 * time.Hour
	maxTTL     = 8 * time.Hour
	// A waiter that stops asking loses its place after this. Ordering uses
	// Since (so re-issuing a bounded wait KEEPS your position), while Seen
	// prunes agents that walked away -- two fields because one cannot do both.
	queueStaleAfter = 15 * time.Minute
)

func LoadLease(name string) (Lease, bool) {
	var l Lease
	b, err := os.ReadFile(leasePath(name))
	if err != nil {
		return l, false
	}
	if json.Unmarshal(b, &l) != nil {
		return l, false
	}
	return l, true
}

func (l Lease) Age() time.Duration {
	t, err := time.Parse(time.RFC3339, l.Since)
	if err != nil {
		return 1 << 62
	}
	return time.Since(t)
}

func (l Lease) Remaining() time.Duration {
	return time.Duration(l.TTLSecs)*time.Second - l.Age()
}

// Expired means the TTL ran out. It does NOT mean the resource is free: see
// the file header. Only Steal converts an expired lease into a held one.
func (l Lease) Expired() bool { return l.Remaining() <= 0 }

// ------------------------------------------------------------------- queue

type QueueEntry struct {
	Agent  string `json:"agent"`
	Reason string `json:"reason"`
	Since  string `json:"since"` // FIFO order -- never rewritten
	Seen   string `json:"seen"`  // liveness of the WAIT -- rewritten each poll
}

func (q QueueEntry) sinceTime() time.Time {
	t, err := time.Parse(time.RFC3339, q.Since)
	if err != nil {
		return time.Unix(1<<62, 0)
	}
	return t
}

func (q QueueEntry) stale() bool {
	t, err := time.Parse(time.RFC3339, q.Seen)
	if err != nil {
		return true
	}
	return time.Since(t) > queueStaleAfter
}

// Queue returns live waiters in FIFO order, oldest request first.
func Queue(name string) []QueueEntry {
	ents, err := os.ReadDir(queueDir(name))
	if err != nil {
		return nil
	}
	var out []QueueEntry
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(queueDir(name), e.Name()))
		if err != nil {
			continue
		}
		var q QueueEntry
		if json.Unmarshal(b, &q) != nil || q.Agent == "" {
			continue
		}
		if q.stale() {
			continue
		}
		out = append(out, q)
	}
	// Tie-break by agent name, because RFC3339 is SECOND-granular: two agents
	// queueing in the same second compare equal on Since, and sort.Slice is not
	// stable, so each could sort itself to the head and both would try to take
	// an unheld lease. atomicCreate still stops the double-grant, but the order
	// must be deterministic or "who is next" differs per caller.
	sort.Slice(out, func(i, j int) bool {
		if ti, tj := out[i].sinceTime(), out[j].sinceTime(); !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

// touchQueue records (or refreshes) my interest. Since is preserved across
// refreshes so a bounded wait can be re-issued without losing FIFO position.
func touchQueue(name, agent, reason string) {
	if err := ensureResourceDirs(name); err != nil {
		return
	}
	q := QueueEntry{Agent: agent, Reason: reason, Since: now(), Seen: now()}
	if b, err := os.ReadFile(queuePath(name, agent)); err == nil {
		var prev QueueEntry
		if json.Unmarshal(b, &prev) == nil && prev.Since != "" {
			q.Since = prev.Since
		}
	}
	b, _ := json.MarshalIndent(q, "", "  ")
	_ = atomicReplace(queuePath(name, agent), append(b, '\n'))
}

func dropQueue(name, agent string) { _ = os.Remove(queuePath(name, agent)) }

func queuePosition(name, agent string) int {
	for i, q := range Queue(name) {
		if q.Agent == agent {
			return i + 1
		}
	}
	return 0
}

// ----------------------------------------------------------------- acquire

// TryAcquire makes exactly one attempt. got=true means the lease is yours.
//
// Mutual exclusion rests on atomicCreate, which links onto the destination and
// fails if it exists -- a real compare-and-set on a local filesystem, not a
// read-then-write that two agents could interleave.
func TryAcquire(name, agent, reason string, ttl time.Duration, pids []int) (got bool, cur Lease, pos int, err error) {
	if _, ok := KnownResource(name); !ok {
		return false, Lease{}, 0, fmt.Errorf("unknown resource %q -- known: %s", name, strings.Join(ResourceNames(), ", "))
	}
	if err := ensureResourceDirs(name); err != nil {
		return false, Lease{}, 0, err
	}
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	if l, ok := LoadLease(name); ok {
		if l.Holder == agent {
			// Idempotent re-acquire doubles as renewal, so a long holder can
			// extend without a release/acquire gap another agent could win.
			l.Reason, l.TTLSecs, l.Pids = reason, int(ttl/time.Second), pids
			b, _ := json.MarshalIndent(l, "", "  ")
			_ = atomicReplace(leasePath(name), append(b, '\n'))
			dropQueue(name, agent)
			return true, l, 0, nil
		}
		touchQueue(name, agent, reason)
		return false, l, queuePosition(name, agent), nil
	}

	// Unheld. Take it only if I am at the head of the queue, so a latecomer
	// polling at the right instant cannot jump the line.
	touchQueue(name, agent, reason)
	if q := Queue(name); len(q) > 0 && q[0].Agent != agent {
		return false, Lease{}, queuePosition(name, agent), nil
	}
	l := Lease{Resource: name, Holder: agent, Reason: reason, Since: now(), TTLSecs: int(ttl / time.Second), Pids: pids}
	b, _ := json.MarshalIndent(l, "", "  ")
	if err := atomicCreate(leasePath(name), append(b, '\n')); err != nil {
		// Lost the race; somebody created it between our check and our link.
		cur, _ := LoadLease(name)
		return false, cur, queuePosition(name, agent), nil
	}
	dropQueue(name, agent)
	return true, l, 0, nil
}

// Acquire blocks up to timeout, polling. Bounded on purpose: an unbounded wait
// holds the agent's turn open with no way for a human to interrupt it, and the
// caller re-issuing is cheap because queue position survives (see touchQueue).
func Acquire(name, agent, reason string, ttl, timeout time.Duration, pids []int) (bool, Lease, int, error) {
	got, cur, pos, err := TryAcquire(name, agent, reason, ttl, pids)
	if got || err != nil {
		return got, cur, pos, err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		got, cur, pos, err = TryAcquire(name, agent, reason, ttl, pids)
		if got || err != nil {
			return got, cur, pos, err
		}
	}
	return false, cur, pos, nil
}

// Release drops a lease you hold. Releasing someone else's is refused rather
// than tolerated: the whole value of the scheme is that the holder's word is
// authoritative, which fails if anyone may end their claim.
func Release(name, agent string) (Lease, error) {
	l, ok := LoadLease(name)
	if !ok {
		dropQueue(name, agent)
		return Lease{}, fmt.Errorf("%s is not held by anyone", name)
	}
	if l.Holder != agent {
		return l, fmt.Errorf("%s is held by %s, not you -- ask them to release it (or `steal` it if it has expired)", name, l.Holder)
	}
	if err := os.Remove(leasePath(name)); err != nil {
		return l, err
	}
	dropQueue(name, agent)
	return l, nil
}

// Steal takes an EXPIRED lease. Deliberate, recorded, and refused while the
// TTL still has time on it -- an expired lease is not an open one.
func Steal(name, agent, why string) (Lease, error) {
	if strings.TrimSpace(why) == "" {
		return Lease{}, fmt.Errorf("steal needs a reason -- it is recorded, and an unexplained reclaim is indistinguishable from a protocol breach")
	}
	l, ok := LoadLease(name)
	if !ok {
		return Lease{}, fmt.Errorf("%s is not held -- acquire it normally", name)
	}
	if l.Holder == agent {
		return l, fmt.Errorf("you already hold %s", name)
	}
	if !l.Expired() {
		return l, fmt.Errorf("%s is held by %s with %s still to run -- not stealable. Ask them, or wait",
			name, l.Holder, span(l.Remaining()))
	}
	prev := l.Holder
	nl := Lease{Resource: name, Holder: agent, Reason: "(stolen) " + why, Since: now(),
		TTLSecs: int(defaultTTL / time.Second), StolenFrom: prev, StealWhy: why}
	b, _ := json.MarshalIndent(nl, "", "  ")
	if err := atomicReplace(leasePath(name), append(b, '\n')); err != nil {
		return l, err
	}
	dropQueue(name, agent)
	return nl, nil
}

// --------------------------------------------------------------- rendering

// span formats a DURATION. describeAge exists for past instants and suffixes
// "ago", which reads as nonsense on a remaining TTL ("1.5h ago left"), so the
// two are kept apart rather than one being bent to cover both.
func span(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d > 1<<60:
		return "forever"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// ResourcesText is the non-blocking poll: who holds what, for how much longer,
// and who is queued. Deliberately answers "should I wait or go do something
// else" rather than just "free/busy".
func ResourcesText(me string) string {
	var b strings.Builder
	for _, r := range knownResources {
		l, held := LoadLease(r.Name)
		q := Queue(r.Name)
		switch {
		case !held:
			fmt.Fprintf(&b, "%-5s FREE\n", r.Name)
		case l.Expired():
			fmt.Fprintf(&b, "%-5s EXPIRED -- %s held it %s, TTL ran out %s ago. Not free: `steal` it with a reason, or ask them.\n",
				r.Name, l.Holder, span(l.Age()), span(-l.Remaining()))
		default:
			who := l.Holder
			if who == me {
				who = "you"
			}
			fmt.Fprintf(&b, "%-5s HELD by %s for %s, %s left\n", r.Name, who, span(l.Age()), span(l.Remaining()))
		}
		if held && l.Reason != "" {
			fmt.Fprintf(&b, "        why: %s\n", l.Reason)
		}
		if held && len(l.Pids) > 0 {
			fmt.Fprintf(&b, "        pids: %v (their registered work -- not a kill list)\n", l.Pids)
		}
		if l.StolenFrom != "" {
			fmt.Fprintf(&b, "        STOLEN from %s: %s\n", l.StolenFrom, l.StealWhy)
		}
		for i, e := range q {
			mark := ""
			if e.Agent == me {
				mark = " <- you"
			}
			fmt.Fprintf(&b, "        queue %d: %s (%s waiting)%s\n", i+1, e.Agent, span(time.Since(e.sinceTime())), mark)
		}
	}
	if b.Len() == 0 {
		return "no resources defined"
	}
	return strings.TrimRight(b.String(), "\n")
}

// HoldText turns an acquire outcome into what the agent should DO, which is the
// only thing it needs. A bare "false" would leave it guessing between waiting,
// working elsewhere, and asking.
func HoldText(name, me string, got bool, cur Lease, pos int, waited time.Duration) string {
	if got {
		return fmt.Sprintf("HELD: %s is yours for %s.\n"+
			"Release it the moment the RESOURCE frees, not when your workflow finishes -- "+
			"pushing and writing up need no cores, and a peer idles the whole time.\n"+
			"  yip release %s", name, span(cur.Remaining()), name)
	}
	if cur.Holder != "" && cur.Expired() {
		return fmt.Sprintf("NOT HELD: %s's lease on %s EXPIRED %s ago (%s).\n"+
			"An expired lease is not an open one -- they may be alive and quiet, since a heartbeat "+
			"tracks turns, not work.\nAsk them first; if there is no answer: yip steal %s \"<why>\"",
			cur.Holder, name, span(-cur.Remaining()), cur.Reason, name)
	}
	if cur.Holder != "" {
		return fmt.Sprintf("WAITING: %s is held by %s (%s), about %s left. You are #%d in the queue after %s.\n"+
			"Your place is kept if you re-issue within %s, so go do something that needs no %s and come back.",
			name, cur.Holder, cur.Reason, span(cur.Remaining()), pos, span(waited),
			span(queueStaleAfter), name)
	}
	return fmt.Sprintf("WAITING: %s is unheld but you are #%d in the queue -- someone asked first. Re-issue to keep your place.", name, pos)
}

// ViolationAdvice is what to do about foreign work found on a resource you
// hold. It is prose rather than a mechanism on purpose -- see the file header.
const ViolationAdvice = `Holding a resource means nobody else STARTS work on it. It is NOT a licence to
kill what is already running:
  1. Identify the owner before believing anything. ` + "`ps`" + ` does not distinguish
     worktrees -- both tracks invoke gates by RELATIVE path, so a grep from your
     tree matches a peer's processes identically. Use
     ` + "`lsof -a -p <pid> -d cwd`" + `, or an absolute artifact path in the args.
  2. If it is a registered peer: tell them on the line and give them a grace
     period. They may have started before you acquired.
  3. If it belongs to nobody registered -- which happens, other sessions and
     stray teardowns exist -- leave it and say so. It is not evidence of a
     breach.
  4. Escalate to the operator if it persists. Killing a peer's gate destroys
     both their work and their evidence, and the killer never sees what they
     destroyed.`
