package main

// Binding: a Claude session answering as the worktree it works in.
//
// Several Claude sessions are often started from ONE folder -- the one
// holding the shared Claude configuration -- and each then creates a worktree
// of its own and works there. Their MCP arguments and hook commands all name
// the folder's identity, so without this they share one name: a call meant
// for one wakes whichever session armed its waiter first.
//
// `bind` records that a running Claude process answers as a worktree's
// identity instead. The worktree joins the line as an ordinary path member
// (its name is a recorded fact, as for any checkout); the binding only says
// which live session speaks for it. It replaces exactly the identity the
// session started as, wherever that identity would have been used -- MCP
// tools, hooks, the CLI in its shell -- and nothing else, so an explicit
// `--as other` still means other.
//
// A session is its Claude process: pid plus kernel start time, so a reused
// pid is not mistaken for it. The MCP server is that process's child, and
// hooks and shell commands are its descendants, so each finds its binding by
// walking its own ancestry -- up to the nearest REGISTERED Claude session, so
// a session started inside a bound one is not mistaken for it. A Claude
// session registers itself when its Yip MCP server (or rewake hook) starts:
// both are started by the Claude process directly, so each knows it. A binding ends with the
// process; a restarted or resumed session starts as its launch identity again
// and binds again.
//
// Sessions started INSIDE a worktree answer to its name by path and are
// outside this contract: bind does not fence them, in either direction.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type procID struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
}

type Binding struct {
	Session  procID `json:"session"`
	Launch   string `json:"launch"`
	Worktree string `json:"worktree"`
	Bound    string `json:"bound"`
}

type Bindings struct {
	Version int `json:"version"`
	// Boot is the kernel boot the sessions below ran in: pid and start time
	// repeat across reboots, so a file from an earlier boot binds nobody.
	Boot     string             `json:"boot"`
	Bindings map[string]Binding `json:"bindings"`
}

func bindingsPath() string { return filepath.Join(Root(), "bindings.json") }

// procStat reads a process's parent and kernel start time from /proc. The
// comm field may hold spaces and parentheses, so fields are counted from the
// last ')'.
func procStat(pid int) (ppid int, start string, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, "", false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, "", false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, "", false
	}
	ppid, err = strconv.Atoi(f[1])
	return ppid, f[19], err == nil
}

// processAncestors lists this process's ancestors, nearest first. Injectable
// so tests can stand in for a Claude process tree.
var processAncestors = func() []procID {
	var out []procID
	for pid, i := os.Getppid(), 0; pid > 1 && i < 32; i++ {
		ppid, start, ok := procStat(pid)
		if !ok {
			break
		}
		out = append(out, procID{pid, start})
		pid = ppid
	}
	return out
}

var bootID = sync.OnceValue(func() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
})

var procAlive = func(p procID) bool {
	_, start, ok := procStat(p.PID)
	return ok && start == p.Start
}

// parentSession is the Claude session of a process Claude started directly
// -- the MCP server: its parent. Zero without /proc.
func parentSession() procID {
	if anc := processAncestors(); len(anc) > 0 {
		return anc[0]
	}
	return procID{}
}

var procCmdline = func(pid int) string {
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	return string(b)
}

// hookSession is the Claude session a hook runs for. Claude runs the hook
// command in a shell: if the command exec'd yip, the parent is Claude; if
// not, the parent is that shell -- its command line carries the hook marker
// -- and Claude is the shell's parent.
func hookSession() procID {
	anc := processAncestors()
	if len(anc) == 0 {
		return procID{}
	}
	if len(anc) > 1 && isHookShell(procCmdline(anc[0].PID)) {
		return anc[1]
	}
	return anc[0]
}

// isHookShell: argv is a shell running a Yip hook command (`sh -c '...
// # yip-line-hook'`) -- not merely a process whose arguments mention the
// marker, as a Claude prompt can.
func isHookShell(cmdline string) bool {
	argv := strings.Split(strings.TrimRight(cmdline, "\x00"), "\x00")
	switch filepath.Base(argv[0]) {
	case "sh", "bash", "dash", "zsh", "ash", "ksh":
	default:
		return false
	}
	for i := 1; i+1 < len(argv); i++ {
		if argv[i] == "-c" {
			return strings.Contains(argv[i+1], hookMarker)
		}
	}
	return false
}

func sessionsDir() string { return filepath.Join(Root(), "sessions") }

// sessionPath names exactly one process: pid and start time, within the pid
// namespace that observed them and the boot they ran in. Two processes never
// share a record file, so no prune can remove a record a registrar has just
// written for a live session.
func sessionPath(p procID) string {
	boot := bootID()
	if boot == "" {
		boot = "0"
	}
	return filepath.Join(sessionsDir(), strconv.Itoa(p.PID)+"-"+p.Start+"-"+nsKey()+"-"+boot+".json")
}

var nsKey = sync.OnceValue(func() string {
	if k := strings.Trim(strings.TrimPrefix(pidNS(), "pid:"), "[]"); k != "" {
		return k
	}
	return "0"
})

type sessionRecord struct {
	Session procID `json:"session"`
	Boot    string `json:"boot"`
	// NS is the registrar's pid namespace: liveness can only be judged from
	// inside it, so only same-namespace records are pruned as dead.
	NS         string `json:"ns,omitempty"`
	Launch     string `json:"launch"`
	Registered string `json:"registered"`
}

var pidNS = sync.OnceValue(func() string {
	ns, _ := os.Readlink("/proc/self/ns/pid")
	return ns
})

// registerSession records p as a Claude session, and forgets sessions that
// have exited. Idempotent: the MCP server, the SessionStart hook and every
// rewake hook register. It takes no lock -- record files are per process, so
// a prune removes only records whose own process is gone -- and so contention
// can never leave a session unregistered: its shell would then walk past it
// to an outer session's binding.
func registerSession(p procID, launch string) error {
	if p.PID <= 1 {
		return nil
	}
	if err := os.MkdirAll(sessionsDir(), 0o755); err != nil {
		return err
	}
	if entries, rerr := os.ReadDir(sessionsDir()); rerr == nil {
		for _, e := range entries {
			var r sessionRecord
			path := filepath.Join(sessionsDir(), e.Name())
			if !strings.HasSuffix(e.Name(), ".json") || readState(path, &r) != nil || bootID() == "" {
				continue
			}
			if r.Boot != bootID() || (r.NS == pidNS() && !procAlive(r.Session)) {
				_ = os.Remove(path)
			}
		}
	}
	if isRegistered(p) {
		return nil
	}
	return writeState(sessionPath(p), sessionRecord{Session: p, Boot: bootID(), NS: pidNS(), Launch: launch, Registered: now()})
}

// isRegistered: p is a Claude session boundary. A record that exists but
// cannot be read still marks one -- crossing it could inherit an outer
// binding -- unless it reads as another boot's.
func isRegistered(p procID) bool {
	if _, err := os.Stat(sessionPath(p)); err != nil {
		return false
	}
	var r sessionRecord
	if readState(sessionPath(p), &r) != nil {
		return true
	}
	return r.Session == p && r.Boot == bootID()
}

// answeringTo: a live registered session of this namespace, other than
// except, that answers to name now -- through its binding, or through its
// launch name if it holds none (one started inside that worktree does).
// A registry it cannot read is an error, not "nobody": that would let a bind
// take a name a live session answers to.
func answeringTo(name string, except procID, b Bindings) (procID, bool, error) {
	entries, err := os.ReadDir(sessionsDir())
	if err != nil && !os.IsNotExist(err) {
		return procID{}, false, err
	}
	for _, e := range entries {
		var r sessionRecord
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if err := readState(filepath.Join(sessionsDir(), e.Name()), &r); err != nil {
			return procID{}, false, err
		}
		if r.Session == except || r.Boot != bootID() || r.NS != pidNS() || !procAlive(r.Session) {
			continue
		}
		cur := r.Launch
		for n, bd := range b.Bindings {
			if bd.Session == r.Session {
				cur = n
			}
		}
		if cur == name {
			return r.Session, true, nil
		}
	}
	return procID{}, false, nil
}

// identityFor is what a caller that started as launch answers to, fenced: a
// bound name answers only in the session that bound it. Any other Claude
// session -- one started inside the worktree, whose configuration names it,
// or one whose shell stands in its folder -- is refused, and so is a
// path-resolved caller outside any session. A person naming an identity
// outright (explicit, outside any Claude session) is honoured.
func identityFor(launch string, explicit bool) (string, error) {
	me, err := boundIdentity(launch)
	if err != nil {
		return "", err
	}
	bd, bound := liveBinding(me)
	if !bound {
		return me, nil
	}
	ns, inSession := nearestSession()
	if (inSession && ns == bd.Session) || (!inSession && explicit) {
		return me, nil
	}
	return "", fmt.Errorf("%s is bound by another live Claude session (pid %d); this process is not that session", me, bd.Session.PID)
}

// nearestSession is the closest registered Claude session above this process.
func nearestSession() (procID, bool) {
	for _, a := range processAncestors() {
		if isRegistered(a) {
			return a, true
		}
	}
	return procID{}, false
}

func loadBindingsStrict() (Bindings, error) {
	b := Bindings{Version: 1, Bindings: map[string]Binding{}}
	if err := readState(bindingsPath(), &b); err != nil {
		return b, err
	}
	if b.Version != 1 {
		return b, fmt.Errorf("%s: unsupported bindings version %d", bindingsPath(), b.Version)
	}
	if b.Bindings == nil || b.Boot != bootID() {
		b.Bindings = map[string]Binding{}
	}
	return b, nil
}

// boundIdentity is what a process that started as launch answers to: the
// identity its Claude session bound, if its nearest registered session is
// that session, else launch. A descendant of the session proves the session is
// alive. A session started inside a bound one is its own -- bound or not.
// An unreadable bindings file is an error, not "unbound": a writer acting
// under the wrong name is worse than one that stops.
func boundIdentity(launch string) (string, error) {
	if _, err := os.Stat(bindingsPath()); os.IsNotExist(err) {
		return launch, nil
	}
	b, err := loadBindingsStrict()
	if err != nil {
		return "", err
	}
	if len(b.Bindings) == 0 {
		return launch, nil
	}
	for _, a := range processAncestors() {
		for name, bd := range b.Bindings {
			if bd.Session == a && bd.Launch == launch {
				return name, nil
			}
		}
		if isRegistered(a) {
			return launch, nil
		}
	}
	return launch, nil
}

// liveBinding: the session currently speaking for name, if any.
func liveBinding(name string) (Binding, bool) {
	b, err := loadBindingsStrict()
	if err != nil {
		return Binding{}, false
	}
	bd, ok := b.Bindings[name]
	return bd, ok && procAlive(bd.Session)
}

var windowsPathRE = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// wslPath converts a Windows path for this Linux host. Injectable for tests.
var wslPath = func(p string) (string, error) {
	out, err := exec.Command("wslpath", "-u", p).Output()
	return strings.TrimSpace(string(out)), err
}

// hostPath: a Windows path (C:\x or C:/x) as WSL sees it; anything else as is.
func hostPath(p string) string {
	if windowsPathRE.MatchString(p) {
		if u, err := wslPath(p); err == nil && u != "" {
			return u
		}
	}
	return p
}

func worktreeRoot(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("give the path of your worktree")
	}
	p = hostPath(p)
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("worktree must be an absolute path, got %q", p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("worktree: %v", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("worktree %s is not a directory", p)
	}
	return checkoutRoot(p), nil
}

type bindResult struct {
	Name     string
	Worktree string
	Joined   bool
	Notes    []string
}

// Bind makes session answer as the identity of worktree instead of launch.
// Binding the launch identity's own checkout ends the binding.
func Bind(launch string, session procID, worktree, as string) (*bindResult, error) {
	if !validComponent(launch) {
		return nil, fmt.Errorf("invalid launch identity %q", launch)
	}
	ep, epErr := readEndpoint(launch)
	if epErr != nil && endpointExists(launch) {
		return nil, epErr
	}
	if epErr == nil && ep.Runtime != "claude-rewake" {
		return nil, fmt.Errorf("%s is delivered through %s, which stays with the name the session started as; bind needs the claude-rewake runtime (yip install --runtime claude-rewake)", launch, ep.Runtime)
	}
	root, err := worktreeRoot(worktree)
	if err != nil {
		return nil, err
	}
	if err := EnsureRoot(); err != nil {
		return nil, err
	}
	// Every identity change on a line is serialised by the members guard.
	unlock, err := fileGuard(membersPath())
	if err != nil {
		return nil, err
	}
	defer unlock()
	m := Members{Line: activeLine, Members: map[string]string{}}
	if err := readState(membersPath(), &m); err != nil {
		return nil, err
	}
	if m.Members == nil {
		return nil, fmt.Errorf("members map is null")
	}
	seats, err := loadSeatsStrict()
	if err != nil {
		return nil, err
	}
	b, err := loadBindingsStrict()
	if err != nil {
		return nil, err
	}
	root = recordedRoot(root, m, seats)
	name := m.AgentAt(root)
	res := &bindResult{Worktree: root}
	switch {
	case name != "" && as != "" && as != name:
		return nil, fmt.Errorf("%s is already on line %s as %q; bind it without as", root, activeLine, name)
	case name == "":
		name = as
		if name == "" {
			name = slugify(filepath.Base(root))
		}
		res.Joined = true
	}
	if !validComponent(name) {
		return nil, fmt.Errorf("invalid agent name %q", name)
	}
	if res.Joined {
		if p := m.PathOf(name); p != "" {
			return nil, fmt.Errorf("the name %q on line %s already belongs to %s; pass as with another name", name, activeLine, p)
		}
		if s, ok := seats.Seats[name]; ok {
			return nil, fmt.Errorf("the name %q on line %s is a %s; pass as with another name", name, activeLine, seatDescription(s))
		}
	} else if name != launch && isCodexIdentity(name, root) {
		return nil, fmt.Errorf("%s is %s's checkout, and %s is a Codex identity", root, name, name)
	}
	cur, bound := b.Bindings[name]
	if bound && cur.Session != session && procAlive(cur.Session) {
		return nil, fmt.Errorf("%s is bound to another live Claude session (pid %d, since %s); two sessions cannot answer to one name", name, cur.Session.PID, cur.Bound)
	}
	// Already this session's: binding again is idempotent, and a session
	// started inside the worktree since then is fenced, not answering.
	if name != launch && !(bound && cur.Session == session) {
		other, ok, err := answeringTo(name, session, b)
		if err != nil {
			return nil, fmt.Errorf("cannot tell who answers to %s: %v", name, err)
		}
		if ok {
			return nil, fmt.Errorf("a live Claude session (pid %d) answers to %s; bind a worktree of your own", other.PID, name)
		}
	}
	res.Name = name
	// A target delivered through Channels or Codex keeps that connection under
	// its name -- a second answerer the waiter cannot fence.
	if tep, terr := readEndpoint(name); name != launch && terr == nil && tep.Runtime != "claude-rewake" {
		return nil, fmt.Errorf("%s is delivered through %s; bind needs a worktree on the claude-rewake runtime or plain hooks", name, tep.Runtime)
	}
	// Prepare before committing, so a failure leaves the identity unchanged.
	if name != launch && epErr == nil {
		warning, err := ensureEndpoint(name, ep.Runtime)
		if err != nil {
			return nil, err
		}
		if warning != "" {
			res.Notes = append(res.Notes, warning)
		}
		if tep, err := readEndpoint(name); err == nil {
			unread := 0
			for _, d := range tep.Events {
				if d.Status == "sent" || d.Status == "unknown" {
					unread++
				}
			}
			if unread > 0 {
				res.Notes = append(res.Notes, fmt.Sprintf("%d notice(s) for %s went to an earlier session and were never acknowledged; see deliveries.", unread, name))
			}
		}
	}
	if res.Joined {
		m.Members[root] = name
		if err := SaveMembers(m); err != nil {
			return nil, err
		}
	}
	// What the session answers to until this commit, and where it lives.
	prev, prevWT := launch, m.PathOf(launch)
	for n, bd := range b.Bindings {
		if bd.Session == session {
			prev, prevWT = n, bd.Worktree
		}
	}
	res.Notes = append(res.Notes, leftBehind(prev, prevWT, name)...)
	for n, bd := range b.Bindings {
		if bd.Session == session || !procAlive(bd.Session) {
			delete(b.Bindings, n)
		}
	}
	if name != launch {
		b.Bindings[name] = Binding{Session: session, Launch: launch, Worktree: root, Bound: now()}
	}
	b.Version, b.Boot = 1, bootID()
	// The commit, the last step. A rewake waiter checks its identity and
	// dispatches under this same guard, so it never hands the old name's
	// notices to a session that has just stopped answering to it.
	unlockB, err := fileGuard(bindingsPath())
	if err != nil {
		return nil, err
	}
	defer unlockB()
	if err := writeState(bindingsPath(), b); err != nil {
		return nil, err
	}
	return res, nil
}

// leftBehind: what the session leaves with prev, the name it stops answering
// to. It can no longer act as prev; a launch name may be shared by others.
func leftBehind(prev, prevWT, name string) []string {
	if name == prev {
		return nil
	}
	var out []string
	for _, r := range ResourceNames() {
		if l, held := LoadLease(r); held && l.Holder == prev {
			out = append(out, fmt.Sprintf("%s holds %s; if that was this session, bind %s again to release it.", prev, r, prevWT))
		}
		for _, q := range Queue(r) {
			if q.Agent == prev {
				out = append(out, fmt.Sprintf("%s is queued for %s; that place stays with %s.", prev, r, prev))
			}
		}
	}
	if rings, err := RingFor(prev); err == nil {
		for _, r := range rings {
			if r.HaveFloor {
				out = append(out, fmt.Sprintf("%s owes a reply on %s; it stays with %s.", prev, r.Call.ID, prev))
			}
		}
	}
	return out
}

func (r *bindResult) text(launch string) string {
	var s string
	if r.Name == launch {
		s = fmt.Sprintf("You answer as %s again.", launch)
	} else {
		joined := ""
		if r.Joined {
			joined = " It joined the line just now."
		}
		s = fmt.Sprintf("You are now %s, the worktree at %s, on line %s.%s Calls to %s reach this session, and %s -- the name you started as -- no longer does. "+
			"This lasts until the session exits; after a restart or resume, bind again.", r.Name, r.Worktree, activeLine, joined, r.Name, launch)
	}
	var peers []string
	for _, n := range LineNames() {
		if n != r.Name {
			peers = append(peers, n)
		}
	}
	if len(peers) > 0 {
		s += " Peers: " + strings.Join(peers, ", ") + "."
	}
	for _, n := range r.Notes {
		s += " " + n
	}
	return s
}
