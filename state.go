package main

// On-disk state for yip.
//
// Everything that two agents could touch concurrently is either an atomic
// create (a turn, a bye marker) or owned by exactly one writer (presence,
// per-agent call state). Resource transitions use a short OS lock because
// their queue and lease read/modify/write steps are shared between agents.
//
// The floor -- whose turn it is to speak -- is DERIVED from the turn files
// rather than stored, so it cannot desync from the transcript it describes.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxTurnBytes = 32 << 20

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/"
}

// Root is the active line's directory: the shared place a group of checkouts
// talk through. YIP_ROOT forces an explicit one (tests, odd layouts).
func Root() string {
	if v := os.Getenv("YIP_ROOT"); v != "" {
		return v
	}
	return lineDirFor(activeLine)
}

func callsDir() string    { return filepath.Join(Root(), "calls") }
func presenceDir() string { return filepath.Join(Root(), "presence") }

func EnsureRoot() error {
	for _, d := range []string{Root(), callsDir(), presenceDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- identity

// WhoAmI resolves the calling agent from RECORDED membership keyed by the
// checkout's path -- not from a naming convention, and not from a name the
// session chooses for itself. Two sessions therefore cannot answer to one
// name, and the answer does not depend on how anybody named a directory.
func WhoAmI(override, cwd string) (string, error) {
	if override != "" {
		return override, nil
	}
	if v := os.Getenv("YIP_AGENT"); v != "" {
		return v, nil
	}
	root := checkoutRoot(cwd)
	if a := LoadMembers().AgentAt(root); a != "" {
		return a, nil
	}
	return "", fmt.Errorf("%s is not on line %s -- run `yip install` here (or pass --as)", root, activeLine)
}

// worktreeFor is a lookup, not a guess: a peer's checkout is a fact recorded
// when it joined.
func worktreeFor(agent string) string { return LoadMembers().PathOf(agent) }

func gitTopLevel(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GitTip observes an agent's HEAD directly -- all worktrees are on this
// machine, so the stamp on a message is measured, never assumed.
func GitTip(agent string) (sha, branch string) {
	dir := worktreeFor(agent)
	if dir == "" {
		return "", ""
	}
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD").Output(); err == nil {
		sha = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
		branch = strings.TrimSpace(string(out))
	}
	return
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ------------------------------------------------------------ atomic write

// atomicCreate fails if the destination exists. Used for turns and bye
// markers, where a clobber would silently drop somebody's words.
func atomicCreate(dst string, data []byte) error {
	tmp, err := stage(dst, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Link(tmp, dst)
}

// atomicReplace overwrites. Used only for state with exactly one writer.
func atomicReplace(dst string, data []byte) error {
	tmp, err := stage(dst, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, dst)
}

// The staging dir sits inside the destination's own directory so the rename
// is same-filesystem, which is what makes it atomic. That is maildir's
// actual reason for tmp/ and it applies here verbatim.
func stage(dst string, data []byte) (string, error) {
	dir := filepath.Dir(dst)
	tmpDir := filepath.Join(dir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(tmpDir, "w-")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// ------------------------------------------------------------------- calls

// Call is written once at open and never rewritten. Everything mutable is a
// separate file with a single writer or an atomic create.
type Call struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	From    string `json:"from"`
	To      string `json:"to"`
	Opened  string `json:"opened"`
}

func (c *Call) Dir() string { return filepath.Join(callsDir(), c.ID) }

func (c *Call) Peer(me string) string {
	if me == c.From {
		return c.To
	}
	return c.From
}

func (c *Call) Involves(agent string) bool { return agent == c.From || agent == c.To }

type Turn struct {
	N       int
	From    string
	At      string
	Tip     string
	PeerTip string
	Barge   bool
	Body    string
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = slugRe.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-")
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	if s == "" {
		s = "call"
	}
	return s
}

func ListCalls() ([]*Call, error) {
	ents, err := os.ReadDir(callsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Call
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		c, err := LoadCall(e.Name())
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func LoadCall(id string) (*Call, error) {
	b, err := os.ReadFile(filepath.Join(callsDir(), id, "call.json"))
	if err != nil {
		return nil, err
	}
	var c Call
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ResolveCall lets the agent omit the id when there is exactly one call it
// could plausibly mean -- the ergonomics matter, because an agent that has
// to track ids will get them wrong.
func ResolveCall(id, agent string) (*Call, error) {
	if id != "" {
		c, err := LoadCall(id)
		if err != nil {
			return nil, fmt.Errorf("no such call %q", id)
		}
		if !c.Involves(agent) {
			return nil, fmt.Errorf("call %s is between %s and %s -- not you", c.ID, c.From, c.To)
		}
		return c, nil
	}
	all, err := ListCalls()
	if err != nil {
		return nil, err
	}
	var open []*Call
	for _, c := range all {
		if c.Involves(agent) {
			turns, _ := Turns(c)
			if CallStatus(c, turns) == "open" {
				open = append(open, c)
			}
		}
	}
	switch len(open) {
	case 0:
		return nil, fmt.Errorf("no open call -- use call() to start one")
	case 1:
		return open[0], nil
	default:
		var ids []string
		for _, c := range open {
			ids = append(ids, c.ID)
		}
		return nil, fmt.Errorf("%d open calls, name one: %s", len(open), strings.Join(ids, ", "))
	}
}

func NewCall(from, to, subject string) (*Call, error) {
	if err := EnsureRoot(); err != nil {
		return nil, err
	}
	existing, _ := ListCalls()
	next := len(existing) + 1
	for attempt := 0; attempt < 32; attempt++ {
		id := fmt.Sprintf("%04d-%s", next+attempt, slugify(subject))
		dir := filepath.Join(callsDir(), id)
		if err := os.Mkdir(dir, 0o755); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, err
		}
		c := &Call{ID: id, Subject: subject, From: from, To: to, Opened: now()}
		b, _ := json.MarshalIndent(c, "", "  ")
		if err := atomicCreate(filepath.Join(dir, "call.json"), append(b, '\n')); err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, fmt.Errorf("could not allocate a call id")
}

// -------------------------------------------------------------------- turns

var turnNameRe = regexp.MustCompile(`^(\d{4})-([a-z0-9_-]+)\.md$`)

func Turns(c *Call) ([]Turn, error) {
	dir := filepath.Join(c.Dir(), "turns")
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Turn
	for _, e := range ents {
		m := turnNameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		t := parseTurn(n, m[2], string(b))
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out, nil
}

func parseTurn(n int, from, raw string) Turn {
	t := Turn{N: n, From: from, Body: raw}
	if !strings.HasPrefix(raw, "---\n") {
		return t
	}
	rest := raw[4:]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return t
	}
	head := rest[:end]
	t.Body = strings.TrimPrefix(rest[end+5:], "\n")
	for _, line := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "at":
			t.At = v
		case "tip":
			t.Tip = v
		case "peer-tip":
			t.PeerTip = v
		case "barge":
			t.Barge = v == "true"
		}
	}
	return t
}

func renderTurn(n int, from, peer, body string, barge bool) string {
	mySha, myBr := GitTip(from)
	peerSha, peerBr := GitTip(peer)
	var b strings.Builder
	fmt.Fprintf(&b, "---\n")
	fmt.Fprintf(&b, "turn: %d\n", n)
	fmt.Fprintf(&b, "from: %s\n", from)
	fmt.Fprintf(&b, "at: %s\n", now())
	fmt.Fprintf(&b, "tip: %s (%s)\n", mySha, myBr)
	fmt.Fprintf(&b, "peer-tip: %s (%s)\n", peerSha, peerBr)
	if barge {
		fmt.Fprintf(&b, "barge: true\n")
	}
	fmt.Fprintf(&b, "---\n\n")
	b.WriteString(strings.TrimRight(body, "\n"))
	b.WriteString("\n")
	return b.String()
}

// AppendTurn creates the next turn file. The turn number is embedded in the
// body, so a lost race has to re-render rather than retry blindly.
func AppendTurn(c *Call, from, body string, barge bool) (int, error) {
	if len(body) > maxTurnBytes {
		return 0, fmt.Errorf("turn body is %d bytes, over the %d cap", len(body), maxTurnBytes)
	}
	dir := filepath.Join(c.Dir(), "turns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	peer := c.Peer(from)
	for attempt := 0; attempt < 16; attempt++ {
		turns, err := Turns(c)
		if err != nil {
			return 0, err
		}
		n := len(turns) + 1
		dst := filepath.Join(dir, fmt.Sprintf("%04d-%s.md", n, from))
		err = atomicCreate(dst, []byte(renderTurn(n, from, peer, body, barge)))
		if err == nil {
			return n, nil
		}
		if !os.IsExist(err) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("turn-number contention did not settle")
}

// FloorHolder is whoever did not write the last turn. Speaking passes it
// back, so it needs no storage and cannot disagree with the transcript.
func FloorHolder(c *Call, turns []Turn) string {
	if len(turns) == 0 {
		return c.From
	}
	return c.Peer(turns[len(turns)-1].From)
}

// --------------------------------------------------------------------- bye

// bye is a proposal. The call closes only when both markers exist, and any
// turn clears them -- somebody still needed something.
func byePath(c *Call, agent string) string {
	return filepath.Join(c.Dir(), "bye-"+agent)
}

func SetBye(c *Call, agent string) error {
	_ = atomicCreate(byePath(c, agent), []byte(now()+"\n"))
	return nil
}

func HasBye(c *Call, agent string) bool {
	_, err := os.Stat(byePath(c, agent))
	return err == nil
}

func ClearByes(c *Call) {
	os.Remove(byePath(c, c.From))
	os.Remove(byePath(c, c.To))
}

func IsClosed(c *Call) bool { return HasBye(c, c.From) && HasBye(c, c.To) }

// ------------------------------------------------- per-agent, single writer

type AgentState struct {
	Seen          int `json:"seen"`
	SeenNotes     int `json:"seen_notes,omitempty"`
	NotesNotified int `json:"notes_notified,omitempty"`
	BlockedAt     int `json:"blocked_at"`  // Stop-hook loop guard
	NotifiedAt    int `json:"notified_at"` // PostToolUse repeat guard
}

func agentStatePath(c *Call, agent string) string {
	return filepath.Join(c.Dir(), "agent-"+agent+".json")
}

func LoadAgentState(c *Call, agent string) AgentState {
	var s AgentState
	if b, err := os.ReadFile(agentStatePath(c, agent)); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveAgentState(c *Call, agent string, s AgentState) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return atomicReplace(agentStatePath(c, agent), append(b, '\n'))
}

// ---------------------------------------------------------------- presence

type Presence struct {
	Agent    string `json:"agent"`
	Tip      string `json:"tip"`
	Branch   string `json:"branch"`
	Beat     string `json:"beat"`
	Busy     string `json:"busy,omitempty"`
	Pids     []int  `json:"pids,omitempty"`
	LastTool string `json:"last_tool,omitempty"`
}

func presencePath(agent string) string {
	return filepath.Join(presenceDir(), agent+".json")
}

func LoadPresence(agent string) (Presence, bool) {
	var p Presence
	b, err := os.ReadFile(presencePath(agent))
	if err != nil {
		return p, false
	}
	if json.Unmarshal(b, &p) != nil {
		return p, false
	}
	return p, true
}

// Beat proves the agent is alive; Busy says what it is doing. The hook does
// the first automatically, the agent declares the second.
func Beat(agent, lastTool string) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	p, _ := LoadPresence(agent)
	p.Agent = agent
	p.Tip, p.Branch = GitTip(agent)
	p.Beat = now()
	if lastTool != "" {
		p.LastTool = lastTool
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return atomicReplace(presencePath(agent), append(b, '\n'))
}

func SetBusy(agent, text string, pids []int) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	p, _ := LoadPresence(agent)
	p.Agent = agent
	p.Tip, p.Branch = GitTip(agent)
	p.Beat = now()
	p.Busy = text
	p.Pids = pids
	b, _ := json.MarshalIndent(p, "", "  ")
	return atomicReplace(presencePath(agent), append(b, '\n'))
}

func (p Presence) Age() time.Duration {
	t, err := time.Parse(time.RFC3339, p.Beat)
	if err != nil {
		return 1 << 62
	}
	return time.Since(t)
}

// A heartbeat older than this means the peer is between turns. It is not a
// timeout on anything -- only a hint for what to tell the caller.
const liveWindow = 3 * time.Minute

func (p Presence) Live() bool { return p.Age() < liveWindow }

func describeAge(d time.Duration) string {
	switch {
	case d > 1<<60:
		return "never"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1fh ago", d.Hours())
	}
}

// ------------------------------------------------------------------- ring

type Ring struct {
	Revision  int
	Call      *Call
	LastTurn  int
	Unseen    int
	HaveFloor bool
	PeerBye   bool
	Closed    bool
}

// RingFor reports every call that wants this agent's attention: unread words
// from the peer, or the floor sitting with us.
func RingFor(agent string) ([]Ring, error) {
	calls, err := ListCalls()
	if err != nil {
		return nil, err
	}
	var out []Ring
	for _, c := range calls {
		if !c.Involves(agent) {
			continue
		}
		turns, err := Turns(c)
		if err != nil {
			continue
		}
		last := 0
		if len(turns) > 0 {
			last = turns[len(turns)-1].N
		}
		st := LoadAgentState(c, agent)
		unseen := 0
		for _, t := range turns {
			if t.N > st.Seen && t.From != agent {
				unseen++
			}
		}
		r := Ring{
			Call: c, LastTurn: last, Unseen: unseen, Revision: last + len(CallEvents(c)),
			HaveFloor: FloorHolder(c, turns) == agent,
			PeerBye:   HasBye(c, c.Peer(agent)),
			Closed:    IsClosed(c),
		}
		if r.Closed || CallStatus(c, turns) != "open" {
			continue
		}
		if r.Unseen > 0 || r.HaveFloor {
			out = append(out, r)
		}
	}
	return out, nil
}

func MarkSeen(c *Call, agent string, upto int) {
	st := LoadAgentState(c, agent)
	if upto > st.Seen {
		st.Seen = upto
		_ = SaveAgentState(c, agent, st)
	}
}
