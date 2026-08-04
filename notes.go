package main

// Notes, ratifications, disputes and attachments.
//
// The organizing rule, learned from the first real two-agent merge run over
// this channel:
//
//	AN ASSERTION MUST STAY EXPENSIVE. EVERYTHING ELSE SHOULD BE CHEAP.
//
// An assertion is a claim that changes what the peer DOES, and the floor is
// what makes it expensive -- you get one shot, so you check before speaking.
// That expense is not friction to be optimized away; it is the whole reason
// the exchange catches things. Every mechanism in this file is for traffic
// that is NOT an assertion, and each is careful not to become a cheap one.
//
// A note therefore cannot create an obligation. It does not take the floor, it
// does not clear a pending bye, and it does not make the Stop hook block. That
// is mechanical, not advisory: there is no way to reply to a note, so there is
// no way to use one to ask the peer for a decision. If you need the peer to
// choose, take the floor.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ------------------------------------------------------------------- notes

// AuthorKind separates a note written by an agent from one written by the
// human. It is the difference between "a peer told me the human approved" and
// "the human told me" -- which is exactly the distinction an always-escalate
// rule depends on, and which the protocol could not express before.
type AuthorKind string

const (
	AuthorAgent AuthorKind = "agent"
	AuthorHuman AuthorKind = "human"
)

type Note struct {
	N    int
	From string
	Kind AuthorKind
	At   string
	Body string
}

var noteNameRe = regexp.MustCompile(`^(\d{4})-([a-z0-9_-]+)\.md$`)

func notesDir(c *Call) string { return filepath.Join(c.Dir(), "notes") }

func Notes(c *Call) ([]Note, error) {
	ents, err := os.ReadDir(notesDir(c))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Note
	for _, e := range ents {
		m := noteNameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(notesDir(c), e.Name()))
		if err != nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		out = append(out, parseNote(n, m[2], string(b)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out, nil
}

func parseNote(n int, from, raw string) Note {
	no := Note{N: n, From: from, Kind: AuthorAgent, Body: raw}
	if !strings.HasPrefix(raw, "---\n") {
		return no
	}
	rest := raw[4:]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return no
	}
	no.Body = strings.TrimPrefix(rest[end+5:], "\n")
	for _, line := range strings.Split(rest[:end], "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "at":
			no.At = v
		case "kind":
			no.Kind = AuthorKind(v)
		}
	}
	return no
}

// AppendNote writes a one-way note. Deliberately does NOT touch the floor and
// does NOT clear byes -- a note is not a turn and must never be usable as a
// cheap one.
func AppendNote(c *Call, from string, kind AuthorKind, body string) (int, error) {
	if len(body) > maxTurnBytes {
		return 0, fmt.Errorf("note is %d bytes, over the %d cap", len(body), maxTurnBytes)
	}
	dir := notesDir(c)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	for attempt := 0; attempt < 16; attempt++ {
		existing, err := Notes(c)
		if err != nil {
			return 0, err
		}
		n := len(existing) + 1
		var b strings.Builder
		fmt.Fprintf(&b, "---\nnote: %d\nfrom: %s\nkind: %s\nat: %s\n", n, from, kind, now())
		if kind == AuthorAgent {
			sha, br := GitTip(from)
			fmt.Fprintf(&b, "tip: %s (%s)\n", sha, br)
		}
		fmt.Fprintf(&b, "---\n\n%s\n", strings.TrimRight(body, "\n"))

		dst := filepath.Join(dir, fmt.Sprintf("%04d-%s.md", n, sanitizeAuthor(from)))
		err = atomicCreate(dst, []byte(b.String()))
		if err == nil {
			return n, nil
		}
		if !os.IsExist(err) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("note-number contention did not settle")
}

var authorSanRe = regexp.MustCompile(`[^a-z0-9_-]+`)

func sanitizeAuthor(s string) string {
	s = authorSanRe.ReplaceAllString(strings.ToLower(s), "-")
	if s = strings.Trim(s, "-"); s == "" {
		s = "anon"
	}
	return s
}

// ---------------------------------------------------------------- disputes
//
// The measurement protocol, which exists INSTEAD of an automated arbiter.
//
// Observed across a full two-agent merge negotiation: every disagreement --
// and there were several, on genuinely contested ground -- was settled by one
// side going and measuring. Not one needed a third party. So the useful
// question when two agents disagree is not "who is right" but:
//
//	WHAT MEASUREMENT WOULD SETTLE THIS?
//
// Both name one. If they name the SAME measurement, run it and the dispute is
// over with no human involved. If they name DIFFERENT ones, run both -- one is
// usually better posed and that is visible. If NEITHER can name one, that is
// the signal that escalates: the disagreement is not factual, it is a value or
// scope judgment, which belongs to the human by right and is not delegable.
//
// That last branch is the point. It distinguishes "we disagree about a fact"
// from "we disagree about what matters", and only the second needs a person.

type Dispute struct {
	ID       string `json:"id"`
	Claim    string `json:"claim"`
	OpenedBy string `json:"opened_by"`
	At       string `json:"at"`
}

// Measurement is per-agent and single-writer, so two agents proposing at once
// cannot lose an update -- the same discipline as the rest of the on-disk
// state. A read-modify-write on one shared file would have been the bug.
type Measurement struct {
	Agent string `json:"agent"`
	Cmd   string `json:"cmd"`
	At    string `json:"at"`
}

type Resolution struct {
	By     string `json:"by"`
	Kind   string `json:"kind"` // measured | human | withdrawn
	Detail string `json:"detail"`
	At     string `json:"at"`
}

func disputesDir(c *Call) string { return filepath.Join(c.Dir(), "disputes") }
func disputeDir(c *Call, id string) string {
	return filepath.Join(disputesDir(c), id)
}

func NewDispute(c *Call, by, claim string) (*Dispute, error) {
	if err := os.MkdirAll(disputesDir(c), 0o755); err != nil {
		return nil, err
	}
	existing, _ := ListDisputes(c)
	next := len(existing) + 1
	for attempt := 0; attempt < 32; attempt++ {
		id := fmt.Sprintf("%03d-%s", next+attempt, slugify(claim))
		dir := disputeDir(c, id)
		if err := os.Mkdir(dir, 0o755); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, err
		}
		d := &Dispute{ID: id, Claim: claim, OpenedBy: by, At: now()}
		b, _ := json.MarshalIndent(d, "", "  ")
		if err := atomicCreate(filepath.Join(dir, "dispute.json"), append(b, '\n')); err != nil {
			return nil, err
		}
		return d, nil
	}
	return nil, fmt.Errorf("could not allocate a dispute id")
}

func ListDisputes(c *Call) ([]*Dispute, error) {
	ents, err := os.ReadDir(disputesDir(c))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Dispute
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(disputeDir(c, e.Name()), "dispute.json"))
		if err != nil {
			continue
		}
		var d Dispute
		if json.Unmarshal(b, &d) == nil {
			out = append(out, &d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func ResolveDispute(c *Call, id string) (*Dispute, error) {
	all, err := ListDisputes(c)
	if err != nil {
		return nil, err
	}
	if id != "" {
		for _, d := range all {
			if d.ID == id || strings.HasPrefix(d.ID, id) {
				return d, nil
			}
		}
		return nil, fmt.Errorf("no such dispute %q", id)
	}
	var open []*Dispute
	for _, d := range all {
		if _, done := DisputeResolution(c, d); !done {
			open = append(open, d)
		}
	}
	switch len(open) {
	case 0:
		return nil, fmt.Errorf("no open dispute")
	case 1:
		return open[0], nil
	default:
		var ids []string
		for _, d := range open {
			ids = append(ids, d.ID)
		}
		return nil, fmt.Errorf("%d open disputes, name one: %s", len(open), strings.Join(ids, ", "))
	}
}

func SetMeasurement(c *Call, d *Dispute, agent, cmd string) error {
	m := Measurement{Agent: agent, Cmd: cmd, At: now()}
	b, _ := json.MarshalIndent(m, "", "  ")
	return atomicReplace(filepath.Join(disputeDir(c, d.ID), "m-"+sanitizeAuthor(agent)+".json"), append(b, '\n'))
}

func Measurements(c *Call, d *Dispute) map[string]Measurement {
	out := map[string]Measurement{}
	ents, err := os.ReadDir(disputeDir(c, d.ID))
	if err != nil {
		return out
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "m-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(disputeDir(c, d.ID), e.Name()))
		if err != nil {
			continue
		}
		var m Measurement
		if json.Unmarshal(b, &m) == nil && m.Agent != "" {
			out[m.Agent] = m
		}
	}
	return out
}

func SetResolution(c *Call, d *Dispute, r Resolution) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	return atomicReplace(filepath.Join(disputeDir(c, d.ID), "resolved.json"), append(b, '\n'))
}

func DisputeResolution(c *Call, d *Dispute) (Resolution, bool) {
	var r Resolution
	b, err := os.ReadFile(filepath.Join(disputeDir(c, d.ID), "resolved.json"))
	if err != nil {
		return r, false
	}
	if json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

// DisputeStatus is the whole value of the mechanism: it says what to do next,
// and in particular it is the ONLY thing that says "this one needs a person".
func DisputeStatus(c *Call, d *Dispute) string {
	if r, done := DisputeResolution(c, d); done {
		return fmt.Sprintf("RESOLVED (%s by %s): %s", r.Kind, r.By, r.Detail)
	}
	ms := Measurements(c, d)
	both := []string{c.From, c.To}
	var missing []string
	for _, a := range both {
		if _, ok := ms[a]; !ok {
			missing = append(missing, a)
		}
	}
	switch len(missing) {
	case 2:
		return "OPEN -- neither side has named a measurement yet"
	case 1:
		return fmt.Sprintf("WAITING on %s to name a measurement", missing[0])
	}
	a, b := ms[both[0]], ms[both[1]]

	// The none-answers are tested BEFORE equality, and the order is the whole
	// correctness of this function. Two sides that both answer "none" are
	// EQUAL, so an equality-first check reports them as AGREED -- telling the
	// agents that the one case which genuinely needs a person needs nobody,
	// and inviting them to "run" a measurement that is the word "none".
	//
	// That is a false clean inside the mechanism whose entire purpose is to
	// route around false confidence, which is why it is worth a comment rather
	// than just an ordering. Caught by a test that asserted on the specific
	// string ESCALATE rather than on "some output appeared".
	if isNoneAnswer(a.Cmd) && isNoneAnswer(b.Cmd) {
		return "ESCALATE -- neither side can name a measurement, so this is NOT a factual " +
			"disagreement. It is a value or scope judgment and belongs to the human."
	}
	if isNoneAnswer(a.Cmd) || isNoneAnswer(b.Cmd) {
		return "PARTIAL -- one side named a measurement and the other could not. Run the one " +
			"that exists; if it does not settle the claim, escalate."
	}
	if normalizeCmd(a.Cmd) == normalizeCmd(b.Cmd) {
		return "AGREED on one measurement -- RUN IT; no human needed"
	}
	return "DIFFER -- two measurements proposed. Run BOTH; usually one is better posed."
}

func normalizeCmd(s string) string { return strings.Join(strings.Fields(strings.TrimSpace(s)), " ") }

// The explicit "I cannot name one" answer, which is a real and useful answer
// rather than a failure to reply.
func isNoneAnswer(s string) bool {
	switch strings.ToLower(normalizeCmd(s)) {
	case "", "none", "-", "n/a", "na", "cannot", "unmeasurable":
		return true
	}
	return false
}

// ------------------------------------------------------------- attachments

// Attachments are COPIED into the call at send time rather than referenced by
// path. An artifact that can change under the reader is worse than no artifact
// -- the same reason turns are staged and linked rather than written in place
// -- and copying also keeps the transcript self-contained.
func attachDir(c *Call) string { return filepath.Join(c.Dir(), "attachments") }

func Attach(c *Call, from, src string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if len(data) > maxTurnBytes {
		return "", fmt.Errorf("attachment is %d bytes, over the %d cap", len(data), maxTurnBytes)
	}
	if err := os.MkdirAll(attachDir(c), 0o755); err != nil {
		return "", err
	}
	base := sanitizeAuthor(filepath.Base(src))
	for attempt := 0; attempt < 64; attempt++ {
		name := base
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d", base, attempt)
		}
		dst := filepath.Join(attachDir(c), name)
		if err := atomicCreate(dst, data); err == nil {
			return dst, nil
		} else if !os.IsExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("could not name the attachment")
}
