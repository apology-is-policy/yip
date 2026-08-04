package main

// The MCP face. Tool descriptions carry the protocol, so the rules arrive at
// the moment the agent is deciding rather than in a document nobody re-reads.
//
// stdout is the wire. Nothing here may print to it except protocol frames.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const serverVersion = "0.1.0"

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any   { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any   { return map[string]any{"type": "integer", "description": desc} }
func yesno(desc string) map[string]any { return map[string]any{"type": "boolean", "description": desc} }

func tools() []toolDef {
	return []toolDef{
		{
			Name: "call",
			Description: "Open a call to the other agent and speak the first turn. Rings them: " +
				"they see it on their next tool call, and they cannot end a turn while owing you a reply. " +
				"Use this for anything needing back-and-forth. For a plain status question " +
				"(is the peer running a gate, whose QEMU is that) use presence instead -- it is free and needs no answer.",
			InputSchema: obj(map[string]any{
				"peer":      str("Agent to call: main, aux, or vault."),
				"subject":   str("One line naming what this call is about."),
				"body":      str("The first turn, inline."),
				"body_path": str("Path to a file holding the first turn. Prefer this for anything long -- it keeps the payload out of the tool call."),
			}, "peer", "subject"),
		},
		{
			Name: "say",
			Description: "Speak your turn. You hold the floor only if you did NOT write the last turn; " +
				"speaking passes it back to the peer. Refuses out of turn unless barge is set, and a barge is " +
				"marked permanently in the transcript. Speaking also clears any pending bye -- somebody still needed something.",
			InputSchema: obj(map[string]any{
				"call":      str("Call id. Omit when only one call is open."),
				"body":      str("What you are saying, inline."),
				"body_path": str("Path to a file holding what you are saying. Prefer this for anything long."),
				"barge":     yesno("Speak out of turn. Only for something urgent the peer must see before continuing."),
			}),
		},
		{
			Name: "read",
			Description: "Read a call's transcript and mark it seen. Each turn is stamped with BOTH worktrees' " +
				"HEAD as observed when it was written -- if the peer-tip on a turn is not your current HEAD, " +
				"that turn predates your commits and anything it computed may be stale. Check before acting on it.",
			InputSchema: obj(map[string]any{
				"call":  str("Call id. Omit when only one call is open."),
				"since": num("Only turns after this number. Omit for the whole transcript."),
			}),
		},
		{
			Name: "wait",
			Description: "Block until the peer replies, the call closes, or the timeout expires. " +
				"Returns at once if the peer is not in a live session -- your words are already queued and will " +
				"ring at their next session start, so there is nothing to wait for. Bounded: default 60s, max 600s.",
			InputSchema: obj(map[string]any{
				"call":      str("Call id. Omit when only one call is open."),
				"timeout_s": num("Seconds to wait. Default 60, capped at 600."),
			}),
		},
		{
			Name: "bye",
			Description: "Propose hanging up. This is a PROPOSAL, not an act: the call closes only once BOTH " +
				"sides have said bye, and any say by either side clears it. So you cannot hang up while the peer " +
				"is still mid-problem. Say it when you believe the matter is settled and you need nothing further.",
			InputSchema: obj(map[string]any{
				"call": str("Call id. Omit when only one call is open."),
			}),
		},
		{
			Name: "note",
			Description: "Say something ONE-WAY: no floor transfer, no reply owed, and it does not clear a " +
				"pending bye. Use it for the traffic that should be cheap -- a correction to something you " +
				"already said, a ratification you received, a heads-up that you are stopping. " +
				"IT CANNOT CARRY A DECISION: there is no way to reply to a note, so it cannot be used to ask " +
				"the peer to choose. If you need the peer to decide, take the floor and say(). " +
				"Reach for this instead of stuffing news into busy(), and instead of barging.",
			InputSchema: obj(map[string]any{
				"call":      str("Call id. Omit when only one call is open."),
				"body":      str("What you are telling them, inline."),
				"body_path": str("Path to a file holding it. Prefer this for anything long."),
			}),
		},
		{
			Name: "dispute",
			Description: "When you and the peer disagree, open a dispute instead of arguing. Then BOTH sides " +
				"name what measurement would settle it (see measure). Same measurement -> run it, nobody else " +
				"needed. Different ones -> run both. NEITHER side can name one -> that is the signal the " +
				"disagreement is not factual at all; it is a value or scope call and belongs to the human. " +
				"Omit claim to list the open disputes and what to do next.",
			InputSchema: obj(map[string]any{
				"call":  str("Call id. Omit when only one call is open."),
				"claim": str("The disputed claim, one line. Omit to list."),
			}),
		},
		{
			Name: "measure",
			Description: "Name the measurement that would settle a dispute -- a command to run, a file to read, " +
				"an experiment. Be concrete: 'git grep -c page_budget kernel/', not 'check the code'. " +
				"\"none\" is a real and useful answer: it means you believe no measurement can settle this, " +
				"which is exactly what distinguishes a factual disagreement from a judgment call.",
			InputSchema: obj(map[string]any{
				"call":    str("Call id. Omit when only one call is open."),
				"dispute": str("Dispute id. Omit when only one is open."),
				"cmd":     str("The measurement, or \"none\"."),
			}, "cmd"),
		},
		{
			Name: "attach",
			Description: "Hand the peer a FILE. It is copied into the call at send time, so it cannot change " +
				"under them and the transcript stays self-contained. Use it instead of quoting a long artifact " +
				"into a turn -- they can still verify it independently, they just do not have to retype it first.",
			InputSchema: obj(map[string]any{
				"call": str("Call id. Omit when only one call is open."),
				"path": str("File to hand over."),
			}, "path"),
		},
		{
			Name:        "ring",
			Description: "What is waiting for you: unread turns, and calls where the floor is yours.",
			InputSchema: obj(map[string]any{}),
		},
		{
			Name: "presence",
			Description: "What the other agents are doing -- their HEAD, branch, declared work, and owned pids. " +
				"Answers 'is main running a gate' or 'whose QEMU is that' WITHOUT opening a call. " +
				"Prefer this over call for any question that does not need a reply.",
			InputSchema: obj(map[string]any{
				"peer": str("Agent to look at. Omit for everyone."),
			}),
		},
		{
			Name: "busy",
			Description: "Declare what you are working on, so the peer can see it without asking. " +
				"Set it before anything long (a gate, a multi-boot, a build) and clear it with an empty string after. " +
				"List the pids you own so the peer does not kill them.",
			InputSchema: obj(map[string]any{
				"text": str("What you are doing. Empty string clears it."),
				"pids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"},
					"description": "Process ids you own, so the peer leaves them alone."},
			}, "text"),
		},
	}
}

// ---------------------------------------------------------------- dispatch

type server struct {
	me  string
	enc *json.Encoder
}

func Serve(me string) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	s := &server{me: me, enc: json.NewEncoder(os.Stdout)}
	dec := json.NewDecoder(os.Stdin)
	for {
		var req rpcReq
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			fmt.Fprintf(os.Stderr, "yip: decode: %v\n", err)
			return err
		}
		s.handle(&req)
	}
}

func (s *server) reply(id json.RawMessage, result any) {
	if id == nil {
		return // notification
	}
	_ = s.enc.Encode(rpcResp{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *server) fail(id json.RawMessage, code int, msg string) {
	if id == nil {
		return
	}
	_ = s.enc.Encode(rpcResp{JSONRPC: "2.0", ID: id, Error: &rpcErr{Code: code, Message: msg}})
}

func (s *server) handle(req *rpcReq) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := p.ProtocolVersion
		if version == "" {
			version = "2024-11-05"
		}
		s.reply(req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "yip", "version": serverVersion},
		})
	case "notifications/initialized", "notifications/cancelled":
		// no reply
	case "ping":
		s.reply(req.ID, map[string]any{})
	case "tools/list":
		s.reply(req.ID, map[string]any{"tools": tools()})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.fail(req.ID, -32602, "bad params: "+err.Error())
			return
		}
		text, err := s.call(p.Name, p.Arguments)
		if err != nil {
			s.reply(req.ID, map[string]any{
				"content": []any{map[string]any{"type": "text", "text": err.Error()}},
				"isError": true,
			})
			return
		}
		s.reply(req.ID, map[string]any{
			"content": []any{map[string]any{"type": "text", "text": text}},
		})
	default:
		s.fail(req.ID, -32601, "unknown method "+req.Method)
	}
}

// ------------------------------------------------------------- arg helpers

func argStr(a map[string]any, k string) string {
	if v, ok := a[k].(string); ok {
		return v
	}
	return ""
}

func argBool(a map[string]any, k string) bool {
	if v, ok := a[k].(bool); ok {
		return v
	}
	return false
}

func argInt(a map[string]any, k string, def int) int {
	if v, ok := a[k].(float64); ok {
		return int(v)
	}
	return def
}

func argInts(a map[string]any, k string) []int {
	raw, ok := a[k].([]any)
	if !ok {
		return nil
	}
	var out []int
	for _, v := range raw {
		if f, ok := v.(float64); ok {
			out = append(out, int(f))
		}
	}
	return out
}

// body resolves the inline/from-file pair, refusing both or neither so a
// caller cannot silently send the wrong one.
func body(a map[string]any) (string, error) {
	inline, path := argStr(a, "body"), argStr(a, "body_path")
	switch {
	case inline != "" && path != "":
		return "", fmt.Errorf("give body or body_path, not both")
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("body_path: %v", err)
		}
		if len(b) == 0 {
			return "", fmt.Errorf("body_path %s is empty", path)
		}
		return string(b), nil
	case inline != "":
		return inline, nil
	default:
		return "", fmt.Errorf("nothing to say: give body or body_path")
	}
}

// ----------------------------------------------------------------- actions

func (s *server) call(name string, a map[string]any) (string, error) {
	switch name {
	case "call":
		return s.doCall(a)
	case "say":
		return s.doSay(a)
	case "read":
		return s.doRead(a)
	case "wait":
		return s.doWait(a)
	case "bye":
		return s.doBye(a)
	case "note":
		return s.doNote(a)
	case "dispute":
		return s.doDispute(a)
	case "measure":
		return s.doMeasure(a)
	case "attach":
		return s.doAttach(a)
	case "ring":
		return RingText(s.me)
	case "presence":
		return presenceText(argStr(a, "peer"), s.me)
	case "busy":
		if err := SetBusy(s.me, argStr(a, "text"), argInts(a, "pids")); err != nil {
			return "", err
		}
		if argStr(a, "text") == "" {
			return "busy cleared", nil
		}
		return "declared: " + argStr(a, "text"), nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// doNote deliberately does NOT clear byes and does NOT check the floor. That
// is the whole point: a note cannot create an obligation, so it cannot be used
// as a cheap assertion.
func (s *server) doNote(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	txt, err := body(a)
	if err != nil {
		return "", err
	}
	n, err := AppendNote(c, s.me, AuthorAgent, txt)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("note %d left on %s (%d bytes). The floor is unchanged (%s) and no reply is owed.",
		n, c.ID, len(txt), floorOf(c)), nil
}

func (s *server) doDispute(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	if claim := argStr(a, "claim"); claim != "" {
		d, err := NewDispute(c, s.me, claim)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("dispute %s opened.\n  %s\n\nNow BOTH sides name a measurement with measure(). "+
			"If you cannot think of one, say \"none\" -- that is a real answer and it is what tells us this "+
			"is a judgment call rather than a fact.", d.ID, d.Claim), nil
	}
	ds, err := ListDisputes(c)
	if err != nil {
		return "", err
	}
	if len(ds) == 0 {
		return "no disputes on " + c.ID, nil
	}
	var b strings.Builder
	for _, d := range ds {
		fmt.Fprintf(&b, "%s  %s\n  %s\n", d.ID, d.Claim, DisputeStatus(c, d))
		for agent, m := range Measurements(c, d) {
			fmt.Fprintf(&b, "    %-10s %s\n", agent+":", m.Cmd)
		}
	}
	return b.String(), nil
}

func (s *server) doMeasure(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	d, err := ResolveDispute(c, argStr(a, "dispute"))
	if err != nil {
		return "", err
	}
	cmd := argStr(a, "cmd")
	if strings.TrimSpace(cmd) == "" {
		return "", fmt.Errorf("give a measurement, or \"none\" if you believe none exists")
	}
	if err := SetMeasurement(c, d, s.me, cmd); err != nil {
		return "", err
	}
	return fmt.Sprintf("recorded for %s.\n%s", d.ID, DisputeStatus(c, d)), nil
}

func (s *server) doAttach(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	dst, err := Attach(c, s.me, argStr(a, "path"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("copied into the call as %s -- it is a snapshot, so it cannot change under them:\n  %s",
		filepath.Base(dst), dst), nil
}

func (s *server) doCall(a map[string]any) (string, error) {
	peer, subject := argStr(a, "peer"), argStr(a, "subject")
	if peer == "" || subject == "" {
		return "", fmt.Errorf("peer and subject are required")
	}
	if peer == s.me {
		return "", fmt.Errorf("you are %s -- cannot call yourself", s.me)
	}
	text, err := body(a)
	if err != nil {
		return "", err
	}
	c, err := NewCall(s.me, peer, subject)
	if err != nil {
		return "", err
	}
	n, err := AppendTurn(c, s.me, text, false)
	if err != nil {
		return "", err
	}
	MarkSeen(c, s.me, n)
	p, _ := LoadPresence(peer)
	live := "not in a live session -- it will ring at their next session start"
	if p.Live() {
		live = "live now -- they will see it on their next tool call"
	}
	return fmt.Sprintf("call %s opened, turn %d sent (%d bytes).\n%s is %s.\nFloor is now theirs; use wait to block for the reply.",
		c.ID, n, len(text), peer, live), nil
}

func (s *server) doSay(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	if IsClosed(c) {
		return "", fmt.Errorf("call %s is closed -- open a new one", c.ID)
	}
	text, err := body(a)
	if err != nil {
		return "", err
	}
	turns, err := Turns(c)
	if err != nil {
		return "", err
	}
	barge := argBool(a, "barge")
	if holder := FloorHolder(c, turns); holder != s.me && !barge {
		return "", fmt.Errorf("the floor is %s's -- they have not replied to turn %d yet. "+
			"Use wait, or set barge if this is urgent enough to speak over them", holder, len(turns))
	}
	ClearByes(c) // somebody still needed something
	n, err := AppendTurn(c, s.me, text, barge)
	if err != nil {
		return "", err
	}
	MarkSeen(c, s.me, n)
	note := ""
	if barge {
		note = " (BARGE -- recorded in the transcript)"
	}
	return fmt.Sprintf("turn %d sent on %s (%d bytes)%s. Floor is now %s's.",
		n, c.ID, len(text), note, c.Peer(s.me)), nil
}

func (s *server) doRead(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	turns, err := Turns(c)
	if err != nil {
		return "", err
	}
	since := argInt(a, "since", 0)
	mySha, _ := GitTip(s.me)

	var b strings.Builder
	fmt.Fprintf(&b, "call %s -- %s\n%s -> %s, opened %s\n", c.ID, c.Subject, c.From, c.To, c.Opened)
	if HasBye(c, c.Peer(s.me)) {
		fmt.Fprintf(&b, "%s has said bye -- say bye too if you need nothing further.\n", c.Peer(s.me))
	}
	fmt.Fprintf(&b, "\n")
	shown := 0
	for _, t := range turns {
		if t.N <= since {
			continue
		}
		shown++
		fmt.Fprintf(&b, "===== turn %d -- %s -- %s\n", t.N, t.From, t.At)
		if t.From != s.me && t.PeerTip != "" && mySha != "" && !strings.HasPrefix(t.PeerTip, mySha) {
			fmt.Fprintf(&b, "!! written when your HEAD was %s; you are now at %s. "+
				"Anything this turn computed about your tree may be stale.\n", t.PeerTip, mySha)
		}
		if t.Barge {
			fmt.Fprintf(&b, "!! BARGE -- spoken out of turn\n")
		}
		fmt.Fprintf(&b, "\n%s\n\n", strings.TrimRight(t.Body, "\n"))
	}
	if shown == 0 {
		fmt.Fprintf(&b, "(nothing new)\n")
	}
	if len(turns) > 0 {
		MarkSeen(c, s.me, turns[len(turns)-1].N)
	}
	if FloorHolder(c, turns) == s.me {
		fmt.Fprintf(&b, "The floor is yours.\n")
	} else {
		fmt.Fprintf(&b, "The floor is %s's.\n", FloorHolder(c, turns))
	}
	return b.String(), nil
}

func (s *server) doWait(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	timeout := time.Duration(argInt(a, "timeout_s", 60)) * time.Second
	if timeout > 600*time.Second {
		timeout = 600 * time.Second
	}
	if timeout < time.Second {
		timeout = time.Second
	}
	peer := c.Peer(s.me)

	turns, _ := Turns(c)
	start := len(turns)
	if FloorHolder(c, turns) == s.me && start > 0 {
		return fmt.Sprintf("nothing to wait for -- the floor is already yours on %s (turn %d). Read it.", c.ID, start), nil
	}
	if p, _ := LoadPresence(peer); !p.Live() {
		return fmt.Sprintf("not waiting: %s last beat %s, so they are not in a live session. "+
			"Turn %d is queued and will ring at their next session start. Carry on with something else.",
			peer, describeAge(p.Age()), start), nil
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		turns, _ = Turns(c)
		if len(turns) > start {
			return fmt.Sprintf("%s replied -- %s is now at turn %d and the floor is yours. Read it.",
				peer, c.ID, len(turns)), nil
		}
		if IsClosed(c) {
			return fmt.Sprintf("%s closed the call.", peer), nil
		}
	}
	return fmt.Sprintf("no reply within %s. %s is in a session but has not spoken -- "+
		"the turn stays queued, so carry on and check ring later.", timeout, peer), nil
}

func (s *server) doBye(a map[string]any) (string, error) {
	c, err := ResolveCall(argStr(a, "call"), s.me)
	if err != nil {
		return "", err
	}
	if err := SetBye(c, s.me); err != nil {
		return "", err
	}
	peer := c.Peer(s.me)
	if IsClosed(c) {
		return fmt.Sprintf("both sides have said bye -- call %s is closed.", c.ID), nil
	}
	return fmt.Sprintf("bye proposed on %s. It stays open until %s says bye too, "+
		"and anything either of you says clears it.", c.ID, peer), nil
}

// ------------------------------------------------------------------ render

func RingText(me string) (string, error) {
	rings, err := RingFor(me)
	if err != nil {
		return "", err
	}
	if len(rings) == 0 {
		return "nothing ringing.", nil
	}
	var b strings.Builder
	for _, r := range rings {
		fmt.Fprintf(&b, "%s -- %s (with %s)\n", r.Call.ID, r.Call.Subject, r.Call.Peer(me))
		if r.Unseen > 0 {
			fmt.Fprintf(&b, "  %d unread turn(s), through %d\n", r.Unseen, r.LastTurn)
		}
		if r.HaveFloor {
			fmt.Fprintf(&b, "  the floor is YOURS\n")
		}
		if r.PeerBye {
			fmt.Fprintf(&b, "  they have said bye -- say bye too if you need nothing further\n")
		}
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func presenceText(peer, me string) (string, error) {
	var agents []string
	if peer != "" {
		agents = []string{peer}
	} else {
		ents, _ := os.ReadDir(presenceDir())
		for _, e := range ents {
			n := strings.TrimSuffix(e.Name(), ".json")
			if n == e.Name() || strings.HasPrefix(n, ".") {
				continue
			}
			agents = append(agents, n)
		}
		sort.Strings(agents)
	}
	if len(agents) == 0 {
		return "no presence recorded yet -- nobody has beaten a heartbeat.", nil
	}
	var b strings.Builder
	for _, a := range agents {
		p, ok := LoadPresence(a)
		if !ok {
			fmt.Fprintf(&b, "%s: no presence recorded\n", a)
			continue
		}
		state := "idle"
		if p.Live() {
			state = "LIVE"
		}
		self := ""
		if a == me {
			self = " (you)"
		}
		fmt.Fprintf(&b, "%s%s: %s, last beat %s\n", a, self, state, describeAge(p.Age()))
		fmt.Fprintf(&b, "  tip %s (%s)\n", p.Tip, p.Branch)
		if p.Busy != "" {
			fmt.Fprintf(&b, "  busy: %s\n", p.Busy)
		}
		if len(p.Pids) > 0 {
			fmt.Fprintf(&b, "  owns pids: %v -- do not kill these\n", p.Pids)
		}
	}
	return strings.TrimRight(b.String(), "\n"), nil
}
