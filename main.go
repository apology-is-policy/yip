package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const usage = `yip -- a telephone between agents working the same tree.

SETTING UP A LINE

  Run this in each checkout that should be able to talk:

    yip install

  It joins the line, writes .mcp.json and .claude/settings.json (MERGING
  into whatever is already there), and records who lives where. Worktrees
  of one repository land on the same line automatically. Separate clones
  need --line <name> to be grouped. Then restart Claude Code.

    yip install --as reviewer      name this checkout explicitly
    yip install --line myproject   group checkouts that share no repo
    yip install --local            use .claude/settings.local.json instead
    yip uninstall                  remove the config and leave the line

COMMANDS

  yip call PEER SUBJECT     open a call; body on stdin
  yip inbox [--all]         compact turns + notes + lifecycle digest
  yip api TOOL [JSON]       all agent operations, JSON result (api list)
  yip retire [--undo]       retire this identity from active views
  yip serve                 MCP server over stdio (what the agents use)
  yip hook <event>          hook handler: posttooluse | stop | sessionstart
  yip ring                  what is waiting for me
  yip read [call]           print a transcript
  yip say  [call]           speak; body on stdin
  yip note [call]           one-way; no floor, no reply owed; body on stdin
  yip bye  [call]           propose hanging up
  yip presence [peer]       what everyone is doing
  yip busy <text> [pids..]  declare what I am doing ("" clears)

SHARED MACHINES -- take the lock, do not measure the machine

  yip resources             who holds what, how long left, who is queued
  yip hold <res> <reason>   take it, blocking until free (--wait 60s, --now)
                            --for 2h sets the TTL; trailing pids register work
  yip release <res>         give it back; the next waiter's block resolves
  yip steal <res> <why>     take an EXPIRED lease. Recorded. Tell them.

  A quiet machine is NOT a free one: an idle host and one BETWEEN PHASES of
  a peer's gate are identical on every dimension you can measure. Only the
  holder's word ends a claim -- so leases expire on WALL CLOCK, never on a
  heartbeat, because a 40-minute gate in one call beats not at all.

  Holding means nobody else STARTS. It is not a licence to kill what runs.
  yip beat                  stamp a heartbeat
  yip calls                 list calls
  yip line                  the line and everyone on it
  yip whoami                which agent this checkout is
  yip setup                 print the config (for pasting by hand)
  yip doctor                check the setup

WAITING WITHOUT POLLING

  yip watch                 one line per event, forever (for a monitor)
  yip watch --once          exit after the first event (for a background wait)
  yip watch --replay        include what is already there
  yip watch --interval 5s   how often to look (default 2s)
  yip watch --timeout 30s   give up waiting (default 10m with --once, else never)

  Exit 0 = an event arrived. Exit 3 = the deadline passed with nothing, which
  is NOT the same as success and must not be read as it.

  Nobody should poll in a shell. Arm it and be woken:

    Monitor(command: "yip watch", persistent: true)
    Bash(run_in_background: true, command: "yip watch --once")

WHEN YOU DISAGREE -- name a measurement, not a winner

  yip dispute "<claim>"     open one
  yip dispute               list them, with what to do next
  yip measure [id] "<cmd>"  say what would settle it ("none" is a real answer)
  yip settled [id] "<how>"  record that it is over

  If both sides name the SAME measurement, run it -- no human needed. If
  NEITHER can name one, the disagreement is not factual: it is a value or
  scope call, and that is the human's by right.

THE HUMAN SEAT

  yip ratify [call]         speak into the call AS THE HUMAN; body on stdin
                            (--by <name>, defaults to $USER)
  yip switchboard           watch the exchange live; ratify and arbitrate from
                            it. No key speaks as an agent -- an assertion has
                            to stay expensive, so there is no fast lane for one.

  Deliberately CLI-only: there is no MCP tool for it, so an agent has no verb
  that can produce a human turn. "The human decides" is unenforceable when the
  only channel is agent-relayed -- this is the seat that fixes it.

Every command takes --as <agent> to override recorded membership.
The transcript is plain markdown under $YIP_ROOT/calls/<id>/turns/ --
readable with cat, so nothing here is ever required to read a message.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// --as may appear anywhere, INCLUDING before the subcommand. Strip it
	// from the whole argv first; whatever is left starts with the command.
	var as string
	var rest []string
	all := os.Args[1:]
	for i := 0; i < len(all); i++ {
		switch {
		case all[i] == "--as" && i+1 < len(all):
			as = all[i+1]
			i++
		case strings.HasPrefix(all[i], "--as="):
			as = strings.TrimPrefix(all[i], "--as=")
		default:
			rest = append(rest, all[i])
		}
	}
	// --line groups checkouts that share no repository.
	var line string
	var local bool
	var rest2 []string
	for i := 0; i < len(rest); i++ {
		switch {
		case rest[i] == "--line" && i+1 < len(rest):
			line = rest[i+1]
			i++
		case strings.HasPrefix(rest[i], "--line="):
			line = strings.TrimPrefix(rest[i], "--line=")
		case rest[i] == "--local":
			local = true
		default:
			rest2 = append(rest2, rest[i])
		}
	}
	rest = rest2

	if len(rest) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := rest[0], rest[1:]

	// Every command but install needs to know which line it is on before it
	// can find anything; install resolves its own.
	if cmd != "install" {
		switch {
		case line != "":
			activeLine = slugify(line)
		case os.Getenv("YIP_LINE") != "":
			activeLine = slugify(os.Getenv("YIP_LINE"))
		default:
			id, err := resolveLine("")
			if err == nil {
				activeLine = id
			}
		}
	}

	// A human observer does not beat as the agent registered at this checkout.
	if cmd != "serve" && cmd != "hook" && cmd != "switchboard" && cmd != "ratify" && cmd != "settled" && cmd != "install" && cmd != "retire" {
		if me, err := WhoAmI(as, ""); err == nil {
			_ = Beat(me, cmd)
		}
	}
	switch cmd {
	case "api":
		me := must(WhoAmI(as, ""))
		if len(args) == 0 {
			check(fmt.Errorf("usage: yip api TOOL [JSON]; api list lists agent tools"))
		}
		if args[0] == "list" {
			b, _ := json.MarshalIndent(tools(), "", "  ")
			fmt.Println(string(b))
			return
		}
		var a map[string]any
		var raw []byte
		if len(args) > 1 {
			raw = []byte(args[1])
		} else {
			raw, _ = io.ReadAll(os.Stdin)
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			raw = []byte("{}")
		}
		check(json.Unmarshal(raw, &a))
		out, err := (&server{me: me}).call(args[0], a)
		result := map[string]any{"ok": err == nil, "result": out}
		if err != nil {
			result["error"] = err.Error()
		}
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		if err != nil {
			os.Exit(1)
		}
	case "call":
		me := must(WhoAmI(as, ""))
		if len(args) < 2 {
			check(fmt.Errorf("usage: yip call PEER SUBJECT < body.txt"))
		}
		b, err := io.ReadAll(os.Stdin)
		check(err)
		out, err := (&server{me: me}).call("call", map[string]any{"peer": args[0], "subject": strings.Join(args[1:], " "), "body": string(b)})
		check(err)
		fmt.Println(out)
	case "inbox":
		me := must(WhoAmI(as, ""))
		out, err := Inbox(me, first(args) == "--all")
		check(err)
		fmt.Println(out)
	case "retire":
		me := must(WhoAmI(as, ""))
		check(Retire(me, first(args) != "--undo"))
		fmt.Println("retirement updated")
	case "install":
		res, err := Install("", line, as, local)
		check(err)
		verb := "joined"
		if res.Reinstall {
			verb = "rejoined"
		}
		fmt.Printf("%s line %q as %q\n", verb, res.Line, res.Agent)
		fmt.Printf("  line dir: %s\n", res.LineDir)
		fmt.Printf("  binary:   %s\n", res.Bin)
		fmt.Printf("  wrote:    %s\n", res.McpPath)
		fmt.Printf("  wrote:    %s\n", res.HookPath)
		if len(res.Peers) > 0 {
			fmt.Printf("  peers:    %s\n", strings.Join(res.Peers, ", "))
		} else {
			fmt.Printf("  peers:    none yet -- run `yip install` in another checkout\n")
		}
		fmt.Printf("\nRestart Claude Code here, then `yip doctor`.\n")
	case "uninstall":
		check(Uninstall(""))
		fmt.Println("left the line; config removed")
	case "line":
		fmt.Printf("line:     %s\n", activeLine)
		fmt.Printf("line dir: %s\n", Root())
		m := LoadMembers()
		if len(m.Members) == 0 {
			fmt.Println("members:  none -- run `yip install`")
			return
		}
		fmt.Println("members:")
		for _, name := range m.Names() {
			fmt.Printf("  %-16s %s\n", name, m.PathOf(name))
		}
	case "serve":
		me := must(WhoAmI(as, ""))
		if err := Serve(me); err != nil {
			os.Exit(1)
		}
	case "hook":
		if len(args) < 1 {
			os.Exit(0) // a malformed hook invocation must not break a session
		}
		RunHook(args[0], as)
	case "ring":
		me := must(WhoAmI(as, ""))
		out, err := RingText(me)
		check(err)
		fmt.Println(out)
	case "read":
		me := must(WhoAmI(as, ""))
		a := map[string]any{"call": first(args)}
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "--since" || args[i] == "--since-note" {
				n, err := strconv.Atoi(args[i+1])
				check(err)
				key := "since"
				if args[i] == "--since-note" {
					key = "since_note"
				}
				a[key] = float64(n)
				i++
			}
		}
		out, err := (&server{me: me}).call("read", a)
		check(err)
		fmt.Print(strings.TrimRight(out, "\n") + "\n")
	case "say":
		me := must(WhoAmI(as, ""))
		b, err := io.ReadAll(os.Stdin)
		check(err)
		out, err := (&server{me: me}).call("say", map[string]any{"call": first(args), "body": string(b)})
		check(err)
		fmt.Println(out)
	case "bye":
		me := must(WhoAmI(as, ""))
		c, err := ResolveCall(first(args), me)
		check(err)
		check(SetBye(c, me))
		if IsClosed(c) {
			fmt.Printf("call %s closed\n", c.ID)
		} else {
			fmt.Printf("bye proposed on %s; waiting for %s\n", c.ID, c.Peer(me))
		}
	case "presence":
		me, _ := WhoAmI(as, "")
		out, err := presenceText(first(args), me)
		check(err)
		fmt.Println(out)
	case "busy":
		me := must(WhoAmI(as, ""))
		if len(args) < 1 {
			check(fmt.Errorf("usage: yip busy <text> [pid...]"))
		}
		var pids []int
		for _, a := range args[1:] {
			if n, err := strconv.Atoi(a); err == nil {
				pids = append(pids, n)
			}
		}
		check(SetBusy(me, args[0], pids))
		fmt.Println("ok")
	case "resources":
		me, _ := WhoAmI(as, "")
		fmt.Println(ResourcesText(me))
	case "hold":
		me := must(WhoAmI(as, ""))
		var ttlS, waitS string
		args, ttlS = takeFlag(args, "--for", "2h")
		args, waitS = takeFlag(args, "--wait", "60s")
		for i, a := range args {
			if a == "--now" {
				args = append(args[:i:i], args[i+1:]...)
				waitS = "0s"
				break
			}
		}
		if len(args) < 2 {
			check(fmt.Errorf("usage: yip hold <%s> <reason> [--for 2h] [--wait 60s] [--now] [pid...]",
				strings.Join(ResourceNames(), "|")))
		}
		name := args[0]
		reason := ""
		var pids []int
		for _, a := range args[1:] {
			if n, err := strconv.Atoi(a); err == nil {
				pids = append(pids, n)
				continue
			}
			if reason != "" {
				reason += " "
			}
			reason += a
		}
		if strings.TrimSpace(reason) == "" {
			check(fmt.Errorf("hold needs a reason -- a lease nobody can read is a lock with the legibility of a stale flag"))
		}
		ttl, err := time.ParseDuration(ttlS)
		check(err)
		wait, err := time.ParseDuration(waitS)
		check(err)
		start := time.Now()
		got, cur, pos, err := Acquire(name, me, reason, ttl, wait, pids)
		check(err)
		fmt.Println(HoldText(name, me, got, cur, pos, time.Since(start)))
		if !got {
			os.Exit(1)
		}
	case "release":
		me := must(WhoAmI(as, ""))
		if len(args) < 1 {
			check(fmt.Errorf("usage: yip release <%s>", strings.Join(ResourceNames(), "|")))
		}
		l, err := Release(args[0], me)
		check(err)
		if q := Queue(args[0]); len(q) > 0 {
			fmt.Printf("released %s after %s -- %s is next and their wait will resolve.\n",
				args[0], span(l.Age()), q[0].Agent)
		} else {
			fmt.Printf("released %s after %s -- nobody is waiting.\n", args[0], span(l.Age()))
		}
	case "steal":
		me := must(WhoAmI(as, ""))
		if len(args) < 2 {
			check(fmt.Errorf("usage: yip steal <resource> <why>   (EXPIRED leases only; recorded)"))
		}
		l, err := Steal(args[0], me, strings.Join(args[1:], " "))
		check(err)
		fmt.Printf("STOLE %s from %s. Recorded, and it is on you to tell them.\nwhy: %s\n", args[0], l.StolenFrom, l.StealWhy)
	case "beat":
		me := must(WhoAmI(as, ""))
		check(Beat(me, ""))
	case "calls":
		me, _ := WhoAmI(as, "")
		calls, err := ListCalls()
		check(err)
		if len(calls) == 0 {
			fmt.Println("no calls")
			return
		}
		for _, c := range calls {
			turns, _ := Turns(c)
			state := CallStatus(c, turns)
			mark := "  "
			if me != "" && c.Involves(me) && state == "open" && FloorHolder(c, turns) == me {
				mark = "* "
			}
			fmt.Printf("%s%-40s %s->%s  %d turns  %s  %s\n", mark, c.ID, c.From, c.To, len(turns), state, c.Subject)
		}
	case "note":
		me := must(WhoAmI(as, ""))
		c, err := ResolveCall(first(args), me)
		check(err)
		body := stdinBody()
		n, err := AppendNote(c, me, AuthorAgent, body)
		check(err)
		fmt.Printf("note %d on %s (floor unchanged: %s)\n", n, c.ID, floorOf(c))
	case "ratify":
		// The human seat. No MCP tool exists for this on purpose.
		by := os.Getenv("USER")
		args, by = takeFlag(args, "--by", by)
		if by == "" {
			by = "human"
		}
		who := must(WhoAmI(as, ""))
		c, err := ResolveCall(first(args), who)
		check(err)
		n, err := AppendNote(c, by, AuthorHuman, stdinBody())
		check(err)
		fmt.Printf("ratification %d recorded on %s as %s (human)\n", n, c.ID, by)
	case "watch":
		me := must(WhoAmI(as, ""))
		var ivs, dls string
		args, ivs = takeFlag(args, "--interval", "2s")
		once := hasFlag(args, "--once")
		// A one-shot wait is bounded by default; an explicit stream is not,
		// because something else (a persistent monitor, a human) stops it.
		def := "0"
		if once {
			def = "10m"
		}
		args, dls = takeFlag(args, "--timeout", def)
		iv, err := time.ParseDuration(ivs)
		check(err)
		dl, err := time.ParseDuration(dls)
		check(err)
		if err := Watch(me, iv, dl, once, hasFlag(args, "--replay")); err != nil {
			// 3 = nothing happened, which is not the same as a failure and
			// must not read as success either.
			fmt.Fprintln(os.Stderr, "yip:", err)
			os.Exit(3)
		}
	case "dispute":
		me := must(WhoAmI(as, ""))
		var callID string
		args, callID = takeFlag(args, "--call", "")
		c, err := ResolveCall(callID, me)
		check(err)
		if claim := first(args); claim != "" {
			d, err := NewDispute(c, me, claim)
			check(err)
			fmt.Printf("dispute %s opened on %s\n  %s\n\nBoth sides now name a measurement:\n  yip measure %s \"<cmd>\"\n",
				d.ID, c.ID, d.Claim, d.ID)
			return
		}
		ds, err := ListDisputes(c)
		check(err)
		if len(ds) == 0 {
			fmt.Printf("no disputes on %s\n", c.ID)
			return
		}
		for _, d := range ds {
			fmt.Printf("%s  %s\n  %s\n", d.ID, d.Claim, DisputeStatus(c, d))
			for a, m := range Measurements(c, d) {
				fmt.Printf("    %-10s %s\n", a+":", m.Cmd)
			}
		}
	case "measure":
		me := must(WhoAmI(as, ""))
		var callID string
		args, callID = takeFlag(args, "--call", "")
		c, err := ResolveCall(callID, me)
		check(err)
		id, cmdStr := "", first(args)
		if len(args) > 1 {
			id, cmdStr = args[0], args[1]
		}
		d, err := ResolveDispute(c, id)
		check(err)
		check(SetMeasurement(c, d, me, cmdStr))
		fmt.Printf("%s recorded for %s\n%s\n", me, d.ID, DisputeStatus(c, d))
	case "settled":
		me := must(WhoAmI(as, ""))
		var callID string
		args, callID = takeFlag(args, "--call", "")
		c, err := ResolveCall(callID, me)
		check(err)
		id, how := "", first(args)
		if len(args) > 1 {
			id, how = args[0], args[1]
		}
		d, err := ResolveDispute(c, id)
		check(err)
		check(SetResolution(c, d, Resolution{By: me, Kind: "measured", Detail: how, At: now()}))
		fmt.Printf("%s resolved\n", d.ID)
	case "whoami":
		me, err := WhoAmI(as, "")
		check(err)
		sha, br := GitTip(me)
		fmt.Printf("%s  (%s  %s %s)\n", me, worktreeFor(me), br, sha)
	case "init":
		check(EnsureRoot())
		fmt.Println(Root())
	case "setup":
		me := must(WhoAmI(as, ""))
		printSetup(me)
	case "switchboard":
		// The human's live seat. It can ratify and arbitrate; it deliberately
		// has no key that speaks as an agent -- see switchboard.go.
		if err := Switchboard(parseSwitchboardArgs(args)); err != nil {
			fmt.Fprintln(os.Stderr, "switchboard:", err)
			os.Exit(1)
		}
	case "doctor":
		doctor(as)
	case "version":
		fmt.Println(serverVersion)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func first(a []string) string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}

// takeFlag pulls "--name value" (or "--name=value") out of args and returns
// what is left, so positional parsing downstream stays simple.
func takeFlag(args []string, name, def string) ([]string, string) {
	val, out := def, args[:0:0]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == name && i+1 < len(args):
			val = args[i+1]
			i++
		case strings.HasPrefix(args[i], name+"="):
			val = strings.TrimPrefix(args[i], name+"=")
		default:
			out = append(out, args[i])
		}
	}
	return out, val
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func stdinBody() string {
	b, err := io.ReadAll(os.Stdin)
	check(err)
	if len(strings.TrimSpace(string(b))) == 0 {
		check(fmt.Errorf("nothing on stdin"))
	}
	return string(b)
}

func floorOf(c *Call) string {
	turns, _ := Turns(c)
	return FloorHolder(c, turns)
}

func must(s string, err error) string {
	check(err)
	return s
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "yip:", err)
		os.Exit(1)
	}
}

func binPath() string {
	if v := os.Getenv("YIP_BIN"); v != "" {
		return v
	}
	if p, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	return "yip"
}

func printSetup(me string) {
	bin := binPath()
	fmt.Printf("# %s -- paste into %s\n\n", me, worktreeFor(me))
	fmt.Printf("## .mcp.json\n\n")
	fmt.Printf(`{
  "mcpServers": {
    "yip": { "command": %q, "args": ["serve"] }
  }
}
`, bin)
	fmt.Printf("\n## .claude/settings.json  (merge the hooks block into what is there)\n\n")
	// Guarded so the config is harmless where the binary is absent: a missing
	// yip means the hook does nothing, rather than erroring every tool call.
	g := func(event string) string {
		return fmt.Sprintf("[ ! -x %s ] || %s hook %s", bin, bin, event)
	}
	fmt.Printf(`{
  "hooks": {
    "PostToolUse": [
      { "hooks": [ { "type": "command", "command": %q } ] }
    ],
    "Stop": [
      { "hooks": [ { "type": "command", "command": %q } ] }
    ],
    "SessionStart": [
      { "matcher": "startup|resume|compact",
        "hooks": [ { "type": "command", "command": %q } ] }
    ]
  }
}
`, g("posttooluse"), g("stop"), g("sessionstart"))
}

func doctor(as string) {
	ok := true
	say := func(good bool, f string, a ...any) {
		mark := "FAIL"
		if good {
			mark = "ok  "
		} else {
			ok = false
		}
		fmt.Printf("%s %s\n", mark, fmt.Sprintf(f, a...))
	}

	root := checkoutRoot("")
	me, err := WhoAmI(as, "")
	say(err == nil, "identity: %v", orErr(me, err))
	say(true, "line: %s", activeLine)
	say(fileExists(Root()), "line dir: %s", Root())

	// "wrote the file" and "the file says what we meant" are different
	// claims, so check the config CONTENT, not that install ran.
	mcpOK, hooksIn := hookInstalled(root)
	say(mcpOK, "mcp server declared in %s/.mcp.json", root)
	say(len(hooksIn) > 0, "hooks declared in .claude/%s", orDash(strings.Join(hooksIn, ", ")))
	// One checkout, one registration. Two files each carrying a full set means
	// every event fires twice, at paths that can name different builds.
	if len(hooksIn) < 2 {
		say(true, "single registration")
	} else {
		say(false, "TWO registrations (%s) -- every event fires twice; re-run `yip install`",
			strings.Join(hooksIn, " + "))
	}

	// And the third claim, which nothing used to check: the thing the config
	// NAMES actually runs. A binary overwritten in place while something is
	// running from it can end up permanently SIGKILLed at exec, and the only
	// symptom is `Killed: 9` inside a hook error that never mentions yip.
	// And the FOURTH claim, which "runs" cannot make: the wired binary is THIS
	// build. Two installs at two paths, three weeks apart, both ran and both
	// answered "0.1.0" -- so a checkout wired to the old one passed doctor and
	// still had no lease tools after a restart. Compare what the wired binary
	// SAYS its version is against what this one says. Different answers mean a
	// stale install: re-run `yip install [--local]` from the current binary and
	// restart Claude Code (the running server keeps its old inode).
	self := binPath()
	for _, bin := range configuredBins(root) {
		runs, why := BinRuns(bin)
		if !runs {
			say(false, "binary DOES NOT RUN: %s -- %s", bin, why)
			continue
		}
		v := BinVersion(bin)
		switch {
		case v == serverVersion:
			say(true, "binary runs, current (%s): %s", v, bin)
		case v == "":
			say(false, "binary runs but reports no version: %s -- older than `yip version`; reinstall", bin)
		default:
			say(false, "binary STALE: %s reports %s, this yip (%s) is %s -- re-run `yip install` from the current binary, then restart Claude Code",
				bin, v, self, serverVersion)
		}
	}

	m := LoadMembers()
	for _, peer := range m.Names() {
		if peer == me {
			continue
		}
		wt := m.PathOf(peer)
		sha, br := GitTip(peer)
		p, seen := LoadPresence(peer)
		state := "no presence yet"
		if seen {
			state = fmt.Sprintf("last beat %s", describeAge(p.Age()))
		}
		if sha == "" {
			say(fileExists(wt), "peer %s: %s -- %s", peer, wt, state)
		} else {
			say(true, "peer %s: %s %s -- %s", peer, br, sha, state)
		}
	}
	if len(m.Members) < 2 {
		say(true, "peers: none yet -- run `yip install` in another checkout")
	}
	if err == nil {
		if rings, err := RingFor(me); err == nil {
			say(true, "ringing: %d", len(rings))
		}
	}
	if !ok {
		os.Exit(1)
	}
}

func orDash(s string) string {
	if s == "" {
		return "(none found)"
	}
	return s
}

func orErr(s string, err error) string {
	if err != nil {
		return err.Error()
	}
	return s
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
