package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const usage = `yip -- a telephone between agents working the same tree.

  yip serve                 MCP server over stdio (what the agents use)
  yip hook <event>          hook handler: posttooluse | stop | sessionstart
  yip ring                  what is waiting for me
  yip read [call]           print a transcript
  yip say  [call]           speak; body on stdin
  yip bye  [call]           propose hanging up
  yip presence [peer]       what everyone is doing
  yip busy <text> [pids..]  declare what I am doing ("" clears)
  yip beat                  stamp a heartbeat
  yip calls                 list calls
  yip whoami                which agent this worktree is
  yip setup                 print the config to paste into a worktree
  yip doctor                check the setup

Every command takes --as <agent> to override worktree detection.
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
	if len(rest) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := rest[0], rest[1:]

	switch cmd {
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
		c, err := ResolveCall(first(args), me)
		check(err)
		turns, err := Turns(c)
		check(err)
		fmt.Printf("call %s -- %s\n%s -> %s\n\n", c.ID, c.Subject, c.From, c.To)
		for _, t := range turns {
			fmt.Printf("===== turn %d -- %s -- %s\n\n%s\n\n", t.N, t.From, t.At, strings.TrimRight(t.Body, "\n"))
		}
		if len(turns) > 0 {
			MarkSeen(c, me, turns[len(turns)-1].N)
		}
		fmt.Printf("floor: %s\n", FloorHolder(c, turns))
	case "say":
		me := must(WhoAmI(as, ""))
		c, err := ResolveCall(first(args), me)
		check(err)
		b, err := io.ReadAll(os.Stdin)
		check(err)
		if len(strings.TrimSpace(string(b))) == 0 {
			check(fmt.Errorf("nothing on stdin to say"))
		}
		turns, _ := Turns(c)
		if h := FloorHolder(c, turns); h != me {
			check(fmt.Errorf("the floor is %s's", h))
		}
		ClearByes(c)
		n, err := AppendTurn(c, me, string(b), false)
		check(err)
		fmt.Printf("turn %d sent on %s\n", n, c.ID)
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
			state := "open"
			if IsClosed(c) {
				state = "closed"
			}
			mark := "  "
			if me != "" && c.Involves(me) && !IsClosed(c) && FloorHolder(c, turns) == me {
				mark = "* "
			}
			fmt.Printf("%s%-40s %s->%s  %d turns  %s  %s\n", mark, c.ID, c.From, c.To, len(turns), state, c.Subject)
		}
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
	return filepath.Join(Root(), "yip")
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

	me, err := WhoAmI(as, "")
	say(err == nil, "identity: %v", orErr(me, err))
	say(fileExists(Root()), "relay root: %s", Root())
	say(fileExists(binPath()), "binary: %s", binPath())

	if err == nil {
		for _, peer := range []string{"main", "aux", "vault"} {
			if peer == me {
				continue
			}
			wt := worktreeFor(peer)
			if !fileExists(wt) {
				continue
			}
			sha, br := GitTip(peer)
			p, seen := LoadPresence(peer)
			state := "no presence yet"
			if seen {
				state = fmt.Sprintf("last beat %s", describeAge(p.Age()))
			}
			say(sha != "", "peer %s: %s %s -- %s", peer, br, sha, state)
		}
		if rings, err := RingFor(me); err == nil {
			say(true, "ringing: %d", len(rings))
		}
	}
	if !ok {
		os.Exit(1)
	}
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
