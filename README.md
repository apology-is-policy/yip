# yip

A telephone between agents working the same tree.

The thylacine's vocalization was a high-pitched yip-bark, used between hunting
pairs to coordinate. That is what this is for.

Two or three Claude Code sessions work one repository from different worktrees.
Without a channel, a human carries messages between them by hand — copying a
merge instruction out of one terminal and pasting it into another, which is
lossy for anything longer than a paragraph and impossible for a 14 KB one.
`yip` gives them a real channel and leaves the human to say, at most, one word.

```
    aux                                   main
     |-- call(main, "merge instruction") --->|   rings
     |                                       |   reads, checks, has an insight
     |<---------------- say ------------------|
     |------------------ say ---------------->|
     |                                       |   executes, hits a conflict
     |<---------------- say ------------------|
     |------------------ say ---------------->|
     |-- bye --------------------------------->
     |<-------------------------------- bye ---   both agree; closed
```

---

## The rule the whole thing is built on

> **An assertion must stay expensive. Everything else should be cheap.**

An *assertion* is a claim that changes what the peer does. The **floor** is what
makes one expensive: you may speak only if you did not write the last turn, so
you get one shot — and that forces you to check before speaking rather than
after being contradicted.

**That expense is the feature.** It is not friction to be optimized away. In the
exchange this was built from, two agents produced seven false-cleans between
them and **not one survived**, because each was caught by the other side
checking a claim about its own code. A cheap, fast channel would have produced a
worse conversation: three "wait, actually—" messages per idea and none of the
greps.

So nothing here makes an ordinary turn cheaper. Everything here is for traffic
that is **not** an assertion — corrections, ratifications, status, artifacts —
and each verb is shaped so it cannot quietly become one.

---

## Why atomic rename, not a lock

A writer stages into `.tmp/` and hard-links the result into place. Three
consequences, all structural rather than remembered:

- A partial message is **unobservable**. The reader lists a directory that can
  only ever contain complete files — there is no half-written state to guard.
- A writer that dies mid-write leaves a fragment **nobody ever sees**. A
  lock-holder that dies leaves a stale lock that blocks the peer forever, and an
  agent session absolutely can die mid-write.
- `os.Link` fails if the destination exists, so two writers racing the same turn
  number cannot silently clobber one another; the loser re-renders.

Maildir has run on this for thirty years for the same reasons.

The **floor** is likewise *derived* from the turn files rather than stored, so it
cannot disagree with the transcript it describes.

---

## How the phone rings

An agent between turns is not executing, so nothing can interrupt it. The ring
is layered over the moments when it *is*:

| Recipient is…                      | Mechanism       | Latency        |
|------------------------------------|-----------------|----------------|
| working (making tool calls)        | `PostToolUse`   | next tool call |
| about to go idle owing a reply     | `Stop` (blocks) | immediate      |
| opening, resuming, or post-compact | `SessionStart`  | at open        |
| idle, owing nothing                | `yip watch`     | one interval   |

The `Stop` hook is what makes an exchange *finish*: an agent cannot end its turn
while the floor sits with it. `BlockedAt` is the loop guard — it blocks once per
turn count, and speaking advances the count, so it re-arms without wedging.

That last row used to read "irreducible — one word from the human". `watch`
closed it.

---

## Waiting without polling

`wait()` needs a call that already exists, so learning that a peer *opened* one
used to mean a hand-rolled shell loop. `watch` is an event stream instead: one
line of stdout per event, which is exactly the shape an agent harness wants.

```
Monitor(command: "yip watch", persistent: true)     # every event, no blocking
Bash(run_in_background: true, "yip watch --once")   # just the next one
```

An idle agent pays nothing to wait and is woken by its peer's write.

`--once` is **bounded** (10m default). A tool that fixes somebody's poll loop by
introducing an infinite one has done nothing. **Exit 0** means an event arrived;
**exit 3** means the deadline passed with nothing — which is not success and
must not be read as it.

---

## Presence

Not every question needs a call. `presence` answers "is main running a gate",
"whose QEMU is that", "what is aux's HEAD" by reading a file:

```
aux: LIVE, last beat 4s ago
  tip a1b2c3d4 (aux-2)
  busy: SMP gate, 40 boots, started 16:12
  owns pids: [41234 41250] -- do not kill these
```

The hook stamps the heartbeat (proves you are alive); you declare `busy` (says
what you are doing).

---

## The human seat

```
yip ratify [call]        speak into the call AS THE HUMAN; body on stdin
```

**Deliberately CLI-only. There is no MCP tool for it**, so an agent has no verb
that can produce a human turn. That is the enforcement, not a convention.

The gap it closes is a correctness one. "Some decisions are the human's" is
unenforceable when the only channel is agent-relayed — a peer saying *"the human
approved"* converts *the human decides* into *an agent told me the human
decided*, and those differ exactly when the guarantee is being tested. This was
observed live: one agent relayed an approval, the other correctly refused to act
on it, and resolving it cost a context switch. `ratify` is the seat that fixes
it.

---

## Notes — one-way, and unable to carry a decision

```
yip note [call]          no floor transfer, no reply owed
```

A note does not take the floor, does not clear a pending bye, and does not make
the `Stop` hook block. **There is no way to reply to one**, so it structurally
cannot be used to ask the peer to choose — which is what keeps it from becoming
a cheap assertion. If you need a decision, take the floor.

It exists because the alternative was observed: an agent holding a correction it
could not send stuffed it into `busy` (a *status* field) three times, and barged
once.

---

## When you disagree — name a measurement, not a winner

```
yip dispute "<claim>"      open one
yip measure [id] "<cmd>"   what would settle it ("none" is a real answer)
```

Every disagreement in the exchange this was built from — several, on genuinely
contested ground — was settled by one side going and measuring. **Not one needed
a third party.** So the useful question is not *who is right* but *what
measurement would settle this*:

| both sides say | verdict |
|---|---|
| the same measurement | **run it** — nobody else needed |
| different measurements | **run both** — usually one is better posed |
| one says "none" | run the other; escalate if it does not settle it |
| **both say "none"** | **escalate** — this is not a factual disagreement at all |

That last row is the point. It distinguishes *we disagree about a fact*
(measurable, no human) from *we disagree about what matters* — which is the
human's by right and is not delegable to anything.

There is deliberately **no automated arbiter**. Its trigger condition has never
occurred, and a deferred one reopens the hole `ratify` closes: *"an agent told me
the advisor decided"* is the relay problem with an extra step.

---

## Artifacts

```
yip attach --path FILE
```

Copied into the call **at send time**. An artifact that can change under the
reader is worse than none — the same reason turns are staged and linked — and
copying keeps the transcript self-contained.

---

## The staleness stamp

Every turn records **both** worktrees' HEAD as observed when it was written. A
reader whose HEAD no longer matches gets told:

```
!! written when your HEAD was 300c1320 (main); you are now at a0b41718.
   Anything this turn computed about your tree may be stale.
```

Without it there is no external reference at all, so no disagreement can even be
reported — and an instruction computed against a tree that has since moved is
exactly the failure neither agent can otherwise detect.

---

## Two faces, one binary

```
yip serve            MCP server over stdio — what the agents use
yip ring|read|say    CLI — what the HOOKS use, and what a human uses
```

The hooks are deliberately CLI, not MCP: a hook has to work when the MCP server
is down, and the hook is exactly what would tell you it is down. A ring system
that depends on the thing it is ringing about is circular.

And the transcript is plain markdown under `calls/<id>/turns/`, so **reading a
message never requires this program**. `cat` is always enough. That is what lets
a peer who has not installed anything yet still receive the first message — and
what makes a transcript survive an agent's context being compacted away.

---

## Install

Put the binary on your PATH, then run this in each checkout that should talk:

```
yip install
```

That is the whole setup. It works out which **line** the checkout belongs to,
writes `.mcp.json` and `.claude/settings.json` (**merging** into whatever is
already there), and records who lives where. Then restart Claude Code and run
`yip doctor`.

```
yip install --as reviewer      name this checkout explicitly
yip install --line myproject   group checkouts that share no repository
yip install --local            use .claude/settings.local.json instead
yip uninstall                  remove the config and leave the line
```

**Worktrees of one repository join the same line automatically** — they share a
git common dir, which is what the line is keyed on. Separate clones have no such
link, so group them with `--line`.

Two notes on what install writes:

- The hook command is guarded (`[ ! -x <bin> ] || <bin> hook …`), so a checkout
  on a machine without yip is unaffected rather than erroring on every tool call.
- It is **idempotent**. Re-installing replaces our entries rather than stacking
  another copy, identified by an explicit `# yip-line-hook` marker rather than by
  the binary's name — the name and path are yours to choose, and matching on
  those would duplicate the hooks for anyone who renamed it.

If two worktrees of one repo merge into each other, prefer `--local` and
gitignore `.mcp.json`: the binary path is host-specific, and a tracked config in
one branch collides with an untracked one in the other.

---

## Identity

**Recorded at install, keyed by the checkout's absolute path** — not derived from
a naming convention, and not a name a session picks for itself. Two sessions
therefore cannot answer to one name (install refuses a name another checkout
holds), and a peer's location is a known fact rather than a guess, which is what
lets yip read the peer's HEAD directly. `--as <agent>` overrides.

---

## Layout

```
~/.yip/lines/<line-id>/
  members.json                    checkout path -> agent name
  calls/0001-<slug>/
    call.json                     written once, never rewritten
    turns/0001-aux.md             one atomic create per turn
    notes/0001-main.md            one-way; `kind: human` for a ratification
    disputes/001-<slug>/          claim.json + one m-<agent>.json per side
    attachments/<name>            snapshots, copied at send time
    bye-<agent>                   marker; both present => closed
    agent-<name>.json             seen / blocked / notified; one writer
  presence/<agent>.json
```

A line lives **outside** every checkout deliberately. Checkouts are on different
branches, so a file committed on one is invisible to the others until merged —
which is the very thing a merge conversation is trying to coordinate.

The line id is a readable name plus a short digest of the path it was derived
from, so two unrelated repositories with the same name cannot end up sharing a
line by accident.

---

## Commands

```
yip serve                 MCP server over stdio
yip hook <event>          posttooluse | stop | sessionstart
yip ring                  what is waiting for me
yip read [call]           print a transcript
yip say  [call]           speak; body on stdin
yip note [call]           one-way; no floor, no reply owed
yip ratify [call]         speak as the HUMAN (no MCP tool exists)
yip watch                 stream events (--once, --replay, --timeout)
yip dispute ["claim"]     open one, or list with what to do next
yip measure [id] "<cmd>"  name what would settle it
yip settled [id] "<how>"  record that it is over
yip bye  [call]           propose hanging up
yip presence [peer]       what everyone is doing
yip busy <text> [pids..]  declare what I am doing ("" clears)
yip calls                 list calls
yip line                  the line and everyone on it
yip whoami                which agent this checkout is
yip doctor                check the setup
```

Every command takes `--as <agent>` to override recorded membership.

---

## Tests

```
./e2e.sh
```

24 assertions over an isolated line. Two notes on how they are written, both
learned the hard way in the same session:

- One asserts an **exit code** rather than the absence of a string, because
  "output contains no TURN" is also satisfied by no output at all — and passed
  vacuously in the first draft.
- The dispute check asserts the specific string `ESCALATE`. That is what caught
  the sharpest bug this code has had: an equality test that ran *before* the
  none-check, so two sides both answering "none" compared equal and were
  reported as **"AGREED — no human needed"**. The one case that most needs a
  person was reported as needing none.

---

## License

MIT. See [LICENSE](LICENSE).
