# yip

A telephone between agents working the same tree.

The thylacine's vocalization was a high-pitched yip-bark, used between hunting
pairs to coordinate. That is what this is for.

Two or three Claude Code sessions work the same repository from different
worktrees. Until now a human carried messages between them by hand -- copying
a merge instruction out of one terminal and pasting it into another, which is
lossy for anything longer than a paragraph and impossible for a 60 KB diff
fragment. `yip` gives them a real channel and leaves the human to say, at
most, one word.

## What it is

Not a mailbox -- a **call**, with turn-taking and a mutual hangup:

    aux                                   main
     |-- call(main, "merge instruction") --->|   rings
     |                                       |   reads, has an insight
     |<---------------- say ------------------|
     |------------------ say ---------------->|
     |                                       |   executes, hits a conflict
     |<---------------- say ------------------|
     |------------------ say ---------------->|
     |-- bye --------------------------------->
     |<-------------------------------- bye ---   both agree; closed

The **floor** is what serializes it: you may speak only if you did not write
the last turn. It is derived from the turn files rather than stored, so it
cannot disagree with the transcript it describes.

**Hanging up is a proposal, not an act.** The call closes only when both sides
have said bye, and any turn by either side clears a pending one. So nobody can
hang up while the other is still mid-problem.

## Why atomic rename, not a lock

A writer stages into `.tmp/` and hard-links the result into place. Three
consequences, all structural rather than remembered:

- A partial message is **unobservable**. The reader lists a directory that can
  only ever contain complete files -- there is no half-written state to guard
  against with a sentinel.
- A writer that dies mid-write leaves a fragment in `.tmp/` that **nobody ever
  sees**. A lock-holder that dies leaves a stale lock that blocks the peer
  forever, and an agent session absolutely can die mid-write.
- `os.Link` fails if the destination exists, so two writers racing the same
  turn number cannot silently clobber one another; the loser re-renders.

Maildir has run on this for thirty years for the same reasons.

## How the phone rings

An agent between turns is not executing, so nothing can interrupt it. The ring
is therefore layered over the moments when it *is*:

| Recipient is...                     | Mechanism      | Latency         |
|-------------------------------------|----------------|-----------------|
| working (making tool calls)         | `PostToolUse`  | next tool call  |
| about to go idle owing a reply      | `Stop` (blocks)| immediate       |
| opening, resuming, or post-compact  | `SessionStart` | at open         |
| idle, owing nothing, human silent   | --             | one word        |

The `Stop` hook is the piece that makes an exchange *finish*: an agent cannot
end its turn while the floor is sitting with it. `BlockedAt` is the loop guard
-- it blocks once per turn count, and speaking advances the count, so it
re-arms without ever wedging a session.

The last row is irreducible, but small: if the human types anything at all,
`UserPromptSubmit` picks it up.

## Presence

Not every question needs a call. `presence` answers "is main running a gate",
"whose QEMU is that", "what is aux's HEAD" by reading a file:

    aux: LIVE, last beat 4s ago
      tip a1b2c3d4 (aux-2)
      busy: SMP gate, 40 boots, started 16:12
      owns pids: [41234 41250] -- do not kill these

The hook stamps the heartbeat (proves you are alive); you declare `busy`
(says what you are doing).

## The staleness stamp

Every turn records **both** worktrees' HEAD as observed when it was written.
A reader whose HEAD no longer matches gets told:

    !! written when your HEAD was 300c1320 (main); you are now at a0b41718.
       Anything this turn computed about your tree may be stale.

Without it there is no external reference at all, so no disagreement can even
be reported -- and an instruction computed against a tree that has since moved
is exactly the failure neither agent can otherwise detect.

## Two faces, one binary

    yip serve            MCP server over stdio -- what the agents use
    yip ring|read|say    CLI -- what the HOOKS use, and what a human uses

The hooks are deliberately CLI, not MCP: a hook has to work when the MCP
server is down, and the hook is exactly what would tell you it is down. A ring
system that depends on the thing it is ringing about is circular.

And the transcript is plain markdown under `calls/<id>/turns/`, so **reading a
message never requires this program**. `cat` is always enough. That is what
lets a peer who has not installed anything yet still receive the first
message.

## Layout

    $YIP_ROOT/                        default ~/projects/.thylacine-relay
      calls/0001-<slug>/
        call.json                     written once, never rewritten
        turns/0001-aux.md             one atomic create per turn
        bye-<agent>                   marker; both present => closed
        agent-<name>.json             seen / blocked / notified; one writer
      presence/<agent>.json
      yip                             the binary

Mailboxes live **outside** every worktree deliberately. Worktrees are on
different branches, so a file committed on one is invisible to the others
until merged -- which is the very thing a merge conversation is trying to
coordinate.

## Identity

Derived from the worktree, not from config, so two sessions cannot be
misconfigured into answering to the same name:

    thylacine       -> main
    thylacine-aux   -> aux
    thylacine-<x>   -> <x>

`--as <agent>` overrides.

## Install

    go build -o ~/projects/.thylacine-relay/yip .
    ~/projects/.thylacine-relay/yip init
    ~/projects/.thylacine-relay/yip setup     # prints the config to paste

`setup` emits the `.mcp.json` and the three hook blocks for the worktree you
run it in.

## Commands

    yip serve                 MCP server over stdio
    yip hook <event>          posttooluse | stop | sessionstart
    yip ring                  what is waiting for me
    yip read [call]           print a transcript
    yip say  [call]           speak; body on stdin
    yip bye  [call]           propose hanging up
    yip presence [peer]       what everyone is doing
    yip busy <text> [pids..]  declare what I am doing ("" clears)
    yip calls                 list calls
    yip whoami                which agent this worktree is
    yip doctor                check the setup
