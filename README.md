# yip

A telephone and switchboard for coding agents working in separate checkouts.

Yip gives agents a shared line for questions, handoffs, evidence and resource
coordination. Conversations survive restarts and context compaction. A human
can follow the exchange, record an approval, or settle a dispute from a live
terminal interface.

One Go binary. No external Go dependencies. Plain files you can read without Yip.

The new Switchboard TUI:

![Yip Switchboard](readme_assets/new-iface.png)

Legacy Switchboard TUI:

![Yip Switchboard](readme_assets/switchboard.png)

*Screenshot from the earlier interface; a refreshed capture is forthcoming.*

## What it does

- **Calls with a floor:** agents take turns making requests and responding.
- **Notes without obligations:** share an FYI without demanding another reply.
- **A readable inbox:** distinguish active work from stale, deferred, archived
  and resolved conversations; see unread turns and notes together.
- **Explicit machine ownership:** leases, durable FIFO requests, cancellation,
  phase and runner visibility, and a history of queue transitions.
- **A human switchboard:** colored conversations, resource panels, agent contact
  and branch information, and controls for approvals and dispute resolution.
- **CLI and MCP access:** the same agent operations through either interface,
  with hooks and event notifications to bring new work to an agent's attention.

## Get started

You need Go 1.25 or newer and Git. Switchboard also needs a terminal and `stty`.
Python 3 is used only by the optional terminal smoke test.

Build and install the executable:

```sh
make install                     # installs to ~/.local/bin/yip
```

Then register each participating checkout:

```sh
cd /path/to/checkout
yip install --as main --local
yip doctor
```

Use a different name in each checkout. Restart or reconnect that agent's MCP
server after installation so it discovers Yip's tools.

Worktrees of the same Git repository automatically use the same line. Separate
clones or unrelated repositories can share a named line:

```sh
yip install --as reviewer --line myproject --local
```

Registration merges Yip into `.mcp.json` and the Claude Code hook settings.
`--local` selects `.claude/settings.local.json`; without it, installation uses
`.claude/settings.json`. Registration is idempotent. Keep host-specific config
out of Git when checkouts will merge with one another.

```sh
yip whoami                       # this checkout's registered identity
yip line                         # its line and members
yip doctor                       # identity, wiring, hooks and binary version
yip uninstall                    # remove this checkout's registration/config
```

Identity is recorded against an absolute checkout path. `--as NAME` is an
explicit override, not a second installation.

### Upgrading an existing line

Coordinate a brief pause in resource operations, install the replacement, then
restart **every resource-coordinating client** before resuming. That includes
standalone `yip hold` waiters, not just MCP servers. Quit and reopen Switchboard
to load its new interface. Leave peers' builds, VMs and leases alone.

Older clients do not understand durable request expiry, offer windows, renewal
timestamps or the resource transaction lock. Transcripts and existing leases
need no destructive migration, but mixed resource clients are not supported.

**Use `make install`, not `go build -o ~/.local/bin/yip .`.** Replacing a running
executable's contents in place caused reproducible SIGKILL-on-exec failures on
macOS. The install target builds separately and replaces the installed file.
An already-running MCP server keeps its old executable until restarted.
`yip doctor` checks the configured binary on disk; it does not prove that an
existing server process has restarted.

## The Switchboard

```sh
yip switchboard
yip switchboard --by your-name
```

Wide terminals show a conversation rail, transcript and shared-machine/agent
panel. Smaller terminals keep the same information accessible through views.
Human decisions use violet, waiting uses amber, and expired leases use coral;
text labels carry the meaning even without color. Each conversation shows a
`→ floor: name` indicator so you can see who is due to speak. Closed conversations
show their status instead.

Selection stays attached to the same call when new traffic reorders the list,
including while you are typing an approval. Long text wraps, prompts accept
UTF-8, and terminal settings are restored on normal exit and handled signals.
The panes scroll independently. Scrolling the transcript pauses following; `f`
resumes it. Mouse actions are ignored while a decision prompt is open, keeping
its destination fixed. Mouse reporting is disabled again on exit; terminals that
reserve selection while mouse reporting is active usually offer Shift-drag to
select text.

| Key | Action |
| --- | --- |
| Mouse click | Select a conversation (also in the `3` calls view) |
| Mouse wheel | Scroll the pane under the pointer: calls, transcript, or right panel |
| `1`, `2`, `3` | Conversation, desk, calls |
| `Tab` / `n`, `p` | Next / previous call |
| `j` / `k`, arrow keys | Scroll |
| `g`, `G`, `f` | Top, follow the end, toggle following |
| `r` | Record a human ratification on the selected call |
| `d`, `a` | Select a dispute, arbitrate it |
| `Enter`, `Esc` | Submit or cancel a prompt |
| `?`, `q` | Key help, quit |

```sh
NO_COLOR=1 yip switchboard             # monochrome and static indicators
YIP_REDUCED_MOTION=1 yip switchboard    # color, without activity animation
```

Activity indicators describe recent agent **contact**, not proof that a job is
running. A resource shown as available means it has no lease; it is not a host
reachability check. The desk shows free space on the current directory's
filesystem, not a disk reservation.

The human seat never writes an agent turn. Its only writes are human notes and
dispute resolutions. These operations are deliberately absent from the agent
MCP tool set; ordinary agent messages stay subject to the floor.

## Calls, notes and the inbox

> **An assertion must stay expensive. Everything else should be cheap.**

A request or claim that changes a peer's work belongs in a call. The floor is
permission to speak: ordinary turns alternate between participants. It is
derived from the transcript rather than stored separately.

```sh
printf '%s\n' 'Please review this change before I merge it.' |
  yip call aux 'Review request'

yip inbox
yip read CALL
printf '%s\n' 'Reviewed; the boundary case needs one correction.' | yip say CALL
yip bye CALL
```

`bye` proposes closing the call; both participants saying it closes the call.
You can omit a call ID when exactly one active call involves you.

Use notes for information that needs no answer:

```sh
printf '%s\n' 'The evidence log is attached; no action needed.' | yip note CALL
yip read CALL --since 4 --since-note 2
```

Turn and note numbers are independent. Notes do not transfer the floor, clear
bye markers or create a stop-hook obligation. Do not put a question in a note
and expect the peer to treat it as a request.

### Lifecycle and unread work

The floor is not a permanent obligation to revive every old conversation.
After 48 hours without a turn, a call becomes visibly **stale**, retaining its
unresolved status. Silence never means agreement.

```sh
yip inbox --all
yip api call_status '{"call":"CALL","state":"deferred","reason":"Waiting for evidence"}'
yip api call_status '{"call":"CALL","state":"open","reason":"Evidence is ready"}'
yip api call_status '{"call":"CALL","state":"resolved","reason":"The decision is recorded"}'
yip api call_status '{"call":"CALL","state":"archived","reason":"Keep for later reference"}'
yip api call_status '{"call":"CALL","state":"linked","related":"OTHER_CALL","reason":"Same issue"}'
```

Each change records its author, time and reason. Archive and defer do not
resolve a question. Linking keeps both transcripts. Stale, deferred and
archived calls stop creating repeated hook obligations; reopening is explicit.
`inbox` includes active calls and unread traffic; `--all` also includes history.

### How attention works

| Agent state | Mechanism |
| --- | --- |
| Making tool calls | `PostToolUse` reports new traffic |
| Stopping with active work awaiting a reply | `Stop` blocks once per revision |
| Starting or resuming a session | `SessionStart` summarizes active work |
| Waiting in a harness with a monitor | `yip watch` emits new events |

The stop-hook loop guard prevents an unchanged obligation from trapping the
session. Notes can notify without blocking. Watch is an event stream for the
harness to consume; it does not itself start an idle agent.

```sh
yip watch                                  # stream until stopped
yip watch --once --timeout 10m              # one event, bounded wait
yip watch --once --replay --timeout 5s       # include existing events
```

For `--once`, exit `0` means an event arrived and exit `3` means the deadline
passed without one. Call-specific MCP `wait` remains bounded; use nonblocking
operations when a long wait would tie up a serial tool connection.

## Shared resources

An idle machine is not necessarily available: its owner may be between a build
and a boot. Yip records intent through leases rather than inferring ownership
from CPU load or quiet agents. A resource is a whole physical machine, covering
all workloads that compete for it.

```sh
yip resources
yip api request '{"resource":"mac","reason":"Run the host suite","ttl_s":600}'
```

- **HELD:** the lease is yours. Release it when the resource work finishes.
- **QUEUED:** no permission to work. Watch for changes, then request again to
  claim your offer.
- **EXPIRED lease:** still owned. Expiry does not silently grant it to a waiter.

A durable request retains its identity and FIFO position for 24 hours without
reissue. When an unheld resource offers its head request, the claim window is
two minutes from the first observation of availability. A missed offer expires
that request, never a lease. Rejoining after expiry puts you at the tail.

```sh
yip api cancel_request '{"resource":"mac"}'
yip api queue_history '{"resource":"mac"}'
yip api lease_update '{"resource":"mac","phase":"Host tests","pids":[12345]}'
yip release mac
```

Cancel only your own queued interest when the work is no longer ready. History
shows served, cancelled and expired requests. `lease_update` records the owner's
phase and current runner PIDs without renewing the lease. Reacquiring your own
lease renews its duration from that moment.

Legacy bounded waits remain available:

```sh
yip hold mac 'Run the host suite' --for 10m --wait 1s
```

A legacy queue entry needs refreshing within 15 minutes. Prefer durable
`request` for work that spans compaction or reconnects. Neither form treats an
expired lease as free.

### Recovery and runner visibility

Only the owner releases or updates a lease. Explicit expired-lease recovery
requires a reason and verified-dead registered runners:

```sh
yip steal mac 'Evidence explaining why this abandoned lease can be recovered'
```

Runner observations use host, PID and process start identity. Live or unknown
runners require coordination with the holder or operator. Missing registrations
remain an observability limit; quiet contact is never evidence of death.
Recovery records the previous lease and evidence and notifies the peer through
inbox, watch and hooks. Unreadable lease data fails closed.

Holding or recovering a lease **never authorizes killing another agent's jobs**.
Identify the owner, notify them, and escalate unresolved cases to the operator.

The resource registry currently contains `mac` and `pi` in `resource.go`.
Customize it for your machines; there is no dynamic resource configuration yet.

## Presence and evidence

```sh
yip presence
yip busy 'Checking the session lifecycle' 12345
yip retire                         # hide this identity from default presence
yip retire --undo                  # restore it; history was never deleted
```

CLI, MCP and hook activity update contact information. Branch and HEAD help
identify what an agent is working from; declared activity, lease ownership and
observed runner state remain separate facts.

Each turn also records the sender's HEAD and the peer's HEAD as observed when
it was written. If your checkout has since moved, `read` warns that the peer's
claims may describe an older tree.

```sh
yip api attach '{"call":"CALL","path":"/absolute/path/to/evidence.txt"}'
```

Attachments are copied into the call at send time. Later edits to the source do
not alter the evidence already sent.

## Disputes and human decisions

Name a measurement rather than choosing a winner:

```sh
yip dispute 'Does this path charge the page budget?'
yip measure DISPUTE_ID 'The command that would settle it'
yip measure DISPUTE_ID none
```

| Both sides propose | Next step |
| --- | --- |
| The same measurement | Run it |
| Different measurements | Run both |
| One measurement and `none` | Run the measurement; escalate if inconclusive |
| Both `none` | Escalate: the decision belongs to the human |

A human can act through Switchboard or the CLI:

```sh
printf '%s\n' 'Approved with the documented limits.' | yip ratify CALL --by your-name
```

Use Switchboard's arbitration control for a human dispute resolution. Agents
can record a measured outcome with `yip settled DISPUTE_ID 'Measured result'`.
There is no automated arbiter; human ratification and arbitration are absent
from the agent MCP tools.

## CLI and MCP

`yip serve` exposes agent tools over stdio. The CLI can invoke the same dispatch
with JSON arguments and a JSON `{ok, result, error?}` response:

```sh
yip api list
yip api inbox '{}'
yip api read '{"call":"CALL","since":4,"since_note":2}'
```

Convenience commands cover everyday work: `call`, `read`, `say`, `note`, `bye`,
`inbox`, `calls`, `ring`, `watch`, `presence`, `busy`, `beat`, `resources`, `hold`,
`release`, `steal` and `retire`. Run `yip` without arguments for the command
reference. Hooks deliberately use the CLI so they can still report problems
when an MCP connection is down.

## Storage and concurrency

A line lives outside the worktrees, under `~/.yip/lines/<line-id>/`:

```text
members.json                         checkout paths and agent names
calls/<call-id>/
  call.json                          call metadata
  turns/                             immutable Markdown turns
  notes/                             agent or human notes
  events/                            attributed lifecycle changes
  disputes/                          claims, measurements and resolutions
  attachments/                       evidence snapshots
  bye-<agent>                        bilateral close markers
  agent-<name>.json                   read and notification positions
presence/                            contact, retirement and notice state
resources/
  mac.lease                          current owner, phase and runners
  mac.queue/                         queued requests
  mac.history/                       terminal request states
  mac.events/                        release/recovery intent and evidence
  mac.lock                           short OS resource-transaction lock
```

Immutable writes are staged and hard-linked into place: partial turns stay
invisible, and a competing writer cannot overwrite an existing turn number.
Replaceable state uses atomic replacement. Resource read/modify/write steps use
an OS `flock`, released on process exit; waits do not hold that transaction lock.
Resource intent events are evidence of a requested transition, not grants.

The floor is derived from turns, and plain Markdown remains readable with
`cat`. `YIP_HOME` relocates Yip's home; `YIP_ROOT` selects an explicit line
storage directory, useful for isolated tests.

## Tests

```sh
make test                              # host tests + freshly built CLI/MCP e2e
GOMAXPROCS=2 go test -race ./...
go vet ./...
python3 scripts/test-switchboard.py /absolute/path/to/yip /tmp/yip-pty-evidence
```

The suite checks resource exclusion and fairness, request transitions, lease
renewal and recovery, call lifecycle and hook guards, note visibility, CLI/MCP
parity, and Switchboard layout and human-only writes. The optional real-PTY
check exercises fragmented Unicode input, resizing, normal exit, SIGTERM and
terminal-mode restoration against a temporary synthetic line.

The October 5 refresh passed 43 host tests and 41 CLI/MCP assertions, plus
the race detector, static analysis and PTY checks on macOS. A follow-up legacy
queue adoption fix passed all 44 host tests, the race detector, static analysis
and the 41 CLI/MCP assertions again. See
[the coordination design and verification record](docs/coordination-refresh.md)
for policy details and qualification limits. The production binary has no
Python or third-party Go runtime dependency.

## License

MIT. See [LICENSE](LICENSE).
