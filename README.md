# Yip

A telephone and switchboard for coding agents working in separate checkouts.

Yip gives agents a shared line for questions, handoffs, evidence and resource
coordination. A human can follow their conversations, broadcast a request to
regroup, read each agent's reply and see who owns the build machine. Messages,
receipts and queues survive session restarts and context compaction.

One Go binary. No third-party Go dependencies. Local files you can inspect
without Yip.

![Yip Switchboard conversation view](readme_assets/new-iface.png)

## What you can do

- **Talk between agents.** Calls have alternating turns and an explicit floor;
  notes carry information without creating a reply obligation.
- **Regroup from Switchboard.** Send announcements, briefings or regroup requests
  to a chosen audience. Track each recipient's read receipt and replies.
- **Notify an idle session.** Claude Code can receive MCP Channels events;
  Codex can receive queued messages in one explicitly registered chat. Hooks
  and the inbox remain available. An optional tmux transport supports controlled
  terminal setups.
- **Share machines without guessing.** Exclusive leases, durable FIFO requests,
  runner identities and recovery history keep a quiet machine from being
  mistaken for an available one.
- **Define your own resources.** Give each line its own build hosts and optional
  disk admission guards, while preserving existing leases and queue history.
- **Keep the evidence.** Calls retain source revisions, attachments, lifecycle
  changes and disputes. Delivery journals distinguish sending from reading.

## Install the binary

Source builds need **Go 1.25+**, Git and a Unix host. Switchboard also needs a
terminal and `stty`. Python 3.11+ is used by packaging and integration tests,
not by the installed binary.

```sh
git clone https://github.com/apology-is-policy/yip.git
cd yip
make install                         # ~/.local/bin/yip
export PATH="$HOME/.local/bin:$PATH" # add to your shell configuration if needed

yip version
yip --help                           # human setup and operations
yip --help-agents                    # agent protocol and MCP/API schemas
```

Run setup inside **each participating checkout**, using a different agent name
for each one. Git worktrees share a line automatically. For separate clones or
repositories, pass the same `--line NAME` in their setup commands and subsequent
operations.

### Claude Code: Channels

Channels is the recommended notification transport when the running Claude Code
session supports it. Yip currently uses the custom-channel research-preview
route, rather than an approved public plugin:

```sh
cd /path/to/checkout
yip install --runtime claude-channels --as main --line myproject --local
claude --dangerously-load-development-channels server:yip
```

Review Claude's preview warning and normal trust prompts. The installation
merges Yip into `.mcp.json` and the hook settings; it does not change runtime
permissions or organization policy. `--local` selects
`.claude/settings.local.json` instead of `.claude/settings.json`.

The connected MCP server sends a diagnostic probe. Claude must acknowledge the
received probe through that connection before Channels becomes the preferred
notification path. Each session needs its own probe; only one Channels server
may own an agent identity at a time.

```sh
yip doctor --runtime claude-channels
yip delivery status
```

The Channels server handles delivery while Claude is open; no separate dispatcher
is needed. Busy sessions may handle notices on a later turn. Delivery does not
guarantee interruption of an executing tool, and cannot launch a closed Claude
session. Startup and Stop hooks remain; ordinary hook notifications provide a
fallback when Channels is not live and verified.

For hook-based Claude integration without Channels:

```sh
yip install --runtime claude --as main --line myproject --local
yip doctor
```

Plain `yip install` retains this hook-based setup for compatibility.

### Codex: an exact chat and a running dispatcher

```sh
cd /path/to/checkout
yip install --runtime codex --as reviewer --line myproject
```

This writes project-local `.codex/config.toml` and `.codex/hooks.json`, merging
with existing configuration and binding the line's absolute storage paths.
Reload Codex from that checkout and review the generated hooks through the
runtime's normal trust flow.

```sh
yip doctor --runtime codex --line myproject
# Use the verified UUID of the intended local chat:
yip delivery register EXACT-CHAT-UUID --line myproject
# Keep this process running in a separate terminal or your supervisor:
yip delivery dispatch --watch 1h --line myproject
```

**Registration alone does not wake Codex.** Installation starts no dispatcher.
`dispatch` without `--watch` runs once; a watch is bounded to at most 24 hours.
Only one watch can own an endpoint. Switchboard distinguishes a registered but
stopped endpoint from a running dispatcher.

The adapter requires a Codex client with `codex queue --thread ... --message ...`.
It targets the registered UUID, never a session-name guess. Setup checks do not
prove delivery: verify that the intended chat receives and acknowledges a notice.
It does not configure remote routing or promise to interrupt tools.

### Optional tmux: the “Stallman channel”

For a controlled terminal setup, explicitly register a socket and pane whose
foreground process directly runs `claude` or `codex`:

```sh
yip delivery register-tmux --socket /absolute/tmux.socket --pane %1
# Inspect this exact pane: it must be idle at its normal empty input prompt.
yip delivery dispatch-tmux --confirm-idle
```

This sends literal text followed by Enter. The endpoint binds the socket, pane,
PID and process start identity; replaced processes, shell wrappers, dead panes
and copy mode are refused. Prompt readiness is the caller's assertion, not
something Yip can infer. There is no automatic tmux fallback or watch loop.
Use a distinct identity when changing transports or replacing a registered target.

## Switchboard and broadcasts

```sh
yip switchboard --line myproject
yip switchboard --line myproject --by your-name
```

Wide terminals show the **conversations list**, selected transcript and a desk
with resource and agent state. Broadcasts stay at the top of the conversations
list, newest activity first, **including after everyone replies**. Click one to
open its transcript directly. Recipient counts, individual receipts and
chronological replies use the same colors as ordinary conversations.

Press **b** to compose a broadcast: choose recipients, choose a kind, enter the
body, review the preview and type **SEND**. Escape retains the draft in memory;
quitting Switchboard discards an unsent draft.

| Kind | Purpose |
| --- | --- |
| `announcement` | Information; no reply obligation |
| `briefing` | Ask the selected agents for reports |
| `regroup` | Bring the selected agents together around a change in direction |

The recipient list is fixed when sent. The default audience excludes retired
members and paused endpoints; an explicit selection can include them. Reading
one agent's response never marks another agent's work complete.

The same operations are available from the CLI:

```sh
printf '%s\n' 'Please report your current work and blockers.' |
  yip broadcast briefing --to main,reviewer --line myproject
yip broadcast list --line myproject
```

Agents use `broadcasts`, `broadcast_read`, `broadcast_reply` and `delivery_ack`
through MCP or `yip api`. A broadcast does not transfer a conversation's floor,
grant a resource, cancel a worker or establish verified approval. `--by` records
attribution; it is not authentication of the person using the CLI.

| Control | Action |
| --- | --- |
| Mouse click | Open a conversation or broadcast from the left list |
| Mouse wheel | Scroll the pane under the pointer |
| `1`, `2`, `3`, `4` | Transcript, desk, conversations, grouped broadcasts |
| `b` | Compose or resume a broadcast draft |
| `Tab` / `n`, `p` | Next or previous conversation/broadcast |
| `j` / `k`, arrows | Scroll |
| `g`, `G`, `f` | Top, follow the end, toggle following |
| `r` | Record human ratification on a call |
| `d`, `a` | Select a dispute, arbitrate it |
| `Enter`, `Esc` | Submit or cancel a prompt |
| `?`, `q` | Key help, quit |

Selection stays attached to its conversation when traffic reorders the list.
Mouse actions cannot change a decision's destination while its prompt is open.
Small terminals expose the same content through the numbered views.

```sh
NO_COLOR=1 yip switchboard
YIP_REDUCED_MOTION=1 yip switchboard
```

Agent activity indicators mean recent **contact**, not proof that a job is
running. Resource availability means no lease, not host reachability. Free disk
space is an observation, not a reservation. Restart Switchboard after upgrading
the executable to load the new interface.

## Delivery that survives reconnects

Yip discovers notices from retained source records and records stable event IDs
and send attempts. Registering an endpoint normally baselines existing history;
`--replay` on its **first** registration includes that history. Re-registering
does not clear receipts or silently resume a paused endpoint.

```sh
yip delivery status
yip delivery pause
yip delivery resume
yip delivery ack EVENT_ID
# Inspect an uncertain attempt before explicitly retrying it:
yip delivery retry EVENT_ID
```

`accepted` means Codex accepted a queue request; `sent` means the transport was
written. Neither means the agent read it. The receiving agent records `read`
with `delivery_ack`, then reads or responds to the underlying call/broadcast as
appropriate. A read receipt is not completion of the requested work.

Failed or uncertain attempts are retained and are not automatically resent.
An explicit retry may duplicate delivery; stable IDs let the recipient recognize
it. Pausing prevents new sends but cannot recall one already accepted.
See the [delivery operating guide](docs/delivery-and-broadcasts.md) for details.

## Calls, notes and evidence

Calls carry requests and claims with alternating turns. The **floor** is derived
from the transcript and identifies who may make the next ordinary turn.

```sh
printf '%s\n' 'Please review this change before I merge it.' |
  yip call reviewer 'Review request'
yip inbox
yip read CALL
printf '%s\n' 'The boundary case needs one correction.' | yip say CALL
yip bye CALL
```

Both participants saying `bye` closes a call. A call ID can be omitted when
exactly one active call involves the current agent.

Notes are an FYI: they do not transfer the floor or create a reply obligation.
Turn and note numbers are independent.

```sh
printf '%s\n' 'Evidence is attached; no action needed.' | yip note CALL
yip read CALL --since 4 --since-note 2
yip api attach '{"call":"CALL","path":"/absolute/path/to/evidence.txt"}'
```

Attachments are copied when sent. Turns record the observed source revisions;
reading warns when the checkout has moved beyond the revision being discussed.

Calls can be explicitly deferred, reopened, resolved, archived or linked to
another call. Each transition records its author and reason. After 48 hours
without a turn, an otherwise active call becomes stale; silence is not agreement.

```sh
yip api call_status '{"call":"CALL","state":"deferred","reason":"Waiting for evidence"}'
yip api call_status '{"call":"CALL","state":"open","reason":"Evidence is ready"}'
yip inbox --all
```

Stale, deferred and archived calls do not repeatedly block an agent's Stop hook.
The hook also guards against looping on an unchanged obligation. `SessionStart`
summarizes active work; `PostToolUse` reports new traffic where applicable.

For a harness that consumes events rather than waking a runtime directly:

```sh
yip watch --once --timeout 10m
```

`watch` does not itself wake an agent. With `--once`, exit 0 means an event
arrived; exit 3 means the deadline passed without one.

Disputes name measurements rather than electing a winner. Agents can propose
measurements and record measured outcomes; humans can ratify or arbitrate from
Switchboard. Operator authoring operations are absent from the agent MCP tool
set, though processes with the same shell/filesystem access can use the CLI.

## Shared resources

A quiet machine may be between build stages. Yip coordinates ownership through
exclusive leases and durable FIFO requests rather than CPU activity. Define one
resource for workloads competing for the same physical machine, including its
VMs; separate aliases must not grant competing leases on that machine.

```sh
yip resources
yip api request '{"resource":"builder","reason":"Run the host suite","ttl_s":600}'
yip api lease_update '{"resource":"builder","phase":"Host tests","pids":[12345]}'
yip release builder
```

A **HELD** response grants the lease. **QUEUED** does not: wait for an offer and
request again to claim it. Durable requests retain their FIFO position for
24 hours; an offer has a two-minute claim window. A missed offer expires the
request, never somebody else's lease.

```sh
yip api cancel_request '{"resource":"builder"}'
yip api queue_history '{"resource":"builder"}'
# Or let a bounded blocking command wait and acquire for you:
yip hold builder 'Run the host suite' --for 10m --wait 1m
```

Release when the resource work finishes. Phase/PID updates do not renew a lease;
reacquiring your own lease renews it. An **expired lease remains owned** until
explicit recovery. `yip steal RESOURCE REASON` requires verified-dead registered
runners; live or unknown runners require coordination. A lease never authorizes
killing another agent's jobs.

### Configure your own line

Without a registry, Yip retains the legacy `mac` and `pi` defaults. A new line can
use its own resource names:

```json
{
  "version": 1,
  "resources": [
    {
      "name": "builder",
      "description": "Build host and its VMs",
      "machine": "build-host-01"
    }
  ]
}
```

Save the proposed JSON as `resources.json`, then, after all coordinating clients
have upgraded and restarted:

```sh
yip config validate resources.json
yip config apply resources.json --clients-restarted
yip config show
```

For an existing unconfigured line, `yip config migrate --clients-restarted`
records its legacy definitions while preserving leases and queues. Config
changes protect active and historical resource identities and retain before/after
records. Optional `host`, `disk_path` and `min_free_gib` fields add local disk
admission checks; they are not ongoing disk monitoring or reservations.
See [resource configuration](docs/RESOURCE-CONFIG.md) for schema and recovery.

## CLI, MCP and storage

`yip serve` exposes agent tools over stdio. The CLI can invoke those same tools
with JSON arguments and a JSON `{ok, result, error?}` response:

```sh
yip api list
yip api inbox '{}'
yip whoami
yip line
yip presence
yip busy 'Reviewing the change'
```

Identity is registered against an absolute checkout path. `--as NAME` explicitly
overrides identity; it does not create a second registration. One active session
per identity keeps delivery and ownership unambiguous.

A line lives outside the checkouts in `~/.yip/lines/<line-id>/`:

```text
members.json           checkout membership
calls/                 Markdown turns, notes, lifecycle, disputes, attachments
broadcasts/            immutable broadcasts and per-recipient receipts/replies
delivery/              endpoint bindings, attempts, acknowledgments, owner locks
presence/              contact and retirement state
resources.json         optional resource definitions
resources/             leases, queues, history, runner and recovery evidence
config-history/        before/after resource definitions
```

Immutable records are staged and linked into place; replaceable state uses
atomic replacement and guarded read/modify/write transactions. OS locks release
on process exit. Never delete lock files to recover a running line.
`YIP_HOME` relocates the home directory; `YIP_ROOT` selects an explicit line
storage directory, useful for isolated fixtures.

## Upgrades and removal

Coordinate client restarts before changing resource schemas or policies. Include
MCP servers, hooks and standalone waiters; running mixed resource-client versions
is unsupported. Keep existing builds, VMs, leases and history intact.

Use `make install` or the supplied `scripts/install-binary.sh`. Do not build over
an installed running executable in place: that caused reproducible macOS
SIGKILL-on-exec failures. The archive installer stages a new executable, saves a
backup and renames it into place. Already-running servers retain their previous
executable until restarted; `doctor` checking the file on disk does not prove a
running server has reloaded.

`yip uninstall` removes this checkout's integration and membership while retaining
line history. Stop its session/dispatcher first and handle its leases explicitly.
`make uninstall` removes only the executable. Neither is a reason to delete
`~/.yip` or restore old lease snapshots over current coordination state.

## Development and release status

```sh
make test
GOMAXPROCS=2 go test -race ./...
go vet ./...
python3 scripts/test-switchboard.py /absolute/path/to/yip /tmp/yip-pty-evidence
python3 scripts/release.py --version YOUR_VERSION --out /absolute/output
```

Tests cover call/state concurrency, resource fairness and guards, durable delivery,
Channels handshakes, Codex routing, broadcasts, terminal interaction and install
preservation. Runtime simulations are distinct from live delivery checks.

The current local rollout was exercised on macOS arm64, including actual Claude
Channels and Codex queue delivery. Reproducible archives can target macOS/Linux
on arm64/amd64; cross-compilation alone does not qualify another runtime. Native
Windows is not supported. Archive generation does not publish a release.

See the [release guide](docs/RELEASE.md),
[package and runtime verification](docs/package-runtime-verification-2026-10-21.md)
and [broadcast rollout correction](docs/broadcast-rollout-fix-2026-10-21.md)
for commands, evidence boundaries and remaining platform work.

## License

[MIT](LICENSE).
