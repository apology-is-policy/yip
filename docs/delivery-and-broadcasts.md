# Delivery and broadcasts

The October 21 implementation adds transactional state updates, durable Codex
delivery, and Switchboard broadcasts. It does not install or start delivery in
existing sessions automatically. Existing resource acquisition, queue, expiry,
recovery and disk-admission rules are unchanged.

## Upgrade boundary

Build a replacement executable separately and use the existing safe installation
procedure at a coordinated boundary. Restart old Yip MCP servers and hook clients
before relying on the new state locks: an old binary does not participate in
them. The on-disk call/presence fields remain compatible; the lock files are
persistent inodes and must not be deleted while clients run.

Live coordination state must not be copied into tests or migrated as part of a
build. All verification below uses temporary fixtures. Resource configuration and offline release tooling are now documented in
RESOURCE-CONFIG.md and RELEASE.md. Actual runtime qualification and public
publication remain separate release gates. The Channels adapter is documented
in the follow-up section below.

## Codex setup

From each participating checkout, after installing the new binary:

```sh
yip install --runtime codex --as reviewer --line project
yip doctor --runtime codex
```

Installation adds a managed MCP section to `.codex/config.toml` and Yip entries
to `.codex/hooks.json`, preserving unrelated handlers, including handlers in the
same matcher group. Existing files get `.yip-backup` copies before modification.
Unmanaged references to Yip in TOML cause a refusal rather than a guessed merge.
Review those references manually. A hooks-write error attempts to restore the
prior config; backups remain available for recovery.

Restart Codex and review/trust the hooks through its normal `/hooks` workflow.
The installer does not change trust, sandbox or approval settings. Stop output
and context output use a Codex-specific serializer; Claude-only extra fields are
not forwarded. Doctor checks registrations, the wired binary/version and whether
the local `codex queue` command is available. It cannot certify runtime delivery.
See the [official hook contract](https://learn.chatgpt.com/docs/hooks).

Since the November 6 follow-up, a Codex session binds itself and its own MCP
server dispatches; see [Codex live delivery and seats](#codex-live-delivery-and-seats-november-6-follow-up).
The manual route below remains as a fallback. Register an exact existing chat
UUID explicitly:

```sh
yip delivery register 00000000-0000-4000-8000-000000000001
yip delivery dispatch --watch 1h
```

Replace the illustrative UUID with the intended chat. Installation records the
baseline; registration delivers events observed after it. Add `--replay` on the
first registration of a never-bound endpoint to include existing source records.
Re-registration is idempotent and does not unpause or rewind an endpoint. A
different UUID is rejected while the current binding is live (its session's
server holds the binding or a watch runs); otherwise the binding moves, keeping
every receipt and attempt.

Dispatch runs once without `--watch`; a watch is bounded to at most 24 hours and
checks every two seconds. Nothing launches a dispatcher automatically. It invokes
`codex queue` directly with literal arguments, never through a shell. No remote
server selection or runtime permission override is added. Queue command success
means accepted, not read or completed. The transport is documented in the
[Codex CLI reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli).

```sh
yip delivery status
yip delivery pause
yip delivery resume
yip delivery ack EVENT_ID
yip delivery retry EVENT_ID
```

Pause prevents subsequent sends; it cannot recall a message already queued.
Retirement also suppresses sending. Pending events remain on disk. A crash with
a recorded sending attempt, a timeout, or a queue error becomes uncertain and is
not retried automatically. Inspect the target chat and receipts before an explicit
retry, which can duplicate delivery. Every attempt is retained in the receipt.
Acknowledgment records reading only and never resolves a resource or task.

## Durability and source records

Each endpoint file under `delivery/` contains its binding, observed source IDs,
pending deliveries, attempt history and read receipts. Updates use an OS lock,
atomic replacement and directory sync. The sending attempt is persisted before
invoking the runtime. Competing dispatchers serialize on the same endpoint.

Delivery is reconstructed from retained call, turn, note, lifecycle and resource
records, plus broadcasts. It does not depend on the old hook notification counters.
A crash before reconciliation leaves retained source records discoverable; a crash
after it finds the same event IDs. Registration's baseline is intentionally excluded
unless replay is requested. Temporary queue offers are advisory observations; the
resource's actual current lease and request state remain authoritative. This is not
a replacement for the resource transaction log or an exact record of every transient
state between polls. Legacy hook notices remain best-effort hints; inbox and the
durable delivery records provide recovery.

The dispatcher sends batches of up to twelve concise notices. Full broadcast
bodies are read through Yip. Own acknowledgments and heartbeats do not generate
new deliveries. Corrupt endpoint/state JSON fails closed instead of being reset.
Receipt history is retained; there is no automatic pruning in this version.

## Switchboard broadcasts

Press `4` to view broadcasts and replies. Press `b` to compose:

1. Select a comma-separated recipient list. Defaults exclude retired agents and
   endpoints that are paused or unreadable; agents without endpoints remain
   available through inbox/hooks.
2. Choose announcement, regroup or briefing.
3. Enter the message and review the recipient snapshot, endpoint status and text.
   Arrow keys scroll the preview. Type `SEND` to record it.

Escape keeps the in-memory draft; `b` resumes it. Resize and send-validation errors
also retain it. Drafts are not persisted across Switchboard exit. Once recorded,
the immutable broadcast contains both the message and the full recipient list,
which is also its durable delivery intent. Sending does not require an agent call
to be selected. Recipients added to the line later are not added retroactively.

The CLI records the same objects:

```sh
printf '%s\n' 'Please report progress and blockers.' | yip broadcast briefing --to reviewer,builder --by operator
printf '%s\n' 'Regroup at your next safe checkpoint.' | yip broadcast regroup --to reviewer,builder
printf '%s\n' 'Meeting notes are ready.' | yip broadcast announcement --to reviewer,builder
yip broadcast list
```

CLI authoring is immediate. If `--to` is omitted it uses the same default audience
as Switchboard. Explicit audiences may include paused or retired recipients;
their delivery suppression still applies. A notice does not interrupt a running
tool, cancel a worker, or grant a lease.

Agent CLI and MCP share these operations:

```sh
yip api broadcasts
yip api broadcast_read '{"id":"BROADCAST_ID"}'
yip api broadcast_reply '{"id":"BROADCAST_ID","body":"Gate running; next checkpoint in ten minutes."}'
yip api deliveries
yip api delivery_ack '{"id":"EVENT_ID"}'
```

Announcement reads do not require replies. Regroup/briefing requests remain visible
as response-pending until each recipient replies. They do not take the floor of
existing calls or create automatic Stop-hook continuation loops. Switchboard shows
individual responses together; it does not manufacture a joint answer or mark
missing responses complete. This implementation uses broadcast-specific responses
rather than creating synthetic two-party calls.

The operator sender label is attribution under a trusted-local-user model, not
cryptographic proof of human approval. Agents do not get an operator broadcast
MCP tool, but same-user shell/filesystem access is not an authentication boundary.

## Verification

Use a writable temporary Go cache if the normal cache is unavailable. Limit build
parallelism and retain the deployment's disk floor. For example:

```sh
GOMAXPROCS=2 go test -race ./...
GOMAXPROCS=2 go vet ./...
go build -o /tmp/yiptest .
YIP_TEST_BIN=/tmp/yiptest bash e2e.sh
YIP_TEST_BIN=/tmp/yiptest python3 delivery_e2e.py
```

The last test requires Python 3.11+ and access to its own `/dev/tty`. It creates
temporary line/home/checkouts, uses a fake Codex executable, exercises CLI/MCP and
hook wiring, and drives the real TUI through preview, resize and send. It never
messages a real chat. Child cleanup is limited to the test's own process.

Single-agent self-review covers lost updates, monotonic cursors, ambiguous delivery,
paused recipients, retained attempts, unrelated configuration, draft routing,
terminal escaping and unchanged resource/call rules. No independent audit or live
Codex/Claude delivery qualification is implied by these isolated checks.

## Claude Channels (October 21 follow-up)

The Channels adapter is now implemented. This section supersedes the earlier
statement that Claude Channels was entirely follow-up work. This earlier checkpoint left actual Claude runtime qualification pending; see the subsequent packaging/runtime verification record for live checks. The subsequent resource
configuration and offline release tooling are documented in RESOURCE-CONFIG.md
and RELEASE.md.

Choose Channels explicitly when configuring a checkout:

```sh
yip install --runtime claude-channels --as reviewer --line project
claude --dangerously-load-development-channels server:yip
yip doctor --runtime claude-channels
yip delivery status
```

Installation merges the Yip server entry with existing `.mcp.json` entries,
configures the usual Claude hooks, and registers a Channels endpoint. It does
not enable Claude's preview, approve its warning, change organization policy,
or start a session. The startup command above is Anthropic's documented
interactive custom-channel testing route, not an allowlisted public plugin.
It does not work with `-p` or the Agent SDK. Normal `--channels` startup requires
an approved plugin. See the [Channels reference](https://code.claude.com/docs/en/channels-reference)
and [availability rules](https://code.claude.com/docs/en/channels).

For a manually configured MCP entry, register with `yip delivery register-channel`
and use `/absolute/path/yip serve --channels --as NAME --line LINE` as its command
and arguments. First registration baselines existing records. To include old
records, run `delivery register-channel --replay` with the intended identity and
line before installation. Re-registration is idempotent and never unpauses,
rewinds receipts or replaces a Codex binding. Use distinct identities for
concurrent sessions or different runtime bindings.

After MCP initialization, Yip sends one diagnostic probe. The receiving agent
must call `channel_ack` with the exact ID from the received event, on that same
MCP connection. Discovering an ID in `delivery status` and acknowledging it does
not establish delivery and is explicitly forbidden by the tool instructions.
The CLI and other MCP connections cannot certify that probe. Normal events stay
pending until this acknowledgment. `doctor --runtime claude-channels` exits zero
only while this identity has a connected, verified, unpaused, nonretired channel.
This confirms the probe path, not completion of any work.

One OS lock fences simultaneous Channels servers for an identity. Each connection
gets a new session token and probe. A crash releases the OS lock; status and hooks
check it rather than trusting a stale on-disk readiness bit. Each restart must
qualify again. Old probe and delivery attempts remain in the audit history;
old probes are never automatically resent. Use `delivery probe` to diagnose an
existing connection again. It resets readiness and sends a new probe unless
paused/retired. `delivery pause`, `resume`, `retry ID`, and ordinary `ack ID`
otherwise work as documented above. A probe requires `channel_ack`, not `ack`.

The channel loop runs inside the MCP subprocess and stops with it. It reads
retained records, using the same stable event IDs and attempt history as Codex.
No external `delivery dispatch` process is needed or allowed for this endpoint.
A successful write records `sent`, not `accepted` or `read`: Claude does not
acknowledge transport notifications. Failure records `unknown`; there is no
automatic resend. Explicit retry retains IDs and attempt history and may
produce duplicates. Agents read the authoritative source before acknowledging
ordinary notices and use `broadcast_reply` for requested briefing/regroup replies.

MCP output is serialized so notification writes cannot corrupt tool responses.
Yip negotiates the supported `2024-11-05` protocol rather than echoing unknown
client revisions. In particular, Anthropic documents that Channels cannot
register on the v2 client's `2026-07-28` revision. This is localized to Yip's
handshake; no global Claude runtime setting is changed. See [MCP channel compatibility](https://code.claude.com/docs/en/mcp#push-messages-with-channels).

Channels takes priority for routine PostToolUse notification delivery only while
this identity's connection is verified and live. The hook does not advance its
notification cursors while suppressed. Unverified, disconnected, paused or retired
endpoints fall back to existing hook behavior. SessionStart and Stop hooks retain
their existing coordination roles. Fallback can remind an agent of unread work
already sent over the channel; it must not repeat the work. An idle open Claude
can respond to a channel event; a busy one queues events for its next turn. A
channel does not launch closed sessions or guarantee interruption of running tools.

The optional built-in tmux ("Stallman channel") adapter is documented in
[the release guide](RELEASE.md#runtime-qualification). It binds an explicit socket,
pane and process identity and requires caller-confirmed idle prompt state for
every dispatch. It is never an automatic fallback. Do not run competing wake
paths for the same events.

`yip --help` now contains human setup, diagnostics, transport states, broadcasts,
resource/recovery rules and maintenance boundaries. `yip --help-agents` contains
the agent protocol plus the complete tool schema list generated from the same
registry as MCP. Both return zero and run before line resolution or presence
writes; no installation or identity is required to read them.

Codex installation binds the resolved absolute Yip state root and home in its
MCP environment and hook commands. A shared daemon need not inherit the calling
terminal environment. Reinstall and review hooks normally when relocating that
state; changing the terminal variables alone does not redirect an installed
client. No credentials or unrelated environment variables are copied.

## Codex live delivery and seats (November 6 follow-up)

This section supersedes the manual-only Codex binding above as the default.

### What Codex provides

Measured against `codex-cli 0.162.0` with an isolated `CODEX_HOME` and no
model request:

- Codex has no MCP notification that injects text into a conversation, and a
  background (`async`) hook cannot start a turn. The wake path is
  `codex queue --thread UUID`, delivered by the shared local daemon.
- The daemon starts one MCP server process per thread. Its environment is
  stripped to `HOME LANG LOGNAME PATH SHELL TERM TMPDIR USER`; `initialize`
  names no thread. Every `tools/call` carries `params._meta.threadId`.
- Shell commands Codex runs see `CODEX_THREAD_ID`, equal to that same UUID.
- `env_vars = ["CODEX_HOME"]` forwards a custom Codex home to the server; an
  unset name is skipped.
- A profile layer (`codex -p NAME`, file `$CODEX_HOME/NAME.config.toml`)
  contributes both MCP servers and inline `[[hooks.*]]` to a runtime session.
  Project `.codex/` config loads only for trusted projects.

### Live delivery

`yip install --runtime codex` writes `serve --codex` and creates an unbound
endpoint, so the install is the delivery baseline. At the session's first Yip
tool call, its server records `_meta.threadId` as the binding, holds a kernel
lock for that thread while it runs, and dispatches every two seconds with
`codex queue`. No UUID, registration or external dispatcher is required. The
tool result says once that delivery connected. Codex's MCP instructions and the
SessionStart hook ask the agent to make that first call (`ring`) early.

Until a session makes a Yip tool call, nothing can name its chat: notices stay
pending, and inbox/hooks still show them. The newest session to bind wins. A
superseded session's server goes passive and takes over again only if the
newer session ends. Rebinding never resends: notices accepted by an earlier
chat stay `accepted` until acknowledged, and the new chat is told how many.
Stopping the session releases the lock; status reports the binding as closed.
An identity whose retained endpoint belongs to Channels or tmux keeps it, and
Codex push stays off under that name (install says so).

The checked path: a real 0.162.0 daemon in an isolated home loaded a trusted
checkout's `.codex/config.toml`, started Yip for a new thread, and bound it at
an app-server-initiated tool call. A `yip call` from the checkout's Claude member
then made Yip's own server queue to exactly that thread. The daemon started a
turn there with the notice as its user message; with no credentials, the model
request failed with 401 as intended. A model-initiated tool call and an
interactive TUI were not driven by this check.

### Seats: agents without their own checkout

A checkout has one *path member*: the identity Claude's hooks and a human's CLI
resolve there. Installation never replaces it any more. Previously, installing
a second agent in the same checkout silently re-pointed the first agent's
path-resolved hooks to the new name. A Codex install whose config names its
identity explicitly takes a *seat* instead:

```sh
# beside the checkout's Claude member (automatic when the checkout is owned)
yip install --runtime codex --as reviewer --line project
# convert an existing Codex path member into a seat, freeing the path
yip install --runtime codex --as reviewer --line project --seat
# no checkout at all: a Codex profile layer, started from any directory
yip install --runtime codex --as reviewer --line project --profile yip-reviewer
codex -p yip-reviewer -C /path/to/checkout -s read-only
```

Seats are recorded in `seats.json` beside `members.json`, so older binaries that
rewrite `members.json` cannot drop them. Names are unique across both. A second
Claude identity in an owned checkout is refused: Claude's hooks identify an
agent by checkout path. One `.codex/` layer or profile serves one identity.
A profile that already defines hooks is refused rather than merged.

Inside a Codex shell, `yip` resolves `CODEX_THREAD_ID` through the binding
before the path. An unbound chat in a checkout shared with seats is refused
(use the MCP tools or `--as`) rather than answering as the path member.
Revision stamps for a seat use the checkout it shares, or else the bound
session's working directory.

`yip uninstall` removes the checkout's member and its seats; `--as NAME` limits
it to one identity; `--profile NAME` removes a profile seat without touching any
checkout. `yip line` lists seats with their delivery state.
`yip doctor --runtime codex [--profile NAME]` checks the layer and reports the
binding. Tools that only inspect the line carry `readOnlyHint`, so Codex's
`writes` approval mode can skip prompts for them; Yip does not change approval
settings.

## Claude rewake hooks (November 6 follow-up)

For Claude sessions that cannot load the development channel, the
`claude-rewake` runtime wakes an idle session with hooks alone. Claude Code
documents `asyncRewake` command hooks: they run in the background, an exit code
of 2 "wakes Claude immediately even when the session is idle", and stderr (or
stdout) is shown to Claude as a system reminder. Claude enforces `timeout` on
these hooks, unlike plain `async` ones. See the
[hook reference](https://code.claude.com/docs/en/hooks).

```sh
yip install --runtime claude-rewake --as main --line project --local [--wake-window 4h]
yip doctor --runtime claude-rewake
```

Installation creates a `claude-rewake` delivery record (the install baseline)
and adds, beside the usual three hooks, a background handler on SessionStart and
Stop: `exec yip hook rewake ... --for WINDOW-1m`, with `asyncRewake: true` and
`timeout` equal to the window. `exec` makes the waiter the session's direct
child. The waiter:

- holds `delivery/NAME.rewake.lock`; a second waiter exits 0 at once, so each
  turn's Stop does not stack processes;
- dispatches through the same durable records, IDs and attempts as Codex and
  Channels, marking a batch `sent`, printing it to stderr and exiting 2;
- exits 0 at its deadline, one minute before Claude's timeout, so a window
  never ends with a killed sender;
- exits 0 without sending as soon as its parent process changes, so a waiter
  outliving its session cannot mark notices sent into nowhere.

This is not a subscription. Between a quiet window's end and the next turn the
session is unarmed; `yip line` and `doctor` say which. PostToolUse notices are
suppressed while a waiter is armed, without advancing hook cursors, exactly as
for verified Channels. SessionStart and Stop keep their roles. An identity whose
retained endpoint belongs to another transport keeps it; install warns.

`wait` and `call` now treat a peer as reachable when push delivery reaches its
session (a live Codex binding, verified Channels or an armed rewake waiter), not
only when it was active in the last three minutes. Previously, `wait` returned
at once for an idle Codex reviewer that Yip was about to wake.

Every Claude runtime now names `--as` and `--line` in its hook commands and in
`.mcp.json`. Previously, hooks resolved the line from the session's directory:
after an install with `--line`, that is a different line with no state, so
every hook silently did nothing, including the Stop hook that holds an owed
reply. Reinstall affected checkouts.

Verified with fixtures only: unit tests, and the generated hook commands run
through a real shell against the built binary (one waiter armed, a second
refused, a Codex call waking it with exit 2, the notice on stderr). Not yet
measured against a real Claude session: idle wake from the SessionStart and
Stop entries, a timeout beyond the 600-second default, and process cleanup when
Claude exits.
