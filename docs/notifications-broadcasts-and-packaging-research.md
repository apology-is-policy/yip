# Yip notifications broadcasts and public packaging

Research and proposed design, 21 October 2026. Prepared by Astra for the operator.

Yip can replace terminal keystroke injection with supported runtime integrations, add operator broadcasts without changing its two-party call protocol, and become a general-purpose package. The first implementation should establish durable event delivery and session registration, then add Codex queue delivery and a Claude hook adapter. Channels are a useful optional transport while their preview requirements remain unsettled.

The important distinction is between an event being recorded, accepted by a runtime, read by an agent, and acted upon. Keep those states separate. A wake notification must never itself grant a resource, resolve a call, or attest that a test passed.

## What the runtimes support

| Mechanism | Idle session | Busy session | Recommended role |
| --- | --- | --- | --- |
| Claude Channels | Push into an open, enabled session | Events batch for the next turn | Optional continuous delivery |
| Claude asyncRewake hook | Exit code 2 explicitly wakes an idle session | No tool-preemption guarantee | First bounded resource-wait adapter |
| Claude cross-session messaging | Starts a turn when accepted | Delivery between tool calls; does not interrupt a running tool | Evaluate for ongoing local notification delivery |
| Codex queue | Native delivery to an existing session; qualify installed-client behavior | Treat as queued work, not a preemption API | Primary Codex adapter |
| Existing Yip hooks | Need a lifecycle event to run | Can report at hook boundaries | Presence, reconciliation and reply obligations |

Claude Channels remain a research preview. They require a running session and compatible authentication/provider and organization settings. Normal channel loading uses the effective approved-plugin list; organizations can approve their own plugins. A custom local development channel can use the explicit development-channel flag. Thus the transcript's assertion that every custom channel always needs that flag is too broad. Installation should explain eligibility and leave enablement to the operator. [Channels overview](https://code.claude.com/docs/en/channels)

The protocol declares `claude/channel` in experimental MCP capabilities and sends `notifications/claude/channel`. Busy-session events are grouped for the next turn. There is no native notification acknowledgment: successful transport writing does not establish processing, and unavailable or disallowed channels may drop events. Yip therefore needs application receipts. The documented examples use the TypeScript MCP SDK; extending Yip's Go server is a design inference that needs a compatibility test, not a verified implementation. [Channels reference](https://code.claude.com/docs/en/channels-reference)

Claude's `asyncRewake: true` command hook runs in the background and wakes an idle session on exit 2, using stderr or fallback stdout as context. Its timeout remains enforced, and each invocation starts another process. Ordinary asynchronous hooks do not provide the same idle wake behavior. These differences make a dedicated bounded wrapper necessary. [Claude hooks](https://code.claude.com/docs/en/hooks)

Claude also documents an inbox socket for scripts and hooks, with endpoint/token variables supplied to the session. Accepted cross-session messages start idle turns and arrive between tool calls when busy. Inbound controls can hold or refuse them. Same-user socket access is not proof of a human sender. An implementation should register the session-provided endpoint and follow the documented authentication and inbound rules; it should not discover private paths or impersonate another session. This is a supported alternative worth prototyping, not a reason to change inbound policy globally. [Cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging)

Codex documents `codex queue --thread <UUID> --message <text>` as stable, with exact names and remote-server options also supported. Local inspection confirmed `codex-cli 0.162.0` exposes this command. Use UUIDs to avoid name ambiguity. The CLI reference does not establish precise busy/idle timing or the transcript's claimed first-supported version, so release qualification must measure those cases. Do not promise closed-session resurrection or tool interruption. [Codex commands](https://learn.chatgpt.com/docs/developer-commands?surface=cli)

Codex has its own hook installation and output contracts. In particular, its Stop continuation uses `decision: block` with `reason`, or exit 2 plus stderr. Its PostToolUse context has a documented event-specific shape. Project hooks require the runtime's trust handling. Generate a separate adapter rather than copying Claude output, including Yip's extra `terminalSequence` field or Stop-specific payload. A blanket claim that all unknown fields fail is broader than the evidence reviewed here. [Codex hooks](https://learn.chatgpt.com/docs/hooks)

## Delivery design

Keep the plain-file line as the durable authority. Add a versioned event journal and a persistent outbox, meaning pending delivery records that survive a dispatcher crash. Existing calls, notes, broadcasts and resource transitions should refer to stable source IDs rather than scraped terminal summaries.

Commit the source event and its delivery intent together under a recoverable transaction. A crash between those steps must be repairable without inventing a second event. Each recipient gets an independent cursor and receipt. The dispatcher reads committed records, batches related notifications, and invokes an adapter through an argument vector rather than shell interpolation.

Distinguish these states:

- **Pending:** recorded, but no successful delivery attempt.
- **Accepted:** the transport accepted an attempt; the agent may not have read it.
- **Read:** the intended endpoint acknowledged the event ID.
- **Answered or completed:** a separate durable response records the requested outcome.
- **Held, failed or unknown:** delivery is blocked, definitively failed, or its outcome is uncertain.

A crash after sending but before saving its receipt makes exactly-once delivery impossible without recipient cooperation. Retain the same event ID on bounded retries, deduplicate at acknowledgment and action boundaries, and show uncertain attempts in Switchboard. Reconcile before retrying; never blindly resend an uncertain operator request. Plain-text runtime queues do not supply an application idempotency guarantee.

Register endpoints separately from agent identity. One agent can have several sessions; bind an explicitly selected endpoint to its line, checkout, runtime, session UUID or socket, host, and lifecycle generation. Store credentials privately and omit them from events and diagnostic output. Default to one primary delivery endpoint per agent. A renamed session must not redirect messages by accident.

Endpoint states should include enabled, paused, disconnected and retired. A disconnected recipient retains pending records. A paused or retired endpoint is not awakened automatically. On resume, reconcile unread records and expiry before delivering. Neither an old PID nor a silent endpoint proves that a resource runner is dead.

Expose a structured watch mode with event IDs and durable resume cursors. Keep the existing readable watch output for people. Prevent own acknowledgments, presence heartbeats and delivery receipts from producing recursive wake events. Rate-limit by endpoint, coalesce repeated resource updates, and avoid polling the model just to say nothing changed. The current two-second filesystem polling can remain initially; filesystem notifications are an optimization, not a correctness mechanism.

### Claude adapter

Start with a dedicated asyncRewake wrapper for an explicitly requested bounded resource wait. Map a real relevant event to exit 2 with a small summary and event ID. Map a quiet deadline to exit 0; the current watch command uses exit 3 for that case. Record operational errors separately so a broken watch cannot masquerade as resource availability. The existing all-success hook dispatcher cannot be reused unchanged.

Allow only one waiter per endpoint and purpose. Preserve its cursor across rearming. Timeout ends the wait; do not claim a session-long subscription unless rearming is itself verified. Retain lifecycle hooks for reconciliation when a session resumes or next uses a tool. For continuous delivery, qualify Channels or the documented inbox integration rather than repeatedly spawning waiters on every tool call.

For Channels, add an outbound writer that serializes notifications with RPC replies, propagates write errors, and stops on disconnect. The current server handles requests serially and writes directly through one encoder. Negotiate only protocol revisions Yip actually supports; the current code echoes the client's revision. Include the documented channel/runtime protocol compatibility caveat in the test matrix. Do not add tool-permission relay to this coordination feature.

### Codex adapter

Add explicit runtime selection to installation and diagnostics. Register the exact target session, then use the queue command for committed outbox records. Capture exit status and bounded diagnostics, but mark successful commands as accepted until a Yip acknowledgment arrives. Capability detection should inspect the installed CLI and configuration rather than assume a version mentioned in a chat.

Generate Codex hook payloads from the same semantic events through a separate serializer. Use documented configuration paths, preserve unrelated settings, and respect project trust. Keep runtime-specific output fixtures so a future Claude-only field cannot silently leak into Codex output. Failure to wake must leave the durable inbox available to normal reads and hooks.

## Broadcasts and joint briefings

Introduce a first-class broadcast record rather than pretending a two-party call has many floor holders. A record should contain an ID, attributed sender, creation time, immutable body, purpose, recipient snapshot, optional deadline, and optional supersedes reference. Changes become new records. Recipients added later should receive an explicit follow-up, not retroactively alter the original audience.

Offer three clear operator actions in Switchboard:

| Action | Expected recipient behavior | Reply obligation |
| --- | --- | --- |
| Announcement | Read context or a decision | None |
| Regroup request | Acknowledge and describe the next safe checkpoint | Explicit per recipient |
| Briefing request | Return progress, blockers and requested decisions | Explicit per recipient |

The compose view should show selected agents, endpoint status, wake behavior and exact text before sending. Default selection excludes paused and retired agents. Show held, offline and missing-endpoint recipients separately. Preserve drafts if the terminal resizes or sending fails. Sanitize all terminal control sequences as the existing TUI does.

For an initial briefing implementation, link one ordinary two-party request call per recipient to the broadcast. Existing floor and resolution semantics then remain intact. Show answers together on a briefing screen with links to their original calls and timestamps. Missing answers are visibly missing. A synthesized summary should distinguish reported facts from the summarizer's interpretation. Forwarding answers to all participants should be an explicit audience choice.

Urgent regroup means “respond at your next safe opportunity.” Agents can report that a gate is still running and propose a checkpoint. Receiving a broadcast does not cancel a worker, transfer its lease, or override the session's instructions. An operator message about priorities is distinct from a verified approval for deployment or another gated action.

### Operator attribution

Today `ratify` writes `AuthorHuman` using `$USER` or `--by`; an agent with shell access can invoke it. Removing the MCP method does not authenticate a human. Describe the existing label as attribution, not verified operator approval.

For ordinary collaboration, a trusted-local-user model can be sufficient if the UI states it accurately. Separate the operator compose action from agent tools to prevent accidental misuse. If Yip must provide enforceable human-only approvals against an agent with the same filesystem authority, it needs a trusted broker or signing authority outside that agent's access. A TTY check, local socket, or key readable by the same agent does not establish that boundary. Do not make general broadcast delivery depend on solving stronger approval infrastructure.

## User-defined resources and packaging

Replace the compiled resource list with versioned line configuration. Start with named exclusive resources: stable slug, display name, description, optional host association, and explicit admission-policy settings. Keep lease owner, runner identities, queue and history in state rather than configuration.

Provide `init`, configuration validation, and a migration that seeds existing lines with their current mac/pi definitions without changing ownership or queue order. Refuse to remove or rename a resource while leases, requests or unresolved recovery records refer to it. Unknown resources should fail clearly. All participating clients must support the schema before switching a live line.

Physical contention remains important: aliases for the same machine must not create two independent grants. Prefer one resource per exclusive machine initially; explicit contention groups can follow. Disk admission observes the actual work filesystem and remains distinct from ownership. Preserve the existing 8 GiB floor and any stricter project guard in this deployment; other installations define their own policies. A lease expiring still does not prove its process has stopped.

The current Go-only, MIT-licensed binary is a good packaging base. Public release work should include:

- A canonical module path such as `github.com/apology-is-policy/yip`, tagged releases, reproducible version metadata, checksums, and documented source-build installation.
- Tested macOS and Linux packages first. Native Windows needs explicit terminal and process-identity work; the current TUI invokes `stty` and uses Unix signals.
- Separate install/uninstall operations for the binary, per-runtime integration and retained line history. Uninstall must not silently delete conversations or leases.
- Idempotent configuration edits, backups and migration recovery. Diagnostics should report the actual wired binary and runtime capabilities, not just that a file was written.
- Isolated CI fixtures for calls, queues, state, adapters and TUI rendering. Examples should use generic agents and resources; machine-specific paths and Thylacine policies belong in deployment documentation.
- An upgrade boundary that restarts old MCP servers and coordinates state-version changes. Preserve replacement of the executable inode rather than overwriting a running macOS binary in place.

Plugin wrappers can follow a working CLI release. They should package runtime setup and guidance without becoming a second state store or requiring a Node dependency for every Yip user.

## Findings in the current source

Source reviewed: `b0cc00323b5f50656cda14e59d40c3352af0279c`, branch `codex/switchboard-coordination`. These are static findings, not runtime reproductions.

| Finding | Evidence | Required response |
| --- | --- | --- |
| Human attribution is unauthenticated | `main.go:428`, `notes.go:113` | State the trust model; separate operator attribution from approval proof |
| State updates can overwrite concurrent changes | `state.go:466–535`: separate read and whole-file replace in agent state and presence | Lock the complete read-modify-write transaction or serialize updates; atomic rename alone is insufficient |
| Watch advice assumes indefinite Monitor support | `main.go:82`, `watch.go:14` | Replace the example and document deadline/rearming behavior |
| Makefile advertises uninstall without a recipe | `Makefile` phony list and targets | Implement and document binary uninstall separately from integration removal |
| Installer and hook output are Claude-specific | `line.go:186`, `hooks.go` | Add explicit runtime installation and output contracts |
| Notification bookkeeping precedes successful delivery | `hooks.go:73–105` | Separate attempted notification from durable agent acknowledgment |
| Resource names are compiled in | `resource.go:78` | Introduce validated configuration and a migration |

The Monitor documentation now specifies a deadline for every watch: five minutes by default, at most thirty minutes, with a lower cap for single-prompt non-interactive runs. Yip should not advertise an indefinite `persistent: true` contract. [Claude tools reference](https://code.claude.com/docs/en/tools-reference)

The handoff's public-branch finding is obsolete. A live read-only remote check returned master `c1d5bc987a3743b453a97fddff605e072822f2f5`. GitHub's comparison shows it contains the reviewed commit plus a merge and a README change; source files match. The locally cached `origin/master` was stale. No fetch, branch change or push was performed. [Public comparison](https://github.com/apology-is-policy/yip/compare/b0cc00323b5f50656cda14e59d40c3352af0279c...c1d5bc987a3743b453a97fddff605e072822f2f5)

## Implementation sequence and acceptance

1. **Protect state and establish events.** Fix read-modify-write transactions; add event IDs, endpoint registration, outbox records and receipts. Verify competing processes cannot lose fields; inject crashes at each commit boundary and recover without losing or duplicating source events.
2. **Deliver to opted-in sessions.** Implement Codex queue and the bounded Claude wake wrapper with fake transports first. Then use dedicated test sessions to measure idle, busy, disconnected, resumed and paused cases. Include unknown send outcomes, duplicate delivery, expired events, and a resource changing hands before a delayed notice is read.
3. **Add Switchboard broadcasts.** Exercise recipient selection, drafts, terminal resizing and hostile terminal bytes under a PTY. Verify announcements create no reply obligation and linked briefing calls preserve individual floors. Acknowledgment must never imply execution success.
4. **Qualify continuous Claude delivery.** Test Channels and the documented inbox route against current installed versions and organizational policy. Choose the default from measured reliability and eligibility. Verify no duplicate delivery when hooks and a push adapter are both enabled.
5. **Generalize and release.** Migrate fixture lines to configurable resources; preserve queues, live leases and historical records. Test removal constraints and incompatible clients. Add release artifacts, clean installation/uninstallation checks and a documented support matrix before publishing.

All mutating tests should use isolated `YIP_ROOT`/`YIP_HOME` and dedicated sessions. Do not send probes to working peers or alter live leases to qualify delivery.

Single-agent self-review: the design preserves two-party floors, separates delivery from authority, retains resource admission and ownership rules, and accounts for crash/retry ambiguity. Research verification consisted of source inspection, local CLI help, official documentation and read-only public Git metadata. No adapters were implemented, no live wake probes were sent, and no runtime compatibility qualification is claimed.
