# Resource configuration, packaging and live transport verification

Astra single-agent self-review, 21 October 2026. This is not an independent audit.
Branch `codex/switchboard-coordination`, base
`b0cc00323b5f50656cda14e59d40c3352af0279c`. Changes remain uncommitted.
Earlier delivery and Channels verification records describe earlier checkpoints
and remain preserved. The matching manifest for this checkpoint is
[package-runtime-source-hashes-2026-10-21.json](package-runtime-source-hashes-2026-10-21.json).

## Implemented

- Line-specific resource definitions, validation, legacy migration, immutable
  before/after records, shared/exclusive registry locking, protected lease/queue
  and historical references, disabled resource definitions, and optional local
  disk admission guards. Missing config keeps legacy mac/pi definitions; corrupt
  config fails closed. Operators must coordinate client restarts before migration.
- Explicit tmux alternative, bound to a socket, pane and process PID/start identity.
  Caller confirmation of an empty idle input prompt is mandatory for every send.
  There is no automatic fallback, prompt-state inference or recurring keystroke loop.
- Canonical module path, four reproducible release archives, checksum manifests,
  binary installation with new-inode replacement and backup, retained state on
  uninstall, generic examples, human/agent help and macOS/Linux CI configuration.
- Codex MCP and hooks explicitly bind the installation's absolute Yip root/home.
  The live test exposed that an existing shared daemon need not inherit the
  invoking terminal's environment. Binding these paths fixes that routing issue.
  No credentials or unrelated environment variables are copied.

## Automated verification

Final source passes 85 Go tests under the race detector, `go vet ./...`, and
`git diff --check`. Legacy integration tests, simulated Channels integration,
Codex adapter tests and real Switchboard PTY tests pass. The Codex regression
executes the installed hook without inherited YIP_ROOT/YIP_HOME and checks the
explicit MCP environment. These fixtures exercise actual Yip binaries; fake
runtime queue tests do not independently establish real Codex behavior.

Resource tests preserve lease and queue bytes during migration, reject invalid
and conflicting definitions, protect active/history-bearing names, verify FIFO
and disabled-resource behavior, enforce disk guards and exercise registry lock
serialization. An initial empty staging-directory handling failure was fixed;
empty `.tmp` directories do not count as pending requests, while nonempty staging
state stays protected. Disabled resources are rejected before creating a request.

The private tmux test uses a real private server and passive executable named
`claude`, not a model. It passes idle-confirmation, pause/resume, literal-text,
no-shell-expansion, deduplication and replaced-process refusal checks. The first
sandboxed attempt could not create a Unix socket; approved terminal access passed.
It does not prove safe input into arbitrary runtime dialogs.

The clean-package test installs twice while an old executable still serves MCP,
checks the backup and process exit, then exercises custom resources and both
runtime integrations. It preserves fixture leases/queues byte-for-byte and an
unrelated MCP entry through install/uninstall. Final validation also runs this
against the binary extracted from the actual release archive.

## Live Claude measurement

Claude Code 2.1.304, dedicated directory `/private/tmp/yip-oct21-live-claude`,
identity `claude-probe`, binary `yip-package` (hash in the manifest).
Only local-development Yip MCP was loaded, built-in tools were disabled, and
fixture trust/preview prompts were reviewed. Existing peer sessions were not used.

An initial sandboxed launch received the probe but could not access login state.
The approved launch used the existing Claude Max login and acknowledged its probe
through the receiving MCP connection. `doctor --runtime claude-channels` then
reported a verified session. An ordinary announcement woke the idle session,
which read the source and acknowledged the delivery. While paused, another notice
remained pending with no attempt; after resume it was read and acknowledged.
A notice sent while the fixture streamed a short counting response arrived during
that response and was acknowledged after it finished. Each ordinary delivery has
one recorded attempt. The earlier BUSY-3 fixture notice arrived before the counting
prompt was submitted, so only BUSY-4 supports the busy-response observation.

The fixture was stopped and its endpoint paused. The stopped client left stale
connection/readiness fields in its journal, but the owner lock was released and
doctor correctly reported disconnected. Yip does not treat those fields alone
as a live qualified connection. Raw PTY output and receipt snapshots are retained.
This is one account/version measurement, not universal organization eligibility,
tool preemption, a closed-session wake guarantee or an approved public plugin.
Revoked-channel behavior and reconnect crash cases have simulator coverage;
this checkpoint does not claim a complete live fault matrix.

## Live Codex measurement

Codex CLI 0.162.0 with its local background server, read-only fixture directory
`/private/tmp/yip-oct21-live-codex`, exact session
`01a15e8a-0d66-7e91-983c-028d71983c09`, identity `codex-probe`.
The original CLI was disconnected and resumed after installing the daemon-path
fix. Only the generated fixture hooks were trusted; fixture MCP tool permissions
were granted for that session. No global allow-all or sandbox bypass was used.

Yip dispatched one notice using the actual `codex queue --thread UUID --message`
command. The idle session read its broadcast and called `delivery_ack`; the durable
record advanced from accepted to read. A second dispatch did not add an attempt.
A paused second notice stayed pending without an attempt. After resume it was
accepted; a further notice was queued two seconds later while the fixture was
handling the prior notice. All three delivery IDs have one attempt and a read
receipt from the receiving session. The raw transcript retains their processing
order. This is not a guarantee of tool interruption or waking a closed client.
An initial harness assertion expected different CLI wording for a zero-send;
inspection confirmed correct paused state, and continuation used state assertions.

The fixture endpoint was paused, its terminal disconnected and its session archived
through the owning CLI daemon after completion. The desktop archive attempt
reported an active writer; the owning CLI archive succeeded.
Receipts and the original fixture files remain as evidence. The initial daemon
attempt created an empty directory for its distinct fixture line under the default
Yip home; it did not enter any existing peer line or acquire resources.

## Release candidate and limits

Local candidate version: `0.0.0-oct21-rc1`.
Artifacts: `/private/tmp/yip-oct21-release-final/`.
Independent repeat build directory: `/private/tmp/yip-oct21-release-final-repro/`.
All four archives are byte-for-byte identical across the two builds using Go
1.25.3 darwin/arm64. Embedded Go source hashes match this checkout. The archive
builder uses CGO_ENABLED=0, trimpath, disabled VCS embedding and fixed archive
metadata. The earlier preview archives remain historical and were not overwritten.

The live Claude binary predates the isolated Codex installer fix. The live Codex
binary includes that fix and predates only an explanatory help-text addition.
The final race run and archive smoke test cover the exact final source/binary;
per-checkpoint source manifests make those distinctions explicit.

macOS arm64 is exercised locally. macOS amd64 and Linux arm64/amd64 are
cross-compiled, not runtime-qualified. No local Linux VM/container runtime was found; no remote Linux qualification was
performed, and the supplied remote CI workflow has not been run. No tag,
push, public release, production client upgrade or live resource migration was
performed. Channels becomes preferred after explicit enablement and a receiving
probe acknowledgment; backward-compatible hook installation remains available.
The public release gate still requires target-host runs/CI and review of the
actual release diff and artifacts. Custom Channels still needs its preview
startup route until approved-plugin packaging is separately available.

Self-review checked lock order, fail-closed admission, migration byte preservation,
immutable receipts/bindings, literal tmux arguments, daemon environment isolation,
installer rollback artifacts, help accuracy and cross-build qualification limits.
No peer jobs were killed or awakened, no leases were reclaimed, and no caches or
historical artifacts were deleted. Free disk space remained above the deployment's
8 GiB floor; the final measured value is recorded in the evidence manifest.
