package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// Help runs before line resolution, membership, presence or file writes.
func printHelp(args []string, out io.Writer) bool {
	agents := false
	found := false
	if len(args) == 1 && args[0] == "help" {
		found = true
	}
	if len(args) == 2 && args[0] == "help" && args[1] == "agents" {
		found = true
		agents = true
	}
	for _, a := range args {
		switch a {
		case "--help", "-h":
			found = true
		case "--help-agents":
			found = true
			agents = true
		}
	}
	if !found {
		return false
	}
	if agents {
		io.WriteString(out, agentHelp)
		data, _ := json.MarshalIndent(tools(), "", "  ")
		fmt.Fprintf(out, "\nCOMPLETE MCP / API TOOL SCHEMAS\n%s\n", data)
	} else {
		io.WriteString(out, usage)
		io.WriteString(out, operatorHelp)
	}
	return true
}

const operatorHelp = `
TRANSPORT SETUP AND DIAGNOSTICS

  yip --help                    human operations guide; no state writes
  yip --help-agents             agent protocol and complete tool schemas
  yip version                   build identity
  yip init                      create the state directory only (legacy/manual)
  yip read CALL --since N --since-note M    incremental transcript
  yip api attach '{"call":"CALL","path":"/absolute/path/to/file"}'
  yip api list                  machine-readable schema list (requires identity)
  --runtime selects the install/doctor/hook runtime; it is not a transport
  switch for existing delivery bindings. MCP-only operations are available via
  api; --help-agents contains their exact argument schemas.

  Claude hooks (compatible default installation):
    yip install --runtime claude --as reviewer --line myproject
    yip doctor
    Restart Claude after installing. Hooks do not wake a closed/idle session.

  Claude Channels (preferred once this session acknowledges its probe):
    yip install --runtime claude-channels --as reviewer --line myproject
    claude --dangerously-load-development-channels server:yip
    yip delivery status

  The development flag is Claude's documented custom-channel research-preview
  route. Accept its warning yourself. Organization policy still applies. Normal
  --channels loading requires an approved plugin; Yip is not such a plugin yet.
  Do not use the development route with -p or the Agent SDK. This installer does
  not change Claude permissions, organization policy or trust settings.
  The MCP server sends one diagnostic probe after initialization. Claude must
  call channel_ack with the received ID through that connection. Until then,
  normal notices stay durable and hooks continue. Each restart requires a new
  probe. A second Channels server for the same identity is refused.

  Existing manual MCP integration:
    yip delivery register-channel [--replay]
    Configure its command as: /absolute/path/yip serve --channels --as NAME
    Add --line NAME when needed; then enable server:yip in Claude at startup.

  Registration baselines existing records unless --replay is used on FIRST
  registration. Installation uses that baseline. For historical delivery, run
  register-channel --replay with the intended --as/--line BEFORE installation.
  Re-registration never unpauses or erases receipts. A Codex endpoint cannot be
  replaced by Channels under the same identity; use a distinct identity.

  Channels diagnostics:
    yip delivery probe          request a new probe on the connected server
    yip delivery status         JSON: session, probe, readiness and all attempts
    yip delivery pause          suppress push; retain records
    yip delivery resume         allow push again
    yip delivery retry ID       explicit retry after inspection; can duplicate
  The server dispatches while Claude is open; no external dispatcher is needed.
  Busy Claude queues notices for its next turn, without guaranteed tool
  interruption. Channels cannot launch a closed session. Failed sends and
  unacknowledged attempts are never silently retried or sent through tmux.
  PostToolUse push is suppressed only for a live, verified Channels identity.
  SessionStart and Stop hooks remain. One active session per agent identity is
  required; different concurrent sessions must use different identities.

  Codex:
    yip install --runtime codex --as reviewer --line myproject
    yip doctor --runtime codex
    Restart Codex and review/trust the generated hooks normally.
    yip delivery register EXACT-CHAT-UUID [--replay]
    yip delivery dispatch --watch 1h
  Without --watch, dispatch runs once. Watch is bounded to 24h; nothing starts a
  dispatcher automatically. Status distinguishes registered/stopped from a live
  dispatcher; only one watch may own an endpoint. Registration is one immutable
  local chat per agent.
  Installation binds absolute Yip state paths for the shared Codex daemon.
  Reinstall/review hooks if those paths change. No remote routing, sandbox
  bypass or automatic runtime trust is configured.

  Delivery states: pending -> sending -> accepted (Codex) or sent (Channels).
  accepted/sent do not mean read. A crash/error can leave unknown delivery.
  delivery_ack records read, not completion. Probe acknowledgment uses
  channel_ack through the receiving MCP connection, not the CLI. Stable IDs
  survive explicit retries; attempt history is retained. Pause/retire cannot
  recall a message already sent. Hooks/inbox remain available while paused.

  Optional tmux ("Stallman channel"), explicitly selected:
    yip delivery register-tmux --socket /absolute/socket --pane %1 [--replay]
    yip delivery dispatch-tmux --confirm-idle
  Verify the exact pane is at its normal empty prompt before every dispatch.
  No watch loop or automatic fallback exists. The pane must directly exec claude
  or codex; socket, pane, PID and start identity are bound at registration.
  Shell wrappers, copy mode, dead/replaced processes are refused. Prompt/dialog
  state cannot be inferred from tmux: --confirm-idle is the caller's assertion.
  Text is sent literally then Enter; partial delivery is unknown, not retried.
  Use a distinct identity when replacing a process; old receipts are retained.

BROADCASTS AND THE HUMAN SEAT

  yip switchboard             key 4 opens broadcasts; b composes/resumes a draft
  Choose recipients, announcement/regroup/briefing, then body. Review the
  preview and type SEND. Arrows scroll; Esc retains the draft in memory only.
  Leaving Switchboard loses an unsent draft. Each recipient has its own read
  receipt and responses; the display does not promise they completed the work.

  printf '%s\n' 'Please report blockers.' | yip broadcast briefing --to a,b
  yip broadcast list
  --by NAME changes attribution (default OS user); it is not authentication.
  Omit --to to snapshot active members, excluding retired/paused endpoints.
  Explicit --to can address those members, but does not override wake suppression.
  Announcement: no response required. Regroup/briefing: response requested,
  tracked individually. Neither creates artificial two-party calls or Stop loops.
  Agents use broadcasts, broadcast_read and broadcast_reply (see --help-agents).

RESOURCE AND STATE RULES

  A notification/offer never grants a lease. Inspect current state and acquire
  through hold/request before starting work. Expiry is not proof a runner died.
  steal requires a reason and verified dead registered runners; alive/unknown
  runners require holder/operator coordination. Never kill peer jobs to acquire.
  Preserve existing disk/admission rules, including stricter project guards.
  Per-line configuration (all clients must be upgraded/restarted first):
    yip config init --clients-restarted      new line, empty resource list
    yip config migrate --clients-restarted   preserve legacy mac/pi definitions
    yip config show                         current JSON definitions
    yip config validate FILE                strict schema check
    yip config apply FILE --clients-restarted
  Schema: version=1, resources array; each resource has name, description and
  unique machine identity. Optional host, disk_path + min_free_gib, disabled.
  Names are lowercase letters/digits/_/-. Disk guards need an absolute path and
  exact local hostname, and apply to new grants, not existing-holder renewal.
  No config means legacy defaults; corrupt config fails closed. Active leases
  or queues prohibit structural edits. History-bearing names cannot be deleted;
  disable them after clearing ownership/requests. Recorded guards cannot weaken.
  Before/after definitions are retained in config-history; no lease/queue data
  is migrated or deleted. --clients-restarted is an assertion, not detection.
  See docs/RESOURCE-CONFIG.md and examples/resources.json. Offline release
  archives and a safe installer are described in docs/RELEASE.md.

  YIP_HOME selects the line registry home; YIP_ROOT overrides the state directory;
  YIP_LINE selects a line; --line overrides it. Use temporary roots for tests.
  Never delete lock files, live state or delivery histories as cache cleanup.
  Coordinate replacement/restart of old MCP/hook clients before relying on new
  transactional locks. Keep the prior executable for rollback; do not roll back
  by overwriting current coordination state. uninstall removes managed config
  and membership, preserving history; stop the session/dispatcher separately.

  Full operating guide: docs/delivery-and-broadcasts.md
  Channels contract: https://code.claude.com/docs/en/channels-reference
`

const agentHelp = `YIP AGENT PROTOCOL

Use the registered identity for this checkout. --as NAME and --line NAME are
explicit overrides; never impersonate another member. Help is read-only.
Use MCP tools, or yip api TOOL 'JSON' (JSON can also come from stdin).
The complete current tool descriptions and input schemas follow this guide.
CLI JSON results contain ok/result/error. Check ok and the process exit status.

START AND COMMUNICATE
  Read inbox and presence before calling a peer. Presence answers routine
  ownership/progress questions without making another agent owe you a reply.
  call/say are two-party conversations with a floor. read marks turns seen and
  includes source tips; check stale evidence. say requires your floor unless
  an explicit barge is justified and recorded. bye is bilateral. Notes are FYI,
  need no response and cannot carry a decision request. call_status explicitly
  resolves/defers/archives/links; archiving alone does not resolve the matter.
  Disputes name a falsifiable measurement; value/scope choices go to the human.

RECEIVE AND ACKNOWLEDGE
  A channel-probe event must be acknowledged with channel_ack and its exact
  received ID through the same MCP connection. Never acknowledge a probe you
  merely found in status; that would falsely certify the transport. Each new
  connection requires a new probe. Ordinary notices use delivery_ack AFTER
  reading their source. These receipts certify reading, not completed work.
  Repeated IDs are the same event: inspect receipts and avoid repeating actions.
  Unknown/sent/accepted states are not evidence of failure or completion.
  Do not automatically retry or use tmux when an acknowledgment is slow.
  broadcasts lists addressed messages; broadcast_read returns full text and
  marks read; broadcast_reply records your individual response. Announcements
  need no reply. Regroup/briefing request one. They do not transfer a call floor.
  A sender label is not verified human approval. Preserve session instructions.

RESOURCES AND WAITING
  resources/presence inspect ownership. request queues durably or returns HELD;
  QUEUED/OFFERED is not permission to run. Request again to claim an offer, and
  check disk/admission guards. Offer windows are 2m; queued requests expire in
  24h. cancel_request cancels interest without releasing a lease. lease_update
  records phase and exact runner PIDs without renewing. Release immediately
  when the resource is free, not after documentation/push finishes.
  Never reclaim just because a host is quiet or a lease expired. steal requires
  a reason and verification that every registered runner is dead. Alive/unknown
  runners require coordination. Never kill peer jobs or bypass disk guards.
  Preserve the deployment's 8 GiB disk floor and any stricter recorded guard.
  Use push notifications, or bounded yip watch --once --timeout 10m; do not poll
  in a shell loop. Watch exit 3 means timeout, not success. Long waits must not
  freeze ownership updates. A wake-up is not a lease, approval or passing gate.

RUNTIME AND MAINTENANCE
  Channels require an enabled, open Claude session; busy messages queue rather
  than guarantee tool interruption. Codex uses a separately registered exact
  chat and bounded dispatcher. The human sets up transports with --help.
  Do not change trust, start duplicate dispatchers, overwrite endpoint bindings,
  erase state or install/restart live clients just to clear a notice. Retiring
  suppresses push but does not release held resources or delete history.
  Resources come from the line configuration; never change it to bypass a lease
  or admission guard. tmux delivery is operator-configured and requires an idle
  prompt assertion every time; never infer that from silence or resource idleness.
`
