# Broadcast display and Astra wake-up correction

Astra single-agent self-review, 21 October 2026; not an independent audit.
Installed candidate `0.0.0-oct21-rc2` in both existing binary locations, with
new-inode replacement and backups. Existing running peer servers were not killed
or restarted. Restart Switchboard to load this display update.

The October 21 rollout registered Astra's exact GUI chat but did not start a
Codex dispatcher. Therefore the operator's regroup broadcast remained discoverable
without a transport attempt. A one-shot dispatch accepted exactly one delivery to
`01a121cd-4ad5-73d1-bb8f-21a4b799519e`. This is queue acceptance, not a verified
wake/read receipt; acknowledgment must come from the receiving chat.

One bounded 24-hour dispatcher was started at 2026-10-21T14:41Z, PID 75987.
Its recorded PID/start identity, logs and immutable delivery attempt are retained.
No uncertain send was retried. The new persistent lock inode prevents duplicate
watch owners and proves liveness; status now says registered/stopped when no
watch owns that lock, rather than misleadingly saying queue enabled. Exit or
crash releases the kernel lock. No automatic indefinite service was installed.

Broadcasts now participate in the conversations rail and activity ordering.
Selection remains attached to the broadcast ID across refreshes; both wide and
narrow mouse selection open its transcript. Violet operator headers, cyan reply
headers, green reads, amber pending responses and muted transport detail match
the existing conversation palette. Replies appear chronologically. The grouped
broadcast view uses the same renderer. Observers do not create read receipts.
Broadcast selections cannot receive call ratifications or dispute resolutions.

Verification passed: Go tests, race detector, vet, diff whitespace checks and
actual PTY interaction. Added regressions cover mixed conversation selection,
refresh, read/reply counts, terminal-control sanitization, monochrome rendering,
width limits, observer neutrality and dispatcher ownership/status. The PTY test
checks the broadcast rail, clicking through, grouped display and terminal state
restoration on both quit and SIGTERM. Initial sandboxed PTY access was denied;
the authorized isolated-terminal run passed. The default Go cache failed to load
`testing`; the existing isolated temporary cache passed without toolchain changes.

Exact source/binary hashes, pre-edit snapshots, raw terminal output, deployment
logs and results are in
`/Users/northkillpd/Documents/Codex/yip-broadcast-fix-20261021/verification.json`
and adjacent artifacts. The dispatcher continues writing its original log under
`/private/tmp/yip-broadcast-fix/`. The short mac verification lease was released
immediately after build/terminal checks. Existing calls, Channels receipts, queue
rules, peer jobs and historical evidence were preserved.

## Follow-up: visible completed broadcasts and confirmed GUI delivery

The original queued broadcast arrived in the exact intended GUI chat. In that
receiving turn Astra read its source through Yip, recorded delivery_ack and
posted the requested status reply. The delivery has one attempt and a read
receipt. Evidence: `gui-delivery-ack.json` in the October 21 broadcast-fix record.

The first conversation-rail integration classified fully answered broadcasts as
resolved, placing them below old calls. Candidate `0.0.0-oct21-rc3` keeps all
broadcasts ahead of ordinary calls, ordered by their latest activity, including
after all replies. An added regression exercises a fully answered broadcast
above twenty calls, mouse selection, and selection retention when a new broadcast
arrives. Ordinary call status ordering is preserved.

The operator explicitly exempted this small Yip change from the machine lease
system. Astra's identity-verified waiting worker and its hold child were stopped,
Astra's queued request cancelled, and the frozen source checked outside leases.
Corona's held lease and Main's queue position were untouched. Tests with the race
detector, vet, build and real terminal checks passed. Both binary paths received
new-inode replacements with backups; installed version is rc3, SHA256
`56c89c5bf4dfa8cc849ca22a809700b610e00314d8e13fcf84da8c89fbb663e7`.
Raw commands, frozen input hashes, tests, terminal output and install logs are
retained under `/private/tmp/yip-broadcast-order/`. This was a single-agent
self-review, not an independent audit. No new platform qualification is claimed.
