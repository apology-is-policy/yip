# Channels and help verification

Astra single-agent self-review, 21 October 2026. Not an independent audit.

This checkpoint extends the earlier delivery implementation on
`codex/switchboard-coordination`, base
`b0cc00323b5f50656cda14e59d40c3352af0279c`. Changes remain uncommitted and have not
been installed into live clients. The earlier delivery manifest is retained as
historical evidence; this checkpoint has its own
[source and evidence manifest](channels-source-hashes-2026-10-21.json).

Binary: `/private/tmp/yip-oct21-build/yip-channels`

Version: `b0cc003-oct21-channels-dirty`

Binary SHA256: `60ee57f7362553a84f1dfc076a1827a2238be0a25e1d84f782f5d4f3be675e2d`

Manifest SHA256: `df2bf69ee5b33bdc9ee99ab8574a0d4c21f360337b0ff6d9408b58bf1e3a4505`

Built using Go 1.25.3 darwin/arm64, GOMAXPROCS=2, with the existing isolated
`/private/tmp/yip-oct21-go-cache` cache. Build command:

```sh
go build -ldflags '-X main.serverVersion=b0cc003-oct21-channels-dirty'   -o /private/tmp/yip-oct21-build/yip-channels .
```

Passed on this source and binary:

- `go test -race ./...`: 77 Test functions, including 10 new Channels/help tests.
- `go vet ./...` and `git diff --check`.
- `python3 channels_e2e.py /private/tmp/yip-oct21-build/yip-channels`: real Yip
  processes and a simulated Claude MCP client. Verified read-only help before
  install, merged installation, compatible handshake, no pre-initialization
  notification, duplicate initialization guard, received-probe acknowledgment,
  exclusive ownership, pause/resume, broadcast delivery, no automatic duplicates,
  crash/restart, disconnected backlog, stale-probe rejection and clean shutdown.
- `YIP_TEST_BIN=/private/tmp/yip-oct21-build/yip-channels bash e2e.sh`: all legacy
  coordination and resource tests passed.
- `YIP_TEST_BIN=/private/tmp/yip-oct21-build/yip-channels python3 delivery_e2e.py`:
  Codex configuration/hooks, fake queue argv, delivery receipts, MCP broadcast
  reads/replies and actual PTY compose/preview/resize/send/exit passed. The first
  sandboxed attempt could not open `/dev/tty`; rerunning with approved terminal
  access passed. No production code change was needed for that restriction.

The manifest names and hashes the raw logs. The PTY transcript was not captured
for this checkpoint; its successful assertions are in `channels-delivery-pty.log`.
All tests use temporary line/home/checkouts. Codex is a fake executable in the
integration test; the Channels client is a protocol simulator. No Claude client,
preview warning, live agent or peer was launched or acknowledged by these tests.
The crash test kills only the subprocess created by that fixture.

Self-review checked session fencing, write-ahead attempt records, transport
isolation, probe acknowledgment authority, serialization of concurrent protocol
writes, and hook fallback without consuming notification cursors. It additionally
clears crash-stale readiness immediately when a replacement server takes its
identity lock, before waiting for initialization. The initial hook-fallback test
fixture created a call without a first turn; it was corrected to create an
actual unread turn before asserting fallback behavior.

No changes to `resource.go`, `queue.go` or `resource_events.go`. No live leases,
queues, registration, trust setting or runtime config was modified. Disk free
space remained above the 8 GiB deployment floor (approximately 10.38 GiB at the
final check). Persistent lock files and historical evidence were preserved.

## Deployment qualification still required

A real interactive Claude session must explicitly enable the preview channel
and acknowledge a received probe. Exercise idle wake, busy queuing, reconnect,
revoked/disabled channels, pause, and duplicate event IDs in a dedicated test
identity before selecting this transport for production agents. The installed
Claude 2.1.304 executable was only queried for its version. Protocol-simulator
success does not establish actual Claude scheduling or organization eligibility.

Channels is preferred only for an opted-in, live, acknowledged connection. The
existing external tmux arrangement remains operator-managed; there is no built-in
tmux adapter or automatic fallback. Public packaging and user-defined resources
remain outside this checkpoint. See the [operating guide](delivery-and-broadcasts.md).
