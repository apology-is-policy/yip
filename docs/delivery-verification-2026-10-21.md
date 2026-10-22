# Delivery implementation verification

Historical checkpoint: the hashes below identify the earlier delivery build,
not the subsequent Channels changes. See `channels-verification-2026-10-21.md`
for the later checkpoint.

Astra single-agent self-review, 21 October 2026. This is not an independent audit.

Base: `b0cc00323b5f50656cda14e59d40c3352af0279c`, working branch
`codex/switchboard-coordination`, with the uncommitted implementation described
in [the operating guide](delivery-and-broadcasts.md). The per-file source hashes
are retained in [the manifest](delivery-source-hashes-2026-10-21.json).

Go: `go1.25.3 darwin/arm64`, with `GOMAXPROCS=2` and an isolated temporary Go
cache. Built binary version: `b0cc003-oct21-delivery-dirty`.

Binary SHA256:
`7723dfa444e8a64edd5c9b74b18808784119cf63b612d66b7af05de89a10f13e`.

Source manifest SHA256:
`eae2d99b0726dd38dc85e9f421447984e3aae44ba46583f1bfdf3ed3a52d9eee`.

Passed checks:

- `go test -race ./...`, including cross-process cursor updates, competing
  dispatchers, crash/unknown delivery handling, retained attempts, paused and
  retired endpoints, serialization of retirement against an active send,
  independent broadcast replies and unchanged lease/floor assertions.
- `go vet ./...` and `git diff --check`.
- Existing `e2e.sh`: all checks passed for calls, notes, disputes, lifecycle,
  CLI/MCP parity and resource queue behavior.
- `delivery_e2e.py` against the source-matched binary: isolated Codex installation,
  generated hook invocation, literal queue arguments, restart deduplication,
  receipt acknowledgment, MCP broadcast reads, independent responses, and an
  actual PTY compose/preview/resize/send/exit sequence.

The final PTY run used the exact binary hashed above. Its Codex executable was a
fixture that recorded argv; no actual chat was queued. Test state, checkouts and
home directories were temporary. The only stopped process was the identified
child of an earlier PTY harness run that blocked while its parent failed to drain
terminal output. The corrected harness drains output and bounds child cleanup.

Self-review additionally corrected mixed hook-group preservation, draft routing
after cancellation, scrolling of a long confirmation preview, corrupt-state
handling and retention of uncertain send attempts. Existing resource implementation
files were not changed. No live Yip installation, lease, queue, runtime trust
setting or agent session was changed. Disk availability remained above 8 GiB.

Remaining deployment boundary: coordinate replacement/restart of old clients
before relying on locks, review Codex hooks normally, and opt in exact endpoint
UUIDs. Actual installed-client idle/busy delivery behavior has not been qualified
by these fake-transport tests. Claude push adapters and configurable resources
are not part of this implementation checkpoint.
