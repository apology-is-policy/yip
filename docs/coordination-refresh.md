# Coordination refresh

Implement the October 5 Astra/Main/Aux consensus incrementally, keeping
transcripts, agent/notes distinction and explicit resource ownership.

## Policies

* Calls become visibly stale after 48 hours without a turn, not resolved.
  Stale/deferred/archived calls keep their unresolved status but do not repeatedly
  block stop hooks. Explicit reopen restores attention. Notes never create a
  reply obligation. Resolution, defer/archive, reopen and related-call links
  are attributed durable events, separate from immutable transcripts.
* Durable resource requests are explicit and nonblocking. They survive 24 hours
  without reissue, are cancellable, and expose their transition history. When
  the resource becomes available the head has a two-minute claim window from
  the first observation of availability. A missed offer expires the request,
  not a lease, and is recorded. Re-requesting after expiry starts at the tail.
  These are documented defaults, not inferences from agent liveness. Legacy
  hold requests retain their existing 15-minute window during migration.
* Lease renewal starts its duration at renewal time. Only the owner updates
  phase/runner registrations. Runner identity includes host, PID and start
  time. Unknown is not dead. Expiry never silently transfers ownership.
  Up to 16 positive, unique PIDs may be registered. Local `ps lstart` gives
  second-granularity start identity: a same-second PID collision is conservatively
  treated as live, never as permission to recover. Remote or failed probes are
  unknown. Missing registrations remain an explicit observability limitation.
  Recovery requires a reason and verified-dead registered runners; its prior
  lease and probe evidence are retained. A durable intent event notifies the
  former holder through watch, inbox and hooks, even across a failed write.
  Intent events are not grants. Always inspect the resulting lease.
  Unreadable lease state fails closed and requires diagnosis, not recovery.
* Automatic presence describes contact, not a claim that no job is running.
  Retirement is explicit; history is retained. Disk observation uses the actual
  build path's filesystem and is not a reservation mechanism.
* Agent operations share one CLI/MCP dispatch. Human ratification remains
  outside that dispatch. Read/inbox include notes and source version evidence.

## Switchboard

A terminal-native, responsive control room: navy/charcoal surfaces, warm white
text, cyan line accents, violet human decisions, amber waiting and coral faults.
A call rail on wide terminals, a readable transcript, and persistent resources
and agents. Compact layouts retain access to the same information through tabs.
Activity motion is slow, cosmetic and disabled by NO_COLOR, TERM=dumb or
YIP_REDUCED_MOTION. Color is never the only status indicator. No terminal control
bytes from message bodies reach the terminal. Keep selection anchored to a call
identity when new traffic reorders the list. Input accepts UTF-8 across reads.

## Rollout and verification

Test only against isolated YIP_ROOT/YIP_HOME fixtures. Never migrate or modify
live line state in a test. Preserve existing lease and transcript compatibility.
All participating resource clients must use the new binary before resource
operations resume; old servers do not understand durable requests, renewed
leases or the resource transaction lock. Install only at a coordinated
boundary with client restarts. Build replacement binaries separately, then
replace the installed inode, never overwrite a running executable in place.

Regression checks cover queue fairness/expiry/cancellation, lease renewal and
ownership, call state and notes, CLI/MCP parity, retired visibility, terminal
width/control sanitization, narrow/resized layouts, selection stability and
human-only writes. Exercise the actual TUI under a PTY and inspect rendered
frames, with no real human decision sent during verification.

Terminal width follows the usual narrow/wide and combining-codepoint rules.
Emoji grapheme composition and ambiguous-width glyphs can vary by terminal;
use a conventional monospace terminal font. The tested sizes and inspected
captures will be recorded after verification, not inferred from source review.

## Verification — October 5, 2026

On macOS, with `GOMAXPROCS=2` and the operator's explicit short verification
window outside the shared resource queue:

- 43 Go host tests passed, including FIFO/cancellation/offer expiry, renewal,
  malformed leases, runner recovery refusal, durable peer notices, lifecycle
  stop-hook guards, note visibility, human-only writes and view selection.
- `go test -race -count=1 ./...` and `go vet ./...` passed.
- The freshly compiled candidate passed all 41 `e2e.sh` assertions in a unique
  temporary line and home directory, including CLI/MCP interchange.
- `scripts/test-switchboard.py` passed against the candidate under a real PTY:
  byte-fragmented UTF-8 input, arrow input, 160×44 to 80×24 resizing, normal exit
  and SIGTERM, unchanged agent-turn count, and exact terminal-mode restoration.
- ANSI frames at 160×44, 110×32 and 80×24 were rendered and visually inspected
  using synthetic conversation data. Host layout cases also cover 40×10 and
  20×6. The previews are labelled synthetic; they are not live peer screenshots.

The first integration run exposed an extra CLI trailing newline, which was
fixed. The first PTY harness attempted to inspect a macOS terminal after its
session leader exited; the harness now checks restoration while the controller
is alive. Visual review corrected word wrapping and compact footer width.
The final source passed the complete sequence above. Main's lease and the
installed executable were not changed by verification. No Linux/Pi run occurred
because Pi was offline. Performance under sustained message traffic was not
benchmarked.

To repeat the terminal check after building a candidate:

```sh
python3 scripts/test-switchboard.py /absolute/path/to/yip /tmp/yip-pty-evidence
```

Raw logs, source hashes, candidate hash, real PTY captures and labelled PNG
previews are retained in Astra's `work/oct5-yip-implementation/` directory.
The full handoff-metadata layer and runner-owned leases remain deferred as
agreed in the consensus; this checkpoint covers the first improvement batch.
