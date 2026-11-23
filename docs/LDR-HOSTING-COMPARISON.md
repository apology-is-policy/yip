# LDR hosting: a Durable Object, or a Go relay the operator runs

**Status:** draft 1, 2026-11-23, written by Fable (Claude) for Codex's
correction. The operator has not seen it. It compares, recommends nothing and
decides nothing. No relay exists in either form, and nothing was run on
Cloudflare.

The **relay** is the server every machine on a line talks to. It puts records
in one order and applies the rules of
[LDR-STATE-MACHINE.md](LDR-STATE-MACHINE.md). Two ways to host it:

- **Durable Object:** a program hosted by Cloudflare that has its own SQLite
  database and runs on a single thread. One would be created per line.
- **Go relay:** a Go program on a host the operator runs, storing the line on
  that host's disk.

They are compared against the state-machine document (§2 stage 6, §4.1, §5.4
to §5.6, §10) and the eight boundaries in §8 of Codex's
LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md.

## The same under either choice

- **Trust.** The relay is trusted for one order and for current
  authorization. A compromised relay can withhold records or show two
  histories. It holds ciphertext and the visible control fields, and never a
  payload key.
- **The agents' machines.** Key custody and the client's own atomic storage,
  two of the eight boundaries, do not depend on hosting.
- **Ciphers.** The relay decrypts nothing, so the payload cipher and key
  wrapping are not hosting questions. The relay decodes strictly, verifies
  signatures, hashes, and issues random challenges.
- **Sizes.** The proposed bound of 512 KiB for a record is far below both
  platforms' request limits.
- **Provisioning and snapshots.** Installing a line's creation descriptor
  takes administrator access in both: to the Cloudflare account, or to the
  host. Serving a new member's snapshot in bounded chunks met no obstacle in
  either, and is unbuilt in both.
- **Moving later.** Moving a line to another relay has no procedure yet
  (Codex's draft, §2.1), so the first choice is not cheaply undone.

## Where they differ

| The design needs | Durable Object | Go relay |
| --- | --- | --- |
| **One atomic step.** Record, sidecars, state, outcome and time floor are saved together, and nothing is answered before that is durable (§2). | Provided, according to the documentation: SQL calls are synchronous, writes with no `await` between them commit as one transaction, and replies are held until the write is confirmed [S, R, ST]. Requests can interleave at an `await` [R], and signature verification is asynchronous, so the step that evaluates and writes must contain no `await`. We cannot crash Cloudflare's machine to test any of this. | Not provided. The repository uses only Go's standard library, which has no transactional store. Either write an append-only store with `fsync` and show how it behaves in a crash, or take the first outside dependency. Killing the process at each step can be tested. The line is on one disk unless copies are added. |
| **Clock.** A stated source, detection of jumps and freezes, a saved floor, and suspension while the clock is uncertain (§4.1). | `Date.now()` is the time of the last I/O, and "No other timers are provided" [SM, PF]. One reading per request is enough to stamp a record. Its source, accuracy and monotonicity are not documented, and there is no second clock to compare it with, so the only detectable fault is a reading below the saved floor. Local development behaves differently [PF]. | The operating system gives a wall clock and a separate monotonic clock [Go `time`], which can be compared within one run of the process. Across a restart only the saved floor remains. The operator configures and monitors time synchronization. |
| **Restore and outside edits.** Restoring an old database is not recovery; revocations and used identifiers must survive it. Neither platform prevents a rollback. The defence is the clients' checkpoints and evidence kept outside the relay's store, and where that evidence lives is not designed. | Code in the object can restore its database to any point in the past 30 days [S]; whether the dashboard or the API can is not documented. An account member with Editor access can read and write the object's SQL data from the dashboard, and each query is audit-logged [DS]. Cloudflare manages the storage encryption keys [SEC]. | Anyone who can write to the host's disk can edit or replace the store, and so can the host's provider if the host is rented. There is no audit log unless one is built. |
| **Sessions.** TLS to a pinned relay, then a signed fresh challenge bound to the connection by a standard mechanism (Codex's draft, §7). | Cloudflare terminates TLS, and "the Workers runtime never sees TLS keys" [SM]. The TLS fields a request exposes are the cipher, the version, client-certificate details and values from the client's hello [RQ]. None is exported keying material, so binding a session to the connection is not established. Client certificates work on all plans, 100 active per zone [MT, CC]. | The relay holds its own TLS key, so clients can pin that key. `crypto/tls` gives exported keying material (RFC 5705) for binding a session to the connection, and supports client certificates. The operator issues, protects and renews the key, and makes the host reachable from every machine. |
| **One set of rules.** Relay and clients must reach the same outcome for every record and accept exactly the same signatures (§2; Codex's draft, §5.2). | First-class languages are JavaScript, TypeScript, Python and Rust; Go runs only as WebAssembly [LG, WA]. Either rewrite the rules and the strict decoder in TypeScript and verify with the platform's Ed25519 [WC], which makes a second implementation and a second signature library, held to the first by test vectors. Or compile the Go code to WebAssembly: a stand-in program builds to 3.4 MB, against a 64 MiB limit [WL], but it has not been run there. | Runs `ldrcore` and the client's own `crypto/ed25519`: one implementation of the rules and one signature library. |
| **Storage growth.** The log is kept, not cached (§5.6), and ciphertext is stored with its record. The design does not yet say what a full line does. | 10 GB per object on the paid plan, 1 GB on the free plan; when full, writes fail and reads continue [L]. With one object per line that is about 19,000 records of the largest proposed size, or about 2.4 million of 4 KiB (my arithmetic, ignoring indexes). | The disk the operator provides. |
| **Running it.** | No server to run. A free plan with daily limits, or a paid plan from $5 a month [P, WP]. Updates restart the object and drop connections, with no shutdown hook [LC]. Data can be confined to `eu`, `us` or `fedramp` [DL]. Request logging is on by default for a new Worker and records each request's method and URL [WLG]. No availability commitment naming Durable Objects was found. Cloudflare sees what the relay sees. | The operator runs a host: supervision, updates, backups, time synchronization, a TLS key. The cost is the host, not priced here. When that host is down, nobody can write to the line. Its provider, if there is one, sees what the relay sees. |

## Not established

- **Durable Object:** whether its clock is monotonic, and where it comes
  from; whether a restore can be started from outside the object's code;
  whether writes made before an uncaught exception are kept; whether Go
  compiled to WebAssembly starts within the 1-second limit [WL] and runs
  correctly; whether the platform's Ed25519 and Go's accept exactly the same
  signatures; whether a session can be bound to the TLS connection.
- **Go relay:** which store, and how it behaves in a crash or a power loss;
  which host, what it costs and how the machines reach it; how a failure of
  time synchronization is noticed.
- **Both:** where security evidence is kept outside the relay; what a full
  line does; how a line moves to another relay.

Settling any of these takes an experiment or a design step outside what the
operator has approved so far, which is the `ldrcore` reference models only.

## Evidence

Cloudflare's documentation, read 2026-11-23. Pages S, SM and L were fetched a
second time and were byte-identical. Paths are under
`https://developers.cloudflare.com`, each with the page's own modification
date:

S `/durable-objects/api/sqlite-storage-api/` (2026-09-21) ·
R `/durable-objects/best-practices/rules-of-durable-objects/` (2026-11-18) ·
ST `/durable-objects/api/state/` (2026-09-30) ·
L `/durable-objects/platform/limits/` (2026-11-13) ·
LC `/durable-objects/concepts/durable-object-lifecycle/` (2026-10-30) ·
DL `/durable-objects/reference/data-location/` (2026-06-26) ·
DS `/durable-objects/observability/data-studio/` (2026-09-15) ·
SEC `/durable-objects/reference/data-security/` (2026-04-21) ·
P `/durable-objects/platform/pricing/` (2026-11-13) ·
WP `/workers/platform/pricing/` (2026-11-18) ·
WL `/workers/platform/limits/` (2026-11-19) ·
SM `/workers/reference/security-model/` (2026-10-18) ·
PF `/workers/runtime-apis/performance/` (2026-10-27) ·
RQ `/workers/runtime-apis/request/` (2026-11-18) ·
WC `/workers/runtime-apis/web-crypto/` (2026-11-21) ·
WA `/workers/runtime-apis/webassembly/` (2026-04-23) ·
LG `/workers/languages/` (2026-07-03) ·
WLG `/workers/observability/logs/workers-logs/` (2026-11-18) ·
CC `/ssl/client-certificates/` (2026-10-12) ·
MT `/api-shield/security/mtls/` (2026-05-06)

Go: `go doc time` and `go doc crypto/tls`, Go 1.25.3. The 3.4 MB figure is a
stand-in program with JSON, SHA-256 and Ed25519 verification, built for
WebAssembly with the standard Go toolchain on 2026-11-23.
