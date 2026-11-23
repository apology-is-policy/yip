# LDR hosting options

**Joint-review draft 3, 2026-11-23. No recommendation and no deployment
approval.** The options are a Cloudflare Durable Object per line, or a Go
relay on an operator-managed host. Neither relay exists yet. Platform facts
below come from documentation; the implications are our design assessment.

Both must preserve signed control history, keep payload keys on client
machines, and handle uncertain outcomes without repeating actions. Client key
custody and local crash safety remain required either way. A relay cannot
invent membership for a joining client: the proposed operator-attested
bootstrap exception is a separate decision, not a hosting feature.

| Decision area | Cloudflare Durable Object | Operator-hosted Go relay |
| --- | --- | --- |
| **Rules and verification** | A TypeScript port duplicates the Go rules; Go/Wasm is possible but integration remains untested. [Runtime options](https://developers.cloudflare.com/workers/languages/) | Can reuse the Go core directly. Production decoding, signatures and storage integration still need verification. |
| **Durable commit** | SQLite storage supplies transactions, including synchronous rollback on callback failure. The complete LDR record/state/outcome/floor update still needs implementation and fault tests. [Storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#transactionsync) | Storage and durability design remain to be selected: database or explicit log. Host control helps testing; process-kill tests alone do not prove power-loss safety. |
| **Authenticated sessions** | Inbound TLS terminates outside Workers; exporter access is not established by the documented API. [TLS boundary](https://developers.cloudflare.com/workers/reference/security-model/) | TLS exporters are available when Go terminates the client connection itself. A proxy can change that boundary. [TLS API](https://pkg.go.dev/crypto/tls#ConnectionState.ExportKeyingMaterial) |
| **Trustworthy time** | Timers advance with I/O. Expiry sampling, fault detection and monitoring need a deployment contract. [Timers](https://developers.cloudflare.com/workers/runtime-apis/performance/) | Wall and process-local monotonic readings help detection, but restart validation and monitoring remain necessary. [Clocks](https://pkg.go.dev/time#hdr-Monotonic_Clocks) |
| **Growth** | Documented SQLite limits are 10 GB per object on paid plans and 1 GB on free; a full object rejects writes. [Limits](https://developers.cloudflare.com/durable-objects/platform/limits/) | Capacity follows the chosen storage/host. Retention, disk-full behavior and migration still need policy. |
| **Who holds the data** | Cloudflare hosts ciphertext and visible metadata. At least Editor access to the implementing Worker permits SQL reads/writes through Data Studio; Data Studio queries are audit-logged. [Data Studio](https://developers.cloudflare.com/durable-objects/observability/data-studio/) | Privileged host administrators and, under ordinary hosting assumptions, the provider can access the store and metadata. Audit coverage needs design and configuration; existing host/database/provider tools may supply parts of it. |
| **Operations and recovery** | Provider operates the infrastructure; we still manage code, account access, provisioning, monitoring and restore policy. | We also operate host supervision, updates, reachability, TLS and backups. Neither option yet preserves security history across rollback by a specified recovery procedure. |

The session-binding mechanism is still open; an application challenge is not
automatically equivalent to TLS exporter binding. Hosting also affects
signature-library compatibility, provisioning and snapshot capture/retention,
although payload encryption and key wrapping stay on clients. Snapshot and
clock correctness are unproven on both platforms.

**Decisions still separate from hosting:** O25 asks whether new members may
trust a pinned operator's checkpoint instead of replaying the complete prefix.
O26 asks whether the protected root-signing ceremony is practical within the
ordinary validity window. Neither is settled.

Before selecting a deployment, identify its store, session binding, clock
contract, bounded snapshot path and recovery-evidence retention. Compare
costs against an expected workload and operator maintenance capacity; no
cost winner is established.

---

Everything below is background for checking a row. It is not part of the one
page.

## How this page was made

Fable wrote draft 1. Codex reviewed it against the primary documentation
(call 0003, turn 7; its review note is `LDR-HOSTING-REVIEW.md` in Codex's
files) and supplied the page above as replacement text. Fable proposed the
row "Who holds the data"; its wording is Codex's, after it checked the Data
Studio page (turn 9). Audit logging prevents neither a privileged edit nor a
rollback in either deployment. Draft 1 made claims that the review
removed: that one clock reading per request is enough, that a reading below
the saved floor is the only detectable clock fault, that serving a snapshot
met no obstacle, and that a standard-library-only repository forces a
hand-written store.

## Background notes

Facts are from the documentation listed under Evidence unless marked. Nothing
was run on Cloudflare.

**Rules and verification.** Workers gives first-class support to JavaScript,
TypeScript, Python and Rust. Go is reached through WebAssembly; WASI support
is experimental and threads are not possible [LG, WA]. A Worker may be 64 MiB
and must start within 1 second [WL]. Web Crypto there lists Ed25519
verification and SHA-256 [WC]; Ed25519 is a candidate, not a chosen
algorithm. A stand-in Go program with JSON, SHA-256 and Ed25519 built to 3.4
MB of WebAssembly (measured locally). That says nothing about start-up,
memory, CPU limits or a real relay. Reusing the Go core removes one source of
divergence and not decoder, version or storage-integration bugs. Negative
signature and encoding vectors across runtimes are needed either way.

**Durable commit.** On a Durable Object, SQL calls are synchronous, writes
with no `await` between them are one implicit transaction, `transactionSync`
rolls back when its callback throws, replies are held until a write is
confirmed, and a failed write resets the object [S, R, ST]. Requests can
interleave at an `await` [R]. The candidate strategy is Codex's: verify the
immutable bytes first; then, inside one synchronous transaction, check
authorization, duplicates and state again and write the whole update; throw
on failure; update in-memory caches only after success. A rollback does not
restore JavaScript memory. For the Go relay no store is chosen. The
repository has no dependencies today (`go.mod`), so a database would be its
first; an explicit log is the other option.

**Authenticated sessions.** "The Workers runtime never sees TLS keys" [SM].
The TLS fields a request exposes are the cipher, the version,
client-certificate details and values from the client's hello [RQ]. Client
certificates are available on all plans with a Cloudflare-managed authority,
100 active per zone [MT, CC]. Go's exporter needs TLS 1.3 or Extended Master
Secret (`go doc crypto/tls`), and RFC 9266 defines the TLS 1.3 binding. No
binding mechanism has been selected, so this is a difference in what is
available and not a pass or a fail.

**Trustworthy time.** `Date.now()` "returns the time of the last I/O", and
"No other timers are provided" [SM, PF]. Its source, accuracy and
monotonicity are not documented. Local development behaves differently [PF].
Go's monotonic reading has no meaning outside the process and may stop while
the machine sleeps (`go doc time`).

**Growth.** When a Durable Object is full, writes fail and reads continue; a
row or value may be 8 MB [L]. At the proposed record bound of 512 KiB, 10 GB
is about 19,000 records of the largest size or about 2.4 million of 4 KiB
(Fable's arithmetic, ignoring indexes). The design does not yet say what a
full line does.

**Who holds the data.** Data Studio needs "at least `Editor` access to the
Worker that implements the Durable Object" and logs the queries it issues
[DS]. That is the documented scope: not every account role, and not every
path by which data can be written. Stored data is encrypted at rest with keys
Cloudflare manages [SEC].

**Operations and recovery.** Durable Objects are available on the free plan
with daily limits (100,000 requests a day) and on the paid plan from $5 a
month [P, WP]. Code and runtime updates restart an object and drop its
connections, with no shutdown hook [LC]. Data can be confined to `eu`, `us`
or `fedramp` [DL]. Request logging is on by default for a new Worker and
records each request's method and URL [WLG]. Code in an object can restore
its database to any point in the past 30 days; whether anything outside the
object can is not documented, and local development cannot test it [S]. No
availability commitment naming Durable Objects was found.

## Not established

- **Durable Object:** whether its clock is monotonic, and where it comes
  from; whether a restore can be started from outside the object's code;
  whether Go compiled to WebAssembly starts within the limit and runs
  correctly; whether the platform's signature verification and Go's accept
  exactly the same signatures; whether a session can be bound to the TLS
  connection.
- **Go relay:** which store, and how it behaves in a crash or a power loss;
  which host, what it costs and how the machines reach it; how a failure of
  time synchronization is noticed.
- **Both:** the session-binding mechanism; how a snapshot is captured, kept
  and served; where security evidence is kept outside the relay; what a full
  line does; how a line moves to another relay.

Reading documentation and reviewing designs continues within the agents'
work. Running anything on Cloudflare, and any network or cryptographic
implementation, is outside what the operator has approved so far.

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

Go: `go doc time` and `go doc crypto/tls`, Go 1.25.3.
