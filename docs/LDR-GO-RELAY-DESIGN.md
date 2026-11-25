# LDR operator-hosted Go relay — architecture, transport, storage, clock and crypto profile (draft v0)

2026-11-25 · Gemini · **Unapproved draft proposal.** Not a specification and
not an authorization to implement production relay, transport or cryptographic
code. Prepared on `gemini/ldr` for cross-review by Codex (Astra), Claude
(Fable) and the operator, following the operator's 2026-11-25 decisions:

- **Hosting:** operator-hosted Go relay (selected over Cloudflare Durable
  Objects so the relay can run on local networks and on closed corporate
  networks between the operator's and colleagues' agents without depending on
  external cloud infrastructure).
- **O25 (new-member control bootstrap):** full control-log replay from genesis
  before ordinary use (envelope-level control metadata without plaintext or
  prior epoch keys is acceptable; supersedes P4 detached attestation and
  archives §14.7 `Profile.StateCommit` for phase 1).
- **O26 (root ceremony and two-key policy):** ordinary 10-minute provisional
  validity window confirmed practical; **equal 1-of-2 roots** (`root_keys`,
  tagged `["root", key]` principals, `tombstones.root_keys`,
  `root_member_replace`).

Companions: [LDR-STATE-MACHINE.md](LDR-STATE-MACHINE.md) (draft v8),
[LDR-CONFORMANCE-VECTORS.json](LDR-CONFORMANCE-VECTORS.json),
[LDR-HOSTING-COMPARISON.md](LDR-HOSTING-COMPARISON.md),
[LDR-RECOVERY.md](LDR-RECOVERY.md) (draft v0),
[LDR-THREAT-MODEL.md](LDR-THREAT-MODEL.md), and
[LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md](LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md)
(draft v3).

---

## 1. Deployment and network model (LAN and closed networks)

### 1.1 Operational shape

The relay is a single-binary Go service (candidate CLI surface:
`yip relay serve`, `yip relay provision`, `yip relay status`) that directly
imports the Go state-machine core (`ldrcore/`). Reusing the Go rule core
eliminates cross-runtime TypeScript/WebAssembly state-machine divergence;
wire decoding, canonical CBOR checks, signature verification and storage
integration still require dedicated cross-checks and negative vectors.

Because the relay is intended for **local networks and closed corporate
networks**, it must operate with **zero dependency on public internet reachability,
public certificate authorities, ACME/Let's Encrypt, or external cloud APIs**.

### 1.2 Endpoint identity and certificate pinning

In a closed network, public WebPKI is frequently unavailable or intercepted by
corporate inspection proxies. The creation descriptor (`ldr.creation-descriptor.v1`,
signed by one of the two initial root keys) therefore pins the relay endpoint
explicitly:

```
relay_origin = {
  url:          "https://<host-or-ip>:<port>",   // no credentials or secrets in URL
  tls_policy:   "pin_spki_sha256" | "pin_ca_root_pem",
  tls_pin:      <32-byte SHA-256 of SubjectPublicKeyInfo, or private CA root cert>,
  proxy_mode:   "direct_tls_only"                // see §2.3
}
```

- **Zero-CA default (`pin_spki_sha256`):** `yip relay init` generates a
  self-signed server certificate (ECDSA P-256 or Ed25519) with explicit SANs
  (IP and/or internal DNS name) and outputs its SPKI SHA-256 pin into the
  creation descriptor. Clients verify the server certificate against that pin
  during TLS handshake (bypassing public CA lookup while still performing full
  TLS 1.3 key exchange and signature verification on the leaf key).
- **Enterprise PKI option (`pin_ca_root_pem`):** for internal corporate CAs,
  the creation descriptor pins the specific internal CA root certificate and
  expected server DNS SAN so standard internal cert rotation works without
  trusting the OS global root bundle.
- **No redirects or silent migration:** HTTP redirects are refused. Moving a
  line to a new relay URL or rotating a pinned SPKI requires an explicit
  root-authenticated migration record (out of scope until specified; clients
  refuse unauthenticated origin changes).

### 1.3 Line provisioning (Appendix A, Q1)

Presenting a self-signed creation descriptor over the network must never
create or reserve a line on the relay. For an operator-hosted Go relay,
provisioning is a **local host-administrator action**:

1. The root ceremony produces a canonical, root-signed
   `ldr.creation-descriptor.v1` containing `line_id`, initial two-member
   `root_keys` (threshold 1), `relay_origin`, `generation = 1`, and the full
   generation-1 `profile`.
2. The relay host administrator runs `yip relay provision --descriptor <file>`
   against the local relay data directory (protected by OS file permissions /
   local admin socket, not an unauthenticated network endpoint).
3. Provisioning validates the descriptor's canonical encoding, verifies the
   root signature under one of the two named `root_keys`, computes `CD` and
   the genesis anchor `H(Enc(["ldr.genesis", 1, line_id, canon(root_keys), CD]))`,
   and atomically writes the provisioned line metadata with empty log state.
4. Once provisioned, the relay accepts the matching root-signed `line_init`
   over the authenticated network API (or locally during setup) and commits
   sequence 1.

### 1.4 Colleague onboarding and explicit 3A consent

For a line shared between the operator's and colleagues' agents on a closed
network:

- Each machine/workstation isolation domain holds its own enrolled credential
  (`signing_key`, `encryption_key`, derived `cred_id`, dedicated
  `namespace_id` and `actor_limit`).
- Under **3A** (operator decision 2026-11-23), every enrolled reader can read
  all future plaintext on the line. Repository access or LAN reachability is
  never implicit consent: onboarding requires the full P3 key-first ceremony
  with out-of-band fingerprint verification (e.g., in-person or verified
  internal chat fingerprint check between operator and colleague) before the
  operator signs `credential_enroll`.
- Under **O25** (operator decision 2026-11-25), the newly enrolled colleague
  machine performs full control-log replay from genesis (`§6`) before
  entering ordinary use and receives no prior epoch keys.

---

## 2. Transport and authenticated session binding (P7)

### 2.1 Direct TLS 1.3 with `tls-exporter` channel binding

Because the operator-hosted Go relay terminates TLS directly using Go's
standard `crypto/tls`, it has direct access to
`tls.ConnectionState.ExportKeyingMaterial`
([RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html)):

- **Minimum TLS:** TLS 1.3 only (`MinVersion: tls.VersionTLS13`). This
  guarantees AEAD ciphers, forward secrecy, handshake transcript signing, and
  unambiguous RFC 9266 `tls-exporter` channel binding.
- **Channel binding value:** on every TLS connection, both client and relay
  independently derive:
  ```
  cb = ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
  ```
  If TLS version < 1.3 or `ExportKeyingMaterial` fails, the connection fails
  closed immediately.

### 2.2 Session challenge handshake

A session authenticates a single tagged principal
(`["credential", cred_id]`, `["operator", key]`, or `["root", key]`) for a
single line and generation, bound to the underlying TLS 1.3 connection:

1. **Client opens** `POST /v1/lines/{line_id}/session/challenge` (or WebSocket
   upgrade on `/v1/lines/{line_id}/session`) sending:
   `{version, profile_digest, line_id, generation, principal}`.
2. **Relay responds** with a fresh single-use challenge packet:
   `{session_id, server_nonce (32 random bytes), issued_mono_deadline}` held in
   ephemeral per-connection memory (short TTL, e.g., 30 s, burned on first
   verification attempt).
3. **Client signs** (with the private key of `principal`):
   ```
   session_proof = Sign(principal, Enc([
     "ldr.session-auth", 1,
     profile_digest, line_id, generation,
     principal, relay_origin_canonical,
     session_id, server_nonce, cb
   ]))
   ```
   and sends `session_proof` on the **exact same TLS connection**.
4. **Relay verifies**:
   - `cb` matches the current TLS connection's `ExportKeyingMaterial`;
   - `server_nonce` is unused and unexpired;
   - `session_proof` signature is strictly canonical and valid under
     `principal`'s public key;
   - **Standing check (re-checked inside serialized state access):**
     - `standingActive`: session opens with `session_key` (see §2.4) for
       request/reply binding.
     - `standingRevoked` (revoked credential, revoked operator key, or
       replaced root key): possession of the exact key is now proven; relay
       returns a bound `unresolved / revoked` response (carrying
       `line_id`, `generation`, `principal`, `session_id`, `server_nonce`)
       and closes the session. No working session, no outcome access, and no
       anchor is granted.
     - `standingNever`: relay returns a generic admission refusal
       (`unknown_signer` / `not_authorized`) without revealing key-registry
       membership, and closes the session.

**Bootstrap exception for `line_init`:** before sequence 1 exists, the relay
verifies `session_proof` against the two `root_keys` provisioned in the
installed creation descriptor (`§1.3`), allowing either provisioned root to
open a bootstrap session solely to submit `line_init`.

### 2.3 Proxy policy (closed corporate networks)

A corporate reverse proxy that terminates TLS breaks `tls-exporter` because
the client and Go relay see different TLS handshakes. Policy:

- **Default (`direct_tls_only`):** the client pins the Go relay's own leaf
  SPKI or private CA cert directly. Any TLS-terminating MITM proxy causes
  pin mismatch and fails closed. This works out of the box on LANs and
  direct internal subnets.
- **If an internal TCP passthrough / SNI proxy is used:** TLS terminates at
  the Go relay, so `tls-exporter` and leaf SPKI pinning work unchanged.
- **TLS-terminating HTTP reverse proxies are unsupported in phase 1.**
  Supporting one would require an explicit separate profile mode and
  application-level mutual authentication (such as Noise/HPKE session keys)
  so the proxy cannot splice sessions or forge `revoked` replies; do not
  silently weaken `tls-exporter` binding.

### 2.4 Request and reply binding (P7)

To satisfy `LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` §7 (and Appendix A, Q14)
without inventing long-lived bearer tokens:

- Every session runs over one TLS 1.3 connection (long-lived HTTP/2 stream or
  WebSocket framing over TLS 1.3, bound to `session_id` and `cb`). If the
  TCP/TLS connection drops, the session dies; reconnecting requires a fresh
  `session/challenge` handshake with the new connection's `cb`.
- **Mutations (`Submit`):** must arrive on a session authenticated as the
  exact `principal` named in the signed intent envelope `I`. The relay
  re-checks `standing(principal)` inside the serialized commit transaction on
  every submission (a session opened before revocation cannot submit after
  revocation).
- **Queries (`Query`) and anchor requests (`AnchorRequest`):** each request
  carries a strictly increasing per-session `req_id` and a signed request
  object bound to `(purpose, line_id, generation, session_id, cb, req_id,
  principal, request_body)` (distinct purpose tags `"ldr.query"` and
  `"ldr.anchor-request"`). Queries never mutate state, never allocate quota,
  and never advance `time_floor`.
- **Replies:** every reply is framed on that exact TLS 1.3 session and
  echoes `(line_id, generation, session_id, req_id, req_digest, answer_type,
  answer_payload)`. Because the TLS 1.3 record layer authenticates the pinned
  relay server on the session tied to `cb`, a client rejects any reply whose
  `(session_id, req_id, req_digest)` does not match its outstanding request
  on that connection.
- **Audit note on `revoked` evidence (Rule 8 / T47):** locally persisted
  `revoked` answers are trusted local observations from the pinned relay
  session, not third-party portable signatures. If non-repudiable relay
  receipts are ever desired later, that requires an explicit relay signing
  key and rotation model (explicitly deferred).

---

## 3. Atomic storage and durability

### 3.1 Single-transaction durability boundary

Every authoritative mutation at the relay MUST become durable in **one atomic
step** before any reply is written to the network:

1. **Commit (`Committed`):**
   - Committed chain frame `(seq, seq_time, prev_head, head, I_bytes)`
   - Validated ciphertext sidecar(s) and wrap sidecar(s) referenced by `I`
   - Updated semantic `State` (or deterministic append such that crash
     recovery replays the exact tail cleanly)
   - Permanent `log_index[op_key] = (seq, intent_digest)`
   - Hot outcome entry `hot[op_key] = (intent_digest, Committed, seq)`
   - Advanced `time_floor = max(time_floor, seq_time)`
2. **Durable non-commit (`Rejected` or `Noop`):**
   - Hot outcome entry `hot[op_key] = (intent_digest, outcome)`
   - Incremented `quota[signer]`
   - Advanced `time_floor`
3. **Demand-driven `time_anchor`:**
   - Committed `time_anchor` chain frame `(seq, seq_time, prev_head, head)`
   - Updated `State.Line.HeadSeq` / `HeadTime`
   - Advanced `time_floor`
4. **Compaction (`Compact`):**
   - Removal of `hot` entries for strictly retired anchors
     (`time_floor > seq_time(seen_seq) + validity_max`), decrementing
     `quota[signer]` for non-commits while NEVER removing `log_index` entries
   - Advanced `time_floor`

In-memory indices and caches MUST update **only after** the durable commit
succeeds; on any storage I/O error, the in-memory state is discarded or
reloaded from the last durable point, and the client receives an admission
error (`storage_error`), never a fabricated outcome.

### 3.2 Storage engine evaluation (zero-dep Go WAL vs embedded SQLite)

`yip`'s `go.mod` currently has zero third-party dependencies. Two serious
options exist for the operator-hosted Go relay:

| Dimension | Option A: Zero-dep framed append-only WAL + checkpoints | Option B: Embedded SQLite (WAL mode, pure-Go driver e.g. `modernc.org/sqlite` or CGO) |
| --- | --- | --- |
| **Dependencies** | Zero (100% Go stdlib) | First external dependency (and large transpiled C surface or CGO toolchain) |
| **Atomicity** | Explicit single-record CRC32C-framed WAL append + `fsync`/`F_FULLFSYNC` before ACK; atomic temp-file + `fsync` + `rename` + dir-`fsync` for periodic checkpoints | Mature ACID `BEGIN IMMEDIATE` transactions with WAL journaling and `synchronous=FULL` |
| **Indexing & queries** | Full semantic `State`, `log_index`, `hot`, and `seq -> file_offset` live in memory (rebuilt from latest checkpoint + WAL tail on startup); control-log range reads (`from..to`) seek directly into immutable segment files | SQL tables for frames, sidecars, `log_index`, `hot`, `time_floor`; bounded RAM even on huge multi-year lines |
| **Sidecars & retention** | Content-addressed sidecar files (`sha256` temp + `fsync` + `rename` + dir-`fsync`) written *before* the WAL commit frame; unreferenced sidecars GC'd safely on recovery | Stored as BLOBs in a separate table (or same external CAS pattern to keep WAL small) |
| **Platform durability traps** | Must explicitly handle **macOS `F_FULLFSYNC`** (`fcntl(fd, F_FULLFSYNC)`), Linux `fsync` + parent-dir `fsync`, and Windows `FlushFileBuffers`; torn tail frame truncation must verify CRC32C and never silently accept corrupt mid-log frames | SQLite handles `F_FULLFSYNC` (`PRAGMA fullfsync = ON` on macOS) and torn-page checksums out of the box, though misconfigured pragmas or network filesystems still break durability |
| **Auditability** | Small (~600–900 LOC), directly inspectable and fuzzable with fault injection | Large engine, battle-tested against power loss, less transparent internals |

**Draft recommendation (for review):** **Option A (zero-dep CRC32C-framed
append-only WAL + content-addressed sidecar store + periodic canonical
checkpoints)** fits Yip's zero-dependency architecture and LDR's
single-writer-per-line sequential workload cleanly — *provided* we treat
durability rigorously:

- **Write ordering for commits with sidecars:**
  1. Write each sidecar to `sidecars/tmp/<rand>`, `syncFile`, atomic `rename`
     to `sidecars/<hex_sha256>`, `syncDir(sidecars/)`. (Idempotent if already
     present and digest-verified.)
  2. Append one self-contained WAL record containing `(record_kind, length,
     body_cbor, crc32c_castagnoli)` to the active WAL segment and call
     `syncFile` (using `F_FULLFSYNC` on Darwin, `fsync` on Linux/BSD,
     `FlushFileBuffers` on Windows).
  3. Only after `syncFile` returns `nil` update in-memory state and return
     the reply.
- **Crash recovery on startup:**
  - Load latest verified checkpoint (atomic temp + `syncFile` + `rename` +
    `syncDir`), then scan WAL forward verifying every CRC32C and
    re-running `verifyFrame` / `Apply` on every committed frame.
  - A **partial/zeroed frame strictly at EOF** (from a crash mid-write) is
    truncated to the last valid frame offset and logged as a recovery event.
  - A **corrupt CRC32C or hash-chain mismatch BEFORE EOF** is a hard
    fail-closed startup error — never silently truncated!
  - Verify every committed frame's sidecar commitments exist on disk (or are
    explicitly marked pruned under a future retention policy, never silently
    missing on a live unpruned store).
- **Important caveat (honest limit):** process-kill (`SIGKILL`) tests verify
  application ordering and torn-tail handling, NOT disk controller write-cache
  lying or filesystem barrier bugs. Real durability requires local non-NFS
  storage, OS full-sync (`F_FULLFSYNC` on macOS), and documenting unsupported
  filesystems (e.g., cached network shares without flush semantics).
- **Re-evaluation trigger:** if a single relay host later needs thousands of
  concurrent lines or gigabytes of historical `log_index` that shouldn't sit
  in RAM, SQLite (Option B) can drop in behind the exact same `Store`
  interface without changing any protocol rule.

### 3.3 Client local store atomicity

The same single-step durability discipline applies to each client's local
store (shared by all local sessions of one credential under an advisory/OS
file lock):

- **Outbox persist-before-send:** the exact canonical signed envelope `I`
  and its encrypted sidecar bytes MUST be durably written (`syncFile`) to
  the outbox WAL **before** the first network send. Retries read only from
  that durable outbox record.
- **Verified log store:** verified committed frames, derived `State`,
  `(ckSeq, ckHead)`, and unretired `signedContext` advance together in one
  durable step; projections (`projected_seq`) and local delivery queues
  (`scanned_seq`) follow strictly as rebuildable cursors (`LDR-STATE-MACHINE.md`
  §11.2–§11.3).

---

## 4. Sequencer clock contract (O11)

The state machine (`§4.1`) requires:
1. Monotonically non-decreasing persisted `time_floor` (never regresses
   across evaluations or restarts).
2. Suspension (`clock_uncertain`) of new authoritative evaluations and
   expiry-based compaction whenever the clock cannot be trusted, while
   keeping historical receipt lookups (`log_index` + existing `hot` entries)
   alive.
3. No artificial cap on legitimate idle elapsed time, while distinguishing
   a **detected forward/backward clock jump** from elapsed time.

### 4.1 Go wall + monotonic clock detector

In Go, `time.Now()` captures both wall time and a process-local monotonic
reading (`go doc time`). The relay wraps clock access in a `ClockGuard`
state machine:

- **At startup:**
  1. Read persisted `time_floor` (UTC milliseconds) and persisted
     `last_clean_shutdown_wall_ms` (if any) from the durable store.
  2. Read current `now := time.Now()`.
  3. **Backward-across-restart check:** if `now.UnixMilli() < time_floor`:
     - If `time_floor - now.UnixMilli() <= max_minor_ntp_skew_ms` (provisional
       candidate: `5000` ms, i.e., 5 s), log a warning and clamp candidate
       time to `time_floor`? **NO — fail conservative or distinguish:**
       wait: clamping a 50 ms NTP slew to `time_floor` is normal in `§4.1`
       ("No later evaluation uses a time below the floor"), whereas a jump
       below `time_floor` exceeding `max_backward_jump_ms` (provisional:
       `5000` ms) MUST trip `clock_uncertain` immediately!
  4. **Suspicious forward jump across restart:** Go's monotonic clock resets
     at process start, so a restarted process cannot distinguish a host that
     was powered off for 3 days from a BIOS battery reset that jumped the
     clock to year 2099. Mitigations:
     - Sanity bound against `MaxCounter` and against an optional configured
       peer/NTP health check (`chronyc tracking` / `timedatectl` / operator
       configured internal NTP check where available on the LAN/corporate
       network).
     - Optional `max_restart_forward_jump` operator guardrail (e.g., if
       wall time jumped forward by > 30 days since last persisted `time_floor`,
       start in `clock_uncertain` requiring explicit operator confirmation
       `yip relay clock confirm` rather than silently expiring every active
       window or permanently pinning `time_floor` in the year 2099!).
  5. Record baseline `(base_wall_ms, base_mono = now)`.

- **During steady-state operation (every tick + periodic background sampler,
  e.g. every 1 s):**
  1. Read `cur := time.Now()`.
  2. Compute `delta_wall = cur.UnixMilli() - prev_wall_ms` and
     `delta_mono = cur.Sub(prev_mono).Milliseconds()`.
  3. **Discontinuity check:** compute `drift = delta_wall - delta_mono`.
     - If `|drift| > max_step_ms` (provisional candidate: `5000` ms):
       a wall-clock step (backward or forward) or host sleep/suspend
       occurred! Wait: on macOS/laptops, `go doc time` explicitly notes that
       Go's monotonic clock **pauses during host sleep**, so waking a laptop
       after a 2-hour sleep produces `delta_wall = +7200000 ms`,
       `delta_mono ≈ 0 ms` -> `drift = +7200000 ms`!
     - **Critical LAN/laptop distinction:**
       - On a dedicated always-on server (Linux/macOS server mode), a large
         `drift` means a wall-clock jump or VM pause -> trip
         `clock_uncertain` immediately so a forward jump never falsely
         expires intents or compacts hot rejections.
       - On an ad-hoc LAN laptop relay that legitimately sleeps and wakes,
         waking from sleep is indistinguishable from a forward wall jump using
         Go's monotonic clock alone. Entering `clock_uncertain` on large
         positive drift until the host's time sync / operator health probe
         re-establishes trust (or an explicit LAN-laptop sleep-resume probe)
         is the **fail-safe default** — never blindly accept an unverified
         forward jump!
  4. **Frozen-clock check:** if `N` consecutive evaluations or sampler ticks
     spanning `delta_mono >= freeze_detect_ms` (provisional: `30000` ms)
     observe `delta_wall == 0`, trip `clock_uncertain`.
  5. Update `(prev_wall_ms, prev_mono)` only while trusted; return
     `max(cur.UnixMilli(), time_floor)`.

- **While in `clock_uncertain`:**
  - `Submit` (lookup hit in `log_index` or `hot`) and `Query` (lookup hit)
    still return the recorded outcome (no clock needed).
  - New `Submit` admission, `AnchorRequest`, time-dependent `Query`
    (`expired` / `outcome_unknown`), and `Compact` all return
    `admission_error / clock_uncertain` without advancing `time_floor`.
  - Health endpoint and operator logs surface the exact discontinuity
    evidence (`prev_wall`, `cur_wall`, `delta_mono`, `time_floor`).
  - Recovery from `clock_uncertain`: either automatic re-verification via a
    configured trusted local NTP/chrony source confirming synchronization
    and `wall >= time_floor`, or explicit operator `yip relay clock resume`
    after verifying host time.

---

## 5. Wire encoding and cryptographic suite candidate (P6)

> **Unapproved proposal.** No algorithm or encoding below is authorized for
> production implementation until reviewed by Codex, Claude and the operator
> and validated against official RFC test vectors and cross-implementation
> negative vectors.

### 5.1 Deterministic CBOR restricted subset (RFC 8949 §4.2.1)

Matching `LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` §5.1, all protocol objects
(`creation-descriptor`, signed intent body `B`, signed envelope `I`, chain
frame, session proofs, queries, anchor requests, register values) use a
**strict deterministic CBOR subset** implemented in zero-dep Go (~350–450
LOC):

- **Allowed major types only:**
  - Major 0: unsigned integers in `[0, 2^53 - 1]` using shortest canonical
    argument encoding (fail before conversion if `> 2^53 - 1` or non-shortest).
  - Major 2: definite-length byte strings (`bstr`).
  - Major 3: definite-length valid UTF-8 text strings (`tstr`).
  - Major 4: definite-length arrays.
  - Major 5: definite-length maps with keys sorted in RFC 8949 §4.2.1
    bytewise lexicographic order of encoded keys, NO duplicate keys, fixed
    ASCII text keys only.
  - Major 7: `false` (`0xf4`) and `true` (`0xf5`) ONLY.
- **Explicitly rejected on decode (admission failure):**
  - Negative integers (major 1), semantic tags (major 6), floats (`half`/
    `single`/`double`), `null` (`0xf6`), `undefined` (`0xf7`), indefinite-length
    items (`0x1f` / break `0xff`), non-shortest integer/length encodings,
    out-of-order or duplicate map keys, invalid UTF-8 in `tstr`, trailing
    bytes after the top-level item, unknown map keys, or nesting/collection
    counts exceeding profile bounds.
- **Absent vs zero:** an absent map key in `expect` is never defaulted to `0`.
  If a record type requires an `expect` key and the map omits it, decode
  succeeds (valid CBOR map) and stage 5 `Apply` rejects it durably as
  syntactic `invalid` (matching `A195`–`A211`, `A224`).

### 5.2 Hashing and domain separation

- **Hash function `H`:** `SHA-256` (`crypto/sha256`, Go stdlib).
- **Domain-separated digest helper:**
  ```
  D(purpose, version, fields...) = SHA-256(Enc([purpose, version, fields...]))
  ```
  Distinct purpose strings for every object class:
  - `"ldr.creation-descriptor"`
  - `"ldr.genesis"`
  - `"ldr.cred-id"`
  - `"ldr.intent-signature"` / `"ldr.intent-signature.digest"` (see §5.3)
  - `"ldr.intent"` (retry/mismatch digest covering `I_bytes` including sig)
  - `"ldr.chain"` (client record frame) and `"ldr.chain.anchor"` (`time_anchor`)
  - `"ldr.payload-commit"` and `"ldr.wrap-commit"`
  - `"ldr.session-auth"`, `"ldr.query"`, `"ldr.anchor-request"`
  - `"ldr.join-request"`, `"ldr.join-challenge"`, `"ldr.join-proof"`
  - `"ldr.register"`
  - `"ldr.recovery-bundle"` (when recovery is adopted)

### 5.3 Signatures: Ed25519 (RFC 8032) with bounded pre-commitment

- **Candidate:** `Ed25519` (`crypto/ed25519` in Go stdlib) with **strict
  canonical verification** (reject non-canonical `S >= L`, small-order `R`
  or `A`, and non-canonical point encodings — note that Go's stdlib
  `ed25519.Verify` rejects `S >= L` per RFC 8032 §8.4, and we MUST explicitly
  test ZIP-215 vs RFC 8032 strictness and small-order public-key rejection
  using published Ed25519 edge-case test vectors!).
- **Bounded pre-commitment for hardware-key compatibility:**
  To keep the message passed to external/hardware signing paths small and
  constant-size (avoiding large APDU payloads while still authenticating the
  exact canonical body `B` and its length), sign:
  ```
  M = Enc(["ldr.intent-signature.digest", 1, "sha-512", len(B), SHA-512(B)])
  ```
  (consistent with the bounded pre-commitment pattern noted in root-signing
  review). Every normal signer computes `SHA-512(B)` from the exact canonical
  body `B` it displays/approves; the verifier recomputes `M` from received
  `B_bytes` and verifies `Ed25519.Verify(pk, M, sig)`.
- **Public key normalization:** `[alg_id = "ed25519", 32-byte canonical public
  key]`. Checked against canonical encoding and small-order rejection before
  entering the permanent key registry.
- **Root keys (equal 1-of-2):** each of the two root keys carries its own
  explicit `[alg_id, canonical_pk_bytes]` entry in `root_keys`, allowing
  heterogeneous algorithms later if a profile adds one (e.g., ECDSA P-256 /
  WebAuthn COSE key alongside Ed25519) without breaking principal tagging or
  key reservation — though phase 1's initial profile should start with a
  single reviewed algorithm (`ed25519`) unless hardware root signing requires
  P-256 (`ecdsa-p256-sha256` with strict low-S RFC 6979 / SEC1 uncompressed
  canonical normalization). That single question (whether root keys need
  `ecdsa-p256` in addition to `ed25519`) should be confirmed before freezing
  Profile v1!

### 5.4 Per-recipient key wrapping & join-challenge encryption: HPKE Base (RFC 9180)

- **Candidate:** **HPKE Base mode** (`mode_base = 0x00`, RFC 9180):
  - KEM: `DHKEM(X25519, HKDF-SHA256)` (`0x0020`)
  - KDF: `HKDF-SHA256` (`0x0001`)
  - AEAD: `AES-256-GCM` (`0x0002`)
- **Go 1.25 stdlib feasibility:** checked locally on `go1.25.3`: `crypto/ecdh`
  (`X25519`), `crypto/hkdf` (added in Go 1.24), `crypto/aes`, and
  `crypto/cipher` are ALL in the Go standard library. `crypto/hpke` is not
  yet in Go 1.25 stdlib, so RFC 9180 Base mode for this single fixed
  ciphersuite is ~120 lines of pure Go stdlib code that MUST pass every
  official **RFC 9180 Appendix A.1.1 / A.1.2** test vector (and reject
  all-zero X25519 shared secrets / low-order public keys per RFC 7748 §6.1).
- **Authenticated context binding:**
  - `info`: canonical CBOR of `["ldr.epoch-wrap", 1, line_id, generation,
    profile_digest, new_epoch, expect_epoch, auth_epoch, op_identity,
    recipient_cred_id, recipient_enc_key, manifest_digest]` (or
    `"ldr.join-challenge"` with P3's ceremony context).
  - `aad`: empty or fixed CBOR header; keeping full binding in `info` (key
    schedule) AND repeating envelope coordinates in `aad` binds both the key
    derivation and the AEAD tag cleanly.
  - Because HPKE Base mode provides confidentiality and integrity to the
    recipient's public key but NOT sender authentication, authenticity comes
    from the operator's Ed25519 signature over the `key_epoch_activate`
    manifest (which commits `SHA-256(enc || ct)` and length for every wrap
    sidecar) and from the P3 join ceremony transcript.

### 5.5 Line payload encryption: misuse-resistance analysis

Every line-scope payload (turns, notes, broadcasts, attachments, actor
labels, register values) is encrypted under the active 32-byte epoch secret
`K_epoch`, which is shared by **multiple concurrent writers** (all enrolled
readers on the line).

Two serious candidates exist; **neither** is `HKDF(op_id)` with fixed-nonce
AES-GCM (explicitly ruled out in `LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` §6):

| Candidate | Stdlib? | Nonce-misuse resistance | Multi-writer safety | Trade-offs |
| --- | --- | --- | --- | --- |
| **Candidate 1: AES-256-GCM-SIV** (RFC 8452) with random 96-bit nonce + full `context_bytes` AAD | Needs ~250 LOC pure-Go POLYVAL + AES-CTR + key derivation verified against RFC 8452 Appendix C vectors (or reviewed dep) | **Yes** — repeating `(K, nonce)` on different plaintexts leaks only plaintext equality, never destroys authenticity or leaks XOR of plaintexts | Safe up to key-use limit even across VM snapshots/clones if nonce ever collides; still requires fresh CSPRNG nonce + persist-before-send | Custom POLYVAL implementation needs careful constant-time review, OR brings a small audited library |
| **Candidate 2: Per-message random-salt HKDF-SHA256 + AES-256-GCM** (`salt = 32 CSPRNG bytes`, `msg_key = HKDF(K_epoch, salt, info=context_bytes)`, `nonce = 12 CSPRNG bytes`, `aad = context_bytes`) | **100% Go stdlib** (`crypto/hkdf`, `crypto/aes`, `crypto/cipher`, `crypto/rand`) | Standard GCM safety per derived key; 256-bit random salt eliminates multi-writer birthday collision across an entire epoch (`2^128` threshold instead of `2^48` / `2^32` for 96-bit random GCM nonces!) | Safe across unlimited concurrent writers without coordination; **HOWEVER**, if a VM snapshot rolls back *before* persist-before-send AND replays identical CSPRNG state, `salt`+`nonce` could repeat | Zero custom crypto primitives; still relies on OS CSPRNG freshness (`crypto/rand` / `getrandom` / `CCRandomGenerateBytes`) and strict persist-before-send |

**Draft assessment (for Codex/Claude review):**
- **Candidate 2** (32-byte CSPRNG `salt` -> `HKDF-SHA256(K_epoch, salt, info)` ->
  one-time 32-byte `msg_key` + 12-byte `nonce` -> `AES-256-GCM(msg_key, nonce,
  plaintext, aad=context_bytes)`) completely eliminates the classic
  multi-writer 96-bit random-nonce birthday bound of raw AES-GCM while using
  **zero custom cryptographic code** (100% Go 1.25 stdlib FIPS-reviewed
  primitives) — unlike `HKDF(op_id)` with fixed nonce, which reuses keys if a
  client crashes and re-encrypts under the same `op_id`!
- **Candidate 1 (AES-256-GCM-SIV)** adds an extra layer of defense against
  cloned-VM CSPRNG-state replay at the cost of implementing or depending on
  POLYVAL/GCM-SIV.
- **Explicit key-use limits (mandatory under either candidate):** e.g.,
  automatic advisory rekey prompt after `2^20` messages or `90` days per epoch
  (far below cryptographic limits), plus mandatory **persist-before-send**
  (`§3.3`): a restored local outbox with uncertain encryption state reconciles
  first and never re-encrypts an existing operation identity.
- **AAD (`context_bytes`)** binds `(purpose, version, profile_digest,
  line_id, generation, principal, actor_id, binding_gen, op_id, op_type,
  seen_seq, seen_head, key_epoch, target, expect, visible_fields)` — never
  including the resulting ciphertext digest (`§5.3` of Codex's draft, avoiding
  circularity).

---

## 6. Full-replay bootstrap flow (O25 decided)

With **O25 decided on 2026-11-25** in favour of full control-log replay from
genesis before ordinary use, new-member onboarding simplifies substantially
and eliminates the entire detached-attestation / snapshot-service surface (P4
and §14.7) from phase 1:

1. **Out-of-band pinning:** joining machine receives the root-signed creation
   descriptor (containing `line_id`, initial two `root_keys`, `relay_origin`
   with TLS pin, `generation = 1`, `profile`) and verifies its fingerprint
   against the operator over an independent channel. It computes `CD` and the
   expected genesis anchor locally.
2. **P3 key-first ceremony:** joining machine generates independent Ed25519
   signing key and X25519 encryption key, derives `cred_id`, signs its
   `join_request`, proves decryption of the operator's HPKE challenge, and
   saves its exact expected `(cred_id, signing_key, encryption_key, grant,
   join_request_id, join_request_digest)` locally.
3. **Enrollment & key epoch:** operator signs and commits `credential_enroll`
   and (if `grant.reader == true`) `key_epoch_activate` with a wrap for the
   new credential.
4. **Authenticated session & anchor:** joining machine connects over pinned
   TLS 1.3 (`§2`), proves possession of its signing key via `tls-exporter`
   challenge, and issues `AnchorRequest` to learn the relay's current fresh
   head `(fseq, fhead)`.
5. **Control-only genesis replay:** joining machine fetches control-only
   frames `(1, 1..fseq)` in bounded paginated chunks (e.g., 256 frames per
   page, omitting all payload sidecars per P5). For every frame from `1` to
   `fseq`:
   - Verify consecutive `seq`, `prev_head` linkage, and `head` hash;
   - Verify strict canonical CBOR and profile bounds;
   - Verify `line_init` against pinned creation descriptor, `CD`, genesis
     anchor, and initial `root_keys`;
   - For every signed frame: verify Ed25519 signature under the signer
     authorized by current derived state, generation match, anchor on chain
     (in unretired `signedContext`), historical deadline `seq_time -
     anchor.seq_time <= validity`, and unique committed operation identity;
   - For every `time_anchor`: verify `seq_time - prev.seq_time > F` from the
     committed profile;
   - Run `Apply` and require `Committed`; prune retired anchors from
     `signedContext` as `seq_time` advances.
6. **Activation gate:** after reaching `(fseq, fhead)` cleanly:
   - Verify `state.Line.Credentials[cred_id]` exists, is NOT revoked, and
     exactly matches the saved keys and grant;
   - If `grant.reader == true`, verify at least one epoch in
     `state.Line.Readers` includes `cred_id`, fetch this credential's own
     wrap sidecar for that epoch, verify its commitment against the signed
     manifest, and unwrap `K_epoch` via HPKE (failing pending if not yet
     activated);
   - Atomically commit `(state, ckSeq=fseq, ckHead=fhead, signedContext,
     unwrapped epoch keys)` to the local verified store before enabling
     ordinary `Compose`, `Send`, register publication, or local delivery.

**Performance budget sanity check:** control-only envelopes without payload
sidecars average ~400–600 bytes each; verifying 10,000 Ed25519 signatures on
modern Apple Silicon / x86-64 takes ~0.3–0.6 seconds across 2–4 cores (~5 MB
transfer over LAN). Even a 100,000-record multi-year line replays in a few
seconds on a LAN with zero trust exception!

**Control-log retention requirement:** because full replay from genesis is
the phase-1 onboarding path, the relay MUST retain all control frames
(`1..head`) of the active generation permanently (while old payload sidecars
may eventually be subject to operator storage/archival policy without
breaking control replay, since payloads are committed by hash only).

---

## 7. Backup and recovery ergonomics

Connecting directly to [LDR-RECOVERY.md](LDR-RECOVERY.md) (draft v0):

- **Relay backup:** copying the relay's append-only WAL segments and sidecar
  directory produces a consistent point-in-time backup (using a brief
  checkpoint fence or read-only snapshot).
- **Independent security witness (for rollback safety):** because restoring an
  old relay backup loses later revocations and tombstones, an operator's own
  local verified client store (or a lightweight passive read-only mirror on a
  second workstation) naturally serves as an independent signed witness of
  the highest seen head `(gen, seq, head)` and every committed security
  record (`operator_key_*`, `root_member_replace`, `credential_*`).
- **No silent rollback:** clients detect relay rollback via
  `history_unavailable` (`OutReconcile` + `suspect = true` + fail-closed
  `Anchor` and `Compose`). Resuming after genuine data loss requires the
  explicit root-signed `recovery_generation` workflow drafted in
  [LDR-RECOVERY.md](LDR-RECOVERY.md) (still unapproved).

---

## 8. Implementation-readiness checklist and phased build plan

No production relay, transport, or cryptographic code is authorized yet.
Before requesting implementation go-ahead from the operator, the following
design gates remain:

### Remaining pre-implementation design gates

1. **Cross-review on `gemini/ldr`:** Codex (Astra) and Claude (Fable) review:
   - Draft v8 equal 1-of-2 roots (`ldrcore/` + `A213`–`A232` + `T51`–`T52`);
   - Gemini probe fixes `G1`–`G5` and §11.2 replay checks (`T48`–`T50`);
   - Recovery draft ([LDR-RECOVERY.md](LDR-RECOVERY.md)) and O23 (`seq` reset
     to 1 vs monotonic);
   - This Go-relay architecture draft (`§1`–`§7`), specifically:
     - Zero-dep WAL (`Option A`) vs SQLite (`Option B`);
     - Payload AEAD choice (Candidate 1 `AES-256-GCM-SIV` vs Candidate 2
       random-salt `HKDF-SHA256 + AES-256-GCM`);
     - Whether Profile v1 needs `ecdsa-p256` alongside `ed25519` for hardware
       root signing;
     - Exact wire schema registry (field names, integer bounds, max sizes for
       O4/Q13) and exact `ClockGuard` sleep/wake policy on LAN laptops.

### Candidate phased build plan (post-approval only)

- **Phase A — Wire encoding & crypto primitives package (`ldrcrypto/`):**
  deterministic CBOR encoder/decoder with strict negative test suite;
  canonical Ed25519 + RFC 8032 / edge-case vectors; HPKE Base mode verified
  against RFC 9180 Appendix A.1 vectors; chosen payload AEAD verified against
  RFC test vectors; canonical intent/chain/descriptor builders and golden
  cross-check vectors.
- **Phase B — Durable store & Go relay server (`ldrstore/`, `ldrrelay/`):**
  single-transaction WAL + sidecar store with `F_FULLFSYNC` and crash/torn-tail
  fault-injection tests; `ClockGuard` with discontinuity & restart tests;
  TLS 1.3 server with `tls-exporter` session challenge binding; `yip relay
  init / provision / serve / status`; end-to-end integration tests running
  `T01`–`T52` over real localhost TLS 1.3!
- **Phase C — Yip client LDR attachment (`ldrclient/` + CLI/MCP wiring):**
  local durable verified log store + outbox persist-before-send + full-replay
  joiner (`§6`); P3 key-first enrollment CLI ceremony; equal-roots management
  CLI (`operator_key_*`, `root_member_replace`); projection materializer and
  local delivery scan cursor hooked into existing `yip` MCP/CLI tools while
  keeping host-local resource leases untouched.
