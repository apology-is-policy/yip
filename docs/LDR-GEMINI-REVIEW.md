# LDR independent review and probe of `2062b74` — Gemini

2026-11-25 · Gemini (gemini seat) · Unapproved design review and model audit.
Not an operator decision, security certification, or implementation/deployment
approval.

While Codex and Claude were temporarily unavailable on Yip, Gemini took over
continuation from `claude/ldr` commit `2062b74` (call 0003 turn 28) and
Codex's companion drafts (`LDR-THREAT-MODEL.md` draft v1,
`LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` draft v3, `LDR-CLIENT-MODEL-REVIEW.md`,
`LDR-STATE-COMMITMENT-REVIEW.md`, `LDR-HOSTING-REVIEW.md`).

All new code and specification edits live on branch `gemini/ldr` (branched from
`claude/ldr` `2062b74`). Neither `master`, `claude/ldr`, nor Codex's local
files in the shared checkout were modified.

## 1. Independent execution against `claude/ldr` (`2062b74`)

Under a held `mac` lease, `claude/ldr` at `2062b74` was exported read-only and
checked before any edits:

- `GOMAXPROCS=2 go test -race -count=1 ./ldrcore` passed in 27.628s.
- Five independent overlay probes (`TestGeminiProbeG1` through
  `TestGeminiProbeG5`, including `G1b`, 12 subtests total) ran via
  `go test -overlay` in 0.157s. Every probe passed by reproducing the undesired
  acceptance/behavior below.

The `mac` lease was released immediately after verification.

## 2. Audit of the live-window completeness argument (`2062b74`)

Call 0003 turn 28 asked for an independent attack on `openWindow` and its
completeness argument (`docs/LDR-STATE-MACHINE.md` §14.7, `ldrcore/join.go`).

**Result against a dishonest relay holding no keys (honest endorser):** the
completeness argument holds.

1. `Apply` enforces non-decreasing `seq_time`, so every suffix record commits
   at `t_S >= T` where `T` is the endorsed head's `seq_time`.
2. Any admissible suffix record anchored at `A` must satisfy
   `t_S - t_A <= validity <= validity_max`, hence `t_A >= T - validity_max =
   oldest`.
3. Under an honest endorser that verified `1..at`, timestamps in `1..at` are
   non-decreasing, so every frame strictly before the stopping frame
   (`e.SeqTime < oldest`) also has `SeqTime < oldest`.
4. Any operation `X` that committed at `s_X <= at` whose anchor `A` satisfies
   `t_A >= oldest` must also satisfy `t_X >= t_A >= oldest`. Because
   `openWindow` stops only on strict `e.SeqTime < oldest`, `openWindow` visits
   `s_X` and indexes `X`'s `OpKey` in `ctx.ops`.
5. Backward hash linkage from `en.SeenHead` (`frameHead`) binds `Prev`, `Seq`,
   `SeqTime`, `Type`, `Digest`, and `StateDigest`; checking `Origin ==
   recordOrigin[Type]` and `signedBy` ties `OpKey` to the frame under the
   model's unique-digest premise.

On Fable's turn 28 question about Codex's wire frame: Codex's
`LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` §5.4 already puts `origin` and exact
`I_bytes` directly inside the chain frame covered by `head`. On the real wire
format, opening the hash chain backwards therefore binds `origin` and `OpKey`
without relying on a separate type-to-origin table.

## 3. Five findings reproduced at `2062b74`

### G1. `ResolveAll` clears `mustResolve` on admission errors

In `outbox.go:444-459`, `ResolveAll` unconditionally set
`c.out.mustResolve = false` at the end of the loop. When a client restarted
with unsettled intents and ran `ResolveAll` while the relay returned
`admission_error / clock_uncertain` (either for all intents, or for an
uncommitted intent while another intent settled from `logIndex`), none of the
unanswered intents were resolved by query, yet `Compose` on a free slot
immediately succeeded instead of returning `ErrMustResolve`.

**Closed on `gemini/ldr`:** `ResolveAll` tracks whether any active key's query
received `ClassAdmission` and clears `mustResolve` only when every active
unsettled intent received a non-admission answer (or its key stopped on
`revoked`). Recorded in §5.7 rule 3 and trace T48.

### G2. `Client.Anchor` contacts the relay while failed closed

In `outbox.go:497-508`, `Anchor` checked `signsNoMore` (Codex's C3) but not
`c.halted != ""` or `c.out.suspect`. Both a client halted on a sequencer
violation and a client suspecting a rollback (`history_unavailable`) still sent
an authenticated `AnchorRequest` to the relay, causing the relay to append a
`time_anchor` record; in the rollback-suspected case `Anchor` returned `nil`.

**Closed on `gemini/ldr`:** `Anchor` checks `c.halted` and `c.out.suspect` and
returns `ErrFailClosed` before contacting the relay. Recorded in §11.2 and
trace T49.

### G3. `openWindow` structural and budget gaps

Against malformed or colluding prefixes (the structural boundary tested by
`TestJoinBindsTheTwoTogether`), `openWindow` missed four checks:

- **Non-monotonic timestamps:** `openWindow` did not verify `p.SeqTime <=
  e.SeqTime` (or `[0, MaxCounter]`), even though Premise 1 of its completeness
  argument assumes non-decreasing time.
- **Missing `StateDigest`:** frames before the endorsed head could omit
  `StateDigest` even under `Profile.StateCommit == true`.
- **Unchecked frame fields:** `OriginSequencer` frames could carry `Sig`,
  `SeenHead`, `Key`, or `Digest`; signed frames were not checked for
  `Key.Signer`, `Key.Generation`, `Key.SeenSeq < e.Seq`, `Key.OpID != ""`, and
  `Digest != ""`; and sequence 1 was not required to be `line_init`.
- **Negative `MaxWindowRecords` bypass:** `case e.Seq == 1:` ran before
  `case n >= budget:`, so a negative budget accepted a 1-frame prefix.

**Closed on `gemini/ldr`:** `join.go` now enforces all four checks and rejects
negative budgets before entering the loop.

### G4. `verifyFrame` and `Apply` admission-field gaps

- `Apply` checked `r.ValidityMS <= prof.ValidityMaxMS` without checking
  `r.ValidityMS >= 0`. On `line_init` (which returns early in `admitted`),
  `ReplayVerified` accepted negative `ValidityMS`.
- `verifyFrame` accepted empty `OpID` or empty `Digest` on signed records, and
  non-empty `Digest` on `time_anchor` frames.

**Closed on `gemini/ldr`:** `apply.go` requires `r.ValidityMS >= 0` (vector
A212), and `commit.go` enforces non-empty `OpID`/`Digest` on signed frames and
empty `Digest` on `OriginSequencer` frames.

### G5. `DecodeState` / `CheckInvariants` accepts unreachable snapshots

`CheckInvariants` accepted generation-1 states with `root_rev == 0`,
`key_epoch == 0` with `rekey_pending == false`, an empty `readers` map or
empty reader list for an active epoch, unknown register names in
`register_writers` (splitting on `/` and discarding the register name), empty
map IDs, and invalid `dispute.resolution.kind` values.

**Closed on `gemini/ldr`:** tightened `invariants.go`; all 210 active
conformance vectors pass.

## 4. Adoption of Fable's §11.2 proposal and anchor-retirement pruning

Call 0003 turn 28 proposed making J1–J3 (generation, historical deadline
against recorded anchor time, unique committed operation identity) normative
replay checks in §11.2 for every replaying client, plus dropping retired
anchors and their identities from verifier memory.

Gemini endorses this proposal and implemented it on `gemini/ldr` (draft,
awaiting Codex, Claude, and operator review):

- `Client.Sync` now runs signed-context replay verification (`verifyFrame`) on
  both the ordinary profile and `Profile.StateCommit`, while preserving the
  ordinary profile's stated signature-as-premise boundary.
- `signedContext.prune` drops every anchor `seq` with `headTime > a.time +
  validityMaxMS` (§5.6 strict comparison) and all committed `OpKey` entries
  under it. Any later record naming a pruned anchor is still refused because
  the anchor is no longer held.
- Covered by trace T50 and regression tests in `ldrcore/gemini_probe_test.go`.
- Measured on `gemini/ldr` after all fixes (Go 1.25, darwin/arm64, under a
  held `mac` lease): `gofmt -l ldrcore/` clean, `go vet ./ldrcore/` clean,
  `GOMAXPROCS=2 go test -count=1 ./ldrcore/` passed (49.389s, including full
  stride-1 `TestHostileRecords`, all 210 active apply vectors, all 50
  conformance traces T01–T50, and `TestGeminiProbeRegressions`), and
  `GOMAXPROCS=2 go test -race -count=1 ./ldrcore/` passed (33.870s).
- Recommendation for Codex's `LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` §5.4: add
  the matching replay obligation (generation, historical deadline against
  recorded anchor time, unique committed operation identity) alongside
  consecutive sequence and `Apply` re-derivation.

## 5. Review of Codex's envelope draft (v3) and recovery gap

Gemini reviewed `LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` draft v3 (P1–P9):

- **Concurrence:** P1–P9 cleanly separate descriptor provisioning, immutable
  two-key credentials, key-first enrollment proofs, detached sidecars, strict
  deterministic CBOR framing, session-bound queries/anchors, permanent
  operator-key tombstones, and enrolled-reader epoch generation. Gemini also
  concurs with rejecting its earlier turn-15 `HKDF(op_id)` + fixed-nonce GCM
  sketch in favour of a reviewed standard construction and test vectors once
  crypto design is authorized.
- **Unaddressed gap — recovery & generation transitions (O23, Invariant 14):**
  all current documents leave `recovery_generation`, cross-generation sequence
  numbering, and rollback security-state reconciliation unspecified. Gemini
  drafted a standalone v0 proposal in [LDR-RECOVERY.md](LDR-RECOVERY.md) for
  cross-review, including two code-grounded model findings (`Broadcast.Receipts`
  `ReadSeq` and projection `derived_seq` view tags both need generation
  qualification before recovery can be modelled).

## 6. Third-provider positions on the open operator choices

These are Gemini's independent design assessments, labelled as proposals and
not decisions:

1. **O25 (New-member control bootstrap):** Gemini concurs with Codex and Claude
   in preferring **full control-log replay from genesis before ordinary use**
   as the default path *provided* the operator confirms that exposing
   envelope-level control metadata (principals, action types, timestamps — no
   message plaintext and no prior epoch keys) to newly enrolled accounts is
   acceptable and a benchmark with real signature verification confirms startup
   cost. If full replay is ruled out, the state-commitment route (§14.7) is
   stronger than detached P4 against a solo compromised enrolling device, but
   only when the relay pin is authenticated independently of that device and
   with the real cost of a consensus-critical state encoding on every frame.
2. **O26 (Root ceremony and two-key policy):** The core distinction between
   **either-of-two equal roots** and **active root + recovery-only second key**
   is whether compromise of the day-to-day root key can strip the recovery
   path. Equal roots minimize state-machine complexity; a recovery-only key
   protects recovery against active-key compromise at the cost of explicit
   asymmetric policy rules. Either way, an end-to-end ceremony dry run against
   the provisional 10-minute validity window is needed before fixing §4.4's
   root validity rule.
3. **Hosting (`LDR-HOSTING-COMPARISON.md`):** No deployment choice is
   recommended before session binding, the clock contract, and external
   recovery-evidence retention are settled. An operator-hosted Go relay avoids
   cross-runtime verification divergence and exposes direct TLS exporters
   (`ExportKeyingMaterial`), at the cost of operating host durability, TLS, and
   availability; a Cloudflare Durable Object offloads hosting and offers
   SQLite `transactionSync`, at the cost of cross-runtime parity, undocumented
   restore/clock semantics, and unestablished inbound TLS exporter access.
