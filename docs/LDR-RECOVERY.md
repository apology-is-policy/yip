# LDR recovery and generation transitions — draft v1

2026-11-25 · Gemini (gemini seat) · Operator approved reference modelling in
`ldrcore/` on 2026-11-25 with O23-B (`seq` reset to 1 with `(gen, seq)`
coordinates), full cross-generation replay `(1, 1..base_seq) -> (2, 1..head)`,
and discarded `call_id` / `broadcast_id` tombstoning; awaits Codex and Claude
cross-review before any relay/client production implementation.

Companions: [LDR-STATE-MACHINE.md](LDR-STATE-MACHINE.md) (§4.4, §5.5, §5.9,
§6.2, §13 O23, Appendix A Q15), `LDR-THREAT-MODEL.md` (Invariant 14), and
`LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` (§2.1, §5.4, §8).

## 1. Problem and impossibility boundary

A relay can lose its latest committed tail (point-in-time database restore,
storage failure, or hosting migration from a backup), or an operator may need
to advance a line to a new immutable profile, a new relay origin, or past
sequence exhaustion (§5.9).

**Core security boundary (Invariant 14):** restoring a database to an older
coordinate `(g, base_seq)` and incrementing the generation number is **not**
safe recovery. A rolled-back log does not contain revocations, actor removals,
tombstones, reserved public keys, consumed join-request IDs, or namespace
grants that committed in the discarded tail `(base_seq, tail]`. If recovery
replays only from `(g, base_seq)` without external security state, a revoked
credential or revoked operator key can silently regain authority, and a
consumed join request or tombstoned key can be reused.

**Impossibility limit:** if *both* the relay tail and every independent witness
holding the security records from `(base_seq, tail]` are lost — and the
operator cannot rule out that revocations or compromises occurred during that
window — no cryptographic trick on the rolled-back database can prove those
events did not happen. In that case the protocol must **fail closed**: keep the
line halted and migrate explicitly to a brand-new `line_id` with freshly
generated keys.

## 2. Three transition cases

| Case | Cause | Discarded tail? | Required security input |
| --- | --- | --- | --- |
| **Planned generation transition** | Immutable profile upgrade, relay endpoint migration, or `head_seq` exhaustion (§5.9) | No (`base_seq == current head_seq`) | Verified current state at `(g, head_seq)`; zero discarded security records |
| **Rollback recovery with reconciled evidence** | Relay restore to `(g, base_seq)` after storage/host failure | Yes: `(base_seq, tail]` | Authenticated security delta from surviving honest witnesses / independent operator security ledger covering `(base_seq, tail]` |
| **Unreconcilable loss** | Relay rollback with missing or disputed security evidence | Unknown | **Refused for in-place recovery.** Explicitly migrate to a new `line_id` |

## 3. Proposal for O23: sequence numbering across generations

Appendix A Q15 and §13 O23 leave undecided whether `seq` restarts in a new
generation or continues from `base_seq + 1`.

| Option | Behavior at `recovery_generation` | Pros | Cons |
| --- | --- | --- | --- |
| **O23-A: continue `seq`** | First record of `g+1` is `seq = base_seq + 1` | Bare sequence numbers stay non-decreasing on planned transitions | **Does not solve `head_seq` exhaustion (§5.9):** if `base_seq == MaxCounter`, `g+1` cannot append a single record. On rollback where a client saw `old_ckSeq > base_seq`, `base_seq + 1 <= old_ckSeq`, so bare `seq` still collides with discarded-tail coordinates and cannot order projection views alone. |
| **O23-B: reset `seq` to 1 (proposed)** | First record of `g+1` is `(g+1, seq = 1)` | Solves `head_seq` exhaustion permanently; cleanly separates discarded tail `(g, base_seq+1..)` from new generation `(g+1, 1..)`; aligns with already generation-qualified `OpKey` and chain domains (§5.4). | Every stored coordinate and tag in `State` and projections must be generation-qualified `(generation, seq)`. |

**Proposed direction: O23-B (reset `seq` to 1 in `g+1`, with every coordinate
generation-qualified as `(generation, seq)`).**

### Code-grounded model audit for O23

Inspecting `ldrcore/` at `2062b74` shows two places that currently assume a
single generation's bare `seq` and **must** become `(generation, seq)` before
recovery can be modelled under O23-B (and view tags need `(generation, seq)`
even under O23-A whenever a rollback discards records):

1. **`Broadcast.Receipts[actor].ReadSeq`** (`ldrcore/state.go:139`,
   `ldrcore/invariants.go:254`): `CheckInvariants` asserts
   `rc.ReadSeq <= l.HeadSeq`. If a broadcast receipt from `(1, 500)` is carried
   into generation `2` starting at `(2, 1)`, a bare `ReadSeq` breaks that
   invariant. Changing `Receipt` to `{ReadGen, ReadSeq}` fixes both storage and
   invariant validation (`ReadGen < Generation` or `ReadSeq <= HeadSeq`).
2. **Projection view tags (`derived_seq`)** (`ldrcore/client.go:351, 413, 460`):
   monotone view replacement compares bare `tag`. After a rollback from
   `(1, 500)` to `(1, 400)` and transition to `(2, 1)`, a new view at `(2, 1)`
   must supersede an archived/stale view from `(1, 450)` — which requires
   lexicographic comparison on `(derived_gen, derived_seq)`.

## 4. `recovery_generation` record structure and rules

`recovery_generation` is a root-origin record, exempt from ordinary validity
(§4.4), and can commit **only** as record `(g+1, seq = 1)`.

### 4.1 Visible signed fields

In addition to standard envelope metadata (protocol version, `line_id`,
`root` principal, `op_id`, empty `payload_commit`, action scope):

| Field | Meaning |
| --- | --- |
| `prior_generation` | Must equal the current generation `g` (`>= 1`) |
| `generation` | Must equal `g + 1` |
| `base_seq`, `base_head` | Coordinate and chain head in generation `g` that this generation branches from (`base_seq >= 1`, `base_head` verified on generation `g`'s chain) |
| `new_profile` | Complete immutable profile for generation `g + 1` (may equal generation `g`'s profile or upgrade parameters such as `F`, `validity_max`, or suite version under an explicit policy) |
| `new_relay_origin` | Pinned HTTPS relay origin and server-auth policy for generation `g + 1` (closes the endpoint-migration gap in `LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md` §2.1) |
| `min_time_floor` | Floor carried forward (`>= seq_time(g, base_seq)`); prevents clock rollback below the accepted base or an operator-observed higher floor |
| `reconciled_revoked_operators` | Normalized operator public keys revoked after `base_seq` (or precautionary revocations during the incident) |
| `reconciled_root_replacements` | Any `root_member_replace` transitions from `(base_seq, tail]` (resulting active 2-member `root_keys` and additional replaced keys in `tombstones.root_keys`) so a root key replaced in the discarded tail can never silently regain authority |
| `reconciled_revoked_creds` | `cred_id` entries revoked after `base_seq` (including any credentials enrolled in the discarded tail that are also being tombstoned, carrying their normalized public keys and namespaces so key/namespace reservations survive) |
| `reconciled_removed_actors` | `actor_id` entries removed after `base_seq` |
| `reconciled_tombstones` | Additional `creds`, `actors`, `join_requests`, `operator_keys`, `root_keys`, `calls`, `broadcasts`, `reserved_keys`, `reserved_namespaces`, and per-writer `used_incarnations` learned from external witnesses |
| `reconciled_epoch_floors` | Minimum post-recovery values for `root_rev`, `auth_epoch`, `audience_rev`, `key_epoch`, per-actor `binding_gen`, and per-writer `writer_rev` so no counter regresses below any value observed in the discarded tail |
| `reconciled_evidence_digests` | Optional list of digests of retained signed revocation/enrollment/removal envelopes from `(base_seq, tail]` backing the delta |
| `reconciled_state_digest` | Commitment to the complete reconciled post-recovery state at `(g+1, 1)` (useful even if ordinary frames do not carry per-record commitments) |

### 4.2 Preconditions (checked by relay and every replaying client)

1. `prior_generation == state.Line.Generation` (`>= 1`) and
   `generation == prior_generation + 1`. Because committing immediately
   advances `Line.Generation` to `g + 1`, the same `recovery_generation` can
   never apply twice.
2. Root signature verifies under one of the two active equal root keys
   (`["root", root_key]`, O26 decided 2026-11-25) authorized at `(g, base_seq)`
   and NOT replaced by `reconciled_root_replacements`.
3. `(g, base_seq, base_head)` matches the accepted generation `g` chain at
   `base_seq`.
4. `seq_time(g+1, 1) >= max(seq_time(g, base_seq), min_time_floor)` and within
   `[0, MaxCounter]`.
5. No key in `reconciled_revoked_operators` or `reconciled_tombstones` may
   appear as active in the resulting state; all reconciled keys and namespaces
   are reserved permanently.
6. Every epoch/revision floor is strictly monotone:
   - `root_rev' >= max(base.root_rev, floor.root_rev) + 1`
   - `auth_epoch' >= max(base.auth_epoch, floor.auth_epoch) + 1`
   - `audience_rev' >= max(base.audience_rev, floor.audience_rev) + 1`
   - `key_epoch' >= max(base.key_epoch, floor.key_epoch)` (and `rekey_pending'`
     is **always** `true`!)
   - For every actor and register writer, `binding_gen'` and `writer_rev'`
     never decrease below `max(base, floor)`.
7. The resulting state satisfies all state invariants (`CheckInvariants()`).

### 4.3 Effects on commit at `(g+1, 1)`

1. State is rebuilt from the verified state at `(g, base_seq)` with the
   reconciled revocations, removals, tombstones, key/namespace reservations,
   and counter floors applied atomically.
2. `Line.Generation = g + 1`, `Line.HeadSeq = 1`, `Line.HeadTime = seq_time`,
   and the generation `g + 1` profile and relay origin become active.
3. **`Line.RekeyPending = true` unconditionally.** No payload-bearing record
   and no advisory register update may commit in generation `g + 1` until an
   active operator commits a fresh `key_epoch_activate` naming exactly the
   reconciled entitled readers.
4. Generation `g + 1`'s hot outcome index starts empty.
5. Generation `g`'s committed log index entries at `seq <= base_seq` remain
   retained and queryable (checked against generation `g`'s profile per §5.5).
   Any entry from `(g, seq > base_seq)` is discarded; queries or resubmissions
   for generation `g` operations not found in `(g, 1..base_seq]` return
   `unresolved / abandoned(g)` — **never** `expired`.
6. Any active advisory register writers from generation `g` are invalidated by
   generation mismatch; publishers must commit a fresh `register_activate` in
   generation `g + 1` (with a fresh incarnation) before publishing.

## 5. External security-state preservation (witness discipline)

Because the relay itself is the component that rolled back, security evidence
for `(base_seq, tail]` must survive outside the relay's primary store:

- **Every synced member is already a witness:** every honest client stores and
  verifies all committed control records (including all revocations,
  enrollments, and actor removals) locally.
- **Dedicated security-log export (recommended deployment obligation):**
  operator devices (and optionally an independent append-only witness sink,
  such as an authenticated backup store outside the relay provider) retain
  every membership/key/actor control envelope verified from the relay.
- **Root ceremony requirement:** before signing `recovery_generation`, the
  trusted operator/root tooling gathers the verified control records from
  available witnesses beyond `base_seq`, merges the union of all observed
  revocations, removals, tombstones, key reservations, join requests, and max
  epoch/revision counters, displays the exact base coordinate, discarded-tail
  span, and reconciled revocations to the human operator (§2.2), and signs the
  canonical `recovery_generation` envelope.

## 6. Client, outbox, and projection rules on generation transition

When a client receives `recovery_generation` at `(g+1, 1)` anchored on
`(g, base_seq, base_head)`:

1. **Case A — client checkpoint is `(g, ckSeq)` with `ckSeq <= base_seq`:**
   catch up and verify generation `g` through `(g, base_seq)` first, confirm
   `head(g, base_seq) == base_head`, then verify and apply `(g+1, 1)`.
2. **Case B — client checkpoint is `(g, ckSeq)` with `ckSeq > base_seq`
   (the client witnessed the discarded tail):**
   - **Never silently overwrite the discarded tail.** Archive records
     `(g, base_seq+1..ckSeq]` in a local forensic archive with provenance.
   - **Mandatory tail-reconciliation check (fail-closed):** scan every
     revocation, actor removal, tombstone, reserved public key, consumed
     join-request ID, and granted namespace in the client's verified discarded
     tail `(g, base_seq+1..ckSeq]`. Verify that **every single one** is
     present (revoked/disabled/tombstoned/reserved) in the post-recovery state
     of `(g+1, 1)` and that no counter regressed below the tail's maximum.
     **If any witnessed revocation or tombstone is missing, the client HALTS
     FAIL-CLOSED** and surfaces a recovery-omission violation. (This catches
     accidental incomplete reconciliation and exposes a compromised/misled root
     attempting to resurrect a revoked key.)
   - **Outbox discipline:** mark every unsettled outbox intent from generation
     `g` as `reconciliation_required` (`abandoned(g)`). Never auto-replay any
     generation-`g` intent into generation `g+1`. Committed intents at
     `seq <= base_seq` retain their outcomes; intents that committed in the
     discarded tail are marked rolled-back/abandoned so callers see that their
     prior commits did not survive into `g+1`.
   - **Revoked-key stops persist:** any local key stop (§5.7 rule 8) stands
     across recovery; recovery never lifts a stop.
   - **Projection and delivery:** rebuild projections cleanly from the
     reconciled verified store using `(generation, seq)` tags. Withhold and
     archive any unacknowledged local delivery notices sourced from discarded
     tail records `(g, >base_seq)`.

## 7. Proposed fault scenarios and conformance traces (prose only)

These are proposed traces for review; none is implemented in `ldrcore/` yet
(numbered from `T53` following Draft v8's `T51`–`T52` for equal 1-of-2 roots):

- **T53 (Reconciled rollback recovery):** `credB` is revoked at `(1, 45)`. The
  relay rolls back to `(1, 40)` and an active root commits `recovery_generation`
  at `(2, 1)` carrying `credB`'s revocation and tombstones. Result: `credB`
  remains revoked and tombstoned in generation 2; an intent committed at
  `(1, 39)` returns its original receipt; an intent from `(1, 42)` returns
  `unresolved / abandoned(1)` (never `expired`); `rekey_pending` is true.
- **T54 (Incomplete reconciliation caught by tail witness):** `credA` synced
  through `(1, 45)` (verifying `credB`'s revocation or a `root_member_replace`)
  before rollback to `(1, 40)`. Root signs a `recovery_generation` omitting
  that revocation/replacement. `credA` checks its archived discarded tail
  `(1, 41..45]`, detects the missing security transition, halts fail-closed,
  and signs nothing in generation 2.
- **T55 (Replay and mismatch protection on `recovery_generation`):** submitting
  the same `recovery_generation` again once generation 2 is active is rejected;
  a `recovery_generation` naming a wrong `prior_generation` or wrong
  `base_head` is refused.
- **T56 (Mandatory rekey gate after recovery):** immediately after `(2, 1)`
  commits, a payload-bearing `call_turn` and an advisory register publication
  are both rejected (`rekey_pending` / wrong generation) until an active
  operator commits `key_epoch_activate` naming only the reconciled entitled
  readers (excluding `credB`).
- **T57 (Generation-qualified receipts and view tags across `seq` reset):** a
  broadcast read receipt recorded at `(1, 40)` survives into `(2, 1)` under
  `(1, 40)` without violating invariants; a call update at `(2, 2)` replaces a
  projection view previously tagged `(1, 45)` because `(2, 2) > (1, 45)`.
- **T58 (Unreconcilable loss):** when no external witness can establish whether
  revocations occurred during a rollback gap, operator tooling refuses to
  construct `recovery_generation` and requires explicit migration to a new
  `line_id`.

## 8. Resolved choices (2026-11-25) and remaining open items

1. **New-member bootstrap into generation `g > 1` (decided 2026-11-25):**
   full cross-generation replay `(1, 1..base_seq)` followed by `(2, 1..head)`
   (and so on for later generations). Preserves full replay's exact trust
   boundary all the way from genesis so a root key cannot silently fabricate
   pre-recovery honest-member history.
2. **Equal 1-of-2 roots across recovery (O26, decided 2026-11-25):** if a root
   key was replaced in `(base_seq, tail]` via `root_member_replace`, a
   reconciled `recovery_generation` carries that replacement forward
   (`active_root_keys` + `tombstones.root_keys`) and must be signed by a root
   key still active after reconciliation; if one of the two roots was
   compromised, recovery cannot guarantee winning a race against the
   compromised root (consistent with equal 1-of-2 trade-offs).
3. **Discarded-tail call/broadcast IDs (decided 2026-11-25):**
   `reconciled_tombstones` includes `calls` and `broadcasts` created in
   `(base_seq, tail]` (`Line.Tombstones.Calls` and `Line.Tombstones.Broadcasts`),
   so an archived discarded call or broadcast can never collide with a new ID
   in generation `g+1`.
4. **Deferred relay-resource phase (§12):** as Codex noted in call 0001 turn
   16, a future phase with relay-managed leases cannot resume grants on
   `(g+1, 1)` alone; it must additionally execute protected-host recovery
   generation transitions and fence/work reconciliation before grants resume.
