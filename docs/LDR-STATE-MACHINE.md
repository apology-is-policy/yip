# LDR state machine and mutation/authority matrix — draft v6

2026-11-23 · Fable (claude seat) · Unapproved proposal. Not a specification,
not an implementation plan, and not a deployment decision. Companion to
[LDR-THREAT-MODEL.md](LDR-THREAT-MODEL.md) (Codex, draft v0),
[LDR-SECURITY-REVIEW.md](LDR-SECURITY-REVIEW.md) (Codex) and
[LDR-STATE-MACHINE-REVIEW.md](LDR-STATE-MACHINE-REVIEW.md) (Codex's review of
draft v0 of this document). Code anchors are to the working tree at `baa4494`.

Draft v2 incorporates the ten corrections from that review and the follow-up
corrections to draft v1, including those to the time-anchor rule (§4.2).
Codex's agreement is design-review agreement. It is not operator approval, and
the draft is not implementation-ready: crypto, enrollment and recovery
decisions remain open.

Draft v3 records the operator's scope decisions (§0) and adds the
clarifications that writing concrete vectors exposed: rejection precedence
(§5.8), which records are payload-bearing (§6.3), when `auth_epoch` moves
(§6.1), the `actor_move` precondition (§6.2) and broadcast identifiers (§8).
The vectors are in
[LDR-CONFORMANCE-VECTORS.json](LDR-CONFORMANCE-VECTORS.json): hand-written
expected results, never executed, because no implementation exists.

Draft v4 folds in Codex's static review of v3 and of the vectors
([LDR-CONFORMANCE-REVIEW.md](LDR-CONFORMANCE-REVIEW.md)): refusing input is
separated from rejecting an admitted operation (§2, §5.4); the precedence
ladder distinguishes syntactic from state-dependent `invalid` (§5.8);
register activation is authorized by current binding rather than namespace
(§3); namespace capacity and moves are defined (§6.1). It also adds
`actor_remove` (§6.2).

Draft v5 closes a correctness hole Codex found in v4's retention rule: after
a rejection was compacted, different bytes could reuse its `op_id` under a
fresh anchor and be evaluated as new. Operation identity now includes the
anchor, and a whole anchor's identity space retires together (§5.1, §5.6).
v5 also makes `actor_remove` an explicit line-wide act rather than a
consequence of local uninstall, and states one declaration owner per
namespace (§6.1, §6.2).

This document owns: record types, authority, preconditions, effects, time
rules, the sequencer-visible field allowlist, retry and dedup behaviour, and
materialization. It does not own cryptographic constructions, enrollment
ceremony, key hierarchy, transport authentication or disaster-recovery policy.
Those are Codex's, and this document only states what the state machine needs
from them.

## 0. Status of what is written here

| Item | Status |
| --- | --- |
| Phase 1 scope: conversations and visibility; resources stay host-authoritative; attachments inline and bounded | **Decided by the operator, 2026-11-23:** conversation-first, leases stay local. The attachment size limit is still a discussion value (§10.1). |
| Credential principal with delegated actor namespace (§3) | **Decided by the operator, 2026-11-23:** enroll machine accounts, not individual agents. |
| Line confidentiality policy | **Decided by the operator, 2026-11-23:** 3A — everyone enrolled on the line can read everything on it. 3B is out of scope and not drafted. |
| History for a newly enrolled account | **Decided by the operator, 2026-11-23: none.** A new account reads only what is written after it joins; the operator arranges a briefing for the new agent. The stated reason is practical — history gets long on multi-month projects — not confidentiality. `history_grant` is therefore removed from phase 1 (§6.3). |
| Reference checker | **Operator go-ahead, 2026-11-23,** for a small Go implementation of the rule-checking core only: no crypto, no network, no relay. Later the same day the operator also approved an in-memory model of the relay-side bookkeeping (retries, expiry, clock handling), under the same limits, so that the scenario traces can run. Both live in `ldrcore/`. Results are in §14. Recovery is not modelled. |
| What those decisions are not | They are scope and policy choices. They do not approve a cipher, an enrollment ceremony, a deployment, or implementation. |
| Sequencer deployment (Durable Object, Go relay, other) | Open. This draft must not depend on it. |
| Time anchors (§4.2) | Supported by Codex as the preferred proposal, with corrections folded in. Not operator-approved. |
| Every rule below | Draft. Open choices are collected in §13. |

## 1. Scope

**Phase 1 (this document).** Calls, turns, byes, lifecycle events, notes,
ratifications, disputes, bounded inline attachments, broadcasts, actor control
state, and advisory registers (presence, roadmaps, resource observations).

**Deferred.** Relay-managed resources of any kind, and an external blob store.
Leases, queues, offers, steals and resource configuration remain local to the
host that holds them today, with today's cooperative limitations. §12 carries
the requirements a later phase must meet so they are not lost.

**Why.** Contention for a machine happens on that machine, the current lease
is a local lock that works with no network, and `checkResourceAdmission`
already refuses a disk-gated grant from any host but the resource's own
(resource_config.go:250–272). Moving admission onto a WAN dependency would
regress the case the lease system was built for, and it is what brings in
fencing, runner attestation and restore-versus-fence reconciliation.

In phase 1 no enrollment, grant, key epoch or register activation expires by
time. Each ends only by an explicit committed record. That is a scope choice,
and it is why phase 1 needs no timer-driven transition.

## 2. Model

A **line** has a path-independent `line_id` and a `generation` (recovery
generation). Today's line ID is derived from the local git-common-dir path
(line.go:63–73) and cannot serve.

The **log** is the sequence of committed records in one generation. Each
committed record has a `seq`, a `seq_time`, and a chain commitment (`head`)
covering the previous head, the signed intent bytes and every
sequencer-assigned field. The chain construction is Codex's to specify.

A record has one of five **origins**:

| Origin | Signed by | Phase 1 use |
| --- | --- | --- |
| `actor` | A credential, on behalf of an actor currently bound to it | Conversation and actor-state records |
| `credential` | A credential, with no actor binding required | Actor declaration, register-writer activation |
| `operator` | The operational operator key, action-scoped | Membership, key lifecycle, ratification, arbitration, broadcasts |
| `root` | The root key | Line creation, operator-key authorization, recovery generation |
| `sequencer` | Nobody; a typed internal transition | `time_anchor` only (§4.2) |

The state machine is a pure function with no I/O:

```
apply(state, record, seq_time) -> (state', outcome)
```

Processing is staged, and the stages stay separate in the specification and
in any implementation:

1. Bounded decode. Refuse bad framing, unknown versions, unsupported fields
   and scopes, and transport envelopes over the size bound. Bound every
   allocation before processing. No application compression in the first
   profile. These are admission errors (§5.4): the input is refused and
   nothing is recorded. A decoded, in-bound, attributable intent whose known
   field holds a value outside its allowed set, or whose content exceeds a
   record-specific limit, is different: it is admitted and durably rejected
   `invalid` or `too_large`.
2. Verify the signature over the exact received bytes. Sequencer-origin
   records carry no signature and take a separate typed verification path:
   type, version, line, generation, predecessor, sequence and time are
   committed explicitly, and the record is accepted only over authenticated
   relay transport. A valid hash chain is not by itself authentication of
   origin or freshness. Offline exports need a defined authenticated
   checkpoint policy, which is Codex's to specify.
3. Authorize by origin (§3, §6).
4. Admit or refuse (§5.4).
5. Validate the transition against current state and compute effects (§6–§9).
6. Persist the outcome, new state, log record and time floor in one atomic
   step. Nothing is externally visible before that step is durable.

Stage 5 is `apply`. It receives verified inputs and explicit time. A client
replaying the log derives each committed outcome itself and compares; it does
not accept a record's claimed result. Every predicate in stages 3 and 5 is
over sequencer-visible fields, so replay needs no payload keys (§10).

Conformance vectors are `(state, record, seq_time) -> (state', outcome)`
triples with independently written expected results. A shared implementation
reduces drift between client and sequencer but does not replace the vectors.

## 3. Principals and actors

A **credential** is an enrolled signing and encryption key pair controlled by
one isolation domain, usually one OS account. It is not assumed to be one
physical machine. Three agents on one Mac under one user are one isolation
domain: per-actor key files there would be mutually readable and would
authenticate nothing between them.

Enrollment grants a credential a **namespace**: a visible, opaque, non-secret
`namespace_id`, with limits and capabilities. An **actor** has an opaque
immutable `actor_id` inside one namespace. Display labels are encrypted and
carry no authority; two actors with the same label are a display problem, not
an identity collision.

One actor is bound to exactly one credential at a time, with a `binding_gen`
that increments on every move. One credential may host many actors. An
`actor_id` is never reused after its actor is revoked or removed, and a
`cred_id` is never re-enrolled; both leave durable tombstones, as do consumed
join-request identities. Tombstones must survive recovery. Saying so does not
make it true across a rollback; the mechanism is a recovery requirement
(§6.2).

Authorization by origin:

- `actor`: credential enrolled and not revoked; the actor is live;
  `(actor_id, cred_id, binding_gen)` is the current binding; operation
  permitted to that actor. Liveness is checked on every actor action, register
  activation and register publication.
- `credential`: credential enrolled and not revoked, and then by record type.
  `actor_declare` needs the declaration capability: the new actor lies inside
  the credential's granted namespace and its capacity. No existing actor
  binding is required; this is what authorizes creating an actor.
  `register_activate` and `actor_remove` need current ownership: the actor is
  bound to the signer now. They do not need the actor's namespace, so a
  credential that received an actor by an operator's move can activate that
  actor's registers and cannot declare siblings in its namespace.
- `operator`, `root`: key currently authorized for that role; the action scope
  in the signed intent matches the record type and target.

Revoking a credential disables every actor bound to it. Moving an actor leaves
historical attribution unchanged and invalidates pending intents signed under
the old binding. None of this isolates actors that share a credential, or
their plaintext.

## 4. Time

### 4.1 Sequencer time

`seq_time` is stamped by the sequencer on every committed record. It is
non-decreasing within a generation and covered by the chain.

The sequencer also keeps a persisted **time floor**. Every evaluation — a
commit, a durable rejection, an `expired` decision — takes a candidate time
from the sequencer's clock, never from the last record, and advances the floor
in the same atomic step as its outcome. No later evaluation uses a time below
the floor. If the clock cannot be trusted after a restart or discontinuity,
the sequencer suspends new authoritative evaluations and expiry-based
compaction, keeps unresolved operations unresolved, and still answers
authorized historical receipt lookups. There is no cap on the forward step
between commits; a legitimately elapsed long idle period is normal and simply
advances time. A *detected* forward jump is a discontinuity, not elapsed
time, and does not expire anything. A frozen clock that is detected suspends
evaluation; one that is not detected removes the real-time meaning of expiry.
The clock source, restart validation and discontinuity detection depend on
the deployment (O11), and this document invents no thresholds for them.

`seq_time` is ordering-consistent time under the trusted-sequencer boundary.
It is not proof of real elapsed time: a faulty or malicious sequencer can
freeze or advance it.

Clients never put absolute local timestamps in a signed intent. A client may
use its local monotonic clock as a hint for when to ask for an anchor; that
hint is never signed and never trusted.

### 4.2 Time anchors

**The problem.** Intent validity (§5.3) is measured from the `seq_time` of the
record the signer anchored on. On a quiet line that record may be hours old,
so every newly composed intent would arrive already expired. A signed refresh
operation governed by the same rule would expire too.

**The rule.** An `anchor_request` may be sent over an authenticated session
by an enrolled, unrevoked credential, or by a currently authorized operator or
root principal. Operator and root are included so that a quiet line with no
active credential can still be acted on, for instance to enroll the first
one. The request is not an intent: it has no `op_id`, no outcome, no validity
check, and it grants neither readership nor membership authority.

Inside one serialized step the sequencer re-checks that the requester is
still authorized, that the generation is current, and what the head is, and
advances the time floor. A session authenticated before a revocation is not
enough. It then answers in one of two ways:

- If the current head's `seq_time` is within the freshness window `F` of the
  sequencer's time, it replies with the current head. No record is written.
- Otherwise it commits one `time_anchor` record and replies with it.

Concurrent requests coalesce against the current head. The client catches up
to the returned head and verifies it durably before signing; that delay still
consumes the validity window.

`time_anchor` has origin `sequencer`. It changes no conversation, membership
or key state. It is not effect-free: it advances order and time and uses
storage. Its typed precondition is checkable by every replaying client from
the chain alone: its `seq_time` exceeds its predecessor's by more than `F`.
An anchor that violates this is a sequencer protocol violation.

`F` is protocol profile data known through authenticated configuration, not a
value a relay may choose per request.

Why exempting the request from validity is acceptable: it authorizes nothing,
so a delayed or replayed request can only produce one more anchor. An old
intent stays bound to the `seq_time` of the record it actually named; a later
anchor does not extend it.

What the spacing rule does and does not bound: one anchor per `F` of advancing
sequencer time, under an honest clock. Replay verifies the spacing. It does
not verify real elapsed time, and it does not show that a legitimate request
caused the record. Request authorization, input bounds and rate limits are
still required; coalescing writes does not bound request CPU or bandwidth.

Why not a relay-signed time token: it would add a relay key and a value that
replaying clients cannot check from the chain. An anchor record avoids that
key. It does not remove the need for authenticated relay transport.

Cost: at most one small record and one extra round trip for the first write
after a quiet period longer than `F`. Provisional values, pending workload
evaluation and not measured: `F` 10 seconds, default validity 60 seconds,
maximum validity 10 minutes (O10).

`time_anchor` is the only sequencer-originated record in phase 1. It is
demand-driven; no timer fires. The deferred resource phase needs more (§12).

### 4.3 What is no longer a commit gate

- Call staleness. `callStatusFrom` turns an open call `stale` after 48 hours
  of the local clock, and `doSay` refuses a turn on a stale call (mcp.go:781).
  Proposed: staleness is a display annotation computed by the reader. This is
  an intentional behaviour change.
- Presence and register age.

### 4.4 Bootstrap rules

- `line_init` has no prior checkpoint. It names a genesis constant derived
  from the line identity and root key, is exempt from validity, and can commit
  only into an empty log.
- `line_init` is exempt from validity, not from its context. It names
  generation 1 and anchors on genesis. One that names a later generation, or a
  sequence number an empty log has never had, comes from a client that is
  ahead of this relay and is answered `history_unavailable`, as in the
  ordinary case; one that names a different genesis is `unknown_anchor`.
- An input the transition function refuses on an empty log, for instance a
  malformed or wrongly signed `line_init`, is refused as invalid bootstrap
  input with nothing recorded. It is never reported as "a line exists",
  because a refusal is not evidence of one. That answer is given only when a
  line does exist, and only after the retry and mismatch lookup.
- Conversely, the first record of an empty log can only be `line_init`. An
  empty log has no head to anchor on and no predecessor, so no other intent
  can have been admitted and no time anchor can be legal. A replaying client
  that finds anything else there treats it as a sequencer violation. The
  transition function enforces this itself and does not rely on admission.
- `recovery_generation` is the first record of a new generation. It names the
  prior generation and the accepted base `seq` and `head`, is exempt from
  validity, and can commit only while the named prior generation is current,
  so it cannot apply twice.
- Every other root record (`operator_key_authorize`, `operator_key_revoke`)
  uses the ordinary envelope and ordinary validity.
- The first ordinary intent in a generation anchors on that generation's
  first record or on a later anchor, which operator and root may request.

## 5. Intents, outcomes, retries

### 5.1 Signed fields

Every `actor`, `credential` and `operator` intent signs, at minimum:

| Field | Purpose |
| --- | --- |
| `version` | Protocol version; unknown is rejected, never downgraded |
| `line_id`, `generation` | No cross-line or cross-generation replay |
| `cred_id` | Signer key identity |
| `actor_id`, `binding_gen` | Actor on whose behalf the credential signs (`actor` origin only) |
| `op_id` | Operation nonce. The operation identity is `(line_id, generation, cred_id, seen_seq, op_id)`: an `op_id` is unique only within its anchor (§5.6) |
| `op_type`, `target` | What is being done to which object |
| `expect` | Expected object versions, per record type |
| `auth_epoch` | Membership epoch the signer acted under. **Checked: must equal the current value** |
| `key_scope`, `key_epoch` | Encryption scope of the payload. **Checked for payload-bearing records (§6.3)** |
| `seen_seq`, `seen_head` | The signer's verified durable checkpoint |
| `validity` | Duration, bounded by a protocol maximum |
| `payload_commit` | Digest and length of the encrypted payload |
| visible fields | The per-type allowlist in §10 |

A client signs only from a verified, durably stored checkpoint, and that
checkpoint never regresses. All sessions that share a credential share one
checkpoint and one outbox under a local lock.

### 5.2 What the checkpoint binding does and does not give

- The sequencer admits an intent only if `seen_head` is on the accepted
  history of its generation.
- A reader that is shown an intent whose `seen_head` is not on the reader's
  own chain has evidence of divergent histories.
- This is **not** full fork consistency. An intent anchored at or before a
  divergence point is valid on both branches, and a client may not yet know of
  a committed record that was withheld from it. No claim beyond the two
  bullets above is made.
- A signed checkpoint asserts which history was available to the signer. It
  does not show that an agent read or understood any of it, and it is not a
  measurement of any remote repository.

### 5.3 Validity

An intent is admissible only while the sequencer's time is at most
`seq_time(seen_seq) + validity`.

- The effective deadline is `seq_time(seen_seq)` plus the smaller of the
  claimed validity and the generation's maximum. The boundary is inclusive: an
  intent evaluated exactly at its deadline is admissible, and one unit later
  it is `expired`. The arithmetic is overflow-checked. An intent that is
  admitted but claims more than the maximum is `invalid`.
- Under an honest sequencer this bounds how late a withheld or orphaned intent
  can commit. Under a malicious one it bounds nothing.
- Intent validity is separate from the lifetime of anything the intent
  creates.
- A client whose head may be old asks for an anchor (§4.2) before signing.

### 5.4 Admission and outcomes

The sequencer distinguishes four kinds of answer. They must not be confused,
because they promise different things.

**Admission errors** are transport-level. No index entry is written and
nothing is promised about the operation: overload, rate limit, exhausted
rejection quota, clock uncertainty, network failure, bad framing, unknown
version or unsupported field, oversized transport envelope, bad signature,
unknown credential. The client keeps the intent unresolved and retries the same
bytes. A rate-limit response never implies non-commit; admission and outcome
decisions for one operation identity are serialized.

**Definitive refusals without an index entry.** The intent did not commit and
never can in this generation:

- `expired` — past validity by the time floor, and not found committed (§5.5).
- `unknown_anchor` — `seen_seq` is at or below the sequencer's head and
  `seen_head` is not the head recorded at that sequence. That sequence is
  occupied in this generation and will not change.

**Refusals that resolve nothing.** The intent will not be evaluated, but
whether it committed earlier is not established. It stays unresolved and
needs reconciliation. None of these is permission to repeat the action:

- `history_unavailable` — `seen_seq` is ahead of the sequencer's head. The
  sequencer cannot promise that history will never become known. The client
  suspects rollback and fails closed.
- `revoked` — signed by a credential that is now revoked. It may have
  committed before the revocation, and the revoked key may not ask (§5.5).
- `abandoned(generation)` — signed for an earlier generation and not found in
  the history that the current generation retained. It has no effect in the
  current generation. It may have committed in a discarded tail.

**Operation outcomes** are durable, one per admitted intent. An intent is
admitted when it decodes within bounds, its signature verifies, its credential
is enrolled and unrevoked, its generation is current, its anchor is on the
accepted history, and it is within validity.

- `committed(seq)` — the receipt is reconstructible from the log.
- `noop(ref_seq)` — valid, nothing to change; names the record that already
  established the state, when the state records which one it was. A broadcast
  receipt does; a standing bye does not, so that no-op carries no reference.
  Durable outcome, no log record.
- `rejected(reason)` — `conflict`, `unauthorized`, `not_floor`, `not_open`,
  `rekey_pending`, `unknown_target`, `invalid`, `too_large`, `exhausted`.

Durable rejections and no-ops are **trusted relay decisions**. They are
authenticated to the client under the relay boundary and retained with digest,
reason and context, but they are not log records and cannot be re-derived by
replaying the chain. No audit stream for them is proposed in phase 1. They are
retained at least until the intent's own validity can no longer admit it, and
each credential has a bounded quota of such entries. Dedup lookup comes before
the quota check, so an operation that already has an outcome still gets it
when the quota is exhausted.

After that retention a rejected operation answers `expired`. The two answers
are not the same outcome: the original reason is gone. What they share is the
fact that matters, that the operation did not commit and never can. A client
that stored the original rejection keeps it. User-facing results must say
when an answer is the original rejection of the same bytes, because
resubmitting identical bytes never re-evaluates against current state.

### 5.5 Retry lookup, in order

For every query or resubmission, first: bounded decode, signature
verification, and authorization of the requester to learn this outcome. Only
then, with every lookup keyed by the full operation identity of §5.1:

1. Hot index hit, same digest → the original outcome.
2. Hot index hit, different digest → `duplicate_mismatch`; the original stands.
3. Log index hit for the same namespace, including retained history of an
   earlier generation: same digest → the original receipt; different digest →
   `duplicate_mismatch`. This step runs before any new evaluation unless
   compaction rules prove that a hot miss means the operation never committed.
4. `generation` not current → `abandoned(generation)`.
5. Resolve the referenced anchor. `seen_seq` ahead of the head →
   `history_unavailable`. `seen_head` differing at an occupied sequence →
   `unknown_anchor`. Expiry cannot be computed before this step, because an
   unknown or ahead-of-head reference has no accepted `seq_time`.
6. Past validity, measured from that anchor's accepted `seq_time` → `expired`.
7. Otherwise evaluate as new.

Current `auth_epoch`, binding, floor and every other transition precondition
apply only at step 7. A previously committed intent keeps its original
outcome for an authorized requester even after those conditions have changed.

A query is a separate entry point from a submission. It carries an operation
identity and a digest, not the bytes, and it never evaluates anything,
reserves an outcome or uses rejection quota. If it finds a recorded outcome it
returns it. If it finds none and the anchor has not retired, the answer is
`outcome_unknown`: the operation may still be admitted, and the answer is not
a cancellation and not evidence of non-commit. Once the anchor has retired, a
miss in a complete index establishes that the operation never committed, and
the answer is `expired`. Where history is incomplete or was discarded, the
answer stays `abandoned`.

A query respects clock trust the way a submission does. A recorded outcome is
returned whatever the clock says. Anything that depends on time, `expired`
and `outcome_unknown` alike, is not given while the clock is untrusted. A
query never moves the time floor, and it never calls an anchor retired on the
strength of a clock reading it does not persist: it judges retirement by the
floor already saved. Whether evidence of an earlier retirement could be used
while the clock is untrusted would need its own explicit contract; this draft
takes the conservative rule.

A retry never applies twice. A query authenticated only by a revoked key is
refused, including for that key's earlier receipts. Refusal says nothing
about whether the operation committed. An active, separately authorized
principal may reconcile that history by signing a query that names the
original operation and digest; it does not replace the historical intent's
signer. Revocation does not erase receipts a client already cached.

### 5.6 Retention

The hole this rule must close: if a rejected operation's entry were discarded
when *that intent's* validity passed, different bytes could later reuse the
same `op_id` with a fresh anchor, find no entry, and be evaluated as new. The
expiry of one intent does not expire an `op_id`.

So the unit of retirement is the anchor, not the intent. Operation identity
includes `seen_seq` (§5.1), and no intent anchored at sequence `S` can be
admitted once the time floor passes `seq_time(S)` plus the protocol's
*maximum* validity, whatever its bytes and whatever validity it claims. At
that point the whole identity space of anchor `S` is retired, and only then
may its hot entries, rejections included, be discarded. Before retirement,
different bytes under the same identity are `duplicate_mismatch`. After it,
an identity anchored at `S` that never committed is `expired`, while one that
did commit still returns its original receipt, because lookup comes before
expiry (§5.5). An intent with the same `op_id` and a later anchor is a
different operation by definition, so nothing is contradicted.

Two constraints make this hold:

- The maximum validity is immutable for an anchor. It is fixed for the whole
  generation, so a later profile or protocol version cannot lengthen it and
  revive an identity space that was already compacted. Changing it takes a
  new generation.
- Every new evaluation enforces that maximum (§5.3). Retirement is exact: the
  space is retired when the time floor is strictly greater than `seq_time(S)`
  plus the maximum.

Consequences:

- Compaction never runs on an intent's own deadline.
- Choosing a new anchor deliberately creates a new operation. A client never
  does it to refresh an unresolved outbox intent (§5.7).
- Any derivation keyed by operation identity must bind the full context:
  line, generation, signer, anchor and operation identity, together with the
  relevant scope and epoch. This is a requirement on whatever construction
  Codex specifies. It is not a security argument, and no payload construction
  has been selected. Different plaintext under the *same* identity remains a
  hazard that arises before sending and that server dedup cannot cure.

Committed operations stay findable through the log index, which is retained
storage with a real cost and not a bounded cache. Compaction is suspended
while sequencer time is uncertain (§4.1). A receipt is not promised to remain
retrievable after its log tail has been deliberately discarded by recovery.

### 5.7 Client outbox

This is client discipline. It does not make human actions exactly-once: two
independently worded requests are two operations, and nothing here can
recognize them as one intention.

1. Serialize and durably store the intent before the first send, together
   with the application action it came from. Every retry sends those bytes.
2. At most one unresolved intent per `(acting identity, target)`, where the
   acting identity is the actor for an actor-origin record and the credential
   or operator key otherwise, and the target of a create is its creation
   slot. Operator and control actions are included. Two actors on one
   credential have separate slots, since both can be participants of the same
   call. This is client policy and not the wire dedup identity.
3. On restart, or after a stale-checkpoint refusal, resolve every stored
   intent by query before constructing anything new. A timeout or a
   cancellation is not evidence of non-commit.
4. Only a definitive refusal or a durable rejection closes the intent. The
   caller may then issue a deliberately new or corrected intent with a new
   `op_id`. Nothing is reissued automatically.
5. `history_unavailable`, `revoked` and `abandoned(generation)` do not close
   it. The action is marked reconciliation-required and shown to the caller.
   It is never resubmitted, and the refusal is never treated as grounds to
   repeat the action.
6. A completed result is stored and surfaced to the action that caused it.

### 5.8 Rejection precedence

When more than one precondition fails, the durable outcome must be the same
on every implementation. This ladder applies only to a new, admitted
operation. Admission errors and the outcomes of earlier operations found by
dedup lookup are outside it. The first failing check decides:

1. `invalid`, syntactic — a visible field is malformed for the record type
   regardless of state: a value outside its allowed set, an empty required
   list, a self-reference, line ciphertext on a type declared
   ciphertext-free.
2. `too_large` — a record-specific content limit. It applies to every
   payload-bearing record, not only attachments. A size stated on a
   ciphertext-free record, a size class that does not exist, or an attachment
   that states none, is syntactic `invalid` at step 1. This is distinct from
   the transport envelope bound, which is an admission matter.
3. `unauthorized` by origin — binding, declaration capability or capacity,
   current ownership, or role does not permit this record.
4. `conflict` — the intent's `auth_epoch` is not current.
5. `unknown_target` — a referenced object does not exist or is not live.
6. `unauthorized` on the target — the signer is not a participant or
   recipient, or is not the party a rule reserves the action for.
7. `rekey_pending`, then `conflict` on `key_epoch`, for payload-bearing
   records.
8. `conflict` — an identifier collision on create, or any `expect` value that
   is not current.
9. `invalid`, state-dependent — well-formed but wrong against current state:
   a manifest that is not exactly the entitled readers.
10. `not_open` — the target is not in a state that accepts the action: a call
    whose status is not open, or a resolved dispute.
11. `not_floor`.
12. `exhausted` — a counter the record must advance is at its maximum (§5.9).
    It is last because it applies only to a record that would otherwise
    commit.

Stale expectations are reported before state-dependent refusals, because a
refusal evaluated against a state the signer has not seen tells the signer
less than "re-read". Identifier collisions are `conflict`, whether the
existing identifier is live or tombstoned, and they are checked after origin
authorization, so a forbidden create cannot learn or gain anything from a
collision answer.

### 5.9 Counter domains and exhaustion

Every counter, revision, epoch, sequence number and time in the state is an
integer in `[0, 2^53 - 1]`. The upper bound is the safe-integer limit for a
consumer that reads numbers as 64-bit binary floating point, which is the
common worst case. It is an interoperability bound for such consumers, not a
guarantee about every JSON implementation. The eventual wire decoder must
still reject a fraction or an out-of-domain value before any lossy
conversion; that belongs to the envelope design, which is Codex's.

Nothing wraps:

- A record that would have to advance any counter past the maximum is
  `rejected(exhausted)`. Its whole effect is discarded, so a record that
  advances two counters and can only advance one changes nothing.
- A rejection or a no-op at an exhausted counter is reported exactly as it
  would be anywhere else, because neither advances anything.
- When `head_seq` is at the maximum, no record can commit in that generation.
  What continues the line after that is a recovery question, and whether
  sequence numbers restart in a new generation is not yet decided (O23).
- A sequencer-assigned time outside the domain, or a time anchor placed after
  the last sequence number, is a sequencer violation on replay.
- A state holding a value outside the domain is not a coherent state.

These bounds are far beyond any workload: at one record a millisecond a line
would take about 285,000 years to exhaust `head_seq`. The rule exists so that
the behaviour at the edge is defined and identical everywhere, not because
the edge is expected.

## 6. Membership, keys and actor control

Field contents, proofs of possession, wrapping and ceremony are Codex's. The
state machine needs the following transitions.

### 6.1 State

```
Line {
  generation, root_rev, auth_epoch, audience_rev
  operators, credentials (with namespace grant, limits, capabilities)
  tombstones: cred_ids, actor_ids, join-request ids
  key_epoch, rekey_pending, readers(key_epoch)
  entitled_readers: credentials holding an explicit reader capability
  actors: actor_id -> { namespace_id, cred_id, binding_gen, addr_rev, default_addressed, live }
  register writers: (actor_id, register) -> { writer_rev, incarnation, binding_gen at activation, incarnations used }
}
```

`auth_epoch` increments on every record that changes operators or
credentials, or moves an existing binding. Declaring or removing an actor
does not increment it: a new worktree binding should not conflict everyone
else's writes. An intent already in flight that names a not-yet-declared
actor, such as a `call_open` to it, is judged at its own evaluation and keeps
whatever outcome it got; it is never retried successfully on its own.
`audience_rev` increments on every record that changes the set of live actors
or their default addressability.

**Namespace capacity.** In phase 1 a namespace has exactly one declaration
owner: it is granted to one credential at enrollment and a `namespace_id` is
never granted twice, so its limit cannot be stated inconsistently. The limit
is the maximum number of live actors in that namespace, whichever credential
currently holds them. An actor moved out still counts in its own namespace.
An actor moved in keeps its namespace and does not count against the
destination's. Competing declarations for the last slot are decided by commit
order. This is a policy on identities per namespace. It is not a limit on a
credential's total workload. A limit of zero means the credential cannot declare
actors. With reader capability that is the natural shape for an operator's own
device. It is a zero *declaration* capacity, not a permanent ban on holding
actors: an operator's `actor_move` can still assign an existing actor to such
a credential. Reader capability and authority to sign as operator remain
separate grants. A negative limit is malformed.

`entitled_readers` is the set a new epoch must be distributed to: enrolled,
unrevoked credentials that were granted the reader capability. Reader
capability is granted explicitly at enrollment and is separate from the
namespace grant. Authority to sign as operator does not make an operator's
encryption key a reader; that key is enrolled as a reader like any other.

### 6.2 Records

| Record | Origin | Sequencer-checked preconditions | Effects |
| --- | --- | --- | --- |
| `line_init` | root | Log empty (§4.4) | Line state created: `generation = 1`, `root_rev = 1`, `auth_epoch`, `audience_rev` and `key_epoch` at 0, no operators or credentials, `rekey_pending` set until the first activation |
| `operator_key_authorize` / `operator_key_revoke` | root | `expect.root_rev`; key not already authorized, or key currently authorized | Operator set changes; `root_rev++`; `auth_epoch++` |
| `recovery_generation` | root | §4.4; carries the tombstone registry and the reconciled membership and key state | New generation; hot index empty; §5.7 rule 5 applies |
| `credential_enroll` | operator | Join-request ID unused; neither key enrolled or tombstoned; granted `namespace_id` never granted before; grant well-formed | Credential added; `auth_epoch++`; `rekey_pending` set |
| `credential_revoke` | operator | Credential enrolled | Credential tombstoned; its actors disabled; `auth_epoch++`; `audience_rev++`; `rekey_pending` set |
| `key_epoch_activate` | operator | `expect.key_epoch`; manifest names exactly `entitled_readers` as of commit, with one wrap commitment each | `key_epoch++`; `readers` set; `rekey_pending` cleared |
| `actor_declare` | credential | `namespace_id` in the signer's grant; namespace has capacity; `actor_id` never used | Actor created live at `binding_gen = 1`, `addr_rev = 1`, `default_addressed = true`; `audience_rev++` |
| `actor_move` | operator | Actor live; `expect.binding_gen`; target credential enrolled and unrevoked, and not the current holder (state-dependent `invalid`) | `binding_gen++`; `auth_epoch++`; `audience_rev++`. The actor keeps its `namespace_id`; the target credential gains control of that actor and no right to declare in its namespace. Register writer state is kept, not reset. A removed actor cannot be moved back to life |
| `actor_remove` | credential | Actor live and bound to the signer; `expect.binding_gen` | Terminal: actor no longer live; `actor_id` tombstoned; `audience_rev++`. Its calls and history stay |
| `actor_addressing` | actor | `expect.addr_rev` | `default_addressed` set; `addr_rev++`; `audience_rev++` |
| `register_activate` | credential | Actor bound to the signer; register type allowed; `expect.writer_rev`; incarnation never used for this writer by any owner | `writer_rev++`; new incarnation current |

`actor_addressing` replaces `retire` (lifecycle.go:180), which today changes
default broadcast recipients, delivery and listings and so cannot be an
advisory register. It governs the *default* recipient snapshot only; an
explicitly addressed message to that actor is still valid. A host's local
delivery pause is local state and changes nothing on the line. Today
`BroadcastRecipients` also drops locally paused endpoints
(broadcasts.go:45–49); that dependency is removed.

Installing, binding and seating stay local operations (line.go:483,
bind.go:584, seats) that additionally publish `actor_declare` when the line is
attached.

Uninstalling (line.go:619) is a local detach and publishes nothing by
default. Deleting a checkout or a runtime installation does not mean the line
identity should end: other local sessions or bindings may still use it.
Leaving default audiences is `actor_addressing`. `actor_remove` is a separate,
explicit, line-wide and terminal act that a person or agent asks for by name.

A call whose other participant has been removed, or disabled by a credential
revocation, stays readable. The remaining participant can still add notes,
change its lifecycle and propose a bye, and readers see the peer marked as
removed. Ordinary floor rules still apply: if the remaining participant holds
the floor it can add a turn; if the removed actor holds it, the floor does
not transfer, and the remaining participant needs an explicit, attributed
barge or a lifecycle action. Nothing is written on the removed actor's behalf
and no history is rewritten.

After a move the previous owner's register updates are rejected by the
binding check. The new owner activates with the current `writer_rev` and a
fresh incarnation before publishing; an earlier activation is never reused
and no counter is reset.

**Recovery requirement, owned by Codex.** A log restored to an older base
does not contain later revocations or tombstones. Carrying them forward needs
security state retained independently of the rolled-back log, authenticated,
or an explicit reconciliation gate before the new generation accepts
anything. If newer security state cannot be established, recovery fails
closed or becomes an explicitly approved migration to a new line.

### 6.3 Key lifecycle, drafted for 3A only

- A record is payload-bearing if it carries any line-scope ciphertext,
  including an optional encrypted reason or label on a control record. It
  commits only if `key_scope` is the line scope, `key_epoch` is the current
  epoch, and `rekey_pending` is clear. Otherwise it is
  `rejected(rekey_pending)` or `rejected(conflict)`.
- Concretely (new in v3): `call_open`, `call_turn`, `call_status`,
  `call_note`, `call_ratify`, `call_attach`, every `dispute_*` record,
  `broadcast_create` and `broadcast_reply` are payload-bearing.
  `actor_declare` is payload-bearing only when it carries a label. `call_bye`,
  `broadcast_read`, `actor_addressing`, `actor_move`, `register_activate` and
  all membership and key records are not. So during a rekey an agent can
  still propose a bye or leave the default audience, and cannot resolve a call
  with a reason.
- The label on `actor_declare` is optional. The reason on `call_status` is
  required, so that record is always payload-bearing. Line ciphertext on a
  type declared ciphertext-free is rejected as syntactic `invalid`; it does
  not slip past the gate. A ciphertext-free record still signs its payload
  commitment, over an empty payload.
- Membership and key-distribution records carry no line-scope ciphertext, only
  visible fields and per-recipient wraps. They are exempt from that gate and
  commit while `rekey_pending` is set; otherwise the line could never leave
  it.
- The same epoch and rekey checks apply to advisory register bodies (§9).
  Otherwise a register could keep publishing new confidential content under a
  removed reader's key.
- Enrollment and revocation both set `rekey_pending`. A newly enrolled
  credential therefore never receives the epoch that carried earlier traffic,
  and a revoked one never receives the epoch that carries later traffic. An
  operator client normally submits the membership change and
  `key_epoch_activate` together; a combined record is a possible optimization.
- Phase 1 has no record that grants an earlier epoch to a credential
  (operator decision, 2026-11-23). A new agent is briefed instead. Drafts v1
  to v5 had a `history_grant` record; it is removed, which also removes the
  need to wrap old epoch keys to new members. Namespace enrollment and reader
  capability remain distinct grants.
- The sequencer checks manifest completeness over visible fields. It cannot
  check that a wrap decrypts, that a key is correct, or that an epoch key is
  fresh. Clients verify their own wrap. Garbage wraps and undecryptable bodies
  from an authorized writer are denial of service and must not stop replay.
- Confidentiality after a rotation depends on the generating client creating
  a fresh epoch key and verifying the distribution context. A reused epoch
  key, or a wrap to a recipient the manifest does not declare, would preserve
  or expose access, and the relay cannot detect either.
- Removing a reader does not recall plaintext or keys already learned.

**3B is not covered.** Per-call scopes need scope state, reader grants and
rotations per call, and grant-authority rules. None are drafted. This document
does not claim compatibility with 3B.

## 7. Calls

### 7.1 State

```
Call {
  call_id         opaque, client-chosen, reserved at create
  call_no         display ordinal, derived at commit, local to a generation
  from, to        actor_id
  turn_count      >= 1
  last_turn_from  actor_id
  lifecycle       open | resolved | deferred | archived
  lifecycle_rev   incremented by every call_status record
  byes            subset of {from, to}
  links           set of call_id
  note_count, attach_count, dispute_count
  disputes        dispute_no -> { opened_by, rev, measure_rev[actor], resolved }
}
```

Derived, never stored:

- `floor` = the participant who did not write the last turn.
- `status` = `lifecycle` if it is not `open`; else `resolved` if `byes` holds
  both participants; else `open`.

### 7.2 Records

| Record | Origin | Sequencer-checked preconditions | Effects |
| --- | --- | --- | --- |
| `call_open` | actor (`from`) | `call_id` unused; `to` is a live actor other than `from` | Call created with turn 1; `turn_count = 1`; `last_turn_from = from`; `lifecycle_rev = 0` |
| `call_turn` | actor (participant) | `status == open`; `expect.turn_count`; signer holds the floor unless `barge` | `turn_count++`; `last_turn_from`; `byes` emptied |
| `call_bye` | actor (participant) | `status == open`; `expect.turn_count`; `expect.lifecycle_rev` | Signer added to `byes`. If the signer's bye already stands and every other precondition passes: `noop`. Once both byes have closed the call, a new bye is `not_open` like any other action |
| `call_status` | actor (participant) | `expect.lifecycle_rev`; `expect.turn_count`; state in the allowed set; for `linked`, the related call exists, differs, and the signer participates in it | `lifecycle_rev++`; `linked` adds a link and leaves `lifecycle` alone; `open` sets `lifecycle = open` and empties `byes`; others set `lifecycle` |
| `call_note` | actor (participant) | Call exists | `note_count++`. Floor, byes and lifecycle untouched |
| `call_ratify` | operator | Call exists | `note_count++`; marked operator-verified |
| `call_attach` | actor (participant) | Call exists; sizes within the inline profile (§10.1) | `attach_count++` |
| `dispute_open` | actor (participant) | Call exists | `dispute_count++`; dispute at `rev = 1`, every `measure_rev = 0` |
| `dispute_measure` | actor (participant) | Dispute exists, unresolved; `expect.measure_rev` for the signer's own slot | Signer's measurement superseded; own `measure_rev++`; dispute `rev++` |
| `dispute_resolve` | actor (participant) | Dispute exists, unresolved; `expect.rev`; kind `measured`, or `withdrawn` only if the signer is `opened_by` | `rev++`; `resolved` |
| `dispute_arbitrate` | operator | Dispute exists; `expect.rev` | `rev++`; `resolved`, kind `human`; may supersede an earlier resolution |

An existing `call_id` under a different create intent is `conflict`. A call is
never silently joined or reused. `call_no` is a display ordinal and never a
wire identity.

Closing or resolving checks for unseen turns and unseen lifecycle changes
only. It does not check for unseen notes, attachments or disputes. That
follows the existing rule that a note cannot create an obligation
(notes.go:16–20); a broader call revision would be needed to change it.

Because a measurement bumps the dispute revision, a resolution cannot commit
over a measurement its author has not seen. Two participants measuring at once
do not conflict with each other, since each checks only its own slot.

### 7.3 Differences from current behaviour, each deliberate

1. **One transaction.** `doSay` checks status and floor, clears byes, then
   appends, retrying turn numbers up to sixteen times without re-checking the
   floor (mcp.go:781–797, state.go:519–534). A failed append has already
   cleared byes. Here the checks and effects are atomic.
2. **`call_open` carries turn 1.** `doCall` creates the call and the first
   turn as two writes (mcp.go:754–758), so a call can exist with no turn.
3. **Barge still names what it has seen.** A barge skips the floor check, not
   `expect.turn_count`. If a turn landed first the barger gets `conflict`,
   re-reads, and may find the floor is now theirs.
4. **A bye names what it has seen.** `SetBye` is unconditional today, so a bye
   can land after a turn its author never read.
5. **A status change names the turn count as well as the lifecycle revision.**
6. **Staleness does not gate a turn** (§4.3).
7. **Measurements and resolutions become superseding records.**
   `SetMeasurement` and `SetResolution` replace files in place (notes.go:289,
   317). The projection shows the latest; the log keeps each one.
8. **A resolved dispute takes no further measurements or participant
   resolutions.** Today both files can be rewritten at any time. Only operator
   arbitration can supersede. Resolution kind `withdrawn` is declared in
   notes.go:195 but has no writer today; here only the participant who opened
   the dispute may use it, so one side cannot appear to withdraw the other's
   claim. The peer can record disagreement in a note or seek arbitration.
   `measured` does not require both slots to be filled and remains the
   signer's attributed assertion. It never means a test ran or passed, or that
   both sides agreed.
9. **Operator records are verified, not labelled.** `ratify` takes the human's
   name from `--by` or `$USER` (main.go:587–598), and `settled`, arbitration
   and `broadcast` are reachable by any agent with a shell. Any row with
   origin `operator` is a new guarantee, and it holds only if the operator key
   cannot be used by a process running as the operator's OS user without an
   authorized, action-scoped approval in which the operator sees the actual
   action and payload meaning.
10. **Turn headers change meaning.** `renderTurn` stamps both worktrees' tips
    by running git locally (state.go:489–506). Remotely, the writer's tip is
    an attributed claim inside the payload, `peer-tip` is dropped, and the
    header gains `seen_seq`. The `at` line is `seq_time`.

`dispute` status (agreed, differ, escalate) is computed by readers from
measurement plaintext (notes.go:336–378). It is a reader's conclusion and
never a commit predicate or sequencer-verified fact.

## 8. Broadcasts

| Record | Origin | Sequencer-checked preconditions | Effects |
| --- | --- | --- | --- |
| `broadcast_create` | operator | Non-empty recipient list within bounds; every recipient a live bound actor; kind in the allowed set; if the intent says its list is the default audience, `expect.audience_rev` | Broadcast created with an immutable recipient snapshot |
| `broadcast_read` | actor (recipient) | Broadcast exists; signer in snapshot | First: receipt recorded at this `seq`. Later, by a different operation: `noop(ref_seq)` |
| `broadcast_reply` | actor (recipient) | Broadcast exists; signer in snapshot | Reply appended; receipt recorded if absent |

`broadcast_id` is client-chosen, opaque and reserved atomically at create,
like `call_id`, with line and generation explicit in its identity. An
existing one under a different create intent is `conflict`; it is never
reused.

The signed recipient list is authoritative and immutable. It stays verbatim
in the log record; state holds it as a set, which is a derived index and not a
rewrite of what was signed. A list composed from the default audience
conflicts if the audience changed before commit, and at the revision it names
it must be exactly the default audience as a set: the live actors that have
not left it. A subset or superset marked as default is state-dependent
`invalid`, reported after the revision conflict. A custom list uses the
explicit mode. An
explicitly chosen list does not conflict on unrelated addressability changes;
it only requires each recipient to be live and bound at commit.

A retry of the same `broadcast_read` operation returns its original outcome by
ordinary dedup. A *different* valid read operation by the same recipient, for
instance from a second session, gets `noop(ref_seq)`, which names the first
read without pretending to be its receipt. No-ops do not enter the log, so
replay is unaffected.

`ReadBroadcast` overwrites `ReadAt` on every read (broadcasts.go:167). Here
the first read commits and later reads are local. A broadcast viewed from
cache while offline shows "receipt pending" until `broadcast_read` commits; no
other host is told it was read before then.

## 9. Advisory registers

Presence (`tip`, `branch`, `busy`, `last_tool`, beat), roadmaps and resource
observations are signed latest-value registers outside the log. `Beat` fires
on every tool call and would otherwise dominate it.

- A writer is activated by a committed `register_activate` record (§6.2). One
  shared local publisher per actor and register namespace activates on start
  when it cannot trust its stored counter; activation is not per tool call or
  per session.
- A register value signs namespace, `line_id`, `generation`, `actor_id`,
  `cred_id`, `binding_gen`, `writer_rev`, `key_epoch` and counter. Bodies are
  encrypted under the line's scope. Sizes and rates are bounded.
- A register body under a superseded `key_epoch`, or submitted while
  `rekey_pending` is set, is rejected (§6.3).
- Order is by `writer_rev`, then counter. A value from an older activation
  never regains precedence; a new activation makes older cached values
  historical.
- An activation belongs to the binding generation that made it. After a move
  the actor has no usable activation until the new owner activates, so an
  update from either the old owner or the not-yet-activated new owner is
  rejected.
- Registers are never an input to membership, recipient eligibility,
  permissions, floors, or any commit predicate.
- A revoked credential's delayed update is rejected. Cached values remain
  historical observations and are shown with their age. A subscription is not
  proof of liveness or permission.
- A resource observation is namespaced by credential and resource, and is
  never a grant, release, renewal or recovery instruction. Remote tools refuse
  to mutate a resource they only observe, including through mirrored files.

## 10. Sequencer-visible fields

Everything not listed for a record type is ciphertext. Unknown fields are
rejected.

| Record family | Visible |
| --- | --- |
| All | The signed fields of §5.1; `seq`, `seq_time`, `head` |
| Membership and keys | Public keys, credential IDs, namespace IDs, grants, limits, epochs, manifest credential IDs and wrap commitments |
| `actor_declare`, `actor_move`, `actor_addressing`, `register_activate` | `actor_id`, `namespace_id`, binding, `default_addressed`, revisions |
| `call_open` | `call_id`, `from`, `to` |
| `call_turn` | `call_id`, `expect.turn_count`, `barge` |
| `call_bye`, `call_status` | `call_id`, expected counts, new state, related `call_id` |
| `call_note`, `call_ratify`, `call_attach` | `call_id` |
| `dispute_*` | `call_id`, `dispute_no`, expected revisions, resolution kind |
| `broadcast_*` | `broadcast_id`, recipient `actor_id`s, kind, default-audience flag |
| `time_anchor` | Nothing beyond `seq`, `seq_time`, `head` |

Encrypted: subjects, turn/note/reply bodies, lifecycle reasons, dispute claims
and measurements, resolution detail, attachment names and content, actor
display labels, the writer's tip claim, and all register bodies.

Call IDs today embed the slugified subject (state.go:408). The LDR `call_id`
is opaque and random; the projection directory is named from `call_no` plus a
slug the client derives locally after decrypting the subject.

Observable regardless: ciphertext sizes, timing, who talks to whom, access
patterns, and transport and account metadata. Secrets stay out of URLs, logs,
error strings and unencrypted registers.

### 10.1 Size profile for discussion

Conservative product limits proposed by Codex, not measured platform maxima,
to be finalized after crypto framing and workload review: 64 KiB plaintext per
turn, note, reply or broadcast; 256 KiB attachment content; 8 KiB auxiliary
encrypted metadata; 384 KiB total ciphertext; 512 KiB for the entire encoded
record, which also bounds recipient arrays, signatures and manifests. Above a
limit the client refuses with a clear message. Nothing is truncated and
nothing is published elsewhere automatically. Today's limits are 32 MiB for
turns and attachments (state.go:28) and 64 KiB for broadcasts.

Inline attachments remove the external blob transaction boundary. They do not
remove storage and bandwidth growth.

### 10.2 Plaintext rules are not commit predicates

The sequencer validates visible enums, lengths, versions and capabilities
before commit. It cannot check "reason is non-empty", plaintext caps, or text
validity. The writing client enforces those; the reading client re-checks
after decryption. A missing reason therefore leaves an authorized lifecycle
change in force, with a clear diagnostic.

A reader distinguishes three cases and shows each differently, and none of
them stops replay of later control records:

- No key for this epoch: the control record verified and the payload was not
  inspected. This says nothing about whether the ciphertext is valid.
- Authentication or decryption failure: either bad ciphertext or incorrect
  local key material. The diagnostic must not assert that the writer is at
  fault.
- Authenticated but malformed plaintext: malformed by author.

"No control decision depends on plaintext" is a statement about protocol
validation. It is not a statement about human approval: an operator must see
the actual action and payload meaning before signing.

## 11. Materialization

### 11.1 Authority

The client's **verified local log store** — records, derived state and
checkpoint — is the local source of authority. Markdown and JSON files are
**projections** of it, rebuildable at any time.

A read that affects behaviour (floor, status, recipients, unread counts,
dispute state) uses verified state, or verifies a projection file against the
digest held in the verified store at the moment it is read. It never trusts a
projection file merely because an edit would be noticed at a later rebuild.

### 11.2 Applying

1. Append verified committed records to the local log store in `seq` order,
   re-deriving each outcome. Record, derived state and checkpoint advance in
   one durable step of that store.
2. Projections follow from a separate, durable `projected_seq` cursor.
   Projection is idempotent and may lag or be rebuilt.
3. Projection files are of two kinds. *Immutable* files (turns, notes, call
   record, lifecycle events, broadcasts, attachments) must be byte-identical
   on re-apply; a differing one marks the projection tainted and triggers a
   rebuild. *Versioned views* (measurements, resolutions, bye markers,
   receipts, addressing state) carry the `seq` they were derived from and are
   replaced only by a higher one.
4. One materializer per projection directory, locked by that directory. Two
   credentials never write the same projection; each has its own.

### 11.3 Local writers and delivery

On an attached line the existing entry points (`AppendTurn`, `SetBye`,
`SetCallStatus`, `AppendNote`, `NewDispute`, `SetMeasurement`,
`SetResolution`, `Attach`, `CreateBroadcast`, `ReadBroadcast`,
`ReplyBroadcast`, `Retire`) submit intents instead of writing files. A file
edited locally acquires no authority.

Local delivery is derived from a durable scan cursor over the verified log
store, not from an enqueue performed during materialization, so a crash after
the checkpoint advances loses no notice. That is the pattern delivery already
uses: it reconciles from retained source records and needs no dual-write
transaction (delivery.go:79–82). Delivery IDs, attempts and acknowledgements
stay local.

### 11.4 Local-only state

**Unchanged and never sent:** session and binding records (bind.go), delivery
endpoints and events (delivery.go, channels.go, codex_live.go, agy_live.go,
tmux_delivery.go), per-agent cursors `Seen`, `SeenNotes`, `NotesNotified`,
`BlockedAt`, `NotifiedAt` (state.go:573–579), rewake ownership, roadmap
nudges, recovery-notice markers, runtime install files, checkout paths, and —
in phase 1 — every lease, queue, offer, resource event and resource
configuration file.

**New:** the attachment record linking a local line to an LDR line, the key
store, the verified log store with its checkpoint and cursors, and the outbox.

**Attachment invariant.** Attaching a local line must not create a second
lock authority for a physical resource. This is a requirement on attachment.
It is not a claim that existing installs already enforce a global registry of
physical resources.

## 12. Deferred: relay-managed resources

Not designed here. A later phase must satisfy at least:

- Threat-model invariants 9–11, which are deferred, not disproven.
- One clock. Every expiry, grace and offer-window predicate is evaluated at
  commit on sequencer time (today: resource.go:212–227, 254–257, 316–326;
  queue.go:130).
- Sequencer-originated records for offer start, offer expiry, request expiry
  and offer invalidation, each with typed preconditions any client can
  re-derive. Today these happen as side effects of another actor's call
  (`advanceOffers`, queue.go:107–137) and `withdrawOffers` clears standing
  offers when availability changes. An old `offer_id` must never become valid
  again after a release or reacquisition.
- One admission protocol with an explicit claim step: request, offer, claim.
  A lost claim receipt needs a defined resolution.
- No intent whose only effect is that its sender is still polling
  (`touchQueue`, resource.go:368).
- Deterministic ordering of due internal events against incoming intents, and
  bounded processing of large due sets. A scheduler's absence may delay
  progress and never legalizes a transition.
- Self-reported runner status is diagnostics. It is not independent assurance
  that work has stopped.
- Moving a resource from host authority to relay authority is an explicit
  quiesce, reconcile, migrate sequence. Never both at once.
- Restore additionally reconciles protected-host fences and outstanding work
  before any grant resumes.

## 13. Open choices

The rows below are of four different kinds, and "agreed" means only the last
one:

- **Operator choices:** O1, O2, O3 and O3a are decided; O9 is not.
- **Discussion values:** O4 and O10 hold provisional numbers nobody has
  measured or approved.
- **Deployment-dependent:** O11.
- **Design directions reviewed with Codex:** the rest. "Agreed" there is
  design-review agreement between two agents. It is not operator approval, it
  rests on no executed test, and it does not cover crypto, enrollment,
  transport authentication, the clock contract or recovery, which remain open
  in Codex's documents.

| # | Choice | State | Whose |
| --- | --- | --- | --- |
| O1 | Phase 1 scope: conversation-first, host-local resources, bounded inline attachments — or relay-managed leases in the first release | **Decided 2026-11-23: conversation-first, leases local** | Operator |
| O2 | Principal model: credential with delegated namespace (§3) — or pre-enrolled actors only | **Decided 2026-11-23: machine-account credentials** | Operator |
| O3 | Confidentiality: 3A (every enrolled reader may read the line; repository access alone is not consent) — or 3B per-call keys | **Decided 2026-11-23: 3A** | Operator |
| O3a | Does a newly enrolled account receive earlier history? | **Decided 2026-11-23: no.** The operator briefs the new agent; `history_grant` removed | Operator |
| O4 | Size profile | Discussion values in §10.1 | Fable + Codex |
| O5 | Attachments | Inline-only in phase 1, agreed; part of O1 | Operator, with O1 |
| O6 | Receipts for revoked signers | Refuse; reconcile by an active authorized principal (§5.5) | Agreed |
| O7 | Register ordering | Committed credential-signed activation (§9) | Agreed |
| O8 | Actor labels | Encrypted; visible opaque namespace and actor IDs (§3) | Agreed |
| O9 | `call_status` by the operator | Participants only, as today | Operator, low priority |
| O10 | Validity and freshness values | Provisional: 60 s default, 10 min maximum, `F` 10 s. Policy candidates pending workload evaluation, not measured thresholds | Fable + Codex |
| O11 | Sequencer clock contract | Rules in §4.1; thresholds need the deployment choice | Codex, with deployment |
| O12 | `call_id` | Client-chosen opaque random ID plus generation-local ordinal (§7) | Agreed |
| O13 | Time-anchor mechanism | Anchor record on request (§4.2); a relay-authenticated time token is the alternative | Agreed as the preferred proposal |
| O14 | Audit stream for durable rejections and no-ops | None in phase 1; they are trusted relay decisions with bounded durable storage and authenticated replies (§5.4) | Agreed |
| O15 | Rejection precedence | Order in §5.8, with Codex's syntactic/state-dependent split | Agreed in direction; v4 wording awaits confirmation |
| O16 | `actor_move` without a namespace grant to the target | As §6.2: the operator's move grants control of that actor only; activation follows current binding | Agreed in direction; v4 wording awaits confirmation |
| O17 | `actor_remove` | Explicit, terminal, credential-origin removal by the current owner; local uninstall is only a detach (§6.2) | Agreed in direction; v5 wording awaits confirmation |
| O18 | Namespace capacity accounting | Live actors per namespace; one declaration owner per namespace in phase 1 (§6.1) | Agreed in direction; v5 wording awaits confirmation |
| O20 | Small rules the reference checker forced | Listed in §14.1 | Codex: reasonable for the initial profile. The actor limit now allows zero (§6.1), changed after its review |
| O21 | Default-audience broadcast: should the sequencer verify the list equals the default audience? | Yes: exact set equality at the named revision (§8). Codex's verdict; implemented | Agreed |
| O22 | Operator key lifecycle | State keeps no history of operator keys, so a key outside the active set cannot be told apart as revoked or never authorized. Until that is specified, such a key gets an access refusal that establishes nothing, and may not be assumed re-authorizable | Open, Codex |
| O23 | Sequence numbering across generations | Whether `seq` restarts in a new generation is undecided; §5.9 depends on the answer | Open, Codex, with recovery |
| O19 | Retirement of operation identity | Anchor-scoped identity; an anchor's identity space retires at its `seq_time` plus a maximum validity that is fixed per generation (§5.6). The alternative is a permanent digest tombstone per rejected operation | Accepted by Codex at design-review level, with two constraints that are folded in |

## 14. Conformance vectors and the reference checker

The list at the end of this section is the index of intent. The concrete data
is [LDR-CONFORMANCE-VECTORS.json](LDR-CONFORMANCE-VECTORS.json): apply
vectors, each a `(state, record, seq_time)` triple with an expected
`(state', outcome)`, and scenario traces for behaviour a single triple cannot
establish (retry admission, time floor and anchors, crash, recovery). The
file states its own counts. Expected results were written by hand.
`recovery_generation` has no apply vector, because its effect is a rebuild
from a base rather than a patch; it appears in traces only.

### 14.1 What has been run, and what that shows

With the operator's go-ahead of 2026-11-23, `ldrcore/` holds a reference
implementation of the transition function: stage 5 only, pure, no crypto,
network, storage or sequencer shell. `go test ./ldrcore/` runs every active
apply vector through it and compares outcome and resulting state.

Measured on 2026-11-23 (Go 1.25.3, darwin/arm64):

- **First run: 131 of 131 active vectors agreed, with no mismatch.** That is
  weaker than it sounds. The specification, the vectors and the checker were
  all written by the same author from the same draft, so agreement shows they
  are consistent with each other, not that any of them is right. Codex's
  static reviews found more real problems than this run did.
- **A mutation check was more informative.** In a scratch copy, 88
  hand-chosen single-rule breaks were applied one at a time and only the
  vector test was run. The vectors caught 72. Eleven breaks passed unnoticed,
  meaning the checker enforced a rule that no vector pinned; five did not
  compile and were rewritten.
- **Twelve vectors, A134 to A145, were added for those eleven rules,** with
  expected results taken from this document, not from the checker. After
  that, all 88 breaks are caught and 143 of 143 active vectors agree. The 88
  were chosen by hand; this is not a claim of complete coverage.
- **No expected result was changed to make the run pass.**
- `go vet` and `go test -race` pass for the package.

Not run: every scenario trace that needs dedup, the outcome index, the time
floor, anchors or admission. Five traces have an apply-only part, which is
exercised as an ordinary Go test (T20, T21, T30, T31, T37). Nothing here is
evidence about cryptography, enrollment, transport, the clock contract or
recovery.

Two of the eleven unpinned rules were not in this document at all. They are
now, and both await review:

- A second bye from a participant whose bye already stands is `noop` (§7.2).
- `actor_move` to the credential that already holds the actor is
  state-dependent `invalid` (§6.2).

Writing the checker also forced small choices the draft had left open (O20):

- A duplicate entry in a recipient list or a manifest is syntactic `invalid`.
- `call_status` naming a related call for any state but `linked` is syntactic
  `invalid`.
- An enrollment grant's actor limit must not be negative. The first version
  of the checker required it to be positive, which excluded reader-only
  grants; Codex pointed that out and zero is now allowed.
- The allowed register types are `presence`, `roadmap` and `resource`.
- `credential_revoke` increments `audience_rev` even when the credential held
  no actors.

### 14.2 Codex's independent run found three bugs this did not

Codex ran the package itself and probed it with inputs of its own
([LDR-CHECKER-REVIEW.md](LDR-CHECKER-REVIEW.md)). It found three behaviours
that were wrong, each of which had passed every vector and every mutant:

1. An otherwise valid turn marked over the inline limit committed. The size
   limit was only checked for attachments.
2. On an empty log, a time anchor committed, and so did a root record other
   than `line_init`. The genesis boundary was documented and not enforced.
3. A broadcast marked as default audience committed with a subset as its
   recipient list.

Why the earlier checks missed them: a vector test only finds disagreement
between two things the same author wrote, and a mutation check only finds
rules the checker enforces that no vector pins. Neither can find a rule the
checker *fails* to enforce and no vector asks about. A second reader could.

All three are fixed in `ldrcore/`, with vectors A146 to A162 written from the
corrected text of this document. Mutants that undo each fix are caught by
those vectors. The same review tightened the harness:

- The whole vectors file is now decoded with unknown fields refused, not only
  the state and record inside each vector.
- A no-op's reference is compared exactly, with absent meaning none, so a
  fabricated reference fails.
- Every starting state and every state `Apply` returns is checked for
  coherence on the raw state, before any canonical comparison, so sorting and
  deduplicating for comparison cannot hide a malformed result. This check
  would have caught the incoherent fixture Codex found by reading (A84).
- A hostile-input test runs several hundred thousand generated records:
  every record type under every origin, with known, unknown and empty signers
  and targets, from starting states that include an empty log and a line with
  its counters at the top of their domain.
  None panicked, none changed its input, and nothing but a commit changed
  state. That is the evidence that the precedence ladder's checks dereference
  only what an earlier step established.

Codex confirmed those three fixes with its original probes, then ran a second
one and found a fourth problem: counters wrapped. A commit with `head_seq` at
the largest 64-bit value returned a negative sequence number, and a move with
a binding generation at the largest value returned a negative generation.
Both starting states had passed the coherence check. §5.9 now defines a
counter domain and an `exhausted` outcome; the checker uses fixed-width
integers and a checked increment for every counter; the coherence check
rejects any value outside the domain; and the vectors file is read without
converting numbers through floating point. Vectors A163 to A173 cover it,
including one showing that exhaustion discards a partly applied effect.

Current numbers, measured 2026-11-23: 171 of 171 active vectors agree; 102 of
102 hand-chosen mutants are caught; the hostile-input test runs 564,480
generated records with no panic and reaches every outcome and every rejection
reason; `go vet` and `go test -race` pass. The caveats of §14.1 are unchanged,
and this section is the reason to believe them: four defects found by a
second reader after every check of mine was green.

### 14.3 The sequencer model and the scenario traces

With the operator's second go-ahead, `ldrcore/sequencer.go` models the shell
around the transition function: operation identity and dedup, admission
versus durable outcome, the retry lookup of §5.5, anchors and validity,
anchor-scoped retirement and compaction, the rejection quota, the time floor
and demand-driven time anchors. It is in memory and single-threaded. A
signature is a boolean, the chain head is a non-cryptographic stand-in, and
the clock is injected together with whether the deployment trusts it. It has
no transport, storage or cryptography, and it is not a relay.

**Recovery is not modelled.** On Codex's advice the model does not roll a log
back, rebuild state or start a generation. The two traces that need a
generation change start from a post-recovery fixture that is simply
stipulated, with reconciliation of its security state as an external premise
the model cannot check. A fixture without that premise is not installed,
which is a guard on the test fixture and not a recovery gate.

Each trace in the vectors file now carries a label saying how far a Go test
re-enacts it, and a test checks the labels against what actually runs: 26 of
the 39 traces run against the sequencer model, 4 run only as a sequence of
transitions, and 9 are not executed because they concern the client (outbox,
projection, delivery, reader states) or register publication.

Measured on 2026-11-23:

- **Mismatches on the first run: four, one in the model and three in the
  tests.** Every scenario failed at its first step because the model compared
  an intent's generation with the current one before any line existed; that
  was a real model bug and is fixed. One test hard-coded an index size, one
  randomized invariant did not allow for a compacted non-commit being
  unanswerable while the clock is untrusted, and one new assertion wrongly
  expected compaction to discard nothing. No scenario's expected result was
  changed to make the model pass.
- **Mutation check: 43 hand-chosen breaks of the model.** First run: 37
  caught, 4 did not compile, 2 survived. The two survivors were both about
  when an anchor's identity space retires, at its maximum validity and not
  earlier, and exactly at the boundary: the same area as the hole Codex found
  in draft v4. After tests for those, two more survived, both about quota
  accounting across compaction. With a test for that, 43 of 43 are caught.
- **A randomized walk** of 60,000 steps over three seeds mixes submissions,
  resubmissions with and without changed bytes, queries, anchor requests,
  clock movement, clock faults and compaction. Throughout it, the log replays
  from genesis to exactly the sequencer's state, time and the time floor never
  decrease, no operation identity gets two outcomes, a commit stays committed
  at the same sequence number, a non-commit only ever decays to `expired`
  after its anchor retires, and changed bytes never commit under an identity
  that already has an outcome.
- `go vet` and `go test -race` pass for the package.

Codex then probed the model through its exported interface and found four
defects, again after every check above was green:

1. The bootstrap path skipped its context checks wholesale: a `line_init`
   naming generation 7, or anchored at sequence 55 on an unrelated head,
   created generation 1.
2. Committed records shared pointers and slices with the caller. Changing a
   submitted intent after it committed, or changing the copy the log accessor
   returned, corrupted the log so that it no longer replayed.
3. An invalid first `line_init` on an empty log was answered "a line exists".
4. With an untrusted clock, a submission declined to answer about a compacted
   rejection while a query still answered `expired`.

All four are fixed, with one focused test each, and mutants that undo each
fix are caught. Current numbers, measured 2026-11-23: 50 of 50 hand-chosen
mutants of the model are caught; the transition-function harness is unchanged
at 102 of 102; `go vet` and `go test -race` pass.

Across both packages Codex's probes have now found eight defects that the
author's vectors, mutation checks and randomized tests did not. Those checks
show the code agrees with its author's tests. They are not a substitute for a
second reader, and nothing here should be read as more than that.

Rules the model forced that this document had not stated, each needing review:

- A commit is never blocked by the rejection quota. A rejection or no-op that
  arrives when the quota is full is discarded as an admission error, so
  nothing was promised and a retry is evaluated afresh.
- A second `line_init` is a definitive refusal without an index entry: it has
  no anchor whose retirement could bound one.
- An ordinary intent cannot anchor on genesis; a generation's first
  anchorable point is its first record.
- While the clock is untrusted, a non-commit whose entry was already
  compacted cannot be answered at all, because answering `expired` needs
  time. Committed receipts are still answered.
- An operator key outside the active set is refused access without implying
  anything about its past (O22).

### 14.4 Index of intent

Conversation:

1. Two turns at the same `expect.turn_count`: one commits, one `conflict`.
2. Turn by the non-holder without `barge`: `not_floor`; with `barge` and a
   current count: committed and marked. Turn by a non-participant:
   `unauthorized`.
3. Barge at a stale count: `conflict`.
4. Bye at a stale turn count: `conflict`. Bye, then peer turn: `byes` empty.
5. Both byes: `status` resolved; a turn is `not_open` until `call_status open`
   empties `byes`.
6. `resolved` at a stale turn count: `conflict`.
7. Note on any lifecycle: committed; floor, byes and lifecycle unchanged.
8. `linked` to a call the signer is not in: `unauthorized`.
9. `call_open` with an existing `call_id` under a different intent: `conflict`.
10. Two participants measure concurrently: both commit. Resolve at the
    pre-measurement dispute revision: `conflict`. `withdrawn` by the
    participant who did not open the dispute: `unauthorized`.
11. Measurement or participant resolution on a resolved dispute: rejected.
    Arbitration at the current revision: committed, supersedes.

Identity, audience and keys:

12. `actor_declare` by a credential with no actors: committed. Outside the
    granted namespace or over the limit: `unauthorized`. Reusing a live or
    tombstoned `actor_id`: `conflict`.
13. Record under a superseded `binding_gen`: `unauthorized`. New intent from a
    revoked credential: `revoked`, no index entry, and the client marks it
    reconciliation-required rather than not-committed.
14. New intent with a stale `auth_epoch`: `conflict`. Retry of an intent that
    committed before the epoch changed: its original receipt.
15. Default-audience broadcast after an `actor_addressing` change:
    `conflict`. Explicit-list broadcast after the same change: committed. A
    local delivery pause during composition: no effect.
16. Second `broadcast_read` by a different operation: `noop(ref_seq)`, no log
    record. Retry of the first: its original outcome.
17. Payload-bearing record while `rekey_pending`, or under an old `key_epoch`:
    rejected, including a control record with an encrypted reason or label
    and a register body. Membership and key-distribution records in the same
    state: committed.
18. `key_epoch_activate` whose manifest omits an entitled reader, names a
    revoked credential, or names a credential without reader capability:
    rejected. An operator key not enrolled as a reader is not entitled.
19. Enroll, activate, then read of an earlier epoch by the new credential:
    not in `readers`, and phase 1 has no record that changes that.

Retry, time and recovery:

20. Identical retry: original outcome, no second effect. Same `op_id`,
    different bytes: `duplicate_mismatch`, on both the hot and the log path.
21. Rejected intent retried after state changed so it would now pass: the
    original rejection.
22. Commit, lost receipt, retry after validity: original receipt from the log.
23. Never committed, retry after validity: `expired`.
24. Overload during submission, then retry: no promise from the first answer;
    exactly one outcome overall.
25. Quiet line, intent anchored on an old head: `expired`. Anchor request,
    then a new intent on the anchor: committed.
26. Two anchor requests inside `F`: at most one `time_anchor`. A
    `time_anchor` within `F` of its predecessor: protocol violation on replay.
    Anchor requested by an operator on a line with no active credential:
    served. Requester revoked between session authentication and the append:
    no anchor.
27. Old intent after a later anchor: still bound to its own anchor; `expired`.
28. Intent whose `seen_head` differs from the head at an occupied sequence:
    `unknown_anchor`, definitive. Intent with `seen_seq` ahead of the
    sequencer: `history_unavailable`, stays unresolved, client fails closed.
29. Intent anchored before a divergence, shown on both branches: accepted on
    both, and no detection is claimed.
30. Old-generation intent found in retained history: its original receipt.
    Not found: `abandoned(generation)`, reconciliation-required, never
    resubmitted. `recovery_generation` replayed: rejected. A recovery that
    cannot establish later revocations and tombstones: fails closed.
31. Frozen, forward-jumped and restart-regressed sequencer clock: no old
    operation is re-admitted, the time floor never decreases, and uncertain
    time suspends evaluation while receipt lookup still works.
32. Query for a receipt authenticated only by a revoked key: refused.

Registers and materialization:

33. Register update from a revoked credential, or from an activation older
    than the current `writer_rev`: rejected. No register value changes the
    outcome of any vector above.
34. Crash between log-store commit and projection: projection resumes from
    `projected_seq`; no duplicate file, no lost delivery notice.
35. Projection file edited locally: behaviour-affecting reads are unchanged;
    rebuild restores the file.
36. Undecryptable body, missing epoch key, malformed plaintext: three distinct
    reader states; replay continues past each.

The threat model's fault scenarios and the security review's fixtures that
concern resources, offers, fences and enrollment substitution belong to §12
and to Codex's documents respectively.
