# LDR state machine and mutation/authority matrix — draft v7

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

Appendix A was added on 2026-11-23, after draft v6 and at Codex's request. It
restates, with section references, what this document needs from the
enrollment, control-bootstrap and envelope design, and lists what it leaves
open. It changes no rule, so the draft number is unchanged.

Draft v7 (2026-11-23) follows Codex's enrollment, control-bootstrap and
envelope draft v1
([LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md](LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md))
and the cross-review of it on call 0003. It changes rules:

- A credential identifier is derived from the credential's two keys, and
  every public key is reserved for life across roles (§3, §6.1, §6.2).
- A revoked operator key leaves a tombstone, is never authorized again, and
  is told that it is revoked (§5.4, §6.2).
- The relay holds the line's creation descriptor before the first record, and
  `line_init` commits the profile (§4.4).
- The signer in an operation identity is the tagged signing principal, and
  the profile digest is a signed field (§5.1).
- A required expectation that is absent is malformed (§5.8).
- A register value signs the incarnation of its activation (§9).
- An admission error is never an instruction to retry (§5.4, §5.7).

Draft v7 was corrected the same day after Codex reviewed it (call 0003, turn
5, and its draft v2). No rule changed. Three statements did: a persistent
admission error suspends automatic sending and does not claim that its cause
can never change (§5.4, §5.7); an error code the client does not know is
treated as persistent; and an intent's profile digest is compared with the
profile of the generation the intent names, never with a later one (§5.5).

These are two agents' design-review agreement and nothing more. None is
operator-approved. Two questions in Codex's draft are the operator's: who
vouches for a new member's starting state, and whether the root key can sign
inside a validity window (§13, O25 and O26). They were put to the operator on
2026-11-23 and are unanswered.

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
| Reference checker | **Operator go-ahead, 2026-11-23,** for a small Go implementation of the rule-checking core only: no crypto, no network, no relay. Later the same day the operator also approved an in-memory model of the relay-side bookkeeping (retries, expiry, clock handling), under the same limits, so that the scenario traces can run. A third go-ahead the same day covers a model of the agent's own machine and of register publication (§14.4). All of it lives in `ldrcore/`, and draft v7's rules are in it (§14.5). Results are in §14. Recovery is not modelled. |
| Enrollment, control bootstrap and envelope | Codex's draft (v3 as of 2026-11-23) is a proposal under cross-review. The rules in this document that follow it carry design-review agreement only. Two points in it are the operator's to accept; they were put to the operator on 2026-11-23 and are unanswered (§13, O25 and O26). |
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

1. Bounded decode. Refuse bad framing, unknown versions, a profile digest
   that is not that of the generation the intent names, unsupported fields
   and scopes, and
   transport envelopes over the size bound. Bound every
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
authenticate nothing between them. A credential is exactly its two public
keys: its `cred_id` is derived from the pair, neither key is replaced in
place, and a different pair is a different credential (§6.1).

Enrollment grants a credential a **namespace**: a visible, opaque, non-secret
`namespace_id`, with limits and capabilities. An **actor** has an opaque
immutable `actor_id` inside one namespace. Display labels are encrypted and
carry no authority; two actors with the same label are a display problem, not
an identity collision.

One actor is bound to exactly one credential at a time, with a `binding_gen`
that increments on every move. One credential may host many actors. An
`actor_id` is never reused after its actor is revoked or removed, and a
`cred_id` is never re-enrolled; both leave durable tombstones, as do consumed
join-request identities and revoked operator keys. Every public key that has
held a role is reserved in the same way (§6.1). Tombstones and reservations
must survive recovery. Saying so does not make it true across a rollback; the
mechanism is a recovery requirement (§6.2).

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

Revoking a credential disables every actor bound to it, and for those actors
that is terminal: a disabled actor is not live, its `actor_id` is tombstoned,
and nothing moves it or brings it back (§6.2). Moving an actor leaves
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

`F` is protocol profile data. The profile is committed in `line_init` (§4.4),
so a replaying client reads `F` from the chain it verifies. It is not a value
a relay may choose per request.

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

- The relay is provisioned before any record exists. Whoever administers the
  deployment installs the line's complete root-signed creation descriptor:
  the line identity, the root key, the relay's origin, generation 1 and the
  whole profile. The genesis constant is derived from the line identity, the
  root key and the descriptor's digest. It is therefore fixed by what was
  provisioned, and not chosen by whichever `line_init` arrives. Presenting a
  self-signed descriptor neither creates nor reserves a line; who may
  provision one is a deployment obligation (Appendix A, Q1).
- `line_init` has no prior checkpoint. It anchors on that genesis constant,
  names the root key, commits the descriptor's digest and the complete
  profile, is exempt from validity, and can commit only into an empty log.
  The profile is immutable for the generation: `F` and the maximum validity
  are read from it, by the relay and by every replaying client.
- `line_init` is exempt from validity, not from its context. It names
  generation 1 and anchors on genesis. One that names a later generation, or a
  sequence number an empty log has never had, comes from a client that is
  ahead of this relay and is answered `history_unavailable`, as in the
  ordinary case; one that names a different genesis is `unknown_anchor`. One
  that anchors on the right genesis and states a root key, a descriptor
  digest or a profile other than the provisioned ones is refused as invalid
  bootstrap input.
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

Every `actor`, `credential`, `operator` and `root` intent signs, at minimum:

| Field | Purpose |
| --- | --- |
| `version` | Protocol version; unknown is rejected, never downgraded |
| `profile` | Digest of the profile of the generation the intent names (§4.4). An intent that states another is refused before admission, like an unknown version. The comparison is with that generation's profile, never with a later generation's (§5.5) |
| `line_id`, `generation` | No cross-line or cross-generation replay |
| `origin`, signing principal | Who signs, tagged by role: a credential (its `cred_id`), an operator key, or the root key. Actor and credential origins both sign as the credential |
| `actor_id`, `binding_gen` | Actor on whose behalf the credential signs (`actor` origin only) |
| `op_id` | Operation nonce. The operation identity is `(line_id, generation, signing principal, seen_seq, op_id)`: an `op_id` is unique only within its anchor (§5.6). Each operator key and the root have an identity space of their own; the two origins a credential signs under share one |
| `op_type`, `target` | What is being done to which object |
| `expect` | Expected object versions, per record type |
| `auth_epoch` | Membership epoch the signer acted under. **Checked: must equal the current value** |
| `key_scope`, `key_epoch` | Encryption scope of the payload. **Checked for payload-bearing records (§6.3)** |
| `seen_seq`, `seen_head` | The signer's verified durable checkpoint |
| `validity` | Duration, bounded by a protocol maximum |
| `payload_commit` | Digest and length of the encrypted payload |
| visible fields | The per-type allowlist in §10 |

Operator and root intents also sign their action scope (§3). `line_init` and
`recovery_generation` differ only as §4.4 says.

The digest that identifies an intent's bytes covers the signed envelope
including its signature, and covers the payload only through
`payload_commit` (Codex's draft, P5). A second signature over the same intent
is therefore different bytes under the same identity. A client signs an
intent once, stores those bytes, and never signs it again (§5.7).

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
nothing is promised about the operation. The client keeps the intent
unresolved. They are of two kinds, and neither closes an intent:

- *Transient:* overload, rate limit, exhausted rejection quota, clock
  uncertainty, network failure. The same bytes may be sent again. Whether and
  how often is client policy, and that policy is bounded: an admission error
  is never an instruction to retry, and never a reason to retry without end.
- *Persistent:* the relay refuses these bytes or this signer for a reason
  that waiting does not remove: bad framing, an unknown version, a profile
  digest that is not that of the generation the intent names, an unsupported
  field, an oversized transport envelope, a bad signature, a signer the relay
  has no record of (a credential never enrolled, an operator key never
  authorized), a requester not entitled to ask. An error code the client does
  not know is treated the same way. "Persistent" means that the client stops
  sending on its own until someone has diagnosed the cause. It does not mean
  the cause can never change: a wrong endpoint can be corrected, a missing
  line provisioned, an unknown key enrolled. None of that shows what became
  of the operation, so the action is marked reconciliation-required (§5.7).

A rate-limit response never implies non-commit; admission and outcome
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
- `revoked` — signed by a credential or an operator key that is now revoked.
  It may have committed before the revocation, and the revoked key may not
  ask (§5.5). The answer goes only to a requester that has shown possession
  of that key, by the signature on the intent or on its session. It says the
  key is revoked and nothing else. A key that never held the role gets the
  persistent admission error above, which does not say even that, and an
  unauthenticated request learns neither.
- `abandoned(generation)` — signed for an earlier generation and not found in
  the history that the current generation retained. It has no effect in the
  current generation. It may have committed in a discarded tail.

**Operation outcomes** are durable, one per admitted intent. An intent is
admitted when it decodes within bounds, its signature verifies, its signer is
in good standing (a credential enrolled and unrevoked, an operator key
currently authorized, or the root), its generation is current, its anchor is
on the accepted history, and it is within validity.

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
verification, and authorization of the requester to learn this outcome. A
resubmission may carry the signed envelope without its payload bytes: the
lookup below comes before any check of them, and a hit returns the recorded
outcome. Only on a miss must the payload be complete, before step 7 (Codex's
draft, P5).

The profile digest is part of that decode, and it is compared with the
profile of the generation the intent names. An intent of an earlier
generation is never refused because its profile is not the current one: that
would hide the receipts of step 3. Either the relay keeps, with the history
it retains from a generation, what it needs to verify that generation's
intents, or the outcome is learned by a query that an authorized principal
signs under the current profile. Which of the two applies belongs to the
recovery design and the wire profile, both Codex's. Neither is modelled, and
no vector covers it.

Then, with every lookup keyed by the full operation identity of §5.1:

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
refused, including for that key's earlier receipts, whether the key was a
credential's or an operator's. The refusal is `revoked` (§5.4), and it says
nothing about whether the operation committed. An active, separately authorized
principal may reconcile that history by signing a query that names the
original operation and digest; it does not replace the historical intent's
signer. Revocation does not erase receipts a client already cached.

A submission is accepted only on a session authenticated as the principal
that signed it. One principal does not submit for another, so holding a
signed intent is not enough to send it (Codex's draft, P7). Reconciling
another principal's operation is always a query and never a submission.

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

1. Sign once. Serialize and durably store the signed intent before the first
   send, together with the application action it came from. Every retry
   sends those bytes; nothing is signed a second time.
2. At most one unresolved intent per `(acting identity, target)`, where the
   acting identity is the actor for an actor-origin record and the credential
   or operator key otherwise, and the target of a create is its creation
   slot. Operator and control actions are included. Two actors on one
   credential have separate slots, since both can be participants of the same
   call. This is client policy and not the wire dedup identity.
3. On restart, or after a stale-checkpoint refusal, resolve every stored
   intent by query before constructing anything new. A timeout or a
   cancellation is not evidence of non-commit. An intent marked
   reconciliation-required is asked about as well: asking is not sending. An
   answer that establishes nothing leaves it as it was, with the reason it
   already had.
4. Only a definitive refusal or a durable rejection closes the intent. The
   caller may then issue a deliberately new or corrected intent with a new
   `op_id`. Nothing is reissued automatically.
5. `history_unavailable`, `revoked` and `abandoned(generation)` do not close
   it. Nor does a persistent admission error (§5.4), such as an unknown
   signer or an error code the client does not know. The client stops
   sending on its own, marks the action reconciliation-required and shows it
   to the caller. The slot stays occupied. The refusal is never grounds to
   free the slot, repeat the action, sign again or choose a new anchor. A
   signed query may still settle the intent, with an outcome or a definitive
   refusal. Sending the stored bytes again once someone has corrected the
   cause would need a client policy of its own; this draft states none, and
   the model never resumes.
6. A completed result is stored and surfaced to the action that caused it.
7. A transient admission error leaves the intent stored and unresolved. The
   client may send the same bytes again, a bounded number of times, and stops
   when its own policy says so. Stopping settles nothing: the intent still
   needs an outcome, a definitive refusal or reconciliation before its slot
   is free.

### 5.8 Rejection precedence

When more than one precondition fails, the durable outcome must be the same
on every implementation. This ladder applies only to a new, admitted
operation. Admission errors and the outcomes of earlier operations found by
dedup lookup are outside it. The first failing check decides:

1. `invalid`, syntactic — a visible field is malformed for the record type
   regardless of state: a value outside its allowed set, an empty required
   list, a self-reference, line ciphertext on a type declared
   ciphertext-free, a required expectation that is absent, a `cred_id` that
   is not the derivation of the enrollment's two keys, one key named in both
   of a credential's roles.
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
8. `conflict` — an identifier collision on create, a public key that has
   already held any role on the line (§6.1), or any `expect` value that is
   not current.
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
collision answer. A reserved public key is an identifier in this sense.

An absent expectation is not an expectation of zero. Zero is a real expected
value: the first `key_epoch_activate` expects `key_epoch` 0, and a new call's
`lifecycle_rev` is 0. Each record type's required expectations are listed
with it (§6.2, §7.2, §8). Leaving one out is malformed whatever the state,
and is reported at step 1, before authorization. The encoding must be able to
tell the two apart, which is Codex's to specify.

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
  root key
  operators: operator keys currently authorized
  credentials: cred_id -> { signing key, encryption key, namespace grant, limits, capabilities, revoked }
  tombstones: cred_ids, actor_ids, join-request ids, revoked operator keys
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

**Keys.** A credential is exactly its two public keys. Its `cred_id` is
derived from the pair, and phase 1 has no record that replaces either key. A
machine that loses or changes a key enrolls as a new credential with a new
namespace (Appendix A, E3).

Every public key that has ever held a role on the line is reserved for life:
the root key, every operator key ever authorized, and both keys of every
credential ever enrolled. A reserved key never takes a second role and never
returns to its first, alone or with a different partner. So a revoked key
cannot come back under a new `cred_id`, as an operator key, or as the other
half of someone else's pair. The sequencer checks this on visible fields
alone, which is why a revoked credential keeps its entry and a revoked
operator key leaves a tombstone. "A key" here means an algorithm identifier
together with that algorithm's one accepted public encoding, so that an alias
or a second encoding of the same key cannot slip past the reservation; the
encoding is Codex's to specify. The principal that names an operator key or
the root key is that same value with its role tag, and not a separate
identifier or a digest; the reservation is over the value without the tag
(Codex's draft, §2). The reservation is of encodings. It cannot tell that
two public keys under different algorithms were derived from one secret, and
no check at the relay can. Enrollment tooling must generate the key of each
role independently; sharing or converting a secret between roles is not an
approved way to make keys.

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
| `line_init` | root | Log empty; names the root key, the creation descriptor's digest and the profile (§4.4) | Line state created: `generation = 1`, `root_rev = 1`, `auth_epoch`, `audience_rev` and `key_epoch` at 0, no operators or credentials, `rekey_pending` set until the first activation. The root key is the first reserved key |
| `operator_key_authorize` | root | `expect.root_rev`; the key has never held any role on the line (§6.1), so in particular it is not authorized now and was never revoked | Key joins the operator set; `root_rev++`; `auth_epoch++` |
| `operator_key_revoke` | root | `expect.root_rev`; key currently authorized | Key leaves the operator set and is tombstoned for good; `root_rev++`; `auth_epoch++` |
| `recovery_generation` | root | §4.4; carries the tombstone registry, the reserved keys and the reconciled membership and key state | New generation; hot index empty; §5.7 rule 5 applies |
| `credential_enroll` | operator | Carries the join-request ID, the digest of the join request, both public keys, the `cred_id` and the grant. Syntactic: the two keys differ, `cred_id` is their derivation, the grant is well-formed. Then: join-request ID unused; `cred_id` never enrolled; neither key has ever held any role (§6.1); granted `namespace_id` never granted before | Credential added with its two keys; `auth_epoch++`; `rekey_pending` set |
| `credential_revoke` | operator | Credential enrolled | Credential tombstoned, its entry and keys kept; its actors disabled for good; `auth_epoch++`; `audience_rev++`; `rekey_pending` set |
| `key_epoch_activate` | operator | `expect.key_epoch`; manifest names exactly `entitled_readers` as of commit, with one wrap commitment each | `key_epoch++`; `readers` set; `rekey_pending` cleared |
| `actor_declare` | credential | `namespace_id` in the signer's grant; namespace has capacity; `actor_id` never used | Actor created live at `binding_gen = 1`, `addr_rev = 1`, `default_addressed = true`; `audience_rev++` |
| `actor_move` | operator | Actor live, which an actor disabled by a revocation is not; `expect.binding_gen`; target credential enrolled and unrevoked, and not the current holder (state-dependent `invalid`) | `binding_gen++`; `auth_epoch++`; `audience_rev++`. The actor keeps its `namespace_id`; the target credential gains control of that actor and no right to declare in its namespace. Register writer state is kept, not reset. A removed actor cannot be moved back to life |
| `actor_remove` | credential | Actor live and bound to the signer; `expect.binding_gen` | Terminal: actor no longer live; `actor_id` tombstoned; `audience_rev++`. Its calls and history stay |
| `actor_addressing` | actor | `expect.addr_rev` | `default_addressed` set; `addr_rev++`; `audience_rev++` |
| `register_activate` | credential | Actor bound to the signer; register type allowed; `expect.writer_rev`; incarnation never used for this writer by any owner | `writer_rev++`; new incarnation current |

The sequencer does not check that a joiner holds the private keys it is
enrolled with. Under Codex's draft (P3) the operator's tooling checks
possession of both before it signs, and the request digest in the record
lets the joiner confirm that the enrollment that committed is the one it
asked for. Neither is a commit predicate.

A credential's revocation is terminal for the actors bound to it at that
moment. They are no longer live, their `actor_id`s are tombstoned, and
`actor_move` needs a live actor. An operator who wants a machine's actors to
survive a change of keys enrolls the new credential, moves the actors, and
only then revokes the old one. If the old key has to be revoked at once, its
actors go with it, and no record brings one back.

A revoked operator key is never authorized again; the root authorizes a new
key instead. What that key signed before its revocation stays in the log
with its signer unchanged, and an active principal can still reconcile it
(§5.5).

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
does not contain later revocations, tombstones or key reservations. Carrying
them forward needs
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
- The device that generates an epoch key learns it. Honest tooling therefore
  generates it on an enrolled reader and lists that credential in the
  manifest; the first enrolled reader generates the first epoch (Codex's
  draft, P9). The grants stay separate: authority to sign as operator can
  live on a protected signer that never sees the key. The sequencer cannot
  check where a key was generated.
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
  `cred_id`, `binding_gen`, `writer_rev`, the incarnation of its activation,
  `key_epoch` and counter. Codex's envelope adds the profile digest and the
  body's commitment. Bodies are encrypted under the line's scope. Sizes and
  rates are bounded.
- A writer revision and its incarnation are committed together, so a value
  that names the current `writer_rev` with any other incarnation is rejected.
  A publisher that cannot trust its stored counter activates again and
  publishes under the new incarnation. It never speaks for an activation it
  did not make.
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
| `line_init` | Root key, creation-descriptor digest, the complete profile |
| Membership and keys | Public keys, credential IDs, join-request IDs and digests, namespace IDs, grants, limits, epochs, manifest credential IDs and wrap commitments |
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

- **Operator choices:** O1, O2, O3 and O3a are decided; O9, O25 and O26 are
  not. O25 and O26 were put to the operator on 2026-11-23 and are
  unanswered.
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
| O22 | Operator key lifecycle | Draft v7, following Codex's P8: a revoked operator key leaves a tombstone, is never authorized again, and is told `revoked` once it has shown possession; a key never authorized gets an admission error (§5.4, §6.2) | Agreed in design review; not operator-approved |
| O23 | Sequence numbering across generations | Whether `seq` restarts in a new generation is undecided; §5.9 depends on the answer | Open, Codex, with recovery |
| O24 | Questions this document leaves to the enrollment, control-bootstrap and envelope design | Listed in Appendix A.7 as Q1 to Q16. Where each stands after Codex's drafts v1 to v3 is in A.8. The four that were gaps in this document's own text or vectors (Q2, Q10, Q11, Q16) are closed in draft v7 | Partly closed; see A.8 |
| O25 | Who vouches for a new member's starting state | Codex's draft (P4) proposes that the enrolling operator's device attests the complete control state at the enrollment's commit, and that the joiner verifies every record after it. That trusts the operator's verified store and signing path for everything before the join. If the records the joiner verifies revoke that operator's key before the joiner has accepted its starting state, the joiner stops, and a currently authorized operator must attest afresh for the same credential; that is not a second enrollment (draft v2, §4.2). The alternative is to replay every control record from genesis, which needs no such trust and grows with the line's age. Neither changes a rule in this document | Open: operator, asked 2026-11-23, unanswered |
| O26 | Whether the root key can sign inside a validity window | §4.4 gives root records ordinary validity, 10 minutes at most on the provisional numbers. Whether a protected or offline root key can catch up and sign in that time is to be found by a dry run. If it cannot, root records need a validity rule this document does not have | Open: operator, asked 2026-11-23, unanswered |
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
projection, delivery, reader states) or register publication. Those nine now
run against the models of §14.4.

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

### 14.4 The client and register models

With the operator's third go-ahead (2026-11-23), `ldrcore/` also models the
agent's own machine, so that the nine traces §14.3 left unexecuted can run:

- `client.go`: the verified local log store and checkpoint, the projection
  with its cursor and its two kinds of file, local delivery from a scan
  cursor, and the three reader states of §10.2.
- `outbox.go`: the client discipline of §5.7.
- `registers.go`: publication of advisory registers against committed writer
  state (§9), including the key gate of §6.3.

The limits are the same as before, and they matter more here. There is no
disk: every field is durable by definition, and a crash is a procedure
stopping between two durable steps. There is no cryptography: whether a
payload decrypts is a flag on the payload, and whether a wrap verified is a
flag on the client. A client starts empty and replays from genesis, which
does not settle how a new member really establishes its first checkpoint
(Appendix A, Q5). Recovery is not modelled. None of this is evidence that an
implementation survives a real crash.

All 39 traces now have a test, and a test checks the labels in the vectors
file against the tables of tests: 26 run against the sequencer model, 7
against the client model, 3 against the register model, and 3 remain a plain
sequence of transitions (T20, T21, T31).

Measured on 2026-11-23:

- **First run: every new test passed except one, and the fault was in the
  test.** It counted acknowledged notices as undelivered ones. No model code
  changed to make a test pass. As §14.1 says, that is weak evidence: the
  model and its tests have one author.
- A randomized test kills the client at each of three points, repeatedly,
  over three seeds, and requires it to end with exactly the files and notices
  of a client that never crashed, with no rebuild.
- `go vet` and `go test -race` pass for the package.
- **Mutation check, run later the same day: 126 hand-chosen breaks of the
  three files, beyond those of §14.5. 86 were caught, 36 were not, and 4 did
  not compile** because the break was written wrongly. The 36 were in the
  order of the reader-state checks, the projection's write rules, who is
  notified, several outbox rules, and the bounds and history test of the
  register model. That is far more than either earlier check left, and it is
  the result for that chosen set only: a count of breaks caught is not a
  measure of rules covered.
- **After it:** tests were added in `client_rules_test.go` and
  `registers_test.go`, the 4 were rewritten, and 4 breaks were added for the
  model change below. The set of 130 was run again: 126 caught. One more
  test was then written for an unreadable view and checked on its own
  against its break, without a third full run. Three breaks remain uncaught,
  and none is a rule a test can reach: a second disagreement after a rebuild
  cannot happen in this model, because a rebuild starts from no files;
  clearing an injected fault on restart belongs to the test harness; and the
  register model's "revoked credential" test of history is implied by the
  others, since revocation disables the credential's actors.
- **One model change came out of it.** Resolving stored intents after a
  restart now asks about those awaiting reconciliation as well as the
  pending ones, which is §5.7 rule 3 read literally. Before, the restart
  demanded a resolve that did nothing for them.
- **No probe by Codex yet.** Both earlier models looked finished at this
  stage and were not.

Rules the models forced that this document had not stated, each needing
review:

- A client that meets a sequencer violation stops: it applies nothing further
  and composes nothing. A different record offered at a sequence number it
  has already verified is a violation; a record offered out of order is only
  a transport error.
- A reader holds an epoch's key when the manifest names its credential and
  its own wrap verified. Bad ciphertext and wrong local key material give the
  same reader state, which is why that state cannot blame the writer.
- A state-derived view is tagged with the last record that changed its
  object. A view that claims a sequence number beyond the checkpoint taints
  the projection. A view that is merely older than the store is lag, not
  corruption, and a verified read of it reports that it is not yet projected.
- Which records owe a local notice, and to whom, is the model's choice, as is
  the delivery ID: generation, sequence number and recipient.
- An outbox slot's target is the object a record acts on, and every record on
  a call shares the call's slot. §5.7 gives the rule and not the table.
- "A stale-checkpoint refusal" in §5.7 rule 3 is read as `expired` or
  `unknown_anchor`.
- `history_unavailable` stops the client from composing anything until the
  suspicion is cleared from outside the model. `duplicate_mismatch` on an
  intent the client itself stored marks it reconciliation-required.
- Within one activation a register value must carry a higher counter than
  the cached one. A value naming a writer revision that does not exist yet is
  refused as having no activation.
- Only `history_unavailable` raises the suspicion of a rollback. This
  document does not say what a client that has been told `revoked` may still
  compose before it has replayed its own revocation, and the model lets it.
  That needs a rule.
- A view file that carries a higher sequence number than the store would
  give it, but not one beyond the checkpoint, is left in place by projection
  and refused when it is read.
- A sender is not notified of its own record, an actor that is no longer
  live is not notified, and an operator's record on a call notifies both
  participants.

### 14.5 Draft v7: the enrollment rules

Draft v7's rules are in the checker and the models. What changed in the
code:

- State holds the root key, each credential's two keys and a tombstone for
  every revoked operator key. The key reservation of §6.1 is computed from
  those, not stored a second time, and the coherence check requires every key
  to hold exactly one role.
- `line_init` names the root key. Enrollment carries the two keys and the
  request digest. A key that has held any role is refused in every role.
- The sequencer model tells a revoked operator key that it is revoked and a
  never-authorized one that it is unknown, which replaces the last rule
  listed in §14.3.
- A register value carries its incarnation.
- The outbox marks an intent reconciliation-required after a persistent
  admission error, and leaves it pending only after a transient one.

What the code does not hold, and why:

- The derivation of `cred_id` is a hash. A record states whether its
  identifier is that derivation, the way it states whether its signature
  verifies. Nothing is computed.
- The creation descriptor, its digest and the profile digest are not
  modelled. The models are handed a line identity and a profile, which stands
  for provisioning; they do not check `line_init` against them.
- Proof of possession is a premise: a signature is a boolean, and a query or
  an anchor request names its principal.
- How a new member gets its starting state (O25) is not modelled. The client
  model still replays from genesis.
- The client's give-up policy after transient errors is not modelled. The
  model sends only when a test tells it to.

Vectors A174 to A211 and traces T40 to T42 were added, and vectors that
already existed were changed where the rules changed: enrollment records and
credential state carry keys, `line_init` names a root key, and a revoked
operator key leaves a tombstone in A120's result. No expected outcome
changed. The vectors file lists each one.

Measured on 2026-11-23, after the change:

- **209 of 209 active vectors agree, and all 42 traces have a test:** 27
  against the sequencer model, 8 against the client model, 4 against the
  register model, and 3 as a plain sequence of transitions. Every test passed
  on its first run. As before, that is weak evidence, because the rules, the
  vectors, the code and the tests have one author.
- **Mutation check: 57 hand-chosen breaks of the new rules, 57 caught.** It
  is weaker than the earlier checks in one respect: the breaks were chosen by
  the person who had just written the tests, and two of the tests (a full
  quota and an uncertain clock leave an intent pending) were written before
  the run because those breaks were expected to survive.
- The two earlier sets were run again against the changed code. Of the 102
  breaks of the transition function, 101 are caught and one no longer
  applies: it removed the check that a key is not already authorized, which
  the key reservation replaced. Of the 50 breaks of the sequencer model, 49
  are caught and one no longer applies, for the same reason: the standing it
  changed no longer exists. Both have successors among the 57, and both
  successors are caught.
- `go vet` and `go test -race` pass for the package.
- **Codex made a bounded check of this change** (call 0003, turn 5). It ran
  five of the tests, and an independent probe through the exported interface
  of six rules: the root key's reservation, one key in both enrollment roles,
  the stated derivation mismatch, both keys still reserved after a
  revocation, no second authorization of an operator key, and the answer to
  a second revocation. All passed. Its review changed three statements and
  no rule; they are listed at the top of this document.
- **The client and register models have had no probe by Codex.** Each time
  before, such a probe found defects after every check above was green.
  Their own mutation check is reported in §14.4.

Rules this change forced that had not been stated, each needing review:

- One key named as both the signing and the encryption key of an enrollment
  is malformed.
- `line_init` without a root key is malformed, and on an empty log that makes
  it invalid bootstrap input with nothing recorded.
- An enrollment whose `cred_id` equals an existing one although both keys are
  new is `conflict`. With a sound derivation it cannot happen; the identifier
  is checked on its own so that the rule does not rest on that.
- Revoking an operator key that is already revoked is `unknown_target`, the
  same as revoking one that never existed.
- A principal that is neither a credential, an operator key nor the root is
  refused like an unknown signer.
- A register value with the current writer revision and a different
  incarnation is refused as `wrong_incarnation`, checked after the binding,
  so a new owner that has not activated still hears "no activation".
- Which admission errors are transient is a short list in the model:
  overload, exhausted quota, uncertain clock. Everything else is persistent,
  including "no line here", "another line" and any code the model does not
  know.

### 14.6 Index of intent

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

Enrollment and keys (draft v7):

37. Enrollment whose `cred_id` is not the derivation of its two keys, or that
    names one key twice: `invalid`. Enrollment with a key that has held any
    role before, in a live or revoked credential, as an operator key or as
    the root key: `conflict`, whatever its partner.
38. `operator_key_authorize` for a revoked operator key, a credential's key
    or the root key: `conflict`. A new intent, a retry or a query from a
    revoked operator key: `revoked`, with nothing about its earlier
    operations. From a key that never was one: refused as an unknown signer.
    An active principal reconciles the revoked key's history by query.
39. `actor_move` of an actor disabled by its credential's revocation:
    `unknown_target`.
40. A required expectation left out: `invalid`, also where the current value
    is 0, and before any authorization check.
41. Register value naming the current writer revision and another
    incarnation: rejected. A fresh activation takes precedence with its
    counter starting over.
42. An intent answered "unknown signer": not sent again, not closed, slot
    held until an authorized principal reconciles it.

The threat model's fault scenarios and the security review's fixtures that
concern resources, offers, fences and enrollment substitution belong to §12
and to Codex's documents respectively.

## Appendix A. What this document requires from the enrollment, control-bootstrap and envelope design

Added 2026-11-23 at Codex's request, as input to its draft and to the
cross-review of it. The rows were brought in line with draft v7 the same day,
and A.8 records where each question of A.7 stands. The appendix itself
changes no rule. Each row restates something a numbered
section already says or depends on, and cites it; if a row and its section
ever differ, the section governs and the row is wrong. Where this document is
silent the point is an open question in A.7, not a rule. No construction,
cipher, library, ceremony or deployment is selected or implied, and nothing
here authorizes implementation.

Setting up a line (A.1) and joining one (A.2, A.3) are kept apart because
their trust inputs differ. At setup nothing exists to verify against. A
joining member has a line whose control state it must establish without that
line's message history.

### A.1 Root and genesis setup

| # | The state machine depends on | From |
| --- | --- | --- |
| G1 | A `line_id` that does not depend on any local path. | §2 |
| G2 | A genesis constant derived from the line identity, the root key and the digest of the root-signed creation descriptor. The relay is provisioned with that descriptor before any record exists, so genesis is fixed in advance. `line_init` names it as its anchor, names generation 1 and the root key, and commits the descriptor's digest and the profile. One that names a different genesis is answered `unknown_anchor`; one that states other contents under the right genesis is refused as invalid bootstrap input. | §4.4 |
| G3 | `line_init` is root-signed, exempt from validity but not from its context, and commits only into an empty log. The first record of an empty log can only be `line_init`; a replaying client treats anything else there as a sequencer violation. A malformed or wrongly signed `line_init` is refused with nothing recorded, and is never answered "a line exists". | §4.4, §6.2 |
| G4 | After `line_init` the line has generation 1, `root_rev` 1, `auth_epoch`, `audience_rev` and `key_epoch` at 0, no operators, no credentials, and `rekey_pending` set. Nothing payload-bearing commits until at least three more records have: a root `operator_key_authorize`, an operator `credential_enroll` that grants reader capability (an activation's manifest is a required list and must equal the entitled readers), and an operator `key_epoch_activate`. | §5.8, §6.2, §6.3 |
| G5 | Every root record other than `line_init` and `recovery_generation` uses the ordinary envelope and ordinary validity. The root key therefore signs from a verified checkpoint, anchored on the generation's first record or a later anchor, inside a validity window whose provisional maximum is 10 minutes. Root may request an anchor over an authenticated session. | §4.2, §4.4, §5.3, O10 |
| G6 | `operator_key_authorize` and `operator_key_revoke` sign `expect.root_rev`. Each increments `root_rev` and `auth_epoch`. | §6.2 |
| G7 | An operator record is a guarantee only if the operator key cannot be used by a process running as the operator's OS user without an authorized, action-scoped approval in which the operator sees the actual action and what the payload means. The signed intent carries an action scope that must match the record type and target. | §3, §7.3 item 9, §10.2 |
| G8 | The freshness window `F` and the maximum validity are protocol profile data, committed in `line_init` and never chosen by the relay per request. The profile is fixed for a whole generation, and its digest is signed in every intent. A replaying client reads `F` from the chain to check `time_anchor` spacing. | §4.2, §4.4, §5.1, §5.6 |

### A.2 Enrolling a credential

| # | The state machine depends on | From |
| --- | --- | --- |
| E1 | A credential is a signing key and an encryption key controlled by one isolation domain, and its `cred_id` is derived from the two together. `credential_enroll` is operator-origin. Its visible fields carry the join-request ID and the digest of the join request, the credential ID, the two public keys, and the grant: `namespace_id`, the limit on live actors (zero or more), whether the credential holds reader capability, and capabilities. A `cred_id` that is not the derivation of the two keys is syntactic `invalid`. | §3, §5.8, §6.1, §6.2, §10 |
| E2 | An enrollment reserves four things for life, and the sequencer checks each on visible fields alone: the join-request ID (never used), each of the two keys (never held any role on the line: not in a live or revoked credential, not as an operator key, not as the root key), the `cred_id` (never re-enrolled), and the `namespace_id` (never granted before). Each reservation must survive recovery. | §3, §6.1, §6.2 |
| E3 | It follows that a machine whose keys are lost or replaced cannot return as the same credential or into the same namespace. It joins as a new credential with a new namespace. Its existing actors keep their identity only if the operator moves them with `actor_move`, and the move must commit before the old credential is revoked: revocation disables every actor bound to it, and a move needs a live actor. The new credential controls the moved actors and cannot declare siblings in their namespace. Once the old credential is revoked nobody can, because a namespace is never granted twice. | §3, §6.1, §6.2 |
| E4 | Namespace grant, reader capability and authority to sign as operator are three separate grants. A grant with an actor limit of zero and reader capability is valid; it is the natural shape for an operator's own device. | §6.1 |
| E5 | `credential_enroll` is an ordinary operator intent. It signs the current `auth_epoch`, an anchor and a validity. Committing it increments `auth_epoch` and sets `rekey_pending`, so every intent in flight that was signed under the old epoch is rejected `conflict`, and nothing payload-bearing commits until the next `key_epoch_activate`. | §5.1, §5.8, §6.2, §6.3 |
| E6 | The sequencer does not check that the joiner holds the private keys, that the join request came from the machine the operator meant, or that the grant is what the operator intended. Field contents, proofs of possession and ceremony are the enrollment design's. The state machine needs only that the result is an operator-signed record whose visible fields it can check as in E2. | §6, §6.2 |

### A.3 What a new member starts from

| # | The state machine depends on | From |
| --- | --- | --- |
| M1 | A new member receives no earlier epoch. Enrollment sets `rekey_pending`; the next `key_epoch_activate` must name exactly the entitled readers as of its commit; and phase 1 has no record that adds a credential to the readers of an earlier epoch. Nothing wraps an old epoch key to a new member. | §0, §6.3, trace T20 |
| M2 | Control state needs no payload keys. Every authorization and transition predicate is over sequencer-visible fields, so a member can verify control records and re-derive each committed outcome for stretches of the log whose payloads it cannot read. A payload under an epoch the reader holds no key for is one of three distinct reader states, and it does not stop replay. | §2, §10, §10.2, trace T24 |
| M3 | Before it signs anything, a member needs a verified, durably stored checkpoint `(seen_seq, seen_head)` with the accepted `seq_time` at that sequence. The checkpoint never regresses and is shared by every session of the credential. Its first intent anchors on a record of the current generation, never on genesis, that is fresh enough; in practice it requests an anchor first, which it may do once enrolled. | §4.2, §4.4, §5.1, §5.3, §14.3 |
| M4 | What it must hold to act correctly is the whole derived state at that checkpoint, not only current membership: `generation`, `root_rev`, `auth_epoch`, `audience_rev`, operators, credentials with their grants, `key_epoch`, `rekey_pending`, the readers of the current epoch, every actor's namespace, binding, `binding_gen`, `addr_rev`, addressability and liveness, register writer state including incarnations already used, the tombstone sets, and the state of every call and broadcast. Calls and broadcasts matter because expected versions refer to them. Tombstones and used identifiers matter because re-deriving a later committed create needs to know the identifier was unused. | §2, §5.1, §6.1, §7.1, §8 |
| M5 | A new member's operation identities cannot collide with anyone else's, because identity includes the signer, the generation and the anchor. It starts with an empty outbox and nothing to reconcile. | §5.1, §5.6, §5.7 |
| M6 | The member declares its own actors with `actor_declare`, inside its granted namespace and capacity; no existing binding is needed. Declaring increments `audience_rev` and leaves `auth_epoch` alone. A declaration with an encrypted label is payload-bearing, so it waits for the member's first epoch; one without a label does not. | §3, §6.1, §6.2, §6.3 |

How M3 and M4 are established is not stated in this document: see Q5.

### A.4 The intent envelope

| # | The state machine depends on | From |
| --- | --- | --- |
| V1 | The signature covers at minimum the fields of §5.1: version; the profile digest; `line_id` and `generation`; the origin and the tagged signing principal; `actor_id` and `binding_gen` for actor origin; `op_id`; `op_type` and `target`; `expect`; `auth_epoch`; `key_scope` and `key_epoch`; `seen_seq` and `seen_head`; `validity`; `payload_commit`; and every field on §10's allowlist for the record type. Operator and root intents also sign their action scope. | §3, §5.1, §10 |
| V2 | The signature is verified over the exact bytes received. A client stores the serialized intent durably before the first send, and every retry sends those bytes. Two submissions are the same operation content when a digest of the intent is equal. | §2, §5.5, §5.7 |
| V3 | Operation identity is `(line_id, generation, signing principal, seen_seq, op_id)`, where the principal is a credential, an operator key or the root, each kind in its own space. An `op_id` is unique only within its anchor. Different bytes under one identity are `duplicate_mismatch` until the anchor retires; after that an identity that never committed is `expired`, and one that committed still returns its receipt. A later anchor makes a different operation by definition, and a client never chooses one to refresh an unresolved intent. | §5.1, §5.5, §5.6, §5.7 |
| V4 | Anything derived per operation must bind the full context: line, generation, signer, anchor and operation identity, with the relevant scope and epoch. Different plaintext under the same identity is a hazard that arises before sending, and dedup at the relay cannot cure it. | §5.6 |
| V5 | Binding generations. An actor-origin intent names `(actor_id, binding_gen)` and is authorized only while that is the current binding to the signing credential and the actor is live. `actor_move` increments `binding_gen` and `auth_epoch`, which invalidates intents pending under the old binding. A register value signs `binding_gen` and `writer_rev`, and an activation belongs to the binding generation that made it. | §3, §6.2, §9 |
| V6 | Expected versions are signed, visible, and defined per record type: `root_rev`; `key_epoch`; `binding_gen`; `addr_rev`; `writer_rev`; `turn_count`; `lifecycle_rev`; a dispute's `rev` and the signer's own `measure_rev`; and `audience_rev` for a default-audience broadcast. A value that is not current is `conflict`. Zero is a real expected value: the first `key_epoch_activate` expects `key_epoch` 0, and a new call's `lifecycle_rev` is 0. See Q10. | §5.1, §5.8, §6.2, §7.2, §8 |
| V7 | Every counter, revision, epoch, sequence number and time is an integer in `[0, 2^53 - 1]`. The decoder rejects a fraction or an out-of-domain value before any lossy conversion. | §5.9 |
| V8 | Decode is bounded before any processing. Unknown versions are refused and never downgraded; unknown or unsupported fields and scopes are refused; there is no application compression in the first profile; and the whole encoded record has a size bound that also bounds recipient arrays, signatures and manifests. | §2, §5.1, §10, §10.1 |
| V9 | The envelope keeps the line between refusing input and rejecting an operation. Bad framing, an unknown version or field, an oversized transport envelope, a bad signature and an unknown credential are admission errors: nothing is recorded and nothing is promised. A decoded, in-bound, attributable intent with a value outside its allowed set, or content over a record-specific limit, is admitted and durably rejected `invalid` or `too_large`. | §2, §5.4, §5.8 |
| V10 | `payload_commit` is the digest and length of the encrypted payload. A ciphertext-free record still signs it, over an empty payload. A payload-bearing record commits only with `key_scope` the line scope, `key_epoch` current and `rekey_pending` clear. Line ciphertext on a type declared ciphertext-free is syntactic `invalid`. Record-specific size limits are judged by the sequencer on what the record states. | §5.1, §5.8, §6.3, §10.1 |
| V11 | A reader can tell three cases apart: no key for the epoch; authentication or decryption failure; authenticated but malformed plaintext. None stops replay, and the second is never reported as the writer's fault. | §10.2 |
| V12 | Everything not on §10's allowlist for a record type is ciphertext: subjects, bodies, reasons, claims and measurements, attachment names and content, actor labels, the writer's tip claim and register bodies. Secrets stay out of URLs, logs, error strings and unencrypted registers. | §10 |

### A.5 Key epochs and wraps

| # | The state machine depends on | From |
| --- | --- | --- |
| K1 | `key_epoch_activate` is operator-origin, signs `expect.key_epoch`, and carries a manifest of credential IDs with one wrap commitment each. It commits only if the manifest names exactly the entitled readers as of commit: enrolled, unrevoked credentials granted reader capability. Omitting one, naming a revoked credential, naming one without reader capability, a duplicate entry, or an empty manifest is rejected. | §5.8, §6.1, §6.2, §14.1, §14.6 item 18 |
| K2 | The sequencer checks completeness over visible fields only. It cannot check that a wrap decrypts, that the key is right, or that the epoch key is fresh. Each client verifies its own wrap. A garbage wrap or an undecryptable body from an authorized writer is denial of service and must not stop replay. | §6.3 |
| K3 | Confidentiality after a rotation depends on the generating client creating a fresh epoch key and verifying the distribution context. A reused epoch key, or a wrap to a recipient the manifest does not declare, preserves or exposes access, and the relay can detect neither. | §6.3 |
| K4 | Membership and key-distribution records carry no line-scope ciphertext, only visible fields and per-recipient wraps, and they commit while `rekey_pending` is set. | §6.3 |
| K5 | No record re-distributes the current epoch. The only repair for a bad or missing wrap is another `key_epoch_activate`, which makes a new epoch. Activation does not require `rekey_pending` to be set, so an operator can rotate at any time. | §6.2 |
| K6 | Removing a reader does not recall plaintext or keys already learned. | §6.3 |
| K7 | Register bodies obey the same epoch and rekey checks. A register value signs namespace, `line_id`, `generation`, `actor_id`, `cred_id`, `binding_gen`, `writer_rev`, the incarnation of its activation, `key_epoch` and counter. | §6.3, §9 |

### A.6 Sessions, anchors and answers

| # | The state machine depends on | From |
| --- | --- | --- |
| S1 | `anchor_request` is not an intent. It is served over an authenticated session to an enrolled, unrevoked credential or a currently authorized operator or root principal, and that authorization is re-checked inside the serialized step that answers it. A session authenticated before a revocation is not enough. | §4.2 |
| S2 | A sequencer-origin record carries no signature and is accepted only over authenticated relay transport. A valid hash chain alone authenticates neither origin nor freshness. | §2 |
| S3 | `head` covers the previous head, the signed intent bytes and every sequencer-assigned field. `seen_head` in an intent is that value. | §2, §5.1 |
| S4 | Durable rejections and no-ops are trusted relay decisions. They are authenticated to the client under the relay boundary and cannot be re-derived from the chain. | §5.4 |
| S5 | A query is signed, carries an operation identity and a digest and not the bytes, and is answered only to a requester authorized to learn that outcome. A query authenticated only by a revoked key, a credential's or an operator's, is refused with `revoked`, and only after that key's possession is shown; a key that never held the role is refused without that distinction. An active, separately authorized principal may reconcile a revoked signer's history by signing a query that names the original operation and digest. | §5.5 |
| S6 | Request authorization, input bounds and rate limits are required for anchor requests and submissions, and each credential has a bounded quota of durable rejections and no-ops. The quota is per credential, so the principal is authenticated before it is charged. A rate-limit answer never implies non-commit. | §4.2, §5.4 |
| S7 | A submission arrives on a session authenticated as the principal that signed it. Standing, quota and the `revoked` answer are all judged for that principal, so a signed intent in someone else's hands cannot be submitted by them. | §5.4, §5.5 |

Recovery is outside this appendix. It touches enrollment in one place: the
tombstones of E2 must survive it (§3, §6.2).

### A.7 What this document leaves open

"Whose" names who writes the answer down. It does not name who decides.

| # | Question | Why the state machine cares | Whose |
| --- | --- | --- | --- |
| Q1 | How does a relay come to hold the line identity and root key it checks the first record against, and who may create a line on a relay? | G2 and G3 assume the relay already has them. The reference model stipulates them. | Codex, with deployment |
| Q2 | Where does the profile live? "Authenticated configuration" is not defined here. | §4.2 says a replaying client can check `time_anchor` spacing from the chain alone. That holds only if `F` is committed in the chain, for instance in a generation's first record, or reaches the client by an equally authenticated path. | Fable, once the content of `line_init` is drafted |
| Q3 | Can the root key meet an ordinary validity window? | G5 needs the root key to catch up to a fresh head and sign within minutes for every operator-key change. If the root key is to be kept offline, either that is workable in practice or these records need a validity rule this document does not have. | Codex to frame; an operational choice for the operator |
| Q4 | Operator key lifecycle (O22). | State keeps no history of operator keys. As written, a revoked operator key could be authorized again, and a key outside the active set cannot be told apart as revoked or never authorized. | Codex |
| Q5 | What is the trust basis for a new member's first checkpoint and state (M3, M4)? Either the member replays every control record from genesis, or it starts from an authenticated checkpoint with state. | Replay from genesis needs only the trust pins, but grows with the line's age and requires the relay to serve the whole log; the operator's stated reason for giving new members no history was its length. A checkpoint is short but needs someone to vouch for it and a rule against a stale one. In either case `head` covers the signed intent bytes, so whether the chain can be verified without downloading ciphertext depends on whether those bytes contain the payload or only `payload_commit`. | Codex; the choice may need the operator |
| Q6 | How does `cred_id` relate to the two keys, and can a credential's keys ever be replaced? | E2 needs "neither key enrolled or tombstoned" to be decidable from visible fields. The reference checker models a credential as one identifier. Phase 1 has no key-replacement record, which is what makes E3 the only path after a lost key store; that should be confirmed as intended. | Codex |
| Q7 | Who checks proof of possession? | If only the operator's client does, the state machine is unchanged. If the sequencer does, the failure needs a place: an admission error or a durable `invalid`. The ladder in §5.8 has no rung for it. | Codex, then Fable for §5.8 |
| Q8 | What does a join request bind? | This document knows only its identifier. Whether it is bound to the line, the joining keys and the grant asked for decides whether a consumed or copied request can be turned into a different enrollment. | Codex |
| Q9 | Which bytes does the intent digest cover: with or without the signature, with the payload or only its commitment? | The digest decides `duplicate_mismatch`. If re-signing the same intent can yield different bytes, a re-signed retry is a mismatch. That is safe, but then "store the bytes, never re-sign" must be a stated client rule and not only a consequence. | Codex |
| Q10 | What is an intent that omits a required expectation? | This document does not say in words. The reference checker rejects it as syntactic `invalid`. Because zero is a real expected value (V6), the encoding must be able to tell an expectation of zero from no expectation. | Fable for §5.8; Codex for the encoding |
| Q11 | What is the signer in an operator or root operation identity? | §5.1 writes `cred_id`. The reference model uses the signing principal, with each operator key and the root having its own identity space. §5.1 should say so, and the action-scoped approval design should confirm it fits. | Fable for §5.1; Codex to confirm |
| Q12 | The client that generates an epoch key holds it. | §6.1 separates authority to sign as operator from reader capability. That separation is of grants. It does not keep an epoch key from the operator device that created it, whether or not that device is an entitled reader. Under 3A this may be acceptable; it should be stated and not left implicit. | Codex |
| Q13 | Which visible quantity do the size limits apply to? | §10.1 states limits for plaintext and for total ciphertext, and the sequencer sees only what the record states about ciphertext. The mapping waits on framing overhead. | Codex and Fable (O4) |
| Q14 | Do queries carry an anchor or a validity, and what binds an answer to its question? | S4 and S5 assume answers are authenticated "under the relay boundary" and say no more. §4.2 argues against a relay signing key for time; that does not settle it for answers. | Codex |
| Q15 | Does `seq` restart in a new generation (O23)? | `seen_seq` is part of operation identity and of every derivation in V4. | Codex, with recovery |
| Q16 | Is an actor whose credential was revoked gone for good? | §3 and §6.2 say revocation disables the credential's actors, and `actor_move` needs a live actor. The reference checker implements that as terminal, which is what E3's ordering rests on. No vector pins it. | Fable: add a vector once confirmed |

### A.8 Where each question stands

As of 2026-11-23, after Codex's drafts v1 to v3
([LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md](LDR-ENROLLMENT-BOOTSTRAP-ENVELOPE.md),
proposals P1 to P9) and the cross-review on call 0003. "Agreed" is
design-review agreement between two agents. Nothing in this table is operator
approval, and no row rests on a cryptographic test.

| # | Stands | Where |
| --- | --- | --- |
| Q1 | Agreed in direction: the relay is provisioned with the creation descriptor before the first record (P1). Who may provision a line, and how that is authenticated, depends on the deployment and is open. | §4.4 |
| Q2 | Closed in this document: the profile is committed in `line_init`, and its digest is signed in every intent (P1). | §4.4, §5.1 |
| Q3 | **Open, the operator's (O26).** Root records keep ordinary validity. Whether a protected or offline root key can sign in time needs a dry run. | §4.4, §13 |
| Q4 | Agreed: operator-key tombstones, no re-authorization, `revoked` only after possession is shown (P8). | §5.4, §6.2 |
| Q5 | **Open, the operator's (O25).** Codex proposes a complete-state attestation by the enrolling operator's device, with root- and operator-signed authority evidence, and a verified suffix (P4). The signed envelopes show signed intent; they do not show commit, completeness or currency. The attestation is a trust exception in favour of that operator's verified store, not a re-derivation from the root, and a compromised or rolled-back attesting device remains a limitation. Replay from genesis is the alternative. Codex withdrew an earlier relay-attested variant after this review found that it let a relay invent a line for a joiner. Draft v2 adds the case this review raised: an attestation has no position in the log, so if the records the joiner verifies revoke the attesting operator before the joiner has accepted its state, the joiner stops and keeps the candidate state aside, and a currently authorized, independently pinned operator attests afresh for the same credential. That is not a second `credential_enroll`. The check covers every record up to and including the head the joiner's fresh anchor names; a revocation after that head follows the ordinary rules, and one the relay withholds is still not seen (draft v3). | Codex's draft §4; §13 |
| Q6 | Agreed: `cred_id` is derived from the two keys; neither key is replaced; each key is reserved for life across roles (P2). | §3, §6.1, §6.2 |
| Q7 | Agreed: the operator's tooling checks possession; the sequencer has no rung for it (P3). | §6.2 |
| Q8 | Agreed in direction: the join request binds the line, both keys, the grant and a request ID, and its digest is a visible field of the enrollment (P3). The ceremony itself is Codex's and is not reviewed here beyond that. | §6.2, §10 |
| Q9 | Agreed: the digest covers the signed envelope including the signature, and the payload only through its commitment; a client never signs an intent twice (P5). | §5.1, §5.7 |
| Q10 | Closed in this document: an absent required expectation is syntactic `invalid`. The encoding that tells absent from zero is Codex's (P6). | §5.8 |
| Q11 | Closed in this document: the signer in an operation identity is the tagged signing principal. For an operator key or the root, the principal names the key's own normalized value, not a separate identifier (Codex's draft v2, §2). | §5.1, §6.1 |
| Q12 | Agreed, as a stated limit: the device that generates an epoch key holds it, so it must be an enrolled reader (P9). The relay cannot check that. | Codex's draft §6 |
| Q13 | Open: waits on the chosen cipher suite and its framing overhead. | §10.1 |
| Q14 | Agreed in direction: queries and anchor requests are bound to a fresh session challenge, not to an anchor or a validity, and answers are bound to their request (P7). The transport mechanism is not chosen. | Codex's draft §7 |
| Q15 | Open, with recovery (O23). Coordinates are generation-qualified meanwhile. | §5.9 |
| Q16 | Closed in this document: terminal. A vector pins it (A194). | §3, §6.2 |
