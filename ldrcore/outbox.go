package ldrcore

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The outbox is the client discipline of spec section 5.7. It does not make a
// human action exactly-once: two independently worded requests are two
// operations, and nothing here can recognize them as one intention.
//
// The rules it holds to:
//
//  1. An intent is stored, with the action it came from, before it is first
//     sent. Every send transmits those stored bytes; nothing in this file can
//     alter them or give them a new anchor.
//  2. At most one unsettled intent per slot. A slot is (acting identity,
//     target): the actor for an actor-origin record, the credential, operator
//     key or root otherwise. This is client policy, not the wire identity.
//  3. After a restart, or after a refusal that says the checkpoint was stale,
//     every stored intent is asked about before anything new is composed.
//  4. Only a durable outcome or a definitive refusal settles an intent.
//  5. A refusal that resolves nothing marks the intent as needing
//     reconciliation. Nothing here sends it again, and it keeps its slot. The
//     same holds for an admission error that waiting does not remove, such as
//     an unknown signer or a code this client does not know. Its cause may be
//     corrected later, but the refusal says nothing about what became of the
//     operation: it is neither a reason to retry nor a non-commit. A query
//     may still settle the intent. This model has no way to resume sending.
//  6. The result is stored with the action that caused it.
//  7. A key that is revoked signs and submits nothing more, and makes no other
//     request with that key either, neither a query nor an anchor request: a
//     revoked key cannot obtain an outcome or an anchor. The client learns
//     that from an authenticated `revoked` answer, or by verifying the
//     revocation itself. Every unsettled intent the key signed keeps its slot
//     and awaits reconciliation by a principal that is still authorized. This
//     is not a suspected rollback, and other keys the device holds go on.
//     Nothing here uses another held key in the stopped key's place.
//     Proposed by Codex on call 0003; the spec had no rule.
type outbox struct {
	entries     []*OutboxEntry
	slots       map[string]string // slot -> ID of the unsettled intent holding it
	nextOp      int64             // op_ids are never reused
	mustResolve bool
	suspect     bool                // history_unavailable was seen: rollback is suspected
	told        map[string]*KeyStop // keys that were told they are revoked, with the evidence
}

// KeyStop reports one key of this device that signs nothing more, and why.
type KeyStop struct {
	Key string
	// Verified: the records this client has verified revoke the key.
	Verified bool
	// Told: an authenticated `revoked` answer about the key was accepted.
	// Answer is the first such answer, and Seq and Head are the client's
	// checkpoint when it arrived. They are evidence for whoever looks into
	// it, and nothing alters them afterwards. They stand in for more than
	// they are: real evidence is the authenticated response with what binds
	// it to the request, the line and the key, and this is no audit trail.
	//
	// Told without Verified is a discrepancy to report, not a verdict. The
	// records verified so far may simply end before the revocation, and a
	// later head does not say which head the answer spoke of. The stop
	// stands either way: this model has no procedure that lifts one.
	Told   bool
	Answer Answer
	Seq    int64
	Head   string
}

// Outbox entry states.
const (
	// OutPending: stored and unresolved. It may be sent again, always as the
	// same bytes.
	OutPending = "pending"
	// OutDone: a durable outcome is stored.
	OutDone = "done"
	// OutClosed: a definitive refusal. It did not commit and never can.
	OutClosed = "closed"
	// OutReconcile: whether it committed is not established. The client has
	// stopped sending it, and it is never grounds for repeating the action.
	OutReconcile = "reconciliation_required"
)

// OutboxEntry is one stored intent and what became of it.
type OutboxEntry struct {
	ID     string // the op_id
	Action string // the application action it came from
	Slot   string
	Intent Intent
	Status string
	Result Answer // the last answer received
	Sends  int
}

// Errors Compose can return. Each means no intent was built.
var (
	// ErrSlotBusy: an unsettled intent already holds this slot.
	ErrSlotBusy = errors.New("ldrcore: an unresolved intent already holds this slot")
	// ErrMustResolve: stored intents have not been asked about since a
	// restart or a stale-checkpoint refusal.
	ErrMustResolve = errors.New("ldrcore: stored intents must be resolved by query before composing")
	// ErrFailClosed: the client saw a sequencer violation or suspects a
	// rollback, and signs nothing until that is cleared from outside.
	ErrFailClosed = errors.New("ldrcore: the client has stopped signing")
	// ErrNotSigner: this device does not hold the key the record needs, or
	// the actor is not bound to this credential in verified state.
	ErrNotSigner = errors.New("ldrcore: this client cannot sign that record")
	// ErrNoLine: nothing but line_init can be composed without a verified
	// record to anchor on.
	ErrNoLine = errors.New("ldrcore: no verified record to anchor on")
	// ErrKeyRevoked: the key this record needs was told it is revoked, or the
	// verified records revoke it. It is not ErrFailClosed: other keys on this
	// device may still sign.
	ErrKeyRevoked = errors.New("ldrcore: this key is revoked and signs nothing more")
)

// principalOf names the key a record of this origin would be signed with on
// this device.
func (c *Client) principalOf(origin string) string {
	switch origin {
	case OriginActor, OriginCredential:
		if c.Cred == "" {
			return ""
		}
		return CredentialPrincipal(c.Cred)
	case OriginOperator:
		if c.OperatorKey == "" {
			return ""
		}
		return OperatorPrincipal(c.OperatorKey)
	case OriginRoot:
		if c.RootKey == "" {
			return ""
		}
		return RootPrincipal(c.RootKey)
	}
	return ""
}

// revokedInRecords reports whether the records this client has verified
// revoke or replace principal p.
func (c *Client) revokedInRecords(p string) bool {
	l := &c.state.Line
	switch {
	case strings.HasPrefix(p, "cred:"):
		cr := l.Credentials[strings.TrimPrefix(p, "cred:")]
		return cr != nil && cr.Revoked
	case strings.HasPrefix(p, "op:"):
		return slices.Contains(l.Tombstones.OperatorKeys, strings.TrimPrefix(p, "op:"))
	case strings.HasPrefix(p, "root:"):
		return slices.Contains(l.Tombstones.RootKeys, strings.TrimPrefix(p, "root:"))
	}
	return false
}

// signsNoMore reports whether principal p has stopped: it was told it is
// revoked, or verified state shows its revocation.
func (c *Client) signsNoMore(p string) bool {
	return c.out.told[p] != nil || c.revokedInRecords(p)
}

// toldRevoked records that an authenticated `revoked` answer about principal
// p was accepted, and stops the key. The first such answer is kept with the
// checkpoint it arrived at; a later one does not replace it.
func (c *Client) toldRevoked(p string, a Answer) {
	if c.out.told[p] == nil {
		c.out.told[p] = &KeyStop{Key: p, Told: true, Answer: a, Seq: c.ckSeq, Head: c.ckHead}
	}
	c.suspend(p)
}

// suspend marks every pending intent that principal p signed as awaiting
// reconciliation: it cannot be sent again under this key, and nothing here
// says whether it committed. Each keeps its slot and the last answer it
// actually received, which for an intent never sent is none.
func (c *Client) suspend(p string) {
	for _, e := range c.out.entries {
		if e.Status == OutPending && signerOf(&e.Intent.Record) == p {
			e.Status = OutReconcile
		}
	}
}

// stopRevoked suspends the intents of each key of this device that has
// stopped. Sync calls it, so that verifying a revocation has the same effect
// as being told of it.
func (c *Client) stopRevoked() {
	for _, p := range c.Stopped() {
		c.suspend(p)
	}
}

// deviceKeys names the keys of this device that can be revoked or replaced.
func (c *Client) deviceKeys() []string {
	var out []string
	if c.Cred != "" {
		out = append(out, CredentialPrincipal(c.Cred))
	}
	if c.OperatorKey != "" {
		out = append(out, OperatorPrincipal(c.OperatorKey))
	}
	if c.RootKey != "" {
		out = append(out, RootPrincipal(c.RootKey))
	}
	return out
}

// Stopped returns the keys of this device that sign nothing more.
func (c *Client) Stopped() []string {
	var out []string
	for _, p := range c.deviceKeys() {
		if c.signsNoMore(p) {
			out = append(out, p)
		}
	}
	return out
}

// Stops reports why each stopped key stopped, with the evidence kept for it.
func (c *Client) Stops() []KeyStop {
	var out []KeyStop
	for _, p := range c.Stopped() {
		s := KeyStop{Key: p}
		if t := c.out.told[p]; t != nil {
			s = *t
		}
		s.Verified = c.revokedInRecords(p)
		out = append(out, s)
	}
	return out
}

func (o *outbox) unsettled() int {
	n := 0
	for _, e := range o.entries {
		if e.Status == OutPending || e.Status == OutReconcile {
			n++
		}
	}
	return n
}

func (o *outbox) find(id string) *OutboxEntry {
	for _, e := range o.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Outbox returns a copy of the stored intents, oldest first.
func (c *Client) Outbox() []OutboxEntry {
	out := make([]OutboxEntry, len(c.out.entries))
	for i, e := range c.out.entries {
		out[i] = *e
		out[i].Intent.Record = e.Intent.Record.Clone()
	}
	return out
}

// acting fills in the signer fields of r from verified state and returns the
// acting identity of its slot.
func (c *Client) acting(r *Record) (string, error) {
	switch r.Origin {
	case OriginActor:
		a := c.state.Line.Actors[r.Actor]
		if a == nil || !a.Live || a.Cred != c.Cred {
			return "", ErrNotSigner
		}
		r.Cred, r.BindingGen = c.Cred, a.BindingGen
		return "actor:" + r.Actor, nil
	case OriginCredential:
		if r.Cred != "" && r.Cred != c.Cred {
			return "", ErrNotSigner
		}
		r.Cred = c.Cred
		return "cred:" + c.Cred, nil
	case OriginOperator:
		if c.OperatorKey == "" || (r.Operator != "" && r.Operator != c.OperatorKey) {
			return "", ErrNotSigner
		}
		r.Operator = c.OperatorKey
		return "op:" + c.OperatorKey, nil
	case OriginRoot:
		if c.RootKey == "" || (r.RootKey != "" && r.RootKey != c.RootKey) {
			return "", ErrNotSigner
		}
		r.RootKey = c.RootKey
		return RootPrincipal(c.RootKey), nil
	}
	return "", ErrNotSigner
}

// targetOf names what a record acts on, for the slot. The target of a create
// is its creation slot. Every record on a call shares the call's slot. This
// mapping is the model's reading of "target"; the spec gives the rule and
// not the table.
func targetOf(r *Record) string {
	switch r.Type {
	case "line_init":
		return "line"
	case "operator_key_authorize", "operator_key_revoke":
		return "operator_key:" + r.OperatorKey
	case "root_member_replace":
		return "root_key:" + r.OldRootKey
	case "credential_enroll", "credential_revoke":
		return "cred:" + r.Cred
	case "key_epoch_activate":
		return "key_epoch"
	case "actor_declare", "actor_move", "actor_remove", "actor_addressing":
		return "actor:" + r.Actor
	case "register_activate":
		return "register:" + r.Actor + "/" + r.Register
	}
	if r.Broadcast != "" {
		return "broadcast:" + r.Broadcast
	}
	return "call:" + r.Call
}

func opKey(in Intent) OpKey {
	return OpKey{Generation: in.Generation, Signer: signerOf(&in.Record), SeenSeq: in.SeenSeq, OpID: in.OpID}
}

// Compose builds an intent for r from the verified checkpoint, stores it with
// the action it came from, and returns its ID. It sends nothing. The caller
// states what the record expects; the signer fields, the epochs and the
// anchor come from verified state.
func (c *Client) Compose(action string, r Record, p Payload) (string, error) {
	switch {
	case c.halted != "":
		return "", fmt.Errorf("%w: %s", ErrFailClosed, c.halted)
	case c.out.suspect:
		return "", fmt.Errorf("%w: a rollback is suspected", ErrFailClosed)
	case c.out.mustResolve:
		return "", ErrMustResolve
	case c.signsNoMore(c.principalOf(r.Origin)):
		return "", ErrKeyRevoked
	}
	r = r.Clone()
	who, err := c.acting(&r)
	if err != nil {
		return "", err
	}
	l := &c.state.Line
	gen := l.Generation
	switch {
	case r.Type == "line_init" && c.ckSeq == 0:
		gen = 1 // line_init names the generation it creates and anchors on genesis
	case c.ckSeq == 0:
		return "", ErrNoLine
	}
	slot := who + "|" + targetOf(&r)
	if _, busy := c.out.slots[slot]; busy {
		return "", ErrSlotBusy
	}
	r.AuthEpoch, r.KeyEpoch = l.AuthEpoch, l.KeyEpoch
	c.out.nextOp++
	id := fmt.Sprintf("%s-%d", c.Cred, c.out.nextOp)
	in := Intent{
		LineID: c.LineID, Generation: gen, OpID: id,
		SeenSeq: c.ckSeq, SeenHead: c.ckHead, ValidityMS: c.ValidityMS,
		// Digest stands for the digest of the exact signed bytes. It is fixed
		// here, once, with them.
		Digest:      fmt.Sprintf("bytes:%s:%s@%d", signerOf(&r), id, c.ckSeq),
		SignatureOK: true, Record: r, Payload: p,
	}
	c.out.entries = append(c.out.entries, &OutboxEntry{ID: id, Action: action, Slot: slot, Intent: in, Status: OutPending})
	c.out.slots[slot] = id
	return id, nil
}

// Send transmits a stored intent, exactly as stored. An intent that is not
// pending is not sent, and its stored result is returned: that covers a
// settled intent, one awaiting reconciliation, and so every intent of a key
// that has stopped.
func (c *Client) Send(q *Sequencer, id string, clk Clock) (Answer, error) {
	e := c.out.find(id)
	if e == nil {
		return Answer{}, fmt.Errorf("ldrcore: no stored intent %q", id)
	}
	if e.Status != OutPending {
		return e.Result, nil
	}
	e.Sends++
	in := e.Intent
	in.Record = in.Record.Clone()
	a := q.Submit(in, clk)
	c.settle(e, a)
	return a, nil
}

// settle applies one answer to a stored intent.
func (c *Client) settle(e *OutboxEntry, a Answer) {
	e.Result = a
	switch a.Class {
	case ClassOutcome:
		e.Status = OutDone
		delete(c.out.slots, e.Slot)
	case ClassRefusal:
		e.Status = OutClosed
		delete(c.out.slots, e.Slot)
		if a.Code == "expired" || a.Code == "unknown_anchor" {
			// The checkpoint this client signed from was stale. Whatever else
			// it signed from there has to be asked about first.
			c.out.mustResolve = c.out.unsettled() > 0
		}
	case ClassUnresolved:
		e.Status = OutReconcile
		switch a.Code {
		case "history_unavailable":
			// The relay knows less history than this client has verified.
			c.out.suspect = true
		case "revoked":
			// The key that signed this intent is revoked. That the answer is
			// authenticated and is about this key is a premise here. It is no
			// sign of a rollback, and it says nothing about what committed.
			c.toldRevoked(signerOf(&e.Intent.Record), a)
		}
	case ClassMismatch:
		// The relay holds other bytes under this identity. Nothing here can
		// explain that, so nothing here may act on it.
		e.Status = OutReconcile
	case ClassAdmission:
		// An admission error promises nothing, so it never closes an intent.
		// A transient one leaves it pending: the same bytes may be sent
		// again. Any other, a code this client does not know included, is
		// the relay refusing these bytes or this signer for a reason that
		// waiting does not remove. Someone may correct the cause, but the
		// client cannot tell that from the refusal, so it stops sending. It
		// is not evidence that nothing committed either, so the intent waits
		// for reconciliation and keeps its slot.
		if !transientAdmission[a.Code] {
			e.Status = OutReconcile
		}
	}
	// outcome_unknown promises nothing either: the intent stays pending.
}

// transientAdmission lists the admission errors that pass by waiting, after
// which the same bytes may be sent again. Whether and how often is client
// policy, and it must be bounded; nothing in this file sends on its own. A
// code that is not listed here suspends sending.
var transientAdmission = map[string]bool{
	"overloaded":      true,
	"quota":           true,
	"clock_uncertain": true,
}

// ResolveAll asks about every unsettled intent by query, without its bytes:
// the pending ones, and the ones awaiting reconciliation, which a query may
// still settle (spec 5.7 rules 3 and 5). It evaluates nothing at the relay,
// and it never sends. An intent the relay has no outcome for keeps the status
// it had. For one awaiting reconciliation, an answer that teaches nothing
// also leaves the stored reason in place.
//
// A key that has stopped asks nothing: a query is signed too, and a revoked
// key cannot obtain an outcome. Its intents are left exactly as they are, for
// a principal that is still authorized, and no answer is made up for them.
// That completes the pass as far as they are concerned, so they do not hold
// back the device's other keys. A key can also learn that it is revoked from
// its first query here; its remaining intents are then not asked about.
func (c *Client) ResolveAll(q *Sequencer, clk Clock) {
	incomplete := false
	for _, e := range c.out.entries {
		if e.Status != OutPending && e.Status != OutReconcile {
			continue
		}
		if c.signsNoMore(signerOf(&e.Intent.Record)) {
			continue
		}
		a := q.Query(signerOf(&e.Intent.Record), opKey(e.Intent), e.Intent.Digest, clk)
		if a.Class == ClassAdmission {
			// An admission error (such as clock_uncertain) means the relay did
			// not answer this query, so the resolve pass is not complete.
			incomplete = true
			if e.Status == OutReconcile {
				continue
			}
		} else if e.Status == OutReconcile && a.Class == ClassUnknown {
			continue
		}
		c.settle(e, a)
	}
	if !incomplete {
		c.out.mustResolve = false
	}
}

// Reconciled records the answer an authorized principal obtained for an
// intent that needed reconciliation. Only a durable outcome or a definitive
// refusal settles it, and it settles exactly as the client's own answer
// would: a refusal that says the checkpoint was stale still forces every
// other stored intent to be asked about before anything new is composed.
//
// That the answer is authenticated, and is about this operation and these
// bytes, is a premise. An Answer carries neither.
func (c *Client) Reconciled(id string, a Answer) error {
	e := c.out.find(id)
	switch {
	case e == nil || e.Status != OutReconcile:
		return fmt.Errorf("ldrcore: intent %q is not awaiting reconciliation", id)
	case a.Class != ClassOutcome && a.Class != ClassRefusal:
		return fmt.Errorf("ldrcore: %s does not settle an intent", a.Class)
	}
	c.settle(e, a)
	return nil
}

// abandonPriorGenerations marks every unsettled intent from a superseded
// generation (< newGen) as awaiting reconciliation. It keeps their slots held
// and never auto-replays them into the new generation.
func (c *Client) abandonPriorGenerations(newGen int64) {
	for _, e := range c.out.entries {
		if e.Status == OutPending && e.Intent.Generation < newGen {
			e.Status = OutReconcile
		}
	}
}

// ClearSuspicion records that a suspected rollback was looked into from
// outside this model. Nothing in the model can clear it.
func (c *Client) ClearSuspicion() { c.out.suspect = false }

// Anchor asks for a time anchor, then catches up to the head it was given and
// verifies it durably, which is what must happen before signing on it.
//
// The request is made as the credential. A refusal that says the credential
// is revoked stops it, like the same answer to a submission or a query. Any
// other refusal stops nothing: an admission error is not evidence of a
// revocation.
//
// A credential that has already stopped makes no request at all, whatever
// relay it is offered: the stop is the client's, and it does not depend on
// what one relay's state says. No other key the device holds is used in its
// place.
func (c *Client) Anchor(q *Sequencer, clk Clock) error {
	switch {
	case c.halted != "":
		return fmt.Errorf("%w: %s", ErrFailClosed, c.halted)
	case c.out.suspect:
		return fmt.Errorf("%w: a rollback is suspected", ErrFailClosed)
	case c.signsNoMore(CredentialPrincipal(c.Cred)):
		return ErrKeyRevoked
	}
	if _, _, _, a := q.AnchorRequest(CredentialPrincipal(c.Cred), clk); a.Class != "" {
		if a.Class == ClassUnresolved && a.Code == "revoked" {
			c.toldRevoked(CredentialPrincipal(c.Cred), a)
		}
		return fmt.Errorf("ldrcore: anchor request refused: %s %s", a.Class, a.Code)
	}
	return c.Run(q.Log())
}
