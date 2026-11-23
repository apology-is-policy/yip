package ldrcore

import (
	"errors"
	"fmt"
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
type outbox struct {
	entries     []*OutboxEntry
	slots       map[string]string // slot -> ID of the unsettled intent holding it
	nextOp      int64             // op_ids are never reused
	mustResolve bool
	suspect     bool // history_unavailable was seen: rollback is suspected
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
)

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
		if !c.Root {
			return "", ErrNotSigner
		}
		return Root, nil
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

// Send transmits a stored intent, exactly as stored. A settled intent is not
// sent: its stored result is returned.
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
		if a.Code == "history_unavailable" {
			// The relay knows less history than this client has verified.
			c.out.suspect = true
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
func (c *Client) ResolveAll(q *Sequencer, clk Clock) {
	for _, e := range c.out.entries {
		if e.Status != OutPending && e.Status != OutReconcile {
			continue
		}
		a := q.Query(signerOf(&e.Intent.Record), opKey(e.Intent), e.Intent.Digest, clk)
		if e.Status == OutReconcile && (a.Class == ClassUnknown || a.Class == ClassAdmission) {
			continue
		}
		c.settle(e, a)
	}
	c.out.mustResolve = false
}

// Reconciled records the answer an authorized principal obtained for an
// intent that needed reconciliation. Only a durable outcome or a definitive
// refusal settles it.
func (c *Client) Reconciled(id string, a Answer) error {
	e := c.out.find(id)
	switch {
	case e == nil || e.Status != OutReconcile:
		return fmt.Errorf("ldrcore: intent %q is not awaiting reconciliation", id)
	case a.Class != ClassOutcome && a.Class != ClassRefusal:
		return fmt.Errorf("ldrcore: %s does not settle an intent", a.Class)
	}
	e.Result = a
	e.Status = OutClosed
	if a.Class == ClassOutcome {
		e.Status = OutDone
	}
	delete(c.out.slots, e.Slot)
	return nil
}

// ClearSuspicion records that a suspected rollback was looked into from
// outside this model. Nothing in the model can clear it.
func (c *Client) ClearSuspicion() { c.out.suspect = false }

// Anchor asks for a time anchor, then catches up to the head it was given and
// verifies it durably, which is what must happen before signing on it.
func (c *Client) Anchor(q *Sequencer, clk Clock) error {
	if _, _, _, a := q.AnchorRequest(CredentialPrincipal(c.Cred), clk); a.Class != "" {
		return fmt.Errorf("ldrcore: anchor request refused: %s %s", a.Class, a.Code)
	}
	return c.Run(q.Log())
}
