package ldrcore

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// Client is an in-memory model of one credential's side of a line: the
// verified local log store with its checkpoint, the projection that follows
// it, local delivery, what a reader can and cannot read, and the outbox
// (outbox.go). It exists to run the scenario traces of spec sections 5.7,
// 10.2 and 11. It is not a client.
//
// What it leaves out, and what stands in:
//
//   - No transport. Records are handed to Sync by the test.
//   - No cryptography. Under the ordinary profile a signature is a premise,
//     the chain head is the same non-cryptographic stand-in the sequencer
//     model uses, and whether a payload decrypts is a flag on Payload.
//     Signed-context replay rules (generation, anchor on chain, historical
//     deadline against recorded times, and unique committed operation
//     identity, with retired anchor pruning) run on every profile (spec 11.2).
//     Under a profile that commits state, Sync additionally verifies the
//     signature stand-in and state commitment (commit.go).
//   - No disk. Every field below is durable by definition. A crash is
//     modelled as a procedure stopping between two durable steps (Fault), so
//     the only thing a crash can lose is the rest of that procedure.
//   - It starts empty and replays from genesis. How a new member really
//     establishes its first checkpoint is open (Appendix A, Q5), and this
//     model does not settle it.
//   - One generation. Recovery is not modelled.
//
// A Client is not safe for concurrent use. The spec requires one materializer
// per projection directory and one outbox per credential under a local lock;
// here every call is serialized.
type Client struct {
	LineID string
	Cred   string
	// OperatorKey and Root say which other keys this device may sign with.
	// They grant nothing on the line: the sequencer decides that.
	OperatorKey string
	Root        bool
	// ValidityMS is the validity a composed intent claims.
	ValidityMS int64
	// Fault names the point at which the next procedure dies. It fires once.
	Fault string

	prof Profile

	// The verified local log store. A record, the state derived from it, the
	// checkpoint and the indexes below advance together in one step (spec
	// 11.2 rule 1). This is the local source of authority (spec 11.1).
	store  []Entry
	state  State
	ckSeq  int64
	ckHead string
	// signed holds the unretired anchor heads and committed operation
	// identities that frame verification checks on replay (commit.go).
	// It advances in the same step as the rest of the store and prunes
	// retired anchors as sequencer time advances.
	signed    *signedContext
	touchedBy [][]string        // per record: the objects it changed
	touched   map[string]int64  // object -> the last record that changed it
	source    map[string]int64  // record-derived file -> the record that defines it
	viewOf    map[string]string // object-view file -> its object
	owed      [][]Notice        // per record: the local notices it owes
	halted    string            // set by a sequencer violation; the client fails closed

	// The projection: rebuildable files that follow a separate cursor (spec
	// 11.2 rules 2 and 3). They hold no authority.
	projected int64
	files     map[string]string
	rebuilds  int

	// Local delivery, derived from a scan cursor over the store (spec 11.3).
	scanned int64
	queue   map[string]*Notice
	paused  map[string]bool

	// Local-only state (spec 11.4).
	seen       map[string]int64 // actor|call -> turns seen
	badWrap    map[int64]bool   // epochs whose wrap did not verify
	corruptKey map[int64]bool   // epochs whose stored key is wrong

	out outbox
}

// Faults a test can inject. Each is a point between two durable steps.
const (
	// FaultBeforeProjection: the record is in the store; nothing is projected.
	FaultBeforeProjection = "before_projection"
	// FaultAfterFileWrite: a record's files are written; the projection cursor
	// has not moved.
	FaultAfterFileWrite = "after_file_write"
	// FaultAfterEnqueue: a record's notices are queued; the scan cursor has
	// not moved.
	FaultAfterEnqueue = "after_enqueue"
)

// ErrCrashed is returned by a procedure that died at an injected fault.
var ErrCrashed = errors.New("ldrcore: the client process died at an injected fault")

// ViolationError reports a record no honest sequencer produces. It is
// evidence against the sequencer, and the client stops: it applies nothing
// further and signs nothing.
type ViolationError struct {
	Seq    int64
	Reason string
}

func (e *ViolationError) Error() string {
	return fmt.Sprintf("ldrcore: sequencer violation at seq %d: %s", e.Seq, e.Reason)
}

// NewClient returns a client with an empty store, anchored on genesis.
func NewClient(lineID, cred string, prof Profile) *Client {
	return &Client{
		signed:     newSignedContext(),
		LineID:     lineID,
		Cred:       cred,
		ValidityMS: min(60000, prof.ValidityMaxMS),
		prof:       prof,
		ckHead:     genesisHead(lineID),
		touched:    map[string]int64{},
		source:     map[string]int64{},
		viewOf:     map[string]string{},
		files:      map[string]string{},
		queue:      map[string]*Notice{},
		paused:     map[string]bool{},
		seen:       map[string]int64{},
		badWrap:    map[int64]bool{},
		corruptKey: map[int64]bool{},
		out:        outbox{slots: map[string]string{}, told: map[string]*KeyStop{}},
	}
}

// genesisHead is the stand-in genesis constant, the same value the sequencer
// model starts from.
func genesisHead(lineID string) string { return "genesis:" + lineID }

// State returns a copy of the verified derived state.
func (c *Client) State() State { return c.state.Clone() }

// Checkpoint returns the verified checkpoint. It never regresses.
func (c *Client) Checkpoint() (int64, string) { return c.ckSeq, c.ckHead }

// ProjectedSeq returns the projection cursor.
func (c *Client) ProjectedSeq() int64 { return c.projected }

// ScannedSeq returns the delivery scan cursor.
func (c *Client) ScannedSeq() int64 { return c.scanned }

// Halted returns why the client stopped, or "" if it has not.
func (c *Client) Halted() string { return c.halted }

// Rebuilds returns how many times the projection was rebuilt from the store.
func (c *Client) Rebuilds() int { return c.rebuilds }

func (c *Client) takeFault(name string) bool {
	if c.Fault != name {
		return false
	}
	c.Fault = ""
	return true
}

// Sync appends verified records to the local log store in sequence order,
// re-deriving each outcome: it does not accept a record's claim to have
// committed. A record at or below the checkpoint must be the one already
// held. Anything that does not chain, or does not commit on replay, is a
// sequencer violation: the client keeps what it had verified and stops.
func (c *Client) Sync(entries []Entry) error {
	if c.halted != "" {
		return &ViolationError{Seq: c.ckSeq, Reason: c.halted}
	}
	for _, e := range entries {
		if e.Seq <= c.ckSeq {
			if e.Seq < 1 || c.store[e.Seq-1].Head != e.Head {
				return c.halt(e.Seq, "a different record is offered at a sequence number already verified")
			}
			continue
		}
		if e.Seq != c.ckSeq+1 {
			// Out of order is a transport matter, not a verdict on anyone.
			return fmt.Errorf("ldrcore: record %d offered while the checkpoint is at %d", e.Seq, c.ckSeq)
		}
		next, err := verifyFrame(c.LineID, c.prof, c.state, c.ckHead, c.signed, e, c.prof.StateCommit)
		if err != nil {
			return c.halt(e.Seq, err.Error())
		}
		// One durable step.
		e.Record = e.Record.Clone()
		changed := changedObjects(c.state, next)
		c.store = append(c.store, e)
		c.touchedBy = append(c.touchedBy, changed)
		for _, obj := range changed {
			c.touched[obj] = e.Seq
			c.viewOf[viewPath(obj)] = obj
		}
		for _, f := range recordFiles(e, "") {
			c.source[f.path] = e.Seq
		}
		c.owed = append(c.owed, c.noticesFor(&next, e))
		c.state, c.ckSeq, c.ckHead = next, e.Seq, e.Head
		c.signed.record(&e, e.Head)
		c.signed.prune(e.SeqTime, c.prof.ValidityMaxMS)
		// A key whose revocation this client has now verified signs nothing
		// more (outbox.go).
		c.stopRevoked()
	}
	return nil
}

func (c *Client) halt(seq int64, reason string) error {
	c.halted = reason
	return &ViolationError{Seq: seq, Reason: reason}
}

// changedObjects names the calls, broadcasts and actors a record changed, by
// comparing the state before and after it.
func changedObjects(before, after State) []string {
	var out []string
	for id, v := range after.Calls {
		if b := before.Calls[id]; b == nil || !reflect.DeepEqual(b, v) {
			out = append(out, "call:"+id)
		}
	}
	for id, v := range after.Broadcasts {
		if b := before.Broadcasts[id]; b == nil || !reflect.DeepEqual(b, v) {
			out = append(out, "broadcast:"+id)
		}
	}
	for id, v := range after.Line.Actors {
		if b := before.Line.Actors[id]; b == nil || !reflect.DeepEqual(b, v) {
			out = append(out, "actor:"+id)
		}
	}
	sort.Strings(out)
	return out
}

// Reader states (spec 10.2). None of them stops replay.
const (
	// ReadNone: the record carries no line-scope ciphertext.
	ReadNone = "none"
	ReadOK   = "readable"
	// ReadNoKey: the control record verified and the payload was not
	// inspected. It says nothing about whether the ciphertext is valid.
	ReadNoKey = "no_key"
	// ReadUndecryptable: authentication or decryption failed. That is either
	// bad ciphertext or wrong local key material, and the reader cannot tell
	// which, so it must not say the writer is at fault.
	ReadUndecryptable = "undecryptable"
	// ReadMalformed: the plaintext authenticated and is malformed by its
	// author. The control record's effect stands.
	ReadMalformed = "malformed_by_author"
)

// HasKey reports whether this client holds the key of an epoch: it was named
// in that epoch's manifest and its own wrap verified.
func (c *Client) HasKey(epoch int64) bool {
	return slices.Contains(c.state.Line.Readers[epoch], c.Cred) && !c.badWrap[epoch]
}

// FailWrap records that this client's wrap for an epoch did not verify, so it
// holds no key for it although the manifest names it.
func (c *Client) FailWrap(epoch int64) { c.badWrap[epoch] = true }

// CorruptKey records that the key this client stored for an epoch is wrong.
func (c *Client) CorruptKey(epoch int64) { c.corruptKey[epoch] = true }

// ReaderState says what this client can make of a record's payload.
func (c *Client) ReaderState(e Entry) string {
	switch {
	case !e.Record.carriesLineCiphertext():
		return ReadNone
	case !c.HasKey(e.Record.KeyEpoch):
		return ReadNoKey
	case e.Payload.Forged || c.corruptKey[e.Record.KeyEpoch]:
		return ReadUndecryptable
	case e.Payload.Malformed:
		return ReadMalformed
	}
	return ReadOK
}

// projFile is one file of the projection. An immutable file must be
// byte-identical whenever it is written again. A view carries the sequence
// number it was derived from and is replaced only by a higher one.
type projFile struct {
	path, content string
	view          bool
	tag           int64
}

func lines(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteString(kv[i] + "=" + kv[i+1] + "\n")
	}
	return b.String()
}

func num(n int64) string { return fmt.Sprintf("%d", n) }

// recordFiles renders the files one committed record defines. Their paths and
// everything but the body line depend only on the record and the values the
// sequencer assigned to it, never on later state. body is the reader state of
// the payload.
func recordFiles(e Entry, body string) []projFile {
	r := e.Record
	head := []string{"type", r.Type, "seq", num(e.Seq), "at", num(e.SeqTime)}
	file := func(path string, kv ...string) projFile {
		return projFile{path: path, content: lines(append(head, kv...)...)}
	}
	view := func(path string, kv ...string) projFile {
		all := append([]string{"derived_seq", num(e.Seq)}, append(head, kv...)...)
		return projFile{path: path, content: lines(all...), view: true, tag: e.Seq}
	}
	call := "calls/" + r.Call + "/"
	switch r.Type {
	case "call_open":
		return []projFile{
			file(call+"call", "call", r.Call, "from", r.Actor, "to", r.To),
			file(call+"turn-1", "call", r.Call, "from", r.Actor, "turn", "1", "barge", "false", "body", body),
		}
	case "call_turn":
		n := int64(0)
		if r.Expect.TurnCount != nil {
			n = *r.Expect.TurnCount + 1
		}
		return []projFile{file(call+"turn-"+num(n), "call", r.Call, "from", r.Actor, "turn", num(n),
			"barge", fmt.Sprint(r.Barge), "body", body)}
	case "call_note":
		return []projFile{file(call+"note-"+num(e.Seq), "call", r.Call, "from", r.Actor, "body", body)}
	case "call_ratify":
		return []projFile{file(call+"ratify-"+num(e.Seq), "call", r.Call, "operator", r.Operator, "body", body)}
	case "call_attach":
		return []projFile{file(call+"attach-"+num(e.Seq), "call", r.Call, "from", r.Actor, "body", body)}
	case "call_status":
		return []projFile{file(call+"status-"+num(e.Seq), "call", r.Call, "from", r.Actor, "state", r.State,
			"related", r.Related, "reason", body)}
	case "dispute_open":
		return []projFile{file(call+"dispute-opened-"+num(e.Seq), "call", r.Call, "from", r.Actor, "claim", body)}
	case "dispute_measure":
		return []projFile{view(call+"dispute-"+r.Dispute+"/measure-"+r.Actor, "call", r.Call, "from", r.Actor,
			"measurement", body)}
	case "dispute_resolve":
		return []projFile{view(call+"dispute-"+r.Dispute+"/resolution", "call", r.Call, "by", r.Actor,
			"kind", r.Kind, "detail", body)}
	case "dispute_arbitrate":
		return []projFile{view(call+"dispute-"+r.Dispute+"/resolution", "call", r.Call, "by", "operator:"+r.Operator,
			"kind", "human", "detail", body)}
	case "broadcast_create":
		return []projFile{file("broadcasts/"+r.Broadcast+"/broadcast", "broadcast", r.Broadcast, "kind", r.Kind,
			"recipients", strings.Join(r.Recipients, ","), "default_audience", fmt.Sprint(r.DefaultAudience), "body", body)}
	case "broadcast_reply":
		return []projFile{file("broadcasts/"+r.Broadcast+"/reply-"+num(e.Seq), "broadcast", r.Broadcast,
			"from", r.Actor, "body", body)}
	case "actor_declare":
		return []projFile{file("actors/"+r.Actor+"/declared", "actor", r.Actor, "namespace", r.Namespace,
			"cred", r.Cred, "label", body)}
	}
	return nil
}

// viewPath is where the state-derived view of an object is projected.
func viewPath(obj string) string {
	kind, id, _ := strings.Cut(obj, ":")
	return kind + "s/" + id + "/view"
}

// objectView renders the current verified state of one object. Its tag is the
// last record that changed the object, so the content is a function of the
// store alone and rendering it twice gives the same bytes.
func (c *Client) objectView(obj string) (projFile, bool) {
	kind, id, _ := strings.Cut(obj, ":")
	tag := c.touched[obj]
	kv := []string{"derived_seq", num(tag)}
	switch kind {
	case "call":
		v := c.state.Calls[id]
		if v == nil {
			return projFile{}, false
		}
		kv = append(kv, "call", id, "call_no", num(v.CallNo), "from", v.From, "to", v.To,
			"turn_count", num(v.TurnCount), "last_turn_from", v.LastTurnFrom, "floor", v.Floor(),
			"lifecycle", v.Lifecycle, "lifecycle_rev", num(v.LifecycleRev), "status", v.Status(),
			"byes", strings.Join(canonSet(v.Byes), ","), "links", strings.Join(canonSet(v.Links), ","),
			"note_count", num(v.NoteCount), "attach_count", num(v.AttachCount), "dispute_count", num(v.DisputeCount))
		ids := make([]string, 0, len(v.Disputes))
		for d := range v.Disputes {
			ids = append(ids, d)
		}
		sort.Strings(ids)
		for _, d := range ids {
			x := v.Disputes[d]
			kv = append(kv, "dispute."+d, fmt.Sprintf("rev:%d resolved:%t opened_by:%s", x.Rev, x.Resolved, x.OpenedBy))
		}
	case "broadcast":
		v := c.state.Broadcasts[id]
		if v == nil {
			return projFile{}, false
		}
		kv = append(kv, "broadcast", id)
		for _, a := range canonSet(v.Recipients) {
			read := "pending"
			if rc, ok := v.Receipts[a]; ok {
				read = num(rc.ReadSeq)
			}
			kv = append(kv, "receipt."+a, read, "replies."+a, num(v.ReplyCount[a]))
		}
	case "actor":
		v := c.state.Line.Actors[id]
		if v == nil {
			return projFile{}, false
		}
		kv = append(kv, "actor", id, "namespace", v.Namespace, "cred", v.Cred, "binding_gen", num(v.BindingGen),
			"addr_rev", num(v.AddrRev), "default_addressed", fmt.Sprint(v.DefaultAddressed), "live", fmt.Sprint(v.Live))
	default:
		return projFile{}, false
	}
	return projFile{path: viewPath(obj), content: lines(kv...), view: true, tag: tag}, true
}

func viewTag(content string) (int64, bool) {
	var n int64
	first, _, _ := strings.Cut(content, "\n")
	if _, err := fmt.Sscanf(first, "derived_seq=%d", &n); err != nil || first != "derived_seq="+num(n) {
		return 0, false
	}
	return n, true
}

// writeFile applies the two write rules. It reports false when the directory
// holds something this store could not have written: the projection is
// tainted and must be rebuilt.
func (c *Client) writeFile(f projFile) bool {
	old, exists := c.files[f.path]
	switch {
	case !exists:
		c.files[f.path] = f.content
		return true
	case !f.view:
		// An existing byte-identical immutable file is success, not
		// corruption: that is what a crash before the cursor moved leaves.
		return old == f.content
	}
	tag, ok := viewTag(old)
	switch {
	case !ok || tag > c.ckSeq:
		// Unreadable, or derived from a record this store does not hold.
		return false
	case tag > f.tag:
		return true // a view is replaced only by a higher one
	case tag == f.tag:
		return old == f.content
	}
	c.files[f.path] = f.content
	return true
}

// filesOf lists everything projecting one record writes: the record's own
// files, then the views of the objects it changed.
func (c *Client) filesOf(seq int64) []projFile {
	e := c.store[seq-1]
	out := recordFiles(e, c.ReaderState(e))
	for _, obj := range c.touchedBy[seq-1] {
		if f, ok := c.objectView(obj); ok {
			out = append(out, f)
		}
	}
	return out
}

// Project brings the projection up to the checkpoint, one record at a time.
// It is idempotent: projecting a record again after a crash rewrites nothing
// and duplicates nothing. If the directory disagrees with the store it is
// rebuilt from the store once; a second disagreement in the same run is
// reported, because a rebuild from an unchanged store cannot disagree with
// itself.
func (c *Client) Project() error {
	rebuilt := false
	for c.projected < c.ckSeq {
		seq := c.projected + 1
		ok := true
		for _, f := range c.filesOf(seq) {
			if !c.writeFile(f) {
				ok = false
				break
			}
		}
		if !ok {
			if rebuilt {
				return fmt.Errorf("ldrcore: the projection disagrees with the store at seq %d after a rebuild", seq)
			}
			rebuilt = true
			c.wipe()
			continue
		}
		if c.takeFault(FaultAfterFileWrite) {
			return ErrCrashed
		}
		c.projected = seq
	}
	return nil
}

func (c *Client) wipe() {
	c.files = map[string]string{}
	c.projected = 0
	c.rebuilds++
}

// Rebuild discards the projection and writes it again from the verified
// store.
func (c *Client) Rebuild() error {
	c.wipe()
	return c.Project()
}

// Files returns a copy of the projection directory.
func (c *Client) Files() map[string]string {
	out := make(map[string]string, len(c.files))
	for k, v := range c.files {
		out[k] = v
	}
	return out
}

// EditFile models a local edit of a projection file, or the creation of one.
// It gives the file no authority.
func (c *Client) EditFile(path, content string) { c.files[path] = content }

// Errors a verified read can return.
var (
	// ErrNoAuthority: the verified store never defined this path.
	ErrNoAuthority = errors.New("ldrcore: the verified store defines no such projection file")
	// ErrNotProjected: the store defines the file and the projection has not
	// written it yet, or holds an older view. Projection may lag.
	ErrNotProjected = errors.New("ldrcore: the projection has not caught up to this file")
	// ErrTainted: the file is not what the store says it must be.
	ErrTainted = errors.New("ldrcore: the projection file does not match the verified store")
)

// ReadFile is a read that may affect behaviour. It returns a projection file
// only if, at this moment, the file is exactly what the verified store says
// it must be (spec 11.1). An edit is caught here, at the read, and not at
// some later rebuild.
func (c *Client) ReadFile(path string) (string, error) {
	var want projFile
	if seq, ok := c.source[path]; ok {
		e := c.store[seq-1]
		for _, f := range recordFiles(e, c.ReaderState(e)) {
			if f.path == path {
				want = f
			}
		}
	} else if obj, ok := c.viewOf[path]; ok {
		want, _ = c.objectView(obj)
	} else {
		return "", ErrNoAuthority
	}
	got, exists := c.files[path]
	switch {
	case got == want.content && exists:
		return got, nil
	case !exists:
		return "", ErrNotProjected
	}
	if tag, ok := viewTag(got); want.view && ok && tag < want.tag && c.projected < want.tag {
		return "", ErrNotProjected
	}
	return "", ErrTainted
}

// Floor, Status and Unread answer from verified state, never from files.

// Floor returns who holds the floor of a call.
func (c *Client) Floor(call string) string {
	if v := c.state.Calls[call]; v != nil {
		return v.Floor()
	}
	return ""
}

// Status returns the derived status of a call.
func (c *Client) Status(call string) string {
	if v := c.state.Calls[call]; v != nil {
		return v.Status()
	}
	return ""
}

// MarkSeen records that a local agent has read a call up to its current turn.
// The cursor is local-only state.
func (c *Client) MarkSeen(actor, call string) {
	if v := c.state.Calls[call]; v != nil {
		c.seen[actor+"|"+call] = v.TurnCount
	}
}

// Unread returns how many turns of a call a local agent has not seen.
func (c *Client) Unread(actor, call string) int64 {
	if v := c.state.Calls[call]; v != nil {
		return v.TurnCount - c.seen[actor+"|"+call]
	}
	return 0
}

// Notice is one local delivery. ID is stable: it is derived from the source
// record and the recipient, so finding the same source again maps to the same
// delivery. BindingGen is the actor's binding generation in the state the
// source record produced: the notice belongs to that binding and to no later
// one. Attempts and acknowledgement never leave this host.
type Notice struct {
	ID         string
	Seq        int64
	Actor      string
	Kind       string
	BindingGen int64
	Attempts   int
	Acked      bool
}

// noticesFor derives the notices one record owes on this host: one to each
// addressed actor that is live and bound to this credential in s, the state
// the record produced. It is computed when the record is stored, so what a
// record owes does not depend on how far the client had replayed before it
// scanned. Which records notify whom is this model's choice; the spec fixes
// only that delivery is derived from the store by a scan cursor.
func (c *Client) noticesFor(s *State, e Entry) []Notice {
	r := e.Record
	var to []string
	other := func() {
		if v := s.Calls[r.Call]; v != nil {
			for _, p := range []string{v.From, v.To} {
				if p != r.Actor {
					to = append(to, p)
				}
			}
		}
	}
	switch r.Type {
	case "call_open", "call_turn", "call_note", "call_attach", "call_status", "call_bye",
		"dispute_open", "dispute_measure", "dispute_resolve":
		other()
	case "call_ratify", "dispute_arbitrate":
		other() // the signer is the operator, so this is both participants
	case "broadcast_create":
		to = append(to, r.Recipients...)
	}
	var out []Notice
	for _, a := range canonSet(to) {
		if v := s.Line.Actors[a]; v != nil && v.Live && v.Cred == c.Cred {
			out = append(out, Notice{
				ID:         fmt.Sprintf("g%d-s%d-%s", s.Line.Generation, e.Seq, a),
				Seq:        e.Seq,
				Actor:      a,
				Kind:       r.Type,
				BindingGen: v.BindingGen,
			})
		}
	}
	return out
}

// Scan brings local delivery up to the checkpoint. A notice is found by the
// cursor, not enqueued while a record is applied, so a crash after the
// checkpoint advances loses none. Enqueueing is idempotent by delivery ID.
func (c *Client) Scan() error {
	for c.scanned < c.ckSeq {
		seq := c.scanned + 1
		for _, n := range c.owed[seq-1] {
			if _, queued := c.queue[n.ID]; !queued {
				c.queue[n.ID] = &n
			}
		}
		if c.takeFault(FaultAfterEnqueue) {
			return ErrCrashed
		}
		c.scanned = seq
	}
	return nil
}

// Pause stops handing an actor's notices to its runtime. It is local state:
// nothing is sent, and no audience on the line changes.
func (c *Client) Pause(actor string) { c.paused[actor] = true }

// Resume undoes Pause.
func (c *Client) Resume(actor string) { delete(c.paused, actor) }

// bound reports whether verified state still shows a notice's actor live, on
// this credential, under the binding the notice was queued for. Being queued
// is not enough: the actor may have been removed or moved since.
func (c *Client) bound(n *Notice) bool {
	a := c.state.Line.Actors[n.Actor]
	return a != nil && a.Live && a.Cred == c.Cred && a.BindingGen == n.BindingGen
}

// Deliver hands every unacknowledged notice of an unpaused actor to its
// runtime and counts the attempt. Delivery is at least once: a notice is
// handed over again until it is acknowledged, always under the same ID.
//
// Eligibility is decided again here, against verified state: a notice whose
// actor has since been removed, or moved to another credential, is withheld.
// It stays in the queue as it was, unacknowledged. An actor that is moved
// away and later moved back has a new binding generation, so the notices of
// its earlier binding stay withheld: a move carries neither notices nor
// acknowledgements between hosts.
func (c *Client) Deliver() []Notice {
	var out []Notice
	for _, n := range c.queue {
		if !n.Acked && !c.paused[n.Actor] && c.bound(n) {
			n.Attempts++
			out = append(out, *n)
		}
	}
	sortNotices(out)
	return out
}

// Withheld returns a copy of the unacknowledged notices that verified state
// no longer lets this host hand over. They are history, not acknowledgements.
func (c *Client) Withheld() []Notice {
	var out []Notice
	for _, n := range c.queue {
		if !n.Acked && !c.bound(n) {
			out = append(out, *n)
		}
	}
	sortNotices(out)
	return out
}

// Ack records that a runtime acknowledged a delivery.
func (c *Client) Ack(id string) {
	if n := c.queue[id]; n != nil {
		n.Acked = true
	}
}

// Notices returns a copy of the local delivery queue.
func (c *Client) Notices() []Notice {
	out := make([]Notice, 0, len(c.queue))
	for _, n := range c.queue {
		out = append(out, *n)
	}
	sortNotices(out)
	return out
}

func sortNotices(n []Notice) {
	sort.Slice(n, func(i, j int) bool {
		if n[i].Seq != n[j].Seq {
			return n[i].Seq < n[j].Seq
		}
		return n[i].Actor < n[j].Actor
	})
}

// Run is the ordinary loop: verify and store, project, scan.
func (c *Client) Run(entries []Entry) error {
	if err := c.Sync(entries); err != nil {
		return err
	}
	if c.takeFault(FaultBeforeProjection) {
		return ErrCrashed
	}
	return c.Catchup()
}

// Catchup projects and scans up to the checkpoint.
func (c *Client) Catchup() error {
	if err := c.Project(); err != nil {
		return err
	}
	return c.Scan()
}

// Restart is what a new process does after a crash. Everything it finds is
// what was durable. It must resolve its stored intents before composing
// anything new (spec 5.7 rule 3), and it catches the projection and delivery
// up from their cursors.
func (c *Client) Restart() error {
	c.Fault = ""
	c.out.mustResolve = c.out.unsettled() > 0
	return c.Catchup()
}
