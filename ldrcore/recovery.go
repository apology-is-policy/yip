package ldrcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
)

// ErrUnreconcilableLoss is returned when a rollback gap exists with missing,
// disconnected, or incomplete external witness evidence, so in-place recovery
// must fail closed and migrate explicitly to a new line_id.
var ErrUnreconcilableLoss = errors.New("ldrcore: rollback gap cannot be reconciled from available witness evidence")

// RecoveryRecord is the root-origin record committed at (PriorGeneration+1, 1)
// to transition a line to a new generation (planned transition or reconciled
// rollback recovery). See docs/LDR-RECOVERY.md.
type RecoveryRecord struct {
	RootKey         string  `json:"root_key"`
	PriorGeneration int64   `json:"prior_generation"`
	Generation      int64   `json:"generation"`
	BaseSeq         int64   `json:"base_seq"`
	BaseHead        string  `json:"base_head"`
	NewProfile      Profile `json:"new_profile"`
	NewRelayOrigin  string  `json:"new_relay_origin,omitempty"`
	MinTimeFloor    int64   `json:"min_time_floor"`

	// Reconciled security delta from (BaseSeq, tail] (or precautionary).
	// ActiveRootKeys, when non-empty, replaces base.Line.RootKeys with the
	// reconciled equal 1-of-2 active root set; any base root key removed must
	// appear in ReconciledTombstones.RootKeys.
	ActiveRootKeys       []string               `json:"active_root_keys,omitempty"`
	RevokedOperators     []string               `json:"revoked_operators,omitempty"`
	RevokedCreds         []string               `json:"revoked_creds,omitempty"`
	DiscardedCreds       map[string]*Credential `json:"discarded_creds,omitempty"`
	RemovedActors        []string               `json:"removed_actors,omitempty"`
	ReconciledTombstones Tombstones             `json:"reconciled_tombstones"`

	// Monotone counter floors from the discarded tail (0 means none).
	RootRevFloor     int64               `json:"root_rev_floor,omitempty"`
	AuthEpochFloor   int64               `json:"auth_epoch_floor,omitempty"`
	AudienceRevFloor int64               `json:"audience_rev_floor,omitempty"`
	KeyEpochFloor    int64               `json:"key_epoch_floor,omitempty"`
	BindingGenFloors map[string]int64    `json:"binding_gen_floors,omitempty"`
	WriterRevFloors  map[string]int64    `json:"writer_rev_floors,omitempty"`
	UsedIncarnations map[string][]string `json:"used_incarnations,omitempty"`
}

// Clone returns a deep copy of r.
func (r *RecoveryRecord) Clone() *RecoveryRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.ActiveRootKeys = slices.Clone(r.ActiveRootKeys)
	out.RevokedOperators = slices.Clone(r.RevokedOperators)
	out.RevokedCreds = slices.Clone(r.RevokedCreds)
	if r.DiscardedCreds != nil {
		out.DiscardedCreds = make(map[string]*Credential, len(r.DiscardedCreds))
		for id, c := range r.DiscardedCreds {
			if c != nil {
				cc := *c
				out.DiscardedCreds[id] = &cc
			}
		}
	}
	out.RemovedActors = slices.Clone(r.RemovedActors)
	out.ReconciledTombstones = Tombstones{
		Creds:        slices.Clone(r.ReconciledTombstones.Creds),
		Actors:       slices.Clone(r.ReconciledTombstones.Actors),
		JoinRequests: slices.Clone(r.ReconciledTombstones.JoinRequests),
		OperatorKeys: slices.Clone(r.ReconciledTombstones.OperatorKeys),
		RootKeys:     slices.Clone(r.ReconciledTombstones.RootKeys),
		Calls:        slices.Clone(r.ReconciledTombstones.Calls),
		Broadcasts:   slices.Clone(r.ReconciledTombstones.Broadcasts),
	}
	out.BindingGenFloors = maps.Clone(r.BindingGenFloors)
	out.WriterRevFloors = maps.Clone(r.WriterRevFloors)
	if r.UsedIncarnations != nil {
		out.UsedIncarnations = make(map[string][]string, len(r.UsedIncarnations))
		for k, v := range r.UsedIncarnations {
			out.UsedIncarnations[k] = slices.Clone(v)
		}
	}
	return &out
}

func recoveryFrameHead(e *Entry) string {
	rb, err := json.Marshal(e.Recovery)
	if err != nil {
		panic("ldrcore: a recovery record does not encode: " + err.Error())
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|g%d|%d|%d|%s|%s|recovery:", e.Prev, e.Gen, e.Seq, e.SeqTime, e.Record.Type, e.Digest)
	h.Write(rb)
	if e.StateDigest != "" {
		fmt.Fprintf(h, "|state:%s", e.StateDigest)
	}
	return fmt.Sprintf("%016x", h.Sum64())
}

// ApplyRecovery applies a root-origin recovery_generation transition from a
// verified base state at (PriorGeneration, BaseSeq, BaseHead) to produce the
// reconciled state at (Generation, 1). Pure: never modifies base.
func ApplyRecovery(base State, baseHead string, r RecoveryRecord, seqTime int64) (State, error) {
	if bad := base.CheckInvariants(); len(bad) > 0 {
		return State{}, fmt.Errorf("ldrcore: recovery base state is not coherent: %v", bad)
	}
	if base.Line.Generation < 1 {
		return State{}, errors.New("ldrcore: cannot recover an empty log")
	}
	if r.PriorGeneration != base.Line.Generation || r.Generation != r.PriorGeneration+1 || r.Generation > MaxCounter {
		return State{}, fmt.Errorf("ldrcore: recovery generation %d->%d does not follow current generation %d",
			r.PriorGeneration, r.Generation, base.Line.Generation)
	}
	if r.BaseSeq < 1 || r.BaseSeq != base.Line.HeadSeq || r.BaseHead == "" || r.BaseHead != baseHead {
		return State{}, fmt.Errorf("ldrcore: recovery base (%d, %q) does not match verified base (%d, %q)",
			r.BaseSeq, r.BaseHead, base.Line.HeadSeq, baseHead)
	}
	if r.NewProfile.FreshnessMS <= 0 || r.NewProfile.FreshnessMS > MaxCounter ||
		r.NewProfile.ValidityMaxMS <= 0 || r.NewProfile.ValidityMaxMS > MaxCounter {
		return State{}, errors.New("ldrcore: recovery new_profile bounds are invalid")
	}
	if r.MinTimeFloor < base.Line.HeadTime || r.MinTimeFloor > MaxCounter {
		return State{}, fmt.Errorf("ldrcore: recovery min_time_floor %d is below base head_time %d or out of domain",
			r.MinTimeFloor, base.Line.HeadTime)
	}
	if seqTime < r.MinTimeFloor || seqTime > MaxCounter {
		return State{}, fmt.Errorf("ldrcore: recovery seq_time %d is below min_time_floor %d or out of domain",
			seqTime, r.MinTimeFloor)
	}
	if r.RootKey == "" || !slices.Contains(base.Line.RootKeys, r.RootKey) {
		return State{}, fmt.Errorf("ldrcore: recovery signer %q is not an active root at (%d,%d)",
			r.RootKey, base.Line.Generation, base.Line.HeadSeq)
	}
	if slices.Contains(r.ReconciledTombstones.RootKeys, r.RootKey) {
		return State{}, fmt.Errorf("ldrcore: recovery signer %q is tombstoned in reconciled_tombstones", r.RootKey)
	}

	next := base.Clone()
	l := &next.Line

	// Merge reconciled root replacements first.
	for _, k := range r.ReconciledTombstones.RootKeys {
		if k == "" {
			return State{}, errors.New("ldrcore: empty key in reconciled_tombstones.root_keys")
		}
		l.Tombstones.RootKeys = addToSet(l.Tombstones.RootKeys, k)
	}
	if len(r.ActiveRootKeys) > 0 {
		if len(r.ActiveRootKeys) != 2 || r.ActiveRootKeys[0] == "" || r.ActiveRootKeys[1] == "" ||
			r.ActiveRootKeys[0] == r.ActiveRootKeys[1] {
			return State{}, errors.New("ldrcore: recovery active_root_keys must name exactly two distinct non-empty keys")
		}
		if !slices.Contains(r.ActiveRootKeys, r.RootKey) {
			return State{}, fmt.Errorf("ldrcore: recovery signer %q is not in reconciled active_root_keys", r.RootKey)
		}
		for _, oldK := range base.Line.RootKeys {
			if !slices.Contains(r.ActiveRootKeys, oldK) {
				l.Tombstones.RootKeys = addToSet(l.Tombstones.RootKeys, oldK)
			}
		}
		for _, newK := range r.ActiveRootKeys {
			if !slices.Contains(base.Line.RootKeys, newK) && base.Line.keyUsed(newK) {
				return State{}, fmt.Errorf("ldrcore: recovery active root key %q was already used", newK)
			}
		}
		l.RootKeys = canonSet(r.ActiveRootKeys)
	}

	// Reconcile revoked operators and operator tombstones.
	for _, op := range r.RevokedOperators {
		if op == "" {
			return State{}, errors.New("ldrcore: empty operator key in revoked_operators")
		}
		l.Operators = slices.DeleteFunc(slices.Clone(l.Operators), func(k string) bool { return k == op })
		l.Tombstones.OperatorKeys = addToSet(l.Tombstones.OperatorKeys, op)
	}
	for _, op := range r.ReconciledTombstones.OperatorKeys {
		if op == "" {
			return State{}, errors.New("ldrcore: empty operator key in reconciled_tombstones.operator_keys")
		}
		l.Operators = slices.DeleteFunc(slices.Clone(l.Operators), func(k string) bool { return k == op })
		l.Tombstones.OperatorKeys = addToSet(l.Tombstones.OperatorKeys, op)
	}

	// Reconcile credentials enrolled in the discarded tail (permanently revoked
	// entries so their keys and namespaces stay reserved).
	for _, id := range sortedKeys(r.DiscardedCreds) {
		c := r.DiscardedCreds[id]
		if id == "" || c == nil || c.SigningKey == "" || c.EncryptionKey == "" ||
			c.SigningKey == c.EncryptionKey || c.Namespace == "" || c.ActorLimit < 0 {
			return State{}, fmt.Errorf("ldrcore: malformed discarded credential %q", id)
		}
		if l.Credentials[id] != nil {
			return State{}, fmt.Errorf("ldrcore: discarded credential %q already exists in base state", id)
		}
		cc := *c
		cc.Revoked = true
		l.Credentials[id] = &cc
		l.Tombstones.Creds = addToSet(l.Tombstones.Creds, id)
	}

	// Reconcile revoked base credentials (and disable their bound actors).
	for _, credID := range r.RevokedCreds {
		c := l.Credentials[credID]
		if c == nil {
			return State{}, fmt.Errorf("ldrcore: revoked credential %q not found in base or discarded credentials", credID)
		}
		c.Revoked = true
		l.Tombstones.Creds = addToSet(l.Tombstones.Creds, credID)
		for aid, a := range l.Actors {
			if a.Cred == credID && a.Live {
				a.Live = false
				l.Tombstones.Actors = addToSet(l.Tombstones.Actors, aid)
			}
		}
	}

	// Reconcile removed actors and all remaining tombstones.
	for _, aid := range r.RemovedActors {
		if aid == "" {
			return State{}, errors.New("ldrcore: empty actor id in removed_actors")
		}
		if a := l.Actors[aid]; a != nil {
			a.Live = false
		}
		l.Tombstones.Actors = addToSet(l.Tombstones.Actors, aid)
	}
	for _, id := range r.ReconciledTombstones.Creds {
		l.Tombstones.Creds = addToSet(l.Tombstones.Creds, id)
	}
	for _, id := range r.ReconciledTombstones.Actors {
		if a := l.Actors[id]; a != nil {
			a.Live = false
		}
		l.Tombstones.Actors = addToSet(l.Tombstones.Actors, id)
	}
	for _, id := range r.ReconciledTombstones.JoinRequests {
		l.Tombstones.JoinRequests = addToSet(l.Tombstones.JoinRequests, id)
	}
	for _, id := range r.ReconciledTombstones.Calls {
		l.Tombstones.Calls = addToSet(l.Tombstones.Calls, id)
	}
	for _, id := range r.ReconciledTombstones.Broadcasts {
		l.Tombstones.Broadcasts = addToSet(l.Tombstones.Broadcasts, id)
	}

	// Monotone counter floors (strictly advancing root_rev, auth_epoch,
	// audience_rev; non-decreasing key_epoch, binding_gen, writer_rev).
	advanceFloor := func(name string, baseVal, floorVal int64) (int64, error) {
		if floorVal < 0 || floorVal > MaxCounter {
			return 0, fmt.Errorf("ldrcore: recovery %s floor %d out of domain", name, floorVal)
		}
		top := max(baseVal, floorVal)
		if top >= MaxCounter {
			return 0, fmt.Errorf("ldrcore: recovery %s exhausted at %d", name, top)
		}
		return top + 1, nil
	}
	var err error
	if l.RootRev, err = advanceFloor("root_rev", l.RootRev, r.RootRevFloor); err != nil {
		return State{}, err
	}
	if l.AuthEpoch, err = advanceFloor("auth_epoch", l.AuthEpoch, r.AuthEpochFloor); err != nil {
		return State{}, err
	}
	if l.AudienceRev, err = advanceFloor("audience_rev", l.AudienceRev, r.AudienceRevFloor); err != nil {
		return State{}, err
	}
	if r.KeyEpochFloor < 0 || r.KeyEpochFloor > MaxCounter {
		return State{}, fmt.Errorf("ldrcore: recovery key_epoch floor %d out of domain", r.KeyEpochFloor)
	}
	l.KeyEpoch = max(l.KeyEpoch, r.KeyEpochFloor)
	// Mandatory rekey gate: no payload-bearing record or register publication
	// commits in generation g+1 until a fresh key_epoch_activate runs.
	l.RekeyPending = true

	for aid, fl := range r.BindingGenFloors {
		if fl < 0 || fl > MaxCounter {
			return State{}, fmt.Errorf("ldrcore: recovery binding_gen floor %d for %s out of domain", fl, aid)
		}
		if a := l.Actors[aid]; a != nil {
			a.BindingGen = max(a.BindingGen, fl)
		}
	}
	for key, incs := range r.UsedIncarnations {
		if w := l.RegisterWriters[key]; w != nil {
			for _, inc := range incs {
				if inc != "" {
					w.Used = addToSet(w.Used, inc)
				}
			}
			w.WriterRev = max(w.WriterRev, int64(len(w.Used)))
		}
	}
	for key, fl := range r.WriterRevFloors {
		if fl < 0 || fl > MaxCounter {
			return State{}, fmt.Errorf("ldrcore: recovery writer_rev floor %d for %s out of domain", fl, key)
		}
		if w := l.RegisterWriters[key]; w != nil {
			w.WriterRev = max(w.WriterRev, fl)
		}
	}

	// Reset sequence coordinate to 1 in the new generation (O23-B).
	l.Generation = r.Generation
	l.HeadSeq = 1
	l.HeadTime = seqTime

	if bad := next.CheckInvariants(); len(bad) > 0 {
		return State{}, fmt.Errorf("ldrcore: recovery produced an incoherent state: %v", bad)
	}
	return next, nil
}

// BuildRecoveryFromWitness constructs a reconciled RecoveryRecord from a
// verified base state at (g, baseSeq, baseHead) and a contiguous witness tail
// covering (g, baseSeq+1..knownTailSeq]. If knownTailSeq > baseSeq and the
// witness tail does not link cleanly from baseHead through knownTailSeq, it
// fails closed with ErrUnreconcilableLoss.
func BuildRecoveryFromWitness(base State, baseHead string, baseProf Profile, knownTailSeq int64, witnessTail []Entry, rootKey string, newProf Profile, newOrigin string) (RecoveryRecord, error) {
	if base.Line.Generation < 1 {
		return RecoveryRecord{}, fmt.Errorf("%w: empty base state", ErrUnreconcilableLoss)
	}
	if knownTailSeq < base.Line.HeadSeq {
		return RecoveryRecord{}, fmt.Errorf("%w: known tail %d precedes base %d", ErrUnreconcilableLoss, knownTailSeq, base.Line.HeadSeq)
	}
	wantLen := knownTailSeq - base.Line.HeadSeq
	if int64(len(witnessTail)) != wantLen {
		return RecoveryRecord{}, fmt.Errorf("%w: need %d witness records for (%d..%d], have %d",
			ErrUnreconcilableLoss, wantLen, base.Line.HeadSeq, knownTailSeq, len(witnessTail))
	}

	r := RecoveryRecord{
		RootKey:          rootKey,
		PriorGeneration:  base.Line.Generation,
		Generation:       base.Line.Generation + 1,
		BaseSeq:          base.Line.HeadSeq,
		BaseHead:         baseHead,
		NewProfile:       newProf,
		NewRelayOrigin:   newOrigin,
		MinTimeFloor:     base.Line.HeadTime,
		DiscardedCreds:   map[string]*Credential{},
		BindingGenFloors: map[string]int64{},
		WriterRevFloors:  map[string]int64{},
		UsedIncarnations: map[string][]string{},
	}

	cur := base.Clone()
	prevHead := baseHead
	for _, e := range witnessTail {
		if e.Seq != cur.Line.HeadSeq+1 || e.Prev != prevHead || frameHead(&e) != e.Head {
			return RecoveryRecord{}, fmt.Errorf("%w: witness record %d does not link onto verified base chain", ErrUnreconcilableLoss, e.Seq)
		}
		next, out := Apply(cur, e.Record, e.SeqTime, baseProf)
		if out.Kind != Committed {
			return RecoveryRecord{}, fmt.Errorf("%w: witness record %d (%s) does not commit: %s %s",
				ErrUnreconcilableLoss, e.Seq, e.Record.Type, out.Kind, out.Reason)
		}
		rec := e.Record
		switch rec.Type {
		case "root_member_replace":
			r.ActiveRootKeys = slices.Clone(next.Line.RootKeys)
			r.ReconciledTombstones.RootKeys = addToSet(r.ReconciledTombstones.RootKeys, rec.OldRootKey)
		case "operator_key_authorize":
			// An operator authorized only in the discarded tail is not carried
			// forward as active, but its key stays permanently reserved.
			r.ReconciledTombstones.OperatorKeys = addToSet(r.ReconciledTombstones.OperatorKeys, rec.OperatorKey)
		case "operator_key_revoke":
			r.RevokedOperators = addToSet(r.RevokedOperators, rec.OperatorKey)
		case "credential_enroll":
			c := *next.Line.Credentials[rec.Cred]
			c.Revoked = true
			r.DiscardedCreds[rec.Cred] = &c
			r.ReconciledTombstones.JoinRequests = addToSet(r.ReconciledTombstones.JoinRequests, rec.JoinRequest)
		case "credential_revoke":
			if base.Line.Credentials[rec.Cred] != nil {
				r.RevokedCreds = addToSet(r.RevokedCreds, rec.Cred)
			}
		case "actor_declare":
			r.ReconciledTombstones.Actors = addToSet(r.ReconciledTombstones.Actors, rec.Actor)
		case "actor_remove":
			if base.Line.Actors[rec.Actor] != nil {
				r.RemovedActors = addToSet(r.RemovedActors, rec.Actor)
			} else {
				r.ReconciledTombstones.Actors = addToSet(r.ReconciledTombstones.Actors, rec.Actor)
			}
		case "actor_move":
			if base.Line.Actors[rec.Actor] != nil {
				r.BindingGenFloors[rec.Actor] = next.Line.Actors[rec.Actor].BindingGen
			}
		case "register_activate":
			key := rec.Actor + "/" + rec.Register
			if base.Line.RegisterWriters[key] != nil {
				r.UsedIncarnations[key] = addToSet(r.UsedIncarnations[key], rec.Incarnation)
				r.WriterRevFloors[key] = next.Line.RegisterWriters[key].WriterRev
			}
		case "call_open":
			r.ReconciledTombstones.Calls = addToSet(r.ReconciledTombstones.Calls, rec.Call)
		case "broadcast_create":
			r.ReconciledTombstones.Broadcasts = addToSet(r.ReconciledTombstones.Broadcasts, rec.Broadcast)
		}
		cur, prevHead = next, e.Head
	}

	r.MinTimeFloor = max(base.Line.HeadTime, cur.Line.HeadTime)
	r.RootRevFloor = cur.Line.RootRev
	r.AuthEpochFloor = cur.Line.AuthEpoch
	r.AudienceRevFloor = cur.Line.AudienceRev
	r.KeyEpochFloor = cur.Line.KeyEpoch
	return r, nil
}

// FullLog returns deep copies of every committed record across all finalized
// earlier generations plus the current generation, oldest first.
func (q *Sequencer) FullLog() []Entry {
	var total int
	for _, pl := range q.priorLogs {
		total += len(pl)
	}
	total += len(q.log)
	out := make([]Entry, 0, total)
	for _, pl := range q.priorLogs {
		for _, e := range pl {
			out = append(out, cloneEntry(e))
		}
	}
	for _, e := range q.log {
		out = append(out, cloneEntry(e))
	}
	return out
}

// RollbackTo models restoring a relay backup taken at sequence baseSeq of the
// current generation. The returned Sequencer holds history 1..baseSeq,
// retained committed receipts through baseSeq, an empty hot index, and a time
// floor at seq_time(baseSeq). It does not alter q.
func (q *Sequencer) RollbackTo(baseSeq int64) (*Sequencer, error) {
	if q.gen < 1 || baseSeq < 1 || baseSeq > q.state.Line.HeadSeq {
		return nil, fmt.Errorf("ldrcore: cannot roll back generation %d (head %d) to %d", q.gen, q.state.Line.HeadSeq, baseSeq)
	}
	if int64(len(q.log)) < baseSeq {
		return nil, fmt.Errorf("ldrcore: current generation log has only %d records", len(q.log))
	}

	prefix := make([]Entry, 0, int(baseSeq))
	for _, pl := range q.priorLogs {
		for _, e := range pl {
			prefix = append(prefix, cloneEntry(e))
		}
	}
	for _, e := range q.log[:baseSeq] {
		prefix = append(prefix, cloneEntry(e))
	}
	initProf := q.priorProfs[1]
	st, _, err := ReplayVerifiedFull(q.LineID, prefix, initProf)
	if err != nil {
		return nil, fmt.Errorf("ldrcore: rollback prefix does not replay: %w", err)
	}

	rb := NewSequencer(q.LineID, q.prof)
	rb.QuotaMax = q.QuotaMax
	rb.gen = q.gen
	rb.genStartSeq = q.genStartSeq
	rb.state = st
	rb.priorProfs = maps.Clone(q.priorProfs)
	for _, pl := range q.priorLogs {
		cp := make([]Entry, len(pl))
		for i, e := range pl {
			cp[i] = cloneEntry(e)
		}
		rb.priorLogs = append(rb.priorLogs, cp)
	}
	rb.log = make([]Entry, baseSeq)
	for i := int64(0); i < baseSeq; i++ {
		e := cloneEntry(q.log[i])
		rb.log[i] = e
		rb.heads[e.Seq] = e.Head
		rb.times[e.Seq] = e.SeqTime
	}
	rb.floor = st.Line.HeadTime
	for k, rc := range q.logIndex {
		if k.Generation < q.gen || (k.Generation == q.gen && rc.Seq <= baseSeq) {
			rb.logIndex[k] = rc
		}
	}
	return rb, nil
}

// CommitRecovery commits a root-origin recovery_generation record at
// (PriorGeneration+1, 1), advancing the sequencer to the new generation with
// sequence reset to 1, an empty hot index, and retained logIndex receipts for
// earlier generations through BaseSeq.
func (q *Sequencer) CommitRecovery(r RecoveryRecord, opID, digest string, c Clock) Answer {
	if q.Overloaded {
		return admission("overloaded")
	}
	if q.gen < 1 {
		return admission("no_line")
	}
	if opID == "" || digest == "" || r.RootKey == "" {
		return admission("malformed")
	}
	signer := RootPrincipal(r.RootKey)
	if a, ok := access(q.standing(signer)); !ok {
		return a
	}
	key := OpKey{Generation: r.Generation, Signer: signer, SeenSeq: 0, OpID: opID}
	if a, found := q.recorded(key, digest); found {
		return a
	}
	if r.PriorGeneration != q.gen {
		return refusal("wrong_generation")
	}
	headSeq, head := q.Head()
	if r.BaseSeq != headSeq || r.BaseHead != head {
		return refusal("unknown_anchor")
	}
	t, ok := q.tick(c)
	if !ok {
		return admission("clock_uncertain")
	}
	next, err := ApplyRecovery(q.state, head, r, t)
	if err != nil {
		return refusal("invalid_recovery")
	}

	// Atomically finalize prior generation and install generation g+1 at seq 1.
	q.priorLogs = append(q.priorLogs, q.Log())
	q.gen = r.Generation
	q.prof = r.NewProfile
	q.priorProfs[q.gen] = q.prof
	q.genStartSeq = 1
	q.log = nil
	q.heads = map[int64]string{}
	q.times = map[int64]int64{}
	q.hot = map[OpKey]hotEntry{}
	q.quota = map[string]int{}
	q.snaps = nil

	rec := Record{Origin: OriginRoot, Type: "recovery_generation", RootKey: r.RootKey}
	e := Entry{
		Gen:      r.Generation,
		Prev:     r.BaseHead,
		SeenHead: r.BaseHead,
		Key:      key,
		Digest:   digest,
		Record:   rec,
		Recovery: r.Clone(),
	}
	q.commit(next, e, t)
	q.logIndex[key] = OpReceipt{Seq: 1, Digest: digest}
	q.hot[key] = hotEntry{digest: digest, outcome: Outcome{Kind: Committed}, seq: 1}
	return Answer{Class: ClassOutcome, Outcome: Outcome{Kind: Committed}, Seq: 1}
}

// ReplayVerifiedFull verifies a complete cross-generation log from genesis,
// including any recovery_generation transitions (O25 full replay + O23-B
// sequence reset).
func ReplayVerifiedFull(lineID string, log []Entry, initialProf Profile) (State, string, error) {
	var s State
	head := genesisHead(lineID)
	prof := initialProf
	ctx := newSignedContext()
	for _, e := range log {
		if e.Record.Type == "recovery_generation" {
			next, err := verifyRecoveryFrame(lineID, prof, s, head, e, prof.StateCommit)
			if err != nil {
				return State{}, "", err
			}
			s, head, prof = next, e.Head, e.Recovery.NewProfile
			ctx = newSignedContext()
			ctx.record(&e, head)
			continue
		}
		next, err := verifyFrame(lineID, prof, s, head, ctx, e, true)
		if err != nil {
			return State{}, "", err
		}
		s, head = next, e.Head
		ctx.record(&e, head)
		ctx.prune(e.SeqTime, prof.ValidityMaxMS)
	}
	return s, head, nil
}

func verifyRecoveryFrame(lineID string, priorProf Profile, base State, baseHead string, e Entry, checkSig bool) (State, error) {
	if e.Recovery == nil {
		return State{}, errors.New("recovery_generation carries no recovery body")
	}
	r := e.Recovery
	if e.Seq != 1 || e.Gen != base.Line.Generation+1 {
		return State{}, fmt.Errorf("recovery_generation at (%d,%d) does not open generation %d at seq 1",
			e.Gen, e.Seq, base.Line.Generation+1)
	}
	if e.Record.Origin != OriginRoot || e.Record.RootKey != r.RootKey {
		return State{}, errors.New("recovery_generation origin or root_key does not match recovery body")
	}
	signer := signerOf(&e.Record)
	if checkSig && !signedBy(&e, signer) {
		return State{}, fmt.Errorf("recovery_generation does not carry the signature of %q", signer)
	}
	if e.Key.Signer != signer || e.Key.Generation != r.Generation || e.Key.SeenSeq != 0 || e.Key.OpID == "" || e.Digest == "" {
		return State{}, errors.New("recovery_generation has an operation identity that does not fit it")
	}
	if e.Prev != baseHead || e.SeenHead != baseHead {
		return State{}, errors.New("recovery_generation does not link onto verified base head")
	}
	if frameHead(&e) != e.Head {
		return State{}, errors.New("recovery_generation head does not match frame contents")
	}
	next, err := ApplyRecovery(base, baseHead, *r, e.SeqTime)
	if err != nil {
		return State{}, err
	}
	switch {
	case r.NewProfile.StateCommit && StateDigest(lineID, r.NewProfile, next) != e.StateDigest:
		return State{}, errors.New("recovery_generation commits to a different state than the one derived")
	case !r.NewProfile.StateCommit && e.StateDigest != "":
		return State{}, errors.New("recovery_generation carries a state digest that its profile does not define")
	}
	_ = priorProf
	return next, nil
}

// applyRecoveryEntry handles a recovery_generation record in Client.Sync.
// If the client witnessed records past BaseSeq (discarded tail), it performs
// a mandatory fail-closed tail-reconciliation check before adopting generation
// g+1 and archiving the discarded tail.
func (c *Client) applyRecoveryEntry(e Entry) error {
	if e.Recovery == nil {
		return c.halt(e.Seq, "recovery_generation carries no recovery body")
	}
	r := e.Recovery
	if c.ckGen == 0 {
		return fmt.Errorf("ldrcore: recovery_generation offered before line_init")
	}
	// Idempotent re-sync of an already-accepted recovery_generation.
	if r.Generation < c.ckGen {
		prior := c.priorStores[r.Generation]
		if len(prior) == 0 || prior[0].Head != e.Head {
			return c.halt(e.Seq, fmt.Sprintf("divergent recovery_generation at (%d,1)", r.Generation))
		}
		return nil
	}
	if r.Generation == c.ckGen {
		if len(c.store) == 0 || c.store[0].Head != e.Head {
			return c.halt(e.Seq, "a different recovery_generation is offered for the current generation")
		}
		return nil
	}
	if r.PriorGeneration != c.ckGen || r.Generation != c.ckGen+1 {
		return fmt.Errorf("ldrcore: recovery_generation %d->%d offered while client is at generation %d",
			r.PriorGeneration, r.Generation, c.ckGen)
	}
	if r.BaseSeq < 1 {
		return c.halt(e.Seq, "recovery_generation names base_seq < 1")
	}
	// Case A (incomplete): client has not synced up to base_seq yet.
	if c.ckSeq < r.BaseSeq {
		return fmt.Errorf("ldrcore: recovery_generation branches from (%d,%d) while checkpoint is at (%d,%d)",
			r.PriorGeneration, r.BaseSeq, c.ckGen, c.ckSeq)
	}

	// Derive exact verified base state at (ckGen, base_seq).
	baseHead := c.store[r.BaseSeq-1].Head
	if baseHead != r.BaseHead {
		return c.halt(e.Seq, "recovery_generation base_head does not match verified history")
	}
	var baseState State
	if r.BaseSeq == c.ckSeq {
		baseState = c.state.Clone()
	} else {
		// Reconstruct exact base state at (ckGen, base_seq) from verified prefix.
		var prefix []Entry
		for g := int64(1); g < c.ckGen; g++ {
			prefix = append(prefix, c.priorStores[g]...)
		}
		prefix = append(prefix, c.store[:r.BaseSeq]...)
		var err error
		baseState, _, err = ReplayVerifiedFull(c.LineID, prefix, c.prof)
		if err != nil {
			return c.halt(e.Seq, fmt.Sprintf("internal error replaying verified base prefix: %v", err))
		}
	}

	next, err := verifyRecoveryFrame(c.LineID, c.prof, baseState, baseHead, e, c.prof.StateCommit)
	if err != nil {
		return c.halt(e.Seq, err.Error())
	}

	// Case B: client witnessed a discarded tail (ckSeq > base_seq). Verify
	// that EVERY witnessed security transition, tombstone, reservation, and
	// counter floor from the discarded tail is preserved in next. Fail closed
	// on any omission.
	var tail []Entry
	if c.ckSeq > r.BaseSeq {
		tail = c.store[r.BaseSeq:]
		if err := checkTailReconciliation(baseState, c.state, tail, next, r.RootKey); err != nil {
			return c.halt(e.Seq, err.Error())
		}
	}

	// Commit generation transition atomically.
	e = cloneEntry(e)
	priorGen := c.ckGen
	c.priorStores[priorGen] = slices.Clone(c.store[:r.BaseSeq])
	for _, te := range tail {
		c.archivedTail = append(c.archivedTail, cloneEntry(te))
	}

	// Prune source entries from the discarded tail and refresh object views.
	for path, coord := range c.source {
		if coord.gen == priorGen && coord.seq > r.BaseSeq {
			delete(c.source, path)
		}
	}
	newCoord := viewCoord{gen: r.Generation, seq: 1}
	changed := changedObjects(baseState, next)
	// Objects that no longer exist in next (created only in the discarded tail)
	// lose their authoritative view entries; surviving objects whose last touch
	// was in the discarded tail or modified by recovery get tagged (g+1, 1).
	for obj, coord := range c.touched {
		if !objectExists(&next, obj) {
			delete(c.touched, obj)
			delete(c.viewOf, viewPath(obj))
			continue
		}
		if coord.gen == priorGen && coord.seq > r.BaseSeq {
			c.touched[obj] = newCoord
			if !slices.Contains(changed, obj) {
				changed = append(changed, obj)
			}
		}
	}
	for _, obj := range changed {
		c.touched[obj] = newCoord
		c.viewOf[viewPath(obj)] = obj
	}
	slices.Sort(changed)

	c.store = []Entry{e}
	c.touchedBy = [][]string{changed}
	c.owed = [][]Notice{nil}
	c.state = next
	c.prof = r.NewProfile
	c.ckGen = r.Generation
	c.ckSeq = 1
	c.ckHead = e.Head
	c.projected = 0
	c.scanned = 0
	c.signed = newSignedContext()
	c.signed.record(&e, e.Head)
	c.abandonPriorGenerations(r.Generation)
	c.stopRevoked()
	return nil
}

func objectExists(s *State, obj string) bool {
	kind, id := "", ""
	for i := 0; i < len(obj); i++ {
		if obj[i] == ':' {
			kind, id = obj[:i], obj[i+1:]
			break
		}
	}
	switch kind {
	case "call":
		return s.Calls[id] != nil
	case "broadcast":
		return s.Broadcasts[id] != nil
	case "actor":
		return s.Line.Actors[id] != nil
	}
	return false
}

// checkTailReconciliation verifies fail-closed that every security transition,
// tombstone, key/namespace reservation, and counter floor witnessed in tail
// (base_seq+1..old_ckSeq] is preserved in post-recovery state next.
func checkTailReconciliation(base, tailEnd State, tail []Entry, next State, recoverySigner string) error {
	nl := &next.Line
	// Counter floors must never regress below witnessed tail end.
	if nl.RootRev <= tailEnd.Line.RootRev {
		return fmt.Errorf("recovery omitted witnessed root_rev progress: got %d, witnessed %d", nl.RootRev, tailEnd.Line.RootRev)
	}
	if nl.AuthEpoch <= tailEnd.Line.AuthEpoch {
		return fmt.Errorf("recovery omitted witnessed auth_epoch progress: got %d, witnessed %d", nl.AuthEpoch, tailEnd.Line.AuthEpoch)
	}
	if nl.AudienceRev <= tailEnd.Line.AudienceRev {
		return fmt.Errorf("recovery omitted witnessed audience_rev progress: got %d, witnessed %d", nl.AudienceRev, tailEnd.Line.AudienceRev)
	}
	if nl.KeyEpoch < tailEnd.Line.KeyEpoch {
		return fmt.Errorf("recovery omitted witnessed key_epoch progress: got %d, witnessed %d", nl.KeyEpoch, tailEnd.Line.KeyEpoch)
	}

	for _, e := range tail {
		rec := e.Record
		switch rec.Type {
		case "root_member_replace":
			if slices.Contains(nl.RootKeys, rec.OldRootKey) || !slices.Contains(nl.Tombstones.RootKeys, rec.OldRootKey) {
				return fmt.Errorf("recovery omitted witnessed replacement of root key %s", rec.OldRootKey)
			}
			if recoverySigner == rec.OldRootKey {
				return fmt.Errorf("recovery signed by root key %s whose replacement was witnessed in discarded tail", rec.OldRootKey)
			}
		case "operator_key_revoke":
			if slices.Contains(nl.Operators, rec.OperatorKey) || !slices.Contains(nl.Tombstones.OperatorKeys, rec.OperatorKey) {
				return fmt.Errorf("recovery omitted witnessed revocation of operator key %s", rec.OperatorKey)
			}
		case "credential_revoke":
			c := nl.Credentials[rec.Cred]
			if c == nil || !c.Revoked || !slices.Contains(nl.Tombstones.Creds, rec.Cred) {
				return fmt.Errorf("recovery omitted witnessed revocation of credential %s", rec.Cred)
			}
			for aid, ba := range base.Line.Actors {
				if ba.Cred == rec.Cred && ba.Live {
					if na := nl.Actors[aid]; na != nil && na.Live {
						return fmt.Errorf("recovery left actor %s live after witnessed revocation of %s", aid, rec.Cred)
					}
					if !slices.Contains(nl.Tombstones.Actors, aid) {
						return fmt.Errorf("recovery omitted tombstone for actor %s disabled by witnessed revocation of %s", aid, rec.Cred)
					}
				}
			}
		case "credential_enroll":
			if !slices.Contains(nl.Tombstones.JoinRequests, rec.JoinRequest) {
				return fmt.Errorf("recovery omitted witnessed join_request tombstone %s", rec.JoinRequest)
			}
			if !nl.keyUsed(rec.SigningKey) || !nl.keyUsed(rec.EncryptionKey) {
				return fmt.Errorf("recovery omitted witnessed key reservations for discarded enrollment %s", rec.Cred)
			}
			nsReserved := false
			for _, nc := range nl.Credentials {
				if nc.Namespace == rec.Grant.Namespace {
					nsReserved = true
					break
				}
			}
			if !nsReserved {
				return fmt.Errorf("recovery omitted witnessed namespace reservation %s for discarded enrollment %s", rec.Grant.Namespace, rec.Cred)
			}
		case "actor_declare":
			if !slices.Contains(nl.Tombstones.Actors, rec.Actor) && nl.Actors[rec.Actor] == nil {
				return fmt.Errorf("recovery omitted witnessed actor_id reservation %s", rec.Actor)
			}
		case "actor_remove":
			if na := nl.Actors[rec.Actor]; na != nil && na.Live {
				return fmt.Errorf("recovery resurrected removed actor %s", rec.Actor)
			}
			if !slices.Contains(nl.Tombstones.Actors, rec.Actor) {
				return fmt.Errorf("recovery omitted witnessed actor removal tombstone %s", rec.Actor)
			}
		case "actor_move":
			if na := nl.Actors[rec.Actor]; na != nil {
				if ta := tailEnd.Line.Actors[rec.Actor]; ta != nil && na.BindingGen < ta.BindingGen {
					return fmt.Errorf("recovery regressed binding_gen for moved actor %s: got %d, witnessed %d", rec.Actor, na.BindingGen, ta.BindingGen)
				}
			}
		case "register_activate":
			key := rec.Actor + "/" + rec.Register
			if nw := nl.RegisterWriters[key]; nw != nil {
				if !slices.Contains(nw.Used, rec.Incarnation) {
					return fmt.Errorf("recovery omitted witnessed register incarnation %s for %s", rec.Incarnation, key)
				}
				if tw := tailEnd.Line.RegisterWriters[key]; tw != nil && nw.WriterRev < tw.WriterRev {
					return fmt.Errorf("recovery regressed writer_rev for %s: got %d, witnessed %d", key, nw.WriterRev, tw.WriterRev)
				}
			}
		case "call_open":
			if !slices.Contains(nl.Tombstones.Calls, rec.Call) {
				return fmt.Errorf("recovery omitted witnessed discarded call tombstone %s", rec.Call)
			}
		case "broadcast_create":
			if !slices.Contains(nl.Tombstones.Broadcasts, rec.Broadcast) {
				return fmt.Errorf("recovery omitted witnessed discarded broadcast tombstone %s", rec.Broadcast)
			}
		}
	}
	return nil
}
