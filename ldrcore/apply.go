package ldrcore

import (
	"slices"
	"strconv"
)

// The rejection ladder of spec section 5.8. When several preconditions fail,
// the lowest rung decides, so every implementation records the same durable
// outcome for the same intent.
type rung int

const (
	rInvalidSyntax rung = iota // malformed regardless of state
	rTooLarge                  // record-specific content limit
	rUnauthOrigin              // binding, declaration capability or capacity, ownership, role
	rAuthEpoch                 // the intent's auth_epoch is not current
	rUnknownTarget             // a referenced object does not exist or is not live
	rUnauthTarget              // not a participant, recipient, or the reserved party
	rRekeyPending              // payload-bearing record while a rekey is pending
	rKeyEpoch                  // payload-bearing record under a superseded key epoch
	rConflict                  // identifier collision, or a stale expect value
	rInvalidState              // well-formed but wrong against current state
	rNotOpen                   // the target does not accept the action in its state
	rNotFloor
	rExhausted // a counter the record must advance is at MaxCounter
	numRungs
)

var rungReason = [numRungs]string{
	rInvalidSyntax: "invalid",
	rTooLarge:      "too_large",
	rUnauthOrigin:  "unauthorized",
	rAuthEpoch:     "conflict",
	rUnknownTarget: "unknown_target",
	rUnauthTarget:  "unauthorized",
	rRekeyPending:  "rekey_pending",
	rKeyEpoch:      "conflict",
	rConflict:      "conflict",
	rInvalidState:  "invalid",
	rNotOpen:       "not_open",
	rNotFloor:      "not_floor",
	rExhausted:     "exhausted",
}

// plan collects one record's preconditions by rung, and its effect. A check
// returns true when it passes. Checks run in rung order and stop at the first
// failure, so a check may rely on everything a lower rung established: a
// participant check can dereference the call an existence check found.
type plan struct {
	checks [numRungs][]func() bool
	// noop, when set, runs after every check passed. It reports whether the
	// record has nothing to change and, if the state records it, which record
	// already established that state.
	noop   func() (refSeq int64, is bool)
	effect func()
	// exhausted is set by inc when an effect needed to advance a counter
	// that was already at MaxCounter. The whole effect is then discarded.
	exhausted bool
}

func (p *plan) require(r rung, ok func() bool) { p.checks[r] = append(p.checks[r], ok) }

// inc advances a counter by one, or records that it could not. Effects use it
// for every counter, so nothing in a State can wrap.
func (p *plan) inc(n *int64) {
	if *n >= MaxCounter {
		p.exhausted = true
		return
	}
	*n++
}

// Apply is the transition function of LDR phase 1:
//
//	apply(state, record, seq_time) -> (state', outcome)
//
// It is pure: no I/O, no clock, no randomness. It never modifies s. On any
// outcome other than Committed the returned state is s itself.
//
// Apply covers stage 5 of the spec's pipeline only. It assumes the record was
// decoded within bounds, its signature verified and the intent admitted. It
// does not implement dedup, the outcome index, the time floor, anchors'
// request handling, or anything else in the sequencer shell.
func Apply(s State, r Record, seqTime int64, prof Profile) (State, Outcome) {
	// A sequencer-assigned time below its predecessor's is not a property of
	// the intent. No honest sequencer stamps it.
	if seqTime < s.Line.HeadTime || seqTime > MaxCounter {
		return s, Outcome{Kind: Violation}
	}
	// The genesis boundary. An empty log has no line, no head to anchor on and
	// no predecessor, so its first record can only be line_init. Anything else
	// there was not admitted by an honest sequencer. This is enforced here and
	// not left to an admission shell this package does not have.
	if s.Line.Generation == 0 && r.Type != "line_init" {
		return s, Outcome{Kind: Violation}
	}
	if r.Origin == OriginSequencer {
		return applySequencer(s, r, seqTime, prof)
	}

	next := s.Clone()
	p := &plan{}
	buildCommon(p, &next, &r, prof)
	build, known := builders[r.Type]
	if known {
		build(p, &next, &r)
	}

	for rg := rung(0); rg < numRungs; rg++ {
		for _, ok := range p.checks[rg] {
			if !ok() {
				return s, Outcome{Kind: Rejected, Reason: rungReason[rg]}
			}
		}
	}
	if p.noop != nil {
		if ref, is := p.noop(); is {
			return s, Outcome{Kind: Noop, RefSeq: ref}
		}
	}
	// Exhaustion is the last rung: it applies only to a record that would
	// otherwise commit, so a rejection or a no-op at an exhausted counter is
	// reported exactly as it would be anywhere else. The effect ran on a
	// clone, which is dropped here, so nothing partial survives.
	p.effect()
	p.inc(&next.Line.HeadSeq)
	if p.exhausted {
		return s, Outcome{Kind: Rejected, Reason: rungReason[rExhausted]}
	}
	next.Line.HeadTime = seqTime
	return next, Outcome{Kind: Committed}
}

// applySequencer handles the typed verification path. time_anchor is the only
// sequencer-origin record in phase 1, and its precondition is checkable from
// the chain alone: it is more than F after its predecessor. Apply has already
// refused it on an empty log, where there is no predecessor.
func applySequencer(s State, r Record, seqTime int64, prof Profile) (State, Outcome) {
	// A sequencer whose sequence space is exhausted has nowhere to put an
	// anchor; one that appears anyway was not produced honestly.
	if r.Type != "time_anchor" || seqTime-s.Line.HeadTime <= prof.FreshnessMS || s.Line.HeadSeq >= MaxCounter {
		return s, Outcome{Kind: Violation}
	}
	next := s.Clone()
	next.Line.HeadSeq = s.Line.HeadSeq + 1
	next.Line.HeadTime = seqTime
	return next, Outcome{Kind: Committed}
}

// buildCommon adds the checks every signed record shares.
func buildCommon(p *plan, s *State, r *Record, prof Profile) {
	l := &s.Line
	want, known := recordOrigin[r.Type]

	p.require(rInvalidSyntax, func() bool { return known })
	p.require(rInvalidSyntax, func() bool { return r.ValidityMS >= 0 && r.ValidityMS <= prof.ValidityMaxMS })
	p.require(rInvalidSyntax, func() bool { return !r.UnexpectedLineCiphertext || r.carriesLineCiphertext() })

	// Record-specific content limit. It applies to every record that carries
	// line ciphertext, not only attachments. A size on a ciphertext-free
	// record, or a size class that does not exist, is malformed. This is not
	// the transport envelope bound, which is an admission matter.
	p.require(rInvalidSyntax, func() bool {
		return r.SizeClass == "" || (sizeClasses[r.SizeClass] && r.carriesLineCiphertext())
	})
	p.require(rTooLarge, func() bool { return r.SizeClass != "over_inline_limit" })

	// Origin authorization. A record type has exactly one origin, so an actor
	// attempting an operator's record fails here, not as a malformed record.
	p.require(rUnauthOrigin, func() bool { return r.Origin == want })
	switch r.Origin {
	case OriginActor:
		p.require(rUnauthOrigin, func() bool {
			c, a := l.Credentials[r.Cred], l.Actors[r.Actor]
			return c != nil && !c.Revoked && a != nil && a.Live &&
				a.Cred == r.Cred && a.BindingGen == r.BindingGen
		})
	case OriginCredential:
		p.require(rUnauthOrigin, func() bool {
			c := l.Credentials[r.Cred]
			return c != nil && !c.Revoked
		})
	case OriginOperator:
		p.require(rUnauthOrigin, func() bool { return slices.Contains(l.Operators, r.Operator) })
	case OriginRoot:
		if r.Type != "line_init" {
			p.require(rUnauthOrigin, func() bool { return slices.Contains(l.RootKeys, r.RootKey) })
		}
	}

	// line_init has no prior state to hold an epoch.
	if r.Type != "line_init" {
		p.require(rAuthEpoch, func() bool { return r.AuthEpoch == l.AuthEpoch })
	}

	if r.carriesLineCiphertext() {
		p.require(rRekeyPending, func() bool { return !l.RekeyPending })
		p.require(rKeyEpoch, func() bool { return r.KeyEpoch == l.KeyEpoch })
	}

	// An unknown type has no effect to run; the rInvalidSyntax check above
	// rejects it before this is reached.
	p.effect = func() {}
}

var builders = map[string]func(p *plan, s *State, r *Record){
	"line_init":              buildLineInit,
	"operator_key_authorize": buildOperatorKeyAuthorize,
	"operator_key_revoke":    buildOperatorKeyRevoke,
	"root_member_replace":    buildRootMemberReplace,
	"credential_enroll":      buildCredentialEnroll,
	"credential_revoke":      buildCredentialRevoke,
	"key_epoch_activate":     buildKeyEpochActivate,
	"actor_declare":          buildActorDeclare,
	"actor_move":             buildActorMove,
	"actor_remove":           buildActorRemove,
	"actor_addressing":       buildActorAddressing,
	"register_activate":      buildRegisterActivate,
	"call_open":              buildCallOpen,
	"call_turn":              buildCallTurn,
	"call_bye":               buildCallBye,
	"call_status":            buildCallStatus,
	"call_note":              buildCallNote,
	"call_ratify":            buildCallRatify,
	"call_attach":            buildCallAttach,
	"dispute_open":           buildDisputeOpen,
	"dispute_measure":        buildDisputeMeasure,
	"dispute_resolve":        buildDisputeResolve,
	"dispute_arbitrate":      buildDisputeArbitrate,
	"broadcast_create":       buildBroadcastCreate,
	"broadcast_read":         buildBroadcastRead,
	"broadcast_reply":        buildBroadcastReply,
}

func is(got *int64, want int64) bool { return got != nil && *got == want }

// ---------------------------------------------------------------- root

func buildLineInit(p *plan, s *State, r *Record) {
	l := &s.Line
	// Equal 1-of-2 roots: line_init provisions exactly two distinct root keys
	// and is signed by one of them.
	p.require(rInvalidSyntax, func() bool {
		return len(r.RootKeys) == 2 &&
			r.RootKeys[0] != "" && r.RootKeys[1] != "" &&
			r.RootKeys[0] != r.RootKeys[1] &&
			r.RootKey != "" && slices.Contains(r.RootKeys, r.RootKey)
	})
	// The line already existing is a collision on the one identifier a log
	// has: itself.
	p.require(rConflict, func() bool { return l.Generation == 0 })
	p.effect = func() {
		*l = Line{
			Generation:      1,
			RootKeys:        canonSet(r.RootKeys), // the first two entries of the key registry
			RootRev:         1,
			RekeyPending:    true, // nothing payload-bearing commits before the first activation
			Operators:       []string{},
			Credentials:     map[string]*Credential{},
			Readers:         map[int64][]string{},
			Tombstones:      Tombstones{Creds: []string{}, Actors: []string{}, JoinRequests: []string{}, OperatorKeys: []string{}, RootKeys: []string{}},
			Actors:          map[string]*Actor{},
			RegisterWriters: map[string]*RegisterWriter{},
		}
	}
}

func buildOperatorKeyAuthorize(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.OperatorKey != "" && r.Expect.RootRev != nil })
	// A key that has held any role is reserved for life. That covers a key
	// already authorized, a revoked operator key, which is never authorized
	// again, a credential's key, and an active or replaced root key.
	p.require(rConflict, func() bool { return !l.keyUsed(r.OperatorKey) })
	p.require(rConflict, func() bool { return is(r.Expect.RootRev, l.RootRev) })
	p.effect = func() {
		l.Operators = addToSet(l.Operators, r.OperatorKey)
		p.inc(&l.RootRev)
		p.inc(&l.AuthEpoch)
	}
}

func buildOperatorKeyRevoke(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.OperatorKey != "" && r.Expect.RootRev != nil })
	p.require(rUnknownTarget, func() bool { return slices.Contains(l.Operators, r.OperatorKey) })
	p.require(rConflict, func() bool { return is(r.Expect.RootRev, l.RootRev) })
	p.effect = func() {
		l.Operators = slices.DeleteFunc(slices.Clone(l.Operators), func(k string) bool { return k == r.OperatorKey })
		// The tombstone is what later tells this key from one that was never
		// authorized, and what keeps it from being authorized again.
		l.Tombstones.OperatorKeys = addToSet(l.Tombstones.OperatorKeys, r.OperatorKey)
		p.inc(&l.RootRev)
		p.inc(&l.AuthEpoch)
	}
}

func buildRootMemberReplace(p *plan, s *State, r *Record) {
	l := &s.Line
	// Threshold (1) and set size (2) stay fixed: an active root replaces the
	// other active root with a fresh key, never itself, and never with itself
	// or with the key being replaced.
	p.require(rInvalidSyntax, func() bool {
		return r.OldRootKey != "" && r.NewRootKey != "" &&
			r.OldRootKey != r.NewRootKey &&
			r.OldRootKey != r.RootKey &&
			r.NewRootKey != r.RootKey &&
			r.Expect.RootRev != nil
	})
	p.require(rUnknownTarget, func() bool { return slices.Contains(l.RootKeys, r.OldRootKey) })
	p.require(rConflict, func() bool { return !l.keyUsed(r.NewRootKey) })
	p.require(rConflict, func() bool { return is(r.Expect.RootRev, l.RootRev) })
	p.effect = func() {
		l.RootKeys = slices.DeleteFunc(slices.Clone(l.RootKeys), func(k string) bool { return k == r.OldRootKey })
		l.RootKeys = addToSet(l.RootKeys, r.NewRootKey)
		l.Tombstones.RootKeys = addToSet(l.Tombstones.RootKeys, r.OldRootKey)
		p.inc(&l.RootRev)
		p.inc(&l.AuthEpoch)
	}
}

// ---------------------------------------------------- membership and keys

func buildCredentialEnroll(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool {
		// A limit of zero is a reader-only grant: the credential can read
		// and cannot declare actors.
		return r.Cred != "" && r.JoinRequest != "" && r.JoinRequestDigest != "" && r.Grant != nil &&
			r.Grant.Namespace != "" && r.Grant.ActorLimit >= 0
	})
	// A credential is two different keys, and its identifier is their
	// derivation. Both are wrong whatever the state, so they are malformed
	// and not a collision.
	p.require(rInvalidSyntax, func() bool {
		return r.SigningKey != "" && r.EncryptionKey != "" && r.SigningKey != r.EncryptionKey
	})
	p.require(rInvalidSyntax, func() bool { return !r.CredIDMismatch })
	// An enrollment reserves five things, and none may have been used before:
	// the join request, the credential identifier, each of the two keys, and
	// the namespace, which has exactly one declaration owner in phase 1.
	p.require(rConflict, func() bool { return !slices.Contains(l.Tombstones.JoinRequests, r.JoinRequest) })
	// With a sound derivation an identifier collides only when both keys do.
	// The check stands on its own so that the rule does not rest on that.
	p.require(rConflict, func() bool {
		return l.Credentials[r.Cred] == nil && !slices.Contains(l.Tombstones.Creds, r.Cred)
	})
	// Each key separately: a used key cannot return with a fresh partner, in
	// this role or another.
	p.require(rConflict, func() bool { return !l.keyUsed(r.SigningKey) })
	p.require(rConflict, func() bool { return !l.keyUsed(r.EncryptionKey) })
	p.require(rConflict, func() bool {
		for _, c := range l.Credentials {
			if c.Namespace == r.Grant.Namespace {
				return false
			}
		}
		return true
	})
	p.effect = func() {
		l.Credentials[r.Cred] = &Credential{
			SigningKey:    r.SigningKey,
			EncryptionKey: r.EncryptionKey,
			Namespace:     r.Grant.Namespace,
			ActorLimit:    r.Grant.ActorLimit,
			Reader:        r.Grant.Reader,
		}
		l.Tombstones.JoinRequests = addToSet(l.Tombstones.JoinRequests, r.JoinRequest)
		p.inc(&l.AuthEpoch)
		// The new member must never receive the epoch that carried earlier
		// traffic, so nothing payload-bearing commits until a new one is out.
		l.RekeyPending = true
	}
}

func buildCredentialRevoke(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.Cred != "" })
	p.require(rUnknownTarget, func() bool {
		c := l.Credentials[r.Cred]
		return c != nil && !c.Revoked
	})
	p.effect = func() {
		l.Credentials[r.Cred].Revoked = true
		l.Tombstones.Creds = addToSet(l.Tombstones.Creds, r.Cred)
		for id, a := range l.Actors {
			if a.Cred == r.Cred && a.Live {
				a.Live = false
				l.Tombstones.Actors = addToSet(l.Tombstones.Actors, id)
			}
		}
		p.inc(&l.AuthEpoch)
		p.inc(&l.AudienceRev)
		l.RekeyPending = true
	}
}

func buildKeyEpochActivate(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool {
		return r.Expect.KeyEpoch != nil && len(r.Manifest) > 0 && !hasDuplicates(r.Manifest)
	})
	p.require(rConflict, func() bool { return is(r.Expect.KeyEpoch, l.KeyEpoch) })
	// A manifest computed against a stale epoch hears "re-read" above. Only a
	// manifest that is wrong against the state its signer saw is invalid.
	p.require(rInvalidState, func() bool { return sameSet(r.Manifest, l.EntitledReaders()) })
	p.effect = func() {
		p.inc(&l.KeyEpoch)
		l.Readers[l.KeyEpoch] = canonSet(r.Manifest)
		l.RekeyPending = false
	}
}

// ------------------------------------------------------------------ actors

func buildActorDeclare(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.Actor != "" && r.Namespace != "" })
	// Declaration capability: the signer's own namespace, and room in it.
	p.require(rUnauthOrigin, func() bool {
		c := l.Credentials[r.Cred]
		return c.Namespace == r.Namespace && l.liveInNamespace(r.Namespace) < c.ActorLimit
	})
	p.require(rConflict, func() bool {
		return l.Actors[r.Actor] == nil && !slices.Contains(l.Tombstones.Actors, r.Actor)
	})
	p.effect = func() {
		l.Actors[r.Actor] = &Actor{
			Namespace:        r.Namespace,
			Cred:             r.Cred,
			BindingGen:       1,
			AddrRev:          1,
			DefaultAddressed: true,
			Live:             true,
		}
		p.inc(&l.AudienceRev)
	}
}

func buildActorMove(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool {
		return r.Actor != "" && r.ToCred != "" && r.Expect.BindingGen != nil
	})
	// A removed actor is not a target: it cannot be moved back to life.
	p.require(rUnknownTarget, func() bool {
		a, c := l.Actors[r.Actor], l.Credentials[r.ToCred]
		return a != nil && a.Live && c != nil && !c.Revoked
	})
	p.require(rConflict, func() bool { return is(r.Expect.BindingGen, l.Actors[r.Actor].BindingGen) })
	p.require(rInvalidState, func() bool { return l.Actors[r.Actor].Cred != r.ToCred })
	p.effect = func() {
		a := l.Actors[r.Actor]
		a.Cred = r.ToCred
		p.inc(&a.BindingGen)
		p.inc(&l.AuthEpoch)
		p.inc(&l.AudienceRev)
	}
}

// ownsActor is current ownership: the actor exists, is live, and is bound to
// the signing credential now. It does not look at the actor's namespace.
func ownsActor(l *Line, r *Record) bool {
	a := l.Actors[r.Actor]
	return a != nil && a.Live && a.Cred == r.Cred
}

func buildActorRemove(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.Actor != "" && r.Expect.BindingGen != nil })
	p.require(rUnauthOrigin, func() bool { return ownsActor(l, r) })
	p.require(rConflict, func() bool { return is(r.Expect.BindingGen, l.Actors[r.Actor].BindingGen) })
	p.effect = func() {
		l.Actors[r.Actor].Live = false
		l.Tombstones.Actors = addToSet(l.Tombstones.Actors, r.Actor)
		p.inc(&l.AudienceRev)
	}
}

func buildActorAddressing(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.Expect.AddrRev != nil })
	p.require(rConflict, func() bool { return is(r.Expect.AddrRev, l.Actors[r.Actor].AddrRev) })
	p.effect = func() {
		a := l.Actors[r.Actor]
		a.DefaultAddressed = r.DefaultAddressed
		p.inc(&a.AddrRev)
		p.inc(&l.AudienceRev)
	}
}

func buildRegisterActivate(p *plan, s *State, r *Record) {
	l := &s.Line
	key := r.Actor + "/" + r.Register
	p.require(rInvalidSyntax, func() bool {
		return r.Actor != "" && registerTypes[r.Register] && r.Incarnation != "" && r.Expect.WriterRev != nil
	})
	p.require(rUnauthOrigin, func() bool { return ownsActor(l, r) })
	p.require(rConflict, func() bool {
		var cur int64
		if w := l.RegisterWriters[key]; w != nil {
			cur = w.WriterRev
		}
		return is(r.Expect.WriterRev, cur)
	})
	// An incarnation is never reused for this writer, by any owner.
	p.require(rConflict, func() bool {
		w := l.RegisterWriters[key]
		return w == nil || !slices.Contains(w.Used, r.Incarnation)
	})
	p.effect = func() {
		w := l.RegisterWriters[key]
		if w == nil {
			w = &RegisterWriter{}
			l.RegisterWriters[key] = w
		}
		p.inc(&w.WriterRev)
		w.Incarnation = r.Incarnation
		w.BindingGen = l.Actors[r.Actor].BindingGen
		w.Used = addToSet(w.Used, r.Incarnation)
	}
}

// ------------------------------------------------------------------- calls

// requireParticipant adds the two checks every participant action shares.
func requireParticipant(p *plan, s *State, r *Record) {
	p.require(rInvalidSyntax, func() bool { return r.Call != "" })
	p.require(rUnknownTarget, func() bool { return s.Calls[r.Call] != nil })
	p.require(rUnauthTarget, func() bool { return s.Calls[r.Call].Involves(r.Actor) })
}

func buildCallOpen(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool { return r.Call != "" && r.To != "" && r.To != r.Actor })
	p.require(rUnknownTarget, func() bool {
		to := l.Actors[r.To]
		return to != nil && to.Live
	})
	// An existing call is never silently joined or reused.
	p.require(rConflict, func() bool { return s.Calls[r.Call] == nil })
	p.effect = func() {
		p.inc(&l.CallCount)
		s.Calls[r.Call] = &Call{
			CallNo:       l.CallCount,
			From:         r.Actor,
			To:           r.To,
			TurnCount:    1, // call_open carries turn 1
			LastTurnFrom: r.Actor,
			Lifecycle:    "open",
			Byes:         []string{},
			Links:        []string{},
			Disputes:     map[string]*Dispute{},
		}
	}
}

func buildCallTurn(p *plan, s *State, r *Record) {
	requireParticipant(p, s, r)
	p.require(rInvalidSyntax, func() bool { return r.Expect.TurnCount != nil })
	// A barge skips the floor check, not the count: it still names what its
	// author had seen.
	p.require(rConflict, func() bool { return is(r.Expect.TurnCount, s.Calls[r.Call].TurnCount) })
	p.require(rNotOpen, func() bool { return s.Calls[r.Call].Status() == "open" })
	p.require(rNotFloor, func() bool { return r.Barge || s.Calls[r.Call].Floor() == r.Actor })
	p.effect = func() {
		c := s.Calls[r.Call]
		p.inc(&c.TurnCount)
		c.LastTurnFrom = r.Actor
		c.Byes = []string{} // somebody still needed something
	}
}

func buildCallBye(p *plan, s *State, r *Record) {
	requireParticipant(p, s, r)
	p.require(rInvalidSyntax, func() bool { return r.Expect.TurnCount != nil && r.Expect.LifecycleRev != nil })
	p.require(rConflict, func() bool {
		c := s.Calls[r.Call]
		return is(r.Expect.TurnCount, c.TurnCount) && is(r.Expect.LifecycleRev, c.LifecycleRev)
	})
	p.require(rNotOpen, func() bool { return s.Calls[r.Call].Status() == "open" })
	// A second bye from the same participant has nothing to change. The state
	// does not record which record set the first, so no reference is given.
	p.noop = func() (int64, bool) { return 0, slices.Contains(s.Calls[r.Call].Byes, r.Actor) }
	p.effect = func() {
		c := s.Calls[r.Call]
		c.Byes = addToSet(c.Byes, r.Actor)
	}
}

func buildCallStatus(p *plan, s *State, r *Record) {
	requireParticipant(p, s, r)
	linked := r.State == "linked"
	p.require(rInvalidSyntax, func() bool {
		if !lifecycleStates[r.State] || r.Expect.LifecycleRev == nil || r.Expect.TurnCount == nil {
			return false
		}
		if linked {
			return r.Related != "" && r.Related != r.Call
		}
		return r.Related == ""
	})
	if linked {
		p.require(rUnknownTarget, func() bool { return s.Calls[r.Related] != nil })
		p.require(rUnauthTarget, func() bool { return s.Calls[r.Related].Involves(r.Actor) })
	}
	// A status decision names the turn count as well as the lifecycle
	// revision, so it cannot commit over a turn its author never read.
	p.require(rConflict, func() bool {
		c := s.Calls[r.Call]
		return is(r.Expect.LifecycleRev, c.LifecycleRev) && is(r.Expect.TurnCount, c.TurnCount)
	})
	p.effect = func() {
		c := s.Calls[r.Call]
		p.inc(&c.LifecycleRev)
		switch r.State {
		case "linked":
			c.Links = addToSet(c.Links, r.Related)
		case "open":
			c.Lifecycle = "open"
			c.Byes = []string{}
		default:
			c.Lifecycle = r.State
		}
	}
}

func buildCallNote(p *plan, s *State, r *Record) {
	requireParticipant(p, s, r)
	// A note cannot create an obligation: floor, byes and lifecycle are
	// untouched, and no lifecycle state refuses one.
	p.effect = func() { p.inc(&s.Calls[r.Call].NoteCount) }
}

func buildCallRatify(p *plan, s *State, r *Record) {
	p.require(rInvalidSyntax, func() bool { return r.Call != "" })
	p.require(rUnknownTarget, func() bool { return s.Calls[r.Call] != nil })
	p.effect = func() { p.inc(&s.Calls[r.Call].NoteCount) }
}

func buildCallAttach(p *plan, s *State, r *Record) {
	requireParticipant(p, s, r)
	// An attachment must state its size class; the limit itself is checked
	// for every payload-bearing record in buildCommon.
	p.require(rInvalidSyntax, func() bool { return r.SizeClass != "" })
	p.effect = func() { p.inc(&s.Calls[r.Call].AttachCount) }
}

// ---------------------------------------------------------------- disputes

func requireDispute(p *plan, s *State, r *Record) {
	p.require(rInvalidSyntax, func() bool { return r.Call != "" && r.Dispute != "" })
	p.require(rUnknownTarget, func() bool {
		c := s.Calls[r.Call]
		return c != nil && c.Disputes[r.Dispute] != nil
	})
}

func buildDisputeOpen(p *plan, s *State, r *Record) {
	requireParticipant(p, s, r)
	p.effect = func() {
		c := s.Calls[r.Call]
		p.inc(&c.DisputeCount)
		c.Disputes[strconv.FormatInt(c.DisputeCount, 10)] = &Dispute{
			OpenedBy:   r.Actor,
			Rev:        1,
			MeasureRev: map[string]int64{c.From: 0, c.To: 0},
		}
	}
}

func buildDisputeMeasure(p *plan, s *State, r *Record) {
	requireDispute(p, s, r)
	p.require(rInvalidSyntax, func() bool { return r.Expect.MeasureRev != nil })
	p.require(rUnauthTarget, func() bool { return s.Calls[r.Call].Involves(r.Actor) })
	// Only the signer's own slot is checked, so two participants measuring at
	// once do not conflict with each other.
	p.require(rConflict, func() bool {
		return is(r.Expect.MeasureRev, s.Calls[r.Call].Disputes[r.Dispute].MeasureRev[r.Actor])
	})
	p.require(rNotOpen, func() bool { return !s.Calls[r.Call].Disputes[r.Dispute].Resolved })
	p.effect = func() {
		d := s.Calls[r.Call].Disputes[r.Dispute]
		own := d.MeasureRev[r.Actor]
		p.inc(&own)
		d.MeasureRev[r.Actor] = own
		// Every measurement advances the revision a resolution checks, so a
		// resolution cannot commit over evidence its author has not seen.
		p.inc(&d.Rev)
	}
}

func buildDisputeResolve(p *plan, s *State, r *Record) {
	requireDispute(p, s, r)
	p.require(rInvalidSyntax, func() bool {
		return (r.Kind == "measured" || r.Kind == "withdrawn") && r.Expect.Rev != nil
	})
	p.require(rUnauthTarget, func() bool {
		c := s.Calls[r.Call]
		if !c.Involves(r.Actor) {
			return false
		}
		// One participant must not appear to withdraw the other's claim.
		return r.Kind != "withdrawn" || c.Disputes[r.Dispute].OpenedBy == r.Actor
	})
	p.require(rConflict, func() bool { return is(r.Expect.Rev, s.Calls[r.Call].Disputes[r.Dispute].Rev) })
	p.require(rNotOpen, func() bool { return !s.Calls[r.Call].Disputes[r.Dispute].Resolved })
	p.effect = func() {
		d := s.Calls[r.Call].Disputes[r.Dispute]
		p.inc(&d.Rev)
		d.Resolved = true
		d.Resolution = &Resolution{Kind: r.Kind, By: r.Actor}
	}
}

func buildDisputeArbitrate(p *plan, s *State, r *Record) {
	requireDispute(p, s, r)
	p.require(rInvalidSyntax, func() bool { return r.Expect.Rev != nil })
	p.require(rConflict, func() bool { return is(r.Expect.Rev, s.Calls[r.Call].Disputes[r.Dispute].Rev) })
	// Arbitration may supersede an earlier resolution, so no not_open check.
	p.effect = func() {
		d := s.Calls[r.Call].Disputes[r.Dispute]
		p.inc(&d.Rev)
		d.Resolved = true
		d.Resolution = &Resolution{Kind: "human", By: r.Operator}
	}
}

// -------------------------------------------------------------- broadcasts

func buildBroadcastCreate(p *plan, s *State, r *Record) {
	l := &s.Line
	p.require(rInvalidSyntax, func() bool {
		if r.Broadcast == "" || !broadcastKinds[r.Kind] || len(r.Recipients) == 0 || hasDuplicates(r.Recipients) {
			return false
		}
		// A list composed from the default audience must say which audience.
		return !r.DefaultAudience || r.Expect.AudienceRev != nil
	})
	p.require(rUnknownTarget, func() bool {
		for _, id := range r.Recipients {
			if a := l.Actors[id]; a == nil || !a.Live {
				return false
			}
		}
		return true
	})
	p.require(rConflict, func() bool { return s.Broadcasts[r.Broadcast] == nil })
	// Only a default-audience list conflicts on an audience change. An
	// explicit list does not care about unrelated addressing changes.
	p.require(rConflict, func() bool { return !r.DefaultAudience || is(r.Expect.AudienceRev, l.AudienceRev) })
	// A list that says it is the default audience must be exactly that, as a
	// set, at the revision it names. A custom subset uses the explicit mode.
	// The stale-revision check above comes first: a list computed against an
	// old audience hears "re-read", not "invalid".
	p.require(rInvalidState, func() bool {
		return !r.DefaultAudience || sameSet(r.Recipients, l.DefaultAudience())
	})
	p.effect = func() {
		// The signed list stays verbatim in the log record. State holds it as
		// a set, which is a derived index and not a rewrite of what was signed.
		s.Broadcasts[r.Broadcast] = &Broadcast{
			Kind:            r.Kind,
			Recipients:      canonSet(r.Recipients),
			DefaultAudience: r.DefaultAudience,
			Receipts:        map[string]Receipt{},
			ReplyCount:      map[string]int64{},
		}
	}
}

func requireRecipient(p *plan, s *State, r *Record) {
	p.require(rInvalidSyntax, func() bool { return r.Broadcast != "" })
	p.require(rUnknownTarget, func() bool { return s.Broadcasts[r.Broadcast] != nil })
	p.require(rUnauthTarget, func() bool { return slices.Contains(s.Broadcasts[r.Broadcast].Recipients, r.Actor) })
}

func buildBroadcastRead(p *plan, s *State, r *Record) {
	requireRecipient(p, s, r)
	// A different read operation by the same recipient names the first read
	// without pretending to be its receipt.
	p.noop = func() (int64, bool) {
		rc, ok := s.Broadcasts[r.Broadcast].Receipts[r.Actor]
		return rc.ReadSeq, ok
	}
	p.effect = func() {
		s.Broadcasts[r.Broadcast].Receipts[r.Actor] = Receipt{ReadSeq: s.Line.HeadSeq + 1}
	}
}

func buildBroadcastReply(p *plan, s *State, r *Record) {
	requireRecipient(p, s, r)
	p.effect = func() {
		b := s.Broadcasts[r.Broadcast]
		replies := b.ReplyCount[r.Actor]
		p.inc(&replies)
		b.ReplyCount[r.Actor] = replies
		if _, ok := b.Receipts[r.Actor]; !ok {
			b.Receipts[r.Actor] = Receipt{ReadSeq: s.Line.HeadSeq + 1}
		}
	}
}
