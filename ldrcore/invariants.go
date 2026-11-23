package ldrcore

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// CheckInvariants reports every way s fails to be a coherent state. A state
// produced by Apply from a coherent state must be coherent, and a test fixture
// that is not coherent is testing something no line can reach.
//
// It is deliberately independent of Canon: Canon sorts and deduplicates sets,
// so comparing canonical forms would hide an Apply that emitted an unsorted or
// duplicated set. This checks the raw state.
func (s State) CheckInvariants() []string {
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	set := func(name string, v []string) {
		if !slices.IsSorted(v) {
			fail("%s is not sorted: %v", name, v)
		}
		if hasDuplicates(v) {
			fail("%s has duplicates: %v", name, v)
		}
	}
	l := &s.Line

	domain := func(name string, v int64) {
		if v < 0 || v > MaxCounter {
			fail("%s is %d, outside the counter domain [0, %d]", name, v, MaxCounter)
		}
	}
	domain("head_seq", l.HeadSeq)
	domain("head_time", l.HeadTime)
	domain("generation", l.Generation)
	domain("root_rev", l.RootRev)
	domain("auth_epoch", l.AuthEpoch)
	domain("audience_rev", l.AudienceRev)
	domain("key_epoch", l.KeyEpoch)
	domain("call_count", l.CallCount)
	for id, c := range l.Credentials {
		domain("credential "+id+" actor_limit", c.ActorLimit)
	}
	for id, a := range l.Actors {
		domain("actor "+id+" binding_gen", a.BindingGen)
		domain("actor "+id+" addr_rev", a.AddrRev)
	}
	for id, w := range l.RegisterWriters {
		domain("register writer "+id+" writer_rev", w.WriterRev)
		domain("register writer "+id+" binding_gen", w.BindingGen)
	}
	for id, c := range s.Calls {
		domain("call "+id+" call_no", c.CallNo)
		domain("call "+id+" turn_count", c.TurnCount)
		domain("call "+id+" lifecycle_rev", c.LifecycleRev)
		domain("call "+id+" note_count", c.NoteCount)
		domain("call "+id+" attach_count", c.AttachCount)
		domain("call "+id+" dispute_count", c.DisputeCount)
		for did, d := range c.Disputes {
			domain("call "+id+" dispute "+did+" rev", d.Rev)
			for who, n := range d.MeasureRev {
				domain("call "+id+" dispute "+did+" measure_rev "+who, n)
			}
		}
	}
	for id, b := range s.Broadcasts {
		for who, rc := range b.Receipts {
			domain("broadcast "+id+" receipt "+who, rc.ReadSeq)
		}
		for who, n := range b.ReplyCount {
			domain("broadcast "+id+" reply_count "+who, n)
		}
	}

	if l.Generation == 0 {
		// No line exists. Nothing else may.
		if l.RootRev != 0 || l.AuthEpoch != 0 || l.AudienceRev != 0 || l.KeyEpoch != 0 || l.CallCount != 0 ||
			l.RootKey != "" ||
			len(l.Operators)+len(l.Credentials)+len(l.Readers)+len(l.Actors)+len(l.RegisterWriters) != 0 ||
			len(l.Tombstones.Creds)+len(l.Tombstones.Actors)+len(l.Tombstones.JoinRequests)+len(l.Tombstones.OperatorKeys) != 0 ||
			len(s.Calls)+len(s.Broadcasts) != 0 {
			fail("generation 0 with line state present")
		}
		return bad
	}

	set("operators", l.Operators)
	set("tombstones.creds", l.Tombstones.Creds)
	set("tombstones.actors", l.Tombstones.Actors)
	set("tombstones.join_requests", l.Tombstones.JoinRequests)
	set("tombstones.operator_keys", l.Tombstones.OperatorKeys)

	// The key registry: every public key holds exactly one role, for life.
	holder := map[string]string{}
	hold := func(key, role string) {
		switch other, dup := holder[key]; {
		case key == "":
			fail("%s has no key", role)
		case dup:
			fail("key %s is held by both %s and %s", key, other, role)
		default:
			holder[key] = role
		}
	}
	hold(l.RootKey, "the root")
	for _, k := range l.Operators {
		hold(k, "operator "+k)
	}
	for _, k := range l.Tombstones.OperatorKeys {
		hold(k, "revoked operator "+k)
	}
	for _, id := range sortedKeys(l.Credentials) {
		hold(l.Credentials[id].SigningKey, "credential "+id+" (signing)")
		hold(l.Credentials[id].EncryptionKey, "credential "+id+" (encryption)")
	}
	// A revoked credential keeps its entry: that entry is what reserves its
	// keys and its namespace.
	for _, id := range l.Tombstones.Creds {
		if l.Credentials[id] == nil {
			fail("tombstoned credential %s has no entry", id)
		}
	}

	namespaces := map[string]string{}
	for id, c := range l.Credentials {
		if c.ActorLimit < 0 {
			fail("credential %s has a negative actor limit", id)
		}
		if other, dup := namespaces[c.Namespace]; dup {
			fail("namespace %s is granted to both %s and %s", c.Namespace, other, id)
		}
		namespaces[c.Namespace] = id
		if c.Revoked != slices.Contains(l.Tombstones.Creds, id) {
			fail("credential %s: revoked=%v but tombstoned=%v", id, c.Revoked, !c.Revoked)
		}
	}
	for ns, owner := range namespaces {
		if n, limit := l.liveInNamespace(ns), l.Credentials[owner].ActorLimit; n > limit {
			fail("namespace %s holds %d live actors, over its limit of %d", ns, n, limit)
		}
	}

	for id, a := range l.Actors {
		c := l.Credentials[a.Cred]
		switch {
		case c == nil:
			fail("actor %s is bound to unknown credential %s", id, a.Cred)
		case a.Live && c.Revoked:
			fail("actor %s is live on revoked credential %s", id, a.Cred)
		}
		if _, ok := namespaces[a.Namespace]; !ok {
			fail("actor %s is in namespace %s, which nobody was granted", id, a.Namespace)
		}
		if a.BindingGen < 1 || a.AddrRev < 1 {
			fail("actor %s has binding_gen %d and addr_rev %d", id, a.BindingGen, a.AddrRev)
		}
		if a.Live == slices.Contains(l.Tombstones.Actors, id) {
			fail("actor %s: live=%v but tombstoned=%v", id, a.Live, a.Live)
		}
	}

	for epoch, readers := range l.Readers {
		set(fmt.Sprintf("readers[%d]", epoch), readers)
		if epoch < 1 || epoch > l.KeyEpoch {
			fail("readers recorded for epoch %d while key_epoch is %d", epoch, l.KeyEpoch)
		}
		for _, r := range readers {
			if l.Credentials[r] == nil {
				fail("epoch %d names unknown reader %s", epoch, r)
			}
		}
	}

	for key, w := range l.RegisterWriters {
		actor, _, ok := strings.Cut(key, "/")
		a := l.Actors[actor]
		if !ok || a == nil {
			fail("register writer %s has no actor", key)
			continue
		}
		set("register writer "+key+" used", w.Used)
		if w.WriterRev < 1 || int64(len(w.Used)) != w.WriterRev || !slices.Contains(w.Used, w.Incarnation) {
			fail("register writer %s: writer_rev %d, incarnation %s, used %v", key, w.WriterRev, w.Incarnation, w.Used)
		}
		if w.BindingGen < 1 || w.BindingGen > a.BindingGen {
			fail("register writer %s was activated at binding_gen %d; the actor is at %d", key, w.BindingGen, a.BindingGen)
		}
	}

	callNos := map[int64]string{}
	for id, c := range s.Calls {
		if other, dup := callNos[c.CallNo]; dup {
			fail("calls %s and %s share call_no %d", other, id, c.CallNo)
		}
		callNos[c.CallNo] = id
		if c.CallNo < 1 || c.CallNo > l.CallCount {
			fail("call %s has call_no %d while call_count is %d", id, c.CallNo, l.CallCount)
		}
		if c.From == c.To || l.Actors[c.From] == nil || l.Actors[c.To] == nil {
			fail("call %s has participants %q and %q", id, c.From, c.To)
		}
		if c.TurnCount < 1 || !c.Involves(c.LastTurnFrom) {
			fail("call %s: turn_count %d, last turn from %q", id, c.TurnCount, c.LastTurnFrom)
		}
		if c.Lifecycle == "linked" || !lifecycleStates[c.Lifecycle] {
			fail("call %s has lifecycle %q", id, c.Lifecycle)
		}
		set("call "+id+" byes", c.Byes)
		for _, b := range c.Byes {
			if !c.Involves(b) {
				fail("call %s has a bye from non-participant %s", id, b)
			}
		}
		set("call "+id+" links", c.Links)
		for _, other := range c.Links {
			if other == id || s.Calls[other] == nil {
				fail("call %s links to %q", id, other)
			}
		}
		if c.DisputeCount != int64(len(c.Disputes)) {
			fail("call %s: dispute_count %d but %d disputes", id, c.DisputeCount, len(c.Disputes))
		}
		for did, d := range c.Disputes {
			if n, err := strconv.ParseInt(did, 10, 64); err != nil || n < 1 || n > c.DisputeCount {
				fail("call %s has dispute key %q", id, did)
			}
			if !c.Involves(d.OpenedBy) || d.Rev < 1 {
				fail("call %s dispute %s: opened by %q at rev %d", id, did, d.OpenedBy, d.Rev)
			}
			if _, a := d.MeasureRev[c.From]; len(d.MeasureRev) != 2 || !a {
				fail("call %s dispute %s: measure slots %v", id, did, d.MeasureRev)
			} else if _, b := d.MeasureRev[c.To]; !b {
				fail("call %s dispute %s: measure slots %v", id, did, d.MeasureRev)
			}
			if d.Resolved != (d.Resolution != nil) {
				fail("call %s dispute %s: resolved=%v but resolution present=%v", id, did, d.Resolved, d.Resolution != nil)
			}
		}
	}

	for id, b := range s.Broadcasts {
		set("broadcast "+id+" recipients", b.Recipients)
		if len(b.Recipients) == 0 || !broadcastKinds[b.Kind] {
			fail("broadcast %s: kind %q, %d recipients", id, b.Kind, len(b.Recipients))
		}
		for _, r := range b.Recipients {
			if l.Actors[r] == nil {
				fail("broadcast %s names unknown recipient %s", id, r)
			}
		}
		for who, rc := range b.Receipts {
			if !slices.Contains(b.Recipients, who) || rc.ReadSeq < 1 || rc.ReadSeq > l.HeadSeq {
				fail("broadcast %s: receipt for %s at seq %d (head %d)", id, who, rc.ReadSeq, l.HeadSeq)
			}
		}
		for who, n := range b.ReplyCount {
			if _, read := b.Receipts[who]; !read || n < 1 {
				fail("broadcast %s: %d replies from %s without a receipt", id, n, who)
			}
		}
	}

	slices.Sort(bad)
	return bad
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
