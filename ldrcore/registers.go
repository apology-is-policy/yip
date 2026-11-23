package ldrcore

// RegisterValue is one signed update of an advisory register: presence, a
// roadmap or a resource observation (spec section 9). Its body is ciphertext
// under the line's scope and is not modelled. A signature is a boolean.
type RegisterValue struct {
	LineID      string
	Generation  int64
	Register    string
	Actor       string
	Cred        string
	BindingGen  int64
	WriterRev   int64
	KeyEpoch    int64
	Counter     int64
	SignatureOK bool
}

// Registers is a model of the relay-side store of advisory registers. It is
// outside the log on purpose: it holds latest values, it is not replayed, and
// nothing in it is ever an input to Apply. The only committed state it reads
// is the writer activation that register_activate records.
//
// It is not a relay component. It has no transport, rate limits or sizes, and
// the time it is handed is only kept so a reader can show a value's age.
type Registers struct {
	LineID string
	values map[string]registerEntry
}

type registerEntry struct {
	value RegisterValue
	at    int64
}

// NewRegisters returns an empty store for one line.
func NewRegisters(lineID string) *Registers {
	return &Registers{LineID: lineID, values: map[string]registerEntry{}}
}

// Reasons Publish gives for refusing a value.
const (
	RegBadSignature = "bad_signature"
	RegWrongLine    = "wrong_line"
	RegUnknownType  = "unknown_register"
	RegMalformed    = "malformed"
	RegUnknownCred  = "unknown_credential"
	// RegRevoked: a revoked credential's delayed update is rejected.
	RegRevoked = "revoked"
	// RegNotLive: the actor was removed, or disabled with its credential.
	RegNotLive = "not_live"
	// RegNotBound: the signer is not the credential the actor is bound to now,
	// at the binding generation it names.
	RegNotBound = "not_bound"
	// RegNoActivation: the current owner has not activated this writer. After
	// a move the actor has no usable activation until the new owner makes one.
	RegNoActivation = "no_activation"
	// RegStaleWriter: the value is from an activation older than the current
	// one. An older activation never regains precedence.
	RegStaleWriter = "stale_writer"
	// RegRekeyPending and RegStaleEpoch are the key gate of spec 6.3, applied
	// to register bodies.
	RegRekeyPending = "rekey_pending"
	RegStaleEpoch   = "stale_key_epoch"
	// RegStaleCounter: order within one activation is by counter.
	RegStaleCounter = "stale_counter"
)

// Publish offers a value against the current committed state. It returns ""
// when the value is accepted and becomes the latest, or the reason it is not.
// A refused value changes nothing: whatever was cached stays, as a historical
// observation.
func (g *Registers) Publish(s State, v RegisterValue, now int64) string {
	l := &s.Line
	switch {
	case !v.SignatureOK:
		return RegBadSignature
	case v.LineID != g.LineID || v.Generation != l.Generation:
		return RegWrongLine
	case !registerTypes[v.Register]:
		return RegUnknownType
	case v.Counter < 0 || v.Counter > MaxCounter || v.WriterRev < 1 || v.WriterRev > MaxCounter:
		return RegMalformed
	}
	switch c := l.Credentials[v.Cred]; {
	case c == nil:
		return RegUnknownCred
	case c.Revoked:
		return RegRevoked
	}
	// Liveness and the current binding are checked on every publication.
	a := l.Actors[v.Actor]
	switch {
	case a == nil || !a.Live:
		return RegNotLive
	case a.Cred != v.Cred || a.BindingGen != v.BindingGen:
		return RegNotBound
	}
	key := v.Actor + "/" + v.Register
	w := l.RegisterWriters[key]
	switch {
	case w == nil || v.WriterRev > w.WriterRev:
		return RegNoActivation
	case v.WriterRev < w.WriterRev:
		return RegStaleWriter
	case w.BindingGen != a.BindingGen:
		// The activation belongs to an earlier binding generation.
		return RegNoActivation
	}
	switch {
	case l.RekeyPending:
		return RegRekeyPending
	case v.KeyEpoch != l.KeyEpoch:
		return RegStaleEpoch
	}
	if old, ok := g.values[key]; ok && old.value.WriterRev == v.WriterRev && v.Counter <= old.value.Counter {
		return RegStaleCounter
	}
	g.values[key] = registerEntry{value: v, at: now}
	return ""
}

// Get returns the cached value of a register and when it was accepted. A
// cached value is an observation with an age. It is not proof that the actor
// is alive or permitted anything.
func (g *Registers) Get(actor, register string) (RegisterValue, int64, bool) {
	e, ok := g.values[actor+"/"+register]
	return e.value, e.at, ok
}

// Historical reports whether the cached value is no longer from the writer
// that is current: its credential was revoked, its actor is gone or was
// moved, or a newer activation exists.
func (g *Registers) Historical(s State, actor, register string) bool {
	e, ok := g.values[actor+"/"+register]
	if !ok {
		return false
	}
	l := &s.Line
	c, a, w := l.Credentials[e.value.Cred], l.Actors[actor], l.RegisterWriters[actor+"/"+register]
	return c == nil || c.Revoked || a == nil || !a.Live ||
		a.Cred != e.value.Cred || a.BindingGen != e.value.BindingGen ||
		w == nil || w.WriterRev != e.value.WriterRev
}
