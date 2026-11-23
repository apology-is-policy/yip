package ldrcore

import (
	"reflect"
	"slices"
	"testing"
)

// These tests execute the scenario traces about advisory registers, against
// the register model. Each is registered under its trace ID in
// registerTraceTests.

func regActivate(cred, actor, incarnation string, writerRev int64) Record {
	return Record{Origin: OriginCredential, Type: "register_activate", Cred: cred, Actor: actor,
		Register: "presence", Incarnation: incarnation, Expect: Expect{WriterRev: ptr(writerRev)}}
}

// regValue is a presence value for actor that is current in every field
// against the sequencer's state. A test that wants a stale field sets it.
func (e *env) regValue(actor string, counter int64) RegisterValue {
	e.t.Helper()
	l := e.q.State().Line
	a := l.Actors[actor]
	v := RegisterValue{LineID: "L", Generation: l.Generation, Register: "presence", Actor: actor,
		Cred: a.Cred, BindingGen: a.BindingGen, KeyEpoch: l.KeyEpoch, Counter: counter, SignatureOK: true}
	if w := l.RegisterWriters[actor+"/presence"]; w != nil {
		v.WriterRev = w.WriterRev
	}
	return v
}

func (e *env) publish(g *Registers, v RegisterValue, want string) {
	e.t.Helper()
	e.now++
	if got := g.Publish(e.q.State(), v, e.now); got != want {
		e.t.Fatalf("publishing %s/%s at writer_rev %d counter %d: got %q, want %q",
			v.Actor, v.Register, v.WriterRev, v.Counter, got, want)
	}
}

var registerTraceTests = map[string]func(*testing.T){
	"T25": func(t *testing.T) { // registers have no authority and old writers do not return
		e := newLine(t)
		g := NewRegisters("L")
		e.commit(regActivate("credA", "a1", "i1", 0))
		old := e.regValue("a1", 1)
		e.publish(g, old, "")
		e.commit(regActivate("credA", "a1", "i2", 1))
		old.Counter = 2 // still signed under writer_rev 1
		e.publish(g, old, RegStaleWriter)
		e.publish(g, e.regValue("a1", 1), "")

		// A revoked credential's delayed update is rejected, and what was
		// cached stays as an observation with its age.
		e.commit(regActivate("credB", "b1", "k1", 0))
		cached := e.regValue("b1", 1)
		e.publish(g, cached, "")
		acceptedAt := e.now
		e.commit(revoke("credB"))
		late := cached
		late.Counter = 2
		e.publish(g, late, RegRevoked)
		got, at, ok := g.Get("b1", "presence")
		if !ok || got != cached || at != acceptedAt {
			t.Fatalf("the cached value changed: %+v accepted at %d", got, at)
		}
		if !g.Historical(e.q.State(), "b1", "presence") {
			t.Fatal("a revoked credential's cached value must be shown as historical")
		}

		// No register value can change an outcome: the transition function is
		// handed a State, and no State can hold one.
		if path := mentions(reflect.TypeOf(State{}), reflect.TypeOf(RegisterValue{}), nil); path != "" {
			t.Fatalf("State can hold a register value at %s", path)
		}
		if path := mentions(reflect.TypeOf(State{}), reflect.TypeOf(Registers{}), nil); path != "" {
			t.Fatalf("State can hold a register store at %s", path)
		}
		before := e.q.State()
		in := e.intent(turn("a1", 2))
		_, out1 := Apply(before, in.Record, e.now, testProfile)
		for i := int64(3); i < 40; i++ {
			g.Publish(e.q.State(), e.regValue("a1", i), e.now)
		}
		_, out2 := Apply(before, in.Record, e.now, testProfile)
		if out1 != out2 {
			t.Fatalf("an outcome changed with register contents: %+v then %+v", out1, out2)
		}
	},

	"T26": func(t *testing.T) { // register bodies obey the key gate
		e := newLine(t)
		g := NewRegisters("L")
		e.commit(regActivate("credA", "a1", "i1", 0))
		v := e.regValue("a1", 1)
		v.KeyEpoch = 1 // the current epoch is 2
		e.publish(g, v, RegStaleEpoch)
		e.commit(enroll("credC", "nsC", "jr3"))
		if !e.q.State().Line.RekeyPending {
			t.Fatal("an enrollment must set rekey_pending")
		}
		e.publish(g, e.regValue("a1", 1), RegRekeyPending)
		if _, _, ok := g.Get("a1", "presence"); ok {
			t.Fatal("a refused value was cached")
		}
	},

	"T37": func(t *testing.T) { // registers across an actor move
		e := newLine(t)
		g := NewRegisters("L")
		e.commit(regActivate("credA", "a2", "i1", 0))
		byOldOwner := e.regValue("a2", 1)
		e.publish(g, byOldOwner, "")

		e.commit(Record{Origin: OriginOperator, Type: "actor_move", Operator: "op1", Actor: "a2", ToCred: "credB",
			Expect: Expect{BindingGen: ptr(1)}})
		if w := e.q.State().Line.RegisterWriters["a2/presence"]; w.WriterRev != 1 || w.Incarnation != "i1" {
			t.Fatalf("writer state was not kept across the move: %+v", w)
		}

		byOldOwner.Counter = 2
		e.publish(g, byOldOwner, RegNotBound) // credA no longer holds a2
		e.publish(g, e.regValue("a2", 1), RegNoActivation)
		if !g.Historical(e.q.State(), "a2", "presence") {
			t.Fatal("the value cached before the move must be shown as historical")
		}

		e.commit(regActivate("credB", "a2", "j1", 1))
		w := e.q.State().Line.RegisterWriters["a2/presence"]
		if w.WriterRev != 2 || !slices.Contains(w.Used, "i1") || !slices.Contains(w.Used, "j1") {
			t.Fatalf("after the new owner activates: %+v; no counter may be reset", w)
		}
		byNewOwner := e.regValue("a2", 1)
		e.publish(g, byNewOwner, "")
		if got, _, _ := g.Get("a2", "presence"); got != byNewOwner || g.Historical(e.q.State(), "a2", "presence") {
			t.Fatalf("the new owner's value is not the current one: %+v", got)
		}
	},
}

func TestRegisterTraces(t *testing.T) {
	for id, fn := range registerTraceTests {
		t.Run(id, fn)
	}
}

// mentions reports where type t can hold a value of type target, or "".
func mentions(t, target reflect.Type, seen map[reflect.Type]bool) string {
	if t == target {
		return t.String()
	}
	if seen == nil {
		seen = map[reflect.Type]bool{}
	}
	if seen[t] {
		return ""
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		if p := mentions(t.Elem(), target, seen); p != "" {
			return t.String() + " > " + p
		}
	case reflect.Map:
		for _, x := range []reflect.Type{t.Key(), t.Elem()} {
			if p := mentions(x, target, seen); p != "" {
				return t.String() + " > " + p
			}
		}
	case reflect.Struct:
		for i := range t.NumField() {
			if p := mentions(t.Field(i).Type, target, seen); p != "" {
				return t.String() + "." + t.Field(i).Name + " > " + p
			}
		}
	}
	return ""
}

// The refusals no trace reaches, and the order within one activation.
func TestRegisterRefusals(t *testing.T) {
	e := newLine(t)
	g := NewRegisters("L")
	e.publish(g, e.regValue("a1", 1), RegMalformed) // no activation yet, so writer_rev 0
	v := e.regValue("a1", 1)
	v.WriterRev = 1
	e.publish(g, v, RegNoActivation)
	e.commit(regActivate("credA", "a1", "i1", 0))

	bad := func(change func(*RegisterValue), want string) {
		t.Helper()
		v := e.regValue("a1", 5)
		change(&v)
		e.publish(g, v, want)
	}
	bad(func(v *RegisterValue) { v.SignatureOK = false }, RegBadSignature)
	bad(func(v *RegisterValue) { v.LineID = "M" }, RegWrongLine)
	bad(func(v *RegisterValue) { v.Generation = 2 }, RegWrongLine)
	bad(func(v *RegisterValue) { v.Register = "lease" }, RegUnknownType)
	bad(func(v *RegisterValue) { v.Counter = -1 }, RegMalformed)
	bad(func(v *RegisterValue) { v.Cred = "credZ" }, RegUnknownCred)
	bad(func(v *RegisterValue) { v.Actor = "zz" }, RegNotLive)
	bad(func(v *RegisterValue) { v.Cred = "credB" }, RegNotBound)
	bad(func(v *RegisterValue) { v.BindingGen = 9 }, RegNotBound)
	bad(func(v *RegisterValue) { v.WriterRev = 2 }, RegNoActivation)
	if _, _, ok := g.Get("a1", "presence"); ok {
		t.Fatal("a refused value was cached")
	}

	e.publish(g, e.regValue("a1", 5), "")
	e.publish(g, e.regValue("a1", 5), RegStaleCounter)
	e.publish(g, e.regValue("a1", 4), RegStaleCounter)
	e.publish(g, e.regValue("a1", 6), "")

	// A removed actor publishes nothing.
	e.commit(Record{Origin: OriginCredential, Type: "actor_remove", Cred: "credA", Actor: "a1", Expect: Expect{BindingGen: ptr(1)}})
	e.publish(g, e.regValue("a1", 7), RegNotLive)
	if !g.Historical(e.q.State(), "a1", "presence") {
		t.Fatal("a removed actor's cached value must be shown as historical")
	}
}
