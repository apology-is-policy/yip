package ldrcore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const vectorsPath = "../docs/LDR-CONFORMANCE-VECTORS.json"

// vectorFile is the whole file. Every field is listed, because the file is
// decoded with unknown fields disallowed at every level: a misspelled key
// anywhere fails the test instead of being silently ignored.
type vectorFile struct {
	Format   string `json:"format"`
	Spec     string `json:"spec"`
	Status   string `json:"status"`
	Author   string `json:"author"`
	Coverage struct {
		ApplyVectors       int            `json:"apply_vectors"`
		RetiredVectors     int            `json:"retired_vectors"`
		Traces             int            `json:"traces"`
		TraceSteps         int            `json:"trace_steps"`
		CheckedBy          string         `json:"checked_by"`
		Executed           string         `json:"executed"`
		ReviewedStatically string         `json:"reviewed_statically"`
		NotCovered         string         `json:"not_covered"`
		TracesAre          string         `json:"traces_are"`
		TracesByScope      map[string]int `json:"traces_by_scope"`
	} `json:"coverage"`
	Conventions map[string]any    `json:"conventions"`
	Premises    map[string]string `json:"premises"`
	Profile     struct {
		Status            string `json:"status"`
		FreshnessMS       int64  `json:"freshness_F_ms"`
		ValidityDefaultMS int64  `json:"validity_default_ms"`
		ValidityMaxMS     int64  `json:"validity_max_ms"`
	} `json:"profile"`
	Defaults struct {
		Fixture  string         `json:"fixture"`
		SeqTime  int64          `json:"seq_time"`
		Premises []string       `json:"premises"`
		Record   map[string]any `json:"record"`
	} `json:"defaults"`
	Fixtures map[string]struct {
		Note    string         `json:"note"`
		State   map[string]any `json:"state"`
		Extends string         `json:"extends"`
		Patch   map[string]any `json:"patch"`
	} `json:"fixtures"`
	ApplyVectors []vector `json:"apply_vectors"`
	Traces       []struct {
		ID string `json:"id"`
		// Run says whether a Go test re-enacts the trace, and how far.
		Run struct {
			Scope  string `json:"scope"`
			Test   string `json:"test"`
			Limits string `json:"limits"`
		} `json:"run"`
		Spec  string `json:"spec"`
		Title string `json:"title"`
		Note  string `json:"note"`
		Steps []struct {
			Do     string `json:"do"`
			Intent string `json:"intent"`
			Expect string `json:"expect"`
		} `json:"steps"`
	} `json:"traces"`
}

type vector struct {
	ID       string         `json:"id"`
	Spec     string         `json:"spec"`
	Title    string         `json:"title"`
	Retired  string         `json:"retired"`
	Fixture  string         `json:"fixture"`
	SeqTime  *int64         `json:"seq_time"`
	Premises []string       `json:"premises"`
	Given    map[string]any `json:"given"`
	Record   map[string]any `json:"record"`
	Expect   struct {
		Outcome string         `json:"outcome"`
		Reason  string         `json:"reason"`
		RefSeq  *int64         `json:"ref_seq"`
		Patch   map[string]any `json:"patch"`
	} `json:"expect"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	// Numbers in the untyped parts stay as written, so a value at the edge
	// of the counter domain never passes through float64.
	dec.UseNumber()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", vectorsPath, err)
	}
	if f.Format != "yip-ldr-conformance/0" {
		t.Fatalf("unexpected vector format %q", f.Format)
	}
	return f
}

// mergePatch is JSON Merge Patch (RFC 7396): objects merge, everything else
// replaces, null deletes. It never modifies its arguments.
func mergePatch(base, patch any) any {
	pm, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	out := map[string]any{}
	if bm, ok := base.(map[string]any); ok {
		for k, v := range bm {
			out[k] = v
		}
	}
	for k, v := range pm {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = mergePatch(out[k], v)
	}
	return out
}

func (f vectorFile) fixture(t *testing.T, name string, depth int) map[string]any {
	t.Helper()
	fx, ok := f.Fixtures[name]
	if !ok || depth > 8 {
		t.Fatalf("fixture %q missing or cyclic", name)
	}
	if fx.State != nil {
		return fx.State
	}
	return mergePatch(f.fixture(t, fx.Extends, depth+1), fx.Patch).(map[string]any)
}

// strict decodes through JSON and refuses any field the target type does not
// have, so a misspelled field in a vector fails instead of being ignored.
func strict(t *testing.T, src any, dst any) {
	t.Helper()
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		t.Fatalf("decoding %s: %v", b, err)
	}
}

func decodeState(t *testing.T, generic any) State {
	t.Helper()
	var s State
	strict(t, generic, &s)
	return s
}

// diff lists the JSON paths at which two states differ, for a readable
// failure. It compares canonical forms.
func diff(got, want State) []string {
	var g, w any
	gb, _ := json.Marshal(got.Canon())
	wb, _ := json.Marshal(want.Canon())
	_ = json.Unmarshal(gb, &g)
	_ = json.Unmarshal(wb, &w)
	var out []string
	walk("", g, w, &out)
	sort.Strings(out)
	return out
}

func walk(path string, g, w any, out *[]string) {
	gm, gok := g.(map[string]any)
	wm, wok := w.(map[string]any)
	if gok && wok {
		keys := map[string]bool{}
		for k := range gm {
			keys[k] = true
		}
		for k := range wm {
			keys[k] = true
		}
		for k := range keys {
			walk(path+"."+k, gm[k], wm[k], out)
		}
		return
	}
	if !reflect.DeepEqual(g, w) {
		gb, _ := json.Marshal(g)
		wb, _ := json.Marshal(w)
		*out = append(*out, fmt.Sprintf("%s: got %s, want %s", strings.TrimPrefix(path, "."), gb, wb))
	}
}

// TestConformanceVectors runs every active apply vector. The expected results
// in the file were written by hand from the draft specification before this
// package existed.
func TestConformanceVectors(t *testing.T) {
	f := loadVectors(t)
	prof := Profile{FreshnessMS: f.Profile.FreshnessMS, ValidityMaxMS: f.Profile.ValidityMaxMS}
	active, retired := 0, 0

	for _, v := range f.ApplyVectors {
		if v.Retired != "" {
			retired++
			continue
		}
		active++
		t.Run(v.ID, func(t *testing.T) {
			name := v.Fixture
			if name == "" {
				name = f.Defaults.Fixture
			}
			generic := mergePatch(f.fixture(t, name, 0), anyMap(v.Given))
			before := decodeState(t, generic)
			var rec Record
			strict(t, mergePatch(anyMap(f.Defaults.Record), anyMap(v.Record)), &rec)
			seqTime := f.Defaults.SeqTime
			if v.SeqTime != nil {
				seqTime = *v.SeqTime
			}

			if bad := before.CheckInvariants(); len(bad) > 0 {
				t.Fatalf("%s: the vector's starting state is not coherent, so it tests nothing a line can reach:\n  %s", v.Title, strings.Join(bad, "\n  "))
			}

			got, out := Apply(before, rec, seqTime, prof)

			if bad := got.CheckInvariants(); len(bad) > 0 {
				t.Errorf("%s: Apply returned an incoherent state:\n  %s", v.Title, strings.Join(bad, "\n  "))
			}

			// Apply must never modify its input.
			if d := diff(before, decodeState(t, generic)); len(d) > 0 {
				t.Errorf("%s: Apply modified its input state:\n  %s", v.Title, strings.Join(d, "\n  "))
			}

			if out.Kind != v.Expect.Outcome || out.Reason != v.Expect.Reason {
				t.Errorf("%s:\n  outcome: got %s, want %s", v.Title, describe(out.Kind, out.Reason), describe(v.Expect.Outcome, v.Expect.Reason))
			}
			// Exact, with absent meaning zero: a reference the vector did not
			// expect is a fabricated one.
			var wantRef int64
			if v.Expect.RefSeq != nil {
				wantRef = *v.Expect.RefSeq
			}
			if out.RefSeq != wantRef {
				t.Errorf("%s:\n  ref_seq: got %d, want %d", v.Title, out.RefSeq, wantRef)
			}

			want := before
			if v.Expect.Outcome == Committed {
				merged := mergePatch(generic, anyMap(v.Expect.Patch)).(map[string]any)
				// Implied on every commit, and omitted from the patches.
				line, _ := merged["line"].(map[string]any)
				line = mergePatch(line, map[string]any{
					"head_seq":  before.Line.HeadSeq + 1,
					"head_time": seqTime,
				}).(map[string]any)
				merged["line"] = line
				want = decodeState(t, merged)
			}
			if d := diff(got, want); len(d) > 0 {
				t.Errorf("%s:\n  state after %s differs:\n  %s", v.Title, describe(out.Kind, out.Reason), strings.Join(d, "\n  "))
			}
		})
	}

	if active != f.Coverage.ApplyVectors || retired != f.Coverage.RetiredVectors {
		t.Errorf("file says %d active and %d retired vectors; found %d and %d",
			f.Coverage.ApplyVectors, f.Coverage.RetiredVectors, active, retired)
	}
	steps := 0
	for _, tr := range f.Traces {
		steps += len(tr.Steps)
	}
	if len(f.Traces) != f.Coverage.Traces || steps != f.Coverage.TraceSteps {
		t.Errorf("file says %d traces and %d steps; found %d and %d",
			f.Coverage.Traces, f.Coverage.TraceSteps, len(f.Traces), steps)
	}
}

func anyMap(m map[string]any) any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func describe(kind, reason string) string {
	if reason == "" {
		return kind
	}
	return kind + " " + reason
}

// The sequences below are the apply-only parts of scenario traces in the
// vectors file. Traces that need the sequencer shell (dedup, time floor,
// anchors, admission) are not executable here.

func baseState(t *testing.T, fixture string) (State, Profile) {
	t.Helper()
	f := loadVectors(t)
	return decodeState(t, f.fixture(t, fixture, 0)),
		Profile{FreshnessMS: f.Profile.FreshnessMS, ValidityMaxMS: f.Profile.ValidityMaxMS}
}

func ptr(n int64) *int64 { return &n }

func mustCommit(t *testing.T, s State, r Record, at int64, p Profile) State {
	t.Helper()
	next, out := Apply(s, r, at, p)
	if out.Kind != Committed {
		t.Fatalf("%s by %s%s: got %s, want committed", r.Type, r.Actor, r.Operator, describe(out.Kind, out.Reason))
	}
	return next
}

func mustReject(t *testing.T, s State, r Record, at int64, p Profile, reason string) {
	t.Helper()
	next, out := Apply(s, r, at, p)
	if out.Kind != Rejected || out.Reason != reason {
		t.Fatalf("%s by %s%s: got %s, want rejected %s", r.Type, r.Actor, r.Operator, describe(out.Kind, out.Reason), reason)
	}
	if d := diff(next, s); len(d) > 0 {
		t.Fatalf("a rejected record changed state:\n  %s", strings.Join(d, "\n  "))
	}
}

// Trace T21: two turns race at the same expected count.
func TestTraceTwoTurnsRace(t *testing.T) {
	s, p := baseState(t, "line_basic")
	a1 := Record{Origin: OriginActor, Type: "call_turn", Cred: "credA", Actor: "a1", BindingGen: 1, AuthEpoch: 3, KeyEpoch: 2, Call: "c1", Expect: Expect{TurnCount: ptr(2)}}
	b1 := Record{Origin: OriginActor, Type: "call_turn", Cred: "credB", Actor: "b1", BindingGen: 1, AuthEpoch: 3, KeyEpoch: 2, Call: "c1", Barge: true, Expect: Expect{TurnCount: ptr(2)}}
	s = mustCommit(t, s, a1, 1005000, p)
	mustReject(t, s, b1, 1005001, p, "conflict")
	if c := s.Calls["c1"]; c.TurnCount != 3 || c.Floor() != "b1" {
		t.Fatalf("after the race: turn_count %d, floor %s", c.TurnCount, c.Floor())
	}
}

// Trace T20: a newly enrolled credential reads from its first epoch only, and
// phase 1 has no record that changes that.
func TestTraceNewMemberIsFutureOnly(t *testing.T) {
	s, p := baseState(t, "line_basic")
	s = mustCommit(t, s, Record{Origin: OriginOperator, Type: "credential_enroll", Operator: "op1", AuthEpoch: 3,
		Cred: "credC", SigningKey: "skC", EncryptionKey: "ekC", JoinRequest: "jr3", JoinRequestDigest: "jd3",
		Grant: &Grant{Namespace: "nsC", ActorLimit: 4, Reader: true}}, 1005000, p)
	if !s.Line.RekeyPending {
		t.Fatal("enrollment did not set rekey_pending")
	}
	// Nothing payload-bearing commits until the new epoch is out.
	mustReject(t, s, Record{Origin: OriginActor, Type: "call_turn", Cred: "credA", Actor: "a1", BindingGen: 1, AuthEpoch: 4, KeyEpoch: 2,
		Call: "c1", Expect: Expect{TurnCount: ptr(2)}}, 1005001, p, "rekey_pending")
	s = mustCommit(t, s, Record{Origin: OriginOperator, Type: "key_epoch_activate", Operator: "op1", AuthEpoch: 4,
		Manifest: []string{"credA", "credB", "credC"}, Expect: Expect{KeyEpoch: ptr(2)}}, 1005002, p)
	for epoch, want := range map[int64]bool{1: false, 2: false, 3: true} {
		got := false
		for _, c := range s.Line.Readers[epoch] {
			got = got || c == "credC"
		}
		if got != want {
			t.Errorf("credC reader of epoch %d: got %v, want %v", epoch, got, want)
		}
	}
	if _, known := recordOrigin["history_grant"]; known {
		t.Error("history_grant must not exist in phase 1 (operator decision, 2026-11-23)")
	}
}

// Trace T30, apply half: a call opened to an actor that is declared a moment
// later is judged at its own evaluation. A new intent after the declaration
// commits; the declaration does not disturb anyone else's auth_epoch.
func TestTraceCallToActorDeclaredLater(t *testing.T) {
	s, p := baseState(t, "line_basic")
	open := Record{Origin: OriginActor, Type: "call_open", Cred: "credA", Actor: "a1", BindingGen: 1, AuthEpoch: 3, KeyEpoch: 2, Call: "c7", To: "a3"}
	mustReject(t, s, open, 1005000, p, "unknown_target")
	s = mustCommit(t, s, Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credA", AuthEpoch: 3, Namespace: "nsA", Actor: "a3"}, 1005001, p)
	if s.Line.AuthEpoch != 3 {
		t.Fatalf("actor_declare changed auth_epoch to %d", s.Line.AuthEpoch)
	}
	s = mustCommit(t, s, open, 1005002, p)
	if c := s.Calls["c7"]; c.CallNo != 3 || c.Floor() != "a3" {
		t.Fatalf("new call: call_no %d, floor %s", c.CallNo, c.Floor())
	}
}

// Trace T31: two declarations race for the last slot in a namespace.
func TestTraceLastNamespaceSlot(t *testing.T) {
	s, p := baseState(t, "line_basic")
	s.Line.Credentials["credA"].ActorLimit = 3
	declare := func(id string) Record {
		return Record{Origin: OriginCredential, Type: "actor_declare", Cred: "credA", AuthEpoch: 3, Namespace: "nsA", Actor: id}
	}
	s = mustCommit(t, s, declare("a3"), 1005000, p)
	mustReject(t, s, declare("a4"), 1005001, p, "unauthorized")
}

// Trace T37, apply half: register writer state across an actor move.
func TestTraceRegisterWriterAcrossMove(t *testing.T) {
	s, p := baseState(t, "line_basic")
	activate := func(cred, inc string, authEpoch, writerRev int64) Record {
		return Record{Origin: OriginCredential, Type: "register_activate", Cred: cred, AuthEpoch: authEpoch,
			Actor: "a2", Register: "presence", Incarnation: inc, Expect: Expect{WriterRev: ptr(writerRev)}}
	}
	s = mustCommit(t, s, activate("credA", "i1", 3, 0), 1005000, p)
	s = mustCommit(t, s, Record{Origin: OriginOperator, Type: "actor_move", Operator: "op1", AuthEpoch: 3,
		Actor: "a2", ToCred: "credB", Expect: Expect{BindingGen: ptr(1)}}, 1005001, p)
	w := s.Line.RegisterWriters["a2/presence"]
	if w.WriterRev != 1 || w.BindingGen != 1 {
		t.Fatalf("writer state was not kept across the move: %+v", w)
	}
	mustReject(t, s, activate("credA", "i2", 4, 1), 1005002, p, "unauthorized") // previous owner
	mustReject(t, s, activate("credB", "i1", 4, 1), 1005002, p, "conflict")     // incarnation reuse
	mustReject(t, s, activate("credB", "j1", 4, 0), 1005002, p, "conflict")     // counter not reset
	s = mustCommit(t, s, activate("credB", "j1", 4, 1), 1005002, p)
	if w := s.Line.RegisterWriters["a2/presence"]; w.WriterRev != 2 || w.BindingGen != 2 {
		t.Fatalf("after the new owner activates: %+v", w)
	}
}

// Every record type the package knows must be exercised by at least one
// vector that commits, or the vectors are not a check of that type's effect.
func TestEveryRecordTypeHasACommittedVector(t *testing.T) {
	f := loadVectors(t)
	seen := map[string]bool{}
	for _, v := range f.ApplyVectors {
		if v.Retired == "" && v.Expect.Outcome == Committed {
			if typ, _ := v.Record["type"].(string); typ != "" {
				seen[typ] = true
			}
		}
	}
	var missing []string
	for typ := range recordOrigin {
		if !seen[typ] {
			missing = append(missing, typ)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("record types with no committed vector: %s", strings.Join(missing, ", "))
	}
}
