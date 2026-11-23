// Package ldrcore is the reference transition function for Yip LDR phase 1,
// as drafted in docs/LDR-STATE-MACHINE.md.
//
// It implements stage 5 of that document's pipeline and nothing else: given
// a state, one already-admitted record and the sequencer's time, it returns
// the next state and an outcome. It is pure. It has no I/O, no clock, no
// cryptography, no network and no storage, and it is not imported by the yip
// binary.
//
// What it is for: running docs/LDR-CONFORMANCE-VECTORS.json, so that the
// hand-written expected results in that file are checked against something
// that computes. What it is not: a relay, a sequencer, or evidence that the
// design is safe. Dedup, the outcome index, the time floor, time-anchor
// requests, admission, enrollment, encryption and recovery are all outside
// it, and the spec's scenario traces that depend on them are not executed.
//
// The draft it follows is unapproved beyond the scope decisions recorded in
// its section 0. Do not build a deployment on this package.
//
// Besides Apply and the sequencer model, the package holds a model of one
// credential's local side (client.go, outbox.go) and of advisory register
// publication (registers.go). They exist to run the scenario traces. They
// have no disk, transport or cryptography, and they are not a client.
package ldrcore
