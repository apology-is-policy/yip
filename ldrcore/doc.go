// Package ldrcore holds reference models for Yip LDR phase 1, as drafted in
// docs/LDR-STATE-MACHINE.md. It exists so that the hand-written expected
// results in docs/LDR-CONFORMANCE-VECTORS.json are checked against something
// that computes.
//
// It has four parts:
//
//   - Apply (apply.go) is the transition function, stage 5 of that document's
//     pipeline: given a state, one already-admitted record and the sequencer's
//     time, it returns the next state and an outcome. It is pure.
//   - Sequencer (sequencer.go) models the shell around Apply in memory:
//     operation identity and dedup, admission, the retry lookup, anchors,
//     validity, retirement, the rejection quota and the time floor.
//   - Client (client.go, outbox.go) models one credential's local side: the
//     verified log store, the projection, local delivery and the outbox.
//   - Registers (registers.go) models publication of advisory registers.
//
// None of it is a relay or a client. There is no I/O, no network, no storage
// and no cryptography: a signature is a boolean, a credential identifier's
// derivation is a stated fact, the chain head is a non-cryptographic
// stand-in, the clock is injected, and a crash is a procedure stopping
// between two steps. Enrollment ceremony, encryption, transport and recovery
// are outside it. The yip binary does not import it.
//
// Two more files are an exploration and not a model of the draft. commit.go
// and join.go try one possible answer to a question the draft leaves open:
// how a new member comes by its starting state (section 13, O25, and section
// 14.7). They are reached only under Profile.StateCommit, which nothing else
// sets, and nobody has chosen that answer. Under that profile a signature is
// a computed stand-in and not a boolean, and the client model checks it and
// the signed context of every record, which it otherwise takes as a premise.
//
// Passing tests here show that the code agrees with tests written by the
// same author. They are not evidence that the design is safe.
//
// The draft it follows is unapproved beyond the scope decisions recorded in
// its section 0. Do not build a deployment on this package.
package ldrcore
