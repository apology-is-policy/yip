package ldrrelay

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrstore"
)

const (
	DefaultQuotaMax = 64
	MaxLogPageSize  = 256
)

const (
	standingActive        = 0
	standingRevoked       = 1
	standingNever         = 2
	standingBootstrapRoot = 3 // provisioned root before line_init commits
)

// SubmitReply is the serialized response to Submit.
type SubmitReply struct {
	Class    string
	Code     string
	Outcome  ldrstore.StoredOutcome
	Head     [32]byte
	SeqTime  uint64
	Original bool
}

// AnchorReply is the serialized response to AnchorRequest.
type AnchorReply struct {
	Class   string
	Code    string
	Gen     uint64
	Seq     uint64
	Head    [32]byte
	SeqTime uint64
	Wrote   bool
}

// ControlFrameWire is one control-only log entry served to replaying members (O25).
type ControlFrameWire struct {
	Gen           uint64
	Seq           uint64
	SeqTime       uint64
	PrevHead      [32]byte
	Head          [32]byte
	Origin        string
	OpType        string
	IntentBytes   []byte
	PayloadCommit *ldrcrypto.Commitment
	WrapCommits   []ldrcrypto.WrapManifestEntry
}

// LineStatus summarizes one provisioned line for operator diagnostics.
type LineStatus struct {
	LineID            string      `json:"line_id"`
	Generation        uint64      `json:"generation"`
	HeadSeq           uint64      `json:"head_seq"`
	Head              string      `json:"head"`
	HotEntries        int         `json:"hot_entries"`
	CommittedOps      int         `json:"committed_ops"`
	RecoveredTornTail bool        `json:"recovered_torn_tail"`
	Clock             ClockStatus `json:"clock"`
}

type lineRuntime struct {
	mu                sync.Mutex
	lineID            []byte
	hexID             string
	desc              ldrcrypto.CreationDescriptor
	cd                [32]byte
	genesis           [32]byte
	profDigest        [32]byte
	coreProf          ldrcore.Profile
	state             ldrcore.State
	frames            []ldrstore.CommittedFrame
	heads             map[uint64][32]byte
	times             map[uint64]uint64
	logIndex          map[ldrstore.StoredOpKey]ldrstore.CommittedReceipt
	hot               map[ldrstore.StoredOpKey]ldrstore.HotEntry
	quota             map[string]int
	clock             *ClockGuard
	recoveredTornTail bool
}

// RelayEngine is the production multi-line LDR sequencer backed by ldrstore.Store,
// ldrcrypto verification, ldrcore.Apply, and ClockGuard.
type RelayEngine struct {
	store    ldrstore.Store
	clockCfg ClockConfig
	nowFn    ClockSource
	quotaMax int

	mu    sync.RWMutex
	lines map[string]*lineRuntime // hex(lineID) -> runtime
}

// NewRelayEngine opens every provisioned line in store, replays and verifies
// every committed frame from genesis (chain heads + real signatures + ldrcore.Apply),
// and initializes per-line ClockGuards. Fails closed on any corruption.
func NewRelayEngine(store ldrstore.Store, clockCfg ClockConfig, nowFn ClockSource) (*RelayEngine, error) {
	if store == nil {
		return nil, errors.New("ldrrelay: nil store")
	}
	if nowFn == nil {
		nowFn = RealClockSource()
	}
	eng := &RelayEngine{
		store:    store,
		clockCfg: clockCfg.normalized(),
		nowFn:    nowFn,
		quotaMax: DefaultQuotaMax,
		lines:    make(map[string]*lineRuntime),
	}
	lineIDs, err := store.ListLines()
	if err != nil {
		return nil, err
	}
	for _, id := range lineIDs {
		rt, err := eng.loadAndVerifyLine(id)
		if err != nil {
			return nil, fmt.Errorf("ldrrelay: startup verification failed for line %x: %w", id, err)
		}
		eng.lines[rt.hexID] = rt
	}
	return eng, nil
}

// SetQuotaMax overrides the per-signer rejection quota (used in tests).
func (e *RelayEngine) SetQuotaMax(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n > 0 {
		e.quotaMax = n
	}
}

func (e *RelayEngine) loadAndVerifyLine(lineID []byte) (*lineRuntime, error) {
	snap, err := e.store.LoadLine(lineID)
	if err != nil {
		return nil, err
	}
	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(snap.Provisioned.SignedDescriptor)
	if err != nil {
		return nil, err
	}
	profDigest, err := desc.Profile.Digest()
	if err != nil {
		return nil, err
	}
	coreProf := ldrcore.Profile{
		FreshnessMS:   int64(desc.Profile.FreshnessMS),
		ValidityMaxMS: int64(desc.Profile.MaxValidityMS),
	}
	rt := &lineRuntime{
		lineID:            bytes.Clone(lineID),
		hexID:             hex.EncodeToString(lineID),
		desc:              desc,
		cd:                cd,
		genesis:           genesis,
		profDigest:        profDigest,
		coreProf:          coreProf,
		frames:            make([]ldrstore.CommittedFrame, 0, len(snap.Frames)),
		heads:             map[uint64][32]byte{0: genesis},
		times:             map[uint64]uint64{},
		logIndex:          snap.LogIndex,
		hot:               snap.Hot,
		quota:             snap.Quota,
		clock:             NewClockGuard(snap.TimeFloor, e.clockCfg, e.nowFn),
		recoveredTornTail: snap.RecoveredTornTail,
	}

	// Replay every committed frame from seq 1..N verifying real chain heads,
	// real cryptographic signatures, and exact ldrcore.Apply transitions.
	lim := ldrcrypto.Limits{MaxBytes: int(desc.Profile.MaxRecordBytes), MaxDepth: 16, MaxItems: 4096}
	prevHead := genesis
	for i, fr := range snap.Frames {
		wantSeq := uint64(i + 1)
		if fr.Gen != 1 || fr.Seq != wantSeq {
			return nil, fmt.Errorf("%w: non-consecutive frame (%d,%d) expected (1,%d)", ldrstore.ErrCorruptWAL, fr.Gen, fr.Seq, wantSeq)
		}
		if fr.PrevHead != prevHead {
			return nil, fmt.Errorf("%w: frame %d prev_head mismatch", ldrstore.ErrCorruptWAL, fr.Seq)
		}
		if fr.Origin == ldrcore.OriginSequencer {
			if fr.OpType != "time_anchor" || len(fr.IntentBytes) != 0 {
				return nil, fmt.Errorf("%w: invalid sequencer frame %d", ldrstore.ErrCorruptWAL, fr.Seq)
			}
			wantHead, err := ldrcrypto.AnchorChainHead(prevHead, profDigest, lineID, fr.Gen, fr.Seq, fr.SeqTime)
			if err != nil || wantHead != fr.Head {
				return nil, fmt.Errorf("%w: time_anchor frame %d head mismatch", ldrstore.ErrCorruptWAL, fr.Seq)
			}
			next, out := ldrcore.Apply(rt.state, ldrcore.Record{Origin: ldrcore.OriginSequencer, Type: "time_anchor"}, int64(fr.SeqTime), coreProf)
			if out.Kind != ldrcore.Committed {
				return nil, fmt.Errorf("%w: time_anchor frame %d failed Apply (%s %s)", ldrstore.ErrCorruptWAL, fr.Seq, out.Kind, out.Reason)
			}
			rt.state = next
		} else {
			env, err := ldrcrypto.UnmarshalSignedIntent(fr.IntentBytes, lim)
			if err != nil {
				return nil, fmt.Errorf("%w: frame %d intent decode: %v", ldrstore.ErrCorruptWAL, fr.Seq, err)
			}
			dec, err := DecodeWireIntentBody(env.BodyBytes, desc.Profile, lim)
			if err != nil {
				return nil, fmt.Errorf("%w: frame %d body decode: %v", ldrstore.ErrCorruptWAL, fr.Seq, err)
			}
			pubKey, stg := rt.resolveSignerKeyLocked(dec.Principal)
			if stg != standingActive && !(fr.Seq == 1 && dec.OpType == "line_init" && stg == standingBootstrapRoot) {
				return nil, fmt.Errorf("%w: frame %d signer unauthorized on replay", ldrstore.ErrCorruptWAL, fr.Seq)
			}
			if err := env.Verify(pubKey); err != nil {
				return nil, fmt.Errorf("%w: frame %d bad signature on replay: %v", ldrstore.ErrCorruptWAL, fr.Seq, err)
			}
			wantHead, err := ldrcrypto.ClientChainHead(prevHead, profDigest, lineID, fr.Gen, fr.Seq, fr.SeqTime, fr.Origin, fr.IntentBytes)
			if err != nil || wantHead != fr.Head {
				return nil, fmt.Errorf("%w: frame %d chain head mismatch", ldrstore.ErrCorruptWAL, fr.Seq)
			}
			next, out := ldrcore.Apply(rt.state, dec.Record, int64(fr.SeqTime), coreProf)
			if out.Kind != ldrcore.Committed {
				return nil, fmt.Errorf("%w: frame %d failed Apply (%s %s)", ldrstore.ErrCorruptWAL, fr.Seq, out.Kind, out.Reason)
			}
			rt.state = next
		}
		rt.frames = append(rt.frames, fr)
		rt.heads[fr.Seq] = fr.Head
		rt.times[fr.Seq] = fr.SeqTime
		prevHead = fr.Head
	}
	return rt, nil
}

// Provision verifies a root-signed creation descriptor, installs it durably
// in store, and registers the line in the live engine.
func (e *RelayEngine) Provision(signedDescriptorBytes []byte) (ldrstore.ProvisionedLine, error) {
	desc, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(signedDescriptorBytes)
	if err != nil {
		return ldrstore.ProvisionedLine{}, err
	}
	prov := ldrstore.ProvisionedLine{
		LineID:           bytes.Clone(desc.LineID),
		SignedDescriptor: bytes.Clone(signedDescriptorBytes),
		DescriptorDigest: cd,
		GenesisAnchor:    genesis,
	}
	if err := e.store.ProvisionLine(prov); err != nil {
		return ldrstore.ProvisionedLine{}, err
	}
	rt, err := e.loadAndVerifyLine(desc.LineID)
	if err != nil {
		return ldrstore.ProvisionedLine{}, err
	}
	e.mu.Lock()
	e.lines[rt.hexID] = rt
	e.mu.Unlock()
	return prov, nil
}

func (e *RelayEngine) getLine(lineID []byte) (*lineRuntime, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rt, ok := e.lines[hex.EncodeToString(lineID)]
	return rt, ok
}

// LineDescriptor returns the provisioned CreationDescriptor, CD, and profile digest.
func (e *RelayEngine) LineDescriptor(lineID []byte) (ldrcrypto.CreationDescriptor, [32]byte, [32]byte, bool) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return ldrcrypto.CreationDescriptor{}, [32]byte{}, [32]byte{}, false
	}
	return rt.desc, rt.cd, rt.profDigest, true
}

// ClockGuardFor returns a line's ClockGuard (for tests and operator resume).
func (e *RelayEngine) ClockGuardFor(lineID []byte) (*ClockGuard, bool) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return nil, false
	}
	return rt.clock, true
}

// VerifySessionPrincipal checks key possession via sig over SessionAuthMessage
// and evaluates the principal's current standing inside the serialized line lock.
// Returns (standing, gen, pubKey, err).
func (e *RelayEngine) VerifySessionPrincipal(lineID []byte, authMsg ldrcrypto.SessionAuthMessage, sig []byte) (int, uint64, error) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return standingNever, 0, ldrstore.ErrLineNotFound
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if authMsg.ProfileDigest != rt.profDigest {
		return standingNever, 0, errors.New("profile_digest mismatch")
	}
	pubKey, stg := rt.resolveSignerKeyLocked(authMsg.Principal)
	if stg == standingNever {
		// Never reveal registry membership before/without proof.
		return standingNever, 0, ldrcrypto.ErrInvalidSignature
	}
	if err := ldrcrypto.VerifySessionAuth(pubKey, authMsg, sig); err != nil {
		return standingNever, 0, err
	}
	gen := uint64(rt.state.Line.Generation)
	if gen == 0 {
		gen = 1
	}
	if authMsg.Generation != gen {
		return standingNever, gen, errors.New("generation mismatch")
	}
	return stg, gen, nil
}

// ResolvePrincipalKey returns the active/revoked public key and standing for an
// already-authenticated principal (re-checked inside the per-line lock).
func (e *RelayEngine) ResolvePrincipalKey(lineID []byte, p ldrcrypto.Principal) (ldrcrypto.PublicKey, int, bool) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return ldrcrypto.PublicKey{}, standingNever, false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pk, stg := rt.resolveSignerKeyLocked(p)
	return pk, stg, true
}

func (rt *lineRuntime) resolveSignerKeyLocked(p ldrcrypto.Principal) (ldrcrypto.PublicKey, int) {
	if err := p.Validate(); err != nil {
		return ldrcrypto.PublicKey{}, standingNever
	}
	l := &rt.state.Line
	switch p.Kind {
	case ldrcrypto.PrincipalRoot:
		if l.Generation == 0 {
			for _, rk := range rt.desc.RootKeys {
				if rk.Equal(*p.Key) {
					return *p.Key, standingBootstrapRoot
				}
			}
			return ldrcrypto.PublicKey{}, standingNever
		}
		tok, err := KeyToken(*p.Key)
		if err != nil {
			return ldrcrypto.PublicKey{}, standingNever
		}
		if slices.Contains(l.RootKeys, tok) {
			return *p.Key, standingActive
		}
		if slices.Contains(l.Tombstones.RootKeys, tok) {
			return *p.Key, standingRevoked
		}
		return ldrcrypto.PublicKey{}, standingNever

	case ldrcrypto.PrincipalOperator:
		if l.Generation == 0 {
			return ldrcrypto.PublicKey{}, standingNever
		}
		tok, err := KeyToken(*p.Key)
		if err != nil {
			return ldrcrypto.PublicKey{}, standingNever
		}
		if slices.Contains(l.Operators, tok) {
			return *p.Key, standingActive
		}
		if slices.Contains(l.Tombstones.OperatorKeys, tok) {
			return *p.Key, standingRevoked
		}
		return ldrcrypto.PublicKey{}, standingNever

	case ldrcrypto.PrincipalCredential:
		if l.Generation == 0 {
			return ldrcrypto.PublicKey{}, standingNever
		}
		c := l.Credentials[CredToken(p.CredID)]
		if c == nil {
			return ldrcrypto.PublicKey{}, standingNever
		}
		pk, err := ParseKeyToken(c.SigningKey)
		if err != nil {
			return ldrcrypto.PublicKey{}, standingNever
		}
		if c.Revoked {
			return pk, standingRevoked
		}
		return pk, standingActive
	default:
		return ldrcrypto.PublicKey{}, standingNever
	}
}

func (rt *lineRuntime) recordedLocked(key ldrstore.StoredOpKey, digest [32]byte) (SubmitReply, bool) {
	if he, ok := rt.hot[key]; ok {
		if he.Digest != digest {
			return SubmitReply{Class: ldrcore.ClassMismatch}, true
		}
		return SubmitReply{
			Class:    ldrcore.ClassOutcome,
			Outcome:  he.Outcome,
			Head:     rt.heads[he.Outcome.Seq],
			SeqTime:  rt.times[he.Outcome.Seq],
			Original: true,
		}, true
	}
	if rec, ok := rt.logIndex[key]; ok {
		if rec.Digest != digest {
			return SubmitReply{Class: ldrcore.ClassMismatch}, true
		}
		return SubmitReply{
			Class:    ldrcore.ClassOutcome,
			Outcome:  ldrstore.StoredOutcome{Kind: ldrcore.Committed, Seq: rec.Seq},
			Head:     rt.heads[rec.Seq],
			SeqTime:  rt.times[rec.Seq],
			Original: true,
		}, true
	}
	return SubmitReply{}, false
}

func (rt *lineRuntime) lookupLocked(key ldrstore.StoredOpKey, digest [32]byte) (SubmitReply, bool) {
	if rep, found := rt.recordedLocked(key, digest); found {
		return rep, true
	}
	curGen := uint64(rt.state.Line.Generation)
	if key.Generation < curGen {
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "abandoned"}, true
	}
	if key.Generation > curGen {
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "history_unavailable"}, true
	}
	return SubmitReply{}, false
}

// Submit processes a mutation intent for lineID under the authenticated session
// principal authPrincipal. Follows P5 lookup-before-sidecars and atomic WAL durability.
func (e *RelayEngine) Submit(lineID []byte, authPrincipal ldrcrypto.Principal, intentBytes, payloadSidecar []byte, wrapSidecars map[[32]byte][]byte) SubmitReply {
	rt, ok := e.getLine(lineID)
	if !ok {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "wrong_line"}
	}

	lim := ldrcrypto.Limits{MaxBytes: int(rt.desc.Profile.MaxRecordBytes), MaxDepth: 16, MaxItems: 4096}
	env, err := ldrcrypto.UnmarshalSignedIntent(intentBytes, lim)
	if err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}
	dec, err := DecodeWireIntentBody(env.BodyBytes, rt.desc.Profile, lim)
	if err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}
	if !bytes.Equal(dec.LineID, rt.lineID) {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "wrong_line"}
	}
	if dec.ProfileDigest != rt.profDigest {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "wrong_profile"}
	}
	// P7 S7: submitter session MUST belong to the exact principal signing the intent.
	if !authPrincipal.Equal(dec.Principal) {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "submitter_mismatch"}
	}
	intentDigest, err := env.Digest()
	if err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if dec.OpType != "line_init" && rt.state.Line.Generation == 0 {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "no_line"}
	}

	// Verify real signature BEFORE any standing disclosure or lookup!
	pubKey, stg := rt.resolveSignerKeyLocked(dec.Principal)
	if stg == standingNever {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "unknown_signer"}
	}
	if err := env.Verify(pubKey); err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "bad_signature"}
	}
	if stg == standingRevoked {
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "revoked"}
	}

	opKey := ldrstore.StoredOpKey{
		Generation: dec.Generation,
		Signer:     dec.PrincipalToken,
		SeenSeq:    dec.SeenSeq,
		OpID:       dec.OpID,
	}

	if dec.OpType == "line_init" {
		return e.submitLineInitLocked(rt, env, dec, opKey, intentDigest)
	}
	if stg != standingActive {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "unknown_signer"}
	}

	// P5 §5.2: Lookup outcome BEFORE requiring or validating sidecars!
	if rep, found := rt.lookupLocked(opKey, intentDigest); found {
		return rep
	}

	// Lookup miss: validate required sidecars BEFORE consuming clock or evaluating Apply.
	sidecars := make(map[[32]byte]ldrstore.SidecarBlob)
	if dec.PayloadCommit.Length > 0 {
		if err := ldrcrypto.VerifyPayloadSidecar(dec.PayloadCommit, payloadSidecar); err != nil {
			return SubmitReply{Class: ldrcore.ClassAdmission, Code: "missing_or_corrupt_sidecar"}
		}
		sidecars[dec.PayloadCommit.Digest] = ldrstore.SidecarBlob{
			Kind: ldrstore.SidecarPayload,
			Data: bytes.Clone(payloadSidecar),
		}
	}
	if dec.OpType == "key_epoch_activate" && len(dec.Manifest) > 0 {
		if err := ldrcrypto.VerifyWrapManifest(dec.Manifest, wrapSidecars); err != nil {
			return SubmitReply{Class: ldrcore.ClassAdmission, Code: "missing_or_corrupt_sidecar"}
		}
		for _, ent := range dec.Manifest {
			sidecars[ent.Commit.Digest] = ldrstore.SidecarBlob{
				Kind: ldrstore.SidecarWrap,
				Data: bytes.Clone(wrapSidecars[ent.CredID]),
			}
		}
	}

	// Sequencer clock reading (must be trusted).
	t, ok := rt.clock.Reading()
	if !ok {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "clock_uncertain"}
	}

	// Anchor resolution and inclusive deadline check.
	curHeadSeq := uint64(rt.state.Line.HeadSeq)
	if dec.SeenSeq > curHeadSeq {
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "history_unavailable"}
	}
	anchorHead, known := rt.heads[dec.SeenSeq]
	if dec.SeenSeq < 1 || !known || anchorHead != dec.SeenHead {
		return SubmitReply{Class: ldrcore.ClassRefusal, Code: "unknown_anchor"}
	}
	effValidity := min(dec.ValidityMS, rt.desc.Profile.MaxValidityMS)
	if t > rt.times[dec.SeenSeq]+effValidity {
		return SubmitReply{Class: ldrcore.ClassRefusal, Code: "expired"}
	}

	// Admitted: evaluate state transition via ldrcore.Apply.
	next, out := ldrcore.Apply(rt.state, dec.Record, int64(t), rt.coreProf)
	switch out.Kind {
	case ldrcore.Committed:
		nextSeq := uint64(next.Line.HeadSeq)
		prevHead := rt.heads[curHeadSeq]
		newHead, err := ldrcrypto.ClientChainHead(prevHead, rt.profDigest, rt.lineID, uint64(next.Line.Generation), nextSeq, t, dec.Origin, env.RawBytes)
		if err != nil {
			return SubmitReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
		}
		var pcCopy *ldrcrypto.Commitment
		if dec.PayloadCommit.Length > 0 {
			c := dec.PayloadCommit
			pcCopy = &c
		}
		keyCopy := opKey
		fr := ldrstore.CommittedFrame{
			Gen:           uint64(next.Line.Generation),
			Seq:           nextSeq,
			SeqTime:       t,
			PrevHead:      prevHead,
			Head:          newHead,
			Origin:        dec.Origin,
			OpType:        dec.OpType,
			IntentBytes:   bytes.Clone(env.RawBytes),
			IntentDigest:  intentDigest,
			OpKey:         &keyCopy,
			PayloadCommit: pcCopy,
			WrapCommits:   append([]ldrcrypto.WrapManifestEntry(nil), dec.Manifest...),
		}
		// Durable commit BEFORE updating any in-memory index or returning!
		if err := e.store.AppendCommit(rt.lineID, fr, sidecars, t); err != nil {
			return SubmitReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
		}
		rt.clock.AdvanceFloor(t)
		rt.state = next
		rt.frames = append(rt.frames, fr)
		rt.heads[nextSeq] = newHead
		rt.times[nextSeq] = t
		rt.logIndex[opKey] = ldrstore.CommittedReceipt{Seq: nextSeq, Digest: intentDigest}
		outcome := ldrstore.StoredOutcome{Kind: ldrcore.Committed, Seq: nextSeq}
		rt.hot[opKey] = ldrstore.HotEntry{Key: opKey, Digest: intentDigest, Outcome: outcome}
		return SubmitReply{Class: ldrcore.ClassOutcome, Outcome: outcome, Head: newHead, SeqTime: t}

	case ldrcore.Rejected, ldrcore.Noop:
		e.mu.RLock()
		qMax := e.quotaMax
		e.mu.RUnlock()
		if rt.quota[opKey.Signer] >= qMax {
			return SubmitReply{Class: ldrcore.ClassAdmission, Code: "quota"}
		}
		outcome := ldrstore.StoredOutcome{
			Kind:   out.Kind,
			Reason: out.Reason,
			RefGen: uint64(out.RefGen),
			RefSeq: uint64(out.RefSeq),
		}
		he := ldrstore.HotEntry{Key: opKey, Digest: intentDigest, Outcome: outcome}
		if err := e.store.AppendNonCommit(rt.lineID, he, t); err != nil {
			return SubmitReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
		}
		rt.clock.AdvanceFloor(t)
		rt.quota[opKey.Signer]++
		rt.hot[opKey] = he
		return SubmitReply{Class: ldrcore.ClassOutcome, Outcome: outcome}

	default:
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "internal_violation"}
	}
}

func (e *RelayEngine) submitLineInitLocked(rt *lineRuntime, env ldrcrypto.SignedIntent, dec *DecodedIntent, opKey ldrstore.StoredOpKey, intentDigest [32]byte) SubmitReply {
	if rep, found := rt.recordedLocked(opKey, intentDigest); found {
		return rep
	}
	if rt.state.Line.Generation != 0 {
		return SubmitReply{Class: ldrcore.ClassRefusal, Code: "line_exists"}
	}
	if dec.Generation < 1 {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}
	if dec.Generation != 1 || dec.SeenSeq > 0 {
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "history_unavailable"}
	}
	if dec.SeenHead != rt.genesis {
		return SubmitReply{Class: ldrcore.ClassRefusal, Code: "unknown_anchor"}
	}
	// Verify line_init matches the provisioned creation descriptor exactly (G2).
	if dec.DescriptorDigest == nil || *dec.DescriptorDigest != rt.cd || dec.InitProfile == nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "invalid_bootstrap"}
	}
	initProfDig, err := dec.InitProfile.Digest()
	if err != nil || initProfDig != rt.profDigest {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "invalid_bootstrap"}
	}
	// Verify root_keys match the provisioned descriptor's canonical root_keys.
	wantR0, _ := KeyToken(rt.desc.RootKeys[0])
	wantR1, _ := KeyToken(rt.desc.RootKeys[1])
	if len(dec.Record.RootKeys) != 2 || dec.Record.RootKeys[0] != wantR0 || dec.Record.RootKeys[1] != wantR1 {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "invalid_bootstrap"}
	}

	t, ok := rt.clock.Reading()
	if !ok {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "clock_uncertain"}
	}
	next, out := ldrcore.Apply(rt.state, dec.Record, int64(t), rt.coreProf)
	if out.Kind != ldrcore.Committed {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "invalid_bootstrap"}
	}
	newHead, err := ldrcrypto.ClientChainHead(rt.genesis, rt.profDigest, rt.lineID, 1, 1, t, dec.Origin, env.RawBytes)
	if err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
	}
	keyCopy := opKey
	fr := ldrstore.CommittedFrame{
		Gen:          1,
		Seq:          1,
		SeqTime:      t,
		PrevHead:     rt.genesis,
		Head:         newHead,
		Origin:       dec.Origin,
		OpType:       "line_init",
		IntentBytes:  bytes.Clone(env.RawBytes),
		IntentDigest: intentDigest,
		OpKey:        &keyCopy,
	}
	if err := e.store.AppendCommit(rt.lineID, fr, nil, t); err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
	}
	rt.clock.AdvanceFloor(t)
	rt.state = next
	rt.frames = append(rt.frames, fr)
	rt.heads[1] = newHead
	rt.times[1] = t
	rt.logIndex[opKey] = ldrstore.CommittedReceipt{Seq: 1, Digest: intentDigest}
	return SubmitReply{
		Class:   ldrcore.ClassOutcome,
		Outcome: ldrstore.StoredOutcome{Kind: ldrcore.Committed, Seq: 1},
		Head:    newHead,
		SeqTime: t,
	}
}

// Query answers an authorized outcome lookup without mutating state, quota, or time_floor.
func (e *RelayEngine) Query(lineID []byte, authPrincipal ldrcrypto.Principal, key ldrstore.StoredOpKey, digest [32]byte) SubmitReply {
	rt, ok := e.getLine(lineID)
	if !ok {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "wrong_line"}
	}
	authTok, err := PrincipalToken(authPrincipal)
	if err != nil {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.state.Line.Generation == 0 {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "no_line"}
	}
	_, stg := rt.resolveSignerKeyLocked(authPrincipal)
	switch stg {
	case standingRevoked:
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "revoked"}
	case standingActive:
	default:
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "unknown_signer"}
	}
	reconciler := authPrincipal.Kind == ldrcrypto.PrincipalRoot || authPrincipal.Kind == ldrcrypto.PrincipalOperator
	if authTok != key.Signer && !reconciler {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "not_authorized"}
	}
	if rep, found := rt.lookupLocked(key, digest); found {
		return rep
	}
	// Time-dependent outcome lookup requires a trusted clock without advancing floor.
	_, trusted := rt.clock.Reading()
	if !trusted {
		return SubmitReply{Class: ldrcore.ClassAdmission, Code: "clock_uncertain"}
	}
	if key.SeenSeq > uint64(rt.state.Line.HeadSeq) {
		return SubmitReply{Class: ldrcore.ClassUnresolved, Code: "history_unavailable"}
	}
	if _, known := rt.heads[key.SeenSeq]; key.SeenSeq < 1 || !known {
		return SubmitReply{Class: ldrcore.ClassRefusal, Code: "unknown_anchor"}
	}
	if rt.clock.Floor() > rt.times[key.SeenSeq]+rt.desc.Profile.MaxValidityMS {
		return SubmitReply{Class: ldrcore.ClassRefusal, Code: "expired"}
	}
	return SubmitReply{Class: ldrcore.ClassUnknown, Code: "outcome_unknown"}
}

// AnchorRequest returns a fresh head, writing a durable time_anchor if elapsed
// time strictly exceeds profile.FreshnessMS (§4.2).
func (e *RelayEngine) AnchorRequest(lineID []byte, authPrincipal ldrcrypto.Principal) AnchorReply {
	rt, ok := e.getLine(lineID)
	if !ok {
		return AnchorReply{Class: ldrcore.ClassAdmission, Code: "wrong_line"}
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.state.Line.Generation == 0 {
		return AnchorReply{Class: ldrcore.ClassAdmission, Code: "no_line"}
	}
	_, stg := rt.resolveSignerKeyLocked(authPrincipal)
	switch stg {
	case standingRevoked:
		return AnchorReply{Class: ldrcore.ClassUnresolved, Code: "revoked"}
	case standingActive:
	default:
		return AnchorReply{Class: ldrcore.ClassAdmission, Code: "not_authorized"}
	}

	t, trusted := rt.clock.Reading()
	if !trusted {
		return AnchorReply{Class: ldrcore.ClassAdmission, Code: "clock_uncertain"}
	}
	curSeq := uint64(rt.state.Line.HeadSeq)
	wrote := false
	if t > uint64(rt.state.Line.HeadTime) && t-uint64(rt.state.Line.HeadTime) > rt.desc.Profile.FreshnessMS {
		next, out := ldrcore.Apply(rt.state, ldrcore.Record{Origin: ldrcore.OriginSequencer, Type: "time_anchor"}, int64(t), rt.coreProf)
		if out.Kind != ldrcore.Committed {
			return AnchorReply{Class: ldrcore.ClassAdmission, Code: "exhausted"}
		}
		nextSeq := uint64(next.Line.HeadSeq)
		prevHead := rt.heads[curSeq]
		newHead, err := ldrcrypto.AnchorChainHead(prevHead, rt.profDigest, rt.lineID, uint64(next.Line.Generation), nextSeq, t)
		if err != nil {
			return AnchorReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
		}
		fr := ldrstore.CommittedFrame{
			Gen:      uint64(next.Line.Generation),
			Seq:      nextSeq,
			SeqTime:  t,
			PrevHead: prevHead,
			Head:     newHead,
			Origin:   ldrcore.OriginSequencer,
			OpType:   "time_anchor",
		}
		if err := e.store.AppendCommit(rt.lineID, fr, nil, t); err != nil {
			return AnchorReply{Class: ldrcore.ClassAdmission, Code: "storage_error"}
		}
		rt.clock.AdvanceFloor(t)
		rt.state = next
		rt.frames = append(rt.frames, fr)
		rt.heads[nextSeq] = newHead
		rt.times[nextSeq] = t
		curSeq = nextSeq
		wrote = true
	}
	return AnchorReply{
		Class:   ldrcore.ClassOutcome,
		Gen:     uint64(rt.state.Line.Generation),
		Seq:     curSeq,
		Head:    rt.heads[curSeq],
		SeqTime: rt.times[curSeq],
		Wrote:   wrote,
	}
}

// Compact durably retires hot entries for strictly expired anchors while
// preserving permanent log_index entries.
func (e *RelayEngine) Compact(lineID []byte) (int, error) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return 0, ldrstore.ErrLineNotFound
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	t, trusted := rt.clock.Reading()
	if !trusted {
		return 0, errors.New("clock_uncertain")
	}
	var retired []ldrstore.StoredOpKey
	for k := range rt.hot {
		if k.Generation == uint64(rt.state.Line.Generation) && t <= rt.times[k.SeenSeq]+rt.desc.Profile.MaxValidityMS {
			continue
		}
		retired = append(retired, k)
	}
	if len(retired) == 0 {
		return 0, nil
	}
	if err := e.store.AppendCompact(rt.lineID, retired, t); err != nil {
		return 0, err
	}
	rt.clock.AdvanceFloor(t)
	for _, k := range retired {
		if he, ok := rt.hot[k]; ok {
			if he.Outcome.Kind != ldrcore.Committed && rt.quota[k.Signer] > 0 {
				rt.quota[k.Signer]--
			}
			delete(rt.hot, k)
		}
	}
	return len(retired), nil
}

// ControlLog returns paginated control-only frames (omitting payload sidecars, O25).
func (e *RelayEngine) ControlLog(lineID []byte, authPrincipal ldrcrypto.Principal, fromSeq, maxCount uint64) ([]ControlFrameWire, string) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return nil, "wrong_line"
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state.Line.Generation == 0 {
		return nil, "no_line"
	}
	_, stg := rt.resolveSignerKeyLocked(authPrincipal)
	switch stg {
	case standingRevoked:
		return nil, "revoked"
	case standingActive:
	default:
		return nil, "not_authorized"
	}
	if fromSeq == 0 {
		fromSeq = 1
	}
	if maxCount == 0 || maxCount > MaxLogPageSize {
		maxCount = MaxLogPageSize
	}
	var out []ControlFrameWire
	for _, fr := range rt.frames {
		if fr.Seq < fromSeq {
			continue
		}
		out = append(out, ControlFrameWire{
			Gen:           fr.Gen,
			Seq:           fr.Seq,
			SeqTime:       fr.SeqTime,
			PrevHead:      fr.PrevHead,
			Head:          fr.Head,
			Origin:        fr.Origin,
			OpType:        fr.OpType,
			IntentBytes:   bytes.Clone(fr.IntentBytes),
			PayloadCommit: fr.PayloadCommit,
			WrapCommits:   append([]ldrcrypto.WrapManifestEntry(nil), fr.WrapCommits...),
		})
		if uint64(len(out)) >= maxCount {
			break
		}
	}
	return out, ""
}

// FetchSidecar returns commitment-verified sidecar bytes to an active principal.
func (e *RelayEngine) FetchSidecar(lineID []byte, authPrincipal ldrcrypto.Principal, kind string, digest [32]byte) ([]byte, string) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return nil, "wrong_line"
	}
	rt.mu.Lock()
	if rt.state.Line.Generation == 0 {
		rt.mu.Unlock()
		return nil, "no_line"
	}
	_, stg := rt.resolveSignerKeyLocked(authPrincipal)
	rt.mu.Unlock()
	switch stg {
	case standingRevoked:
		return nil, "revoked"
	case standingActive:
	default:
		return nil, "not_authorized"
	}
	data, err := e.store.GetSidecar(lineID, kind, digest)
	if err != nil {
		if errors.Is(err, ldrstore.ErrMissingSidecar) {
			return nil, "not_found"
		}
		return nil, "storage_error"
	}
	return data, ""
}

// Shutdown records clean shutdown markers on every line before closing the store.
func (e *RelayEngine) Shutdown() error {
	e.mu.RLock()
	rts := make([]*lineRuntime, 0, len(e.lines))
	for _, rt := range e.lines {
		rts = append(rts, rt)
	}
	e.mu.RUnlock()
	sample := e.nowFn()
	var wall uint64
	if sample.WallMS > 0 {
		wall = uint64(sample.WallMS)
	}
	for _, rt := range rts {
		rt.mu.Lock()
		_ = e.store.RecordCleanShutdown(rt.lineID, rt.clock.Floor(), wall)
		rt.mu.Unlock()
	}
	return e.store.Close()
}

// Status returns non-secret operational diagnostics for every provisioned line.
func (e *RelayEngine) Status() []LineStatus {
	e.mu.RLock()
	rts := make([]*lineRuntime, 0, len(e.lines))
	for _, rt := range e.lines {
		rts = append(rts, rt)
	}
	e.mu.RUnlock()
	sort.Slice(rts, func(i, j int) bool { return rts[i].hexID < rts[j].hexID })
	out := make([]LineStatus, 0, len(rts))
	for _, rt := range rts {
		rt.mu.Lock()
		curSeq := uint64(rt.state.Line.HeadSeq)
		h := rt.heads[curSeq]
		out = append(out, LineStatus{
			LineID:            rt.hexID,
			Generation:        uint64(rt.state.Line.Generation),
			HeadSeq:           curSeq,
			Head:              hex.EncodeToString(h[:]),
			HotEntries:        len(rt.hot),
			CommittedOps:      len(rt.logIndex),
			RecoveredTornTail: rt.recoveredTornTail,
			Clock:             rt.clock.Status(),
		})
		rt.mu.Unlock()
	}
	return out
}
