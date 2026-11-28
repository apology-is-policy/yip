package ldrrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

const (
	// MaxRegisterPageCount bounds entries returned by a single /register/list page.
	MaxRegisterPageCount = 64
	// MaxRegisterPageBytes bounds cumulative encoded entry bytes per /register/list
	// page so responses stay safely below maxHTTPBodyBytes (1 MiB) even when many
	// actors hold large 64 KiB encrypted registers.
	MaxRegisterPageBytes = 512 * 1024
	maxRegisterListPages = 1024
)

type storedRegister struct {
	actor        string
	register     string
	envBytes     []byte
	payload      []byte
	acceptedAtMS uint64
}

// RegisterPutReply is the relay response to publishing an advisory register value (§9).
type RegisterPutReply struct {
	Class        string
	Code         string
	AcceptedAtMS uint64
}

// RegisterEntryWire is one cached signed/encrypted advisory register entry served
// by the relay. Clients MUST independently verify the envelope signature, payload
// commitment, writer incarnation/binding, and Historical status against their own
// verified log state.
type RegisterEntryWire struct {
	Actor        string
	Register     string
	EnvBytes     []byte
	Payload      []byte
	AcceptedAtMS uint64
	Historical   bool
}

func registerEntryCBOR(ent RegisterEntryWire) ldrcrypto.Map {
	return ldrcrypto.Map{
		{Key: "accepted_at_ms", Value: ent.AcceptedAtMS},
		{Key: "actor", Value: ent.Actor},
		{Key: "envelope", Value: ent.EnvBytes},
		{Key: "historical", Value: ent.Historical},
		{Key: "payload", Value: ent.Payload},
		{Key: "register", Value: ent.Register},
	}
}

// PublishRegister verifies and publishes one signed/encrypted advisory register
// update outside the log (§9). Never mutates committed log state or time_floor.
func (e *RelayEngine) PublishRegister(lineID []byte, sessPrincipal ldrcrypto.Principal, envBytes, payload []byte) RegisterPutReply {
	rt, ok := e.getLine(lineID)
	if !ok {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "wrong_line"}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.quarantined {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "storage_quarantined"}
	}
	pubKey, stg := rt.resolveSignerKeyLocked(sessPrincipal)
	switch stg {
	case standingRevoked:
		return RegisterPutReply{Class: ldrcore.ClassUnresolved, Code: "revoked"}
	case standingNever:
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "unknown_signer"}
	}
	if sessPrincipal.Kind != ldrcrypto.PrincipalCredential {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "unauthorized_principal"}
	}
	if len(envBytes) == 0 || len(envBytes) > ldrcrypto.MaxRegisterEnvelopeBytes {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}
	env, bodyBytes, err := ldrcrypto.ParseRegisterEnvelope(envBytes)
	if err != nil {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "malformed"}
	}
	if !bytes.Equal(env.LineID, rt.lineID) || env.ProfileDigest != rt.profDigest {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: ldrcore.RegWrongLine}
	}
	if env.CredID != sessPrincipal.CredID {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "signer_mismatch"}
	}
	if len(payload) == 0 || uint64(len(payload)) > ldrcrypto.MaxRegisterBodyBytes || uint64(len(payload)) > rt.desc.Profile.MaxCiphertextBytes {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "payload_too_large"}
	}
	if err := ldrcrypto.VerifyPayloadSidecar(env.PayloadCommit, payload); err != nil {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: "commitment_mismatch"}
	}
	if err := ldrcrypto.VerifyDomain(pubKey, ldrcrypto.PurposeRegister, 1, bodyBytes, env.Sig); err != nil {
		return RegisterPutReply{Class: ldrcore.ClassAdmission, Code: ldrcore.RegBadSignature}
	}

	nowMS := e.nowFn().WallMS
	if nowMS < 0 {
		nowMS = 0
	}
	rv := ldrcore.RegisterValue{
		LineID:      rt.hexID,
		Generation:  int64(env.Generation),
		Register:    env.Register,
		Actor:       env.ActorID,
		Cred:        CredToken(env.CredID),
		BindingGen:  int64(env.BindingGen),
		WriterRev:   int64(env.WriterRev),
		Incarnation: env.Incarnation,
		KeyEpoch:    int64(env.KeyEpoch),
		Counter:     int64(env.Counter),
		SignatureOK: true,
	}
	if reason := rt.registers.Publish(rt.state, rv, nowMS); reason != "" {
		return RegisterPutReply{Class: ldrcore.Rejected, Code: reason}
	}
	key := env.ActorID + "/" + env.Register
	rt.regData[key] = storedRegister{
		actor:        env.ActorID,
		register:     env.Register,
		envBytes:     bytes.Clone(envBytes),
		payload:      bytes.Clone(payload),
		acceptedAtMS: uint64(nowMS),
	}
	return RegisterPutReply{Class: "ok", AcceptedAtMS: uint64(nowMS)}
}

// ListRegistersPage returns one deterministic, sorted page of cached advisory
// registers strictly after afterKey, bounded by both maxCount and maxBytes
// (exact canonical CBOR encoded entry byte budget).
func (e *RelayEngine) ListRegistersPage(lineID []byte, sessPrincipal ldrcrypto.Principal, registerFilter, afterKey string, maxCount, maxBytes uint64) ([]RegisterEntryWire, string, bool, string) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return nil, "", false, "wrong_line"
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.quarantined {
		return nil, "", false, "storage_quarantined"
	}
	_, stg := rt.resolveSignerKeyLocked(sessPrincipal)
	switch stg {
	case standingRevoked:
		return nil, "", false, "revoked"
	case standingNever:
		return nil, "", false, "unknown_signer"
	}
	if registerFilter != "" && !ldrcrypto.ValidRegisterType(registerFilter) {
		return nil, "", false, ldrcore.RegUnknownType
	}
	if maxCount == 0 || maxCount > MaxRegisterPageCount {
		maxCount = MaxRegisterPageCount
	}
	if maxBytes == 0 || maxBytes > MaxRegisterPageBytes {
		maxBytes = MaxRegisterPageBytes
	}

	keys := make([]string, 0, len(rt.regData))
	for k, sr := range rt.regData {
		if registerFilter != "" && sr.register != registerFilter {
			continue
		}
		if afterKey != "" && k <= afterKey {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]RegisterEntryWire, 0, min(len(keys), int(maxCount)))
	var usedBytes uint64
	hasMore := false
	nextCursor := ""
	for _, k := range keys {
		sr := rt.regData[k]
		ent := RegisterEntryWire{
			Actor:        sr.actor,
			Register:     sr.register,
			EnvBytes:     bytes.Clone(sr.envBytes),
			Payload:      bytes.Clone(sr.payload),
			AcceptedAtMS: sr.acceptedAtMS,
			Historical:   rt.registers.Historical(rt.state, sr.actor, sr.register),
		}
		enc, err := ldrcrypto.MarshalCBORWithLimits(registerEntryCBOR(ent), ldrcrypto.Limits{
			MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 1024,
		})
		if err != nil {
			return nil, "", false, "internal_encoding_error"
		}
		entBytes := uint64(len(enc))
		if uint64(len(out)) >= maxCount || (len(out) > 0 && usedBytes+entBytes > maxBytes) {
			hasMore = true
			last := out[len(out)-1]
			nextCursor = last.Actor + "/" + last.Register
			break
		}
		out = append(out, ent)
		usedBytes += entBytes
	}
	return out, nextCursor, hasMore, ""
}

// ListRegisters returns all cached advisory register entries for an authenticated
// standing principal, optionally filtered by register type.
func (e *RelayEngine) ListRegisters(lineID []byte, sessPrincipal ldrcrypto.Principal, registerFilter string) ([]RegisterEntryWire, string) {
	var all []RegisterEntryWire
	after := ""
	for page := 0; page < maxRegisterListPages; page++ {
		entries, next, more, errCode := e.ListRegistersPage(lineID, sessPrincipal, registerFilter, after, MaxRegisterPageCount, MaxRegisterPageBytes)
		if errCode != "" {
			return nil, errCode
		}
		all = append(all, entries...)
		if !more {
			return all, ""
		}
		after = next
	}
	return all, ""
}

func (s *RelayServer) handleRegisterPut(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBOR(body, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 1024})
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"envelope", "payload", "req_id", "session_id", "v"}); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err1 := ldrcrypto.MapBytesLen(m, "session_id", 16)
	reqID, err2 := ldrcrypto.MapUint(m, "req_id")
	envBytes, err3 := ldrcrypto.MapBytes(m, "envelope")
	payload, err4 := ldrcrypto.MapBytes(m, "payload")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	rep := s.engine.PublishRegister(lineID, prin, envBytes, payload)
	status := http.StatusOK
	if rep.Class != "ok" {
		if rep.Code == "revoked" || rep.Code == "unauthorized_principal" || rep.Code == "unknown_signer" {
			status = http.StatusForbidden
		} else if rep.Code == "storage_quarantined" {
			status = http.StatusServiceUnavailable
		} else {
			status = http.StatusBadRequest
		}
	}
	writeCBOR(w, status, ldrcrypto.Map{
		{Key: "accepted_at_ms", Value: rep.AcceptedAtMS},
		{Key: "class", Value: rep.Class},
		{Key: "code", Value: rep.Code},
		{Key: "line_id", Value: lineID},
		{Key: "req_digest", Value: reqDigest[:]},
		{Key: "req_id", Value: reqID},
		{Key: "session_gen", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
	})
}

func (s *RelayServer) handleRegisterList(w http.ResponseWriter, lineID []byte, cb [32]byte, body []byte, reqDigest [32]byte) {
	dec, err := ldrcrypto.UnmarshalCBORDefault(body)
	if err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	m, ok := dec.(map[string]any)
	if !ok {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"register", "req_id", "session_id", "v"}, "after_key", "max_count"); err != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	sid, err1 := ldrcrypto.MapBytesLen(m, "session_id", 16)
	reqID, err2 := ldrcrypto.MapUint(m, "req_id")
	regFilter, err3 := ldrcrypto.MapString(m, "register")
	if err1 != nil || err2 != nil || err3 != nil {
		writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
		return
	}
	var afterKey string
	if _, has := m["after_key"]; has {
		afterKey, err = ldrcrypto.MapString(m, "after_key")
		if err != nil {
			writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
			return
		}
	}
	var maxCount uint64
	if _, has := m["max_count"]; has {
		maxCount, err = ldrcrypto.MapUint(m, "max_count")
		if err != nil {
			writeCBOR(w, http.StatusBadRequest, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "malformed"}, {Key: "v", Value: uint64(1)}})
			return
		}
	}
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	entries, nextCursor, hasMore, errCode := s.engine.ListRegistersPage(lineID, prin, regFilter, afterKey, maxCount, s.registerPageByteCap())
	if errCode != "" {
		cls := ldrcore.ClassAdmission
		status := http.StatusForbidden
		if errCode == "revoked" {
			cls = ldrcore.ClassUnresolved
		} else if errCode == ldrcore.RegUnknownType {
			status = http.StatusBadRequest
		} else if errCode == "storage_quarantined" {
			status = http.StatusServiceUnavailable
		}
		writeCBOR(w, status, ldrcrypto.Map{
			{Key: "class", Value: cls},
			{Key: "code", Value: errCode},
			{Key: "line_id", Value: lineID},
			{Key: "req_digest", Value: reqDigest[:]},
			{Key: "req_id", Value: reqID},
			{Key: "session_gen", Value: gen},
			{Key: "session_id", Value: sid},
			{Key: "v", Value: uint64(1)},
		})
		return
	}
	arr := make([]any, len(entries))
	for i, ent := range entries {
		arr[i] = registerEntryCBOR(ent)
	}
	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "class", Value: "ok"},
		{Key: "entries", Value: arr},
		{Key: "has_more", Value: hasMore},
		{Key: "line_id", Value: lineID},
		{Key: "next_cursor", Value: nextCursor},
		{Key: "req_digest", Value: reqDigest[:]},
		{Key: "req_id", Value: reqID},
		{Key: "session_gen", Value: gen},
		{Key: "session_id", Value: sid},
		{Key: "v", Value: uint64(1)},
	})
}

// PutRegister publishes one signed/encrypted advisory register value over the bound session.
func (c *SessionClient) PutRegister(ctx context.Context, envBytes, payload []byte) (RegisterPutReply, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	rawReq, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "envelope", Value: envBytes},
		{Key: "payload", Value: payload},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "v", Value: uint64(1)},
	}, ldrcrypto.Limits{MaxBytes: maxHTTPBodyBytes, MaxDepth: 16, MaxItems: 1024})
	if err != nil {
		return RegisterPutReply{}, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "register/put", rawReq)
	if err != nil {
		return RegisterPutReply{}, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return RegisterPutReply{}, err
	}
	var out RegisterPutReply
	if out.Class, err = ldrcrypto.MapString(resp, "class"); err != nil {
		return RegisterPutReply{}, err
	}
	out.Code, _ = ldrcrypto.MapString(resp, "code")
	out.AcceptedAtMS, _ = ldrcrypto.MapUint(resp, "accepted_at_ms")
	return out, nil
}

// ListRegistersPage fetches one bounded page of cached advisory registers over
// the bound session. Returns *AuthError when the relay returns a reply-bound
// unresolved/revoked refusal.
func (c *SessionClient) ListRegistersPage(ctx context.Context, registerFilter, afterKey string, maxCount uint64) ([]RegisterEntryWire, string, bool, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	reqMap := ldrcrypto.Map{
		{Key: "register", Value: registerFilter},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "v", Value: uint64(1)},
	}
	if afterKey != "" {
		reqMap = append(reqMap, ldrcrypto.MapEntry{Key: "after_key", Value: afterKey})
	}
	if maxCount > 0 {
		reqMap = append(reqMap, ldrcrypto.MapEntry{Key: "max_count", Value: maxCount})
	}
	rawReq, err := ldrcrypto.MarshalCBOR(reqMap)
	if err != nil {
		return nil, "", false, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "register/list", rawReq)
	if err != nil {
		return nil, "", false, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return nil, "", false, err
	}
	cls, err := ldrcrypto.MapString(resp, "class")
	if err != nil || cls == "" {
		return nil, "", false, errors.New("ldrrelay: malformed register list reply class")
	}
	if cls != "ok" {
		code, err := ldrcrypto.MapString(resp, "code")
		if err != nil || code == "" {
			return nil, "", false, errors.New("ldrrelay: malformed register list refusal code")
		}
		if cls == ldrcore.ClassUnresolved && code == "revoked" {
			return nil, "", false, &AuthError{Class: cls, Code: code}
		}
		return nil, "", false, fmt.Errorf("ldrrelay: register list refused (%s / %s)", cls, code)
	}
	if err := ldrcrypto.RequireExactKeys(resp, []string{
		"class", "entries", "has_more", "line_id", "next_cursor",
		"req_digest", "req_id", "session_gen", "session_id", "v",
	}); err != nil {
		return nil, "", false, fmt.Errorf("ldrrelay: malformed register list reply: %w", err)
	}
	hasMore, err := ldrcrypto.MapBool(resp, "has_more")
	if err != nil {
		return nil, "", false, err
	}
	nextCursor, err := ldrcrypto.MapString(resp, "next_cursor")
	if err != nil {
		return nil, "", false, err
	}
	arr, err := ldrcrypto.MapArray(resp, "entries")
	if err != nil {
		return nil, "", false, err
	}
	out := make([]RegisterEntryWire, 0, len(arr))
	for _, elem := range arr {
		em, ok := elem.(map[string]any)
		if !ok {
			return nil, "", false, errors.New("ldrrelay: invalid register entry element")
		}
		if err := ldrcrypto.RequireExactKeys(em, []string{"accepted_at_ms", "actor", "envelope", "historical", "payload", "register"}); err != nil {
			return nil, "", false, fmt.Errorf("ldrrelay: invalid register entry keys: %w", err)
		}
		var ent RegisterEntryWire
		if ent.Actor, err = ldrcrypto.MapString(em, "actor"); err != nil {
			return nil, "", false, err
		}
		if ent.Register, err = ldrcrypto.MapString(em, "register"); err != nil {
			return nil, "", false, err
		}
		if ent.EnvBytes, err = ldrcrypto.MapBytes(em, "envelope"); err != nil {
			return nil, "", false, err
		}
		if ent.Payload, err = ldrcrypto.MapBytes(em, "payload"); err != nil {
			return nil, "", false, err
		}
		if ent.AcceptedAtMS, err = ldrcrypto.MapUint(em, "accepted_at_ms"); err != nil {
			return nil, "", false, err
		}
		if ent.Historical, err = ldrcrypto.MapBool(em, "historical"); err != nil {
			return nil, "", false, err
		}
		out = append(out, ent)
	}
	if hasMore && (len(out) == 0 || nextCursor == "") {
		return nil, "", false, errors.New("ldrrelay: register list page indicates has_more without progress")
	}
	if !hasMore && nextCursor != "" {
		return nil, "", false, errors.New("ldrrelay: register list final page must have empty next_cursor")
	}
	return out, nextCursor, hasMore, nil
}

// ListRegisters fetches all cached advisory registers across bounded pages,
// enforcing strictly advancing cursors and sorted unique keys.
func (c *SessionClient) ListRegisters(ctx context.Context, registerFilter string) ([]RegisterEntryWire, error) {
	var all []RegisterEntryWire
	afterKey := ""
	prevKey := ""
	for page := 0; page < maxRegisterListPages; page++ {
		entries, nextCursor, hasMore, err := c.ListRegistersPage(ctx, registerFilter, afterKey, MaxRegisterPageCount)
		if err != nil {
			return nil, err
		}
		for _, ent := range entries {
			k := ent.Actor + "/" + ent.Register
			if prevKey != "" && k <= prevKey {
				return nil, fmt.Errorf("ldrrelay: non-monotonic register list key %q after %q", k, prevKey)
			}
			prevKey = k
			all = append(all, ent)
		}
		if !hasMore {
			return all, nil
		}
		if nextCursor <= afterKey || nextCursor != prevKey {
			return nil, fmt.Errorf("ldrrelay: invalid register list cursor %q (after=%q last=%q)", nextCursor, afterKey, prevKey)
		}
		afterKey = nextCursor
	}
	return nil, errors.New("ldrrelay: register list exceeded maximum page count")
}
