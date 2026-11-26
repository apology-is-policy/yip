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
// commitment, and Historical status against their own verified log state.
type RegisterEntryWire struct {
	Actor        string
	Register     string
	EnvBytes     []byte
	Payload      []byte
	AcceptedAtMS uint64
	Historical   bool
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

// ListRegisters returns cached advisory register entries for an authenticated
// standing principal, optionally filtered by register type ("presence", "roadmap", "resource").
func (e *RelayEngine) ListRegisters(lineID []byte, sessPrincipal ldrcrypto.Principal, registerFilter string) ([]RegisterEntryWire, string) {
	rt, ok := e.getLine(lineID)
	if !ok {
		return nil, "wrong_line"
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.quarantined {
		return nil, "storage_quarantined"
	}
	_, stg := rt.resolveSignerKeyLocked(sessPrincipal)
	switch stg {
	case standingRevoked:
		return nil, "revoked"
	case standingNever:
		return nil, "unknown_signer"
	}
	if registerFilter != "" && !ldrcrypto.ValidRegisterType(registerFilter) {
		return nil, ldrcore.RegUnknownType
	}

	keys := make([]string, 0, len(rt.regData))
	for k, sr := range rt.regData {
		if registerFilter != "" && sr.register != registerFilter {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]RegisterEntryWire, 0, len(keys))
	for _, k := range keys {
		sr := rt.regData[k]
		out = append(out, RegisterEntryWire{
			Actor:        sr.actor,
			Register:     sr.register,
			EnvBytes:     bytes.Clone(sr.envBytes),
			Payload:      bytes.Clone(sr.payload),
			AcceptedAtMS: sr.acceptedAtMS,
			Historical:   rt.registers.Historical(rt.state, sr.actor, sr.register),
		})
	}
	return out, ""
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
	if err := ldrcrypto.RequireExactKeys(m, []string{"register", "req_id", "session_id", "v"}); err != nil {
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
	prin, gen, ok := s.validateSession(sid, lineID, cb, reqID, true)
	if !ok {
		writeCBOR(w, http.StatusUnauthorized, ldrcrypto.Map{{Key: "class", Value: ldrcore.ClassAdmission}, {Key: "code", Value: "invalid_session"}, {Key: "v", Value: uint64(1)}})
		return
	}
	entries, errCode := s.engine.ListRegisters(lineID, prin, regFilter)
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
		arr[i] = ldrcrypto.Map{
			{Key: "accepted_at_ms", Value: ent.AcceptedAtMS},
			{Key: "actor", Value: ent.Actor},
			{Key: "envelope", Value: ent.EnvBytes},
			{Key: "historical", Value: ent.Historical},
			{Key: "payload", Value: ent.Payload},
			{Key: "register", Value: ent.Register},
		}
	}
	writeCBOR(w, http.StatusOK, ldrcrypto.Map{
		{Key: "class", Value: "ok"},
		{Key: "entries", Value: arr},
		{Key: "line_id", Value: lineID},
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

// ListRegisters fetches cached advisory registers over the bound session.
func (c *SessionClient) ListRegisters(ctx context.Context, registerFilter string) ([]RegisterEntryWire, error) {
	c.mu.Lock()
	c.nextReqID++
	reqID := c.nextReqID
	c.mu.Unlock()

	rawReq, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "register", Value: registerFilter},
		{Key: "req_id", Value: reqID},
		{Key: "session_id", Value: c.sessionID},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return nil, err
	}
	reqDigest := sha256.Sum256(rawReq)
	resp, err := c.postRawCBOR(ctx, "register/list", rawReq)
	if err != nil {
		return nil, err
	}
	if err := c.verifyReplyBinding(resp, reqID, reqDigest); err != nil {
		return nil, err
	}
	cls, _ := ldrcrypto.MapString(resp, "class")
	if cls != "ok" {
		code, _ := ldrcrypto.MapString(resp, "code")
		return nil, fmt.Errorf("ldrrelay: register list refused (%s / %s)", cls, code)
	}
	arr, err := ldrcrypto.MapArray(resp, "entries")
	if err != nil {
		return nil, err
	}
	out := make([]RegisterEntryWire, 0, len(arr))
	for _, elem := range arr {
		em, ok := elem.(map[string]any)
		if !ok {
			return nil, errors.New("ldrrelay: invalid register entry element")
		}
		if err := ldrcrypto.RequireExactKeys(em, []string{"accepted_at_ms", "actor", "envelope", "historical", "payload", "register"}); err != nil {
			return nil, fmt.Errorf("ldrrelay: invalid register entry keys: %w", err)
		}
		var ent RegisterEntryWire
		if ent.Actor, err = ldrcrypto.MapString(em, "actor"); err != nil {
			return nil, err
		}
		if ent.Register, err = ldrcrypto.MapString(em, "register"); err != nil {
			return nil, err
		}
		if ent.EnvBytes, err = ldrcrypto.MapBytes(em, "envelope"); err != nil {
			return nil, err
		}
		if ent.Payload, err = ldrcrypto.MapBytes(em, "payload"); err != nil {
			return nil, err
		}
		if ent.AcceptedAtMS, err = ldrcrypto.MapUint(em, "accepted_at_ms"); err != nil {
			return nil, err
		}
		if ent.Historical, err = ldrcrypto.MapBool(em, "historical"); err != nil {
			return nil, err
		}
		out = append(out, ent)
	}
	return out, nil
}
