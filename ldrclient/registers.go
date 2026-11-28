package ldrclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

var (
	ErrRegisterUncertain = errors.New("ldrclient: register writer state write uncertain; call ReconcileDurability")
	ErrRegisterRejected  = errors.New("ldrclient: register publication rejected")
)

type persistedRegisterWriter struct {
	Actor          string
	Register       string
	BindingGen     uint64
	WriterRev      uint64
	Incarnation    string
	NextCounter    uint64
	TrustedCounter bool
}

type persistedRegisters struct {
	Writers map[string]*persistedRegisterWriter // key: actor + "/" + register
}

// VerifiedRegister is an independently authenticated and decrypted §9 advisory
// register observation. Historical is computed locally from verified.wal state.
type VerifiedRegister struct {
	Actor        string
	Register     string
	CredID       [32]byte
	BindingGen   uint64
	WriterRev    uint64
	Incarnation  string
	KeyEpoch     uint64
	Counter      uint64
	AcceptedAtMS uint64
	Historical   bool
	ReadStatus   string // ldrcore.ReadOK, ReadNoKey, ReadUndecryptable
	Plaintext    []byte
}

func (c *Client) registersPath() string { return filepath.Join(c.dir, "registers.cbor") }

func clonePersistedRegisters(in persistedRegisters) persistedRegisters {
	out := persistedRegisters{Writers: make(map[string]*persistedRegisterWriter, len(in.Writers))}
	for k, w := range in.Writers {
		cp := *w
		out.Writers[k] = &cp
	}
	return out
}

func marshalRegisters(r persistedRegisters) ([]byte, error) {
	keys := make([]string, 0, len(r.Writers))
	for k := range r.Writers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	arr := make([]any, 0, len(keys))
	for _, k := range keys {
		w := r.Writers[k]
		arr = append(arr, ldrcrypto.Map{
			{Key: "actor", Value: w.Actor},
			{Key: "binding_gen", Value: w.BindingGen},
			{Key: "incarnation", Value: w.Incarnation},
			{Key: "next_counter", Value: w.NextCounter},
			{Key: "register", Value: w.Register},
			{Key: "trusted_counter", Value: w.TrustedCounter},
			{Key: "writer_rev", Value: w.WriterRev},
		})
	}
	raw, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "v", Value: uint64(1)},
		{Key: "writers", Value: arr},
	}, ldrcrypto.Limits{MaxBytes: 512 * 1024, MaxDepth: 12, MaxItems: 8192})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ldrstore.ErrPreWrite, err)
	}
	return raw, nil
}

func saveRegistersWithHooks(path string, r persistedRegisters, syncFile func(*os.File) error, syncDir func(string) error) error {
	raw, err := marshalRegisters(r)
	if err != nil {
		return err
	}
	return atomicWriteFileWithHooks(path, raw, 0o600, syncFile, syncDir)
}

func loadRegisters(path string) (persistedRegisters, error) {
	out := persistedRegisters{Writers: make(map[string]*persistedRegisterWriter)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	dec, err := ldrcrypto.UnmarshalCBOR(raw, ldrcrypto.Limits{MaxBytes: 512 * 1024, MaxDepth: 12, MaxItems: 8192})
	if err != nil {
		return out, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return out, errors.New("ldrclient: invalid registers.cbor")
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"v", "writers"}); err != nil {
		return out, err
	}
	if v, err := ldrcrypto.MapUint(m, "v"); err != nil || v != 1 {
		return out, errors.New("ldrclient: unsupported registers.cbor version")
	}
	arr, err := ldrcrypto.MapArray(m, "writers")
	if err != nil {
		return out, err
	}
	for _, elem := range arr {
		wm, ok := elem.(map[string]any)
		if !ok {
			return out, errors.New("ldrclient: invalid register writer entry")
		}
		if err := ldrcrypto.RequireExactKeys(wm, []string{
			"actor", "binding_gen", "incarnation", "next_counter",
			"register", "trusted_counter", "writer_rev",
		}); err != nil {
			return out, err
		}
		w := &persistedRegisterWriter{}
		if w.Actor, err = ldrcrypto.MapString(wm, "actor"); err != nil {
			return out, err
		}
		if w.Register, err = ldrcrypto.MapString(wm, "register"); err != nil {
			return out, err
		}
		if w.BindingGen, err = ldrcrypto.MapUint(wm, "binding_gen"); err != nil {
			return out, err
		}
		if w.WriterRev, err = ldrcrypto.MapUint(wm, "writer_rev"); err != nil {
			return out, err
		}
		if w.Incarnation, err = ldrcrypto.MapString(wm, "incarnation"); err != nil {
			return out, err
		}
		if w.NextCounter, err = ldrcrypto.MapUint(wm, "next_counter"); err != nil {
			return out, err
		}
		if w.TrustedCounter, err = ldrcrypto.MapBool(wm, "trusted_counter"); err != nil {
			return out, err
		}
		out.Writers[w.Actor+"/"+w.Register] = w
	}
	return out, nil
}

func (c *Client) persistRegistersLocked(cand persistedRegisters) error {
	return saveRegistersWithHooks(c.registersPath(), cand, c.syncFileFn, c.syncDirFn)
}

func (c *Client) markRegistersUncertainOnErrLocked(err error) {
	if err == nil || errors.Is(err, ldrstore.ErrPreWrite) {
		return
	}
	c.registersUncertain = true
	c.registersUncertainMsg = err.Error()
	for _, w := range c.registers.Writers {
		w.TrustedCounter = false
	}
}

func (c *Client) recordValidatedRevokedStopLocked(prinTok, code string) error {
	stop := &KeyStop{Key: prinTok, Told: true, Seq: c.ckSeq, Head: c.ckHead, Code: code}
	cand := clonePersistedOutbox(c.outbox)
	c.recordToldRevokedOnLocked(&cand, prinTok, code)
	if err := c.persistOutboxLocked(cand); err != nil {
		// Never discard a validated Rule 8 stop even on ErrPreWrite: stop the
		// exact principal immediately in memory, suspend its pending entries,
		// and fence outboxUncertain until ReconcileDurability persists it.
		if c.pendingStops == nil {
			c.pendingStops = make(map[string]*KeyStop)
		}
		if c.pendingStops[prinTok] == nil {
			c.pendingStops[prinTok] = stop
		}
		c.suspendSignerOnLocked(&c.outbox, prinTok)
		c.outboxUncertain = true
		c.outboxUncertainReason = fmt.Sprintf("pending Rule 8 stop persistence for %s: %v", prinTok, err)
		return err
	}
	c.outbox = cand
	delete(c.pendingStops, prinTok)
	return nil
}

func randomIncarnationID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return "inc-" + hex.EncodeToString(b), nil
}

// EnsureRegisterActivated ensures that this credential owns an active, trusted
// §9 writer incarnation for (actorID, register). Enforces Rule 8 credential stop
// checks before taking any fast path or issuing requests.
func (c *Client) EnsureRegisterActivated(ctx context.Context, sess *ldrrelay.SessionClient, actorID, register string) error {
	if !ldrcrypto.ValidRegisterType(register) || actorID == "" {
		return fmt.Errorf("ldrclient: invalid actor %q or register %q", actorID, register)
	}
	if sess == nil {
		return errors.New("ldrclient: nil session")
	}
	key := actorID + "/" + register

	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return ErrEpochsUncertain
	}
	if c.registersUncertain {
		c.mu.Unlock()
		return ErrRegisterUncertain
	}
	if c.outbox.Halted != "" || c.outbox.Suspect {
		c.mu.Unlock()
		return ErrFailClosed
	}
	if c.outbox.MustResolve {
		c.mu.Unlock()
		return ErrMustResolve
	}
	if !c.outbox.Activated {
		c.mu.Unlock()
		return ErrNotActivated
	}
	if c.credKeys == nil {
		c.mu.Unlock()
		return errors.New("ldrclient: credential keys required for register activation")
	}
	credTok := ldrrelay.CredToken(c.credKeys.CredID)
	credPrinTok := ldrcore.CredentialPrincipal(credTok)
	if c.signsNoMoreLocked(credPrinTok) {
		c.mu.Unlock()
		return ErrKeyRevoked
	}
	sessPrin := sess.Principal()
	if sessPrin.Kind != ldrcrypto.PrincipalCredential || sessPrin.CredID != c.credKeys.CredID {
		c.mu.Unlock()
		return errors.New("ldrclient: register activation session principal does not match loaded credential")
	}
	actor := c.state.Line.Actors[actorID]
	if actor == nil || !actor.Live || actor.Cred != credTok {
		c.mu.Unlock()
		return fmt.Errorf("ldrclient: actor %q is not live and bound to this credential", actorID)
	}
	cw := c.state.Line.RegisterWriters[key]
	lw := c.registers.Writers[key]
	if cw != nil && cw.BindingGen == actor.BindingGen &&
		lw != nil && lw.TrustedCounter &&
		lw.BindingGen == uint64(actor.BindingGen) &&
		lw.WriterRev == uint64(cw.WriterRev) &&
		lw.Incarnation == cw.Incarnation {
		c.mu.Unlock()
		return nil
	}
	expectRev := uint64(0)
	if cw != nil {
		expectRev = uint64(cw.WriterRev)
	}
	c.mu.Unlock()

	incarnation, err := randomIncarnationID()
	if err != nil {
		return err
	}
	opID, err := c.ComposeAndPersist(ComposeParams{
		Action: "register_activate:" + key,
		Origin: ldrcore.OriginCredential,
		OpType: "register_activate",
		Expect: ldrcrypto.ExpectMap{"writer_rev": expectRev},
		Fields: ldrcrypto.Map{
			{Key: "actor_id", Value: actorID},
			{Key: "incarnation", Value: incarnation},
			{Key: "register", Value: register},
		},
	})
	if err != nil {
		return err
	}
	rep, err := c.Send(ctx, sess, opID)
	if err != nil {
		return err
	}
	if rep.Class != ldrcore.ClassOutcome || rep.Outcome.Kind != ldrcore.Committed {
		return fmt.Errorf("ldrclient: register_activate not committed: class=%s code=%s kind=%s reason=%s",
			rep.Class, rep.Code, rep.Outcome.Kind, rep.Outcome.Reason)
	}
	if _, err := c.Sync(ctx, sess); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	actor = c.state.Line.Actors[actorID]
	cw = c.state.Line.RegisterWriters[key]
	if actor == nil || !actor.Live || actor.Cred != credTok || cw == nil ||
		cw.BindingGen != actor.BindingGen || cw.Incarnation != incarnation {
		return fmt.Errorf("ldrclient: register_activate for %s did not commit expected incarnation", key)
	}
	cand := clonePersistedRegisters(c.registers)
	cand.Writers[key] = &persistedRegisterWriter{
		Actor:          actorID,
		Register:       register,
		BindingGen:     uint64(actor.BindingGen),
		WriterRev:      uint64(cw.WriterRev),
		Incarnation:    incarnation,
		NextCounter:    1,
		TrustedCounter: true,
	}
	if err := c.persistRegistersLocked(cand); err != nil {
		c.markRegistersUncertainOnErrLocked(err)
		return err
	}
	c.registers = cand
	return nil
}

// PublishRegister encrypts plaintext under the active key epoch, signs a §9
// advisory register envelope with a durably advanced monotonic counter, and
// publishes it to the relay. Enforces local Rule 8 stops before signing/sending
// and durably persists Rule 8 terminal evidence on a validated unresolved/revoked reply.
func (c *Client) PublishRegister(ctx context.Context, sess *ldrrelay.SessionClient, actorID, register string, plaintext []byte) (ldrrelay.RegisterPutReply, error) {
	if !ldrcrypto.ValidRegisterType(register) || actorID == "" {
		return ldrrelay.RegisterPutReply{}, fmt.Errorf("ldrclient: invalid actor %q or register %q", actorID, register)
	}
	if sess == nil {
		return ldrrelay.RegisterPutReply{}, errors.New("ldrclient: nil session")
	}
	key := actorID + "/" + register

	for attempt := 0; attempt < 2; attempt++ {
		if err := c.EnsureRegisterActivated(ctx, sess, actorID, register); err != nil {
			return ldrrelay.RegisterPutReply{}, err
		}

		c.mu.Lock()
		if c.outboxUncertain {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrOutboxUncertain
		}
		if c.epochsUncertain {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrEpochsUncertain
		}
		if c.registersUncertain {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrRegisterUncertain
		}
		if c.outbox.Halted != "" || c.outbox.Suspect {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrFailClosed
		}
		if !c.outbox.Activated {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrNotActivated
		}
		if c.credKeys == nil {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, errors.New("ldrclient: credential keys required for register publish")
		}
		credPrinTok := ldrcore.CredentialPrincipal(ldrrelay.CredToken(c.credKeys.CredID))
		if c.signsNoMoreLocked(credPrinTok) {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrKeyRevoked
		}
		sessPrin := sess.Principal()
		if sessPrin.Kind != ldrcrypto.PrincipalCredential || sessPrin.CredID != c.credKeys.CredID {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, errors.New("ldrclient: register publish session principal does not match loaded credential")
		}
		if c.state.Line.RekeyPending {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, fmt.Errorf("%w: %s", ErrRegisterRejected, ldrcore.RegRekeyPending)
		}
		keyEpoch := uint64(c.state.Line.KeyEpoch)
		epKey, ok := c.epochs.Keys[keyEpoch]
		if !ok || keyEpoch == 0 {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, ErrNoEpochKey
		}
		lw := c.registers.Writers[key]
		if lw == nil || !lw.TrustedCounter {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, errors.New("ldrclient: untrusted register counter after activation")
		}
		counter := lw.NextCounter
		if counter > ldrcrypto.MaxCounter {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, errors.New("ldrclient: register counter exhausted")
		}

		ctxBytes, err := ldrcrypto.RegisterPayloadContextBytes(
			c.profDigest, c.cfg.LineID, c.ckGen, register, actorID,
			c.credKeys.CredID, lw.BindingGen, lw.WriterRev, lw.Incarnation, keyEpoch, counter,
		)
		if err != nil {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, err
		}
		pkg, err := ldrcrypto.SealPayload(epKey, ctxBytes, plaintext)
		if err != nil {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, err
		}
		if len(pkg) > ldrcrypto.MaxRegisterBodyBytes {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, fmt.Errorf("ldrclient: encrypted register body %d exceeds %d", len(pkg), ldrcrypto.MaxRegisterBodyBytes)
		}
		commit, err := ldrcrypto.CommitPayload(pkg)
		if err != nil {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, err
		}
		envBytes, err := ldrcrypto.SignRegisterEnvelope(c.credKeys.Signing.Signer, ldrcrypto.RegisterEnvelope{
			Version:       1,
			LineID:        c.cfg.LineID,
			Generation:    c.ckGen,
			ProfileDigest: c.profDigest,
			Register:      register,
			ActorID:       actorID,
			CredID:        c.credKeys.CredID,
			BindingGen:    lw.BindingGen,
			WriterRev:     lw.WriterRev,
			Incarnation:   lw.Incarnation,
			KeyEpoch:      keyEpoch,
			Counter:       counter,
			PayloadCommit: commit,
		})
		if err != nil {
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, err
		}

		// Persist incremented counter BEFORE network publication so a crash
		// never reuses a counter under the same incarnation (§9).
		cand := clonePersistedRegisters(c.registers)
		cand.Writers[key].NextCounter = counter + 1
		if err := c.persistRegistersLocked(cand); err != nil {
			c.markRegistersUncertainOnErrLocked(err)
			c.mu.Unlock()
			return ldrrelay.RegisterPutReply{}, err
		}
		c.registers = cand
		c.mu.Unlock()

		rep, err := sess.PutRegister(ctx, envBytes, pkg)
		if err != nil {
			return rep, err
		}
		if rep.Class == "ok" {
			return rep, nil
		}
		if rep.Class == ldrcore.ClassUnresolved && rep.Code == "revoked" {
			// Reply binding was verified on the pinned TLS 1.3 session for
			// credPrinTok; persist Rule 8 terminal stop before returning.
			c.mu.Lock()
			perr := c.recordValidatedRevokedStopLocked(credPrinTok, rep.Code)
			c.mu.Unlock()
			if perr != nil {
				return rep, perr
			}
			return rep, ErrKeyRevoked
		}
		if attempt == 0 && (rep.Code == ldrcore.RegStaleWriter || rep.Code == ldrcore.RegNoActivation ||
			rep.Code == ldrcore.RegWrongIncarnation || rep.Code == ldrcore.RegStaleCounter) {
			if _, serr := c.Sync(ctx, sess); serr != nil {
				return rep, serr
			}
			c.mu.Lock()
			if c.registers.Writers[key] != nil {
				cand := clonePersistedRegisters(c.registers)
				cand.Writers[key].TrustedCounter = false
				if perr := c.persistRegistersLocked(cand); perr != nil {
					c.markRegistersUncertainOnErrLocked(perr)
					c.mu.Unlock()
					return rep, perr
				}
				c.registers = cand
			}
			c.mu.Unlock()
			continue
		}
		return rep, fmt.Errorf("%w: %s (%s)", ErrRegisterRejected, rep.Code, rep.Class)
	}
	return ldrrelay.RegisterPutReply{}, ErrRegisterRejected
}

// ReadRegisters fetches advisory registers from the relay across bounded pages,
// enforces local Rule 8 stop checks on the session principal, cryptographically
// verifies every envelope signature, payload commitment, and committed writer
// incarnation/binding against local verified.wal state, computes Historical
// locally per §9, and decrypts bodies using locally unwrapped epoch keys.
func (c *Client) ReadRegisters(ctx context.Context, sess *ldrrelay.SessionClient, registerFilter string) ([]VerifiedRegister, error) {
	if registerFilter != "" && !ldrcrypto.ValidRegisterType(registerFilter) {
		return nil, fmt.Errorf("ldrclient: unknown register %q", registerFilter)
	}
	if sess == nil {
		return nil, errors.New("ldrclient: nil session")
	}
	sessPrinTok, err := ldrrelay.PrincipalToken(sess.Principal())
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return nil, ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return nil, ErrEpochsUncertain
	}
	if c.outbox.Halted != "" {
		reason := c.outbox.Halted
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrViolation, reason)
	}
	if c.signsNoMoreLocked(sessPrinTok) {
		c.mu.Unlock()
		return nil, ErrKeyRevoked
	}
	c.mu.Unlock()

	entries, err := sess.ListRegisters(ctx, registerFilter)
	if err != nil {
		var authErr *ldrrelay.AuthError
		if errors.As(err, &authErr) && authErr.Class == ldrcore.ClassUnresolved && authErr.Code == "revoked" {
			c.mu.Lock()
			perr := c.recordValidatedRevokedStopLocked(sessPrinTok, authErr.Code)
			c.mu.Unlock()
			if perr != nil {
				return nil, perr
			}
			return nil, ErrKeyRevoked
		}
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain {
		return nil, ErrOutboxUncertain
	}
	if c.epochsUncertain {
		return nil, ErrEpochsUncertain
	}
	if c.outbox.Halted != "" {
		return nil, fmt.Errorf("%w: %s", ErrViolation, c.outbox.Halted)
	}

	out := make([]VerifiedRegister, 0, len(entries))
	for _, ent := range entries {
		env, bodyBytes, err := ldrcrypto.ParseRegisterEnvelope(ent.EnvBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid register envelope: %v", ErrViolation, err)
		}
		if ent.Actor != env.ActorID || ent.Register != env.Register {
			return nil, fmt.Errorf("%w: register outer metadata disagrees with signed envelope", ErrViolation)
		}
		if registerFilter != "" && env.Register != registerFilter {
			return nil, fmt.Errorf("%w: relay returned unfiltered register %q", ErrViolation, env.Register)
		}
		if !bytes.Equal(env.LineID, c.cfg.LineID) || env.Generation != c.ckGen || env.ProfileDigest != c.profDigest {
			return nil, fmt.Errorf("%w: register envelope line/gen/profile mismatch", ErrViolation)
		}
		if err := ldrcrypto.VerifyPayloadSidecar(env.PayloadCommit, ent.Payload); err != nil {
			return nil, fmt.Errorf("%w: register payload commitment mismatch: %v", ErrViolation, err)
		}
		credTok := ldrrelay.CredToken(env.CredID)
		cred := c.state.Line.Credentials[credTok]
		if cred == nil {
			return nil, fmt.Errorf("%w: register credential %s unknown in local verified log", ErrViolation, credTok)
		}
		pub, err := ldrrelay.ParseKeyToken(cred.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid credential signing key in verified log: %v", ErrViolation, err)
		}
		if err := ldrcrypto.VerifyDomain(pub, ldrcrypto.PurposeRegister, 1, bodyBytes, env.Sig); err != nil {
			return nil, fmt.Errorf("%w: register envelope signature invalid: %v", ErrViolation, err)
		}

		// Verify exact committed activation tuple (writer_rev, incarnation,
		// binding_gen, owning credential) against verified.wal history for
		// BOTH current and superseded revisions (§9).
		rkey := env.ActorID + "/" + env.Register
		actor := c.state.Line.Actors[env.ActorID]
		w := c.state.Line.RegisterWriters[rkey]
		act, ok := c.regActivations[rkey][env.WriterRev]
		if !ok {
			return nil, fmt.Errorf("%w: register writer_rev %d was never committed for %s", ErrViolation, env.WriterRev, rkey)
		}
		if env.Incarnation != act.Incarnation || env.BindingGen != act.BindingGen || credTok != act.Cred {
			return nil, fmt.Errorf("%w: register writer_rev %d contradicts committed activation (incarnation/binding_gen/cred) for %s", ErrViolation, env.WriterRev, rkey)
		}

		// Compute Historical locally against verified.wal state (§9); never trust relay boolean.
		historical := cred.Revoked ||
			actor == nil || !actor.Live ||
			actor.Cred != credTok ||
			uint64(actor.BindingGen) != env.BindingGen ||
			w == nil ||
			w.BindingGen != actor.BindingGen ||
			uint64(w.WriterRev) != env.WriterRev ||
			w.Incarnation != env.Incarnation

		vr := VerifiedRegister{
			Actor:        env.ActorID,
			Register:     env.Register,
			CredID:       env.CredID,
			BindingGen:   env.BindingGen,
			WriterRev:    env.WriterRev,
			Incarnation:  env.Incarnation,
			KeyEpoch:     env.KeyEpoch,
			Counter:      env.Counter,
			AcceptedAtMS: ent.AcceptedAtMS,
			Historical:   historical,
		}
		epKey, hasKey := c.epochs.Keys[env.KeyEpoch]
		if !hasKey {
			vr.ReadStatus = ldrcore.ReadNoKey
		} else {
			ctxBytes, err := ldrcrypto.RegisterPayloadContextBytes(
				c.profDigest, c.cfg.LineID, env.Generation, env.Register, env.ActorID,
				env.CredID, env.BindingGen, env.WriterRev, env.Incarnation, env.KeyEpoch, env.Counter,
			)
			if err != nil {
				vr.ReadStatus = ldrcore.ReadUndecryptable
			} else if plain, err := ldrcrypto.OpenPayload(epKey, ctxBytes, ent.Payload); err != nil {
				vr.ReadStatus = ldrcore.ReadUndecryptable
			} else {
				vr.ReadStatus = ldrcore.ReadOK
				vr.Plaintext = plain
			}
		}
		out = append(out, vr)
	}
	return out, nil
}
