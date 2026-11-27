package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
)

// LDRAttachment links a local Yip line (~/.yip/lines/<id>) to an enrolled
// ldrclient directory. Host-local resource leases and delivery endpoints stay
// in the local line directory; calls, broadcasts, disputes, presence, and
// roadmaps route through the verified encrypted LDR client.
type LDRAttachment struct {
	Version   int               `json:"version"`
	ClientDir string            `json:"client_dir"`
	Actors    map[string]string `json:"actors,omitempty"` // local agent name -> LDR actor_id
}

func bdMatchesLDRRoute(bd Binding, att LDRAttachment) bool {
	if strings.TrimSpace(bd.LDRActor) == "" {
		return false
	}
	if strings.TrimSpace(bd.LDRClientDir) == "" || strings.TrimSpace(att.ClientDir) == "" {
		return false
	}
	return sameDir(bd.LDRClientDir, att.ClientDir)
}

func (a LDRAttachment) rawActorFor(localName string) string {
	if a.Actors != nil {
		if mapped := strings.TrimSpace(a.Actors[localName]); mapped != "" {
			return mapped
		}
	}
	return localName
}

func (a LDRAttachment) actorFor(localName string) string {
	if a.Actors != nil {
		if mapped := strings.TrimSpace(a.Actors[localName]); mapped != "" {
			return mapped
		}
	}
	if bd, ok, _ := liveBinding(localName); ok && bdMatchesLDRRoute(bd, a) {
		return strings.TrimSpace(bd.LDRActor)
	}
	return localName
}

func ldrAttachmentPath() string { return filepath.Join(Root(), "ldr.json") }
func ldrCursorsPath() string    { return filepath.Join(Root(), "ldr-cursors.json") }

var ldrAckTimeout = 5 * time.Second

// loadLDRAttachment distinguishes three states:
//   - (att, true, nil):  valid LDR attachment active (from ldr.json or YIP_LDR_DIR)
//   - (zero, false, nil): genuinely unattached local-only line (ldr.json absent & YIP_LDR_DIR empty)
//   - (zero, true, err): ldr.json exists or cannot be stat/read, or is malformed/unsupported
//
// Callers MUST NOT fall back to YIP_LDR_DIR or local-only writes when err != nil.
func loadLDRAttachment() (LDRAttachment, bool, error) {
	return readLDRAttachment(ldrAttachmentPath(), strings.TrimSpace(os.Getenv("YIP_LDR_DIR")))
}

func readLDRAttachment(p, envDir string) (LDRAttachment, bool, error) {
	b, err := os.ReadFile(p)
	if err == nil {
		var att LDRAttachment
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&att); derr != nil {
			return LDRAttachment{}, true, fmt.Errorf("invalid LDR attachment %s: %w", p, derr)
		}
		if derr := dec.Decode(new(any)); derr != io.EOF {
			return LDRAttachment{}, true, fmt.Errorf("invalid LDR attachment %s: trailing data", p)
		}
		if att.Version != 1 {
			return LDRAttachment{}, true, fmt.Errorf("unsupported LDR attachment %s version %d (want 1)", p, att.Version)
		}
		if strings.TrimSpace(att.ClientDir) == "" {
			return LDRAttachment{}, true, fmt.Errorf("invalid LDR attachment %s: empty client_dir", p)
		}
		if att.Actors == nil {
			att.Actors = map[string]string{}
		}
		return att, true, nil
	}
	if !os.IsNotExist(err) {
		return LDRAttachment{}, true, fmt.Errorf("cannot read LDR attachment %s: %w", p, err)
	}
	if envDir != "" {
		return LDRAttachment{Version: 1, ClientDir: envDir, Actors: map[string]string{}}, true, nil
	}
	return LDRAttachment{}, false, nil
}

func validateLDRClientAndActor(cl *ldrclient.Client, dir, localAs, effActor string) (ldrclient.ClientStatus, map[string]bool, error) {
	st := cl.Status()
	if st.CredID == "" {
		return st, nil, fmt.Errorf("cannot attach LDR directory %s: no credential keys loaded (enroll a workstation or reader credential first)", dir)
	}
	if !st.Activated {
		return st, nil, fmt.Errorf("cannot attach LDR directory %s: credential %s is not activated (complete enrollment and run `yip ldr join activate` first)", dir, st.CredID)
	}
	if st.Suspect || st.Halted != "" {
		return st, nil, fmt.Errorf("cannot attach halted or suspect LDR directory %s", dir)
	}
	if st.OutboxUncertain || st.EpochsUncertain || st.CursorsUncertain {
		return st, nil, fmt.Errorf("cannot attach LDR directory %s with uncertain local durability state", dir)
	}
	if slices.Contains(st.StoppedKeys, "cred:"+st.CredID) {
		return st, nil, fmt.Errorf("cannot attach LDR directory %s: credential %s is revoked or stopped", dir, st.CredID)
	}
	liveCredActors := map[string]bool{}
	foreignActors := map[string]string{}
	for _, a := range cl.ListActors() {
		if !a.Live {
			continue
		}
		if a.Cred == st.CredID {
			liveCredActors[a.ID] = true
		} else {
			foreignActors[a.ID] = a.Cred
		}
	}
	if localAs != "" && !liveCredActors[effActor] {
		if ownerCred, foreign := foreignActors[effActor]; foreign {
			return st, nil, fmt.Errorf("cannot map local seat %q to LDR actor %q: actor belongs to credential %s, not %s in %s", localAs, effActor, ownerCred, st.CredID, dir)
		}
		return st, nil, fmt.Errorf("cannot map local seat %q to LDR actor %q: actor is not declared as a live actor for credential %s in %s (run `yip ldr sync` and `yip ldr actor declare` first)", localAs, effActor, st.CredID, dir)
	}
	return st, liveCredActors, nil
}

type preparedLDRAttach struct {
	att LDRAttachment
}

func openAndValidateLDRAttach(clientDir, localAs, actorID string) (string, string, string, map[string]bool, error) {
	clientDir = strings.TrimSpace(clientDir)
	localAs = strings.TrimSpace(localAs)
	actorID = strings.TrimSpace(actorID)
	if clientDir == "" {
		return "", "", "", nil, errors.New("ldr attach requires --dir <client-dir>")
	}
	if actorID != "" && localAs == "" {
		return "", "", "", nil, fmt.Errorf("ldr attach --actor %q requires --as <local-agent> to identify the local seat", actorID)
	}
	if localAs != "" && !validComponent(localAs) {
		return "", "", "", nil, fmt.Errorf("invalid local agent name %q", localAs)
	}
	absDir, err := filepath.Abs(clientDir)
	if err != nil {
		return "", "", "", nil, err
	}
	effActor := actorID
	if effActor == "" {
		effActor = localAs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := ldrclient.OpenClientWait(ctx, absDir)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("cannot open LDR client dir %s: %w", absDir, err)
	}
	_, liveCredActors, verr := validateLDRClientAndActor(cl, absDir, localAs, effActor)
	_ = cl.Close()
	if verr != nil {
		return "", "", "", nil, verr
	}
	return absDir, localAs, actorID, liveCredActors, nil
}

// preflightLDRAttachLocked validates clientDir, actor ownership, and existing
// ldr.json state while fileGuard(membersPath()) is already held, before install
// writes any checkout or line files.
func preflightLDRAttachLocked(clientDir, localAs, actorID string) (*preparedLDRAttach, error) {
	absDir, localAs, actorID, liveCredActors, err := openAndValidateLDRAttach(clientDir, localAs, actorID)
	if err != nil {
		return nil, err
	}
	return buildLDRAttachLocked(absDir, localAs, actorID, liveCredActors)
}

func buildLDRAttachLocked(absDir, localAs, actorID string, liveCredActors map[string]bool) (*preparedLDRAttach, error) {
	effActor := actorID
	if effActor == "" {
		effActor = localAs
	}
	prev, prevOk, err := readLDRAttachment(ldrAttachmentPath(), "")
	if err != nil {
		return nil, fmt.Errorf("existing LDR attachment is invalid (fix or run `yip ldr detach` first): %w", err)
	}
	actors := map[string]string{}
	if prevOk && sameDir(prev.ClientDir, absDir) {
		for seat, mapped := range prev.Actors {
			if liveCredActors[mapped] {
				actors[seat] = mapped
			}
		}
	}
	if localAs != "" {
		for otherSeat, otherActor := range actors {
			if otherSeat != localAs && otherActor == effActor {
				return nil, fmt.Errorf("cannot map local seat %q to LDR actor %q: local seat %q on line %s already maps to %q", localAs, effActor, otherSeat, activeLine, effActor)
			}
		}
		if actorID != "" {
			actors[localAs] = actorID
		} else {
			delete(actors, localAs)
		}
	}
	return &preparedLDRAttach{
		att: LDRAttachment{
			Version:   1,
			ClientDir: absDir,
			Actors:    actors,
		},
	}, nil
}

func commitLDRAttachLocked(p *preparedLDRAttach) (LDRAttachment, error) {
	if err := writeState(ldrAttachmentPath(), p.att); err != nil {
		return LDRAttachment{}, err
	}
	return p.att, nil
}

// AttachLDRLine validates clientDir and records the attachment in the active local line,
// serialized under the line's membership transaction lock.
func AttachLDRLine(clientDir, localAs, actorID string) (LDRAttachment, error) {
	absDir, localAs, actorID, liveCredActors, err := openAndValidateLDRAttach(clientDir, localAs, actorID)
	if err != nil {
		return LDRAttachment{}, err
	}
	if err := EnsureRoot(); err != nil {
		return LDRAttachment{}, err
	}
	unlock, err := fileGuard(membersPath())
	if err != nil {
		return LDRAttachment{}, err
	}
	defer unlock()
	prep, err := buildLDRAttachLocked(absDir, localAs, actorID, liveCredActors)
	if err != nil {
		return LDRAttachment{}, err
	}
	return commitLDRAttachLocked(prep)
}

// DetachLDRLine removes ldr.json from the active local line without touching the LDR client directory,
// serialized under the line's membership transaction lock.
func DetachLDRLine() error {
	if _, err := os.Stat(Root()); os.IsNotExist(err) {
		return nil
	}
	unlock, err := fileGuard(membersPath())
	if err != nil {
		return err
	}
	defer unlock()
	err = os.Remove(ldrAttachmentPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func ldrAttachCLI(rest []string, out io.Writer) error {
	var dir, localAs, actorID string
	rest, dir = takeFlag(rest, "--dir", "")
	rest, localAs = takeFlag(rest, "--as", "")
	rest, actorID = takeFlag(rest, "--actor", "")
	if strings.TrimSpace(dir) == "" || len(rest) != 0 {
		return errors.New("usage: yip ldr attach --dir <client-dir> [--line <line>] [--as <local-agent>] [--actor <ldr-actor>]")
	}
	att, err := AttachLDRLine(dir, localAs, actorID)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"line":       activeLine,
		"line_dir":   Root(),
		"attachment": att,
	})
}

func ldrDetachCLI(rest []string, out io.Writer) error {
	if len(rest) != 0 {
		return errors.New("usage: yip [--line <line>] ldr detach")
	}
	if err := DetachLDRLine(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"line":     activeLine,
		"detached": true,
	})
}

// pruneLDRActors is called from uninstallLocked while fileGuard(membersPath()) is held.
func pruneLDRActors(names ...string) {
	if len(names) == 0 {
		return
	}
	att, ok, err := readLDRAttachment(ldrAttachmentPath(), "")
	if !ok || err != nil || len(att.Actors) == 0 {
		return
	}
	changed := false
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, exists := att.Actors[n]; exists {
			delete(att.Actors, n)
			changed = true
		}
	}
	if !changed {
		return
	}
	_ = writeState(ldrAttachmentPath(), att)
}

func prepareLDRBind(launch, name, as string, session procID, convID string, b Bindings) (string, string, string, string, error) {
	att, ok, err := loadLDRAttachment()
	if err != nil {
		return "", "", "", "", err
	}
	if !ok {
		return "", "", "", "", nil
	}
	absDir, err := filepath.Abs(att.ClientDir)
	if err != nil {
		return "", "", "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, err := ldrclient.OpenClientWait(ctx, absDir)
	if err != nil {
		return "", "", "", "", fmt.Errorf("cannot open LDR client dir %s for bind: %w", absDir, err)
	}
	st, liveCredActors, verr := validateLDRClientAndActor(cl, absDir, "", "")
	_ = cl.Close()
	if verr != nil {
		return "", "", "", "", verr
	}

	var targetActor, note string
	if name == launch {
		targetActor = att.rawActorFor(launch)
		if !liveCredActors[targetActor] {
			return "", "", "", "", fmt.Errorf("launch seat %q maps to LDR actor %q, which is not a live actor of credential %s in %s", launch, targetActor, st.CredID, absDir)
		}
	} else {
		if mapped := strings.TrimSpace(att.Actors[name]); mapped != "" {
			if !liveCredActors[mapped] {
				return "", "", "", "", fmt.Errorf("mapped LDR actor %q for %q is not a live actor of credential %s in %s", mapped, name, st.CredID, absDir)
			}
			targetActor = mapped
		} else if liveCredActors[name] {
			targetActor = name
		} else if strings.TrimSpace(as) != "" {
			return "", "", "", "", fmt.Errorf("cannot bind worktree as %q on LDR line %s: %q is not a live actor of credential %s in %s (declare it with `yip ldr actor declare` or map it with `yip ldr attach` first)", name, activeLine, name, st.CredID, absDir)
		} else {
			launchActor := att.rawActorFor(launch)
			if !liveCredActors[launchActor] {
				return "", "", "", "", fmt.Errorf("cannot bind worktree %q on LDR line %s: neither %q nor launch seat %q maps to a live actor of credential %s in %s", name, activeLine, name, launch, st.CredID, absDir)
			}
			if other, inUse, aerr := answeringTo(launch, session, b); aerr != nil {
				return "", "", "", "", fmt.Errorf("cannot tell who answers to %s: %w", launch, aerr)
			} else if inUse {
				return "", "", "", "", fmt.Errorf("cannot bind worktree %q on LDR line %s: launch actor %q (%s) is already in use by live session pid %d; declare a separate actor with `yip ldr actor declare` and pass as", name, activeLine, launchActor, launch, other.PID)
			}
			targetActor = launchActor
			note = fmt.Sprintf("LDR relay actor remains %q (from %s).", targetActor, launch)
		}
	}

	for otherName, bd := range b.Bindings {
		if sameBindingOwner(bd, session, convID) || !procAlive(bd.Session) {
			continue
		}
		var bdActor string
		if mapped := strings.TrimSpace(att.Actors[otherName]); mapped != "" {
			bdActor = mapped
		} else if bdMatchesLDRRoute(bd, att) && bd.LDRCredID == st.CredID {
			bdActor = strings.TrimSpace(bd.LDRActor)
		} else if strings.TrimSpace(bd.LDRClientDir) == "" && strings.TrimSpace(bd.LDRActor) != "" {
			bdActor = strings.TrimSpace(bd.LDRActor)
		} else {
			continue
		}
		if bdActor == targetActor {
			return "", "", "", "", fmt.Errorf("cannot bind %q on LDR line %s: relay actor %q is already bound to %q by live session pid %d; two sessions cannot share one relay actor", name, activeLine, targetActor, otherName, bd.Session.PID)
		}
	}
	if name == launch {
		return "", "", "", "", nil
	}
	return absDir, st.CredID, targetActor, note, nil
}

func resolveSessionLDRActor(att LDRAttachment, me string) (string, error) {
	bd, bound, err := liveBinding(me)
	if err != nil {
		return "", err
	}
	var actor string
	switch {
	case strings.TrimSpace(att.Actors[me]) != "":
		actor = strings.TrimSpace(att.Actors[me])
	case bound && bdMatchesLDRRoute(bd, att):
		actor = strings.TrimSpace(bd.LDRActor)
	case bound && strings.TrimSpace(bd.LDRClientDir) != "" && !sameDir(bd.LDRClientDir, att.ClientDir):
		return "", fmt.Errorf("worktree %q was bound under previous LDR client %s; call bind again for current LDR client %s", me, bd.LDRClientDir, att.ClientDir)
	default:
		actor = att.rawActorFor(me)
	}
	if !bound {
		if _, serr := os.Stat(bindingsPath()); serr == nil {
			b, lerr := loadBindingsStrict()
			if lerr != nil {
				return "", lerr
			}
			curConv := envConvID()
			curSess, inSess := nearestSession()
			for otherName, otherBD := range b.Bindings {
				if otherName == me || !procAlive(otherBD.Session) {
					continue
				}
				var otherActor string
				if mapped := strings.TrimSpace(att.Actors[otherName]); mapped != "" {
					otherActor = mapped
				} else if bdMatchesLDRRoute(otherBD, att) {
					otherActor = strings.TrimSpace(otherBD.LDRActor)
				} else {
					continue
				}
				if otherActor != actor {
					continue
				}
				if (curConv != "" && curConv != otherBD.ConvID) || (inSess && curSess != otherBD.Session) {
					return "", fmt.Errorf("LDR relay actor %q (from %s) is currently bound to worktree %s (%s) by live session pid %d; declare and bind a distinct relay actor", actor, me, otherBD.Worktree, otherName, otherBD.Session.PID)
				}
			}
		}
	}
	return actor, nil
}

func actorMovedToBoundWorktree(att LDRAttachment, localAgent string) bool {
	if _, bound, err := liveBinding(localAgent); err != nil || bound {
		return false
	}
	if _, err := os.Stat(bindingsPath()); os.IsNotExist(err) {
		return false
	}
	b, err := loadBindingsStrict()
	if err != nil {
		return false
	}
	myActor := att.rawActorFor(localAgent)
	for otherName, bd := range b.Bindings {
		if otherName == localAgent || !procAlive(bd.Session) {
			continue
		}
		var otherActor string
		if mapped := strings.TrimSpace(att.Actors[otherName]); mapped != "" {
			otherActor = mapped
		} else if bdMatchesLDRRoute(bd, att) {
			otherActor = strings.TrimSpace(bd.LDRActor)
		} else {
			continue
		}
		if otherActor == myActor {
			return true
		}
	}
	return false
}

// --- Local seen/hook cursor bookkeeping (outside authoritative LDR verified state) ---

type ldrCallCursor struct {
	SeenTurns   int `json:"seen_turns"`
	SeenNotes   int `json:"seen_notes"`
	NotifiedRev int `json:"notified_rev"`
	BlockedRev  int `json:"blocked_rev"`
}

type ldrLocalCursors struct {
	Version int                                 `json:"version"`
	Agents  map[string]map[string]ldrCallCursor `json:"agents"` // agent -> callID -> cursor
}

func loadLDRCursor(agent, callID string) ldrCallCursor {
	var st ldrLocalCursors
	if err := readState(ldrCursorsPath(), &st); err != nil || st.Agents == nil {
		return ldrCallCursor{}
	}
	return st.Agents[agent][callID]
}

func updateLDRCursor(agent, callID string, fn func(*ldrCallCursor)) error {
	return updateJSON(ldrCursorsPath(), func(st *ldrLocalCursors) error {
		st.Version = 1
		if st.Agents == nil {
			st.Agents = map[string]map[string]ldrCallCursor{}
		}
		if st.Agents[agent] == nil {
			st.Agents[agent] = map[string]ldrCallCursor{}
		}
		cur := st.Agents[agent][callID]
		fn(&cur)
		st.Agents[agent][callID] = cur
		return nil
	})
}

// --- LDR Client Session Helpers ---

func withLDRSession(ctx context.Context, att LDRAttachment, fn func(*ldrclient.Client, *ldrrelay.SessionClient) error) error {
	cl, err := ldrclient.OpenClientWait(ctx, att.ClientDir)
	if err != nil {
		return err
	}
	defer cl.Close()
	sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		return err
	}
	defer sess.Close()
	return fn(cl, sess)
}

type ldrPresencePayload struct {
	Tip      string `json:"tip,omitempty"`
	Branch   string `json:"branch,omitempty"`
	Busy     string `json:"busy,omitempty"`
	Pids     []int  `json:"pids,omitempty"`
	LastTool string `json:"last_tool,omitempty"`
	At       string `json:"at"`
}

type ldrRoadmapPayload struct {
	Cleared bool     `json:"cleared,omitempty"`
	Roadmap *Roadmap `json:"roadmap,omitempty"`
}

func ldrPublishPresence(ctx context.Context, cl *ldrclient.Client, sess *ldrrelay.SessionClient, localAgent, actor, lastTool string) error {
	p, _ := LoadPresence(localAgent)
	tip := p.Tip
	branch := p.Branch
	if tip == "" {
		if sha, br := stampTip(localAgent); sha != "" {
			tip, branch = sha, br
		}
	}
	payload := ldrPresencePayload{
		Tip:      tip,
		Branch:   branch,
		Busy:     p.Busy,
		Pids:     p.Pids,
		LastTool: lastTool,
		At:       now(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = cl.PublishRegister(ctx, sess, actor, "presence", b)
	return err
}

// --- MCP & API Tool Dispatch when LDR Attached ---

// ldrToolCall intercepts Yip MCP / API tools when the active local line is
// attached to an LDR client directory (or has a malformed/unreadable ldr.json).
// Host-local resource leases, local bind, and local delivery endpoint tools
// ALWAYS return handled=false BEFORE consulting ldr.json so host-local leases
// remain usable even if ldr.json is broken.
func ldrToolCall(me, name string, a map[string]any) (string, bool, error) {
	// Host-local invariant: resource leases, local session bindings, and local
	// delivery endpoints are NEVER routed to the remote relay.
	switch name {
	case "resources", "hold", "release", "steal", "request", "cancel_request", "queue_history", "lease_update",
		"bind", "channel_ack", "deliveries", "delivery_ack":
		return "", false, nil
	}
	att, ok, err := loadLDRAttachment()
	if err != nil {
		return "", true, err
	}
	if !ok {
		return "", false, nil
	}

	actor, err := resolveSessionLDRActor(att, me)
	if err != nil {
		return "", true, err
	}
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()

	switch name {
	case "call":
		peer := argStr(a, "peer")
		subject := argStr(a, "subject")
		if peer == "" || subject == "" {
			return "", true, fmt.Errorf("peer and subject are required")
		}
		peerActor := att.actorFor(peer)
		if peerActor == actor {
			return "", true, fmt.Errorf("you are %s -- cannot call yourself", actor)
		}
		text, err := body(a)
		if err != nil {
			return "", true, err
		}
		tip, _ := stampTip(me)
		var callID string
		var res ldrclient.OpCommitResult
		err = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			callID = cl.NextCallID(subject)
			var serr error
			res, serr = cl.SubmitCallOpen(ctx, sess, actor, peerActor, callID, subject, text, tip, "")
			return serr
		})
		if err != nil {
			return "", true, err
		}
		_ = updateLDRCursor(me, callID, func(c *ldrCallCursor) { c.SeenTurns = max(c.SeenTurns, 1) })
		return fmt.Sprintf("call %s opened on LDR relay (seq %d), turn 1 sent (%d bytes).\nFloor is now %s's; use wait to block for the reply.",
			callID, res.Seq, len(text), peerActor), true, nil

	case "say":
		text, err := body(a)
		if err != nil {
			return "", true, err
		}
		barge := argBool(a, "barge")
		tip, _ := stampTip(me)
		var callID, peer string
		var turnNo int
		var res ldrclient.OpCommitResult
		err = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			callID = cid
			call := cl.State().Calls[cid]
			if call.Status() != "open" {
				return fmt.Errorf("call %s is %s -- explicitly reopen it with call_status first", cid, call.Status())
			}
			if holder := call.Floor(); holder != actor && !barge {
				return fmt.Errorf("the floor is %s's -- they have not replied to turn %d yet. Use wait, or set barge if this is urgent enough to speak over them", holder, call.TurnCount)
			}
			var serr error
			res, serr = cl.SubmitCallTurn(ctx, sess, actor, cid, text, barge, tip, "")
			if serr != nil {
				return serr
			}
			after := cl.State().Calls[cid]
			turnNo = int(after.TurnCount)
			peer = after.To
			if peer == actor {
				peer = after.From
			}
			return nil
		})
		if err != nil {
			return "", true, err
		}
		_ = updateLDRCursor(me, callID, func(c *ldrCallCursor) { c.SeenTurns = max(c.SeenTurns, turnNo) })
		mark := ""
		if barge {
			mark = " (BARGE -- recorded in the transcript)"
		}
		return fmt.Sprintf("turn %d sent on %s (seq %d, %d bytes)%s. Floor is now %s's.",
			turnNo, callID, res.Seq, len(text), mark, peer), true, nil

	case "read":
		since := argInt(a, "since", 0)
		sinceNote := argInt(a, "since_note", 0)
		mySha, _ := stampTip(me)
		var tr *ldrclient.CallTranscript
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			var rerr error
			tr, rerr = cl.ReadCallTranscript(ctx, sess, cid)
			return rerr
		})
		if err != nil {
			return "", true, err
		}
		_ = updateLDRCursor(me, tr.ID, func(c *ldrCallCursor) {
			c.SeenTurns = max(c.SeenTurns, len(tr.Turns))
			c.SeenNotes = max(c.SeenNotes, len(tr.Notes))
		})
		return formatLDRTranscript(tr, actor, mySha, since, sinceNote), true, nil

	case "wait":
		timeout := time.Duration(argInt(a, "timeout_s", 60)) * time.Second
		if timeout > 600*time.Second {
			timeout = 600 * time.Second
		}
		if timeout < time.Second {
			timeout = time.Second
		}
		waitCtx, waitCancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
		defer waitCancel()

		callArg := argStr(a, "call")

		// Dial one TLS 1.3 session without holding the exclusive client-directory
		// lock across poll sleeps so co-resident peers, hooks, and delivery
		// listeners sharing att.ClientDir can acquire it freely between polls.
		dialSess := func() (*ldrrelay.SessionClient, error) {
			cl, err := ldrclient.OpenClientWait(waitCtx, att.ClientDir)
			if err != nil {
				return nil, err
			}
			defer cl.Close()
			return cl.Dial(waitCtx, ldrcrypto.PrincipalCredential)
		}
		sess, err := dialSess()
		if err != nil {
			return "", true, err
		}
		defer func() {
			if sess != nil {
				sess.Close()
			}
		}()

		syncAndInspect := func(targetCID string) (cid, status, floor, peer string, turnCount int, err error) {
			cl, err := ldrclient.OpenClientWait(waitCtx, att.ClientDir)
			if err != nil {
				return "", "", "", "", 0, err
			}
			defer cl.Close()
			if _, serr := cl.Sync(waitCtx, sess); serr != nil {
				// If the long-lived TLS session dropped, re-dial once and retry sync.
				if !errors.Is(serr, ldrclient.ErrKeyRevoked) && !errors.Is(serr, ldrclient.ErrViolation) &&
					!errors.Is(serr, ldrclient.ErrOutboxUncertain) && !errors.Is(serr, ldrclient.ErrEpochsUncertain) {
					if newSess, derr := cl.Dial(waitCtx, ldrcrypto.PrincipalCredential); derr == nil {
						sess.Close()
						sess = newSess
						_, serr = cl.Sync(waitCtx, sess)
					}
				}
				if serr != nil {
					return "", "", "", "", 0, serr
				}
			}
			if targetCID == "" {
				cid, err = cl.ResolveCallID(actor, callArg)
				if err != nil {
					return "", "", "", "", 0, err
				}
			} else {
				cid = targetCID
			}
			call := cl.State().Calls[cid]
			if call == nil {
				return cid, "", "", "", 0, nil
			}
			peer = call.To
			if peer == actor {
				peer = call.From
			}
			return cid, call.Status(), call.Floor(), peer, int(call.TurnCount), nil
		}

		cid, status, floor, peer, start, err := syncAndInspect("")
		if err != nil {
			return "", true, err
		}
		if status != "open" {
			return "not waiting: call is " + status + "; reopen explicitly to resume", true, nil
		}
		if floor == actor && start > 0 {
			return fmt.Sprintf("nothing to wait for -- the floor is already yours on %s (turn %d). Read it.", cid, start), true, nil
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			select {
			case <-waitCtx.Done():
				return "", true, waitCtx.Err()
			case <-time.After(250 * time.Millisecond):
			}
			_, curStatus, curFloor, _, curTurns, err := syncAndInspect(cid)
			if err != nil {
				return "", true, err
			}
			if curStatus == "" {
				break
			}
			if curTurns > start {
				if curFloor == actor {
					return fmt.Sprintf("%s replied -- %s is now at turn %d and the floor is yours. Read it.", peer, cid, curTurns), true, nil
				}
				return fmt.Sprintf("%s is now at turn %d (floor: %s). Read it.", cid, curTurns, curFloor), true, nil
			}
			if curStatus != "open" {
				return "call is now " + curStatus, true, nil
			}
		}
		return fmt.Sprintf("no reply within %s. %s has not sent a new turn -- check ring later.", timeout, peer), true, nil

	case "bye":
		var callID, peer, status string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			callID = cid
			if _, err := cl.SubmitCallBye(ctx, sess, actor, cid); err != nil {
				return err
			}
			call := cl.State().Calls[cid]
			status = call.Status()
			peer = call.To
			if peer == actor {
				peer = call.From
			}
			return nil
		})
		if err != nil {
			return "", true, err
		}
		if status != "open" {
			return fmt.Sprintf("both sides have said bye -- call %s is closed (%s).", callID, status), true, nil
		}
		return fmt.Sprintf("bye proposed on %s. It stays open until %s says bye too, and anything either of you says clears it.", callID, peer), true, nil

	case "note":
		text, err := body(a)
		if err != nil {
			return "", true, err
		}
		var callID, floor string
		var noteNo int
		err = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			callID = cid
			if _, err := cl.SubmitCallNote(ctx, sess, actor, cid, text); err != nil {
				return err
			}
			call := cl.State().Calls[cid]
			noteNo = int(call.NoteCount)
			floor = call.Floor()
			return nil
		})
		if err != nil {
			return "", true, err
		}
		return fmt.Sprintf("note %d left on %s (%d bytes). The floor is unchanged (%s) and no reply is owed.",
			noteNo, callID, len(text), floor), true, nil

	case "call_status":
		state := argStr(a, "state")
		reason := argStr(a, "reason")
		related := argStr(a, "related")
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			_, err = cl.SubmitCallStatus(ctx, sess, actor, cid, state, reason, related)
			return err
		})
		if err != nil {
			return "", true, err
		}
		return "call state recorded", true, nil

	case "dispute":
		claim := argStr(a, "claim")
		var out string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if claim != "" {
				if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
					return err
				}
				cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
				if err != nil {
					return err
				}
				_, dispID, err := cl.SubmitDisputeOpen(ctx, sess, actor, cid, claim)
				if err != nil {
					return err
				}
				out = fmt.Sprintf("dispute %s opened on %s.\n  %s\n\nNow BOTH sides name a measurement with measure().", dispID, cid, claim)
				return nil
			}
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			tr, err := cl.ReadCallTranscript(ctx, sess, cid)
			if err != nil {
				return err
			}
			if len(tr.Disputes) == 0 {
				out = "no disputes on " + cid
				return nil
			}
			var b strings.Builder
			for _, d := range tr.Disputes {
				st := "open"
				if d.Resolved {
					st = fmt.Sprintf("resolved (%s by %s): %s", d.ResolutionKind, d.ResolutionBy, d.ResolutionText)
				}
				fmt.Fprintf(&b, "%s  %s\n  %s\n", d.ID, d.Claim, st)
				names := make([]string, 0, len(d.Measurements))
				for k := range d.Measurements {
					names = append(names, k)
				}
				sort.Strings(names)
				for _, k := range names {
					fmt.Fprintf(&b, "    %-12s %s\n", k+":", d.Measurements[k])
				}
			}
			out = strings.TrimRight(b.String(), "\n")
			return nil
		})
		return out, true, err

	case "measure":
		cmd := strings.TrimSpace(argStr(a, "cmd"))
		if cmd == "" {
			return "", true, fmt.Errorf("give a measurement, or \"none\" if you believe none exists")
		}
		var dispID string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			dispID = argStr(a, "dispute")
			if dispID == "" {
				call := cl.State().Calls[cid]
				var open []string
				for id, d := range call.Disputes {
					if !d.Resolved {
						open = append(open, id)
					}
				}
				sort.Strings(open)
				if len(open) != 1 {
					return fmt.Errorf("specify dispute id (%d open disputes on %s)", len(open), cid)
				}
				dispID = open[0]
			}
			_, err = cl.SubmitDisputeMeasure(ctx, sess, actor, cid, dispID, cmd)
			return err
		})
		if err != nil {
			return "", true, err
		}
		return fmt.Sprintf("recorded measurement for dispute %s.", dispID), true, nil

	case "attach":
		path := argStr(a, "path")
		data, err := os.ReadFile(path)
		if err != nil {
			return "", true, err
		}
		var callID string
		var res ldrclient.OpCommitResult
		err = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			cid, err := cl.ResolveCallID(actor, argStr(a, "call"))
			if err != nil {
				return err
			}
			callID = cid
			var serr error
			res, serr = cl.SubmitCallAttach(ctx, sess, actor, cid, filepath.Base(path), data)
			return serr
		})
		if err != nil {
			return "", true, err
		}
		return fmt.Sprintf("attached %s to %s (seq %d, %d bytes encrypted snapshot).", filepath.Base(path), callID, res.Seq, len(data)), true, nil

	case "ring":
		var out string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			sums, err := cl.ListCallSummaries(ctx, sess, actor, false)
			if err != nil {
				return err
			}
			out = formatLDRRing(sums, me, actor)
			return nil
		})
		return out, true, err

	case "inbox":
		includeAll := argBool(a, "all")
		var out string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			sums, err := cl.ListCallSummaries(ctx, sess, actor, includeAll)
			if err != nil {
				return err
			}
			bvs, err := cl.ListBroadcasts(ctx, sess, actor, includeAll)
			if err != nil {
				return err
			}
			out = formatLDRInbox(sums, bvs, me, actor)
			return nil
		})
		return out, true, err

	case "broadcasts":
		includeAll := argBool(a, "all")
		var out string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			bvs, err := cl.ListBroadcasts(ctx, sess, actor, includeAll)
			if err != nil {
				return err
			}
			out = formatLDRBroadcasts(bvs)
			return nil
		})
		return out, true, err

	case "broadcast_read":
		bid := argStr(a, "id")
		if bid == "" {
			return "", true, errors.New("broadcast id required")
		}
		var bv *ldrclient.BroadcastView
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			if _, err := cl.SubmitBroadcastRead(ctx, sess, actor, bid); err != nil {
				return err
			}
			var rerr error
			bv, rerr = cl.ReadBroadcast(ctx, sess, actor, bid)
			return rerr
		})
		if err != nil {
			return "", true, err
		}
		return formatLDRBroadcastDetail(bv), true, nil

	case "broadcast_reply":
		bid := argStr(a, "id")
		bodyText := argStr(a, "body")
		if bid == "" || strings.TrimSpace(bodyText) == "" {
			return "", true, errors.New("broadcast id and body required")
		}
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			_, err := cl.SubmitBroadcastReply(ctx, sess, actor, bid, bodyText)
			return err
		})
		if err != nil {
			return "", true, err
		}
		return "response recorded", true, nil

	case "presence":
		peerFilter := argStr(a, "peer")
		if peerFilter != "" {
			peerFilter = att.actorFor(peerFilter)
		}
		var out string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			regs, err := cl.ReadRegisters(ctx, sess, "presence")
			if err != nil {
				return err
			}
			actors := cl.ListActors()
			out = formatLDRPresence(regs, actors, actor, peerFilter)
			return nil
		})
		return out, true, err

	case "busy":
		txt := argStr(a, "text")
		pids := argInts(a, "pids")
		if err := SetBusy(me, txt, pids); err != nil {
			return "", true, err
		}
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			return ldrPublishPresence(ctx, cl, sess, me, actor, "busy")
		})
		if err != nil {
			return "", true, err
		}
		if txt == "" {
			return "busy cleared", true, nil
		}
		return "declared: " + txt, true, nil

	case "roadmap_post", "roadmap_at", "roadmap_clear":
		localOut, err := doRoadmap(me, name, a)
		if err != nil {
			return "", true, err
		}
		var payload ldrRoadmapPayload
		if name == "roadmap_clear" {
			payload.Cleared = true
		} else {
			r, ok, lerr := LoadRoadmap(me)
			if lerr != nil || !ok {
				return "", true, fmt.Errorf("failed to reload local roadmap: %v", lerr)
			}
			r.Agent = actor
			payload.Roadmap = &r
		}
		b, _ := json.Marshal(payload)
		err = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			_, err := cl.PublishRegister(ctx, sess, actor, "roadmap", b)
			return err
		})
		if err != nil {
			return "", true, err
		}
		return localOut, true, nil

	case "roadmaps":
		agentFilter := argStr(a, "agent")
		if agentFilter != "" {
			agentFilter = att.actorFor(agentFilter)
		}
		var out string
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if _, err := cl.Sync(ctx, sess); err != nil {
				return err
			}
			regs, err := cl.ReadRegisters(ctx, sess, "roadmap")
			if err != nil {
				return err
			}
			out = formatLDRRoadmaps(regs, agentFilter)
			return nil
		})
		return out, true, err

	case "retire":
		undo := argBool(a, "undo")
		err := withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
			if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
				return err
			}
			_, err := cl.SubmitActorAddressing(ctx, sess, actor, undo)
			return err
		})
		if err != nil {
			return "", true, err
		}
		_ = Retire(me, !undo)
		return "retirement updated", true, nil
	}

	return "", false, nil
}

// --- Delivery & Hook Integration for LDR-Attached Lines ---

// ldrHostLocalResourceSnapshot collects strictly host-local resource events
// (never remote LDR calls/broadcasts).
func ldrHostLocalResourceSnapshot(localAgent string) map[string]string {
	out := map[string]string{}
	if _, e := LoadResourceConfig(); e != nil {
		out["config-error:"+e.Error()] = "RESOURCE CONFIGURATION ERROR: " + e.Error()
	}
	for _, r := range resourceList() {
		queue := Queue(r.Name)
		for _, e := range ResourceEvents(r.Name) {
			if resourceEventConcerns(e, localAgent, queue) {
				out["resource-event:"+r.Name+":"+e.ID] = "RESOURCE " + r.Name + " " + e.Action + " by " + e.By + "; inspect current lease before work"
			}
		}
		for _, q := range queue {
			if q.Agent == localAgent {
				if q.Offered != "" {
					key := "offer:" + r.Name + ":" + q.ID + ":" + q.Offered
					out[key] = "RESOURCE OFFER " + r.Name + " for " + localAgent + "; inspect current lease and claim explicitly before work"
				}
			}
		}
		history, _ := QueueHistory(r.Name)
		for _, line := range strings.Split(history, "\n") {
			if line != "" && strings.Contains("REQUEST "+r.Name+" "+line, " "+localAgent+" ") {
				out["queue-state:"+r.Name+":"+line] = "REQUEST " + r.Name + " " + line + "; inspect current lease before work"
			}
		}
	}
	return out
}

// ldrDeliverySnapshot pulls verified LDR notices for localAgent and merges ONLY
// host-local resource lease events (resources stay strictly host-local).
func ldrDeliverySnapshot(att LDRAttachment, localAgent string) map[string]string {
	out := ldrHostLocalResourceSnapshot(localAgent)
	if actorMovedToBoundWorktree(att, localAgent) {
		return out
	}

	// 2. Remote verified LDR notices (sync + ScanDelivery + DeliverableNotices).
	actor := att.actorFor(localAgent)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_ = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
		_, _ = cl.Sync(ctx, sess)
		_, _ = cl.ScanDelivery()
		desc, cd, _, _ := cl.Descriptor()
		for _, n := range cl.DeliverableNotices() {
			if n.Actor != actor {
				continue
			}
			out[formatLDRDeliverySource(desc.LineID, cd, n.ID)] = fmt.Sprintf("LDR %s %s (seq %d) for %s -- inspect via Yip tools",
				strings.ToUpper(n.Kind), n.Target, n.Seq, n.Actor)
		}
		return nil
	})
	return out
}

const ldrDeliveryLinePrefix = "ldr:line:"

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

// formatLDRDeliverySource binds an LDR delivery notice to its originating line_id
// and creation descriptor digest prefix so switching a local endpoint to another
// LDR line with matching (gen, seq, actor, kind) coordinates cannot suppress new
// notices via ep.Known or route an old ack to the wrong line.
func formatLDRDeliverySource(lineID []byte, descDigest [32]byte, noticeID string) string {
	return fmt.Sprintf("%s%x:%x:%s", ldrDeliveryLinePrefix, lineID, descDigest[:8], noticeID)
}

func parseLDRDeliverySource(source string) (lineHex, descHex, noticeID string, qualified bool) {
	if !strings.HasPrefix(source, ldrDeliveryLinePrefix) {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(source, ldrDeliveryLinePrefix)
	p1 := strings.IndexByte(rest, ':')
	if p1 <= 0 {
		return "", "", "", false
	}
	lineHex = rest[:p1]
	rest = rest[p1+1:]
	p2 := strings.IndexByte(rest, ':')
	if p2 <= 0 {
		return "", "", "", false
	}
	descHex = rest[:p2]
	noticeID = rest[p2+1:]
	if len(lineHex) < 32 || len(lineHex) > 128 || len(lineHex)%2 != 0 || len(descHex) != 16 || noticeID == "" || !isLowerHex(lineHex) || !isLowerHex(descHex) {
		return "", "", "", false
	}
	return lineHex, descHex, noticeID, true
}

func ldrAckNotice(source string) error {
	if !strings.HasPrefix(source, "ldr:") {
		return nil
	}
	lineHex, descHex, noticeID, qualified := parseLDRDeliverySource(source)
	if !qualified {
		return fmt.Errorf("cannot acknowledge legacy unqualified LDR delivery %q without originating line identifier (refusing to guess current attachment)", source)
	}
	att, ok, err := loadLDRAttachment()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("cannot acknowledge LDR delivery notice: no LDR attachment configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), ldrAckTimeout)
	defer cancel()
	cl, err := ldrclient.OpenClientWait(ctx, att.ClientDir)
	if err != nil {
		return fmt.Errorf("cannot open LDR client for delivery ack: %w", err)
	}
	defer cl.Close()
	desc, cd, _, _ := cl.Descriptor()
	curLineHex := hex.EncodeToString(desc.LineID)
	curDescHex := hex.EncodeToString(cd[:8])
	if curLineHex != lineHex || curDescHex != descHex {
		return fmt.Errorf("cannot acknowledge LDR delivery for line %s (%s): local line is currently attached to line %s (%s)",
			lineHex, descHex, curLineHex, curDescHex)
	}
	if err := cl.AckNotice(noticeID); err != nil {
		return fmt.Errorf("LDR delivery ack failed: %w", err)
	}
	return nil
}

func ldrCallsListText(att LDRAttachment, me string) (string, error) {
	actor, err := resolveSessionLDRActor(att, me)
	if err != nil {
		return "", err
	}
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	var sums []ldrclient.CallSummary
	err = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
		if _, err := cl.Sync(ctx, sess); err != nil {
			return err
		}
		var lerr error
		sums, lerr = cl.ListCallSummaries(ctx, sess, actor, true)
		return lerr
	})
	if err != nil {
		return "", err
	}
	if len(sums) == 0 {
		return "no calls", nil
	}
	var b strings.Builder
	for _, s := range sums {
		mark := "  "
		if s.Status == "open" && s.Floor == actor {
			mark = "* "
		}
		fmt.Fprintf(&b, "%s%-40s %s->%s  %d turns  %s  %s\n", mark, s.ID, s.From, s.To, s.TurnCount, s.Status, s.Subject)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func ldrHookRings(att LDRAttachment, me string) ([]ldrclient.CallSummary, []ldrclient.BroadcastView) {
	actor := att.actorFor(me)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var sums []ldrclient.CallSummary
	var bvs []ldrclient.BroadcastView
	_ = withLDRSession(ctx, att, func(cl *ldrclient.Client, sess *ldrrelay.SessionClient) error {
		_, _ = cl.Sync(ctx, sess)
		sums, _ = cl.ListCallSummaries(ctx, sess, actor, false)
		bvs, _ = cl.ListBroadcasts(ctx, sess, actor, false)
		return nil
	})
	return sums, bvs
}

func ldrHookPostToolUse(att LDRAttachment, me string, in hookInput) any {
	_ = Beat(me, in.toolName())
	if channelPreferred(me) || rewakeArmed(me) || agyPushLive(me) {
		return nil
	}
	actor := att.actorFor(me)
	sums, bvs := ldrHookRings(att, me)
	var lines []string
	for _, s := range sums {
		cur := loadLDRCursor(me, s.ID)
		rev := s.TurnCount + s.NoteCount
		unseen := max(0, s.TurnCount-cur.SeenTurns)
		haveFloor := s.Floor == actor
		if !haveFloor && unseen == 0 {
			continue
		}
		if rev <= cur.NotifiedRev {
			continue
		}
		_ = updateLDRCursor(me, s.ID, func(c *ldrCallCursor) { c.NotifiedRev = rev })
		lines = append(lines, fmt.Sprintf("%s on %s (turn %d, floor:%s).", s.Peer, s.ID, s.TurnCount, s.Floor))
	}
	for _, b := range bvs {
		if !b.ReadByActor {
			lines = append(lines, fmt.Sprintf("unread broadcast %s [%s].", b.ID, b.Kind))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":     "PostToolUse",
		"additionalContext": "[yip] " + strings.Join(lines, " ") + " Use read; reply only when a call requires it.",
	}}
}

func ldrHookStop(att LDRAttachment, me string) any {
	actor := att.actorFor(me)
	sums, _ := ldrHookRings(att, me)
	var lines []string
	for _, s := range sums {
		cur := loadLDRCursor(me, s.ID)
		rev := s.TurnCount
		unseen := max(0, s.TurnCount-cur.SeenTurns)
		haveFloor := s.Floor == actor
		if !haveFloor && unseen == 0 {
			continue
		}
		if rev <= cur.BlockedRev {
			continue
		}
		_ = updateLDRCursor(me, s.ID, func(c *ldrCallCursor) { c.BlockedRev = rev })
		lines = append(lines, fmt.Sprintf("The floor is yours on %s (turn %d).", s.ID, s.TurnCount))
	}
	if len(lines) == 0 {
		return nil
	}
	msg := "[yip] " + strings.Join(lines, " ") +
		" Read and reply before stopping. If the matter is settled, say bye. " +
		"If you cannot answer now, say that on the call so the peer is not left waiting."
	return map[string]any{
		"decision": "block",
		"reason":   msg,
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "Stop",
			"additionalContext": msg,
		},
	}
}

func ldrHookSessionStart(att LDRAttachment, me string) any {
	_ = Beat(me, "")
	actor := att.actorFor(me)
	sums, bvs := ldrHookRings(att, me)
	var parts []string
	if txt := formatLDRRing(sums, me, actor); txt != "nothing ringing." {
		parts = append(parts, "[yip] "+txt)
	}
	if len(bvs) > 0 {
		parts = append(parts, "[yip broadcasts] "+formatLDRBroadcasts(bvs))
	}
	if len(parts) == 0 {
		return nil
	}
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":     "SessionStart",
		"additionalContext": strings.Join(parts, "\n"),
	}}
}

// --- Formatting helpers matching familiar Yip text output ---

func fmtMS(ms uint64) string {
	if ms == 0 {
		return "unknown"
	}
	return time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
}

func formatLDRTranscript(tr *ldrclient.CallTranscript, actor, mySha string, since, sinceNote int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "call %s -- %s\n%s -> %s, opened %s\n", tr.ID, tr.Subject, tr.From, tr.To, fmtMS(tr.OpenedMS))
	peer := tr.To
	if peer == actor {
		peer = tr.From
	}
	for _, byeBy := range tr.Byes {
		if byeBy == peer {
			fmt.Fprintf(&b, "%s has said bye -- say bye too if you need nothing further.\n", peer)
		}
	}
	fmt.Fprintf(&b, "\n")
	shown := 0
	for _, t := range tr.Turns {
		if t.Number <= since {
			continue
		}
		shown++
		tip := t.Tip
		if tip == "" {
			tip = fmt.Sprintf("seq:%d", t.Seq)
		}
		fmt.Fprintf(&b, "===== turn %d -- %s -- %s -- %s\n", t.Number, t.From, fmtMS(t.SeqTimeMS), tip)
		if t.From != actor && t.PeerTip != "" && mySha != "" && !strings.HasPrefix(t.PeerTip, mySha) {
			fmt.Fprintf(&b, "!! written when your HEAD was %s; you are now at %s.\n", t.PeerTip, mySha)
		}
		if t.Barge {
			fmt.Fprintf(&b, "!! BARGE -- spoken out of turn\n")
		}
		fmt.Fprintf(&b, "\n%s\n\n", strings.TrimRight(t.Body, "\n"))
	}
	for _, n := range tr.Notes {
		if n.Number <= sinceNote {
			continue
		}
		shown++
		fmt.Fprintf(&b, "===== %s note %d -- %s -- %s\n\n%s\n\n", n.Kind, n.Number, n.From, fmtMS(n.SeqTimeMS), n.Body)
	}
	for _, att := range tr.Attachments {
		fmt.Fprintf(&b, "ATTACHMENT %s by %s at %s (%d bytes, %s)\n", att.Name, att.From, fmtMS(att.SeqTimeMS), len(att.Data), att.ReadStatus)
	}
	for _, e := range tr.Events {
		fmt.Fprintf(&b, "STATE %s by %s at %s: %s %s\n", e.State, e.By, fmtMS(e.SeqTimeMS), e.Reason, e.Related)
	}
	fmt.Fprintf(&b, "Status: %s\n", tr.Status)
	if shown == 0 {
		fmt.Fprintf(&b, "(nothing new)\n")
	}
	if tr.Floor == actor {
		fmt.Fprintf(&b, "The floor is yours.\n")
	} else {
		fmt.Fprintf(&b, "The floor is %s's.\n", tr.Floor)
	}
	fmt.Fprintf(&b, "floor: %s\n", tr.Floor)
	return b.String()
}

func formatLDRRing(sums []ldrclient.CallSummary, localAgent, actor string) string {
	var b strings.Builder
	for _, s := range sums {
		cur := loadLDRCursor(localAgent, s.ID)
		unseen := max(0, s.TurnCount-cur.SeenTurns)
		haveFloor := s.Floor == actor
		if !haveFloor && unseen == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s -- %s (with %s)\n", s.ID, s.Subject, s.Peer)
		if unseen > 0 {
			fmt.Fprintf(&b, "  %d unread turn(s), through %d\n", unseen, s.TurnCount)
		}
		if haveFloor {
			fmt.Fprintf(&b, "  the floor is YOURS\n")
		}
		if s.PeerBye {
			fmt.Fprintf(&b, "  they have said bye -- say bye too if you need nothing further\n")
		}
	}
	if b.Len() == 0 {
		return "nothing ringing."
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatLDRInbox(sums []ldrclient.CallSummary, bvs []ldrclient.BroadcastView, localAgent, actor string) string {
	var b strings.Builder
	for _, s := range sums {
		cur := loadLDRCursor(localAgent, s.ID)
		unseen := max(0, s.TurnCount-cur.SeenTurns)
		fmt.Fprintf(&b, "CALL %s [%s] (%s <-> %s) turns:%d unread:%d floor:%s -- %s\n",
			s.ID, s.Status, s.From, s.To, s.TurnCount, unseen, s.Floor, s.Subject)
	}
	for _, bv := range bvs {
		state := "unread"
		if len(bv.Replies) > 0 {
			state = fmt.Sprintf("replied(%d)", len(bv.Replies))
		} else if bv.ReadByActor {
			state = "read"
		}
		fmt.Fprintf(&b, "BROADCAST %s [%s] %s -- %s\n", bv.ID, bv.Kind, state, firstLine(bv.Body))
	}
	if b.Len() == 0 {
		return "inbox clear (use all=true for history)"
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatLDRBroadcasts(bvs []ldrclient.BroadcastView) string {
	if len(bvs) == 0 {
		return "no broadcasts."
	}
	var b strings.Builder
	for _, bv := range bvs {
		state := "unread"
		if bv.ReadByActor {
			state = "read"
		}
		fmt.Fprintf(&b, "%s  [%s]  %s  by %s  %s\n", bv.ID, bv.Kind, state, bv.By, firstLine(bv.Body))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatLDRBroadcastDetail(bv *ldrclient.BroadcastView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "broadcast %s [%s] by %s at %s\nrecipients: %s\n\n%s\n",
		bv.ID, bv.Kind, bv.By, fmtMS(bv.CreatedMS), strings.Join(bv.Recipients, ", "), bv.Body)
	for _, r := range bv.Replies {
		fmt.Fprintf(&b, "\n-- reply from %s at %s --\n%s\n", r.From, fmtMS(r.SeqTimeMS), r.Body)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatLDRPresence(regs []ldrclient.VerifiedRegister, actors []ldrclient.ActorSummary, selfActor, peerFilter string) string {
	regByActor := map[string]ldrclient.VerifiedRegister{}
	for _, r := range regs {
		regByActor[r.Actor] = r
	}
	var names []string
	seen := map[string]bool{}
	for _, a := range actors {
		if peerFilter != "" && a.ID != peerFilter {
			continue
		}
		if peerFilter == "" && !a.Live {
			continue
		}
		names = append(names, a.ID)
		seen[a.ID] = true
	}
	for _, r := range regs {
		if peerFilter != "" && r.Actor != peerFilter {
			continue
		}
		if !seen[r.Actor] {
			names = append(names, r.Actor)
			seen[r.Actor] = true
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "no actors or presence recorded yet."
	}
	var b strings.Builder
	for _, name := range names {
		self := ""
		if name == selfActor {
			self = " (you)"
		}
		vr, hasReg := regByActor[name]
		if !hasReg {
			fmt.Fprintf(&b, "%s%s: declared (no presence published yet)\n", name, self)
			continue
		}
		age := time.Since(time.UnixMilli(int64(vr.AcceptedAtMS)))
		if age < 0 {
			age = 0
		}
		state := "quiet (advisory register)"
		if vr.Historical {
			state = "HISTORICAL (writer revoked/moved/superseded)"
		} else if age < 3*time.Minute {
			state = "LIVE"
		}
		fmt.Fprintf(&b, "%s%s: %s, updated %s ago\n", name, self, state, span(age))
		if vr.ReadStatus != ldrcore.ReadOK {
			fmt.Fprintf(&b, "  payload: %s (epoch %d)\n", vr.ReadStatus, vr.KeyEpoch)
			continue
		}
		var pp ldrPresencePayload
		if json.Unmarshal(vr.Plaintext, &pp) == nil {
			if pp.Tip != "" {
				fmt.Fprintf(&b, "  tip %s (%s)\n", pp.Tip, pp.Branch)
			}
			if pp.Busy != "" {
				fmt.Fprintf(&b, "  busy: %s\n", pp.Busy)
			}
			if len(pp.Pids) > 0 {
				fmt.Fprintf(&b, "  owns pids: %v\n", pp.Pids)
			}
		} else if len(vr.Plaintext) > 0 {
			fmt.Fprintf(&b, "  %s\n", strings.TrimSpace(string(vr.Plaintext)))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatLDRRoadmaps(regs []ldrclient.VerifiedRegister, agentFilter string) string {
	var parts []string
	for _, vr := range regs {
		if agentFilter != "" && vr.Actor != agentFilter {
			continue
		}
		if vr.ReadStatus != ldrcore.ReadOK {
			parts = append(parts, fmt.Sprintf("%s: [%s epoch %d]", vr.Actor, vr.ReadStatus, vr.KeyEpoch))
			continue
		}
		var rp ldrRoadmapPayload
		if err := json.Unmarshal(vr.Plaintext, &rp); err != nil {
			parts = append(parts, fmt.Sprintf("%s: %s", vr.Actor, strings.TrimSpace(string(vr.Plaintext))))
			continue
		}
		if rp.Cleared || rp.Roadmap == nil {
			continue
		}
		line := RoadmapSummary(*rp.Roadmap)
		if vr.Historical {
			line += " [HISTORICAL]"
		}
		parts = append(parts, line)
	}
	if len(parts) == 0 {
		return "no roadmaps posted."
	}
	return strings.Join(parts, "\n")
}
