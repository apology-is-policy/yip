package ldrclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
)

// OpenClientWait opens a client directory, retrying with short bounded waits if
// another local process on the same workstation briefly holds the directory lock.
// Fails immediately on ctx cancellation or any non-lock error.
func OpenClientWait(ctx context.Context, dir string) (*Client, error) {
	return openClientWait(ctx, dir, true)
}

func openClientWait(ctx context.Context, dir string, recoverOutbox bool) (*Client, error) {
	for {
		cl, err := openClient(dir, nil, nil, recoverOutbox)
		if err == nil {
			return cl, nil
		}
		if !errors.Is(err, ErrClientLocked) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrClientLocked, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// OpCommitResult reports a committed log operation produced by a Submit* helper.
type OpCommitResult struct {
	OpID             string   `json:"op_id,omitempty"`
	Seq              uint64   `json:"seq"`
	SeqTime          uint64   `json:"seq_time"`
	Head             [32]byte `json:"-"`
	AlreadyCommitted bool     `json:"already_committed,omitempty"`
}

// PrepareForMutation resolves any restart-pending outbox intents for role,
// syncs verified local state to the relay head, and ensures a fresh anchor.
func (c *Client) PrepareForMutation(ctx context.Context, sess *ldrrelay.SessionClient, role string) error {
	st := c.Status()
	if st.MustResolve {
		prin, err := c.principalForRole(role)
		if err != nil {
			return err
		}
		if err := c.ResolveAll(ctx, sess, prin); err != nil {
			return err
		}
	}
	if _, err := c.Sync(ctx, sess); err != nil {
		return err
	}
	if _, err := c.Anchor(ctx, sess); err != nil {
		return err
	}
	return nil
}

func (c *Client) principalForRole(role string) (ldrcrypto.Principal, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch role {
	case ldrcrypto.PrincipalCredential:
		if c.credKeys == nil {
			return ldrcrypto.Principal{}, errors.New("ldrclient: credential keys not loaded")
		}
		return ldrcrypto.CredentialPrincipal(c.credKeys.CredID), nil
	case ldrcrypto.PrincipalOperator:
		if c.operatorKey == nil {
			return ldrcrypto.Principal{}, errors.New("ldrclient: operator key not attached")
		}
		return ldrcrypto.OperatorPrincipal(c.operatorKey.Signer.PublicKey()), nil
	case ldrcrypto.PrincipalRoot:
		if c.rootKey == nil {
			return ldrcrypto.Principal{}, errors.New("ldrclient: root key not attached")
		}
		return ldrcrypto.RootPrincipal(c.rootKey.Signer.PublicKey()), nil
	default:
		return ldrcrypto.Principal{}, fmt.Errorf("ldrclient: unknown role %q", role)
	}
}

func (c *Client) submitAndSync(ctx context.Context, sess *ldrrelay.SessionClient, p ComposeParams) (OpCommitResult, error) {
	opID, err := c.ComposeAndPersist(p)
	if err != nil {
		return OpCommitResult{}, err
	}
	rep, err := c.Send(ctx, sess, opID)
	if err != nil {
		return OpCommitResult{}, err
	}
	if rep.Class != ldrcore.ClassOutcome || rep.Outcome.Kind != ldrcore.Committed {
		return OpCommitResult{}, fmt.Errorf("ldrclient: %s not committed: class=%s code=%s kind=%s reason=%s",
			p.OpType, rep.Class, rep.Code, rep.Outcome.Kind, rep.Outcome.Reason)
	}
	if _, err := c.Sync(ctx, sess); err != nil {
		return OpCommitResult{}, err
	}
	return OpCommitResult{
		OpID:    opID,
		Seq:     rep.Outcome.Seq,
		SeqTime: rep.SeqTime,
		Head:    rep.Head,
	}, nil
}

// NextCallID produces a readable unique call identifier ("0001-<slug>") that
// does not collide with any existing call or tombstoned call_id in verified state.
func (c *Client) NextCallID(subject string) string {
	st := c.State()
	slug := slugifyLDR(subject)
	if slug == "" {
		slug = "call"
	}
	if len(slug) > 48 {
		slug = strings.TrimRight(slug[:48], "-")
	}
	n := len(st.Calls) + 1
	for {
		cand := fmt.Sprintf("%04d-%s", n, slug)
		if st.Calls[cand] == nil && !containsStr(st.Line.Tombstones.Calls, cand) {
			return cand
		}
		n++
	}
}

func slugifyLDR(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func containsStr(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

// ResolveCallID resolves an optional call selector for actor against verified state.
// If callArg is empty, returns the single open call involving actor.
func (c *Client) ResolveCallID(actor, callArg string) (string, error) {
	st := c.State()
	if callArg != "" {
		if st.Calls[callArg] != nil {
			return callArg, nil
		}
		var matches []string
		for id := range st.Calls {
			if strings.HasPrefix(id, callArg) || strings.Contains(id, callArg) {
				matches = append(matches, id)
			}
		}
		sort.Strings(matches)
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return "", fmt.Errorf("ldrclient: ambiguous call %q (matches: %s)", callArg, strings.Join(matches, ", "))
		}
		return "", fmt.Errorf("ldrclient: unknown call %q", callArg)
	}
	var open []string
	for id, call := range st.Calls {
		if call.Status() == "open" && (actor == "" || call.Involves(actor)) {
			open = append(open, id)
		}
	}
	sort.Strings(open)
	switch len(open) {
	case 0:
		return "", fmt.Errorf("ldrclient: no open call for %s", actor)
	case 1:
		return open[0], nil
	default:
		return "", fmt.Errorf("ldrclient: multiple open calls (%s); specify call id", strings.Join(open, ", "))
	}
}

// --- High-level verified mutation helpers ---

// SubmitCallOpen opens a new call from actor to peer with encrypted subject/body.
func (c *Client) SubmitCallOpen(ctx context.Context, sess *ldrrelay.SessionClient, actor, peer, callID, subject, body, tip, peerTip string) (OpCommitResult, error) {
	if callID == "" {
		callID = c.NextCallID(subject)
	}
	payload := map[string]string{"subject": subject, "body": body}
	if tip != "" {
		payload["tip"] = tip
	}
	if peerTip != "" {
		payload["peer_tip"] = peerTip
	}
	pt, _ := json.Marshal(payload)
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "call_open:" + callID,
		Origin:    ldrcore.OriginActor,
		OpType:    "call_open",
		ActorID:   actor,
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}, {Key: "to", Value: peer}},
		Plaintext: pt,
	})
}

// SubmitCallTurn appends an encrypted turn to callID.
func (c *Client) SubmitCallTurn(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, body string, barge bool, tip, peerTip string) (OpCommitResult, error) {
	call := c.State().Calls[callID]
	if call == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	payload := map[string]string{"body": body}
	if tip != "" {
		payload["tip"] = tip
	}
	if peerTip != "" {
		payload["peer_tip"] = peerTip
	}
	pt, _ := json.Marshal(payload)
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "call_turn:" + callID,
		Origin:    ldrcore.OriginActor,
		OpType:    "call_turn",
		ActorID:   actor,
		Expect:    ldrcrypto.ExpectMap{"turn_count": uint64(call.TurnCount)},
		Fields:    ldrcrypto.Map{{Key: "barge", Value: barge}, {Key: "call_id", Value: callID}},
		Plaintext: pt,
	})
}

// SubmitCallBye proposes closing callID (bilateral; closes once both sides say bye).
func (c *Client) SubmitCallBye(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID string) (OpCommitResult, error) {
	call := c.State().Calls[callID]
	if call == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:  "call_bye:" + callID,
		Origin:  ldrcore.OriginActor,
		OpType:  "call_bye",
		ActorID: actor,
		Expect: ldrcrypto.ExpectMap{
			"lifecycle_rev": uint64(call.LifecycleRev),
			"turn_count":    uint64(call.TurnCount),
		},
		Fields: ldrcrypto.Map{{Key: "call_id", Value: callID}},
	})
}

// SubmitCallNote adds a one-way note to callID (does not change floor or clear byes).
func (c *Client) SubmitCallNote(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, body string) (OpCommitResult, error) {
	if c.State().Calls[callID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	pt, _ := json.Marshal(map[string]string{"body": body})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "call_note:" + callID,
		Origin:    ldrcore.OriginActor,
		OpType:    "call_note",
		ActorID:   actor,
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}},
		Plaintext: pt,
	})
}

// SubmitCallRatify adds an operator-signed ratification note to callID.
func (c *Client) SubmitCallRatify(ctx context.Context, sess *ldrrelay.SessionClient, callID, body string) (OpCommitResult, error) {
	if c.State().Calls[callID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	pt, _ := json.Marshal(map[string]string{"body": body})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "call_ratify:" + callID,
		Origin:    ldrcore.OriginOperator,
		OpType:    "call_ratify",
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}},
		Plaintext: pt,
	})
}

// SubmitCallStatus transitions a call's explicit lifecycle state (open/resolved/deferred/archived/linked).
func (c *Client) SubmitCallStatus(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, state, reason, related string) (OpCommitResult, error) {
	call := c.State().Calls[callID]
	if call == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	fields := ldrcrypto.Map{
		{Key: "call_id", Value: callID},
		{Key: "state", Value: state},
	}
	if related != "" {
		fields = append(fields, ldrcrypto.MapEntry{Key: "related", Value: related})
	}
	pt, _ := json.Marshal(map[string]string{"reason": reason})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:  "call_status:" + callID,
		Origin:  ldrcore.OriginActor,
		OpType:  "call_status",
		ActorID: actor,
		Expect: ldrcrypto.ExpectMap{
			"lifecycle_rev": uint64(call.LifecycleRev),
			"turn_count":    uint64(call.TurnCount),
		},
		Fields:    fields,
		Plaintext: pt,
	})
}

// SubmitCallAttach attaches an encrypted inline file snapshot to callID.
func (c *Client) SubmitCallAttach(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, filename string, data []byte) (OpCommitResult, error) {
	if c.State().Calls[callID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	desc, _, _, _ := c.Descriptor()
	pt, _ := json.Marshal(map[string]string{
		"name":     filename,
		"encoding": "base64",
		"data":     base64.StdEncoding.EncodeToString(data),
	})
	if uint64(len(pt)) > desc.Profile.MaxAttachmentBytes {
		return OpCommitResult{}, fmt.Errorf("ldrclient: attachment payload %d exceeds profile inline limit %d", len(pt), desc.Profile.MaxAttachmentBytes)
	}
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "call_attach:" + callID,
		Origin:    ldrcore.OriginActor,
		OpType:    "call_attach",
		ActorID:   actor,
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}, {Key: "size_class", Value: "within_inline_limit"}},
		Plaintext: pt,
	})
}

// SubmitDisputeOpen opens a dispute on callID and returns the commit result + the
// exact dispute ID assigned at the caller's committed sequence number.
func (c *Client) SubmitDisputeOpen(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, claim string) (OpCommitResult, string, error) {
	call := c.State().Calls[callID]
	if call == nil {
		return OpCommitResult{}, "", fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	pt, _ := json.Marshal(map[string]string{"claim": claim})
	res, err := c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "dispute_open:" + callID,
		Origin:    ldrcore.OriginActor,
		OpType:    "dispute_open",
		ActorID:   actor,
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}},
		Plaintext: pt,
	})
	if err != nil {
		return OpCommitResult{}, "", err
	}
	dispID, err := c.disputeIDAtSeq(callID, res.Seq)
	if err != nil {
		return res, "", err
	}
	return res, dispID, nil
}

func (c *Client) disputeIDAtSeq(callID string, seq uint64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seq < 1 || seq > uint64(len(c.entries)) {
		return "", fmt.Errorf("ldrclient: committed dispute_open seq %d not present in verified store", seq)
	}
	ve := c.entries[seq-1]
	if ve.frame.Seq != seq || ve.decoded == nil || ve.decoded.OpType != "dispute_open" || ve.decoded.Record.Call != callID || ve.disputeID == "" {
		return "", fmt.Errorf("ldrclient: seq %d is not a committed dispute_open for call %q", seq, callID)
	}
	return ve.disputeID, nil
}

// SubmitDisputeMeasure records actor's proposed measurement on disputeID.
func (c *Client) SubmitDisputeMeasure(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, disputeID, cmd string) (OpCommitResult, error) {
	call := c.State().Calls[callID]
	if call == nil || call.Disputes[disputeID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown dispute %q on call %q", disputeID, callID)
	}
	disp := call.Disputes[disputeID]
	pt, _ := json.Marshal(map[string]string{"cmd": cmd})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "dispute_measure:" + callID + ":" + disputeID,
		Origin:    ldrcore.OriginActor,
		OpType:    "dispute_measure",
		ActorID:   actor,
		Expect:    ldrcrypto.ExpectMap{"measure_rev": uint64(disp.MeasureRev[actor])},
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}, {Key: "dispute", Value: disputeID}},
		Plaintext: pt,
	})
}

// SubmitDisputeResolve resolves disputeID (kind: "measured" or "withdrawn").
func (c *Client) SubmitDisputeResolve(ctx context.Context, sess *ldrrelay.SessionClient, actor, callID, disputeID, kind, detail string) (OpCommitResult, error) {
	call := c.State().Calls[callID]
	if call == nil || call.Disputes[disputeID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown dispute %q on call %q", disputeID, callID)
	}
	disp := call.Disputes[disputeID]
	pt, _ := json.Marshal(map[string]string{"detail": detail})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "dispute_resolve:" + callID + ":" + disputeID,
		Origin:    ldrcore.OriginActor,
		OpType:    "dispute_resolve",
		ActorID:   actor,
		Expect:    ldrcrypto.ExpectMap{"rev": uint64(disp.Rev)},
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}, {Key: "dispute", Value: disputeID}, {Key: "kind", Value: kind}},
		Plaintext: pt,
	})
}

// SubmitDisputeArbitrate records an operator-signed arbitration on disputeID.
func (c *Client) SubmitDisputeArbitrate(ctx context.Context, sess *ldrrelay.SessionClient, callID, disputeID, detail string) (OpCommitResult, error) {
	call := c.State().Calls[callID]
	if call == nil || call.Disputes[disputeID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown dispute %q on call %q", disputeID, callID)
	}
	disp := call.Disputes[disputeID]
	pt, _ := json.Marshal(map[string]string{"detail": detail})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "dispute_arbitrate:" + callID + ":" + disputeID,
		Origin:    ldrcore.OriginOperator,
		OpType:    "dispute_arbitrate",
		Expect:    ldrcrypto.ExpectMap{"rev": uint64(disp.Rev)},
		Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}, {Key: "dispute", Value: disputeID}},
		Plaintext: pt,
	})
}

// SubmitBroadcastCreate creates an operator-signed broadcast addressed to recipients.
// If defaultAudience is true and recipients is empty, snapshots all live default-addressed actors.
func (c *Client) SubmitBroadcastCreate(ctx context.Context, sess *ldrrelay.SessionClient, broadcastID, kind, by, body string, recipients []string, defaultAudience bool) (OpCommitResult, error) {
	st := c.State()
	recips := append([]string(nil), recipients...)
	if defaultAudience && len(recips) == 0 {
		for id, a := range st.Line.Actors {
			if a != nil && a.Live && a.DefaultAddressed {
				recips = append(recips, id)
			}
		}
	}
	sort.Strings(recips)
	if len(recips) == 0 {
		return OpCommitResult{}, errors.New("ldrclient: broadcast requires at least one recipient")
	}
	recArr := make([]any, len(recips))
	for i, r := range recips {
		recArr[i] = r
	}
	var expect ldrcrypto.ExpectMap
	if defaultAudience {
		expect = ldrcrypto.ExpectMap{"audience_rev": uint64(st.Line.AudienceRev)}
	}
	pt, _ := json.Marshal(map[string]string{"by": by, "body": body})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action: "broadcast_create:" + broadcastID,
		Origin: ldrcore.OriginOperator,
		OpType: "broadcast_create",
		Expect: expect,
		Fields: ldrcrypto.Map{
			{Key: "broadcast_id", Value: broadcastID},
			{Key: "default_audience", Value: defaultAudience},
			{Key: "kind", Value: kind},
			{Key: "recipients", Value: recArr},
		},
		Plaintext: pt,
	})
}

// SubmitBroadcastRead commits a broadcast read receipt on first read (§8).
// Subsequent reads by the same actor return AlreadyCommitted=true without sending a duplicate record.
func (c *Client) SubmitBroadcastRead(ctx context.Context, sess *ldrrelay.SessionClient, actor, broadcastID string) (OpCommitResult, error) {
	b := c.State().Broadcasts[broadcastID]
	if b == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown broadcast %q", broadcastID)
	}
	if rc, ok := b.Receipts[actor]; ok {
		return OpCommitResult{Seq: uint64(rc.ReadSeq), AlreadyCommitted: true}, nil
	}
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:  "broadcast_read:" + broadcastID + ":" + actor,
		Origin:  ldrcore.OriginActor,
		OpType:  "broadcast_read",
		ActorID: actor,
		Fields:  ldrcrypto.Map{{Key: "broadcast_id", Value: broadcastID}},
	})
}

// SubmitBroadcastReply posts an encrypted reply from actor to broadcastID.
func (c *Client) SubmitBroadcastReply(ctx context.Context, sess *ldrrelay.SessionClient, actor, broadcastID, body string) (OpCommitResult, error) {
	if c.State().Broadcasts[broadcastID] == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown broadcast %q", broadcastID)
	}
	pt, _ := json.Marshal(map[string]string{"body": body})
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:    "broadcast_reply:" + broadcastID + ":" + actor,
		Origin:    ldrcore.OriginActor,
		OpType:    "broadcast_reply",
		ActorID:   actor,
		Fields:    ldrcrypto.Map{{Key: "broadcast_id", Value: broadcastID}},
		Plaintext: pt,
	})
}

// SubmitActorDeclare declares actorID under this credential's namespace.
func (c *Client) SubmitActorDeclare(ctx context.Context, sess *ldrrelay.SessionClient, actorID, namespace string) (OpCommitResult, error) {
	if namespace == "" {
		cid, ok := c.CredID()
		if !ok {
			return OpCommitResult{}, errors.New("ldrclient: credential keys not loaded")
		}
		cr := c.State().Line.Credentials[ldrrelay.CredToken(cid)]
		if cr == nil {
			return OpCommitResult{}, errors.New("ldrclient: credential not enrolled")
		}
		namespace = cr.Namespace
	}
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action: "actor_declare:" + actorID,
		Origin: ldrcore.OriginCredential,
		OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: actorID}, {Key: "label", Value: false}, {Key: "namespace_id", Value: namespace}},
	})
}

// SubmitActorRemove permanently removes actorID owned by this credential.
func (c *Client) SubmitActorRemove(ctx context.Context, sess *ldrrelay.SessionClient, actorID string) (OpCommitResult, error) {
	a := c.State().Line.Actors[actorID]
	if a == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown actor %q", actorID)
	}
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action: "actor_remove:" + actorID,
		Origin: ldrcore.OriginCredential,
		OpType: "actor_remove",
		Expect: ldrcrypto.ExpectMap{"binding_gen": uint64(a.BindingGen)},
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: actorID}},
	})
}

// SubmitActorAddressing sets actorID's default_addressed flag (used by retire/unretire).
func (c *Client) SubmitActorAddressing(ctx context.Context, sess *ldrrelay.SessionClient, actorID string, defaultAddressed bool) (OpCommitResult, error) {
	a := c.State().Line.Actors[actorID]
	if a == nil {
		return OpCommitResult{}, fmt.Errorf("ldrclient: unknown actor %q", actorID)
	}
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action:  "actor_addressing:" + actorID,
		Origin:  ldrcore.OriginActor,
		OpType:  "actor_addressing",
		ActorID: actorID,
		Expect:  ldrcrypto.ExpectMap{"addr_rev": uint64(a.AddrRev)},
		Fields:  ldrcrypto.Map{{Key: "default_addressed", Value: defaultAddressed}},
	})
}

// SubmitCredentialRevoke revokes an enrolled credential (operator-origin).
func (c *Client) SubmitCredentialRevoke(ctx context.Context, sess *ldrrelay.SessionClient, credID [32]byte) (OpCommitResult, error) {
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action: "credential_revoke:" + ldrrelay.CredToken(credID),
		Origin: ldrcore.OriginOperator,
		OpType: "credential_revoke",
		Fields: ldrcrypto.Map{{Key: "cred_id", Value: credID[:]}},
	})
}

// SubmitOperatorRevoke revokes an authorized operator key (root-origin).
func (c *Client) SubmitOperatorRevoke(ctx context.Context, sess *ldrrelay.SessionClient, opPub ldrcrypto.PublicKey) (OpCommitResult, error) {
	opCBOR, err := opPub.ToCBOR()
	if err != nil {
		return OpCommitResult{}, err
	}
	st := c.State()
	return c.submitAndSync(ctx, sess, ComposeParams{
		Action: "operator_key_revoke",
		Origin: ldrcore.OriginRoot,
		OpType: "operator_key_revoke",
		Expect: ldrcrypto.ExpectMap{"root_rev": uint64(st.Line.RootRev)},
		Fields: ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
	})
}

// --- Verified Transcript, Summary, Broadcast & Actor Read Models ---

type TranscriptTurn struct {
	Number     int
	Seq        uint64
	SeqTimeMS  uint64
	From       string
	Barge      bool
	Body       string
	Tip        string
	PeerTip    string
	ReadStatus string
}

type TranscriptNote struct {
	Number     int
	Seq        uint64
	SeqTimeMS  uint64
	Kind       string // "agent" or "human"
	From       string
	Body       string
	ReadStatus string
}

type TranscriptAttachment struct {
	Seq        uint64
	SeqTimeMS  uint64
	From       string
	Name       string
	Data       []byte
	ReadStatus string
}

type TranscriptStatusEvent struct {
	Seq        uint64
	SeqTimeMS  uint64
	By         string
	State      string
	Related    string
	Reason     string
	ReadStatus string
}

type TranscriptDispute struct {
	ID             string
	OpenedBy       string
	Claim          string
	Resolved       bool
	ResolutionKind string
	ResolutionBy   string
	ResolutionText string
	Measurements   map[string]string
}

type CallTranscript struct {
	ID          string
	From        string
	To          string
	Subject     string
	OpenedMS    uint64
	Status      string
	Lifecycle   string
	Floor       string
	Byes        []string
	Links       []string
	Turns       []TranscriptTurn
	Notes       []TranscriptNote
	Attachments []TranscriptAttachment
	Disputes    []TranscriptDispute
	Events      []TranscriptStatusEvent
}

type CallSummary struct {
	ID          string
	From        string
	To          string
	Peer        string
	Subject     string
	Status      string
	Lifecycle   string
	Floor       string
	TurnCount   int
	NoteCount   int
	PeerBye     bool
	OpenedMS    uint64
	LastTimeMS  uint64
	LastTurnSeq uint64
	LastNoteSeq uint64
}

type BroadcastReplyView struct {
	Seq        uint64
	SeqTimeMS  uint64
	From       string
	Body       string
	ReadStatus string
}

type BroadcastView struct {
	ID          string
	Kind        string
	By          string
	Body        string
	ReadStatus  string
	CreatedMS   uint64
	Recipients  []string
	ReadByActor bool
	ReadSeq     uint64
	Replies     []BroadcastReplyView
}

type ActorSummary struct {
	ID               string
	Namespace        string
	Cred             string
	Live             bool
	DefaultAddressed bool
	BindingGen       int64
}

func decodePayloadJSONMap(pt []byte) map[string]string {
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err == nil && m != nil {
		return m
	}
	return nil
}

func readStatusFallback(rs string, epoch uint64) string {
	switch rs {
	case ldrcore.ReadNoKey:
		return fmt.Sprintf("[encrypted: no key for epoch %d]", epoch)
	case ldrcore.ReadUndecryptable:
		return fmt.Sprintf("[encrypted: undecryptable payload at epoch %d]", epoch)
	default:
		return "[encrypted]"
	}
}

func (c *Client) readDecryptedEntry(ctx context.Context, sess *ldrrelay.SessionClient, e verifiedEntry) ([]byte, string, error) {
	if e.decoded == nil || e.decoded.PayloadCommit.Length == 0 {
		return nil, ldrcore.ReadNone, nil
	}
	pt, rs, err := c.ReadPayload(ctx, sess, e.frame.Seq)
	if err != nil {
		return nil, "", err
	}
	return pt, rs, nil
}

func (c *Client) checkReadReadyLocked() error {
	if c.outboxUncertain {
		return ErrOutboxUncertain
	}
	if c.epochsUncertain {
		return ErrEpochsUncertain
	}
	if c.outbox.Halted != "" {
		return fmt.Errorf("%w: %s", ErrViolation, c.outbox.Halted)
	}
	if !c.outbox.Activated {
		return ErrNotActivated
	}
	return nil
}

// ReadCallTranscript builds a verified, decrypted transcript for callID directly
// from local verified.wal entries and epoch-verified payload reads.
func (c *Client) ReadCallTranscript(ctx context.Context, sess *ldrrelay.SessionClient, callID string) (*CallTranscript, error) {
	c.mu.Lock()
	if err := c.checkReadReadyLocked(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	call := c.state.Calls[callID]
	if call == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("ldrclient: unknown call %q", callID)
	}
	tr := &CallTranscript{
		ID:        callID,
		From:      call.From,
		To:        call.To,
		Status:    call.Status(),
		Lifecycle: call.Lifecycle,
		Floor:     call.Floor(),
		Byes:      sortedCopy(call.Byes),
		Links:     sortedCopy(call.Links),
	}
	var matching []verifiedEntry
	for _, e := range c.entries {
		if e.decoded != nil && e.decoded.Record.Call == callID {
			matching = append(matching, e)
		}
	}
	c.mu.Unlock()

	disputes := map[string]*TranscriptDispute{}
	disputeSeq := 0
	turnNo := 0
	noteNo := 0

	for _, e := range matching {
		r := e.decoded.Record
		pt, rs, err := c.readDecryptedEntry(ctx, sess, e)
		if err != nil {
			return nil, err
		}
		m := decodePayloadJSONMap(pt)
		epoch := uint64(e.decoded.Record.KeyEpoch)

		switch r.Type {
		case "call_open":
			tr.OpenedMS = e.frame.SeqTime
			turnNo++
			bodyText := string(pt)
			subj := ""
			tip, peerTip := "", ""
			if rs != ldrcore.ReadOK {
				bodyText = readStatusFallback(rs, epoch)
				subj = bodyText
			} else if m != nil {
				subj = m["subject"]
				bodyText = m["body"]
				tip = m["tip"]
				peerTip = m["peer_tip"]
			}
			tr.Subject = subj
			tr.Turns = append(tr.Turns, TranscriptTurn{
				Number: turnNo, Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				From: r.Actor, Barge: false, Body: bodyText, Tip: tip, PeerTip: peerTip, ReadStatus: rs,
			})

		case "call_turn":
			turnNo++
			bodyText := string(pt)
			tip, peerTip := "", ""
			if rs != ldrcore.ReadOK {
				bodyText = readStatusFallback(rs, epoch)
			} else if m != nil {
				bodyText = m["body"]
				tip = m["tip"]
				peerTip = m["peer_tip"]
			}
			tr.Turns = append(tr.Turns, TranscriptTurn{
				Number: turnNo, Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				From: r.Actor, Barge: r.Barge, Body: bodyText, Tip: tip, PeerTip: peerTip, ReadStatus: rs,
			})

		case "call_note":
			noteNo++
			bodyText := string(pt)
			if rs != ldrcore.ReadOK {
				bodyText = readStatusFallback(rs, epoch)
			} else if m != nil {
				bodyText = m["body"]
			}
			tr.Notes = append(tr.Notes, TranscriptNote{
				Number: noteNo, Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				Kind: "agent", From: r.Actor, Body: bodyText, ReadStatus: rs,
			})

		case "call_ratify":
			noteNo++
			bodyText := string(pt)
			if rs != ldrcore.ReadOK {
				bodyText = readStatusFallback(rs, epoch)
			} else if m != nil {
				bodyText = m["body"]
			}
			tr.Notes = append(tr.Notes, TranscriptNote{
				Number: noteNo, Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				Kind: "human", From: "operator", Body: bodyText, ReadStatus: rs,
			})

		case "call_status":
			reason := string(pt)
			if rs != ldrcore.ReadOK {
				reason = readStatusFallback(rs, epoch)
			} else if m != nil {
				reason = m["reason"]
			}
			tr.Events = append(tr.Events, TranscriptStatusEvent{
				Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				By: r.Actor, State: r.State, Related: r.Related, Reason: reason, ReadStatus: rs,
			})

		case "call_attach":
			att := TranscriptAttachment{
				Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				From: r.Actor, ReadStatus: rs,
			}
			if rs == ldrcore.ReadOK {
				if m != nil {
					att.Name = m["name"]
					if m["encoding"] == "base64" {
						if dec, err := base64.StdEncoding.DecodeString(m["data"]); err == nil {
							att.Data = dec
						}
					} else {
						att.Data = []byte(m["data"])
					}
				} else {
					att.Name = fmt.Sprintf("attach-%d", e.frame.Seq)
					att.Data = pt
				}
			}
			tr.Attachments = append(tr.Attachments, att)

		case "dispute_open":
			disputeSeq++
			id := strconv.Itoa(disputeSeq)
			claim := string(pt)
			if rs != ldrcore.ReadOK {
				claim = readStatusFallback(rs, epoch)
			} else if m != nil {
				claim = m["claim"]
			}
			disputes[id] = &TranscriptDispute{
				ID: id, OpenedBy: r.Actor, Claim: claim, Measurements: map[string]string{},
			}

		case "dispute_measure":
			if d := disputes[r.Dispute]; d != nil {
				cmd := string(pt)
				if rs != ldrcore.ReadOK {
					cmd = readStatusFallback(rs, epoch)
				} else if m != nil {
					cmd = m["cmd"]
				}
				d.Measurements[r.Actor] = cmd
			}

		case "dispute_resolve":
			if d := disputes[r.Dispute]; d != nil {
				detail := string(pt)
				if rs != ldrcore.ReadOK {
					detail = readStatusFallback(rs, epoch)
				} else if m != nil {
					detail = m["detail"]
				}
				d.Resolved = true
				d.ResolutionKind = r.Kind
				d.ResolutionBy = r.Actor
				d.ResolutionText = detail
			}

		case "dispute_arbitrate":
			if d := disputes[r.Dispute]; d != nil {
				detail := string(pt)
				if rs != ldrcore.ReadOK {
					detail = readStatusFallback(rs, epoch)
				} else if m != nil {
					detail = m["detail"]
				}
				d.Resolved = true
				d.ResolutionKind = "human"
				d.ResolutionBy = "operator"
				d.ResolutionText = detail
			}
		}
	}

	dIDs := make([]string, 0, len(disputes))
	for id := range disputes {
		dIDs = append(dIDs, id)
	}
	sort.Strings(dIDs)
	for _, id := range dIDs {
		tr.Disputes = append(tr.Disputes, *disputes[id])
	}
	return tr, nil
}

// ListCallSummaries returns verified call summaries for actor (or all calls if actor=="").
func (c *Client) ListCallSummaries(ctx context.Context, sess *ldrrelay.SessionClient, actor string, includeAll bool) ([]CallSummary, error) {
	c.mu.Lock()
	if err := c.checkReadReadyLocked(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	var ids []string
	for id, call := range c.state.Calls {
		if actor != "" && !call.Involves(actor) {
			continue
		}
		if !includeAll && call.Status() != "open" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	entriesCopy := append([]verifiedEntry(nil), c.entries...)
	callsCopy := make(map[string]*ldrcore.Call, len(ids))
	for _, id := range ids {
		cp := *c.state.Calls[id]
		callsCopy[id] = &cp
	}
	c.mu.Unlock()

	openEntry := make(map[string]verifiedEntry, len(ids))
	lastTime := make(map[string]uint64, len(ids))
	lastTurnSeq := make(map[string]uint64, len(ids))
	lastNoteSeq := make(map[string]uint64, len(ids))
	for _, e := range entriesCopy {
		if e.decoded == nil {
			continue
		}
		cid := e.decoded.Record.Call
		if callsCopy[cid] == nil {
			continue
		}
		if e.frame.SeqTime > lastTime[cid] {
			lastTime[cid] = e.frame.SeqTime
		}
		switch e.decoded.Record.Type {
		case "call_open":
			openEntry[cid] = e
			lastTurnSeq[cid] = e.frame.Seq
		case "call_turn":
			lastTurnSeq[cid] = e.frame.Seq
		case "call_note", "call_ratify":
			lastNoteSeq[cid] = e.frame.Seq
		}
	}

	out := make([]CallSummary, 0, len(ids))
	for _, id := range ids {
		call := callsCopy[id]
		peer := call.To
		if actor != "" && actor == call.To {
			peer = call.From
		}
		peerBye := containsStr(call.Byes, peer)
		subj := ""
		opened := uint64(0)
		if oe, ok := openEntry[id]; ok {
			opened = oe.frame.SeqTime
			pt, rs, err := c.readDecryptedEntry(ctx, sess, oe)
			if err != nil {
				return nil, err
			}
			if rs == ldrcore.ReadOK {
				if m := decodePayloadJSONMap(pt); m != nil {
					subj = m["subject"]
				}
			} else if rs != ldrcore.ReadNone {
				subj = readStatusFallback(rs, uint64(oe.decoded.Record.KeyEpoch))
			}
		}
		out = append(out, CallSummary{
			ID:          id,
			From:        call.From,
			To:          call.To,
			Peer:        peer,
			Subject:     subj,
			Status:      call.Status(),
			Lifecycle:   call.Lifecycle,
			Floor:       call.Floor(),
			TurnCount:   int(call.TurnCount),
			NoteCount:   int(call.NoteCount),
			PeerBye:     peerBye,
			OpenedMS:    opened,
			LastTimeMS:  lastTime[id],
			LastTurnSeq: lastTurnSeq[id],
			LastNoteSeq: lastNoteSeq[id],
		})
	}
	return out, nil
}

// ReadBroadcast returns the verified, decrypted view of broadcastID.
func (c *Client) ReadBroadcast(ctx context.Context, sess *ldrrelay.SessionClient, actor, broadcastID string) (*BroadcastView, error) {
	c.mu.Lock()
	if err := c.checkReadReadyLocked(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	b := c.state.Broadcasts[broadcastID]
	if b == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("ldrclient: unknown broadcast %q", broadcastID)
	}
	bv := &BroadcastView{
		ID:         broadcastID,
		Kind:       b.Kind,
		Recipients: sortedCopy(b.Recipients),
	}
	if actor != "" {
		if rc, ok := b.Receipts[actor]; ok {
			bv.ReadByActor = true
			bv.ReadSeq = uint64(rc.ReadSeq)
		}
	}
	var matching []verifiedEntry
	for _, e := range c.entries {
		if e.decoded != nil && e.decoded.Record.Broadcast == broadcastID {
			matching = append(matching, e)
		}
	}
	c.mu.Unlock()

	for _, e := range matching {
		r := e.decoded.Record
		pt, rs, err := c.readDecryptedEntry(ctx, sess, e)
		if err != nil {
			return nil, err
		}
		m := decodePayloadJSONMap(pt)
		epoch := uint64(e.decoded.Record.KeyEpoch)
		switch r.Type {
		case "broadcast_create":
			bv.CreatedMS = e.frame.SeqTime
			bv.ReadStatus = rs
			if rs != ldrcore.ReadOK {
				bv.Body = readStatusFallback(rs, epoch)
			} else if m != nil {
				bv.By = m["by"]
				bv.Body = m["body"]
			} else {
				bv.Body = string(pt)
			}
		case "broadcast_reply":
			bodyText := string(pt)
			if rs != ldrcore.ReadOK {
				bodyText = readStatusFallback(rs, epoch)
			} else if m != nil {
				bodyText = m["body"]
			}
			bv.Replies = append(bv.Replies, BroadcastReplyView{
				Seq: e.frame.Seq, SeqTimeMS: e.frame.SeqTime,
				From: r.Actor, Body: bodyText, ReadStatus: rs,
			})
		}
	}
	return bv, nil
}

// ListBroadcasts lists broadcasts addressed to actor (or all broadcasts if actor=="").
func (c *Client) ListBroadcasts(ctx context.Context, sess *ldrrelay.SessionClient, actor string, includeAll bool) ([]BroadcastView, error) {
	c.mu.Lock()
	if err := c.checkReadReadyLocked(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	var ids []string
	for id, b := range c.state.Broadcasts {
		if actor != "" && !containsStr(b.Recipients, actor) {
			continue
		}
		if !includeAll && actor != "" {
			_, read := b.Receipts[actor]
			replied := b.ReplyCount[actor] > 0
			if b.Kind == "announcement" && read {
				continue
			}
			if b.Kind != "announcement" && replied {
				continue
			}
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	c.mu.Unlock()

	out := make([]BroadcastView, 0, len(ids))
	for _, id := range ids {
		bv, err := c.ReadBroadcast(ctx, sess, actor, id)
		if err != nil {
			return nil, err
		}
		out = append(out, *bv)
	}
	return out, nil
}

// ListActors returns all actors recorded in verified.wal sorted by ID.
func (c *Client) ListActors() []ActorSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.state.Line.Actors))
	for id := range c.state.Line.Actors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ActorSummary, 0, len(ids))
	for _, id := range ids {
		a := c.state.Line.Actors[id]
		out = append(out, ActorSummary{
			ID:               id,
			Namespace:        a.Namespace,
			Cred:             a.Cred,
			Live:             a.Live,
			DefaultAddressed: a.DefaultAddressed,
			BindingGen:       a.BindingGen,
		})
	}
	return out
}
