package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

func ldrRootRevokeOperatorCLI(rest []string, out io.Writer) error {
	var dir, rootKeyPath, opPubPath string
	rest, dir = takeFlag(rest, "--dir", "")
	rest, rootKeyPath = takeFlag(rest, "--root-key", "")
	rest, opPubPath = takeFlag(rest, "--operator-pub", "")
	if dir == "" || rootKeyPath == "" || opPubPath == "" {
		return errors.New("root revoke-operator requires --dir, --root-key, --operator-pub")
	}
	rootKM, err := ldrclient.LoadSigningKey(rootKeyPath)
	if err != nil {
		return err
	}
	opPub, err := ldrclient.LoadPublicKey(opPubPath)
	if err != nil {
		return err
	}
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	cl, err := ldrclient.OpenClientWait(ctx, dir)
	if err != nil {
		return err
	}
	defer cl.Close()
	cl.AttachRootKey(rootKM)
	sess, err := cl.Dial(ctx, ldrcrypto.PrincipalRoot)
	if err != nil {
		return err
	}
	defer sess.Close()
	if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalRoot); err != nil {
		return err
	}
	res, err := cl.SubmitOperatorRevoke(ctx, sess, opPub)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(res)
}

func ldrJoinRevokeCLI(rest []string, out io.Writer) error {
	var dir, opKeyPath, credHex string
	rest, dir = takeFlag(rest, "--dir", "")
	rest, opKeyPath = takeFlag(rest, "--operator-key", "")
	rest, credHex = takeFlag(rest, "--cred-id", "")
	if dir == "" || opKeyPath == "" || credHex == "" {
		return errors.New("join revoke requires --dir, --operator-key, --cred-id")
	}
	rawCID, err := hex.DecodeString(strings.TrimSpace(credHex))
	if err != nil || len(rawCID) != 32 {
		return errors.New("invalid --cred-id hex (must be 32 bytes)")
	}
	var cid [32]byte
	copy(cid[:], rawCID)
	opKM, err := ldrclient.LoadSigningKey(opKeyPath)
	if err != nil {
		return err
	}
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	cl, err := ldrclient.OpenClientWait(ctx, dir)
	if err != nil {
		return err
	}
	defer cl.Close()
	cl.AttachOperatorKey(opKM)
	sess, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		return err
	}
	defer sess.Close()
	if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalOperator); err != nil {
		return err
	}
	res, err := cl.SubmitCredentialRevoke(ctx, sess, cid)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"op_id":   res.OpID,
		"seq":     res.Seq,
		"cred_id": hex.EncodeToString(cid[:]),
	})
}

func ldrActorExtraCLI(sub string, rest []string, out io.Writer) error {
	switch sub {
	case "list":
		var dir string
		rest, dir = takeFlag(rest, "--dir", "")
		if dir == "" {
			return errors.New("actor list requires --dir")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		return json.NewEncoder(out).Encode(cl.ListActors())

	case "remove":
		var dir, actorID string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actorID = takeFlag(rest, "--actor", "")
		if dir == "" || actorID == "" {
			return errors.New("actor remove requires --dir and --actor")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		res, err := cl.SubmitActorRemove(ctx, sess, actorID)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(res)

	case "addressing":
		var dir, actorID, mode string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actorID = takeFlag(rest, "--actor", "")
		rest, mode = takeFlag(rest, "--default", "")
		if dir == "" || actorID == "" || (mode != "true" && mode != "false") {
			return errors.New("actor addressing requires --dir, --actor, --default true|false")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		res, err := cl.SubmitActorAddressing(ctx, sess, actorID, mode == "true")
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(res)

	default:
		return fmt.Errorf("unknown actor subcommand %q", sub)
	}
}

func ldrCallExtraCLI(sub string, rest []string, out io.Writer) error {
	switch sub {
	case "bye":
		var dir, from, callID string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		if dir == "" || from == "" {
			return errors.New("call bye requires --dir and --from")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, err := cl.SubmitCallBye(ctx, sess, from, cid)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"op_id": res.OpID, "seq": res.Seq, "call": cid, "status": cl.State().Calls[cid].Status()})

	case "note":
		var dir, from, callID, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, body = takeFlag(rest, "--body", "")
		if dir == "" || from == "" || body == "" {
			return errors.New("call note requires --dir, --from, --body")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, err := cl.SubmitCallNote(ctx, sess, from, cid, body)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"op_id": res.OpID, "seq": res.Seq, "call": cid})

	case "status":
		var dir, from, callID, state, reason, related string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, state = takeFlag(rest, "--state", "")
		rest, reason = takeFlag(rest, "--reason", "")
		rest, related = takeFlag(rest, "--related", "")
		if dir == "" || from == "" || state == "" || reason == "" {
			return errors.New("call status requires --dir, --from, --state, --reason")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, err := cl.SubmitCallStatus(ctx, sess, from, cid, state, reason, related)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"op_id": res.OpID, "seq": res.Seq, "call": cid, "state": state})

	case "attach":
		var dir, from, callID, path string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, path = takeFlag(rest, "--path", "")
		if dir == "" || from == "" || path == "" {
			return errors.New("call attach requires --dir, --from, --path")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, err := cl.SubmitCallAttach(ctx, sess, from, cid, filepath.Base(path), data)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"op_id": res.OpID, "seq": res.Seq, "call": cid, "name": filepath.Base(path)})

	case "ratify":
		var dir, opKeyPath, callID, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, opKeyPath = takeFlag(rest, "--operator-key", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, body = takeFlag(rest, "--body", "")
		if dir == "" || opKeyPath == "" || callID == "" || body == "" {
			return errors.New("call ratify requires --dir, --operator-key, --call, --body")
		}
		opKM, err := ldrclient.LoadSigningKey(opKeyPath)
		if err != nil {
			return err
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		cl.AttachOperatorKey(opKM)
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalOperator); err != nil {
			return err
		}
		res, err := cl.SubmitCallRatify(ctx, sess, callID, body)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(res)

	case "dispute":
		var dir, from, callID, claim string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, claim = takeFlag(rest, "--claim", "")
		if dir == "" || from == "" || claim == "" {
			return errors.New("call dispute requires --dir, --from, --claim")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, dispID, err := cl.SubmitDisputeOpen(ctx, sess, from, cid, claim)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"op_id": res.OpID, "seq": res.Seq, "call": cid, "dispute": dispID})

	case "measure":
		var dir, from, callID, dispID, cmd string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, dispID = takeFlag(rest, "--dispute", "")
		rest, cmd = takeFlag(rest, "--cmd", "")
		if dir == "" || from == "" || dispID == "" || cmd == "" {
			return errors.New("call measure requires --dir, --from, --dispute, --cmd")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, err := cl.SubmitDisputeMeasure(ctx, sess, from, cid, dispID, cmd)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(res)

	case "resolve":
		var dir, from, callID, dispID, kind, detail string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, dispID = takeFlag(rest, "--dispute", "")
		rest, kind = takeFlag(rest, "--kind", "measured")
		rest, detail = takeFlag(rest, "--detail", "")
		if dir == "" || from == "" || dispID == "" || detail == "" {
			return errors.New("call resolve requires --dir, --from, --dispute, --detail")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID(from, callID)
		if err != nil {
			return err
		}
		res, err := cl.SubmitDisputeResolve(ctx, sess, from, cid, dispID, kind, detail)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(res)

	case "read":
		var dir, callID string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, callID = takeFlag(rest, "--call", "")
		if dir == "" || callID == "" {
			return errors.New("call read requires --dir and --call")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Sync(ctx, sess); err != nil {
			return err
		}
		cid, err := cl.ResolveCallID("", callID)
		if err != nil {
			return err
		}
		tr, err := cl.ReadCallTranscript(ctx, sess, cid)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(tr)

	case "list":
		var dir, actor string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actor = takeFlag(rest, "--actor", "")
		all := hasFlag(rest, "--all")
		if dir == "" {
			return errors.New("call list requires --dir")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Sync(ctx, sess); err != nil {
			return err
		}
		sums, err := cl.ListCallSummaries(ctx, sess, actor, all)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(sums)

	default:
		return fmt.Errorf("unknown call subcommand %q", sub)
	}
}

func ldrBroadcastCLI(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yip ldr broadcast <create|list|read|reply> --dir <client-dir> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		var dir, opKeyPath, bid, kind, toCSV, by, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, opKeyPath = takeFlag(rest, "--operator-key", "")
		rest, bid = takeFlag(rest, "--id", "")
		rest, kind = takeFlag(rest, "--kind", "briefing")
		rest, toCSV = takeFlag(rest, "--to", "")
		rest, by = takeFlag(rest, "--by", "operator")
		rest, body = takeFlag(rest, "--body", "")
		defAud := hasFlag(rest, "--default-audience")
		if dir == "" || opKeyPath == "" || body == "" {
			return errors.New("broadcast create requires --dir, --operator-key, --body")
		}
		if bid == "" {
			bid = requestID()
		}
		var recips []string
		for _, a := range strings.Split(toCSV, ",") {
			if a = strings.TrimSpace(a); a != "" {
				recips = append(recips, a)
			}
		}
		if len(recips) == 0 {
			defAud = true
		}
		opKM, err := ldrclient.LoadSigningKey(opKeyPath)
		if err != nil {
			return err
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		cl.AttachOperatorKey(opKM)
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalOperator); err != nil {
			return err
		}
		res, err := cl.SubmitBroadcastCreate(ctx, sess, bid, kind, by, body, recips, defAud)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"id": bid, "op_id": res.OpID, "seq": res.Seq})

	case "list":
		var dir, actor string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actor = takeFlag(rest, "--actor", "")
		all := hasFlag(rest, "--all")
		if dir == "" {
			return errors.New("broadcast list requires --dir")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Sync(ctx, sess); err != nil {
			return err
		}
		bvs, err := cl.ListBroadcasts(ctx, sess, actor, all)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(bvs)

	case "read":
		var dir, actor, bid string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actor = takeFlag(rest, "--actor", "")
		rest, bid = takeFlag(rest, "--id", "")
		if dir == "" || actor == "" || bid == "" {
			return errors.New("broadcast read requires --dir, --actor, --id")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		if _, err := cl.SubmitBroadcastRead(ctx, sess, actor, bid); err != nil {
			return err
		}
		bv, err := cl.ReadBroadcast(ctx, sess, actor, bid)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(bv)

	case "reply":
		var dir, actor, bid, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actor = takeFlag(rest, "--actor", "")
		rest, bid = takeFlag(rest, "--id", "")
		rest, body = takeFlag(rest, "--body", "")
		if dir == "" || actor == "" || bid == "" || body == "" {
			return errors.New("broadcast reply requires --dir, --actor, --id, --body")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		res, err := cl.SubmitBroadcastReply(ctx, sess, actor, bid, body)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(res)

	default:
		return fmt.Errorf("unknown broadcast subcommand %q", sub)
	}
}

func ldrRegisterCLI(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yip ldr register <put|list> --dir <client-dir> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "put":
		var dir, actor, reg, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, actor = takeFlag(rest, "--actor", "")
		rest, reg = takeFlag(rest, "--register", "")
		rest, body = takeFlag(rest, "--body", "")
		if dir == "" || actor == "" || reg == "" || body == "" {
			return errors.New("register put requires --dir, --actor, --register, --body")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.PrepareForMutation(ctx, sess, ldrcrypto.PrincipalCredential); err != nil {
			return err
		}
		rep, err := cl.PublishRegister(ctx, sess, actor, reg, []byte(body))
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(rep)

	case "list":
		var dir, reg string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, reg = takeFlag(rest, "--register", "")
		if dir == "" {
			return errors.New("register list requires --dir")
		}
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		cl, err := ldrclient.OpenClientWait(ctx, dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Sync(ctx, sess); err != nil {
			return err
		}
		regs, err := cl.ReadRegisters(ctx, sess, reg)
		if err != nil {
			return err
		}
		type item struct {
			Actor        string `json:"actor"`
			Register     string `json:"register"`
			WriterRev    uint64 `json:"writer_rev"`
			Counter      uint64 `json:"counter"`
			AcceptedAtMS uint64 `json:"accepted_at_ms"`
			Historical   bool   `json:"historical"`
			ReadStatus   string `json:"read_status"`
			Body         string `json:"body,omitempty"`
		}
		items := make([]item, len(regs))
		for i, r := range regs {
			items[i] = item{
				Actor:        r.Actor,
				Register:     r.Register,
				WriterRev:    r.WriterRev,
				Counter:      r.Counter,
				AcceptedAtMS: r.AcceptedAtMS,
				Historical:   r.Historical,
				ReadStatus:   r.ReadStatus,
				Body:         string(r.Plaintext),
			}
		}
		return json.NewEncoder(out).Encode(items)

	default:
		return fmt.Errorf("unknown register subcommand %q", sub)
	}
}
