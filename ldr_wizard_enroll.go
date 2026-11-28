package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
)

const invitePurpose = "yip.ldr.workstation-invitation"

type wizardInvitation struct {
	Version    int    `json:"version"`
	ID         []byte `json:"invitation_id"`
	Descriptor []byte `json:"signed_descriptor"`
	Operator   string `json:"operator_public_key"`
	Namespace  string `json:"namespace"`
	Limit      uint64 `json:"actor_limit"`
	Reader     bool   `json:"reader"`
	Signature  []byte `json:"signature"`
}

func (v wizardInvitation) body() ([]byte, error) {
	return ldrcrypto.MarshalCBOR([]any{uint64(1), v.ID, v.Descriptor, v.Operator, v.Namespace, v.Limit, v.Reader})
}

func (v wizardInvitation) validate() (ldrcrypto.CreationDescriptor, [32]byte, error) {
	desc, d, _, _, err := ldrcrypto.VerifyCreationDescriptor(v.Descriptor)
	if err != nil {
		return desc, d, err
	}
	if v.Version != 1 || len(v.ID) != 16 || len(v.Namespace) > 128 || strings.IndexFunc(v.Namespace, unicode.IsControl) >= 0 {
		return desc, d, errors.New("invalid workstation invitation")
	}
	if err = (ldrcrypto.JoinGrant{NamespaceID: v.Namespace, ActorLimit: v.Limit, Reader: v.Reader}).Validate(); err != nil {
		return desc, d, err
	}
	pk, err := ldrrelay.ParseKeyToken(v.Operator)
	if err != nil {
		return desc, d, err
	}
	body, err := v.body()
	if err != nil {
		return desc, d, err
	}
	return desc, d, ldrcrypto.VerifyDomain(pk, invitePurpose, 1, body, v.Signature)
}

type wizardAuthority struct{ Admin, Key string }

func (w wizardArgs) createInvite() (string, error) {
	if w.setupDir == "" && w.admin == "" && w.operator == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		w.setupDir = filepath.Join(home, ".yip-ldr", "setup")
	}
	if w.setupDir != "" {
		if w.admin != "" || w.operator != "" {
			return "", errors.New("choose either an operator setup folder or an existing administrative client and signing key")
		}
		var custody wizardCustody
		if err := wizardLoad(filepath.Join(w.setupDir, "custody.json"), &custody); err != nil {
			return "", err
		}
		w.admin = filepath.Join(w.setupDir, "admin")
		w.operator = custody.Operator
	}
	if w.admin == "" || w.operator == "" || w.namespace == "" {
		return "", errors.New("choose the operator client directory, signing key and workstation namespace")
	}
	admin, err := filepath.Abs(w.admin)
	if err != nil {
		return "", err
	}
	key, err := filepath.Abs(w.operator)
	if err != nil {
		return "", err
	}
	auth := wizardAuthority{admin, key}
	km, err := ldrclient.LoadSigningKey(key)
	if err != nil {
		return "", err
	}
	token, err := ldrrelay.KeyToken(km.Signer.PublicKey())
	if err != nil {
		return "", err
	}
	cl, err := ldrclient.OpenClient(admin)
	if err != nil {
		return "", err
	}
	defer cl.Close()
	if cl.Status().DirKind != ldrclient.DirKindAdmin {
		return "", errors.New("choose the administrator's enrolled client directory")
	}
	line, err := wizardAnchor(cl, km, false)
	if err != nil {
		return "", err
	}
	if !slices.Contains(line.Operators, token) {
		return "", errors.New("this key is not an active operator")
	}
	id, haveID := cl.CredID()
	own := line.Credentials[ldrrelay.CredToken(id)]
	if !haveID || own == nil || own.Revoked || !own.Reader {
		return "", errors.New("initialize the operator reader before inviting a workstation")
	}
	inv := wizardInvitation{Version: 1, Descriptor: cl.SignedDescriptor(), Operator: token, Namespace: w.namespace, Limit: w.limit, Reader: !w.noReader}
	saved := w.path("invitation.yip")
	var prev wizardInvitation
	if err = wizardLoad(saved, &prev); err == nil {
		inv.ID = prev.ID
		inv.Signature = prev.Signature
	} else if errors.Is(err, os.ErrNotExist) {
		for _, credential := range line.Credentials {
			if credential.Namespace == inv.Namespace {
				return "", fmt.Errorf("workstation name %q is already reserved on this line", inv.Namespace)
			}
		}
		inv.ID = make([]byte, 16)
		if _, err = rand.Read(inv.ID); err != nil {
			return "", err
		}
		body, e := inv.body()
		if e != nil {
			return "", e
		}
		inv.Signature, err = ldrcrypto.SignDomain(km.Signer, invitePurpose, 1, body)
		if err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	if _, _, err = inv.validate(); err != nil {
		return "", fmt.Errorf("check the invitation settings or use a fresh workspace: %w", err)
	}
	if err = wizardRecord(w.path("authority.json"), auth); err != nil {
		return "", err
	}
	if err = wizardRecord(saved, inv); err != nil {
		return "", err
	}
	dst := w.shared("invitation.yip")
	if err = wizardCopy(saved, dst); err != nil {
		return "", err
	}
	return fmt.Sprintf("Send %s to the owner of %q over an authenticated channel. They open Join a line and return a request.", dst, inv.Namespace), nil
}

func wizardSnapshot(src, dir string) (string, func(), error) {
	b, err := wizardRead(src)
	if err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(dir, ".received-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.Remove(f.Name()) }
	_, err = f.Write(b)
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return f.Name(), cleanup, nil
}

func (w wizardArgs) inviting() (string, error) {
	if w.step == "invite" {
		return w.createInvite()
	}
	var inv wizardInvitation
	if err := wizardLoad(w.path("invitation.yip"), &inv); err != nil {
		return "", err
	}
	desc, d, err := inv.validate()
	if err != nil {
		return "", err
	}
	var auth wizardAuthority
	if err = wizardLoad(w.path("authority.json"), &auth); err != nil {
		return "", err
	}
	km, err := ldrclient.LoadSigningKey(auth.Key)
	if err != nil {
		return "", err
	}
	token, err := ldrrelay.KeyToken(km.Signer.PublicKey())
	if err != nil || token != inv.Operator {
		return "", errors.New("operator key differs from this invitation")
	}
	reqPath := w.path("reviewed.cbor")
	src := reqPath
	if w.step == "review" {
		tmp, clean, e := wizardSnapshot(w.input, w.workspace)
		if e != nil {
			return "", e
		}
		defer clean()
		src = tmp
	}
	req, dig, err := ldrclient.LoadJoinRequest(src)
	if err != nil {
		return "", err
	}
	if req.DescriptorDigest != d || !bytes.Equal(req.LineID, desc.LineID) || req.Generation != desc.Generation || !bytes.Equal(req.RequestID, inv.ID) || req.Grant.NamespaceID != inv.Namespace || req.Grant.ActorLimit != inv.Limit || req.Grant.Reader != inv.Reader || len(req.Grant.Capabilities) != 0 {
		return "", errors.New("request differs from this invitation or its offered permissions")
	}
	code := wizardCode(dig)
	switch w.step {
	case "review":
		if err = ldrclient.SaveJoinRequest(reqPath, req); err != nil {
			return "", err
		}
		return fmt.Sprintf("Line %x at %s\nWorkstation %q · up to %d actors · receives encrypted content: %t\nWorkstation code %s\nConfirm the code with its owner over your trusted channel. Choose Approve workstation to grant these permissions.", desc.LineID, desc.RelayOrigin.URL, inv.Namespace, inv.Limit, inv.Reader, code), nil
	case "approve":
		if !strings.EqualFold(w.code, code) {
			return "", errors.New("enter the matching code from the workstation owner")
		}
		if err = w.challenge(auth.Key, reqPath, dig); err != nil {
			return "", err
		}
		dst := w.shared("challenge.cbor")
		if err = wizardCopy(w.path("challenge.cbor"), dst); err != nil {
			return "", err
		}
		return fmt.Sprintf("Send %s to the workstation. Ask the owner to return the proof.", dst), nil
	default:
		tmp, clean, e := wizardSnapshot(w.input, w.workspace)
		if e != nil {
			return "", e
		}
		defer clean()
		if err = w.enroll(auth, reqPath, tmp); err != nil {
			return "", err
		}
		return fmt.Sprintf("Enrolled %q. The owner can now choose Activate workstation.", inv.Namespace), nil
	}
}

func (w wizardArgs) challenge(key, req string, digest [32]byte) error {
	ch := w.path("challenge.cbor")
	exists, err := wizardExists(ch)
	if err != nil || exists {
		return err
	}
	return wizardLDR("join", "challenge", "--operator-key", key, "--request", req, "--expect-request", hex.EncodeToString(digest[:]), "--out-challenge", ch, "--out-secret", w.path("secret.cbor"))
}

func wizardAnchor(cl *ldrclient.Client, km *ldrclient.SigningKeyMaterial, root bool, retry ...string) (ldrcore.Line, error) {
	role := ldrcrypto.PrincipalOperator
	principal := ldrcrypto.OperatorPrincipal(km.Signer.PublicKey())
	if root {
		role = ldrcrypto.PrincipalRoot
		principal = ldrcrypto.RootPrincipal(km.Signer.PublicKey())
		cl.AttachRootKey(km)
	} else {
		cl.AttachOperatorKey(km)
	}
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	s, err := cl.Dial(ctx, role)
	if err != nil {
		return ldrcore.Line{}, err
	}
	defer s.Close()
	if err = cl.ResolveAll(ctx, s, principal); err != nil {
		return ldrcore.Line{}, err
	}
	status := cl.Status()
	if status.Suspect || status.Halted != "" {
		return ldrcore.Line{}, ldrclient.ErrFailClosed
	}
	// A crash can leave the original signed bytes in the outbox before the
	// first send. Retry only this ceremony's operations under their signer.
	signer, err := ldrrelay.PrincipalToken(principal)
	if err != nil {
		return ldrcore.Line{}, err
	}
	for _, entry := range cl.OutboxSnapshot() {
		if entry.Status != ldrcore.OutPending || entry.SignerToken != signer || !slices.Contains(retry, entry.Action) {
			continue
		}
		rep, e := cl.Send(ctx, s, entry.OpID)
		if e != nil {
			return ldrcore.Line{}, e
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return ldrcore.Line{}, fmt.Errorf("saved %s received %s %s %s", entry.OpType, rep.Class, rep.Code, rep.Outcome.Reason)
		}
	}
	ar, err := cl.Anchor(ctx, s)
	if err != nil {
		if root && ar.Class == ldrcore.ClassAdmission && ar.Code == "no_line" && cl.State().Line.Generation == 0 {
			return cl.State().Line, nil
		}
		return ldrcore.Line{}, err
	}
	return cl.State().Line, nil
}

func wizardMembership(auth wizardAuthority, km *ldrclient.SigningKeyMaterial, req ldrcrypto.JoinRequest, d [32]byte) (enrolled, ready bool, err error) {
	cl, err := ldrclient.OpenClient(auth.Admin)
	if err != nil {
		return false, false, err
	}
	defer cl.Close()
	_, cd, _, _ := cl.Descriptor()
	if cd != req.DescriptorDigest {
		return false, false, errors.New("operator directory belongs to another line")
	}
	line, err := wizardAnchor(cl, km, false, fmt.Sprintf("wizard-enroll:%x", d), fmt.Sprintf("wizard-epoch:%x", d))
	if err != nil {
		return false, false, err
	}
	id := ldrrelay.CredToken(req.CredID)
	cr := line.Credentials[id]
	if cr == nil {
		return false, false, nil
	}
	matched, rekeyed := cl.EnrollmentProgress(id, hex.EncodeToString(req.RequestID), hex.EncodeToString(d[:]))
	if cr.Revoked || !matched {
		return false, false, errors.New("credential retired or enrolled with a different request")
	}
	return true, rekeyed && (!cr.Reader || slices.Contains(line.Readers[line.KeyEpoch], id)), nil
}

func (w wizardArgs) enroll(auth wizardAuthority, reqPath, proofPath string) error {
	req, d, err := ldrclient.LoadJoinRequest(reqPath)
	if err != nil {
		return err
	}
	km, err := ldrclient.LoadSigningKey(auth.Key)
	if err != nil {
		return err
	}
	sec, ch, err := ldrclient.LoadJoinSecretWithChallenge(w.path("secret.cbor"))
	if err != nil {
		return err
	}
	proof, err := ldrclient.LoadJoinProof(proofPath)
	if err != nil {
		return err
	}
	if err = ldrcrypto.VerifyJoinProof(km.Signer.PublicKey(), req, ch, sec, proof); err != nil {
		return err
	}
	unlock, err := fileGuard(filepath.Join(auth.Admin, ".wizard-admission"))
	if err != nil {
		return err
	}
	defer unlock()
	enrolled, active, err := wizardMembership(auth, km, req, d)
	if err != nil {
		return err
	}
	if !enrolled {
		if err = ldrJoinAction([]string{"enroll", "--dir", auth.Admin, "--operator-key", auth.Key, "--request", reqPath, "--challenge", w.path("challenge.cbor"), "--secret", w.path("secret.cbor"), "--proof", proofPath}, io.Discard, fmt.Sprintf("wizard-enroll:%x", d)); err != nil {
			return err
		}
	}
	if !active {
		if err = ldrEpochAction([]string{"activate", "--dir", auth.Admin, "--operator-key", auth.Key}, io.Discard, fmt.Sprintf("wizard-epoch:%x", d), func(cl *ldrclient.Client) bool {
			_, active := cl.EnrollmentProgress(ldrrelay.CredToken(req.CredID), hex.EncodeToString(req.RequestID), hex.EncodeToString(d[:]))
			return active
		}); err != nil {
			return err
		}
	}
	enrolled, active, err = wizardMembership(auth, km, req, d)
	if err != nil {
		return err
	}
	if !enrolled || !active {
		return errors.New("waiting for verified membership and reader epoch")
	}
	return nil
}

func (w wizardArgs) joining() (string, error) {
	dir := w.path("client")
	reqPath := filepath.Join(dir, "request.cbor")
	if w.step == "join" {
		var inv wizardInvitation
		if err := wizardLoad(w.input, &inv); err != nil {
			return "", err
		}
		desc, d, err := inv.validate()
		if err != nil {
			return "", err
		}
		if err = wizardRecord(w.path("invitation.yip"), inv); err != nil {
			return "", err
		}
		err = wizardInitDir(dir, func(tmp string) error {
			ck, e := ldrclient.GenerateCredentialKeys(ldrcrypto.AlgEd25519)
			if e != nil {
				return e
			}
			grant := ldrcrypto.JoinGrant{NamespaceID: inv.Namespace, ActorLimit: inv.Limit, Reader: inv.Reader}
			req, e := ldrcrypto.SignJoinRequest(ck.Signing.Signer, ldrcrypto.JoinRequest{RequestID: inv.ID, LineID: desc.LineID, Generation: desc.Generation, DescriptorDigest: d, Grant: grant, EncryptionKey: ck.Encryption.PublicKey()})
			if e != nil {
				return e
			}
			digest, e := ldrcrypto.VerifyJoinRequest(req)
			if e != nil {
				return e
			}
			cl, e := ldrclient.InitClientDir(ldrclient.InitDirOptions{Dir: tmp, DirKind: ldrclient.DirKindMember, SignedDescriptor: inv.Descriptor, CredKeys: ck, ExpectedGrant: &grant, ExpectedJoinReq: inv.ID, ExpectedJoinReqDigest: &digest})
			if e != nil {
				return e
			}
			cl.Close()
			return ldrclient.SaveJoinRequest(filepath.Join(tmp, "request.cbor"), req)
		})
		if err != nil {
			return "", err
		}
		_, digest, err := ldrclient.LoadJoinRequest(reqPath)
		if err != nil {
			return "", err
		}
		dst := w.shared("request.cbor")
		if err = wizardCopy(reqPath, dst); err != nil {
			return "", err
		}
		return fmt.Sprintf("Joining %s as %q · up to %d actors · receives encrypted content: %t\nSend %s to the operator. Confirm this workstation code with them: %s", desc.RelayOrigin.URL, inv.Namespace, inv.Limit, inv.Reader, dst, wizardCode(digest)), nil
	}
	if w.step == "prove" {
		var inv wizardInvitation
		if err := wizardLoad(w.path("invitation.yip"), &inv); err != nil {
			return "", err
		}
		if _, _, err := inv.validate(); err != nil {
			return "", err
		}
		pub, err := hex.DecodeString(inv.Operator)
		if err != nil {
			return "", err
		}
		if err = wizardSave(w.path("operator.pub"), pub); err != nil {
			return "", err
		}
		tmp, clean, err := wizardSnapshot(w.input, w.workspace)
		if err != nil {
			return "", err
		}
		defer clean()
		dst := w.shared("proof.cbor")
		if err = wizardLDR("join", "prove", "--dir", dir, "--operator-pub", w.path("operator.pub"), "--request", reqPath, "--challenge", tmp, "--out", dst); err != nil {
			return "", err
		}
		return fmt.Sprintf("Send %s back to the operator. Choose Activate workstation after they confirm enrollment.", dst), nil
	}
	if err := wizardLDR("join", "activate", "--dir", dir); err != nil {
		return "", fmt.Errorf("activation needs a verified enrollment and any granted reader key: %w", err)
	}
	if err := wizardLDR("sync", "--dir", dir, "--project", "--scan"); err != nil {
		return "", err
	}
	cl, err := ldrclient.OpenClient(dir)
	if err != nil {
		return "", err
	}
	defer cl.Close()
	s := cl.Status()
	return fmt.Sprintf("Active on line %s at verified checkpoint %d. Client directory: %s\nNext, declare an actor and attach your local line in Connect to a Relay.", s.LineID, s.CheckpointSeq, dir), nil
}
