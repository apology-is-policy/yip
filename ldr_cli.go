package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrcrypto"
)

const ldrUsage = `yip ldr -- Long Distance Relay client, equal-roots admin, and P3 enrollment ceremony.

  ROOT & LINE BOOTSTRAP (equal 1-of-2 roots, Ed25519 or ECDSA P-256)
    yip ldr root keygen --out <keyfile> [--pub <pubfile>] [--alg ed25519|ecdsa-p256-sha256]
    yip ldr root descriptor --line-id <hex|auto> --root1 <file> --root2 <file> \
        --url <https://...> --tls-policy <pin_spki_sha256|pin_ca_root_pem|webpki> \
        [--tls-pin <hex-or-pem-file>] --signer <root-keyfile> --out <desc.cbor>
    yip ldr root init-line --dir <client-dir> --descriptor <desc.cbor> --root-key <file>
    yip ldr root authorize-operator --dir <client-dir> --root-key <file> --operator-pub <file>
    yip ldr root replace-root --dir <client-dir> --root-key <file> --old-root-pub <file> --new-root-pub <file>

  P3 KEY-FIRST ENROLLMENT & O25 FULL-REPLAY ONBOARDING
    yip ldr join request --dir <client-dir> --descriptor <desc.cbor> --namespace <ns> [--actor-limit 4] [--reader] --out <req.cbor>
    yip ldr join challenge --operator-key <file> --request <req.cbor> --out-challenge <ch.cbor> --out-secret <sec.cbor>
    yip ldr join prove --dir <client-dir> --operator-pub <file> --request <req.cbor> --challenge <ch.cbor> --out <proof.cbor>
    yip ldr join enroll --dir <client-dir> --operator-key <file> --request <req.cbor> --challenge <ch.cbor> --secret <sec.cbor> --proof <proof.cbor>
    yip ldr join activate --dir <client-dir>

  EPOCHS, SYNC, ACTORS, CALLS & STATUS (host-local resource leases stay local)
    yip ldr epoch activate --dir <client-dir> --operator-key <file>
    yip ldr sync --dir <client-dir> [--role credential|operator|root] [--key <file>] [--project] [--scan]
    yip ldr actor declare --dir <client-dir> --actor <id> [--namespace <ns>]
    yip ldr call open --dir <client-dir> --from <actor> --to <actor> --call <id> --subject <text> --body <text>
    yip ldr call say --dir <client-dir> --from <actor> --call <id> --body <text>
    yip ldr status --dir <client-dir>
`

// LDRCLI dispatches `yip ldr <group> <subcommand> ...`.
func LDRCLI(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(out, ldrUsage)
		return nil
	}
	group, rest := args[0], args[1:]
	switch group {
	case "root":
		return ldrRootCLI(rest, out)
	case "join":
		return ldrJoinCLI(rest, out)
	case "epoch":
		return ldrEpochCLI(rest, out)
	case "sync":
		return ldrSyncCLI(rest, out)
	case "actor":
		return ldrActorCLI(rest, out)
	case "call":
		return ldrCallCLI(rest, out)
	case "status":
		return ldrStatusCLI(rest, out)
	default:
		return fmt.Errorf("unknown ldr command %q\n\n%s", group, ldrUsage)
	}
}

func ldrTimeoutCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func ldrRootCLI(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yip ldr root <keygen|descriptor|init-line|authorize-operator|replace-root>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "keygen":
		var outPath, pubPath, alg string
		rest, outPath = takeFlag(rest, "--out", "")
		rest, pubPath = takeFlag(rest, "--pub", "")
		rest, alg = takeFlag(rest, "--alg", ldrcrypto.AlgEd25519)
		if outPath == "" {
			return errors.New("root keygen requires --out <keyfile>")
		}
		km, err := ldrclient.GenerateSigningKey(alg)
		if err != nil {
			return err
		}
		if err := ldrclient.SaveSigningKey(outPath, km); err != nil {
			return err
		}
		if pubPath != "" {
			if err := ldrclient.SavePublicKey(pubPath, km.Signer.PublicKey()); err != nil {
				return err
			}
		}
		fp, err := ldrclient.KeyFingerprint(km.Signer.PublicKey())
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"key":         outPath,
			"pub":         pubPath,
			"alg":         km.Alg,
			"fingerprint": fp,
		})

	case "descriptor":
		var lineHex, r1Path, r2Path, rawURL, tlsPol, tlsPinArg, signerPath, outPath string
		rest, lineHex = takeFlag(rest, "--line-id", "auto")
		rest, r1Path = takeFlag(rest, "--root1", "")
		rest, r2Path = takeFlag(rest, "--root2", "")
		rest, rawURL = takeFlag(rest, "--url", "")
		rest, tlsPol = takeFlag(rest, "--tls-policy", ldrcrypto.TLSPolicyPinSPKISHA256)
		rest, tlsPinArg = takeFlag(rest, "--tls-pin", "")
		rest, signerPath = takeFlag(rest, "--signer", "")
		rest, outPath = takeFlag(rest, "--out", "")
		if r1Path == "" || r2Path == "" || rawURL == "" || signerPath == "" || outPath == "" {
			return errors.New("root descriptor requires --root1, --root2, --url, --signer, --out")
		}
		var lineID []byte
		if lineHex == "auto" {
			lineID = make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, lineID); err != nil {
				return err
			}
		} else {
			var err error
			lineID, err = hex.DecodeString(lineHex)
			if err != nil {
				return err
			}
		}
		pk1, err := ldrclient.LoadPublicKey(r1Path)
		if err != nil {
			return err
		}
		pk2, err := ldrclient.LoadPublicKey(r2Path)
		if err != nil {
			return err
		}
		signerKM, err := ldrclient.LoadSigningKey(signerPath)
		if err != nil {
			return err
		}
		var tlsPin []byte
		switch tlsPol {
		case ldrcrypto.TLSPolicyPinSPKISHA256:
			tlsPin, err = hex.DecodeString(strings.TrimSpace(tlsPinArg))
			if err != nil {
				return fmt.Errorf("invalid hex --tls-pin: %w", err)
			}
		case ldrcrypto.TLSPolicyPinCARootPEM:
			tlsPin, err = os.ReadFile(tlsPinArg)
			if err != nil {
				return err
			}
		case ldrcrypto.TLSPolicyWebPKI:
			tlsPin = nil
		default:
			return fmt.Errorf("unsupported --tls-policy %q", tlsPol)
		}
		desc := ldrcrypto.CreationDescriptor{
			Version:    1,
			LineID:     lineID,
			Generation: 1,
			RootKeys:   []ldrcrypto.PublicKey{pk1, pk2},
			RelayOrigin: ldrcrypto.RelayOrigin{
				URL:            rawURL,
				TLSPolicy:      tlsPol,
				TLSPin:         tlsPin,
				SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
			},
			Profile: ldrcrypto.ProfileV1(),
		}
		signed, err := ldrcrypto.SignCreationDescriptor(signerKM.Signer, desc)
		if err != nil {
			return err
		}
		raw, err := signed.MarshalCanonical()
		if err != nil {
			return err
		}
		_, cd, genesis, _, err := ldrcrypto.VerifyCreationDescriptor(raw)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(outPath, raw, 0o644); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"descriptor":        outPath,
			"line_id":           hex.EncodeToString(lineID),
			"descriptor_digest": hex.EncodeToString(cd[:]),
			"genesis_anchor":    hex.EncodeToString(genesis[:]),
		})

	case "init-line":
		var dir, descPath, rootKeyPath string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, descPath = takeFlag(rest, "--descriptor", "")
		rest, rootKeyPath = takeFlag(rest, "--root-key", "")
		if dir == "" || descPath == "" || rootKeyPath == "" {
			return errors.New("root init-line requires --dir, --descriptor, --root-key")
		}
		rawDesc, err := os.ReadFile(descPath)
		if err != nil {
			return err
		}
		rootKM, err := ldrclient.LoadSigningKey(rootKeyPath)
		if err != nil {
			return err
		}
		cl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
			Dir: dir, DirKind: ldrclient.DirKindAdmin, SignedDescriptor: rawDesc, Activated: true,
		})
		if err != nil {
			return err
		}
		defer cl.Close()
		cl.AttachRootKey(rootKM)

		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalRoot)
		if err != nil {
			return err
		}
		defer sess.Close()
		desc, cd, _, _ := cl.Descriptor()
		rk0, _ := desc.RootKeys[0].ToCBOR()
		rk1, _ := desc.RootKeys[1].ToCBOR()
		profMap, _ := desc.Profile.ToCBORMap()
		opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
			Action: "line_init", Origin: ldrcore.OriginRoot, OpType: "line_init",
			Fields: ldrcrypto.Map{
				{Key: "descriptor_digest", Value: cd[:]},
				{Key: "profile", Value: profMap},
				{Key: "root_keys", Value: []any{rk0, rk1}},
			},
		})
		if err != nil {
			return err
		}
		rep, err := cl.Send(ctx, sess, opID)
		if err != nil {
			return err
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return fmt.Errorf("line_init did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
		}
		if _, err := cl.Sync(ctx, sess); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"op_id": opID, "seq": rep.Outcome.Seq, "head": hex.EncodeToString(rep.Head[:]),
		})

	case "authorize-operator":
		var dir, rootKeyPath, opPubPath string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, rootKeyPath = takeFlag(rest, "--root-key", "")
		rest, opPubPath = takeFlag(rest, "--operator-pub", "")
		if dir == "" || rootKeyPath == "" || opPubPath == "" {
			return errors.New("root authorize-operator requires --dir, --root-key, --operator-pub")
		}
		rootKM, err := ldrclient.LoadSigningKey(rootKeyPath)
		if err != nil {
			return err
		}
		opPub, err := ldrclient.LoadPublicKey(opPubPath)
		if err != nil {
			return err
		}
		opCBOR, err := opPub.ToCBOR()
		if err != nil {
			return err
		}
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		cl.AttachRootKey(rootKM)

		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalRoot)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Anchor(ctx, sess); err != nil {
			return err
		}
		st := cl.State()
		opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
			Action: "authorize_operator", Origin: ldrcore.OriginRoot, OpType: "operator_key_authorize",
			Expect: ldrcrypto.ExpectMap{"root_rev": uint64(st.Line.RootRev)},
			Fields: ldrcrypto.Map{{Key: "operator_key", Value: opCBOR}},
		})
		if err != nil {
			return err
		}
		rep, err := cl.Send(ctx, sess, opID)
		if err != nil {
			return err
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return fmt.Errorf("operator_key_authorize did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
		}
		_, _ = cl.Sync(ctx, sess)
		return json.NewEncoder(out).Encode(map[string]any{"op_id": opID, "seq": rep.Outcome.Seq})

	case "replace-root":
		var dir, rootKeyPath, oldPath, newPath string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, rootKeyPath = takeFlag(rest, "--root-key", "")
		rest, oldPath = takeFlag(rest, "--old-root-pub", "")
		rest, newPath = takeFlag(rest, "--new-root-pub", "")
		if dir == "" || rootKeyPath == "" || oldPath == "" || newPath == "" {
			return errors.New("root replace-root requires --dir, --root-key, --old-root-pub, --new-root-pub")
		}
		rootKM, err := ldrclient.LoadSigningKey(rootKeyPath)
		if err != nil {
			return err
		}
		oldPK, err := ldrclient.LoadPublicKey(oldPath)
		if err != nil {
			return err
		}
		newPK, err := ldrclient.LoadPublicKey(newPath)
		if err != nil {
			return err
		}
		oldC, err := oldPK.ToCBOR()
		if err != nil {
			return err
		}
		newC, err := newPK.ToCBOR()
		if err != nil {
			return err
		}
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		cl.AttachRootKey(rootKM)

		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalRoot)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Anchor(ctx, sess); err != nil {
			return err
		}
		st := cl.State()
		opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
			Action: "replace_root", Origin: ldrcore.OriginRoot, OpType: "root_member_replace",
			Expect: ldrcrypto.ExpectMap{"root_rev": uint64(st.Line.RootRev)},
			Fields: ldrcrypto.Map{{Key: "new_root_key", Value: newC}, {Key: "old_root_key", Value: oldC}},
		})
		if err != nil {
			return err
		}
		rep, err := cl.Send(ctx, sess, opID)
		if err != nil {
			return err
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return fmt.Errorf("root_member_replace did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
		}
		_, _ = cl.Sync(ctx, sess)
		return json.NewEncoder(out).Encode(map[string]any{"op_id": opID, "seq": rep.Outcome.Seq})

	default:
		return fmt.Errorf("unknown root subcommand %q", sub)
	}
}

func ldrJoinCLI(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yip ldr join <request|challenge|prove|enroll|activate>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "request":
		var dir, descPath, ns, limitStr, alg, outPath string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, descPath = takeFlag(rest, "--descriptor", "")
		rest, ns = takeFlag(rest, "--namespace", "")
		rest, limitStr = takeFlag(rest, "--actor-limit", "4")
		rest, alg = takeFlag(rest, "--alg", ldrcrypto.AlgEd25519)
		rest, outPath = takeFlag(rest, "--out", "")
		reader := hasFlag(rest, "--reader")
		if dir == "" || descPath == "" || ns == "" || outPath == "" {
			return errors.New("join request requires --dir, --descriptor, --namespace, --out")
		}
		limit, err := strconv.ParseUint(limitStr, 10, 64)
		if err != nil {
			return err
		}
		rawDesc, err := os.ReadFile(descPath)
		if err != nil {
			return err
		}
		desc, cd, _, _, err := ldrcrypto.VerifyCreationDescriptor(rawDesc)
		if err != nil {
			return err
		}
		credKeys, err := ldrclient.GenerateCredentialKeys(alg)
		if err != nil {
			return err
		}
		reqID := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, reqID); err != nil {
			return err
		}
		grant := ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: limit, Reader: reader}
		req, err := ldrcrypto.SignJoinRequest(credKeys.Signing.Signer, ldrcrypto.JoinRequest{
			RequestID:        reqID,
			LineID:           desc.LineID,
			Generation:       1,
			DescriptorDigest: cd,
			EncryptionKey:    credKeys.Encryption.PublicKey(),
			Grant:            grant,
		})
		if err != nil {
			return err
		}
		reqDig, err := ldrcrypto.VerifyJoinRequest(req)
		if err != nil {
			return err
		}
		cl, err := ldrclient.InitClientDir(ldrclient.InitDirOptions{
			Dir:                   dir,
			DirKind:               ldrclient.DirKindMember,
			SignedDescriptor:      rawDesc,
			CredKeys:              credKeys,
			ExpectedGrant:         &grant,
			ExpectedJoinReq:       reqID,
			ExpectedJoinReqDigest: &reqDig,
			Activated:             false,
		})
		if err != nil {
			return err
		}
		_ = cl.Close()
		if err := ldrclient.SaveJoinRequest(outPath, req); err != nil {
			return err
		}
		sigFP, _ := ldrclient.KeyFingerprint(req.SigningKey)
		encFP, _ := ldrclient.KeyFingerprint(req.EncryptionKey)
		return json.NewEncoder(out).Encode(map[string]any{
			"request":         outPath,
			"cred_id":         hex.EncodeToString(req.CredID[:]),
			"sig_fingerprint": sigFP,
			"enc_fingerprint": encFP,
			"namespace":       ns,
			"actor_limit":     limit,
			"reader":          reader,
		})

	case "challenge":
		var opKeyPath, reqPath, outCh, outSec string
		rest, opKeyPath = takeFlag(rest, "--operator-key", "")
		rest, reqPath = takeFlag(rest, "--request", "")
		rest, outCh = takeFlag(rest, "--out-challenge", "")
		rest, outSec = takeFlag(rest, "--out-secret", "")
		if opKeyPath == "" || reqPath == "" || outCh == "" || outSec == "" {
			return errors.New("join challenge requires --operator-key, --request, --out-challenge, --out-secret")
		}
		opKM, err := ldrclient.LoadSigningKey(opKeyPath)
		if err != nil {
			return err
		}
		req, _, err := ldrclient.LoadJoinRequest(reqPath)
		if err != nil {
			return err
		}
		ch, sec, err := ldrcrypto.CreateJoinChallenge(opKM.Signer.PublicKey(), req)
		if err != nil {
			return err
		}
		if err := ldrclient.SaveJoinChallenge(outCh, ch); err != nil {
			return err
		}
		if err := ldrclient.SaveJoinSecret(outSec, sec); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"challenge":    outCh,
			"secret":       outSec,
			"challenge_id": hex.EncodeToString(ch.ChallengeID),
		})

	case "prove":
		var dir, opPubPath, reqPath, chPath, outPath string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, opPubPath = takeFlag(rest, "--operator-pub", "")
		rest, reqPath = takeFlag(rest, "--request", "")
		rest, chPath = takeFlag(rest, "--challenge", "")
		rest, outPath = takeFlag(rest, "--out", "")
		if dir == "" || opPubPath == "" || reqPath == "" || chPath == "" || outPath == "" {
			return errors.New("join prove requires --dir, --operator-pub, --request, --challenge, --out")
		}
		ck, err := ldrclient.LoadCredentialKeys(filepath.Join(dir, "cred.key"))
		if err != nil {
			return err
		}
		opPub, err := ldrclient.LoadPublicKey(opPubPath)
		if err != nil {
			return err
		}
		req, _, err := ldrclient.LoadJoinRequest(reqPath)
		if err != nil {
			return err
		}
		ch, err := ldrclient.LoadJoinChallenge(chPath)
		if err != nil {
			return err
		}
		pr, err := ldrcrypto.RespondJoinChallenge(ck.Signing.Signer, ck.Encryption, opPub, req, ch)
		if err != nil {
			return err
		}
		if err := ldrclient.SaveJoinProof(outPath, pr); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{
			"proof":        outPath,
			"challenge_id": hex.EncodeToString(pr.ChallengeID),
		})

	case "enroll":
		var dir, opKeyPath, reqPath, chPath, secPath, proofPath string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, opKeyPath = takeFlag(rest, "--operator-key", "")
		rest, reqPath = takeFlag(rest, "--request", "")
		rest, chPath = takeFlag(rest, "--challenge", "")
		rest, secPath = takeFlag(rest, "--secret", "")
		rest, proofPath = takeFlag(rest, "--proof", "")
		if dir == "" || opKeyPath == "" || reqPath == "" || chPath == "" || secPath == "" || proofPath == "" {
			return errors.New("join enroll requires --dir, --operator-key, --request, --challenge, --secret, --proof")
		}
		opKM, err := ldrclient.LoadSigningKey(opKeyPath)
		if err != nil {
			return err
		}
		req, reqDig, err := ldrclient.LoadJoinRequest(reqPath)
		if err != nil {
			return err
		}
		ch, err := ldrclient.LoadJoinChallenge(chPath)
		if err != nil {
			return err
		}
		sec, err := ldrclient.LoadJoinSecret(secPath)
		if err != nil {
			return err
		}
		pr, err := ldrclient.LoadJoinProof(proofPath)
		if err != nil {
			return err
		}
		if err := ldrcrypto.VerifyJoinProof(opKM.Signer.PublicKey(), req, ch, sec, pr); err != nil {
			return fmt.Errorf("P3 proof verification failed: %w", err)
		}
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		cl.AttachOperatorKey(opKM)

		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Anchor(ctx, sess); err != nil {
			return err
		}
		skC, _ := req.SigningKey.ToCBOR()
		ekC, _ := req.EncryptionKey.ToCBOR()
		opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
			Action: "credential_enroll", Origin: ldrcore.OriginOperator, OpType: "credential_enroll",
			Fields: ldrcrypto.Map{
				{Key: "cred_id", Value: req.CredID[:]},
				{Key: "encryption_key", Value: ekC},
				{Key: "grant", Value: ldrcrypto.Map{
					{Key: "actor_limit", Value: req.Grant.ActorLimit},
					{Key: "namespace_id", Value: req.Grant.NamespaceID},
					{Key: "reader", Value: req.Grant.Reader},
				}},
				{Key: "join_request_digest", Value: reqDig[:]},
				{Key: "join_request_id", Value: req.RequestID},
				{Key: "signing_key", Value: skC},
			},
		})
		if err != nil {
			return err
		}
		rep, err := cl.Send(ctx, sess, opID)
		if err != nil {
			return err
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return fmt.Errorf("credential_enroll did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
		}
		_, _ = cl.Sync(ctx, sess)
		return json.NewEncoder(out).Encode(map[string]any{
			"op_id": opID, "seq": rep.Outcome.Seq, "cred_id": hex.EncodeToString(req.CredID[:]),
		})

	case "activate":
		var dir string
		rest, dir = takeFlag(rest, "--dir", "")
		if dir == "" {
			return errors.New("join activate requires --dir <client-dir>")
		}
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if err := cl.VerifyEnrollmentAndActivate(ctx, sess); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(cl.Status())

	default:
		return fmt.Errorf("unknown join subcommand %q", sub)
	}
}

func ldrEpochCLI(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "activate" {
		return errors.New("usage: yip ldr epoch activate --dir <enrolled-reader-dir> --operator-key <file>")
	}
	rest := args[1:]
	var dir, opKeyPath string
	rest, dir = takeFlag(rest, "--dir", "")
	rest, opKeyPath = takeFlag(rest, "--operator-key", "")
	if dir == "" || opKeyPath == "" {
		return errors.New("epoch activate requires --dir and --operator-key")
	}
	opKM, err := ldrclient.LoadSigningKey(opKeyPath)
	if err != nil {
		return err
	}
	cl, err := ldrclient.OpenClient(dir)
	if err != nil {
		return err
	}
	defer cl.Close()
	cl.AttachOperatorKey(opKM)

	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	sess, err := cl.Dial(ctx, ldrcrypto.PrincipalOperator)
	if err != nil {
		return err
	}
	defer sess.Close()
	if _, err := cl.Anchor(ctx, sess); err != nil {
		return err
	}
	opID, _, err := cl.ComposeEpochActivate("epoch_activate")
	if err != nil {
		return err
	}
	rep, err := cl.Send(ctx, sess, opID)
	if err != nil {
		return err
	}
	if rep.Outcome.Kind != ldrcore.Committed {
		return fmt.Errorf("key_epoch_activate did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
	}
	_, _ = cl.Sync(ctx, sess)
	return json.NewEncoder(out).Encode(map[string]any{"op_id": opID, "seq": rep.Outcome.Seq, "key_epoch": cl.State().Line.KeyEpoch})
}

func ldrSyncCLI(args []string, out io.Writer) error {
	var dir, role, keyPath string
	args, dir = takeFlag(args, "--dir", "")
	args, role = takeFlag(args, "--role", ldrcrypto.PrincipalCredential)
	args, keyPath = takeFlag(args, "--key", "")
	doProject := hasFlag(args, "--project")
	doScan := hasFlag(args, "--scan")
	if dir == "" {
		return errors.New("sync requires --dir <client-dir>")
	}
	cl, err := ldrclient.OpenClient(dir)
	if err != nil {
		return err
	}
	defer cl.Close()
	if keyPath != "" {
		km, err := ldrclient.LoadSigningKey(keyPath)
		if err != nil {
			return err
		}
		if role == ldrcrypto.PrincipalRoot {
			cl.AttachRootKey(km)
		} else {
			cl.AttachOperatorKey(km)
		}
	}
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	sess, err := cl.Dial(ctx, role)
	if err != nil {
		return err
	}
	defer sess.Close()
	applied, err := cl.Sync(ctx, sess)
	if err != nil {
		return err
	}
	if doProject {
		if err := cl.Project(ctx, sess); err != nil {
			return err
		}
	}
	noticesAdded := 0
	if doScan {
		noticesAdded, err = cl.ScanDelivery()
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"applied":       applied,
		"notices_added": noticesAdded,
		"deliverable":   cl.DeliverableNotices(),
		"status":        cl.Status(),
	})
}

func ldrActorCLI(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "declare" {
		return errors.New("usage: yip ldr actor declare --dir <client-dir> --actor <id> [--namespace <ns>]")
	}
	rest := args[1:]
	var dir, actorID, ns string
	rest, dir = takeFlag(rest, "--dir", "")
	rest, actorID = takeFlag(rest, "--actor", "")
	rest, ns = takeFlag(rest, "--namespace", "")
	if dir == "" || actorID == "" {
		return errors.New("actor declare requires --dir and --actor")
	}
	cl, err := ldrclient.OpenClient(dir)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := ldrTimeoutCtx()
	defer cancel()
	sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		return err
	}
	defer sess.Close()
	if _, err := cl.Anchor(ctx, sess); err != nil {
		return err
	}
	if ns == "" {
		cid, ok := cl.CredID()
		if !ok {
			return errors.New("no credential loaded")
		}
		cr := cl.State().Line.Credentials[hex.EncodeToString(cid[:])]
		if cr == nil {
			return errors.New("credential not enrolled")
		}
		ns = cr.Namespace
	}
	opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
		Action: "actor_declare:" + actorID, Origin: ldrcore.OriginCredential, OpType: "actor_declare",
		Fields: ldrcrypto.Map{{Key: "actor_id", Value: actorID}, {Key: "label", Value: false}, {Key: "namespace_id", Value: ns}},
	})
	if err != nil {
		return err
	}
	rep, err := cl.Send(ctx, sess, opID)
	if err != nil {
		return err
	}
	if rep.Outcome.Kind != ldrcore.Committed {
		return fmt.Errorf("actor_declare did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
	}
	_, _ = cl.Sync(ctx, sess)
	return json.NewEncoder(out).Encode(map[string]any{"op_id": opID, "seq": rep.Outcome.Seq, "actor": actorID, "namespace": ns})
}

func ldrCallCLI(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yip ldr call <open|say> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "open":
		var dir, from, to, callID, subject, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, to = takeFlag(rest, "--to", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, subject = takeFlag(rest, "--subject", "")
		rest, body = takeFlag(rest, "--body", "")
		if dir == "" || from == "" || to == "" || callID == "" {
			return errors.New("call open requires --dir, --from, --to, --call")
		}
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Anchor(ctx, sess); err != nil {
			return err
		}
		pt, _ := json.Marshal(map[string]string{"subject": subject, "body": body})
		opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
			Action: "call_open:" + callID, Origin: ldrcore.OriginActor, OpType: "call_open",
			ActorID:   from,
			Fields:    ldrcrypto.Map{{Key: "call_id", Value: callID}, {Key: "to", Value: to}},
			Plaintext: pt,
		})
		if err != nil {
			return err
		}
		rep, err := cl.Send(ctx, sess, opID)
		if err != nil {
			return err
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return fmt.Errorf("call_open did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
		}
		_, _ = cl.Sync(ctx, sess)
		return json.NewEncoder(out).Encode(map[string]any{"op_id": opID, "seq": rep.Outcome.Seq, "call": callID})

	case "say":
		var dir, from, callID, body string
		rest, dir = takeFlag(rest, "--dir", "")
		rest, from = takeFlag(rest, "--from", "")
		rest, callID = takeFlag(rest, "--call", "")
		rest, body = takeFlag(rest, "--body", "")
		barge := hasFlag(rest, "--barge")
		if dir == "" || from == "" || callID == "" {
			return errors.New("call say requires --dir, --from, --call")
		}
		cl, err := ldrclient.OpenClient(dir)
		if err != nil {
			return err
		}
		defer cl.Close()
		ctx, cancel := ldrTimeoutCtx()
		defer cancel()
		sess, err := cl.Dial(ctx, ldrcrypto.PrincipalCredential)
		if err != nil {
			return err
		}
		defer sess.Close()
		if _, err := cl.Anchor(ctx, sess); err != nil {
			return err
		}
		callObj := cl.State().Calls[callID]
		if callObj == nil {
			return fmt.Errorf("unknown call %q in verified state", callID)
		}
		pt, _ := json.Marshal(map[string]string{"body": body})
		opID, err := cl.ComposeAndPersist(ldrclient.ComposeParams{
			Action: "call_turn:" + callID, Origin: ldrcore.OriginActor, OpType: "call_turn",
			ActorID:   from,
			Expect:    ldrcrypto.ExpectMap{"turn_count": uint64(callObj.TurnCount)},
			Fields:    ldrcrypto.Map{{Key: "barge", Value: barge}, {Key: "call_id", Value: callID}},
			Plaintext: pt,
		})
		if err != nil {
			return err
		}
		rep, err := cl.Send(ctx, sess, opID)
		if err != nil {
			return err
		}
		if rep.Outcome.Kind != ldrcore.Committed {
			return fmt.Errorf("call_turn did not commit: %s %s %s", rep.Class, rep.Code, rep.Outcome.Reason)
		}
		_, _ = cl.Sync(ctx, sess)
		return json.NewEncoder(out).Encode(map[string]any{"op_id": opID, "seq": rep.Outcome.Seq, "call": callID})

	default:
		return fmt.Errorf("unknown call subcommand %q", sub)
	}
}

func ldrStatusCLI(args []string, out io.Writer) error {
	var dir string
	args, dir = takeFlag(args, "--dir", "")
	if dir == "" {
		return errors.New("status requires --dir <client-dir>")
	}
	cl, err := ldrclient.OpenClient(dir)
	if err != nil {
		return err
	}
	defer cl.Close()
	return json.NewEncoder(out).Encode(map[string]any{
		"status":      cl.Status(),
		"deliverable": cl.DeliverableNotices(),
		"stops":       cl.Stops(),
	})
}
