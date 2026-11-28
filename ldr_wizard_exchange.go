package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apology-is-policy/yip/ldrclient"
)

// The transport is a folder the two people already share through a trusted
// channel. Each direction has its own immutable files. No listener or new
// relay principal is involved.
func (w wizardArgs) exchangeFiles() (string, error) {
	if w.exchange == "" {
		return "", errors.New("choose a separate authenticated exchange folder for this invitation")
	}
	exchange, err := ldrclient.CanonicalPath(w.exchange)
	if err != nil {
		return "", err
	}
	if wizardContains(exchange, w.workspace) || wizardContains(w.workspace, exchange) {
		return "", errors.New("the exchange folder and private workspace must be separate")
	}
	if w.step == "exchange-invite" {
		var auth wizardAuthority
		if err = wizardLoad(w.path("authority.json"), &auth); err != nil {
			return "", err
		}
		for _, p := range []string{auth.Admin, auth.Key} {
			real, e := ldrclient.CanonicalPath(p)
			if e != nil {
				return "", e
			}
			if wizardContains(exchange, real) || wizardContains(real, exchange) {
				return "", errors.New("keep operator credentials outside the exchange folder")
			}
		}
	}
	if err = os.MkdirAll(exchange, 0700); err != nil {
		return "", err
	}
	var message string
	// Stop waiting whenever either person needs to see or confirm a code.
	deadline := time.Now().Add(2 * time.Minute)
	for {
		var awaited string
		if w.step == "exchange-invite" {
			message, awaited, err = w.exchangeOperator(exchange)
		} else {
			message, awaited, err = w.exchangeMember(exchange)
		}
		if err != nil || awaited == "" || !w.wait || time.Now().After(deadline) {
			return message, err
		}
		for {
			if time.Now().After(deadline) {
				return message, nil
			}
			time.Sleep(time.Second)
			ready, e := wizardExists(awaited)
			if e != nil {
				return "", e
			}
			if ready {
				break
			}
		}
	}
}

func (w wizardArgs) exchangeOperator(dir string) (string, string, error) {
	if err := wizardCopy(w.path("invitation.yip"), filepath.Join(dir, "invitation.yip")); err != nil {
		return "", "", err
	}
	request := filepath.Join(dir, "request.cbor")
	exists, err := wizardExists(request)
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "Invitation ready. Ask the workstation owner to open this exchange folder. Waiting for their signed request.", request, nil
	}
	reviewed, err := wizardExists(w.path("reviewed.cbor"))
	if err != nil {
		return "", "", err
	}
	w.step = "review"
	w.input = request
	msg, err := w.inviting()
	if err != nil {
		return "", "", err
	}
	ch, err := wizardExists(w.path("challenge.cbor"))
	if err != nil {
		return "", "", err
	}
	if !ch {
		if !reviewed || w.code == "" {
			return msg + "\nReturn to this exchange step with the confirmed code to approve.", "", nil
		}
		w.step = "approve"
		if _, err = w.inviting(); err != nil {
			return "", "", err
		}
	}
	if err = wizardCopy(w.path("challenge.cbor"), filepath.Join(dir, "challenge.cbor")); err != nil {
		return "", "", err
	}
	proof := filepath.Join(dir, "proof.cbor")
	ok, err := wizardExists(proof)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "Approval recorded. Waiting for the workstation to return its proof through the exchange folder.", proof, nil
	}
	w.step = "admit"
	w.input = proof
	msg, err = w.inviting()
	if err != nil {
		return "", "", err
	}
	_, digest, err := ldrclient.LoadJoinRequest(w.path("reviewed.cbor"))
	if err != nil {
		return "", "", err
	}
	err = wizardSave(filepath.Join(dir, "enrolled.txt"), []byte(fmt.Sprintf("%x\n", digest)))
	return msg, "", err
}

func (w wizardArgs) exchangeMember(dir string) (string, string, error) {
	w.step = "join"
	w.input = filepath.Join(dir, "invitation.yip")
	started, err := wizardExists(w.path("client"))
	if err != nil {
		return "", "", err
	}
	exists, err := wizardExists(w.input)
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "Waiting for the operator to place the invitation in the exchange folder.", w.input, nil
	}
	msg, err := w.joining()
	if err != nil {
		return "", "", err
	}
	if err = wizardCopy(w.shared("request.cbor"), filepath.Join(dir, "request.cbor")); err != nil {
		return "", "", err
	}
	_, digest, err := ldrclient.LoadJoinRequest(w.shared("request.cbor"))
	if err != nil {
		return "", "", err
	}
	w.step = "prove"
	w.input = filepath.Join(dir, "challenge.cbor")
	ok, err := wizardExists(w.input)
	if err != nil {
		return "", "", err
	}
	if !ok {
		awaited := ""
		if started {
			awaited = w.input
		}
		summary, _, _ := strings.Cut(msg, "\n")
		return fmt.Sprintf("%s\nRequest delivered. Confirm workstation code %s with the operator. Return to this step to finish pairing.", summary, wizardCode(digest)), awaited, nil
	}
	if _, err = w.joining(); err != nil {
		return "", "", err
	}
	if err = wizardCopy(w.shared("proof.cbor"), filepath.Join(dir, "proof.cbor")); err != nil {
		return "", "", err
	}
	b, err := wizardRead(filepath.Join(dir, "enrolled.txt"))
	if errors.Is(err, os.ErrNotExist) {
		return "Proof delivered. Waiting for the operator to complete enrollment.", filepath.Join(dir, "enrolled.txt"), nil
	}
	if err != nil {
		return "", "", err
	}
	if string(b) != fmt.Sprintf("%x\n", digest) {
		return "", "", errors.New("exchange receipt belongs to another workstation request")
	}
	// The receipt is only a wakeup. Replay the actual membership and reader wrap.
	w.step = "activate"
	msg, err = w.joining()
	return msg, "", err
}
