package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// The human Switchboard addresses a particular call and dispute. Its author
// label has the same local attribution semantics as the original terminal UI.
func switchboardOperator(action string, args []string) (string, error) {
	if _, attached, err := loadLDRAttachment(); err != nil {
		return "", err
	} else if attached {
		return "", errors.New("this action requires a local line")
	}
	args, by := takeFlag(args, "--by", "")
	if by == "" {
		by = "operator"
	}
	if action == "--reprobe" {
		v := view{st: (&sbLoader{}).load(), by: by}
		v.reprobe()
		if strings.Contains(v.flash, "FAILED") {
			return "", errors.New(v.flash)
		}
		return v.flash, nil
	}
	args, callID := takeFlag(args, "--call", "")
	args, dispute := takeFlag(args, "--dispute", "")
	if !filepath.IsLocal(callID) || filepath.Base(callID) != callID || !filepath.IsLocal(dispute) || filepath.Base(dispute) != dispute {
		return "", errors.New("select a local call ID and dispute ID")
	}
	if len(args) != 0 {
		return "", errors.New("unexpected arbitration arguments")
	}
	call, err := LoadCall(callID)
	if err != nil {
		return "", err
	}
	d, err := ResolveDispute(call, dispute)
	if err != nil {
		return "", err
	}
	err = SetResolution(call, d, Resolution{By: by, Kind: "human", Detail: stdinBody(), At: now()})
	return fmt.Sprintf("Resolved %s as %s (human)", d.ID, by), err
}
