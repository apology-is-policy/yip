package main

import (
	"errors"
	"fmt"
	"os"
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

// Match the ID the normal --line resolver will use on subsequent launches.
func createSwitchboardLine(args []string) error {
	if len(args) != 1 || !validComponent(args[0]) || slugify(args[0]) != args[0] {
		return errors.New("use a line name of 1–48 lowercase letters, digits or internal hyphens")
	}
	if os.Getenv("YIP_ROOT") != "" {
		return errors.New("YIP_ROOT fixes this session to one directory")
	}
	activeLine = args[0]
	if err := os.MkdirAll(filepath.Dir(Root()), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(Root(), 0755); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("line %q already exists; select it in Manage Lines", activeLine)
		}
		return err
	}
	return EnsureRoot()
}
