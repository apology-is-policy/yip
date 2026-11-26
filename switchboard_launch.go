package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Release builds select a content-addressed sibling so an upgrade or rollback
// always launches the renderer built for that executable.
var switchboardRenderer = "yip-switchboard"

func launchSwitchboard(args []string) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	bin, err = filepath.EvalSymlinks(bin)
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	renderer := filepath.Join(filepath.Dir(bin), switchboardRenderer)
	if err := os.Setenv("YIP_SWITCHBOARD_BIN", bin); err != nil {
		return err
	}
	if err := os.Setenv("YIP_SWITCHBOARD_DIR", dir); err != nil {
		return err
	}
	if activeLine != "" {
		if err := os.Setenv("YIP_LINE", activeLine); err != nil {
			return err
		}
	}
	args, by := takeFlag(args, "--by", os.Getenv("USER"))
	if err := os.Setenv("YIP_SWITCHBOARD_BY", by); err != nil {
		return err
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "--demo" && args[0] != "--check" {
		return fmt.Errorf("unknown Switchboard arguments: %v", args)
	}
	err = syscall.Exec(renderer, append([]string{renderer}, args...), os.Environ())
	return fmt.Errorf("launch Switchboard: %w (install the matching renderer or run make build)", err)
}
