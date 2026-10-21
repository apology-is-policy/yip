package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func dispatchWatchPath(agent string) string {
	return filepath.Join(Root(), "delivery", agent+".dispatcher.lock")
}

// A kernel-owned lock is the liveness proof, not a stale PID or heartbeat.
// Keep its inode permanently: replacing it would permit two owners.
func beginDispatchWatch(agent string) (func(), error) {
	if !validComponent(agent) {
		return nil, fmt.Errorf("invalid agent")
	}
	ep, err := readEndpoint(agent)
	if err != nil {
		return nil, err
	}
	if ep.Runtime != "codex" {
		return nil, fmt.Errorf("watch requires a Codex endpoint")
	}
	f, err := os.OpenFile(dispatchWatchPath(agent), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("dispatcher already running or lock unavailable: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func dispatchWatchAlive(agent string) bool {
	if !validComponent(agent) {
		return false
	}
	f, err := os.OpenFile(dispatchWatchPath(agent), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false
	}
	return err == syscall.EWOULDBLOCK || err == syscall.EAGAIN
}
