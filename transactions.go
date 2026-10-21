package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// A persistent inode carries the OS lock. Never unlink it: a second process
// could otherwise lock a replacement inode while the first still owns this one.
func fileGuard(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func readState(path string, dst any) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return fmt.Errorf("%s: empty or null state", path)
	}
	if err = json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeState(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err = atomicReplace(path, append(b, '\n')); err != nil {
		return err
	}
	// Persist the renamed directory entry as well as stage()'s file contents.
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func updateJSON[T any](path string, edit func(*T) error) error {
	unlock, err := fileGuard(path)
	if err != nil {
		return err
	}
	defer unlock()
	var value T
	if err = readState(path, &value); err != nil {
		return err
	}
	if err = edit(&value); err != nil {
		return err
	}
	return writeState(path, value)
}
