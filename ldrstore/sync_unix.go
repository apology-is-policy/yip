//go:build unix && !darwin

package ldrstore

import (
	"errors"
	"os"
	"syscall"
)

// SyncFile flushes f to persistent storage via fsync.
func SyncFile(f *os.File) error {
	return f.Sync()
}

// SyncDir flushes directory metadata via fsync.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func flockExclusive(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrStoreLocked
	}
	return err
}

func funlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
