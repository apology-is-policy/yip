//go:build darwin

package ldrstore

import (
	"errors"
	"os"
	"syscall"
)

// SyncFile flushes f's data and metadata to persistent storage using macOS
// F_FULLFSYNC so disk write-caches are flushed before acknowledging commits.
func SyncFile(f *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_FULLFSYNC, 0)
	if errno == 0 {
		return nil
	}
	// Some virtual/memory test filesystems do not support F_FULLFSYNC.
	if errno == syscall.ENOTSUP || errno == syscall.EINVAL || errno == syscall.ENOTTY {
		return f.Sync()
	}
	return errno
}

// SyncDir flushes directory metadata after atomic renames or file creation.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return SyncFile(d)
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
