//go:build windows

package ldrstore

import "os"

// SyncFile flushes f to persistent storage via FlushFileBuffers.
func SyncFile(f *os.File) error {
	return f.Sync()
}

// SyncDir is a no-op on Windows where directory handles are not fsynced.
func SyncDir(dir string) error {
	return nil
}

func flockExclusive(f *os.File) error {
	return nil
}

func funlock(f *os.File) error {
	return nil
}
