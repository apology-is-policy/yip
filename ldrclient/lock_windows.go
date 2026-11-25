//go:build windows

package ldrclient

import "os"

func flockExclusive(f *os.File) error { return nil }
func funlock(f *os.File) error        { return nil }
