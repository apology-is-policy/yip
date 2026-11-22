//go:build darwin

package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Darwin sysctl MIB constants from <sys/sysctl.h>.
const (
	darwinCtlKern      = 1
	darwinKernProc     = 14
	darwinKernProcPID  = 1
	darwinKernBoottime = 21
	darwinKernProcArgs = 49
)

// struct kinfo_proc offsets on 64-bit Darwin (arm64 and amd64):
//   kp_proc.p_un.p_starttime (struct timeval): 0..16
//   kp_proc.p_pid (pid_t):                     40..44
//   kp_eproc.e_ppid (pid_t):                   560..564
//   sizeof(struct kinfo_proc):                 648
const (
	darwinKinfoProcMinLen = 564
	darwinOffPID          = 40
	darwinOffPPID         = 560
)

func sysctlMIB(mib []int32) ([]byte, error) {
	var n uintptr
	_, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		0, uintptr(unsafe.Pointer(&n)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	_, _, errno = syscall.Syscall6(syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return buf[:n], nil
}

// procStat reads a process's parent PID and microsecond kernel start time
// directly via kern.proc.pid sysctl (no /proc, no setuid ps subprocess).
func procStat(pid int) (ppid int, start string, ok bool) {
	if pid <= 0 {
		return 0, "", false
	}
	kp, err := sysctlMIB([]int32{darwinCtlKern, darwinKernProc, darwinKernProcPID, int32(pid)})
	if err != nil || len(kp) < darwinKinfoProcMinLen {
		return 0, "", false
	}
	if int(int32(binary.LittleEndian.Uint32(kp[darwinOffPID:darwinOffPID+4]))) != pid {
		return 0, "", false
	}
	ppid = int(int32(binary.LittleEndian.Uint32(kp[darwinOffPPID : darwinOffPPID+4])))
	sec := int64(binary.LittleEndian.Uint64(kp[0:8]))
	usec := int32(binary.LittleEndian.Uint32(kp[8:12]))
	return ppid, fmt.Sprintf("%d.%06d", sec, usec), true
}

func readBootID() string {
	bt, err := sysctlMIB([]int32{darwinCtlKern, darwinKernBoottime})
	if err != nil || len(bt) < 12 {
		return ""
	}
	sec := int64(binary.LittleEndian.Uint64(bt[0:8]))
	usec := int32(binary.LittleEndian.Uint32(bt[8:12]))
	return fmt.Sprintf("%d.%06d", sec, usec)
}

// readProcCmdline parses kern.procargs2 into NUL-separated argv, matching the
// /proc/<pid>/cmdline layout expected by isHookShell.
func readProcCmdline(pid int) string {
	if pid <= 0 {
		return ""
	}
	pa, err := sysctlMIB([]int32{darwinCtlKern, darwinKernProcArgs, int32(pid)})
	if err != nil || len(pa) < 4 {
		return ""
	}
	argc := int(binary.LittleEndian.Uint32(pa[0:4]))
	if argc <= 0 {
		return ""
	}
	rest := pa[4:]
	i := 0
	for i < len(rest) && rest[i] != 0 {
		i++
	}
	for i < len(rest) && rest[i] == 0 {
		i++
	}
	argv := make([]string, 0, argc)
	for len(argv) < argc && i < len(rest) {
		j := i
		for j < len(rest) && rest[j] != 0 {
			j++
		}
		argv = append(argv, string(rest[i:j]))
		i = j + 1
	}
	if len(argv) == 0 {
		return ""
	}
	return strings.Join(argv, "\x00") + "\x00"
}

func readPidNS() string { return "" }
