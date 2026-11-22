//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// procStat reads a process's parent and kernel start time from /proc. The
// comm field may hold spaces and parentheses, so fields are counted from the
// last ')'.
func procStat(pid int) (ppid int, start string, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, "", false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, "", false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, "", false
	}
	ppid, err = strconv.Atoi(f[1])
	return ppid, f[19], err == nil
}

func readBootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

func readProcCmdline(pid int) string {
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	return string(b)
}

func readPidNS() string {
	ns, _ := os.Readlink("/proc/self/ns/pid")
	return ns
}
