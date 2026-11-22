//go:build !linux && !darwin

package main

func procStat(int) (int, string, bool) { return 0, "", false }
func readBootID() string               { return "" }
func readProcCmdline(int) string       { return "" }
func readPidNS() string                { return "" }
