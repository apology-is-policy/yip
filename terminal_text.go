package main

import (
	"strings"
	"unicode"
)

// Drop terminal control sequences from untrusted transcript/metadata text.
// In particular OSC clipboard/title commands never reach the operator's tty.
func terminalText(s string) string {
	var b strings.Builder
	r := []rune(s)
	for i := 0; i < len(r); i++ {
		c := r[i]
		if c == 27 {
			if i+1 < len(r) && r[i+1] == '[' {
				i += 2
				for i < len(r) && !(r[i] >= 0x40 && r[i] <= 0x7e) {
					i++
				}
				continue
			}
			if i+1 < len(r) && (r[i+1] == ']' || r[i+1] == 'P' || r[i+1] == '_' || r[i+1] == '^') {
				i += 2
				for i < len(r) {
					if r[i] == 7 {
						break
					}
					if r[i] == 27 && i+1 < len(r) && r[i+1] == '\\' {
						i++
						break
					}
					i++
				}
				continue
			}
			if i+1 < len(r) {
				i++
			}
			continue
		}
		if c == '\n' {
			b.WriteRune(c)
		} else if c == '\t' {
			b.WriteString("    ")
		} else if !unicode.IsControl(c) && c != 0x202e && c != 0x202d && c != 0x202a && c != 0x202b && c != 0x202c {
			b.WriteRune(c)
		}
	}
	return b.String()
}
func cellWidth(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == 0x200d || r == 0xfe0f {
		return 0
	}
	if unicode.IsControl(r) {
		return 0
	}
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a || r >= 0x2e80 && r <= 0xa4cf || r >= 0xac00 && r <= 0xd7a3 || r >= 0xf900 && r <= 0xfaff || r >= 0xfe10 && r <= 0xfe19 || r >= 0xfe30 && r <= 0xfe6f || r >= 0xff00 && r <= 0xff60 || r >= 0xffe0 && r <= 0xffe6 || r >= 0x1f300 && r <= 0x1faff || r >= 0x20000 && r <= 0x3ffff) {
		return 2
	}
	return 1
}

// Only internally generated SGR is retained here. All external strings must
// pass terminalText before styling. Clip by terminal cells, not escape bytes.
func fitCells(s string, w int, pad bool) string {
	if w <= 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	r := []rune(s)
	clipped := false
	for i := 0; i < len(r); i++ {
		if r[i] == 27 && i+1 < len(r) && r[i+1] == '[' {
			j := i + 2
			for j < len(r) && ((r[j] >= '0' && r[j] <= '9') || r[j] == ';') {
				j++
			}
			if j < len(r) && r[j] == 'm' {
				b.WriteString(string(r[i : j+1]))
				i = j
				continue
			}
		}
		n := cellWidth(r[i])
		if used+n > w {
			clipped = true
			continue
		}
		if clipped {
			continue
		}
		b.WriteRune(r[i])
		used += n
	}
	if pad && used < w {
		b.WriteString(strings.Repeat(" ", w-used))
	}
	return b.String()
}
func plainWidth(s string) int {
	n := 0
	for _, r := range terminalText(s) {
		n += cellWidth(r)
	}
	return n
}
func stripSGR(s string) string { return terminalText(s) }

func tailCells(s string, w int) string {
	r := []rune(s)
	used := 0
	i := len(r)
	for i > 0 {
		n := cellWidth(r[i-1])
		if used+n > w {
			break
		}
		used += n
		i--
	}
	for i < len(r) && cellWidth(r[i]) == 0 {
		i++
	}
	return string(r[i:])
}
