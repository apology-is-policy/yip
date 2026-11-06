package main

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Drop terminal control sequences from untrusted transcript/metadata text.
// In particular OSC clipboard/title commands never reach the operator's tty.
func terminalText(s string) string {
	// Almost every string here is plain ASCII, and this runs on every line of every frame.
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\n' && (c < 0x20 || c >= 0x7f) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
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
	if (r >= 0x20 && r < 0x7f) || (r >= 0x2500 && r <= 0x25ff) { // text and the box drawing the frame is made of
		return 1
	}
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
	b.Grow(len(s) + w)
	used := 0
	clipped := false
	for i := 0; i < len(s); {
		if s[i] == 27 && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == ';') {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				b.WriteString(s[i : j+1])
				i = j + 1
				continue
			}
		}
		r, size := rune(s[i]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRuneInString(s[i:])
		}
		i += size
		n := cellWidth(r)
		if used+n > w {
			clipped = true
			continue
		}
		if clipped {
			continue
		}
		b.WriteRune(r)
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
