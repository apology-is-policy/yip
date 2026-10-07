package main

import (
	"strconv"
	"strings"
)

// Geometry is shared by painting and hit testing. Coordinates are zero-based;
// SGR mouse reports are converted from terminal coordinates in the decoder.
type sbLayout struct {
	top, height, cols           int
	railW, centerW, sideW       int
	centerX, sideX              int
	railLen, centerLen, sideLen int
}

func paneLayout(rows, cols int) sbLayout {
	l := sbLayout{top: 5, cols: cols}
	if rows < 10 || cols < 40 {
		return l
	}
	l.height = rows - 8
	if cols >= 125 {
		l.railW = 27
		l.centerX = l.railW + 2
	}
	if cols >= 85 {
		l.sideW = 31
	}
	if cols >= 150 {
		l.sideW = 36
	}
	l.centerW = cols - l.centerX
	if l.sideW > 0 {
		l.centerW -= l.sideW + 2
		l.sideX = l.centerX + l.centerW + 2
	}
	return l
}

type sbMouse struct {
	button, x, y int
	release      bool
}
type sbInput struct {
	key   rune
	mouse *sbMouse
	arrow bool
}

// Read complete CSI packets before dispatch, including fragmented mouse reports.
// Unknown or oversized sequences are swallowed, never interpreted as commands
// or approval text. Only lone Escape has a timeout in the terminal driver.
type sbInputDecoder struct {
	state    int
	seq      []rune
	overflow bool
}

func (d *sbInputDecoder) loneEscape() bool { return d.state == 1 }
func (d *sbInputDecoder) feed(r rune) []sbInput {
	if d.state == 0 {
		if r == 27 {
			d.state = 1
			return nil
		}
		return []sbInput{{key: r}}
	}
	if d.state == 1 {
		if r == '[' {
			d.state = 2
			return nil
		}
		if r == 'O' {
			d.state = 2
			return nil
		} // application-cursor keys
		*d = sbInputDecoder{}
		return append([]sbInput{{key: 27}}, d.feed(r)...)
	}
	if r >= 0x40 && r <= 0x7e {
		s, overflow := string(d.seq), d.overflow
		*d = sbInputDecoder{}
		if overflow {
			return nil
		}
		if s == "" && (r == 'A' || r == 'B') {
			k := 'k'
			if r == 'B' {
				k = 'j'
			}
			return []sbInput{{key: k, arrow: true}}
		}
		if strings.HasPrefix(s, "<") && (r == 'M' || r == 'm') {
			parts := strings.Split(s[1:], ";")
			if len(parts) != 3 {
				return nil
			}
			var n [3]int
			for i, p := range parts {
				if p == "" || strings.Trim(p, "0123456789") != "" {
					return nil
				}
				v, err := strconv.Atoi(p)
				if err != nil || v > 1000000 {
					return nil
				}
				n[i] = v
			}
			if n[1] == 0 || n[2] == 0 {
				return nil
			}
			return []sbInput{{mouse: &sbMouse{button: n[0], x: n[1] - 1, y: n[2] - 1, release: r == 'm'}}}
		}
		return nil
	}
	if len(d.seq) < 64 {
		d.seq = append(d.seq, r)
	} else {
		d.overflow = true
	}
	return nil
}

func (v *view) handleInput(e sbInput) {
	if e.mouse != nil {
		v.mouse(*e.mouse)
		return
	}
	if e.arrow && v.prompt != "" {
		return
	}
	v.key(e.key)
}

func (v *view) revealCall() {
	h := v.panes.height
	if h <= 0 {
		return
	}
	start, end := 2+3*v.sel, 2+3*v.sel+2
	if start < v.railScroll {
		v.railScroll = start
	}
	if end >= v.railScroll+h {
		v.railScroll = max(0, end-h+1)
	}
}

func (v *view) mouse(m sbMouse) {
	l := v.panes
	// Freeze the decision's destination while the human composes it.
	if v.prompt != "" || m.release || m.x < 0 || m.x >= l.cols || m.y < l.top || m.y >= l.top+l.height {
		return
	}
	pane := 0 // separators are not content
	if m.x < l.railW {
		pane = 1
	} else if m.x >= l.centerX && m.x < l.centerX+l.centerW {
		pane = 2
	} else if l.sideW > 0 && m.x >= l.sideX {
		pane = 3
	}
	if pane == 0 {
		return
	}
	// Ignore motion, horizontal wheel, and non-left buttons. Modifier bits
	// do not change the target; the wheel packet itself supplies the position.
	button := m.button &^ (4 | 8 | 16)
	list := pane == 1 || (pane == 2 && v.tab == 2)
	if button == 64 || button == 65 {
		delta := 3
		if button == 64 {
			delta = -delta
		}
		offset, length := &v.scroll, l.centerLen
		if list {
			offset, length = &v.railScroll, l.railLen
		} else if pane == 3 {
			offset, length = &v.sideScroll, l.sideLen
		}
		*offset = min(max(0, *offset+delta), max(0, length-l.height))
		if pane == 2 && v.tab == 0 {
			v.follow = false
		}
		return
	}
	if button == 0 && list {
		row := m.y - l.top + v.railScroll - 2
		if row < 0 || row/3 >= len(v.st.calls) {
			return
		}
		v.sel = row / 3
		v.scroll, v.selD = 0, 0
		v.follow = true
		v.flash = ""
		if pane == 2 {
			v.tab = 0
		} // narrow-screen calls view opens the chat
	}
}
