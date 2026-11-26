package main

// #cgo CXXFLAGS: -std=c++11 -DIMGUI_USE_WCHAR32 -I${SRCDIR}/../../third_party/imtui
// #include <stdlib.h>
// #include "bridge.h"
import "C"

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	"github.com/gdamore/tcell/v2"
)

type input struct {
	x, y                    int
	down                    bool
	wheel                   float32
	toggleCalls, toggleChat bool
}

var foreground [256]tcell.Color

func initBoard() {
	// ImTUI positions each code point in one cell. Reserve the trailing
	// cell before passing wide text through its glyph renderer.
	sample := C.CString(terminalCells("界  東京  🐦"))
	defer C.free(unsafe.Pointer(sample))
	var inks [256]C.uint32_t
	C.board_init(sample, &inks[0])
	registerActions()
	for i, rgb := range inks {
		foreground[i] = tcell.PaletteColor(i)
		if rgb != 0 {
			foreground[i] = tcell.NewHexColor(int32(rgb))
		}
	}
}

func frame(screen tcell.Screen, in input, elapsed time.Duration) bool {
	width, height := screen.Size()
	if width < 40 || height < 10 {
		screen.Clear()
		for x, r := range []rune("Resize to at least 40 × 10") {
			if x < width && height > 0 {
				screen.SetContent(x, 0, r, nil, tcell.StyleDefault)
			}
		}
		screen.Show()
		return false
	}

	var colors, glyphs *C.uint32_t
	var down, calls, chat C.int
	if in.down {
		down = 1
	}
	if in.toggleCalls {
		calls = 1
	}
	if in.toggleChat {
		chat = 1
	}
	quit := C.board_frame(C.int(width), C.int(height), C.float(elapsed.Seconds()),
		C.int(in.x), C.int(in.y), down, C.float(in.wheel), calls, chat, &colors, &glyphs)
	palette := unsafe.Slice(colors, width*height)
	text := unsafe.Slice(glyphs, width*height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			i := y*width + x
			ink := uint32(palette[i])
			r := rune(text[i])
			if !unicode.IsPrint(r) {
				r = ' '
			}
			style := tcell.StyleDefault.Background(tcell.PaletteColor(int(ink >> 24)))
			if r != ' ' {
				style = style.Foreground(foreground[ink>>16&0xff])
			}
			screen.SetContent(x, y, r, nil, style)
			_, _, _, cells := screen.GetContent(x, y)
			x += max(0, cells-1)
		}
	}
	screen.Show()
	return quit != 0
}

func run(screen tcell.Screen, yip, dir string) (foregroundArgs []string) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var selected atomic.Value
	selected.Store("")
	var updates <-chan boardSnapshot
	var current boardSnapshot
	var views atomic.Uint32
	var stopObserver context.CancelFunc
	startObserver := func() {
		if yip == "" {
			return
		}
		var observeCtx context.Context
		observeCtx, stopObserver = context.WithCancel(ctx)
		updates = snapshots(observeCtx, yip, dir, &selected, &views)
	}
	if yip != "" {
		applySnapshot(boardSnapshot{Error: "Connecting to Yip..."}, "")
	}
	startObserver()
	defer func() {
		if stopObserver != nil {
			stopObserver()
		}
		if updates != nil {
			for range updates {
			}
		}
	}()
	type completion struct {
		message string
		err     error
	}
	finished := make(chan completion, 1)
	screen.EnableMouse()
	events := make(chan tcell.Event)
	done := make(chan struct{})
	defer close(done)
	go screen.ChannelEvents(events, done)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	in := input{x: -1, y: -1}
	last := time.Now().Add(-time.Millisecond)
	for {
		now := time.Now()
		if frame(screen, in, max(time.Millisecond, now.Sub(last))) {
			return
		}
		if index := int(C.board_selected()); index >= 0 && index < len(current.Calls) {
			selected.Store(current.Calls[index].ID)
		}
		views.Store(uint32(C.board_views()))
		if index := int(C.board_take_action()); index >= 0 && index < len(actions) {
			a := actions[index]
			values := make([]string, len(a.fields))
			for i := range values {
				values[i] = C.GoString(C.board_value(C.int(i)))
			}
			args, body, err := a.arguments(values)
			if err != nil {
				actionStatus(err.Error(), false, true)
			} else if a.command == "@serve" {
				return append([]string{"relay", "serve"}, args[1:]...)
			} else if a.command == "@line" && os.Getenv("YIP_ROOT") != "" {
				actionStatus("YIP_ROOT fixes this session to one directory.", false, true)
			} else {
				stopObserver()
				old := updates
				updates = nil
				actionStatus(a.label+"…", true, false)
				go func() {
					for range old {
					} // release the observer's client-directory lock
					if a.command == "@monitor" {
						err := os.Setenv("YIP_RELAY_ADMIN_SOCKET", args[2])
						finished <- completion{"Relay health now reads " + args[2], err}
						return
					}
					if a.command == "@line" {
						err := os.Setenv("YIP_LINE", values[0])
						finished <- completion{"Selected line " + values[0], err}
						return
					}
					msg, err := runAction(ctx, yip, dir, args, body)
					if msg == "" && err == nil {
						msg = a.label + " completed"
					}
					finished <- completion{msg, err}
				}()
			}
		}
		last = now
		in.wheel, in.toggleCalls, in.toggleChat = 0, false, false
		select {
		case <-ctx.Done():
			return
		case r := <-finished:
			if r.err != nil {
				r.message = strings.TrimSpace(r.message + "\n" + r.err.Error())
			}
			actionStatus(r.message, false, r.err != nil)
			current = boardSnapshot{Error: "Refreshing line…"}
			selected.Store(applySnapshot(current, ""))
			startObserver()
		case <-ticker.C:
		case next, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			if next.Line == "" && next.Error != "" {
				current.Error = next.Error
			} else {
				current = next
			}
			selected.Store(applySnapshot(current, selected.Load().(string)))
		case e, ok := <-events:
			if !ok {
				return
			}
			switch e := e.(type) {
			case *tcell.EventKey:
				if e.Key() >= tcell.KeyF3 && e.Key() <= tcell.KeyF7 {
					C.board_toggle_view(C.int(e.Key() - tcell.KeyF3))
					continue
				}
				if e.Key() == tcell.KeyCtrlC || (e.Rune() == 'q' && C.board_editing() == 0) {
					return
				}
				if C.board_editing() != 0 {
					code := map[tcell.Key]int{tcell.KeyBackspace: 8, tcell.KeyBackspace2: 8, tcell.KeyEnter: 13, tcell.KeyEscape: 27, tcell.KeyLeft: 256, tcell.KeyRight: 257, tcell.KeyHome: 258, tcell.KeyEnd: 259, tcell.KeyDelete: 260, tcell.KeyTab: 9}[e.Key()]
					C.board_key(C.int(code), C.uint(e.Rune()))
				} else {
					if n := len(current.Calls); n > 0 {
						i := int(C.board_selected())
						if e.Rune() == 'n' {
							C.board_select(C.int((i + 1) % n))
						}
						if e.Rune() == 'p' {
							C.board_select(C.int((i + n - 1) % n))
						}
					}
					in.toggleCalls, in.toggleChat = e.Rune() == '1', e.Rune() == '2'
				}
			case *tcell.EventMouse:
				in.x, in.y = e.Position()
				buttons := e.Buttons()
				in.down = buttons&tcell.Button1 != 0
				if buttons&tcell.WheelUp != 0 {
					in.wheel = 1
				}
				if buttons&tcell.WheelDown != 0 {
					in.wheel = -1
				}
			case *tcell.EventResize:
				screen.Sync()
			}
		}
	}
}

func start() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(os.Args) == 2 && os.Args[1] == "--check" {
		return check()
	}
	screen, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := screen.Init(); err != nil {
		return err
	}
	yip := os.Getenv("YIP_SWITCHBOARD_BIN")
	if len(os.Args) == 2 && os.Args[1] == "--demo" {
		yip = ""
	}
	args := func() []string {
		defer screen.Fini()
		initBoard()
		defer C.board_close()
		return run(screen, yip, os.Getenv("YIP_SWITCHBOARD_DIR"))
	}()
	if len(args) > 0 {
		return syscall.Exec(yip, append([]string{yip}, args...), os.Environ())
	}
	return nil
}

func main() {
	if err := start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
