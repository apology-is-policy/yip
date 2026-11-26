package main

// #include <stdlib.h>
// #include "bridge.h"
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"github.com/mattn/go-runewidth"
)

type callSnapshot struct {
	ID, Subject, Status, Floor, Participants, Route, Progress string
}

type boardSnapshot struct {
	Lines                                            []string
	Line, Error, TranscriptID, Transcript            string
	Calls                                            []callSnapshot
	Overview, Topology, Health, Broadcasts, Roadmaps []string
	HealthInks, BroadcastInks, RoadmapInks           string
	TranscriptInks, OverviewInks, TopologyInks       string
}

func snapshots(ctx context.Context, yip, dir string, selected *atomic.Value, views *atomic.Uint32) <-chan boardSnapshot {
	updates := make(chan boardSnapshot, 1)
	go func() {
		defer close(updates)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			err := readSnapshots(ctx, yip, dir, selected, views, updates, ticker.C)
			if ctx.Err() != nil {
				return
			}
			select {
			case updates <- boardSnapshot{Error: err.Error()}:
			case <-ctx.Done():
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	return updates
}

func readSnapshots(ctx context.Context, yip, dir string, selected *atomic.Value, views *atomic.Uint32, updates chan<- boardSnapshot, tick <-chan time.Time) error {
	cmd := exec.CommandContext(ctx, yip, "switchboard", "--snapshot-stream")
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	requests, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer requests.Close()
	responses, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer responses.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	send, receive := json.NewEncoder(requests), json.NewDecoder(responses)

	for {
		var next boardSnapshot
		v := views.Load()
		err = send.Encode(struct {
			Selected                     string
			Broadcasts, Roadmaps, Health bool
		}{selected.Load().(string), v&1 != 0, v&2 != 0, v&4 != 0})
		if err == nil {
			err = receive.Decode(&next)
		}
		if err != nil {
			// Close a broken stream before waiting for stderr.
			_ = requests.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if detail := strings.TrimSpace(stderr.String()); detail != "" {
				return fmt.Errorf("%s", detail)
			}
			return fmt.Errorf("read Yip snapshot: %w", err)
		}
		select {
		case updates <- next:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-tick:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func terminalCells(text string) string {
	var padded strings.Builder
	for _, r := range text {
		switch {
		case r == '\t':
			padded.WriteString("    ")
		case r == '\n':
			padded.WriteRune(r)
		case unicode.IsPrint(r):
			padded.WriteRune(r)
			if runewidth.RuneWidth(r) == 2 {
				padded.WriteByte(' ')
			}
		}
	}
	return padded.String()
}

func applySnapshot(next boardSnapshot, selected string) string {
	var allocations []*C.char
	copyString := func(s string) *C.char {
		p := C.CString(s)
		allocations = append(allocations, p)
		return p
	}
	defer func() {
		for _, p := range allocations {
			C.free(unsafe.Pointer(p))
		}
	}()

	C.board_lines(copyString(strings.Join(next.Lines, "\n")))
	C.board_snapshot(copyString(terminalCells(next.Line)), copyString(terminalCells(next.Error)),
		copyString(next.TranscriptID), copyString(terminalCells(next.Transcript)),
		copyString(terminalCells(strings.Join(next.Overview, "\n"))),
		copyString(terminalCells(strings.Join(next.Topology, "\n"))),
		copyString(next.TranscriptInks), copyString(next.OverviewInks), copyString(next.TopologyInks))
	for i, group := range []struct {
		rows []string
		inks string
	}{{next.Topology, next.TopologyInks}, {next.Health, next.HealthInks}, {next.Broadcasts, next.BroadcastInks}, {next.Roadmaps, next.RoadmapInks}} {
		C.board_extra(C.int(i), copyString(terminalCells(strings.Join(group.rows, "\n"))), copyString(group.inks))
	}
	index := 0
	for i, call := range next.Calls {
		if call.ID == selected {
			index = i
		}
		subject := strings.ReplaceAll(terminalCells(call.Subject), "\n", " ")
		C.board_add_call(copyString(call.ID), copyString(subject),
			copyString(terminalCells(call.Status)), copyString(terminalCells(call.Floor)), copyString(terminalCells(call.Participants)), copyString(call.Route), copyString(terminalCells(call.Progress)))
	}
	C.board_select(C.int(index))
	if len(next.Calls) == 0 {
		return ""
	}
	return next.Calls[index].ID
}
