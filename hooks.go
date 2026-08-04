package main

// The hook face.
//
// Deliberately CLI, not MCP: the hook has to work when the MCP server is
// down, and the hook is exactly what would tell you it is down. A ring
// system that depends on the thing it is ringing about is circular.
//
// A hook must never break the session it runs in. Every path here exits 0
// and prints nothing rather than failing.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type hookInput struct {
	Cwd           string `json:"cwd"`
	ToolName      string `json:"tool_name"`
	HookEventName string `json:"hook_event_name"`
	Source        string `json:"source"`
}

func readHookInput() hookInput {
	var in hookInput
	_ = json.NewDecoder(os.Stdin).Decode(&in)
	return in
}

func emit(v any) {
	if v == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Println(string(b))
}

// RunHook dispatches and always succeeds. A relay that is not set up yet, a
// worktree we cannot name, an unreadable call -- all mean "say nothing".
func RunHook(event string, override string) {
	in := readHookInput()
	me, err := WhoAmI(override, in.Cwd)
	if err != nil {
		return
	}
	if _, err := os.Stat(Root()); err != nil {
		return
	}
	switch strings.ToLower(event) {
	case "posttooluse":
		emit(hookPostToolUse(me, in))
	case "stop":
		emit(hookStop(me))
	case "sessionstart":
		emit(hookSessionStart(me))
	}
}

// ------------------------------------------------------------ PostToolUse

// Fires on every tool call, so it must be quiet unless something actually
// changed. NotifiedAt is what keeps it from repeating itself: one notice per
// new turn, not one per tool call until the agent reads.
func hookPostToolUse(me string, in hookInput) any {
	_ = Beat(me, in.ToolName)

	rings, err := RingFor(me)
	if err != nil || len(rings) == 0 {
		return nil
	}
	var lines []string
	fresh := false
	brandNew := false
	for _, r := range rings {
		st := LoadAgentState(r.Call, me)
		if r.LastTurn <= st.NotifiedAt {
			continue
		}
		fresh = true
		if st.NotifiedAt == 0 && st.Seen == 0 {
			brandNew = true
		}
		st.NotifiedAt = r.LastTurn
		_ = SaveAgentState(r.Call, me, st)
		lines = append(lines, ringLine(r, me))
	}
	if !fresh {
		return nil
	}
	out := map[string]any{
		"hookEventName":     "PostToolUse",
		"additionalContext": "[yip] " + strings.Join(lines, " ") + " Use mcp__yip__read then mcp__yip__say.",
	}
	res := map[string]any{"hookSpecificOutput": out}
	if brandNew {
		// An actual ring: bell, and the window title says who is calling.
		res["terminalSequence"] = "\a\x1b]0;yip: incoming call\x07"
	}
	return res
}

func ringLine(r Ring, me string) string {
	peer := r.Call.Peer(me)
	switch {
	case r.Unseen > 0 && r.HaveFloor:
		return fmt.Sprintf("%s spoke on %s (turn %d, %d unread); the floor is yours.",
			peer, r.Call.ID, r.LastTurn, r.Unseen)
	case r.Unseen > 0:
		return fmt.Sprintf("%s spoke on %s (turn %d, %d unread).", peer, r.Call.ID, r.LastTurn, r.Unseen)
	default:
		return fmt.Sprintf("The floor is yours on %s (turn %d).", r.Call.ID, r.LastTurn)
	}
}

// ------------------------------------------------------------------- Stop

// The piece that makes an exchange finish without the user: an agent cannot
// end its turn while it owes the peer a reply.
//
// BlockedAt is the loop guard. It records the turn count we blocked at, so a
// second Stop with nothing changed does not block again -- and speaking
// advances the count, which re-arms it for the next turn.
func hookStop(me string) any {
	rings, err := RingFor(me)
	if err != nil || len(rings) == 0 {
		return nil
	}
	var lines []string
	for _, r := range rings {
		if !r.HaveFloor && r.Unseen == 0 {
			continue
		}
		st := LoadAgentState(r.Call, me)
		if r.LastTurn <= st.BlockedAt {
			continue // already blocked at this state; do not wedge the session
		}
		st.BlockedAt = r.LastTurn
		_ = SaveAgentState(r.Call, me, st)
		lines = append(lines, ringLine(r, me))
	}
	if len(lines) == 0 {
		return nil
	}
	msg := "[yip] " + strings.Join(lines, " ") +
		" Read and reply before stopping. If the matter is settled, say bye. " +
		"If you cannot answer now, say that on the call so the peer is not left waiting."
	return map[string]any{
		"decision": "block",
		"reason":   msg,
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "Stop",
			"additionalContext": msg,
		},
	}
}

// ----------------------------------------------------------- SessionStart

// Catches the cold open, a resume, and the turn after a compaction -- so a
// long session gets re-told what it owes.
func hookSessionStart(me string) any {
	_ = Beat(me, "")

	var parts []string
	if rings, err := RingFor(me); err == nil && len(rings) > 0 {
		var lines []string
		for _, r := range rings {
			lines = append(lines, ringLine(r, me))
		}
		parts = append(parts, "[yip] "+strings.Join(lines, " "))
	}
	if txt, err := presenceText("", me); err == nil && txt != "" {
		peers := []string{}
		for _, line := range strings.Split(txt, "\n") {
			if strings.HasPrefix(line, " ") || strings.Contains(line, "(you)") {
				continue
			}
			peers = append(peers, strings.TrimSpace(line))
		}
		if len(peers) > 0 {
			parts = append(parts, "[yip] peers: "+strings.Join(peers, "; "))
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "SessionStart",
			"additionalContext": strings.Join(parts, "\n"),
		},
	}
}
