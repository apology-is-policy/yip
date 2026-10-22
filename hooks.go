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
func RunHook(event string, override string) { RunHookRuntime(event, override, "claude") }
func RunHookRuntime(event string, override string, runtime string) {
	in := readHookInput()
	me, err := WhoAmI(override, in.Cwd)
	if err != nil {
		return
	}
	if _, err := os.Stat(Root()); err != nil {
		return
	}
	var result any
	switch strings.ToLower(event) {
	case "posttooluse":
		result = hookPostToolUse(me, in)
	case "stop":
		result = hookStop(me)
	case "sessionstart":
		result = hookSessionStart(me)
	}
	if runtime == "codex" {
		result = codexHookOutput(event, result)
	}
	emit(result)
}

// ------------------------------------------------------------ PostToolUse

// Fires on every tool call, so it must be quiet unless something actually
// changed. NotifiedAt is what keeps it from repeating itself: one notice per
// new turn, not one per tool call until the agent reads.
func hookPostToolUse(me string, in hookInput) any {
	_ = Beat(me, in.ToolName)
	if channelPreferred(me) {
		return nil
	}

	rings, err := RingFor(me)
	if err != nil {
		return nil
	}
	lines := append(NoteNotices(me), FreshRecoveryNotices(me)...)
	lines = append(lines, BroadcastNotices(me)...)
	fresh := len(lines) > 0
	brandNew := false
	for _, r := range rings {
		notify := false
		err := UpdateAgentState(r.Call, me, func(st *AgentState) {
			if r.Revision <= st.NotifiedAt {
				return
			}
			notify = true
			if st.NotifiedAt == 0 && st.Seen == 0 {
				brandNew = true
			}
			st.NotifiedAt = r.Revision
		})
		if err != nil || !notify {
			continue
		}
		fresh = true
		lines = append(lines, ringLine(r, me))
	}
	if !fresh {
		return nil
	}
	out := map[string]any{
		"hookEventName":     "PostToolUse",
		"additionalContext": "[yip] " + strings.Join(lines, " ") + " Use read; reply only when a call requires it. Notes are FYIs.",
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
		block := false
		err := UpdateAgentState(r.Call, me, func(st *AgentState) {
			if r.Revision > st.BlockedAt {
				st.BlockedAt = r.Revision
				block = true
			}
		})
		if err != nil || !block {
			continue
		}
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
	if b := BroadcastInbox(me, false); b != "" {
		parts = append(parts, b)
	}
	if notices := FreshRecoveryNotices(me); len(notices) > 0 {
		parts = append(parts, "[yip resources] "+strings.Join(notices, " "))
	}
	if notices := NoteNotices(me); len(notices) > 0 {
		parts = append(parts, "[yip notes] "+strings.Join(notices, " "))
	}
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
