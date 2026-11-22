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
	SessionID     string `json:"session_id"`

	// Antigravity (agy) camelCase protojson fields.
	ConversationID     string `json:"conversationId"`
	AgyHookEventName   string `json:"hookEventName"`
	TerminationReason  string `json:"terminationReason"`
	ContinuationActive bool   `json:"continuationActive"`
	FullyIdle          bool   `json:"fullyIdle"`
	ToolCall           *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"toolCall"`
}

func (in hookInput) toolName() string {
	if in.ToolName != "" {
		return in.ToolName
	}
	if in.ToolCall != nil {
		return in.ToolCall.Name
	}
	return ""
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
	quiet := func() {
		if runtime == "agy" {
			emit(map[string]any{})
		}
	}
	if _, err := os.Stat(Root()); err != nil {
		quiet()
		return
	}
	// A Claude/Antigravity session's boundary is recorded before anything resolves
	// an identity for it -- by whichever hook runs first -- or a session started
	// inside a bound one would answer as that one. Unregistrable: say nothing
	// once anybody is bound; until then answer to the launch name outright --
	// resolution would walk past this session to a binding made meanwhile.
	var me string
	var launch string
	if runtime != "codex" {
		var err error
		launch, err = launchIdentity(override, in.Cwd)
		if err != nil {
			quiet()
			return
		}
		if s := hookSession(); !isRegistered(s) && registerSession(s, launch) != nil {
			if anyLiveBinding() {
				quiet()
				return
			}
			me = launch
		}
	}
	if me == "" {
		var err error
		if runtime == "agy" && threadRE.MatchString(in.ConversationID) {
			me, err = identityForConv(launch, true, in.ConversationID)
		} else {
			me, err = WhoAmI(override, in.Cwd)
		}
		if err != nil {
			quiet()
			return
		}
	}
	if launch == "" {
		launch = me
	}
	var result any
	switch strings.ToLower(event) {
	case "posttooluse":
		if runtime == "agy" {
			// Antigravity PostToolUse expects `{}` only and cannot inject context;
			// heartbeat presence here and deliver mid-turn notices in PreInvocation.
			_ = Beat(me, in.toolName())
		} else {
			result = hookPostToolUse(me, in)
		}
	case "preinvocation":
		result = hookPostToolUse(me, in)
	case "stop":
		if runtime == "agy" && in.TerminationReason != "" && in.TerminationReason != "NO_TOOL_CALL" {
			// Never hold a turn that stopped due to user cancel, error, or limits.
			result = nil
		} else {
			result = hookStop(me)
		}
	case "sessionstart":
		result = hookSessionStart(me)
		if runtime == "codex" {
			result = withContext(result, "SessionStart", codexBindNudge(me, in.SessionID))
		} else if runtime == "agy" {
			result = withContext(result, "SessionStart", agyListenNudge(me, launch, activeLine, in.ConversationID))
		}
	}
	switch runtime {
	case "codex":
		result = codexHookOutput(event, result)
	case "agy":
		result = agyHookOutput(event, result)
	}
	emit(result)
}

// codexBindNudge: a Codex chat binds delivery at its first Yip tool call, and
// a new chat has made none. Say so once, at session start, unless this exact
// session already holds a live binding. The hook names the session but does
// not bind it: only the session's own MCP server can prove it serves it.
func codexBindNudge(me, session string) string {
	ep, err := readEndpoint(me)
	if err != nil || ep.Runtime != "codex" || ep.Paused || Retired(me) {
		return ""
	}
	if session != "" && ep.Thread == session && codexSessionAlive(me, session) {
		return ""
	}
	return "[yip] You are " + me + ". Call the Yip ring tool now so Yip notices for " + me + " are delivered to this chat."
}

func withContext(result any, event, line string) any {
	if line == "" {
		return result
	}
	m, _ := result.(map[string]any)
	if m == nil {
		return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": event, "additionalContext": line}}
	}
	h, _ := m["hookSpecificOutput"].(map[string]any)
	if h == nil {
		h = map[string]any{"hookEventName": event}
		m["hookSpecificOutput"] = h
	}
	if prev, _ := h["additionalContext"].(string); prev != "" {
		line = prev + "\n" + line
	}
	h["additionalContext"] = line
	return m
}

// ------------------------------------------------------------ PostToolUse

// Fires on every tool call, so it must be quiet unless something actually
// changed. NotifiedAt is what keeps it from repeating itself: one notice per
// new turn, not one per tool call until the agent reads.
func hookPostToolUse(me string, in hookInput) any {
	_ = Beat(me, in.toolName())
	nudge := roadmapNudge(me)
	// A live push path delivers these already; repeating them per tool call is
	// noise. Cursors are not advanced, so the hook resumes when push lapses.
	// The roadmap nudge is not a delivered notice, so it still speaks.
	if channelPreferred(me) || rewakeArmed(me) || agyPushLive(me) {
		if nudge == "" {
			return nil
		}
		return map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"additionalContext": "[yip] " + nudge,
		}}
	}

	rings, err := RingFor(me)
	if err != nil {
		return nil
	}
	lines := append(NoteNotices(me), FreshRecoveryNotices(me)...)
	lines = append(lines, BroadcastNotices(me)...)
	if nudge != "" {
		lines = append(lines, nudge)
	}
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
	defer func() { _ = MeasureTip(me) }() // bounded; after the decision
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
	if r, ok, err := LoadRoadmap(me); err == nil && ok {
		parts = append(parts, "[yip] Your roadmap: "+RoadmapSummary(r)+" Updated "+span(roadmapAge(r))+" ago; roadmap_at moves the marker.")
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
