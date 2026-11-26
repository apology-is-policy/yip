package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/apology-is-policy/yip/ldrclient"
	"strings"
	"testing"
)

func TestSwitchboardSnapshotStream(t *testing.T) {
	tmpLine(t)
	var out bytes.Buffer
	if err := serveSwitchboardSnapshots(context.Background(), strings.NewReader("\"\"\n\"missing\"\n"), &out); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	for i := 0; i < 2; i++ {
		var snap switchboardSnapshot
		if err := dec.Decode(&snap); err != nil {
			t.Fatal(err)
		}
		if snap.Error != "" || len(snap.Overview) == 0 || snap.TranscriptID != "" {
			t.Fatalf("unexpected empty-line snapshot: %+v", snap)
		}
	}
}

func TestSwitchboardSnapshotFollowsSelectedCall(t *testing.T) {
	state := sbState{calls: []*sbCall{
		{call: &Call{ID: "first"}},
		{call: &Call{ID: "second", Subject: "\033[31mLive call", From: "self", To: "peer"}, entries: []sbEntry{
			{kind: "TURN", from: "peer", n: 3, body: "message\033[0m with 東京"},
		}},
	}}
	snap := makeSwitchboardSnapshot(state, "second", ldrclient.ObservationViews{})
	if snap.TranscriptID != "second" || snap.Transcript != "peer · TURN #3\nmessage with 東京" || !strings.HasPrefix(snap.TranscriptInks, "g ") ||
		len(snap.Calls) != 2 || snap.Calls[1].Subject != "Live call" || snap.Calls[1].Route != "Local call" || snap.Calls[1].Participants != "self ⇄ peer" {
		t.Fatalf("unexpected selected snapshot: %+v", snap)
	}
}
