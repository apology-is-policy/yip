package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/apology-is-policy/yip/ldrclient"
	"github.com/apology-is-policy/yip/ldrcore"
	"os"
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
	snap := makeSwitchboardSnapshot(state, "second", ldrclient.ObservationViews{}, 65)
	if snap.TranscriptID != "second" || snap.Transcript != "peer · TURN #3\nmessage with 東京" || !strings.HasPrefix(snap.TranscriptInks, "g ") ||
		len(snap.Calls) != 2 || snap.Calls[1].Subject != "Live call" || snap.Calls[1].Route != "Local call" || snap.Calls[1].Participants != "self ⇄ peer" {
		t.Fatalf("unexpected selected snapshot: %+v", snap)
	}
}

func TestSwitchboardCreateNamedLine(t *testing.T) {
	previous := activeLine
	t.Cleanup(func() { activeLine = previous })
	t.Setenv("YIP_HOME", t.TempDir())
	t.Setenv("YIP_ROOT", "")
	if err := createSwitchboardLine([]string{"garden"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(callsDir()); err != nil {
		t.Fatal(err)
	}
	if err := createSwitchboardLine([]string{"garden"}); err == nil {
		t.Fatal("accepted duplicate")
	}
	if err := createSwitchboardLine([]string{"../other"}); err == nil {
		t.Fatal("accepted invalid name")
	}
}

func TestSwitchboardRelayRoadmapUsesVerifiedActorAndStations(t *testing.T) {
	payload := ldrRoadmapPayload{Roadmap: &Roadmap{Agent: "untrusted-label", Arc: "Release", Active: "review", Stations: []RoadmapStation{{Name: "Draft", ID: "draft"}, {Name: "Review", ID: "review"}}}}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	st := sbState{relay: &sbRelay{CallObservation: ldrclient.CallObservation{Roadmaps: []ldrclient.VerifiedRegister{{Actor: "garden-bot", ReadStatus: ldrcore.ReadOK, Plaintext: body, Historical: true}}}}}
	snap := makeSwitchboardSnapshot(st, "", ldrclient.ObservationViews{Roadmaps: true}, 110)
	text := strings.Join(snap.Roadmaps, "\n")
	for _, label := range []string{"garden-bot", "Release", "[historical]", "Review", "Draft", "NOW"} {
		if !strings.Contains(text, label) {
			t.Fatalf("missing %q: %s", label, text)
		}
	}
	if strings.Contains(text, "untrusted-label") {
		t.Fatal("displayed actor label from roadmap body")
	}
}
