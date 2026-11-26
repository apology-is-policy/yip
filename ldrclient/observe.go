package ldrclient

import (
	"context"
	"errors"
	"github.com/apology-is-policy/yip/ldrrelay"
	"slices"
	"sort"
	"time"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

// CallObservation describes one verified client checkpoint. Viewing a call
// keeps delivery receipts, scan cursors and pending send recovery independent.
type CallObservation struct {
	Origin                       ldrcrypto.RelayOrigin
	Status                       ClientStatus
	VerifiedAt                   time.Time
	Calls                        []CallSummary
	Actors                       []ActorSummary
	Credentials                  []ObservedCredential
	Transcript                   *CallTranscript
	Broadcasts                   []BroadcastView
	Roadmaps                     []VerifiedRegister
	Stage                        string
	BroadcastError, RoadmapError string
}

type ObservedCredential struct {
	ID        string
	Namespace string
	Revoked   bool
}

// ObserveCalls acquires the member directory only for this refresh. Sync may
// advance verified.wal and unwrap epoch keys, but the observer cannot submit
// operations or initiate outbox recovery on behalf of its co-resident agent.
func ObserveCalls(ctx context.Context, dir, selected string, previous *CallObservation) (CallObservation, error) {
	return ObserveSwitchboard(ctx, dir, selected, previous, ObservationViews{})
}

type ObservationViews struct{ Broadcasts, Roadmaps bool }

func ObserveSwitchboard(ctx context.Context, dir, selected string, previous *CallObservation, views ObservationViews) (CallObservation, error) {
	next := CallObservation{Stage: "Opening client directory"}
	c, err := openClientWait(ctx, dir, false)
	if err != nil {
		return next, err
	}
	defer c.Close()
	desc, _, _, _ := c.Descriptor()
	next.Origin, next.Status = desc.RelayOrigin, c.Status()
	next.Stage = "Authenticating relay session"
	sess, err := c.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		var refused *ldrrelay.AuthError
		if errors.As(err, &refused) {
			next.Stage = "Relay reached · credential refused"
		} else {
			next.Stage = "Relay session unavailable"
		}
		return next, err
	}
	defer sess.Close()
	next.Stage = "Verifying control log"
	if _, err = c.Sync(ctx, sess); err != nil {
		return next, err
	}
	next.Status = c.Status()
	reuse := previous != nil && !previous.VerifiedAt.IsZero() && previous.Status.LineID == next.Status.LineID &&
		previous.Status.CredID == next.Status.CredID && previous.Status.CheckpointHd == next.Status.CheckpointHd &&
		slices.Equal(previous.Status.HasEpochKeys, next.Status.HasEpochKeys)
	if reuse {
		next.Calls, next.Actors, next.Credentials = previous.Calls, previous.Actors, previous.Credentials
	} else {
		next.Calls, err = c.ListCallSummaries(ctx, sess, "", true)
		if err != nil {
			return next, err
		}
		sort.SliceStable(next.Calls, func(i, j int) bool {
			a, b := next.Calls[i], next.Calls[j]
			if (a.Status == "open") != (b.Status == "open") {
				return a.Status == "open"
			}
			return a.LastTimeMS > b.LastTimeMS
		})
		next.Actors = c.ListActors()
		for id, cred := range c.state.Line.Credentials {
			next.Credentials = append(next.Credentials, ObservedCredential{id, cred.Namespace, cred.Revoked})
		}
		sort.Slice(next.Credentials, func(i, j int) bool { return next.Credentials[i].ID < next.Credentials[j].ID })
	}
	if len(next.Calls) > 0 {
		id := next.Calls[0].ID
		for _, call := range next.Calls {
			if call.ID == selected {
				id = selected
				break
			}
		}
		if reuse && previous.Transcript != nil && previous.Transcript.ID == id {
			next.Transcript = previous.Transcript
		} else {
			next.Transcript, err = c.ReadCallTranscript(ctx, sess, id)
			if err != nil {
				return next, err
			}
		}
	}
	next.Stage = "Authenticated and synced · last refresh"
	next.VerifiedAt = time.Now()
	if views.Broadcasts {
		next.Broadcasts, err = c.ListBroadcasts(ctx, sess, "", true)
		if err != nil {
			next.BroadcastError = err.Error()
		}
	}
	if views.Roadmaps {
		next.Roadmaps, err = c.ReadRegisters(ctx, sess, "roadmap")
		if err != nil {
			next.RoadmapError = err.Error()
		}
	}
	return next, nil
}
