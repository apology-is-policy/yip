package ldrclient

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

// CallObservation describes one verified client checkpoint. Viewing a call
// keeps delivery receipts, scan cursors and pending send recovery independent.
type CallObservation struct {
	Origin      ldrcrypto.RelayOrigin
	Status      ClientStatus
	VerifiedAt  time.Time
	Calls       []CallSummary
	Actors      []ActorSummary
	Credentials []ObservedCredential
	Transcript  *CallTranscript
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
	var next CallObservation
	c, err := openClient(dir, nil, nil, false)
	if err != nil {
		return next, err
	}
	defer c.Close()
	desc, _, _, _ := c.Descriptor()
	next.Origin, next.Status = desc.RelayOrigin, c.Status()
	sess, err := c.Dial(ctx, ldrcrypto.PrincipalCredential)
	if err != nil {
		return next, err
	}
	defer sess.Close()
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
	next.VerifiedAt = time.Now()
	return next, nil
}
