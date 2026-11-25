// Package ldrrelay implements the operator-hosted Go LDR relay: ClockGuard
// discontinuity detector, canonical wire-intent bridge into ldrcore.Apply,
// serialized per-line sequencer engine backed by ldrstore.Store, and TLS 1.3
// server/client transport with RFC 9266 tls-exporter channel binding.
package ldrrelay

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/apology-is-policy/yip/ldrcore"
)

// ClockSample pairs a wall-clock reading (UTC ms) with a process-local
// monotonic reading (ms).
type ClockSample struct {
	WallMS int64
	MonoMS int64
}

// ClockSource returns a synchronized pair of wall and monotonic milliseconds.
type ClockSource func() ClockSample

// RealClockSource returns a ClockSource backed by Go's time.Now() wall and
// monotonic clocks.
func RealClockSource() ClockSource {
	boot := time.Now()
	return func() ClockSample {
		now := time.Now()
		return ClockSample{
			WallMS: now.UnixMilli(),
			MonoMS: now.Sub(boot).Milliseconds(),
		}
	}
}

// ClockConfig tunes discontinuity, freeze, and restart-jump guardrails (§4.1).
type ClockConfig struct {
	// MaxBackwardSkewMS allows clamping minor backward NTP slews up to this
	// threshold to the persisted time_floor; larger backward steps trip
	// clock_uncertain. Default: 5000 ms (5 s).
	MaxBackwardSkewMS int64
	// MaxStepDriftMS trips clock_uncertain when |delta_wall - delta_mono|
	// exceeds this threshold (catches forward/backward wall jumps and host sleep).
	// Default: 5000 ms (5 s).
	MaxStepDriftMS int64
	// FreezeDetectMS trips clock_uncertain if delta_mono >= FreezeDetectMS while
	// delta_wall == 0. Default: 30000 ms (30 s).
	FreezeDetectMS int64
	// MaxRestartForwardJumpMS trips clock_uncertain at startup if wall time is
	// more than this far ahead of a non-zero persisted time_floor (guards against
	// RTC/BIOS jumps to far future). Default: 30 days.
	MaxRestartForwardJumpMS int64
}

// DefaultClockConfig returns conservative Phase B clock-guard thresholds.
func DefaultClockConfig() ClockConfig {
	return ClockConfig{
		MaxBackwardSkewMS:       5_000,
		MaxStepDriftMS:          5_000,
		FreezeDetectMS:          30_000,
		MaxRestartForwardJumpMS: 30 * 24 * 3600 * 1000,
	}
}

func (c ClockConfig) normalized() ClockConfig {
	d := DefaultClockConfig()
	if c.MaxBackwardSkewMS <= 0 {
		c.MaxBackwardSkewMS = d.MaxBackwardSkewMS
	}
	if c.MaxStepDriftMS <= 0 {
		c.MaxStepDriftMS = d.MaxStepDriftMS
	}
	if c.FreezeDetectMS <= 0 {
		c.FreezeDetectMS = d.FreezeDetectMS
	}
	if c.MaxRestartForwardJumpMS <= 0 {
		c.MaxRestartForwardJumpMS = d.MaxRestartForwardJumpMS
	}
	return c
}

// ClockStatus reports diagnostic state for operator status/health inspection.
type ClockStatus struct {
	Trusted         bool   `json:"trusted"`
	UncertainReason string `json:"uncertain_reason,omitempty"`
	FloorMS         uint64 `json:"floor_ms"`
	LastWallMS      int64  `json:"last_wall_ms"`
	LastDriftMS     int64  `json:"last_drift_ms"`
}

// ClockGuard enforces LDR's monotonic time_floor and fail-closed discontinuity
// detection (LDR-GO-RELAY-DESIGN §4.1). Safe for concurrent use.
type ClockGuard struct {
	mu               sync.Mutex
	cfg              ClockConfig
	nowFn            ClockSource
	floorMS          int64
	trusted          bool
	uncertainReason  string
	prevWallMS       int64
	prevMonoMS       int64
	lastWallChangeMo int64
	lastDriftMS      int64
}

// NewClockGuard initializes a ClockGuard against a persisted time_floor.
func NewClockGuard(persistedFloor uint64, cfg ClockConfig, nowFn ClockSource) *ClockGuard {
	cfg = cfg.normalized()
	if nowFn == nil {
		nowFn = RealClockSource()
	}
	sample := nowFn()
	g := &ClockGuard{
		cfg:              cfg,
		nowFn:            nowFn,
		floorMS:          int64(persistedFloor),
		trusted:          true,
		prevWallMS:       sample.WallMS,
		prevMonoMS:       sample.MonoMS,
		lastWallChangeMo: sample.MonoMS,
	}
	if sample.WallMS < 0 || sample.WallMS > ldrcore.MaxCounter {
		g.tripLocked("wall_clock_out_of_domain")
		return g
	}
	if g.floorMS > 0 {
		if sample.WallMS < g.floorMS {
			skew := g.floorMS - sample.WallMS
			if skew > cfg.MaxBackwardSkewMS {
				g.tripLocked(fmt.Sprintf("restart_backward_jump_%dms", skew))
			}
		} else if sample.WallMS-g.floorMS > cfg.MaxRestartForwardJumpMS {
			g.tripLocked(fmt.Sprintf("restart_forward_jump_%dms", sample.WallMS-g.floorMS))
		}
	}
	return g
}

func (g *ClockGuard) tripLocked(reason string) {
	if g.trusted {
		g.trusted = false
		g.uncertainReason = reason
	}
}

// Sample reads the clock and updates drift/freeze checks without advancing floor.
func (g *ClockGuard) Sample() ClockStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sampleLocked()
	return g.statusLocked()
}

func (g *ClockGuard) sampleLocked() ClockSample {
	cur := g.nowFn()
	if !g.trusted {
		return cur
	}
	if cur.WallMS < 0 || cur.WallMS > ldrcore.MaxCounter {
		g.tripLocked("wall_clock_out_of_domain")
		return cur
	}
	deltaWall := cur.WallMS - g.prevWallMS
	deltaMono := cur.MonoMS - g.prevMonoMS
	if deltaMono < 0 {
		g.tripLocked("monotonic_clock_regressed")
		return cur
	}
	drift := deltaWall - deltaMono
	g.lastDriftMS = drift
	absDrift := drift
	if absDrift < 0 {
		absDrift = -absDrift
	}
	if absDrift > g.cfg.MaxStepDriftMS {
		g.tripLocked(fmt.Sprintf("clock_step_drift_%dms", drift))
		return cur
	}
	if cur.WallMS < g.floorMS && g.floorMS-cur.WallMS > g.cfg.MaxBackwardSkewMS {
		g.tripLocked(fmt.Sprintf("backward_below_floor_%dms", g.floorMS-cur.WallMS))
		return cur
	}
	if cur.WallMS != g.prevWallMS {
		g.lastWallChangeMo = cur.MonoMS
	} else if cur.MonoMS-g.lastWallChangeMo >= g.cfg.FreezeDetectMS {
		g.tripLocked(fmt.Sprintf("wall_clock_frozen_%dms", cur.MonoMS-g.lastWallChangeMo))
		return cur
	}
	g.prevWallMS = cur.WallMS
	g.prevMonoMS = cur.MonoMS
	return cur
}

// Reading returns the current trustworthy evaluation time (>= persisted floor)
// or (0, false) if the clock is uncertain. Calling Reading does NOT mutate the
// persisted floor until AdvanceFloor is called after a durable write.
func (g *ClockGuard) Reading() (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur := g.sampleLocked()
	if !g.trusted {
		return 0, false
	}
	t := cur.WallMS
	if t < g.floorMS {
		t = g.floorMS
	}
	if t < 0 || t > ldrcore.MaxCounter {
		g.tripLocked("evaluation_time_out_of_domain")
		return 0, false
	}
	return uint64(t), true
}

// AdvanceFloor monotonically advances the in-memory floor after durable persistence.
func (g *ClockGuard) AdvanceFloor(floor uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if int64(floor) > g.floorMS {
		g.floorMS = int64(floor)
	}
}

// Floor returns the current persisted floor in milliseconds.
func (g *ClockGuard) Floor() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return uint64(g.floorMS)
}

// Status returns a snapshot of the ClockGuard state.
func (g *ClockGuard) Status() ClockStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.statusLocked()
}

func (g *ClockGuard) statusLocked() ClockStatus {
	return ClockStatus{
		Trusted:         g.trusted,
		UncertainReason: g.uncertainReason,
		FloorMS:         uint64(g.floorMS),
		LastWallMS:      g.prevWallMS,
		LastDriftMS:     g.lastDriftMS,
	}
}

// ConfirmResume re-baselines ClockGuard after an operator or trusted health
// check confirms the host wall clock is synchronized and >= floor.
func (g *ClockGuard) ConfirmResume() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur := g.nowFn()
	if cur.WallMS < 0 || cur.WallMS > ldrcore.MaxCounter {
		return errors.New("ldrrelay: cannot resume clock outside safe domain")
	}
	if cur.WallMS < g.floorMS {
		return fmt.Errorf("ldrrelay: cannot resume clock while wall %d < floor %d", cur.WallMS, g.floorMS)
	}
	g.prevWallMS = cur.WallMS
	g.prevMonoMS = cur.MonoMS
	g.lastWallChangeMo = cur.MonoMS
	g.lastDriftMS = 0
	g.trusted = true
	g.uncertainReason = ""
	return nil
}
