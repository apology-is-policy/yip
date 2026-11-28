package ldrrelay

import (
	"math"
	"strings"
	"testing"

	"github.com/apology-is-policy/yip/ldrcore"
)

type fakeClock struct {
	wall int64
	mono int64
}

func (f *fakeClock) source() ClockSource {
	return func() ClockSample {
		return ClockSample{WallMS: f.wall, MonoMS: f.mono}
	}
}

func TestClockGuardNormalAndMinorNTPSlew(t *testing.T) {
	fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
	cg := NewClockGuard(1_700_000_000_000, DefaultClockConfig(), fc.source())

	if st := cg.Status(); !st.Trusted {
		t.Fatalf("expected trusted at start, got %+v", st)
	}
	// Normal 1s progress.
	fc.wall += 1000
	fc.mono += 1000
	tm, ok := cg.Reading()
	if !ok || tm != 1_700_000_001_000 {
		t.Fatalf("expected 1700000001000 trusted, got (%d, %v)", tm, ok)
	}
	cg.AdvanceFloor(tm)

	// Minor 100ms backward NTP slew: drift = -200ms (within 5s), clamped safely to floor.
	fc.wall -= 100
	fc.mono += 100
	tm, ok = cg.Reading()
	if !ok || tm != 1_700_000_001_000 {
		t.Fatalf("minor NTP slew should clamp to floor 1700000001000, got (%d, %v)", tm, ok)
	}
}

func TestClockGuardDetectsDiscontinuitiesAndResumes(t *testing.T) {
	t.Run("forward_wall_jump_or_laptop_sleep", func(t *testing.T) {
		fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
		cg := NewClockGuard(0, DefaultClockConfig(), fc.source())
		cg.AdvanceFloor(uint64(fc.wall))

		// Simulate 2-hour laptop sleep: wall advances 7,200,000 ms while mono advances 5 ms.
		fc.wall += 7_200_000
		fc.mono += 5
		if _, ok := cg.Reading(); ok {
			t.Fatalf("expected clock_uncertain after sleep/forward jump")
		}
		if st := cg.Status(); st.Trusted || !strings.Contains(st.UncertainReason, "clock_step_drift") {
			t.Fatalf("unexpected status: %+v", st)
		}
		// Explicit operator/health confirmation resumes safely because wall >= floor.
		if err := cg.ConfirmResume(); err != nil {
			t.Fatalf("ConfirmResume: %v", err)
		}
		tm, ok := cg.Reading()
		if !ok || tm != uint64(fc.wall) {
			t.Fatalf("expected trusted after resume, got (%d, %v)", tm, ok)
		}
	})

	t.Run("backward_wall_jump", func(t *testing.T) {
		fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
		cg := NewClockGuard(0, DefaultClockConfig(), fc.source())
		cg.AdvanceFloor(uint64(fc.wall))

		fc.wall -= 10_000
		fc.mono += 100
		if _, ok := cg.Reading(); ok {
			t.Fatalf("expected clock_uncertain on 10s backward jump")
		}
		// Resume MUST fail while wall < floor.
		if err := cg.ConfirmResume(); err == nil {
			t.Fatalf("ConfirmResume succeeded while wall < floor")
		}
		// Once host clock catches back up to floor, resume succeeds.
		fc.wall += 12_000
		fc.mono += 1000
		if err := cg.ConfirmResume(); err != nil {
			t.Fatalf("ConfirmResume after fix: %v", err)
		}
	})

	t.Run("frozen_wall_clock", func(t *testing.T) {
		fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
		cfg := DefaultClockConfig()
		cfg.MaxStepDriftMS = 60_000 // isolate freeze check from step drift check
		cfg.FreezeDetectMS = 30_000
		cg := NewClockGuard(0, cfg, fc.source())

		fc.mono += 10_000
		if _, ok := cg.Reading(); !ok {
			t.Fatalf("should still be trusted at 10s")
		}
		fc.mono += 25_000 // total 35s with zero wall progress
		if _, ok := cg.Reading(); ok {
			t.Fatalf("expected clock_uncertain on frozen wall clock")
		}
		if st := cg.Status(); !strings.Contains(st.UncertainReason, "wall_clock_frozen") {
			t.Fatalf("unexpected reason: %+v", st)
		}
	})

	t.Run("restart_backward_and_far_forward_jumps", func(t *testing.T) {
		persistedFloor := uint64(1_700_000_000_000)

		// Restart with clock 15s behind persisted floor -> starts uncertain.
		fcBack := &fakeClock{wall: int64(persistedFloor) - 15_000, mono: 0}
		cgBack := NewClockGuard(persistedFloor, DefaultClockConfig(), fcBack.source())
		if cgBack.Status().Trusted {
			t.Fatalf("expected uncertain on 15s backward restart")
		}

		// Restart with clock 60 days ahead of persisted floor (BIOS/RTC jump) -> starts uncertain.
		fcFwd := &fakeClock{wall: int64(persistedFloor) + 60*24*3600*1000, mono: 0}
		cgFwd := NewClockGuard(persistedFloor, DefaultClockConfig(), fcFwd.source())
		if cgFwd.Status().Trusted {
			t.Fatalf("expected uncertain on 60-day forward restart jump")
		}
	})
}

// TestClockGuardOutOfDomainFloorFailClosed verifies Codex Turn 30 Finding 1:
// persisted floors above ldrcore.MaxCounter (including MaxCounter+1, MaxInt64,
// MaxInt64+1 signed-wrap boundary, and MaxUint64) are rejected BEFORE signed
// conversion and keep ClockGuard fail-closed across Sample, Reading, AdvanceFloor,
// and ConfirmResume.
func TestClockGuardOutOfDomainFloorFailClosed(t *testing.T) {
	// Exact protocol upper boundary MaxCounter MUST remain valid.
	fcMax := &fakeClock{wall: ldrcore.MaxCounter, mono: 0}
	cgMax := NewClockGuard(uint64(ldrcore.MaxCounter), DefaultClockConfig(), fcMax.source())
	if st := cgMax.Status(); !st.Trusted || st.FloorMS != uint64(ldrcore.MaxCounter) {
		t.Fatalf("exact MaxCounter floor should be trusted, got %+v", st)
	}
	if tm, ok := cgMax.Reading(); !ok || tm != uint64(ldrcore.MaxCounter) {
		t.Fatalf("exact MaxCounter Reading: got (%d, %v), want (%d, true)", tm, ok, ldrcore.MaxCounter)
	}

	outOfDomain := []struct {
		name  string
		floor uint64
	}{
		{name: "max_counter_plus_1", floor: uint64(ldrcore.MaxCounter) + 1},
		{name: "max_int64", floor: uint64(math.MaxInt64)},
		{name: "signed_wrap_max_int64_plus_1", floor: uint64(math.MaxInt64) + 1},
		{name: "max_uint64", floor: math.MaxUint64},
	}

	for _, tc := range outOfDomain {
		tc := tc
		t.Run("startup_"+tc.name, func(t *testing.T) {
			fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
			cg := NewClockGuard(tc.floor, DefaultClockConfig(), fc.source())
			st := cg.Status()
			if st.Trusted {
				t.Fatalf("%s: expected fail-closed untrusted ClockGuard, got %+v", tc.name, st)
			}
			if !strings.Contains(st.UncertainReason, "floor_out_of_domain") {
				t.Fatalf("%s: unexpected reason %q", tc.name, st.UncertainReason)
			}
			if st.FloorMS != tc.floor || cg.Floor() != tc.floor {
				t.Fatalf("%s: floor corrupted/wrapped: got %d, want %d", tc.name, cg.Floor(), tc.floor)
			}
			if tm, ok := cg.Reading(); ok || tm != 0 {
				t.Fatalf("%s: Reading MUST fail closed, got (%d, %v)", tc.name, tm, ok)
			}
			if s2 := cg.Sample(); s2.Trusted {
				t.Fatalf("%s: Sample MUST stay untrusted, got %+v", tc.name, s2)
			}
			if err := cg.ConfirmResume(); err == nil {
				t.Fatalf("%s: ConfirmResume MUST refuse out-of-domain persisted floor", tc.name)
			}
			if tm, ok := cg.Reading(); ok || tm != 0 {
				t.Fatalf("%s: Reading after failed ConfirmResume MUST stay fail-closed, got (%d, %v)", tc.name, tm, ok)
			}
		})

		t.Run("advance_floor_"+tc.name, func(t *testing.T) {
			fc := &fakeClock{wall: 1_700_000_000_000, mono: 0}
			cg := NewClockGuard(1_700_000_000_000, DefaultClockConfig(), fc.source())
			if !cg.Status().Trusted {
				t.Fatalf("expected trusted before AdvanceFloor")
			}
			cg.AdvanceFloor(tc.floor)
			if st := cg.Status(); st.Trusted || !strings.Contains(st.UncertainReason, "floor_out_of_domain") {
				t.Fatalf("%s: AdvanceFloor out of domain MUST trip fail-closed, got %+v", tc.name, st)
			}
			if tm, ok := cg.Reading(); ok || tm != 0 {
				t.Fatalf("%s: Reading after out-of-domain AdvanceFloor got (%d, %v)", tc.name, tm, ok)
			}
			if err := cg.ConfirmResume(); err == nil {
				t.Fatalf("%s: ConfirmResume MUST refuse after out-of-domain AdvanceFloor", tc.name)
			}
		})
	}
}
