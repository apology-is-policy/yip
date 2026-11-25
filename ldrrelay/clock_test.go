package ldrrelay

import (
	"strings"
	"testing"
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
