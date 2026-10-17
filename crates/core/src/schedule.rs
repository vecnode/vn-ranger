//! When the next scan is due, and whether the machine went to sleep.
//!
//! Pure arithmetic, because both questions are decisions rather than IO: a plan says how
//! often a resident ranger should look, and a gap between two ticks says whether the
//! machine was asleep. "Now" is a parameter, so every rule here has a test that runs in
//! microseconds rather than in six hours.

/// How often a resident ranger rescans the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The interval, in seconds.
    pub every_secs: u64,
    /// How much the interval may vary, in percent, so a hundred machines do not all scan
    /// on the same second.
    pub jitter_percent: u8,
}

impl Plan {
    /// Six hours, give or take a tenth: often enough to notice, rare enough that a laptop
    /// on battery is not woken for it.
    pub const DEFAULT: Self = Self {
        every_secs: 6 * 60 * 60,
        jitter_percent: 10,
    };

    /// A plan for a caller that wants a fixed interval, as the tests do.
    #[must_use]
    pub fn fixed(every_secs: u64) -> Self {
        Self {
            every_secs,
            jitter_percent: 0,
        }
    }

    /// The interval with this plan's jitter applied, in seconds.
    ///
    /// The offset is derived from the seed rather than from a random source, so the same
    /// machine idles the same way across launches, and a test can predict it.
    #[must_use]
    pub fn interval(&self, seed: u64) -> u64 {
        let spread = u64::from(self.jitter_percent.min(100));
        if spread == 0 || self.every_secs == 0 {
            return self.every_secs;
        }
        let window = self.every_secs.saturating_mul(spread) / 100;
        if window == 0 {
            return self.every_secs;
        }
        // A cheap mixing step: the seed's low bits are stable across launches, and the
        // high bits change with the clock, which is enough for a jitter nobody analyses.
        let mixed = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32;
        let offset = mixed % window.saturating_mul(2).saturating_add(1);
        self.every_secs.saturating_add(offset).saturating_sub(window)
    }
}

/// Whether a scan is due.
#[must_use]
pub fn is_due(now_unix: u64, next_at_unix: u64) -> bool {
    now_unix >= next_at_unix
}

/// When the scan after `now_unix` should happen.
#[must_use]
pub fn next_at(now_unix: u64, plan: Plan, seed: u64) -> u64 {
    now_unix.saturating_add(plan.interval(seed))
}

/// Whether the gap between two observations means the machine was asleep.
///
/// Three intervals is deliberate: one missed tick is a busy machine, two is a slow scan,
/// and three is a lid that closed. A clock that went backwards is not a resume — it is a
/// clock that went backwards, and scanning because of it would loop.
#[must_use]
pub fn resumed(previous_unix: u64, now_unix: u64, tick_secs: u64) -> bool {
    if now_unix <= previous_unix || tick_secs == 0 {
        return false;
    }
    now_unix.saturating_sub(previous_unix) >= tick_secs.saturating_mul(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_plan_has_no_jitter() {
        let plan = Plan::fixed(3600);
        for seed in [0, 1, 42, u64::MAX] {
            assert_eq!(plan.interval(seed), 3600);
        }
    }

    #[test]
    fn the_default_jitter_stays_inside_a_tenth_either_way() {
        let plan = Plan::DEFAULT;
        let window = plan.every_secs / 10;
        for seed in 0..500 {
            let interval = plan.interval(seed);
            assert!(
                interval >= plan.every_secs - window,
                "seed {seed} is too early: {interval}"
            );
            assert!(
                interval <= plan.every_secs + window,
                "seed {seed} is too late: {interval}"
            );
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_interval() {
        let plan = Plan::DEFAULT;
        assert_eq!(plan.interval(7), plan.interval(7));
        let distinct: std::collections::HashSet<u64> = (0..64).map(|seed| plan.interval(seed)).collect();
        assert!(distinct.len() > 1, "jitter that never varies is not jitter");
    }

    #[test]
    fn an_absurd_jitter_is_capped_rather_than_overflowing() {
        let plan = Plan {
            every_secs: 100,
            jitter_percent: 250,
        };
        let interval = plan.interval(9);
        assert!((0..=200).contains(&interval), "got {interval}");
    }

    #[test]
    fn a_zero_interval_never_divides_by_zero() {
        let plan = Plan {
            every_secs: 0,
            jitter_percent: 10,
        };
        assert_eq!(plan.interval(5), 0);
    }

    #[test]
    fn a_scan_is_due_only_when_its_time_has_come() {
        assert!(!is_due(100, 101));
        assert!(is_due(101, 101));
        assert!(is_due(200, 101));
    }

    #[test]
    fn the_next_scan_is_in_the_future() {
        let now = 1_700_000_000;
        let plan = Plan::DEFAULT;
        let next = next_at(now, plan, 3);
        assert!(next > now);
        assert!(!is_due(now, next));
        assert!(is_due(next, next));
    }

    #[test]
    fn a_gap_of_three_ticks_is_a_resume_and_two_is_not() {
        assert!(!resumed(100, 102, 2));
        assert!(!resumed(100, 104, 2));
        assert!(resumed(100, 106, 2));
        assert!(resumed(100, 10_000, 2));
    }

    #[test]
    fn a_clock_that_went_backwards_is_not_a_resume() {
        assert!(!resumed(200, 100, 2));
        assert!(!resumed(100, 100, 2));
        assert!(!resumed(100, 500, 0), "a zero tick would resume on every frame");
    }

    #[test]
    fn waking_from_sleep_does_not_scan_more_than_once_for_one_gap() {
        // The caller records the frame that saw the gap, so the next frame's gap is one
        // tick and the resume does not repeat.
        let woke = 100_000;
        assert!(resumed(1_000, woke, 2));
        assert!(!resumed(woke, woke + 2, 2));
    }
}
