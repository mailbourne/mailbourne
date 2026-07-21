//! # 6 · retry — try again, with manners
//!
//! A `4xx` means "not now" — and some receivers say it *on purpose* to
//! unknown senders (greylisting), betting that real mail servers retry and
//! spam cannons don't. Being a real mail server means proving them right:
//!
//! - exponential backoff (minutes → hours), per message
//! - a total queue lifetime (days) before a temporary failure is honestly
//!   converted into a bounce
//!
//! The schedule is pure arithmetic — no clocks, no I/O — so the queue can
//! ask "when next?" and tests can prove every edge without waiting.

use std::time::Duration;

/// The retry schedule: how patient we are, and for how long.
///
/// Defaults follow the internet's long-standing conventions (Postfix backs
/// off from ~17 minutes; queues conventionally live 4–5 days): first retry
/// after 5 minutes, doubling each attempt, capped at 6 hours between tries,
/// giving up after 5 days.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Delay before the first retry.
    pub first_delay: Duration,
    /// Delays double each attempt but never exceed this.
    pub cap: Duration,
    /// Total time a message may wait in the queue before we stop trying
    /// and bounce it.
    pub lifetime: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(5 * 60),
            cap: Duration::from_secs(6 * 60 * 60),
            lifetime: Duration::from_secs(5 * 24 * 60 * 60),
        }
    }
}

impl Policy {
    /// When to try again after the `attempt`-th failure (1-based), given
    /// how long the message has already waited in the queue.
    ///
    /// Returns `None` when the lifetime is spent — the message's temporary
    /// failures now become a permanent, honest bounce.
    pub fn next_delay(&self, attempt: u32, elapsed: Duration) -> Option<Duration> {
        if elapsed >= self.lifetime {
            return None;
        }
        let mut delay = self.first_delay;
        for _ in 1..attempt {
            if delay >= self.cap {
                break; // already at the ceiling — no point doubling further
            }
            delay = delay.saturating_mul(2);
        }
        Some(delay.min(self.cap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(60 * 60);
    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    #[test]
    fn the_first_retry_waits_the_first_delay() {
        let policy = Policy::default();
        assert_eq!(policy.next_delay(1, MIN), Some(5 * MIN));
    }

    #[test]
    fn delays_double_with_each_failed_attempt() {
        let policy = Policy::default();
        assert_eq!(policy.next_delay(2, MIN), Some(10 * MIN));
        assert_eq!(policy.next_delay(3, MIN), Some(20 * MIN));
        assert_eq!(policy.next_delay(4, MIN), Some(40 * MIN));
    }

    #[test]
    fn delays_never_exceed_the_cap() {
        let policy = Policy::default();
        assert_eq!(policy.next_delay(10, MIN), Some(6 * HOUR));
        // Even absurd attempt counts must not overflow past the cap.
        assert_eq!(policy.next_delay(1_000, MIN), Some(6 * HOUR));
    }

    #[test]
    fn a_message_older_than_the_lifetime_gets_no_more_tries() {
        let policy = Policy::default();
        assert_eq!(policy.next_delay(20, 5 * DAY), None);
        assert_eq!(policy.next_delay(20, 6 * DAY), None);
    }
}
