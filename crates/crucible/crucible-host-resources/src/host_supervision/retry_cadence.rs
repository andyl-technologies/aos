//! Bounds physical retry frequency in the host operational clock domain.
//!
//! A cadence describes scheduling only. Callers retain and check their actual
//! operation before and after effects; elapsed time supplies no Work or Cleanup
//! authority and never enters guest time or deterministic execution state.

// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::{HostSupervisionError, host_now};

/// Retains one physical retry schedule without allocating or renewing a budget.
///
/// Moving or copying this observation preserves its existing next retry. A
/// readiness event for another job cannot advance this job's schedule.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostRetryCadence {
    next: Option<Instant>,
}

impl HostRetryCadence {
    /// Returns the remaining delay, or schedules one eligible physical attempt.
    ///
    /// A zero delay describes scheduling eligibility only. The next retry is
    /// recorded before the caller attempts an effect, even if that effect fails.
    /// The caller must independently check the same retained operation around
    /// every physical attempt; this method creates no operation or permission.
    ///
    /// # Errors
    /// Returns [`HostSupervisionError::InvalidBudget`] for a zero interval or an
    /// unrepresentable next retry. Refusal preserves the previous schedule.
    pub fn poll(&mut self, interval: Duration) -> Result<Duration, HostSupervisionError> {
        self.poll_at(host_now(), interval)
    }

    /// Reports whether an eligible retry has already established a schedule.
    ///
    /// This observation proves neither a physical attempt nor its completion.
    #[must_use]
    pub fn is_scheduled(&self) -> bool {
        self.next.is_some()
    }

    fn poll_at(
        &mut self,
        now: Instant,
        interval: Duration,
    ) -> Result<Duration, HostSupervisionError> {
        if interval.is_zero() {
            return Err(HostSupervisionError::InvalidBudget);
        }

        if let Some(next) = self.next.filter(|next| *next > now) {
            return Ok(next.duration_since(now));
        }

        let next = now
            .checked_add(interval)
            .ok_or(HostSupervisionError::InvalidBudget)?;
        self.next = Some(next);
        Ok(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_readiness_cannot_accelerate_a_scheduled_job() {
        let now = host_now();
        let interval = Duration::from_millis(10);
        let mut job = HostRetryCadence::default();
        let mut other = HostRetryCadence::default();

        assert_eq!(job.poll_at(now, interval), Ok(Duration::ZERO));
        for elapsed in 1..10 {
            let event = now + Duration::from_millis(elapsed);
            let _ = other.poll_at(event, interval).unwrap();
            assert_eq!(
                job.poll_at(event, interval),
                Ok(Duration::from_millis(10 - elapsed))
            );
        }

        assert_eq!(job.poll_at(now + interval, interval), Ok(Duration::ZERO));
        assert_eq!(job.poll_at(now + interval, interval), Ok(interval));
    }

    #[test]
    fn moving_to_quarantine_keeps_the_existing_retry_delay() {
        let now = host_now();
        let interval = Duration::from_millis(10);
        let mut running = HostRetryCadence::default();
        assert!(!running.is_scheduled());
        assert_eq!(running.poll_at(now, interval), Ok(Duration::ZERO));

        let mut quarantined = running;
        assert!(quarantined.is_scheduled());
        assert_eq!(quarantined.poll_at(now, interval), Ok(interval));
    }

    #[test]
    fn invalid_intervals_preserve_the_previous_schedule() {
        let now = host_now();
        let mut cadence = HostRetryCadence::default();

        assert_eq!(
            cadence.poll_at(now, Duration::ZERO),
            Err(HostSupervisionError::InvalidBudget)
        );
        assert!(!cadence.is_scheduled());
        assert_eq!(
            cadence.poll_at(now, Duration::MAX),
            Err(HostSupervisionError::InvalidBudget)
        );
        assert!(!cadence.is_scheduled());

        let interval = Duration::from_millis(10);
        assert_eq!(cadence.poll_at(now, interval), Ok(Duration::ZERO));
        let scheduled = cadence.next;
        assert_eq!(
            cadence.poll_at(now + interval, Duration::MAX),
            Err(HostSupervisionError::InvalidBudget)
        );
        assert_eq!(cadence.next, scheduled);
    }
}
