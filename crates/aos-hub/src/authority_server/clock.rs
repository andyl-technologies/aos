//! Durable unresolved sessions and conservative Native observation intervals.
//!
//! A session is committed before its first sample and is never cleared by
//! serving. Every returned interval covers a fresh post-commit observation under
//! externally reviewed uncertainty, latency and whole-second rounding bounds.
//! Successful observations do not authorize automatic restart; an unresolved
//! session requires a later explicit reviewed operator resolution.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::lease::{LeaseClock, LeaseInteger};

use crate::authority_journal::{AuthorityClockSession, AuthorityJournal};

pub(super) trait ClockSource: Send + Sync {
    fn observe(&self) -> Result<LeaseClock>;
}

struct ClockContinuity {
    greatest_sample: i64,
    failed: bool,
}

pub(super) struct NativeClock {
    session: AuthorityClockSession,
    uncertainty: i64,
    latency_seconds: i64,
    continuity: Mutex<ClockContinuity>,
}

impl NativeClock {
    pub(super) fn new(
        journal: AuthorityJournal,
        uncertainty: i64,
        latency_seconds: i64,
        retained_floor: i64,
    ) -> Result<Self> {
        Self::new_with_resolution(journal, uncertainty, latency_seconds, retained_floor, None)
    }

    pub(super) fn new_with_resolution(
        journal: AuthorityJournal,
        uncertainty: i64,
        latency_seconds: i64,
        retained_floor: i64,
        resolution: Option<&crate::authority_journal::recovery::ClockRecoveryReceipt>,
    ) -> Result<Self> {
        ensure!(
            uncertainty >= 0 && latency_seconds > 0 && retained_floor >= 0,
            "invalid clock qualification"
        );
        let total = uncertainty
            .checked_add(latency_seconds)
            .and_then(|value| value.checked_add(1))
            .context("clock interval qualification overflow")?;
        let current = journal.load()?;
        ensure!(
            total
                <= current
                    .journal
                    .policy
                    .timing_profile
                    .maximum_clock_uncertainty
                    .get(),
            "uncertainty, commit latency and rounding exceed reviewed profile"
        );
        // No SystemTime sample precedes this actual retained claim. A crash or
        // failed bound check cannot silently regain clock authority on restart.
        let session = match resolution {
            Some(receipt) => journal.begin_recovered_clock_session(receipt)?,
            None => journal.begin_clock_observation_session()?,
        };
        Ok(Self {
            session,
            uncertainty,
            latency_seconds,
            continuity: Mutex::new(ClockContinuity {
                greatest_sample: retained_floor,
                failed: false,
            }),
        })
    }
}

impl ClockSource for NativeClock {
    fn observe(&self) -> Result<LeaseClock> {
        let mut continuity = self
            .continuity
            .lock()
            .map_err(|_| anyhow::anyhow!("authority clock continuity unavailable"))?;
        ensure!(!continuity.failed, "authority clock session is uncertain");
        let result = (|| {
            let monotonic_start = Instant::now();
            let start = sample()?;
            ensure!(
                start >= continuity.greatest_sample,
                "authority clock rolled backwards"
            );
            continuity.greatest_sample = start;
            let padding = self
                .latency_seconds
                .checked_add(1)
                .context("clock rounding overflow")?;
            let ceiling = start
                .checked_add(padding)
                .context("clock ceiling overflow")?;
            let uncertainty = self
                .uncertainty
                .checked_add(padding)
                .context("clock uncertainty overflow")?;
            ensure!(
                start >= uncertainty,
                "clock interval has a negative lower bound"
            );
            // Retain the actual sample as the monotonic floor. Commit latency
            // widens the interval; it must not manufacture a future observation
            // that an immediate consumer would mistake for clock rollback.
            let interval = LeaseClock {
                observed_at: start,
                uncertainty,
            };
            self.session.retain_ceiling(interval)?;

            // This actual observation follows the last commit and every operation
            // it could delay. It exposes no time unless the durable interval covers
            // it; no further commit/await follows, so there is no recursive observer.
            let final_sample = sample()?;
            ensure!(
                final_sample >= continuity.greatest_sample,
                "authority clock rolled backwards after commit"
            );
            continuity.greatest_sample = final_sample;
            ensure!(
                monotonic_start.elapsed()
                    <= Duration::from_secs(u64::try_from(self.latency_seconds)?)
                    && final_sample <= ceiling,
                "clock observation exceeded reviewed interval"
            );
            LeaseInteger::new(start)?;
            Ok(interval)
        })();
        if result.is_err() {
            // The already durable unresolved session prevents restart recovery;
            // this local flag also refuses later calls in the current process.
            continuity.failed = true;
        }
        result
    }
}

fn sample() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
