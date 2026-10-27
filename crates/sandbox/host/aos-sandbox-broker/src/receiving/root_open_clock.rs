//! Retains RootOpen's actual first kernel pair and immutable flight interval.
//!
//! The original begins only at the existing first-clock frontier. Later live
//! comparisons borrow this owner; supplied clock DATA cannot install its first
//! pair, replace its Instant or extend its 65-second interval.

use std::error::Error;
use std::time::{Duration, Instant};

use aos_sandbox_model::RawPairedClockSample;

use crate::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};

const MAXIMUM_ROOT_FLIGHT: Duration = Duration::from_secs(65);
const ROOT_FLIGHT_NANOSECONDS: u64 = 65_000_000_000;

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("Source genesis owner or credential is not current")]
    Stale,
    #[error(transparent)]
    Kernel(aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(error)
    }
}

/// Reports refusal while the actual clock cause remains on its same owner.
#[derive(Debug, thiserror::Error)]
#[error("the original RootOpen clock is incomplete or changed")]
pub struct RootOpenClockClosedV1;

/// Retains RootOpen's actual first pair, first Instant and native reader causes.
///
/// Construction is inert. This owner admits neither an accepted connection nor
/// a semantic purpose, publication, append or financial interval.
pub struct RootOpenClockOriginalV1 {
    attempt: RetainedKernelPairedClockAttemptV1<ClockError>,
    initial: Option<Result<RawPairedClockSample, ClockError>>,
    started: Option<Instant>,
    reentry: Option<RootOpenClockClosedV1>,
}

impl Default for RootOpenClockOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl RootOpenClockOriginalV1 {
    /// Creates the empty actual clock destinations without observing time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attempt: RetainedKernelPairedClockAttemptV1::default(),
            initial: None,
            started: None,
            reentry: None,
        }
    }

    /// Starts the same first Instant and kernel pair once at RootOpen entry.
    ///
    /// # Errors
    /// Refuses reentry or a failed native pair, retaining the actual failure.
    pub fn start_once_v1(&mut self) -> Result<RawPairedClockSample, RootOpenClockClosedV1> {
        if self.started.is_some() {
            self.reentry.get_or_insert(RootOpenClockClosedV1);
            return Err(RootOpenClockClosedV1);
        }
        self.started = Some(Instant::now());
        self.initial = Some(self.attempt.observe_once(None));
        let (clock, _) = self.initial_data_v1()?;
        Ok(clock)
    }

    /// Copies only the first pair and Instant retained by this actual owner.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or reentered first observation.
    pub fn initial_data_v1(
        &self,
    ) -> Result<(RawPairedClockSample, Instant), RootOpenClockClosedV1> {
        if self.reentry.is_some() {
            return Err(RootOpenClockClosedV1);
        }
        let Some(Ok(clock)) = &self.initial else {
            return Err(RootOpenClockClosedV1);
        };
        let Some(started) = self.started else {
            return Err(RootOpenClockClosedV1);
        };
        Ok((*clock, started))
    }

    /// Derives the unchanged original cutoff for the actual RootOpen body.
    ///
    /// This performs no observation. The real body constructor invokes it at
    /// its original checked-add frontier and owns its sequence-overflow lane.
    ///
    /// # Errors
    /// Refuses an unavailable first pair or overflowing original cutoff.
    pub fn cutoff_data_v1(&self) -> Result<u64, RootOpenClockClosedV1> {
        let (clock, _) = self.initial_data_v1()?;
        clock
            .boottime_nanoseconds()
            .checked_add(ROOT_FLIGHT_NANOSECONDS)
            .ok_or(RootOpenClockClosedV1)
    }

    /// Compares a reached sample against this actual immutable original.
    ///
    /// The cutoff argument is comparison DATA from the genuine body. It must
    /// equal this same original's exact cutoff and cannot renew the interval.
    ///
    /// # Errors
    /// Refuses a changed boot/pair, foreign cutoff or elapsed original interval.
    pub fn require_current_v1(
        &self,
        current: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), RootOpenClockClosedV1> {
        let (original, started) = self.initial_data_v1()?;
        original
            .validate_later_sample(current)
            .map_err(|_| RootOpenClockClosedV1)?;
        if cutoff != self.cutoff_data_v1()?
            || current.boottime_nanoseconds() >= cutoff
            || started.elapsed() >= MAXIMUM_ROOT_FLIGHT
        {
            return Err(RootOpenClockClosedV1);
        }
        Ok(())
    }

    /// Borrows the actual first native reader or retained pair failure.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(error) = self.attempt.failure() {
            return Some(error);
        }
        if let Some(Err(error)) = &self.initial {
            return Some(error);
        }
        match &self.reentry {
            Some(error) => Some(error),
            None => None,
        }
    }

    /// Measures this original's extra constructors and finite call controls.
    ///
    /// The containing actual receiving shape pays its resident Self. This
    /// quote adds its two new construction/return planes and exact new helper
    /// argument/result planes. Existing kernel-reader backing remains paid by
    /// the same actual first-clock supplier; it is not duplicated here.
    #[must_use]
    pub fn additional_control_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<RawPairedClockSample, ClockError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<RawPairedClockSample, RootOpenClockClosedV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(RawPairedClockSample, Instant), RootOpenClockClosedV1>>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<Result<u64, RootOpenClockClosedV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), RootOpenClockClosedV1>>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<(&Self, RawPairedClockSample, u64)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&Self>().checked_mul(9)?)?
            .checked_add(std::mem::size_of::<&mut Self>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&RawPairedClockSample>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<RawPairedClockSample>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<Instant>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<Option<u64>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<u64>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Duration>().checked_mul(3)?)
    }
}
