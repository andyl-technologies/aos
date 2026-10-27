//! Bounds the complete preauthentication opening with one paid native clock pair.
//!
//! The real listener funds both independent attempts before accepting a socket.
//! Partial payloads, interruptions and peer work never renew the opening origin.

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use std::error::Error as StdError;

const OPENING_WINDOW_NANOSECONDS: u64 = 5_000_000_000;

#[derive(Debug, thiserror::Error)]
enum OpeningClockError {
    #[error("Root policy opening clock or deadline is unavailable")]
    Clock,
    #[error("Root policy opening clock was already entered")]
    Reentry,
}

#[derive(Default)]
pub(super) struct RootPolicyOpeningClockV1 {
    entered: bool,
    before_original: RetainedKernelPairedClockAttemptV1,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cutoff: Option<Result<u64, OpeningClockError>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    comparison: Option<Result<(), OpeningClockError>>,
    closed: Option<OpeningClockError>,
}

impl RootPolicyOpeningClockV1 {
    pub(super) fn fixed_demand_v1() -> ResourceVector {
        let bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok());
        // Inline fields are already part of the actual receiver constructor.
        // This additional conservative bound pays both native reservoirs.
        let bytes = match bytes {
            Some(bytes) => bytes,
            None => u64::MAX,
        };
        ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
            D::OpenFiles,
            2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
        )
    }

    pub(super) fn begin_once_v1(&mut self) -> Result<u64, super::RootPolicyPreludeErrorV1> {
        if self.entered || self.after.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(OpeningClockError::Reentry);
            return Err(super::RootPolicyPreludeErrorV1::Opening);
        }
        self.entered = true;
        self.before = Some(self.before_original.observe_once(None));
        self.cutoff = Some(
            self.before
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .ok_or(OpeningClockError::Clock)
                .and_then(|sample| opening_cutoff(*sample)),
        );
        self.cutoff
            .as_ref()
            .and_then(|cutoff| cutoff.as_ref().ok())
            .copied()
            .ok_or(super::RootPolicyPreludeErrorV1::Opening)
    }

    pub(super) fn finish_once_v1(&mut self) -> Result<(), super::RootPolicyPreludeErrorV1> {
        if self.after.is_some() {
            self.closed.get_or_insert(OpeningClockError::Reentry);
            return Err(super::RootPolicyPreludeErrorV1::Opening);
        }
        // Both native attempts were paid before accept. The post runs even
        // when endpoint validation, the origin or a partial payload failed.
        self.after = Some(self.after_original.observe_once(None));
        self.comparison = Some((|| {
            let before = *self
                .before
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .ok_or(OpeningClockError::Clock)?;
            let after = *self
                .after
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .ok_or(OpeningClockError::Clock)?;
            let cutoff = *self
                .cutoff
                .as_ref()
                .and_then(|cutoff| cutoff.as_ref().ok())
                .ok_or(OpeningClockError::Clock)?;
            require_opening_post(before, after, cutoff)
        })());
        if matches!(self.comparison, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(super::RootPolicyPreludeErrorV1::Opening)
        }
    }

    pub(super) fn cutoff_v1(&self) -> Result<u64, super::RootPolicyPreludeErrorV1> {
        self.cutoff.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(super::RootPolicyPreludeErrorV1::Opening)
    }

    pub(super) fn is_finished_v1(&self) -> bool { self.after.is_some() }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.before_original
            .failure()
            .or_else(|| cause(&self.before))
            .or_else(|| cause(&self.cutoff))
            .or_else(|| self.after_original.failure())
            .or_else(|| cause(&self.after))
            .or_else(|| cause(&self.comparison))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn opening_cutoff(before: RawPairedClockSample) -> Result<u64, OpeningClockError> {
    before
        .boottime_nanoseconds()
        .checked_add(OPENING_WINDOW_NANOSECONDS)
        .ok_or(OpeningClockError::Clock)
}

fn require_opening_post(
    before: RawPairedClockSample,
    after: RawPairedClockSample,
    cutoff: u64,
) -> Result<(), OpeningClockError> {
    before
        .validate_later_sample(after)
        .map_err(|_| OpeningClockError::Clock)?;
    if cutoff != opening_cutoff(before)? || after.boottime_nanoseconds() >= cutoff {
        return Err(OpeningClockError::Clock);
    }
    Ok(())
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(wall: i64, boot: u64, host: u8) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [host; 16],
            wall,
            boot,
        )
        .unwrap()
    }

    #[test]
    fn partial_progress_cannot_renew_the_original_opening_deadline() {
        let before = sample(100, 10_000_000_000, 2);
        let cutoff = opening_cutoff(before).unwrap();
        let timely = sample(104, cutoff - 1, 2);
        assert!(require_opening_post(before, timely, cutoff).is_ok());

        let expired = sample(105, cutoff, 2);
        assert!(require_opening_post(before, expired, cutoff).is_err());
        assert!(require_opening_post(before, expired, opening_cutoff(timely).unwrap()).is_err());
    }

    #[test]
    fn the_owed_post_rejects_a_different_boot() {
        let before = sample(100, 10_000_000_000, 2);
        let after = sample(101, 11_000_000_000, 3);
        assert!(require_opening_post(before, after, opening_cutoff(before).unwrap()).is_err());
    }
}
