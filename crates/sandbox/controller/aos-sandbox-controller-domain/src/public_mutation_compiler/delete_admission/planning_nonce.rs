//! Derives one planning query's nonce and horizon from actual authorization.
//!
//! Inventory and planning-only Root comparison share this same bounded kernel
//! entropy and paired-clock owner. It supplies no caller nonce/cutoff, payer,
//! permission or positive profile; actual fixed admission must precede entry.

use super::DeleteAuthorizationBindingV1;
use crate::JournalError;
use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use std::error::Error;

type Clock = RetainedKernelPairedClockAttemptV1<PlanningClockError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PlanningClockError {
    #[error("the actual Delete authorization/query clock is stale")]
    Stale,
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for PlanningClockError {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(cause: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(cause)
    }
}

pub(crate) struct PlanningNonce {
    original: RawPairedClockSample,
    expires: i64,
    original_cutoff: Option<u64>,
    interval_before: Option<RawPairedClockSample>,
    nonce: RetainedKernelNonceOriginalV1,
    sampled: Option<Result<[u8; 16], EntropyError>>,
    before: Clock,
    before_result: Option<Result<RawPairedClockSample, PlanningClockError>>,
    cutoff: Option<Result<u64, PlanningClockError>>,
    after: Clock,
    after_result: Option<Result<RawPairedClockSample, PlanningClockError>>,
    after_comparison: Option<Result<(), PlanningClockError>>,
}

impl PlanningNonce {
    pub(crate) fn demand_v1() -> Result<ResourceVector, JournalError> {
        let memory = Clock::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| {
                bytes.checked_add(RetainedKernelNonceOriginalV1::construction_bytes_v1()?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Delete planning nonce/clock"))?;
        let files = u64::try_from(Clock::MAXIMUM_RETAINED_FILES_V1)
            .ok()
            .and_then(|files| files.checked_mul(2))
            .ok_or(JournalError::LimitExceeded("Delete planning clock files"))?;
        let names = Clock::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::LimitExceeded(
                "Delete planning clock namespaces",
            ))?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, files)
            .with(D::MetadataEntries, names))
    }

    pub(crate) fn new(authorization: &DeleteAuthorizationBindingV1<'_>) -> Self {
        let (original, expires) = authorization.authorization_horizon_v1();
        Self {
            original,
            expires,
            original_cutoff: None,
            interval_before: None,
            nonce: RetainedKernelNonceOriginalV1::new(),
            sampled: None,
            before: Clock::default(),
            before_result: None,
            cutoff: None,
            after: Clock::default(),
            after_result: None,
            after_comparison: None,
        }
    }

    /// Reuses the entropy/clock engine under the actual accepted Root horizon.
    pub(crate) fn post_network_v4(
        fence: &crate::journal::SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        bound: crate::normal_root::DeleteSourceClockBoundDataV3,
    ) -> Self {
        let (original, expires) = fence.authorization_horizon_v1();
        Self {
            original,
            expires: expires.min(bound.expires),
            original_cutoff: Some(bound.cutoff),
            interval_before: Some(bound.after),
            nonce: RetainedKernelNonceOriginalV1::new(),
            sampled: None,
            before: Clock::default(),
            before_result: None,
            cutoff: None,
            after: Clock::default(),
            after_result: None,
            after_comparison: None,
        }
    }

    pub(crate) fn begin_once(&mut self) -> Result<(), JournalError> {
        if self.before_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.before_result = Some(self.before.observe_once(None));
        self.cutoff = Some((|| {
            let current = *self
                .before_result
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(PlanningClockError::Stale)?;
            query_cutoff(
                self.original,
                self.expires,
                self.original_cutoff,
                self.interval_before,
                current,
            )
        })());
        if !matches!(self.cutoff, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.sampled = Some(self.nonce.observe_once());
        if matches!(self.sampled, Some(Ok(_))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn finish_once(&mut self) -> Result<(), JournalError> {
        if self.after_result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        // This independent native sample is prepaid before begin_once. Earlier
        // entropy, before-clock or Session failures cannot suppress it.
        self.after_result = Some(self.after.observe_once(None));
        self.after_comparison = Some((|| {
            let after = *self
                .after_result
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(PlanningClockError::Stale)?;
            self.original
                .validate_later_sample(after)
                .map_err(|_| PlanningClockError::Stale)?;
            let before = *self
                .before_result
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(PlanningClockError::Stale)?;
            before
                .validate_later_sample(after)
                .map_err(|_| PlanningClockError::Stale)?;
            let cutoff = self
                .cutoff
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(PlanningClockError::Stale)?;
            if after.boottime_nanoseconds() >= cutoff {
                return Err(PlanningClockError::Stale);
            }
            Ok(())
        })());
        if matches!(self.after_comparison, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn coordinates(&self) -> Result<([u8; 16], u64), JournalError> {
        let nonce = self
            .nonce
            .value()
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let cutoff = self
            .cutoff
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok((nonce, cutoff))
    }

    pub(crate) fn completed_sample_v4(&self) -> Result<RawPairedClockSample, JournalError> {
        if !matches!(self.after_comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.after_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before
            .failure()
            .or_else(|| error(&self.before_result))
            .or_else(|| error(&self.cutoff))
            .or_else(|| self.nonce.failure())
            .or_else(|| error(&self.sampled))
            .or_else(|| self.after.failure())
            .or_else(|| error(&self.after_result))
            .or_else(|| error(&self.after_comparison))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn query_cutoff(
    original: RawPairedClockSample,
    expires: i64,
    upper: Option<u64>,
    interval_before: Option<RawPairedClockSample>,
    current: RawPairedClockSample,
) -> Result<u64, PlanningClockError> {
    original
        .validate_later_sample(current)
        .map_err(|_| PlanningClockError::Stale)?;
    if let Some(before) = interval_before {
        before
            .validate_later_sample(current)
            .map_err(|_| PlanningClockError::Stale)?;
    }
    let expiry = original
        .conservative_expiry_deadline_data_v1(expires)
        .ok_or(PlanningClockError::Stale)?;
    let local = current
        .boottime_nanoseconds()
        .checked_add(5_000_000_000)
        .ok_or(PlanningClockError::Stale)?;
    let cutoff = expiry.min(local).min(upper.unwrap_or(u64::MAX));
    if current.boottime_nanoseconds() >= cutoff {
        return Err(PlanningClockError::Stale);
    }
    Ok(cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(boot: u8, wall: i64, seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [boot; 16],
            wall,
            seconds * 1_000_000_000,
        )
        .unwrap()
    }

    #[test]
    fn post_network_query_cannot_renew_original_root_cutoff() {
        let original = sample(2, 100, 10);
        let before = sample(2, 101, 11);
        let current = sample(2, 102, 12);

        let cutoff =
            query_cutoff(original, 200, Some(13_000_000_000), Some(before), current).unwrap();

        assert_eq!(cutoff, 13_000_000_000);
        assert!(query_cutoff(original, 200, Some(12_000_000_000), Some(before), current).is_err());
        assert!(query_cutoff(original, 200, Some(11_000_000_000), Some(before), current).is_err());
    }

    #[test]
    fn post_network_query_rejects_reversed_interval_and_changed_boot() {
        let original = sample(2, 100, 10);
        let before = sample(2, 102, 12);

        assert!(
            query_cutoff(
                original,
                200,
                Some(20_000_000_000),
                Some(before),
                sample(2, 101, 11)
            )
            .is_err()
        );
        assert!(
            query_cutoff(
                original,
                200,
                Some(20_000_000_000),
                Some(before),
                sample(3, 103, 13)
            )
            .is_err()
        );
        assert!(
            query_cutoff(
                original,
                102,
                Some(20_000_000_000),
                Some(before),
                sample(2, 103, 13)
            )
            .is_err()
        );
    }
}
