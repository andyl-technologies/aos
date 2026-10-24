//! Retains clock bookends of one already-issued disabling disposition.
//!
//! These samples observe native continuity without comparing the old effect
//! deadline. They neither replace its clock owner nor restore positive Source
//! capability. A failed before observation cannot suppress owed containment.

use super::*;
use crate::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};

#[derive(Debug, thiserror::Error)]
pub(super) enum CleanupClockErrorV2 {
    #[error("issued worker cleanup clock observation refused")]
    Stale,
    #[error(transparent)]
    Kernel(aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for CleanupClockErrorV2 {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(error)
    }
}

type Attempt = RetainedKernelPairedClockAttemptV1<CleanupClockErrorV2>;

pub(super) struct IssuedCleanupOriginalV2 {
    before: Attempt,
    before_result: Option<Result<RawPairedClockSample, CleanupClockErrorV2>>,
    after: Attempt,
    after_entered: bool,
    after_result: Option<Result<RawPairedClockSample, CleanupClockErrorV2>>,
    continuity: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    boot: [u8; 16],
    wrong_boot: bool,
}

impl IssuedCleanupOriginalV2 {
    pub(super) fn new(boot: [u8; 16]) -> Self {
        Self {
            before: Default::default(),
            before_result: None,
            after: Default::default(),
            after_entered: false,
            after_result: None,
            continuity: None,
            boot,
            wrong_boot: false,
        }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let bytes = Attempt::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<Attempt>()))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(overflow)?;
        let names = Attempt::receiving_metadata_cells_v1()
            .and_then(|value| value.checked_mul(2))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(overflow)?;
        let files = Attempt::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(2)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(overflow)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, names)
            .with(D::OpenFiles, files))
    }

    pub(super) fn observe_before(&mut self) {
        self.before_result = Some(self.before.observe_once(None));
        self.check_boot();
    }

    fn check_boot(&mut self) {
        for sample in [self.before_result.as_ref(), self.after_result.as_ref()]
            .into_iter()
            .flatten()
            .filter_map(|result| result.as_ref().ok())
        {
            if sample.host_boot_id() != self.boot {
                self.wrong_boot = true;
            }
        }
    }

    pub(super) fn observe_after(&mut self) {
        if self.after_entered {
            return;
        }
        self.after_entered = true;
        self.after_result = Some(self.after.observe_once(None));
        self.check_boot();
        if let (Some(Ok(before)), Some(Ok(after))) = (&self.before_result, &self.after_result) {
            self.continuity = Some(before.validate_later_sample(*after));
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before
            .failure()
            .or_else(|| self.after.failure())
            .or_else(|| {
                self.continuity
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|error| error as _)
            })
            .or_else(|| self.wrong_boot.then_some(&CleanupClockErrorV2::Stale as _))
    }
}

pub(super) struct CleanupAfterV2<'a>(pub(super) &'a mut IssuedCleanupOriginalV2);

impl Drop for CleanupAfterV2<'_> {
    fn drop(&mut self) {
        self.0.observe_after();
    }
}
