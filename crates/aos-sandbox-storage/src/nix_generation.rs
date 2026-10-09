//! Retains original input and results for the selected Nix Prepare boundary.
//!
//! Prepared only records the existing four-value transaction. It is neither
//! Clone Apply authority nor physical funding, readiness or retirement proof.

use aos_sandbox::{CommitResult, JournalError};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::nix_generation::CanonicalNixGenerationPreparationV1;

use crate::authorization::StorageAdmissionError;
use crate::{StorageBrokerError, StorageCatalogPreparationOutcomeV1};

pub(crate) mod seed;

/// Classifies a selected refusal while its actual cause remains resident.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("original Nix generation preparation is closed")]
pub struct StorageGenerationStoppedV1;

#[derive(Clone, Copy)]
pub(crate) enum StorageGenerationCauseV1 {
    Request,
    Native,
    Preparation,
    Runtime,
    Clock,
    NativeClock,
    Occupied,
    Kernel,
    Handoff,
    Allocation,
}

/// Lends only the disjoint resident native result and its chronological marker.
pub(crate) struct StorageGenerationNativeLoanV1<'original> {
    pub(crate) native: &'original mut Option<Result<CommitResult, JournalError>>,
    pub(crate) clock: &'original mut Option<Result<RawPairedClockSample, crate::StorageRuntimeError>>,
    pub(crate) clock_validation: &'original mut Option<StorageAdmissionError>,
    pub(crate) first: &'original mut Option<StorageGenerationCauseV1>,
    pub(crate) initial: RawPairedClockSample,
    pub(crate) boot: [u8; 16],
    pub(crate) deadline: u64,
}

/// Owns one selected original request, native result and Prepared result.
///
/// The enclosing installed cycle must retain this noncloneable reservoir.
/// No reset/retry, raw writer access or positive authority factory is exposed.
pub struct StorageGenerationAttemptV1 {
    pub(crate) request: Option<Vec<u8>>,
    pub(crate) checked: Option<Result<
        CanonicalNixGenerationPreparationV1,
        aos_sandbox_protocol::ProtocolValidationError,
    >>,
    pub(crate) initial: Option<Result<RawPairedClockSample, StorageAdmissionError>>,
    pub(crate) native: Option<Result<CommitResult, JournalError>>,
    pub(crate) native_clock: Option<Result<RawPairedClockSample, crate::StorageRuntimeError>>,
    pub(crate) native_clock_validation: Option<StorageAdmissionError>,
    pub(crate) prepared: Option<Result<StorageCatalogPreparationOutcomeV1, StorageBrokerError>>,
    pub(crate) runtime_error: Option<crate::StorageRuntimeError>,
    pub(crate) kernel: Option<Result<
        aos_sandbox_linux::boot::KernelBootId,
        aos_sandbox_linux::Error,
    >>,
    pub(crate) handoff: Option<Result<(), crate::DormantStorageBrokerCallErrorV1>>,
    pub(crate) allocation: Option<std::collections::TryReserveError>,
    pub(crate) clock_debt: Option<StorageAdmissionError>,
    pub(crate) first: Option<StorageGenerationCauseV1>,
    pub(crate) entered: bool,
    pub(crate) finished: bool,
}

impl Default for StorageGenerationAttemptV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StorageGenerationAttemptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StorageGenerationAttemptV1(<resident original preparation>)")
    }
}

impl StorageGenerationAttemptV1 {
    /// Creates vacant local custody without I/O or authorization.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            request: None,
            checked: None,
            initial: None,
            native: None,
            native_clock: None,
            native_clock_validation: None,
            prepared: None,
            runtime_error: None,
            kernel: None,
            handoff: None,
            allocation: None,
            clock_debt: None,
            first: None,
            entered: false,
            finished: false,
        }
    }

    /// Borrows the real first error without moving original result custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            StorageGenerationCauseV1::Request => self.checked.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::Native => self.native.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::Preparation => self.prepared.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::Runtime => self.runtime_error.as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::Clock => self.initial.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::NativeClock => {
                if let Some(Err(error)) = &self.native_clock {
                    Some(error)
                } else {
                    self.native_clock_validation.as_ref()
                        .map(|error| error as &(dyn std::error::Error + 'static))
                }
            }
            StorageGenerationCauseV1::Occupied => None,
            StorageGenerationCauseV1::Kernel => self.kernel.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::Handoff => self.handoff.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            StorageGenerationCauseV1::Allocation => self.allocation.as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
        }
    }

    /// Borrows the independent late clock debt separately from the first cause.
    #[must_use]
    pub fn clock_debt(&self) -> Option<&StorageAdmissionError> {
        self.clock_debt.as_ref()
    }

    /// Borrows the actual native result, including an ambiguous append failure.
    #[must_use]
    pub fn native_result(&self) -> Option<&Result<CommitResult, JournalError>> {
        self.native.as_ref()
    }

    /// Borrows Prepared only after every selected final check succeeded.
    #[must_use]
    pub fn prepared(&self) -> Option<&StorageCatalogPreparationOutcomeV1> {
        if !self.finished || self.first.is_some() || self.clock_debt.is_some() {
            return None;
        }
        self.prepared.as_ref()?.as_ref().ok()
    }

    pub(crate) fn retain_runtime_error(&mut self, error: crate::StorageRuntimeError) {
        self.runtime_error = Some(error);
        self.first.get_or_insert(StorageGenerationCauseV1::Runtime);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vacant_custody_is_neither_prepared_nor_failed() {
        let original = StorageGenerationAttemptV1::new();

        assert!(original.failure().is_none());
        assert!(original.prepared().is_none());
        assert!(original.native_result().is_none());
        assert!(original.clock_debt().is_none());
    }

    #[test]
    fn native_error_stays_owned_and_first_when_late_clock_fails() {
        let mut original = StorageGenerationAttemptV1::new();
        original.native = Some(Err(JournalError::Poisoned));
        original.first = Some(StorageGenerationCauseV1::Native);
        original.clock_debt = Some(StorageAdmissionError::FenceRejected);

        assert!(matches!(original.native_result(), Some(Err(JournalError::Poisoned))));
        assert!(original.failure().is_some());
        assert!(original.clock_debt().is_some());
        assert!(original.prepared().is_none());
    }
}
