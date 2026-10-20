//! Holds Root's actual activation, image/PID1 pair and fixed envelope law.
//!
//! The native owner captures its own fixed original table and runs the shared
//! complete pair parser. The one-time layout parameter names actual upper
//! Controller/Q04 representations; it cannot supply descriptors, observations,
//! payment or authority. Root's installed caller passes its unchanged native
//! layout calculation. Recipient/profile/kernel joins and closed purpose
//! admission remain the genuine role owner's separate obligations.

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, NativeLayoutDemand};

use super::{ActivationNamesErrorV1, OriginalEnrollment, OriginalEnrollmentPairAttemptV1,
    RootInitialActivationErrorV1, RootInitialActivationOriginalsV1};

/// Describes a refused or repeated Root original-pair authentication.
#[derive(Debug, thiserror::Error)]
pub enum RootEnrollmentErrorV1 {
    /// The actual pair or its Root receiving envelope is unavailable.
    #[error("original Root enrollment is unavailable")]
    Unavailable,
    /// The once-only original destination was entered again.
    #[error("original Root enrollment was already entered")]
    Conflict,
}

/// Retains the actual original Root table, complete pair and envelope result.
///
/// The type has no constructor from account DATA or a successful observation.
/// Its successful pair observation is still DATA: this owner cannot mint a
/// purpose loan, semantic writer, accepted flight, Use or Q04 authority.
pub struct RootEnrollmentOriginalsV1 {
    activation: RootInitialActivationOriginalsV1,
    original: Option<Result<OriginalEnrollment, RootEnrollmentErrorV1>>,
    pair: OriginalEnrollmentPairAttemptV1,
    shape: Option<Result<(), bank::ResourceBankDataError>>,
}

impl RootEnrollmentOriginalsV1 {
    /// Creates inert destinations with actual Controller representation DATA.
    ///
    /// The layout is passed only to the existing full policy parser. It is
    /// neither a capacity nor a substitute for the actual inherited pair.
    #[must_use]
    pub fn new(layout: NativeLayoutDemand) -> Self {
        Self {
            activation: RootInitialActivationOriginalsV1::new(),
            original: None,
            pair: OriginalEnrollmentPairAttemptV1::new_controller(layout),
            shape: None,
        }
    }

    /// Captures this process's fixed original Root table.
    ///
    /// # Errors
    /// Retains the actual table/names causes and refuses invalid roles or reentry.
    pub fn capture_once(&mut self) -> Result<(), RootInitialActivationErrorV1> {
        self.activation.capture_once()
    }

    /// Authenticates the same original files with the complete shared parser.
    ///
    /// # Errors
    /// Retains actual native/canonical pair errors and the complete Root-envelope
    /// result. Reentry and use before capture or in another process are refused.
    pub fn authenticate_once(&mut self) -> Result<ResourceVector, RootEnrollmentErrorV1> {
        if self.original.is_some() || !self.activation.is_captured_v1() {
            return Err(RootEnrollmentErrorV1::Conflict);
        }
        let (policy, delivery) = self.activation.enrollment_originals_v1()
            .ok_or(RootEnrollmentErrorV1::Unavailable)?;
        self.original = Some(match self.pair.observe_once(policy, delivery) {
            Ok(original) => Ok(*original),
            Err(_) => Err(RootEnrollmentErrorV1::Unavailable),
        });
        let original = self.enrollment_v1().ok_or(RootEnrollmentErrorV1::Unavailable)?;
        self.shape = Some(original.policy.bootstrap_provisions().root_receiving
            .ok_or(bank::ResourceBankDataError::EnrollmentUnavailable)
            .and_then(bank::require_root_service_envelope));
        if !matches!(self.shape, Some(Ok(()))) {
            return Err(RootEnrollmentErrorV1::Unavailable);
        }
        self.enrollment_v1().and_then(|original| original.policy.bootstrap_provisions().root_receiving)
            .ok_or(RootEnrollmentErrorV1::Unavailable)
    }

    /// Borrows the actual complete pair's nonauthorizing enrollment DATA.
    #[must_use]
    pub fn enrollment_v1(&self) -> Option<&OriginalEnrollment> {
        self.original.as_ref()?.as_ref().ok()
    }

    /// Borrows the actual complete Root-envelope validation result.
    #[must_use]
    pub fn root_shape_result_v1(&self) -> Option<&Result<(), bank::ResourceBankDataError>> {
        self.shape.as_ref()
    }

    /// Borrows the current process identity captured with the actual table.
    #[must_use]
    pub fn process_id_v1(&self) -> u32 {
        self.activation.process_id_v1()
    }

    /// Reports the same original physical capture's completion.
    #[must_use]
    pub fn is_captured_v1(&self) -> bool {
        self.activation.is_captured_v1()
    }

    /// Borrows the original PID1/profile move slots after role-owned admission.
    pub fn profile_originals_v1(
        &mut self,
    ) -> Option<(&mut Option<OwnedFd>, &mut Option<OwnedFd>)> {
        if !matches!(self.shape, Some(Ok(()))) {
            return None;
        }
        self.activation.profile_originals_v1()
    }

    /// Prices actual extra construction and retained result/control carriers.
    ///
    /// This helper is arithmetic only. The genuine Root recipient adds it to
    /// the same cumulative prefix; it cannot create credit or admit a purpose.
    #[must_use]
    pub fn additional_receiving_demand_v1() -> Option<ResourceVector> {
        let memory = std::mem::size_of::<Self>().checked_mul(2)?;
        let additional = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            // New wrapper destination/construction and native original/shape
            // results. Existing upper classification results remain separate.
            .with(D::MetadataEntries, 4);
        RootInitialActivationOriginalsV1::additional_receiving_demand_v1()?
            .checked_add(additional).ok()
    }

    /// Borrows the table cause for the existing Root classification adapter.
    #[must_use]
    pub fn table_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.activation.table_failure_v1()
    }

    /// Borrows the names cause for the existing Root classification adapter.
    #[must_use]
    pub fn names_failure_v1(&self) -> Option<&ActivationNamesErrorV1> {
        self.activation.names_failure_v1()
    }

    /// Borrows the role refusal for the existing Root classification adapter.
    #[must_use]
    pub fn role_failure_v1(&self) -> Option<&RootInitialActivationErrorV1> {
        self.activation.role_failure_v1()
    }

    /// Borrows the earliest actual pair cause without replacing upper markers.
    #[must_use]
    pub fn pair_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.pair.failure()
    }

    /// Borrows the earliest reached actual failure without releasing originals.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.activation.failure()
            .or_else(|| self.pair.failure())
            .or_else(|| self.original.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.shape.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_data_alone_cannot_authenticate_or_supply_originals() {
        // The inert layout contains the same armed original-table fence.
        let mut original = std::mem::ManuallyDrop::new(
            RootEnrollmentOriginalsV1::new(NativeLayoutDemand::new(1, 2)),
        );
        assert!(matches!(original.authenticate_once(), Err(RootEnrollmentErrorV1::Conflict)));
        assert!(original.enrollment_v1().is_none());
        assert!(original.root_shape_result_v1().is_none());
        assert!(original.profile_originals_v1().is_none());
        assert!(original.failure().is_none());
    }
}
