//! Keeps resident Source custody distinct from actual pager page-state work.
//!
//! Native invokes the resident borrower only after its real Source/runtime,
//! admitted nonpaging RAM inventory and independent writer loan are current.
//! This fixed body issues none of those owners; it retains the module side of
//! that invocation until the durable Source field physically returns.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::paged_ram::engine::OrdinaryPagingCustody;
use crate::paged_ram::source::SourceOperationClass;

pub(super) enum PhysicalCustody {
    Paging(OrdinaryPagingCustody),
    Resident(ResidentCustody),
}

impl PhysicalCustody {
    pub(super) fn retain(
        placement: FingerprintPlacement,
        context: &FingerprintBorrowContext,
        id: u64,
        userdata: *mut c_void,
    ) -> Result<Self, RamError> {
        match placement {
            FingerprintPlacement::Paging => {
                let owner = crate::paged_ram::controller::registered_current_owner(id, userdata)?;
                Ok(Self::Paging(OrdinaryPagingCustody::retain(owner, context)?))
            }
            FingerprintPlacement::Resident => {
                // The authentic resident registrar and Native phase1 proof
                // precede this actual callback. Absence of a controller alone
                // cannot construct this loan or turn a paging refusal resident.
                Ok(Self::Resident(ResidentCustody { original: None }))
            }
        }
    }

    pub(super) fn bind_original(
        &mut self,
        serial: u64,
        class: SourceOperationClass,
    ) -> Result<(), RamError> {
        match self {
            Self::Paging(paging) => paging.bind_original(serial, class),
            Self::Resident(resident) => resident.bind_original(serial, class),
        }
    }

    pub(super) fn settle(&mut self, operation: &dyn SourceOperation) -> Result<(), RamError> {
        match self {
            Self::Paging(paging) => paging.settle(operation),
            Self::Resident(resident) => resident.check_live(operation),
        }
    }

    pub(super) fn rearm(
        &self,
        topology: u64,
        operation: &dyn SourceOperation,
    ) -> Result<(), RamError> {
        match self {
            Self::Paging(paging) => paging.rearm(topology, operation),
            Self::Resident(resident) => resident.check_live(operation),
        }
    }

    pub(super) fn return_identity(&mut self) -> Result<(), RamError> {
        match self {
            Self::Paging(paging) => paging.return_identity(),
            // No module PageStates or UFFD worker were borrowed on the real
            // resident route. The saved Source field still returns separately;
            // Native keeps its writer/inventory owners until the actual end.
            Self::Resident(_) => Ok(()),
        }
    }
}

pub(super) struct ResidentCustody {
    original: Option<(u64, SourceOperationClass)>,
}

impl ResidentCustody {
    fn bind_original(&mut self, serial: u64, class: SourceOperationClass) -> Result<(), RamError> {
        if serial == 0
            || !matches!(
                class,
                SourceOperationClass::FingerprintInitialization
                    | SourceOperationClass::FingerprintUpdate
            )
            || self
                .original
                .is_some_and(|previous| previous != (serial, class))
        {
            return Err(RamError::Invariant("resident Original identity changed"));
        }
        self.original = Some((serial, class));
        Ok(())
    }

    fn check_live(&self, operation: &dyn SourceOperation) -> Result<(), RamError> {
        if self.original.is_none() {
            return Err(RamError::Invariant("resident Original identity absent"));
        }
        // A resident realization has no page-protection work, not an exemption
        // from the SAME Source Original. Native checks versions and writer
        // ownership around this phase and performs its one independent post.
        operation
            .wait_slice_for_observation()
            .map(|_| ())
            .map_err(ObservationOperationError::into_io)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are metadata refusal controls, not native borrower constructors.
    #[test]
    fn changed_resident_original_cannot_replace_retained_provenance() {
        let class = SourceOperationClass::FingerprintInitialization;
        let mut resident = ResidentCustody {
            original: Some((7, class)),
        };

        assert!(resident.bind_original(8, class).is_err());
        assert!(
            resident
                .bind_original(7, SourceOperationClass::FingerprintUpdate)
                .is_err()
        );
        assert_eq!(resident.original, Some((7, class)));
    }

    #[test]
    fn non_fingerprint_or_zero_identity_cannot_bind_resident_work() {
        let mut resident = ResidentCustody { original: None };

        assert!(
            resident
                .bind_original(0, SourceOperationClass::FingerprintUpdate)
                .is_err()
        );
        assert!(
            resident
                .bind_original(7, SourceOperationClass::PageIn)
                .is_err()
        );
        assert!(resident.original.is_none());
    }
}
