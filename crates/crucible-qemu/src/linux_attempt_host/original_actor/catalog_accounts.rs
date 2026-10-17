//! Supplies fixed catalog scopes from the same published original actor.
//!
//! This inline capability owns no store, SQLite trait, path allocation or new
//! supervisor. The daemon pays actual controls before publication and retains
//! these existing account and original aliases through physical closure.

use std::sync::Arc;

use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaError};

use super::{
    OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorCatalogPurpose,
    OriginalActorDecodeOwner,
};

/// Retains fixed catalog accounting and operations without exposing its banks.
pub struct OriginalActorCatalogAccounts {
    original: Arc<HostOperationGuard>,
    supervisor: HostOperationSupervisor,
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
}

impl OriginalActorAccountCustody {
    /// Borrows the same published accounts into closed inline catalog custody.
    ///
    /// # Errors
    /// Refuses missing custody, a different decoder original or original expiry.
    pub fn prepare_catalog_accounts(
        &self,
        decoder: &OriginalActorDecodeOwner,
    ) -> Result<OriginalActorCatalogAccounts, OriginalActorAccountError> {
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        decoder.verify_original(&held.preparation)?;
        held.preparation.wait_slice()?;
        Ok(OriginalActorCatalogAccounts {
            original: Arc::clone(&held.preparation),
            supervisor: held._supervisor.clone(),
            resident: held.resident.clone(),
            metadata: held.metadata.clone(),
        })
    }
}

impl OriginalActorCatalogAccounts {
    /// Prepays actual target control bytes under both original counters.
    ///
    /// # Errors
    /// Refuses either bank or the same original before or after admission.
    pub fn reserve_controls(
        &self,
        bytes: u64,
    ) -> Result<HostServiceLeasePair, OriginalActorAccountError> {
        self.original.wait_slice()?;
        let result = self.resident.reserve_paired_bytes(&self.metadata, bytes);
        let after = self.original.wait_slice();
        let (resident, metadata) =
            result.map_err(|source| OriginalActorAccountError::NativeAccountBoundary {
                source,
                original: after.err(),
            })?;
        let credit = HostServiceLeasePair::new(resident, metadata);
        if let Err(source) = after {
            drop(credit);
            return Err(source.into());
        }
        Ok(credit)
    }

    /// Checks the existing preparation alias without exposing catalog accounts.
    ///
    /// # Errors
    /// Refuses a different original allocation or the retained original boundary.
    pub fn verify_preparation(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        if !Arc::ptr_eq(&self.original, original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.check()?;
        Ok(())
    }

    /// Checks the same retained original without returning its guard.
    ///
    /// # Errors
    /// Refuses the actual original cancellation, expiry or terminal state.
    pub fn check(&self) -> Result<(), HostSupervisionError> {
        self.original.wait_slice().map(|_| ())
    }

    /// Starts the fixed PageIn scope in the existing original roster.
    ///
    /// # Errors
    /// Refuses the existing roster or original boundary.
    pub fn begin_read(&self) -> Result<HostOperationGuard, HostSupervisionError> {
        self.supervisor.begin(HostOperationClass::PageIn)
    }

    /// Starts the fixed Writeback scope in the existing original roster.
    ///
    /// # Errors
    /// Refuses the existing roster or original boundary.
    pub fn begin_write(&self) -> Result<HostOperationGuard, HostSupervisionError> {
        self.supervisor.begin(HostOperationClass::Writeback)
    }

    /// Starts the fixed Preparation scope in the existing original roster.
    ///
    /// # Errors
    /// Refuses the existing roster or retained original boundary.
    pub fn begin_preparation(&self) -> Result<HostOperationGuard, HostSupervisionError> {
        self.check()?;
        self.supervisor.begin(HostOperationClass::Preparation)
    }

    /// Starts the fixed Cleanup scope in the existing original roster.
    ///
    /// # Errors
    /// Refuses the existing roster or retained original boundary.
    pub fn begin_cleanup(&self) -> Result<HostOperationGuard, HostSupervisionError> {
        self.check()?;
        self.supervisor.begin(HostOperationClass::Cleanup)
    }

    /// Moves the exact authenticated catalog purpose into its unstarted audit.
    ///
    /// The caller publishes this inline owner before starting any scope or I/O.
    ///
    /// # Errors
    /// Refuses a different original purpose or an expired original.
    pub fn prepare_physical_audit(
        &self,
        purpose: OriginalActorCatalogPurpose,
    ) -> Result<OriginalCatalogPhysicalAudit, OriginalActorAccountError> {
        self.check()?;
        if !Arc::ptr_eq(&self.original, &purpose.original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(OriginalCatalogPhysicalAudit {
            purpose,
            supervisor: self.supervisor.clone(),
            operation: None,
        })
    }
}

/// Preserves the actual audit setup or quota error without storage-layer coupling.
#[derive(Debug, thiserror::Error)]
pub enum OriginalCatalogAuditError {
    /// The fixed audit scope has not been installed.
    #[error(transparent)]
    Account(#[from] OriginalActorAccountError),
    /// The actual installed kernel project refused verification.
    #[error(transparent)]
    Quota(#[from] LinuxProjectQuotaError),
}

/// Retains the fixed physical catalog audit through every uncertain cut.
pub struct OriginalCatalogPhysicalAudit {
    purpose: OriginalActorCatalogPurpose,
    supervisor: HostOperationSupervisor,
    operation: Option<HostOperationGuard>,
}

impl OriginalCatalogPhysicalAudit {
    /// Starts this already published fixed Preparation audit once.
    ///
    /// # Errors
    /// Refuses a repeated start or the existing original roster.
    pub fn start(&mut self) -> Result<(), OriginalActorAccountError> {
        if self.operation.is_some() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.operation = Some(
            self.supervisor
                .begin_work(HostOperationClass::Preparation, 1_048_576)?,
        );
        self.operation
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .wait_slice()?;
        Ok(())
    }

    /// Binds the one fixed catalog namespace to its authenticated project.
    ///
    /// # Errors
    /// Refuses missing scope, unsafe namespace, missing quota or kernel drift.
    pub fn bind_existing(&self) -> Result<LinuxProjectQuotaBinding, OriginalCatalogAuditError> {
        Ok(LinuxProjectQuotaBinding::bind_existing_under(
            std::path::Path::new("/var/lib/crucible/measurement/catalog"),
            self.purpose.project_id,
            8 << 30,
            1_048_576,
            self.supervisor.clone(),
            self.operation
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?,
        )?)
    }

    /// Completes only the actual audit scope after physical verification.
    ///
    /// # Errors
    /// Refuses missing scope or its unchanged original boundary.
    pub fn complete(&mut self) -> Result<(), OriginalActorAccountError> {
        self.operation
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .complete()?;
        drop(self.operation.take());
        Ok(())
    }
}

impl Drop for OriginalCatalogPhysicalAudit {
    fn drop(&mut self) {
        if self.operation.is_some() {
            // An uncertain audit cannot mark completion or refund its scope.
            std::mem::forget(self.operation.take());
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixed-purpose identity and canceled original controls stop on incorrect admission.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::HostOperationBudgets;

    fn fixture() -> (HostOperationSupervisor, OriginalActorCatalogAccounts) {
        let root = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let accounts = OriginalActorCatalogAccounts {
            original: Arc::new(root.begin(HostOperationClass::Preparation).unwrap()),
            supervisor: root.clone(),
            resident: HostServiceAllocator::new(1, 32, 4 << 20).unwrap(),
            metadata: HostServiceAllocator::new(1, 32, 4 << 20).unwrap(),
        };
        (root, accounts)
    }

    #[test]
    fn independent_guard_refuses_before_audit_publication() {
        let (root, accounts) = fixture();
        let purpose = OriginalActorCatalogPurpose {
            original: Arc::new(root.begin(HostOperationClass::Preparation).unwrap()),
            project_id: 43,
        };
        assert!(accounts.prepare_physical_audit(purpose).is_err());
    }

    #[test]
    fn canceled_same_original_refuses_before_audit_publication() {
        let (root, accounts) = fixture();
        let purpose = OriginalActorCatalogPurpose {
            original: Arc::clone(&accounts.original),
            project_id: 43,
        };
        root.cancel().unwrap();
        assert!(accounts.prepare_physical_audit(purpose).is_err());
    }
}
