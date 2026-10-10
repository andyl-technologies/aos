//! Supplies catalog operations from the already published original actor.
//!
//! The external owner pays both supervisor controls before publication. Catalog
//! operations use the existing root roster, whose structural admission already
//! covers its bounded operation records; no clock, class roster or bank is born.
//! Outstanding operations and backend loans prevent healthy control closure.

use std::alloc::Layout;
use std::sync::{Arc, Mutex};

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeScratch, ResourceLoan};
use crucible_cas::content_store::{
    SqliteCatalogOperation, SqliteCatalogOperationKind, SqliteCatalogSupervisor, StoreError,
};
use crucible_linux_resource::host_services::{
    HostServiceError, HostServiceLease, HostServiceLeasePair,
};
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use crucible_qemu::{
    OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorCatalogAccounts,
    OriginalActorDecodeOwner,
};

mod accounts;
use accounts::CatalogAccounts;

#[cfg(test)]
pub(crate) mod tests;

mod physical;

struct CatalogAuthority {
    physical: Mutex<Option<physical::CatalogPhysical>>,
    accounts: CatalogAccounts,
    budget: DecodeBudget,
    failure: Mutex<Option<DecodeAdmissionError>>,
}

struct CatalogSupervisor(Arc<CatalogAuthority>);

struct CatalogCredit {
    _scratch: DecodeScratch,
    _authority: Arc<CatalogAuthority>,
}

struct CatalogOperation {
    guard: Option<HostOperationGuard>,
    authority: Arc<CatalogAuthority>,
}

#[derive(Debug, thiserror::Error)]
enum CatalogCause {
    #[error("catalog quota refused: {source}; original: {original_after:?}")]
    Quota {
        #[source]
        source: crucible_linux_resource::LinuxProjectQuotaError,
        original_after: Option<HostSupervisionError>,
    },
    #[error("catalog account refused: {source}; original: {original_after:?}")]
    Account {
        #[source]
        source: OriginalActorAccountError,
        original_after: Option<HostSupervisionError>,
    },
    #[error("catalog operation refused: {source}; original: {original_after:?}")]
    Supervision {
        #[source]
        source: HostSupervisionError,
        original_after: Option<HostSupervisionError>,
    },
    #[error("catalog operation abandoned before completion")]
    Abandoned,
    #[error("catalog refusal storage is poisoned")]
    Poisoned,
}

/// Keeps catalog control payment outside every backend and operation alias.
///
/// Only the same authenticated actor can construct this owner. The supervisor
/// does not certify a physical catalog, filesystem quota or service admission.
#[must_use = "retain catalog custody through every backend and operation control"]
pub struct OriginalActorCatalogOwner {
    supervisor: Option<Arc<CatalogSupervisor>>,
    authority: Option<Arc<CatalogAuthority>>,
    controls: Option<HostServiceLeasePair>,
    close_failure: Option<DecodeAdmissionError>,
}

impl OriginalActorCatalogOwner {
    pub(crate) fn prepare(
        actor: &OriginalActorAccountCustody,
        decoder: &OriginalActorDecodeOwner,
    ) -> Result<Self, OriginalActorAccountError> {
        let accounts = actor.prepare_catalog_accounts(decoder)?;
        let budget = decoder.budget()?;
        budget
            .verify_live()
            .map_err(OriginalActorAccountError::Decode)?;
        let bytes = shared_extent::<CatalogAuthority>()?
            .checked_add(shared_extent::<CatalogSupervisor>()?)
            .and_then(|bytes| bytes.checked_add(shared_extent::<CatalogCause>().ok()?))
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or(HostServiceError::CapacityExhausted)?;
        let controls = accounts.reserve_controls(bytes)?;
        let mut owner = Self {
            supervisor: None,
            authority: None,
            controls: Some(controls),
            close_failure: None,
        };
        owner.authority = Some(Arc::new(CatalogAuthority {
            physical: Mutex::new(None),
            accounts: CatalogAccounts::Original(accounts),
            budget: budget.clone(),
            failure: Mutex::new(None),
        }));
        let authority = owner
            .authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        owner.supervisor = Some(Arc::new(CatalogSupervisor(Arc::clone(authority))));
        authority.accounts.check()?;
        Ok(owner)
    }
}

impl OriginalActorCatalogOwner {
    /// Shares the admitted supervisor with the genuine catalog backend.
    ///
    /// # Errors
    /// Refuses consumed custody or the same original's sticky boundary.
    pub fn supervisor(&self) -> Result<Arc<dyn SqliteCatalogSupervisor>, StoreError> {
        let supervisor = self.supervisor.as_ref().ok_or(StoreError::Unauthorized)?;
        supervisor.0.check()?;
        Ok(Arc::clone(supervisor) as Arc<dyn SqliteCatalogSupervisor>)
    }

    /// Closes catalog controls after their genuine users have physically freed.
    ///
    /// # Errors
    /// Returns this same owner after any original refusal, recorded failure or
    /// surviving strong/weak alias. It does not retire a filesystem or service.
    pub fn try_close(mut self) -> Result<(), Self> {
        if self.close_failure.is_some() {
            return Err(self);
        }
        if let Some(supervisor) = self.supervisor.as_mut() {
            if let Err(error) = supervisor.0.check() {
                self.save_close_failure(error);
                return Err(self);
            }
            if Arc::get_mut(supervisor).is_none() {
                return Err(self);
            }
            drop(self.supervisor.take());
        }
        let Some(authority) = self.authority.as_mut() else {
            return Err(self);
        };
        if let Err(error) = authority.check() {
            self.save_close_failure(error);
            return Err(self);
        }
        let post_budget = authority.budget.clone();
        if Arc::get_mut(authority).is_none() {
            return Err(self);
        }
        drop(self.authority.take());
        if let Err(source) = post_budget.verify_live() {
            // The one precharged failure allocation has not been consumed in
            // a healthy authority. Its late deallocation postcut owns it here.
            self.close_failure = Some(source);
            return Err(self);
        }
        drop(self.controls.take());
        Ok(())
    }

    fn save_close_failure(&mut self, error: StoreError) {
        if let StoreError::DecodeAdmission { source, .. } = error {
            self.close_failure = Some(source);
        }
    }
}

impl Drop for OriginalActorCatalogOwner {
    fn drop(&mut self) {
        if self.authority.is_some() || self.supervisor.is_some() {
            // A body or caller facade dropping cannot refund the controls of
            // an outstanding backend, abandoned operation or opaque error.
            std::mem::forget(self.supervisor.take());
            std::mem::forget(self.authority.take());
        }
        // This includes a post-deallocation original refusal, when both Arc
        // fields are empty but the original control payment must still remain.
        std::mem::forget(self.controls.take());
        std::mem::forget(self.close_failure.take());
    }
}

impl std::fmt::Debug for OriginalActorCatalogOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalActorCatalogOwner")
            .field("close_failure", &self.close_failure)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for OriginalActorCatalogOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.close_failure.as_ref() {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("catalog controls retain a strong or weak alias"),
        }
    }
}

impl std::error::Error for OriginalActorCatalogOwner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.close_failure
            .as_ref()
            .map(|error| error as &dyn std::error::Error)
    }
}

impl CatalogAuthority {
    fn reconcile_account<T>(
        &self,
        result: Result<T, OriginalActorAccountError>,
    ) -> Result<T, StoreError> {
        let after = self.accounts.check();
        match (result, after) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(source), after) => Err(self.remember(CatalogCause::Account {
                source,
                original_after: after.err(),
            })),
            (Ok(_), Err(source)) => Err(self.remember(CatalogCause::Supervision {
                source,
                original_after: None,
            })),
        }
    }

    fn check(&self) -> Result<(), StoreError> {
        match self.failure.lock() {
            Ok(slot) => {
                if let Some(source) = slot.as_ref() {
                    return Err(self.decode_error(source.clone()));
                }
            }
            Err(poison) => {
                drop(poison.into_inner());
                return Err(self.remember(CatalogCause::Poisoned));
            }
        }
        self.budget
            .check()
            .map_err(|source| self.decode_error(source))?;
        self.budget
            .verify_live()
            .map_err(|source| self.decode_error(source))
    }

    fn decode_error(&self, source: DecodeAdmissionError) -> StoreError {
        StoreError::DecodeAdmission {
            source,
            custody: Some(self.budget.custody()),
        }
    }

    fn remember(&self, cause: CatalogCause) -> StoreError {
        let mut slot = match self.failure.lock() {
            Ok(slot) => slot,
            Err(poison) => poison.into_inner(),
        };
        // Exactly one typed failure control was admitted with this authority.
        let source = slot
            .get_or_insert_with(|| DecodeAdmissionError::new(cause))
            .clone();
        self.decode_error(source)
    }

    fn reconcile<T>(&self, result: Result<T, HostSupervisionError>) -> Result<T, StoreError> {
        let after = self.accounts.check();
        match (result, after) {
            (Ok(value), Ok(_)) => Ok(value),
            (Err(source), after) => Err(self.remember(CatalogCause::Supervision {
                source,
                original_after: after.err(),
            })),
            (Ok(_), Err(source)) => Err(self.remember(CatalogCause::Supervision {
                source,
                original_after: None,
            })),
        }
    }
}

impl SqliteCatalogSupervisor for CatalogSupervisor {
    fn reserve_resident_bytes(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.check()?;
        let extent = bytes
            .checked_add(ResourceLoan::allocation_bytes::<CatalogCredit>())
            .ok_or(StoreError::Quota)?;
        let scratch = self
            .0
            .budget
            .reserve_scratch_bytes(extent)
            .map_err(|source| self.0.decode_error(source))?;
        let loan = ResourceLoan::new(CatalogCredit {
            _scratch: scratch,
            _authority: Arc::clone(&self.0),
        });
        self.0.check()?;
        Ok(loan)
    }

    fn begin(
        &self,
        kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        self.0.check()?;
        self.0
            .budget
            .charge_bytes(std::mem::size_of::<CatalogOperation>() as u64)
            .map_err(|source| self.0.decode_error(source))?;

        // Publish the actual guard in its already paid box before observing
        // the separate original postcut. Uncertainty leaves the first cause.
        let mut operation = Box::new(CatalogOperation {
            guard: None,
            authority: Arc::clone(&self.0),
        });
        let result = match kind {
            SqliteCatalogOperationKind::Read => self.0.accounts.begin_read(),
            SqliteCatalogOperationKind::Write => self.0.accounts.begin_write(),
        };
        match result {
            Ok(guard) => operation.guard = Some(guard),
            Err(source) => {
                return self
                    .0
                    .reconcile::<()>(Err(source))
                    .map(|()| operation as Box<dyn SqliteCatalogOperation>);
            }
        }
        self.0.reconcile(Ok(()))?;
        Ok(operation)
    }
}

impl SqliteCatalogOperation for CatalogOperation {
    fn check(&self) -> Result<(), StoreError> {
        self.authority.check()?;
        let guard = self.guard.as_ref().ok_or(StoreError::Unauthorized)?;
        self.authority.reconcile(guard.wait_slice().map(|_| ()))
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        // Moving out first frees the actual Box control while the stack value
        // still pins its authority. Healthy closure cannot race that deallocation.
        let mut operation = *self;
        operation.authority.check()?;
        let guard = operation.guard.as_ref().ok_or(StoreError::Unauthorized)?;
        operation
            .authority
            .reconcile(guard.complete().map(|_| ()))?;
        drop(operation.guard.take());
        Ok(())
    }
}

impl Drop for CatalogOperation {
    fn drop(&mut self) {
        if self.guard.is_some() {
            let _ = self.authority.remember(CatalogCause::Abandoned);
            std::mem::forget(self.guard.take());
        }
    }
}

fn shared_extent<T>() -> Result<u64, HostServiceError> {
    let (layout, _) = Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map_err(|_| HostServiceError::CapacityExhausted)?;
    u64::try_from(layout.pad_to_align().size()).map_err(|_| HostServiceError::CapacityExhausted)
}
