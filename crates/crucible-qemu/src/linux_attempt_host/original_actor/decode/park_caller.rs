//! Prepays a fixed park caller loan from the already-admitted actor decoder.
//!
//! The workflow keeps its external decoder owner. This nominal loan shares its
//! exact authority and budget, and therefore prevents that owner from closing
//! while an executor or retained phase still borrows it. It creates no bank,
//! guard, clock, process contract or native capability.

use std::sync::Arc;

use crucible::owned_decode::DecodeBudget;
use crucible_linux_resource::host_supervision::HostOperationGuard;
use crucible_ram::ResourceLoan;

use super::{
    OriginalActorAccountError, OriginalActorDecodeOwner, OriginalDecodeAuthority, shared_extent,
};

/// Borrows the same actor's decoder authority for a fixed later park operation.
///
/// Only the genuine decoder owner can construct its enclosing prepaid lease.
/// The loan does not copy the external owner's closure or containment duties.
pub struct OriginalActorParkCaller {
    pub(super) budget: Option<DecodeBudget>,
    pub(super) authority: Option<Arc<OriginalDecodeAuthority>>,
}

/// Retains the fixed caller body and its original external credit together.
///
/// Clones alias the same precreated allocation. The final body and shared
/// control close before the original credit; surrounding executor/phase
/// owners must also prepay their own storage before retaining an alias.
#[derive(Clone)]
#[must_use = "retain through the complete executor or park phase disposition"]
pub struct OriginalActorParkCallerLease {
    state: Arc<OriginalActorParkCaller>,
    // The shared caller allocation closes before this original loan refunds.
    _credit: ResourceLoan,
}

impl std::fmt::Debug for OriginalActorParkCallerLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalActorParkCallerLease")
            .finish_non_exhaustive()
    }
}

impl OriginalActorParkCallerLease {
    /// Lends the same fixed caller without exposing a guard or account getter.
    pub fn caller(&self) -> &OriginalActorParkCaller {
        &self.state
    }
}

impl OriginalActorParkCaller {
    /// Checks the exact retained Preparation before any park effect.
    ///
    /// # Errors
    /// Refuses another original allocation, consumed custody or actual expiry.
    pub fn verify_parent_park_preparation(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        self.verify_original(original)
    }

    pub(crate) fn verify_original(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !Arc::ptr_eq(original, &authority.original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        authority.require_original()
    }

    /// Lends the existing decode budget for the fixed provider's prepaid body.
    ///
    /// # Errors
    /// Refuses spent original custody or an absent budget. Every actual caller
    /// storage and transport allocation still requires its own reservation.
    pub fn budget(&self) -> Result<&DecodeBudget, OriginalActorAccountError> {
        self.authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .require_original()?;
        self.budget
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)
    }
}

impl OriginalActorDecodeOwner {
    /// Prepays a fixed caller loan from this exact workflow decoder.
    ///
    /// The closed actor issuer supplies its retained Preparation. This check
    /// authenticates that allocation before aliases or shared storage are born;
    /// a supervisor, equal timeout or caller-supplied budget cannot replace it.
    /// The workflow keeps this external owner through all loan retirement.
    ///
    /// # Errors
    /// Refuses different/spent original custody or original credit admission.
    pub fn retain_parent_park_caller(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<OriginalActorParkCallerLease, OriginalActorAccountError> {
        self.verify_original(original)?;
        let authority = self
            .authority
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let budget = self.budget()?;
        let bytes = shared_extent::<OriginalActorParkCaller>()?
            .checked_add((2 * std::mem::size_of::<OriginalActorParkCallerLease>()) as u64)
            .ok_or(crucible_linux_resource::host_services::HostServiceError::CapacityExhausted)?;
        let credit = authority.reserve_original(bytes, 0)?;
        let loan = OriginalActorParkCallerLease {
            state: Arc::new(OriginalActorParkCaller {
                budget: Some(budget.clone()),
                authority: Some(Arc::clone(authority)),
            }),
            _credit: credit,
        };
        self.verify_original(original)?;
        Ok(loan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_services::HostServiceAllocator;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_linux_resource::test_support::TestAllocationObserver;

    #[test]
    fn park_caller_loan_rejects_different_live_original_before_birth() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let different = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner =
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();

        let (refusal, counts) =
            TestAllocationObserver::count(|| owner.retain_parent_park_caller(&different));

        assert!(matches!(
            refusal,
            Err(OriginalActorAccountError::Unavailable)
        ));
        assert_eq!(counts.allocations, 0);
        original.wait_slice().unwrap();
        different.wait_slice().unwrap();
        assert!(owner.try_close().is_ok());
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_ok());
    }

    #[test]
    fn park_caller_alias_keeps_external_decoder_open_until_last_loan_drop() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let resident = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20).unwrap();
        let owner =
            OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20).unwrap();
        let caller = owner.retain_parent_park_caller(&original).unwrap();
        let alias = caller.clone();
        caller
            .caller()
            .verify_parent_park_preparation(&original)
            .unwrap();

        let owner = owner.try_close().err().unwrap();
        drop(caller);
        let owner = owner.try_close().err().unwrap();
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
        alias
            .caller()
            .verify_parent_park_preparation(&original)
            .unwrap();
        drop(alias);

        assert!(owner.try_close().is_ok());
        assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
        assert!(metadata.reserve_resources(1, 64, 1 << 20).is_ok());
    }
}
