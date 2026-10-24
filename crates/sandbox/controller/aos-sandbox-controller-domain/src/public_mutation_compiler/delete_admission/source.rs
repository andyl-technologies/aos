//! Keeps the actual authorized Delete and its same-C17 Source borrow together.
//!
//! The sole constructor splits one live authorization scope and immediately
//! lends that exact financial loan to the actual protected Source Journal.
//! Callers cannot assemble this pair from unrelated authorization or history
//! DATA. It grants neither Controller acceptance nor a fresh Root floor.

use super::*;
use crate::journal::SourceDeleteSemanticScopeV1;

mod candidate;
pub use candidate::ControllerDeleteCandidateOriginalV2;
mod planning_root;
mod pending;
pub use pending::{ControllerDeletePendingOriginalV2, OriginalDeleteStoragePreparationLoanV3, OriginalDeleteStorageApplyLoanV3, OriginalDeleteNetworkApplyLoanV4, OriginalDeleteMountReapLoanV4};
pub(crate) use planning_root::ControllerDeletePlanningRootCutDataV1;

/// Keeps the exact authorized request beside its continuously borrowed Source/C17 cut.
#[doc(hidden)]
pub struct ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original> {
    authorization: DeleteAuthorizationBindingV1<'scope>,
    source: SourceDeleteSemanticScopeV1<'scope, 'original>,
}

impl<'original> ControllerDeleteAuthorizedScopeV1<'original> {
    /// Joins only this actual authorization to the Bank's same Source scope.
    ///
    /// # Errors
    /// Refuses absent authorization, changed same-C/profile/Launch, native
    /// uncertainty or Source ownership/currentness before returning any scope.
    pub fn borrow_source_authorized_v1<'scope>(
        &'scope mut self,
        source: &'scope mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>, ResourceReservationErrorV1> {
        let (authorization, receiving) = self.split_for_source_v1(bank, controller, profile)?;
        let source = bank.borrow_delete_semantic_scope_v1(source, receiving, controller, profile)?;
        Ok(ControllerDeleteSourceAuthorizedScopeV1 { authorization, source })
    }
}

impl<'scope, 'original> ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original> {
    // This direct owed route never reenters the healthy authorization, model
    // admission or primary. The actual failed caller keeps all originals live.
    pub(crate) fn finish_outer_source_failure_once_v1(&mut self,
        controller: &mut Journal,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), crate::JournalError> {
        self.source.finish_native_once_v1(controller, launch, profile)
    }

    /// Prepays and derives the three cuts from this exact authorized pair.
    pub(crate) fn planning_base_cuts_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<crate::journal::DeletePlanningBaseCutsDataV2, ResourceReservationErrorV1> {
        bank.capture_delete_planning_base_cuts_v2(
            &mut self.source, &self.authorization, controller, profile,
        )
    }

    /// Checks the actual default-local compiled image beside this same C17 cut.
    ///
    /// The returned claim is comparison DATA, not a local Transfer absence
    /// grant. The Runtime must separately seal its never-opened private owner;
    /// Root must independently observe the fixed Transfer and Ownership names.
    ///
    /// # Errors
    /// Refuses a compiled remote execution graph, absent authorization, changed
    /// C/Source/profile/Launch or construction beyond the same declared lane.
    #[doc(hidden)]
    pub fn local_transfer_runtime_funding_data_v3(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        construction_bytes: usize,
    ) -> Result<aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, ResourceReservationErrorV1> {
        #[cfg(feature = "multi-node")]
        {
            let _ = (bank, controller, profile, construction_bytes);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        #[cfg(not(feature = "multi-node"))]
        {
            self.reserve_query_construction_v1(controller, bank, profile, construction_bytes)?;
            bank.delete_local_runtime_funding_data_v3(&self.source, controller, profile)
        }
    }

    pub(crate) fn reserve_query_construction_v1(
        &mut self,
        controller: &mut Journal,
        bank: &ControllerResourceBankOpeningV1,
        profile: &ProductionControllerNormalRootProfileV1,
        bytes: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        // This numeric DATA can only add debt on the already held genuine
        // purpose. It cannot choose a slot, declare capacity or create a loan.
        bank.reserve_delete_query_construction_v1(
            &mut self.source, controller, profile, bytes,
        )
    }

    // Only the private pair can supply these two parts together. The shared
    // query entrance is implemented beside its sole native engine and calls
    // this exact borrow; no public tuple constructor or adoption exists.
    pub(crate) fn planning_parts_v1(
        &mut self,
    ) -> (&DeleteAuthorizationBindingV1<'scope>, &mut SourceDeleteSemanticScopeV1<'scope, 'original>) {
        (&self.authorization, &mut self.source)
    }
}
