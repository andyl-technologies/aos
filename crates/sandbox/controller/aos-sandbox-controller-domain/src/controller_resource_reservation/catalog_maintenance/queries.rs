//! Lends finite maintenance inventories to the sole retained query engine.
//!
//! Every query keeps its own originals on the same maintenance owner. This
//! borrower supplies no effect authority or replacement deadline. The public
//! SDK entrance accepts only the continuously held completed Session borrower.

use super::*;
use crate::ControllerInitialBrokerSessionReceivingV1;
use crate::controller_resource_reservation::operator_create_recovery::storage::inventory::{
    InventoryOriginalsV1, RecoveryInventorySourceV2,
};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;

/// Borrows the actual current C, Source and maintenance owner together.
///
/// This value cannot be constructed from a budget, role, deadline or detached
/// native receipt. Ending it releases only Rust borrows, never charged custody.
#[doc(hidden)]
pub struct ControllerCatalogMaintenanceLoanV2<'owner, 'controller> {
    pub(super) owner: &'owner mut CatalogMaintenanceOriginalV2,
    pub(super) controller: &'controller mut Journal,
    pub(super) source: &'controller ProtectedSourceDomainJournalOwnerV1,
}

impl CatalogMaintenanceOriginalV2 {
    /// Borrows a paid interval after the actual complete Source replay.
    ///
    /// # Errors
    /// Refuses missing payment, Source replay, replaced native owners, expiry,
    /// failed earlier work or an interval whose independent posts have begun.
    pub fn borrow_interval_v2<'owner, 'controller>(
        &'owner mut self,
        controller: &'controller mut Journal,
        source: &'controller ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<ControllerCatalogMaintenanceLoanV2<'owner, 'controller>, CatalogMaintenanceClosedV2>
    {
        self.require_current_v2(controller, source)
            .map_err(|_| CatalogMaintenanceClosedV2)?;
        self.source_projection
            .require_same_projection_v2(source.journal_ref_v1())
            .map_err(|_| CatalogMaintenanceClosedV2)?;
        self.check_frontier_v2()
            .map_err(|_| CatalogMaintenanceClosedV2)?;
        Ok(ControllerCatalogMaintenanceLoanV2 {
            owner: self,
            controller,
            source,
        })
    }
}

impl<'owner, 'controller> ControllerCatalogMaintenanceLoanV2<'owner, 'controller> {
    pub(in crate::controller_resource_reservation) fn state_v2(
        &self,
        index: usize,
    ) -> &InventoryOriginalsV1 {
        &self.owner.inventory[index]
    }

    pub(in crate::controller_resource_reservation) fn state_mut_v2(
        &mut self,
        index: usize,
    ) -> &mut InventoryOriginalsV1 {
        &mut self.owner.inventory[index]
    }

    pub(in crate::controller_resource_reservation) fn require_current_v2(
        &mut self,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_current_v2(self.controller, self.source)
    }

    pub(in crate::controller_resource_reservation) fn check_frontier_v2(
        &mut self,
    ) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        self.owner.check_frontier_v2().map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation) fn reserve_additional_v2(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner
            .reserve_additional_v2(self.controller, self.source, demand)
    }

    pub(in crate::controller_resource_reservation) fn original_cutoff_v2(
        &self,
    ) -> Result<u64, ResourceReservationErrorV1> {
        self.owner.clock.cutoff_data_v2().map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation) fn require_completed_session_v2(
        &self,
        receiving: &ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal,
        index: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_completed_session_data_v3(self.controller, receiving, journal, index)
    }

    /// Returns the method fixed by this actual maintenance query ordinal.
    ///
    /// # Errors
    /// Refuses an unsupported ordinal or failed current Source/C/native join.
    pub fn inventory_method_data_v2(
        &mut self,
        index: usize,
    ) -> Result<BrokerMethod, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        super::super::operator_create_recovery::storage::inventory::maintenance_context_v2(index)
            .map(|(_, method)| method)
    }

    /// Borrows one actual completed ordinary Session for its fixed inventory.
    ///
    /// The native constructor independently rejoins its private receiver to
    /// the current B generation. SDK callers must use the same opaque Session
    /// borrower throughout the protected exchange and positive disposition.
    ///
    /// # Errors
    /// Refuses order, duplicate entry, another Session, missing current native
    /// custody, expiry, geometry or financial admission before new work.
    pub fn borrow_inventory_once_v2<'query>(
        &'query mut self,
        index: usize,
        receiving: &ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal,
        shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<
        crate::ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'static, 'static>,
        ResourceReservationErrorV1,
    > {
        self.require_current_v2()?;
        let first = match self.owner.purpose {
            Some(MaintenancePurposeV2::ColdPopulation) => 0,
            Some(MaintenancePurposeV2::CatalogRefresh) => 1,
            None => return Err(ResourceReservationErrorV1::Conflict),
        };
        if index < first
            || index >= self.owner.inventory.len()
            || !self.owner.inventory[first..index]
                .iter()
                .all(InventoryOriginalsV1::is_completed_query_v2)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.begin_snapshot_fence_once_v2(index)?;
        RecoveryInventorySourceV2::maintenance_v2(self, index)?
            .begin_query_v2(receiving, journal, shape)
    }

    /// Latches the actual native query cause before any independent posts.
    pub fn retain_sdk_refusal_once_v2(&mut self) {
        if self.owner.first.is_some() {
            return;
        }
        if let Some(index) = self
            .owner
            .inventory
            .iter()
            .position(|query| query.failure_v1().is_some())
        {
            self.owner.first = Some(First::Inventory(index));
        } else {
            self.owner
                .sdk_refusal
                .get_or_insert(JournalError::ProtectedBoundary);
            self.owner.first = Some(First::Sdk);
        }
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    pub(crate) fn enter_publication_source_once_v2(
        &mut self,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2, ResourceReservationErrorV1>{
        self.require_current_v2()?;
        if self.owner.catalog_source_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.catalog_source_entered = true;
        self.check_frontier_v2()?;
        let bank = self
            .owner
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.catalog_maintenance_identity_current_v2(
            self.owner
                .native
                .as_ref()
                .and_then(|native| native.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            self.controller,
            self.owner
                .profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        )
    }

    pub(crate) fn require_publication_identity_current_v2(
        &mut self,
        identity: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        if !self.owner.catalog_source_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bank = self
            .owner
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.require_catalog_maintenance_identity_current_v2(
            self.owner
                .native
                .as_ref()
                .and_then(|native| native.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            identity,
            self.controller,
            self.owner
                .profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        )
    }

    pub(crate) fn commit_catalog_recipe_v2(
        &mut self,
        transaction: &crate::JournalTransaction,
        recipe: &crate::host_catalog_reconciliation::publication_recipe::HostCatalogCommitRecipeV2<
            '_,
        >,
    ) -> Result<crate::CommitResult, JournalError> {
        self.owner.commit_append_recipe_once_v2(
            self.controller,
            self.source,
            transaction,
            super::append_recipe::CatalogMaintenanceAppendRecipeV2::HostCatalog(recipe),
        )
    }

    pub(crate) fn original_failure_selected_v2(&self) -> bool {
        self.owner.original_failure_selected_v2()
    }
}

/// Keeps the actual native/source association while canonical Source owns C.
///
/// Only the completed inventory borrower constructs this short view. It keeps
/// C outside the view so the same canonical pending/confirmation engine can
/// pass its genuine writer directly into the scoped native append kernel.
pub(crate) struct CatalogMaintenanceSourceReceivingV2<'loan> {
    pub(super) owner: &'loan mut CatalogMaintenanceOriginalV2,
    pub(super) source: &'loan ProtectedSourceDomainJournalOwnerV1,
}

impl CatalogMaintenanceSourceReceivingV2<'_> {
    pub(crate) fn enter_once_v2(&mut self, controller: &Journal)
    -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2, ResourceReservationErrorV1>{
        self.owner.require_current_v2(controller, self.source)?;
        if self.owner.catalog_source_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.catalog_source_entered = true;
        self.owner.check_frontier_v2()?;
        let bank = self
            .owner
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.catalog_maintenance_identity_current_v2(
            self.owner
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            controller,
            self.owner
                .profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        )
    }

    pub(crate) fn require_current_v2(
        &mut self,
        controller: &Journal,
        identity: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_current_v2(controller, self.source)?;
        if !self.owner.catalog_source_entered {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bank = self
            .owner
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.require_catalog_maintenance_identity_current_v2(
            self.owner
                .native
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            identity,
            controller,
            self.owner
                .profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
        )
    }

    pub(crate) fn admit_canonical_source_v2(
        &mut self,
        controller: &Journal,
        identity: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2(controller, identity)?;
        self.owner
            .reserve_additional_v2(controller, self.source, demand)?;
        self.owner.check_frontier_v2()?;
        Ok(())
    }

    pub(crate) fn commit_catalog_recipe_v2(
        &mut self,
        controller: &mut Journal,
        transaction: &crate::JournalTransaction,
        recipe: &crate::host_catalog_reconciliation::publication_recipe::HostCatalogCommitRecipeV2<
            '_,
        >,
    ) -> Result<crate::CommitResult, JournalError> {
        self.owner.commit_append_recipe_once_v2(
            controller,
            self.source,
            transaction,
            super::append_recipe::CatalogMaintenanceAppendRecipeV2::HostCatalog(recipe),
        )
    }

    pub(crate) fn original_failure_selected_v2(&self) -> bool {
        self.owner.original_failure_selected_v2()
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Prepares the canonical no-slot catalog from this interval's real snapshots.
    ///
    /// The method consumes only the three actual snapshots produced by the
    /// same completed native queries. A caller supplies no inventory model,
    /// comparison digest, payer, transaction or descriptor.
    ///
    /// # Errors
    /// Refuses incomplete inventories, repeated Source entry, changed native
    /// affinity, current attachment requirements, geometry, append or sealing.
    #[doc(hidden)]
    pub fn prepare_catalog_publication_once_v2(
        &mut self,
        publication: &mut crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
    ) -> Result<
        crate::host_catalog_reconciliation::CatalogMaintenancePublicationStatusV2,
        crate::host_catalog_reconciliation::StartHostCatalogPublicationClosedV2,
    > {
        use crate::host_catalog_reconciliation::StartHostCatalogPublicationClosedV2 as Closed;
        self.require_current_v2().map_err(|_| Closed)?;
        let first = match self.owner.purpose {
            Some(MaintenancePurposeV2::ColdPopulation) => 0,
            Some(MaintenancePurposeV2::CatalogRefresh) => 1,
            None => return Err(Closed),
        };
        if !self.owner.inventory[first..]
            .iter()
            .all(InventoryOriginalsV1::is_completed_query_v2)
        {
            return Err(Closed);
        }
        let prior_mount = self.owner.snapshots.prior_mount_record_digest_data_v2();
        let (storage, network, mount) = self
            .owner
            .snapshots
            .take_catalog_inputs_once_v2()
            .map_err(|_| Closed)?;
        let mut receiving = CatalogMaintenanceSourceReceivingV2 {
            owner: self.owner,
            source: self.source,
        };
        publication.prepare_maintenance_pending_once_v2(
            self.controller,
            &mut receiving,
            storage,
            network,
            mount,
            prior_mount,
        )
    }
}

impl CatalogMaintenanceSourceReceivingV2<'_> {
    pub(crate) fn require_terminal_for_confirmation_v2(
        &mut self,
        controller: &Journal,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner.require_current_v2(controller, self.source)?;
        source.require_same_maintenance_source_v2(self, controller)?;
        let native = self
            .owner
            .native
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.owner
            .catalog_io
            .require_terminal_v2(native, source, outcome)
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Confirms only this same actual completed native Catalog17 exchange.
    ///
    /// The short IO borrower must have returned. Signed response DATA alone
    /// cannot enter: the actual owner must retain its consumed complete stage,
    /// Sent/ReceivedRecord originals and independent native Session post.
    ///
    /// # Errors
    /// Retains changed native/source affinity, repeated confirmation, canonical
    /// history, exact scoped append or readback refusal.
    #[doc(hidden)]
    pub fn confirm_catalog_publication_once_v2(
        &mut self,
        publication: &mut crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), crate::host_catalog_reconciliation::StartHostCatalogPublicationClosedV2> {
        let mut receiving = CatalogMaintenanceSourceReceivingV2 {
            owner: self.owner,
            source: self.source,
        };
        publication.confirm_maintenance_once_v2(self.controller, &mut receiving, outcome)
    }
}

impl CatalogMaintenanceOriginalV2 {
    pub(super) fn require_completed_session_data_v3(
        &self,
        controller: &Journal,
        receiving: &ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal,
        index: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        let role = match index {
            0 => crate::ControllerInitialBrokerSessionRoleV1::Host,
            1 => crate::ControllerInitialBrokerSessionRoleV1::Mount,
            2 => crate::ControllerInitialBrokerSessionRoleV1::Storage,
            3 => crate::ControllerInitialBrokerSessionRoleV1::Network,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        let bank = self
            .bank
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        receiving.require_completed_catalog_maintenance_journal_v2(
            self
                .native
                .as_ref()
                .and_then(|native| native.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            &bank,
            controller,
            self
                .profile
                .as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?,
            journal,
            role,
        )
    }

}

impl CatalogMaintenanceSourceReceivingV2<'_> {
    /// Prices only the actual retained cold branch's second structural pass.
    pub(crate) fn stopped_retention_receiving_demand_v1(
        &self,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.owner.cold.retained.is_none() {
            return Ok(ResourceVector::ZERO);
        }
        crate::host_catalog_reconciliation::retained_population_receiving_demand_v1(controller)
            .map_err(Into::into)
    }

    /// Rejoins the actual stopped comparison before the Current-only projection.
    pub(crate) fn stopped_retention_data_v1(
        &mut self,
        controller: &Journal,
    ) -> Result<Option<(
        &crate::host_catalog_reconciliation::StoppedRetentionComparisonV1,
        &super::completed_start::CatalogMaintenanceCompletedStartDataV1,
        crate::lifecycle::completed_stop::CompletedStopHistoryDataV1,
    )>, ResourceReservationErrorV1> {
        self.owner.require_current_v2(controller, self.source)?;
        if self.owner.cold.retained.is_none() {
            return Ok(None);
        }
        let same = self.owner.source_projection.require_stopped_current_v2(
            controller, self.source.journal_ref_v1());
        if same.is_err() {
            self.owner.first.get_or_insert(First::SourceProjection);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let record = self.owner.cold.retained.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let (history, starts) = self.owner.source_projection.stopped_history_v2(
            controller, self.source.journal_ref_v1())?
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let start = starts.require_stopped_scope_v1(record.scope_v1())?;
        let stop = history.require_scope_v1(record.scope_v1())?;
        Ok(Some((record, start, stop)))
    }
}
