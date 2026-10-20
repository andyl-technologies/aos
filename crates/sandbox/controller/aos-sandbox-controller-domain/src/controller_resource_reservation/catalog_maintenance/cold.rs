//! Joins fresh native population and the same paid complete C/Source family.
//!
//! The sealed decoded models must match actual physically disposed query
//! originals. Historical Recover supplies comparison fields only; all payment,
//! freshness and native posts belong to this new maintenance interval.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::{
    ControllerInventoryDecodedOriginalV2, ControllerInventoryModelDataV2,
};

pub(super) struct CatalogMaintenanceColdOriginalV2 {
    pub(super) baseline: Option<Result<(), JournalError>>,
    observed: Option<Result<(), JournalError>>,
    pub(super) retained: Option<crate::host_catalog_reconciliation::StoppedRetentionComparisonV1>,
    repeated: Option<JournalError>,
}

impl CatalogMaintenanceColdOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            baseline: None,
            observed: None,
            retained: None,
            repeated: None,
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.baseline
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.observed
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Joins the exact fresh native absence certificates to this new paid interval.
    ///
    /// Each sole-decoder model is first compared with the same native query's
    /// stored request/body commitments and actual positive disposal. Historical
    /// C/Source family fields grant neither old R time nor effect authority.
    ///
    /// # Errors
    /// Refuses another purpose, reentry, unpaid/incomplete or substituted model,
    /// current family changes, unknown physical population or foreign Storage.
    #[doc(hidden)]
    pub fn observe_cold_population_once_v2(
        &mut self,
        host: (
            &AuthenticatedBrokerMethodOutcomeV1,
            &ControllerInventoryDecodedOriginalV2,
        ),
        mount: (
            &AuthenticatedBrokerMethodOutcomeV1,
            &ControllerInventoryDecodedOriginalV2,
        ),
        storage: (
            &AuthenticatedBrokerMethodOutcomeV1,
            &ControllerInventoryDecodedOriginalV2,
        ),
        network: (
            &AuthenticatedBrokerMethodOutcomeV1,
            &ControllerInventoryDecodedOriginalV2,
        ),
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        if self.owner.purpose != Some(MaintenancePurposeV2::ColdPopulation)
            || self.owner.cold.observed.is_some()
            || !matches!(self.owner.cold.baseline, Some(Ok(())))
        {
            self.owner
                .cold
                .repeated
                .get_or_insert(JournalError::ProtectedBoundary);
            self.owner.first.get_or_insert(First::Cold);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.cold.observed = Some((|| {
            for (index, (outcome, model)) in [host, mount, storage, network].into_iter().enumerate()
            {
                self.owner
                    .inventory_evidence
                    .require_model_v2(index, outcome, model)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            }
            self.owner
                .source_projection
                .require_source_families_v2(self.source.journal_ref_v1())?;

            let stopped = self.owner.source_projection.stopped_history_v2(
                self.controller, self.source.journal_ref_v1())?.is_some();
            if stopped {
                let demand = crate::host_catalog_reconciliation::
                    retained_population_model_receiving_demand_v1(
                        self.controller, storage.1, mount.1, network.1)?;
                self.owner.reserve_additional_v2(self.controller, self.source, demand)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                self.owner.check_frontier_v2()?;
                let observed = [
                    self.owner.inventory[0].completed_observed_boottime_data_v3()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                    self.owner.inventory[1].completed_observed_boottime_data_v3()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                    self.owner.inventory[2].completed_observed_boottime_data_v3()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                    self.owner.inventory[3].completed_observed_boottime_data_v3()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ];
                let (history, starts) = self.owner.source_projection.stopped_history_v2(
                    self.controller, self.source.journal_ref_v1())?
                    .ok_or(JournalError::ProtectedBoundary)?;
                self.owner.cold.retained = Some(
                    {
                    #[cfg(target_os = "linux")]
                    { crate::controller_inventory_absence::
                        require_cold_maintenance_inventory_population_v1(
                            self.controller, history, starts,
                            self.owner.clock.original_sample_data_v2()?,
                            self.owner.clock.cutoff_data_v2()?, observed,
                            host, mount, storage, network)? }
                    #[cfg(not(target_os = "linux"))]
                    { return Err(JournalError::ProtectedBoundary); }
                    });
                Ok(())
            } else {
                let ControllerInventoryModelDataV2::Storage(inventory, _) = storage.1.model_v2() else {
                    return Err(JournalError::ProtectedBoundary);
                };
                self.controller.require_cold_storage_for_maintenance_data_v2(inventory)?;
                crate::controller_inventory_absence::require_first_local_inventory_absence_data_v2(
                    self.owner.clock.original_sample_data_v2()?,
                    self.owner.clock.cutoff_data_v2()?,
                    host.0, host.1, mount.0, mount.1, network.0, network.1)
            }
        })());
        if !matches!(self.owner.cold.observed, Some(Ok(()))) {
            self.owner.first.get_or_insert(First::Cold);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }
}

/// Borrows only the actual completed new-B cold native owner after every post.
///
/// This is not an effect grant. The SDK must independently retain the same
/// four authenticated Session/model/disposal originals before exposing its
/// completed cold result to the worker.
#[doc(hidden)]
pub struct CatalogMaintenanceColdCompletedNativeBorrowV2<'completed> {
    _owner: &'completed CatalogMaintenanceOriginalV2,
}

impl CatalogMaintenanceOriginalV2 {
    /// Rejoins actual fresh cold observations, canonical catalog and every native post.
    ///
    /// # Errors
    /// Refuses incomplete physical discovery, changed canonical source, missing
    /// native/SDK disposal, current C identity or any independently owed post.
    #[doc(hidden)]
    pub fn completed_cold_native_v2<'completed>(
        &'completed self,
        controller: &Journal,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
    ) -> Result<CatalogMaintenanceColdCompletedNativeBorrowV2<'completed>, ResourceReservationErrorV1>
    {
        self.require_completed_posts_v2(controller)?;
        if self.purpose != Some(MaintenancePurposeV2::ColdPopulation)
            || !matches!(self.cold.baseline, Some(Ok(())))
            || !matches!(self.cold.observed, Some(Ok(())))
            || self.cold.repeated.is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self
            .native
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.require_completed_maintenance_source_data_v2(native, controller)?;
        if self.catalog_io_entered {
            self.catalog_io.require_disposed_v2()?;
        }
        Ok(CatalogMaintenanceColdCompletedNativeBorrowV2 { _owner: self })
    }
}
