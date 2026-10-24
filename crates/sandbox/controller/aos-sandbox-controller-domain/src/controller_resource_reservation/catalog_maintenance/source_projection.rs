//! Retains complete paid Source replay and finite cold lifecycle comparisons.
//!
//! Historical completed Stop and Start rows are comparison DATA. The same
//! maintenance native owners continue to enforce the actual current C/Source
//! cuts, original horizon, financial admission and independently owed posts.

use super::closed_family::CatalogMaintenanceClosedFamilyOriginalV1;
use super::completed_start::CatalogMaintenanceCompletedStartOriginalV1;
use super::recover_family::CatalogMaintenanceRecoverFamilyOriginalV1;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::{
    LifecycleHistoricalReadOriginalV1, completed_stop::CompletedStopHistoryOriginalV1,
};
use crate::{Journal, JournalError, RecordNamespace};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use std::error::Error;

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Geometry,
    Family,
    Identity,
    Projection,
    ColdScope,
}

pub(super) struct CatalogMaintenanceSourceProjectionV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    family: Option<Result<Option<(aos_sandbox_model::OperationId, [u8; 32])>, JournalError>>,
    identity: Option<Result<SourceProvisioningIdentityV1, JournalError>>,
    model: Option<Box<LifecycleHistoricalReadOriginalV1>>,
    history: Option<Box<CompletedStopHistoryOriginalV1>>,
    starts: Option<Box<CatalogMaintenanceCompletedStartOriginalV1>>,
    recoveries: Option<Box<CatalogMaintenanceRecoverFamilyOriginalV1>>,
    closed_family: Option<Box<CatalogMaintenanceClosedFamilyOriginalV1>>,
    historical_geometry: bool,
    stopped: bool,
    observed: Option<Result<(), JournalError>>,
    cold_scope: Option<Result<(), JournalError>>,
    current_family: Option<Result<(), JournalError>>,
    first: Option<First>,
    closed: JournalError,
}

impl CatalogMaintenanceSourceProjectionV2 {
    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            family: None,
            identity: None,
            model: None,
            history: None,
            starts: None,
            recoveries: None,
            closed_family: None,
            historical_geometry: false,
            stopped: false,
            observed: None,
            cold_scope: None,
            current_family: None,
            first: None,
            closed: JournalError::ProtectedBoundary,
        }
    }

    pub(super) fn prepare_geometry_once_v2(
        &mut self,
        source: &Journal,
        controller: &Journal,
        cold: bool,
    ) {
        if self.geometry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return;
        }
        // Presence chooses only an invoice. Completion is proved after payment.
        self.historical_geometry =
            cold && controller.records(RecordNamespace::Effect).next().is_some();
        self.geometry =
            Some((|| {
                let graph = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
                    source.all_records(),
                )
                .ok_or(JournalError::JournalTooLarge)?;
                let selection = crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::
                additional_selection_receiving_v1(source.all_records())
                .ok_or(JournalError::JournalTooLarge)?;
                let carrier = LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(JournalError::JournalTooLarge)?;
                let mut demand = controller
                    .create_storage_semantic_append_demand_v1()?
                    .checked_add(graph)?
                    .checked_add(selection)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))?;
                if self.historical_geometry {
                    let history = CompletedStopHistoryOriginalV1::receiving_demand_v1(
                        controller.historical_read_view_v1().rows_data_v2(),
                        source.historical_read_view_v1().rows_data_v2(),
                    )
                    .ok_or(JournalError::JournalTooLarge)?;
                    let starts = CatalogMaintenanceCompletedStartOriginalV1::receiving_demand_v1(
                        controller, source,
                    )
                    .ok_or(JournalError::JournalTooLarge)?;
                    let recoveries =
                        CatalogMaintenanceRecoverFamilyOriginalV1::receiving_demand_v1(controller)
                            .ok_or(JournalError::JournalTooLarge)?;
                    let family = CatalogMaintenanceClosedFamilyOriginalV1::receiving_demand_v1(
                        controller, source,
                    )
                    .ok_or(JournalError::JournalTooLarge)?;
                    let population = crate::host_catalog_reconciliation::
                    retained_population_receiving_demand_v1(controller)?;
                    demand = demand
                        .checked_add(history)?
                        .checked_add(starts)?
                        .checked_add(recoveries)?
                        .checked_add(family)?
                        .checked_add(population)?;
                }
                Ok(demand)
            })());
        if !matches!(self.geometry, Some(Ok(_))) {
            self.first = Some(First::Geometry);
        }
    }

    pub(super) fn receiving_demand_v2(&self) -> Result<ResourceVector, JournalError> {
        if self.first.is_some() || self.identity.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn observe_once_v2(
        &mut self,
        source: &Journal,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        if self.first.is_some()
            || self.identity.is_some()
            || self.observed.is_some()
            || !matches!(self.geometry, Some(Ok(_)))
        {
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.identity = Some(source.source_provisioning_identity_v1());
        if !matches!(self.identity, Some(Ok(_))) {
            self.first = Some(First::Identity);
            return Err(JournalError::ProtectedBoundary);
        }
        self.model = Some(Box::new(LifecycleHistoricalReadOriginalV1::new()));
        self.observed = Some((|| {
            let model = self.model.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            model.observe_rows_projection_once_v3(
                source.historical_read_view_v1().rows_data_v2(),
            )?;
            if self.historical_geometry {
                self.history = Some(Box::new(CompletedStopHistoryOriginalV1::new()));
                let history = self
                    .history
                    .as_mut()
                    .ok_or(JournalError::ProtectedBoundary)?;
                history
                    .observe_once_v1(controller.historical_read_view_v1().rows_data_v2(), model)?;
                self.stopped = history.has_completed_stops_v1()?;
                if self.stopped {
                    self.starts = Some(Box::new(CatalogMaintenanceCompletedStartOriginalV1::new()));
                    self.recoveries =
                        Some(Box::new(CatalogMaintenanceRecoverFamilyOriginalV1::new()));
                    self.closed_family =
                        Some(Box::new(CatalogMaintenanceClosedFamilyOriginalV1::new()));
                    let starts = self
                        .starts
                        .as_mut()
                        .ok_or(JournalError::ProtectedBoundary)?;
                    starts.observe_once_v1(controller, model, history)?;
                    let recoveries = self
                        .recoveries
                        .as_mut()
                        .ok_or(JournalError::ProtectedBoundary)?;
                    recoveries.observe_once_v1(controller, history)?;
                    self.closed_family
                        .as_mut()
                        .ok_or(JournalError::ProtectedBoundary)?
                        .observe_once_v1(controller, model, history, starts, recoveries)?;
                    return Ok(());
                }
            }
            self.family = Some(controller.catalog_maintenance_source_family_data_v2());
            let family = self
                .family
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            if let Some((parent, _)) = family {
                model.select_current_operation_once_v3(parent)?;
            }
            Ok(())
        })());
        if !matches!(self.observed, Some(Ok(()))) {
            self.first = Some(if matches!(self.family, Some(Err(_))) {
                First::Family
            } else {
                First::Projection
            });
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn require_same_projection_v2(
        &self,
        source: &Journal,
    ) -> Result<&LifecycleHistoricalReadOriginalV1, JournalError> {
        if self.first.is_some() || !matches!(self.observed, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let identity = self
            .identity
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        source.require_current_source_provisioning_identity_v1(identity)?;
        let model = self
            .model
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        model.projection_ready_v1()?;
        Ok(model)
    }

    pub(super) fn stopped_history_v2(
        &self,
        controller: &Journal,
        source: &Journal,
    ) -> Result<
        Option<(
            &CompletedStopHistoryOriginalV1,
            &CatalogMaintenanceCompletedStartOriginalV1,
        )>,
        JournalError,
    > {
        let model = self.require_same_projection_v2(source)?;
        if !self.stopped {
            return Ok(None);
        }
        let history = self
            .history
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        history.require_same_v1(controller.historical_read_view_v1().rows_data_v2(), model)?;
        self.closed_family
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_same_v1(controller)?;
        let starts = self
            .starts
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        starts.require_complete_v1()?;
        Ok(Some((history, starts)))
    }

    pub(super) fn require_stopped_current_v2(
        &mut self,
        controller: &Journal,
        source: &Journal,
    ) -> Result<(), JournalError> {
        if matches!(self.current_family, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.current_family = Some((|| {
            self.stopped_history_v2(controller, source)?
                .ok_or(JournalError::ProtectedBoundary)?;
            self.require_source_families_v2(source)
        })());
        if !matches!(self.current_family, Some(Ok(()))) {
            self.first.get_or_insert(First::ColdScope);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn observe_cold_scope_once_v2(
        &mut self,
        source: &Journal,
    ) -> Result<(), JournalError> {
        if self.cold_scope.is_some() || self.first.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.cold_scope = Some(self.require_source_families_v2(source));
        if !matches!(self.cold_scope, Some(Ok(()))) {
            self.first.get_or_insert(First::ColdScope);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn require_source_families_v2(&self, source: &Journal) -> Result<(), JournalError> {
        let model = self.require_same_projection_v2(source)?;
        if self.stopped {
            crate::controller_resource_reservation::source_family::
                require_completed_stop_source_families_data_v1(source, model,
                    self.history.as_deref().ok_or(JournalError::ProtectedBoundary)?,
                    self.starts.as_deref().ok_or(JournalError::ProtectedBoundary)?,
                    self.closed_family.as_deref().ok_or(JournalError::ProtectedBoundary)?)
        } else {
            crate::controller_resource_reservation::source_family::
                require_first_local_source_families_data_v2(source, model,
                    self.family.as_ref().and_then(|value| value.as_ref().ok())
                        .copied().ok_or(JournalError::ProtectedBoundary)?)
        }
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => Some(&self.closed),
            First::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Identity => self.identity.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Family => self.family.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Projection => {
                // These owning observations run sequentially and each error
                // returns before the next owner can enter. Later family or
                // currentness checks cannot replace this selected operation.
                self.model.as_ref().and_then(|model| model.failure())
                    .or_else(|| self.history.as_ref().and_then(|value| value.failure()))
                    .or_else(|| self.starts.as_ref().and_then(|value| value.failure()))
                    .or_else(|| self.recoveries.as_ref().and_then(|value| value.failure()))
                    .or_else(|| self.closed_family.as_ref().and_then(|value| value.failure()))
                    .or_else(|| self.observed.as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            First::ColdScope => self.cold_scope.as_ref()
                .and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.current_family.as_ref()?
                    .as_ref().err().map(|cause| cause as _)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_geometry_error_remains_the_selected_original() {
        let mut original = CatalogMaintenanceSourceProjectionV2::new();
        original.geometry = Some(Err(JournalError::JournalTooLarge));
        original.identity = Some(Err(JournalError::ProtectedBoundary));
        original.cold_scope = Some(Err(JournalError::ProtectedBoundary));
        original.first = Some(First::Geometry);

        let selected: &(dyn Error + 'static) =
            original.geometry.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::addr_eq(original.failure_v2().unwrap(), selected));
    }

    #[test]
    fn selected_currentness_error_does_not_scan_other_operation_diagnostics() {
        let mut original = CatalogMaintenanceSourceProjectionV2::new();
        original.geometry = Some(Err(JournalError::JournalTooLarge));
        original.current_family = Some(Err(JournalError::ProtectedBoundary));
        original.first = Some(First::ColdScope);

        let selected: &(dyn Error + 'static) =
            original.current_family.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::addr_eq(original.failure_v2().unwrap(), selected));
    }
}
