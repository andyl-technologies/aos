//! Runs the same canonical Source builder under a genuine maintenance borrower.
//!
//! The caller supplies no catalog, digest tuple, snapshot or descriptor. The
//! short native borrower is privately constructed only after the maintenance's
//! completed inventories, and retains its original native turn identity across
//! history, projection, pending append, sealing and confirmation.

use super::*;
use crate::controller_resource_reservation::CatalogMaintenanceSourceReceivingV2;

#[derive(Clone, Copy)]
pub(super) enum MaintenanceSourceModeV2 {
    New,
    Resume,
}

/// Reports actual canonical Source work without asserting Controller readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum CatalogMaintenancePublicationStatusV2 {
    /// Fresh complete comparisons produced the same current canonical catalog.
    Unchanged,
    /// The real canonical pending catalog requires its protected Host17 exchange.
    PublicationPending,
}

impl StartHostCatalogPublicationOriginalV2 {
    pub(crate) fn prepare_maintenance_pending_once_v2(
        &mut self,
        controller: &mut Journal,
        receiving: &mut CatalogMaintenanceSourceReceivingV2<'_>,
        storage: DurableStorageResourceInventorySnapshotV1,
        network: DurableNetworkResourceInventorySnapshotV1,
        destinations: DurableDestinationSlotInventorySnapshotV1,
        prior_mount: Option<[u8; 32]>,
    ) -> Result<CatalogMaintenancePublicationStatusV2, StartHostCatalogPublicationClosedV2> {
        if self.entry.is_some() || self.maintenance_identity.is_some() || self.first.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.maintenance_identity = Some(receiving.enter_once_v2(controller));
        let Some(Ok(identity)) = self.maintenance_identity.as_ref() else {
            self.original_selected = receiving.original_failure_selected_v2();
            self.first = Some(First::MaintenanceEntry);
            return Err(CLOSED);
        };
        self.maintenance_mode = Some(MaintenanceSourceModeV2::New);
        self.geometry = Some((|| {
            let inline = size_of::<Self>()
                .checked_mul(2)
                .and_then(|bytes| {
                    bytes.checked_add(
                        size_of::<CatalogMaintenanceSourceReceivingV2<'_>>().checked_mul(2)?,
                    )
                })
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let history =
                super::super::source_receiving::canonical_source_history_receiving_demand_v2(
                    controller, inline,
                )?;
            let projection = super::super::source_receiving::maintenance_no_slots_projection_receiving_demand_v2(
                controller, storage.inventory(), network.inventory(), destinations.inventory())?;
            let retention = receiving.stopped_retention_receiving_demand_v1(controller)?;
            history
                .checked_add(projection)?
                .checked_add(retention)
                .map_err(Into::into)
        })());
        let Some(Ok(demand)) = self.geometry.as_ref() else {
            self.first = Some(First::Geometry);
            return Err(CLOSED);
        };
        self.funding = Some(receiving.admit_canonical_source_v2(controller, identity, *demand));
        if !matches!(self.funding, Some(Ok(()))) {
            self.original_selected = receiving.original_failure_selected_v2();
            self.first = Some(First::Funding);
            return Err(CLOSED);
        }
        self.history = Some(CatalogHistory::load(controller));
        let Some(Ok(history)) = self.history.as_ref() else {
            self.first = Some(First::History);
            return Err(CLOSED);
        };
        self.maintenance_mode = Some(if history.pending.is_some() {
            MaintenanceSourceModeV2::Resume
        } else {
            MaintenanceSourceModeV2::New
        });
        // The history fee includes both the retained source decoder and this
        // same canonical projection decoder's construction plane.
        self.maintenance_projection = Some((|| {
            let projection_history = CatalogHistory::load(controller)?;
            let retention = match receiving.stopped_retention_data_v1(controller) {
                Ok(retention) => retention,
                Err(_) => {
                    self.original_selected = receiving.original_failure_selected_v2();
                    return Err(HostCatalogReconciliationError::InventoryConflict);
                }
            };
            if let Some((retained, start, completed)) = retention {
                return super::super::retained_population::prepare_stopped_retention_model_data_v1(
                    controller,
                    storage,
                    network,
                    destinations,
                    projection_history,
                    retained,
                    start,
                    &completed,
                );
            }
            prepare_projection_model_with_history_v2(
                controller,
                storage,
                network,
                CatalogMountInputV2::NoSlots16,
                destinations,
                projection_history,
                prior_mount,
            )
        })());
        let Some(Ok(projection)) = self.maintenance_projection.as_ref() else {
            self.first = Some(First::MaintenanceProjection);
            return Err(CLOSED);
        };
        if matches!(projection, PreparedHostCatalogModelDataV2::Current(_)) {
            if let Some(Ok(PreparedHostCatalogModelDataV2::Current(current))) =
                self.maintenance_projection.take()
            {
                self.maintenance_current_row_digest = controller
                    .get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
                    .map(|bytes| Sha256::digest(bytes).into());
                if self.maintenance_current_row_digest.is_none() {
                    self.first = Some(First::MaintenanceProjection);
                    return Err(CLOSED);
                }
                self.maintenance_current_catalog = Some(current);
                return Ok(CatalogMaintenancePublicationStatusV2::Unchanged);
            }
            self.first = Some(First::MaintenanceProjection);
            return Err(CLOSED);
        }
        self.maintenance_extent = Some(match projection {
            PreparedHostCatalogModelDataV2::Pending { catalog, .. } => {
                catalog.canonical_encoded_bytes_data_v2()
            }
            PreparedHostCatalogModelDataV2::Current(_) => return Err(CLOSED),
        });
        let Some(Ok(bytes)) = self.maintenance_extent.as_ref() else {
            self.first = Some(First::MaintenanceExtent);
            return Err(CLOSED);
        };
        self.maintenance_output_geometry = Some(
            super::super::source_receiving::canonical_source_output_receiving_demand_v2(*bytes),
        );
        let Some(Ok(output)) = self.maintenance_output_geometry.as_ref() else {
            self.first = Some(First::MaintenanceOutputGeometry);
            return Err(CLOSED);
        };
        self.maintenance_output_funding =
            Some(receiving.admit_canonical_source_v2(controller, identity, *output));
        if !matches!(self.maintenance_output_funding, Some(Ok(()))) {
            self.original_selected = receiving.original_failure_selected_v2();
            self.first = Some(First::MaintenanceOutputFunding);
            return Err(CLOSED);
        }
        if matches!(self.maintenance_mode, Some(MaintenanceSourceModeV2::Resume)) {
            self.pending = Some(
                self.history
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .and_then(|history| history.pending.as_ref())
                    .cloned()
                    .ok_or(HostCatalogReconciliationError::CorruptState),
            );
            self.transaction = Some(positive(&self.pending).and_then(CatalogRecord::transaction));
            if !matches!(self.transaction, Some(Ok(_))) {
                self.first = Some(First::Transaction);
                return Err(CLOSED);
            }
            // There is no invented successful pending commit. The actual C
            // row is rechecked, and confirmation uses its distinct append slot.
            self.readback = Some((|| {
                let actual = CatalogHistory::load(controller)?;
                if actual.pending.as_ref() != Some(positive(&self.pending)?) {
                    return Err(HostCatalogReconciliationError::InventoryConflict);
                }
                Ok(actual)
            })());
            if !matches!(self.readback, Some(Ok(_))) {
                self.first = Some(First::Readback);
                return Err(CLOSED);
            }
            self.seal_canonical_pending_v2()?;
            return Ok(CatalogMaintenancePublicationStatusV2::PublicationPending);
        }
        self.pending = Some(match self.maintenance_projection.take() {
            Some(Ok(PreparedHostCatalogModelDataV2::Pending {
                mount_source,
                controller_state,
                inventory_digests,
                prior,
                catalog,
            })) => CatalogRecord::pending_with_mount_source_v2(
                controller_state,
                inventory_digests,
                prior.as_ref(),
                catalog,
                mount_source,
            ),
            _ => Err(HostCatalogReconciliationError::CorruptState),
        });
        if !matches!(self.pending, Some(Ok(_))) {
            self.first = Some(First::Pending);
            return Err(CLOSED);
        }
        self.commit_and_seal_pending_v2(controller, |controller, transaction, recipe| {
            let returned = receiving.commit_catalog_recipe_v2(controller, transaction, recipe);
            (returned, receiving.original_failure_selected_v2())
        })?;
        Ok(CatalogMaintenancePublicationStatusV2::PublicationPending)
    }

    pub(crate) fn require_same_maintenance_source_v2(
        &self,
        receiving: &mut CatalogMaintenanceSourceReceivingV2<'_>,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let identity = self
            .maintenance_identity
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        receiving.require_current_v2(controller, identity)?;
        if self.first.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.maintenance_current_catalog.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if !matches!(self.maintenance_output_funding, Some(Ok(())))
            || !matches!(self.seal, Some(Ok(())))
            || (matches!(self.maintenance_mode, Some(MaintenanceSourceModeV2::New))
                && !matches!(self.commit, Some(Ok(_))))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let transaction = self
            .transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let [record] = transaction.records() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if record.namespace() != RecordNamespace::HostCatalogReconciliation
            || record.key() != PENDING_KEY
            || controller.get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
                != record.value()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl StartHostCatalogPublicationOriginalV2 {
    pub(crate) fn maintenance_identity_data_v2(&self)
    -> Result<&aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceIdentityV2, ResourceReservationErrorV1>{
        if self.first.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.seal, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.maintenance_identity
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl StartHostCatalogPublicationOriginalV2 {
    pub(crate) fn confirm_maintenance_once_v2(
        &mut self,
        controller: &mut Journal,
        receiving: &mut CatalogMaintenanceSourceReceivingV2<'_>,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), StartHostCatalogPublicationClosedV2> {
        if self.first.is_some() || self.confirmation_entry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.confirmation_entry =
            Some(receiving.require_terminal_for_confirmation_v2(controller, self, outcome));
        if !matches!(self.confirmation_entry, Some(Ok(()))) {
            self.original_selected = receiving.original_failure_selected_v2();
            self.first = Some(First::ConfirmationEntry);
            return Err(CLOSED);
        }
        self.confirm_canonical_pending_v2(controller, outcome, |controller, transaction, recipe| {
            let returned = receiving.commit_catalog_recipe_v2(controller, transaction, recipe);
            (returned, receiving.original_failure_selected_v2())
        })
    }
}

impl StartHostCatalogPublicationOriginalV2 {
    pub(crate) fn require_completed_maintenance_source_data_v2(
        &self,
        native: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let identity = self
            .maintenance_identity
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.first.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !native.matches_identity_data_v2(identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.maintenance_current_catalog.is_some() {
            let actual = controller
                .get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
                .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)));
            if self.maintenance_current_row_digest.is_none()
                || actual != self.maintenance_current_row_digest
                || controller
                    .get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
                    .is_some()
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        } else {
            self.require_confirmed_native_source_v2(controller)
        }
    }
}

impl StartHostCatalogPublicationOriginalV2 {
    /// Borrows only this actual canonical source's completed catalog coordinates.
    ///
    /// This historical DATA getter supplies no native disposal, cold result or authority.
    #[doc(hidden)]
    #[must_use]
    pub fn completed_maintenance_catalog_status_data_v2(
        &self,
    ) -> Option<(u64, aos_sandbox_core::ObjectDigest)> {
        if self.first.is_some() {
            return None;
        }
        if let Some(current) = self.maintenance_current_catalog.as_ref() {
            return Some((current.generation(), current.catalog_digest()));
        }
        if !matches!(self.confirmation_commit, Some(Ok(_))) {
            return None;
        }
        let current = self
            .confirmation_readback
            .as_ref()?
            .as_ref()
            .ok()?
            .current
            .as_ref()?;
        Some((
            current.catalog.generation(),
            aos_sandbox_core::ObjectDigest::from_bytes(current.catalog_digest),
        ))
    }
}
