//! Persists real maintenance query bodies through the same snapshot reducers.
//!
//! Native query/model affinity precedes output geometry and canonical model
//! growth. Each snapshot's private recipe reaches the existing eight-slot C
//! append engine. Ordinary library paths delegate the same snapshot reducer;
//! this selected path never falls back to ordinary `Journal::commit`.

use super::append_recipe::CatalogMaintenanceAppendRecipeV2;
use super::*;
use crate::RecordNamespace;
use crate::destination_slot_inventory::{
    DestinationSlotInventoryObservationFenceV1, DurableDestinationSlotInventorySnapshotV1,
};
use crate::resource_inventory::{
    DurableNetworkResourceInventorySnapshotV1, DurableStorageResourceInventorySnapshotV1,
    NetworkInventoryObservationFenceV1, StorageInventoryObservationFenceV1,
};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::{
    AuthenticatedBrokerMethodOutcomeCaptureV1, ControllerInventoryDecodedOriginalV2,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};

#[derive(Debug, thiserror::Error)]
enum SnapshotErrorV2 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Original(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Resource(#[from] crate::ResourceInventoryError),
    #[error(transparent)]
    Mount(#[from] crate::MountAttemptError),
}

enum SnapshotFenceV2 {
    Mount(DestinationSlotInventoryObservationFenceV1),
    Storage(StorageInventoryObservationFenceV1),
    Network(NetworkInventoryObservationFenceV1),
}

pub(super) enum SnapshotValueV2 {
    Mount(DurableDestinationSlotInventorySnapshotV1),
    Storage(DurableStorageResourceInventorySnapshotV1),
    Network(DurableNetworkResourceInventorySnapshotV1),
}

#[derive(Clone, Copy)]
enum SnapshotFirstV2 {
    HistoryGeometry,
    HistoryFunding,
    Fence,
    OutputGeometry,
    OutputFunding,
    Body,
    Reentry,
}

enum SnapshotRetainedV2 {
    Mount(
        crate::mount_inventory_snapshot::MountInventorySnapshotRetainedV2<
            crate::destination_slot_inventory::DestinationSlotInventoryKind,
        >,
    ),
    Resource(crate::resource_inventory::ResourceInventorySnapshotRetainedV2),
}

struct SnapshotOriginalV2 {
    retained: Option<SnapshotRetainedV2>,
    history_geometry: Option<Result<ResourceVector, JournalError>>,
    history_funding: Option<Result<(), ResourceReservationErrorV1>>,
    fence: Option<Result<SnapshotFenceV2, SnapshotErrorV2>>,
    output_geometry: Option<Result<ResourceVector, JournalError>>,
    output_funding: Option<Result<(), ResourceReservationErrorV1>>,
    result: Option<Result<SnapshotValueV2, SnapshotErrorV2>>,
    first: Option<SnapshotFirstV2>,
    reentry: Option<JournalError>,
}

impl SnapshotOriginalV2 {
    fn new() -> Self {
        Self {
            retained: None,
            history_geometry: None,
            history_funding: None,
            fence: None,
            output_geometry: None,
            output_funding: None,
            result: None,
            first: None,
            reentry: None,
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(
            slot: &Option<Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            SnapshotFirstV2::HistoryGeometry => cause(&self.history_geometry),
            SnapshotFirstV2::HistoryFunding => cause(&self.history_funding),
            SnapshotFirstV2::Fence => cause(&self.fence),
            SnapshotFirstV2::OutputGeometry => cause(&self.output_geometry),
            SnapshotFirstV2::OutputFunding => cause(&self.output_funding),
            SnapshotFirstV2::Body => cause(&self.result),
            SnapshotFirstV2::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

pub(super) struct CatalogMaintenanceSnapshotsOriginalV2 {
    slots: [SnapshotOriginalV2; 5],
}

impl CatalogMaintenanceSnapshotsOriginalV2 {
    pub(super) fn require_fresh_storage_snapshot_v3(&self) -> Result<(), ResourceReservationErrorV1> {
        let slot = &self.slots[4];
        if slot.first.is_some() || !matches!(slot.result, Some(Ok(SnapshotValueV2::Storage(_)))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| SnapshotOriginalV2::new()),
        }
    }
    pub(super) fn failure_v2(&self, index: usize) -> Option<&(dyn Error + 'static)> {
        self.slots.get(index)?.failure()
    }

    pub(super) fn storage_snapshot_data_v2(
        &self,
    ) -> Result<&DurableStorageResourceInventorySnapshotV1, ResourceReservationErrorV1> {
        let slot = &self.slots[if self.slots[4].history_geometry.is_some() { 4 } else { 2 }];
        if slot.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        match slot.result.as_ref() {
            Some(Ok(SnapshotValueV2::Storage(snapshot))) => Ok(snapshot),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    pub(super) fn prior_mount_record_digest_data_v2(&self) -> Option<[u8; 32]> {
        let slot = &self.slots[1];
        if slot.first.is_some() || !matches!(slot.result, Some(Ok(_))) {
            return None;
        }
        match slot.retained.as_ref()? {
            SnapshotRetainedV2::Mount(retained) => retained.prior_record_digest_data_v2(),
            SnapshotRetainedV2::Resource(_) => None,
        }
    }

    pub(super) fn take_catalog_inputs_once_v2(
        &mut self,
    ) -> Result<
        (
            DurableStorageResourceInventorySnapshotV1,
            DurableNetworkResourceInventorySnapshotV1,
            DurableDestinationSlotInventorySnapshotV1,
        ),
        ResourceReservationErrorV1,
    > {
        if !(1..4).all(|index| {
            self.slots[index].first.is_none() && matches!(self.slots[index].result, Some(Ok(_)))
        }) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let Some(Ok(SnapshotValueV2::Mount(mount))) = self.slots[1].result.take() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let storage_index = if self.slots[4].history_geometry.is_some() { 4 } else { 2 };
        if self.slots[storage_index].first.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let Some(Ok(SnapshotValueV2::Storage(storage))) = self.slots[storage_index].result.take() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let Some(Ok(SnapshotValueV2::Network(network))) = self.slots[3].result.take() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        Ok((storage, network, mount))
    }
}

fn recipe_v2(index: usize) -> Result<(RecordNamespace, BrokerMethod), JournalError> {
    match index {
        1 => Ok((
            RecordNamespace::DestinationSlotInventory,
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
        )),
        2 | 4 => Ok((
            RecordNamespace::StorageResourceInventory,
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        )),
        3 => Ok((
            RecordNamespace::NetworkResourceInventory,
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        )),
        _ => Err(JournalError::ProtectedBoundary),
    }
}

// The same format-owned schema recipe covers each reached canonical history
// decoder. Six source-censused copies cover candidate, transaction, retained
// prior history, readback, returned snapshot and construction backing together.
fn carrier_geometry_v2(index: usize) -> Result<(usize, usize), JournalError> {
    match index {
        1 => crate::destination_slot_inventory::canonical_snapshot_carrier_geometry_data_v2(),
        2 | 3 | 4 => crate::resource_inventory::canonical_snapshot_carrier_geometry_data_v2(),
        _ => None,
    }
    .ok_or(JournalError::JournalTooLarge)
}

fn dynamic_demand_v2(method: BrokerMethod, bytes: usize) -> Result<ResourceVector, JournalError> {
    let one = AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(method, bytes)
        .ok_or(JournalError::JournalTooLarge)?;
    let raw = bytes
        .checked_mul(6)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    one.checked_add(one)
        .and_then(|demand| demand.checked_add(one))
        .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, raw)))
        .map_err(JournalError::ReceivingAccounting)
}

impl ControllerCatalogMaintenanceLoanV2<'_, '_> {
    /// Captures the real post31 snapshot fence before entering the shared IO loan.
    ///
    /// # Errors
    /// Refuses a foreign Root-transferred request, reentry, currentness,
    /// canonical history, geometry or same-F prepayment failure.
    #[doc(hidden)]
    pub fn begin_refresh_storage_snapshot_once_v3(
        &mut self,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.owner
            .guest_root
            .root
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_transferred_request_v3(prepared)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.begin_snapshot_fence_once_v2(4)
    }

    /// Persists the same native-completed fresh18 through the sole canonical reducer.
    ///
    /// The initial snapshot stays resident and cannot replace a failed fresh
    /// result. Only the exact actual31/fresh18 protected terminal/native pair
    /// may reach the shared storage snapshot assembly and same-M append kernel.
    ///
    /// # Errors
    /// Retains changed outcome/native identity, missing pre-query fence,
    /// canonical physical continuity, complete payment or native append refusal.
    #[doc(hidden)]
    pub fn persist_refresh_storage_snapshot_once_v3(
        &mut self,
        resource: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        native: &[u8; 64],
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.owner
            .guest_root
            .storage_io
            .require_outcomes_v3(resource, inventory, native)?;
        self.persist_snapshot_from_native_once_v3(4, inventory)
    }

    pub(super) fn begin_snapshot_fence_once_v2(
        &mut self,
        index: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        if index == 0 {
            return Ok(());
        }
        self.require_current_v2()?;
        let (namespace, method) =
            recipe_v2(index).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let slot = &mut self.owner.snapshots.slots[index];
        if slot.history_geometry.is_some() || slot.first.is_some() {
            slot.reentry.get_or_insert(JournalError::ProtectedBoundary);
            slot.first.get_or_insert(SnapshotFirstV2::Reentry);
            self.owner.first.get_or_insert(First::Snapshot(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        slot.history_geometry = Some((|| {
            let (_, carriers) = carrier_geometry_v2(index)?;
            let carriers = u64::try_from(carriers).map_err(|_| JournalError::JournalTooLarge)?;
            let base = self
                .controller
                .create_storage_semantic_append_demand_v1()?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carriers))
                .map_err(JournalError::ReceivingAccounting)?;
            self.controller
                .records(namespace)
                .try_fold(base, |demand, (key, value)| {
                    let bytes = key
                        .len()
                        .checked_add(value.len())
                        .ok_or(JournalError::JournalTooLarge)?;
                    demand
                        .checked_add(dynamic_demand_v2(method, bytes)?)
                        .map_err(JournalError::ReceivingAccounting)
                })
        })());
        let demand = match slot.history_geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                slot.first = Some(SnapshotFirstV2::HistoryGeometry);
                self.owner.first.get_or_insert(First::Snapshot(index));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let funding = self.reserve_additional_v2(demand);
        let slot = &mut self.owner.snapshots.slots[index];
        slot.history_funding = Some(funding);
        if !matches!(slot.history_funding, Some(Ok(()))) {
            slot.first = Some(SnapshotFirstV2::HistoryFunding);
            self.owner.first.get_or_insert(First::Snapshot(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        slot.fence = Some(match index {
            1 => {
                crate::destination_slot_inventory::authenticated::begin_observation(self.controller)
                    .map(SnapshotFenceV2::Mount)
                    .map_err(Into::into)
            }
            2 | 4 => {
                crate::resource_inventory::authenticated::begin_storage_observation(self.controller)
                    .map(SnapshotFenceV2::Storage)
                    .map_err(Into::into)
            }
            3 => {
                crate::resource_inventory::authenticated::begin_network_observation(self.controller)
                    .map(SnapshotFenceV2::Network)
                    .map_err(Into::into)
            }
            _ => Err(JournalError::ProtectedBoundary.into()),
        });
        if !matches!(slot.fence, Some(Ok(_))) {
            slot.first = Some(SnapshotFirstV2::Fence);
            self.owner.first.get_or_insert(First::Snapshot(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }

    /// Persists one real completed query through its exact canonical snapshot engine.
    ///
    /// Host3 is retained only for the cold physical conjunction and has no
    /// snapshot append. Every other role requires its original pre-query fence,
    /// the same sole decoded model and actual completed native evidence first.
    ///
    /// # Errors
    /// Retains changed scope, model substitution, duplicate persistence,
    /// geometry/payment, canonical continuity, native append or readback failure.
    #[doc(hidden)]
    pub fn persist_inventory_snapshot_once_v2(
        &mut self,
        index: usize,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        decoded: &ControllerInventoryDecodedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.owner
            .inventory_evidence
            .require_model_v2(index, outcome, decoded)?;
        self.persist_snapshot_from_native_once_v3(index, outcome)
    }

    fn persist_snapshot_from_native_once_v3(
        &mut self,
        index: usize,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v2()?;
        if index == 0 {
            return Ok(());
        }
        let (_, method) = recipe_v2(index).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let slot = &mut self.owner.snapshots.slots[index];
        if slot.result.is_some() || slot.output_geometry.is_some() || slot.first.is_some() {
            slot.reentry.get_or_insert(JournalError::ProtectedBoundary);
            slot.first.get_or_insert(SnapshotFirstV2::Reentry);
            self.owner.first.get_or_insert(First::Snapshot(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        slot.output_geometry = Some((|| {
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
            else {
                return Err(JournalError::ProtectedBoundary);
            };
            let (prefix, _) = carrier_geometry_v2(index)?;
            let bytes = outcome
                .request()
                .exact_body()
                .len()
                .checked_add(exact_body.len())
                .and_then(|bytes| bytes.checked_add(prefix))
                .ok_or(JournalError::JournalTooLarge)?;
            let recipe_headers = std::mem::size_of::<
                crate::resource_inventory::ResourceInventoryCommitRecipeV2<'_>,
            >()
            .checked_add(std::mem::size_of::<
                crate::mount_inventory_snapshot::MountInventoryCommitRecipeV2<'_>,
            >())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
            dynamic_demand_v2(method, bytes)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, recipe_headers))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let demand = match slot.output_geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                slot.first = Some(SnapshotFirstV2::OutputGeometry);
                self.owner.first.get_or_insert(First::Snapshot(index));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let funding = self.reserve_additional_v2(demand);
        let slot = &mut self.owner.snapshots.slots[index];
        slot.output_funding = Some(funding);
        if !matches!(slot.output_funding, Some(Ok(()))) {
            slot.first = Some(SnapshotFirstV2::OutputFunding);
            self.owner.first.get_or_insert(First::Snapshot(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let fence = slot.fence.take();
        // Move only the short sink borrow outside `owner`: the actual append
        // callback needs the same owner mutably. It is restored on every result.
        let mut retained = match index {
            1 => SnapshotRetainedV2::Mount(
                crate::mount_inventory_snapshot::MountInventorySnapshotRetainedV2::new(),
            ),
            _ => SnapshotRetainedV2::Resource(
                crate::resource_inventory::ResourceInventorySnapshotRetainedV2::new(),
            ),
        };
        let result = match (fence, &mut retained) {
            (Some(Ok(SnapshotFenceV2::Mount(fence))), SnapshotRetainedV2::Mount(retained)) => {
                crate::destination_slot_inventory::authenticated::complete_observation_with_commit_v2(
                    self.controller, fence, outcome, retained, |controller, transaction, recipe| {
                        self.owner.commit_append_recipe_once_v2(controller, self.source, transaction,
                            CatalogMaintenanceAppendRecipeV2::DestinationSlotInventory(recipe)).map_err(Into::into)
                    }).map(SnapshotValueV2::Mount).map_err(Into::into)
            }
            (Some(Ok(SnapshotFenceV2::Storage(fence))), SnapshotRetainedV2::Resource(retained)) => {
                crate::resource_inventory::authenticated::complete_storage_observation_with_commit_v2(
                    self.controller, fence, outcome, retained, |controller, transaction, recipe| {
                        self.owner.commit_append_recipe_once_v2(controller, self.source, transaction,
                            CatalogMaintenanceAppendRecipeV2::ResourceInventory(recipe)).map_err(Into::into)
                    }).map(SnapshotValueV2::Storage).map_err(Into::into)
            }
            (Some(Ok(SnapshotFenceV2::Network(fence))), SnapshotRetainedV2::Resource(retained)) => {
                crate::resource_inventory::authenticated::complete_network_observation_with_commit_v2(
                    self.controller, fence, outcome, retained, |controller, transaction, recipe| {
                        self.owner.commit_append_recipe_once_v2(controller, self.source, transaction,
                            CatalogMaintenanceAppendRecipeV2::ResourceInventory(recipe)).map_err(Into::into)
                    }).map(SnapshotValueV2::Network).map_err(Into::into)
            }
            (Some(Err(cause)), _) => Err(cause),
            _ => Err(SnapshotErrorV2::Journal(JournalError::ProtectedBoundary)),
        };
        self.owner.snapshots.slots[index].retained = Some(retained);
        self.owner.snapshots.slots[index].result = Some(result);
        if !matches!(self.owner.snapshots.slots[index].result, Some(Ok(_))) {
            self.owner.snapshots.slots[index].first = Some(SnapshotFirstV2::Body);
            self.owner.first.get_or_insert(First::Snapshot(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.check_frontier_v2()?;
        Ok(())
    }
}
