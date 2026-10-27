//! Preserves sole-decoded resource models after genuine SDK native disposal.
//!
//! Only the actual completed SDK path constructs this owner, after exact Root
//! packet/native comparison. Model bytes move from their original captures;
//! no parser, Session, currentness or resource authority is reconstructed.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::ResourceDimension as D;
use aos_sandbox_protocol::{ProtocolValidationError, ValidatedDestinationSlotInventory,
    ValidatedNetworkInventory, mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1};
use aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2;

use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::CapturedBrokerMethodModelDataV2 as CapturedModel;

enum Models {
    Network(Option<CapturedModel<ValidatedNetworkInventory>>),
    Storage(Option<CapturedModel<(ValidatedStorageInventory, InventoryStorageResourcesResponse)>>),
    Mount {
        namespace: Option<CapturedModel<ValidatedAttachmentAnchorResourceV1>>,
        inventory: Option<CapturedModel<ValidatedDestinationSlotInventory>>,
    },
}

/// Retains actual completed resource models through the later Host comparison.
///
/// Fields and issuer are private. Borrowing requires the same intrinsic Root
/// completion and a genuine NEW current Host loan after that role's SDK disposal.
#[doc(hidden)]
pub struct StartResourceCompletedModelsOriginalV2 {
    models: Models,
    proof: Result<[u8; 32], aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    geometry: Option<Result<usize, ProtocolValidationError>>,
    closed: Option<ProtocolValidationError>,
}

impl StartResourceCompletedModelsOriginalV2 {
    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.proof.as_ref().err().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn require_v2(&self, completed: &RootStartResourceCompletedOriginalV2,
        loan: &aos_sandbox_controller_domain::OriginalStartHostRootLoanV1<'_, '_>, controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.failure_v2().is_some()
            || !matches!((self.proof.as_ref(), completed.completed_model_association_v2(loan, controller)),
                (Ok(retained), Ok(digest)) if digest == *retained) {
            return Err(OutputPreparationClosedV1);
        }
        Ok(())
    }

    /// Measures the retained model residue without returning capacity or traffic.
    #[must_use]
    pub fn resident_memory_bytes_data_v2(&self) -> Option<usize> {
        if self.failure_v2().is_some() { return None; }
        self.geometry.as_ref()?.as_ref().ok().copied()
    }

    /// Borrows the actual Network19 model after its native/SDK disposal.
    ///
    /// # Errors
    /// Refuses another role, intrinsic completion, failed payload or current loan.
    pub fn network_v2<'held>(&'held self, completed: &RootStartResourceCompletedOriginalV2,
        loan: &aos_sandbox_controller_domain::OriginalStartHostRootLoanV1<'_, '_>, controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<&'held CapturedModel<ValidatedNetworkInventory>, OutputPreparationClosedV1> {
        self.require_v2(completed, loan, controller)?;
        match &self.models {
            Models::Network(Some(value)) => Ok(value),
            _ => Err(OutputPreparationClosedV1),
        }
    }

    /// Borrows the actual Storage18 model and the same decoder's wire message.
    ///
    /// # Errors
    /// Refuses another role, completion, missing payload or changed current loan.
    pub fn storage_v2<'held>(&'held self, completed: &RootStartResourceCompletedOriginalV2,
        loan: &aos_sandbox_controller_domain::OriginalStartHostRootLoanV1<'_, '_>, controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<&'held CapturedModel<(ValidatedStorageInventory, InventoryStorageResourcesResponse)>, OutputPreparationClosedV1> {
        self.require_v2(completed, loan, controller)?;
        match &self.models {
            Models::Storage(Some(value)) => Ok(value),
            _ => Err(OutputPreparationClosedV1),
        }
    }

    /// Borrows the actual Mount62 namespace and complete signed Mount16 model.
    ///
    /// # Errors
    /// Refuses another role, incomplete payload, foreign Root or current loan.
    pub fn mount_v2<'held>(&'held self, completed: &RootStartResourceCompletedOriginalV2,
        loan: &aos_sandbox_controller_domain::OriginalStartHostRootLoanV1<'_, '_>, controller: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(&'held CapturedModel<ValidatedAttachmentAnchorResourceV1>, &'held CapturedModel<ValidatedDestinationSlotInventory>),
        OutputPreparationClosedV1> {
        self.require_v2(completed, loan, controller)?;
        match &self.models {
            Models::Mount { namespace: Some(namespace), inventory: Some(inventory) } => Ok((namespace, inventory)),
            _ => Err(OutputPreparationClosedV1),
        }
    }
}

impl StartResourceProvisioningSessionIoOriginalV4 {
    pub(crate) fn retain_completed_models_once_v2(&mut self,
        completed: &RootStartResourceCompletedOriginalV2,
    ) -> Result<usize, OutputPreparationClosedV1> {
        if let Some(retained) = self.completed_models.as_mut() {
            retained.closed.get_or_insert(ProtocolValidationError::InvalidField("repeated completed model retention"));
            return Err(OutputPreparationClosedV1);
        }
        if self.inner.failure().is_some() { return Err(OutputPreparationClosedV1); }
        let proof = completed.comparison_data_v2();
        let (models, method, complete) = match self.inner.inventory.kind {
            ProvisioningKindV4::Network => (Models::Network(None),
                BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
                self.completed_inventory_model_v4().is_some()),
            ProvisioningKindV4::StartStorage => (Models::Storage(None),
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
                self.completed_storage_inventory_model_v2().is_some()),
            ProvisioningKindV4::Mount => (Models::Mount { namespace: None, inventory: None },
                BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
                self.completed_mount_namespace_result_v2().is_some()
                    && self.completed_mount_inventory_model_v2().is_some()),
            ProvisioningKindV4::Storage | ProvisioningKindV4::Host
                | ProvisioningKindV4::HostCatalog | ProvisioningKindV4::DeletePreparation
                | ProvisioningKindV4::MaintenanceCatalog | ProvisioningKindV4::MaintenanceStorage | ProvisioningKindV4::DeleteApply | ProvisioningKindV4::DeleteNetwork | ProvisioningKindV4::DeleteMount | ProvisioningKindV4::ExecutionAvailability | ProvisioningKindV4::ExecutionNoApply =>
                return Err(OutputPreparationClosedV1),
        };
        // Initialize the resident cause/model destinations before fallible
        // hashing or geometry. No failed Result is replaced by a marker.
        self.completed_models = Some(StartResourceCompletedModelsOriginalV2 {
            models, proof: proof.digest_v2(), geometry: None, closed: None,
        });
        let retained = self.completed_models.as_mut().ok_or(OutputPreparationClosedV1)?;
        if retained.proof.is_err() { return Err(OutputPreparationClosedV1); }
        retained.geometry = Some((|| {
            let invalid = || ProtocolValidationError::InvalidField("completed Start model geometry");
            let dynamic = AuthenticatedBrokerMethodOutcomeCaptureV1::
                controller_inventory_dynamic_receiving_demand_v1(method, proof.inventory_outcome.len())
                .ok_or_else(invalid)?;
            let namespace_bytes = if matches!(self.inner.inventory.kind, ProvisioningKindV4::Mount) {
                aos_sandbox_protocol::mount_attachment_anchor::attachment_anchor_resource_decoding_memory_v4(
                    proof.resource_outcome.len())?
            } else { 0 };
            usize::try_from(dynamic.get(D::MemoryBytes)).ok()
                .and_then(|bytes| bytes.checked_add(namespace_bytes))
                .and_then(|bytes| bytes.checked_add(size_of::<StartResourceCompletedModelsOriginalV2>().checked_mul(2)?))
                .ok_or_else(invalid)
        })());
        let memory_bytes = retained.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(OutputPreparationClosedV1)?;
        if !complete {
            retained.closed = Some(ProtocolValidationError::InvalidField("incomplete Start resource models"));
            return Err(OutputPreparationClosedV1);
        }
        // Both models and fixed payload were already paid in the actual full
        // flight. Move into this resident destination before any later refusal.
        let retained = self.completed_models.as_mut().ok_or(OutputPreparationClosedV1)?;
        let complete = match &mut retained.models {
            Models::Network(value) => {
                *value = self.inner.inventory.outcome.as_mut()
                    .and_then(|capture| capture.take_retained_network_inventory_data_v2());
                value.is_some()
            }
            Models::Storage(value) => {
                *value = self.inner.inventory.outcome.as_mut()
                    .and_then(|capture| capture.take_retained_storage_inventory_data_v2());
                value.is_some()
            }
            Models::Mount { namespace, inventory } => {
                *namespace = self.inner.apply.outcome.as_mut()
                    .and_then(|capture| capture.take_retained_mount_namespace_data_v2());
                *inventory = self.inner.inventory.outcome.as_mut()
                    .and_then(|capture| capture.take_retained_mount_inventory_data_v2());
                namespace.is_some() && inventory.is_some()
            }
        };
        if !complete {
            retained.closed = Some(ProtocolValidationError::InvalidField("completed Start resource model custody"));
            return Err(OutputPreparationClosedV1);
        }
        Ok(memory_bytes)
    }

    pub(crate) fn retire_completed_flights_v2(&mut self) {
        // Passive model residue survives; only actual completed native flights
        // leave this owner. The Domain token publishes the new resident sum.
        let kind = self.inner.inventory.kind;
        self.inner = StorageProvisioningSessionIoOriginalV1::new_kind_v4(kind);
    }

    /// Borrows the private-issued retained payload without constructing proof.
    #[must_use]
    pub fn completed_models_v2(&self) -> Option<&StartResourceCompletedModelsOriginalV2> {
        self.completed_models.as_ref().filter(|value| value.failure_v2().is_none())
    }
}
