//! Joins only genuine Create, Start resource and closed Delete IO borrowers.
//!
//! Every closed variant keeps its original C/Bank/profile/Source/Root predicates.
//! This private adapter shares the finite native stages and cost geometry; it
//! cannot construct a borrower, adopt a Session or lend an arbitrary payer.

use super::*;
use crate::{
    PreparedStartResourceRequestOriginalV2, StartResourceProvisioningIoLoanV2,
    StartHostCatalogIoLoanV2,
    StartResourceSessionCurrentnessErrorV4,
};
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;

#[derive(Debug, thiserror::Error)]
pub(in crate::controller_resource_reservation) enum IoContractErrorV2 {
    #[error(transparent)]
    Create(#[from] crate::CreateProvisioningStorageIoErrorV1),
    #[error(transparent)]
    Start(#[from] ResourceReservationErrorV1),
}

#[derive(Debug, thiserror::Error)]
pub(in crate::controller_resource_reservation) enum IoSessionAssociationErrorV2 {
    #[error(transparent)]
    Create(#[from] ClientSessionAssociationErrorV1),
    #[error(transparent)]
    Start(#[from] StartResourceSessionCurrentnessErrorV4),
    #[error(transparent)]
    StartJournal(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Maintenance(#[from] crate::ControllerCatalogMaintenanceSessionCurrentnessErrorV2),
    #[error(transparent)]
    Delete(ResourceReservationErrorV1),
    #[error(transparent)]
    ExecutionAvailability(#[from] crate::controller_execution_operation::ControllerExecutionAvailabilitySessionCurrentnessErrorV2),
}

pub(in crate::controller_resource_reservation) enum NativeSessionIoMemberV2<'io, 'scope, 'source, 'original> {
    CreateStorage(&'io mut CreateProvisioningStorageIoLoanV1<'scope>),
    StartResource(&'io mut StartResourceProvisioningIoLoanV2<'scope>),
    HostCatalog(&'io mut StartHostCatalogIoLoanV2<'scope>),
    MaintenanceCatalog(&'io mut crate::ControllerCatalogMaintenanceIoLoanV2<'scope>),
    MaintenanceStorage(&'io mut crate::ControllerMaintenanceStorageIoLoanV3<'scope>),
    DeletePreparation(&'io mut crate::OriginalDeleteStoragePreparationLoanV3<'scope>),
    ExecutionAvailability(&'io mut crate::controller_execution_operation::ControllerExecutionAvailabilityClientLoanV2<'scope>),
    ExecutionNoApply(&'io mut crate::controller_execution_operation::ControllerExecutionNoApplyClientLoanV2<'scope, 'source, 'original>),
    DeleteApply(&'io mut crate::OriginalDeleteStorageApplyLoanV3<'scope>),
    DeleteNetwork(&'io mut crate::OriginalDeleteNetworkApplyLoanV4<'scope>),
    DeleteMount(&'io mut crate::OriginalDeleteMountReapLoanV4<'scope>),
}

impl<'io, 'scope, 'source, 'original> NativeSessionIoMemberV2<'io, 'scope, 'source, 'original> {
    pub(in crate::controller_resource_reservation) fn pure_model_demand_v2(&self, demand: ResourceVector) -> ResourceVector {
        match self {
            Self::CreateStorage(_) | Self::DeletePreparation(_) | Self::DeleteApply(_) => demand,
            Self::StartResource(_) | Self::HostCatalog(_) | Self::MaintenanceCatalog(_) | Self::MaintenanceStorage(_) | Self::ExecutionAvailability(_) | Self::ExecutionNoApply(_) | Self::DeleteNetwork(_) | Self::DeleteMount(_) => network_pure_model_demand_v2(demand),
        }
    }

    pub(in crate::controller_resource_reservation) fn stages_v2(&mut self) -> &mut StorageIoStagesV1 {
        match self {
            Self::CreateStorage(loan) => &mut loan.original_and_controller_v1().0.storage_io,
            Self::StartResource(loan) => loan.io_stages_v2(),
            Self::HostCatalog(loan) => loan.io_stages_v2(),
            Self::MaintenanceCatalog(loan) => loan.io_stages_v2(),
            Self::MaintenanceStorage(loan) => loan.io_stages_v2(),
            Self::ExecutionAvailability(loan) => loan.availability_io_stages_v2(),
            Self::ExecutionNoApply(loan) => loan.no_apply_io_stages_v2(),
            Self::DeletePreparation(loan) => &mut loan.io_original_v3().stages,
            Self::DeleteApply(loan) => &mut loan.io_original_v3().stages,
            Self::DeleteNetwork(loan) => &mut loan.io_original_v3().stages,
            Self::DeleteMount(loan) => &mut loan.io_original_v3().stages,
        }
    }

    pub(in crate::controller_resource_reservation) fn into_stages_v2(self) -> &'io mut StorageIoStagesV1 {
        match self {
            Self::CreateStorage(loan) => &mut loan.original_and_controller_v1().0.storage_io,
            Self::StartResource(loan) => loan.io_stages_v2(),
            Self::HostCatalog(loan) => loan.io_stages_v2(),
            Self::MaintenanceCatalog(loan) => loan.io_stages_v2(),
            Self::MaintenanceStorage(loan) => loan.io_stages_v2(),
            Self::ExecutionAvailability(loan) => loan.availability_io_stages_v2(),
            Self::ExecutionNoApply(loan) => loan.no_apply_io_stages_v2(),
            Self::DeletePreparation(loan) => &mut loan.io_original_v3().stages,
            Self::DeleteApply(loan) => &mut loan.io_original_v3().stages,
            Self::DeleteNetwork(loan) => &mut loan.io_original_v3().stages,
            Self::DeleteMount(loan) => &mut loan.io_original_v3().stages,
        }
    }

    pub(in crate::controller_resource_reservation) fn native_turn_v2(&mut self) -> u64 {
        match self {
            Self::CreateStorage(loan) => loan.original_and_controller_v1().0.native_turn,
            Self::StartResource(loan) => loan.native_turn_data_v2(),
            Self::HostCatalog(loan) => loan.native_turn_data_v2(),
            Self::MaintenanceCatalog(loan) => loan.native_turn_data_v2(),
            Self::MaintenanceStorage(_) => 0,
            Self::ExecutionAvailability(_) => 0,
            Self::ExecutionNoApply(_) => 0,
            Self::DeletePreparation(loan) => loan.native_turn_data_v3(),
            Self::DeleteApply(loan) => loan.native_turn_data_v3(),
            Self::DeleteNetwork(loan) => loan.native_turn_data_v3(),
            Self::DeleteMount(loan) => loan.native_turn_data_v3(),
        }
    }

    pub(in crate::controller_resource_reservation) fn require_current_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::CreateStorage(loan) => {
                let (original, controller) = loan.original_and_controller_v1();
                original.require_current_v1(controller)
            }
            Self::StartResource(loan) => loan.require_current_v2().map(|_| ()),
            Self::HostCatalog(loan) => loan.require_current_native_v2(),
            Self::MaintenanceCatalog(loan) => loan.require_current_native_v2(),
            Self::MaintenanceStorage(loan) => loan.require_current_native_v2(),
            Self::ExecutionAvailability(loan) => loan.require_transport_current_v2(),
            Self::ExecutionNoApply(loan) => loan.require_transport_current_v2(),
            Self::DeletePreparation(loan) => loan.require_current_v3(),
            Self::DeleteApply(loan) => loan.require_current_v3(),
            Self::DeleteNetwork(loan) => loan.require_current_v3(),
            Self::DeleteMount(loan) => loan.require_current_v3(),
        }
    }

    pub(in crate::controller_resource_reservation) fn complete_base_v2(
        &mut self,
        incoming: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        match self {
            Self::CreateStorage(loan) => loan.complete_for_storage_v1(incoming),
            Self::StartResource(loan) => loan.complete_base_native_v2(incoming),
            Self::HostCatalog(loan) => loan.complete_base_native_v2(incoming),
            Self::MaintenanceCatalog(loan) => loan.complete_base_native_v2(incoming),
            Self::MaintenanceStorage(loan) => loan.complete_base_native_v2(incoming),
            Self::ExecutionAvailability(loan) => loan.complete_transport_base_v2(incoming),
            Self::ExecutionNoApply(loan) => loan.complete_transport_base_v2(incoming),
            Self::DeletePreparation(loan) => loan.complete_base_native_v3(incoming),
            Self::DeleteApply(loan) => loan.complete_base_native_v3(incoming),
            Self::DeleteNetwork(loan) => loan.complete_base_native_v3(incoming),
            Self::DeleteMount(loan) => loan.complete_base_native_v3(incoming),
        }
    }

    pub(in crate::controller_resource_reservation) fn require_complete_v2(
        &mut self,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::CreateStorage(loan) => {
                let (original, controller) = loan.original_and_controller_v1();
                original.require_complete_v1(controller, complete)
            }
            Self::StartResource(loan) => loan.require_prepared_complete_native_v2(complete),
            Self::HostCatalog(loan) => loan.require_prepared_complete_native_v2(complete),
            Self::MaintenanceCatalog(loan) => loan.require_prepared_complete_native_v2(complete),
            Self::MaintenanceStorage(loan) => loan.require_prepared_complete_native_v2(complete),
            Self::ExecutionAvailability(loan) => loan.require_transport_complete_v2(complete),
            Self::ExecutionNoApply(loan) => loan.require_transport_complete_v2(complete),
            Self::DeletePreparation(loan) => loan.require_prepared_complete_native_v3(complete),
            Self::DeleteApply(loan) => loan.require_prepared_complete_native_v3(complete),
            Self::DeleteNetwork(loan) => loan.require_prepared_complete_native_v3(complete),
            Self::DeleteMount(loan) => loan.require_prepared_complete_native_v3(complete),
        }
    }

    pub(in crate::controller_resource_reservation) fn require_session_v2(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), IoSessionAssociationErrorV2> {
        // No financial currentness guard may suppress this native observation.
        // Each variant uses its actual continuously held completed Session.
        match self {
            Self::CreateStorage(loan) => loan
                .original_and_controller_v1()
                .0
                .client_session
                .require_completed_provisioning_session_v1(journal, socket, transcript)
                .map_err(Into::into),
            Self::StartResource(loan) => loan
                .require_session_association_v2(journal, socket, transcript)
                .map_err(Into::into),
            Self::HostCatalog(loan) => loan
                .require_session_association_v2(journal, socket, transcript)
                .map_err(Into::into),
            Self::MaintenanceCatalog(loan) => loan.require_session_association_v2(journal, socket, transcript).map_err(Into::into),
            Self::MaintenanceStorage(loan) => loan.require_session_association_v2(journal, socket, transcript).map_err(Into::into),
            Self::ExecutionAvailability(loan) => loan.require_transport_session_v2(journal, socket, transcript).map_err(Into::into),
            Self::ExecutionNoApply(loan) => loan.require_transport_session_v2(journal, socket, transcript).map_err(Into::into),
            Self::DeletePreparation(loan) => loan.require_session_association_v3(journal, socket, transcript)
                .map_err(IoSessionAssociationErrorV2::Delete),
            Self::DeleteApply(loan) => loan.require_session_association_v3(journal, socket, transcript)
                .map_err(IoSessionAssociationErrorV2::Delete),
            Self::DeleteNetwork(loan) => loan.require_session_association_v3(journal, socket, transcript)
                .map_err(IoSessionAssociationErrorV2::Delete),
            Self::DeleteMount(loan) => loan.require_session_association_v3(journal, socket, transcript)
                .map_err(IoSessionAssociationErrorV2::Delete),
        }
    }

    pub(in crate::controller_resource_reservation) fn require_journal_v2(
        &mut self,
        journal: &Journal,
    ) -> Result<(), IoSessionAssociationErrorV2> {
        match self {
            Self::CreateStorage(loan) => loan
                .original_and_controller_v1()
                .0
                .client_session
                .require_completed_journal_v1(journal)
                .map_err(Into::into),
            Self::StartResource(loan) => {
                loan.require_session_journal_v2(journal).map_err(Into::into)
            }
            Self::HostCatalog(loan) => loan.require_session_journal_v2(journal).map_err(Into::into),
            Self::MaintenanceCatalog(loan) => loan.require_session_journal_v2(journal).map_err(Into::into),
            Self::MaintenanceStorage(loan) => loan.require_session_journal_v2(journal).map_err(Into::into),
            Self::ExecutionAvailability(loan) => loan.require_transport_journal_v2(journal).map_err(Into::into),
            Self::ExecutionNoApply(loan) => loan.require_transport_journal_v2(journal).map_err(Into::into),
            Self::DeletePreparation(loan) => loan.require_session_journal_v3(journal)
                .map_err(IoSessionAssociationErrorV2::Delete),
            Self::DeleteApply(loan) => loan.require_session_journal_v3(journal)
                .map_err(IoSessionAssociationErrorV2::Delete),
            Self::DeleteNetwork(loan) => loan.require_session_journal_v3(journal)
                .map_err(IoSessionAssociationErrorV2::Delete),
            Self::DeleteMount(loan) => loan.require_session_journal_v3(journal)
                .map_err(IoSessionAssociationErrorV2::Delete),
        }
    }

    pub(in crate::controller_resource_reservation) fn protocol_v2(&self) -> BrokerSessionProtocolV1 {
        match self {
            Self::CreateStorage(_) | Self::DeletePreparation(_) | Self::DeleteApply(_) => BrokerSessionProtocolV1::Storage,
            Self::DeleteNetwork(_) => BrokerSessionProtocolV1::Network,
            Self::DeleteMount(_) => BrokerSessionProtocolV1::Mount,
            Self::StartResource(loan) => loan.protocol_data_v2(),
            Self::HostCatalog(loan) => loan.protocol_data_v2(),
            Self::MaintenanceCatalog(_) => BrokerSessionProtocolV1::Host,
            Self::MaintenanceStorage(_) => BrokerSessionProtocolV1::Storage,
            Self::ExecutionAvailability(loan) => loan.availability_protocol_data_v2(),
            Self::ExecutionNoApply(_) => BrokerSessionProtocolV1::Host,
        }
    }

    pub(in crate::controller_resource_reservation) fn method_v2(&self, inventory: bool) -> BrokerMethod {
        match (self, inventory) {
            (Self::CreateStorage(_), false) => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            (Self::CreateStorage(_), true) => {
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            }
            (Self::StartResource(loan), false) => loan.method_data_v2(false),
            (Self::StartResource(loan), true) => loan.method_data_v2(true),
            (Self::HostCatalog(_), false) => BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
            (Self::HostCatalog(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::MaintenanceCatalog(_), false) => BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
            (Self::MaintenanceCatalog(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::MaintenanceStorage(_), false) => BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT,
            (Self::MaintenanceStorage(_), true) => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            (Self::ExecutionAvailability(loan), false) => loan.availability_method_data_v2(),
            (Self::ExecutionNoApply(loan), false) => loan.no_apply_method_data_v2(),
            (Self::ExecutionAvailability(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::ExecutionNoApply(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::DeletePreparation(_), false) => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
            (Self::DeletePreparation(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::DeleteApply(_), false) => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            (Self::DeleteApply(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::DeleteNetwork(_), false) => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            (Self::DeleteNetwork(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            (Self::DeleteMount(_), false) => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            (Self::DeleteMount(_), true) => BrokerMethod::BROKER_METHOD_UNSPECIFIED
        }
    }

    pub(in crate::controller_resource_reservation) fn request_additional_v2(
        &self,
        request_bytes: usize,
        inventory: bool,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if inventory {
            return Ok(ResourceVector::ZERO);
        }
        match self {
            Self::CreateStorage(_) | Self::DeleteApply(_) => aos_sandbox_protocol::authenticated_session::all_methods::request_capture::AuthenticatedBrokerMethodRequestCaptureV1::storage_apply_additional_receiving_demand_v1(request_bytes)
                .ok_or(ResourceReservationErrorV1::Conflict),
            Self::StartResource(loan) => loan.request_additional_receiving_demand_v2(request_bytes),
            Self::DeleteMount(_) => aos_sandbox_protocol::mount_attachment_anchor::
                attachment_anchor_request_decoding_demand_v4(request_bytes)
                .map(network_pure_model_demand_v2)
                .map_err(|_| ResourceReservationErrorV1::Conflict),
            Self::MaintenanceStorage(_) => crate::PreparedStartResourceRequestOriginalV2::storage_request_receiving_demand_v2(),
            // Host17's retained context contains only fixed header/length/hash
            // coordinates. Common request capture already prices that enum and
            // its complete actual packet; the catalog lives in the source FD.
            Self::HostCatalog(_) | Self::DeletePreparation(_) | Self::MaintenanceCatalog(_) | Self::ExecutionAvailability(_) | Self::ExecutionNoApply(_) | Self::DeleteNetwork(_) => Ok(ResourceVector::ZERO),
        }
    }

    pub(in crate::controller_resource_reservation) fn response_decode_v2(
        &self,
        packet_bytes: usize,
        inventory: bool,
    ) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
        use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1;
        if inventory && matches!(self, Self::CreateStorage(_)) {
            return crate::journal::broker_session_receiving::storage_inventory_client_response_decode_demand_v1(packet_bytes);
        }
        if inventory && self.protocol_v2() == BrokerSessionProtocolV1::Host {
            return AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
                BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME, packet_bytes)
                .ok_or(StorageSessionGeometryRefusalV1);
        }
        let common =
            AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(packet_bytes)
                .ok_or(StorageSessionGeometryRefusalV1)?;
        let common = self.pure_model_demand_v2(common);
        if inventory {
            let model = match self.protocol_v2() {
                BrokerSessionProtocolV1::Network => crate::journal::broker_session_receiving::
                    network_inventory_client_response_decode_demand_v2(packet_bytes)?,
                BrokerSessionProtocolV1::Storage => network_pure_model_demand_v2(
                    crate::journal::broker_session_receiving::storage_inventory_client_response_decode_demand_v1(packet_bytes)?),
                BrokerSessionProtocolV1::Mount => aos_sandbox_protocol::mount_destination_slot::
                    destination_slot_inventory_receiving_demand_v2(packet_bytes).ok_or(StorageSessionGeometryRefusalV1)?,
                _ => return Err(StorageSessionGeometryRefusalV1),
            };
            common.checked_add(model).map_err(|_| StorageSessionGeometryRefusalV1)
        } else if self.protocol_v2() == BrokerSessionProtocolV1::Mount {
            // The returned resource retains one descriptor media-type string;
            // two model/string planes cover validation and result construction.
            // The sole successful resource decoder enforces its 4096-byte row.
            let backing = packet_bytes.min(aos_sandbox_protocol::mount_attachment_anchor::
                MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1);
            let bytes = std::mem::size_of::<aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1>()
                .checked_add(backing).and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(StorageSessionGeometryRefusalV1)?;
            common.checked_add(ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
                .map_err(|_| StorageSessionGeometryRefusalV1)
        } else {
            Ok(common)
        }
    }
}

// These inherited suppliers describe parser/model/control backing, rather
// than an actual Network namespace. Keep their entire other-dimension demand.
// Genuine native/Journal residency and Inventory uniqueness rows are joined
// separately by their actual producers, never passed through this projection.
fn network_pure_model_demand_v2(demand: ResourceVector) -> ResourceVector {
    demand.with(aos_sandbox_core::ResourceDimension::MetadataEntries, 0)
}

impl StartResourceProvisioningIoLoanV2<'_> {
    /// Admits the actual signed Network63 request before preparation or IO.
    ///
    /// # Errors
    /// Retains changed prepared/Start/Root/Source association, native Session
    /// refusal and the same current C's complete receiving error.
    #[doc(hidden)]
    pub fn admit_resource_request_io_once_v2(
        &mut self,
        prepared: &PreparedStartResourceRequestOriginalV2,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_contract_once_v2(prepared, 0, Some(false))?;
        let cutoff = prepared
            .request_header_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?
            .deadline_boottime_nanoseconds;
        NativeSessionIoMemberV2::StartResource(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Admits fresh Inventory19 while keeping the actual Network63 stage resident.
    ///
    /// # Errors
    /// Refuses incomplete preparation, changed originals, reentry or the same
    /// current C's full simultaneous receiving requirement.
    #[doc(hidden)]
    pub fn admit_resource_inventory_io_once_v2(
        &mut self,
        prepared: &PreparedStartResourceRequestOriginalV2,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_resource_contract_once_v2(prepared, 0, Some(true))?;
        let cutoff = prepared
            .request_header_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?
            .deadline_boottime_nanoseconds;
        NativeSessionIoMemberV2::StartResource(self)
            .admit_io_v2(journal, socket, transcript, shape, true, cutoff)
    }

    /// Borrows the actual retained finite Network IO cause without new work.
    #[doc(hidden)]
    pub fn resource_io_failure_v2(&mut self) -> Option<&(dyn Error + 'static)> {
        self.io_stages_v2().failure()
    }

    pub(in crate::controller_resource_reservation) fn require_resource_contract_once_v2(
        &mut self,
        prepared: &PreparedStartResourceRequestOriginalV2,
        ordinal: usize,
        select: Option<bool>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.io_stages_v2().failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = self
            .require_prepared_v2(prepared)
            .map_err(IoContractErrorV2::Start);
        let stages = self.io_stages_v2();
        if let Some(inventory) = select {
            stages.active = Some(inventory);
        }
        let stage = stages.active_mut()?;
        let slot = stage
            .contracts
            .get_mut(ordinal)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if slot.is_some() {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *slot = Some(returned);
        if matches!(slot, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ResourceDimension as D;
    use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1;

    #[test]
    fn network_model_geometry_preserves_backing_and_real_inventory_index() {
        let legacy =
            AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(4096).unwrap();
        let common = network_pure_model_demand_v2(legacy);
        let inventory =
            crate::journal::broker_session_receiving::network_inventory_client_response_decode_demand_v2(4096).unwrap();
        let completed = common.checked_add(inventory).unwrap();
        let expected_other_dimensions = legacy.checked_add(inventory).unwrap();

        assert!(legacy.get(D::MetadataEntries) > 0);
        assert!(inventory.get(D::MetadataEntries) > 0);
        assert_eq!(
            completed.get(D::MetadataEntries),
            inventory.get(D::MetadataEntries),
        );
        for dimension in D::ALL {
            if dimension != D::MetadataEntries {
                assert_eq!(common.get(dimension), legacy.get(dimension));
                assert_eq!(completed.get(dimension), expected_other_dimensions.get(dimension));
            }
        }
    }
}

impl StartHostCatalogIoLoanV2<'_> {
    /// Admits the exact pending catalog flight before any Session IO or model growth.
    ///
    /// # Errors
    /// Retains changed private child/source/Root, reused phase, native Session
    /// refusal or the original full simultaneous receiving error.
    #[doc(hidden)]
    pub fn admit_catalog_io_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_catalog_contract_once_v2(source, 0, Some(false))?;
        let cutoff = self.cutoff_data_v2();
        NativeSessionIoMemberV2::HostCatalog(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)
    }

    /// Borrows the actual same-stage cost/native cause without new IO.
    #[must_use]
    #[doc(hidden)]
    pub fn catalog_io_failure_v2(&mut self) -> Option<&(dyn Error + 'static)> {
        self.io_stages_v2().failure()
    }

    pub(in crate::controller_resource_reservation) fn require_catalog_contract_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        ordinal: usize, select: Option<bool>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.io_stages_v2().failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = self.require_catalog_source_v2(source).map_err(IoContractErrorV2::Start);
        let stages = self.io_stages_v2();
        if let Some(inventory) = select {
            if inventory { return Err(ResourceReservationErrorV1::Conflict); }
            stages.active = Some(false);
        }
        let stage = stages.active_mut()?;
        let slot = stage.contracts.get_mut(ordinal).ok_or(ResourceReservationErrorV1::Conflict)?;
        if slot.is_some() {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *slot = Some(returned);
        if matches!(slot, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl crate::ControllerCatalogMaintenanceIoLoanV2<'_> {
    /// Admits the exact pending catalog flight before any Session IO or model growth.
    ///
    /// # Errors
    /// Retains changed private child/source/Root, reused phase, native Session
    /// refusal or the original full simultaneous receiving error.
    #[doc(hidden)]
    pub fn admit_catalog_io_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_catalog_contract_once_v2(source, 0, Some(false))?;
        let cutoff = self.cutoff_data_v2();
        NativeSessionIoMemberV2::MaintenanceCatalog(self)
            .admit_io_v2(journal, socket, transcript, shape, false, cutoff)?;
        self.prepare_nonce_once_v2()
    }

    /// Borrows the actual same-stage cost/native cause without new IO.
    #[must_use]
    #[doc(hidden)]
    pub fn catalog_io_failure_v2(&mut self) -> Option<&(dyn Error + 'static)> {
        self.io_stages_v2().failure()
    }

    pub(in crate::controller_resource_reservation) fn require_catalog_contract_once_v2(&mut self,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        ordinal: usize, select: Option<bool>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.io_stages_v2().failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = self.require_catalog_source_v2(source).map_err(IoContractErrorV2::Start);
        let stages = self.io_stages_v2();
        if let Some(inventory) = select {
            if inventory { return Err(ResourceReservationErrorV1::Conflict); }
            stages.active = Some(false);
        }
        let stage = stages.active_mut()?;
        let slot = stage.contracts.get_mut(ordinal).ok_or(ResourceReservationErrorV1::Conflict)?;
        if slot.is_some() {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *slot = Some(returned);
        if matches!(slot, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

impl crate::ControllerMaintenanceStorageIoLoanV3<'_> {
    /// Admits one actual signed31 or fresh18 stage on the same paid M.
    ///
    /// # Errors
    /// Retains changed Root/prepared/Session association, reentry, exact native
    /// receiving refusal, or the actual fresh18 entropy failure after payment.
    #[doc(hidden)]
    pub fn admit_storage_io_once_v3(
        &mut self,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v3(prepared, 0, Some(inventory))?;
        let cutoff = self.cutoff_data_v3();
        NativeSessionIoMemberV2::MaintenanceStorage(self)
            .admit_io_v2(journal, socket, transcript, shape, inventory, cutoff)?;
        if inventory {
            self.prepare_inventory_nonce_once_v3()?;
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation) fn require_storage_contract_once_v3(
        &mut self,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
        ordinal: usize,
        select: Option<bool>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.io_stages_v2().failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = self
            .require_prepared_v3(prepared)
            .map_err(IoContractErrorV2::Start);
        let stages = self.io_stages_v2();
        if let Some(inventory) = select {
            stages.active = Some(inventory);
        }
        let stage = stages.active_mut()?;
        let slot = stage
            .contracts
            .get_mut(ordinal)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if slot.is_some() {
            stage.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        *slot = Some(returned);
        if matches!(slot, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}
