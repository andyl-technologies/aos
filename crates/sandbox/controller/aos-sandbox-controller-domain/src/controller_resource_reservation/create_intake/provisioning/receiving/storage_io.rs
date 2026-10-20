//! Prices finite Create, Start resource and Delete26 IO on their original C owners.
//!
//! The private Core scope and genuine Start/Root issuer lend distinct borrowers.
//! A closed member adapter shares their native phase and receiving engine while
//! preserving each issuer's Bank, profile, Source and Session predicates. No
//! amount, transcript or completed DATA can construct either borrower.

mod turns;
pub(in crate::controller_resource_reservation) mod catalog_completion;
mod delete;
pub use delete::{DeleteStoragePreparationIoOriginalV3, DeleteStorageApplyIoOriginalV3, DeleteNetworkApplyIoOriginalV4, DeleteMountReapIoOriginalV4};
pub(in crate::controller_resource_reservation) mod member;
mod execution_availability;
mod execution_no_apply;
pub(crate) use execution_no_apply::ExecutionNoApplyIoOriginalV2;
pub(crate) use execution_availability::ExecutionAvailabilityIoOriginalV2;
use member::{IoContractErrorV2, IoSessionAssociationErrorV2, NativeSessionIoMemberV2};
mod workspace;
pub use workspace::StorageProvisioningWorkspaceOriginalV1;
pub use turns::StorageProvisioningIoDisposalV1;

use super::*;
use crate::{CreateProvisioningStorageIoLoanV1, PreparedAuthorityEffectV1};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_model::component_receiving::{operation_traffic_demand_v1, without_operation_traffic_v1};
use super::super::super::ready::client_session::ClientSessionAssociationErrorV1;
use crate::journal::{JournalError, ProtectedJournalPreopenReplayExtentV1};
use crate::journal::broker_session_receiving::{
    StorageSessionGeometryRefusalV1,
    storage_retained_current_replay_demand_v1,
    storage_create_prepare_client_request_demand_v1,
};

/// Describes the actual fixed Security representation before native or schema work.
///
/// This is representation DATA from the sole Security recipe. The actual loan
/// still checks its private Core contract, current C and completed native Session.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct StorageProvisioningSessionIoShapeDataV1 {
    /// Complete actual inline, raw-buffer and native-helper construction bytes.
    pub receiving_bytes: usize,
    /// Actual same-engine zero-rights receive native descriptor peak.
    pub receive_files: usize,
    /// Distinct actual retained endpoint/native post destinations, outside recvmsg.
    pub retained_endpoint_files: usize,
    /// Actual native namespace entries, excluding Rust controls and fields.
    pub namespace_entries: usize,
    /// Complete request packet ceiling derived from the existing format owner.
    pub request_bytes: usize,
    /// The same negotiated response bound enforced before the native receive.
    pub response_bytes: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("the original provisioning Session IO remains closed with its reached custody")]
struct StorageProvisioningIoClosedV1;

#[derive(Default)]
pub(in crate::controller_resource_reservation) struct StorageIoStagesV1 {
    apply: IoStageV1,
    inventory: IoStageV1,
    resident: ResourceVector,
    traffic: ResourceVector,
    traffic_turn: Option<u64>,
    active: Option<bool>,
    workspace_admission: Option<Result<(), ResourceReservationErrorV1>>,
    workspace_comparison: Option<Result<(), ResourceReservationErrorV1>>,
    workspace_association: Option<Result<(), ClientSessionAssociationErrorV1>>,
}

#[derive(Default)]
struct IoStageV1 {
    contracts: [Option<Result<(), IoContractErrorV2>>; 4],
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<(), IoSessionAssociationErrorV2>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    variable: Option<Result<(), ResourceReservationErrorV1>>,
    cutoff: u64,
    binding: [u8; 32],
    authenticated_request: Option<[u8; 32]>,
    request_binding: Option<Result<(), ResourceReservationErrorV1>>,
    native_journal: Option<Result<(), IoSessionAssociationErrorV2>>,
    native_key: Option<Vec<u8>>,
    native_row: aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryDecodeCaptureV1,
    native_history: aos_sandbox_broker_session_protocol::durable::history::BrokerSessionDurableHistoryDecodeCaptureV1,
    native_position: Option<Result<[u8; 32], ResourceReservationErrorV1>>,
    terminal_identity: Option<([u8; 32], [u8; 32])>,
    terminal_association: Option<Result<(), IoSessionAssociationErrorV2>>,
    terminal_names: crate::journal::ProtectedJournalCurrentnessOriginalsV1,
    terminal_witness: aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>,
    terminal_native: Option<Result<[u8; 64], JournalError>>,
    phase: IoPhaseV1,
    before: Option<Result<(), ResourceReservationErrorV1>>,
    before_association: Option<Result<(), IoSessionAssociationErrorV2>>,
    after_association: Option<Result<(), IoSessionAssociationErrorV2>>,
    pending_binding: Option<Result<(), aos_sandbox_linux::seqpacket::RecordBindingError>>,
    pending_native: Option<Result<u64, aos_sandbox_linux::Error>>,
    decode_geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    decode: Option<Result<(), ResourceReservationErrorV1>>,
    outcome_geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    outcome: Option<Result<(), ResourceReservationErrorV1>>,
    predecessor_metadata: Option<std::io::Result<std::fs::Metadata>>,
    predecessor_extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    predecessor_geometry: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    predecessor: Option<Result<(), ResourceReservationErrorV1>>,
    closed: bool,
    shape: Option<StorageProvisioningSessionIoShapeDataV1>,
}

impl IoStageV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.contracts.iter().find_map(|slot| slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.fixed.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.association.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.metadata.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.extent.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
             .or_else(|| self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.variable.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.request_binding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.before.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.before_association.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.after_association.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.pending_native.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.pending_binding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.decode_geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.decode.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.outcome_geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.outcome.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.predecessor_metadata.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.predecessor_extent.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.predecessor_geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.predecessor.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.native_journal.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.native_row.failure().map(|cause| cause as _))
            .or_else(|| self.native_history.failure().map(|cause| cause as _))
            .or_else(|| self.native_position.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.terminal_association.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.terminal_names.failure())
            .or_else(|| self.terminal_witness.failure().map(|cause| cause as _))
            .or_else(|| self.terminal_native.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.then_some(&StorageProvisioningIoClosedV1 as &(dyn Error + 'static)))
    }
}

impl StorageIoStagesV1 {
    pub(in crate::controller_resource_reservation) fn retained_demand_v1(&self, turn: u64) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let traffic = if self.traffic_turn == Some(turn) { self.traffic } else { ResourceVector::ZERO };
        self.resident.checked_add(traffic).map_err(Into::into)
    }

    pub(in crate::controller_resource_reservation) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.apply.failure().or_else(|| self.inventory.failure())
            .or_else(|| self.workspace_admission.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.workspace_comparison.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.workspace_association.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }
}

impl CreateProvisioningStorageIoLoanV1<'_> {
    /// Admits the actual Apply receiving representation before its first IO.
    ///
    /// # Errors
    /// Retains exact-contract, same-C, native Session association, held extent,
    /// arithmetic and full receiving refusal. No failed stage can reenter.
    #[doc(hidden)]
    pub fn admit_storage_apply_io_once_v1(&mut self,
        prepared: &PreparedAuthorityEffectV1,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v1(prepared, 0, Some(false))?;
        self.admit_storage_io_v1(journal, socket, transcript, shape, false, prepared.attempt().deadline_boottime_nanoseconds())
    }

    /// Admits the fresh Inventory stage while retaining the earlier Apply owner.
    ///
    /// No completed-data flag refunds Apply storage or native descriptors. Both
    /// stages' resident representation stays on C23 through the later Source and
    /// Root consumer, and same-turn spent traffic is added before this request.
    ///
    /// # Errors
    /// Refuses missing Apply entry, reentry, a different native Session or C23,
    /// or an unpayable complete receiving requirement.
    #[doc(hidden)]
    pub fn admit_storage_inventory_io_once_v1(&mut self,
        prepared: &PreparedAuthorityEffectV1,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_storage_contract_once_v1(prepared, 0, Some(true))?;
        self.admit_storage_io_v1(journal, socket, transcript, shape, true, prepared.attempt().deadline_boottime_nanoseconds())
    }

    /// Borrows the original finite-stage native cause without replacing custody.
    #[doc(hidden)]
    pub fn storage_io_failure_v1(&mut self) -> Option<&(dyn Error + 'static)> {
        self.original_and_controller_v1().0.storage_io.failure()
    }

    fn require_storage_contract_once_v1(&mut self, prepared: &PreparedAuthorityEffectV1,
        ordinal: usize, select: Option<bool>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.original_and_controller_v1().0.storage_io.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = self.require_prepared_v1(prepared).map_err(IoContractErrorV2::Create);
        let original = self.original_and_controller_v1().0;
        if let Some(inventory) = select { original.storage_io.active = Some(inventory); }
        let stage = original.storage_io.active_mut()?;
        let slot = stage.contracts.get_mut(ordinal).ok_or(ResourceReservationErrorV1::Conflict)?;
        if slot.is_some() { stage.closed = true; return Err(ResourceReservationErrorV1::Conflict); }
        *slot = Some(returned);
        if matches!(slot, Some(Ok(()))) { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn admit_storage_io_v1(&mut self,
        journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1, inventory: bool, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        NativeSessionIoMemberV2::CreateStorage(self)
            .admit_io_v2(journal, socket, transcript, shape, inventory, cutoff)
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum IoPhaseV1 {
    #[default]
    Fresh,
    Preparing,
    Prepared,
    Sending,
    Receiving,
    WaitingSend,
    WaitingReceive,
    Decode,
    Complete,
}

impl StorageIoStagesV1 {
    fn active_mut(&mut self) -> Result<&mut IoStageV1, ResourceReservationErrorV1> {
        match self.active {
            Some(false) => Ok(&mut self.apply),
            Some(true) => Ok(&mut self.inventory),
            None => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

impl StorageIoStagesV1 {
    fn retain_paid_v1(&mut self, turn: u64, incoming: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        let resident = self.resident.checked_add(without_operation_traffic_v1(incoming))?;
        let prior = if self.traffic_turn == Some(turn) { self.traffic } else { ResourceVector::ZERO };
        let traffic = prior.checked_add(operation_traffic_demand_v1(incoming))?;
        self.resident = resident;
        self.traffic = traffic;
        self.traffic_turn = Some(turn);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::ResourceDimension as D;

    #[test]
    fn io_residency_persists_and_same_turn_wire_accumulates() {
        let mut originals = StorageIoStagesV1::default();
        let apply = ResourceVector::ZERO.with(D::MemoryBytes, 31)
            .with(D::StorageBytes, 7).with(D::NetworkBytes, 41)
            .with(D::OutputBytes, 13).with(D::LogBytes, 59);
        let inventory = ResourceVector::ZERO.with(D::MemoryBytes, 17)
            .with(D::NetworkBytes, 23).with(D::OutputBytes, 11).with(D::LogBytes, 29);

        originals.retain_paid_v1(4, apply).unwrap();
        originals.retain_paid_v1(4, inventory).unwrap();

        assert_eq!(originals.retained_demand_v1(4).unwrap(), apply.checked_add(inventory).unwrap());
        assert_eq!(originals.retained_demand_v1(5).unwrap(),
            without_operation_traffic_v1(apply.checked_add(inventory).unwrap()));
        // A new-turn view does not mutate or refund the old spent-wire record;
        // the same lower C23 ledger also carries that prior traffic in its base.
        assert_eq!(originals.traffic_turn, Some(4));
        assert_eq!(originals.traffic, operation_traffic_demand_v1(apply.checked_add(inventory).unwrap()));
    }
}

impl StorageIoStagesV1 {
    pub(in crate::controller_resource_reservation) fn has_entered_v1(&self) -> bool {
        self.active.is_some() || self.apply.fixed.is_some() || self.inventory.fixed.is_some()
    }

    // The genuine Start loan uses this DATA discriminator to lend its own
    // already sealed content only for63. It neither constructs nor admits IO.
    pub(in crate::controller_resource_reservation) fn network_preparation_active_v2(&self)
        -> Result<bool, ResourceReservationErrorV1>
    {
        if self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        match self.active {
            Some(false) => Ok(true),
            Some(true) => Ok(false),
            None => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}

impl StorageProvisioningSessionIoShapeDataV1 {
    /// Describes the actual same-Session final association's result carriers.
    ///
    /// This is inert representation DATA. The genuine Core scope prepays it
    /// with the whole Security native post before lending a mutable IO original.
    /// No descriptor, currentness proof or financial permission is returned.
    #[doc(hidden)]
    #[must_use]
    pub fn native_post_carrier_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Result<(), IoSessionAssociationErrorV2>>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<(), ResourceReservationErrorV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<NativeSessionIoMemberV2<'static, 'static, 'static, 'static>>().checked_mul(2)?)
    }
}


impl StorageIoStagesV1 {
    // This is the stored resident plane, independent of the spent traffic of
    // any previous native turn. Its native/decoder bound remains conservative
    // until the actual SDK owner proves a smaller physically disposed extent.
    pub(in crate::controller_resource_reservation) fn completed_resident_receiving_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        if self.failure().is_some()
            || self.apply.phase != IoPhaseV1::Complete
            || self.inventory.phase != IoPhaseV1::Complete
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(self.resident)
    }
}


impl NativeSessionIoMemberV2<'_, '_, '_, '_> {
    pub(in crate::controller_resource_reservation) fn admit_io_v2(&mut self,
        journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: StorageProvisioningSessionIoShapeDataV1, inventory: bool, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_model::ResourceDimension as D;
        let invalid = || ResourceReservationErrorV1::Conflict;
        if shape.request_bytes == 0 || shape.response_bytes == 0
            || shape.response_bytes != (transcript.negotiated_maximum_response_bytes() as usize).min(aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            || shape.request_bytes > aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
        { return Err(invalid()); }
        let (_, native_files) = SeqpacketSocket::storage_preparation_receive_obligations_v1(shape.response_bytes)
            .ok_or_else(invalid)?;
        if shape.receive_files != native_files || cutoff == 0 { return Err(invalid()); }
        let member_bytes = std::mem::size_of::<NativeSessionIoMemberV2<'static, 'static, 'static, 'static>>()
            .checked_mul(2).ok_or_else(invalid)?;
        let key_bytes = aos_sandbox_protocol::authenticated_session::stored_history::canonical_protocol_key_receiving_bytes_v1()
            .checked_mul(2).ok_or_else(invalid)?;
        let receiving_bytes = shape.receiving_bytes.checked_add(member_bytes)
            .and_then(|bytes| bytes.checked_add(key_bytes)).ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(receiving_bytes).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(shape.receive_files.checked_add(shape.retained_endpoint_files)
                .ok_or_else(invalid)?).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(shape.namespace_entries).map_err(|_| invalid())?);
        let fixed_complete = self.complete_base_v2(fixed)?;
        if self.stages_v2().failure().is_some()
            || (inventory && self.stages_v2().apply.phase != IoPhaseV1::Complete)
            || if inventory { self.stages_v2().inventory.fixed.is_some() }
                else { self.stages_v2().apply.fixed.is_some() }
        { return Err(invalid()); }
        self.stages_v2().active = Some(inventory);
        let paid = self.require_complete_v2(fixed_complete);
        let stage = if inventory { &mut self.stages_v2().inventory } else { &mut self.stages_v2().apply };
        stage.shape = Some(shape);
        stage.cutoff = cutoff;
        stage.binding = transcript.session_binding();
        stage.fixed = Some(paid);
        if !matches!(stage.fixed, Some(Ok(()))) { return Err(invalid()); }
        let association = self.require_session_v2(journal, socket, transcript);
        let stage = if inventory { &mut self.stages_v2().inventory } else { &mut self.stages_v2().apply };
        stage.association = Some(association);
        if !matches!(stage.association, Some(Ok(()))) { return Err(invalid()); }
        stage.extent = Some(journal.held_session_receiving_extent_v1(&mut stage.metadata));
        let extent = stage.extent.as_ref().and_then(|value| value.as_ref().ok()).ok_or_else(invalid)?;
        let geometry = storage_retained_current_replay_demand_v1(extent)
            .and_then(|replay| storage_create_prepare_client_request_demand_v1(extent, shape.request_bytes)
                .and_then(|request| replay.checked_add(request).map_err(|_| crate::journal::broker_session_receiving::StorageSessionGeometryRefusalV1)));
        let geometry = geometry.map(|demand| self.pure_model_demand_v2(demand));
        let stage = self.stages_v2().active_mut()?;
        stage.geometry = Some(geometry);
        let variable = stage.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or_else(invalid)?;
        let wire = u64::try_from(shape.request_bytes.checked_add(shape.response_bytes).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let traffic = ResourceVector::ZERO.with(D::NetworkBytes, wire)
            .with(D::OutputBytes, u64::try_from(shape.request_bytes).map_err(|_| invalid())?)
            .with(D::LogBytes, wire.checked_mul(64).ok_or_else(invalid)?);
        let request_capture = aos_sandbox_protocol::authenticated_session::all_methods::request_capture::AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(shape.request_bytes)
            .ok_or_else(invalid)?;
        let request_capture = self.pure_model_demand_v2(request_capture);
        let portable = self.request_additional_v2(shape.request_bytes, inventory)?;
        let incoming = fixed.checked_add(variable)?.checked_add(request_capture)?.checked_add(portable)?.checked_add(traffic)?;
        // Release the split loan before joining its exact already-admitted
        // Core/Root/model base. Existing resident IO and spent same-turn wire
        // are added by require_complete_v1, never treated as phase credit.
        let complete = self.complete_base_v2(incoming)?;
        let paid = self.require_complete_v2(complete);
        let stage = if inventory { &mut self.stages_v2().inventory } else { &mut self.stages_v2().apply };
        stage.variable = Some(paid);
        if !matches!(stage.variable, Some(Ok(()))) { return Err(invalid()); }
        let turn = self.native_turn_v2();
        self.stages_v2().retain_paid_v1(turn, incoming)?;
        self.stages_v2().active = Some(inventory);
        Ok(())
    }
}

impl StorageIoStagesV1 {
    pub(in crate::controller_resource_reservation) fn completed_session_native_data_v2(&self) -> Result<&[u8; 64], ResourceReservationErrorV1> {
        if self.failure().is_some() || [ &self.apply, &self.inventory ].into_iter().any(|stage|
            stage.phase != IoPhaseV1::Complete
                || !matches!(stage.terminal_association, Some(Ok(())))
                || !matches!(stage.native_position, Some(Ok(_)))
                || stage.terminal_identity.is_none()
                || !matches!(stage.request_binding, Some(Ok(())))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let resource = self.apply.terminal_native.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let inventory = self.inventory.terminal_native.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if resource[..48] != inventory[..48] { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(inventory)
    }
}

#[cfg(test)]
mod completed_resource_native_tests {
    use super::*;

    #[test]
    fn raw_position_or_completed_phase_cannot_replace_real_terminal_posts() {
        let mut stages = StorageIoStagesV1::default();
        stages.inventory.terminal_native = Some(Ok([7; 64]));
        assert!(stages.completed_session_native_data_v2().is_err());

        stages.apply.phase = IoPhaseV1::Complete;
        stages.inventory.phase = IoPhaseV1::Complete;
        stages.apply.terminal_native = Some(Ok([7; 64]));
        assert!(stages.completed_session_native_data_v2().is_err());

        stages.apply.terminal_association = Some(Ok(()));
        stages.inventory.terminal_association = Some(Ok(()));
        assert!(stages.completed_session_native_data_v2().is_err());
    }
}

impl StorageIoStagesV1 {
    /// Rejoins the actual complete Host1/fresh3 protected terminal/native stages.
    pub(in crate::controller_resource_reservation) fn require_completed_host_outcomes_v2(&self,
        host: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
        self.require_completed_outcomes_data_v3(host, inventory,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME, BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME)
    }

    pub(in crate::controller_resource_reservation) fn require_completed_storage_outcomes_v3(&self,
        resource: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
        self.require_completed_outcomes_data_v3(resource, inventory,
            BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT, BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
    }

    fn require_completed_outcomes_data_v3(&self,
        host: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        resource_method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
        inventory_method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.completed_session_native_data_v2()?;
        if host.method() != resource_method
            || inventory.method() != inventory_method
            || host.request().session_binding() != inventory.request().session_binding()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        for (stage, outcome) in [(&self.apply, host), (&self.inventory, inventory)] {
            let identity = (outcome.request().signed_request_digest(),
                *blake3::hash(outcome.canonical_packet()).as_bytes());
            if stage.terminal_identity != Some(identity)
                || stage.binding != outcome.request().session_binding()
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(())
    }
}
