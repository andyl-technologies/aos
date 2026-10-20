//! Keeps one genuine C17 Inventory Session append interval continuously borrowed.
//!
//! The genuine authorized planning Source scope or intrinsic pending fence and
//! actual C remain exclusively held for this finite query. The real Security owner must keep the whole Session beside
//! this borrower. One shared captured appender retains request/terminal native
//! stages; no Journal, account, File or writer is reopened or copied here.

use std::error::Error;
use std::sync::Arc;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerDeletePreacceptTurnOriginalV1, ControllerDeletePreacceptTurnDisposalV1,
    ControllerOperationIntakeFailureViewV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, SeqpacketSocket, StorageSeqpacketSessionOriginV1,
};

use super::*;

mod io;
mod io_port;
mod source;
use source::{PlanningNonce, QuerySource};
pub use io::DeleteInventoryIoDisposalV1;
use crate::journal::broker_session_receiving::{
    StorageSessionGeometryRefusalV1, controller_inventory_append_encoded_bound_v1,
    protected_session_journal_limits_v1,
};
use crate::journal::native_interval::captured::{
    CapturedAppendOwnerV1, DeleteSessionAppendWindowV1,
};
use crate::journal::StorageNativeOpeningOwnerLinkV1;
use crate::ControllerInitialBrokerSessionRoleV1 as Role;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Fresh, Captured, Finished, Complete, Failed }

#[derive(Clone, Copy)]
enum First {
    ControllerBeforeAccess, ControllerBefore, Binding, SessionBefore, Socket, Metadata, Materialized, Extent,
    FutureExtent, Geometry, Admission, Installation, CaptureAfter, FinalBinding, FinalSocket, FinalAfter, ControllerAfterAccess, ControllerAfter,
    NonceBefore, NonceAfter, DecodeGeometry, DecodeAdmission,
    IoGeometry, IoAdmission, Io, OutcomeGeometry, OutcomeAdmission, SecurityAdmission, Predecessor,
    Disposal, DisposalControllerAccess, DisposalController, FinalClock, DisposalClock, Reentry,
}

/// Describes only the actual Security query's compiled representation.
///
/// This passive layout contains no financial amount, role or admission. The
/// genuine native constructor pays its fixed raw receive frontier, and Security
/// compares the exact layout before it constructs a query owner.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteInventorySecurityShapeDataV1 {
    /// Actual resident and construction headers of the concrete Security owner.
    pub construction_bytes: usize,
    /// Additional readiness/currentness backing outside those inline headers.
    pub backing_bytes: usize,
    /// Distinct native endpoint probes owned by the retained predecessor sampler.
    pub retained_endpoint_files: usize,
    /// Exact existing retained proc witness footprint, compared by Security.
    pub process_evidence: crate::CreateStorageEndpointRevalidationShapeDataV1,
}

impl DeleteInventorySecurityShapeDataV1 {
    pub(crate) fn demand_v1(self) -> Result<ResourceVector, JournalError> {
        if self.construction_bytes == 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        let (receive, files) = SeqpacketSocket::storage_preparation_receive_obligations_v1(
            aos_sandbox_broker_session_protocol::projection::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
        ).ok_or(JournalError::LimitExceeded("Delete Inventory raw receiver"))?;
        // The reused process helper's legacy cell field includes parser and
        // Result controls, not namespace entries. Its reached stat owner keeps
        // one File plus raw byte buffers; the proc path/parser are temporary.
        // Price the actual backing and FD bound, without charging those cells
        // as names. Other native namespace suppliers remain separate below.
        let memory = self.construction_bytes.checked_add(self.backing_bytes)
            .and_then(|bytes| bytes.checked_add(receive))
            .and_then(|bytes| bytes.checked_add(self.process_evidence.inline_bytes.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(self.process_evidence.heap_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Delete Inventory Security representation"))?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OpenFiles,
            u64::try_from(files.checked_add(self.retained_endpoint_files)
                .and_then(|files| files.checked_add(self.process_evidence.file_descriptors))
                .ok_or(JournalError::LimitExceeded("Delete Inventory process files"))?)
                .map_err(|_| JournalError::LimitExceeded("Delete Inventory receive files"))?))
    }
}

/// Keeps the actual pending/C borrow through one private Session append window.
///
/// Construction is private to the genuine authorized Source pair or intrinsic
/// pending fence after actual fixed admission. Security must not expose the retained Session while this finite
/// borrower lives, and must run its already-paid final observation after every
/// entered primary. Lower success establishes no six-cut or effect authority.
#[must_use]
pub struct DeleteInventorySessionAppendOriginalV1<
    'turn, 'fence, 'journal, 'original, 'authorization, 'profile,
> {
    turn: Option<ControllerDeletePreacceptTurnOriginalV1<'profile>>,
    security_shape: DeleteInventorySecurityShapeDataV1,
    source: QuerySource<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>,
    controller: &'turn mut Journal,
    launch: &'turn ControllerBankLaunchOriginalV1,
    profile: &'profile ControllerSelfProfileOriginalV1,
    directory: &'static str,
    method: BrokerMethod,
    protocol: BrokerSessionProtocolV1,
    uid: u32,
    binding: [u8; 32],
    journal: Option<StorageNativeOpeningOwnerLinkV1>,
    socket: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    binding_validation: Option<Result<(), JournalError>>,
    before: ProtectedJournalCurrentnessOriginalsV1,
    before_result: Option<Result<(), JournalError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    materialized: Option<Result<u64, JournalError>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    encoded: Option<Result<u64, StorageSessionGeometryRefusalV1>>,
    future_extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    admission: Option<Result<(), JournalError>>,
    installation: Option<Result<(), JournalError>>,
    capture_after: ProtectedJournalCurrentnessOriginalsV1,
    capture_after_result: Option<Result<(), JournalError>>,
    final_binding: Option<Result<(), JournalError>>,
    final_socket: Option<Result<(), RecordBindingError>>,
    final_after: ProtectedJournalCurrentnessOriginalsV1,
    final_witness: aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>,
    final_after_result: Option<Result<[u8; 64], JournalError>>,
    controller_before_access: Option<JournalError>,
    controller_after_access: Option<JournalError>,
    disposal_controller_access: Option<JournalError>,
    controller_before: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    controller_after: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    io: io::IoOriginals,
    io_phase: io_port::IoPhase,
    io_geometry: Option<Result<ResourceVector, JournalError>>,
    io_admission: Option<Result<(), JournalError>>,
    outcome_geometry: Option<Result<ResourceVector, JournalError>>,
    outcome_admission: Option<Result<(), JournalError>>,
    predecessor: Option<Result<(), JournalError>>,
    security_admission: Option<Result<(), JournalError>>,
    decode_geometry: Option<Result<ResourceVector, JournalError>>,
    decode_admission: Option<Result<(), JournalError>>,
    clock_final: Option<rustix::time::Timespec>,
    deadline_final: Option<Result<(), JournalError>>,
    clock_disposal: Option<rustix::time::Timespec>,
    deadline_disposal: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    disposal_controller: Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>,
    window: Option<Arc<DeleteSessionAppendWindowV1>>,
    temporary_sink: bool,
    phase: Phase,
    first: Option<First>,
    reentry: Option<JournalError>,
    completed: bool,
    outer_source_after: Option<Result<(), JournalError>>,
}

impl<'fence, 'journal, 'original, 'authorization>
    SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>
{
    pub(crate) fn into_host_confirmation_once_v4<'turn, 'profile>(
        mut self,
        accepted: &'turn crate::journal::ControllerDeleteAdmissionOriginalV3,
        contract: &mut Option<Result<(), Box<dyn Error + Send + Sync>>>,
        root: &'turn mut crate::normal_root::RootDeleteClientOriginalV1<'profile>,
        controller: &'turn mut Journal,
        launch: &'turn ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        security_shape: DeleteInventorySecurityShapeDataV1,
        upper_bytes: usize,
    ) -> Result<
        DeleteInventorySessionAppendOriginalV1<
            'turn,
            'fence,
            'journal,
            'original,
            'authorization,
            'profile,
        >,
        JournalError,
    > {
        let (role, method) = inventory_recipe(transcript)?;
        if role != Role::Host {
            return Err(JournalError::ProtectedBoundary);
        }
        let directory =
            crate::journal::storage_captured_open::controller_session_directory_data_v1(role);
        let uid = controller
            .native
            .protected_uid()
            .ok_or(JournalError::ProtectedBoundary)?;
        let upper_bytes = u64::try_from(upper_bytes).map_err(|_| JournalError::JournalTooLarge)?;
        let demand = fixed_demand(directory, security_shape)?
            .checked_add(PlanningNonce::demand_v1()?)
            .and_then(|demand| {
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, upper_bytes))
            })
            .map_err(JournalError::ReceivingAccounting)?;
        self.reserve_preaccept_additional_v1(controller, launch, profile, demand)?;
        *contract = Some(accepted.completed_native_v3(controller, &self).map(|_| ()));
        if !matches!(contract, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        root.begin_host_confirmation_once_v4(&mut self, controller, launch, accepted)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        // A reached Root before returns its original even after refusal. The
        // query carries that first cause and still owes the same Root/C after.
        let bound = root.host_confirmation_bound_v4(&self, controller, launch, accepted);
        let nonce = bound
            .as_ref()
            .ok()
            .map(|bound| PlanningNonce::post_network_v4(&self, *bound));
        let turn = root.take_host_confirmation_turn_v4();
        if turn.is_none() {
            std::process::abort();
        }
        Ok(DeleteInventorySessionAppendOriginalV1::new_prepaid(
            turn,
            QuerySource::HostConfirmation {
                fence: self,
                root,
                accepted,
                bound,
                nonce,
                post: None,
                comparison: None,
            },
            controller,
            launch,
            profile,
            directory,
            method,
            uid,
            transcript,
            security_shape,
        ))
    }

    // Both genuine D query entrances compare the SAME intrinsic fence and
    // live Root owner. No decoded challenge DATA constructs a Cache borrower.
    pub(crate) fn require_live_inventory_challenge_v1(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        challenge: &crate::normal_root::RootDeleteChallengeLoanV1<'_>,
    ) -> Result<(), JournalError> {
        challenge.open_v2().require_batch_v2(self.batch_bytes()?)
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        challenge.challenge_v2().require_open_v2(*challenge.open_v2())
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        if challenge.open_v2().source_pending != *self.native_position_data_v1()? {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let (funding, next, end) = self.controller_funding_cut_data_v3(controller, launch, profile)?;
        let encoded_funding = funding.encode_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let (expected_funding, expected_next, expected_end) = challenge.controller_funding_cut_v3();
        if encoded_funding.as_slice() != expected_funding || next != expected_next || end != expected_end {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    // The actual shared Inventory Security constructor supplies its compiled
    // own header/backing DATA before allocation. This private append subowner
    // adds only its actual representations and three possible native samples.
    pub(crate) fn into_inventory_append_once_v2<'turn, 'profile>(
        mut self,
        controller: &'turn mut Journal,
        launch: &'turn ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        security_shape: DeleteInventorySecurityShapeDataV1,
        challenge: &'turn crate::normal_root::RootDeleteChallengeLoanV1<'turn>,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<
        'turn, 'fence, 'journal, 'original, 'authorization, 'profile,
    >, JournalError> {
        let (role, method) = inventory_recipe(transcript)?;
        let directory = crate::journal::storage_captured_open::controller_session_directory_data_v1(role);
        let uid = controller.native.protected_uid().ok_or(JournalError::ProtectedBoundary)?;
        let fixed = fixed_demand(directory, security_shape)?;
        self.reserve_preaccept_additional_v1(controller, launch, profile, fixed)?;
        self.require_live_inventory_challenge_v1(controller, launch, profile, challenge)?;
        let turn = self.prepare_preaccept_turn_v1(
            controller, launch, profile, ResourceVector::ZERO,
        )?;
        Ok(DeleteInventorySessionAppendOriginalV1::new_prepaid(
            Some(turn), QuerySource::Preaccept { fence: self, challenge }, controller,
            launch, profile, directory, method, uid, transcript, security_shape,
        ))
    }
}

fn fixed_demand(directory: &str, security_shape: DeleteInventorySecurityShapeDataV1) -> Result<ResourceVector, JournalError> {
    let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            std::path::Path::new(directory), "session.journal",
        )?;
    let bytes = std::mem::size_of::<DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_>>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DeleteInventorySessionAppendDisposalV1<'_>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(2 * aos_sandbox_protocol::domain_ledger::resource_bank::OPERATION_INTAKE_FUNDING_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Delete Inventory append header"))?;
    let fixed = one.checked_add(one).and_then(|demand| demand.checked_add(one))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::ReceivingAccounting)?;
    let security = security_shape.demand_v1()?;
    let witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::<JournalError>::receiving_footprint_v1()
        .and_then(|footprint| u64::try_from(footprint.memory_bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    fixed.checked_add(io::IoOriginals::fixed_demand(directory)?)
        .and_then(|fixed| fixed.checked_add(security))
        .and_then(|fixed| fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, witness)))
        .map_err(JournalError::ReceivingAccounting)
}

impl<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>
    DeleteInventorySessionAppendOriginalV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    fn new_prepaid(
        turn: Option<ControllerDeletePreacceptTurnOriginalV1<'profile>>,
        source: QuerySource<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>,
        controller: &'turn mut Journal,
        launch: &'turn ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        directory: &'static str,
        method: BrokerMethod,
        uid: u32,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        security_shape: DeleteInventorySecurityShapeDataV1,
    ) -> Self {
        Self {
            turn, security_shape, source, controller, launch, profile, directory, method,
            protocol: transcript.protocol(), uid, binding: transcript.session_binding(),
            journal: None, socket: None, binding_validation: None,
            before: ProtectedJournalCurrentnessOriginalsV1::new(), before_result: None,
            metadata: None, materialized: None, extent: None, encoded: None,
            future_extent: None, geometry: None, admission: None, installation: None,
            capture_after: ProtectedJournalCurrentnessOriginalsV1::new(), capture_after_result: None,
            final_binding: None, final_socket: None,
            final_after: ProtectedJournalCurrentnessOriginalsV1::new(), final_after_result: None,
            final_witness: aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::new(),
            controller_before_access: None, controller_after_access: None,
            disposal_controller_access: None, controller_before: None, controller_after: None,
            io: io::IoOriginals::new(), io_phase: io_port::IoPhase::Unprepared,
            io_geometry: None, io_admission: None,
            outcome_geometry: None, outcome_admission: None, predecessor: None, security_admission: None,
            decode_geometry: None, decode_admission: None,
            clock_final: None, deadline_final: None, clock_disposal: None, deadline_disposal: None,
            disposal: None, disposal_controller: None,
            window: None, temporary_sink: false, phase: Phase::Fresh,
            first: None, reentry: None, completed: false, outer_source_after: None,
        }
    }
}

impl<'scope, 'original>
    crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>
{
    pub(crate) fn borrow_planning_inventory_once_v1<'turn, 'profile>(
        &'turn mut self,
        controller: &'turn mut Journal,
        launch: &'turn ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        security_shape: DeleteInventorySecurityShapeDataV1,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<
        'turn, 'turn, 'scope, 'original, 'scope, 'profile,
    >, JournalError> {
        let (authorization, source) = self.planning_parts_v1();
        source.borrow_planning_inventory_append_once_v1(
            authorization, controller, launch, profile, transcript, security_shape,
        )
    }
}

impl<'journal, 'original> SourceDeleteSemanticScopeV1<'journal, 'original> {
    fn borrow_planning_inventory_append_once_v1<'turn, 'authorization, 'profile>(
        &'turn mut self,
        authorization: &'turn crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1<'authorization>,
        controller: &'turn mut Journal,
        launch: &'turn ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        security_shape: DeleteInventorySecurityShapeDataV1,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<
        'turn, 'turn, 'journal, 'original, 'authorization, 'profile,
    >, JournalError> {
        // The actual authorized/source pair is the only caller. Keep the
        // canonical request and all authorization-native originals borrowed;
        // no accepted Operation or historical inventory is substituted here.
        if self.failure().is_some() || !matches!(authorization.authorization().request().request(),
            aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Delete(_)) {
            return Err(JournalError::ProtectedBoundary);
        }
        let (role, method) = inventory_recipe(transcript)?;
        let directory = crate::journal::storage_captured_open::controller_session_directory_data_v1(role);
        let uid = controller.native.protected_uid().ok_or(JournalError::ProtectedBoundary)?;
        let fixed = fixed_demand(directory, security_shape)?.checked_add(PlanningNonce::demand_v1()?)
            .map_err(JournalError::ReceivingAccounting)?;
        self.native.reserve_delete_preaccept_additional_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(fixed),
        ).map_err(JournalError::ControllerNative)?;
        self.native.current_delete_funding_data_v3(
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile,
        ).map_err(JournalError::ControllerNative)?;
        let turn = self.native.prepare_delete_preaccept_turn_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(authorization.demand()),
        ).map_err(JournalError::ControllerNative)?;
        let nonce = PlanningNonce::new(authorization);
        Ok(DeleteInventorySessionAppendOriginalV1::new_prepaid(
            Some(turn), QuerySource::Planning { scope: self, authorization, nonce },
            controller, launch, profile, directory, method, uid, transcript, security_shape,
        ))
    }
}

impl DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_> {
    /// Borrows the actual native planning or verified live Root association.
    ///
    /// Planning retains its kernel nonce and original authorization horizon;
    /// preaccept keeps the live Root challenge borrowed for the entire query.
    /// The fixed request constructor uses this exact nonce and cutoff. Neither
    /// value is adopted from a decoded frame or caller input.
    ///
    /// # Errors
    /// Refuses a failed or not-yet-captured genuine query association.
    pub fn query_coordinates_v1(&self) -> Result<([u8; 16], u64), JournalError> {
        if self.phase != Phase::Captured || self.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.source.coordinates()
    }

    /// Captures the fixed same-Session append/frontier before any request work.
    ///
    /// # Errors
    /// Retains C, authorization horizon, Session, native or payment refusal;
    /// the independently prepaid final C/profile post remains owed.
    pub fn capture_session_once_v1(
        &mut self,
        journal: &mut Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        if self.phase != Phase::Fresh || !matches!(self.security_admission, Some(Ok(()))) {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        if !self.source.is_host_confirmation() {
            match self.controller.controller_coordinator_for_bank_read_v1() {
                Ok(controller) => {
                    self.controller_before = Some(match self.turn.as_mut() {
                        Some(turn) => turn.observe_before_once_v1(controller),
                        None => std::process::abort(),
                    });
                    if self.controller_before.as_ref().is_some_and(Result::is_err) {
                        self.first.get_or_insert(First::ControllerBefore);
                    }
                }
                Err(cause) => {
                    self.controller_before_access = Some(cause);
                    self.first.get_or_insert(First::ControllerBeforeAccess);
                }
            }
        }
        // A failed before never suppresses the already-funded held-name after.
        let primary = self.capture_primary(journal, socket, transcript);
        if self.before_result.is_some() {
            // A rejected pure recipe enters no Session native observation.
            // Once the actual before starts, its separate after is owed even
            // if that before or a later capture/admission refused.
            self.capture_after_result =
                Some(journal.observe_held_names_post_retaining_v1(&mut self.capture_after));
            if self
                .capture_after_result
                .as_ref()
                .is_some_and(Result::is_err)
            {
                self.first.get_or_insert(First::CaptureAfter);
            }
        }
        if primary.is_ok() && self.first.is_none() {
            self.phase = Phase::Captured;
            Ok(())
        } else {
            if let Some(turn) = self.turn.as_mut() {
                turn.refuse_primary_v1();
            }
            self.phase = Phase::Failed;
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn capture_primary(&mut self, journal: &mut Journal,
        socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        if self.first.is_some() { return Err(JournalError::ProtectedBoundary); }
        if self.source.begin_nonce().is_err() {
            self.first.get_or_insert(First::NonceBefore);
            return Err(JournalError::ProtectedBoundary);
        }
        self.binding_validation = Some((|| {
            if transcript.session_binding() != self.binding
                || transcript.protocol() != self.protocol
                || inventory_recipe(transcript)?.1 != self.method
                || journal.configured_limits() != protected_session_journal_limits_v1()
                || !matches!(&journal.native, JournalNativeBackingV1::Ordinary(_)) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if self.binding_validation.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Binding);
            return Err(JournalError::ProtectedBoundary);
        }
        self.before_result = Some(journal.validate_held_owned_at_for_uid_retaining(
            self.directory, "session.journal", self.uid, &mut self.before,
        ));
        if self.before_result.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::SessionBefore);
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal = Some(journal.held_session_owner_link_v1());
        self.socket = Some(socket.capture_storage_session_origin_v1());
        if self.socket.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Socket);
            return Err(JournalError::ProtectedBoundary);
        }
        let (metadata, limits) = journal.held_native_receiving_metadata_v1();
        self.metadata = Some(metadata);
        if self.metadata.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Metadata);
            return Err(JournalError::ProtectedBoundary);
        }
        self.materialized = Some(journal.held_materialized_encoding_bytes_v1());
        if self.materialized.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Materialized);
            return Err(JournalError::ProtectedBoundary);
        }
        let physical = self.metadata.as_ref().and_then(|value| value.as_ref().ok())
            .map(std::fs::Metadata::len).ok_or(JournalError::ProtectedBoundary)?;
        let materialized = self.materialized.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            limits, physical.max(materialized),
        ));
        let extent = match self.extent.as_ref() {
            Some(Ok(extent)) => extent,
            _ => {
                self.first.get_or_insert(First::Extent);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.encoded = Some(controller_inventory_append_encoded_bound_v1(extent));
        self.future_extent = Some((|| {
            let append = self.encoded.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            let future = extent.native_bytes.checked_add(append)
                .ok_or(JournalError::JournalTooLarge)?;
            crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(limits, future)
        })());
        if self.future_extent.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::FutureExtent);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            let encoded = self.encoded.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            let future = self.future_extent.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            crate::journal::inventory_native::append_geometry_v2(journal, extent,
                future, encoded, self.method, self.directory)
        })());
        let demand = match self.geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                self.first.get_or_insert(First::Geometry);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.admission = Some(self.source.reserve_additional(
            self.controller, self.launch, self.profile, demand,
        ));
        if self.admission.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Admission);
            return Err(JournalError::ProtectedBoundary);
        }
        // Actual same-C17 admission precedes either allocation. This installs
        // no new Journal, native writer or resource account.
        let encoded = self.encoded.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.window = Some(Arc::new(DeleteSessionAppendWindowV1::new_prepaid_v1(encoded)));
        let window = self.window.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.installation = Some((|| {
            let JournalNativeBackingV1::Ordinary(ordinary) = &mut journal.native
            else { return Err(JournalError::ProtectedBoundary); };
            if ordinary.captured_append.is_none() {
                ordinary.captured_append = Some(CapturedAppendOwnerV1::new(
                    self.directory, "session.journal", self.uid,
                ));
                self.temporary_sink = true;
            }
            let owner = ordinary.captured_append.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            owner.require_delete_identity_v1(self.directory, "session.journal", self.uid)?;
            owner.install_delete_window_v1(Arc::clone(window))?;
            window.open_primary_once_v1()
        })());
        if self.installation.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Installation);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Admits the actual raw response before any outer or body decoder.
    ///
    /// # Errors
    /// Retains invalid real geometry or same-C17 exhaustion. Raw native custody
    /// and independently prepaid final posts remain with the actual query.
    pub fn reserve_response_decode_once_v1(
        &mut self,
        packet: &[u8],
    ) -> Result<(), JournalError> {
        if self.phase != Phase::Captured || self.first.is_some() || self.decode_geometry.is_some() {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        self.decode_geometry = Some(
            aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
                AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
                    self.method, packet.len(),
                ).ok_or(JournalError::LimitExceeded("Delete Inventory response model")),
        );
        let demand = match self.decode_geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                self.first.get_or_insert(First::DecodeGeometry);
                if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
                self.phase = Phase::Failed;
                return Err(JournalError::ProtectedBoundary);
            }
        };
        self.decode_admission = Some(self.source.reserve_additional(
            self.controller, self.launch, self.profile, demand,
        ));
        if self.decode_admission.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::DecodeAdmission);
            self.phase = Phase::Failed;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn refuse(&mut self) {
        if let Some(turn) = self.turn.as_mut() { turn.refuse_primary_v1(); }
        self.reentry.get_or_insert(JournalError::ProtectedBoundary);
        if self.first.is_none() && self.io.failure().is_some() {
            self.first = Some(First::Io);
        }
        self.first.get_or_insert(First::Reentry);
        self.phase = Phase::Failed;
    }

    /// Permanently closes primary entry without suppressing prepaid final posts.
    pub fn mark_primary_refused_v1(&mut self) {
        self.refuse();
    }

    /// Runs the prepaid final observations after either whole primary outcome.
    ///
    /// No fresh debit or healthy admission follows an entered primary failure.
    ///
    /// # Errors
    /// Retains reentry, the actual earlier primary or independent final refusal.
    pub fn finish_native_once_v1(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        if self.final_binding.is_some() || self.clock_final.is_some() {
            self.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        if let Some(window) = &self.window {
            window.close_primary_v1();
        }
        self.final_binding = Some(
            if self
                .journal
                .as_ref()
                .is_some_and(|owner| owner.matches_journal_v1(journal))
                && transcript.session_binding() == self.binding
                && transcript.protocol() == self.protocol
            {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            },
        );
        if self.final_binding.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::FinalBinding);
        }
        if let Some(Ok(origin)) = self.socket.as_ref() {
            self.final_socket = Some(origin.require_same_socket(socket));
            if self.final_socket.as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert(First::FinalSocket);
            }
        }
        if self.before_result.is_some() {
            self.final_after_result =
                Some(journal.observe_session_completion_position_retaining_v2(
                    &mut self.final_after,
                    &mut self.final_witness,
                ));
            if self.final_after_result.as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert(First::FinalAfter);
            }
        }
        if !self.source.is_host_confirmation() {
            match self.controller.controller_coordinator_for_bank_read_v1() {
                Ok(controller) => {
                    self.controller_after = Some(match self.turn.as_mut() {
                        Some(turn) => turn.observe_after_once_v1(controller),
                        None => std::process::abort(),
                    });
                    if self.controller_after.as_ref().is_some_and(Result::is_err) {
                        self.first.get_or_insert(First::ControllerAfter);
                    }
                }
                Err(cause) => {
                    self.controller_after_access = Some(cause);
                    self.first.get_or_insert(First::ControllerAfterAccess);
                }
            }
        }
        if self
            .source
            .finish_nonce(&mut self.turn, self.controller, self.first.is_some())
            .is_err()
        {
            self.first.get_or_insert(First::NonceAfter);
        }
        self.clock_final = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_final = Some((|| {
            let (_, cutoff) = self.source.coordinates()?;
            io::require_before(self.clock_final, cutoff)
        })());
        if self.deadline_final.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::FinalClock);
        }
        if self.first.is_some() {
            self.phase = Phase::Failed;
            Err(JournalError::ProtectedBoundary)
        } else {
            self.phase = Phase::Finished;
            Ok(())
        }
    }

    /// Holds native completion while the actual successful upper capsule ends.
    ///
    /// This is only append/bookend disposition. The Security owner separately
    /// requires its exact authenticated request, committed terminal and current
    /// predecessor before requesting it. No lower success is a six-cut proof.
    ///
    /// # Errors
    /// Retains an incomplete/failed query, late cutoff, changed original or
    /// absent pair of actual native positive append completions.
    pub fn prepare_positive_disposal_v1<'disposal>(
        &'disposal mut self,
        journal: &'disposal mut Journal,
    ) -> Result<DeleteInventorySessionAppendDisposalV1<'disposal>, JournalError> {
        self.disposal = Some((|| {
            if self.phase != Phase::Finished
                || self.first.is_some()
                || self.completed
                || !self.io.is_idle()
                || self.io_phase != io_port::IoPhase::Decoded
                || !matches!(self.outcome_admission, Some(Ok(())))
                || !matches!(self.predecessor, Some(Ok(())))
                || journal.native_interval.is_some()
                || !self
                    .journal
                    .as_ref()
                    .is_some_and(|owner| owner.matches_journal_v1(journal))
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let window = self
                .window
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            let JournalNativeBackingV1::Ordinary(ordinary) = &journal.native else {
                return Err(JournalError::ProtectedBoundary);
            };
            ordinary
                .captured_append
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .require_delete_window_retirement_v1(window)
        })());
        if self.disposal.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Disposal);
            if let Some(turn) = self.turn.as_mut() {
                turn.refuse_primary_v1();
            }
            self.phase = Phase::Failed;
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller,
                    self.launch,
                    self.profile,
                ));
            }
            return Err(JournalError::ProtectedBoundary);
        }
        self.clock_disposal = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.deadline_disposal = Some((|| {
            let (_, cutoff) = self.source.coordinates()?;
            io::require_before(self.clock_disposal, cutoff)
        })());
        if self.deadline_disposal.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::DisposalClock);
            if let Some(turn) = self.turn.as_mut() {
                turn.refuse_primary_v1();
            }
            self.phase = Phase::Failed;
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller,
                    self.launch,
                    self.profile,
                ));
            }
            return Err(JournalError::ProtectedBoundary);
        }
        let boundary = match self.final_after.completed_held_file_boundary_data_v1() {
            Some((device, inode, bytes)) => (journal.native.next_sequence(), device, inode, bytes),
            None => {
                self.disposal = Some(Err(JournalError::ProtectedBoundary));
                self.first.get_or_insert(First::Disposal);
                if let Some(turn) = self.turn.as_mut() {
                    turn.refuse_primary_v1();
                }
                self.phase = Phase::Failed;
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller,
                        self.launch,
                        self.profile,
                    ));
                }
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let terminal_native = match self
            .final_after_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
        {
            Some(native) => *native,
            None => std::process::abort(),
        };
        // The exclusive borrow preserves the just-checked backing and window.
        // Every fallible gate precedes the returned infallible disposition.
        let JournalNativeBackingV1::Ordinary(ordinary) = &mut journal.native else {
            self.refuse();
            if self.outer_source_after.is_none() {
                self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                    self.controller,
                    self.launch,
                    self.profile,
                ));
            }
            return Err(JournalError::ProtectedBoundary);
        };
        let controller = match self.controller.controller_coordinator_for_bank_read_v1() {
            Ok(controller) => controller,
            Err(cause) => {
                self.disposal_controller_access = Some(cause);
                self.first.get_or_insert(First::DisposalControllerAccess);
                if let Some(turn) = self.turn.as_mut() {
                    turn.refuse_primary_v1();
                }
                self.phase = Phase::Failed;
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller,
                        self.launch,
                        self.profile,
                    ));
                }
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let turn = match self.turn.as_mut() {
            Some(turn) => turn,
            None => std::process::abort(),
        };
        let native = match turn.prepare_positive_disposal_v1(controller) {
            Ok(native) => native,
            Err(cause) => {
                self.disposal_controller = Some(cause);
                self.first.get_or_insert(First::DisposalController);
                self.phase = Phase::Failed;
                if self.outer_source_after.is_none() {
                    self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
                        self.controller,
                        self.launch,
                        self.profile,
                    ));
                }
                return Err(JournalError::ProtectedBoundary);
            }
        };
        Ok(DeleteInventorySessionAppendDisposalV1 {
            native,
            boundary,
            terminal_native,
            captured: &mut ordinary.captured_append,
            temporary: self.temporary_sink,
            before: &mut self.before,
            capture_after: &mut self.capture_after,
            final_after: &mut self.final_after,
            final_witness: &mut self.final_witness,
            phase: &mut self.phase,
            completed: &mut self.completed,
        })
    }

    /// Attempts the same prepaid enclosing Source/C17 after on a failed query.
    ///
    /// The whole query, Session and prior positive answers must remain resident.
    /// This closes no success token, performs no new debit and cannot reenter
    /// a healthy primary. Its original Result remains separate from first cause.
    ///
    /// # Errors
    /// Retains the original outer post refusal or rejects healthy/repeated use.
    pub fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), JournalError> {
        if self.outer_source_after.is_some() || self.first.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.outer_source_after = Some(self.source.finish_outer_failure_once_v1(
            self.controller, self.launch, self.profile));
        match &self.outer_source_after {
            Some(Ok(())) => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Borrows only this owner's exact first local cause.
    ///
    /// The actual caller resolves Controller/admission marker sites through
    /// controller_failure_view_v1 instead of replacing earlier local errors.
    pub fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let Some(first) = self.first else { return self.io.failure(); };
        match first {
            First::ControllerBeforeAccess => self.controller_before_access.as_ref().map(|cause| cause as _),
            First::ControllerBefore => error(&self.controller_before),
            First::Binding => error(&self.binding_validation),
            First::SessionBefore => self.before.failure().or_else(|| error(&self.before_result)),
            First::Socket => error(&self.socket),
            First::Metadata => error(&self.metadata),
            First::Materialized => error(&self.materialized),
            First::Extent => error(&self.extent),
            First::FutureExtent => error(&self.future_extent),
            First::Geometry => error(&self.encoded).or_else(|| error(&self.geometry)),
            First::Admission => error(&self.admission),
            First::Installation => self.window.as_ref().and_then(|window| window.failure())
                .or_else(|| error(&self.installation)),
            First::CaptureAfter => self.capture_after.failure()
                .or_else(|| error(&self.capture_after_result)),
            First::FinalBinding => error(&self.final_binding),
            First::FinalSocket => error(&self.final_socket),
            First::FinalAfter => self.final_after.failure().or_else(|| self.final_witness.failure().map(|cause| cause as _))
                .or_else(|| error(&self.final_after_result)),
            First::ControllerAfterAccess => self.controller_after_access.as_ref().map(|cause| cause as _),
            First::ControllerAfter => error(&self.controller_after),
            First::NonceBefore | First::NonceAfter => self.source.failure(),
            First::IoGeometry => error(&self.io_geometry),
            First::IoAdmission => error(&self.io_admission),
            First::Io => self.io.failure(),
            First::OutcomeGeometry => error(&self.outcome_geometry),
            First::OutcomeAdmission => error(&self.outcome_admission),
            First::SecurityAdmission => error(&self.security_admission),
            First::Predecessor => error(&self.predecessor),
            First::DecodeGeometry => error(&self.decode_geometry),
            First::DecodeAdmission => error(&self.decode_admission),
            First::FinalClock => error(&self.deadline_final),
            First::DisposalClock => error(&self.deadline_disposal),
            First::Disposal => error(&self.disposal),
            First::DisposalControllerAccess => self.disposal_controller_access.as_ref().map(|cause| cause as _),
            First::DisposalController => self.disposal_controller.as_ref().map(|cause| cause as _),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    /// Borrows the original guard only at this owner's exact Controller site.
    pub fn controller_failure_view_v1(&self)
        -> Option<ControllerOperationIntakeFailureViewV1<'_>>
    {
        match self.first? {
            First::Admission | First::DecodeAdmission | First::IoAdmission
                | First::OutcomeAdmission | First::SecurityAdmission => self.source.intake_failure(self.profile),
            First::ControllerBefore | First::ControllerAfter | First::DisposalController => self.turn.as_ref().and_then(|turn| turn.failure_view_v1()),
            First::NonceBefore | First::NonceAfter => self.source.root_intake_failure(),
            _ => None,
        }
    }


}

/// Keeps the same C17 slot and actual Session sink exclusive through disposal.
#[must_use]
pub struct DeleteInventorySessionAppendDisposalV1<'disposal> {
    native: ControllerDeletePreacceptTurnDisposalV1<'disposal>,
    boundary: (u64, u64, u64, u64),
    terminal_native: [u8; 64],
    captured: &'disposal mut Option<CapturedAppendOwnerV1>,
    temporary: bool,
    before: &'disposal mut ProtectedJournalCurrentnessOriginalsV1,
    capture_after: &'disposal mut ProtectedJournalCurrentnessOriginalsV1,
    final_after: &'disposal mut ProtectedJournalCurrentnessOriginalsV1,
    final_witness: &'disposal mut aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>,
    phase: &'disposal mut Phase,
    completed: &'disposal mut bool,
}

impl DeleteInventorySessionAppendDisposalV1<'_> {
    /// Copies the same final names, native sequence and held byte boundary.
    ///
    /// This is the existing Session completion-position format, not a COMMIT
    /// digest or authority. Its producer is the actual final native witness.
    #[must_use]
    pub const fn completed_native_position_data_v4(&self) -> &[u8; 64] {
        &self.terminal_native
    }

    /// Copies actual native NEXT, device, inode and sampled completed byte length.
    ///
    /// The token was reached only after the real query's final original name,
    /// socket, Source/C17/profile and clock posts. This comparison DATA is not
    /// a live Session, six-cut, protected append or effect authority.
    #[must_use]
    pub const fn completed_boundary_data_v2(&self) -> (u64, u64, u64, u64) {
        self.boundary
    }

    // The Session and separately paid complete answer owner persist. Dispose
    // only successful transient query IO/parser capsules before this Native
    // completion; retaining the answer never grants a memory/traffic refund.
    /// Completes after successful transient query IO owners were disposed.
    pub fn complete_after_upper_disposal_v1(self) {
        let Self {
            native,
            boundary: _,
            terminal_native: _,
            captured,
            temporary,
            before,
            capture_after,
            final_after,
            final_witness,
            phase,
            completed,
        } = self;
        before.settle_positive_once_v1();
        capture_after.settle_positive_once_v1();
        final_after.settle_positive_once_v1();
        if !final_witness.retire_positive_metadata_once_v1() {
            std::process::abort();
        }
        if temporary {
            drop(captured.take());
        } else if let Some(owner) = captured.as_mut() {
            owner.complete_delete_window_retirement_v1();
        }
        *completed = true;
        *phase = Phase::Complete;
        native.complete_after_upper_disposal_v1();
    }
}

impl Drop for DeleteInventorySessionAppendOriginalV1<'_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if self.completed {
            drop(self.turn.take());
            self.source.complete_positive_disposal();
        } else {
            // The actual Security owner must retain every negative prefix.
            // Abandonment cannot drop native uncertainty or reopen this loan.
            std::process::abort();
        }
    }
}

fn inventory_recipe(transcript: &VerifiedBrokerSessionTranscriptV1)
    -> Result<(Role, BrokerMethod), JournalError>
{
    crate::journal::inventory_native::inventory_recipe(transcript)
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn Error + 'static)>
{
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
