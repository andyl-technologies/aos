//! Shares the existing Root subject stream and strict reply receive loops.
//!
//! The finite adapters borrow actual financial originals. Encoded fields and
//! announced widths remain passive DATA; they cannot select another account,
//! create a loan, or extend a deadline. Failed native leaves stay in the same
//! caller-owned destinations through independently owed whole-flight posts.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_protocol::domain_ledger::provisioning_root::{
    storage_apply::{ApplyRootDataErrorV1, StorageApplyReplyDataV1, StorageApplySubjectDataV1},
    host_launch::{HostLaunchSubjectDataV1, HostResourceReplyDataV1},
    host_launch::completion::ResourceCompletionProofDataV2,
    finality_recover::{FinalityRecoverQueryDataV1, FinalityRecoverAcknowledgementDataV1},
    start_assignment_inputs::{StartAssignmentInputsSubjectDataV2, StartAssignmentInputsReplyDataV2},
};
use crate::{Journal, OriginalCreateProvisioningRootLoanV1, OriginalStartHostRootLoanV1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::policy_compiler::bounded_stream_io::{FixedDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use super::peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1,
    sample::PeerSampleV1};
use super::profile_owner::ProductionControllerNormalRootProfileV1;
use super::root_connection::ControllerRootConnectionOriginalV1;
use super::strict_chunk::RootStrictChunkOriginalV1;

/// Selects only an already genuine financial original for the existing loop.
pub(super) enum RootClientLoanV1<'loan, 'turn, 'intake, 'exec_turn, 'exec_source, 'exec_original> {
    StopCleanup(&'loan mut crate::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'turn, 'intake>),
    ExecutionNoApply(&'loan mut crate::controller_execution_operation::ControllerExecutionNoApplyClientLoanV2<'exec_turn, 'exec_source, 'exec_original>),
    Apply(&'loan mut OriginalCreateProvisioningRootLoanV1<'turn, 'intake>),
    Start(&'loan mut OriginalStartHostRootLoanV1<'turn, 'intake>),
    StartAssignmentInputs(&'loan mut crate::OriginalStartAssignmentInputsLoanV2<'turn, 'intake>),
    Recover(&'loan mut crate::OperatorCreateRecoveryLoanV1<'turn, 'intake>),
    MaintenanceStorage(&'loan mut crate::controller_resource_reservation::ControllerCatalogMaintenanceRootLoanV3<'turn, 'intake>),
}

impl RootClientLoanV1<'_, '_, '_, '_, '_, '_> {
    fn require_complete(&mut self, context: RootClientControllerContextV2<'_>, demand: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        if let Self::ExecutionNoApply(loan) = self {
            if !matches!(context, RootClientControllerContextV2::ExecutionOwned) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            return loan.admit_root_transport_complete_v2(demand);
        }
        let RootClientControllerContextV2::External(controller) = context else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        match self {
            Self::StopCleanup(loan) => loan.admit_root_transport_complete_v1(controller, demand),
            Self::ExecutionNoApply(_) => Err(ResourceReservationErrorV1::Conflict),
            Self::Apply(loan) => loan.require_complete_v1(controller, demand),
            Self::Start(loan) => loan.require_complete_v1(controller, demand),
            Self::StartAssignmentInputs(loan) => loan.require_complete_v2(controller, demand),
            Self::MaintenanceStorage(loan) => loan.require_complete_v3(controller, demand),
            Self::Recover(loan) => {
                loan.require_root_controller_v1(controller)?;
                loan.check_frontier_v1()?;
                loan.require_complete_v1(demand)
            }
        }
    }

    fn has_original_failure(&self) -> bool {
        match self {
            Self::StopCleanup(loan) => loan.failure_v1().is_some(),
            Self::ExecutionNoApply(loan) => loan.failure_v2().is_some(),
            Self::Apply(loan) => loan.failure_v1().is_some(),
            Self::Start(loan) => loan.failure_v1().is_some(),
            Self::StartAssignmentInputs(loan) => loan.failure_v2().is_some(),
            Self::MaintenanceStorage(loan) => loan.failure_v3().is_some(),
            Self::Recover(loan) => loan.failure_v1().is_some(),
        }
    }
}

/// Selects the actual Controller owner without exposing NoApply's held writer.
#[derive(Clone, Copy)]
pub(super) enum RootClientControllerContextV2<'held> {
    External(&'held Journal),
    ExecutionOwned,
}

/// Borrows the caller's real cumulative counters and retained debit result.
pub(super) struct RootClientFundingV1<'owner> {
    pub complete: ResourceVector,
    pub observations: &'owner mut usize,
    pub wire: &'owner mut u64,
    pub output: &'owner mut u64,
    pub received_bound: &'owner mut usize,
    pub admission: &'owner mut Option<Result<(), ResourceReservationErrorV1>>,
    pub funding_original: &'owner mut bool,
}

impl RootClientFundingV1<'_> {
    pub(super) fn charge(&mut self, loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>,
        controller: &Journal, observations: usize, wire: usize, output: usize,
    ) -> Result<(), RootStreamStageV1> {
        self.charge_for_v2(loan, RootClientControllerContextV2::External(controller), observations, wire, output)
    }

    pub(super) fn charge_for_v2(&mut self, loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>,
        context: RootClientControllerContextV2<'_>, observations: usize, wire: usize, output: usize,
    ) -> Result<(), RootStreamStageV1> {
        let result = (|| {
            let bad = || ResourceReservationErrorV1::Conflict;
            let observations = self.observations.checked_add(observations).ok_or_else(bad)?;
            let wire = self.wire.checked_add(u64::try_from(wire).map_err(|_| bad())?)
                .ok_or_else(bad)?;
            let output = self.output.checked_add(u64::try_from(output).map_err(|_| bad())?)
                .ok_or_else(bad)?;
            let buffer = u64::try_from(*self.received_bound).ok()
                .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(bad)?;
            let complete = self.complete.checked_add(peer_traffic_v1(observations)?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, buffer)
                    .with(D::NetworkBytes, wire).with(D::OutputBytes, output))?;
            let debit = loan.require_complete(context, complete);
            if debit.is_err() && loan.has_original_failure() {
                *self.funding_original = true;
            }
            debit?;
            *self.observations = observations;
            *self.wire = wire;
            *self.output = output;
            Ok(())
        })();
        *self.admission = Some(result);
        if matches!(self.admission, Some(Ok(()))) { Ok(()) }
        else { Err(RootStreamStageV1::Admission) }
    }
}

pub(super) fn peer_traffic_v1(observations: usize)
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    let (wire, logs) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(observations)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(ResourceVector::ZERO.with(D::NetworkBytes, wire).with(D::LogBytes, logs))
}

/// Selects bytes only; every variant has its own fixed purpose magic/domain.
pub(super) enum RootSubjectDataV1<'held> {
    StopCleanup(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupSubjectDataV1<'held>),
    StopSignature(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupSignatureDataV1<'held>),
    StopObservedDecision(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupObservedDecisionDataV1<'held>),
    StopFinal(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupFinalDataV1<'held>),
    ExecutionAcquisition(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ExecutionNoApplyAcquisitionSubjectDataV2<'held>),
    ExecutionNoApplySubject(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplySubjectDataV2<'held>),
    ExecutionNoApplyCurrent(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplyCurrentDataV2<'held>),
    ExecutionNoApplyAcknowledgement(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplyAcknowledgementDataV2<'held>),
    Apply(StorageApplySubjectDataV1<'held>),
    Start(HostLaunchSubjectDataV1<'held>),
    ResourceCompletion(ResourceCompletionProofDataV2<'held>),
    StartAssignmentInputs(StartAssignmentInputsSubjectDataV2<'held>),
    Recover(FinalityRecoverQueryDataV1),
    MaintenanceStorage(aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageSubjectDataV2<'held>),
}

impl RootSubjectDataV1<'_> {
    pub(super) fn encoded_bytes(&self) -> Result<usize, ApplyRootDataErrorV1> {
        match self {
            Self::StopCleanup(value) => Ok(value.encoded_bytes_v1()?),
            Self::StopSignature(value) => Ok(value.encoded_bytes_v1()?),
            Self::StopObservedDecision(value) => Ok(value.encoded_bytes_v1()?),
            Self::StopFinal(value) => Ok(value.encoded_bytes_v1()?),
            Self::ExecutionAcquisition(value) => Ok(value.encoded_bytes_v2()?),
            Self::ExecutionNoApplySubject(value) => Ok(value.encoded_bytes_v2()?),
            Self::ExecutionNoApplyCurrent(value) => Ok(value.encoded_bytes_v2()?),
            Self::ExecutionNoApplyAcknowledgement(value) => Ok(value.encoded_bytes_v2()?),
            Self::Apply(value) => value.encoded_bytes_v1(),
            Self::Start(value) => Ok(value.encoded_bytes_v1()?),
            Self::ResourceCompletion(value) => Ok(value.encoded_bytes_v2()?),
            Self::StartAssignmentInputs(value) => Ok(value.encoded_bytes_v2()?),
            Self::MaintenanceStorage(value) => Ok(value.encoded_bytes_v2()?),
            Self::Recover(_) => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::FINALITY_RECOVER_QUERY_BYTES_V1),
        }
    }

    fn encode_range(&self, offset: usize, output: &mut [u8])
        -> Result<(), ApplyRootDataErrorV1>
    {
        match self {
            Self::StopCleanup(value) => Ok(value.encode_range_v1(offset, output)?),
            Self::StopSignature(value) => Ok(value.encode_range_v1(offset, output)?),
            Self::StopObservedDecision(value) => Ok(value.encode_range_v1(offset, output)?),
            Self::StopFinal(value) => Ok(value.encode_range_v1(offset, output)?),
            Self::ExecutionAcquisition(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::ExecutionNoApplySubject(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::ExecutionNoApplyCurrent(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::ExecutionNoApplyAcknowledgement(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::Apply(value) => value.encode_range_v1(offset, output),
            Self::Start(value) => Ok(value.encode_range_v1(offset, output)?),
            Self::ResourceCompletion(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::StartAssignmentInputs(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::MaintenanceStorage(value) => Ok(value.encode_range_v2(offset, output)?),
            Self::Recover(value) => {
                let bytes = value.encode_v1()?;
                let end = offset.checked_add(output.len()).ok_or(ApplyRootDataErrorV1::Extent)?;
                output.copy_from_slice(bytes.get(offset..end).ok_or(ApplyRootDataErrorV1::Extent)?);
                Ok(())
            }
        }
    }
}

pub(super) enum RootReplyPurposeV1 { StopCleanup, StopDecision, StopReceipt, ExecutionAcquisition, ExecutionNoApplyNonce, ExecutionNoApplyFloor, Apply, Start, StartAssignmentInputs, Recover, MaintenanceStorage }

impl RootReplyPurposeV1 {
    fn header_bytes_v2(&self) -> usize {
        match self {
            Self::StopCleanup => aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::REPLY_HEADER_BYTES_V1,
            Self::StopDecision => aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::DECISION_HEADER_BYTES_V1,
            Self::StopReceipt => aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::RECEIPT_HEADER_BYTES_V1,
            Self::ExecutionAcquisition => aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ACQUISITION_REPLY_HEADER_BYTES_V2,
            _ => 20,
        }
    }

    fn declared_bytes(&self, header: &[u8]) -> Result<usize, ApplyRootDataErrorV1> {
        match self {
            Self::StopCleanup => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupReplyDataV1::declared_bytes_v1(header)?),
            Self::StopDecision => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupObservedDecisionDataV1::declared_bytes_v1(header)?),
            Self::StopReceipt => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::stop_cleanup::StopCleanupReceiptDataV1::declared_bytes_v1(header)?),
            Self::ExecutionAcquisition => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ExecutionNoApplyAcquisitionReplyDataV2::declared_bytes_v2(header)?),
            Self::ExecutionNoApplyNonce => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplyNonceReplyDataV2::declared_bytes_v2(header)?),
            Self::ExecutionNoApplyFloor => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::ExecutionNoApplyFloorReplyDataV2::declared_bytes_v2(header)?),
            Self::Apply => StorageApplyReplyDataV1::declared_encoded_bytes_v1(header),
            Self::Start => Ok(HostResourceReplyDataV1::declared_bytes_v1(header)?),
            Self::StartAssignmentInputs => Ok(StartAssignmentInputsReplyDataV2::declared_bytes_v2(header)?),
            Self::MaintenanceStorage => Ok(aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageReplyDataV2::declared_bytes_v2(header)?),
            Self::Recover => Ok(FinalityRecoverAcknowledgementDataV1::declared_encoded_bytes_v1(header)?),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum RootStreamStageV1 { Query, Send, Admission, Receive, Reply }

/// Runs the sole bounded subject loop over the caller's actual destinations.
pub(super) fn send_subject_v1(subject: RootSubjectDataV1<'_>,
    connection: &mut ControllerRootConnectionOriginalV1,
    sender: &mut FixedDeadlineStreamIoV1<4096>,
    sent: &mut Option<Result<(), HistoryErrorV1>>, scratch: &mut [u8; 4096],
    data_failure: &mut Option<ApplyRootDataErrorV1>, cutoff: u64,
) -> Result<(), RootStreamStageV1> {
    let total = subject.encoded_bytes().map_err(|cause| {
        *data_failure = Some(cause);
        RootStreamStageV1::Query
    })?;
    let mut offset = 0;
    while offset < total {
        let bytes = (total - offset).min(scratch.len());
        subject.encode_range(offset, &mut scratch[..bytes]).map_err(|cause| {
            *data_failure = Some(cause);
            RootStreamStageV1::Query
        })?;
        *sent = Some(sender.run_prefix_once(
            connection.stream_mut().map_err(|_| RootStreamStageV1::Send)?,
            scratch, bytes, cutoff, DeadlineStreamDirectionV1::Write));
        if !matches!(sent, Some(Ok(()))) || !sender.completed_exact() {
            return Err(RootStreamStageV1::Send);
        }
        offset += bytes;

        // Only the timely positive syscall leaf is retired. The whole socket,
        // initial peer anchor and separately paid outer after remain owned.
        *sender = Default::default();
        *sent = None;
    }
    Ok(())
}

/// Borrows actual receive destinations, retaining every refused native prefix.
pub(super) struct RootReplyReceiveV1<'owner> {
    pub connection: &'owner mut ControllerRootConnectionOriginalV1,
    pub received: &'owner mut RetainedSubjectStreamReadV1,
    pub preparation: &'owner mut Option<Result<(), SubjectStreamReadErrorV1>>,
    pub extension: &'owner mut Option<Result<(), SubjectStreamReadErrorV1>>,
    pub chunk: &'owner mut Option<Box<RootStrictChunkOriginalV1>>,
    pub data_failure: &'owner mut Option<ApplyRootDataErrorV1>,
    pub peer_before: &'owner PeerSampleV1,
    pub profile: &'owner ProductionControllerNormalRootProfileV1,
    pub cutoff: u64,
}

impl RootReplyReceiveV1<'_> {
    /// Receives a fixed final acknowledgement through the same attributed loop.
    ///
    /// The genuine caller chooses its protocol's fixed width. Its complete
    /// buffer and wire geometry are admitted before allocation, and each
    /// reached chunk retains the same independently checked native subject.
    ///
    /// # Errors
    /// Retains funding, buffer, transport, subject or original-cutoff refusal.
    pub(super) fn receive_fixed_reply_v2(
        &mut self,
        bytes: usize,
        loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>,
        controller: &Journal,
        funding: &mut RootClientFundingV1<'_>,
    ) -> Result<(), RootStreamStageV1> {
        self.receive_fixed_reply_for_v2(bytes, loan, RootClientControllerContextV2::External(controller), funding)
    }

    pub(super) fn receive_fixed_reply_for_v2(
        &mut self, bytes: usize, loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>,
        context: RootClientControllerContextV2<'_>, funding: &mut RootClientFundingV1<'_>,
    ) -> Result<(), RootStreamStageV1> {
        *funding.received_bound = match context {
            RootClientControllerContextV2::ExecutionOwned => (*funding.received_bound).max(bytes),
            RootClientControllerContextV2::External(_) if matches!(loan, RootClientLoanV1::StopCleanup(_)) =>
                (*funding.received_bound).max(bytes),
            RootClientControllerContextV2::External(_) => bytes,
        };
        funding.charge_for_v2(loan, context, 0, bytes, 0)?;
        *self.preparation = Some(self.received.prepare_exact_once(bytes));
        if !matches!(self.preparation, Some(Ok(()))) {
            return Err(RootStreamStageV1::Receive);
        }
        self.receive_to_target(loan, context, funding)
    }

    pub(super) fn receive_reply(&mut self, purpose: RootReplyPurposeV1,
        loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>, controller: &Journal,
        funding: &mut RootClientFundingV1<'_>,
    ) -> Result<(), RootStreamStageV1> {
        self.receive_reply_for_v2(purpose, loan, RootClientControllerContextV2::External(controller), funding)
    }

    pub(super) fn receive_reply_for_v2(&mut self, purpose: RootReplyPurposeV1,
        loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>, context: RootClientControllerContextV2<'_>,
        funding: &mut RootClientFundingV1<'_>,
    ) -> Result<(), RootStreamStageV1> {
        // The finite purpose selects its literal header width. The caller
        // already admitted this fixed prefix with its request.
        let header_bytes = purpose.header_bytes_v2();
        *self.preparation = Some(self.received.prepare_exact_once(header_bytes));
        if !matches!(self.preparation, Some(Ok(()))) { return Err(RootStreamStageV1::Receive); }
        self.receive_to_target(loan, context, funding)?;
        let total = purpose.declared_bytes(self.received.bytes()).map_err(|cause| {
            *self.data_failure = Some(cause);
            RootStreamStageV1::Reply
        })?;
        *funding.received_bound = match context {
            RootClientControllerContextV2::ExecutionOwned => (*funding.received_bound).max(total),
            RootClientControllerContextV2::External(_) if matches!(loan, RootClientLoanV1::StopCleanup(_)) =>
                (*funding.received_bound).max(total),
            RootClientControllerContextV2::External(_) => total,
        };
        // The entire announced extent is charged before native growth or any
        // plan decode. A refusal retains the already received header unchanged.
        funding.charge_for_v2(loan, context, 0,
            total.checked_sub(header_bytes).ok_or(RootStreamStageV1::Reply)?, 0)?;
        *self.extension = Some(self.received.extend_completed_exact_once(total));
        if !matches!(self.extension, Some(Ok(()))) { return Err(RootStreamStageV1::Receive); }
        self.receive_to_target(loan, context, funding)
    }

    fn receive_to_target(&mut self, loan: &mut RootClientLoanV1<'_, '_, '_, '_, '_, '_>,
        context: RootClientControllerContextV2<'_>, funding: &mut RootClientFundingV1<'_>,
    ) -> Result<(), RootStreamStageV1> {
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| RootStreamStageV1::Receive)?;
        while !self.received.completed_exact() {
            funding.charge_for_v2(loan, context, 1, 0, 0)?;
            *self.chunk = Some(Box::new(RootStrictChunkOriginalV1::default()));
            let chunk = self.chunk.as_mut().ok_or(RootStreamStageV1::Receive)?;
            if chunk.receive_once(self.received,
                self.connection.stream_mut().map_err(|_| RootStreamStageV1::Receive)?,
                self.peer_before, self.profile, &geometry, self.cutoff).is_err() {
                return Err(RootStreamStageV1::Receive);
            }
            // Every failed chunk remains resident; only a native positive leaf
            // whose subject and late cutoff settled can reach this retirement.
            drop(self.chunk.take());
        }
        Ok(())
    }
}
