//! Holds the real initial-six send/ACK interval on the original D connection.
//!
//! A distinct actual C17 turn and new Root samples use the immutable verified
//! challenge cutoff. Completed local disposal precedes the fresh-query gate;
//! no opening field is reset and no old five-second deadline is renewed.

use super::super::strict_chunk::RootStrictChunkOriginalV1;
use super::*;
mod resource_continuation;
use resource_continuation::ResourceReadContinuationV4;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    controller_cut::{DeleteRootControllerCutDataV3, DELETE_ROOT_CONTROLLER_CUT_BYTES_V3},
    final_inventory::{DeleteRootFreshFrameDataV2, DELETE_ROOT_FRESH_FRAME_BYTES_V2,
        DeleteRootPreparatoryApprovalDataV3, DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3,
        initial_ack_commitment_data_v2},
    resource_exchange::{DeleteRootResourceDraftDataV2, DeleteRootResourceContextDataV2,
        DeleteRootResourceWireErrorV2, DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2},
};
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1, RootSubjectReadinessV1};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::{
    seqpacket::SeqpacketError,
    unix_stream::{
        RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
    },
};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::HistoryErrorV1,
    delete_root::initial_inventory::{
        DELETE_ROOT_INITIAL_ACK_BYTES_V3, DELETE_ROOT_INITIAL_FRAME_BYTES_V3,
        DeleteRootInitialAckDataV3, DeleteRootInitialDataErrorV3, DeleteRootInitialFrameDataV3,
    },
    delete_root::{
        final_inventory::{DELETE_ROOT_FRESH_TRANSFER_BYTES_V2, DeleteRootFreshTransferDataV2},
        planning::DeleteRootPlanningDataErrorV3,
    },
};

#[derive(Clone, Copy)]
enum ReadPurposeV2<'frame> {
    Initial { frame: &'frame DeleteRootInitialFrameDataV3, initial_six: [u8; 32] },
    FreshTransfer { initial: DeleteRootInitialAckDataV3 },
    PreparatoryApproval { initial: DeleteRootInitialAckDataV3, frame: DeleteRootFreshFrameDataV2,
        draft_bytes: &'frame [u8], signed: aos_sandbox_protocol::domain_ledger::delete_root::
            resource_exchange::DeleteRootResourceSignedDataV2<'frame>,
        presign: RawPairedClockSample, prior: RawPairedClockSample, expires: i64,
        continuation: Option<ResourceReadContinuationV4> },
    ResourceDraft { initial: DeleteRootInitialAckDataV3,
        owners: [DeleteBatchOwnerCutDataV2; 6], cache_nonce: [u8; 16], cache_cutoff: u64,
        continuation: Option<ResourceReadContinuationV4> },
}

impl ReadPurposeV2<'_> {
    fn resource_purpose_v3(self) -> DeleteResourcePurposeV3 {
        match self {
            Self::ResourceDraft { continuation: Some(value), .. }
                | Self::PreparatoryApproval { continuation: Some(value), .. } => value.purpose(),
            _ => DeleteResourcePurposeV3::Preparation26,
        }
    }

    fn received_bytes_v2(self) -> usize {
        match self {
            Self::Initial { .. } => DELETE_ROOT_INITIAL_ACK_BYTES_V3,
            Self::FreshTransfer { .. } => DELETE_ROOT_FRESH_TRANSFER_BYTES_V2,
            Self::ResourceDraft { .. } => DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2,
            Self::PreparatoryApproval { .. } => DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3,
        }
    }
}

#[derive(Clone, Copy)]
enum InitialFirst {
    BeforeClock,
    CBefore,
    RootBefore,
    Encode,
    Send,
    Geometry,
    Preparation,
    Admission,
    Chunk,
    Ack,
    FreshTransfer,
    FreshController,
    ResourceEncoding,
    ResourceExtent,
    ResourceAdmission,
    ResourceExtension,
    ResourceDraft,
    ResourceCopy,
    RootAfter,
    CAfter,
    AfterClock,
    Settlement,
    ExternalPrimary,
    PreparatoryApproval,
}

pub(super) struct RootDeleteClientInitialOriginalV2 {
    before_original: RetainedKernelPairedClockAttemptV1,
    before_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), DeleteRootWireErrorV2>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), DeleteRootWireErrorV2>>,
    c_before: Option<Result<(), JournalError>>,
    c_after: Option<Result<(), JournalError>>,
    root_before: PeerSampleV1,
    root_before_result: Option<Result<(), NormalRootStartupErrorV1>>,
    root_after: PeerSampleV1,
    root_after_result: Option<Result<(), NormalRootStartupErrorV1>>,
    encoding: Option<Result<(), DeleteRootInitialDataErrorV3>>,
    encoded: [u8; DELETE_ROOT_INITIAL_FRAME_BYTES_V3],
    sent_io: FixedDeadlineStreamIoV1<DELETE_ROOT_INITIAL_FRAME_BYTES_V3>,
    sent: Option<Result<(), HistoryErrorV1>>,
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    buffer: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    admission: Option<Result<(), JournalError>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    ack: Option<Result<DeleteRootInitialAckDataV3, DeleteRootInitialDataErrorV3>>,
    transfer: Option<Result<DeleteRootFreshTransferDataV2, DeleteRootPlanningDataErrorV3>>,
    fresh_controller: Option<Result<DeleteRootControllerCutDataV3, JournalError>>,
    fresh_frame: Option<Result<DeleteRootFreshFrameDataV2, DeleteRootWireErrorV2>>,
    resource_encoding: Option<Result<(), Box<dyn Error + Send + Sync>>>,
    resource_extent: Option<Result<usize, DeleteRootResourceWireErrorV2>>,
    resource_admission: Option<Result<(), JournalError>>,
    resource_extension: Option<Result<(), SubjectStreamReadErrorV1>>,
    resource_draft: Option<Result<DeleteRootResourceContextDataV2, DeleteRootResourceWireErrorV2>>,
    resource_copy: Option<Result<(), std::collections::TryReserveError>>,
    resource_bytes: Vec<u8>,
    approval: Option<Result<DeleteRootPreparatoryApprovalDataV3, DeleteRootResourceWireErrorV2>>,
    approval_time: Option<Result<(), DeleteRootResourceWireErrorV2>>,
    approval_expires: Option<i64>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    first: Option<InitialFirst>,
    complete: bool,
    closed: RootDeleteClientClosedV1,
}

impl RootDeleteClientInitialOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            before_original: Default::default(),
            before_clock: None,
            before_binding: None,
            after_original: Default::default(),
            after_clock: None,
            after_binding: None,
            c_before: None,
            c_after: None,
            root_before: PeerSampleV1::new(),
            root_before_result: None,
            root_after: PeerSampleV1::new(),
            root_after_result: None,
            encoding: None,
            encoded: [0; DELETE_ROOT_INITIAL_FRAME_BYTES_V3],
            sent_io: Default::default(),
            sent: None,
            geometry: CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1(),
            buffer: RetainedSubjectStreamReadV1::new(),
            preparation: None,
            admission: None,
            chunk: None,
            ack: None,
            transfer: None,
            fresh_controller: None, fresh_frame: None, resource_encoding: None,
            resource_extent: None, resource_admission: None, resource_extension: None,
            resource_draft: None, resource_copy: None, resource_bytes: Vec::new(),
            approval: None, approval_time: None, approval_expires: None,
            settlement: None,
            first: None,
            complete: false,
            closed: RootDeleteClientClosedV1,
        }
    }

    fn fixed_demand_v2(profile: &ProductionControllerNormalRootProfileV1)
        -> Result<ResourceVector, JournalError>
    {
        Self::receiving_recipe_v2(profile, DELETE_ROOT_INITIAL_ACK_BYTES_V3, DELETE_ROOT_INITIAL_FRAME_BYTES_V3)
    }

    fn fresh_transfer_demand_v2(profile: &ProductionControllerNormalRootProfileV1)
        -> Result<ResourceVector, JournalError>
    {
        Self::receiving_recipe_v2(profile, DELETE_ROOT_FRESH_TRANSFER_BYTES_V2, 0)
    }

    fn resource_draft_demand_v2(profile: &ProductionControllerNormalRootProfileV1)
        -> Result<ResourceVector, JournalError>
    {
        Self::resource_draft_demand_for_purpose_v3(profile, DeleteResourcePurposeV3::Preparation26)
    }

    fn resource_draft_demand_for_purpose_v3(profile: &ProductionControllerNormalRootProfileV1,
        purpose: DeleteResourcePurposeV3,
    ) -> Result<ResourceVector, JournalError> {
        let output = match purpose {
            DeleteResourcePurposeV3::Preparation26 => DELETE_ROOT_FRESH_FRAME_BYTES_V2 + DELETE_ROOT_CONTROLLER_CUT_BYTES_V3,
            DeleteResourcePurposeV3::Apply7 | DeleteResourcePurposeV3::Network9 | DeleteResourcePurposeV3::MountReap62 => 0,
        };
        let fixed = Self::receiving_recipe_v2(profile, DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2,
            output)?;
        let bytes = std::mem::size_of::<DeleteRootResourceContextDataV2>().checked_mul(3)
            .and_then(|n| n.checked_add(std::mem::size_of::<DeleteRootFreshFrameDataV2>().checked_mul(3)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<DeleteRootControllerCutDataV3>().checked_mul(3)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<ResourceDraftReceiptV2>().checked_mul(3)?))
            .and_then(|n| n.checked_add(DeleteRootResourceDraftDataV2::
                comparison_receiving_memory_bytes_v2().ok()?))
            .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
        fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn receiving_recipe_v2(profile: &ProductionControllerNormalRootProfileV1, received: usize, output: usize)
        -> Result<ResourceVector, JournalError>
    {
        let invalid = || JournalError::ProtectedBoundary;
        let native = CreateStorageRootPeerReceivingOriginalsV1::delete_native_peak_v1(profile)
            .ok_or_else(invalid)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| invalid())?;
        let (subject_bytes, subject_files) = geometry.receive_obligations_v1();
        let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ReadPurposeV2<'_>>().checked_mul(3)?))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<RootStrictChunkOriginalV1>().checked_mul(3)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<DeleteRootInitialFrameDataV3>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(aos_sandbox_protocol::domain_ledger::delete_root::
                initial_inventory::initial_comparison_decoding_bytes_v3()?)
            })
            .and_then(|bytes| bytes.checked_add(subject_bytes.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(clock.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(received.checked_mul(3)?))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    usize::try_from(RootSubjectReadinessV1::receiving_construction_bytes_v1()?)
                        .ok()?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(2)
            .and_then(|files| files.checked_add(subject_files))
            .and_then(|files| files.checked_add(3))
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(invalid)?;
        let clock_names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| n.checked_mul(2)).and_then(|n| u64::try_from(n).ok())
            .ok_or_else(invalid)?;
        let output = u64::try_from(output).map_err(|_| invalid())?;
        let network = usize::try_from(output).map_err(|_| invalid())?
            .checked_add(received)
            .and_then(|bytes| bytes.checked_add(1))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        native
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, files)
                    .with(D::Pids, 1)
                    .with(D::MetadataEntries, clock_names)
                    .with(D::NetworkBytes, network)
                    .with(D::OutputBytes, output),
            )
            .map_err(|_| invalid())
    }

    fn run_once_v2(
        &mut self,
        connection: &mut ControllerRootConnectionOriginalV1,
        stable: &StableRootPeerV1,
        turn: &mut ControllerDeletePreacceptTurnOriginalV1<'_>,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ProductionControllerNormalRootProfileV1,
        open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2,
        frame: &DeleteRootInitialFrameDataV3,
        initial_six: [u8; 32],
    ) {
        self.run_read_interval_once_v2(connection, stable, turn, fence, controller,
            launch, profile, open, challenge, ReadPurposeV2::Initial { frame, initial_six });
    }

    fn run_read_interval_once_v2(
        &mut self, connection: &mut ControllerRootConnectionOriginalV1,
        stable: &StableRootPeerV1, turn: &mut ControllerDeletePreacceptTurnOriginalV1<'_>,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ProductionControllerNormalRootProfileV1,
        open: DeleteRootOpenDataV2, challenge: DeleteRootChallengeDataV2, purpose: ReadPurposeV2<'_>,
    ) {
        let cutoff = challenge.source.cutoff;
        self.begin_native_interval_once_v2(connection, stable, turn, controller,
            profile, open, challenge);
        if let ReadPurposeV2::PreparatoryApproval { prior, expires, draft_bytes, .. } = purpose {
            if self.first.is_none() {
                self.approval_time = Some((|| {
                    let before = self.before_sample_data_v2().map_err(|_| DeleteRootWireErrorV2::Clock)?;
                    prior.validate_later_sample(before).map_err(|_| DeleteRootWireErrorV2::Clock)?;
                    if before.wall_seconds() >= expires { return Err(DeleteRootWireErrorV2::Clock.into()); }
                    let resource_purpose = purpose.resource_purpose_v3();
                    let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(draft_bytes, resource_purpose)?;
                    let context = DeleteRootResourceContextDataV2::decode_for_purpose_v3(draft.context, resource_purpose)?;
                    if before.wall_seconds() >= context.policy_expires_seconds { return Err(DeleteRootWireErrorV2::Clock.into()); }
                    self.resource_draft = Some(Ok(context));
                    self.approval_expires = Some(expires);
                    Ok(())
                })());
                if !matches!(self.approval_time, Some(Ok(()))) { self.first = Some(InitialFirst::PreparatoryApproval); }
            }
        }
        if let ReadPurposeV2::Initial { frame, .. } = purpose {
            if self.first.is_none() {
                self.encoding = Some((|| {
                    frame.require_exchange_v3(open, challenge)?;
                    self.encoded = frame.encode_v3()?;
                    Ok(())
                })());
                if !matches!(self.encoding, Some(Ok(()))) {
                    self.first = Some(InitialFirst::Encode);
                }
            }
            if self.first.is_none() {
                self.sent = Some((|| {
                    self.sent_io.run_once(connection.stream_mut()?, &mut self.encoded,
                        cutoff, DeadlineStreamDirectionV1::Write)
                })());
                if !matches!(self.sent, Some(Ok(()))) {
                    self.first = Some(InitialFirst::Send);
                }
            }
        }
        if let ReadPurposeV2::ResourceDraft { initial, owners, cache_nonce, cache_cutoff, continuation: None } = purpose {
            if self.first.is_none() {
                self.fresh_controller = Some((|| {
                    let (funding, next, end) = fence.controller_funding_cut_data_v3(controller, launch,
                        profile.lower_original_v1())?;
                    Ok(DeleteRootControllerCutDataV3 {
                        challenge: challenge.digest_v2().map_err(|_| JournalError::ProtectedBoundary)?,
                        funding, next, end,
                    })
                })());
                if !matches!(self.fresh_controller, Some(Ok(_))) {
                    self.first = Some(InitialFirst::FreshController);
                }
            }
            if self.first.is_none() {
                self.resource_encoding = Some((|| {
                    let current = *self.fresh_controller.as_ref()
                        .and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
                    let frame = DeleteRootFreshFrameDataV2 {
                        open: open.digest_v2()?, challenge: challenge.digest_v2()?,
                        initial_ack: initial_ack_commitment_data_v2(&initial.encode_v3()?),
                        controller: current.digest_v3()?, owners, cache_nonce, cache_cutoff,
                    };
                    frame.require_exchange_v2(open, challenge, initial, current)?;
                    let bytes = frame.encode_v2()?;
                    let cut = current.encode_v3()?;
                    self.encoded[..DELETE_ROOT_FRESH_FRAME_BYTES_V2].copy_from_slice(&bytes);
                    self.encoded[DELETE_ROOT_FRESH_FRAME_BYTES_V2..
                        DELETE_ROOT_FRESH_FRAME_BYTES_V2 + DELETE_ROOT_CONTROLLER_CUT_BYTES_V3]
                        .copy_from_slice(&cut);
                    self.fresh_frame = Some(Ok(frame));
                    Ok(())
                })());
                if !matches!(self.resource_encoding, Some(Ok(()))) {
                    self.first = Some(InitialFirst::ResourceEncoding);
                }
            }
            if self.first.is_none() {
                self.sent = Some((|| {
                    self.sent_io.run_prefix_once(connection.stream_mut()?, &mut self.encoded,
                        DELETE_ROOT_FRESH_FRAME_BYTES_V2 + DELETE_ROOT_CONTROLLER_CUT_BYTES_V3,
                        cutoff, DeadlineStreamDirectionV1::Write)
                })());
                if !matches!(self.sent, Some(Ok(()))) {
                    self.first = Some(InitialFirst::Send);
                }
            }
        }
        if let ReadPurposeV2::ResourceDraft { continuation: Some(value), .. } = purpose {
            // The actual completed26 flight already sent the original fresh
            // frame. Apply consumes its retained DATA and sends no replacement.
            self.fresh_frame = Some(Ok(value.frame()));
        }
        if self.first.is_none() && self.geometry.is_err() {
            self.first = Some(InitialFirst::Geometry);
        }
        if self.first.is_none() {
            self.preparation = Some(
                self.buffer
                    .prepare_exact_once(purpose.received_bytes_v2()),
            );
            if !matches!(self.preparation, Some(Ok(()))) {
                self.first = Some(InitialFirst::Preparation);
            }
        }
        while self.first.is_none() {
            if self.buffer.completed_exact() {
                if matches!(purpose, ReadPurposeV2::ResourceDraft { .. })
                    && self.resource_extent.is_none()
                {
                    self.resource_extent = Some(DeleteRootResourceDraftDataV2::declared_bytes_for_purpose_v3(
                        self.buffer.bytes(), purpose.resource_purpose_v3()));
                    if !matches!(self.resource_extent, Some(Ok(_))) {
                        self.first = Some(InitialFirst::ResourceExtent);
                        break;
                    }
                    self.resource_admission = Some((|| {
                        let total = *self.resource_extent.as_ref().and_then(|r| r.as_ref().ok())
                            .ok_or(JournalError::ProtectedBoundary)?;
                        // Exact-buffer extension may temporarily retain its old
                        // prefix. The completed owned copy coexists until all
                        // native posts and positive physical disposal pass.
                        let memory = total.checked_mul(3).and_then(|n| u64::try_from(n).ok())
                            .ok_or(JournalError::JournalTooLarge)?;
                        let input = total.checked_sub(DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2)
                            .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
                        fence.reserve_preaccept_additional_v1(controller, launch, profile.lower_original_v1(),
                            ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::NetworkBytes, input))
                    })());
                    if !matches!(self.resource_admission, Some(Ok(()))) {
                        self.first = Some(InitialFirst::ResourceAdmission);
                        break;
                    }
                    self.resource_extension = Some(match self.resource_extent.as_ref().and_then(|r| r.as_ref().ok()) {
                        Some(total) => self.buffer.extend_completed_exact_once(*total),
                        None => Err(SubjectStreamReadErrorV1::Extent),
                    });
                    if !matches!(self.resource_extension, Some(Ok(()))) {
                        self.first = Some(InitialFirst::ResourceExtension);
                        break;
                    }
                } else {
                    break;
                }
            }
            self.admission = Some(RootDeleteClientOriginalV1::peer_traffic_v1(1).and_then(
                |traffic| {
                    fence.reserve_preaccept_additional_v1(
                        controller,
                        launch,
                        profile.lower_original_v1(),
                        traffic,
                    )
                },
            ));
            if !matches!(self.admission, Some(Ok(()))) {
                self.first = Some(InitialFirst::Admission);
                break;
            }
            self.chunk = Some(Box::new(RootStrictChunkOriginalV1::default()));
            let result = match (
                self.chunk.as_mut(),
                self.geometry.as_ref(),
                connection.stream_mut(),
            ) {
                (Some(chunk), Ok(geometry), Ok(stream)) => chunk.receive_once(
                    &mut self.buffer,
                    stream,
                    &self.root_before,
                    profile,
                    geometry,
                    cutoff,
                ),
                _ => Err(HistoryErrorV1::Correlation),
            };
            if result.is_err() {
                self.first = Some(InitialFirst::Chunk);
                break;
            }
            // The sole leaf completed its own native/cutoff/raw-prefix posts.
            // Cumulative ACK bytes stay held through the independent afters.
            drop(self.chunk.take());
        }
        if self.first.is_none() {
            match purpose {
                ReadPurposeV2::Initial { frame, initial_six } => {
                    self.ack = Some((|| {
                        let ack = DeleteRootInitialAckDataV3::decode_v3(self.buffer.bytes())?;
                        ack.require_exchange_v3(*frame, open, challenge, initial_six)?;
                        Ok(ack)
                    })());
                    if !matches!(self.ack, Some(Ok(_))) { self.first = Some(InitialFirst::Ack); }
                }
                ReadPurposeV2::FreshTransfer { initial } => {
                    self.transfer = Some((|| {
                        let data = DeleteRootFreshTransferDataV2::decode_v2(self.buffer.bytes())?;
                        data.require_exchange_v2(open, challenge, initial)?;
                        Ok(data)
                    })());
                    if !matches!(self.transfer, Some(Ok(_))) {
                        self.first = Some(InitialFirst::FreshTransfer);
                    }
                }
                ReadPurposeV2::PreparatoryApproval { initial, frame, draft_bytes, signed, presign, expires, continuation, .. } => {
                    self.approval = Some((|| {
                        let resource_purpose = purpose.resource_purpose_v3();
                        let approval = DeleteRootPreparatoryApprovalDataV3::decode_for_purpose_v3(self.buffer.bytes(), resource_purpose)?;
                        let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(draft_bytes, resource_purpose)?;
                        match continuation {
                            None => approval.require_exchange_v3(frame, challenge, initial, draft, signed)?,
                            Some(value) => value.require_approval(approval, frame, challenge, initial, draft, signed)?,
                        }
                        // Root may send before this separate read starts. Its
                        // causal lower bound is the actual presign sample;
                        // the independently paid receive-after is its upper.
                        presign.validate_later_sample(approval.clock).map_err(|_| DeleteRootWireErrorV2::Clock)?;
                        if approval.clock.wall_seconds() >= expires { return Err(DeleteRootWireErrorV2::Clock.into()); }
                        Ok(approval)
                    })());
                    if !matches!(self.approval, Some(Ok(_))) { self.first = Some(InitialFirst::PreparatoryApproval); }
                }
                ReadPurposeV2::ResourceDraft { continuation, .. } => {
                    self.resource_draft = Some((|| {
                        let resource_purpose = purpose.resource_purpose_v3();
                        let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(self.buffer.bytes(), resource_purpose)?;
                        let context = DeleteRootResourceContextDataV2::decode_for_purpose_v3(draft.context, resource_purpose)?;
                        let frame = *self.fresh_frame.as_ref().and_then(|r| r.as_ref().ok())
                            .ok_or(DeleteRootWireErrorV2::Association)?;
                        // The current lease is independently authenticated at
                        // the later signing gate; here require exact full cut.
                        let lower = match continuation {
                            None => {
                                context.require_frame_v2(frame, context.lease)?;
                                *self.before_clock.as_ref().and_then(|r| r.as_ref().ok())
                                    .ok_or(DeleteRootWireErrorV2::Clock)?
                            }
                            Some(value) => value.require_context(context, frame)?,
                        };
                        lower
                            .validate_later_sample(context.clock)
                            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
                        require_cutoff(context.clock, open, cutoff)?;
                        Ok(context)
                    })());
                    if !matches!(self.resource_draft, Some(Ok(_))) {
                        self.first = Some(InitialFirst::ResourceDraft);
                    }
                    if self.first.is_none() {
                        self.resource_copy = Some(self.resource_bytes.try_reserve_exact(self.buffer.bytes().len()));
                        if matches!(self.resource_copy, Some(Ok(()))) {
                            self.resource_bytes.extend_from_slice(self.buffer.bytes());
                        } else {
                            self.first = Some(InitialFirst::ResourceCopy);
                        }
                    }
                }
            }
        }
        self.finish_native_interval_once_v2(connection, stable, turn, controller,
            profile, open, challenge);
    }

    pub(super) fn begin_native_interval_once_v2(
        &mut self, connection: &mut ControllerRootConnectionOriginalV1,
        stable: &StableRootPeerV1, turn: &mut ControllerDeletePreacceptTurnOriginalV1<'_>,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        open: DeleteRootOpenDataV2, challenge: DeleteRootChallengeDataV2,
    ) {
        let cutoff = challenge.source.cutoff;
        self.before_clock = Some(self.before_original.observe_once(None));
        self.before_binding = Some((|| {
            challenge.require_open_v2(open)?;
            let before = *self
                .before_clock
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            challenge
                .clock
                .validate_later_sample(before)
                .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            require_cutoff(before, open, cutoff)
        })());
        if !matches!(self.before_binding, Some(Ok(()))) {
            self.first = Some(InitialFirst::BeforeClock);
        }
        self.c_before = Some((|| {
            turn.observe_before_once_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)
        })());
        if !matches!(self.c_before, Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::CBefore);
        }
        if self.first.is_none() {
            if let Ok(stream) = connection.stream() {
                self.root_before_result = Some(self.root_before.observe_delete_once_v1(
                    profile,
                    stream,
                    Some(stable),
                    None,
                    false,
                    cutoff,
                ));
            }
            if !matches!(self.root_before_result, Some(Ok(()))) {
                self.first = Some(InitialFirst::RootBefore);
            }
        }
    }

    pub(super) fn finish_native_interval_once_v2(
        &mut self, connection: &mut ControllerRootConnectionOriginalV1,
        stable: &StableRootPeerV1, turn: &mut ControllerDeletePreacceptTurnOriginalV1<'_>,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        open: DeleteRootOpenDataV2, challenge: DeleteRootChallengeDataV2,
    ) {
        let cutoff = challenge.source.cutoff;
        // These afters were paid before entry and remain owed on every primary.
        if let Ok(stream) = connection.stream() {
            self.root_after_result = Some(if matches!(self.root_before_result, Some(Ok(()))) {
                self.root_after.observe_delete_against_sample_once_v1(
                    profile,
                    stream,
                    &self.root_before,
                    None,
                    true,
                    cutoff,
                )
            } else {
                self.root_after.observe_delete_once_v1(
                    profile,
                    stream,
                    Some(stable),
                    None,
                    true,
                    cutoff,
                )
            });
        }
        if !matches!(self.root_after_result, Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::RootAfter);
        }
        self.c_after = Some((|| {
            turn.observe_after_once_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)
        })());
        if !matches!(self.c_after, Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::CAfter);
        }
        self.after_clock = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            let before = *self
                .before_clock
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            let after = *self
                .after_clock
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            before
                .validate_later_sample(after)
                .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            challenge
                .clock
                .validate_later_sample(after)
                .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            if let Some(Ok(ack)) = self.ack.as_ref() {
                ack.clock
                    .validate_later_sample(after)
                    .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            }
            if let Some(Ok(transfer)) = self.transfer.as_ref() {
                transfer.observation.native.clock.validate_later_sample(after)
                    .map_err(|_| DeleteRootWireErrorV2::Clock)?;
            }
            if let Some(Ok(approval)) = self.approval.as_ref() {
                approval.clock.validate_later_sample(after).map_err(|_| DeleteRootWireErrorV2::Clock)?;
                if self.approval_expires.is_none_or(|expires| after.wall_seconds() >= expires) {
                    return Err(DeleteRootWireErrorV2::Clock);
                }
            }
            if let Some(Ok(context)) = self.resource_draft.as_ref() {
                context.clock.validate_later_sample(after)
                    .map_err(|_| DeleteRootWireErrorV2::Clock)?;
                if after.wall_seconds() >= context.policy_expires_seconds {
                    return Err(DeleteRootWireErrorV2::Clock);
                }
            }
            require_cutoff(after, open, cutoff)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::AfterClock);
        }
        if self.first.is_none() {
            self.settlement = Some(
                self.root_before
                    .settle_positive_once()
                    .and_then(|()| self.root_after.settle_positive_once()),
            );
            if !matches!(self.settlement, Some(Ok(()))) {
                self.first = Some(InitialFirst::Settlement);
            }
        }
        self.complete = self.first.is_none() && self.failure().is_none();
    }

    pub(super) fn before_sample_data_v2(&self) -> Result<RawPairedClockSample, RootDeleteClientClosedV1> {
        if self.first.is_some() || !matches!(self.c_before, Some(Ok(())))
            || !matches!(self.root_before_result, Some(Ok(()))) {
            return Err(self.closed);
        }
        self.before_clock.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(self.closed)
    }

    pub(super) fn after_sample_data_v2(&self) -> Result<RawPairedClockSample, RootDeleteClientClosedV1> {
        self.after_clock.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(self.closed)
    }

    pub(super) fn mark_external_primary_refusal_v2(&mut self) {
        self.first.get_or_insert(InitialFirst::ExternalPrimary);
    }

    pub(super) fn completed_interval_v2(&self) -> bool { self.complete }

    pub(super) fn c_failure_selected(&self) -> bool {
        matches!(
            self.first,
            Some(InitialFirst::CBefore | InitialFirst::CAfter)
        )
    }

    pub(super) fn financial_failure_selected(&self) -> bool {
        matches!(self.first, Some(InitialFirst::Admission | InitialFirst::ResourceAdmission))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first? {
            InitialFirst::BeforeClock => self
                .before_original
                .failure()
                .or_else(|| cause(&self.before_clock))
                .or_else(|| cause(&self.before_binding)),
            InitialFirst::CBefore => cause(&self.c_before),
            InitialFirst::CAfter => cause(&self.c_after),
            InitialFirst::RootBefore => self
                .root_before
                .failure()
                .or_else(|| cause(&self.root_before_result)),
            InitialFirst::RootAfter => self
                .root_after
                .failure()
                .or_else(|| cause(&self.root_after_result)),
            InitialFirst::Encode => cause(&self.encoding),
            InitialFirst::Send => self.sent_io.failure().or_else(|| cause(&self.sent)),
            InitialFirst::Geometry => self.geometry.as_ref().err().map(|cause| cause as _),
            InitialFirst::Preparation => self.buffer.failure().or_else(|| cause(&self.preparation)),
            InitialFirst::Admission => cause(&self.admission),
            InitialFirst::Chunk => self
                .chunk
                .as_ref()
                .and_then(|chunk| chunk.failure(&self.buffer)),
            InitialFirst::Ack => cause(&self.ack),
            InitialFirst::FreshTransfer => cause(&self.transfer),
            InitialFirst::FreshController => cause(&self.fresh_controller),
            InitialFirst::ResourceEncoding => self.resource_encoding.as_ref()
                .and_then(|r| r.as_ref().err()).map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            InitialFirst::ResourceExtent => cause(&self.resource_extent),
            InitialFirst::ResourceAdmission => cause(&self.resource_admission),
            InitialFirst::ResourceExtension => self.buffer.failure().or_else(|| cause(&self.resource_extension)),
            InitialFirst::ResourceDraft => cause(&self.resource_draft),
            InitialFirst::ResourceCopy => cause(&self.resource_copy),
            InitialFirst::AfterClock => self
                .after_original
                .failure()
                .or_else(|| cause(&self.after_clock))
                .or_else(|| cause(&self.after_binding)),
            InitialFirst::PreparatoryApproval => cause(&self.approval_time).or_else(|| cause(&self.approval)),
            InitialFirst::ExternalPrimary => Some(&self.closed as _),
            InitialFirst::Settlement => self
                .root_before
                .failure()
                .or_else(|| self.root_after.failure())
                .or_else(|| cause(&self.settlement)),
        };
        selected.or(Some(&self.closed))
    }

    pub(super) fn property_failure_view(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            InitialFirst::RootBefore => self.root_before.property_failure_view_v1(),
            InitialFirst::RootAfter => self.root_after.property_failure_view_v1(),
            InitialFirst::Chunk => self.chunk.as_ref()?.property_failure_view_v1(),
            InitialFirst::Settlement => self
                .root_before
                .property_failure_view_v1()
                .or_else(|| self.root_after.property_failure_view_v1()),
            _ => None,
        }
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn require_profile_v2(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some() {
            return Err(self.closed);
        }
        if !std::ptr::eq(self.profile, profile) {
            self.association = Some(Err(JournalError::ProtectedBoundary));
            self.first = Some(First::Association);
            return Err(self.closed);
        }
        Ok(())
    }

    pub(crate) fn financial_failure_is_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::SourceAdmissionFunding | First::ApplyActivationAdmission | First::NetworkActivationAdmission))
            || matches!(self.first, Some(First::SourceAdmission))
                && self.source_admission.as_ref().is_some_and(|state| state.c_failure_selected_v3())
            || matches!(self.first, Some(First::Admission | First::InitialFrameAdmission | First::InitialAdmission | First::FreshTransferAdmission | First::ResourceDraftAdmission | First::ResourceSigningAdmission | First::PreparatoryApprovalAdmission))
            || matches!(self.first, Some(First::Initial))
                && self
                    .initial
                    .as_ref()
                    .is_some_and(|local| local.financial_failure_selected())
            || matches!(self.first, Some(First::FreshTransfer))
                && self.fresh_transfer.as_ref().is_some_and(|local| local.financial_failure_selected())
            || matches!(self.first, Some(First::ResourceDraft))
                && self.resource_draft[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.financial_failure_selected())
    }

    pub(crate) fn current_turn_failure_view_v2(
        &self,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'_>> {
        if matches!(
            self.first,
            Some(First::Before | First::After | First::Disposal | First::InitialDisposal | First::FreshTransferDisposal | First::ResourceDraftDisposal | First::ResourceSigningDisposal | First::PreparatoryApprovalDisposal)
        ) || matches!(self.first, Some(First::Initial))
            && self
                .initial
                .as_ref()
                .is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::FreshTransfer))
                && self.fresh_transfer.as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::ResourceDraft))
                && self.resource_draft[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::ResourceSigning))
                && self.resource_signing[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::PreparatoryApproval))
                && self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.c_failure_selected())
            || matches!(self.first, Some(First::SourceAdmission))
                && self.source_admission.as_ref().is_some_and(|state| state.c_failure_selected_v3())
        {
            return self.turn.as_ref()?.failure_view_v1();
        }
        None
    }

    pub(crate) fn pending_intake_failure_view_v2<'cause>(
        &'cause self,
        pending: &'cause crate::ControllerDeletePendingOriginalV2<'_, '_>,
    ) -> Option<ControllerOperationIntakeFailureViewV1<'cause>> {
        if self.financial_failure_is_selected_v2()
            || pending.source_readiness_funding_failure_is_selected_v3() {
            return pending.intake_failure_view_v2(self.profile.lower_original_v1());
        }
        None
    }

    /// Lends comparison digests only, without a pre-ACK query original.
    fn initial_association_data_v2(
        &mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<([u8; 32], [u8; 32]), RootDeleteClientClosedV1> {
        if !self.opening_complete
            || self.first.is_some()
            || self.terminal_complete
            || self.initial_admission.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        self.association = Some(self.require_same_pending(fence, controller, launch));
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(First::Association);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let challenge = self
            .challenge
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        Ok((
            open.digest_v2().map_err(|_| self.closed)?,
            challenge.digest_v2().map_err(|_| self.closed)?,
        ))
    }

    /// Pays fixed comparison construction on the same actual pending C17.
    ///
    /// Refusal remains resident as the first financial stage; later framing
    /// cannot replace it or reenter the account. No native query is lent.
    pub(crate) fn prepare_initial_frame_data_v2(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<([u8; 32], [u8; 32]), RootDeleteClientClosedV1> {
        let association = self.initial_association_data_v2(fence, controller, launch)?;
        if self.initial_frame_admission.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        self.initial_frame_admission = Some((|| {
            // The complete frame and transient planning encodings coexist.
            // Receiving/move copies cover those fixed arrays and digests;
            // Runtime separately pays its typed retained construction Result.
            let bytes = std::mem::size_of::<DeleteRootInitialFrameDataV3>()
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(64usize.checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(
                controller, launch, self.profile.lower_original_v1(),
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            )
        })());
        if !matches!(self.initial_frame_admission, Some(Ok(()))) {
            self.first = Some(First::InitialFrameAdmission);
            return Err(self.closed);
        }
        Ok(association)
    }

    /// Sends full initial preimages and receives the actual same-flight ACK.
    ///
    /// Successful Root/C posts, native settlement and physical local disposal
    /// precede the private query gate. The stable Root core/socket stay resident.
    pub(crate) fn exchange_initial_inventory_once_v2(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        frame: &DeleteRootInitialFrameDataV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if !self.opening_complete
            || self.first.is_some()
            || self.terminal_complete
            || !matches!(self.initial_frame_admission, Some(Ok(())))
            || self.initial_admission.is_some()
            || self.initial.is_some()
            || self.initial_complete.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let challenge = *self
            .challenge
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        self.association = Some(self.require_same_pending(fence, controller, launch));
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(First::Association);
            return Err(self.closed);
        }
        self.initial_admission = Some((|| {
            let demand = RootDeleteClientInitialOriginalV2::fixed_demand_v2(self.profile)?;
            fence.reserve_preaccept_additional_v1(
                controller,
                launch,
                self.profile.lower_original_v1(),
                demand,
            )?;
            fence.reserve_preaccept_additional_v1(
                controller,
                launch,
                self.profile.lower_original_v1(),
                Self::peer_traffic_v1(2)?,
            )?;
            self.turn = Some(fence.prepare_preaccept_turn_v1(
                controller,
                launch,
                self.profile.lower_original_v1(),
                ResourceVector::ZERO,
            )?);
            Ok(())
        })());
        if !matches!(self.initial_admission, Some(Ok(()))) {
            self.first = Some(First::InitialAdmission);
            return Err(self.closed);
        }
        self.initial = Some(Box::new(RootDeleteClientInitialOriginalV2::new()));
        if let (Some(local), Some(stable), Some(turn)) = (
            self.initial.as_mut(),
            self.stable.as_ref(),
            self.turn.as_mut(),
        ) {
            local.run_once_v2(
                &mut self.connection,
                stable,
                turn,
                fence,
                controller,
                launch,
                self.profile,
                open,
                challenge,
                frame,
                self.initial_six,
            );
        }
        if !self.initial.as_ref().is_some_and(|local| local.complete) {
            self.first = Some(First::Initial);
            return Err(self.closed);
        }
        self.initial_complete = Some((|| {
            let local = self
                .initial
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            let ack = *local
                .ack
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let token = self
                .turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(self.initial.take());
            token.complete_after_upper_disposal_v1();
            Ok(ack)
        })());
        if !matches!(self.initial_complete, Some(Ok(_))) {
            self.first = Some(First::InitialDisposal);
            return Err(self.closed);
        }
        drop(self.turn.take());
        Ok(())
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn receive_fresh_transfer_once_v2(
        &mut self, fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal, launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if !self.opening_complete || self.first.is_some() || self.terminal_complete
            || !matches!(self.initial_complete, Some(Ok(_)))
            || self.fresh_transfer_admission.is_some() || self.fresh_transfer.is_some()
            || self.fresh_transfer_complete.is_some() || self.turn.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let initial = *self.initial_complete.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        self.association = Some(self.require_same_pending(fence, controller, launch));
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(First::Association);
            return Err(self.closed);
        }
        self.fresh_transfer_admission = Some((|| {
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                RootDeleteClientInitialOriginalV2::fresh_transfer_demand_v2(self.profile)?)?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                Self::peer_traffic_v1(2)?)?;
            self.turn = Some(fence.prepare_preaccept_turn_v1(controller, launch,
                self.profile.lower_original_v1(), ResourceVector::ZERO)?);
            Ok(())
        })());
        if !matches!(self.fresh_transfer_admission, Some(Ok(()))) {
            self.first = Some(First::FreshTransferAdmission);
            return Err(self.closed);
        }
        self.fresh_transfer = Some(Box::new(RootDeleteClientInitialOriginalV2::new()));
        if let (Some(local), Some(stable), Some(turn)) =
            (self.fresh_transfer.as_mut(), self.stable.as_ref(), self.turn.as_mut())
        {
            local.run_read_interval_once_v2(&mut self.connection, stable, turn, fence,
                controller, launch, self.profile, open, challenge,
                ReadPurposeV2::FreshTransfer { initial });
        }
        if !self.fresh_transfer.as_ref().is_some_and(|local| local.complete) {
            self.first = Some(First::FreshTransfer);
            return Err(self.closed);
        }
        self.fresh_transfer_complete = Some((|| {
            let data = *self.fresh_transfer.as_ref()
                .and_then(|local| local.transfer.as_ref()).and_then(|r| r.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(self.fresh_transfer.take());
            token.complete_after_upper_disposal_v1();
            Ok(data)
        })());
        if !matches!(self.fresh_transfer_complete, Some(Ok(_))) {
            self.first = Some(First::FreshTransferDisposal);
            return Err(self.closed);
        }
        drop(self.turn.take());
        Ok(())
    }

    pub(crate) fn fresh_transfer_comparison_data_v2(&self)
        -> Result<&DeleteRootFreshTransferDataV2, RootDeleteClientClosedV1>
    {
        if self.first.is_some() || self.terminal_complete || self.turn.is_some() {
            return Err(self.closed);
        }
        self.fresh_transfer_complete.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)
    }
}

pub(super) fn require_cutoff(
    sample: RawPairedClockSample,
    open: DeleteRootOpenDataV2,
    cutoff: u64,
) -> Result<(), DeleteRootWireErrorV2> {
    open.authorization_clock
        .validate_later_sample(sample)
        .map_err(|_| DeleteRootWireErrorV2::Clock)?;
    if sample.boottime_nanoseconds() >= cutoff
        || sample.wall_seconds() >= open.authorization_expires
    {
        return Err(DeleteRootWireErrorV2::Clock);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn sample(wall: i64, boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            boot * 1_000_000_000,
        )
        .unwrap()
    }

    fn open() -> DeleteRootOpenDataV2 {
        // Comparison DATA only; no native/client/query original is constructed.
        DeleteRootOpenDataV2 {
            project: [3; 16],
            operation: [4; 16],
            batch: [5; 32],
            batch_bytes: 1024,
            authorization_clock: sample(100, 10),
            authorization_expires: 130,
            source_pending: [6; 64],
        }
    }

    #[test]
    fn ack_phase_uses_original_root_horizon_without_rearming_the_opening() {
        let opening = open();
        // An independent later phase may occur after the disposed five-second
        // opening, but cannot renew its original Root/authorization cutoff.
        assert!(require_cutoff(sample(106, 16), opening, 30_000_000_000).is_ok());
        assert!(require_cutoff(sample(120, 30), opening, 30_000_000_000).is_err());
        assert!(require_cutoff(sample(130, 29), opening, 30_000_000_000).is_err());
        assert!(require_cutoff(sample(99, 9), opening, 30_000_000_000).is_err());
    }
}

/// Retains DATA copied only after the actual same-D read completed all posts.
/// It grants neither signing nor desired-state acceptance.
pub(super) struct ResourceDraftReceiptV2 {
    pub(super) bytes: Vec<u8>,
    pub(super) frame: DeleteRootFreshFrameDataV2,
    pub(super) after_clock: RawPairedClockSample,
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn exchange_resource_draft_once_v2(
        &mut self, fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal, launch: &ControllerBankLaunchOriginalV1,
        owners: [DeleteBatchOwnerCutDataV2; 6], cache_nonce: [u8; 16], cache_cutoff: u64,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.exchange_resource_draft_inner_v3(fence, controller, launch, owners, cache_nonce, cache_cutoff, None)
    }

    pub(crate) fn exchange_apply_resource_draft_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let frame = self.resource_draft_complete[0].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(self.closed)?.frame;
        self.exchange_resource_draft_inner_v3(fence, controller, launch, frame.owners,
            frame.cache_nonce, frame.cache_cutoff, Some(accepted))
    }

    fn exchange_resource_draft_inner_v3(
        &mut self, fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal, launch: &ControllerBankLaunchOriginalV1,
        owners: [DeleteBatchOwnerCutDataV2; 6], cache_nonce: [u8; 16], cache_cutoff: u64,
        accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if !self.opening_complete || self.first.is_some() || self.terminal_complete
            || !matches!(self.fresh_transfer_complete, Some(Ok(_)))
            || self.resource_draft_admission[resource_slot_v3(self.resource_purpose)].is_some() || self.resource_draft[resource_slot_v3(self.resource_purpose)].is_some()
            || self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].is_some() || self.turn.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let initial = *self.initial_complete.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        self.association = Some(self.require_resource_flight_pending_v3(fence, controller, launch, accepted));
        if !matches!(self.association, Some(Ok(()))) {
            self.first.get_or_insert(First::Association);
            return Err(self.closed);
        }
        self.resource_draft_admission[resource_slot_v3(self.resource_purpose)] = Some((|| {
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                RootDeleteClientInitialOriginalV2::resource_draft_demand_for_purpose_v3(self.profile, self.resource_purpose)?)?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                Self::peer_traffic_v1(2)?)?;
            self.turn = Some(fence.prepare_preaccept_turn_v1(controller, launch,
                self.profile.lower_original_v1(), ResourceVector::ZERO)?);
            Ok(())
        })());
        if !matches!(self.resource_draft_admission[resource_slot_v3(self.resource_purpose)], Some(Ok(()))) {
            self.first = Some(First::ResourceDraftAdmission);
            return Err(self.closed);
        }
        let continuation = self.resource_read_continuation_v4()?;
        self.resource_draft[resource_slot_v3(self.resource_purpose)] = Some(Box::new(RootDeleteClientInitialOriginalV2::new()));
        if let (Some(local), Some(stable), Some(turn)) =
            (self.resource_draft[resource_slot_v3(self.resource_purpose)].as_mut(), self.stable.as_ref(), self.turn.as_mut())
        {
            local.run_read_interval_once_v2(&mut self.connection, stable, turn, fence,
                controller, launch, self.profile, open, challenge,
                ReadPurposeV2::ResourceDraft { initial, owners, cache_nonce, cache_cutoff, continuation });
        }
        if !self.resource_draft[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.complete) {
            self.first = Some(First::ResourceDraft);
            return Err(self.closed);
        }
        self.resource_draft_complete[resource_slot_v3(self.resource_purpose)] = Some((|| {
            let local = self.resource_draft[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let frame = *local.fresh_frame.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            // Only the paid passive draft bytes move out. All completed native
            // scratch physically drops before acknowledging its disposal.
            let after_clock = *local.after_clock.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let bytes = std::mem::take(&mut local.resource_bytes);
            drop(self.resource_draft[resource_slot_v3(self.resource_purpose)].take());
            token.complete_after_upper_disposal_v1();
            Ok(ResourceDraftReceiptV2 { bytes, frame, after_clock })
        })());
        if !matches!(self.resource_draft_complete[resource_slot_v3(self.resource_purpose)], Some(Ok(_))) {
            self.first = Some(First::ResourceDraftDisposal);
            return Err(self.closed);
        }
        drop(self.turn.take());
        Ok(())
    }

    pub(crate) fn resource_draft_comparison_data_v2(&self)
        -> Result<DeleteRootResourceDraftDataV2<'_>, RootDeleteClientClosedV1>
    {
        if self.first.is_some() || self.terminal_complete || self.turn.is_some() {
            return Err(self.closed);
        }
        let received = self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(self.closed)?;
        DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&received.bytes, self.resource_purpose).map_err(|_| self.closed)
    }
}


/// Retains DATA only after the actual signature-bound read and native disposal.
pub(super) struct DeletePreparatoryApprovalReceiptV3 {
    pub(super) approval: DeleteRootPreparatoryApprovalDataV3,
    pub(super) after_clock: RawPairedClockSample,
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn receive_preparatory_approval_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.receive_resource_approval_inner_v3(fence, controller, launch, None)
    }

    pub(crate) fn receive_apply_approval_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.receive_resource_approval_inner_v3(fence, controller, launch, Some(accepted))
    }

    fn receive_resource_approval_inner_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
    ) -> Result<(), RootDeleteClientClosedV1> {
        if self.first.is_some() || self.terminal_complete || self.turn.is_some()
            || self.preparatory_approval_admission[resource_slot_v3(self.resource_purpose)].is_some()
            || !matches!(self.resource_signing_complete[resource_slot_v3(self.resource_purpose)], Some(Ok(_))) {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let initial = *self.initial_complete.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let continuation = self.resource_read_continuation_v4()?;
        self.preparatory_approval_admission[resource_slot_v3(self.resource_purpose)] = Some((|| {
            let demand = RootDeleteClientInitialOriginalV2::receiving_recipe_v2(self.profile,
                DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3, 0)?;
            let bytes = std::mem::size_of::<DeletePreparatoryApprovalReceiptV3>().checked_mul(3)
                .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(),
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)?;
            fence.reserve_preaccept_additional_v1(controller, launch, self.profile.lower_original_v1(), Self::peer_traffic_v1(2)?)?;
            self.association = Some(self.require_resource_flight_pending_v3(fence, controller, launch, accepted));
            if !matches!(self.association, Some(Ok(()))) {
                self.first.get_or_insert(First::Association);
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            self.turn = Some(fence.prepare_preaccept_turn_v1(controller, launch,
                self.profile.lower_original_v1(), ResourceVector::ZERO)?);
            Ok(())
        })());
        if !matches!(self.preparatory_approval_admission[resource_slot_v3(self.resource_purpose)], Some(Ok(()))) {
            self.first.get_or_insert(First::PreparatoryApprovalAdmission);
            return Err(self.closed);
        }
        self.preparatory_approval[resource_slot_v3(self.resource_purpose)] = Some(Box::new(RootDeleteClientInitialOriginalV2::new()));
        if let (Some(local), Some(stable), Some(turn), Some(Ok(sent)), Some(Ok(received))) =
            (self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_mut(), self.stable.as_ref(), self.turn.as_mut(),
                self.resource_signing_complete[resource_slot_v3(self.resource_purpose)].as_ref(), self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref()) {
            let signed = aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::
                DeleteRootResourceSignedDataV2 { draft: &sent.draft_digest,
                    canonical_signature: sent.signed.canonical_signature() };
            local.run_read_interval_once_v2(&mut self.connection, stable, turn, fence,
                controller, launch, self.profile, open, challenge,
                ReadPurposeV2::PreparatoryApproval { initial, frame: received.frame,
                    draft_bytes: &received.bytes, signed, presign: sent.presign_clock, prior: sent.after_clock,
                    expires: sent.preparation.preparation_v2().plan_data_v1().expires_seconds(), continuation });
        }
        if !self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local| local.complete) {
            self.first.get_or_insert(First::PreparatoryApproval);
            return Err(self.closed);
        }
        self.preparatory_approval_complete[resource_slot_v3(self.resource_purpose)] = Some((|| {
            let local = self.preparatory_approval[resource_slot_v3(self.resource_purpose)].as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let approval = *local.approval.as_ref().and_then(|r| r.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            let after_clock = local.after_sample_data_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(self.preparatory_approval[resource_slot_v3(self.resource_purpose)].take());
            token.complete_after_upper_disposal_v1();
            Ok(DeletePreparatoryApprovalReceiptV3 { approval, after_clock })
        })());
        if !matches!(self.preparatory_approval_complete[resource_slot_v3(self.resource_purpose)], Some(Ok(_))) {
            self.first.get_or_insert(First::PreparatoryApprovalDisposal);
            return Err(self.closed);
        }
        drop(self.turn.take());
        Ok(())
    }
}

impl RootDeleteClientOriginalV1<'_> {
    fn resource_read_continuation_v4(&self) -> Result<Option<ResourceReadContinuationV4>, RootDeleteClientClosedV1> {
        if self.resource_purpose == DeleteResourcePurposeV3::Preparation26 { return Ok(None); }
        let frame = self.resource_draft_complete[0].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(self.closed)?.frame;
        Ok(Some(match self.resource_purpose {
            DeleteResourcePurposeV3::Apply7 => ResourceReadContinuationV4::Apply(
                *self.apply_activation.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?, frame),
            DeleteResourcePurposeV3::Network9 => ResourceReadContinuationV4::Network(
                *self.network_activation.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?, frame),
            DeleteResourcePurposeV3::Preparation26 => return Err(self.closed),
            DeleteResourcePurposeV3::MountReap62 => ResourceReadContinuationV4::Mount(
                *self.mount_activation.as_ref().and_then(|result| result.as_ref().ok()).ok_or(self.closed)?, frame),
        }))
    }
}
