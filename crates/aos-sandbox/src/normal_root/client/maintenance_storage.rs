//! Retains the actual Maintenance Storage Root child on its original fixed socket.
//!
//! The distinct subject borrows the same signed18 and protected reservation.
//! Native peer verification, fixed IO, strict chunks and bounded reply growth
//! use the common Controller-to-Root engines. No accepted Start, old opening,
//! replacement Source, currentness receipt or relative deadline is adopted.

use std::{error::Error, mem::size_of, sync::Arc};

use super::{
    NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1,
    peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1, sample::PeerSampleV1},
    resource_stream::{
        self, RootClientFundingV1, RootClientLoanV1, RootReplyPurposeV1, RootReplyReceiveV1,
        RootStreamStageV1, RootSubjectDataV1,
    },
    root_connection::ControllerRootConnectionOriginalV1,
    strict_chunk::RootStrictChunkOriginalV1,
};
use crate::controller_resource_reservation::{
    ControllerCatalogMaintenanceRootLoanV3, ResourceReservationErrorV1,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1,
    bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1},
};
use crate::Journal;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::HistoryErrorV1,
    provisioning_root::{
        maintenance_storage::{
            MaintenanceStorageAdmissionDataV2, MaintenanceStorageQueryDataV2,
            MaintenanceStorageReplyDataV2, MaintenanceStorageSubjectDataV2, QUERY_BYTES_V2,
        },
        storage_apply::ApplyRootDataErrorV1,
    },
    resource_bank::ACCOUNT_HEAD_BYTES_V1,
};

mod construction;
mod final_ack;

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the actual Maintenance Storage Root child is incomplete or refused")]
pub(crate) struct RootMaintenanceStorageClientClosedV3;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Reentry,
    Entropy,
    Metadata,
    Native,
    Model,
    Query,
    Funding,
    BeforeClock,
    BeforeTime,
    Connect,
    BeforePeer,
    Reporting,
    Send,
    Receive,
    Reply,
    AfterPeer,
    AfterClock,
    Temporal,
    Construction,
    Final,
}

pub(crate) struct RootMaintenanceStorageClientOriginalV3 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    state: Option<Box<Opening>>,
    construction_entry: Option<Result<(), Cause>>,
    construction: Option<Box<construction::Construction>>,
    transferred_request: Option<[u8; 32]>,
    final_entry: Option<Result<(), Cause>>,
    final_ack: Option<Box<final_ack::FinalAcknowledgement>>,
    complete: ResourceVector,
    observations: usize,
    wire: u64,
    output: u64,
    received_bound: usize,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    first: Option<First>,
}

struct Opening {
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    origin: RawPairedClockSample,
    original_cutoff: u64,
    cutoff: u64,
    nonce: [u8; 16],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    nonce_comparison: Option<Result<(), aos_sandbox_protocol::ProtocolValidationError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    source_position: crate::journal::CreateStorageWriterPositionOriginalV1,
    session_position: crate::journal::CreateStorageWriterPositionOriginalV1,
    native: Option<Result<(), ResourceReservationErrorV1>>,
    source_native: [u8; 64],
    session_native: [u8; 64],
    account: [u8; ACCOUNT_HEAD_BYTES_V1],
    request_body: Vec<u8>,
    model: Option<Result<(), Cause>>,
    query: Option<Result<MaintenanceStorageQueryDataV2, HistoryErrorV1>>,
    query_bytes: [u8; QUERY_BYTES_V2],
    connection: ControllerRootConnectionOriginalV1,
    connect: Option<Result<(), HistoryErrorV1>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), HistoryErrorV1>>,
    peer_before: Option<Box<PeerSampleV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    query_sender: FixedDeadlineStreamIoV1<QUERY_BYTES_V2>,
    query_sent: Option<Result<(), HistoryErrorV1>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    reply: Option<Result<MaintenanceStorageAdmissionDataV2, HistoryErrorV1>>,
    peer_after: Option<Box<PeerSampleV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    temporal: Option<Result<u64, HistoryErrorV1>>,
}

impl RootMaintenanceStorageClientOriginalV3 {
    pub(crate) fn new_v3() -> Self {
        Self {
            entry: None,
            state: None,
            construction_entry: None,
            construction: None,
            transferred_request: None,
            final_entry: None,
            final_ack: None,
            complete: ResourceVector::ZERO,
            observations: 0,
            wire: 0,
            output: 0,
            received_bound: 20,
            admission: None,
            funding_original: false,
            first: None,
        }
    }

    fn receiving_demand_v3(
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let native =
            CreateStorageRootPeerReceivingOriginalsV1::provisioning_native_peak_v1(profile)
                .ok_or_else(bad)?;
        let connection =
            ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(bad)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| bad())?;
        let (raw, files) = geometry.receive_obligations_v1();
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(bad)?;
        let request = aos_sandbox_protocol::semantics::CanonicalStorageGuestRootArgumentsV1::
            deadline_free_request_receiving_bytes_v2().ok_or_else(bad)?;
        let cells = crate::journal::CreateStorageWriterPositionOriginalV1::receiving_metadata_cells_v1(
            crate::controller_resource_reservation::HistoryRoleV1::Source)?
            .checked_add(crate::journal::CreateStorageWriterPositionOriginalV1::
                controller_storage_client_receiving_metadata_cells_v1()?)
            .and_then(|cells| cells.checked_add(1))
            .and_then(|cells| u64::try_from(cells).ok()).ok_or_else(bad)?;
        let memory = size_of::<Self>()
            .checked_add(size_of::<Opening>())
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootStrictChunkOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootClientFundingV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootReplyReceiveV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(raw))
            .and_then(|bytes| bytes.checked_add(clocks))
            .and_then(|bytes| bytes.checked_add(request))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(bad)?;
        let files = files
            .checked_add(2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(bad)?;
        Ok(native
            .checked_add(connection)?
            .checked_add(crate::journal::create_storage_name_peak_demand_v1()?)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, cells),
            )?)
    }

    pub(crate) fn begin_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        if self.entry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        self.entry = Some((|| {
            loan.require_initial_inventory_v3(controller)?;
            let (origin, cutoff) = loan.horizon_data_v3()?;
            let profile = loan.retained_profile_v3()?;
            self.complete = Self::receiving_demand_v3(&profile)?
                .checked_add(controller.create_storage_semantic_append_demand_v1()?)?;
            loan.require_complete_v3(
                controller,
                self.complete
                    .checked_add(resource_stream::peer_traffic_v1(3)?)?,
            )?;
            self.observations = 3;
            self.state = Some(Box::new(Opening::new(profile, origin, cutoff)));
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        if let Err(first) = self.open_inner(loan, controller) {
            self.first = Some(first);
        }
        // Neither an earlier body failure nor a failed first native sample
        // suppresses the separately paid peer and paired-clock destinations.
        self.finish_opening_posts();
        if self.first.is_none() {
            let state = self
                .state
                .as_mut()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            state.model = Some((|| -> Result<(), Cause> {
                let admission = positive(&state.reply)?;
                loan.narrow_returned_authority_v3(
                    controller,
                    admission.policy_expires_seconds,
                    admission.lease_expires_seconds,
                )?;
                state.cutoff = state.cutoff.min(loan.horizon_data_v3()?.1);
                Ok(())
            })());
            if !matches!(state.model, Some(Ok(()))) {
                self.first = Some(First::Model);
            }
        }
        if self.first.is_some() {
            Err(RootMaintenanceStorageClientClosedV3)
        } else {
            Ok(())
        }
    }

    fn open_inner(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
    ) -> Result<(), First> {
        let state = self.state.as_mut().ok_or(First::Entry)?;
        state.entropy = Some(rustix::rand::getrandom(
            &mut state.nonce,
            rustix::rand::GetRandomFlags::empty(),
        ));
        state.nonce_comparison = Some(
            if matches!(state.entropy, Some(Ok(16))) && state.nonce != [0; 16] {
                Ok(())
            } else {
                Err(aos_sandbox_protocol::ProtocolValidationError::InvalidField(
                    "Maintenance Root nonce",
                ))
            },
        );
        if !matches!(state.nonce_comparison, Some(Ok(()))) {
            return Err(First::Entropy);
        }
        state.metadata = Some(controller.held_native_receiving_metadata_v1().0);
        let end = state
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(First::Metadata)?
            .len();
        state.native = Some(loan.capture_source_session_native_once_v3(
            controller,
            &mut state.source_position,
            &mut state.session_position,
        ));
        if !matches!(state.native, Some(Ok(()))) {
            return Err(First::Native);
        }
        state.model = Some((|| -> Result<(), Cause> {
            state.source_native = encode_position(state.source_position.position()?);
            state.session_native = encode_position(state.session_position.position()?);
            let account: &[u8; ACCOUNT_HEAD_BYTES_V1] =
                loan.controller_account_data_v3(controller)?.try_into()?;
            state.account.copy_from_slice(account);
            state.request_body = loan
                .canonical_arguments_data_v3(controller)?
                .deadline_free_request_body_v2(state.nonce)?;
            Ok(())
        })());
        if !matches!(state.model, Some(Ok(()))) {
            return Err(First::Model);
        }
        state.query = Some((|| {
            let subject = state
                .subject(loan, controller)
                .map_err(|_| HistoryErrorV1::Malformed)?;
            let query = MaintenanceStorageQueryDataV2 {
                controller_nonce: state.nonce,
                original_boot: state.origin.host_boot_id(),
                original_boottime_ns: state.origin.boottime_nanoseconds(),
                original_cutoff_ns: state.original_cutoff,
                subject_bytes: u64::try_from(subject.encoded_bytes_v2()?)
                    .map_err(|_| HistoryErrorV1::Extent)?,
                subject_digest: subject.digest_v2()?,
                controller_next: controller.snapshot_sequence(),
                controller_end: end,
            };
            state.query_bytes = query.encode_v2()?;
            Ok(query)
        })());
        let query = *positive(&state.query).map_err(|_| First::Query)?;
        let output = usize::try_from(query.subject_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(QUERY_BYTES_V2))
            .ok_or(First::Funding)?;
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        funding
            .charge(
                &mut RootClientLoanV1::MaintenanceStorage(loan),
                controller,
                0,
                output.checked_add(20).ok_or(First::Funding)?,
                output,
            )
            .map_err(stream_stage)?;
        state.before_sample = Some(state.before_clock.observe_once(Some(state.origin)));
        let before = *positive(&state.before_sample).map_err(|_| First::BeforeClock)?;
        state.before_time = Some(require_original_sample(
            state.origin,
            state.original_cutoff,
            before,
        ));
        if !matches!(state.before_time, Some(Ok(()))) {
            return Err(First::BeforeTime);
        }
        state.connect = Some(state.connection.connect_once());
        if !matches!(state.connect, Some(Ok(()))) {
            return Err(First::Connect);
        }
        state.before = Some(
            state
                .peer_before
                .as_mut()
                .ok_or(First::BeforePeer)?
                .observe_with_cutoff_once_v1(
                    &state.profile,
                    state.connection.stream().map_err(|_| First::BeforePeer)?,
                    None,
                    None,
                    false,
                    state.cutoff,
                ),
        );
        if !matches!(state.before, Some(Ok(()))) {
            return Err(First::BeforePeer);
        }
        state.reporting = Some(
            state
                .connection
                .stream_mut()
                .map_err(|_| First::Reporting)?
                .enable_subject_reporting(),
        );
        if !matches!(state.reporting, Some(Ok(()))) {
            return Err(First::Reporting);
        }
        state.query_sent = Some(state.query_sender.run_once(
            state.connection.stream_mut().map_err(|_| First::Send)?,
            &mut state.query_bytes,
            state.cutoff,
            DeadlineStreamDirectionV1::Write,
        ));
        if !matches!(state.query_sent, Some(Ok(()))) {
            return Err(First::Send);
        }

        // Borrow the finite source fields without borrowing the disjoint native
        // sender destinations. The canonical framing and loop remain shared.
        let (inventory_request, inventory_outcome) = loan.inventory_packets_data_v3();
        let subject = MaintenanceStorageSubjectDataV2 {
            reservation: loan
                .reservation_record_data_v3(controller)
                .map_err(|_| First::Model)?,
            request_body: &state.request_body,
            inventory_request,
            inventory_outcome,
            controller_account: &state.account,
            source_native: &state.source_native,
            session_native: &state.session_native,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::MaintenanceStorage(subject),
            &mut state.connection,
            &mut state.sender,
            &mut state.sent,
            &mut state.scratch,
            &mut state.data_failure,
            state.cutoff,
        )
        .map_err(stream_stage)?;
        let mut receive = RootReplyReceiveV1 {
            connection: &mut state.connection,
            received: &mut state.received,
            preparation: &mut state.preparation,
            extension: &mut state.extension,
            chunk: &mut state.chunk,
            data_failure: &mut state.data_failure,
            peer_before: state.peer_before.as_deref().ok_or(First::Receive)?,
            profile: &state.profile,
            cutoff: state.cutoff,
        };
        receive
            .receive_reply(
                RootReplyPurposeV1::MaintenanceStorage,
                &mut RootClientLoanV1::MaintenanceStorage(loan),
                controller,
                &mut funding,
            )
            .map_err(stream_stage)?;
        state.reply = Some(
            MaintenanceStorageReplyDataV2::decode_v2(state.received.bytes())
                .and_then(|reply| MaintenanceStorageAdmissionDataV2::decode_v2(reply.admission)),
        );
        state.cutoff = state
            .cutoff
            .min(positive(&state.reply).map_err(|_| First::Reply)?.cutoff_ns);
        Ok(())
    }

    fn finish_opening_posts(&mut self) {
        let Some(state) = self.state.as_mut() else {
            return;
        };
        if let Ok(stream) = state.connection.stream() {
            state.after = Some(match state.peer_after.as_mut() {
                Some(after) => match state
                    .peer_before
                    .as_deref()
                    .filter(|_| matches!(state.before, Some(Ok(()))))
                {
                    Some(before) => after.observe_against_sample_with_cutoff_once_v1(
                        &state.profile,
                        stream,
                        before,
                        None,
                        true,
                        state.cutoff,
                    ),
                    None => after.observe_with_cutoff_once_v1(
                        &state.profile,
                        stream,
                        None,
                        None,
                        true,
                        state.cutoff,
                    ),
                },
                None => Err(NormalRootStartupErrorV1::Service),
            });
            if !matches!(state.after, Some(Ok(()))) {
                self.first.get_or_insert(First::AfterPeer);
            }
        }
        state.after_sample = Some(state.after_clock.observe_once(Some(state.origin)));
        if !matches!(state.after_sample, Some(Ok(_))) {
            self.first.get_or_insert(First::AfterClock);
        }
        if self.first.is_some() {
            return;
        }
        state.temporal = Some((|| {
            require_maintenance_temporal(
                state.origin,
                state.original_cutoff,
                *positive(&state.query)?,
                *positive(&state.reply)?,
                *positive(&state.before_sample)?,
                *positive(&state.after_sample)?,
            )
        })());
        if let Some(Ok(cutoff)) = state.temporal {
            state.cutoff = state.cutoff.min(cutoff);
        } else {
            self.first = Some(First::Temporal);
        }
        // The exact opening peer/native originals remain resident through
        // signing, real31/fresh18, final Root proof and enclosing M posts.
    }

    pub(crate) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        let first = self.first?;
        let closed = || Some(&RootMaintenanceStorageClientClosedV3 as &(dyn Error + 'static));
        if matches!(first, First::Entry) {
            return cause(&self.entry).or_else(closed);
        }
        if matches!(first, First::Reentry) {
            return closed();
        }
        if matches!(first, First::Funding) {
            return cause(&self.admission).or_else(closed);
        }
        if matches!(first, First::Construction) {
            return self.construction.as_ref().and_then(|state| state.failure())
                .or_else(|| self.construction_entry.as_ref()?.as_ref().err()
                    .map(|cause| cause.as_ref() as &(dyn Error + 'static)))
                .or_else(closed);
        }
        if matches!(first, First::Final) {
            if self.final_ack.as_ref().is_some_and(|state| state.settlement_failed_v3()) {
                let opening = self.state.as_ref()?;
                return opening.peer_before.as_ref().and_then(|peer| peer.failure())
                    .or_else(|| opening.peer_after.as_ref().and_then(|peer| peer.failure()))
                    .or_else(|| self.construction.as_ref().and_then(|state| state.failure()))
                    .or_else(|| self.final_ack.as_ref().and_then(|state| state.failure()))
                    .or_else(closed);
            }
            return self.final_ack.as_ref().and_then(|state| state.failure())
                .or_else(|| self.final_entry.as_ref()?.as_ref().err()
                    .map(|cause| cause.as_ref() as &(dyn Error + 'static)))
                .or_else(closed);
        }
        let state = self.state.as_ref()?;
        match first {
            First::Entropy => cause(&state.entropy).or_else(|| cause(&state.nonce_comparison)),
            First::Metadata => cause(&state.metadata),
            First::Native => state
                .source_position
                .failure()
                .or_else(|| state.session_position.failure())
                .or_else(|| cause(&state.native)),
            First::Model => state
                .model
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            First::Query => cause(&state.query),
            First::BeforeClock => state
                .before_clock
                .failure()
                .or_else(|| cause(&state.before_sample)),
            First::BeforeTime => cause(&state.before_time),
            First::Connect => state.connection.failure().or_else(|| cause(&state.connect)),
            First::BeforePeer => state
                .peer_before
                .as_ref()
                .and_then(|peer| peer.failure())
                .or_else(|| cause(&state.before)),
            First::Reporting => cause(&state.reporting),
            First::Send => state
                .query_sender
                .failure()
                .or_else(|| state.sender.failure())
                .or_else(|| cause(&state.query_sent))
                .or_else(|| cause(&state.sent)),
            First::Receive => state
                .chunk
                .as_ref()
                .and_then(|chunk| chunk.failure(&state.received))
                .or_else(|| state.received.failure())
                .or_else(|| cause(&state.preparation))
                .or_else(|| cause(&state.extension)),
            First::Reply => cause(&state.reply),
            First::AfterPeer => state
                .peer_after
                .as_ref()
                .and_then(|peer| peer.failure())
                .or_else(|| cause(&state.after)),
            First::AfterClock => state
                .after_clock
                .failure()
                .or_else(|| cause(&state.after_sample)),
            First::Temporal => cause(&state.temporal),
            First::Entry | First::Reentry | First::Funding | First::Construction | First::Final => None,
        }
        .or_else(|| state.data_failure.as_ref().map(|cause| cause as _))
        .or_else(closed)
    }

    pub(crate) fn has_pending_work_v3(&self) -> bool {
        // The unsigned opening never closes this child. The whole actual
        // signed31/fresh18/final acknowledgement continuation is still owed.
        self.entry.is_some() && !self.final_ack_completed_v3()
    }
}

impl Opening {
    fn new(
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        origin: RawPairedClockSample,
        cutoff: u64,
    ) -> Self {
        Self {
            profile,
            origin,
            original_cutoff: cutoff,
            cutoff,
            nonce: [0; 16],
            entropy: None,
            nonce_comparison: None,
            metadata: None,
            source_position: Default::default(),
            session_position: Default::default(),
            native: None,
            source_native: [0; 64],
            session_native: [0; 64],
            account: [0; ACCOUNT_HEAD_BYTES_V1],
            request_body: Vec::new(),
            model: None,
            query: None,
            query_bytes: [0; QUERY_BYTES_V2],
            connection: Default::default(),
            connect: None,
            before_clock: Default::default(),
            before_sample: None,
            before_time: None,
            peer_before: Some(Box::new(PeerSampleV1::new())),
            before: None,
            reporting: None,
            query_sender: Default::default(),
            query_sent: None,
            sender: Default::default(),
            sent: None,
            scratch: [0; 4096],
            data_failure: None,
            received: RetainedSubjectStreamReadV1::new(),
            preparation: None,
            extension: None,
            chunk: None,
            reply: None,
            peer_after: Some(Box::new(PeerSampleV1::new())),
            after: None,
            after_clock: Default::default(),
            after_sample: None,
            temporal: None,
        }
    }

    fn subject<'held>(
        &'held self,
        loan: &'held ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &'held Journal,
    ) -> Result<MaintenanceStorageSubjectDataV2<'held>, ResourceReservationErrorV1> {
        let (inventory_request, inventory_outcome) = loan.inventory_packets_data_v3();
        Ok(MaintenanceStorageSubjectDataV2 {
            reservation: loan.reservation_record_data_v3(controller)?,
            request_body: &self.request_body,
            inventory_request,
            inventory_outcome,
            controller_account: &self.account,
            source_native: &self.source_native,
            session_native: &self.session_native,
        })
    }
}

fn require_original_sample(
    origin: RawPairedClockSample,
    cutoff: u64,
    sample: RawPairedClockSample,
) -> Result<(), HistoryErrorV1> {
    origin
        .validate_later_sample(sample)
        .map_err(|_| HistoryErrorV1::Malformed)?;
    if sample.boottime_nanoseconds() >= cutoff {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(())
}

fn require_maintenance_temporal(
    origin: RawPairedClockSample,
    original_cutoff: u64,
    query: MaintenanceStorageQueryDataV2,
    admission: MaintenanceStorageAdmissionDataV2,
    before: RawPairedClockSample,
    after: RawPairedClockSample,
) -> Result<u64, HistoryErrorV1> {
    let bad = || HistoryErrorV1::Malformed;
    require_original_sample(origin, original_cutoff, before)?;
    before.validate_later_sample(after).map_err(|_| bad())?;
    let observed = RawPairedClockSample::new_untrusted(
        origin.provenance(),
        admission.original_boot,
        admission.observed_wall_seconds,
        admission.observed_boottime_ns,
    )
    .map_err(|_| bad())?;
    before.validate_later_sample(observed).map_err(|_| bad())?;
    observed.validate_later_sample(after).map_err(|_| bad())?;
    let policy = before
        .conservative_expiry_deadline_data_v1(admission.policy_expires_seconds)
        .ok_or_else(bad)?;
    let lease = before
        .conservative_expiry_deadline_data_v1(admission.lease_expires_seconds)
        .ok_or_else(bad)?;
    let cutoff = original_cutoff
        .min(admission.cutoff_ns)
        .min(policy)
        .min(lease);
    if admission.controller_nonce != query.controller_nonce
        || admission.query_digest != query.digest_v2()?
        || admission.original_boot != origin.host_boot_id()
        || admission.original_boottime_ns != origin.boottime_nanoseconds()
        || admission.original_cutoff_ns != original_cutoff
        || after.wall_seconds() >= admission.policy_expires_seconds
        || after.wall_seconds() >= admission.lease_expires_seconds
        || after.boottime_nanoseconds() >= cutoff
    {
        return Err(bad());
    }
    Ok(cutoff)
}

fn encode_position(
    position: crate::controller_resource_reservation::CreateStorageWriterPositionV1,
) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[..48].copy_from_slice(&position.names.to_bytes());
    bytes[48..56].copy_from_slice(&position.next.to_be_bytes());
    bytes[56..].copy_from_slice(&position.end.to_be_bytes());
    bytes
}

fn stream_stage(stage: RootStreamStageV1) -> First {
    match stage {
        RootStreamStageV1::Query => First::Query,
        RootStreamStageV1::Send => First::Send,
        RootStreamStageV1::Admission => First::Funding,
        RootStreamStageV1::Receive => First::Receive,
        RootStreamStageV1::Reply => First::Reply,
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, HistoryErrorV1> {
    value
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(HistoryErrorV1::Malformed)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod temporal_tests {
    use super::*;

    fn sample(wall: i64, boot_seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            aos_sandbox_core::RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            boot_seconds * 1_000_000_000,
        )
        .unwrap()
    }

    fn fields() -> (
        MaintenanceStorageQueryDataV2,
        MaintenanceStorageAdmissionDataV2,
    ) {
        let query = MaintenanceStorageQueryDataV2 {
            controller_nonce: [3; 16],
            original_boot: [2; 16],
            original_boottime_ns: 10_000_000_000,
            original_cutoff_ns: 20_000_000_000,
            subject_bytes: 7,
            subject_digest: [4; 32],
            controller_next: 9,
            controller_end: 10,
        };
        let admission = MaintenanceStorageAdmissionDataV2 {
            root_nonce: [5; 16],
            controller_nonce: query.controller_nonce,
            query_digest: query.digest_v2().unwrap(),
            original_boot: query.original_boot,
            original_boottime_ns: query.original_boottime_ns,
            original_cutoff_ns: query.original_cutoff_ns,
            observed_wall_seconds: 102,
            observed_boottime_ns: 12_000_000_000,
            cutoff_ns: 19_000_000_000,
            policy_expires_seconds: 150,
            lease_expires_seconds: 140,
        };
        (query, admission)
    }

    #[test]
    fn maintenance_reply_preserves_its_actual_horizon_and_both_authorities() {
        let (query, admission) = fields();
        let check = |reply| {
            require_maintenance_temporal(
                sample(100, 10),
                20_000_000_000,
                query,
                reply,
                sample(101, 11),
                sample(103, 13),
            )
        };

        assert_eq!(check(admission).unwrap(), 19_000_000_000);

        let mut changed = admission;
        changed.controller_nonce[0] ^= 1;
        assert!(check(changed).is_err());
        changed = admission;
        changed.query_digest[0] ^= 1;
        assert!(check(changed).is_err());
        changed = admission;
        changed.original_cutoff_ns += 1;
        assert!(check(changed).is_err());
        changed = admission;
        changed.lease_expires_seconds = 103;
        assert!(check(changed).is_err());
        changed = admission;
        changed.policy_expires_seconds = 103;
        assert!(check(changed).is_err());
    }

    #[test]
    fn maintenance_root_sample_must_remain_inside_the_actual_controller_pair() {
        let (query, admission) = fields();
        let check = |reply| {
            require_maintenance_temporal(
                sample(100, 10),
                20_000_000_000,
                query,
                reply,
                sample(101, 11),
                sample(103, 13),
            )
        };

        let mut changed = admission;
        changed.observed_boottime_ns = 14_000_000_000;
        assert!(check(changed).is_err());
        changed = admission;
        changed.observed_boottime_ns = 10_000_000_000;
        assert!(check(changed).is_err());
        changed = admission;
        changed.original_boot[0] ^= 1;
        assert!(check(changed).is_err());
        assert!(
            require_maintenance_temporal(
                sample(100, 10),
                20_000_000_000,
                query,
                admission,
                sample(101, 11),
                sample(100, 13)
            )
            .is_err()
        );
    }
}
