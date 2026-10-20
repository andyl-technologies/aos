//! Retains one actual fresh Start resource flight to the fixed Root service.
//!
//! This owner opens only Network Prepare. It borrows the accepted Start's own
//! native interval and verified fresh renewal; historical Create packets remain
//! comparison inputs. The live socket is never replaced after refusal. Signing,
//! actual resource execution, final proof and independently owed posts must all
//! complete on this same child before another resource purpose can begin.

mod current_turn;
mod terminal;
pub use terminal::{RootStartResourceExchangeDataV2, RootStartResourceCompletedOriginalV2};
mod diagnostics;
mod opening_purpose;
mod assignment_inputs;
use opening_purpose::{StartOpeningPurposeV2, StartOpeningLoanV2, StartOpeningQueryV2, StartOpeningAdmissionV2, initial_accepted_cutoff_v2, require_opening_sample_order_v2};
pub use assignment_inputs::RootStartAssignmentInputsClientOriginalV2;
pub use current_turn::{RootStartResourceCurrentTurnV2, RootStartResourceConstructionTurnV2, RootHostPublicationTurnKindV2};

use std::{error::Error, sync::Arc, mem::size_of};
use rand::{TryRngCore as _, rngs::OsRng};
use aos_sandbox_core::{OperationId, RawPairedClockSample, ResourceVector, ResourceDimension as D};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::{resource_bank::ACCOUNT_HEAD_BYTES_V1,
    create_storage_history::{HistoryErrorV1, continuation::ContinuationKindV1,
        outcome::ROOT_CLOSED_RECEIPT_BYTES_V1},
    provisioning_root::{storage_apply::ApplyRootDataErrorV1, host_launch::{
        HostLaunchQueryDataV1, HostLaunchSubjectDataV1, HostResourceReplyDataV1,
        HostResourceAdmissionDataV1, HostResourcePurposeDataV1, QUERY_BYTES_V1}},
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use crate::{Journal, OriginalStartHostRootLoanV1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    bounded_stream_io::{FixedDeadlineStreamIoV1, DeadlineStreamDirectionV1}};
use super::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1,
    root_connection::ControllerRootConnectionOriginalV1, strict_chunk::RootStrictChunkOriginalV1,
    peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1, StableRootPeerV1,
        sample::PeerSampleV1}, resource_stream::{self, RootClientFundingV1,
        RootClientLoanV1, RootSubjectDataV1, RootReplyPurposeV1, RootReplyReceiveV1,
        RootStreamStageV1}};

/// Reports an unfinished or refused genuine Start resource Root child.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Start Root resource flight is incomplete or refused")]
pub struct RootHostLaunchClientClosedV1;

#[derive(Clone, Copy)]
enum First { Entry, Reentry, Nonce, Metadata, Input, Query, BeforeClock, Temporal,
    Connect, Before, Reporting, Send, RequestEnd, Admission, Receive, Reply, ReplyEof, After, AfterClock,
    Settlement, ControllerAfter, Preparation }

/// Retains the only native Root child for one resource of the accepted Start.
#[doc(hidden)]
#[must_use = "retain the actual resource flight through final proof and disposal"]
pub struct RootHostLaunchClientOriginalV1 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    entry_context: Option<Result<(RawPairedClockSample, u64, i64), ResourceReservationErrorV1>>,
    state: Option<Box<OpeningV1>>,
    first: Option<First>,
    outer_after: Option<Result<(), ResourceReservationErrorV1>>,
    complete: ResourceVector,
    observations: usize,
    wire: u64,
    output: u64,
    received_bound: usize,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    terminal_complete: bool,
    terminal_entry: Option<Result<(), ResourceReservationErrorV1>>,
    terminal_complete_demand: Option<ResourceVector>,
    terminal: Option<Box<terminal::ResourceTerminalOriginalV2>>,
    completed_resource: Option<Box<RootStartResourceCompletedOriginalV2>>,
    preparation_binding: Option<Result<(), ResourceReservationErrorV1>>,
    turns: current_turn::ResourceTurnsV2,
    next_refusal: Option<Box<super::peer_receiving::refusal::RootPeerRefusalOriginalV1>>,
}

struct OpeningV1 {
    parent: OperationId,
    purpose: StartOpeningPurposeV2,
    native_turn: u64,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    origin: RawPairedClockSample,
    original_cutoff: u64,
    accepted_expiry: i64,
    cutoff: u64,
    signed_plan_expires: Option<i64>,
    connection: ControllerRootConnectionOriginalV1,
    nonce: [u8; 16],
    entropy: Option<Result<(), rand::rand_core::OsError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    input: Option<Result<(), ResourceReservationErrorV1>>,
    query: Option<Result<StartOpeningQueryV2, HistoryErrorV1>>,
    query_encoding: Option<Result<(), HistoryErrorV1>>,
    query_bytes: [u8; QUERY_BYTES_V1],
    request_body: Vec<u8>,
    request_growth: Option<Result<(), std::collections::TryReserveError>>,
    controller_head: [u8; ACCOUNT_HEAD_BYTES_V1],
    root_closed: [u8; ROOT_CLOSED_RECEIPT_BYTES_V1],
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    temporal: Option<Result<u64, HistoryErrorV1>>,
    connect: Option<Result<(), HistoryErrorV1>>,
    peer_before: Option<Box<PeerSampleV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    query_sender: FixedDeadlineStreamIoV1<QUERY_BYTES_V1>,
    query_sent: Option<Result<(), HistoryErrorV1>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    request_end: Option<Result<(), rustix::io::Errno>>,
    reply_eof: FixedDeadlineStreamIoV1<1>,
    reply_eof_byte: [u8; 1],
    reply_ended: Option<Result<(), HistoryErrorV1>>,
    scratch: [u8; 4096],
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    data_failure: Option<ApplyRootDataErrorV1>,
    reply: Option<Result<StartOpeningAdmissionV2, HistoryErrorV1>>,
    peer_after: Option<Box<PeerSampleV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    stable: Option<StableRootPeerV1>,
}

impl RootHostLaunchClientOriginalV1 {
    pub(super) fn selected_resource_purpose_v2(&self)
        -> Result<HostResourcePurposeDataV1, RootHostLaunchClientClosedV1> {
        match self.state.as_ref().map(|state| state.purpose) {
            Some(StartOpeningPurposeV2::Network) => Ok(HostResourcePurposeDataV1::NetworkPrepare),
            Some(StartOpeningPurposeV2::Storage) => Ok(HostResourcePurposeDataV1::StorageGuestRoot),
            Some(StartOpeningPurposeV2::Mount) => Ok(HostResourcePurposeDataV1::MountNamespace),
            Some(StartOpeningPurposeV2::Host) => Ok(HostResourcePurposeDataV1::HostLaunch),
            Some(StartOpeningPurposeV2::AssignmentInputs) | None => Err(CLOSED),
        }
    }

    /// Constructs only an inert destination with no native owner or grant.
    #[must_use]
    pub fn new() -> Self {
        Self {entry: None, entry_context: None, state: None, first: None, outer_after: None,
            complete: ResourceVector::ZERO, observations: 0, wire: 0, output: 0,
            received_bound: 20, admission: None, funding_original: false,
            terminal_complete: false, terminal_entry: None, terminal_complete_demand: None,
            terminal: None, completed_resource: None,
            preparation_binding: None, turns: Default::default(), next_refusal: None}
    }

    /// Binds the actual completed signed preparation before Session acquisition.
    ///
    /// # Errors
    /// Retains foreign parent/reply/native turn, incomplete construction or
    /// repeated binding without accepting caller-selected expiry DATA.
    #[doc(hidden)]
    pub fn bind_network_preparation_once_v2(&mut self,
        prepared: &crate::PreparedStartResourceRequestOriginalV2,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_network_purpose_v2()?;
        self.bind_resource_preparation_once_v2(prepared, entry, controller)
    }

    pub(crate) fn bind_resource_preparation_once_v2(&mut self,
        prepared: &crate::PreparedStartResourceRequestOriginalV2,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(prepared.purpose_data_v2())?;
        if self.preparation_binding.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.preparation_binding = Some((|| {
            let (parent, digest, native_turn, expires) = prepared.completed_root_binding_v2()?;
            self.require_completed_resource_construction_v2(entry, controller, prepared.purpose_data_v2(), parent, digest, native_turn)?;
            self.state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?.signed_plan_expires = Some(expires);
            Ok(())
        })());
        if !matches!(self.preparation_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::Preparation);
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(crate) fn fixed_receiving_demand_v1(profile: &ProductionControllerNormalRootProfileV1)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        let bad = || ResourceReservationErrorV1::Conflict;
        let native = CreateStorageRootPeerReceivingOriginalsV1::provisioning_native_peak_v1(profile)
            .ok_or_else(bad)?;
        let connection = ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(bad)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| bad())?;
        let (raw, files) = geometry.receive_obligations_v1();
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(3)).ok_or_else(bad)?;
        let readiness = crate::policy_compiler::RootSubjectReadinessV1::receiving_construction_bytes_v1()
            .ok_or_else(bad)?;
        let memory = size_of::<Self>().checked_add(size_of::<OpeningV1>())
            .and_then(|n| n.checked_add(size_of::<opening_purpose::OpeningTemporalFieldsV2>()))
            .and_then(|n| n.checked_add(size_of::<opening_purpose::StartOpeningLoanV2<'static, 'static, 'static>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(assignment_inputs::completion_construction_bytes_v2()?))
            .and_then(|n| n.checked_add(size_of::<RootStrictChunkOriginalV1>()))
            .and_then(|n| n.checked_add(size_of::<super::peer_receiving::refusal::RootPeerRefusalOriginalV1>()))
            .and_then(|n| n.checked_add(size_of::<RootClientFundingV1<'_>>()))
            .and_then(|n| n.checked_add(size_of::<RootReplyReceiveV1<'_>>()))
            .and_then(|n| n.checked_add(diagnostics::receiving_bytes_v2()?))
            .and_then(|n| n.checked_add(raw)).and_then(|n| n.checked_add(clocks))
            .and_then(|n| n.checked_mul(2)).and_then(|n| u64::try_from(n).ok())
            .and_then(|n| n.checked_add(readiness)).ok_or_else(bad)?;
        let files = files.checked_add(3 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
        Ok(native.checked_add(connection)?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, memory).with(D::OpenFiles, files)
            .with(D::Pids, u64::try_from(CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1())
                .map_err(|_| bad())?))?)
    }

    /// Opens only the genuine accepted Start's Network resource Root child.
    ///
    /// The actual original loan prepays both independent native samples before
    /// any allocation, entropy, metadata, socket or clock observation. A failed
    /// debit leaves the complete result inline and enters no Root native work.
    ///
    /// # Errors
    /// Retains reentry, changed genuine originals, financial/native/transport,
    /// framing, temporal or independently owed post failure on this same owner.
    #[doc(hidden)]
    pub fn begin_network_prepare_once_v1(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1,
        request_body: &[u8],
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_prepare_once_v2(HostResourcePurposeDataV1::NetworkPrepare,
            loan, controller, ready, preparation, request_body)
    }

    /// Opens only the genuine final Host resource on this original Root connection.
    ///
    /// # Errors
    /// Refuses changed current Start/Source, lease, funding or native transport.
    #[doc(hidden)]
    pub fn begin_host_prepare_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1, request_body: &[u8],
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.begin_resource_prepare_once_v2(HostResourcePurposeDataV1::HostLaunch,
            loan, controller, ready, preparation, request_body)
    }

    pub(crate) fn begin_resource_prepare_once_v2(&mut self,
        purpose: HostResourcePurposeDataV1,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1, request_body: &[u8],
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let selected = match purpose {
            HostResourcePurposeDataV1::NetworkPrepare => StartOpeningPurposeV2::Network,
            HostResourcePurposeDataV1::StorageGuestRoot => StartOpeningPurposeV2::Storage,
            HostResourcePurposeDataV1::MountNamespace => StartOpeningPurposeV2::Mount,
            HostResourcePurposeDataV1::HostLaunch => StartOpeningPurposeV2::Host,
        };
        self.begin_opening_once_v2(selected, StartOpeningLoanV2::Resource(loan),
            controller, ready, preparation, request_body)
    }

    fn begin_opening_once_v2(&mut self, purpose: StartOpeningPurposeV2,
        mut loan: StartOpeningLoanV2<'_, '_, '_>, controller: &Journal,
        ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1, request_body: &[u8],
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        if self.entry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(RootHostLaunchClientClosedV1);
        }
        self.entry = Some((|| {
            loan.require_inputs_v2(purpose, controller, ready, preparation)?;
            if (purpose != StartOpeningPurposeV2::AssignmentInputs && request_body.is_empty())
                || request_body.len() > aos_sandbox_broker_session_protocol::projection::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.entry_context = Some((|| {
                let (origin, cutoff) = loan.horizon_v2();
                Ok((origin, cutoff, loan.expiry_v2()?))
            })());
            self.entry_context.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let request_memory = u64::try_from(request_body.len()).ok()
                .and_then(|n| n.checked_mul(2)).ok_or(ResourceReservationErrorV1::Conflict)?;
            self.complete = Self::fixed_receiving_demand_v1(loan.profile_v2())?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, request_memory))?;
            loan.complete_v2(controller,
                self.complete.checked_add(resource_stream::peer_traffic_v1(3)?)?)
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(RootHostLaunchClientClosedV1);
        }
        self.observations = 3;
        self.next_refusal = Some(Box::new(super::peer_receiving::refusal::RootPeerRefusalOriginalV1::new()));
        let Some(Ok((origin, original_cutoff, accepted_expiry))) = self.entry_context else {
            self.first = Some(First::Entry);
            return Err(RootHostLaunchClientClosedV1);
        };
        self.state = Some(Box::new(OpeningV1::new(loan.parent_v2(), purpose,
            loan.retained_profile_v2(), origin, original_cutoff, accepted_expiry, loan.turn_v2())));
        let returned = self.open_inner(&mut loan, controller, ready, preparation, request_body);
        if let Err(first) = returned { self.first = Some(first); }
        self.finish_opening_posts(&loan);
        if self.first.is_some() { Err(RootHostLaunchClientClosedV1) } else { Ok(()) }
    }

    fn open_inner(&mut self, loan: &mut StartOpeningLoanV2<'_, '_, '_>, controller: &Journal,
        ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1, request_body: &[u8],
    ) -> Result<(), First> {
        let state = self.state.as_mut().ok_or(First::Input)?;
        state.request_growth = Some(state.request_body.try_reserve_exact(request_body.len()));
        if !matches!(state.request_growth, Some(Ok(()))) { return Err(First::Input); }
        state.request_body.extend_from_slice(request_body);
        state.entropy = Some(OsRng.try_fill_bytes(&mut state.nonce));
        if !matches!(state.entropy, Some(Ok(()))) || state.nonce == [0; 16] { return Err(First::Nonce); }
        let (metadata, _) = controller.held_native_receiving_metadata_v1();
        state.metadata = Some(metadata);
        let end = state.metadata.as_ref().and_then(|value| value.as_ref().ok()).ok_or(First::Metadata)?.len();
        state.input = Some((|| {
            let head: &[u8; ACCOUNT_HEAD_BYTES_V1] = loan.account_v2(controller)?
                .try_into().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            state.controller_head.copy_from_slice(head);
            let lane = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1::borrow_field_framing_data_v1(ready)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?.lane;
            loan.original_create_v2().root_closed_receipt_v1()?.encode_into(lane,
                ContinuationKindV1::Closed, &mut state.root_closed)
                .map_err(|_| ResourceReservationErrorV1::Conflict)
        })());
        if !matches!(state.input, Some(Ok(()))) { return Err(First::Input); }
        let parent = state.parent.into_bytes();
        let subject = loan.subject_v2(controller, state.purpose, ready, preparation, &state.request_body,
            &parent, &state.root_closed, &state.controller_head).map_err(|_| First::Input)?;
        state.query = Some((|| {
            let subject_bytes = u64::try_from(subject.encoded_bytes_v2()?).map_err(|_| HistoryErrorV1::Extent)?;
            let subject_digest = subject.digest_v2()?;
            Ok(match state.purpose {
                StartOpeningPurposeV2::AssignmentInputs => StartOpeningQueryV2::AssignmentInputs(
                    aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::StartAssignmentInputsQueryDataV2 {
                        controller_nonce: state.nonce, original_boot: state.origin.host_boot_id(),
                        original_boottime_ns: state.origin.boottime_nanoseconds(), original_cutoff_ns: state.original_cutoff,
                        subject_bytes, subject_digest, controller_next: controller.snapshot_sequence(), controller_end: end,
                    }),
                _ => StartOpeningQueryV2::Resource(HostLaunchQueryDataV1 {
                    controller_nonce: state.nonce, original_boot: state.origin.host_boot_id(),
                    original_boottime_ns: state.origin.boottime_nanoseconds(), original_cutoff_ns: state.original_cutoff,
                    subject_bytes, subject_digest, controller_next: controller.snapshot_sequence(), controller_end: end,
                }),
            })
        })());
        let query = *positive(&state.query).map_err(|_| First::Query)?;
        state.query_encoding = Some(query.encode_v2().map(|bytes| state.query_bytes = bytes));
        if !matches!(state.query_encoding, Some(Ok(()))) { return Err(First::Query); }
        let output = usize::try_from(query.subject_bytes_v2()).ok().and_then(|n| n.checked_add(QUERY_BYTES_V1))
            .ok_or(First::Admission)?;
        let mut funding = RootClientFundingV1 {complete: self.complete, observations: &mut self.observations,
            wire: &mut self.wire, output: &mut self.output, received_bound: &mut self.received_bound,
            admission: &mut self.admission, funding_original: &mut self.funding_original};
        funding.charge(&mut loan.funding_v2(), controller, 0,
            output.checked_add(if state.purpose == StartOpeningPurposeV2::AssignmentInputs { 21 } else { 20 })
                .ok_or(First::Admission)?, output).map_err(stream_stage)?;
        state.before_sample = Some(state.before_clock.observe_once(Some(state.origin)));
        let before = *state.before_sample.as_ref().and_then(|value| value.as_ref().ok()).ok_or(First::BeforeClock)?;
        state.temporal = Some(loan.initial_cutoff_v2(state.origin, state.original_cutoff, state.accepted_expiry, before));
        state.cutoff = *positive(&state.temporal).map_err(|_| First::Temporal)?;
        state.connect = Some(state.connection.connect_once());
        if !matches!(state.connect, Some(Ok(()))) { return Err(First::Connect); }
        state.before = Some(state.peer_before.as_mut().ok_or(First::Before)?
            .observe_with_cutoff_once_v1(&state.profile, state.connection.stream().map_err(|_| First::Before)?,
                None, None, false, state.cutoff));
        if !matches!(state.before, Some(Ok(()))) { return Err(First::Before); }
        state.reporting = Some(state.connection.stream_mut().map_err(|_| First::Reporting)?.enable_subject_reporting());
        if !matches!(state.reporting, Some(Ok(()))) { return Err(First::Reporting); }
        state.query_sent = Some(state.query_sender.run_once(state.connection.stream_mut().map_err(|_| First::Send)?,
            &mut state.query_bytes, state.cutoff, DeadlineStreamDirectionV1::Write));
        if !matches!(state.query_sent, Some(Ok(()))) { return Err(First::Send); }
        // Reborrow the genuine input fields only after mutable funding ended.
        let subject = loan.subject_v2(controller, state.purpose, ready, preparation, &state.request_body,
            &parent, &state.root_closed, &state.controller_head).map_err(|_| First::Input)?;
        resource_stream::send_subject_v1(subject.stream_v2(), &mut state.connection,
            &mut state.sender, &mut state.sent, &mut state.scratch, &mut state.data_failure,
            state.cutoff).map_err(stream_stage)?;
        if state.purpose == StartOpeningPurposeV2::AssignmentInputs {
            state.request_end = Some(rustix::net::shutdown(
                state.connection.stream().map_err(|_| First::RequestEnd)?.as_fd(),
                rustix::net::Shutdown::Write,
            ));
            if !matches!(state.request_end, Some(Ok(()))) { return Err(First::RequestEnd); }
        }
        let mut receive = RootReplyReceiveV1 {connection: &mut state.connection, received: &mut state.received,
            preparation: &mut state.preparation, extension: &mut state.extension, chunk: &mut state.chunk,
            data_failure: &mut state.data_failure,
            peer_before: state.peer_before.as_deref().ok_or(First::Receive)?,
            profile: state.profile.as_ref(), cutoff: state.cutoff};
        receive.receive_reply(state.purpose.reply_v2(), &mut loan.funding_v2(),
            controller, &mut funding).map_err(stream_stage)?;
        state.reply = Some(StartOpeningAdmissionV2::decode_v2(state.purpose, state.received.bytes()));
        state.cutoff = state.cutoff.min(positive(&state.reply).map_err(|_| First::Reply)?.cutoff_v2());
        if state.purpose == StartOpeningPurposeV2::AssignmentInputs {
            state.reply_ended = Some(state.reply_eof.run_once(
                state.connection.stream_mut().map_err(|_| First::ReplyEof)?,
                &mut state.reply_eof_byte, state.cutoff, DeadlineStreamDirectionV1::Eof,
            ));
            if !matches!(state.reply_ended, Some(Ok(()))) || !state.reply_eof.completed_exact() {
                return Err(First::ReplyEof);
            }
        }
        Ok(())
    }

    fn finish_opening_posts(&mut self, loan: &StartOpeningLoanV2<'_, '_, '_>) {
        let Some(state) = self.state.as_mut() else { return; };
        if let Ok(stream) = state.connection.stream() {
            state.after = Some(match state.peer_after.as_mut() {
                Some(after) => match state.peer_before.as_deref().filter(|_| matches!(state.before, Some(Ok(())))) {
                    Some(before) => after.observe_against_sample_with_cutoff_once_v1(&state.profile,
                        stream, before, None, true, state.cutoff),
                    None => after.observe_with_cutoff_once_v1(&state.profile, stream, None, None, true, state.cutoff),
                },
                None => Err(NormalRootStartupErrorV1::Service),
            });
            if !matches!(state.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        }
        state.after_sample = Some(state.after_clock.observe_once(Some(state.origin)));
        if !matches!(state.after_sample, Some(Ok(_))) { self.first.get_or_insert(First::AfterClock); }
        if self.first.is_some() { return; }
        state.temporal = Some((|| {
            loan.require_temporal_v2(state.origin, state.original_cutoff, state.accepted_expiry,
                *positive(&state.query)?, *positive(&state.reply)?,
                *state.before_sample.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryErrorV1::Malformed)?,
                *state.after_sample.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryErrorV1::Malformed)?)
        })());
        let Some(Ok(cutoff)) = state.temporal else { self.first = Some(First::Temporal); return; };
        state.cutoff = state.cutoff.min(cutoff);
        state.settlement = Some((|| {
            let before = state.peer_before.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
            before.settle_positive_once()?;
            state.peer_after.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.settle_positive_once()?;
            state.stable = before.take_initial_binding();
            if state.stable.is_none() { return Err(NormalRootStartupErrorV1::Service); }
            Ok(())
        })());
        if matches!(state.settlement, Some(Ok(()))) {
            drop(state.peer_before.take());
            drop(state.peer_after.take());
        } else { self.first = Some(First::Settlement); }
    }

    pub(crate) fn opening_peer_traffic_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        resource_stream::peer_traffic_v1(3)
    }

    pub(crate) fn selected_original_failure_v1(&self) -> bool {
        matches!(self.first, Some(First::Entry | First::ControllerAfter))
            || matches!(self.first, Some(First::Admission)) && self.funding_original
            || self.first.is_none() && self.turns.original_failure_is_selected_v2()
    }

    pub(crate) fn retain_controller_after_from_entry_v1(&mut self,
        returned: Option<&Result<(), ResourceReservationErrorV1>>,
    ) {
        if self.entry.is_none() { return; }
        if self.outer_after.is_some() { std::process::abort(); }
        self.outer_after = Some(match returned {
            Some(Ok(())) => Ok(()),
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.outer_after, Some(Ok(()))) { self.first.get_or_insert(First::ControllerAfter); }
    }

    /// Borrows genuine unsigned Network admission while the same Start is current.
    ///
    /// # Errors
    /// Refuses any earlier failure, incomplete C/Root posts, changed actual Start,
    /// current native owner/profile, or malformed retained unsigned reply.
    #[doc(hidden)]
    pub fn borrow_network_prepare_admission_v1<'a, 'turn, 'intake>(&'a self,
        loan: &OriginalStartHostRootLoanV1<'turn, 'intake>, controller: &Journal,
    ) -> Result<RootStartResourcePrepareAdmissionOriginalV2<'a>, RootHostLaunchClientClosedV1>
    where 'turn: 'a {
        self.borrow_resource_prepare_admission_v2(HostResourcePurposeDataV1::NetworkPrepare, loan, controller)
    }

    pub(crate) fn borrow_resource_prepare_admission_v2<'a, 'turn, 'intake>(&'a self, purpose: HostResourcePurposeDataV1,
        loan: &OriginalStartHostRootLoanV1<'turn, 'intake>, controller: &Journal,
    ) -> Result<RootStartResourcePrepareAdmissionOriginalV2<'a>, RootHostLaunchClientClosedV1>
    where 'turn: 'a {
        self.require_resource_purpose_v2(purpose)?;
        let state = self.state.as_ref().ok_or(RootHostLaunchClientClosedV1)?;
        if self.first.is_some() || !matches!(self.outer_after, Some(Ok(())))
            || state.purpose == StartOpeningPurposeV2::AssignmentInputs || state.stable.is_none() || state.parent != loan.parent_operation_v1()
            || !std::ptr::eq(state.profile.as_ref(), loan.profile_v1()) {
            return Err(RootHostLaunchClientClosedV1);
        }
        loan.require_current_v1(controller).map_err(|_| RootHostLaunchClientClosedV1)?;
        Ok(RootStartResourcePrepareAdmissionOriginalV2 {client: self, parent: state.parent,
            lease: loan.fresh_ownership_lease_v1().map_err(|_| RootHostLaunchClientClosedV1)?})
    }

    /// Borrows the chronological retained cause, preserving source originals.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let Some(first) = self.first else {
            return cause(&self.terminal_entry)
                .or_else(|| self.terminal.as_deref().and_then(|terminal| terminal.failure_with_admission(&self.admission)))
                .or_else(|| self.turns.failure());
        };
        if matches!(first, First::Entry) { return cause(&self.entry_context).or_else(|| cause(&self.entry)).or(Some(&CLOSED as &(dyn Error + 'static))); }
        if matches!(first, First::ControllerAfter) { return cause(&self.outer_after).or(Some(&CLOSED)); }
        if matches!(first, First::Admission) { return cause(&self.admission).or(Some(&CLOSED)); }
        let Some(state) = self.state.as_ref() else { return Some(&CLOSED); };
        match first {
            First::Preparation => cause(&self.preparation_binding),
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
            First::Nonce => cause(&state.entropy),
            First::Metadata => cause(&state.metadata),
            First::Input => cause(&state.request_growth).or_else(|| cause(&state.input)),
            First::Query => cause(&state.query).or_else(|| cause(&state.query_encoding)).or_else(|| state.data_failure.as_ref().map(|e| e as _)),
            First::BeforeClock => state.before_clock.failure().or_else(|| cause(&state.before_sample)),
            First::Temporal => cause(&state.temporal),
            First::Connect => state.connection.failure().or_else(|| cause(&state.connect)),
            First::Before => state.peer_before.as_deref().and_then(PeerSampleV1::failure).or_else(|| cause(&state.before)),
            First::Reporting => cause(&state.reporting),
            First::RequestEnd => cause(&state.request_end),
            First::ReplyEof => state.reply_eof.failure().or_else(|| cause(&state.reply_ended)),
            First::Send => state.query_sender.failure().or_else(|| state.sender.failure()).or_else(|| cause(&state.query_sent)).or_else(|| cause(&state.sent)),
            First::Receive => state.chunk.as_ref().and_then(|chunk| chunk.failure(&state.received))
                .or_else(|| state.received.failure()).or_else(|| cause(&state.preparation)).or_else(|| cause(&state.extension)),
            First::Reply => state.data_failure.as_ref().map(|e| e as _).or_else(|| cause(&state.reply)),
            First::After => state.peer_after.as_deref().and_then(PeerSampleV1::failure).or_else(|| cause(&state.after)),
            First::AfterClock => state.after_clock.failure().or_else(|| cause(&state.after_sample)),
            First::Settlement => state.peer_before.as_deref().and_then(PeerSampleV1::failure)
                .or_else(|| state.peer_after.as_deref().and_then(PeerSampleV1::failure)).or_else(|| cause(&state.settlement)),
            First::Entry | First::Admission | First::ControllerAfter => None,
        }.or(Some(&CLOSED))
    }
}

impl OpeningV1 {
    fn new(parent: OperationId, purpose: StartOpeningPurposeV2, profile: Arc<ProductionControllerNormalRootProfileV1>,
        origin: RawPairedClockSample, cutoff: u64, accepted_expiry: i64, native_turn: u64,
    ) -> Self {
        Self {parent, purpose, native_turn, profile, origin, original_cutoff: cutoff, accepted_expiry, cutoff, signed_plan_expires: None,
            connection: Default::default(), nonce: [0; 16], entropy: None, metadata: None, input: None,
            query: None, query_encoding: None, query_bytes: [0; QUERY_BYTES_V1],
            request_body: Vec::new(), request_growth: None,
            controller_head: [0; ACCOUNT_HEAD_BYTES_V1], root_closed: [0; ROOT_CLOSED_RECEIPT_BYTES_V1],
            before_clock: Default::default(), before_sample: None, temporal: None, connect: None,
            peer_before: Some(Box::new(PeerSampleV1::new())), before: None, reporting: None,
            query_sender: Default::default(), query_sent: None, sender: Default::default(), sent: None,
            request_end: None, reply_eof: Default::default(), reply_eof_byte: [0; 1], reply_ended: None,
            scratch: [0; 4096], received: Default::default(), preparation: None, extension: None,
            chunk: None, data_failure: None, reply: None, peer_after: Some(Box::new(PeerSampleV1::new())),
            after: None, after_clock: Default::default(), after_sample: None, settlement: None, stable: None}
    }
}

/// Borrows only the actual reply and freshly verified lease of this Root child.
#[doc(hidden)]
pub struct RootStartResourcePrepareAdmissionOriginalV2<'flight> {
    client: &'flight RootHostLaunchClientOriginalV1,
    parent: OperationId,
    lease: &'flight SignedOwnershipLease,
}

impl RootStartResourcePrepareAdmissionOriginalV2<'_> {
    pub(crate) fn purpose_data_v2(&self) -> Result<HostResourcePurposeDataV1, ResourceReservationErrorV1> {
        let state = self.client.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        match state.purpose {
            StartOpeningPurposeV2::Network => Ok(HostResourcePurposeDataV1::NetworkPrepare),
            StartOpeningPurposeV2::Mount => Ok(HostResourcePurposeDataV1::MountNamespace),
            StartOpeningPurposeV2::Storage => Ok(HostResourcePurposeDataV1::StorageGuestRoot),
            StartOpeningPurposeV2::Host => Ok(HostResourcePurposeDataV1::HostLaunch),
            StartOpeningPurposeV2::AssignmentInputs => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Borrows the exact retained canonical unsigned plan and signing statement.
    ///
    /// # Errors
    /// Refuses an incomplete child or malformed retained reply framing.
    pub fn reply_v1(&self) -> Result<HostResourceReplyDataV1<'_>, RootHostLaunchClientClosedV1> {
        HostResourceReplyDataV1::decode_v1(self.client.state.as_ref()
            .ok_or(RootHostLaunchClientClosedV1)?.received.bytes()).map_err(|_| RootHostLaunchClientClosedV1)
    }

    /// Borrows the exact deadline-free request sent on this same Root socket.
    ///
    /// # Errors
    /// Refuses a missing retained opening destination.
    pub fn request_body_v1(&self) -> Result<&[u8], RootHostLaunchClientClosedV1> {
        Ok(&self.client.state.as_ref().ok_or(RootHostLaunchClientClosedV1)?.request_body)
    }

    /// Borrows the genuine current authority's verified fresh renewal.
    #[must_use]
    pub fn lease_v1(&self) -> &SignedOwnershipLease { self.lease }

    /// Returns the exact accepted Start operation retained by the actual flight.
    #[must_use]
    pub fn parent_operation_v1(&self) -> OperationId {
        self.parent
    }
}

fn subject_v1<'held>(loan: &'held OriginalStartHostRootLoanV1<'_, '_>, controller: &'held Journal,
    ready: &'held [u8], preparation: &'held AuthenticatedBrokerMethodOutcomeV1,
    request_body: &'held [u8], parent: &'held [u8; 16], root_closed: &'held [u8], head: &'held [u8],
    purpose: &'static [u8; 1],
) -> Result<HostLaunchSubjectDataV1<'held>, ResourceReservationErrorV1> {
    let lease = loan.fresh_ownership_lease_v1()?;
    let accepted_start = controller.get(crate::RecordNamespace::Operation, parent)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    Ok(HostLaunchSubjectDataV1 {start_operation: parent,
        purpose, request_body,
        ownership_claim: loan.fresh_ownership_claim_v1()?.canonical_bytes(),
        ownership_lease: lease.canonical_lease(), ownership_signature: lease.canonical_signature(),
        ownership_receipt: lease.canonical_receipt(), ownership_receipt_signature: lease.canonical_receipt_signature(),
        accepted_start, ready, prepare_request: preparation.request().canonical_packet(),
        prepare_outcome: preparation.canonical_packet(), root_closed, controller_account: head})
}

fn initial_cutoff_v1(origin: RawPairedClockSample, original_cutoff: u64,
    accepted_expiry: i64, before: RawPairedClockSample, lease: &SignedOwnershipLease,
) -> Result<u64, HistoryErrorV1> {
    let accepted = initial_accepted_cutoff_v2(origin, original_cutoff, accepted_expiry, before)?;
    let lease_deadline = before.conservative_lease_expiry_deadline_data_v2(
        lease.authority_expires_seconds(), lease.maximum_clock_skew_seconds())
        .map_err(|_| HistoryErrorV1::Malformed)?;
    let cutoff = original_cutoff.min(accepted).min(lease_deadline);
    if before.wall_seconds() < lease.authority_issued_seconds() || before.boottime_nanoseconds() >= cutoff {
        return Err(HistoryErrorV1::Malformed);
    }
    Ok(cutoff)
}

fn require_temporal_v1(origin: RawPairedClockSample, original_cutoff: u64, accepted_expiry: i64,
    query: HostLaunchQueryDataV1, admission: HostResourceAdmissionDataV1,
    before: RawPairedClockSample, after: RawPairedClockSample, lease: &SignedOwnershipLease,
) -> Result<u64, HistoryErrorV1> {
    let bad = || HistoryErrorV1::Malformed;
    let initial = initial_cutoff_v1(origin, original_cutoff, accepted_expiry, before, lease)?;
    let cutoff = require_opening_sample_order_v2(origin, original_cutoff, accepted_expiry,
        query.controller_nonce, query.digest_v1()?, admission.into(), before, after, initial)?;
    if admission.lease_expires_seconds != lease.authority_expires_seconds()
        || after.wall_seconds() >= lease.authority_expires_seconds() {
        return Err(bad());
    }
    Ok(cutoff)
}

fn stream_stage(stage: RootStreamStageV1) -> First {
    match stage {RootStreamStageV1::Query => First::Query, RootStreamStageV1::Send => First::Send,
        RootStreamStageV1::Admission => First::Admission, RootStreamStageV1::Receive => First::Receive,
        RootStreamStageV1::Reply => First::Reply}
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, HistoryErrorV1> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryErrorV1::Malformed)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl Default for RootHostLaunchClientOriginalV1 { fn default() -> Self { Self::new() } }

impl Drop for RootHostLaunchClientOriginalV1 {
    fn drop(&mut self) {
        if self.entry.is_some() && !self.terminal_complete { std::process::abort(); }
    }
}

const CLOSED: RootHostLaunchClientClosedV1 = RootHostLaunchClientClosedV1;

impl RootHostLaunchClientOriginalV1 {
    /// Borrows admission only from the actual storage opening and fresh Start owner.
    ///
    /// # Errors
    /// Refuses a foreign purpose, incomplete signed reply or changed native turn.
    #[doc(hidden)]
    pub fn borrow_storage_prepare_admission_v2<'held, 'turn, 'intake>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'turn, 'intake>, controller: &Journal,
    ) -> Result<RootStartResourcePrepareAdmissionOriginalV2<'held>, RootHostLaunchClientClosedV1>
    where 'turn: 'held {
        self.borrow_resource_prepare_admission_v2(HostResourcePurposeDataV1::StorageGuestRoot, loan, controller)
    }

    /// Borrows admission only from the actual mount opening and fresh Start owner.
    ///
    /// # Errors
    /// Refuses a foreign purpose, incomplete signed reply or changed native turn.
    #[doc(hidden)]
    pub fn borrow_mount_prepare_admission_v2<'held, 'turn, 'intake>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'turn, 'intake>, controller: &Journal,
    ) -> Result<RootStartResourcePrepareAdmissionOriginalV2<'held>, RootHostLaunchClientClosedV1>
    where 'turn: 'held {
        self.borrow_resource_prepare_admission_v2(HostResourcePurposeDataV1::MountNamespace, loan, controller)
    }

}

impl RootHostLaunchClientOriginalV1 {
    /// Binds the actual Mount preparation only after its completed construction.
    ///
    /// # Errors
    /// Refuses another immutable purpose, incomplete posts or changed C/Entry.
    #[doc(hidden)]
    pub fn bind_mount_preparation_once_v2(&mut self,
        prepared: &crate::PreparedStartResourceRequestOriginalV2,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::MountNamespace)?;
        self.bind_resource_preparation_once_v2(prepared, entry, controller)
    }
}

impl RootHostLaunchClientOriginalV1 {
    /// Binds the actual Storage preparation only after its completed construction.
    ///
    /// # Errors
    /// Refuses another immutable purpose, incomplete posts or changed C/Entry.
    #[doc(hidden)]
    pub fn bind_storage_preparation_once_v2(&mut self,
        prepared: &crate::PreparedStartResourceRequestOriginalV2,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::StorageGuestRoot)?;
        self.bind_resource_preparation_once_v2(prepared, entry, controller)
    }
}


impl RootHostLaunchClientOriginalV1 {
    /// Borrows the actual Host reply under its genuine construction loan.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete reply or changed native Start owner.
    #[doc(hidden)]
    pub fn borrow_host_prepare_admission_v2<'held, 'turn, 'intake>(
        &'held self, loan: &OriginalStartHostRootLoanV1<'turn, 'intake>, controller: &Journal,
    ) -> Result<RootStartResourcePrepareAdmissionOriginalV2<'held>, RootHostLaunchClientClosedV1>
    where 'turn: 'held {
        self.borrow_resource_prepare_admission_v2(HostResourcePurposeDataV1::HostLaunch, loan, controller)
    }

    /// Binds the genuine Host pair after its actual construction posts.
    ///
    /// # Errors
    /// Refuses another purpose, unfinished construction or changed C/Entry.
    #[doc(hidden)]
    pub fn bind_host_preparation_once_v2(&mut self,
        prepared: &crate::PreparedStartResourceRequestOriginalV2,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)?;
        self.bind_resource_preparation_once_v2(prepared, entry, controller)
    }
}
