//! Retains the actual newly authorized metadata-finality Root exchange.
//!
//! The paid new Recover owner supplies the only input and payer. The whole
//! connection, strict ACK/EOF, peer samples and clock destinations remain
//! owned until the native metadata CAS and enclosing independent posts finish.
//! No decoded response can construct this owner or restore an old Apply grant.

use std::{error::Error, mem::size_of, sync::Arc};

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::HistoryErrorV1,
    provisioning_root::{
        finality_recover::{
            FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1 as ACK_BYTES,
            FINALITY_RECOVER_QUERY_BYTES_V1 as QUERY_BYTES,
            FinalityRecoverAcknowledgementDataV1 as Acknowledgement,
            FinalityRecoverQueryDataV1 as Query,
        },
        storage_apply::ApplyRootDataErrorV1,
    },
};

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
    ResourceReservationErrorV1, operator_create_recovery::finality::RecoverRootAssociationV1,
};
use crate::policy_compiler::{
    bounded_stream_io::{DeadlineStreamDirectionV1 as Direction, FixedDeadlineStreamIoV1},
    provisioning_current::{RootContinuationClockGateV1 as Clock, RootContinuationHorizonDataV1},
};
use crate::{Journal, JournalError, OperatorCreateRecoveryLoanV1};

type Cause = Box<dyn Error + Send + Sync>;

/// Reports an incomplete or refused actual new Recover Root flight.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("the original metadata-finality Root flight is incomplete or refused")]
pub struct RootFinalityRecoverClientClosedV1;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Reentry,
    Context,
    Body,
    Clock,
    Connect,
    Before,
    Reporting,
    Send,
    Shutdown,
    Admission,
    Receive,
    Reply,
    Eof,
    After,
    AfterClock,
    Settlement,
}

/// Retains the sole real Root flight for a newly authorized metadata completion.
#[doc(hidden)]
#[must_use = "retain the whole Root flight through the exact native metadata completion"]
#[derive(Default)]
pub struct RootFinalityRecoverClientOriginalV1 {
    entered: bool,
    parked: bool,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    context: Option<Result<RootContinuationHorizonDataV1, JournalError>>,
    state: Option<Box<State>>,
    first: Option<First>,
    complete: ResourceVector,
    observations: usize,
    wire: u64,
    output: u64,
    received_bound: usize,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
}

struct State {
    association: Arc<RecoverRootAssociationV1>,
    query: Query,
    controller_next: u64,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    cutoff: u64,
    connection: ControllerRootConnectionOriginalV1,
    clock: Clock,
    after_clock: Clock,
    before_sample: Option<Result<RawPairedClockSample, JournalError>>,
    after_sample: Option<Result<RawPairedClockSample, JournalError>>,
    connect: Option<Result<(), HistoryErrorV1>>,
    before: Box<PeerSampleV1>,
    before_result: Option<Result<(), NormalRootStartupErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    reply: Option<Result<Acknowledgement, Cause>>,
    eof: [u8; 1],
    eof_io: FixedDeadlineStreamIoV1<1>,
    ended: Option<Result<(), HistoryErrorV1>>,
    after: Box<PeerSampleV1>,
    after_result: Option<Result<(), NormalRootStartupErrorV1>>,
    temporal: Option<Result<(), JournalError>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    body: Option<Result<(), Cause>>,
}

impl RootFinalityRecoverClientOriginalV1 {
    pub(crate) fn park_in_native_attempt_v1(&mut self) {
        self.parked = true;
    }

    /// Prices the real connection, two owed peer samples and two CLI clock owners.
    pub(crate) fn fixed_receiving_demand_v1(
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let native =
            CreateStorageRootPeerReceivingOriginalsV1::finality_recover_native_peak_v1(profile)
                .ok_or_else(bad)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| bad())?;
        let (raw, files) = geometry.receive_obligations_v1();
        let readiness =
            crate::policy_compiler::RootSubjectReadinessV1::receiving_construction_bytes_v1()
                .ok_or_else(bad)?;
        let diagnostic = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(1)
            .and_then(|(_, logs)| logs.checked_mul(2))
            .ok_or_else(bad)?;
        let memory = size_of::<Self>()
            .checked_add(size_of::<State>())
            .and_then(|n| n.checked_add(size_of::<RootStrictChunkOriginalV1>()))
            .and_then(|n| n.checked_add(size_of::<RootClientFundingV1<'static>>()))
            .and_then(|n| n.checked_add(size_of::<RootReplyReceiveV1<'static>>()))
            .and_then(|n| n.checked_add(size_of::<RootClientLoanV1<'static, 'static, 'static, 'static, 'static, 'static>>()))
            .and_then(|n| n.checked_add(size_of::<RootSubjectDataV1<'static>>()))
            .and_then(|n| n.checked_add(size_of::<RootReplyPurposeV1>()))
            .and_then(|n| n.checked_add(size_of::<RootStreamStageV1>()))
            .and_then(|n| n.checked_add(raw))
            .and_then(|n| {
                n.checked_add(2 * size_of::<aos_systemd::FixedPid1PropertyFailureViewV1<'static>>())
            })
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| u64::try_from(n).ok())
            .and_then(|n| n.checked_add(readiness))
            .and_then(|n| n.checked_add(diagnostic))
            .ok_or_else(bad)?;
        let clock = Clock::controller_authorization_receiving_demand_v1()
            .map_err(ResourceReservationErrorV1::Journal)?;
        Ok(native
            .checked_add(
                ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(bad)?,
            )?
            .checked_add(clock)?
            .checked_add(clock)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, u64::try_from(files).map_err(|_| bad())?)
                    .with(
                        D::Pids,
                        u64::try_from(
                            CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1(),
                        )
                        .map_err(|_| bad())?,
                    ),
            )?)
    }

    /// Enters only from the same actual authorized Recover and completed signed18.
    ///
    /// The native owner prepays the full metadata destination and all initially
    /// owed Root observations before this method allocates or opens a socket.
    ///
    /// # Errors
    /// Retains every reached original and independent peer/CLI post. Refusal
    /// cannot reconnect, reenter, renew a deadline or authorize another effect.
    pub fn observe_once_v1(
        &mut self,
        loan: &mut OperatorCreateRecoveryLoanV1<'_, '_>,
        controller: &Journal,
        session: &Journal,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), RootFinalityRecoverClientClosedV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.entered = true;
        let prepared = loan.prepare_root_finality_once_v1(
            controller,
            session,
            inventory,
            Self::fixed_receiving_demand_v1(loan.profile_v1()),
            resource_stream::peer_traffic_v1(2),
        );
        let (association, query, base) = match prepared {
            Ok(value) => value,
            Err(cause) => {
                self.entry = Some(Err(cause));
                self.first = Some(First::Entry);
                return Err(CLOSED);
            }
        };
        self.entry = Some(Ok(()));
        self.complete = base;
        self.observations = 2;
        self.received_bound = 20;
        self.context = Some(
            RootContinuationHorizonDataV1::from_original_data_v1(query.original, query.cutoff)
                .map(|horizon| horizon.with_wall_expiry_data_v1(query.wall_expiry)),
        );
        let horizon = match self
            .context
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
        {
            Some(horizon) => horizon,
            None => {
                self.first = Some(First::Context);
                return Err(CLOSED);
            }
        };
        self.state = Some(Box::new(State::new(
            association,
            query,
            controller.snapshot_sequence(),
            Arc::clone(loan.profile_v1()),
            horizon,
        )));
        let result = self.observe_inner_v1(loan, controller);
        if let Some(state) = self.state.as_mut() {
            state.body = Some(result);
        }
        if self.first.is_none()
            && self
                .state
                .as_ref()
                .is_some_and(|state| matches!(state.body, Some(Err(_))))
        {
            self.first = Some(First::Body);
        }
        // Source/C outer posts run later; their refusal cannot replace this
        // selected Root cause. Both Root destinations were paid before entry.
        self.finish_posts_once_v1();
        self.require_complete_v1().map_err(|_| CLOSED)
    }

    fn observe_inner_v1(
        &mut self,
        loan: &mut OperatorCreateRecoveryLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<(), Cause> {
        let state = self.state.as_mut().ok_or(CLOSED)?;
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
                &mut RootClientLoanV1::Recover(loan),
                controller,
                0,
                QUERY_BYTES + 20 + 1,
                QUERY_BYTES,
            )
            .map_err(|_| {
                self.first = Some(First::Admission);
                CLOSED
            })?;
        state.before_sample = Some(state.clock.check_next_once_v1());
        if !matches!(state.before_sample, Some(Ok(_))) {
            self.first = Some(First::Clock);
            return Err(CLOSED.into());
        }
        state.connect = Some(state.connection.connect_once());
        if !matches!(state.connect, Some(Ok(()))) {
            self.first = Some(First::Connect);
            return Err(CLOSED.into());
        }
        state.before_result = Some(state.before.observe_with_cutoff_once_v1(
            &state.profile,
            state.connection.stream()?,
            None,
            None,
            false,
            state.cutoff,
        ));
        if !matches!(state.before_result, Some(Ok(()))) {
            self.first = Some(First::Before);
            return Err(CLOSED.into());
        }
        state.reporting = Some(state.connection.stream_mut()?.enable_subject_reporting());
        if !matches!(state.reporting, Some(Ok(()))) {
            self.first = Some(First::Reporting);
            return Err(CLOSED.into());
        }
        if state.clock.check_next_once_v1().is_err() {
            self.first = Some(First::Clock);
            return Err(CLOSED.into());
        }
        resource_stream::send_subject_v1(
            RootSubjectDataV1::Recover(state.query),
            &mut state.connection,
            &mut state.sender,
            &mut state.sent,
            &mut state.scratch,
            &mut state.data_failure,
            state.cutoff,
        )
        .map_err(|stage| {
            self.first = Some(stream_first(stage));
            CLOSED
        })?;
        state.shutdown = Some(rustix::net::shutdown(
            state.connection.stream()?.as_fd(),
            rustix::net::Shutdown::Write,
        ));
        if !matches!(state.shutdown, Some(Ok(()))) {
            self.first = Some(First::Shutdown);
            return Err(CLOSED.into());
        }
        if state.clock.check_next_once_v1().is_err() {
            self.first = Some(First::Clock);
            return Err(CLOSED.into());
        }
        let mut receive = RootReplyReceiveV1 {
            connection: &mut state.connection,
            received: &mut state.received,
            preparation: &mut state.preparation,
            extension: &mut state.extension,
            chunk: &mut state.chunk,
            data_failure: &mut state.data_failure,
            peer_before: &state.before,
            profile: &state.profile,
            cutoff: state.cutoff,
        };
        receive
            .receive_reply(
                RootReplyPurposeV1::Recover,
                &mut RootClientLoanV1::Recover(loan),
                controller,
                &mut funding,
            )
            .map_err(|stage| {
                self.first = Some(stream_first(stage));
                CLOSED
            })?;
        state.reply = Some(
            Acknowledgement::decode_v1(state.received.bytes())
                .map_err(|cause| Box::new(cause) as Cause),
        );
        let reply = *state
            .reply
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(|| {
                self.first = Some(First::Reply);
                CLOSED
            })?;
        state.cutoff = state.cutoff.min(reply.cutoff);
        state.ended = Some(state.eof_io.run_once(
            state.connection.stream_mut()?,
            &mut state.eof,
            state.cutoff,
            Direction::Eof,
        ));
        if !matches!(state.ended, Some(Ok(()))) {
            self.first = Some(First::Eof);
            return Err(CLOSED.into());
        }
        Ok(())
    }

    fn finish_posts_once_v1(&mut self) {
        let Some(state) = self.state.as_mut() else {
            return;
        };
        if let Ok(stream) = state.connection.stream() {
            state.after_result = Some(if matches!(state.before_result, Some(Ok(()))) {
                state.after.observe_against_sample_with_cutoff_once_v1(
                    &state.profile,
                    stream,
                    &state.before,
                    None,
                    true,
                    state.cutoff,
                )
            } else {
                state.after.observe_with_cutoff_once_v1(
                    &state.profile,
                    stream,
                    None,
                    None,
                    true,
                    state.cutoff,
                )
            });
            if !matches!(state.after_result, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
        }
        // A distinct prepaid CLI owner must observe even if primary failed.
        state.after_sample = Some(state.after_clock.check_next_once_v1());
        if !matches!(state.after_sample, Some(Ok(_))) {
            self.first.get_or_insert(First::AfterClock);
        }
        if self.first.is_some() {
            return;
        }
        state.temporal = Some((|| {
            let before = *state
                .before_sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let after = *state
                .after_sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let reply = state
                .reply
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            before
                .validate_later_sample(reply.sample)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            reply
                .sample
                .validate_later_sample(after)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            state.clock.require_final_sample_v1(after)?;
            let query = state.query;
            if reply.nonce != query.nonce
                || reply.admission != query.admission
                || reply.inventory != query.inventory
                || reply.cutoff > query.cutoff
                || reply.wall_expiry > query.wall_expiry
                || after.wall_seconds() >= reply.wall_expiry
                || after.boottime_nanoseconds() >= reply.cutoff
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if !matches!(state.temporal, Some(Ok(()))) {
            self.first = Some(First::Reply);
            return;
        }
        state.settlement = Some((|| {
            state.before.settle_positive_once()?;
            state.after.settle_positive_once()?;
            Ok(())
        })());
        if !matches!(state.settlement, Some(Ok(()))) {
            self.first = Some(First::Settlement);
        }
    }

    fn require_complete_v1(&self) -> Result<(), RootFinalityRecoverClientClosedV1> {
        let state = self.state.as_ref().ok_or(CLOSED)?;
        if self.first.is_some()
            || !matches!(state.body, Some(Ok(())))
            || !matches!(state.ended, Some(Ok(())))
            || !matches!(state.after_result, Some(Ok(())))
            || !matches!(state.after_sample, Some(Ok(_)))
            || !matches!(state.temporal, Some(Ok(())))
            || !matches!(state.settlement, Some(Ok(())))
        {
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(crate) fn require_metadata_ack_v1(
        &self,
        association: &Arc<RecoverRootAssociationV1>,
        controller: &Journal,
    ) -> Result<Acknowledgement, RootFinalityRecoverClientClosedV1> {
        self.require_complete_v1()?;
        let state = self.state.as_ref().ok_or(CLOSED)?;
        if !Arc::ptr_eq(&state.association, association)
            || state.controller_next != controller.snapshot_sequence()
        {
            return Err(CLOSED);
        }
        state
            .reply
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(CLOSED)
    }

    /// Borrows the actual selected source before later independently owed posts.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let first = self.first?;
        if matches!(first, First::Reentry) {
            return Some(&CLOSED);
        }
        if matches!(first, First::Entry) {
            return cause(&self.entry).or(Some(&CLOSED));
        }
        if matches!(first, First::Context) {
            return cause(&self.context).or(Some(&CLOSED));
        }
        if matches!(first, First::Admission) {
            return cause(&self.admission).or(Some(&CLOSED));
        }
        let state = self.state.as_ref()?;
        match first {
            First::Body => cause_box(&state.body),
            First::Clock => state
                .clock
                .failure()
                .or_else(|| cause(&state.before_sample)),
            First::Connect => state.connection.failure().or_else(|| cause(&state.connect)),
            First::Before => state
                .before
                .failure()
                .or_else(|| cause(&state.before_result)),
            First::Reporting => cause(&state.reporting),
            First::Send => state.sender.failure().or_else(|| cause(&state.sent)),
            First::Shutdown => cause(&state.shutdown),
            First::Receive => state
                .chunk
                .as_ref()
                .and_then(|chunk| chunk.failure(&state.received))
                .or_else(|| state.received.failure())
                .or_else(|| cause(&state.preparation))
                .or_else(|| cause(&state.extension)),
            First::Reply => state
                .data_failure
                .as_ref()
                .map(|cause| cause as _)
                .or_else(|| cause_box(&state.reply))
                .or_else(|| cause(&state.temporal)),
            First::Eof => state.eof_io.failure().or_else(|| cause(&state.ended)),
            First::After => state.after.failure().or_else(|| cause(&state.after_result)),
            First::AfterClock => state
                .after_clock
                .failure()
                .or_else(|| cause(&state.after_sample)),
            First::Settlement => state
                .before
                .failure()
                .or_else(|| state.after.failure())
                .or_else(|| cause(&state.settlement)),
            First::Entry | First::Reentry | First::Context | First::Admission => None,
        }
        .or(Some(&CLOSED))
    }

    pub(crate) fn selects_original_funding_v1(&self) -> bool {
        matches!(self.first, Some(First::Entry))
            || matches!(self.first, Some(First::Admission)) && self.funding_original
    }

    /// Borrows only the selected actual native property archive.
    #[doc(hidden)]
    pub fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        let marker = self
            .failure()?
            .downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>()?;
        let state = self.state.as_ref()?;
        for sample in [&*state.before, &*state.after] {
            if sample
                .failure()
                .and_then(|cause| cause.downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>())
                .is_some_and(|cause| std::ptr::eq(cause, marker))
            {
                return sample.property_failure_view_v1();
            }
        }
        let chunk = state.chunk.as_ref()?;
        if chunk
            .failure(&state.received)
            .and_then(|cause| cause.downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>())
            .is_some_and(|cause| std::ptr::eq(cause, marker))
        {
            chunk.property_failure_view_v1()
        } else {
            None
        }
    }
}

impl State {
    fn new(
        association: Arc<RecoverRootAssociationV1>,
        query: Query,
        controller_next: u64,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        horizon: RootContinuationHorizonDataV1,
    ) -> Self {
        Self {
            association,
            query,
            controller_next,
            profile,
            cutoff: query.cutoff,
            connection: Default::default(),
            clock: Clock::new_controller_authorization_v1(horizon),
            after_clock: Clock::new_controller_authorization_v1(horizon),
            before_sample: None,
            after_sample: None,
            connect: None,
            before: Box::new(PeerSampleV1::new()),
            before_result: None,
            reporting: None,
            sender: Default::default(),
            sent: None,
            scratch: [0; 4096],
            data_failure: None,
            shutdown: None,
            received: Default::default(),
            preparation: None,
            extension: None,
            chunk: None,
            reply: None,
            eof: [0; 1],
            eof_io: Default::default(),
            ended: None,
            after: Box::new(PeerSampleV1::new()),
            after_result: None,
            temporal: None,
            settlement: None,
            body: None,
        }
    }
}

fn stream_first(stage: RootStreamStageV1) -> First {
    match stage {
        RootStreamStageV1::Query => First::Reply,
        RootStreamStageV1::Send => First::Send,
        RootStreamStageV1::Admission => First::Admission,
        RootStreamStageV1::Receive => First::Receive,
        RootStreamStageV1::Reply => First::Reply,
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn cause_box<T>(slot: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| &**cause as _)
}

const CLOSED: RootFinalityRecoverClientClosedV1 = RootFinalityRecoverClientClosedV1;

impl Drop for RootFinalityRecoverClientOriginalV1 {
    fn drop(&mut self) {
        if self.entered && !self.parked {
            std::process::abort();
        }
    }
}
