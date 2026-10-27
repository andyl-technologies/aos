//! Retains the initial Source exchange on the same admitted native Current.
//!
//! The owner keeps the actual fixed transport, two distinct retained clocks,
//! independent writer bookends and peer post. Reply DATA is authenticated only
//! against its own captured issuer pin and exact original request. It grants no
//! complete Ready, Cache, Use, append, terminal or released-owner capability.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_broker::source_signer_transport::{
    RootSourceSignerTransportOriginalsV1, RootSourceTransportClosedV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    source_current::{
        SourceCurrentQueryDataV1, SourceCurrentReplyDataV1, SourceCurrentReplyFieldsV1,
        SOURCE_CURRENT_BODY_BYTES_V1, SOURCE_CURRENT_PACKET_BYTES_V1,
        SOURCE_CURRENT_QUERY_BYTES_V1, SOURCE_CURRENT_REPLY_FRAME_BYTES_V1,
        SOURCE_CURRENT_REPLY_MAGIC_V1, SOURCE_CURRENT_SIGNATURE_DOMAIN_V1,
    },
};

use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::source_current_data::{
    require_source_current_interval_data_v1, verify_source_current_signature_data_v1,
};

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{
    RootInitialClockErrorV1, RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1,
};
use super::initial_pins::{RootInitialPinsErrorV1, RootInitialPinsOriginalV1};
use super::initial_ready::RootInitialReadyOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_source_query::{RootInitialSourceQueryErrorV1, RootInitialSourceQueryOriginalV1};
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;
use super::proof_turn::RootCurrentProofTurnV1;

/// Retains incomplete actual Source exchange without substituting reply authority.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialSourceExchangeErrorV1 {
    /// Retains same-owner native, original Open or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains failure of the actual initial request owner.
    #[error(transparent)]
    Query(#[from] RootInitialSourceQueryErrorV1),
    /// Retains failure of the actual independently captured issuer pin.
    #[error(transparent)]
    Pins(#[from] RootInitialPinsErrorV1),
    /// Retains canonical framing, query correlation or reply interval refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// Reports transport refusal while its whole native prefix stays retained.
    #[error(transparent)]
    Transport(#[from] RootSourceTransportClosedV1),
    /// The same genuine exchange or one independently owed post is incomplete.
    #[error("initial Source exchange is incomplete")]
    Incomplete,
}

type E = RootInitialSourceExchangeErrorV1;
type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
type Transport = RootSourceSignerTransportOriginalsV1<
    SOURCE_CURRENT_QUERY_BYTES_V1, SOURCE_CURRENT_REPLY_FRAME_BYTES_V1,
>;

pub(super) struct RootInitialSourceExchangeOriginalV1 {
    stage: RootInitialStageOriginalV1,
    predecessor: Option<RootObservationErrorV1>,
    turn_binding: Option<Result<Option<[u8; 32]>, E>>,
    before_writers: RootInitialWriterSampleOriginalV1,
    before_readback: Option<Result<(), RootInitialOpenErrorV1>>,
    before_clock: Clock,
    before_sample: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    before_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    cutoff: Option<Result<u64, HistoryErrorV1>>,
    transport: Transport,
    framing: Option<Result<(), HistoryErrorV1>>,
    reply: Option<Result<SourceCurrentReplyDataV1, HistoryErrorV1>>,
    signature: Option<Result<(), ed25519_dalek::SignatureError>>,
    correlation: Option<Result<(), HistoryErrorV1>>,
    production: Option<Result<(), E>>,
    after_writers: RootInitialWriterSampleOriginalV1,
    after_readback: Option<Result<(), RootInitialOpenErrorV1>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    after_clock: Clock,
    after_sample: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    after_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    freshness: Option<Result<(), HistoryErrorV1>>,
    entered: bool,
    closed: bool,
}

impl RootInitialSourceExchangeOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: RootInitialStageOriginalV1::new(),
            predecessor: None,
            turn_binding: None,
            before_writers: RootInitialWriterSampleOriginalV1::new(),
            before_readback: None,
            before_clock: Clock::default(),
            before_sample: None,
            before_cutoff: None,
            cutoff: None,
            transport: Transport::default(),
            framing: None,
            reply: None,
            signature: None,
            correlation: None,
            production: None,
            after_writers: RootInitialWriterSampleOriginalV1::new(),
            after_readback: None,
            peer_history: None,
            peer_arm: None,
            peer: None,
            after_clock: Clock::default(),
            after_sample: None,
            after_cutoff: None,
            freshness: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn claim_entry_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn refuse_unprepared_v1(&mut self) {
        self.closed = true;
    }

    pub(super) fn park_predecessor_refusal_v1(&mut self, error: RootObservationErrorV1) {
        self.predecessor.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn begin_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        query: &RootInitialSourceQueryOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.entered || self.closed || self.stage.entered {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.stage.entered = true;
        self.stage.financial = Some(financial.clone());

        self.stage.permit = Some((|| {
            query.require_complete_for_v1(open, ready).map_err(|_| NativeError::boundary())?;
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if initial.failure().is_some()
                || !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !query.same_financial_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = query.completed_prefix_v1().map_err(|_| NativeError::boundary())?;
            let demand = base.checked_add(Self::fixed_demand_v1()?)
                .map_err(|_| NativeError::boundary())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(demand)
        })());
        self.stage.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn exchange_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        query: &RootInitialSourceQueryOriginalV1,
        signer_uid: u32,
        socket_gid: u32,
    ) -> Result<(), E> {
        self.exchange_for_turn_once_v1(writers, open, pins, query, signer_uid, socket_gid,
            RootCurrentProofTurnV1::Initial)
    }

    pub(super) fn exchange_for_turn_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        query: &RootInitialSourceQueryOriginalV1,
        signer_uid: u32,
        socket_gid: u32,
        turn: RootCurrentProofTurnV1<'_>,
    ) -> Result<(), E> {
        if self.production.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.production = Some(self.exchange_inner_v1(
            writers, open, pins, query, signer_uid, socket_gid, turn,
        ));
        positive(&self.production).map(|_| ())
    }

    fn exchange_inner_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        query: &RootInitialSourceQueryOriginalV1,
        signer_uid: u32,
        socket_gid: u32,
        turn: RootCurrentProofTurnV1<'_>,
    ) -> Result<(), E> {
        pins.require_complete_v1()?;
        let request = query.prepared_bytes_v1()?;
        self.stage.require_complete_v1()?;
        self.turn_binding = Some(turn.authorization_checksum_v1(open).map_err(E::Open));
        positive(&self.turn_binding)?;

        let (authority, policy) = match writers.opened_pair_view_v1() {
            Ok(pair) => pair,
            Err(error) => {
                self.before_readback = Some(Err(RootInitialOpenErrorV1::Root(error)));
                return Err(E::Incomplete);
            }
        };
        self.before_writers.capture_once_v1(authority, policy, open);
        self.before_readback = Some(turn.readback_v1(open, authority, policy));
        self.before_writers.require_complete_v1()?;
        positive(&self.before_readback)?;

        self.cutoff = Some(SourceCurrentQueryDataV1::decode(request).and_then(|query| {
            Ok(query.root_body()?.cutoff.min(
                query.source_receipt()?.body(query.root_body()?.open.lane)?.cutoff,
            ))
        }));
        positive(&self.cutoff)?;
        self.before_sample = Some(self.before_clock.observe_once(None));
        self.before_cutoff = Some(require_clock(open, &self.before_sample, &self.cutoff));
        positive(&self.before_cutoff)?;

        self.transport.run_once_v1(signer_uid, socket_gid, request, *positive(&self.cutoff)?)?;
        self.framing = Some(if self.transport.frame_v1()[..8] == *SOURCE_CURRENT_REPLY_MAGIC_V1 {
            Ok(())
        } else {
            Err(HistoryErrorV1::Malformed)
        });
        positive(&self.framing)?;
        self.reply = Some(SourceCurrentReplyDataV1::decode(&self.transport.frame_v1()[8..]));
        let reply = *positive(&self.reply)?;
        let signer = pins.source_signer_v1()?;
        self.signature = Some(verify_source_current_signature_data_v1(
            self.transport.frame_v1(), reply.signature, signer.verifying_key(),
        ));
        positive(&self.signature)?;
        self.correlation = Some(SourceCurrentQueryDataV1::decode(request)
            .and_then(|query| reply.fields.require_query(query, signer.generation())));
        positive(&self.correlation).map(|_| ())
    }

    pub(super) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        self.observe_native_posts_for_turn_once_v1(writers, open, RootCurrentProofTurnV1::Initial);
    }

    pub(super) fn observe_native_posts_for_turn_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        turn: RootCurrentProofTurnV1<'_>,
    ) {
        // This purpose owes posts only after its actual fixed admission. A
        // socket/clock/codec/signature failure after that point never skips them.
        if self.stage.require_complete_v1().is_err() || self.after_readback.is_some() {
            return;
        }
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.after_writers.capture_once_v1(authority, policy, open);
                self.after_readback = Some(turn.readback_v1(open, authority, policy));
            }
            Err(error) => {
                self.after_readback = Some(Err(RootInitialOpenErrorV1::Root(error)));
            }
        }
    }

    pub(super) fn arm_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        if self.stage.require_complete_v1().is_err() || self.after_readback.is_none()
            || self.peer_arm.is_some() || self.peer.is_some()
        {
            self.closed = true;
            return Err(());
        }
        self.peer_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
            predecessor, startup, exclusion,
        ));
        self.peer_arm = Some(match &self.peer_history {
            Some(history) => history.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn refuse_peer_arm_once_v1(&mut self) {
        if self.peer_arm.is_none() && self.peer.is_none() {
            self.peer_arm = Some(Err(RootObservationErrorV1::Service));
        }
        self.closed = true;
    }

    pub(super) fn park_peer_refusal_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_none() {
            self.peer_arm = Some(Err(error));
        } else {
            self.closed = true;
        }
    }

    pub(super) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if self.stage.require_complete_v1().is_err() || self.after_readback.is_none()
            || self.peer_arm.is_none() || self.peer.is_some()
        {
            return;
        }
        self.peer = Some(match &mut self.peer_history {
            Some(history) => match history.borrow_accepted_v1(&originals.peer, &originals.stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer, Some(Ok(()))) {
            drop(self.peer_history.take());
        }
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_cutoff = Some(require_clock(open, &self.after_sample, &self.cutoff));
        if self.reply.as_ref().is_some_and(Result::is_ok) {
            self.freshness = Some(self.require_fresh_interval_v1());
        }
    }

    fn require_fresh_interval_v1(&self) -> Result<(), HistoryErrorV1> {
        let before = positive(&self.before_sample).map_err(|_| HistoryErrorV1::Correlation)?;
        let after = positive(&self.after_sample).map_err(|_| HistoryErrorV1::Correlation)?;
        let reply = positive(&self.reply).map_err(|_| HistoryErrorV1::Correlation)?.fields;
        require_source_current_interval_data_v1(before, after, &reply)
    }

    pub(super) fn require_use_complete_for_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &super::use_tail::reserved::RootUseReservedOriginalV1,
    ) -> Result<(), E> {
        self.require_complete_v1()?;
        let expected = RootCurrentProofTurnV1::Reserved { authorization, reserved }
            .authorization_checksum_v1(open)?;
        if expected.is_none() || *positive(&self.turn_binding)? != expected {
            return Err(E::Incomplete);
        }
        Ok(())
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.closed || self.failure_v1().is_some() {
            return Err(E::Incomplete);
        }
        self.stage.require_complete_v1()?;
        positive(&self.production)?;
        self.after_writers.require_complete_v1()?;
        positive(&self.after_readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.after_cutoff)?;
        positive(&self.freshness).map(|_| ())
    }

    pub(super) fn fields_v1(&self) -> Result<SourceCurrentReplyFieldsV1, E> {
        self.require_complete_v1()?;
        Ok(positive(&self.reply)?.fields)
    }

    pub(super) fn verified_packet_v1(&self) -> Result<&[u8; SOURCE_CURRENT_PACKET_BYTES_V1], E> {
        self.require_complete_v1()?;
        self.transport.frame_v1()[8..].try_into().map_err(|_| E::Incomplete)
    }

    pub(super) fn original_cutoff_v1(&self) -> Result<u64, E> {
        self.require_complete_v1()?;
        positive(&self.cutoff).copied()
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        Ok(self.stage.require_complete_v1()?)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.stage.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, NativeError> {
        let invalid = || NativeError::Mechanical(Mechanical::JournalTooLarge);
        let pair = Clock::dominant_requested_bytes_v1().ok_or_else(invalid)?;
        let message = SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()
            .checked_add(SOURCE_CURRENT_BODY_BYTES_V1).ok_or_else(invalid)?;
        let bytes = size_of::<Self>().checked_add(pair.checked_mul(2).ok_or_else(invalid)?)
            .and_then(|bytes| bytes.checked_add(message))
            .and_then(|bytes| bytes.checked_add(30 * 256))
            .and_then(|bytes| bytes.checked_add(crate::source_current_data::additional_control_bytes_v1()?))
            .ok_or_else(invalid)?;
        let cells = Clock::receiving_metadata_cells_v1().and_then(|cells| cells.checked_mul(2))
            .ok_or_else(invalid)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?)
            .with(D::OpenFiles, 1 + 2 * Clock::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::NetworkBytes, (SOURCE_CURRENT_QUERY_BYTES_V1 + SOURCE_CURRENT_REPLY_FRAME_BYTES_V1 + 1) as u64)
            .with(D::OutputBytes, SOURCE_CURRENT_QUERY_BYTES_V1 as u64);
        let names = RootInitialWriterSampleOriginalV1::additional_native_demand_v1()?;
        own.checked_add(names).and_then(|demand| demand.checked_add(names))
            .map_err(|_| invalid())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().map(|error| error as _)
            .or_else(|| self.stage.failure_v1())
            .or_else(|| cause(&self.turn_binding))
            .or_else(|| self.before_writers.failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| cause(&self.cutoff))
            .or_else(|| self.before_clock.failure())
            .or_else(|| cause(&self.before_sample))
            .or_else(|| cause(&self.before_cutoff))
            .or_else(|| self.transport.failure())
            .or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.reply))
            .or_else(|| cause(&self.signature))
            .or_else(|| cause(&self.correlation))
            .or_else(|| cause(&self.production))
            .or_else(|| self.after_writers.failure_v1())
            .or_else(|| cause(&self.after_readback))
            .or_else(|| self.peer_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer_arm))
            .or_else(|| cause(&self.peer))
            .or_else(|| self.after_clock.failure())
            .or_else(|| cause(&self.after_sample))
            .or_else(|| cause(&self.after_cutoff))
            .or_else(|| cause(&self.freshness))
    }
}

fn require_clock(
    open: &RootInitialOpenPreparedOriginalV1,
    sample: &Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    cutoff: &Option<Result<u64, HistoryErrorV1>>,
) -> Result<(), RootInitialOpenErrorV1> {
    let current = *positive(sample).map_err(|_| RootInitialOpenErrorV1::Boundary)?;
    let body = open.body_v1()?;
    open.clock_original_v1().require_current_v1(current, body.cutoff)?;
    if current.boottime_nanoseconds() >= *positive(cutoff).map_err(|_| RootInitialOpenErrorV1::Boundary)? {
        return Err(RootInitialOpenErrorV1::Boundary);
    }
    Ok(())
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Incomplete)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
