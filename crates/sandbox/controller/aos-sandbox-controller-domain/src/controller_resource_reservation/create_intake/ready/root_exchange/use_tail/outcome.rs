//! Transfers the actual C9 outcome and retains Root5's independent binding.
//!
//! Every frame borrows the same completed C9 and original signed Session packets. A positive
//! send and its full Root posts retire the single scratch before its next use.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{OutcomeBundleDataV1, RootOutcomeBodyDataV1, CONTROLLER_OUTCOME_RECEIPT_BYTES_V1},
};
use crate::controller_resource_reservation::create_intake::ready::{
    OriginalCreateStorageReadyV1, use_reserved::OriginalCreateStorageOutcomeV1,
};
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1,
    RootExchangeOriginalsV1, RootPostFrontierV1, RootReceivePurposeV1,
};

#[derive(Clone, Copy)]
enum FirstV1 { Association, Before, Encoding, Send, After, Settlement, Geometry, Receive, Comparison, Post, Cutoff, FinalSettlement }

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
struct RootOutcomeTurnOriginalsV1 {
    entered: bool,
    frame_entered: bool,
    association: Option<Result<(), ResourceReservationErrorV1>>,
    failed_position: Option<Result<crate::controller_resource_reservation::create_intake::history::CreateStorageWriterPositionV1, ResourceReservationErrorV1>>,
    recorded_encoding: Option<Result<[u8; CONTROLLER_OUTCOME_RECEIPT_BYTES_V1], HistoryErrorV1>>,
    before: Option<Result<(), Closed>>,
    encoded: Option<Result<(), HistoryErrorV1>>,
    sent: Option<Result<(), HistoryErrorV1>>,
    after: Option<Result<(), Closed>>,
    settlement: Option<Result<(), HistoryErrorV1>>,
    chunks_sent: u32,
    transfer_complete: bool,
    geometry: Option<Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>>,
    entry_post: Option<Result<(), Closed>>,
    received: Option<Result<(), Closed>>,
    body: Option<Result<RootOutcomeBodyDataV1, HistoryErrorV1>>,
    compared: Option<Result<(), Closed>>,
    final_settlement: Option<Result<(), HistoryErrorV1>>,
    first: Option<FirstV1>,
    complete: bool,
    cutoff: Option<u64>,
    post_cutoff: Option<Result<(), ResourceReservationErrorV1>>,
    completed_clock: Option<aos_sandbox_model::RawPairedClockSample>,
}

impl RootOutcomeTurnOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn cutoff_v1(&self) -> Option<u64> { self.cutoff }

    // Only the private actual-C9 refusal entry sets this retained Result.
    // A failed comparison permits observation, never primary work or disposal.
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failed_position_post_is_active_v1(&self) -> bool {
        self.entered && matches!(self.failed_position, Some(Err(_)))
            && self.entry_post.is_none() && !self.frame_entered
    }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn before_is_owed(&self) -> bool { self.frame_entered && self.before.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn after_is_owed(&self) -> bool { self.frame_entered && self.after.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn admission_is_owed(&self) -> bool { self.entered && self.entry_post.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn entry_is_owed(&self) -> bool { self.transfer_complete && self.geometry.is_some() && self.entry_post.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn comparison_is_owed(&self) -> bool { self.body.is_some() && self.compared.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failure<'a>(&'a self, tail: &'a RootUseTailOriginalsV1,
        peer: &'a CreateStorageRootPeerReceivingOriginalsV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        match self.first {
            Some(FirstV1::Association) => cause(&self.association),
            Some(FirstV1::Before) => peer.failure().or_else(|| cause(&self.before)),
            Some(FirstV1::Encoding) => cause(&tail.outcome_index).or_else(|| cause(&self.recorded_encoding))
                .or_else(|| tail.sender.failure()).or_else(|| cause(&self.encoded)),
            Some(FirstV1::Send) => tail.sender.failure().or_else(|| cause(&self.sent)),
            Some(FirstV1::After) => peer.failure().or_else(|| cause(&self.after)),
            Some(FirstV1::Settlement) => cause(&self.settlement),
            Some(FirstV1::Geometry) => cause(&self.geometry),
            Some(FirstV1::Receive) => tail.outcome_ack.failure(peer).or_else(|| cause(&self.received)),
            Some(FirstV1::Comparison) => cause(&self.body),
            Some(FirstV1::Post) => peer.failure().or_else(|| cause(&self.compared)),
            Some(FirstV1::Cutoff) => cause(&self.post_cutoff),
            Some(FirstV1::FinalSettlement) => cause(&self.final_settlement),
            None => None,
        }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Transfers the original C9 outcome and accepts Root's independent binding.
    ///
    /// The packets remain borrowed from the same authenticated Session flight;
    /// the genuine C9 native owner selects the closed Controller position.
    ///
    /// # Errors
    /// Retains incomplete C9/terminal posts, reentry, association, funding, IO,
    /// changed currentness/cutoff, a differing receipt or any owed post failure.
    #[doc(hidden)]
    pub fn exchange_original_storage_outcome_once(&mut self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), Closed> {
        if self.failure().is_some() { return Err(Closed); }
        let original_cutoff = self.original.accepted().map_err(|_| Closed)?.original_cutoff;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        if root.turn.use_tail.outcome_turn.started() { return Err(Closed); }
        let (recorded, receiving) = owner.storage_use.split_outcome_receiving_v1().map_err(|_| Closed)?;
        root.turn.expected_controller = Some(recorded.position_v1().map_err(|_| Closed)?);
        root.turn.use_tail.outcome_turn.entered = true;
        root.turn.use_tail.outcome_turn.association = Some(recorded.require_outcome_v1(outcome));
        if !matches!(root.turn.use_tail.outcome_turn.association, Some(Ok(()))) {
            root.turn.use_tail.outcome_turn.first = Some(FirstV1::Association);
        }
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(receiving),
        };
        loan.run_outcome_once(&mut root.peer, &recorded, outcome, original_cutoff)
    }
}

#[derive(Clone, Copy)]
enum OutcomeFrameV1 { Index, Chunk(u32), Recorded }

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    fn run_outcome_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        recorded: &OriginalCreateStorageOutcomeV1<'_>, outcome: &AuthenticatedBrokerMethodOutcomeV1,
        original_cutoff: u64,
    ) -> Result<(), Closed> {
        let cutoff = self.state.transport.hello_body().map_err(|_| Closed)?.cutoff.min(original_cutoff)
            .min(recorded.cutoff_v1().map_err(|_| Closed)?);
        self.state.use_tail.outcome_turn.cutoff = Some(cutoff);
        if self.state.use_tail.outcome_turn.first.is_some() || self.prepay_use_root_observations_once(3).is_err() {
            self.observe_outcome_admission_post_once(peer);
            return Err(Closed);
        }
        self.send_outcome_frame_once(peer, recorded, outcome, OutcomeFrameV1::Index, cutoff)?;
        let count = positive(&self.state.use_tail.outcome_index).map_err(|_| Closed)?.count();
        for index in 0..count {
            self.send_outcome_frame_once(peer, recorded, outcome, OutcomeFrameV1::Chunk(index), cutoff)?;
        }
        self.send_outcome_frame_once(peer, recorded, outcome, OutcomeFrameV1::Recorded, cutoff)?;
        self.state.use_tail.outcome_turn.transfer_complete = true;
        self.receive_outcome_ack_once(peer, recorded, outcome, cutoff)
    }

    fn observe_outcome_admission_post_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1) {
        // The actual preceding C8/terminal handoff paid this one negative-only
        // post. A failed new U debit cannot suppress or finance this native IO.
        self.state.owed_post = Some(RootPostFrontierV1::OutcomeAdmission);
        let post = peer.recheck_once(self);
        self.state.use_tail.outcome_turn.entry_post = Some(post);
    }

    fn send_outcome_frame_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        recorded: &OriginalCreateStorageOutcomeV1<'_>, outcome: &AuthenticatedBrokerMethodOutcomeV1,
        frame: OutcomeFrameV1, cutoff: u64,
    ) -> Result<(), Closed> {
        if self.prepay_use_root_observations_once(3).is_err() {
            self.observe_outcome_admission_post_once(peer);
            return Err(Closed);
        }
        let progress = &mut self.state.use_tail.outcome_turn;
        progress.frame_entered = true;
        // The preceding scratch/native interval has completed both posts.
        // A negative result cannot reach this next-frame retirement point.
        progress.before = None;
        progress.encoded = None;
        progress.sent = None;
        progress.after = None;
        progress.settlement = None;
        progress.post_cutoff = None;
        self.state.owed_post = Some(RootPostFrontierV1::OutcomeBefore);
        let before = peer.recheck_once(self);
        self.state.use_tail.outcome_turn.before = Some(before);
        if !matches!(self.state.use_tail.outcome_turn.before, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Before);
        }
        if self.state.use_tail.outcome_turn.first.is_none() {
            let encoded = self.encode_outcome_frame_once(recorded, outcome, frame);
            self.state.use_tail.outcome_turn.encoded = Some(encoded);
            if !matches!(self.state.use_tail.outcome_turn.encoded, Some(Ok(()))) {
                self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Encoding);
            }
        }
        if self.state.use_tail.outcome_turn.first.is_none() {
            let sent = self.send_outcome_prepared_once(cutoff);
            self.state.use_tail.outcome_turn.sent = Some(sent);
            if !matches!(self.state.use_tail.outcome_turn.sent, Some(Ok(()))) {
                self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Send);
            }
        }
        self.state.owed_post = Some(RootPostFrontierV1::OutcomeAfter);
        let after = peer.recheck_once(self);
        self.state.use_tail.outcome_turn.after = Some(after);
        if !matches!(self.state.use_tail.outcome_turn.after, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::After);
        }
        if matches!(self.state.use_tail.outcome_turn.after, Some(Ok(()))) {
            self.require_outcome_post_cutoff_v1(cutoff);
        }
        if self.state.use_tail.outcome_turn.first.is_some() || self.state.use_tail.first.is_some() { return Err(Closed); }
        let settled = (|| {
            self.state.use_tail.sender.dispose_after_posts_once()?;
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)?.advance_after_posts()?;
            let progress = &mut self.state.use_tail.outcome_turn;
            if let OutcomeFrameV1::Chunk(index) = frame {
                if index != progress.chunks_sent { return Err(HistoryErrorV1::Correlation); }
                progress.chunks_sent = progress.chunks_sent.checked_add(1).ok_or(HistoryErrorV1::Extent)?;
            }
            progress.frame_entered = false;
            Ok(())
        })();
        self.state.use_tail.outcome_turn.settlement = Some(settled);
        if !matches!(self.state.use_tail.outcome_turn.settlement, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Settlement);
            return Err(Closed);
        }
        Ok(())
    }

    fn encode_outcome_frame_once(&mut self, recorded: &OriginalCreateStorageOutcomeV1<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, frame: OutcomeFrameV1,
    ) -> Result<(), HistoryErrorV1> {
        let bundle = OutcomeBundleDataV1 { request: outcome.request().canonical_packet(),
            outcome: outcome.canonical_packet() };
        let kind = match frame {
            OutcomeFrameV1::Index => FrameKindV1::OutcomeIndex,
            OutcomeFrameV1::Chunk(_) => FrameKindV1::OutcomeChunk,
            OutcomeFrameV1::Recorded => FrameKindV1::OutcomeRecorded,
        };
        let coordinates = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?.current(kind);
        match frame {
            OutcomeFrameV1::Index => {
                if self.state.use_tail.outcome_index.is_some() { return Err(HistoryErrorV1::Correlation); }
                let request_maximum = recorded.reserved_v1().request_shape_bytes_v1()
                    .map_err(|_| HistoryErrorV1::Extent)?;
                if bundle.request.len() > request_maximum || bundle.outcome.len() > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
                    return Err(HistoryErrorV1::Extent);
                }
                self.state.use_tail.outcome_index = Some(TransferIndexV1::new(
                    u64::try_from(bundle.encoded_bytes()?).map_err(|_| HistoryErrorV1::Extent)?, bundle.transfer_digest_v1()?));
                let index = *positive(&self.state.use_tail.outcome_index)?;
                self.state.use_tail.sender.prepare_once(coordinates, &index.encode())
            }
            OutcomeFrameV1::Chunk(chunk) => {
                if chunk != self.state.use_tail.outcome_turn.chunks_sent { return Err(HistoryErrorV1::Correlation); }
                let index = *positive(&self.state.use_tail.outcome_index)?;
                self.state.use_tail.sender.prepare_outcome_chunk_once(coordinates, index, chunk, bundle)
            }
            OutcomeFrameV1::Recorded => {
                let lane = self.state.transport.hello_body()?.open.lane;
                self.state.use_tail.outcome_turn.recorded_encoding = Some((|| {
                    let mut encoded = [0; CONTROLLER_OUTCOME_RECEIPT_BYTES_V1];
                    recorded.receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?.encode_into(
                        lane, ContinuationKindV1::ControllerOutcomeRecorded, &mut encoded)?;
                    Ok(encoded)
                })());
                let encoded = positive(&self.state.use_tail.outcome_turn.recorded_encoding)?;
                self.state.use_tail.sender.prepare_once(coordinates, encoded)
            }
        }
    }

    fn send_outcome_prepared_once(&mut self, cutoff: u64) -> Result<(), HistoryErrorV1> {
        let length = *positive(&self.state.use_tail.sender.encoding)?;
        self.debit_use_stream_once(length).map_err(|_| HistoryErrorV1::Correlation)?;
        let (transport, tail) = (&mut self.state.transport, &mut self.state.use_tail);
        tail.sender.send_once(transport.stream_mut()?, cutoff)
    }

    fn receive_outcome_ack_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        recorded: &OriginalCreateStorageOutcomeV1<'_>, outcome: &AuthenticatedBrokerMethodOutcomeV1, cutoff: u64,
    ) -> Result<(), Closed> {
        let funded = self.debit_use_stream_once(FRAME_HEADER_BYTES + ROOT_OUTCOME_RECEIPT_BYTES_V1);
        self.state.use_tail.outcome_turn.geometry = Some(CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1());
        let geometry = self.state.use_tail.outcome_turn.geometry.as_ref().and_then(|v| v.as_ref().ok()).copied();
        if funded.is_err() || geometry.is_none() {
            if funded.is_ok() { self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Geometry); }
            self.state.owed_post = Some(RootPostFrontierV1::OutcomeAckEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.outcome_turn.entry_post = Some(post);
            return Err(Closed);
        }
        let received = self.receive_root_subject_once(peer, cutoff, &geometry.ok_or(Closed)?, RootReceivePurposeV1::OutcomeAcknowledged);
        self.state.use_tail.outcome_turn.received = Some(received);
        if !matches!(self.state.use_tail.outcome_turn.received, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Receive);
            return Err(Closed);
        }
        // Pay this comparison and the next purpose's one refusal post while
        // the existing strict-receive spare still protects failed extension.
        if self.prepay_use_root_observations_once(2).is_err() {
            self.state.owed_post = Some(RootPostFrontierV1::OutcomeAckEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.outcome_turn.entry_post = Some(post);
            return Err(Closed);
        }
        self.state.use_tail.outcome_turn.body = Some(self.compare_outcome_ack_once(recorded, outcome));
        if !matches!(self.state.use_tail.outcome_turn.body, Some(Ok(_))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Comparison);
        }
        self.state.owed_post = Some(RootPostFrontierV1::OutcomeComparison);
        let post = peer.recheck_once(self);
        self.state.use_tail.outcome_turn.compared = Some(post);
        if !matches!(self.state.use_tail.outcome_turn.compared, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Post);
        }
        if matches!(self.state.use_tail.outcome_turn.compared, Some(Ok(()))) {
            self.require_outcome_post_cutoff_v1(cutoff);
        }
        if self.state.use_tail.outcome_turn.first.is_some() || self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.outcome_turn.final_settlement = Some(self.state.use_tail.coordinates.as_mut()
            .ok_or(HistoryErrorV1::Correlation).and_then(TailCoordinatesV1::advance_after_posts));
        if !matches!(self.state.use_tail.outcome_turn.final_settlement, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::FinalSettlement);
            return Err(Closed);
        }
        self.state.use_tail.outcome_turn.completed_clock = self.state.last_native_clock;
        self.state.use_tail.outcome_turn.complete = true;
        Ok(())
    }

    fn require_outcome_post_cutoff_v1(&mut self, cutoff: u64) {
        self.state.use_tail.outcome_turn.post_cutoff = Some((|| {
            let clock = self.state.last_native_clock.ok_or(ResourceReservationErrorV1::Conflict)?;
            if clock.boottime_nanoseconds() >= cutoff { return Err(ResourceReservationErrorV1::Conflict); }
            Ok(())
        })());
        if !matches!(self.state.use_tail.outcome_turn.post_cutoff, Some(Ok(()))) {
            self.state.use_tail.outcome_turn.first.get_or_insert(FirstV1::Cutoff);
        }
    }

    fn compare_outcome_ack_once(&self, recorded: &OriginalCreateStorageOutcomeV1<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<RootOutcomeBodyDataV1, HistoryErrorV1> {
        let hello = self.state.transport.hello_body()?;
        let lane = hello.open.lane;
        let expected = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?
            .current(FrameKindV1::RootOutcomeRecorded);
        let frame = FrameEnvelopeV1::decode(self.state.use_tail.outcome_ack.buffer.bytes(), expected)?;
        let receipt = ContinuationNativeReceiptDataV1::decode(frame.payload(), lane, ContinuationKindV1::OutcomeRecorded)?;
        let original = ContinuationNativeReceiptDataV1::decode(
            &self.state.use_tail.signed_bound.buffer.bytes()[FRAME_HEADER_BYTES..], lane, ContinuationKindV1::SignedBound)?;
        let previous = original.record_data(lane, ContinuationKindV1::SignedBound)?;
        receipt.require_successor(lane, ContinuationKindV1::OutcomeRecorded, previous.checksum(),
            hello.open.seed, original.names, original.after_next, original.after_end)?;
        let envelope = receipt.record_data(lane, ContinuationKindV1::OutcomeRecorded)?;
        let body = RootOutcomeBodyDataV1::decode(envelope.body())?;
        let actual = recorded.receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
            .record_data(lane, ContinuationKindV1::ControllerOutcomeRecorded)?;
        let native = recorded.body_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        let bundle = OutcomeBundleDataV1 { request: outcome.request().canonical_packet(),
            outcome: outcome.canonical_packet() };
        if body.controller_outcome != actual.checksum() || body.prepared_receipt != native.prepared_receipt
            || body.outcome_bundle != bundle.commitment()? {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }
}

/// Borrows Root5 only through its actual completed native transport owner.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageRootOutcomeV1<'held> {
    turn: &'held RootUseTailOriginalsV1,
    lane: [u8; 16],
}

impl RootExchangeOriginalsV1 {
    // This entry is negative-only and can borrow only an actual entered C9
    // attempt. Its native position is never replaced by an earlier C8 head.
    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_outcome_entry_refusal_once(&mut self,
        parent: &super::super::ProjectPreparationReservationAttemptV1,
        intake: &mut super::super::Q04OriginalIntakeAttemptV1,
        controller: &mut super::super::Journal,
        source: &mut super::super::ProtectedSourceDomainJournalOwnerV1,
        profile: &super::super::ProductionControllerNormalRootProfileV1,
        cache: &mut super::super::OriginalCreateStorageCacheLoanV1<'_>,
        attempt: &crate::controller_resource_reservation::create_intake::history::outcome::OutcomeOriginalsV1,
        receiving: &mut crate::controller_resource_reservation::create_intake::ready::use_reserved::UseReceivingOriginalsV1,
    ) -> Result<(), Closed> {
        if !attempt.started() || self.turn.use_tail.outcome_turn.entered {
            return Err(Closed);
        }
        self.turn.use_tail.outcome_turn.entered = true;
        self.turn.use_tail.outcome_turn.failed_position = Some(attempt.position());
        self.turn.expected_controller = self.turn.use_tail.outcome_turn.failed_position.as_ref()
            .and_then(|position| position.as_ref().ok()).copied();
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent, intake, controller, source, profile, cache,
            state: &mut self.turn, use_receiving: Some(receiving),
        };
        loan.observe_outcome_admission_post_once(&mut self.peer);
        // The earlier actual C9 producer retains its primary cause. This
        // negative-only post cannot manufacture completion or mask that cause.
        Err(Closed)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_committed_outcome_v1<'held>(&'held self,
        committed: &crate::controller_resource_reservation::create_intake::ready::use_reserved::OriginalCreateStorageUseCommittedV1<'_>,
    ) -> Result<OriginalCreateStorageRootOutcomeV1<'held>, ResourceReservationErrorV1> {
        let closed = || ResourceReservationErrorV1::Conflict;
        if self.failure().is_some() || !self.turn.use_tail.outcome_turn.complete
            || self.turn.expected_controller != Some(committed.position_v1()?) {
            return Err(closed());
        }
        let clock = self.turn.use_tail.outcome_turn.completed_clock.ok_or_else(closed)?;
        if committed.transition_v1()?.original_clock != Some(clock) { return Err(closed()); }
        let lane = self.turn.transport.hello_body().map_err(|_| closed())?.open.lane;
        let original = self.turn.use_tail.outcome_turn.recorded_encoding.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        let original = ContinuationNativeReceiptDataV1::decode(original, lane,
            ContinuationKindV1::ControllerOutcomeRecorded).map_err(|_| closed())?;
        let current = committed.recorded_v1().receipt_v1()?;
        if original.record != current.record || original.latest_head != current.latest_head
            || original.names != current.names || original.after_next != current.after_next
            || original.after_end != current.after_end {
            return Err(closed());
        }
        Ok(OriginalCreateStorageRootOutcomeV1 { turn: &self.turn.use_tail, lane })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_outcome_v1<'held>(&'held self, recorded: &OriginalCreateStorageOutcomeV1<'_>)
        -> Result<OriginalCreateStorageRootOutcomeV1<'held>, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.turn.use_tail.outcome_turn.complete
            || self.turn.use_tail.outcome_turn.completed_clock.is_none()
            || self.turn.expected_controller != Some(recorded.position_v1()?) { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(OriginalCreateStorageRootOutcomeV1 { turn: &self.turn.use_tail,
            lane: self.turn.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)?.open.lane })
    }
}

impl<'held> OriginalCreateStorageRootOutcomeV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        ContinuationNativeReceiptDataV1::decode(&self.turn.outcome_ack.buffer.bytes()[FRAME_HEADER_BYTES..],
            self.lane, ContinuationKindV1::OutcomeRecorded).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.turn.outcome_turn.cutoff.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn clock_v1(&self) -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1> {
        self.turn.outcome_turn.completed_clock.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<&'held RootOutcomeBodyDataV1, ResourceReservationErrorV1> {
        self.turn.outcome_turn.body.as_ref().and_then(|v| v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_chunk_crosses_original_packet_boundaries_in_the_same_sender() {
        let request = vec![7; CLAIM_CHUNK_BYTES - 20];
        let response = vec![9; 40];
        let bundle = OutcomeBundleDataV1 { request: &request, outcome: &response };
        let index = TransferIndexV1::new(bundle.encoded_bytes().unwrap() as u64, bundle.transfer_digest_v1().unwrap()).unwrap();
        let coordinates = FrameCoordinatesV1 { kind: FrameKindV1::OutcomeChunk,
            lane: [1; 16], sequence: 13, root_nonce: [2; 16], controller_nonce: [3; 16] };
        let mut sender = RootTailSendOriginalsV1::default();

        sender.prepare_outcome_chunk_once(coordinates, index, 0, bundle).unwrap();
        let length = *positive(&sender.encoding).unwrap();
        let frame = FrameEnvelopeV1::decode(&sender.bytes[..length], coordinates).unwrap();
        let chunk = aos_sandbox_protocol::domain_ledger::create_storage_history::transport::ChunkEnvelopeV1::
            decode(frame.payload(), index, 0).unwrap();
        let mut expected = vec![0; CLAIM_CHUNK_BYTES];
        bundle.encode_range_into_v1(0, &mut expected).unwrap();

        assert_eq!(chunk.payload(), expected);
        assert!(sender.dispose_after_posts_once().is_err());
        assert!(sender.prepare_outcome_chunk_once(coordinates, index, 1, bundle).is_err());
    }

    #[test]
    fn outcome_encoding_cause_precedes_a_later_independent_post_failure() {
        let mut tail = RootUseTailOriginalsV1::default();
        tail.outcome_turn.entered = true;
        tail.outcome_turn.encoded = Some(Err(HistoryErrorV1::Extent));
        tail.outcome_turn.after = Some(Err(Closed));
        tail.outcome_turn.first = Some(FirstV1::Encoding);
        let peer = CreateStorageRootPeerReceivingOriginalsV1::new();

        let first = tail.outcome_turn.failure(&tail, &peer).unwrap();

        assert!(matches!(first.downcast_ref::<HistoryErrorV1>(), Some(HistoryErrorV1::Extent)));
        assert!(!tail.outcome_turn.complete);
    }
}
