//! Transfers the actual C10 and released originals on the retained Root stream.
//!
//! The same strict subject receiver checks Root6. Completion lends the actual
//! native receipt only after every Root, control, socket and cutoff post passes.

use super::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{ReleaseProofsDataV1, RootClosedBodyDataV1, HandoffRetainedBodyDataV1,
        HANDOFF_RETAINED_RECEIPT_BYTES_V1, RELEASED_RECEIPT_BYTES_V1},
};
use crate::controller_resource_reservation::create_intake::ready::{
    OriginalCreateStorageReadyV1, use_reserved::OriginalCreateStorageHandoffV1,
};
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1,
    RootExchangeOriginalsV1, RootPostFrontierV1, RootReceivePurposeV1,
};

#[derive(Clone, Copy)]
enum FirstV1 { Entry, Funding, Before, Encoding, Send, After, Settlement, Geometry, Receive, Comparison, Post, Cutoff, FinalSettlement }

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
struct RootClosedTurnOriginalsV1 {
    entered: bool,
    frame_entered: bool,
    entry: Option<Result<u64, ResourceReservationErrorV1>>,
    admission: Option<Result<(), Closed>>,
    before: Option<Result<(), Closed>>,
    encoded: Option<Result<(), HistoryErrorV1>>,
    sent: Option<Result<(), HistoryErrorV1>>,
    after: Option<Result<(), Closed>>,
    settlement: Option<Result<(), HistoryErrorV1>>,
    transfer_complete: bool,
    geometry: Option<Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>>,
    entry_post: Option<Result<(), Closed>>,
    received: Option<Result<(), Closed>>,
    body: Option<Result<RootClosedBodyDataV1, HistoryErrorV1>>,
    compared: Option<Result<(), Closed>>,
    cutoff: Option<Result<(), ResourceReservationErrorV1>>,
    final_settlement: Option<Result<(), HistoryErrorV1>>,
    completed_clock: Option<aos_sandbox_model::RawPairedClockSample>,
    first: Option<FirstV1>,
    complete: bool,
}

impl RootClosedTurnOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn admission_is_owed_v1(&self) -> bool { self.entered && !self.frame_entered && self.admission.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn before_is_owed_v1(&self) -> bool { self.frame_entered && self.before.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn after_is_owed_v1(&self) -> bool { self.frame_entered && self.after.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn entry_is_owed_v1(&self) -> bool { self.transfer_complete && self.geometry.is_some() && self.entry_post.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn comparison_is_owed_v1(&self) -> bool { self.body.is_some() && self.compared.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failure<'cause>(&'cause self, tail: &'cause RootUseTailOriginalsV1,
        peer: &'cause CreateStorageRootPeerReceivingOriginalsV1,
        property_geometry: &'cause Option<Result<ResourceVector, ResourceReservationErrorV1>>,
        property_funding: &'cause Option<Result<(), ResourceReservationErrorV1>>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            FirstV1::Entry => cause(&self.entry).or_else(|| cause(&self.admission)),
            FirstV1::Funding => tail.failure(peer, property_geometry, property_funding),
            FirstV1::Before => peer.failure().or_else(|| cause(&self.before)),
            FirstV1::Encoding => tail.sender.failure().or_else(|| cause(&self.encoded)),
            FirstV1::Send => tail.sender.failure().or_else(|| cause(&self.sent)),
            FirstV1::After => peer.failure().or_else(|| cause(&self.after)),
            FirstV1::Settlement => cause(&self.settlement),
            FirstV1::Geometry => cause(&self.geometry),
            FirstV1::Receive => tail.closed.failure(peer).or_else(|| cause(&self.received)),
            FirstV1::Comparison => cause(&self.body),
            FirstV1::Post => peer.failure().or_else(|| cause(&self.compared)),
            FirstV1::Cutoff => cause(&self.cutoff),
            FirstV1::FinalSettlement => cause(&self.final_settlement),
        }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Exchanges the original released-owner proofs for Root's final native receipt.
    ///
    /// # Errors
    /// Retains incomplete C10, reentry, exhausted U, changed native originals,
    /// stream or strict-subject failure, mismatched Root6, cutoff or owed posts.
    #[doc(hidden)]
    pub fn exchange_root_releases_once(&mut self) -> Result<(), Closed> {
        if self.failure().is_some() { return Err(Closed); }
        let owner = &mut *self.original.owner;
        let (handoff, receiving) = owner.storage_use.split_handoff_receiving_v1().map_err(|_| Closed)?;
        let root = &mut owner.root_exchange;
        if root.turn.use_tail.closed_turn.started() {
            root.closed.get_or_insert(Closed);
            return Err(Closed);
        }
        root.turn.expected_controller = Some(handoff.position_v1().map_err(|_| Closed)?);
        root.turn.use_tail.closed_turn.entered = true;
        root.turn.use_tail.closed_turn.entry = Some((|| {
            let hello = root.turn.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            Ok(handoff.cutoff_v1()?.min(hello.cutoff))
        })());
        let mut loan = OriginalCreateStorageRootExchangeV1 { parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(receiving) };
        loan.run_closed_once(&mut root.peer, &handoff)
    }
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    fn observe_closed_admission_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1) {
        self.state.owed_post = Some(RootPostFrontierV1::ClosedAdmission);
        let post = peer.recheck_once(self);
        self.state.use_tail.closed_turn.admission = Some(post);
    }

    fn run_closed_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        handoff: &OriginalCreateStorageHandoffV1<'_>,
    ) -> Result<(), Closed> {
        let cutoff = self.state.use_tail.closed_turn.entry.as_ref().and_then(|r| r.as_ref().ok()).copied();
        if cutoff.is_none() {
            self.state.use_tail.closed_turn.first = Some(FirstV1::Entry);
            self.observe_closed_admission_once(peer);
            return Err(Closed);
        }
        if self.prepay_use_root_observations_once(3).is_err() {
            self.state.use_tail.closed_turn.first = Some(FirstV1::Funding);
            self.observe_closed_admission_once(peer);
            return Err(Closed);
        }
        let cutoff = cutoff.ok_or(Closed)?;
        self.state.use_tail.closed_turn.frame_entered = true;
        self.state.owed_post = Some(RootPostFrontierV1::ClosedBefore);
        let before = peer.recheck_once(self);
        self.state.use_tail.closed_turn.before = Some(before);
        if !matches!(self.state.use_tail.closed_turn.before, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first = Some(FirstV1::Before);
        }
        if self.state.use_tail.closed_turn.first.is_none() {
            let encoded = self.encode_release_frame_once(handoff);
            self.state.use_tail.closed_turn.encoded = Some(encoded);
            if !matches!(self.state.use_tail.closed_turn.encoded, Some(Ok(()))) {
                self.state.use_tail.closed_turn.first = Some(FirstV1::Encoding);
            }
        }
        if self.state.use_tail.closed_turn.first.is_none() {
            let sent = (|| {
                let length = *positive(&self.state.use_tail.sender.encoding)?;
                if self.debit_use_stream_once(length).is_err() {
                    self.state.use_tail.closed_turn.first = Some(FirstV1::Funding);
                    return Err(HistoryErrorV1::Correlation);
                }
                let (transport, tail) = (&mut self.state.transport, &mut self.state.use_tail);
                tail.sender.send_once(transport.stream_mut()?, cutoff)
            })();
            self.state.use_tail.closed_turn.sent = Some(sent);
            if !matches!(self.state.use_tail.closed_turn.sent, Some(Ok(()))) {
                self.state.use_tail.closed_turn.first.get_or_insert(FirstV1::Send);
            }
        }
        self.state.owed_post = Some(RootPostFrontierV1::ClosedAfter);
        let after = peer.recheck_once(self);
        self.state.use_tail.closed_turn.after = Some(after);
        if !matches!(self.state.use_tail.closed_turn.after, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first.get_or_insert(FirstV1::After);
        }
        if self.state.use_tail.closed_turn.first.is_some() || self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.closed_turn.settlement = Some((|| {
            self.state.use_tail.sender.dispose_after_posts_once()?;
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)?.advance_after_posts()
        })());
        if !matches!(self.state.use_tail.closed_turn.settlement, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first = Some(FirstV1::Settlement);
            return Err(Closed);
        }
        self.state.use_tail.closed_turn.frame_entered = false;
        self.state.use_tail.closed_turn.transfer_complete = true;
        self.receive_closed_once(peer, handoff, cutoff)
    }

    fn encode_release_frame_once(&mut self, handoff: &OriginalCreateStorageHandoffV1<'_>)
        -> Result<(), HistoryErrorV1> {
        let lane = self.state.transport.hello_body()?.open.lane;
        let mut controller = [0; HANDOFF_RETAINED_RECEIPT_BYTES_V1];
        let mut source = [0; RELEASED_RECEIPT_BYTES_V1];
        let mut cache = [0; RELEASED_RECEIPT_BYTES_V1];
        handoff.receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
            .encode_into(lane, ContinuationKindV1::HandoffRetained, &mut controller)?;
        handoff.released_v1().source_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
            .encode_into(lane, ContinuationKindV1::SourceReleased, &mut source)?;
        handoff.released_v1().cache_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
            .encode_into(lane, ContinuationKindV1::CacheReleased, &mut cache)?;
        let proofs = ReleaseProofsDataV1 { controller: &controller, source: &source, cache: &cache };
        let mut payload = [0; RELEASE_PROOFS_BYTES_V1];
        proofs.encode_into(lane, &mut payload)?;
        let coordinates = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?
            .current(FrameKindV1::ReleaseProofs);
        self.state.use_tail.sender.prepare_once(coordinates, &payload)
    }

    fn receive_closed_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        handoff: &OriginalCreateStorageHandoffV1<'_>, cutoff: u64,
    ) -> Result<(), Closed> {
        let funded = self.debit_use_stream_once(FRAME_HEADER_BYTES + ROOT_CLOSED_RECEIPT_BYTES_V1);
        self.state.use_tail.closed_turn.geometry = Some(CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1());
        let geometry = self.state.use_tail.closed_turn.geometry.as_ref().and_then(|v| v.as_ref().ok()).copied();
        if funded.is_err() || geometry.is_none() {
            if funded.is_ok() { self.state.use_tail.closed_turn.first = Some(FirstV1::Geometry); }
            self.state.owed_post = Some(RootPostFrontierV1::ClosedEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.closed_turn.entry_post = Some(post);
            return Err(Closed);
        }
        let received = self.receive_root_subject_once(peer, cutoff, &geometry.ok_or(Closed)?, RootReceivePurposeV1::Closed);
        self.state.use_tail.closed_turn.received = Some(received);
        if !matches!(self.state.use_tail.closed_turn.received, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first = Some(FirstV1::Receive);
            return Err(Closed);
        }
        if self.prepay_use_root_observations_once(1).is_err() {
            self.state.owed_post = Some(RootPostFrontierV1::ClosedEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.closed_turn.entry_post = Some(post);
            return Err(Closed);
        }
        self.state.use_tail.closed_turn.body = Some(self.compare_closed_once(handoff));
        if !matches!(self.state.use_tail.closed_turn.body, Some(Ok(_))) {
            self.state.use_tail.closed_turn.first = Some(FirstV1::Comparison);
        }
        self.state.owed_post = Some(RootPostFrontierV1::ClosedComparison);
        let post = peer.recheck_once(self);
        self.state.use_tail.closed_turn.compared = Some(post);
        if !matches!(self.state.use_tail.closed_turn.compared, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first.get_or_insert(FirstV1::Post);
        }
        self.state.use_tail.closed_turn.cutoff = Some((|| {
            let clock = self.state.last_native_clock.ok_or(ResourceReservationErrorV1::Conflict)?;
            handoff.clock_v1()?.validate_later_sample(clock).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if clock.boottime_nanoseconds() >= cutoff { return Err(ResourceReservationErrorV1::Conflict); }
            Ok(())
        })());
        if !matches!(self.state.use_tail.closed_turn.cutoff, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first.get_or_insert(FirstV1::Cutoff);
        }
        if self.state.use_tail.closed_turn.first.is_some() || self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.closed_turn.final_settlement = Some(self.state.use_tail.coordinates.as_mut()
            .ok_or(HistoryErrorV1::Correlation).and_then(TailCoordinatesV1::advance_after_posts));
        if !matches!(self.state.use_tail.closed_turn.final_settlement, Some(Ok(()))) {
            self.state.use_tail.closed_turn.first = Some(FirstV1::FinalSettlement);
            return Err(Closed);
        }
        self.state.use_tail.closed_turn.completed_clock = self.state.last_native_clock;
        self.state.use_tail.closed_turn.complete = true;
        Ok(())
    }

    fn compare_closed_once(&self, handoff: &OriginalCreateStorageHandoffV1<'_>)
        -> Result<RootClosedBodyDataV1, HistoryErrorV1> {
        let hello = self.state.transport.hello_body()?;
        let lane = hello.open.lane;
        let expected = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?
            .current(FrameKindV1::Closed);
        let frame = FrameEnvelopeV1::decode(self.state.use_tail.closed.buffer.bytes(), expected)?;
        let receipt = ContinuationNativeReceiptDataV1::decode(frame.payload(), lane, ContinuationKindV1::Closed)?;
        let previous = ContinuationNativeReceiptDataV1::decode(
            &self.state.use_tail.outcome_ack.buffer.bytes()[FRAME_HEADER_BYTES..], lane, ContinuationKindV1::OutcomeRecorded)?;
        receipt.require_successor(lane, ContinuationKindV1::Closed,
            previous.record_data(lane, ContinuationKindV1::OutcomeRecorded)?.checksum(), hello.open.seed,
            previous.names, previous.after_next, previous.after_end)?;
        let body = RootClosedBodyDataV1::decode(receipt.record_data(lane, ContinuationKindV1::Closed)?.body())?;
        require_closed_handoff_v1(body, handoff, lane)?;
        Ok(body)
    }
}

fn require_closed_handoff_v1(body: RootClosedBodyDataV1, handoff: &OriginalCreateStorageHandoffV1<'_>, lane: [u8; 16])
    -> Result<(), HistoryErrorV1> {
    let record = handoff.receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
        .record_data(lane, ContinuationKindV1::HandoffRetained)?;
    let terminal = HandoffRetainedBodyDataV1::decode(record.body())?;
    let source = handoff.released_v1().source_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
        .record_data(lane, ContinuationKindV1::SourceReleased)?;
    let cache = handoff.released_v1().cache_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
        .record_data(lane, ContinuationKindV1::CacheReleased)?;
    if body != (RootClosedBodyDataV1 { handoff_retained: record.checksum(), source_released: source.checksum(),
        cache_released: cache.checksum(), committed_use_claim: terminal.committed_use_claim }) {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

/// Borrows only the fully observed same-stream Root6 terminal.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageRootClosedV1<'held> {
    turn: &'held RootUseTailOriginalsV1,
    lane: [u8; 16],
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_closed_v1<'held>(&'held self, handoff: &OriginalCreateStorageHandoffV1<'_>)
        -> Result<OriginalCreateStorageRootClosedV1<'held>, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.turn.use_tail.closed_turn.complete
            || self.turn.use_tail.closed_turn.completed_clock.is_none()
            || self.turn.expected_controller != Some(handoff.position_v1()?) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let closed = OriginalCreateStorageRootClosedV1 { turn: &self.turn.use_tail,
            lane: self.turn.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)?.open.lane };
        closed.require_handoff_v1(handoff)?;
        Ok(closed)
    }
}

impl<'held> OriginalCreateStorageRootClosedV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        ContinuationNativeReceiptDataV1::decode(&self.turn.closed.buffer.bytes()[FRAME_HEADER_BYTES..], self.lane,
            ContinuationKindV1::Closed).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn require_handoff_v1(&self, handoff: &OriginalCreateStorageHandoffV1<'_>) -> Result<(), ResourceReservationErrorV1> {
        let body = *self.turn.closed_turn.body.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        require_closed_handoff_v1(body, handoff, self.lane).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn clock_v1(&self) -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1> {
        self.turn.closed_turn.completed_clock.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.turn.closed_turn.entry.as_ref().and_then(|r| r.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}
