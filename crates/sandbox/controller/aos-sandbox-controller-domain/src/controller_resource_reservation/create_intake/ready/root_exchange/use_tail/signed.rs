//! Transfers the actual C6 bundle and retains Root4's independent binding.
//!
//! Every frame borrows the same completed C6 and spends the same U. A positive
//! send and its full Root posts retire the single scratch before its next use.

use super::*;
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1, SignedBoundBodyDataV1},
};
use crate::controller_resource_reservation::create_intake::ready::{
    OriginalCreateStorageReadyV1, use_reserved::OriginalCreateStorageSignedV1,
};
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1,
    RootExchangeOriginalsV1, RootPostFrontierV1, RootReceivePurposeV1,
};

#[derive(Clone, Copy)]
enum FirstV1 { Before, Encoding, Send, After, Settlement, Geometry, Receive, Comparison, Post, FinalSettlement }

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
struct RootSignedTurnOriginalsV1 {
    entered: bool,
    frame_entered: bool,
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
    body: Option<Result<SignedBoundBodyDataV1, HistoryErrorV1>>,
    compared: Option<Result<(), Closed>>,
    final_settlement: Option<Result<(), HistoryErrorV1>>,
    first: Option<FirstV1>,
    complete: bool,
}

impl RootSignedTurnOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn before_is_owed(&self) -> bool { self.frame_entered && self.before.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn after_is_owed(&self) -> bool { self.frame_entered && self.after.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn entry_is_owed(&self) -> bool { self.transfer_complete && self.geometry.is_some() && self.entry_post.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn comparison_is_owed(&self) -> bool { self.body.is_some() && self.compared.is_none() }

    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn failure<'a>(&'a self, tail: &'a RootUseTailOriginalsV1,
        peer: &'a CreateStorageRootPeerReceivingOriginalsV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        match self.first {
            Some(FirstV1::Before) => peer.failure().or_else(|| cause(&self.before)),
            Some(FirstV1::Encoding) => cause(&tail.signed_index).or_else(|| tail.sender.failure()).or_else(|| cause(&self.encoded)),
            Some(FirstV1::Send) => tail.sender.failure().or_else(|| cause(&self.sent)),
            Some(FirstV1::After) => peer.failure().or_else(|| cause(&self.after)),
            Some(FirstV1::Settlement) => cause(&self.settlement),
            Some(FirstV1::Geometry) => cause(&self.geometry),
            Some(FirstV1::Receive) => tail.signed_bound.failure(peer).or_else(|| cause(&self.received)),
            Some(FirstV1::Comparison) => cause(&self.body),
            Some(FirstV1::Post) => peer.failure().or_else(|| cause(&self.compared)),
            Some(FirstV1::FinalSettlement) => cause(&self.final_settlement),
            None => None,
        }
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Transfers the original C6 bundle and accepts Root's independent binding.
    ///
    /// The same U, Root stream, Source, Cache and native peers stay held. The
    /// actual returned C6 position advances the closed Controller comparison.
    ///
    /// # Errors
    /// Retains incomplete signing/C6, reentry, accounting, native IO, changed
    /// currentness/cutoff, differing receipt or independently owed post failure.
    #[doc(hidden)]
    pub fn exchange_root_signed_once(&mut self) -> Result<(), Closed> {
        if self.failure().is_some() { return Err(Closed); }
        self.original.require_operation_currentness_peak_v1(&self.cache).map_err(|_| Closed)?;
        let original_cutoff = self.original.accepted().map_err(|_| Closed)?.original_cutoff;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        root.require_completed_signing_v1().map_err(|_| Closed)?;
        if !root.turn.use_tail.admitted_complete || root.turn.use_tail.signed_turn.started() { return Err(Closed); }
        let (signed, receiving) = owner.storage_use.split_signed_receiving_v1().map_err(|_| Closed)?;
        root.turn.expected_controller = Some(signed.position_v1().map_err(|_| Closed)?);
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(RootUseReceivingV1::Original(receiving)),
        };
        loan.run_signed_once(&mut root.peer, &signed, original_cutoff)
    }
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    fn run_signed_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        signed: &OriginalCreateStorageSignedV1<'_>, original_cutoff: u64,
    ) -> Result<(), Closed> {
        let cutoff = self.state.transport.hello_body().map_err(|_| Closed)?.cutoff.min(original_cutoff);
        self.prepay_use_root_observations_once(3)?;
        self.state.use_tail.signed_turn.entered = true;
        self.send_signed_frame_once(peer, signed, None, cutoff)?;
        let count = positive(&self.state.use_tail.signed_index).map_err(|_| Closed)?.count();
        for index in 0..count { self.send_signed_frame_once(peer, signed, Some(index), cutoff)?; }
        self.state.use_tail.signed_turn.transfer_complete = true;
        self.receive_signed_bound_once(peer, signed, cutoff)
    }

    fn send_signed_frame_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        signed: &OriginalCreateStorageSignedV1<'_>, chunk: Option<u32>, cutoff: u64,
    ) -> Result<(), Closed> {
        self.prepay_use_root_observations_once(3)?;
        let progress = &mut self.state.use_tail.signed_turn;
        progress.frame_entered = true;
        // The preceding scratch/native interval has completed both posts.
        // A negative result cannot reach this next-frame retirement point.
        progress.before = None;
        progress.encoded = None;
        progress.sent = None;
        progress.after = None;
        progress.settlement = None;
        self.state.owed_post = Some(RootPostFrontierV1::SignedBefore);
        let before = peer.recheck_once(self);
        self.state.use_tail.signed_turn.before = Some(before);
        if !matches!(self.state.use_tail.signed_turn.before, Some(Ok(()))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Before);
        }
        if self.state.use_tail.signed_turn.first.is_none() {
            let encoded = self.encode_signed_frame_once(signed, chunk);
            self.state.use_tail.signed_turn.encoded = Some(encoded);
            if !matches!(self.state.use_tail.signed_turn.encoded, Some(Ok(()))) {
                self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Encoding);
            }
        }
        if self.state.use_tail.signed_turn.first.is_none() {
            let sent = self.send_signed_prepared_once(cutoff);
            self.state.use_tail.signed_turn.sent = Some(sent);
            if !matches!(self.state.use_tail.signed_turn.sent, Some(Ok(()))) {
                self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Send);
            }
        }
        self.state.owed_post = Some(RootPostFrontierV1::SignedAfter);
        let after = peer.recheck_once(self);
        self.state.use_tail.signed_turn.after = Some(after);
        if !matches!(self.state.use_tail.signed_turn.after, Some(Ok(()))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::After);
        }
        if self.state.use_tail.signed_turn.first.is_some() || self.state.use_tail.first.is_some() { return Err(Closed); }
        let settled = (|| {
            self.state.use_tail.sender.dispose_after_posts_once()?;
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)?.advance_after_posts()?;
            let progress = &mut self.state.use_tail.signed_turn;
            if let Some(index) = chunk {
                if index != progress.chunks_sent { return Err(HistoryErrorV1::Correlation); }
                progress.chunks_sent = progress.chunks_sent.checked_add(1).ok_or(HistoryErrorV1::Extent)?;
            }
            progress.frame_entered = false;
            Ok(())
        })();
        self.state.use_tail.signed_turn.settlement = Some(settled);
        if !matches!(self.state.use_tail.signed_turn.settlement, Some(Ok(()))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Settlement);
            return Err(Closed);
        }
        Ok(())
    }

    fn encode_signed_frame_once(&mut self, signed: &OriginalCreateStorageSignedV1<'_>, chunk: Option<u32>)
        -> Result<(), HistoryErrorV1> {
        let bytes = signed.bundle_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        if chunk.is_none() {
            if self.state.use_tail.signed_index.is_some() { return Err(HistoryErrorV1::Correlation); }
            self.state.use_tail.signed_index = Some(TransferIndexV1::new(
                u64::try_from(bytes.len()).map_err(|_| HistoryErrorV1::Extent)?, Sha256::digest(bytes).into()));
        }
        let index = *positive(&self.state.use_tail.signed_index)?;
        let kind = if chunk.is_some() { FrameKindV1::SignedChunk } else { FrameKindV1::SignedIndex };
        let coordinates = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?.current(kind);
        match chunk {
            None => self.state.use_tail.sender.prepare_once(coordinates, &index.encode()),
            Some(chunk) => {
                if chunk != self.state.use_tail.signed_turn.chunks_sent { return Err(HistoryErrorV1::Correlation); }
                let offset = usize::try_from(chunk).ok().and_then(|n| n.checked_mul(CLAIM_CHUNK_BYTES)).ok_or(HistoryErrorV1::Extent)?;
                let end = offset.checked_add(CLAIM_CHUNK_BYTES).ok_or(HistoryErrorV1::Extent)?.min(bytes.len());
                let payload = bytes.get(offset..end).ok_or(HistoryErrorV1::Extent)?;
                let header = index.encode_chunk_header(chunk, payload)?;
                self.state.use_tail.sender.prepare_parts_once(coordinates, &header, payload)
            }
        }
    }

    fn send_signed_prepared_once(&mut self, cutoff: u64) -> Result<(), HistoryErrorV1> {
        let length = *positive(&self.state.use_tail.sender.encoding)?;
        self.debit_use_stream_once(length).map_err(|_| HistoryErrorV1::Correlation)?;
        let (transport, tail) = (&mut self.state.transport, &mut self.state.use_tail);
        tail.sender.send_once(transport.stream_mut()?, cutoff)
    }

    fn receive_signed_bound_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        signed: &OriginalCreateStorageSignedV1<'_>, cutoff: u64,
    ) -> Result<(), Closed> {
        let funded = self.debit_use_stream_once(FRAME_HEADER_BYTES + SIGNED_BOUND_RECEIPT_BYTES_V1);
        self.state.use_tail.signed_turn.geometry = Some(CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1());
        let geometry = self.state.use_tail.signed_turn.geometry.as_ref().and_then(|v| v.as_ref().ok()).copied();
        if funded.is_err() || geometry.is_none() {
            if funded.is_ok() { self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Geometry); }
            self.state.owed_post = Some(RootPostFrontierV1::SignedBoundEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.signed_turn.entry_post = Some(post);
            return Err(Closed);
        }
        let received = self.receive_root_subject_once(peer, cutoff, &geometry.ok_or(Closed)?, RootReceivePurposeV1::SignedBound);
        self.state.use_tail.signed_turn.received = Some(received);
        if !matches!(self.state.use_tail.signed_turn.received, Some(Ok(()))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Receive);
            return Err(Closed);
        }
        // Pay this comparison and the next purpose's one refusal post while
        // the existing strict-receive spare still protects failed extension.
        if self.prepay_use_root_observations_once(2).is_err() {
            self.state.owed_post = Some(RootPostFrontierV1::SignedBoundEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.signed_turn.entry_post = Some(post);
            return Err(Closed);
        }
        self.state.use_tail.signed_turn.body = Some(self.compare_signed_bound_once(signed));
        if !matches!(self.state.use_tail.signed_turn.body, Some(Ok(_))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Comparison);
        }
        self.state.owed_post = Some(RootPostFrontierV1::SignedBoundComparison);
        let post = peer.recheck_once(self);
        self.state.use_tail.signed_turn.compared = Some(post);
        if !matches!(self.state.use_tail.signed_turn.compared, Some(Ok(()))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::Post);
        }
        if self.state.use_tail.signed_turn.first.is_some() || self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.signed_turn.final_settlement = Some(self.state.use_tail.coordinates.as_mut()
            .ok_or(HistoryErrorV1::Correlation).and_then(TailCoordinatesV1::advance_after_posts));
        if !matches!(self.state.use_tail.signed_turn.final_settlement, Some(Ok(()))) {
            self.state.use_tail.signed_turn.first.get_or_insert(FirstV1::FinalSettlement);
            return Err(Closed);
        }
        self.state.use_tail.signed_turn.complete = true;
        Ok(())
    }

    fn compare_signed_bound_once(&self, signed: &OriginalCreateStorageSignedV1<'_>)
        -> Result<SignedBoundBodyDataV1, HistoryErrorV1> {
        let hello = self.state.transport.hello_body()?;
        let lane = hello.open.lane;
        let expected = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?.current(FrameKindV1::SignedBound);
        let frame = FrameEnvelopeV1::decode(self.state.use_tail.signed_bound.buffer.bytes(), expected)?;
        let receipt = ContinuationNativeReceiptDataV1::decode(frame.payload(), lane, ContinuationKindV1::SignedBound)?;
        let original = signed.body_v1(lane).map_err(|_| HistoryErrorV1::Correlation)?;
        let admitted = RecordEnvelopeV1::decode(original.admitted.record,
            KeyV1::new(lane, OwnerV1::Root, 3)?, PhaseV1::new(OwnerV1::Root, 3)?)?;
        receipt.require_successor(lane, ContinuationKindV1::SignedBound, admitted.checksum(),
            hello.open.seed, original.admitted.names, original.admitted.after_next, original.admitted.after_end)?;
        let envelope = RecordEnvelopeV1::decode(receipt.record,
            KeyV1::new(lane, OwnerV1::Root, 4)?, PhaseV1::new(OwnerV1::Root, 4)?)?;
        let bound = SignedBoundBodyDataV1::decode(envelope.body())?;
        original.bundle_data_v1(lane, signed.request_shape_bytes_v1().map_err(|_| HistoryErrorV1::Extent)?)?.require_bound(bound)?;
        if bound.request_id != signed.request_id_v1().map_err(|_| HistoryErrorV1::Correlation)? { return Err(HistoryErrorV1::Correlation); }
        Ok(bound)
    }
}

/// Borrows Root4 only through its actual completed native transport owner.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageRootSignedBoundV1<'held> {
    turn: &'held RootUseTailOriginalsV1,
    lane: [u8; 16],
}

impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_signed_bound_v1<'held>(&'held self, signed: &OriginalCreateStorageSignedV1<'_>)
        -> Result<OriginalCreateStorageRootSignedBoundV1<'held>, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.turn.use_tail.signed_turn.complete
            || self.turn.expected_controller != Some(signed.position_v1()?) { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(OriginalCreateStorageRootSignedBoundV1 { turn: &self.turn.use_tail,
            lane: self.turn.transport.hello_body().map_err(|_| ResourceReservationErrorV1::Conflict)?.open.lane })
    }
}

impl<'held> OriginalCreateStorageRootSignedBoundV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        ContinuationNativeReceiptDataV1::decode(&self.turn.signed_bound.buffer.bytes()[FRAME_HEADER_BYTES..],
            self.lane, ContinuationKindV1::SignedBound).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.turn.admitted_cutoff.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<&'held SignedBoundBodyDataV1, ResourceReservationErrorV1> {
        self.turn.signed_turn.body.as_ref().and_then(|v| v.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::transport::ChunkEnvelopeV1;

    #[test]
    fn indexed_sender_uses_one_scratch_and_the_existing_canonical_chunk_grammar() {
        let payload = b"actual original signed-bundle bytes";
        let index = TransferIndexV1::new(payload.len() as u64, Sha256::digest(payload).into()).unwrap();
        let header = index.encode_chunk_header(0, payload).unwrap();
        let coordinates = FrameCoordinatesV1 { kind: FrameKindV1::SignedChunk,
            lane: [1; 16], sequence: 13, root_nonce: [2; 16], controller_nonce: [3; 16] };
        let mut sender = RootTailSendOriginalsV1::default();

        sender.prepare_parts_once(coordinates, &header, payload).unwrap();
        let length = *positive(&sender.encoding).unwrap();
        let frame = FrameEnvelopeV1::decode(&sender.bytes[..length], coordinates).unwrap();
        let chunk = ChunkEnvelopeV1::decode(frame.payload(), index, 0).unwrap();

        assert_eq!(chunk.payload(), payload);
        assert!(sender.prepare_parts_once(coordinates, &header, payload).is_err());
        assert!(sender.dispose_after_posts_once().is_err());
    }

    #[test]
    fn signed_encoding_cause_precedes_a_later_independent_post_failure() {
        let mut tail = RootUseTailOriginalsV1::default();
        tail.signed_turn.entered = true;
        tail.signed_turn.encoded = Some(Err(HistoryErrorV1::Extent));
        tail.signed_turn.after = Some(Err(Closed));
        tail.signed_turn.first = Some(FirstV1::Encoding);
        let peer = CreateStorageRootPeerReceivingOriginalsV1::new();

        let first = tail.signed_turn.failure(&tail, &peer).unwrap();

        assert!(matches!(first.downcast_ref::<HistoryErrorV1>(), Some(HistoryErrorV1::Extent)));
        assert!(!tail.signed_turn.complete);
    }
}
