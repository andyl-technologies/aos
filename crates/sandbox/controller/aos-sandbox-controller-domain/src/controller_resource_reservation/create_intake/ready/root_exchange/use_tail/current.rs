//! Sends second current proofs and lends Root's fully checked signing inputs.
//!
//! The lender retains the original stream's raw frame and native U association;
//! decoded fields alone cannot construct it or issue a signing permission.

use super::*;
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1,
        UseAdmittedBodyDataV1, UseAdmissionTransferDataV1},
    use_authorized::UseAuthorizedNativeReceiptDataV1,
    use_reserved::{UseCurrentProofsDataV1, UseReservedNativeReceiptDataV1,
        use_current_proofs_commitment_v1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::current_proof::CACHE_CURRENT_PROOF_PACKET_BYTES_V1;
use crate::controller_resource_reservation::create_intake::ready::{
    OriginalCreateStorageReadyV1, use_reserved::OriginalCreateStorageUseReservedV1,
};
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1,
    RootExchangeOriginalsV1, RootPostFrontierV1,
};

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Sends the distinct second proof and receives original Root signing inputs.
    ///
    /// The same returned U, Cache, Root stream and native peers remain held.
    /// This neither signs nor sends Prepare, settles U, or finishes the Effect.
    ///
    /// # Errors
    /// Retains wrong phase/original, U accounting, native send/receive, cutoff,
    /// exact receipt/proof/claim comparison and independently owed post failure.
    #[doc(hidden)]
    pub fn exchange_root_use_current_once(&mut self) -> Result<(), Closed> {
        if self.failure().is_some() { return Err(Closed); }
        self.original.require_operation_currentness_peak_v1(&self.cache).map_err(|_| Closed)?;
        let original_cutoff = self.original.accepted().map_err(|_| Closed)?.original_cutoff;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        if !root.turn.use_cache_complete || root.turn.use_tail.proofs_entered { return Err(Closed); }
        let packet = root.use_cache_current_proof.completed_packet_v1()?;
        let mut original = owner.storage_use.borrow_root_receiving_once_v1().map_err(|_| Closed)?;
        let (reserved, receiving) = original.split_original_and_receiving_v1().map_err(|_| Closed)?;
        if root.turn.expected_controller != Some(reserved.position_v1().map_err(|_| Closed)?) {
            return Err(Closed);
        }
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(RootUseReceivingV1::Original(receiving)),
        };
        loan.run_use_current_once(&mut root.peer, reserved, packet, original_cutoff)
    }
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    fn run_use_current_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        reserved: &OriginalCreateStorageUseReservedV1<'_>,
        packet: &[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1], original_cutoff: u64,
    ) -> Result<(), Closed> {
        // Before, independently owed after and following refusal are prepaid
        // before a new Root-native purpose. No failed admission is refreshed.
        self.prepay_use_root_observations_once(3)?;
        self.state.use_tail.proofs_entered = true;
        let cutoff = self.state.transport.hello_body().map_err(|_| Closed)?.cutoff.min(original_cutoff);
        self.state.use_tail.admitted_cutoff = Some(cutoff);
        self.state.owed_post = Some(RootPostFrontierV1::UseProofsBefore);
        let before = peer.recheck_once(self);
        self.state.use_tail.proofs_before = Some(before);
        if !matches!(self.state.use_tail.proofs_before, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::ProofsBefore);
        }
        if self.state.use_tail.first.is_none() {
            self.state.use_tail.proofs_encoding = Some(self.encode_use_proofs_once(reserved, packet));
            if !matches!(self.state.use_tail.proofs_encoding, Some(Ok(_))) {
                self.state.use_tail.first.get_or_insert(TailFailureV1::ProofsEncoding);
            }
        }
        if self.state.use_tail.first.is_none() {
            let sent = self.send_use_proofs_once(cutoff);
            self.state.use_tail.proofs_sent = Some(sent);
            if !matches!(self.state.use_tail.proofs_sent, Some(Ok(()))) {
                self.state.use_tail.first.get_or_insert(TailFailureV1::ProofsSend);
            }
        }
        // Actual encoding/send/accounting failure cannot suppress this post.
        self.state.owed_post = Some(RootPostFrontierV1::UseProofsAfter);
        let after = peer.recheck_once(self);
        self.state.use_tail.proofs_after = Some(after);
        if !matches!(self.state.use_tail.proofs_after, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::ProofsAfter);
        }
        if self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.proofs_settlement = Some((|| {
            self.state.use_tail.sender.dispose_after_posts_once()?;
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)?
                .advance_after_posts()
        })());
        if !matches!(self.state.use_tail.proofs_settlement, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::ProofsSettlement);
            return Err(Closed);
        }
        self.state.use_tail.proofs_complete = true;
        self.receive_use_admitted_once(peer, reserved, packet, cutoff)
    }

    fn encode_use_proofs_once(&self, reserved: &OriginalCreateStorageUseReservedV1<'_>,
        packet: &[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1],
    ) -> Result<[u8; USE_CURRENT_PROOFS_BYTES_V1], HistoryErrorV1> {
        let lane = self.state.transport.hello_body()?.open.lane;
        let receipt = reserved.receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        if positive(&self.state.use_tail.reserved_encoding)? != &receipt.encode(lane)? {
            return Err(HistoryErrorV1::Correlation);
        }
        UseCurrentProofsDataV1 { controller: receipt, cache_packet: packet }.encode(lane)
    }

    fn send_use_proofs_once(&mut self, cutoff: u64) -> Result<(), HistoryErrorV1> {
        let coordinates = self.state.use_tail.coordinates.as_ref()
            .ok_or(HistoryErrorV1::Correlation)?.current(FrameKindV1::UseCurrentProofs);
        let payload = positive(&self.state.use_tail.proofs_encoding)?;
        self.state.use_tail.sender.prepare_once(coordinates, payload)?;
        self.debit_use_stream_once(FRAME_HEADER_BYTES + USE_CURRENT_PROOFS_BYTES_V1)
            .map_err(|_| HistoryErrorV1::Correlation)?;
        let (transport, tail) = (&mut self.state.transport, &mut self.state.use_tail);
        tail.sender.send_once(transport.stream_mut()?, cutoff)
    }

    fn receive_use_admitted_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        reserved: &OriginalCreateStorageUseReservedV1<'_>,
        packet: &[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1], cutoff: u64,
    ) -> Result<(), Closed> {
        let width = reserved.request_shape_bytes_v1().map_err(|_| Closed)?;
        let maximum = width.checked_mul(2)
            .and_then(|bytes| bytes.checked_add(USE_ADMISSION_PREFIX_BYTES + USE_ADMITTED_RECEIPT_BYTES_V1))
            .ok_or(Closed)?;
        let frame_maximum = maximum.checked_add(FRAME_HEADER_BYTES).ok_or(Closed)?;
        let admitted = self.debit_use_stream_once(frame_maximum);
        self.state.use_tail.admitted_geometry = Some(
            CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1());
        let geometry = self.state.use_tail.admitted_geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied();
        if admitted.is_err() || geometry.is_none() {
            if admitted.is_ok() {
                self.state.use_tail.first.get_or_insert(TailFailureV1::AdmittedGeometry);
            }
            self.state.owed_post = Some(RootPostFrontierV1::UseAdmittedEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.admitted_entry_post = Some(post);
            return Err(Closed);
        }
        let expected = self.state.use_tail.coordinates.as_ref().ok_or(Closed)?
            .current(FrameKindV1::UseAdmitted);
        let received = self.receive_root_variable_frame_once(
            peer, cutoff, &geometry.ok_or(Closed)?, expected, maximum);
        self.state.use_tail.admitted_received = Some(received);
        if !matches!(self.state.use_tail.admitted_received, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::AdmittedReceive);
            return Err(Closed);
        }
        self.state.use_tail.admitted_body = Some(self.compare_use_admitted_once(reserved, packet, width));
        if !matches!(self.state.use_tail.admitted_body, Some(Ok(_))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::AdmittedComparison);
        }
        self.state.owed_post = Some(RootPostFrontierV1::UseAdmittedComparison);
        let post = peer.recheck_once(self);
        self.state.use_tail.admitted_post = Some(post);
        if !matches!(self.state.use_tail.admitted_post, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::AdmittedPost);
        }
        if self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.admitted_settlement = Some(
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)
                .and_then(TailCoordinatesV1::advance_after_posts));
        if !matches!(self.state.use_tail.admitted_settlement, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::AdmittedSettlement);
            return Err(Closed);
        }
        self.state.use_tail.admitted_complete = true;
        Ok(())
    }

    fn compare_use_admitted_once(&self, reserved: &OriginalCreateStorageUseReservedV1<'_>,
        packet: &[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1], maximum: usize,
    ) -> Result<UseAdmittedBodyDataV1, HistoryErrorV1> {
        let hello = self.state.transport.hello_body()?;
        let lane = hello.open.lane;
        let expected = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?
            .current(FrameKindV1::UseAdmitted);
        let frame = FrameEnvelopeV1::decode(self.state.use_tail.admitted.buffer.bytes(), expected)?;
        let transfer = UseAdmissionTransferDataV1::decode(frame.payload(), lane, maximum, maximum)?;
        let body = transfer.body(lane)?;
        let receipt = ContinuationNativeReceiptDataV1::decode(
            transfer.receipt, lane, ContinuationKindV1::UseAdmitted)?;
        let original = UseAuthorizedNativeReceiptDataV1::decode(
            &self.state.use_turn.original_authorization_frame_v1()[FRAME_HEADER_BYTES..], lane)?;
        let record = RecordEnvelopeV1::decode(original.record,
            KeyV1::new(lane, OwnerV1::Root, 2)?, PhaseV1::new(OwnerV1::Root, 2)?)?;
        receipt.require_successor(lane, ContinuationKindV1::UseAdmitted,
            record.checksum(), hello.open.seed, original.names,
            original.after_next, original.after_end)?;
        let reserved = reserved.receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        let row = RecordEnvelopeV1::decode(reserved.record,
            KeyV1::new(lane, OwnerV1::Controller, 5)?, PhaseV1::new(OwnerV1::Controller, 4)?)?;
        let held = reserved.body(lane)?;
        let claim = aos_sandbox_protocol::domain_ledger::resource_bank::Claim::decode(held.claim)
            .map_err(|_| HistoryErrorV1::Correlation)?;
        if body.use_reserved != row.checksum()
            || body.current_proofs != use_current_proofs_commitment_v1(positive(&self.state.use_tail.proofs_encoding)?)
            || body.cache_current != <[u8; 32]>::from(Sha256::digest(packet))
            || body.use_claim != claim.native_fields().id {
            return Err(HistoryErrorV1::Correlation);
        }
        // Source2's commitment is authenticated Root attestation DATA; C's
        // separate semantic/key/scope/clock signing checks remain mandatory.
        Ok(body)
    }
}

/// Borrows actual Root8 after strict native receipt and every owed post.
///
/// There is no constructor from bytes, a vector, cutoff or supplied success.
pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageRootUseAdmittedV1<'held> {
    turn: &'held RootUseTailOriginalsV1,
    reserved: &'held OriginalCreateStorageUseReservedV1<'held>,
    cutoff: u64,
    maximum: usize,
}

impl<'held> OriginalCreateStorageRootUseAdmittedV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn frame_v1(&self) -> &'held [u8] { self.turn.admitted.buffer.bytes() }

    fn transfer_v1(&self) -> Result<UseAdmissionTransferDataV1<'held>, ResourceReservationErrorV1> {
        let coordinates = self.turn.coordinates.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        UseAdmissionTransferDataV1::decode(&self.frame_v1()[FRAME_HEADER_BYTES..],
            coordinates.hello.open.lane, self.maximum, self.maximum)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        let lane = self.turn.coordinates.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.hello.open.lane;
        ContinuationNativeReceiptDataV1::decode(self.transfer_v1()?.receipt,
            lane, ContinuationKindV1::UseAdmitted).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<&'held UseAdmittedBodyDataV1, ResourceReservationErrorV1> {
        self.turn.admitted_body.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn plan_v1(&self) -> Result<&'held [u8], ResourceReservationErrorV1> { Ok(self.transfer_v1()?.plan) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn statement_v1(&self) -> Result<&'held [u8], ResourceReservationErrorV1> { Ok(self.transfer_v1()?.statement) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn reserved_v1(&self) -> Result<UseReservedNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        self.reserved.receipt_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> u64 { self.cutoff }
}


impl RootExchangeOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn borrow_use_admitted_v1<'held>(&'held self,
        reserved: &'held OriginalCreateStorageUseReservedV1<'held>,
    ) -> Result<OriginalCreateStorageRootUseAdmittedV1<'held>, ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.use_cache_current_proof.completed_packet_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        borrow_admitted_from_turn_v1(&self.turn, reserved)
    }
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    // The long native signing borrower can take this short input view, end it,
    // and then run its independently owed posts using this same mutable loan.
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn borrow_use_admitted_v1<'held>(&'held self,
        reserved: &'held OriginalCreateStorageUseReservedV1<'held>,
    ) -> Result<OriginalCreateStorageRootUseAdmittedV1<'held>, ResourceReservationErrorV1> {
        self.require_fixed().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.use_receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .require_reserved_v1()?;
        borrow_admitted_from_turn_v1(self.state, reserved)
    }
}

fn borrow_admitted_from_turn_v1<'held>(
    state: &'held super::super::RootTurnStateV1,
    reserved: &'held OriginalCreateStorageUseReservedV1<'held>,
) -> Result<OriginalCreateStorageRootUseAdmittedV1<'held>, ResourceReservationErrorV1> {
    let turn = &state.use_tail;
    if !state.use_cache_complete || !turn.admitted_complete || turn.first.is_some()
        || !turn.proofs_complete
        || state.samples.iter().any(Option::is_some)
        || !matches!(turn.admitted_received, Some(Ok(())))
        || !matches!(turn.admitted_body, Some(Ok(_)))
        || !matches!(turn.admitted_post, Some(Ok(())))
        || !matches!(turn.admitted_settlement, Some(Ok(())))
        || state.expected_controller != Some(reserved.position_v1()?) {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    Ok(OriginalCreateStorageRootUseAdmittedV1 {
        turn, reserved, cutoff: turn.admitted_cutoff.ok_or(ResourceReservationErrorV1::Conflict)?,
        maximum: reserved.request_shape_bytes_v1()?,
    })
}
