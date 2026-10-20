//! Sends the actual same-bank U receipt and accepts Root's second invitation.
//!
//! The only entry splits the real completed native U owner alongside its own
//! ledger. No caller supplies a receipt, position, width, amount or nonce.

use super::*;
use crate::controller_resource_reservation::create_intake::ready::{
    OriginalCreateStorageReadyV1,
    use_reserved::OriginalCreateStorageUseReservedV1,
};
use crate::controller_resource_reservation::create_intake::ready::root_exchange::{
    CreateStorageRootExchangeClosedV1 as Closed,
    OriginalCreateStorageRootExchangeV1, RootPostFrontierV1, RootReceivePurposeV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    current_proofs::CurrentProofsChallengeDataV1, root_open::RootHelloDataV1,
};

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Sends the actual UseReserved receipt on the continuously held Root stream.
    ///
    /// This enters only after the same native U reserve and Controller pair
    /// have completed. Root's fresh second invitation is checked on that stream
    /// before the separate second Cache producer can be entered.
    ///
    /// # Errors
    /// Refuses reentry, unresolved earlier originals, wrong current position,
    /// exceeded U receiving limits, changed Root/Source/Cache/native state,
    /// deadline expiry or any native/independent post failure. Custody remains
    /// in the same Ready and actual U is never refunded or reconstructed.
    #[doc(hidden)]
    pub fn exchange_root_use_reserved_once(&mut self) -> Result<(), Closed> {
        if self.failure().is_some() || self.original.owner.root_exchange.turn.use_tail.started() {
            return Err(Closed);
        }
        self.original.require_operation_currentness_peak_v1(&self.cache).map_err(|_| Closed)?;
        self.original.owner.root_exchange.borrow_use_authorization_v1().map_err(|_| Closed)?;
        let original_cutoff = self.original.accepted().map_err(|_| Closed)?.original_cutoff;
        let owner = &mut *self.original.owner;
        let root = &mut owner.root_exchange;
        if root.turn.samples.iter().any(Option::is_some) || root.peer.failure().is_some() {
            return Err(Closed);
        }
        let mut original = owner.storage_use.borrow_root_receiving_once_v1().map_err(|_| Closed)?;
        let (reserved, receiving) = original.split_original_and_receiving_v1().map_err(|_| Closed)?;
        // This is the actual returned/readback position, not a public setter
        // and not an equal-or-later head reconstructed from receipt DATA.
        root.turn.expected_controller = Some(reserved.position_v1().map_err(|_| Closed)?);
        root.turn.use_tail.attempted = true;
        let mut loan = OriginalCreateStorageRootExchangeV1 {
            parent: &owner.parent, intake: &mut owner.intake,
            controller: self.original.controller, source: self.original.source,
            profile: self.original.profile, cache: &mut self.cache,
            state: &mut root.turn, use_receiving: Some(receiving),
        };
        loan.run_reserved_turn_once(&mut root.peer, reserved, original_cutoff)
    }
}

impl OriginalCreateStorageRootExchangeV1<'_, '_, '_> {
    // This branch is reachable only through the private actual U constructor.
    // Old J observations use their original funding code and paid counter.
    pub(in crate::controller_resource_reservation::create_intake::ready::root_exchange)
    fn prepay_use_root_observations_once(&mut self, following: usize) -> Result<(), Closed> {
        let required = self.state.property_used.checked_add(following).ok_or(Closed)?;
        if required <= self.state.use_tail.property_paid { return Ok(()); }
        let delta = required.checked_sub(self.state.use_tail.property_paid).ok_or(Closed)?;
        self.state.property_geometry = Some((|| {
            if required > self.state.use_tail.property_limit {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let actual = self.profile.create_storage_producer_traffic_v1(
                delta.checked_mul(2).ok_or(ResourceReservationErrorV1::Conflict)?,
            ).ok_or(ResourceReservationErrorV1::Conflict)?;
            let bound = crate::normal_root::ProductionControllerNormalRootProfileV1::
                create_storage_producer_traffic_bound_v1(
                    delta.checked_mul(2).ok_or(ResourceReservationErrorV1::Conflict)?,
                ).ok_or(ResourceReservationErrorV1::Conflict)?;
            if actual != bound { return Err(ResourceReservationErrorV1::Conflict); }
            root_use_observation_traffic_v1(delta)
        })());
        self.state.property_funding = Some(match self.state.property_geometry.as_ref() {
            Some(Ok(demand)) => match self.use_receiving.as_deref_mut() {
                Some(original) => original.reserve_once(*demand),
                None => Err(ResourceReservationErrorV1::Conflict),
            },
            _ => Err(ResourceReservationErrorV1::Conflict),
        });
        if matches!(self.state.property_funding, Some(Ok(()))) {
            self.state.use_tail.property_paid = required;
            Ok(())
        } else {
            self.state.use_tail.first.get_or_insert(TailFailureV1::Funding);
            Err(Closed)
        }
    }

    fn run_reserved_turn_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        reserved: &OriginalCreateStorageUseReservedV1<'_>, original_cutoff: u64,
    ) -> Result<(), Closed> {
        let used = self.state.property_used;
        self.state.use_tail.shape = Some((|| {
            let shape = create_storage_root_use_tail_shape_v1(reserved.request_shape_bytes_v1()?)?;
            self.state.use_tail.property_limit = used.checked_add(shape.root_observations)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let properties = root_use_observation_traffic_v1(shape.root_observations)?;
            self.state.use_tail.wire_limit = shape.receiving.get(D::NetworkBytes)
                .checked_sub(properties.get(D::NetworkBytes))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(shape)
        })());
        if !matches!(self.state.use_tail.shape, Some(Ok(_))) {
            self.state.use_tail.first = Some(TailFailureV1::Geometry);
            return Err(Closed);
        }
        self.state.use_tail.property_paid = used;
        // Admit the first before, its independent after, and one following
        // refusal post before entering a new Root-native purpose. Failed pure
        // pre-entry admission starts no Root IO or hidden replacement scope.
        self.prepay_use_root_observations_once(3)?;
        self.state.use_tail.entered = true;
        let shape = self.state.use_tail.shape.as_ref().and_then(|v| v.as_ref().ok()).ok_or(Closed)?;
        self.state.use_tail.fixed = Some(self.use_receiving.as_deref_mut().ok_or(Closed)?
            .reserve_once(shape.receiving.with(D::NetworkBytes, 0).with(D::LogBytes, 0)));
        if !matches!(self.state.use_tail.fixed, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::Funding);
        }
        let cutoff = self.state.transport.hello_body().map_err(|_| Closed)?.cutoff.min(original_cutoff);
        if self.state.use_tail.first.is_none() {
            self.state.owed_post = Some(RootPostFrontierV1::UseTailBefore);
            let before = peer.recheck_once(self);
            self.state.use_tail.before = Some(before);
            if !matches!(self.state.use_tail.before, Some(Ok(()))) {
                self.state.use_tail.first.get_or_insert(TailFailureV1::Before);
            }
        }
        if self.state.use_tail.first.is_none() {
            self.state.use_tail.sent_reserved = Some(self.send_actual_reserved_once(reserved, cutoff));
            if !matches!(self.state.use_tail.sent_reserved, Some(Ok(()))) {
                self.state.use_tail.first.get_or_insert(TailFailureV1::Send);
            }
        }
        // This independently owed full Root/Controller/Source/Cache/native
        // sample runs after every entered outcome, including admission refusal.
        self.state.owed_post = Some(RootPostFrontierV1::UseTailAfter);
        let after = peer.recheck_once(self);
        self.state.use_tail.after = Some(after);
        if !matches!(self.state.use_tail.after, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::After);
        }
        if self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.reserved_settlement = Some((|| {
            self.state.use_tail.sender.dispose_after_posts_once()?;
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)?
                .advance_after_posts()
        })());
        if !matches!(self.state.use_tail.reserved_settlement, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::ReservedSettlement);
            return Err(Closed);
        }
        self.state.use_tail.reserved_complete = true;
        self.await_use_invitation_once(peer, cutoff)
    }

    fn send_actual_reserved_once(&mut self, reserved: &OriginalCreateStorageUseReservedV1<'_>,
        cutoff: u64,
    ) -> Result<(), HistoryErrorV1> {
        let hello = *self.state.transport.hello_body()?;
        let index = self.state.transport.completed_index()?;
        self.state.use_tail.coordinates = Some(TailCoordinatesV1::new(hello, index)?);
        let coordinates = self.state.use_tail.coordinates.as_ref().ok_or(HistoryErrorV1::Correlation)?
            .current(FrameKindV1::UseReserved);
        // The whole actual receipt remains borrowed beside mutable U. Encoding
        // begins only after its fixed/native peak and same Root before passed.
        self.state.use_tail.reserved_encoding = Some(reserved.receipt_v1()
            .map_err(|_| HistoryErrorV1::Correlation).and_then(|receipt| receipt.encode(hello.open.lane)));
        let payload = self.state.use_tail.reserved_encoding.as_ref().and_then(|v| v.as_ref().ok())
            .ok_or(HistoryErrorV1::Correlation)?;
        self.state.use_tail.sender.prepare_once(coordinates, payload)?;
        self.debit_use_stream_once(FRAME_HEADER_BYTES + USE_RESERVED_RECEIPT_BYTES_V1)
            .map_err(|_| HistoryErrorV1::Correlation)?;
        let (transport, tail) = (&mut self.state.transport, &mut self.state.use_tail);
        tail.sender.send_once(transport.stream_mut()?, cutoff)
    }

    pub(super) fn debit_use_stream_once(&mut self, bytes: usize) -> Result<(), Closed> {
        self.state.use_tail.wire_funding = Some((|| {
            let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let reached = self.state.use_tail.wire_used.checked_add(bytes)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if reached > self.state.use_tail.wire_limit {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.use_receiving.as_deref_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .reserve_once(ResourceVector::ZERO.with(D::NetworkBytes, bytes))?;
            self.state.use_tail.wire_used = reached;
            Ok(())
        })());
        if matches!(self.state.use_tail.wire_funding, Some(Ok(()))) { Ok(()) }
        else {
            self.state.use_tail.first.get_or_insert(TailFailureV1::Funding);
            Err(Closed)
        }
    }

    fn await_use_invitation_once(&mut self, peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        cutoff: u64,
    ) -> Result<(), Closed> {
        let funded = self.debit_use_stream_once(CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1);
        if funded.is_err() {
            self.state.owed_post = Some(RootPostFrontierV1::UseTailInvitationEntry);
            let post = peer.recheck_once(self);
            self.state.use_tail.invitation_entry_post = Some(post);
            return Err(Closed);
        }
        self.state.use_tail.invitation_geometry = Some(
            CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1());
        let geometry = match self.state.use_tail.invitation_geometry.as_ref() {
            Some(Ok(geometry)) => *geometry,
            _ => {
                self.state.use_tail.first.get_or_insert(TailFailureV1::InvitationGeometry);
                self.state.owed_post = Some(RootPostFrontierV1::UseTailInvitationEntry);
                let post = peer.recheck_once(self);
                self.state.use_tail.invitation_entry_post = Some(post);
                return Err(Closed);
            }
        };
        let received = self.receive_root_subject_once(peer, cutoff, &geometry, RootReceivePurposeV1::UseInvitation);
        if received.is_err() {
            self.state.use_tail.first.get_or_insert(TailFailureV1::ReceiveInvitation);
            return Err(Closed);
        }
        self.state.use_tail.invitation_decoding = Some((|| {
            let body = self.state.transport.hello_body()?;
            let hello = RootHelloDataV1::decode(self.state.transport.hello_frame(), body.open)?;
            let value = CurrentProofsChallengeDataV1::decode_use_frame(
                self.state.use_tail.invitation.buffer.bytes(), &hello, self.state.transport.completed_index()?)?;
            // The first invitation already joined the exact completed B Held
            // bytes to this Hello. The second purpose has the SAME challenge,
            // while its actual independent signer half and clock are fresh.
            if self.state.invitation.as_ref().and_then(|v| v.as_ref().ok()) != Some(&value) {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(value)
        })());
        if !matches!(self.state.use_tail.invitation_decoding, Some(Ok(_))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::DecodeInvitation);
        }
        self.state.owed_post = Some(RootPostFrontierV1::UseTailInvitation);
        let post = peer.recheck_once(self);
        self.state.use_tail.invitation_post = Some(post);
        if !matches!(self.state.use_tail.invitation_post, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::InvitationPost);
        }
        if self.state.use_tail.first.is_some() { return Err(Closed); }
        self.state.use_tail.invitation_settlement = Some(
            self.state.use_tail.coordinates.as_mut().ok_or(HistoryErrorV1::Correlation)
                .and_then(TailCoordinatesV1::advance_after_posts));
        if !matches!(self.state.use_tail.invitation_settlement, Some(Ok(()))) {
            self.state.use_tail.first.get_or_insert(TailFailureV1::InvitationSettlement);
            return Err(Closed);
        }
        self.state.use_tail.invitation_complete = true;
        Ok(())
    }
}
