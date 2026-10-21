//! Keeps original Ready framing across the independent Controller proof receive.
//!
//! The parsed bundle borrows the enclosing programme's immutable Ready bytes.
//! The nested mechanical subject loan borrows disjoint mutable Cache/stream
//! fields and ends before Root completes its own independent signer flight.

use std::error::Error;
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    cache_held::{CACHE_HELD_RECEIPT_BYTES_V1, CacheHeldReceiptDataV1,
        current_proof::{current_cache_challenge_digest_v1, verify_current_cache_proof_retaining_v1}},
    current_proofs::CurrentProofsChallengeDataV1,
    ready::ReadyBundleDataV1,
    root_open::RootHelloDataV1,
    transport::TransferIndexV1,
};

use super::{
    E, HistoryErrorV1, RootInitialCacheProofOriginalV1,
    RootInitialBundleOwnershipOriginalV1, RootInitialOpenPreparedOriginalV1,
    RootInitialPinsOriginalV1, RootInitialReadyOriginalV1,
    RootInitialSourceExchangeOriginalV1, RootCurrentAcceptedOriginalsV1,
    RootCurrentWritersOriginalV1, PROOFS_FRAME_BYTES, USE_PROOFS_FRAME_BYTES, positive, require_clock, received_proofs_v1,
    received_use_proofs_v1, require_same_reserved_receipt_v1,
};
use super::super::initial_subject::RootInitialSubjectFrameBorrowV1;
use super::super::proof_turn::RootCurrentProofTurnV1;

/// Borrows the same Ready fields through Initial Cache proof verification.
///
/// Only a real admitted owning programme constructs this frame. A nested subject
/// loan uses its actual retained stream and peer; no raw stream, replacement
/// parsed Ready, supplied interval or successful result can create this loan.
pub struct RootInitialCacheProofFrameBorrowV1<'cut, 'startup> {
    state: &'cut mut RootInitialCacheProofOriginalV1,
    turn: RootCurrentProofTurnV1<'cut>,
    bundle: ReadyBundleDataV1<'cut>,
    raw: &'cut [u8],
    hello: RootHelloDataV1<'cut>,
    index: TransferIndexV1,
    open: &'cut RootInitialOpenPreparedOriginalV1,
    source: &'cut RootInitialSourceExchangeOriginalV1,
    pins: &'cut RootInitialPinsOriginalV1,
    originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
}

impl<'cut, 'startup> RootInitialCacheProofFrameBorrowV1<'cut, 'startup> {
    pub(in crate::native::root_current) fn prepare_once_v1(
        state: &'cut mut RootInitialCacheProofOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        pins: &'cut RootInitialPinsOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        original: &UnixStream,
    ) -> Result<Self, E> {
        Self::prepare_for_turn_once_v1(state, writers, open, ready, source, pins,
            ownership, originals, original, RootCurrentProofTurnV1::Initial)
    }

    pub(in crate::native::root_current) fn prepare_reserved_once_v1(
        state: &'cut mut RootInitialCacheProofOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        pins: &'cut RootInitialPinsOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        original: &UnixStream,
        authorization: &'cut super::super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &'cut super::super::use_tail::reserved::RootUseReservedOriginalV1,
    ) -> Result<Self, E> {
        Self::prepare_for_turn_once_v1(state, writers, open, ready, source, pins,
            ownership, originals, original,
            RootCurrentProofTurnV1::Reserved { authorization, reserved })
    }

    fn prepare_for_turn_once_v1(
        state: &'cut mut RootInitialCacheProofOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        pins: &'cut RootInitialPinsOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        original: &UnixStream,
        turn: RootCurrentProofTurnV1<'cut>,
    ) -> Result<Self, E> {
        if state.body_entered || state.closed {
            state.closed = true;
            return Err(E::Incomplete);
        }
        state.body_entered = true;
        let result = prepare_body_v1(
            state, writers, open, ready, source, ownership, originals, original, turn,
        );
        let (bundle, raw, hello, index) = match result {
            Ok(prepared) => {
                state.prepared = Some(Ok(()));
                prepared
            }
            Err(error) => {
                state.prepared = Some(Err(error));
                return Err(E::Incomplete);
            }
        };
        Ok(Self { state, turn, bundle, raw, hello, index, open, source, pins, originals })
    }

    /// Borrows this same prepared Controller frame and genuine subject receiver.
    ///
    /// Run the sole shared subject programme with its existing short actual
    /// Initial/L arms. End this nested loan before finishing the signer flight.
    ///
    /// # Errors
    /// Refuses failed preparation or unavailable actual geometry/Source interval.
    pub fn borrow_subject_once_v1(
        &mut self,
    ) -> Result<RootInitialSubjectFrameBorrowV1<'_, 'startup>, super::RootInitialOpenErrorV1> {
        positive(&self.state.prepared).map_err(|_| super::RootInitialOpenErrorV1::Boundary)?;
        let geometry = *self.state.geometry.as_ref()
            .map_err(|_| super::RootInitialOpenErrorV1::Boundary)?;
        self.state.chunks.borrow_source_frame_v1(
            &mut self.state.received_frame, self.originals, self.open, self.source, geometry,
        )
    }

    /// Finishes Root's independently received and pinned packet after forwarding.
    ///
    /// # Errors
    /// Retains incomplete subject custody, frame/receipt mismatch, signer refusal,
    /// signature failure or any disagreement between the two actual packets.
    pub fn finish_once_v1(&mut self) -> Result<(), E> {
        if self.state.primary.is_some() || self.state.closed {
            self.state.closed = true;
            return Err(E::Incomplete);
        }
        self.state.primary = Some(self.finish_inner_v1());
        positive(&self.state.primary).map(|_| ())
    }

    fn finish_inner_v1(&mut self) -> Result<(), E> {
        positive(&self.state.prepared)?;
        self.state.received = Some(if self.state.received_frame.completed_exact()
            && self.state.chunks.disposed_v1()
        {
            Ok(())
        } else {
            Err(E::Incomplete)
        });
        positive(&self.state.received)?;
        let body = self.hello.body;
        let hello = self.hello;
        let index = self.index;
        let raw = self.raw;
        let held: &[u8; CACHE_HELD_RECEIPT_BYTES_V1] = self.bundle.cache_held.try_into()
            .map_err(|_| HistoryErrorV1::Extent)?;

        self.state.proofs_binding = Some((|| {
            match self.turn {
                RootCurrentProofTurnV1::Initial => {
                    let proofs = received_proofs_v1(self.state.received_frame.bytes(), hello, index)?;
                    if proofs.cache_packet.len() != 1064 {
                        return Err(HistoryErrorV1::Extent);
                    }
                    proofs.controller.body(body.open.lane)?.require_bundle(raw)
                }
                RootCurrentProofTurnV1::Reserved { reserved, .. } => {
                    let proofs = received_use_proofs_v1(self.state.received_frame.bytes(), hello, index)?;
                    let expected = reserved.completed_receipt_v1(body.open.lane)
                        .map_err(|_| HistoryErrorV1::Correlation)?;
                    require_same_reserved_receipt_v1(proofs.controller, expected)
                }
            }
        })());
        positive(&self.state.proofs_binding)?;
        self.state.finish = Some(self.state.transport.finish_once());
        positive(&self.state.finish)?;
        let packet = match self.state.transport.packet() {
            Ok(packet) => {
                self.state.packet = Some(Ok(()));
                packet
            }
            Err(error) => {
                self.state.packet = Some(Err(error));
                return Err(E::Incomplete);
            }
        };
        let pin = self.pins.cache_signer_v1()?;
        self.state.verified = Some(verify_current_cache_proof_retaining_v1(
            packet, pin.verifying_key(), pin.generation(), &mut self.state.verification,
        ));
        positive(&self.state.verified)?;
        self.state.association = Some((|| {
            let signed = self.state.verification.body().ok_or(HistoryErrorV1::Correlation)?;
            signed.compare_root_hello_data(hello)?;
            signed.compare_held_data(CacheHeldReceiptDataV1::decode(held, body.open.lane)?)?;
            let forwarded = match self.turn {
                RootCurrentProofTurnV1::Initial => received_proofs_v1(
                    self.state.received_frame.bytes(), hello, index,
                )?.cache_packet,
                RootCurrentProofTurnV1::Reserved { .. } => received_use_proofs_v1(
                    self.state.received_frame.bytes(), hello, index,
                )?.cache_packet,
            };
            if forwarded != packet {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(())
        })());
        positive(&self.state.association).map(|_| ())
    }

    /// Borrows the actual first retained cause while this scoped frame is live.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.state.failure_v1()
    }
}

fn prepare_body_v1<'ready, 'open>(
    state: &mut RootInitialCacheProofOriginalV1,
    writers: &RootCurrentWritersOriginalV1,
    open: &'open RootInitialOpenPreparedOriginalV1,
    ready: &'ready RootInitialReadyOriginalV1,
    source: &RootInitialSourceExchangeOriginalV1,
    ownership: &RootInitialBundleOwnershipOriginalV1,
    originals: &RootCurrentAcceptedOriginalsV1<'_>,
    original: &UnixStream,
    turn: RootCurrentProofTurnV1<'_>,
) -> Result<(ReadyBundleDataV1<'ready>, &'ready [u8], RootHelloDataV1<'open>, TransferIndexV1), E> {
    state.stage.require_complete_v1()?;
    ownership.require_complete_v1()?;
    source.require_complete_v1()?;
    state.turn_binding = Some(turn.authorization_checksum_v1(open).map_err(E::Open));
    positive(&state.turn_binding)?;
    let raw = ready.raw_ready_bytes_v1()?;
    let bundle = match ReadyBundleDataV1::borrow_field_framing_data_v1(raw) {
        Ok(bundle) => {
            state.framing = Some(Ok(()));
            bundle
        }
        Err(error) => {
            state.framing = Some(Err(error));
            return Err(E::Incomplete);
        }
    };
    state.configuration = Some(match originals.peer.native_peer_original_v1() {
        Ok(peer) => peer.current_cache_signer_identity_data_v1(),
        Err(error) => Err(error),
    });
    let (uid, gid, socket_gid) = *positive(&state.configuration)?;
    state.hello_copy = Some(ready.original_hello_frame_v1(open, &mut state.hello));
    positive(&state.hello_copy)?;
    let body = open.body_v1()?;
    let hello = RootHelloDataV1::decode(&state.hello, body.open)?;
    let held: &[u8; CACHE_HELD_RECEIPT_BYTES_V1] = bundle.cache_held.try_into()
        .map_err(|_| HistoryErrorV1::Extent)?;
    let cutoff = source.original_cutoff_v1()?;

    match writers.opened_pair_view_v1() {
        Ok((authority, policy)) => {
            state.before.observe_once_v1(authority, policy);
            state.before_readback = Some(turn.readback_v1(open, authority, policy));
        }
        Err(error) => {
            state.before_readback = Some(Err(super::RootInitialOpenErrorV1::Root(error)));
        }
    }
    state.before.require_complete_v1()?;
    positive(&state.before_readback)?;
    state.before_sample = Some(state.before_clock.observe_once(None));
    state.before_cutoff = Some(require_clock(open, source, &state.before_sample));
    positive(&state.before_cutoff)?;

    state.begin = Some(state.transport.begin_root_half_once(
        &state.hello, held, uid, gid, socket_gid, cutoff,
    ));
    positive(&state.begin)?;
    let index = ready.original_transfer_index_v1()?;
    let invitation = CurrentProofsChallengeDataV1 {
        lane: body.open.lane,
        root_open: hello.checksum,
        root_nonce: body.root_nonce,
        ready: body.open.ready,
        challenge: current_cache_challenge_digest_v1(&state.hello, held),
    };
    state.invitation_encoding = Some(match turn {
        RootCurrentProofTurnV1::Initial => invitation.encode_frame(&hello, index),
        RootCurrentProofTurnV1::Reserved { .. } => invitation.encode_use_frame(&hello, index),
    }.map(|bytes| state.invitation = bytes));
    positive(&state.invitation_encoding)?;
    let mut stream = original;
    state.sent = Some(state.invitation_io.run_once(
        &mut stream, &mut state.invitation, cutoff, DeadlineStreamDirectionV1::Write,
    ));
    positive(&state.sent)?;
    state.preparation = Some(state.received_frame.prepare_exact_once(match turn {
        RootCurrentProofTurnV1::Initial => PROOFS_FRAME_BYTES,
        RootCurrentProofTurnV1::Reserved { .. } => USE_PROOFS_FRAME_BYTES,
    }));
    positive(&state.preparation)?;
    // The old caller checks its saved geometry only after preparing the buffer.
    state.geometry.as_ref().map_err(|_| E::Incomplete)?;
    // The decoded header/body/checksum are saved across the receive. Its
    // record borrow points into the same immutable Open record copied above,
    // avoiding a self-reference to mutable Cache state or a second decode.
    let hello = RootHelloDataV1 {
        record: open.committed_record_v1()?,
        body: hello.body,
        checksum: hello.checksum,
    };
    Ok((bundle, raw, hello, index))
}
