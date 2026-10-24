//! Quotes the complete selected upload suffix against unchanged lifetime banks.
//!
//! Additional content custody does not expand the original B/F/sequence or
//! endpoint record ledger. This readonly check precedes any selected lease
//! receipt. Unknown incoming originals retain the full negotiated raw allowance.

use super::*;
use crate::reference_packet::service::complete_restore::{
    PacketNative5CompleteRestoreSelection, transfer::PacketCompleteRestorePrepareRequest,
};
use crucible_node_format::ContentRef;
use std::cell::Ref;

/// Reports protocol demand data without reserving slots or granting receive rights.
#[derive(Clone, Copy)]
pub(crate) struct NativeRestoreInputProtocolDemand {
    pub(crate) incoming_frames: usize,
    pub(crate) outgoing_frames: usize,
    pub(crate) incoming_framed_bytes: usize,
    pub(crate) outgoing_framed_bytes: usize,
    pub(crate) endpoint_transport_bytes: usize,
}

fn demand(
    lengths: [usize; 6],
    chunk: usize,
    maximum_frame: usize,
    ack: usize,
    maximum_held_evidence: usize,
) -> Result<NativeRestoreInputProtocolDemand, ProviderError> {
    if chunk == 0 || chunk > 4096 || maximum_frame > 65536 || ack < 4 || maximum_held_evidence == 0
    {
        return Err(credit());
    }
    let blob_requests = lengths.into_iter().try_fold(0usize, |count, length| {
        if length == 0 {
            return Err(credit());
        }
        count
            .checked_add(2)
            .and_then(|count| count.checked_add(length.div_ceil(chunk)))
            .ok_or_else(credit)
    })?;
    // The genuine held gate travels before the terminal Commit response.
    // Its maximum comes from the actual closed producer's compiled field walk,
    // never from a caller scalar, the input-bank lengths or protocol P.
    let held_requests = maximum_held_evidence
        .div_ceil(chunk)
        .checked_add(2)
        .ok_or_else(credit)?;
    let incoming_frames = blob_requests
        .checked_add(1)
        .and_then(|n| n.checked_add(held_requests))
        .ok_or_else(credit)?;
    let outgoing_frames = blob_requests
        .checked_add(2)
        .and_then(|n| n.checked_add(held_requests))
        .ok_or_else(credit)?;
    let raw = maximum_frame.checked_add(4).ok_or_else(credit)?;
    // No selected host ACK-reader scope exists for this proof. Each ACK keeps
    // the complete negotiated raw allowance, independently of upload ACK bounds.
    let held_ack_bytes = held_requests.checked_mul(raw).ok_or_else(credit)?;
    let incoming_framed_bytes = incoming_frames.checked_mul(raw).ok_or_else(credit)?;
    let outgoing_framed_bytes = blob_requests
        .checked_mul(ack)
        .and_then(|bytes| bytes.checked_add(2usize.checked_mul(raw)?))
        .and_then(|bytes| bytes.checked_add(held_requests.checked_mul(raw)?))
        .ok_or_else(credit)?;
    // Charge both directions' retained proof envelopes/decoded responses and
    // canonical banks conservatively. Typed Vec/owner layouts remain in the
    // separately admitted simultaneous allocation quote.
    let endpoint_transport_bytes = outgoing_framed_bytes
        .checked_add(held_ack_bytes)
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or_else(credit)?;
    Ok(NativeRestoreInputProtocolDemand {
        incoming_frames,
        outgoing_frames,
        incoming_framed_bytes,
        outgoing_framed_bytes,
        endpoint_transport_bytes,
    })
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn quote_original_complete_restore_input_protocol(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<NativeRestoreInputProtocolDemand, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || self.fenced
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.original_restore_inputs.is_some()
        {
            return Err(credit());
        }
        let chunk = allowance(self.authority.limits().blob_chunk_bytes.get())?.min(4096);
        let raw = allowance(self.authority.limits().frame_bytes.get())?;
        let mut lengths = [0; 6];
        for (length, reference) in lengths
            .iter_mut()
            .zip(super::restore_input_quote::input_references(request))
        {
            *length = allowance(reference.length.get())?;
        }
        demand(
            lengths,
            chunk,
            raw,
            self.original_canonical_blob_ack_framed_bytes()?,
            crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_bytes()?,
        )
    }

    pub(crate) fn preflight_original_complete_restore_input_suffix(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
        endpoint_remaining_records: usize,
        retained_endpoint_transport_bytes: usize,
    ) -> Result<(), ProviderError> {
        let demand = self.quote_original_complete_restore_input_protocol(request)?;
        if demand.outgoing_frames > endpoint_remaining_records
            || retained_endpoint_transport_bytes
                .checked_add(demand.endpoint_transport_bytes)
                .is_none_or(|bytes| {
                    bytes > crate::reference_packet::endpoint::MAXIMUM_PACKET_TRANSPORT_BYTES
                })
        {
            return Err(credit());
        }
        self.guard
            .preflight_restore_input_sequences(demand.outgoing_frames, demand.incoming_frames)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(credit)?
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("restore input protocol bank borrowed"))?;
        bank.preflight_framed_suffix(
            demand.outgoing_frames,
            demand.outgoing_framed_bytes,
            demand.incoming_frames,
            demand.incoming_framed_bytes,
        )
    }

    pub(crate) fn original_complete_restore_input_reference(
        &self,
        index: usize,
    ) -> Result<Ref<'_, ContentRef>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let installed = self.original_restore_inputs.as_ref().ok_or_else(credit)?;
        installed.token.authenticate_current(self)?;
        let request = installed.token.request(self)?;
        Ref::filter_map(request, |request| {
            super::restore_input_quote::input_references(request)
                .into_iter()
                .nth(index)
        })
        .map_err(|_| credit())
    }
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("complete restore original protocol suffix")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "checks finite original frame demand")]
mod tests {
    use super::*;

    fn held_maximum() -> usize {
        crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_bytes().unwrap()
    }

    #[test]
    fn current_202_bank_cannot_admit_six_inputs_and_actual_held_proof() {
        let maximum = held_maximum();
        let held_requests = maximum.div_ceil(4096) + 2;
        let quote = demand([1; 6], 4096, 65536, 1824, maximum).unwrap();
        assert!(maximum > 0);
        assert_eq!(quote.incoming_frames, 19 + held_requests);
        assert_eq!(quote.outgoing_frames, 20 + held_requests);
        assert_eq!(quote.incoming_framed_bytes, (19 + held_requests) * 65_540);
        assert_eq!(
            quote.outgoing_framed_bytes,
            18 * 1824 + (2 + held_requests) * 65_540
        );
        assert_eq!(
            quote.endpoint_transport_bytes,
            (quote.outgoing_framed_bytes + held_requests * 65_540) * 3
        );
        // Even the smallest nonempty held body needs Begin/Chunk/Finish and
        // three raw success ACKs: at least 22 incoming frames, 1,441,880 bytes.
        assert!(quote.incoming_frames >= 22);
        assert!(quote.incoming_framed_bytes >= 1_441_880);
        let bank =
            crate::transport::original_frames::OriginalFrameReservation::reserve(1_048_576, 64)
                .unwrap();

        assert!(
            bank.preflight_framed_suffix(
                quote.outgoing_frames,
                quote.outgoing_framed_bytes,
                quote.incoming_frames,
                quote.incoming_framed_bytes,
            )
            .is_err()
        );
        assert_eq!(bank.frames().count(), 0);
    }

    #[test]
    fn actual_held_proof_quote_exact_boundary_and_one_short() {
        let quote = demand([1; 6], 4096, 65536, 1824, held_maximum()).unwrap();
        let total = quote
            .outgoing_framed_bytes
            .checked_add(quote.incoming_framed_bytes)
            .unwrap();
        let frames = quote.outgoing_frames.max(quote.incoming_frames);
        let exact =
            crate::transport::original_frames::OriginalFrameReservation::reserve(total, frames)
                .unwrap();
        let short =
            crate::transport::original_frames::OriginalFrameReservation::reserve(total - 1, frames)
                .unwrap();

        exact
            .preflight_framed_suffix(
                quote.outgoing_frames,
                quote.outgoing_framed_bytes,
                quote.incoming_frames,
                quote.incoming_framed_bytes,
            )
            .unwrap();
        assert!(
            short
                .preflight_framed_suffix(
                    quote.outgoing_frames,
                    quote.outgoing_framed_bytes,
                    quote.incoming_frames,
                    quote.incoming_framed_bytes
                )
                .is_err()
        );
        assert_eq!(exact.frames().count(), 0);
        assert_eq!(short.frames().count(), 0);
    }

    #[test]
    fn input_and_held_chunk_boundaries_and_overflow_do_not_earn_credit() {
        let maximum = held_maximum();
        let first = demand([4096; 6], 4096, 65536, 1824, maximum).unwrap();
        let second = demand([4097; 6], 4096, 65536, 1824, maximum).unwrap();
        assert_eq!(second.incoming_frames - first.incoming_frames, 6);
        assert_eq!(second.outgoing_frames - first.outgoing_frames, 6);
        let one = demand([1; 6], 4096, 65536, 1824, 4096).unwrap();
        let two = demand([1; 6], 4096, 65536, 1824, 4097).unwrap();
        assert_eq!(two.incoming_frames - one.incoming_frames, 1);
        assert_eq!(two.outgoing_frames - one.outgoing_frames, 1);
        assert!(demand([0; 6], 4096, 65536, 1824, maximum).is_err());
        assert!(demand([usize::MAX; 6], 1, 65536, 1824, maximum).is_err());
        assert!(demand([1; 6], 1, 65536, 1824, usize::MAX).is_err());
        assert!(demand([1; 6], 4096, 65536, 1824, 0).is_err());
    }
}
