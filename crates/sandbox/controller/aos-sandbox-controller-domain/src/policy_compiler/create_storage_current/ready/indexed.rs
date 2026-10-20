//! Shares the existing strict indexed chunk copy and positive native disposal.
//!
//! The actual Ready and Signed owners separately fund fixed/index/raw work on
//! the SAME Root R before this helper. Format selection is passive DATA; this
//! child cannot create a paid stage, peer, current cut or semantic success.

use std::collections::TryReserveError;
use std::os::unix::net::UnixStream;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, ready::ready_commitment_v1,
    continuation::SignedPreparationBundleDataV1,
    transport::{TransferIndexV1, FrameCoordinatesV1, FrameEnvelopeV1,
        FrameKindV1, ChunkEnvelopeV1, FRAME_HEADER_BYTES, CHUNK_HEADER_BYTES},
};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use super::subject::RootCurrentChunkReceivingV1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error, root_open::RootCurrentOpenStateV1};

#[derive(Clone, Copy)]
pub(in crate::policy_compiler::create_storage_current) enum IndexedTransferPurposeDataV1 {
    Ready,
    Signed { maxima: [usize; 3] },
    Outcome { maxima: [usize; 2] },
}

impl IndexedTransferPurposeDataV1 {
    fn chunk_kind(self) -> FrameKindV1 {
        match self { Self::Ready => FrameKindV1::ReadyChunk, Self::Signed { .. } => FrameKindV1::SignedChunk, Self::Outcome { .. } => FrameKindV1::OutcomeChunk }
    }

    fn commitment(self, bytes: &[u8]) -> Result<[u8; 32], HistoryErrorV1> {
        match self {
            Self::Ready => Ok(ready_commitment_v1(bytes)),
            Self::Signed { maxima } => SignedPreparationBundleDataV1::decode(bytes, maxima)?.commitment(),
            Self::Outcome { maxima } => aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::
                OutcomeBundleDataV1::decode(bytes, maxima)?.commitment(),
        }
    }
}

pub(in crate::policy_compiler::create_storage_current) struct IndexedReceiveSlotsV1<'slots> {
    pub(in crate::policy_compiler::create_storage_current) allocation: &'slots mut Option<Result<(), TryReserveError>>,
    pub(in crate::policy_compiler::create_storage_current) bytes: &'slots mut Vec<u8>,
    pub(in crate::policy_compiler::create_storage_current) frame: &'slots mut Option<RetainedSubjectStreamReadV1>,
    pub(in crate::policy_compiler::create_storage_current) frame_binding: &'slots mut Option<Result<(), HistoryErrorV1>>,
    pub(in crate::policy_compiler::create_storage_current) next_chunk: &'slots mut u32,
    pub(in crate::policy_compiler::create_storage_current) chunks: &'slots mut RootCurrentChunkReceivingV1,
    pub(in crate::policy_compiler::create_storage_current) digest: &'slots mut Option<Result<(), HistoryErrorV1>>,
}

pub(in crate::policy_compiler::create_storage_current) fn construction_bytes_v1() -> Option<u64> {
    let bytes = std::mem::size_of::<IndexedReceiveSlotsV1<'static>>()
        .checked_add(std::mem::size_of::<IndexedTransferPurposeDataV1>())?.checked_mul(2)?;
    u64::try_from(bytes).ok()
}

pub(in crate::policy_compiler::create_storage_current) fn receive_chunks_once_v1(
    slots: IndexedReceiveSlotsV1<'_>, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    original: &UnixStream, root_open: &RootCurrentOpenStateV1,
    geometry: &SubjectStreamReceiveGeometryV1, index: TransferIndexV1,
    purpose: IndexedTransferPurposeDataV1, first_sequence: u64, cutoff: u64,
) -> Result<(), Error> {
    let IndexedReceiveSlotsV1 { allocation, bytes, frame, frame_binding,
        next_chunk, chunks, digest } = slots;
    let body = root_open.completed_body()?;
    let total = usize::try_from(index.total()).map_err(|_| Error::Ready)?;
    *allocation = Some(bytes.try_reserve_exact(total));
    positive(allocation)?;

    while *next_chunk < index.count() {
        let offset = u64::from(*next_chunk).checked_mul(CLAIM_CHUNK_BYTES as u64)
            .ok_or(Error::Ready)?;
        let remaining = index.total().checked_sub(offset).ok_or(Error::Ready)?;
        let payload = usize::try_from(remaining.min(CLAIM_CHUNK_BYTES as u64))
            .map_err(|_| Error::Ready)?;
        let frame_bytes = FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES + payload;
        *frame = Some(RetainedSubjectStreamReadV1::new());
        let current_frame = frame.as_mut().ok_or(Error::Ready)?;
        current_frame.prepare_exact_once(frame_bytes).map_err(|_| Error::Ready)?;
        match purpose {
            IndexedTransferPurposeDataV1::Ready => chunks.receive_exact(flight, original, current_frame, root_open, geometry)?,
            IndexedTransferPurposeDataV1::Signed { .. } | IndexedTransferPurposeDataV1::Outcome { .. } => chunks.receive_exact_until(flight, original, current_frame, root_open, geometry, cutoff)?,
        }
        *frame_binding = Some((|| {
            let envelope = FrameEnvelopeV1::decode(current_frame.bytes(), FrameCoordinatesV1 {
                kind: purpose.chunk_kind(),
                lane: body.open.lane,
                sequence: first_sequence.checked_add(u64::from(*next_chunk)).ok_or(HistoryErrorV1::Extent)?,
                root_nonce: body.root_nonce,
                controller_nonce: body.open.controller_nonce,
            })?;
            let chunk = ChunkEnvelopeV1::decode(envelope.payload(), index, *next_chunk)?;
            let reached = bytes.len().checked_add(chunk.payload().len())
                .ok_or(HistoryErrorV1::Extent)?;
            if reached > total || reached > bytes.capacity() {
                return Err(HistoryErrorV1::Extent);
            }
            bytes.extend_from_slice(chunk.payload());
            Ok(())
        })());
        positive(frame_binding)?;
        // Exact framed bytes, checksum, next-index geometry and cumulative
        // copy have all completed. Dispose this positive raw frame before
        // the next bounded frame. A failed frame stays in frame.
        drop(frame.take());
        *frame_binding = None;
        *next_chunk = (*next_chunk).checked_add(1).ok_or(Error::Ready)?;
    }
    *digest = Some(if bytes.len() != total {
        Err(HistoryErrorV1::Correlation)
    } else {
        purpose.commitment(bytes).and_then(|observed| {
            if observed == index.digest() { Ok(()) }
            else { Err(HistoryErrorV1::Correlation) }
        })
    });
    positive(digest).map(|_| ())
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::Ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_commitment_binds_each_received_field() {
        let bundle = SignedPreparationBundleDataV1 { plan: b"actual plan", signature: b"actual signature", request_body: b"actual request" };
        let mut encoded = vec![0; bundle.encoded_bytes().unwrap()];
        bundle.encode_into(&mut encoded).unwrap();
        let purpose = IndexedTransferPurposeDataV1::Signed { maxima: [11, 16, 14] };
        assert_eq!(purpose.commitment(&encoded).unwrap(), bundle.commitment().unwrap());

        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert_ne!(purpose.commitment(&encoded).unwrap(), bundle.commitment().unwrap());
        assert_eq!(purpose.chunk_kind(), FrameKindV1::SignedChunk);
        assert_eq!(IndexedTransferPurposeDataV1::Ready.chunk_kind(), FrameKindV1::ReadyChunk);
    }

    #[test]
    fn signed_cumulative_decoder_rejects_extent_and_trailing_bytes() {
        let bundle = SignedPreparationBundleDataV1 { plan: b"plan", signature: b"signature", request_body: b"request" };
        let mut encoded = vec![0; bundle.encoded_bytes().unwrap()];
        bundle.encode_into(&mut encoded).unwrap();
        assert!(IndexedTransferPurposeDataV1::Signed { maxima: [3, 9, 7] }.commitment(&encoded).is_err());

        encoded.push(0);
        assert!(IndexedTransferPurposeDataV1::Signed { maxima: [4, 9, 7] }.commitment(&encoded).is_err());
    }
}
