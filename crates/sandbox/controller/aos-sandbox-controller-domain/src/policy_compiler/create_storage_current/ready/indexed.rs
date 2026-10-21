//! Shares the existing strict indexed chunk copy and positive native disposal.
//!
//! The actual Ready and Signed owners separately fund fixed/index/raw work on
//! the SAME Root R before this helper. Format selection is passive DATA; this
//! child cannot create a paid stage, peer, current cut or semantic success.

use std::collections::TryReserveError;
use std::os::unix::net::UnixStream;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, transport::TransferIndexV1,
};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use super::subject::RootCurrentChunkReceivingV1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error, root_open::RootCurrentOpenStateV1};

pub(in crate::policy_compiler::create_storage_current) use
    aos_sandbox_protocol::domain_ledger::create_storage_history::indexed_transfer::IndexedTransferPurposeDataV1;

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

    macro_rules! indexed_stage {
        (extent, $total:ident) => {
            aos_sandbox_broker::root_indexed_transfer_extent_v1! {
                index: index, total: $total, error: Error::Ready,
            }
        };
        (allocate, $total:ident) => {
            aos_sandbox_broker::root_indexed_transfer_allocate_v1! {
                allocation: allocation, bytes: bytes, total: $total, positive: positive,
            }
        };
        (has_next) => { *next_chunk < index.count() };
        (prepare_frame, $current_frame:ident) => {
            aos_sandbox_broker::root_indexed_transfer_prepare_frame_v1! {
                index: index, next_chunk: next_chunk, frame: frame,
                current_frame: $current_frame, error: Error::Ready,
            }
        };
        (receive_frame, $current_frame:ident) => {
            match purpose {
                IndexedTransferPurposeDataV1::Ready => chunks.receive_exact(flight, original, $current_frame, root_open, geometry)?,
                IndexedTransferPurposeDataV1::Signed { .. } | IndexedTransferPurposeDataV1::Outcome { .. } => chunks.receive_exact_until(flight, original, $current_frame, root_open, geometry, cutoff)?,
            }
        };
        (bind_copy, $current_frame:ident, $total:ident) => {
            aos_sandbox_broker::root_indexed_transfer_bind_copy_v1! {
                frame_binding: frame_binding, current_frame: $current_frame,
                purpose: purpose, body: body, first_sequence: first_sequence,
                next_chunk: next_chunk, index: index, bytes: bytes, total: $total,
                positive: positive,
            }
        };
        (dispose_frame, $current_frame:ident) => {
            aos_sandbox_broker::root_indexed_transfer_dispose_frame_v1! {
                frame: frame, frame_binding: frame_binding, next_chunk: next_chunk,
                error: Error::Ready,
            }
        };
        (digest, $total:ident) => {
            aos_sandbox_broker::root_indexed_transfer_digest_v1! {
                digest: digest, bytes: bytes, total: $total, purpose: purpose,
                index: index, positive: positive,
            }
        };
    }
    aos_sandbox_broker::root_indexed_transfer_receive_v1!(indexed_stage)
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::Ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        continuation::SignedPreparationBundleDataV1, transport::FrameKindV1,
    };

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
