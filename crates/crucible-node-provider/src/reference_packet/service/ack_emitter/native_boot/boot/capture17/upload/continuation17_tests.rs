//! Exercises the consumed exact next-step decision without creating native rights.

use super::*;
use crate::{
    bodies::{BlobChunkRequest, BlobFinishRequest},
    handshake::Limits,
    reference_packet::service::{
        native_startup::original_restored_settled_capture_auxiliary_geometry_for_lengths_data,
        restored_settled_capture::upload::PacketRestoredSettledCaptureUploadContinuation,
    },
};
use crucible_node_contract::{Bytes, Extensions, Id};

fn continuation() -> PacketRestoredSettledCaptureUploadContinuation {
    // This constructible DATA has no genuine Source proof or native seed.
    PacketRestoredSettledCaptureUploadContinuation {
        schema: "source-owned.packet-restored-settled-capture-upload-continuation/17".into(),
        context_digest: Bytes::new(vec![0; 32]),
        capture_operation: Id::new("capture").unwrap(),
        transfer_id: Id::new("transfer").unwrap(),
    }
}

#[test]
fn actual_ten_kilobyte_geometry_accepts_only_its_exact_contiguous_chunks_and_finish() {
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(256),
        journal_entries: U64::new(256),
        blob_chunk_bytes: U64::new(65536),
    };
    let geometry = original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
        &limits,
        [10000, 5000],
        256,
    )
    .unwrap();
    assert_eq!(geometry.maximum_chunk_bytes_data(), 4096);
    let continuation = continuation();
    let mut next = 0u64;
    for (offset, length) in [(0, 4096), (4096, 4096), (8192, 1808)] {
        let body = BlobChunkRequest {
            transfer_id: continuation.transfer_id.clone(),
            offset: U64::new(offset),
            bytes: Bytes::new(vec![b'x'; length]),
            extensions: Extensions::new(),
        };
        let phase = || NativeCapture17PhaseData::Chunk {
            body: &body,
            continuation: &continuation,
        };

        authenticate_next_phase_data(phase(), &geometry, 0, U64::new(10000), U64::new(next))
            .unwrap();

        assert!(
            authenticate_next_phase_data(
                phase(),
                &geometry,
                0,
                U64::new(10000),
                U64::new(next + 1)
            )
            .is_err()
        );
        next += u64::try_from(length).unwrap();
    }
    assert_eq!(next, 10000);
    let body = BlobFinishRequest {
        transfer_id: continuation.transfer_id.clone(),
        extensions: Extensions::new(),
    };
    let phase = || NativeCapture17PhaseData::Finish {
        body: &body,
        continuation: &continuation,
    };
    authenticate_next_phase_data(phase(), &geometry, 0, U64::new(10000), U64::new(10000)).unwrap();
    for next in [0, 9999, 10001] {
        assert!(
            authenticate_next_phase_data(phase(), &geometry, 0, U64::new(10000), U64::new(next))
                .is_err()
        );
    }
}

#[test]
fn tiny_oversized_unaligned_reordered_and_past_end_chunks_cannot_change_the_grid() {
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(256),
        journal_entries: U64::new(256),
        blob_chunk_bytes: U64::new(4096),
    };
    let geometry = original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
        &limits,
        [10000, 5000],
        256,
    )
    .unwrap();
    let continuation = continuation();
    for (offset, length, next) in [
        (0, 1, 0),
        (0, 4097, 0),
        (1, 4096, 1),
        (4096, 4096, 0),
        (8192, 1807, 8192),
        (8192, 1809, 8192),
        (10000, 1, 10000),
    ] {
        let body = BlobChunkRequest {
            transfer_id: continuation.transfer_id.clone(),
            offset: U64::new(offset),
            bytes: Bytes::new(vec![b'x'; length]),
            extensions: Extensions::new(),
        };
        assert!(
            authenticate_next_phase_data(
                NativeCapture17PhaseData::Chunk {
                    body: &body,
                    continuation: &continuation
                },
                &geometry,
                0,
                U64::new(10000),
                U64::new(next)
            )
            .is_err()
        );
    }
}
