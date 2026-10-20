//! Checks the selected three-object Capture frame population before owner effects.

#![allow(clippy::unwrap_used)]

use super::*;

fn selected() -> (PacketNative5StorageLimits, Limits) {
    (
        PacketNative5StorageLimits {
            snapshot_bytes: U64::new(1024),
            control_snapshot_bytes: U64::new(512),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(26),
            hello_bytes: U64::new(256 * 1024),
            settlement_bytes: U64::new(1024 * 1024),
        },
        Limits {
            frame_bytes: U64::new(8192),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(1024),
            blob_chunk_bytes: U64::new(512),
        },
    )
}

#[test]
fn selected_capture_counts_separate_control_and_terminal_frame() {
    let (mut storage, limits) = selected();
    // The former two-object formula admitted 23 slots, excluding Control.
    storage.frames_per_direction = U64::new(23);
    assert!(storage.validate(&limits).is_err());

    storage.frames_per_direction = U64::new(25);
    assert!(storage.validate(&limits).is_err());

    storage.frames_per_direction = U64::new(26);
    storage.validate(&limits).unwrap();
}

#[test]
fn selected_capture_respects_complete_4096_frame_boundary() {
    let (mut storage, mut limits) = selected();
    limits.blob_chunk_bytes = U64::new(4096);
    storage.snapshot_bytes = U64::new(8 * 1024 * 1024);
    storage.control_snapshot_bytes = U64::new(2039 * 4096);
    storage.frames_per_direction = U64::new(4095);
    assert!(storage.validate(&limits).is_err());

    storage.frames_per_direction = U64::new(4096);
    storage.validate(&limits).unwrap();

    storage.control_snapshot_bytes = U64::new(2040 * 4096);
    assert!(storage.validate(&limits).is_err());
}
