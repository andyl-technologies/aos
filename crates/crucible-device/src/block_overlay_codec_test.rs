//! Block overlay and wire-codec tests.

use super::test_support::*;
use super::*;
use crate::DeviceError;
use crate::subnode::IoCore;
use crucible_shmem::{FrameEntry, KIND_VM, NodeSlot, RingHeader};

#[test]
fn read_falls_through_to_base_when_overlay_empty() {
    let base = ramp_base(PAGE_SIZE * 3);
    let overlay = CowOverlay::new();
    let got = ok(overlay.read(&base, 100, 50));
    assert_eq!(got, &base.bytes()[100..150]);
    assert_eq!(overlay.page_count(), 0, "a read must not copy up");
}

#[test]
fn write_copies_up_and_read_sees_overlay_over_base() {
    let base = ramp_base(PAGE_SIZE * 3);
    let mut overlay = CowOverlay::new();
    ok(overlay.write(&base, 4090, &[0xAB; 12]));
    // Spans the boundary between page 0 and page 1, so two pages copy up.
    assert_eq!(overlay.page_count(), 2);
    let got = ok(overlay.read(&base, 4088, 16));
    let mut want = base.bytes()[4088..4104].to_vec();
    want[2..14].fill(0xAB);
    assert_eq!(got, want);
}

#[test]
fn base_bytes_never_change_under_writes() {
    let base = ramp_base(PAGE_SIZE * 2);
    let original = base.bytes().to_vec();
    let original_hash = base.hash();
    let mut overlay = CowOverlay::new();
    ok(overlay.write(&base, 0, &[0xFF; PAGE_SIZE]));
    ok(overlay.write(&base, PAGE_SIZE as u64, &[0x01; 10]));
    assert_eq!(base.bytes(), &original[..], "base bytes mutated");
    assert_eq!(base.hash(), original_hash, "base identity changed");
}

#[test]
fn out_of_range_read_and_write_error_not_truncate() {
    let base = ramp_base(PAGE_SIZE);
    let mut overlay = CowOverlay::new();
    assert!(overlay.read(&base, PAGE_SIZE as u64, 1).is_err());
    assert!(overlay.read(&base, PAGE_SIZE as u64 - 1, 2).is_err());
    assert!(overlay.write(&base, PAGE_SIZE as u64 - 1, &[0; 2]).is_err());
    // Exactly at the end with zero length is in range.
    assert!(overlay.read(&base, PAGE_SIZE as u64, 0).is_ok());
}

// ---- dirty tracking (IO-7) ----

#[test]
fn dirty_set_tracks_written_pages_and_clears_at_boundary() {
    let base = ramp_base(PAGE_SIZE * 4);
    let mut overlay = CowOverlay::new();
    ok(overlay.write(&base, 0, &[1; 10]));
    ok(overlay.write(&base, (PAGE_SIZE * 2) as u64, &[2; 10]));
    let dirty: Vec<u64> = overlay.dirty_pages().iter().copied().collect();
    assert_eq!(dirty, vec![0, (PAGE_SIZE * 2) as u64]);
    assert_eq!(overlay.dirty_delta().pages.len(), 2);

    overlay.clear_dirty();
    assert!(overlay.dirty_pages().is_empty());
    // Pages still present; only dirty bookkeeping reset.
    assert_eq!(overlay.page_count(), 2);

    // Subsequent write produces a disjoint delta.
    ok(overlay.write(&base, (PAGE_SIZE * 3) as u64, &[3; 10]));
    let delta: Vec<u64> = overlay.dirty_delta().pages.keys().copied().collect();
    assert_eq!(delta, vec![(PAGE_SIZE * 3) as u64]);
}

// ---- materialize (IO-12) ----

#[test]
fn materialize_applies_overlay_over_base_without_mutating_base() {
    let base = ramp_base(PAGE_SIZE * 2 + 100);
    let original = base.bytes().to_vec();
    let mut overlay = CowOverlay::new();
    ok(overlay.write(&base, 5, &[0x55; 20]));
    let image = overlay.materialize(&base);
    assert_eq!(image.len(), base.len() as usize);
    let mut want = original.clone();
    want[5..25].fill(0x55);
    assert_eq!(image, want);
    assert_eq!(base.bytes(), &original[..], "materialize mutated base");
}

// ---- wire ABI round-trip + fuzz (IO-8) ----

#[test]
fn request_round_trips_for_every_op() {
    let cases = [
        BlockRequest::read(7, 4096, 512),
        BlockRequest::write(8, 100, vec![0xDE; 64]),
        BlockRequest::flush(9),
        BlockRequest::get_length(10),
        BlockRequest::discard(11, 4096, 512),
    ];
    for req in cases {
        let decoded = ok(BlockRequest::decode(&ok(req.encode())));
        assert_eq!(decoded, req);
    }
}

#[test]
fn response_round_trips() {
    let resp = BlockResponse::ok(11, vec![1, 2, 3, 4]);
    assert_eq!(ok(BlockResponse::decode(&ok(resp.encode()))), resp);
    let err = BlockResponse::error(12, BlockErrorCode::NoSpace);
    assert_eq!(ok(BlockResponse::decode(&ok(err.encode()))), err);
}

#[test]
fn every_typed_error_round_trips() {
    let errors = [
        BlockErrorCode::Offline,
        BlockErrorCode::ReadOnly,
        BlockErrorCode::InvalidRange,
        BlockErrorCode::Busy,
        BlockErrorCode::Timeout,
        BlockErrorCode::MediumError,
        BlockErrorCode::IntegrityError,
        BlockErrorCode::IoError,
        BlockErrorCode::NoSpace,
        BlockErrorCode::NotFound,
        BlockErrorCode::Stale,
    ];
    for error in errors {
        let response = BlockResponse::error(12, error);
        let decoded = ok(BlockResponse::decode(&ok(response.encode())));
        assert_eq!(ok(decoded.error_code()), error);
    }
}

#[test]
fn decode_rejects_malformed_typed_error_payloads() {
    for data in [Vec::new(), vec![0], vec![1, 2]] {
        let response = BlockResponse {
            status: BlockStatus::Error,
            epoch: 0,
            request_id: 12,
            data,
        };
        assert!(BlockResponse::decode(&ok(response.encode())).is_err());
    }
}

#[test]
fn decode_rejects_bad_version_and_unknown_op() {
    let mut wire = ok(BlockRequest::read(1, 0, 0).encode());
    wire[1] = 99; // corrupt version byte
    assert!(matches!(
        BlockRequest::decode(&wire),
        Err(BlockCodecError::VersionMismatch { .. })
    ));

    let mut wire = ok(BlockRequest::read(1, 0, 0).encode());
    wire[0] = 200; // unknown op
    assert!(matches!(
        BlockRequest::decode(&wire),
        Err(BlockCodecError::UnknownOp { .. })
    ));
}

#[test]
fn decode_rejects_nonzero_reserved_request_and_response_headers() {
    let mut request = ok(BlockRequest::read(1, 0, 0).encode());
    request[2..4].copy_from_slice(&1_u16.to_le_bytes());
    assert_eq!(
        BlockRequest::decode(&request),
        Err(BlockCodecError::NonZeroReserved { reserved: 1 })
    );

    let mut response = ok(BlockResponse::ok(1, Vec::new()).encode());
    response[2..4].copy_from_slice(&0x0201_u16.to_le_bytes());
    assert_eq!(
        BlockResponse::decode(&response),
        Err(BlockCodecError::NonZeroReserved { reserved: 0x0201 })
    );
}

#[test]
fn decode_rejects_write_count_exceeding_payload() {
    // Encode a valid write, then corrupt the on-wire count field (LE u32 at
    // offset 24) to exceed the payload, simulating a hostile frame.
    let mut wire = ok(BlockRequest::write(1, 0, vec![0xAA; 8]).encode());
    wire[24..28].copy_from_slice(&9999u32.to_le_bytes());
    assert!(matches!(
        BlockRequest::decode(&wire),
        Err(BlockCodecError::CountExceedsPayload { .. })
    ));
}

#[test]
fn decode_never_panics_on_arbitrary_bytes() {
    // A deterministic LCG fuzz: feed varied byte strings of varied length and
    // assert decode always returns (Ok or Err), never panics or OOB-reads.
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..20_000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = (state >> 56) as usize % 40;
        let mut bytes = Vec::with_capacity(len);
        let mut s = state;
        for _ in 0..len {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push((s >> 33) as u8);
        }
        // Neither call may panic; the result is ignored.
        let _ = BlockRequest::decode(&bytes);
        let _ = BlockResponse::decode(&bytes);
    }
}

// ---- end-to-end device serve (IO-5,6 over the lifecycle) ----
