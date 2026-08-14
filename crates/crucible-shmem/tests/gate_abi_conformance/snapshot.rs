//! Canonical ring-snapshot golden and malformed-byte corpus.

use super::*;

pub(super) fn assert_snapshot_canonical_codec_corpus() {
    let snapshot = SpscRingSnapshot {
        frames: vec![frame(1, 2, 3, b"first"), frame(5, 8, 13, b"second")],
    };
    let encoded = match snapshot.canonical_bytes() {
        Ok(encoded) => encoded,
        Err(error) => panic!("snapshot should encode: {error}"),
    };
    assert_eq!(
        SpscRingSnapshot::from_canonical_bytes(&encoded),
        Ok(snapshot)
    );

    for bytes in snapshot_malformed_byte_corpus() {
        let decoded = match catch_unwind(AssertUnwindSafe(|| {
            SpscRingSnapshot::from_canonical_bytes(&bytes)
        })) {
            Ok(decoded) => decoded,
            Err(_) => panic!("snapshot canonical byte decoder must not panic"),
        };
        assert!(
            decoded.is_err(),
            "malformed snapshot bytes must be rejected: {bytes:?}"
        );
    }
}

pub(super) fn regression_corpus() -> &'static str {
    GOLDEN_VECTOR_FIXTURE
}

pub(super) fn snapshot_malformed_byte_corpus() -> Vec<Vec<u8>> {
    let mut trailing = Vec::new();
    trailing.extend_from_slice(&0_u64.to_le_bytes());
    trailing.push(0xff);

    let mut missing_frame = Vec::new();
    missing_frame.extend_from_slice(&1_u64.to_le_bytes());

    let oversized = snapshot_frame_prefix(9, 10, 11, (MAX_FRAME_DATA + 1) as u16);

    let mut truncated_payload = snapshot_frame_prefix(9, 10, 11, 4);
    truncated_payload.extend_from_slice(b"abc");

    vec![
        Vec::new(),
        vec![0, 1, 2],
        u64::MAX.to_le_bytes().to_vec(),
        trailing,
        missing_frame,
        oversized,
        truncated_payload,
    ]
}

pub(super) fn snapshot_frame_prefix(
    delivery_icount: u64,
    src_node: u32,
    seq: u32,
    len: u16,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&delivery_icount.to_le_bytes());
    bytes.extend_from_slice(&src_node.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes
}

pub(super) fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should fit: {error}"),
    }
}
