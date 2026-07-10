//! Checks the shared-memory ABI against frozen cross-language vectors.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_shmem::{
    ABI_VERSION, COVERAGE_ENTRY_BLOCK_LEN_OFFSET, COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
    COVERAGE_ENTRY_GUEST_PC_OFFSET, COVERAGE_ENTRY_MAP_INDEX_OFFSET, COVERAGE_ENTRY_SIZE,
    COVERAGE_ENTRY_VCPU_INDEX_OFFSET, FRAME_ENTRY_DATA_OFFSET, FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
    FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_SEQ_OFFSET, FRAME_ENTRY_SIZE, FRAME_ENTRY_SRC_NODE_OFFSET,
    FrameEntry, MAX_FRAME_DATA, NODE_SLOT_CURRENT_ICOUNT_OFFSET, NODE_SLOT_CURRENT_NS_OFFSET,
    NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET, NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, NODE_SLOT_KIND_OFFSET,
    NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, NODE_SLOT_PUBLISH_GEN_OFFSET, NODE_SLOT_SIZE,
    NODE_SLOT_STATUS_OFFSET, NODE_SLOT_WAKE_SIGNAL_OFFSET, REGION_HEADER_ABI_VERSION_OFFSET,
    REGION_HEADER_ENTRY_STRIDE_OFFSET, REGION_HEADER_ICOUNT_SHIFT_OFFSET,
    REGION_HEADER_MAGIC_OFFSET, REGION_HEADER_NODE_COUNT_OFFSET,
    REGION_HEADER_PAUSE_REQUESTED_OFFSET, REGION_HEADER_QUEUE_CAPACITY_OFFSET,
    REGION_HEADER_REGION_SIZE_OFFSET, REGION_HEADER_RING_COUNT_OFFSET,
    REGION_HEADER_RING_DATA_OFF_OFFSET, REGION_HEADER_RING_HDR_OFF_OFFSET,
    REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET, REGION_HEADER_SIZE, REGION_MAGIC,
    RING_HEADER_READ_IDX_OFFSET, RING_HEADER_SIZE, RING_HEADER_WRITE_IDX_OFFSET, RegionConfig,
    RegionLayout, STATUS_IDLE, SpscRingSnapshot, generated_c_header,
};

const COMMITTED_HEADER: &str = include_str!("../include/crucible_shmem_abi.h");
const GOLDEN_VECTOR_FIXTURE: &str = include_str!("fixtures/shmem_abi_golden.fixture");

const GOLDEN_VM_NODE_COUNT: u32 = 2;
const GOLDEN_QUEUE_CAPACITY: u32 = 8;
const GOLDEN_ICOUNT_SHIFT: u32 = 4;
const GOLDEN_NODE_SLOT_BASE: usize = REGION_HEADER_SIZE;
const GOLDEN_RING_HEADER_BASE: usize = GOLDEN_NODE_SLOT_BASE + NODE_SLOT_SIZE;
const GOLDEN_FRAME_ENTRY_BASE: usize = GOLDEN_RING_HEADER_BASE + RING_HEADER_SIZE;
const GOLDEN_COVERAGE_ENTRY_BASE: usize = GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SIZE;
const GOLDEN_TOTAL_LEN: usize = GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_SIZE;

#[test]
fn gate_abi_conformance_checks_generated_header_and_golden_vectors() {
    generated_header_matches_committed_copy();
    generated_header_carries_static_asserts_for_every_shared_struct();

    let fixture = assert_frozen_golden_vectors();
    assert_abi_version_field(&fixture);
    let state = assert_decode_encode_roundtrip(&fixture);
    assert_version_bump_regenerates_vectors(&fixture);
    assert_structure_aware_fuzz_corpus(&fixture, &state);
    assert_snapshot_canonical_codec_corpus();
    golden_vector_negative_control_detects_layout_drift();
}

#[test]
fn generated_header_matches_committed_copy() {
    assert_eq!(COMMITTED_HEADER, generated_c_header());
}

#[test]
fn generated_header_carries_static_asserts_for_every_shared_struct() {
    let header = generated_c_header();
    for needle in [
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_region_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_region_header)",
        "offsetof(crucible_shmem_region_header, magic)",
        "offsetof(crucible_shmem_region_header, abi_version)",
        "offsetof(crucible_shmem_region_header, node_count)",
        "offsetof(crucible_shmem_region_header, queue_capacity)",
        "offsetof(crucible_shmem_region_header, ring_count)",
        "offsetof(crucible_shmem_region_header, ring_hdr_off)",
        "offsetof(crucible_shmem_region_header, ring_data_off)",
        "offsetof(crucible_shmem_region_header, entry_stride)",
        "offsetof(crucible_shmem_region_header, region_size)",
        "offsetof(crucible_shmem_region_header, icount_shift)",
        "offsetof(crucible_shmem_region_header, pause_requested)",
        "offsetof(crucible_shmem_region_header, shutdown_requested)",
        "offsetof(crucible_shmem_region_header, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_node_slot)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_node_slot)",
        "offsetof(crucible_shmem_node_slot, current_icount)",
        "offsetof(crucible_shmem_node_slot, current_ns)",
        "offsetof(crucible_shmem_node_slot, max_advance_icount)",
        "offsetof(crucible_shmem_node_slot, idle_wake_icount)",
        "offsetof(crucible_shmem_node_slot, wake_signal)",
        "offsetof(crucible_shmem_node_slot, status)",
        "offsetof(crucible_shmem_node_slot, kind)",
        "offsetof(crucible_shmem_node_slot, device_io_active)",
        "offsetof(crucible_shmem_node_slot, pad0)",
        "offsetof(crucible_shmem_node_slot, publish_gen)",
        "offsetof(crucible_shmem_node_slot, reserved)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_ring_header)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_ring_header)",
        "offsetof(crucible_shmem_ring_header, read_idx)",
        "offsetof(crucible_shmem_ring_header, pad_read)",
        "offsetof(crucible_shmem_ring_header, write_idx)",
        "offsetof(crucible_shmem_ring_header, pad_write)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_frame_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_frame_entry)",
        "offsetof(crucible_shmem_frame_entry, delivery_icount)",
        "offsetof(crucible_shmem_frame_entry, src_node)",
        "offsetof(crucible_shmem_frame_entry, seq)",
        "offsetof(crucible_shmem_frame_entry, len)",
        "offsetof(crucible_shmem_frame_entry, pad)",
        "offsetof(crucible_shmem_frame_entry, data)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(sizeof(crucible_shmem_coverage_entry)",
        "CRUCIBLE_SHMEM_STATIC_ASSERT(_Alignof(crucible_shmem_coverage_entry)",
        "offsetof(crucible_shmem_coverage_entry, current_icount)",
        "offsetof(crucible_shmem_coverage_entry, guest_pc)",
        "offsetof(crucible_shmem_coverage_entry, map_index)",
        "offsetof(crucible_shmem_coverage_entry, vcpu_index)",
        "offsetof(crucible_shmem_coverage_entry, block_len)",
        "offsetof(crucible_shmem_coverage_entry, reserved)",
    ] {
        assert!(
            header.contains(needle),
            "generated C header missing `{needle}`"
        );
    }
}

#[test]
fn rust_golden_vector_round_trip_matches_fixture() {
    let fixture = assert_frozen_golden_vectors();
    assert_abi_version_field(&fixture);
    let state = assert_decode_encode_roundtrip(&fixture);
    assert_structure_aware_fuzz_corpus(&fixture, &state);
    assert_snapshot_canonical_codec_corpus();
}

#[test]
fn golden_vector_negative_control_detects_layout_drift() {
    let fixture = assert_frozen_golden_vectors();
    let mut drifted = live_golden_bytes();
    write_u32(
        &mut drifted,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        GOLDEN_VM_NODE_COUNT,
    );
    write_u32(
        &mut drifted,
        REGION_HEADER_NODE_COUNT_OFFSET,
        GOLDEN_QUEUE_CAPACITY,
    );

    assert_ne!(
        fixture.bytes, drifted,
        "golden vector must detect swapped region-header layout fields"
    );
}

fn assert_frozen_golden_vectors() -> Fixture {
    let fixture = match parse_fixture(regression_corpus()) {
        Ok(fixture) => fixture,
        Err(error) => panic!("failed to parse shmem ABI golden fixture: {error}"),
    };

    assert_eq!(fixture.abi_version, ABI_VERSION);
    assert_eq!(fixture.bytes.len(), GOLDEN_TOTAL_LEN);
    assert_eq!(fixture.bytes, live_golden_bytes());
    fixture
}

fn assert_decode_encode_roundtrip(fixture: &Fixture) -> GoldenState {
    let decoded = match decode_golden_state(&fixture.bytes) {
        Ok(decoded) => decoded,
        Err(error) => panic!("failed to decode shmem ABI golden vector: {error}"),
    };
    let encoded = encode_golden_state(&decoded);
    assert_eq!(encoded, fixture.bytes);
    decoded
}

fn assert_abi_version_field(fixture: &Fixture) {
    assert_eq!(fixture.abi_version, ABI_VERSION);
    assert_eq!(
        read_u32(&fixture.bytes, REGION_HEADER_ABI_VERSION_OFFSET),
        ABI_VERSION
    );
}

fn assert_version_bump_regenerates_vectors(fixture: &Fixture) {
    let mut bumped = fixture.bytes.clone();
    write_u32(
        &mut bumped,
        REGION_HEADER_ABI_VERSION_OFFSET,
        ABI_VERSION + 1,
    );
    assert_ne!(
        bumped, fixture.bytes,
        "ABI version changes must alter frozen golden vectors"
    );
    assert_eq!(
        read_u32(&bumped, REGION_HEADER_ABI_VERSION_OFFSET),
        ABI_VERSION + 1
    );
}

fn assert_structure_aware_fuzz_corpus(fixture: &Fixture, decoded: &GoldenState) {
    assert_eq!(decoded.region.magic, REGION_MAGIC);
    assert_eq!(decoded.region.abi_version, ABI_VERSION);
    assert_eq!(decoded.region.node_count, 32);
    assert_eq!(decoded.region.queue_capacity, GOLDEN_QUEUE_CAPACITY);
    assert_eq!(decoded.region.ring_count, 12);
    assert_eq!(decoded.node.status, STATUS_IDLE);
    assert_eq!(decoded.node.kind, 0);
    assert_eq!(decoded.frame.payload, b"PING");
    assert_eq!(decoded.coverage.current_icount, 901);
    assert_eq!(decoded.coverage.guest_pc, 0x4010);
    assert_eq!(decoded.coverage.map_index, 17);
    assert_eq!(decoded.coverage.vcpu_index, 2);
    assert_eq!(decoded.coverage.block_len, 4);

    let mut payload_mutation = fixture.bytes.clone();
    payload_mutation[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
        ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + 4]
        .copy_from_slice(b"PONG");
    let mutated = match decode_golden_state(&payload_mutation) {
        Ok(mutated) => mutated,
        Err(error) => panic!("failed to decode structured payload mutation: {error}"),
    };
    assert_eq!(mutated.frame.payload, b"PONG");
    assert_eq!(encode_golden_state(&mutated), payload_mutation);
    assert_ne!(payload_mutation, fixture.bytes);

    let mut oversized = fixture.bytes.clone();
    write_u16(
        &mut oversized,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET,
        (MAX_FRAME_DATA as u16) + 1,
    );
    assert!(
        decode_golden_state(&oversized).is_err(),
        "oversized structured frame mutation must be rejected"
    );
}

fn assert_snapshot_canonical_codec_corpus() {
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

fn regression_corpus() -> &'static str {
    GOLDEN_VECTOR_FIXTURE
}

fn snapshot_malformed_byte_corpus() -> Vec<Vec<u8>> {
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

fn snapshot_frame_prefix(delivery_icount: u64, src_node: u32, seq: u32, len: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&delivery_icount.to_le_bytes());
    bytes.extend_from_slice(&src_node.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should fit: {error}"),
    }
}

fn live_golden_bytes() -> Vec<u8> {
    let layout = match RegionLayout::for_config(RegionConfig::new(
        GOLDEN_VM_NODE_COUNT,
        GOLDEN_QUEUE_CAPACITY,
        GOLDEN_ICOUNT_SHIFT,
    )) {
        Ok(layout) => layout,
        Err(error) => panic!("failed to compute golden shmem layout: {error}"),
    };

    let mut bytes = vec![0; GOLDEN_TOTAL_LEN];

    write_u64(&mut bytes, REGION_HEADER_MAGIC_OFFSET, REGION_MAGIC);
    write_u32(&mut bytes, REGION_HEADER_ABI_VERSION_OFFSET, ABI_VERSION);
    write_u32(
        &mut bytes,
        REGION_HEADER_NODE_COUNT_OFFSET,
        layout.node_count,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        layout.queue_capacity,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_RING_COUNT_OFFSET,
        layout.ring_count,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_HDR_OFF_OFFSET,
        layout.ring_hdr_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_DATA_OFF_OFFSET,
        layout.ring_data_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_ENTRY_STRIDE_OFFSET,
        layout.entry_stride,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_REGION_SIZE_OFFSET,
        layout.region_size,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET,
        layout.icount_shift,
    );
    write_u8(&mut bytes, REGION_HEADER_PAUSE_REQUESTED_OFFSET, 1);
    write_u8(&mut bytes, REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET, 0);

    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_ICOUNT_OFFSET,
        128,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_NS_OFFSET,
        2048,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
        256,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
        180,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_WAKE_SIGNAL_OFFSET,
        7,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_STATUS_OFFSET,
        STATUS_IDLE,
    );
    write_u8(&mut bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_KIND_OFFSET, 0);
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
        1,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PUBLISH_GEN_OFFSET,
        4,
    );

    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_READ_IDX_OFFSET,
        5,
    );
    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_WRITE_IDX_OFFSET,
        9,
    );

    write_u64(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
        777,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SRC_NODE_OFFSET,
        2,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SEQ_OFFSET,
        42,
    );
    write_u16(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET,
        4,
    );
    bytes[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
        ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + 4]
        .copy_from_slice(b"PING");

    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
        901,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_GUEST_PC_OFFSET,
        0x4010,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_MAP_INDEX_OFFSET,
        17,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
        2,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
        4,
    );

    bytes
}

fn parse_fixture(fixture: &str) -> Result<Fixture, String> {
    let mut abi_version = None;
    let mut total_len = None;
    let mut segments = Vec::new();

    for (line_index, raw_line) in fixture.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: missing `=`"))?;
        match key {
            "abi_version" => {
                abi_version = Some(parse_u32_value(value, line_number, "abi_version")?);
            }
            "total_len" => {
                total_len = Some(parse_usize_value(value, line_number, "total_len")?);
            }
            offset => {
                let offset = parse_usize_value(offset, line_number, "offset")?;
                let bytes = parse_hex_bytes(value, line_number)?;
                segments.push((offset, bytes));
            }
        }
    }

    let abi_version = abi_version.ok_or_else(|| "fixture missing abi_version".to_string())?;
    let total_len = total_len.ok_or_else(|| "fixture missing total_len".to_string())?;
    let mut bytes = vec![0; total_len];
    for (offset, segment) in segments {
        let end = offset
            .checked_add(segment.len())
            .ok_or_else(|| format!("fixture segment at {offset} overflows"))?;
        if end > bytes.len() {
            return Err(format!(
                "fixture segment at {offset} extends past total_len {total_len}"
            ));
        }
        bytes[offset..end].copy_from_slice(&segment);
    }

    Ok(Fixture { abi_version, bytes })
}

fn parse_u32_value(value: &str, line_number: usize, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|error| format!("line {line_number}: invalid {label}: {error}"))
}

fn parse_usize_value(value: &str, line_number: usize, label: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("line {line_number}: invalid {label}: {error}"))
}

fn parse_hex_bytes(hex: &str, line_number: usize) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("line {line_number}: hex payload has odd length"));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair_index in 0..hex.len() / 2 {
        let start = pair_index * 2;
        let end = start + 2;
        let pair = &hex[start..end];
        if !pair.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(format!("line {line_number}: invalid hex pair `{pair}`"));
        }
        let value = u8::from_str_radix(pair, 16)
            .map_err(|error| format!("line {line_number}: invalid hex pair `{pair}`: {error}"))?;
        bytes.push(value);
    }
    Ok(bytes)
}

fn decode_golden_state(bytes: &[u8]) -> Result<GoldenState, String> {
    if bytes.len() != GOLDEN_TOTAL_LEN {
        return Err(format!(
            "golden vector length {} does not match expected {GOLDEN_TOTAL_LEN}",
            bytes.len()
        ));
    }

    let frame_len = read_u16(bytes, GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET);
    let frame_len_usize = usize::from(frame_len);
    if frame_len_usize > MAX_FRAME_DATA {
        return Err(format!(
            "frame payload length {frame_len} exceeds MAX_FRAME_DATA"
        ));
    }

    Ok(GoldenState {
        region: RegionHeaderState {
            magic: read_u64(bytes, REGION_HEADER_MAGIC_OFFSET),
            abi_version: read_u32(bytes, REGION_HEADER_ABI_VERSION_OFFSET),
            node_count: read_u32(bytes, REGION_HEADER_NODE_COUNT_OFFSET),
            queue_capacity: read_u32(bytes, REGION_HEADER_QUEUE_CAPACITY_OFFSET),
            ring_count: read_u32(bytes, REGION_HEADER_RING_COUNT_OFFSET),
            ring_hdr_off: read_u64(bytes, REGION_HEADER_RING_HDR_OFF_OFFSET),
            ring_data_off: read_u64(bytes, REGION_HEADER_RING_DATA_OFF_OFFSET),
            entry_stride: read_u64(bytes, REGION_HEADER_ENTRY_STRIDE_OFFSET),
            region_size: read_u64(bytes, REGION_HEADER_REGION_SIZE_OFFSET),
            icount_shift: read_u32(bytes, REGION_HEADER_ICOUNT_SHIFT_OFFSET),
            pause_requested: read_u8(bytes, REGION_HEADER_PAUSE_REQUESTED_OFFSET),
            shutdown_requested: read_u8(bytes, REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET),
        },
        node: NodeSlotState {
            current_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_ICOUNT_OFFSET,
            ),
            current_ns: read_u64(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_NS_OFFSET),
            max_advance_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
            ),
            idle_wake_icount: read_u64(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
            ),
            wake_signal: read_u32(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_WAKE_SIGNAL_OFFSET),
            status: read_u8(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_STATUS_OFFSET),
            kind: read_u8(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_KIND_OFFSET),
            device_io_active: read_u8(
                bytes,
                GOLDEN_NODE_SLOT_BASE + NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
            ),
            publish_gen: read_u32(bytes, GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PUBLISH_GEN_OFFSET),
        },
        ring: RingHeaderState {
            read_idx: read_u64(bytes, GOLDEN_RING_HEADER_BASE + RING_HEADER_READ_IDX_OFFSET),
            write_idx: read_u64(
                bytes,
                GOLDEN_RING_HEADER_BASE + RING_HEADER_WRITE_IDX_OFFSET,
            ),
        },
        frame: FrameEntryState {
            delivery_icount: read_u64(
                bytes,
                GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
            ),
            src_node: read_u32(bytes, GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SRC_NODE_OFFSET),
            seq: read_u32(bytes, GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SEQ_OFFSET),
            payload: bytes[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
                ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + frame_len_usize]
                .to_vec(),
        },
        coverage: CoverageEntryState {
            current_icount: read_u64(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
            ),
            guest_pc: read_u64(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_GUEST_PC_OFFSET,
            ),
            map_index: read_u64(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_MAP_INDEX_OFFSET,
            ),
            vcpu_index: read_u32(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
            ),
            block_len: read_u32(
                bytes,
                GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
            ),
        },
    })
}

fn encode_golden_state(state: &GoldenState) -> Vec<u8> {
    let mut bytes = vec![0; GOLDEN_TOTAL_LEN];

    write_u64(&mut bytes, REGION_HEADER_MAGIC_OFFSET, state.region.magic);
    write_u32(
        &mut bytes,
        REGION_HEADER_ABI_VERSION_OFFSET,
        state.region.abi_version,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_NODE_COUNT_OFFSET,
        state.region.node_count,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        state.region.queue_capacity,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_RING_COUNT_OFFSET,
        state.region.ring_count,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_HDR_OFF_OFFSET,
        state.region.ring_hdr_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_RING_DATA_OFF_OFFSET,
        state.region.ring_data_off,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_ENTRY_STRIDE_OFFSET,
        state.region.entry_stride,
    );
    write_u64(
        &mut bytes,
        REGION_HEADER_REGION_SIZE_OFFSET,
        state.region.region_size,
    );
    write_u32(
        &mut bytes,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET,
        state.region.icount_shift,
    );
    write_u8(
        &mut bytes,
        REGION_HEADER_PAUSE_REQUESTED_OFFSET,
        state.region.pause_requested,
    );
    write_u8(
        &mut bytes,
        REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET,
        state.region.shutdown_requested,
    );

    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_ICOUNT_OFFSET,
        state.node.current_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_CURRENT_NS_OFFSET,
        state.node.current_ns,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
        state.node.max_advance_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
        state.node.idle_wake_icount,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_WAKE_SIGNAL_OFFSET,
        state.node.wake_signal,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_STATUS_OFFSET,
        state.node.status,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_KIND_OFFSET,
        state.node.kind,
    );
    write_u8(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
        state.node.device_io_active,
    );
    write_u32(
        &mut bytes,
        GOLDEN_NODE_SLOT_BASE + NODE_SLOT_PUBLISH_GEN_OFFSET,
        state.node.publish_gen,
    );

    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_READ_IDX_OFFSET,
        state.ring.read_idx,
    );
    write_u64(
        &mut bytes,
        GOLDEN_RING_HEADER_BASE + RING_HEADER_WRITE_IDX_OFFSET,
        state.ring.write_idx,
    );

    write_u64(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
        state.frame.delivery_icount,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SRC_NODE_OFFSET,
        state.frame.src_node,
    );
    write_u32(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_SEQ_OFFSET,
        state.frame.seq,
    );
    write_u16(
        &mut bytes,
        GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_LEN_OFFSET,
        state.frame.payload.len() as u16,
    );
    bytes[GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET
        ..GOLDEN_FRAME_ENTRY_BASE + FRAME_ENTRY_DATA_OFFSET + state.frame.payload.len()]
        .copy_from_slice(&state.frame.payload);

    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
        state.coverage.current_icount,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_GUEST_PC_OFFSET,
        state.coverage.guest_pc,
    );
    write_u64(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_MAP_INDEX_OFFSET,
        state.coverage.map_index,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_VCPU_INDEX_OFFSET,
        state.coverage.vcpu_index,
    );
    write_u32(
        &mut bytes,
        GOLDEN_COVERAGE_ENTRY_BASE + COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
        state.coverage.block_len,
    );

    bytes
}

fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut out = [0; 2];
    out.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(out)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(out)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

fn write_u8(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fixture {
    abi_version: u32,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GoldenState {
    region: RegionHeaderState,
    node: NodeSlotState,
    ring: RingHeaderState,
    frame: FrameEntryState,
    coverage: CoverageEntryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RegionHeaderState {
    magic: u64,
    abi_version: u32,
    node_count: u32,
    queue_capacity: u32,
    ring_count: u32,
    ring_hdr_off: u64,
    ring_data_off: u64,
    entry_stride: u64,
    region_size: u64,
    icount_shift: u32,
    pause_requested: u8,
    shutdown_requested: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeSlotState {
    current_icount: u64,
    current_ns: u64,
    max_advance_icount: u64,
    idle_wake_icount: u64,
    wake_signal: u32,
    status: u8,
    kind: u8,
    device_io_active: u8,
    publish_gen: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RingHeaderState {
    read_idx: u64,
    write_idx: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameEntryState {
    delivery_icount: u64,
    src_node: u32,
    seq: u32,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CoverageEntryState {
    current_icount: u64,
    guest_pc: u64,
    map_index: u64,
    vcpu_index: u32,
    block_len: u32,
}
