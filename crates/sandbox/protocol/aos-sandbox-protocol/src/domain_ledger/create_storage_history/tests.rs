//! Exercises strict V1 envelope corruption and original-coordinate substitution.

use super::transport::{
    CHUNK_HEADER_BYTES, ChunkEnvelopeV1, FRAME_HEADER_BYTES, FrameCoordinatesV1,
    FrameEnvelopeV1, FrameKindV1, OpenQueryV1, TransferIndexV1,
};
use super::*;

fn key(owner: OwnerV1, revision: u64) -> KeyV1 {
    KeyV1::new([1; 16], owner, revision).unwrap()
}

fn coordinates(revision: u64, predecessor: [u8; 32]) -> RecordCoordinatesV1 {
    RecordCoordinatesV1 {
        key: key(OwnerV1::Controller, revision),
        phase: PhaseV1::new(OwnerV1::Controller, 1).unwrap(),
        predecessor,
        correlation: [2; 32],
    }
}

fn encoded_record(coordinates: RecordCoordinatesV1, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; RECORD_OVERHEAD_BYTES + body.len()];
    RecordEnvelopeV1::encode_into(coordinates, body, &mut bytes).unwrap();
    bytes
}

fn decode_record(
    bytes: &[u8],
    coordinates: RecordCoordinatesV1,
) -> Result<RecordEnvelopeV1<'_>, HistoryErrorV1> {
    RecordEnvelopeV1::decode(bytes, coordinates.key, coordinates.phase)
}

fn reseal_record(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let checksum = record_checksum(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
}

#[test]
fn exact_keys_and_owner_specific_phase_registries_reject_unknown_codes() {
    for (owner, last) in [
        (OwnerV1::Controller, 12),
        (OwnerV1::Source, 3),
        (OwnerV1::Cache, 3),
        (OwnerV1::Root, 7),
    ] {
        for revision in [0, 1, u64::MAX] {
            let original = key(owner, revision);
            let encoded = original.encode();

            assert_eq!(encoded.len(), 43);
            assert_eq!(&encoded[..18], b"create-storage-v1\0");
            assert_eq!(KeyV1::decode(&encoded).unwrap(), original);
            for length in 0..encoded.len() {
                assert!(KeyV1::decode(&encoded[..length]).is_err());
            }
            assert!(KeyV1::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
        }
        for state in 1..=last {
            let phase = PhaseV1::new(owner, state).unwrap();
            assert_eq!(phase.owner(), owner);
            assert_eq!(phase.state(), state);
        }
        assert_eq!(PhaseV1::new(owner, 0), Err(HistoryErrorV1::Malformed));
        assert_eq!(PhaseV1::new(owner, last + 1), Err(HistoryErrorV1::Malformed));
    }

    // AssignmentPlanned is the new Controller-only phase. Reusing its code
    // under another owner's registry must still fail closed.
    assert_eq!(PhaseV1::new(OwnerV1::Controller, 12).unwrap().state(), 12);
    for owner in [OwnerV1::Source, OwnerV1::Cache, OwnerV1::Root] {
        assert_eq!(PhaseV1::new(owner, 12), Err(HistoryErrorV1::Malformed));
    }

    for code in [0, 5, u8::MAX] {
        assert_eq!(OwnerV1::decode(code), Err(HistoryErrorV1::Malformed));
    }
    assert!(KeyV1::new([0; 16], OwnerV1::Controller, 1).is_err());
}

#[test]
fn record_roundtrip_borrows_exact_body_and_head_matches_original_record() {
    let coordinates = coordinates(1, [0; 32]);
    let body = b"opaque body: its typed stage schema is deliberately not asserted";
    let bytes = encoded_record(coordinates, body);

    let record = decode_record(&bytes, coordinates).unwrap();
    let head = LatestHeadV1::new(1, record.checksum()).unwrap();
    let head_key = key(OwnerV1::Controller, 0);
    let decoded_head = LatestHeadV1::decode(&head.encode(), head_key).unwrap();

    assert_eq!(bytes.len(), 140 + body.len());
    assert_eq!(&bytes[..8], b"AOSXPR01");
    assert_eq!(&bytes[8..16], &[0, 1, 1, 1, 0, 0, 0, 0]);
    assert_eq!(record.coordinates(), coordinates);
    assert_eq!(record.body(), body);
    assert!(std::ptr::eq(record.body().as_ptr(), bytes[108..].as_ptr()));
    assert_eq!(decoded_head, head);
    decoded_head.check_record(head_key, record).unwrap();
    assert!(decoded_head.check_record(key(OwnerV1::Source, 0), record).is_err());
    assert!(LatestHeadV1::decode(&head.encode(), coordinates.key).is_err());
}

#[test]
fn every_record_corruption_truncation_and_tail_is_rejected() {
    let coordinates = coordinates(1, [0; 32]);
    let bytes = encoded_record(coordinates, b"original body");

    for length in 0..bytes.len() {
        assert!(decode_record(&bytes[..length], coordinates).is_err());
    }
    for offset in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(decode_record(&corrupt, coordinates).is_err(), "offset {offset}");
    }
    assert!(decode_record(&[bytes.as_slice(), &[0]].concat(), coordinates).is_err());

    for offset in [12, 13, 14, 15] {
        let mut corrupt = bytes.clone();
        corrupt[offset] = 1;
        reseal_record(&mut corrupt);

        assert_eq!(decode_record(&corrupt, coordinates), Err(HistoryErrorV1::Malformed));
    }

    let mut oversized = bytes;
    oversized[104..108].copy_from_slice(&u32::MAX.to_be_bytes());
    reseal_record(&mut oversized);
    assert_eq!(decode_record(&oversized, coordinates), Err(HistoryErrorV1::Extent));
}

#[test]
fn predecessor_and_latest_head_checks_reject_substitution_without_semantic_admission() {
    let first_coordinates = coordinates(1, [0; 32]);
    let first_bytes = encoded_record(first_coordinates, b"first");
    let first = decode_record(&first_bytes, first_coordinates).unwrap();
    let second_coordinates = coordinates(2, first.checksum());
    let second_bytes = encoded_record(second_coordinates, b"second");
    let second = decode_record(&second_bytes, second_coordinates).unwrap();

    second.check_predecessor(first).unwrap();
    assert!(first.check_predecessor(second).is_err());
    assert!(LatestHeadV1::new(1, first.checksum()).unwrap()
        .check_record(key(OwnerV1::Controller, 0), second).is_err());

    let skipped_coordinates = coordinates(3, first.checksum());
    let skipped_bytes = encoded_record(skipped_coordinates, b"skipped");
    assert!(decode_record(&skipped_bytes, skipped_coordinates).unwrap()
        .check_predecessor(first).is_err());

    let maximum_coordinates = coordinates(u64::MAX, [9; 32]);
    let maximum_bytes = encoded_record(maximum_coordinates, b"maximum");
    let maximum = decode_record(&maximum_bytes, maximum_coordinates).unwrap();
    assert!(second.check_predecessor(maximum).is_err());

    for invalid in [
        RecordCoordinatesV1 { key: key(OwnerV1::Controller, 0), ..first_coordinates },
        RecordCoordinatesV1 { predecessor: [1; 32], ..first_coordinates },
        RecordCoordinatesV1 { correlation: [0; 32], ..first_coordinates },
        RecordCoordinatesV1 { phase: PhaseV1::new(OwnerV1::Source, 1).unwrap(), ..first_coordinates },
    ] {
        let mut output = vec![7; RECORD_OVERHEAD_BYTES + 4];
        let before = output.clone();
        assert!(RecordEnvelopeV1::encode_into(invalid, b"body", &mut output).is_err());
        assert_eq!(output, before);
    }
}

#[test]
fn every_short_or_extended_latest_head_and_zero_field_is_rejected() {
    let head = LatestHeadV1::new(1, [4; 32]).unwrap().encode();
    let head_key = key(OwnerV1::Root, 0);

    for length in 0..head.len() {
        assert!(LatestHeadV1::decode(&head[..length], head_key).is_err());
    }
    assert!(LatestHeadV1::decode(&[head.as_slice(), &[0]].concat(), head_key).is_err());
    assert!(LatestHeadV1::decode(&[0; HEAD_BYTES], head_key).is_err());
    assert!(LatestHeadV1::new(0, [4; 32]).is_err());
    assert!(LatestHeadV1::new(1, [0; 32]).is_err());
}

fn open() -> OpenQueryV1 {
    OpenQueryV1 {
        controller_nonce: [1; 16],
        lane: [2; 16],
        seed: [3; 32],
        ready: [4; 32],
    }
}

fn frame_coordinates(kind: FrameKindV1) -> FrameCoordinatesV1 {
    FrameCoordinatesV1 {
        kind,
        lane: [2; 16],
        sequence: 1,
        root_nonce: [5; 16],
        controller_nonce: [1; 16],
    }
}

#[test]
fn fixed_open_is_not_a_hello_frame_and_rejects_reserved_and_zero_fields() {
    let original = open();
    let bytes = original.encode().unwrap();

    assert_eq!(bytes.len(), 112);
    assert_eq!(&bytes[..8], b"AOSXPQ01");
    assert_eq!(&bytes[24..32], &[0; 8]);
    assert_eq!(OpenQueryV1::decode(&bytes).unwrap(), original);
    assert!(FrameEnvelopeV1::decode(&bytes, frame_coordinates(FrameKindV1::Hello)).is_err());
    for length in 0..bytes.len() {
        assert!(OpenQueryV1::decode(&bytes[..length]).is_err());
    }
    for offset in 24..32 {
        let mut corrupt = bytes;
        corrupt[offset] = 1;
        assert_eq!(OpenQueryV1::decode(&corrupt), Err(HistoryErrorV1::Malformed));
    }
    for (start, end) in [(8, 24), (32, 48), (48, 80), (80, 112)] {
        let mut corrupt = bytes;
        corrupt[start..end].fill(0);
        assert_eq!(OpenQueryV1::decode(&corrupt), Err(HistoryErrorV1::Malformed));
    }
    assert!(OpenQueryV1::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
}

#[test]
fn frame_roundtrip_checks_every_byte_and_rejects_kind_nonce_lane_and_sequence_substitution() {
    let coordinates = frame_coordinates(FrameKindV1::ReadyChunk);
    let payload = b"complete exact payload";
    let header = coordinates.encode_header(payload).unwrap();
    let bytes = [header.as_slice(), payload].concat();

    let frame = FrameEnvelopeV1::decode(&bytes, coordinates).unwrap();

    assert_eq!(header.len(), FRAME_HEADER_BYTES);
    assert_eq!(&header[..16], &[65, 79, 83, 88, 80, 70, 48, 49, 0, 1, 0, 3, 0, 0, 0, 0]);
    assert_eq!(frame.coordinates(), coordinates);
    assert_eq!(frame.payload(), payload);
    assert!(std::ptr::eq(frame.payload().as_ptr(), bytes[112..].as_ptr()));
    for length in 0..bytes.len() {
        assert!(FrameEnvelopeV1::decode(&bytes[..length], coordinates).is_err());
    }
    for offset in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(FrameEnvelopeV1::decode(&corrupt, coordinates).is_err(), "offset {offset}");
    }
    assert!(FrameEnvelopeV1::decode(&[bytes.as_slice(), &[0]].concat(), coordinates).is_err());
    for changed in [
        FrameCoordinatesV1 { kind: FrameKindV1::SignedChunk, ..coordinates },
        FrameCoordinatesV1 { sequence: 2, ..coordinates },
        FrameCoordinatesV1 { lane: [8; 16], ..coordinates },
        FrameCoordinatesV1 { root_nonce: [8; 16], ..coordinates },
        FrameCoordinatesV1 { controller_nonce: [8; 16], ..coordinates },
    ] {
        assert_eq!(FrameEnvelopeV1::decode(&bytes, changed), Err(HistoryErrorV1::Correlation));
    }
    assert!(FrameCoordinatesV1 { sequence: 0, ..coordinates }.encode_header(payload).is_err());
}

#[test]
fn all_registered_frame_kinds_are_closed_and_wrong_domain_or_reserved_fields_fail() {
    let kinds = [
        FrameKindV1::Hello, FrameKindV1::ReadyIndex, FrameKindV1::ReadyChunk,
        FrameKindV1::CurrentProofs, FrameKindV1::UseAuthorized, FrameKindV1::UseReserved,
        FrameKindV1::UseCurrentProofs, FrameKindV1::UseAdmitted, FrameKindV1::SignedIndex,
        FrameKindV1::SignedChunk, FrameKindV1::SignedBound, FrameKindV1::OutcomeIndex,
        FrameKindV1::OutcomeChunk, FrameKindV1::OutcomeRecorded, FrameKindV1::ReleaseProofs,
        FrameKindV1::Closed, FrameKindV1::RecoveryQuery, FrameKindV1::RecoveryState,
        FrameKindV1::CurrentProofsChallenge, FrameKindV1::UseCurrentProofsChallenge,
        FrameKindV1::RootOutcomeRecorded,
    ];
    for kind in kinds {
        let coordinates = frame_coordinates(kind);
        let header = coordinates.encode_header(&[]).unwrap();
        FrameEnvelopeV1::decode(&header, coordinates).unwrap();
    }

    let coordinates = frame_coordinates(FrameKindV1::Hello);
    let original = coordinates.encode_header(&[]).unwrap();
    for code in [0_u16, 22, u16::MAX] {
        let mut bytes = original;
        bytes[10..12].copy_from_slice(&code.to_be_bytes());
        assert_eq!(FrameEnvelopeV1::decode(&bytes, coordinates), Err(HistoryErrorV1::Malformed));
    }
    for offset in [12, 13, 14, 15, 44, 45, 46, 47] {
        let mut bytes = original;
        bytes[offset] = 1;
        assert_eq!(FrameEnvelopeV1::decode(&bytes, coordinates), Err(HistoryErrorV1::Malformed));
    }

    let mut bytes = original;
    let wrong: [u8; 32] = Sha256::new()
        .chain_update(b"wrong domain")
        .chain_update(&bytes[..80])
        .finalize()
        .into();
    bytes[80..].copy_from_slice(&wrong);
    assert_eq!(FrameEnvelopeV1::decode(&bytes, coordinates), Err(HistoryErrorV1::Checksum));
}

#[test]
fn indexed_chunks_cover_exact_original_bytes_without_accepting_repeats_or_wrong_final_lengths() {
    let width = super::super::create_q04_history::CLAIM_CHUNK_BYTES;
    let original = vec![9; width * 2 + 1];
    let index = TransferIndexV1::new(original.len() as u64, [3; 32]).unwrap();
    let index_bytes = index.encode();

    assert_eq!(TransferIndexV1::decode(&index_bytes).unwrap(), index);
    assert_eq!(index.total(), original.len() as u64);
    assert_eq!(index.count(), 3);
    assert_eq!(index.digest(), [3; 32]);
    let mut reconstructed = Vec::new();
    for number in 0..3 {
        let start = number as usize * width;
        let payload = &original[start..original.len().min(start + width)];
        let header = index.encode_chunk_header(number, payload).unwrap();
        let bytes = [header.as_slice(), payload].concat();

        let chunk = ChunkEnvelopeV1::decode(&bytes, index, number).unwrap();

        assert_eq!(chunk.index(), number);
        assert_eq!(bytes.len(), CHUNK_HEADER_BYTES + payload.len());
        assert!(std::ptr::eq(chunk.payload().as_ptr(), bytes[24..].as_ptr()));
        reconstructed.extend_from_slice(chunk.payload());
        assert!(ChunkEnvelopeV1::decode(&bytes, index, number + 1).is_err());
        for length in 0..bytes.len() {
            assert!(ChunkEnvelopeV1::decode(&bytes[..length], index, number).is_err());
        }
        assert!(ChunkEnvelopeV1::decode(&[bytes.as_slice(), &[0]].concat(), index, number).is_err());
        for offset in 0..24 {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(ChunkEnvelopeV1::decode(&corrupt, index, number).is_err());
        }
    }
    assert_eq!(reconstructed, original);
    assert!(index.encode_chunk_header(3, &[]).is_err());
    assert!(index.encode_chunk_header(2, &[0; 2]).is_err());
}

#[test]
fn index_limits_are_wire_representation_checks_without_allocating_a_claimed_total() {
    let width = super::super::create_q04_history::CLAIM_CHUNK_BYTES as u64;
    let maximum = width * u64::from(u32::MAX);
    let large = TransferIndexV1::new(maximum, [7; 32]).unwrap();

    assert_eq!(large.count(), u32::MAX);
    assert_eq!(TransferIndexV1::decode(&large.encode()).unwrap(), large);
    assert!(TransferIndexV1::new(maximum + 1, [7; 32]).is_err());
    assert!(TransferIndexV1::new(u64::MAX, [7; 32]).is_err());
    assert!(TransferIndexV1::new(0, [7; 32]).is_err());
    assert!(TransferIndexV1::new(1, [0; 32]).is_err());
    for total in [1, width - 1, width, width + 1] {
        let index = TransferIndexV1::new(total, [7; 32]).unwrap();
        let bytes = index.encode();
        for length in 0..bytes.len() {
            assert!(TransferIndexV1::decode(&bytes[..length]).is_err());
        }
        assert!(TransferIndexV1::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        for offset in 12..16 {
            let mut corrupt = bytes;
            corrupt[offset] = 1;
            assert_eq!(TransferIndexV1::decode(&corrupt), Err(HistoryErrorV1::Malformed));
        }
        let mut changed_count = bytes;
        changed_count[8..12].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(TransferIndexV1::decode(&changed_count), Err(HistoryErrorV1::Correlation));
    }
}
