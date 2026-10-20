//! Pure fixed-format regression tests; no current Cache authority is issued.

use super::*;

fn digest(value: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([value; 32])
}

fn record() -> CacheDurableRecordV1 {
    let projections = (digest(5), digest(6), digest(7), digest(8));
    CacheDurableRecordV1::new(
        CacheRecordKindV1::Domain,
        1,
        1,
        OperationId::from_bytes([1; 16]),
        digest(2),
        digest(3),
        digest(4),
        atomic_projection_digest(projections.0, projections.1, projections.2, projections.3),
        digest(9),
        digest(10),
        projections.0,
        projections.1,
        projections.2,
        projections.3,
        digest(11),
        0,
        1,
        ObjectDigest::from_bytes([0; 32]),
        ObjectDigest::from_bytes([0; 32]),
    ).unwrap()
}

#[test]
fn durable_record_preserves_closed_registry_framing_and_commitment() {
    let original = record();
    let encoded = encode_record(&original).unwrap();

    assert_eq!(decode_record(&encoded).unwrap(), original);
    assert_eq!(decode_record(&encoded[..encoded.len() - 1]), Err(CacheFormatError::Malformed));

    let mut unknown_kind = encoded;
    unknown_kind[10] = 255;
    assert_eq!(decode_record(&unknown_kind), Err(CacheFormatError::UnknownKind));

    let mut reserved = encoded;
    reserved[12] = 1;
    assert_eq!(decode_record(&reserved), Err(CacheFormatError::Malformed));

    let mut changed_payload = encoded;
    changed_payload[360] ^= 1;
    assert_eq!(decode_record(&changed_payload), Err(CacheFormatError::InvalidRecord));
}

#[test]
fn checkpoint_and_floor_bind_exact_history_and_next_sequence() {
    let original = record();
    let checkpoint = CacheCheckpointV1::new(
        original.sequence,
        original.digest,
        original.model,
        original.catalog_projection,
        original.reservation_projection,
        original.pin_projection,
        original.progress_projection,
        1, 1, 0, 0, 0, 0,
        ObjectDigest::from_bytes([0; 32]),
    ).unwrap();
    let encoded = encode_checkpoint(&checkpoint).unwrap();

    assert_eq!(decode_checkpoint(&encoded).unwrap(), checkpoint);

    let floor = CacheHistoryFloorV1::new(
        2,
        checkpoint.digest,
        ObjectDigest::from_bytes([0; 32]),
        checkpoint.history_head,
    ).unwrap();
    assert_eq!(decode_floor(&encode_floor(&floor).unwrap()).unwrap(), floor);

    let mut changed_count = encoded;
    changed_count[168] ^= 1;
    assert_eq!(decode_checkpoint(&changed_count), Err(CacheFormatError::InvalidCheckpoint));
}
