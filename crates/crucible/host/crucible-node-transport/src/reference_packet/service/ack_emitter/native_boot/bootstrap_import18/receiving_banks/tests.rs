//! Exercises real seven-bank allocation, wire-body mutation and failure custody.
//!
//! These primitive DATA controls create no native Prepare token, opaque Recipe,
//! Initial, model or Ready. References use the independent canonical CNP hash.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crucible_node_format::{Bytes, Extensions, Id, U64, canonical};

fn bodies() -> [Vec<u8>; 7] {
    [
        b"native protocol".to_vec(),
        b"logical control".to_vec(),
        b"captured anchor".to_vec(),
        b"owner snapshot".to_vec(),
        b"source journal".to_vec(),
        b"target normalization".to_vec(),
        (0..5000).map(|index| (index % 251) as u8).collect(),
    ]
}

fn references(bodies: &[Vec<u8>; 7]) -> [ContentRef; 7] {
    bodies.each_ref().map(|body| ContentRef {
        hash: canonical::hash("cnp.blob.v1", body).unwrap(),
        length: U64::new(body.len() as u64),
        media_type: "application/octet-stream".to_owned(),
    })
}

fn reserve(references: &[ContentRef; 7]) -> OriginalImport18ReceivingBanks {
    let mut owner = OriginalImport18ReceivingBanks::empty();
    owner
        .reserve_data(
            references.each_ref(),
            references
                .each_ref()
                .map(|reference| reference.length.get() as usize),
            usize::MAX,
        )
        .unwrap();
    owner
}

fn begin(ordinal: usize, reference: &ContentRef) -> BlobBeginRequest {
    BlobBeginRequest {
        transfer_id: Id::new(format!("input-{ordinal}")).unwrap(),
        content: reference.clone(),
        extensions: Extensions::new(),
    }
}

fn chunk(begin: &BlobBeginRequest, offset: usize, bytes: &[u8]) -> BlobChunkRequest {
    BlobChunkRequest {
        transfer_id: begin.transfer_id.clone(),
        offset: U64::new(offset as u64),
        bytes: Bytes::new(bytes.to_vec()),
        extensions: Extensions::new(),
    }
}

fn finish(begin: &BlobBeginRequest) -> BlobFinishRequest {
    BlobFinishRequest {
        transfer_id: begin.transfer_id.clone(),
        extensions: Extensions::new(),
    }
}

#[test]
fn seven_distinct_inputs_complete_in_order_without_growing_reserved_backing() {
    let bodies = bodies();
    let references = references(&bodies);
    let mut owner = reserve(&references);
    let retained = owner.retained_backing_data().unwrap();
    let row = OriginalImport18ReceivingBanks::backing_construction_data(
        references.each_ref(),
        bodies.each_ref().map(Vec::len),
        usize::MAX,
    )
    .unwrap();
    assert_eq!(retained, row[0]);

    for (ordinal, body) in bodies.iter().enumerate() {
        assert!(owner.bodies_data().is_err());
        let begin = begin(ordinal, &references[ordinal]);
        assert_eq!(owner.begin_data(&begin).unwrap(), 0);
        let mut offset = 0;
        for bytes in body.chunks(4096) {
            offset += bytes.len();
            assert_eq!(
                owner
                    .chunk_data(&chunk(&begin, offset - bytes.len(), bytes))
                    .unwrap(),
                offset
            );
            assert_eq!(owner.retained_backing_data().unwrap(), retained);
        }
        assert_eq!(owner.begin_data(&begin).unwrap(), body.len());
        assert_eq!(owner.finish_data(&finish(&begin)).unwrap(), ordinal);
    }

    assert_eq!(
        owner.bodies_data().unwrap(),
        bodies.each_ref().map(Vec::as_slice)
    );
    assert_eq!(owner.retained_backing_data().unwrap(), retained);
    assert!(
        owner
            .reserve_data(references.each_ref(), [usize::MAX; 7], usize::MAX)
            .is_err()
    );
    assert_eq!(
        owner.bodies_data().unwrap(),
        bodies.each_ref().map(Vec::as_slice)
    );
}

#[test]
fn one_byte_short_or_invalid_reference_reserves_nothing_and_stays_spent() {
    let references = references(&bodies());
    let row = OriginalImport18ReceivingBanks::backing_construction_data(
        references.each_ref(),
        [usize::MAX; 7],
        usize::MAX,
    )
    .unwrap();
    let mut owner = OriginalImport18ReceivingBanks::empty();
    assert!(
        owner
            .reserve_data(
                references.each_ref(),
                [usize::MAX; 7],
                row.iter().sum::<usize>() - 1
            )
            .is_err()
    );
    assert_eq!(owner.retained_backing_data().unwrap(), 0);
    assert!(
        owner
            .reserve_data(references.each_ref(), [usize::MAX; 7], usize::MAX)
            .is_err()
    );

    for mutation in 0..6 {
        let mut changed = references.clone();
        match mutation {
            0 => changed[6].hash.algorithm = "sha256".to_owned(),
            1 => changed[6].hash.domain = "cnp.world-binding.v1".to_owned(),
            2 => changed[6].hash.digest.make_ascii_uppercase(),
            3 => changed[6].media_type.clear(),
            4 => changed[6].media_type = "non\nascii".to_owned(),
            5 => changed[6].length = U64::new(0),
            _ => unreachable!(),
        }
        let mut owner = OriginalImport18ReceivingBanks::empty();
        assert!(
            owner
                .reserve_data(changed.each_ref(), [usize::MAX; 7], usize::MAX)
                .is_err()
        );
        assert_eq!(owner.retained_backing_data().unwrap(), 0);
        assert!(owner.banks.iter().all(|bank| bank.reference.is_none()));
        assert!(owner.bodies_data().is_err());
    }
}

#[test]
fn real_capacity_overflow_retains_six_banks_and_the_last_partial_reference() {
    let bodies = bodies();
    let mut references = references(&bodies);
    // Vec rejects a byte layout above isize::MAX before asking the allocator.
    // This exercises actual partial reservation failure without a large request.
    references[6].length = U64::new((isize::MAX as u64) + 1);
    let mut owner = OriginalImport18ReceivingBanks::empty();
    assert!(
        owner
            .reserve_data(references.each_ref(), [usize::MAX; 7], usize::MAX)
            .is_err()
    );
    assert!(
        owner.banks[..6]
            .iter()
            .zip(&bodies[..6])
            .all(|(bank, body)| bank.bytes.capacity() == body.len())
    );
    assert_eq!(owner.banks[6].bytes.capacity(), 0);
    assert_eq!(owner.banks[6].reference.as_ref(), Some(&references[6]));
    let retained = owner.retained_backing_data().unwrap();
    assert!(retained > bodies[..6].iter().map(Vec::len).sum::<usize>());
    assert!(
        owner
            .reserve_data(references.each_ref(), [usize::MAX; 7], usize::MAX)
            .is_err()
    );
    assert_eq!(owner.retained_backing_data().unwrap(), retained);
    assert!(owner.begin_data(&begin(0, &references[0])).is_err());
    assert!(owner.bodies_data().is_err());
}

#[test]
fn bad_transfers_retain_bytes_and_cannot_restart_or_lend_complete_bodies() {
    let bodies = bodies();
    let references = references(&bodies);
    for mutation in 0..10 {
        let mut owner = reserve(&references);
        let original = begin(0, &references[0]);
        let retained = owner.retained_backing_data().unwrap();
        let prefix = &bodies[0][..3];
        owner.begin_data(&original).unwrap();
        owner.chunk_data(&chunk(&original, 0, prefix)).unwrap();

        let result = match mutation {
            0 => owner.chunk_data(&chunk(&original, 4, b"gap")),
            1 => owner.chunk_data(&chunk(&original, 0, prefix)),
            2 => owner.chunk_data(&chunk(&original, 3, b"")),
            3 => owner.chunk_data(&chunk(&original, 3, &[42; 4097])),
            4 => owner.chunk_data(&chunk(&original, 3, &[42; 20])),
            5 => owner.finish_data(&finish(&original)),
            6 => {
                let foreign = begin(1, &references[1]);
                owner.chunk_data(&chunk(&foreign, 3, b"foreign"))
            }
            7 => {
                let mut changed = original.clone();
                changed.content.media_type = "application/json".to_owned();
                owner.begin_data(&changed)
            }
            8 => {
                let mut changed = chunk(&original, 3, b"extension");
                changed
                    .extensions
                    .insert("unselected".to_owned(), serde_json::Value::Bool(true));
                owner.chunk_data(&changed)
            }
            9 => owner.begin_data(&begin(1, &references[1])),
            _ => unreachable!(),
        };
        assert!(result.is_err());
        assert_eq!(owner.banks[0].bytes.as_slice(), prefix);
        assert_eq!(owner.retained_backing_data().unwrap(), retained);
        assert!(
            owner
                .chunk_data(&chunk(&original, 3, &bodies[0][3..]))
                .is_err()
        );
        assert!(owner.bodies_data().is_err());
    }
}

#[test]
fn wrong_digest_or_reused_role_transfer_cannot_complete() {
    let bodies = bodies();
    let references = references(&bodies);
    let mut owner = reserve(&references);
    let first = begin(0, &references[0]);
    owner.begin_data(&first).unwrap();
    let wrong = vec![42; bodies[0].len()];
    owner.chunk_data(&chunk(&first, 0, &wrong)).unwrap();
    assert!(owner.finish_data(&finish(&first)).is_err());
    assert_eq!(owner.banks[0].bytes, wrong);
    assert!(owner.bodies_data().is_err());

    let mut owner = reserve(&references);
    owner.begin_data(&first).unwrap();
    owner.chunk_data(&chunk(&first, 0, &bodies[0])).unwrap();
    owner.finish_data(&finish(&first)).unwrap();
    let mut second = begin(1, &references[1]);
    second.transfer_id = first.transfer_id.clone();
    assert!(owner.begin_data(&second).is_err());
    assert_eq!(owner.banks[0].bytes, bodies[0]);
    assert!(owner.bodies_data().is_err());
}
