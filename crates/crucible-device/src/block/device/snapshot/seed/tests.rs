//! Concrete block seed grammar and pre-member refusal controls.

use super::*;
use crate::block::test_support::{device, ok};

fn decode(
    bytes: &[u8],
    admit: &mut dyn FnMut(u64) -> Result<(), &'static str>,
) -> Result<BlockSnapshot, BlockSnapshotCodecError> {
    let mut scratch = vec![0; bytes.len()];
    BlockSnapshot::from_canonical_bytes_with_wire_decoder(
        bytes,
        MAX_BLOCK_SNAPSHOT_BYTES,
        admit,
        &mut |_| Ok(()),
        |payload, seed| ciborium::de::from_reader_with_buffer_seed(seed, payload, &mut scratch),
        |bytes, length, maximum, admit_output| {
            BlockFaultState::from_canonical_bytes_with_decoder(
                bytes,
                length,
                maximum,
                admit_output,
                |payload| ciborium::de::from_reader(payload),
            )
        },
    )
}

#[test]
fn saved_block_seed_preserves_complete_canonical_snapshot() {
    let snapshot = device(PAGE_SIZE).snapshot();
    let bytes = ok(snapshot.to_canonical_bytes());
    let mut allocations = Vec::new();

    let actual = ok(decode(&bytes, &mut |bytes| {
        allocations.push(bytes);
        Ok(())
    }));

    assert_eq!(actual, snapshot);
    assert!(!allocations.is_empty());
    assert_eq!(ok(actual.to_canonical_bytes()), bytes);
}

#[test]
fn block_wire_max_refuses_before_actual_first_member_or_admission() {
    let mut bytes = BLOCK_SNAPSHOT_MAGIC.to_vec();
    bytes.extend_from_slice(&[0xa1, 0x64, b'c', b'o', b'r', b'e', 0x1b]);
    bytes.extend_from_slice(&(MAX_BLOCK_SNAPSHOT_BYTES + 1).to_be_bytes());
    // Replace the integer major type with an array while retaining its width.
    let header = bytes.len() - 9;
    bytes[header] = 0x9b;
    bytes.push(0xff);
    let mut calls = 0;

    let error = decode(&bytes, &mut |_| {
        calls += 1;
        Ok(())
    })
    .err()
    .unwrap();

    assert!(matches!(error, BlockSnapshotCodecError::ResourceLimit {
        field: "device snapshot sequence",
        requested,
        ..
    } if requested == MAX_BLOCK_SNAPSHOT_BYTES + 1));
    assert_eq!(calls, 0);
}

#[test]
fn block_table_refusal_precedes_malformed_first_payload_member() {
    let mut bytes = BLOCK_SNAPSHOT_MAGIC.to_vec();
    bytes.extend_from_slice(&[0xa1, 0x64, b'c', b'o', b'r', b'e', 0x82, 0xff]);
    let mut allocations = Vec::new();

    let error = decode(&bytes, &mut |bytes| {
        allocations.push(bytes);
        Err("same original block table refusal")
    })
    .err()
    .unwrap();

    assert_eq!(allocations, [2]);
    assert_eq!(error, BlockSnapshotCodecError::Malformed);
}

#[test]
fn page_map_validates_each_page_before_its_insertion_admission() {
    let valid = ok(SnapshotPage::new(vec![7; PAGE_SIZE], "test page"));
    let invalid = ok(SnapshotPage::new(vec![8], "test page"));
    let pages = ok(SnapshotPages::new(
        vec![(0, valid), (PAGE_SIZE as u64, invalid)],
        "test pages",
    ));
    let mut calls = Vec::new();

    let result = decode_pages(pages, &mut |allocation| {
        calls.push(allocation);
        Ok(())
    });

    assert_eq!(result.err(), Some(BlockSnapshotCodecError::Invalid));
    assert_eq!(calls, [DeviceSnapshotAllocation::BlockPage]);
}

#[test]
fn refused_first_page_insertion_precedes_later_invalid_page() {
    let valid = ok(SnapshotPage::new(vec![7; PAGE_SIZE], "test page"));
    let invalid = ok(SnapshotPage::new(vec![8], "test page"));
    let pages = ok(SnapshotPages::new(
        vec![(0, valid), (PAGE_SIZE as u64, invalid)],
        "test pages",
    ));
    let mut calls = 0;

    let result = decode_pages(pages, &mut |_| {
        calls += 1;
        Err("saved page map refusal")
    });

    assert_eq!(result.err(), Some(BlockSnapshotCodecError::Nested));
    assert_eq!(calls, 1);
}

#[test]
fn dirty_set_admits_only_actual_new_keys() {
    let pages = ok(SnapshotDirtyPages::new(
        vec![0, 0, PAGE_SIZE as u64],
        "test dirty pages",
    ));
    let mut calls = Vec::new();

    let actual = ok(decode_dirty_pages(pages, &mut |allocation| {
        calls.push(allocation);
        Ok(())
    }));

    assert_eq!(actual, BTreeSet::from([0, PAGE_SIZE as u64]));
    assert_eq!(calls, [DeviceSnapshotAllocation::BlockDirtyPage; 2]);
}
