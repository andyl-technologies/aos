//! Rejects malformed capture spools before durable page publication.

use super::*;
use crucible_ram::{
    MetadataBudget, PageDigest, RamSnapshot, RegionClass, RegionDescriptor, RegionTree, Topology,
};
use std::io::Write;

fn fixture() -> (RootRecord, Vec<u8>) {
    let budget = MetadataBudget::new(65536);
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("ram", RegionClass::MutableMain, 4099)
                .unwrap_or_else(|error| panic!("valid capture fixture: {error}")),
        ],
        Limits::default(),
    )
    .unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    let digests = [
        PageDigest::hash(&[7; 4096])
            .unwrap_or_else(|error| panic!("valid capture fixture: {error}")),
        PageDigest::hash(&[8; 3]).unwrap_or_else(|error| panic!("valid capture fixture: {error}")),
    ];
    let tree = RegionTree::from_page_digests(4099, &digests, &budget)
        .unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    let root = RamSnapshot::new(topology, vec![tree], &budget)
        .unwrap_or_else(|error| panic!("valid capture fixture: {error}"))
        .root_record(Scope::Exact)
        .unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    let encoded = root.encode();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&EDITION.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&17_u64.to_be_bytes());
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(root.digest().as_bytes());
    bytes.extend_from_slice(&encoded);
    for (index, length, value) in [(0_u64, 4096_u32, 7_u8), (1, 3, 8)] {
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&23_u64.to_be_bytes());
        bytes.resize(bytes.len() + length as usize, value);
    }
    (root, bytes)
}

fn admit(bytes: &[u8]) -> Result<QemuPagedRamCapture, QemuNodeError> {
    let mut file =
        tempfile::tempfile().unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    QemuPagedRamCapture::admit(file, bytes.len() as u64)
}

#[test]
fn full_capture_preserves_short_tail_and_frozen_generation() {
    let (root, bytes) = fixture();
    let mut capture =
        admit(&bytes).unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    assert_eq!(capture.record(), &root);
    assert_eq!(capture.generation(), 17);
    assert!(capture.initial());
    let first = capture
        .next_page()
        .unwrap_or_else(|error| panic!("valid captured page: {error}"))
        .unwrap_or_else(|| panic!("expected captured page"));
    let tail = capture
        .next_page()
        .unwrap_or_else(|error| panic!("valid captured page: {error}"))
        .unwrap_or_else(|| panic!("expected captured page"));
    assert_eq!(first.bytes, vec![7; 4096]);
    assert_eq!(tail.bytes, vec![8; 3]);
    assert_eq!((tail.page_index, tail.version), (1, 23));
    assert!(
        capture
            .next_page()
            .unwrap_or_else(|error| panic!("valid capture fixture: {error}"))
            .is_none()
    );
}

#[test]
fn spool_authentication_and_allocation_bounds_precede_page_reads() {
    let (_, bytes) = fixture();
    for (offset, value) in [
        (16, 0_u64.to_be_bytes().to_vec()),
        (32, ((MAX_ROOT_BYTES + 1) as u32).to_be_bytes().to_vec()),
        (40, vec![99; 32]),
    ] {
        let mut changed = bytes.clone();
        changed[offset..offset + value.len()].copy_from_slice(&value);
        assert!(admit(&changed).is_err());
    }
}

#[test]
fn duplicate_coordinate_and_zero_version_cannot_acknowledge_a_page() {
    let (root, bytes) = fixture();
    let first = HEADER_BYTES + root.encoded_len();
    let second = first + PAGE_HEADER_BYTES + 4096;
    for (offset, value) in [(second + 8, 0_u64), (second + 16, 0)] {
        let mut changed = bytes.clone();
        changed[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        let mut capture =
            admit(&changed).unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
        assert!(
            capture
                .next_page()
                .unwrap_or_else(|error| panic!("valid capture fixture: {error}"))
                .is_some()
        );
        assert!(capture.next_page().is_err());
    }
}

#[test]
fn complete_record_count_cannot_hide_trailing_bytes() {
    let (_, mut bytes) = fixture();
    bytes.push(1);
    let mut capture =
        admit(&bytes).unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
    assert!(
        capture
            .next_page()
            .unwrap_or_else(|error| panic!("valid capture fixture: {error}"))
            .is_some()
    );
    assert!(
        capture
            .next_page()
            .unwrap_or_else(|error| panic!("valid capture fixture: {error}"))
            .is_some()
    );
    assert!(capture.next_page().is_err());
}
