//! Exercises actual private File-seed transfer without inventing Source authority.

use super::super::import18_seed::OriginalImport18PrivateSeed;
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
    coordinator, installation, producer, storage_selection,
};
use crucible_node_format::{HashRef, U64};
use std::{io::Read, os::fd::AsRawFd};

fn current_host() -> ContentRef {
    let mut file = File::open("/proc/self/exe").unwrap();
    let length = file.metadata().unwrap().len();
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&length.to_be_bytes());
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: hash.finalize().to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".into(),
    }
}

// The defining File helper authenticates this actual executable. Its retained
// byte banks are DATA; no Source, native member or public boot loan is forged.
fn retained_birth() -> OriginalAckPeerBirth {
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(
        &current_host(),
        &Id::new("birth-capacity-original").unwrap(),
    )
    .unwrap();
    let mut source = Vec::with_capacity(173);
    source.extend_from_slice(b"retained source DATA");
    let mut registration = Vec::with_capacity(211);
    registration.extend_from_slice(b"retained registration DATA");
    let mut output = None;
    seed.retain_birth_into(&mut source, &mut registration, &mut output)
        .unwrap();
    output.unwrap()
}

#[test]
fn birth_census_keeps_actual_input_spare_capacity_and_original_file() {
    let birth = retained_birth();
    let descriptor = birth.host_file.as_raw_fd();
    let source_pointer = birth.source_birth.as_ptr();
    let registration_pointer = birth.expected_host_registration.as_ptr();
    let key = birth.key;
    let old = birth
        .retained_heap_storage_data_with_error::<RuntimeError>(usize::MAX)
        .unwrap();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    birth.record_retained_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.vector_banks, 2);
    assert_eq!(
        facts.vector_capacity_bytes,
        birth.source_birth.capacity() + birth.expected_host_registration.capacity()
    );
    assert_eq!(facts.string_banks, 5);
    assert_eq!(facts.capacity_records, 7);
    // One full reference (seven visits), the private Id and both byte Vecs.
    assert_eq!(
        facts.observed_nodes,
        10 + birth.source_birth.len() + birth.expected_host_registration.len()
    );
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts, old
        ),
        Ok(old)
    );
    assert!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts,
            old - 1
        )
        .is_err()
    );
    assert_eq!(birth.host_file.as_raw_fd(), descriptor);
    assert_eq!(birth.source_birth.as_ptr(), source_pointer);
    assert_eq!(
        birth.expected_host_registration.as_ptr(),
        registration_pointer
    );
    assert_eq!(birth.key, key);
    assert!(!birth.boot_started.get());
    assert!(birth.report_startup.is_none());
    assert!(birth.native_startup.is_none());
    assert!(birth.native_import18.is_none());
}

#[test]
fn revoked_birth_retains_the_same_backing_without_restoring_boot_permission() {
    let mut birth = retained_birth();
    let mut before = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    birth.record_retained_capacity_data(&mut before).unwrap();
    let expected = before.finish();
    birth.revoke_isolated_construction();
    let mut after = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    birth.record_retained_capacity_data(&mut after).unwrap();
    let actual = after.finish();

    assert_eq!(actual, expected);
    assert!(birth.failed);
    assert!(!birth.ready);
    assert!(birth.begin_private_boot().is_err());
    assert!(!birth.boot_started.get());
    let mut short = OriginalOwnerCapacityMetadataData::new(actual.capacity_records - 1, None);
    assert_eq!(
        birth.record_retained_capacity_data(&mut short),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(short.finish().capacity_records, actual.capacity_records - 1);
}

#[test]
fn busy_marker_keeps_birth_prefix_and_foreign_birth_refuses_before_rows() {
    let mut birth = retained_birth();
    let loan = birth.host_startup.borrow_mut();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    assert_eq!(
        birth.record_retained_capacity_data(&mut census),
        Err(RuntimeError::OwnerBusy)
    );
    assert_eq!(census.finish().capacity_records, 7);
    drop(loan);
    birth.process = birth.process.wrapping_add(1);
    let mut foreign = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    assert_eq!(
        birth.record_retained_capacity_data(&mut foreign),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(foreign.finish(), RetainedProtocolMetadataFacts::default());
    assert!(birth.host_startup.borrow().is_none());
}

#[test]
fn source_birth_census_refuses_busy_or_foreign_owner_without_installing_a_birth() {
    let coordinator = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap();
    assert_eq!(
        source.original_complete_birth_capacity_data(None).unwrap(),
        RetainedProtocolMetadataFacts::default()
    );
    let loan = source.ack_peer_birth.borrow_mut();

    assert_eq!(
        source.original_complete_birth_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(loan);
    source.process = source.process.wrapping_add(1);

    assert_eq!(
        source.original_complete_birth_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    assert!(source.ack_peer_birth.borrow().is_none());
}
