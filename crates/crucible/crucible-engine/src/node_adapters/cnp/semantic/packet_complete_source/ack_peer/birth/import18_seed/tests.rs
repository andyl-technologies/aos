//! Checks the real current-executable component without inventing Source authority.
//!
//! The expected reference here is a test measurement for the File helper only.
//! Production uses the independently pinned and parent-authenticated host ref.

use super::*;
use crucible_node_format::{HashRef, U64};
use std::io::Read;
use std::os::fd::AsRawFd;

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

#[test]
fn actual_file_seed_matches_quoted_clones_and_refuses_repeated_preparation() {
    let host = current_host();
    let private_launch = Id::new("private-seed-component-control").unwrap();
    let row =
        OriginalImport18PrivateSeed::construction_data(&host, &private_launch, usize::MAX).unwrap();
    let exact = *row.iter().max().unwrap();
    assert_eq!(
        OriginalImport18PrivateSeed::construction_data(&host, &private_launch, exact).unwrap(),
        row
    );
    assert!(
        OriginalImport18PrivateSeed::construction_data(&host, &private_launch, exact - 1).is_err()
    );
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(&host, &private_launch).unwrap();
    seed.authenticate().unwrap();
    assert_eq!(seed.known_backing().unwrap(), row[0]);
    let original_fd = seed.file.as_ref().unwrap().as_raw_fd();
    let original_birth = seed.birth_id;

    assert_eq!(
        seed.prepare(&host, &private_launch),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), original_fd);
    assert_eq!(seed.birth_id, original_birth);
}

#[test]
fn wrong_expected_host_keeps_first_file_prefix_and_spent_failure() {
    let mut host = current_host();
    host.length = U64::new(host.length.get() + 1);
    let private_launch = Id::new("private-seed-refusal-control").unwrap();
    let mut seed = OriginalImport18PrivateSeed::empty();
    assert!(seed.prepare(&host, &private_launch).is_err());
    assert!(seed.started && !seed.complete);
    assert!(matches!(seed.failure, Some(RuntimeError::ForeignAuthority)));
    assert!(seed.file.is_some() && seed.revision.is_some());
    assert!(seed.host.is_some() && seed.private_launch.is_some());
    assert!(seed.birth_id.is_none());
    assert_eq!(seed.key, [0; 32]);
    let fd = seed.file.as_ref().unwrap().as_raw_fd();
    assert_eq!(
        seed.prepare(&current_host(), &private_launch),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), fd);
    assert!(matches!(seed.failure, Some(RuntimeError::ForeignAuthority)));
    assert!(seed.known_backing().unwrap() > 0);
}

#[test]
fn retained_original_file_authentication_rejects_foreign_descriptor() {
    let host = current_host();
    let private_launch = Id::new("private-seed-file-control").unwrap();
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(&host, &private_launch).unwrap();
    let path = std::env::temp_dir().join(format!(
        "crucible-private-seed-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let foreign = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    let original = seed.file.replace(foreign);
    assert_eq!(seed.authenticate(), Err(RuntimeError::ForeignAuthority));
    seed.file = original;
    seed.authenticate().unwrap();
}

#[test]
fn private_birth_transfer_preserves_original_identity_and_bank_allocations() {
    let host = current_host();
    let launch = Id::new("private-birth-transfer").unwrap();
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(&host, &launch).unwrap();
    let descriptor = seed.file.as_ref().unwrap().as_raw_fd();
    let key = seed.key;
    let identity = seed.birth_id.unwrap();
    let mut source = b"original source bank".to_vec();
    let mut registration = b"original registration bank".to_vec();
    let source_pointer = source.as_ptr();
    let registration_pointer = registration.as_ptr();
    let mut output = None;

    seed.retain_birth_into(&mut source, &mut registration, &mut output)
        .unwrap();

    let birth = output.as_ref().unwrap();
    assert_eq!(birth.host_file.as_raw_fd(), descriptor);
    assert_eq!(birth.host_executable, host);
    assert_eq!(birth.private_launch, launch);
    assert_eq!(birth.key, key);
    assert_eq!(birth.birth_id, identity);
    assert_eq!(birth.source_birth.as_ptr(), source_pointer);
    assert_eq!(
        birth.expected_host_registration.as_ptr(),
        registration_pointer
    );
    assert_eq!(birth.source_birth, b"original source bank");
    assert_eq!(
        birth.expected_host_registration,
        b"original registration bank"
    );
    birth.authenticate_unstarted_storage_phase().unwrap();
    birth
        .authenticate_isolated_construction_storage_data()
        .unwrap();
    assert!(birth.report_startup_required);
    assert!(birth.report_startup.is_none());
    assert!(birth.native_startup.is_none());
    assert!(birth.native_import18.is_none());
    assert!(birth.native_host_finalization.is_none());
    assert!(birth.host_startup.borrow().is_none());
    assert!(!birth.boot_started.get());
    assert!(source.is_empty() && source.capacity() == 0);
    assert!(registration.is_empty() && registration.capacity() == 0);
    assert_eq!(seed.known_backing().unwrap(), 0);
    assert_eq!(seed.key, [0; 32]);
    assert!(seed.authenticate().is_err());

    assert_eq!(
        seed.retain_birth_into(&mut source, &mut registration, &mut output),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(output.as_ref().unwrap().host_file.as_raw_fd(), descriptor);
}

#[test]
fn missing_bank_refuses_transfer_without_consuming_original_seed() {
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(
        &current_host(),
        &Id::new("private-birth-missing-bank").unwrap(),
    )
    .unwrap();
    let descriptor = seed.file.as_ref().unwrap().as_raw_fd();
    let identity = seed.birth_id;
    let mut source = b"retained source".to_vec();
    let mut registration = Vec::new();
    let mut output = None;

    assert_eq!(
        seed.retain_birth_into(&mut source, &mut registration, &mut output),
        Err(RuntimeError::InvalidReceipt)
    );

    seed.authenticate().unwrap();
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), descriptor);
    assert_eq!(seed.birth_id, identity);
    assert_eq!(source, b"retained source");
    assert!(output.is_none());
}

#[test]
fn construction_census_refuses_started_boot_and_retains_failed_birth_backing() {
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(&current_host(), &Id::new("private-birth-census").unwrap())
        .unwrap();
    let mut source = b"source".to_vec();
    let mut registration = b"registration".to_vec();
    let mut output = None;
    seed.retain_birth_into(&mut source, &mut registration, &mut output)
        .unwrap();
    let birth = output.as_mut().unwrap();
    let backing = birth
        .retained_heap_storage_data_with_error::<RuntimeError>(usize::MAX)
        .unwrap();

    birth.revoke_isolated_construction();
    birth
        .authenticate_isolated_construction_storage_data()
        .unwrap();
    assert_eq!(
        birth.retained_heap_storage_data_with_error::<RuntimeError>(usize::MAX),
        Ok(backing)
    );
    assert!(birth.authenticate_unstarted_storage_phase().is_err());
    assert!(birth.begin_private_boot().is_err());

    birth.boot_started.set(true);
    assert_eq!(
        birth.authenticate_isolated_construction_storage_data(),
        Err(RuntimeError::OutstandingObligations)
    );
}

#[test]
fn seed_census_retains_failed_clones_spare_capacity_and_original_file() {
    let text = |capacity, value: &str| {
        let mut text = String::with_capacity(capacity);
        text.push_str(value);
        text
    };
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.host = Some(ContentRef {
        hash: HashRef {
            algorithm: text(41, "blake3-256"),
            domain: text(53, "retained-seed-data"),
            digest: text(79, "not-a-private-birth-grant"),
        },
        length: U64::new(0),
        media_type: text(97, "application/octet-stream"),
    });
    seed.private_launch = Some(Id::new(text(149, "retained-seed-launch")).unwrap());
    seed.file = Some(File::open("/proc/self/exe").unwrap());
    seed.revision = Some(private_identity::read_revision(seed.file.as_ref().unwrap()).unwrap());
    seed.key = [7; 32];
    seed.birth_id = Some([9; 32]);
    seed.started = true;
    seed.failure = Some(RuntimeError::SchedulerRefused(text(
        131,
        "original failed prefix",
    )));
    let descriptor = seed.file.as_ref().unwrap().as_raw_fd();
    let original_media = seed.host.as_ref().unwrap().media_type.as_ptr();
    let expected_bytes = 41 + 53 + 79 + 97 + 149 + 131;
    let mut census = OriginalOwnerCapacityMetadataData::new(6, None);

    seed.record_retained_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 6);
    assert_eq!(facts.string_banks, 6);
    assert_eq!(facts.string_capacity_bytes, expected_bytes);
    assert_eq!(facts.vector_banks, 0);
    assert_eq!(facts.shared_backing_views, 0);
    assert_eq!(facts.boxed_value_bytes, 0);
    assert!(facts.observed_nodes > facts.capacity_records);
    assert_eq!(seed.known_backing(), Ok(expected_bytes));
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts,
            expected_bytes - 1,
        ),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), descriptor);
    assert_eq!(
        seed.host.as_ref().unwrap().media_type.as_ptr(),
        original_media
    );
    assert!(seed.started && !seed.complete && seed.failure.is_some());
    assert_eq!(seed.key, [7; 32]);
    assert_eq!(seed.birth_id, Some([9; 32]));

    let mut short = OriginalOwnerCapacityMetadataData::new(5, None);
    assert_eq!(
        seed.record_retained_capacity_data(&mut short),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(short.finish().capacity_records, 5);
    assert_eq!(seed.known_backing(), Ok(expected_bytes));
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), descriptor);
}

#[test]
fn empty_seed_census_counts_fixed_work_and_foreign_creator_refuses_before_rows() {
    let mut seed = OriginalImport18PrivateSeed::empty();
    let mut census = OriginalOwnerCapacityMetadataData::new(0, None);

    seed.record_retained_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 0);
    assert_eq!(facts.observed_nodes, 11);
    assert_eq!(seed.known_backing(), Ok(0));
    assert!(!seed.started && !seed.complete);
    assert_eq!(seed.key, [0; 32]);

    seed.process = seed.process.wrapping_add(1);
    let mut foreign = OriginalOwnerCapacityMetadataData::new(0, None);
    assert_eq!(
        seed.record_retained_capacity_data(&mut foreign),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(foreign.finish(), Default::default());
    assert_eq!(seed.known_backing(), Err(RuntimeError::ForeignAuthority));
    assert!(!seed.started && !seed.complete && seed.failure.is_none());
}
