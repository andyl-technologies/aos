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

#[test]
fn truncated_admitted_spool_retains_io_without_acknowledging_a_page() {
    let (root, bytes) = fixture();
    let first = HEADER_BYTES + root.encoded_len();

    for length in [first + 1, first + PAGE_HEADER_BYTES + 1] {
        let mut capture =
            admit(&bytes).unwrap_or_else(|error| panic!("valid capture fixture: {error}"));
        let remaining = (capture.remaining_records, capture.remaining_bytes);
        capture
            .file
            .set_len(length as u64)
            .unwrap_or_else(|error| panic!("truncate admitted spool: {error}"));

        let error = capture
            .next_page()
            .err()
            .unwrap_or_else(|| panic!("expected original typed failure"));
        let CaptureReadError::Io(source) = error else {
            panic!("truncation must retain the original IO error");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(
            (capture.remaining_records, capture.remaining_bytes),
            remaining
        );
        assert_eq!(capture.previous, None);
    }
}

#[test]
fn admitted_reader_retains_actual_descriptor_errno() {
    let (_, bytes) = fixture();
    let mut spool = tempfile::NamedTempFile::new()
        .unwrap_or_else(|error| panic!("create capture spool: {error}"));
    spool
        .write_all(&bytes)
        .unwrap_or_else(|error| panic!("write capture spool: {error}"));
    let file = spool
        .reopen()
        .unwrap_or_else(|error| panic!("open readable capture spool: {error}"));
    let mut capture = QemuPagedRamCapture::admit(file, bytes.len() as u64)
        .unwrap_or_else(|error| panic!("admit capture spool: {error}"));
    capture.file = std::fs::OpenOptions::new()
        .write(true)
        .open(spool.path())
        .unwrap_or_else(|error| panic!("open deliberately unreadable capture spool: {error}"));

    let error = capture
        .next_page()
        .err()
        .unwrap_or_else(|| panic!("expected original typed failure"));
    let CaptureReadError::Io(source) = error else {
        panic!("descriptor failure must retain the original IO error");
    };
    assert_eq!(source.raw_os_error(), Some(libc::EBADF));
    assert_eq!(capture.remaining_records, 2);
    assert_eq!(capture.previous, None);
}

#[test]
fn logical_coordinate_validation_keeps_its_typed_cause() {
    let (root, mut bytes) = fixture();
    let first = HEADER_BYTES + root.encoded_len();
    bytes[first + 8..first + 16].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut capture =
        admit(&bytes).unwrap_or_else(|error| panic!("valid capture fixture: {error}"));

    assert!(matches!(
        capture.next_page(),
        Err(CaptureReadError::Validation(
            crucible_ram::RamError::OutOfRange
        ))
    ));
    assert_eq!(capture.remaining_records, 2);
    assert_eq!(capture.previous, None);
    eprintln!(
        "owned capture read error={} align={}",
        std::mem::size_of::<CaptureReadError>(),
        std::mem::align_of::<CaptureReadError>()
    );
}

#[test]
fn original_paid_capture_reads_pages_without_entering_another_operation() {
    let (mut owner, original, supervisor, _event, account) =
        super::super::capture_original::loan_fixture();
    let (_, bytes) = fixture();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    let mut capture =
        QemuPagedRamCapture::admit_under_original(file, bytes.len() as u64, original).unwrap();

    assert_eq!(capture.next_page().unwrap().unwrap().bytes.len(), 4096);
    assert_eq!(capture.next_page().unwrap().unwrap().bytes.len(), 3);
    assert!(capture.next_page().unwrap().is_none());
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);

    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 2, 16384).is_err());
    drop(capture);
    assert!(account.reserve_resources(0, 2, 16384).is_ok());
}

#[test]
fn retained_page_reader_refuses_cancellation_before_advancing_the_real_file() {
    let (_owner, original, supervisor, event, _account) =
        super::super::capture_original::loan_fixture();
    let (_, bytes) = fixture();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    let mut capture =
        QemuPagedRamCapture::admit_under_original(file, bytes.len() as u64, original).unwrap();
    let offset = capture.file.stream_position().unwrap();
    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();

    let error = capture.next_page().unwrap_err();

    let CaptureReadError::Io(error) = error else {
        panic!("expected typed original refusal");
    };
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<crucible_host_resources::host_supervision::HostSupervisionError>()
            .is_some()
    );
    assert_eq!(capture.file.stream_position().unwrap(), offset);
    assert_eq!(capture.remaining_records, 2);
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn canceled_original_refuses_before_spool_metadata_or_root_decode() {
    let (_owner, original, supervisor, event, _account) =
        super::super::capture_original::loan_fixture();
    let file = tempfile::tempfile().unwrap();
    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();

    let error = QemuPagedRamCapture::admit_under_original(file, 0, original).unwrap_err();

    assert!(matches!(error, QemuNodeError::CheckpointOriginal { .. }));
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn device_publication_reader_checks_same_original_on_read_seek_and_metadata() {
    let (_owner, original, supervisor, _event, _account) =
        super::super::capture_original::loan_fixture();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"device").unwrap();
    let mut reader = super::super::QemuCheckpointDeviceReader {
        file: &mut file,
        original,
    };

    reader.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(reader.metadata().unwrap().len(), 6);
    let mut bytes = [0; 6];
    reader.read_exact(&mut bytes).unwrap();

    assert_eq!(&bytes, b"device");
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn canceled_device_original_refuses_read_and_seek_without_moving_file_cursor() {
    let (_owner, original, supervisor, event, _account) =
        super::super::capture_original::loan_fixture();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"device").unwrap();
    file.seek(SeekFrom::Start(2)).unwrap();
    let mut reader = super::super::QemuCheckpointDeviceReader {
        file: &mut file,
        original,
    };
    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();
    let mut bytes = [0; 1];

    assert!(reader.read(&mut bytes).is_err());
    assert!(reader.seek(SeekFrom::Start(0)).is_err());
    assert!(reader.metadata().is_err());
    drop(reader);

    assert_eq!(file.stream_position().unwrap(), 2);
    assert_eq!(bytes, [0]);
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}
