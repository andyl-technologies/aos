use super::*;
use std::io;
use std::os::fd::AsRawFd;

#[test]
fn mapped_blob_pack_reads_frozen_empty_payload_fixture() {
    let path = temp_path("frozen-empty");
    {
        let mut file = fs::File::create(&path).expect("fixture file creates");
        file.write_all(&FROZEN_EMPTY_BLOB_PACK)
            .expect("fixture bytes write");
        file.sync_all().expect("fixture file syncs");
    }
    let pack = map_pack(&path);
    let payload = pack
        .payload(
            BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, 0),
            BlobPackHash::for_bytes(b""),
        )
        .expect("frozen empty fixture payload reads");

    assert_eq!(pack.len(), FROZEN_EMPTY_BLOB_PACK.len());
    assert_eq!(payload.as_bytes(), b"");

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_with_read_lease_returns_payload_slices() {
    let path = temp_path("leased-payloads");
    let payload = b"leased payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let file = fs::File::open(&path).expect("pack opens read-only");
    let lease = FrozenTestLease;
    let pack = MappedBlobPack::map_file_with_lease(&file, &lease).expect("lease maps blob pack");
    let mapped_payload = pack
        .payload(locations[0], BlobPackHash::for_bytes(payload))
        .expect("leased payload reads");

    assert_eq!(pack.len(), pack.as_mapped_pack().len());
    assert_eq!(
        pack.payload_window(locations[0], BlobPackHash::for_bytes(payload))
            .expect("leased payload window validates")
            .payload_range(),
        (locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64)
            ..(locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64 + payload.len() as u64)
    );
    assert_eq!(
        pack.records().expect("leased records scan"),
        [BlobPackRecord::new(
            BlobPackHash::for_bytes(payload),
            locations[0]
        )]
    );
    assert_eq!(mapped_payload.as_bytes(), payload);

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_with_read_lease_rejects_uncovered_files() {
    let path = temp_path("rejected-lease");
    write_pack(&path, &[b"payload"]);
    let file = fs::File::open(&path).expect("pack opens read-only");
    let lease = RejectingTestLease;

    let error =
        MappedBlobPack::map_file_with_lease(&file, &lease).expect_err("uncovered file is rejected");

    assert!(matches!(error, MappedBlobPackError::LeaseRejected));
    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_file_read_lease_maps_matching_file() {
    let path = temp_path("file-lease-matching");
    let payload = b"advisory payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let file = fs::File::open(&path).expect("pack opens read-only");
    let lease = BlobPackFileReadLease::new(&file).expect("file read lease snapshots");
    let pack =
        MappedBlobPack::map_file_with_lease(&file, &lease).expect("lease maps matching file");

    let mapped_payload = pack
        .payload(locations[0], BlobPackHash::for_bytes(payload))
        .expect("payload reads through file lease");

    assert_eq!(mapped_payload.as_bytes(), payload);

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_file_read_lease_rejects_different_file() {
    let left_path = temp_path("file-lease-left");
    let right_path = temp_path("file-lease-right");
    write_pack(&left_path, &[b"left"]);
    write_pack(&right_path, &[b"right"]);
    let left = fs::File::open(&left_path).expect("left pack opens");
    let right = fs::File::open(&right_path).expect("right pack opens");
    let lease = BlobPackFileReadLease::new(&left).expect("left lease snapshots");

    let error = MappedBlobPack::map_file_with_lease(&right, &lease)
        .expect_err("lease rejects a different file identity");

    assert!(matches!(error, MappedBlobPackError::LeaseRejected));

    let _ = fs::remove_file(left_path);
    let _ = fs::remove_file(right_path);
}

#[test]
fn blob_pack_file_read_lease_holds_shared_pack_lock() {
    let path = temp_path("file-lease-lock");
    write_pack(&path, &[b"locked"]);
    let file = fs::File::open(&path).expect("pack opens read-only");
    let lease = BlobPackFileReadLease::new(&file).expect("file read lease snapshots");

    let error = try_exclusive_pack_lock(&path).expect_err("read lease blocks exclusive lock");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    drop(lease);
    let exclusive = try_exclusive_pack_lock(&path).expect("exclusive lock acquires after lease");
    drop(exclusive);
    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_file_identity_matches_reopened_same_file() {
    let path = temp_path("identity-same");
    write_pack(&path, &[b"payload"]);
    let file = fs::File::open(&path).expect("pack opens read-only");
    let identity = BlobPackFileIdentity::for_file(&file).expect("identity snapshots");
    let reopened = fs::File::open(&path).expect("pack reopens read-only");

    assert!(
        identity
            .matches_file(&reopened)
            .expect("same file metadata reads")
    );
    assert!(!identity.is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_file_identity_rejects_different_file() {
    let left_path = temp_path("identity-left");
    let right_path = temp_path("identity-right");
    write_pack(&left_path, &[b"left"]);
    write_pack(&right_path, &[b"right"]);
    let left = fs::File::open(&left_path).expect("left pack opens read-only");
    let right = fs::File::open(&right_path).expect("right pack opens read-only");
    let identity = BlobPackFileIdentity::for_file(&left).expect("left identity snapshots");

    assert!(
        !identity
            .matches_file(&right)
            .expect("right file metadata reads")
    );

    let _ = fs::remove_file(left_path);
    let _ = fs::remove_file(right_path);
}

#[test]
fn blob_pack_file_identity_rejects_changed_length() {
    let path = temp_path("identity-changed-length");
    write_pack(&path, &[b"payload"]);
    let file = fs::File::open(&path).expect("pack opens read-only");
    let identity = BlobPackFileIdentity::for_file(&file).expect("identity snapshots");
    {
        let mut append = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("pack opens for append");
        append.write_all(b"tail").expect("tail writes");
        append.sync_all().expect("appended pack syncs");
    }

    assert!(
        !identity
            .matches_file(&file)
            .expect("changed file metadata reads")
    );
    assert_eq!(
        identity.len() + 4,
        file.metadata().expect("metadata reads").len()
    );

    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_returns_verified_payload_slices() {
    let path = temp_path("payloads");
    let first = b"first payload".as_slice();
    let second = b"second payload".as_slice();
    let locations = write_pack(&path, &[first, second]);
    let pack = map_pack(&path);

    let first_payload = pack
        .payload(locations[0], BlobPackHash::for_bytes(first))
        .expect("first payload maps");
    let second_payload = pack
        .payload(locations[1], BlobPackHash::for_bytes(second))
        .expect("second payload maps");

    assert_eq!(
        pack.len(),
        BLOB_PACK_HEADER_LEN + 2 * BLOB_RECORD_HEADER_LEN + 27
    );
    assert_eq!(first_payload.hash(), BlobPackHash::for_bytes(first));
    assert_eq!(first_payload.location(), locations[0]);
    assert_eq!(first_payload.as_bytes(), first);
    assert_eq!(second_payload.as_bytes(), second);

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_scans_verified_records() {
    let path = temp_path("record-scan");
    let first = b"first payload".as_slice();
    let second = b"second payload".as_slice();
    let locations = write_pack(&path, &[first, second]);
    let pack = map_pack(&path);

    let records = pack.records().expect("records scan");

    assert_eq!(
        records,
        [
            BlobPackRecord::new(BlobPackHash::for_bytes(first), locations[0]),
            BlobPackRecord::new(BlobPackHash::for_bytes(second), locations[1]),
        ]
    );
    assert_eq!(records[0].hash(), BlobPackHash::for_bytes(first));
    assert_eq!(records[1].location(), locations[1]);

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_records_returns_empty_for_header_only_pack() {
    let path = temp_path("record-scan-empty");
    BlobPackAppender::open(path.clone()).expect("header-only pack initializes");
    let pack = map_pack(&path);

    assert!(pack.records().expect("empty records scan").is_empty());

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_returns_metadata_payload_window_without_hashing_payload() {
    let path = temp_path("payload-window-no-hash");
    let declared = BlobPackHash::for_bytes(b"declared");
    let actual = b"actual!!".as_slice();
    let location = BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, actual.len() as u64);
    let payload_start = location.record_offset() + BLOB_RECORD_HEADER_LEN as u64;
    let payload_end = payload_start + actual.len() as u64;
    {
        let mut file = fs::File::create(&path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        file.write_all(&BlobRecordHeader::new(declared, actual.len() as u64).encode())
            .expect("record header writes");
        file.write_all(actual).expect("payload writes");
        file.sync_all().expect("pack file syncs");
    }
    let pack = map_pack(&path);

    let window = pack
        .payload_window(location, declared)
        .expect("metadata payload window validates");

    assert_eq!(window.record(), BlobPackRecord::new(declared, location));
    assert_eq!(window.hash(), declared);
    assert_eq!(window.location(), location);
    assert_eq!(window.payload_start(), payload_start);
    assert_eq!(window.payload_end(), payload_end);
    assert_eq!(window.payload_len(), actual.len() as u64);
    assert_eq!(window.payload_range(), payload_start..payload_end);
    let error = pack
        .payload(location, declared)
        .expect_err("payload hash mismatch still fails full payload read");
    assert!(matches!(
        error,
        MappedBlobPackError::PayloadHashMismatch { expected, actual: observed }
            if expected == declared && observed == BlobPackHash::for_bytes(actual)
    ));

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_rejects_wrong_lookup_hash() {
    let path = temp_path("wrong-hash");
    let payload = b"payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let pack = map_pack(&path);
    let other = BlobPackHash::for_bytes(b"other");

    let error = pack
        .payload(locations[0], other)
        .expect_err("wrong lookup hash fails");

    assert!(matches!(
        error,
        MappedBlobPackError::RecordHashMismatch { expected, actual }
            if expected == other && actual == BlobPackHash::for_bytes(payload)
    ));
    let error = pack
        .payload_window(locations[0], other)
        .expect_err("wrong lookup hash fails metadata window");

    assert!(matches!(
        error,
        MappedBlobPackError::RecordHashMismatch { expected, actual }
            if expected == other && actual == BlobPackHash::for_bytes(payload)
    ));

    let error = pack
        .payload_window(
            BlobPackLocation::new(locations[0].record_offset(), payload.len() as u64 + 1),
            BlobPackHash::for_bytes(payload),
        )
        .expect_err("wrong lookup length fails metadata window");

    assert!(matches!(
        error,
        MappedBlobPackError::RecordLengthMismatch { expected, actual }
            if expected == payload.len() as u64 + 1 && actual == payload.len() as u64
    ));

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_rejects_payload_hash_mismatch() {
    let path = temp_path("payload-mismatch");
    let declared = BlobPackHash::for_bytes(b"declared");
    let actual = b"actual!!".as_slice();
    let location = BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, actual.len() as u64);
    {
        let mut file = fs::File::create(&path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        file.write_all(&BlobRecordHeader::new(declared, actual.len() as u64).encode())
            .expect("record header writes");
        file.write_all(actual).expect("payload writes");
        file.sync_all().expect("pack file syncs");
    }
    let pack = map_pack(&path);

    let error = pack
        .payload(location, declared)
        .expect_err("payload hash mismatch fails");

    assert!(matches!(
        error,
        MappedBlobPackError::PayloadHashMismatch { expected, actual: observed }
            if expected == declared && observed == BlobPackHash::for_bytes(actual)
    ));

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_records_rejects_payload_hash_mismatch() {
    let path = temp_path("record-scan-payload-mismatch");
    let declared = BlobPackHash::for_bytes(b"declared");
    let actual = b"actual!!".as_slice();
    {
        let mut file = fs::File::create(&path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        file.write_all(&BlobRecordHeader::new(declared, actual.len() as u64).encode())
            .expect("record header writes");
        file.write_all(actual).expect("payload writes");
        file.sync_all().expect("pack file syncs");
    }
    let pack = map_pack(&path);

    let error = pack.records().expect_err("payload hash mismatch fails");

    assert!(matches!(
        error,
        MappedBlobPackError::PayloadHashMismatch { expected, actual: observed }
            if expected == declared && observed == BlobPackHash::for_bytes(actual)
    ));

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_rejects_truncated_payload_window() {
    let path = temp_path("truncated");
    let hash = BlobPackHash::for_bytes(b"too short");
    let location = BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, 9);
    {
        let mut file = fs::File::create(&path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        file.write_all(&BlobRecordHeader::new(hash, 9).encode())
            .expect("record header writes");
        file.write_all(b"short").expect("payload writes");
        file.sync_all().expect("pack file syncs");
    }
    let pack = map_pack(&path);

    let error = pack
        .payload(location, hash)
        .expect_err("truncated payload fails");

    assert!(matches!(
        error,
        MappedBlobPackError::RecordExtendsPastEnd { .. }
    ));
    let error = pack
        .payload_window(location, hash)
        .expect_err("truncated payload window fails");

    assert!(matches!(
        error,
        MappedBlobPackError::RecordExtendsPastEnd { .. }
    ));

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn mapped_blob_pack_records_rejects_truncated_record_tail() {
    let path = temp_path("record-scan-truncated-tail");
    {
        let mut file = fs::File::create(&path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        file.write_all(b"bad").expect("truncated tail writes");
        file.sync_all().expect("pack file syncs");
    }
    let pack = map_pack(&path);

    let error = pack.records().expect_err("truncated record tail fails");

    assert!(matches!(
        error,
        MappedBlobPackError::Format(BlobPackFormatError::ShortRecordHeader { actual: 3, .. })
    ));

    drop(pack);
    let _ = fs::remove_file(path);
}

fn try_exclusive_pack_lock(path: &PathBuf) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let result = unsafe {
        // SAFETY: `file` owns a live descriptor for this call, and `flock`
        // does not outlive or alias Rust references.
        libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
    };
    if result == 0 {
        return Ok(file);
    }
    Err(io::Error::last_os_error())
}
