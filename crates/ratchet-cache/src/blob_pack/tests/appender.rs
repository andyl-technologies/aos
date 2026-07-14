use super::*;

#[test]
fn blob_pack_appender_open_initializes_header() {
    let root = temp_path("appender-open-root");
    let path = root.join("values").join("pack.blob");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");

    assert_eq!(appender.path(), path.as_path());
    assert_eq!(
        fs::read(&path).expect("pack header reads").as_slice(),
        BlobPackHeader::current().encode().as_slice()
    );
    assert_eq!(
        appender.len().expect("pack length reads"),
        BLOB_PACK_HEADER_LEN as u64
    );
    assert!(!appender.is_empty().expect("pack emptiness reads"));
    BlobPackAppender::open(path.clone()).expect("initialized appender reopens");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn blob_pack_appender_rejects_corrupt_header_without_rewriting() {
    let root = temp_path("appender-corrupt-root");
    let path = root.join("values").join("pack.blob");
    fs::create_dir_all(path.parent().expect("pack parent exists")).expect("parent creates");
    fs::write(&path, b"bad").expect("corrupt pack writes");

    let error = BlobPackAppender::open(path.clone()).expect_err("corrupt pack errors");

    assert!(matches!(
        error,
        BlobPackAppendError::Format {
            source: BlobPackFormatError::ShortPackHeader { actual: 3, .. },
            ..
        }
    ));
    assert_eq!(
        fs::read(&path).expect("corrupt pack reads").as_slice(),
        b"bad"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn blob_pack_appender_appends_mapped_payloads() {
    let path = temp_path("appender-payloads");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
    let first = b"first payload".as_slice();
    let second = b"second payload".as_slice();
    let first_hash = BlobPackHash::for_bytes(first);
    let second_hash = BlobPackHash::for_bytes(second);

    let first_location = appender
        .append_payload(first_hash, first)
        .expect("first payload appends");
    let second_location = appender
        .append_payload(second_hash, second)
        .expect("second payload appends");

    assert_eq!(first_location.record_offset(), BLOB_PACK_HEADER_LEN as u64);
    assert_eq!(first_location.payload_len(), first.len() as u64);
    assert_eq!(
        second_location.record_offset(),
        BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + first.len() as u64
    );
    assert_eq!(second_location.payload_len(), second.len() as u64);

    let pack = map_pack(&path);
    assert_eq!(
        pack.payload(first_location, first_hash)
            .expect("first mapped payload reads")
            .as_bytes(),
        first
    );
    assert_eq!(
        pack.payload(second_location, second_hash)
            .expect("second mapped payload reads")
            .as_bytes(),
        second
    );

    drop(pack);
    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_appender_rejects_payload_hash_mismatch_without_appending() {
    let path = temp_path("appender-hash-mismatch");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
    let payload = b"payload".as_slice();
    let wrong_hash = BlobPackHash::for_bytes(b"wrong");
    let before_len = appender.len().expect("initial pack length reads");

    let error = appender
        .append_payload(wrong_hash, payload)
        .expect_err("hash mismatch errors");

    assert!(matches!(
        error,
        BlobPackAppendError::PayloadHashMismatch { expected, actual }
            if expected == wrong_hash && actual == BlobPackHash::for_bytes(payload)
    ));
    assert_eq!(appender.len().expect("final pack length reads"), before_len);

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_appender_trusted_batch_matches_verified_batch() {
    let first = b"first payload".as_slice();
    let second = b"second payload".as_slice();
    let records = [
        (BlobPackHash::for_bytes(first), first),
        (BlobPackHash::for_bytes(second), second),
    ];

    let verified_path = temp_path("appender-trusted-verified");
    let verified = BlobPackAppender::open(verified_path.clone()).expect("verified appender opens");
    let verified_locations = verified
        .append_payloads_batch(&records)
        .expect("verified batch appends");

    let trusted_path = temp_path("appender-trusted-batch");
    let trusted = BlobPackAppender::open(trusted_path.clone()).expect("trusted appender opens");
    let trusted_locations = trusted
        .append_payloads_batch_trusted(&records)
        .expect("trusted batch appends");

    // The trusted path skips only the pre-write hash verification; the on-disk
    // record bytes and returned locations must be identical to the verified path.
    assert_eq!(verified_locations, trusted_locations);
    assert_eq!(
        fs::read(&verified_path).expect("verified pack reads"),
        fs::read(&trusted_path).expect("trusted pack reads"),
    );

    let reader = BlobPackReader::open(trusted_path.clone()).expect("reader opens trusted pack");
    assert_eq!(
        reader.records().expect("trusted records scan"),
        [
            BlobPackRecord::new(records[0].0, trusted_locations[0]),
            BlobPackRecord::new(records[1].0, trusted_locations[1]),
        ]
    );

    let _ = fs::remove_file(verified_path);
    let _ = fs::remove_file(trusted_path);
}

#[test]
fn blob_pack_appender_trim_tail_removes_unneeded_records() {
    let path = temp_path("appender-trim-tail");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
    let first = b"first payload".as_slice();
    let second = b"second payload".as_slice();
    let first_hash = BlobPackHash::for_bytes(first);
    let second_hash = BlobPackHash::for_bytes(second);
    let first_location = appender
        .append_payload(first_hash, first)
        .expect("first payload appends");
    let second_location = appender
        .append_payload(second_hash, second)
        .expect("second payload appends");
    let before_len = appender.len().expect("pack length reads");

    let removed = appender
        .trim_tail(second_location.record_offset())
        .expect("tail trims");

    assert_eq!(removed, before_len - second_location.record_offset());
    assert_eq!(
        appender.len().expect("trimmed pack length reads"),
        second_location.record_offset()
    );
    let reader = BlobPackReader::open(path.clone()).expect("reader opens trimmed pack");
    assert_eq!(
        reader.records().expect("trimmed records scan"),
        [BlobPackRecord::new(first_hash, first_location)]
    );
    assert_eq!(
        reader
            .read_payload(first_location, first_hash)
            .expect("retained payload reads"),
        first
    );

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_appender_trim_tail_noops_at_current_len() {
    let path = temp_path("appender-trim-tail-noop");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
    let payload = b"payload".as_slice();
    appender
        .append_payload(BlobPackHash::for_bytes(payload), payload)
        .expect("payload appends");
    let len = appender.len().expect("pack length reads");

    let removed = appender.trim_tail(len).expect("current len trim noops");

    assert_eq!(removed, 0);
    assert_eq!(appender.len().expect("final pack length reads"), len);

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_appender_trim_tail_rejects_offset_before_header() {
    let path = temp_path("appender-trim-tail-before-header");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");

    let error = appender
        .trim_tail(BLOB_PACK_HEADER_LEN as u64 - 1)
        .expect_err("offset before header errors");

    assert!(matches!(
        error,
        BlobPackTrimError::InvalidRecordOffset { record_offset }
            if record_offset == BLOB_PACK_HEADER_LEN as u64 - 1
    ));
    assert_eq!(
        appender.len().expect("final pack length reads"),
        BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_appender_trim_tail_rejects_offset_past_end() {
    let path = temp_path("appender-trim-tail-past-end");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
    let len = appender.len().expect("pack length reads");

    let error = appender
        .trim_tail(len + 1)
        .expect_err("offset past end errors");

    assert!(matches!(
        error,
        BlobPackTrimError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        } if payload_end == len + 1 && pack_len == len
    ));
    assert_eq!(appender.len().expect("final pack length reads"), len);

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_appender_trim_tail_rejects_corrupt_header_without_rewriting() {
    let path = temp_path("appender-trim-tail-corrupt-header");
    let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
    fs::write(&path, b"bad").expect("corrupt pack writes");

    let error = appender
        .trim_tail(BLOB_PACK_HEADER_LEN as u64)
        .expect_err("corrupt header errors");

    assert!(matches!(
        error,
        BlobPackTrimError::Format {
            source: BlobPackFormatError::ShortPackHeader { actual: 3, .. },
            ..
        }
    ));
    assert_eq!(
        fs::read(&path).expect("corrupt pack reads").as_slice(),
        b"bad"
    );

    let _ = fs::remove_file(path);
}
