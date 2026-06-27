use super::*;

#[test]
fn blob_pack_reader_reads_and_verifies_buffered_payloads() {
    let path = temp_path("reader-payloads");
    let first = b"first payload".as_slice();
    let second = b"second payload".as_slice();
    let locations = write_pack(&path, &[first, second]);
    let first_hash = BlobPackHash::for_bytes(first);
    let second_hash = BlobPackHash::for_bytes(second);
    let reader = BlobPackReader::open(path.clone()).expect("reader opens");

    assert_eq!(reader.path(), path.as_path());
    assert_eq!(
        reader.len().expect("reader length reads"),
        BLOB_PACK_HEADER_LEN as u64
            + (BLOB_RECORD_HEADER_LEN as u64 * 2)
            + first.len() as u64
            + second.len() as u64
    );
    assert!(!reader.is_empty().expect("reader emptiness reads"));
    assert_eq!(
        reader.records().expect("records scan"),
        [
            BlobPackRecord::new(first_hash, locations[0]),
            BlobPackRecord::new(second_hash, locations[1]),
        ]
    );

    let window = reader
        .payload_window(locations[0], first_hash)
        .expect("payload window reads");
    assert_eq!(
        window.record(),
        BlobPackRecord::new(first_hash, locations[0])
    );
    assert_eq!(
        window.payload_range(),
        locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64
            ..locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64 + first.len() as u64
    );
    assert_eq!(
        reader
            .verify_payload(locations[0], first_hash)
            .expect("payload verifies"),
        window
    );
    assert!(
        reader
            .payload_matches(locations[0], first_hash, first)
            .expect("payload match reads")
    );
    assert!(
        !reader
            .payload_matches(locations[0], first_hash, b"first payloae")
            .expect("payload mismatch reads")
    );
    assert!(
        !reader
            .payload_matches(locations[0], first_hash, b"short")
            .expect("payload length mismatch reads")
    );
    assert_eq!(
        reader
            .read_payload(locations[1], second_hash)
            .expect("payload reads"),
        second
    );

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_writes_relocated_records_to_temp_pack() {
    let path = temp_path("reader-relocated-source");
    let tmp_path = temp_path("reader-relocated-temp");
    let first = b"first payload".as_slice();
    let stale = b"stale payload".as_slice();
    let second = b"second payload".as_slice();
    let locations = write_pack(&path, &[first, stale, second]);
    fs::write(&tmp_path, b"stale temp").expect("stale temp writes");
    let first_hash = BlobPackHash::for_bytes(first);
    let stale_hash = BlobPackHash::for_bytes(stale);
    let second_hash = BlobPackHash::for_bytes(second);
    let relocated_first = BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, first.len() as u64);
    let relocated_second = BlobPackLocation::new(
        BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + first.len() as u64,
        second.len() as u64,
    );
    let relocations = [
        BlobPackRecordRelocation::new(first_hash, locations[0], relocated_first),
        BlobPackRecordRelocation::new(second_hash, locations[2], relocated_second),
    ];
    let reader = BlobPackReader::open(path.clone()).expect("reader opens");

    let rewritten = reader
        .write_relocated_records_to(tmp_path.clone(), &relocations)
        .expect("records relocate");

    assert_eq!(rewritten.path(), tmp_path.as_path());
    assert_eq!(
        rewritten.records().expect("rewritten records scan"),
        [
            BlobPackRecord::new(first_hash, relocated_first),
            BlobPackRecord::new(second_hash, relocated_second),
        ]
    );
    assert_eq!(
        rewritten
            .read_payload(relocated_first, first_hash)
            .expect("relocated first reads"),
        first
    );
    assert_eq!(
        rewritten
            .read_payload(relocated_second, second_hash)
            .expect("relocated second reads"),
        second
    );
    assert_eq!(
        reader
            .read_payload(locations[1], stale_hash)
            .expect("source stale record remains"),
        stale
    );

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(tmp_path);
}

#[test]
fn blob_pack_reader_relocation_rejects_source_as_temp_path() {
    let path = temp_path("reader-relocation-source-as-temp");
    let payload = b"payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let hash = BlobPackHash::for_bytes(payload);
    let relocation = BlobPackRecordRelocation::new(
        hash,
        locations[0],
        BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, payload.len() as u64),
    );
    let reader = BlobPackReader::open(path.clone()).expect("reader opens");

    let error = reader
        .write_relocated_records_to(path.clone(), &[relocation])
        .expect_err("source path as temp errors");

    assert!(matches!(
        error,
        BlobPackRewriteError::SourceEqualsTemp { source_path, tmp_path }
            if source_path == path && tmp_path == path
    ));
    assert_eq!(
        reader
            .read_payload(locations[0], hash)
            .expect("source remains readable after exact rejection"),
        payload
    );

    let alias_path = path
        .parent()
        .expect("pack parent exists")
        .join(".")
        .join(path.file_name().expect("pack file name exists"));
    let error = reader
        .write_relocated_records_to(alias_path.clone(), &[relocation])
        .expect_err("source alias as temp errors");
    assert!(matches!(
        error,
        BlobPackRewriteError::SourceEqualsTemp { source_path, tmp_path }
            if source_path == path && tmp_path == alias_path
    ));
    assert_eq!(
        reader
            .read_payload(locations[0], hash)
            .expect("source remains readable after alias rejection"),
        payload
    );

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_relocation_cleans_temp_on_location_mismatch() {
    let path = temp_path("reader-relocation-mismatch-source");
    let tmp_path = temp_path("reader-relocation-mismatch-temp");
    let payload = b"payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let hash = BlobPackHash::for_bytes(payload);
    let wrong_location =
        BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64 + 1, payload.len() as u64);
    let relocations = [BlobPackRecordRelocation::new(
        hash,
        locations[0],
        wrong_location,
    )];
    let reader = BlobPackReader::open(path.clone()).expect("reader opens");

    let error = reader
        .write_relocated_records_to(tmp_path.clone(), &relocations)
        .expect_err("mismatched location errors");

    assert!(matches!(
        error,
        BlobPackRewriteError::RecordLocationMismatch { expected, actual }
            if expected == wrong_location
                && actual == BlobPackLocation::new(
                    BLOB_PACK_HEADER_LEN as u64,
                    payload.len() as u64
                )
    ));
    assert!(!tmp_path.exists());

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_relocation_cleans_temp_on_corrupt_source() {
    let path = temp_path("reader-relocation-corrupt-source");
    let tmp_path = temp_path("reader-relocation-corrupt-temp");
    let payload = b"payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let hash = BlobPackHash::for_bytes(payload);
    let payload_offset = locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("source opens for corruption");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");
    let relocation = BlobPackRecordRelocation::new(
        hash,
        locations[0],
        BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, payload.len() as u64),
    );
    let reader = BlobPackReader::open(path.clone()).expect("reader opens");

    let error = reader
        .write_relocated_records_to(tmp_path.clone(), &[relocation])
        .expect_err("corrupt source errors");

    assert!(matches!(
        error,
        BlobPackRewriteError::ReadSource {
            source: BlobPackReadError::PayloadHashMismatch { .. }
        }
    ));
    assert!(!tmp_path.exists());

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_rejects_corrupt_header_without_rewriting() {
    let path = temp_path("reader-corrupt-header");
    fs::write(&path, b"bad").expect("corrupt pack writes");

    let error = BlobPackReader::open(path.clone()).expect_err("corrupt pack errors");

    assert!(matches!(
        error,
        BlobPackReadError::Format {
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

#[test]
fn blob_pack_reader_rejects_mismatched_lookup_metadata() {
    let path = temp_path("reader-mismatch");
    let payload = b"payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let reader = BlobPackReader::open(path.clone()).expect("reader opens");
    let hash = BlobPackHash::for_bytes(payload);
    let wrong_hash = BlobPackHash::for_bytes(b"other");

    assert!(matches!(
        reader
            .payload_window(locations[0], wrong_hash)
            .expect_err("wrong hash errors"),
        BlobPackReadError::RecordHashMismatch { expected, actual }
            if expected == wrong_hash && actual == hash
    ));
    assert!(matches!(
        reader
            .payload_window(BlobPackLocation::new(
                locations[0].record_offset(),
                locations[0].payload_len() + 1
            ), hash)
            .expect_err("wrong length errors"),
        BlobPackReadError::RecordLengthMismatch { expected, actual }
            if expected == locations[0].payload_len() + 1 && actual == locations[0].payload_len()
    ));
    assert!(matches!(
        reader
            .read_payload(BlobPackLocation::new(0, locations[0].payload_len()), hash)
            .expect_err("header offset errors"),
        BlobPackReadError::InvalidRecordOffset { record_offset: 0 }
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_rejects_short_trailing_record_header() {
    let path = temp_path("reader-short-tail");
    write_pack(&path, &[b"payload"]);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("pack opens for corruption");
    file.write_all(b"tail").expect("tail writes");
    file.flush().expect("tail flushes");
    let reader = BlobPackReader::open(path.clone()).expect("reader opens by header");

    let error = reader.records().expect_err("short tail errors");

    assert!(matches!(
        error,
        BlobPackReadError::Format {
            source: BlobPackFormatError::ShortRecordHeader { actual: 4, .. },
            ..
        }
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_rejects_record_payload_past_end() {
    let path = temp_path("reader-past-end");
    let hash = BlobPackHash::for_bytes(b"payload");
    let mut file = fs::File::create(&path).expect("pack file creates");
    file.write_all(&BlobPackHeader::current().encode())
        .expect("pack header writes");
    file.write_all(&BlobRecordHeader::new(hash, 7).encode())
        .expect("record header writes");
    file.write_all(b"pay").expect("partial payload writes");
    file.flush().expect("partial payload flushes");
    let reader = BlobPackReader::open(path.clone()).expect("reader opens by header");

    let error = reader.records().expect_err("past-end payload errors");

    assert!(matches!(
        error,
        BlobPackReadError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        } if payload_end == BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + 7
            && pack_len == BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + 3
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn blob_pack_reader_rejects_corrupt_payload_bytes() {
    let path = temp_path("reader-corrupt-payload");
    let payload = b"payload".as_slice();
    let locations = write_pack(&path, &[payload]);
    let hash = BlobPackHash::for_bytes(payload);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("pack opens for corruption");
    file.seek(SeekFrom::Start(
        locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64,
    ))
    .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");
    let reader = BlobPackReader::open(path.clone()).expect("reader opens by header");

    assert!(matches!(
        reader
            .records()
            .expect_err("corrupt payload scan errors"),
        BlobPackReadError::PayloadHashMismatch { expected, actual }
            if expected == hash && actual == BlobPackHash::for_bytes(b"Xayload")
    ));
    assert!(matches!(
        reader
            .read_payload(locations[0], hash)
            .expect_err("corrupt payload read errors"),
        BlobPackReadError::PayloadHashMismatch { expected, actual }
            if expected == hash && actual == BlobPackHash::for_bytes(b"Xayload")
    ));

    let _ = fs::remove_file(path);
}
