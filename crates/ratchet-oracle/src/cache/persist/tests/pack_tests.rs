//! Tests for packfile and record headers and blob-pack append/read.

use super::*;

#[test]
fn packfile_header_round_trips() {
    let header = PersistBlobPackHeader::current();
    let encoded = header.encode();

    assert_eq!(encoded.len(), PERSIST_BLOB_PACK_HEADER_LEN);
    assert_eq!(&encoded[..16], PERSIST_BLOB_PACK_MAGIC.as_slice());
    assert_eq!(
        &encoded[16..20],
        PERSIST_BLOB_PACK_VERSION.to_le_bytes().as_slice()
    );
    assert_eq!(
        &encoded[20..24],
        (PERSIST_BLOB_PACK_HEADER_LEN as u32)
            .to_le_bytes()
            .as_slice()
    );
    assert_eq!(
        PersistBlobPackHeader::decode(&encoded).expect("pack header decodes"),
        header
    );
    assert_eq!(header.version(), PERSIST_BLOB_PACK_VERSION);
}

#[test]
fn packfile_header_decodes_from_prefix() {
    let header = PersistBlobPackHeader::current();
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(b"trailing pack bytes");

    assert_eq!(
        PersistBlobPackHeader::decode(&bytes).expect("pack header decodes from prefix"),
        header
    );
}

#[test]
fn packfile_header_rejects_invalid_prefixes() {
    let encoded = PersistBlobPackHeader::current().encode();

    let error = PersistBlobPackHeader::decode(&encoded[..8]).expect_err("short header errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortPackHeader {
            expected: PERSIST_BLOB_PACK_HEADER_LEN,
            actual: 8,
        }
    );

    let mut invalid_magic = encoded;
    invalid_magic[0] = b'X';
    let error = PersistBlobPackHeader::decode(&invalid_magic).expect_err("bad magic errors");
    assert!(matches!(
        error,
        PersistPackFormatError::InvalidPackMagic { .. }
    ));

    let mut invalid_version = encoded;
    invalid_version[16..20].copy_from_slice(&2u32.to_le_bytes());
    let error = PersistBlobPackHeader::decode(&invalid_version).expect_err("bad version errors");
    assert_eq!(
        error,
        PersistPackFormatError::UnsupportedPackVersion { version: 2 }
    );

    let mut invalid_len = encoded;
    invalid_len[20..24].copy_from_slice(&12u32.to_le_bytes());
    let error = PersistBlobPackHeader::decode(&invalid_len).expect_err("bad header length errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidPackHeaderLength { header_len: 12 }
    );
}

#[test]
fn blob_record_header_round_trips() {
    let hash = DurableBlake3Hash::for_bytes(b"record payload");
    let header = PersistBlobRecordHeader::new(hash, 987);
    let encoded = header.encode();

    assert_eq!(encoded.len(), PERSIST_BLOB_RECORD_HEADER_LEN);
    assert_eq!(&encoded[..32], hash.as_bytes().as_slice());
    assert_eq!(&encoded[32..40], 987u64.to_le_bytes().as_slice());
    assert_eq!(
        PersistBlobRecordHeader::decode(&encoded).expect("record header decodes"),
        header
    );
    assert_eq!(header.hash(), hash);
    assert_eq!(header.payload_len(), 987);
    assert_eq!(
        header.key(PersistBlobStore::Values),
        PersistBlobKey::new(PersistBlobStore::Values, hash)
    );
}

#[test]
fn blob_record_header_decodes_from_prefix() {
    let hash = DurableBlake3Hash::for_bytes(b"record payload");
    let header = PersistBlobRecordHeader::new(hash, 987);
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(b"serialized payload bytes");

    assert_eq!(
        PersistBlobRecordHeader::decode(&bytes).expect("record header decodes from prefix"),
        header
    );
}

#[test]
fn blob_record_header_rejects_short_prefix() {
    let error = PersistBlobRecordHeader::decode(&[0; 8]).expect_err("short record errors");

    assert_eq!(
        error,
        PersistPackFormatError::ShortRecordHeader {
            expected: PERSIST_BLOB_RECORD_HEADER_LEN,
            actual: 8,
        }
    );
}

#[test]
fn blob_pack_open_initializes_header() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");

    assert_eq!(pack.path(), path.as_path());
    assert_eq!(
        fs::read(&path).expect("pack header reads").as_slice(),
        PersistBlobPackHeader::current().encode().as_slice()
    );
    PersistBlobPack::open(&path).expect("initialized pack reopens");

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_open_rejects_corrupt_header_without_rewriting() {
    let path = temp_root().join("values").join("pack.blob");
    fs::create_dir_all(path.parent().expect("pack parent exists")).expect("parent creates");
    fs::write(&path, b"bad").expect("corrupt pack writes");

    let error = PersistBlobPack::open(&path).expect_err("corrupt pack errors");

    assert!(matches!(
        error,
        PersistBlobPackError::Format {
            source: PersistPackFormatError::ShortPackHeader { actual: 3, .. },
            ..
        }
    ));
    assert_eq!(
        fs::read(&path).expect("corrupt pack reads").as_slice(),
        b"bad"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_len_uses_scoped_mapped_pack() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");

    assert_eq!(pack.mapped_read_count_for_tests(), 0);
    assert_eq!(
        pack.len().expect("empty pack length reads"),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        1,
        "pack length should validate through the scoped mapping"
    );

    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    pack.append_blob(hash, payload).expect("blob appends");

    assert_eq!(
        pack.len().expect("appended pack length reads"),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        2,
        "subsequent length reads should keep using the scoped mapping"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_len_rejects_corrupt_header_through_scoped_mapping() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    fs::write(&path, b"bad").expect("corrupt pack writes");

    let error = pack.len().expect_err("corrupt header length errors");

    assert!(matches!(
        error,
        PersistBlobPackError::Format {
            source: PersistPackFormatError::ShortPackHeader { actual: 3, .. },
            ..
        }
    ));
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        0,
        "failed mapped length validation should not count as a successful mapped read"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_appends_and_reads_verified_payloads() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let first_payload = b"first payload";
    let first_hash = DurableBlake3Hash::for_bytes(first_payload);
    let second_payload = b"second payload";
    let second_hash = DurableBlake3Hash::for_bytes(second_payload);

    let first = pack
        .append_blob(first_hash, first_payload)
        .expect("first blob appends");
    let second = pack
        .append_blob(second_hash, second_payload)
        .expect("second blob appends");

    assert_eq!(first.record_offset(), PERSIST_BLOB_PACK_HEADER_LEN as u64);
    assert_eq!(first.payload_len(), first_payload.len() as u64);
    assert_eq!(
        second.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + first_payload.len() as u64
    );
    assert_eq!(
        pack.read_blob(first, first_hash)
            .expect("first blob reads")
            .as_slice(),
        first_payload
    );
    assert_eq!(
        pack.read_blob(second, second_hash)
            .expect("second blob reads")
            .as_slice(),
        second_payload
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_borrowed_read_uses_scoped_mapped_payload() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"mapped payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");

    assert_eq!(pack.mapped_read_count_for_tests(), 0);
    let observed_len = pack
        .with_blob(location, hash, |mapped| {
            assert_eq!(mapped, payload);
            assert_eq!(
                pack.mapped_read_count_for_tests(),
                1,
                "mapped read should be counted before the visitor runs"
            );
            mapped.len()
        })
        .expect("borrowed payload visit succeeds");

    assert_eq!(observed_len, payload.len());
    assert_eq!(pack.mapped_read_count_for_tests(), 1);
    assert_eq!(
        pack.read_blob(location, hash)
            .expect("owned blob read succeeds")
            .as_slice(),
        payload
    );
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        2,
        "owned lower-level reads should clone through the mapped visitor"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_payload_window_validates_lookup_bounds_without_hashing_payload() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");
    let payload_start = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let payload_end = payload_start + payload.len() as u64;

    assert_eq!(pack.mapped_read_count_for_tests(), 0);
    let window = pack
        .payload_window(location, hash)
        .expect("payload window validates");

    assert_eq!(window.record().hash(), hash);
    assert_eq!(window.record().location(), location);
    assert_eq!(window.hash(), hash);
    assert_eq!(window.location(), location);
    assert_eq!(
        window.key(PersistBlobStore::Values),
        PersistBlobKey::new(PersistBlobStore::Values, hash)
    );
    assert_eq!(window.payload_start(), payload_start);
    assert_eq!(window.payload_end(), payload_end);
    assert_eq!(window.payload_len(), payload.len() as u64);
    assert_eq!(window.payload_range(), payload_start..payload_end);
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        1,
        "payload windows should validate through the scoped mapping"
    );

    let mut file = OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for mutation");
    file.seek(SeekFrom::Start(payload_start))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    pack.payload_window(location, hash)
        .expect("payload window ignores payload bytes");
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        2,
        "metadata-only payload window should still use the mapped adapter"
    );
    let error = pack
        .read_blob(location, hash)
        .expect_err("corrupt payload errors");
    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        2,
        "failed mapped payload verification should not count as a successful mapped read"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_verify_blob_uses_scoped_mapped_payload_without_materializing() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = vec![b'x'; 16 * 1024 + 17];
    let hash = DurableBlake3Hash::for_bytes(&payload);
    let location = pack
        .append_blob(hash, &payload)
        .expect("large blob appends");

    assert_eq!(pack.mapped_read_count_for_tests(), 0);
    let window = pack
        .verify_blob(location, hash)
        .expect("large payload verifies");

    assert_eq!(window.location(), location);
    assert_eq!(window.hash(), hash);
    assert_eq!(
        window.payload_end(),
        location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64 + payload.len() as u64
    );
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        1,
        "verify_blob should use the mapped adapter"
    );

    let mut file = OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for mutation");
    file.seek(SeekFrom::Start(window.payload_start() + 3))
        .expect("payload offset seeks");
    file.write_all(b"y").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = pack
        .verify_blob(location, hash)
        .expect_err("corrupt payload verification errors");
    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        1,
        "failed mapped payload verification should not count as a successful visit"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_payload_matches_compares_verified_payload_bytes() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");

    assert_eq!(pack.mapped_read_count_for_tests(), 0);
    assert!(
        pack.payload_matches(location, hash, payload)
            .expect("matching payload verifies")
    );
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        1,
        "matching payload comparisons should use the mapped adapter"
    );
    assert!(
        !pack
            .payload_matches(location, hash, b"payloae")
            .expect("same-length mismatch verifies")
    );
    assert_eq!(pack.mapped_read_count_for_tests(), 2);
    assert!(
        !pack
            .payload_matches(location, hash, b"payload with suffix")
            .expect("length mismatch validates metadata")
    );
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        3,
        "length mismatches should still verify through the mapped adapter"
    );
    let wrong_hash = DurableBlake3Hash::for_bytes(b"other payload");
    let error = pack
        .payload_matches(location, wrong_hash, payload)
        .expect_err("wrong hash errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordHashMismatch { .. }
    ));
    assert_eq!(pack.mapped_read_count_for_tests(), 3);

    let mut file = OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for mutation");
    file.seek(SeekFrom::Start(
        location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64,
    ))
    .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = pack
        .payload_matches(location, hash, payload)
        .expect_err("corrupt matching payload errors");
    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        3,
        "failed mapped payload comparisons should not count as successful visits"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_records_scans_verified_records_in_pack_order() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let first_payload = b"first payload";
    let first_hash = DurableBlake3Hash::for_bytes(first_payload);
    let second_payload = b"second payload";
    let second_hash = DurableBlake3Hash::for_bytes(second_payload);

    assert_eq!(pack.mapped_read_count_for_tests(), 0);
    assert!(pack.records().expect("empty pack scan succeeds").is_empty());
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        1,
        "empty physical record scans should still use the mapped adapter"
    );
    let first = pack
        .append_blob(first_hash, first_payload)
        .expect("first blob appends");
    let second = pack
        .append_blob(second_hash, second_payload)
        .expect("second blob appends");

    let records = pack.records().expect("pack records scan");

    assert_eq!(records.len(), 2);
    assert_eq!(
        pack.mapped_read_count_for_tests(),
        2,
        "physical record scans should use the mapped adapter"
    );
    assert_eq!(records[0].hash(), first_hash);
    assert_eq!(records[0].location(), first);
    assert_eq!(
        records[0].key(PersistBlobStore::Values),
        PersistBlobKey::new(PersistBlobStore::Values, first_hash)
    );
    assert_eq!(records[1].hash(), second_hash);
    assert_eq!(records[1].location(), second);
    assert_eq!(
        records[1].key(PersistBlobStore::Files),
        PersistBlobKey::for_file(PersistFileBlobHash::from_durable_hash(second_hash))
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_records_accepts_zero_length_payloads() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("empty blob appends");

    let records = pack.records().expect("pack records scan");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].hash(), hash);
    assert_eq!(records[0].location(), location);
    assert_eq!(
        pack.read_blob(location, hash)
            .expect("empty blob reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_rejects_append_payload_hash_mismatch() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let wrong_hash = DurableBlake3Hash::for_bytes(b"other payload");

    let error = pack
        .append_blob(wrong_hash, payload)
        .expect_err("hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    assert_eq!(
        fs::metadata(&path).expect("pack metadata reads").len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_trim_tail_removes_unneeded_records() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let first_payload = b"first payload";
    let first_hash = DurableBlake3Hash::for_bytes(first_payload);
    let second_payload = b"second payload";
    let second_hash = DurableBlake3Hash::for_bytes(second_payload);
    let first = pack
        .append_blob(first_hash, first_payload)
        .expect("first blob appends");
    let second = pack
        .append_blob(second_hash, second_payload)
        .expect("second blob appends");
    let before_len = pack.len().expect("pack length reads");

    let removed = pack
        .trim_tail(second.record_offset())
        .expect("pack tail trims");

    assert_eq!(removed, before_len - second.record_offset());
    assert_eq!(
        pack.len().expect("trimmed pack length reads"),
        second.record_offset()
    );
    let records = pack.records().expect("trimmed records scan");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].hash(), first_hash);
    assert_eq!(records[0].location(), first);
    assert_eq!(
        pack.read_blob(first, first_hash)
            .expect("retained blob reads")
            .as_slice(),
        first_payload
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_trim_tail_rejects_corrupt_header_without_rewriting() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    fs::write(&path, b"bad").expect("corrupt pack writes");

    let error = pack
        .trim_tail(PERSIST_BLOB_PACK_HEADER_LEN as u64)
        .expect_err("corrupt header errors");

    assert!(matches!(
        error,
        PersistBlobPackError::Format {
            source: PersistPackFormatError::ShortPackHeader { actual: 3, .. },
            ..
        }
    ));
    assert_eq!(
        fs::read(&path).expect("corrupt pack reads").as_slice(),
        b"bad"
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_trim_tail_rejects_offsets_outside_pack() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let len = pack.len().expect("pack length reads");

    let error = pack
        .trim_tail(PERSIST_BLOB_PACK_HEADER_LEN as u64 - 1)
        .expect_err("offset before header errors");
    assert!(matches!(
        error,
        PersistBlobPackError::InvalidRecordOffset { record_offset }
            if record_offset == PERSIST_BLOB_PACK_HEADER_LEN as u64 - 1
    ));

    let error = pack.trim_tail(len + 1).expect_err("offset past end errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        } if payload_end == len + 1 && pack_len == len
    ));
    assert_eq!(pack.len().expect("final pack length reads"), len);

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_read_rejects_mismatched_lookup_metadata() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");

    let error = pack
        .read_blob(location, DurableBlake3Hash::for_bytes(b"other payload"))
        .expect_err("wrong hash errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordHashMismatch { .. }
    ));
    let error = pack
        .with_blob(
            location,
            DurableBlake3Hash::for_bytes(b"other payload"),
            |_| panic!("wrong hash must not call the borrowed visitor"),
        )
        .expect_err("wrong borrowed hash errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordHashMismatch { .. }
    ));
    let error = pack
        .payload_window(location, DurableBlake3Hash::for_bytes(b"other payload"))
        .expect_err("wrong window hash errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordHashMismatch { .. }
    ));

    let error = pack
        .read_blob(
            PersistBlobLocation::new(location.record_offset(), location.payload_len() + 1),
            hash,
        )
        .expect_err("wrong length errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordLengthMismatch { .. }
    ));
    let error = pack
        .payload_window(
            PersistBlobLocation::new(location.record_offset(), location.payload_len() + 1),
            hash,
        )
        .expect_err("wrong window length errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordLengthMismatch { .. }
    ));

    let error = pack
        .read_blob(PersistBlobLocation::new(0, location.payload_len()), hash)
        .expect_err("header offset errors");
    assert!(matches!(
        error,
        PersistBlobPackError::InvalidRecordOffset { record_offset: 0 }
    ));
    let error = pack
        .payload_window(PersistBlobLocation::new(0, location.payload_len()), hash)
        .expect_err("header window offset errors");
    assert!(matches!(
        error,
        PersistBlobPackError::InvalidRecordOffset { record_offset: 0 }
    ));

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_read_rejects_truncated_payload_before_allocation() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for truncation")
        .set_len(payload_offset + 1)
        .expect("pack truncates");

    let error = pack
        .read_blob(location, hash)
        .expect_err("truncated payload errors");

    assert!(matches!(
        error,
        PersistBlobPackError::RecordExtendsPastEnd { .. }
    ));
    let error = pack
        .payload_window(location, hash)
        .expect_err("truncated payload window errors");
    assert!(matches!(
        error,
        PersistBlobPackError::RecordExtendsPastEnd { .. }
    ));

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_records_rejects_truncated_tail_record() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let first_payload = b"first payload";
    let first_hash = DurableBlake3Hash::for_bytes(first_payload);
    let second_payload = b"second payload";
    let second_hash = DurableBlake3Hash::for_bytes(second_payload);
    let first = pack
        .append_blob(first_hash, first_payload)
        .expect("first blob appends");
    let second = pack
        .append_blob(second_hash, second_payload)
        .expect("second blob appends");
    let second_payload_offset = second.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for truncation")
        .set_len(second_payload_offset + 1)
        .expect("pack truncates");

    let error = pack.records().expect_err("truncated scan errors");

    assert!(matches!(
        error,
        PersistBlobPackError::RecordExtendsPastEnd { .. }
    ));
    assert_eq!(
        pack.read_blob(first, first_hash)
            .expect("first record remains readable")
            .as_slice(),
        first_payload
    );

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_records_rejects_short_trailing_record_header() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    pack.append_blob(hash, payload).expect("blob appends");
    let mut file = OpenOptions::new()
        .append(true)
        .open(pack.path())
        .expect("pack opens for append");
    file.write_all(&[0; PERSIST_BLOB_RECORD_HEADER_LEN - 1])
        .expect("short header appends");
    file.flush().expect("short header flushes");

    let error = pack.records().expect_err("short trailing header errors");

    assert!(matches!(
        error,
        PersistBlobPackError::Format {
            source: PersistPackFormatError::ShortRecordHeader { actual, .. },
            ..
        } if actual == PERSIST_BLOB_RECORD_HEADER_LEN - 1
    ));

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_direct_lookup_rejects_short_record_header_as_format() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    pack.append_blob(hash, payload).expect("blob appends");
    let record_offset = pack.len().expect("pack length reads");
    let mut file = OpenOptions::new()
        .append(true)
        .open(pack.path())
        .expect("pack opens for append");
    file.write_all(&[0; PERSIST_BLOB_RECORD_HEADER_LEN - 1])
        .expect("short header appends");
    file.flush().expect("short header flushes");

    let location = PersistBlobLocation::new(record_offset, 0);
    let error = pack
        .read_blob(location, hash)
        .expect_err("short direct record header errors");
    assert!(matches!(
        error,
        PersistBlobPackError::Format {
            source: PersistPackFormatError::ShortRecordHeader { actual, .. },
            ..
        } if actual == PERSIST_BLOB_RECORD_HEADER_LEN - 1
    ));

    let error = pack
        .payload_window(location, hash)
        .expect_err("short direct record header window errors");
    assert!(matches!(
        error,
        PersistBlobPackError::Format {
            source: PersistPackFormatError::ShortRecordHeader { actual, .. },
            ..
        } if actual == PERSIST_BLOB_RECORD_HEADER_LEN - 1
    ));

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_read_rejects_corrupt_payload() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = pack
        .read_blob(location, hash)
        .expect_err("corrupt payload errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    let error = pack
        .with_blob(location, hash, |_| {
            panic!("corrupt payload must not call the borrowed visitor")
        })
        .expect_err("corrupt borrowed payload errors");
    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}

#[test]
fn blob_pack_records_rejects_corrupt_payload() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let payload = b"payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let location = pack.append_blob(hash, payload).expect("blob appends");
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(pack.path())
        .expect("pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = pack.records().expect_err("corrupt scan errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
}
