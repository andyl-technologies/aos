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
        PersistBlobKey::for_value(hash)
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
fn blob_pack_records_scans_verified_records_in_pack_order() {
    let path = temp_root().join("values").join("pack.blob");
    let pack = PersistBlobPack::open(&path).expect("pack opens");
    let first_payload = b"first payload";
    let first_hash = DurableBlake3Hash::for_bytes(first_payload);
    let second_payload = b"second payload";
    let second_hash = DurableBlake3Hash::for_bytes(second_payload);

    assert!(pack.records().expect("empty pack scan succeeds").is_empty());
    let first = pack
        .append_blob(first_hash, first_payload)
        .expect("first blob appends");
    let second = pack
        .append_blob(second_hash, second_payload)
        .expect("second blob appends");

    let records = pack.records().expect("pack records scan");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].hash(), first_hash);
    assert_eq!(records[0].location(), first);
    assert_eq!(
        records[0].key(PersistBlobStore::Values),
        PersistBlobKey::for_value(first_hash)
    );
    assert_eq!(records[1].hash(), second_hash);
    assert_eq!(records[1].location(), second);
    assert_eq!(
        records[1].key(PersistBlobStore::Files),
        PersistBlobKey::for_file(second_hash)
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
        .read_blob(PersistBlobLocation::new(0, location.payload_len()), hash)
        .expect_err("header offset errors");
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
