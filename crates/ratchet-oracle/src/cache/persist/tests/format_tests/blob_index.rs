//! Blob index format tests.

use super::*;

#[test]
fn blob_packfile_paths_are_store_separated() {
    let layout = PersistLayout::new(temp_root());

    assert_eq!(
        layout.blob_packfile_path(PersistBlobStore::Values),
        layout.value_packfile_path()
    );
    assert_eq!(
        layout.blob_packfile_path(PersistBlobStore::Files),
        layout.file_packfile_path()
    );
    assert_eq!(
        layout.value_packfile_path(),
        layout.values_dir().join("pack.blob")
    );
    assert_eq!(
        layout.file_packfile_path(),
        layout.files_dir().join("pack.blob")
    );
    assert_ne!(layout.value_packfile_path(), layout.file_packfile_path());
}

#[test]
fn blob_index_paths_are_store_separated() {
    let layout = PersistLayout::new(temp_root());

    assert_eq!(
        layout.blob_index_path(PersistBlobStore::Values),
        layout.value_index_path()
    );
    assert_eq!(
        layout.blob_index_path(PersistBlobStore::Files),
        layout.file_index_path()
    );
    assert_eq!(
        layout.value_index_path(),
        layout.values_dir().join("index.blob")
    );
    assert_eq!(
        layout.file_index_path(),
        layout.files_dir().join("index.blob")
    );
    assert_eq!(
        layout.file_artifact_index_path(),
        layout.nodes_dir().join("file-artifacts.index")
    );
    assert_eq!(
        layout.parse_artifact_index_path(),
        layout.nodes_dir().join("parse-artifacts.index")
    );
    assert_eq!(
        layout.node_metadata_index_path(),
        layout.nodes_dir().join("metadata.index")
    );
    assert_eq!(
        layout.node_trace_log_path(),
        layout.nodes_dir().join("traces.log")
    );
    assert_ne!(layout.value_index_path(), layout.file_index_path());
    assert_ne!(layout.file_artifact_index_path(), layout.file_index_path());
    assert_ne!(
        layout.parse_artifact_index_path(),
        layout.file_artifact_index_path()
    );
    assert_ne!(
        layout.node_metadata_index_path(),
        layout.parse_artifact_index_path()
    );
    assert_ne!(
        layout.node_trace_log_path(),
        layout.node_metadata_index_path()
    );
}

#[test]
fn blob_index_keys_are_domain_separated_by_store() {
    let hash = DurableBlake3Hash::for_bytes(b"same bytes");
    let value_key = PersistBlobKey::new(PersistBlobStore::Values, hash).index_bytes();
    let file_key =
        PersistBlobKey::for_file(PersistFileBlobHash::from_durable_hash(hash)).index_bytes();

    assert_ne!(value_key, file_key);
    assert_eq!(value_key[0], 1);
    assert_eq!(file_key[0], 2);
    assert_eq!(&value_key[1..], hash.as_bytes().as_slice());
    assert_eq!(&file_key[1..], hash.as_bytes().as_slice());
}

#[test]
fn blob_index_keys_are_stable_content_addresses() {
    let first = DurableBlake3Hash::for_bytes(b"first payload");
    let first_again = DurableBlake3Hash::for_bytes(b"first payload");
    let second = DurableBlake3Hash::for_bytes(b"second payload");
    let first_key = PersistBlobKey::new(PersistBlobStore::Values, first);
    let first_key_again = PersistBlobKey::new(PersistBlobStore::Values, first_again);
    let second_key = PersistBlobKey::new(PersistBlobStore::Values, second);

    assert_eq!(first_key.store(), PersistBlobStore::Values);
    assert_eq!(first_key.hash(), first);
    assert_eq!(first_key.index_bytes(), first_key_again.index_bytes());
    assert_ne!(first_key.index_bytes(), second_key.index_bytes());
}

#[test]
fn blob_index_keys_decode_and_reject_invalid_prefixes() {
    let key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"payload"));
    let mut encoded = key.index_bytes().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        PersistBlobKey::decode_index_bytes(&encoded).expect("blob index key decodes"),
        key
    );

    let error = PersistBlobKey::decode_index_bytes(&[0; 8]).expect_err("short index key errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortBlobIndexKey {
            expected: PERSIST_BLOB_INDEX_KEY_LEN,
            actual: 8,
        }
    );

    let mut invalid_tag = key.index_bytes();
    invalid_tag[0] = 99;
    let error = PersistBlobKey::decode_index_bytes(&invalid_tag).expect_err("bad tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 }
    );
}

#[test]
fn blob_index_values_round_trip_locations() {
    let location = PersistBlobLocation::new(123, 456);
    let encoded = location.encode_index_value();

    assert_eq!(encoded.len(), PERSIST_BLOB_INDEX_VALUE_LEN);
    assert_eq!(&encoded[..8], 123u64.to_le_bytes().as_slice());
    assert_eq!(&encoded[8..16], 456u64.to_le_bytes().as_slice());
    assert_eq!(
        PersistBlobLocation::decode_index_value(&encoded).expect("index value decodes"),
        location
    );
}

#[test]
fn blob_index_values_decode_from_prefix() {
    let location = PersistBlobLocation::new(123, 456);
    let mut encoded = location.encode_index_value().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        PersistBlobLocation::decode_index_value(&encoded).expect("index value decodes from prefix"),
        location
    );
}

#[test]
fn blob_index_values_reject_short_prefix() {
    let error =
        PersistBlobLocation::decode_index_value(&[0; 8]).expect_err("short index value errors");

    assert_eq!(
        error,
        PersistPackFormatError::ShortIndexValue {
            expected: PERSIST_BLOB_INDEX_VALUE_LEN,
            actual: 8,
        }
    );
}

#[test]
fn blob_index_entries_round_trip_key_value_records() {
    let key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"payload"));
    let location = PersistBlobLocation::new(123, 456);
    let entry = PersistBlobIndexEntry::new(key, location);
    let entry_bytes = entry.encode_index_entry();
    let mut encoded = entry_bytes.to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(entry.key(), key);
    assert_eq!(entry.location(), location);
    assert_eq!(entry_bytes.len(), PERSIST_BLOB_INDEX_ENTRY_LEN);
    assert_eq!(
        &entry_bytes[..PERSIST_BLOB_INDEX_KEY_LEN],
        key.index_bytes().as_slice()
    );
    assert_eq!(
        &entry_bytes[PERSIST_BLOB_INDEX_KEY_LEN..],
        location.encode_index_value().as_slice()
    );
    assert_eq!(
        PersistBlobIndexEntry::decode_index_entry(&encoded).expect("blob index entry decodes"),
        entry
    );
}

#[test]
fn blob_index_entries_reject_invalid_prefixes() {
    let error = PersistBlobIndexEntry::decode_index_entry(&[0; 8]).expect_err("short entry errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortBlobIndexEntry {
            expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
            actual: 8,
        }
    );

    let key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"payload"));
    let location = PersistBlobLocation::new(123, 456);
    let entry = PersistBlobIndexEntry::new(key, location);
    let mut invalid_key = entry.encode_index_entry();
    invalid_key[0] = 99;
    let error = PersistBlobIndexEntry::decode_index_entry(&invalid_key)
        .expect_err("bad embedded blob key errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 }
    );
}

#[test]
fn blob_index_appends_and_finds_latest_matching_entry() {
    let root = temp_root();
    let index_path = root.join("values").join("index.blob");
    let index = PersistBlobIndex::open(&index_path).expect("index opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"payload"),
    );
    let other_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"other payload"));
    let first = PersistBlobLocation::new(123, 456);
    let other = PersistBlobLocation::new(789, 10);
    let latest = PersistBlobLocation::new(999, 11);

    assert_eq!(index.path(), index_path.as_path());
    assert_eq!(index.lookup(key).expect("empty lookup succeeds"), None);

    index
        .append_entry(PersistBlobIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistBlobIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistBlobIndexEntry::new(key, latest))
        .expect("latest entry appends");

    assert_eq!(
        index.lookup(key).expect("key lookup succeeds"),
        Some(latest)
    );
    assert_eq!(
        index.lookup(other_key).expect("other lookup succeeds"),
        Some(other)
    );
    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn blob_index_compacts_to_latest_entries() {
    let root = temp_root();
    let index_path = root.join("values").join("index.blob");
    let index = PersistBlobIndex::open(&index_path).expect("index opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"payload"),
    );
    let other_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"other payload"));
    let first = PersistBlobLocation::new(123, 456);
    let other = PersistBlobLocation::new(789, 10);
    let latest = PersistBlobLocation::new(999, 11);
    index
        .append_entry(PersistBlobIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistBlobIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistBlobIndexEntry::new(key, latest))
        .expect("latest entry appends");

    let mut expected = vec![
        PersistBlobIndexEntry::new(key, latest),
        PersistBlobIndexEntry::new(other_key, other),
    ];
    expected.sort_by_key(|entry| entry.key().index_bytes());
    assert_eq!(
        index.latest_entries().expect("latest entries load"),
        expected
    );
    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 3) as u64
    );

    assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);

    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        index.lookup(key).expect("key lookup succeeds"),
        Some(latest)
    );
    assert_eq!(
        index.lookup(other_key).expect("other lookup succeeds"),
        Some(other)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn blob_index_open_rejects_truncated_records() {
    let root = temp_root();
    let index_path = root.join("values").join("index.blob");
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, b"partial").expect("partial index writes");

    let error = PersistBlobIndex::open(&index_path).expect_err("truncated index errors");

    assert!(matches!(
        error,
        PersistBlobIndexError::Format {
            source: PersistPackFormatError::ShortBlobIndexEntry {
                expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
                actual: 7,
            },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn blob_index_lookup_rejects_malformed_records() {
    let root = temp_root();
    let index_path = root.join("values").join("index.blob");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"payload"),
    );
    let location = PersistBlobLocation::new(123, 456);
    let mut encoded = PersistBlobIndexEntry::new(key, location).encode_index_entry();
    encoded[0] = 99;
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, encoded).expect("malformed index writes");
    let index = PersistBlobIndex::open(&index_path).expect("index opens by length");

    let error = index.lookup(key).expect_err("malformed record errors");

    assert!(matches!(
        error,
        PersistBlobIndexError::Format {
            source: PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn blob_index_compaction_rejects_malformed_records() {
    let root = temp_root();
    let index_path = root.join("values").join("index.blob");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"payload"),
    );
    let location = PersistBlobLocation::new(123, 456);
    let mut encoded = PersistBlobIndexEntry::new(key, location).encode_index_entry();
    encoded[0] = 99;
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, encoded).expect("malformed index writes");
    let index = PersistBlobIndex::open(&index_path).expect("index opens by length");

    let error = index
        .compact_latest_entries()
        .expect_err("malformed record errors");

    assert!(matches!(
        error,
        PersistBlobIndexError::Format {
            source: PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}
