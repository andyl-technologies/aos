//! File artifact index format tests.

use super::*;

#[test]
fn file_artifact_index_keys_include_path_content_and_parse_identity() {
    use crate::cache::parse::{PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags};

    let source = b"let x = 1; in x";
    let flags = ParseCacheFlags::new();
    let parse_key = ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, flags);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);

    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let same = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let other_path = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let changed_source = b"let x = 2; in x";
    let changed_file_key = ParseFileKey::for_source("/src/default.nix", changed_source);
    let changed_parse_key =
        ParseCacheKey::for_source(changed_source, PARSE_CACHE_SCHEMA_VERSION, flags);
    let changed_content =
        PersistFileArtifactKey::from_parse_file_key(&changed_file_key, changed_parse_key);
    let bumped_parse_key = ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION + 1, flags);
    let changed_parse_identity =
        PersistFileArtifactKey::from_parse_file_key(&file_key, bumped_parse_key);

    assert_eq!(key, same);
    assert_eq!(key.index_bytes().len(), PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN);
    assert_eq!(key.index_bytes()[0], PERSIST_FILE_ARTIFACT_INDEX_TAG);
    assert_ne!(key, other_path);
    assert_ne!(key, changed_content);
    assert_ne!(key, changed_parse_identity);
}

#[test]
fn file_artifact_index_keys_decode_and_reject_invalid_prefixes() {
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let mut encoded = key.index_bytes().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        PersistFileArtifactKey::decode_index_bytes(&encoded).expect("file artifact key decodes"),
        key
    );

    let error = PersistFileArtifactKey::decode_index_bytes(&[0; 8])
        .expect_err("short file artifact key errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortFileArtifactIndexKey {
            expected: PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN,
            actual: 8,
        }
    );

    let mut invalid_tag = key.index_bytes();
    invalid_tag[0] = 99;
    let error = PersistFileArtifactKey::decode_index_bytes(&invalid_tag)
        .expect_err("bad file artifact tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 }
    );
}

#[test]
fn file_artifact_index_values_round_trip_file_blob_locations() {
    let blob_hash = PersistFileBlobHash::for_payload(b"serialized IR artifact");
    let location = PersistBlobLocation::new(123, 456);
    let value = PersistFileArtifactIndexValue::new(blob_hash, location);
    let mut encoded = value.encode_index_value().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        value.blob_key(),
        PersistBlobKey::for_file(value.blob_hash())
    );
    assert_eq!(value.location(), location);
    assert_eq!(
        value.encode_index_value().len(),
        PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN
    );
    assert_eq!(
        PersistFileArtifactIndexValue::decode_index_value(&encoded)
            .expect("file artifact value decodes"),
        value
    );
}

#[test]
fn file_artifact_index_values_reject_invalid_prefixes() {
    let error = PersistFileArtifactIndexValue::decode_index_value(&[0; 8])
        .expect_err("short file artifact index value errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortFileArtifactIndexValue {
            expected: PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN,
            actual: 8,
        }
    );

    let blob_hash = DurableBlake3Hash::for_bytes(b"serialized value");
    let location = PersistBlobLocation::new(123, 456);
    let mut encoded = [0; PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN];
    encoded[..PERSIST_BLOB_INDEX_KEY_LEN]
        .copy_from_slice(&PersistBlobKey::new(PersistBlobStore::Values, blob_hash).index_bytes());
    encoded[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&location.encode_index_value());

    let error = PersistFileArtifactIndexValue::decode_index_value(&encoded)
        .expect_err("value blob store errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidFileArtifactBlobStore {
            store: PersistBlobStore::Values,
        }
    );
}

#[test]
fn file_artifact_index_entries_round_trip_key_value_records() {
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized IR artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let entry = PersistFileArtifactIndexEntry::new(key, value);
    let mut encoded = entry.encode_index_entry().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(entry.key(), key);
    assert_eq!(entry.value(), value);
    assert_eq!(
        entry.encode_index_entry().len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN
    );
    assert_eq!(
        PersistFileArtifactIndexEntry::decode_index_entry(&encoded)
            .expect("file artifact entry decodes"),
        entry
    );
}

#[test]
fn file_artifact_index_entries_reject_invalid_prefixes() {
    let error = PersistFileArtifactIndexEntry::decode_index_entry(&[0; 8])
        .expect_err("short file artifact entry errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortFileArtifactIndexEntry {
            expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
            actual: 8,
        }
    );

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized IR artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let entry = PersistFileArtifactIndexEntry::new(key, value);

    let mut invalid_key = entry.encode_index_entry();
    invalid_key[0] = 99;
    let error = PersistFileArtifactIndexEntry::decode_index_entry(&invalid_key)
        .expect_err("bad entry key tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 }
    );

    let mut invalid_value = entry.encode_index_entry();
    invalid_value[PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN] = PersistBlobStore::Values.index_tag();
    let error = PersistFileArtifactIndexEntry::decode_index_entry(&invalid_value)
        .expect_err("bad entry value store errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidFileArtifactBlobStore {
            store: PersistBlobStore::Values,
        }
    );
}

#[test]
fn file_artifact_index_appends_and_finds_latest_matching_entry() {
    let root = temp_root();
    let index_path = root.join("nodes").join("file-artifacts.index");
    let index = PersistFileArtifactIndex::open(&index_path).expect("index opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let other_key = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let first = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let other = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"other artifact"),
        PersistBlobLocation::new(789, 10),
    );
    let latest = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest artifact"),
        PersistBlobLocation::new(999, 11),
    );

    assert_eq!(index.path(), index_path.as_path());
    assert_eq!(index.lookup(key).expect("empty lookup succeeds"), None);

    index
        .append_entry(PersistFileArtifactIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistFileArtifactIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistFileArtifactIndexEntry::new(key, latest))
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
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn file_artifact_index_compacts_to_latest_entries() {
    let root = temp_root();
    let index_path = root.join("nodes").join("file-artifacts.index");
    let index = PersistFileArtifactIndex::open(&index_path).expect("index opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let other_key = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let first = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let other = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"other artifact"),
        PersistBlobLocation::new(789, 10),
    );
    let latest = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest artifact"),
        PersistBlobLocation::new(999, 11),
    );
    index
        .append_entry(PersistFileArtifactIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistFileArtifactIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistFileArtifactIndexEntry::new(key, latest))
        .expect("latest entry appends");

    let mut expected = vec![
        PersistFileArtifactIndexEntry::new(key, latest),
        PersistFileArtifactIndexEntry::new(other_key, other),
    ];
    expected.sort_by_key(|entry| entry.key().index_bytes());
    assert_eq!(
        index.latest_entries().expect("latest entries load"),
        expected
    );
    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * 3) as u64
    );

    assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);

    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
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
fn file_artifact_index_open_rejects_truncated_records() {
    let root = temp_root();
    let index_path = root.join("nodes").join("file-artifacts.index");
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, b"partial").expect("partial index writes");

    let error = PersistFileArtifactIndex::open(&index_path).expect_err("truncated index errors");

    assert!(matches!(
        error,
        PersistFileArtifactIndexError::Format {
            source: PersistPackFormatError::ShortFileArtifactIndexEntry {
                expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
                actual: 7,
            },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn file_artifact_index_lookup_rejects_malformed_records() {
    let root = temp_root();
    let index_path = root.join("nodes").join("file-artifacts.index");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized IR artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let mut encoded = PersistFileArtifactIndexEntry::new(key, value).encode_index_entry();
    encoded[0] = 99;
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, encoded).expect("malformed index writes");
    let index = PersistFileArtifactIndex::open(&index_path).expect("index opens by length");

    let error = index.lookup(key).expect_err("malformed record errors");

    assert!(matches!(
        error,
        PersistFileArtifactIndexError::Format {
            source: PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}
