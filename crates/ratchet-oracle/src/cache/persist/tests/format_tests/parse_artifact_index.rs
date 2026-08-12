//! Parse artifact index format tests.

use super::*;

#[test]
fn parse_artifact_index_keys_are_parse_identity_only() {
    use crate::cache::parse::{PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags};

    let source = b"let x = 1; in x";
    let flags = ParseCacheFlags::new();
    let parse_key = ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, flags);
    let same_parse_key = ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, flags);
    let changed_source =
        ParseCacheKey::for_source(b"let x = 2; in x", PARSE_CACHE_SCHEMA_VERSION, flags);
    let bumped_schema = ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION + 1, flags);

    let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let same = PersistParseArtifactKey::from_parse_cache_key(same_parse_key);
    let changed_content = PersistParseArtifactKey::from_parse_cache_key(changed_source);
    let changed_schema = PersistParseArtifactKey::from_parse_cache_key(bumped_schema);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    assert_eq!(key, same);
    assert_eq!(key.hash(), parse_key.as_durable_hash());
    assert_eq!(
        key.index_bytes().len(),
        PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN
    );
    assert_eq!(key.index_bytes()[0], PERSIST_PARSE_ARTIFACT_INDEX_TAG);
    assert_ne!(key, changed_content);
    assert_ne!(key, changed_schema);
    assert_ne!(key.index_bytes(), file_artifact.index_bytes());
}

#[test]
fn parse_artifact_index_keys_decode_and_reject_invalid_prefixes() {
    let key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 1; in x"));
    let mut encoded = key.index_bytes().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        PersistParseArtifactKey::decode_index_bytes(&encoded).expect("parse artifact key decodes"),
        key
    );

    let error = PersistParseArtifactKey::decode_index_bytes(&[0; 8])
        .expect_err("short parse artifact key errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortParseArtifactIndexKey {
            expected: PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN,
            actual: 8,
        }
    );

    let mut invalid_tag = key.index_bytes();
    invalid_tag[0] = 99;
    let error = PersistParseArtifactKey::decode_index_bytes(&invalid_tag)
        .expect_err("bad parse artifact tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidParseArtifactIndexTag { tag: 99 }
    );
}

#[test]
fn parse_artifact_index_values_round_trip_file_blob_locations() {
    let blob_hash = PersistFileBlobHash::for_payload(b"serialized parse artifact");
    let location = PersistBlobLocation::new(123, 456);
    let value = PersistParseArtifactIndexValue::new(blob_hash, location);
    let mut encoded = value.encode_index_value().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        value.blob_key(),
        PersistBlobKey::for_file(value.blob_hash())
    );
    assert_eq!(value.location(), location);
    assert_eq!(
        value.encode_index_value().len(),
        PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN
    );
    assert_eq!(
        PersistParseArtifactIndexValue::decode_index_value(&encoded)
            .expect("parse artifact value decodes"),
        value
    );
}

#[test]
fn parse_artifact_index_values_reject_invalid_prefixes() {
    let error = PersistParseArtifactIndexValue::decode_index_value(&[0; 8])
        .expect_err("short parse artifact index value errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortParseArtifactIndexValue {
            expected: PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN,
            actual: 8,
        }
    );

    let blob_hash = DurableBlake3Hash::for_bytes(b"serialized value");
    let location = PersistBlobLocation::new(123, 456);
    let mut encoded = [0; PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN];
    encoded[..PERSIST_BLOB_INDEX_KEY_LEN]
        .copy_from_slice(&PersistBlobKey::new(PersistBlobStore::Values, blob_hash).index_bytes());
    encoded[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&location.encode_index_value());

    let error = PersistParseArtifactIndexValue::decode_index_value(&encoded)
        .expect_err("value blob store errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidParseArtifactBlobStore {
            store: PersistBlobStore::Values,
        }
    );
}

#[test]
fn parse_artifact_index_entries_round_trip_key_value_records() {
    let key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 1; in x"));
    let value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized parse artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let entry = PersistParseArtifactIndexEntry::new(key, value);
    let mut encoded = entry.encode_index_entry().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(entry.key(), key);
    assert_eq!(entry.value(), value);
    assert_eq!(
        entry.encode_index_entry().len(),
        PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN
    );
    assert_eq!(
        PersistParseArtifactIndexEntry::decode_index_entry(&encoded)
            .expect("parse artifact entry decodes"),
        entry
    );
}

#[test]
fn parse_artifact_index_entries_reject_invalid_prefixes() {
    let error = PersistParseArtifactIndexEntry::decode_index_entry(&[0; 8])
        .expect_err("short parse artifact entry errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortParseArtifactIndexEntry {
            expected: PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN,
            actual: 8,
        }
    );

    let key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 1; in x"));
    let value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized parse artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let entry = PersistParseArtifactIndexEntry::new(key, value);

    let mut invalid_key = entry.encode_index_entry();
    invalid_key[0] = 99;
    let error = PersistParseArtifactIndexEntry::decode_index_entry(&invalid_key)
        .expect_err("bad entry key tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidParseArtifactIndexTag { tag: 99 }
    );

    let mut invalid_value = entry.encode_index_entry();
    invalid_value[PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN] = PersistBlobStore::Values.index_tag();
    let error = PersistParseArtifactIndexEntry::decode_index_entry(&invalid_value)
        .expect_err("bad entry value store errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidParseArtifactBlobStore {
            store: PersistBlobStore::Values,
        }
    );
}

#[test]
fn parse_artifact_index_appends_and_finds_latest_matching_entry() {
    let root = temp_root();
    let index_path = root.join("nodes").join("parse-artifacts.index");
    let index = PersistParseArtifactIndex::open(&index_path).expect("index opens");
    let key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 1; in x"));
    let other_key =
        PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 2; in x"));
    let first = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let other = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"other artifact"),
        PersistBlobLocation::new(789, 10),
    );
    let latest = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest artifact"),
        PersistBlobLocation::new(999, 11),
    );

    assert_eq!(index.path(), index_path.as_path());
    assert_eq!(index.lookup(key).expect("empty lookup succeeds"), None);

    index
        .append_entry(PersistParseArtifactIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistParseArtifactIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistParseArtifactIndexEntry::new(key, latest))
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
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn parse_artifact_index_compacts_to_latest_entries() {
    let root = temp_root();
    let index_path = root.join("nodes").join("parse-artifacts.index");
    let index = PersistParseArtifactIndex::open(&index_path).expect("index opens");
    let key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 1; in x"));
    let other_key =
        PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 2; in x"));
    let first = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let other = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"other artifact"),
        PersistBlobLocation::new(789, 10),
    );
    let latest = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest artifact"),
        PersistBlobLocation::new(999, 11),
    );
    index
        .append_entry(PersistParseArtifactIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistParseArtifactIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistParseArtifactIndexEntry::new(key, latest))
        .expect("latest entry appends");

    let mut expected = vec![
        PersistParseArtifactIndexEntry::new(key, latest),
        PersistParseArtifactIndexEntry::new(other_key, other),
    ];
    expected.sort_by_key(|entry| entry.key().index_bytes());
    assert_eq!(
        index.latest_entries().expect("latest entries load"),
        expected
    );
    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * 3) as u64
    );

    assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);

    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
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
fn parse_artifact_index_open_rejects_truncated_records() {
    let root = temp_root();
    let index_path = root.join("nodes").join("parse-artifacts.index");
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, b"partial").expect("partial index writes");

    let error = PersistParseArtifactIndex::open(&index_path).expect_err("truncated index errors");

    assert!(matches!(
        error,
        PersistParseArtifactIndexError::Format {
            source: PersistPackFormatError::ShortParseArtifactIndexEntry {
                expected: PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN,
                actual: 7,
            },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn parse_artifact_index_lookup_rejects_malformed_records() {
    let root = temp_root();
    let index_path = root.join("nodes").join("parse-artifacts.index");
    let key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let x = 1; in x"));
    let value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized parse artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let mut encoded = PersistParseArtifactIndexEntry::new(key, value).encode_index_entry();
    encoded[0] = 99;
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, encoded).expect("malformed index writes");
    let index = PersistParseArtifactIndex::open(&index_path).expect("index opens by length");

    let error = index.lookup(key).expect_err("malformed record errors");

    assert!(matches!(
        error,
        PersistParseArtifactIndexError::Format {
            source: PersistPackFormatError::InvalidParseArtifactIndexTag { tag: 99 },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}
