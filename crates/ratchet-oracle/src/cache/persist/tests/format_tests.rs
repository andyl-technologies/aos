//! Tests for the on-disk format primitives: blob/file-artifact keys, index
//! encodings, and node metadata.

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
}

#[test]
fn blob_index_keys_are_domain_separated_by_store() {
    let hash = DurableBlake3Hash::for_bytes(b"same bytes");
    let value_key = PersistBlobKey::for_value(hash).index_bytes();
    let file_key = PersistBlobKey::for_file(hash).index_bytes();

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
    let first_key = PersistBlobKey::for_value(first);
    let first_key_again = PersistBlobKey::for_value(first_again);
    let second_key = PersistBlobKey::for_value(second);

    assert_eq!(first_key.store(), PersistBlobStore::Values);
    assert_eq!(first_key.hash(), first);
    assert_eq!(first_key.index_bytes(), first_key_again.index_bytes());
    assert_ne!(first_key.index_bytes(), second_key.index_bytes());
}

#[test]
fn blob_index_keys_decode_and_reject_invalid_prefixes() {
    let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"payload"));
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
    let blob_hash = DurableBlake3Hash::for_bytes(b"serialized IR artifact");
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
        .copy_from_slice(&PersistBlobKey::for_value(blob_hash).index_bytes());
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
        DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
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
        DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
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
        DurableBlake3Hash::for_bytes(b"first artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let other = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"other artifact"),
        PersistBlobLocation::new(789, 10),
    );
    let latest = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"latest artifact"),
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
        DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
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
    assert_eq!(key.hash().as_bytes(), parse_key.as_bytes());
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
    let blob_hash = DurableBlake3Hash::for_bytes(b"serialized parse artifact");
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
        .copy_from_slice(&PersistBlobKey::for_value(blob_hash).index_bytes());
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
        DurableBlake3Hash::for_bytes(b"serialized parse artifact"),
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
        DurableBlake3Hash::for_bytes(b"serialized parse artifact"),
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
        DurableBlake3Hash::for_bytes(b"first artifact"),
        PersistBlobLocation::new(123, 456),
    );
    let other = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"other artifact"),
        PersistBlobLocation::new(789, 10),
    );
    let latest = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"latest artifact"),
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
        DurableBlake3Hash::for_bytes(b"serialized parse artifact"),
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

#[test]
fn node_metadata_index_keys_cover_expression_identity_and_free_vars() {
    use crate::compile::IrId;

    let source = DurableBlake3Hash::for_bytes(b"source");
    let identity = CacheExprIdentity::new(source, IrId::new(7));
    let same = CacheExprIdentity::new(source, IrId::new(7));
    let source_changed =
        CacheExprIdentity::new(DurableBlake3Hash::for_bytes(b"other source"), IrId::new(7));
    let node_changed = CacheExprIdentity::new(source, IrId::new(8));
    let left = DurableBlake3Hash::for_bytes(b"left");
    let right = DurableBlake3Hash::for_bytes(b"right");

    let key = PersistNodeMetadataKey::for_expression(identity, [left, right]);
    let same_key = PersistNodeMetadataKey::for_expression(same, [left, right]);
    let source_changed_key = PersistNodeMetadataKey::for_expression(source_changed, [left, right]);
    let node_changed_key = PersistNodeMetadataKey::for_expression(node_changed, [left, right]);
    let order_changed_key = PersistNodeMetadataKey::for_expression(identity, [right, left]);
    let file_key = PersistFileArtifactKey::from_parse_file_key(
        &ParseFileKey::for_source("/src/default.nix", b"source"),
        test_parse_key(b"source"),
    );
    let parse_key = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"source"));

    assert_eq!(key, same_key);
    assert_eq!(key.index_bytes().len(), PERSIST_NODE_METADATA_INDEX_KEY_LEN);
    assert_eq!(key.index_bytes()[0], PERSIST_NODE_METADATA_INDEX_TAG);
    assert_ne!(key, source_changed_key);
    assert_ne!(key, node_changed_key);
    assert_ne!(key, order_changed_key);
    assert_ne!(key.index_bytes(), file_key.index_bytes());
    assert_ne!(key.index_bytes(), parse_key.index_bytes());
}

#[test]
fn node_metadata_index_keys_cover_impure_input_identities() {
    let identity = DurableBlake3Hash::for_bytes(b"input identity");
    let other_identity = DurableBlake3Hash::for_bytes(b"other input identity");
    let key = PersistNodeMetadataKey::for_impure_input(identity);
    let same_key = PersistNodeMetadataKey::for_impure_input(identity);
    let other_key = PersistNodeMetadataKey::for_impure_input(other_identity);
    let expression_key = PersistNodeMetadataKey::for_expression(
        CacheExprIdentity::new(identity, crate::compile::IrId::new(0)),
        [identity],
    );

    assert_eq!(key, same_key);
    assert_eq!(key.hash(), same_key.hash());
    assert_ne!(key, other_key);
    assert_ne!(key, expression_key);
}

#[test]
fn node_metadata_index_keys_decode_and_reject_invalid_prefixes() {
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let mut encoded = key.index_bytes().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(
        PersistNodeMetadataKey::decode_index_bytes(&encoded).expect("node metadata key decodes"),
        key
    );

    let error = PersistNodeMetadataKey::decode_index_bytes(&[0; 8])
        .expect_err("short node metadata key errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortNodeMetadataIndexKey {
            expected: PERSIST_NODE_METADATA_INDEX_KEY_LEN,
            actual: 8,
        }
    );

    let mut invalid_tag = key.index_bytes();
    invalid_tag[0] = 99;
    let error = PersistNodeMetadataKey::decode_index_bytes(&invalid_tag)
        .expect_err("bad node metadata tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: 99 }
    );
}

#[test]
fn node_metadata_index_values_round_trip_reuse_metadata() {
    let reuse = MaterializationReuse::new(2, 3);
    let value = PersistNodeMetadataIndexValue::new(reuse);
    let mut encoded = value.encode_index_value().to_vec();
    encoded.extend_from_slice(b"trailing node metadata bytes");

    assert_eq!(value.materialization_reuse(), reuse);
    assert_eq!(value.materialized_value_hash(), None);
    assert_eq!(
        value.encode_index_value().len(),
        PERSIST_NODE_METADATA_INDEX_VALUE_LEN
    );
    assert_eq!(
        PersistNodeMetadataIndexValue::decode_index_value(&encoded)
            .expect("node metadata value decodes"),
        value
    );
}

#[test]
fn node_metadata_index_values_round_trip_materialized_value_hash() {
    let reuse = MaterializationReuse::new(2, 3);
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let value = PersistNodeMetadataIndexValue::with_materialized_value_hash(reuse, value_hash);

    let decoded = PersistNodeMetadataIndexValue::decode_index_value(&value.encode_index_value())
        .expect("node metadata value decodes");

    assert_eq!(decoded.materialization_reuse(), reuse);
    assert_eq!(decoded.materialized_value_hash(), Some(value_hash));
    assert_eq!(decoded, value);
}

#[test]
fn node_metadata_index_values_reject_short_prefix() {
    let error = PersistNodeMetadataIndexValue::decode_index_value(&[0; 8])
        .expect_err("short node metadata index value errors");

    assert_eq!(
        error,
        PersistPackFormatError::ShortNodeMetadataIndexValue {
            expected: PERSIST_NODE_METADATA_INDEX_VALUE_LEN,
            actual: 8,
        }
    );
}

#[test]
fn node_metadata_index_values_reject_malformed_value_hash_field() {
    let mut invalid_tag =
        PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3)).encode_index_value();
    invalid_tag[PERSIST_MATERIALIZATION_REUSE_LEN] = 99;
    let error = PersistNodeMetadataIndexValue::decode_index_value(&invalid_tag)
        .expect_err("invalid value hash tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidNodeMetadataValueHashTag { tag: 99 }
    );

    let mut nonzero_absent =
        PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3)).encode_index_value();
    nonzero_absent[PERSIST_MATERIALIZATION_REUSE_LEN + 1] = 1;
    let error = PersistNodeMetadataIndexValue::decode_index_value(&nonzero_absent)
        .expect_err("nonzero absent value hash errors");
    assert_eq!(
        error,
        PersistPackFormatError::NonZeroNodeMetadataValueHashPadding
    );
}

#[test]
fn node_metadata_index_entries_round_trip_key_value_records() {
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value = PersistNodeMetadataIndexValue::with_materialized_value_hash(
        MaterializationReuse::new(2, 3),
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value")),
    );
    let entry = PersistNodeMetadataIndexEntry::new(key, value);
    let mut encoded = entry.encode_index_entry().to_vec();
    encoded.extend_from_slice(b"trailing index bytes");

    assert_eq!(entry.key(), key);
    assert_eq!(entry.value(), value);
    assert_eq!(
        entry.encode_index_entry().len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN
    );
    assert_eq!(
        PersistNodeMetadataIndexEntry::decode_index_entry(&encoded)
            .expect("node metadata entry decodes"),
        entry
    );
}

#[test]
fn node_metadata_index_entries_reject_invalid_prefixes() {
    let error = PersistNodeMetadataIndexEntry::decode_index_entry(&[0; 8])
        .expect_err("short node metadata entry errors");
    assert_eq!(
        error,
        PersistPackFormatError::ShortNodeMetadataIndexEntry {
            expected: PERSIST_NODE_METADATA_INDEX_ENTRY_LEN,
            actual: 8,
        }
    );

    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3));
    let entry = PersistNodeMetadataIndexEntry::new(key, value);

    let mut invalid_key = entry.encode_index_entry();
    invalid_key[0] = 99;
    let error = PersistNodeMetadataIndexEntry::decode_index_entry(&invalid_key)
        .expect_err("bad entry key tag errors");
    assert_eq!(
        error,
        PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: 99 }
    );
}

#[test]
fn node_metadata_index_appends_and_finds_latest_matching_entry() {
    let root = temp_root();
    let index_path = root.join("nodes").join("metadata.index");
    let index = PersistNodeMetadataIndex::open(&index_path).expect("index opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let first = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(1, 2));
    let other = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(3, 4));
    let latest = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(5, 6));

    assert_eq!(index.path(), index_path.as_path());
    assert_eq!(index.lookup(key).expect("empty lookup succeeds"), None);

    index
        .append_entry(PersistNodeMetadataIndexEntry::new(key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistNodeMetadataIndexEntry::new(other_key, other))
        .expect("other entry appends");
    index
        .append_entry(PersistNodeMetadataIndexEntry::new(key, latest))
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
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_metadata_index_lists_latest_entries_in_key_order() {
    let root = temp_root();
    let index_path = root.join("nodes").join("metadata.index");
    let index = PersistNodeMetadataIndex::open(&index_path).expect("index opens");
    let first_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"a"));
    let second_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"b"));
    let first = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(1, 2));
    let second = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(3, 4));
    let latest = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(5, 6));

    assert_eq!(
        index.latest_entries().expect("empty latest entries"),
        Vec::new()
    );

    index
        .append_entry(PersistNodeMetadataIndexEntry::new(second_key, second))
        .expect("second entry appends");
    index
        .append_entry(PersistNodeMetadataIndexEntry::new(first_key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistNodeMetadataIndexEntry::new(second_key, latest))
        .expect("latest entry appends");

    let entries = index.latest_entries().expect("latest entries load");
    assert_eq!(entries.len(), 2);
    assert!(entries.windows(2).all(|pair| pair[0].key() < pair[1].key()));
    assert!(entries.contains(&PersistNodeMetadataIndexEntry::new(first_key, first)));
    assert!(entries.contains(&PersistNodeMetadataIndexEntry::new(second_key, latest)));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_metadata_index_compacts_to_latest_entries() {
    let root = temp_root();
    let index_path = root.join("nodes").join("metadata.index");
    let index = PersistNodeMetadataIndex::open(&index_path).expect("index opens");
    let first_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"a"));
    let second_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"b"));
    let first = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(1, 2));
    let stale = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(3, 4));
    let latest = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(5, 6));

    index
        .append_entry(PersistNodeMetadataIndexEntry::new(second_key, stale))
        .expect("stale entry appends");
    index
        .append_entry(PersistNodeMetadataIndexEntry::new(first_key, first))
        .expect("first entry appends");
    index
        .append_entry(PersistNodeMetadataIndexEntry::new(second_key, latest))
        .expect("latest entry appends");

    assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);
    assert_eq!(
        fs::metadata(index.path()).expect("index metadata").len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(index.lookup(first_key).expect("first lookup"), Some(first));
    assert_eq!(
        index.lookup(second_key).expect("second lookup"),
        Some(latest)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_metadata_index_open_rejects_truncated_records() {
    let root = temp_root();
    let index_path = root.join("nodes").join("metadata.index");
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, b"partial").expect("partial index writes");

    let error = PersistNodeMetadataIndex::open(&index_path).expect_err("truncated index errors");

    assert!(matches!(
        error,
        PersistNodeMetadataIndexError::Format {
            source: PersistPackFormatError::ShortNodeMetadataIndexEntry {
                expected: PERSIST_NODE_METADATA_INDEX_ENTRY_LEN,
                actual: 7,
            },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn node_metadata_index_lookup_rejects_malformed_records() {
    let root = temp_root();
    let index_path = root.join("nodes").join("metadata.index");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3));
    let mut encoded = PersistNodeMetadataIndexEntry::new(key, value).encode_index_entry();
    encoded[0] = 99;
    fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
    fs::write(&index_path, encoded).expect("malformed index writes");
    let index = PersistNodeMetadataIndex::open(&index_path).expect("index opens by length");

    let error = index.lookup(key).expect_err("malformed record errors");

    assert!(matches!(
        error,
        PersistNodeMetadataIndexError::Format {
            source: PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: 99 },
            ..
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn materialization_reuse_metadata_round_trips_counters() {
    let reuse = MaterializationReuse::new(2, 3);
    let encoded = reuse.encode_persist_metadata();
    let mut prefixed = encoded.to_vec();
    prefixed.extend_from_slice(b"trailing metadata bytes");

    assert_eq!(encoded.len(), PERSIST_MATERIALIZATION_REUSE_LEN);
    assert_eq!(&encoded[..8], 2u64.to_le_bytes().as_slice());
    assert_eq!(&encoded[8..16], 3u64.to_le_bytes().as_slice());
    assert_eq!(
        MaterializationReuse::decode_persist_metadata(&prefixed).expect("reuse metadata decodes"),
        reuse
    );
}

#[test]
fn materialization_reuse_metadata_rejects_short_prefix() {
    let error = MaterializationReuse::decode_persist_metadata(&[0; 8])
        .expect_err("short reuse metadata errors");

    assert_eq!(
        error,
        PersistPackFormatError::ShortMaterializationReuseMetadata {
            expected: PERSIST_MATERIALIZATION_REUSE_LEN,
            actual: 8,
        }
    );
}

#[test]
fn blob_index_entries_round_trip_key_value_records() {
    let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"payload"));
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

    let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"payload"));
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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"payload"));
    let other_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"other payload"));
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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"payload"));
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
