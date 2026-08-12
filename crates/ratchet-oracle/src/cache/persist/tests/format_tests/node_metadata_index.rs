//! Node metadata index format tests.

use super::*;

#[test]
fn node_metadata_index_keys_cover_expression_identity_and_free_vars() {
    use crate::compile::IrId;

    let source = test_cache_expr_source_hash(b"source");
    let identity = CacheExprIdentity::new(source, IrId::new(7));
    let same = CacheExprIdentity::new(source, IrId::new(7));
    let source_changed =
        CacheExprIdentity::new(test_cache_expr_source_hash(b"other source"), IrId::new(7));
    let node_changed = CacheExprIdentity::new(source, IrId::new(8));
    let left = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"left"));
    let right = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"right"));

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
    let identity = test_impure_input_identity_hash(b"input identity");
    let other_identity = test_impure_input_identity_hash(b"other input identity");
    let key = PersistNodeMetadataKey::for_impure_input(identity);
    let same_key = PersistNodeMetadataKey::for_impure_input(identity);
    let other_key = PersistNodeMetadataKey::for_impure_input(other_identity);
    let expression_key = PersistNodeMetadataKey::for_expression(
        CacheExprIdentity::new(
            CacheExprSourceHash::from_persisted_hash(identity.as_durable_hash()),
            crate::compile::IrId::new(0),
        ),
        [ValueHash::from_canonical_value_hash(
            identity.as_durable_hash(),
        )],
    );

    assert_eq!(key, same_key);
    assert_eq!(key.hash(), same_key.hash());
    assert_ne!(key, other_key);
    assert_ne!(key, expression_key);
}

#[test]
fn node_metadata_index_keys_decode_and_reject_invalid_prefixes() {
    let key = test_impure_input_node_key(b"input");
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
    let key = test_impure_input_node_key(b"input");
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

    let key = test_impure_input_node_key(b"input");
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
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
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
    let first_key = test_impure_input_node_key(b"a");
    let second_key = test_impure_input_node_key(b"b");
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
    let first_key = test_impure_input_node_key(b"a");
    let second_key = test_impure_input_node_key(b"b");
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
    let key = test_impure_input_node_key(b"input");
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
