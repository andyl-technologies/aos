//! Cross-crate node metadata sidecar format compatibility checks.
//!
//! These tests prove the safe oracle-side typed node metadata wrapper and the
//! engine-side generic fixed-record sidecar wrapper agree on the current
//! `nodes/metadata.index` format.

use ratchet_cache::node_metadata::{
    NodeMetadataEntry, NodeMetadataIndex, NodeMetadataKey, NodeMetadataValue,
};
use ratchet_oracle::cache::{
    DurableBlake3Hash, MaterializationReuse, PersistNodeMetadataIndex,
    PersistNodeMetadataIndexEntry, PersistNodeMetadataIndexError, PersistNodeMetadataIndexValue,
    PersistNodeMetadataKey, PersistPackFormatError, ValueHash,
};

fn engine_key_from_oracle(key: PersistNodeMetadataKey) -> NodeMetadataKey {
    let encoded = key.index_bytes();
    let mut digest = [0; 32];
    digest.copy_from_slice(&encoded[1..]);
    NodeMetadataKey::new(encoded[0], digest)
}

fn engine_value_from_oracle(value: PersistNodeMetadataIndexValue) -> NodeMetadataValue {
    NodeMetadataValue::from_bytes(value.encode_index_value())
}

fn oracle_key(name: &[u8]) -> PersistNodeMetadataKey {
    PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(name))
}

fn oracle_value(previous: u64, current: u64, name: &[u8]) -> PersistNodeMetadataIndexValue {
    PersistNodeMetadataIndexValue::with_materialized_value_hash(
        MaterializationReuse::new(previous, current),
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(name)),
    )
}

#[test]
fn oracle_node_metadata_writer_is_readable_by_engine_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("metadata.index");
    let oracle = PersistNodeMetadataIndex::open(&index_path).expect("oracle index opens");
    let key = oracle_key(b"oracle node");
    let value = oracle_value(2, 3, b"oracle value");

    oracle
        .append_entry(PersistNodeMetadataIndexEntry::new(key, value))
        .expect("node metadata entry appends through oracle");

    let engine = NodeMetadataIndex::open(&index_path).expect("engine index opens oracle sidecar");

    assert_eq!(
        engine
            .lookup(engine_key_from_oracle(key))
            .expect("engine lookup succeeds"),
        Some(engine_value_from_oracle(value))
    );
}

#[test]
fn engine_node_metadata_writer_is_readable_by_oracle_index() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("metadata.index");
    let engine = NodeMetadataIndex::open(&index_path).expect("engine index opens");
    let key = oracle_key(b"engine node");
    let value = oracle_value(5, 8, b"engine value");

    engine
        .append_entry(NodeMetadataEntry::new(
            engine_key_from_oracle(key),
            engine_value_from_oracle(value),
        ))
        .expect("node metadata entry appends through engine");

    let oracle = PersistNodeMetadataIndex::open(&index_path).expect("oracle index opens");

    assert_eq!(
        oracle
            .lookup(key)
            .expect("oracle lookup succeeds through engine sidecar"),
        Some(value)
    );
}

#[test]
fn oracle_rejects_engine_node_metadata_sidecar_with_unknown_namespace() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("metadata.index");
    let engine = NodeMetadataIndex::open(&index_path).expect("engine index opens");
    let key = oracle_key(b"valid node");
    let value = oracle_value(1, 1, b"value");
    engine
        .append_entry(NodeMetadataEntry::new(
            NodeMetadataKey::new(99, DurableBlake3Hash::for_bytes(b"generic node").as_bytes()),
            engine_value_from_oracle(value),
        ))
        .expect("generic engine accepts unknown namespace");
    let oracle = PersistNodeMetadataIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(key)
        .expect_err("oracle rejects unknown metadata namespace during scan");

    assert!(matches!(
        error,
        PersistNodeMetadataIndexError::Format {
            source: PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: 99 },
            ..
        }
    ));
}

#[test]
fn oracle_rejects_stale_malformed_engine_node_metadata_value() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let index_path = temp.path().join("nodes").join("metadata.index");
    let engine = NodeMetadataIndex::open(&index_path).expect("engine index opens");
    let key = oracle_key(b"node");
    let stale_value = oracle_value(1, 1, b"stale value");
    let latest_value = oracle_value(2, 3, b"latest value");
    let mut malformed_stale = stale_value.encode_index_value();
    malformed_stale[16] = 0;
    malformed_stale[17] = 1;

    engine
        .append_entry(NodeMetadataEntry::new(
            engine_key_from_oracle(key),
            NodeMetadataValue::from_bytes(malformed_stale),
        ))
        .expect("malformed stale record appends through generic engine");
    engine
        .append_entry(NodeMetadataEntry::new(
            engine_key_from_oracle(key),
            engine_value_from_oracle(latest_value),
        ))
        .expect("latest record appends through generic engine");
    let oracle = PersistNodeMetadataIndex::open(&index_path).expect("oracle index opens by length");

    let error = oracle
        .lookup(key)
        .expect_err("oracle validates stale records before newest lookup succeeds");

    assert!(matches!(
        error,
        PersistNodeMetadataIndexError::Format {
            source: PersistPackFormatError::NonZeroNodeMetadataValueHashPadding,
            ..
        }
    ));
}
