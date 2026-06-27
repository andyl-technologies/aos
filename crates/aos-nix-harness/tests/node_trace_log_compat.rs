//! Cross-crate node trace log format compatibility checks.
//!
//! These tests prove the safe oracle-side typed node trace wrapper and the
//! engine-side generic variable-length log wrapper agree on the current
//! `nodes/traces.log` format.

use ratchet_cache::node_trace_log::{
    NodeTraceLog, NodeTraceLogEntry, NodeTraceLogKey, NodeTraceLogValueHash,
};
use ratchet_oracle::cache::{
    CacheableInputFingerprint, DurableBlake3Hash, ImpureInputKind, ImpureInputMode,
    PersistNodeMetadataKey, PersistNodeTraceLog, PersistNodeTraceLogEntry,
    PersistNodeTraceLogError, PersistNodeTraceLogFormatError, PersistNodeTracePayload,
    PersistPackFormatError, ValueHash,
};

fn engine_key_from_oracle(key: PersistNodeMetadataKey) -> NodeTraceLogKey {
    let encoded = key.index_bytes();
    let mut digest = [0; 32];
    digest.copy_from_slice(&encoded[1..]);
    NodeTraceLogKey::new(encoded[0], digest)
}

fn engine_value_hash_from_oracle(value_hash: ValueHash) -> NodeTraceLogValueHash {
    NodeTraceLogValueHash::from_bytes(value_hash.as_durable_hash().as_bytes())
}

fn oracle_key(name: &[u8]) -> PersistNodeMetadataKey {
    PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(name))
}

fn oracle_value_hash(name: &[u8]) -> ValueHash {
    ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(name))
}

fn trace_payload(subject: &[u8], hash_byte: u8) -> PersistNodeTracePayload {
    let input = CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::ReadFile,
        ImpureInputMode::Default,
        subject,
        DurableBlake3Hash::from_bytes([hash_byte; 32]),
    )
    .expect("input fingerprint builds");
    PersistNodeTracePayload::from_cacheable_inputs([input]).expect("trace payload builds")
}

#[test]
fn oracle_node_trace_writer_is_readable_by_engine_log() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let log_path = temp.path().join("nodes").join("traces.log");
    let oracle = PersistNodeTraceLog::open(&log_path).expect("oracle trace log opens");
    let key = oracle_key(b"oracle node");
    let value_hash = oracle_value_hash(b"oracle value");
    let payload = trace_payload(b"/src/oracle", 7);

    oracle
        .append_entry(PersistNodeTraceLogEntry::new(
            key,
            value_hash,
            payload.clone(),
        ))
        .expect("node trace entry appends through oracle");

    let engine = NodeTraceLog::open(&log_path).expect("engine trace log opens oracle sidecar");
    let engine_entry = engine
        .lookup(engine_key_from_oracle(key))
        .expect("engine lookup succeeds")
        .expect("trace entry exists");

    assert_eq!(
        engine_entry.value_hash(),
        engine_value_hash_from_oracle(value_hash)
    );
    assert_eq!(
        engine_entry.payload(),
        payload.encode().expect("payload encodes").as_slice()
    );
}

#[test]
fn engine_node_trace_writer_is_readable_by_oracle_log() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let log_path = temp.path().join("nodes").join("traces.log");
    let engine = NodeTraceLog::open(&log_path).expect("engine trace log opens");
    let key = oracle_key(b"engine node");
    let value_hash = oracle_value_hash(b"engine value");
    let payload = trace_payload(b"/src/engine", 8);

    engine
        .append_entry(NodeTraceLogEntry::new(
            engine_key_from_oracle(key),
            engine_value_hash_from_oracle(value_hash),
            payload.encode().expect("payload encodes"),
        ))
        .expect("node trace entry appends through engine");

    let oracle = PersistNodeTraceLog::open(&log_path).expect("oracle trace log opens");

    assert_eq!(
        oracle
            .lookup(key)
            .expect("oracle lookup succeeds through engine log"),
        Some(PersistNodeTraceLogEntry::new(key, value_hash, payload))
    );
}

#[test]
fn oracle_rejects_engine_node_trace_log_with_unknown_namespace_on_open() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let log_path = temp.path().join("nodes").join("traces.log");
    let engine = NodeTraceLog::open(&log_path).expect("engine trace log opens");
    let payload = trace_payload(b"/src/generic", 9);
    engine
        .append_entry(NodeTraceLogEntry::new(
            NodeTraceLogKey::new(99, DurableBlake3Hash::for_bytes(b"generic node").as_bytes()),
            engine_value_hash_from_oracle(oracle_value_hash(b"generic value")),
            payload.encode().expect("payload encodes"),
        ))
        .expect("generic engine accepts unknown namespace");

    let error = PersistNodeTraceLog::open(&log_path)
        .expect_err("oracle rejects unknown node trace namespace during open scan");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::Format {
            source: PersistNodeTraceLogFormatError::Key {
                source: PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: 99 },
            },
            ..
        }
    ));
}

#[test]
fn oracle_rejects_stale_malformed_engine_node_trace_payload_on_open() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let log_path = temp.path().join("nodes").join("traces.log");
    let engine = NodeTraceLog::open(&log_path).expect("engine trace log opens");
    let key = oracle_key(b"node");
    let stale_value_hash = oracle_value_hash(b"stale value");
    let latest_value_hash = oracle_value_hash(b"latest value");
    let mut malformed_stale = trace_payload(b"/src/stale", 10)
        .encode()
        .expect("stale payload encodes");
    malformed_stale[0] = b'X';
    let latest_payload = trace_payload(b"/src/latest", 11);

    engine
        .append_entry(NodeTraceLogEntry::new(
            engine_key_from_oracle(key),
            engine_value_hash_from_oracle(stale_value_hash),
            malformed_stale,
        ))
        .expect("malformed stale record appends through generic engine");
    engine
        .append_entry(NodeTraceLogEntry::new(
            engine_key_from_oracle(key),
            engine_value_hash_from_oracle(latest_value_hash),
            latest_payload.encode().expect("latest payload encodes"),
        ))
        .expect("latest record appends through generic engine");

    let error = PersistNodeTraceLog::open(&log_path)
        .expect_err("oracle validates stale trace records before open succeeds");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::Format {
            source: PersistNodeTraceLogFormatError::Payload { .. },
            ..
        }
    ));
}

#[test]
fn oracle_append_rejects_existing_malformed_engine_node_trace_payload() {
    let temp = tempfile::tempdir().expect("tempdir creates");
    let log_path = temp.path().join("nodes").join("traces.log");
    let oracle = PersistNodeTraceLog::open(&log_path).expect("oracle trace log opens");
    let engine = NodeTraceLog::open(&log_path).expect("engine trace log opens");
    let key = oracle_key(b"node");
    let mut malformed = trace_payload(b"/src/stale", 12)
        .encode()
        .expect("payload encodes");
    malformed[0] = b'X';

    engine
        .append_entry(NodeTraceLogEntry::new(
            engine_key_from_oracle(key),
            engine_value_hash_from_oracle(oracle_value_hash(b"stale value")),
            malformed,
        ))
        .expect("malformed record appends through generic engine");

    let error = oracle
        .append_entry(PersistNodeTraceLogEntry::new(
            key,
            oracle_value_hash(b"latest value"),
            trace_payload(b"/src/latest", 13),
        ))
        .expect_err("oracle append validates existing trace records first");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::Format {
            source: PersistNodeTraceLogFormatError::Payload { .. },
            ..
        }
    ));
}
