//! Tests for routed blob I/O and materialization decisions on the cache.

use super::*;
use crate::cache::cutoff::CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION;
use crate::cache::{
    CacheableInputFingerprint, CachedExpressionValue, CachedExpressionValuePayloadError,
    ImpureInputFingerprint, ImpureInputIdentity, ImpureInputKind, ImpureInputRevalidator,
    ValueHash,
};
use crate::value::Value;

#[derive(Clone, Debug)]
struct StaticRevalidator {
    trace: Vec<ImpureInputFingerprint>,
    calls: usize,
}

impl StaticRevalidator {
    fn new(trace: Vec<ImpureInputFingerprint>) -> Self {
        Self { trace, calls: 0 }
    }

    const fn calls(&self) -> usize {
        self.calls
    }
}

impl ImpureInputRevalidator for StaticRevalidator {
    fn revalidate_impure_input(
        &mut self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        self.calls = self.calls.saturating_add(1);
        self.trace.iter().find_map(|fingerprint| {
            let cacheable = fingerprint.as_cacheable()?;
            if cacheable.identity() == identity {
                Some(fingerprint.clone())
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug)]
struct FixedRevalidator {
    fingerprint: ImpureInputFingerprint,
    calls: usize,
}

impl FixedRevalidator {
    const fn new(fingerprint: ImpureInputFingerprint) -> Self {
        Self {
            fingerprint,
            calls: 0,
        }
    }

    const fn calls(&self) -> usize {
        self.calls
    }
}

impl ImpureInputRevalidator for FixedRevalidator {
    fn revalidate_impure_input(
        &mut self,
        _identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        self.calls = self.calls.saturating_add(1);
        Some(self.fingerprint.clone())
    }
}

fn test_read_file_fingerprint(subject: &[u8], hash_byte: u8) -> CacheableInputFingerprint {
    CacheableInputFingerprint::from_observation_hash(
        ImpureInputKind::ReadFile,
        ImpureInputMode::Default,
        subject,
        DurableBlake3Hash::from_bytes([hash_byte; 32]),
    )
    .expect("persisted readFile input builds")
}

fn test_node_trace_payload(subject: &[u8], hash_byte: u8) -> PersistNodeTracePayload {
    let input = test_read_file_fingerprint(subject, hash_byte);
    PersistNodeTracePayload::from_cacheable_inputs([input]).expect("trace payload builds")
}

fn noncanonical_context_string_payload() -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION);
    encoded.extend_from_slice(b"string");
    encoded.extend_from_slice(&0u128.to_le_bytes());
    encoded.extend_from_slice(b"context");
    encoded.extend_from_slice(&2u128.to_le_bytes());
    for path in [b"/nix/store/z".as_slice(), b"/nix/store/a".as_slice()] {
        encoded.push(0);
        encoded.extend_from_slice(&(path.len() as u128).to_le_bytes());
        encoded.extend_from_slice(path);
    }
    encoded
}

#[test]
fn cache_blob_io_is_routed_by_key_store() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"shared payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let value_key = PersistBlobKey::for_value(hash);
    let file_key = PersistBlobKey::for_file(hash);

    let value_location = cache
        .append_blob(value_key, payload)
        .expect("value blob appends");
    let file_location = cache
        .append_blob(file_key, payload)
        .expect("file blob appends");

    assert_eq!(
        value_location.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        file_location.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        cache
            .read_blob(value_key, value_location)
            .expect("value blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(
        cache
            .read_blob(file_key, file_location)
            .expect("file blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_io_updates_index_and_reads_by_key() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"indexed payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let same_hash_file_key = PersistBlobKey::for_file(key.hash());

    let entry = cache
        .append_blob_indexed(key, payload)
        .expect("indexed blob appends");

    assert_eq!(entry.key(), key);
    assert_eq!(
        entry.location().record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(entry.location())
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(same_hash_file_key)
            .expect("other store lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_read_returns_none_on_miss() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"missing"));

    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("lookup miss succeeds"),
        None
    );
    assert_eq!(
        cache.read_blob_indexed(key).expect("read miss succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_append_rejects_hash_mismatch_before_index_write() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

    let error = cache
        .append_blob_indexed(key, b"payload")
        .expect_err("hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::Append {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_io_rejects_payload_hash_mismatch() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

    let error = cache
        .append_blob(key, b"payload")
        .expect_err("hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_index_records_and_looks_up_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let other_key = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let value = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );

    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
        .expect("file artifact index entry records");

    assert_eq!(
        cache
            .lookup_file_artifact(key)
            .expect("file artifact lookup succeeds"),
        Some(value)
    );
    assert_eq!(
        cache
            .lookup_file_artifact(other_key)
            .expect("file artifact miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_index_records_and_looks_up_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let value = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3));

    cache
        .record_node_metadata(PersistNodeMetadataIndexEntry::new(key, value))
        .expect("node metadata index entry records");

    assert_eq!(
        cache
            .lookup_node_metadata(key)
            .expect("node metadata lookup succeeds"),
        Some(value)
    );
    assert_eq!(
        cache
            .lookup_node_metadata(other_key)
            .expect("node metadata miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_trace_log_records_and_looks_up_payloads() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let first_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let latest_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"latest value"));
    let first = test_node_trace_payload(b"/src/first", 1);
    let latest = test_node_trace_payload(b"/src/latest", 2);

    assert_eq!(
        cache.node_trace_log().path(),
        cache.layout().node_trace_log_path().as_path()
    );
    assert_eq!(
        cache
            .lookup_node_trace(key)
            .expect("empty trace lookup succeeds"),
        None
    );

    cache
        .record_node_trace(key, first_value_hash, &first)
        .expect("first node trace records");
    cache
        .record_node_trace(key, latest_value_hash, &latest)
        .expect("latest node trace records");

    assert_eq!(
        cache
            .lookup_node_trace(key)
            .expect("node trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            latest_value_hash,
            latest.clone()
        ))
    );
    assert_eq!(
        cache
            .lookup_node_trace(other_key)
            .expect("node trace miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        (PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN * 2) as u64
            + first.encode().expect("first payload encodes").len() as u64
            + latest.encode().expect("latest payload encodes").len() as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_materialization_reuse_records_and_looks_up_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let reuse = MaterializationReuse::new(2, 3);

    cache
        .record_node_materialization_reuse(key, reuse)
        .expect("node reuse records");

    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(reuse)
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(other_key)
            .expect("node reuse miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_preserves_reuse_and_materialized_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");

    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3)
    );
    assert_eq!(metadata.materialized_value_hash(), Some(value_hash));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(5, 6))
        .expect("node reuse update records");
    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(5, 6)
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_clear_materialized_value_hash_preserves_reuse() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");

    assert!(
        cache
            .clear_node_materialized_value_hash(key)
            .expect("value hash clears")
    );
    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3)
    );
    assert_eq!(metadata.materialized_value_hash(), None);
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        None
    );
    assert!(
        !cache
            .clear_node_materialized_value_hash(key)
            .expect("second value hash clear is a no-op")
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_current_demand_updates_latest_reuse_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));

    let first = cache
        .record_node_current_demand(key)
        .expect("first demand records");
    assert_eq!(first, MaterializationReuse::new(0, 1));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(7, u64::MAX))
        .expect("saturated reuse records");
    let saturated = cache
        .record_node_current_demand(key)
        .expect("saturating demand records");

    assert_eq!(saturated, MaterializationReuse::new(7, u64::MAX));
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(saturated)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_materialization_decision_uses_prior_reuse_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let missing =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing input"));
    let profitable = MaterializationCosts::new(100, 10, 20, 30);
    let equal_cost = MaterializationCosts::new(60, 10, 20, 30);

    assert_eq!(
        cache
            .node_materialization_signals(missing, profitable)
            .expect("missing signals build"),
        MaterializationReuse::default().signals(profitable)
    );
    assert_eq!(
        cache
            .node_materialization_decision(missing, profitable)
            .expect("missing decision succeeds"),
        MaterializationDecision::KeepInMemory
    );

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(0, 3))
        .expect("same-run reuse records");
    assert_eq!(
        cache
            .node_materialization_decision(key, profitable)
            .expect("same-run decision succeeds"),
        MaterializationDecision::KeepInMemory,
        "current-run demand must not predict cross-run reuse before advancement"
    );

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 0))
        .expect("prior-run reuse records");
    let metadata_len = fs::metadata(cache.node_metadata_index().path())
        .expect("node metadata index metadata")
        .len();
    let value_pack_len = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    assert_eq!(
        cache
            .node_materialization_signals(key, profitable)
            .expect("prior-run signals build"),
        MaterializationReuse::new(2, 0).signals(profitable)
    );
    assert_eq!(
        cache
            .node_materialization_decision(key, profitable)
            .expect("profitable decision succeeds"),
        MaterializationDecision::Materialize
    );
    assert_eq!(
        cache
            .node_materialization_decision(key, equal_cost)
            .expect("equal-cost decision succeeds"),
        MaterializationDecision::KeepInMemory,
        "prior reuse alone does not materialize when write cost is not lower"
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        metadata_len,
        "decision helpers must not append metadata"
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        value_pack_len,
        "decision helpers must not write payloads"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_materialization_reuse_advances_run_boundaries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let missing =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    assert_eq!(
        cache
            .advance_node_materialization_reuse_run(missing)
            .expect("missing advance succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        0
    );

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(u64::MAX - 1, 2))
        .expect("reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");
    let advanced = cache
        .advance_node_materialization_reuse_run(key)
        .expect("advance records");

    assert_eq!(advanced, Some(MaterializationReuse::new(u64::MAX, 0)));
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        advanced
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_all_node_materialization_reuse_advances_changed_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"first"));
    let second_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"second"));
    let third_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"third"));
    let first_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let third_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"third value"));

    cache
        .record_node_materialization_reuse(first_key, MaterializationReuse::new(1, 2))
        .expect("first reuse records");
    cache
        .record_node_materialization_reuse(second_key, MaterializationReuse::new(9, 0))
        .expect("second reuse records");
    cache
        .record_node_materialization_reuse(first_key, MaterializationReuse::new(4, 5))
        .expect("first latest reuse records");
    cache
        .record_node_materialized_value_hash(first_key, first_hash)
        .expect("first value hash records");
    cache
        .record_node_materialization_reuse(third_key, MaterializationReuse::new(u64::MAX - 1, 3))
        .expect("third reuse records");
    cache
        .record_node_materialized_value_hash(third_key, third_hash)
        .expect("third value hash records");

    let advanced = cache
        .advance_all_node_materialization_reuse_runs()
        .expect("all node reuse advances");

    assert_eq!(advanced.len(), 2);
    assert!(
        advanced
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key())
    );
    assert!(advanced.contains(&PersistNodeMetadataIndexEntry::new(
        first_key,
        PersistNodeMetadataIndexValue::with_materialized_value_hash(
            MaterializationReuse::new(9, 0),
            first_hash
        )
    )));
    assert!(advanced.contains(&PersistNodeMetadataIndexEntry::new(
        third_key,
        PersistNodeMetadataIndexValue::with_materialized_value_hash(
            MaterializationReuse::new(u64::MAX, 0),
            third_hash
        )
    )));
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(second_key)
            .expect("second lookup succeeds"),
        Some(MaterializationReuse::new(9, 0))
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(first_key)
            .expect("first value hash lookup succeeds"),
        Some(first_hash)
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(third_key)
            .expect("third value hash lookup succeeds"),
        Some(third_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 8) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_compacts_to_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let other_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"other value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("stale reuse records");
    cache
        .record_node_materialization_reuse(other_key, MaterializationReuse::new(3, 4))
        .expect("other reuse records");
    cache
        .record_node_materialized_value_hash(other_key, other_value_hash)
        .expect("other value hash records");
    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(5, 6))
        .expect("latest reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");

    assert_eq!(cache.compact_node_metadata().expect("metadata compacts"), 2);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(5, 6))
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(other_key)
            .expect("other node reuse lookup succeeds"),
        Some(MaterializationReuse::new(3, 4))
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(other_key)
            .expect("other value hash lookup succeeds"),
        Some(other_value_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 2) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_decision_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

    let result = cache
        .materialize_blob(key, b"payload", MaterializationDecision::KeepInMemory)
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(result.index_entry(key), None);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_decision_appends_when_requested() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

    let result = cache
        .materialize_blob(key, payload, MaterializationDecision::Materialize)
        .expect("materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
    assert_eq!(
        location.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        result.index_entry(key),
        Some(PersistBlobIndexEntry::new(key, location))
    );
    assert_eq!(
        cache
            .read_blob(key, location)
            .expect("materialized blob reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_decision_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

    let result = cache
        .materialize_blob_indexed(key, b"payload", MaterializationDecision::KeepInMemory)
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(result.index_entry(key), None);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_decision_appends_and_indexes_when_requested() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

    let result = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
    assert_eq!(
        result.index_entry(key),
        Some(PersistBlobIndexEntry::new(key, location))
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_materialization_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::context_free_string(b"cached string".to_vec());

    let result = cache
        .materialize_cached_expression_value_indexed(
            &payload,
            MaterializationDecision::KeepInMemory,
        )
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash.as_durable_hash());

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed blob reads")
            .expect("indexed blob exists")
            .as_slice(),
        payload
            .encode_persistent_payload()
            .expect("payload encodes")
            .as_slice()
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("payload loads")
            .expect("payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_empty_list_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::empty_list();
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash.as_durable_hash());

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("empty list payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("empty list payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("empty list payload loads")
            .expect("empty list payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_materialization_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::context_free_string(b"cached string".to_vec());

    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::KeepInMemory,
        )
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(
        cache
            .lookup_node_metadata(node_key)
            .expect("node metadata lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_materializes_and_loads_by_node_key() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");

    cache
        .record_node_materialization_reuse(node_key, MaterializationReuse::new(2, 3))
        .expect("reuse records");
    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");

    assert!(matches!(result, PersistMaterialization::Materialized(_)));
    let metadata = cache
        .lookup_node_metadata(node_key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3)
    );
    assert_eq!(metadata.materialized_value_hash(), Some(value_hash));
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("node payload loads")
            .expect("node payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_load_with_trace_revalidation_hits_matching_trace() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let input = test_read_file_fingerprint(b"/tmp/source", 7);
    let trace_payload =
        PersistNodeTracePayload::from_cacheable_inputs([input.clone()]).expect("trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &trace_payload)
        .expect("trace records");

    let mut revalidator = StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("trace-verified payload lookup succeeds"),
        Some(payload)
    );
    assert_eq!(revalidator.calls(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_misses_without_matching_trace() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let other_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"other value"));
    let input = test_read_file_fingerprint(b"/tmp/source", 7);
    let trace_payload =
        PersistNodeTracePayload::from_cacheable_inputs([input.clone()]).expect("trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");

    let mut missing_trace_revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(input.clone())]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(
                node_key,
                &mut missing_trace_revalidator,
            )
            .expect("missing trace lookup succeeds"),
        None
    );
    assert_eq!(missing_trace_revalidator.calls(), 0);

    cache
        .record_node_trace(node_key, other_value_hash, &trace_payload)
        .expect("mismatched trace records");
    let mut mismatched_trace_revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(
                node_key,
                &mut mismatched_trace_revalidator,
            )
            .expect("mismatched trace lookup succeeds"),
        None
    );
    assert_eq!(mismatched_trace_revalidator.calls(), 0);
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(node_key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_misses_on_stale_inputs() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let input = test_read_file_fingerprint(b"/tmp/source", 7);
    let changed_input = test_read_file_fingerprint(b"/tmp/source", 8);
    let other_identity_input = test_read_file_fingerprint(b"/tmp/other-source", 7);
    let trace_payload =
        PersistNodeTracePayload::from_cacheable_inputs([input.clone()]).expect("trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &trace_payload)
        .expect("trace records");

    let mut changed_revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(changed_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(
                node_key,
                &mut changed_revalidator,
            )
            .expect("changed trace lookup succeeds"),
        None
    );
    assert_eq!(changed_revalidator.calls(), 1);

    let mut unavailable_revalidator = StaticRevalidator::new(Vec::new());
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(
                node_key,
                &mut unavailable_revalidator,
            )
            .expect("unavailable trace lookup succeeds"),
        None
    );
    assert_eq!(unavailable_revalidator.calls(), 1);

    let mut different_identity_revalidator =
        FixedRevalidator::new(ImpureInputFingerprint::Cacheable(other_identity_input));
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(
                node_key,
                &mut different_identity_revalidator,
            )
            .expect("different-identity trace lookup succeeds"),
        None
    );
    assert_eq!(different_identity_revalidator.calls(), 1);

    let mut uncacheable_revalidator = FixedRevalidator::new(ImpureInputFingerprint::current_time());
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(
                node_key,
                &mut uncacheable_revalidator,
            )
            .expect("uncacheable trace lookup succeeds"),
        None
    );
    assert_eq!(uncacheable_revalidator.calls(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_misses_without_value_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let input = test_read_file_fingerprint(b"/tmp/source", 7);
    let trace_payload =
        PersistNodeTracePayload::from_cacheable_inputs([input.clone()]).expect("trace builds");

    cache
        .record_node_materialized_value_hash(node_key, value_hash)
        .expect("node value hash records");
    cache
        .record_node_trace(node_key, value_hash, &trace_payload)
        .expect("trace records");

    let mut revalidator = StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("missing value blob lookup succeeds"),
        None
    );
    assert_eq!(revalidator.calls(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_load_misses_without_linked_value() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let missing =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing"));
    let reuse_only =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"reuse-only"));

    cache
        .record_node_materialization_reuse(reuse_only, MaterializationReuse::new(2, 3))
        .expect("reuse records");

    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(missing)
            .expect("missing node lookup succeeds"),
        None
    );
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(reuse_only)
            .expect("reuse-only node lookup succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_load_rejects_noncanonical_indexed_bytes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = noncanonical_context_string_payload();
    let payload_hash = DurableBlake3Hash::for_bytes(&payload);
    let key = PersistBlobKey::for_value(payload_hash);
    cache
        .append_blob_indexed(key, &payload)
        .expect("manual non-canonical blob indexes");

    let error = cache
        .load_cached_expression_value_indexed(ValueHash::from_canonical_value_hash(payload_hash))
        .expect_err("non-canonical indexed payload errors");

    assert!(matches!(
        error,
        PersistCachedExpressionValueIndexedLoadError::Decode {
            source: CachedExpressionValuePayloadError::NonCanonicalStringContext { index: 1 }
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_materialization_signals_drive_writes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::path(b"/nix/store/source".to_vec());
    let value_hash = payload.value_hash().expect("payload hashes");

    let skipped = cache
        .materialize_cached_expression_value_indexed_with_signals(
            &payload,
            profitable_materialization_signals(false),
        )
        .expect("skip succeeds");
    assert_eq!(skipped, PersistMaterialization::Skipped);
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("missing payload lookup succeeds"),
        None
    );

    let written = cache
        .materialize_cached_expression_value_indexed_with_signals(
            &payload,
            profitable_materialization_signals(true),
        )
        .expect("write succeeds");
    assert!(matches!(written, PersistMaterialization::Materialized(_)));
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("payload loads")
            .expect("payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_materialization_signals_drive_writes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::path(b"/nix/store/source".to_vec());

    let skipped = cache
        .materialize_cached_expression_node_value_indexed_with_signals(
            node_key,
            &payload,
            profitable_materialization_signals(false),
        )
        .expect("skip succeeds");
    assert_eq!(skipped, PersistMaterialization::Skipped);
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("missing node payload lookup succeeds"),
        None
    );

    let written = cache
        .materialize_cached_expression_node_value_indexed_with_signals(
            node_key,
            &payload,
            profitable_materialization_signals(true),
        )
        .expect("write succeeds");
    assert!(matches!(written, PersistMaterialization::Materialized(_)));
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("node payload loads")
            .expect("node payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_decision_propagates_append_errors() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

    let error = cache
        .materialize_blob(key, b"payload", MaterializationDecision::Materialize)
        .expect_err("materialization hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_signals_append_when_threshold_passes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

    let result = cache
        .materialize_blob_indexed_with_signals(
            key,
            payload,
            profitable_materialization_signals(true),
        )
        .expect("indexed materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_signals_can_skip_without_hashing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

    let result = cache
        .materialize_blob_with_signals(key, b"payload", profitable_materialization_signals(false))
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(result.index_entry(key), None);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_signals_append_when_threshold_passes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

    let result = cache
        .materialize_blob_with_signals(key, payload, profitable_materialization_signals(true))
        .expect("materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
    assert_eq!(
        result.index_entry(key),
        Some(PersistBlobIndexEntry::new(key, location))
    );
    assert_eq!(
        cache
            .read_blob(key, location)
            .expect("materialized blob reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}
