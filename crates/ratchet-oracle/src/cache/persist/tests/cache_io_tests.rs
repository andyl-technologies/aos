//! Tests for routed blob I/O and materialization decisions on the cache.

use super::*;
use crate::attrs::AttrPosition;
use crate::cache::cutoff::CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION;
use crate::cache::{
    CacheableInputFingerprint, CachedExpressionValue, CachedExpressionValuePayloadError,
    ImpureInputFingerprint, ImpureInputIdentity, ImpureInputKind, ImpureInputRevalidator,
    ValueHash,
};
use crate::string::{ContextElement, StringContext};
use crate::syntax::Span;
use crate::value::Value;
use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockError, AdvisoryFileLockMode};
use std::io::ErrorKind;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

mod blob_index_rebuild;
mod blob_sidecars;
mod metadata_sidecars;
mod node_metadata_io;
mod storage_maintenance;

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

fn wait_until_advisory_try_lock_blocks(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match AdvisoryFileLock::try_lock(path, AdvisoryFileLockMode::Exclusive) {
            Ok(lock) => drop(lock),
            Err(AdvisoryFileLockError::Lock { source, .. })
                if source.kind() == ErrorKind::WouldBlock =>
            {
                return;
            }
            Err(error) => panic!("advisory lock probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "worker did not acquire advisory lock before the deadline"
        );
        thread::sleep(Duration::from_millis(10));
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

fn all_context_kinds() -> StringContext {
    StringContext::new(vec![
        ContextElement::single_output(b"/nix/store/pkg.drv".to_vec(), b"out".to_vec())
            .expect("single-output context builds"),
        ContextElement::opaque_path(b"/nix/store/source".to_vec()).expect("opaque context builds"),
        ContextElement::deep_derivation(b"/nix/store/toolchain.drv".to_vec())
            .expect("deep context builds"),
    ])
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
fn cache_advance_node_reuse_run_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .advance_node_materialization_reuse_run(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("reuse advance result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let advanced = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reuse advance completes after same-process lock release")
        .expect("reuse advances");
    assert_eq!(advanced, Some(MaterializationReuse::new(3, 0)));
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after reuse advance");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(3, 0))
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
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
fn cache_advance_all_node_reuse_runs_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");
    cache
        .record_node_materialization_reuse(other_key, MaterializationReuse::new(5, 0))
        .expect("other reuse records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .advance_all_node_materialization_reuse_runs()
            .map_err(|error| error.to_string());
        tx.send(result).expect("all reuse advance result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let advanced = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("all reuse advance completes after same-process lock release")
        .expect("all reuse advances");
    assert_eq!(advanced.len(), 1);
    assert!(advanced.contains(&PersistNodeMetadataIndexEntry::new(
        key,
        PersistNodeMetadataIndexValue::with_materialized_value_hash(
            MaterializationReuse::new(3, 0),
            value_hash
        )
    )));
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after all reuse advance");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(3, 0))
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(other_key)
            .expect("other node reuse lookup succeeds"),
        Some(MaterializationReuse::new(5, 0))
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
fn cache_compact_node_metadata_acquires_advisory_metadata_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("stale reuse records");
    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(5, 6))
        .expect("latest reuse records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_node_metadata()
            .map_err(|error| error.to_string());
        tx.send(result)
            .expect("node metadata compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let retained = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("node metadata compaction completes after same-process lock release")
        .expect("node metadata compaction succeeds");
    assert_eq!(retained, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after compaction");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(5, 6))
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
fn cache_append_blob_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let payload = b"raw advisory payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .append_blob(key, payload)
            .map(|location| location.record_offset())
            .map_err(|error| error.to_string());
        tx.send(result).expect("append result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let record_offset = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("raw append completes after same-process lock release")
        .expect("raw append succeeds");
    assert_eq!(record_offset, PERSIST_BLOB_PACK_HEADER_LEN as u64);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.blob_store_lock_path(PersistBlobStore::Values),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("blob advisory lock releases after raw append");
    drop(released_lock);

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
fn cache_indexed_materialization_reuses_verified_existing_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let first = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("first indexed materialization succeeds");
    let PersistMaterialization::Materialized(first_location) = first else {
        panic!("first materialization should append");
    };
    let pack_len = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    let index_len = fs::metadata(cache.value_index().path())
        .expect("value index metadata")
        .len();

    let second = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("second indexed materialization succeeds");

    assert_eq!(second, PersistMaterialization::Materialized(first_location));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        pack_len
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        index_len
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_single_flights_cloned_cache_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = Arc::new(b"payload".to_vec());
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload.as_slice()));
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let worker_cache = cache.clone();
        let worker_payload = Arc::clone(&payload);
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            let result = worker_cache
                .materialize_blob_indexed(
                    key,
                    worker_payload.as_slice(),
                    MaterializationDecision::Materialize,
                )
                .expect("indexed materialization succeeds");
            let PersistMaterialization::Materialized(location) = result else {
                panic!("materialization should report a location");
            };
            location
        }));
    }

    let mut locations = Vec::new();
    for handle in handles {
        locations.push(handle.join().expect("worker should not panic"));
    }

    let first_location = *locations.first().expect("worker locations exist");
    assert!(locations.iter().all(|location| *location == first_location));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        1
    );
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("value index latest entries"),
        vec![PersistBlobIndexEntry::new(key, first_location)]
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload.as_slice()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_reports_poisoned_shared_clone_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = cache.clone();
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value write lock acquires");
        panic!("poison persistent value write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let error = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect_err("poisoned shared value lock should reject materialization");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
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
fn cache_indexed_materialization_single_flights_independently_opened_cache_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = Arc::new(b"payload".to_vec());
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload.as_slice()));
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_payload = Arc::clone(&payload);
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            let result = worker_cache
                .materialize_blob_indexed(
                    key,
                    worker_payload.as_slice(),
                    MaterializationDecision::Materialize,
                )
                .expect("indexed materialization succeeds");
            let PersistMaterialization::Materialized(location) = result else {
                panic!("materialization should report a location");
            };
            location
        }));
    }

    let mut locations = Vec::new();
    for handle in handles {
        locations.push(handle.join().expect("worker should not panic"));
    }

    let first_location = *locations.first().expect("worker locations exist");
    assert!(locations.iter().all(|location| *location == first_location));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        1
    );
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("value index latest entries"),
        vec![PersistBlobIndexEntry::new(key, first_location)]
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload.as_slice()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let payload = b"advisory indexed payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
            .map(|materialization| {
                matches!(materialization, PersistMaterialization::Materialized(_))
            })
            .map_err(|error| error.to_string());
        tx.send(result).expect("materialization result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let materialized = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("indexed materialization completes after same-process lock release")
        .expect("indexed materialization succeeds");
    assert!(materialized);
    handle.join().expect("worker joins");
    assert!(
        layout
            .blob_store_lock_path(PersistBlobStore::Values)
            .is_file()
    );
    let released_lock = AdvisoryFileLock::try_lock(
        layout.blob_store_lock_path(PersistBlobStore::Values),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("indexed blob advisory lock releases after materialization");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value write lock acquires");
        panic!("poison persistent value write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let error = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect_err("poisoned shared value lock should reject materialization");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
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
fn cache_append_blob_indexed_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let error = cache
        .append_blob_indexed(key, payload)
        .expect_err("poisoned shared value lock should reject indexed append");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
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
fn cache_append_blob_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-pack write lock acquires");
        panic!("poison persistent value blob-pack write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let error = cache
        .append_blob(key, payload)
        .expect_err("poisoned shared value lock should reject raw append");

    assert!(matches!(
        error,
        PersistBlobPackError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_compaction_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_blob_index(PersistBlobStore::Values)
            .map_err(|error| error.to_string());
        tx.send(result).expect("compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let compacted_entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-index compaction completes after same-process lock release")
        .expect("blob-index compaction succeeds");
    assert_eq!(compacted_entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_compaction_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .compact_blob_index(PersistBlobStore::Values)
        .expect_err("poisoned shared value lock should reject blob-index compaction");

    assert!(matches!(
        error,
        PersistBlobIndexError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .rebuild_blob_index_from_pack(PersistBlobStore::Values)
            .map(|plan| plan.planned_entries().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("rebuild result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let planned_entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-index rebuild completes after same-process lock release")
        .expect("blob-index rebuild succeeds");
    assert_eq!(planned_entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect_err("poisoned shared value lock should reject blob-index rebuild");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Values)
            .map(|trim| trim.reclaimed_bytes())
            .map_err(|error| error.to_string());
        tx.send(result).expect("tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let reclaimed_bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-pack tail trim completes after same-process lock release")
        .expect("blob-pack tail trim succeeds");
    assert_eq!(reclaimed_bytes, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let payload = b"rooted file artifact payload";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    let index_value = index_entry.value();
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    let tail_payload = b"unindexed file tail payload";
    let tail_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unindexed file tail appends");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + tail_payload.len() as u64;
    let expected_bytes_after = index_value.location().record_offset()
        + PERSIST_BLOB_RECORD_HEADER_LEN as u64
        + payload.len() as u64;
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map(|trim| {
                (
                    trim.live_entries(),
                    trim.reclaimed_bytes(),
                    trim.bytes_after(),
                )
            })
            .map_err(|error| error.to_string());
        tx.send(result).expect("file tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    drop(guard);

    let (live_entries, reclaimed_bytes, bytes_after) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack tail trim completes after same-process lock release")
        .expect("file blob-pack tail trim succeeds");
    assert_eq!(live_entries, 1);
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(bytes_after, expected_bytes_after);
    handle.join().expect("worker joins");
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("rooted file artifact remains readable")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(tail_key, tail_location).is_err(),
        "unindexed file tail record should be truncated"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_acquires_file_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map(|trim| trim.reclaimed_bytes())
            .map_err(|error| error.to_string());
        tx.send(result).expect("file tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    drop(guard);

    let reclaimed_bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack tail trim completes after file-artifact lock release")
        .expect("file blob-pack tail trim succeeds");
    assert_eq!(reclaimed_bytes, 0);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after tail trim");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_acquires_parse_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map(|trim| trim.reclaimed_bytes())
            .map_err(|error| error.to_string());
        tx.send(result).expect("file tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    drop(guard);

    let reclaimed_bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack tail trim completes after parse-artifact lock release")
        .expect("file blob-pack tail trim succeeds");
    assert_eq!(reclaimed_bytes, 0);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after tail trim");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted value before repack";
    let unrooted_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unrooted_payload));
    let unrooted_location = cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted value appends");
    let payload = b"indexed value after unrooted prefix";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    cache
        .append_blob_indexed(key, payload)
        .expect("indexed value appends");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_value_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("value repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("value blob-pack repack completes after same-process lock release")
        .expect("value blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed value reads")
            .expect("indexed value exists")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(unrooted_key, unrooted_location).is_err(),
        "unrooted value record should be omitted by repack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted file before repack";
    let unrooted_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(unrooted_payload));
    let unrooted_location = cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"rooted file artifact after unrooted prefix";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_file_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack repack completes after same-process lock release")
        .expect("file blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    let relocated = cache
        .lookup_file_artifact(file_artifact_key)
        .expect("file artifact lookup succeeds")
        .expect("file artifact remains indexed");
    assert_eq!(
        cache
            .read_file_artifact(relocated)
            .expect("relocated file artifact reads")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(unrooted_key, unrooted_location).is_err(),
        "unrooted file record should be omitted by repack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_acquires_file_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted file before file-artifact repack";
    let unrooted_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(unrooted_payload));
    cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"rooted file artifact after advisory prefix";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_file_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack repack completes after file-artifact lock release")
        .expect("file blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after repack");
    drop(released_lock);
    let relocated = cache
        .lookup_file_artifact(file_artifact_key)
        .expect("file artifact lookup succeeds")
        .expect("file artifact remains indexed");
    assert_eq!(
        cache
            .read_file_artifact(relocated)
            .expect("relocated file artifact reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_acquires_parse_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted file before parse-artifact repack";
    let unrooted_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(unrooted_payload));
    cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let parse_artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let payload = b"rooted parse artifact after advisory prefix";
    let materialized = cache
        .materialize_parse_artifact(parse_key, payload, MaterializationDecision::Materialize)
        .expect("parse artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("parse artifact should materialize");
    cache
        .record_parse_artifact(index_entry)
        .expect("parse artifact mapping records");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_file_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack repack completes after parse-artifact lock release")
        .expect("file blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after repack");
    drop(released_lock);
    let relocated = cache
        .lookup_parse_artifact(parse_artifact_key)
        .expect("parse artifact lookup succeeds")
        .expect("parse artifact remains indexed");
    assert_eq!(
        cache
            .read_parse_artifact(relocated)
            .expect("relocated parse artifact reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_reports_poisoned_same_root_blob_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect_err("poisoned shared value lock should reject value pack trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::BlobIndex {
            source: PersistBlobIndexError::WriteLockPoisoned {
                store: PersistBlobStore::Values
            }
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_reports_poisoned_same_root_file_artifact_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_file_artifacts_for_tests()
            .expect("file-artifact write lock acquires");
        panic!("poison persistent file-artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect_err("poisoned shared file-artifact lock should reject file pack trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::FileArtifactIndex {
            source: PersistFileArtifactIndexError::WriteLockPoisoned
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_reports_poisoned_same_root_parse_artifact_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_parse_artifacts_for_tests()
            .expect("parse-artifact write lock acquires");
        panic!("poison persistent parse-artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect_err("poisoned shared parse-artifact lock should reject file pack trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::ParseArtifactIndex {
            source: PersistParseArtifactIndexError::WriteLockPoisoned
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_replaces_stale_index_location() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let stale_location = PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0);
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, stale_location))
        .expect("stale index entry appends");

    let result = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization repairs stale location");
    let PersistMaterialization::Materialized(fresh_location) = result else {
        panic!("materialization should append fresh bytes");
    };

    assert_ne!(fresh_location, stale_location);
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(fresh_location)
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
fn cache_indexed_materialization_repairs_wrong_record_pointer_before_compaction() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let other_payload = b"other payload";
    let other_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(other_payload));
    let stale_location = cache
        .append_blob(other_key, other_payload)
        .expect("other blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, stale_location))
        .expect("wrong-record index entry appends");

    let stale_read = cache
        .read_blob_indexed(key)
        .expect_err("wrong-record pointer does not verify for key");
    assert!(matches!(
        stale_read,
        PersistBlobIndexedReadError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));

    let result = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization repairs wrong-record pointer");
    let PersistMaterialization::Materialized(fresh_location) = result else {
        panic!("materialization should append fresh bytes");
    };

    assert_ne!(fresh_location, stale_location);
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(fresh_location)
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
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    let pack_len_after_repair = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    assert_eq!(
        cache
            .read_blob(other_key, stale_location)
            .expect("stale pack record remains readable before compaction")
            .as_slice(),
        other_payload
    );

    assert_eq!(
        cache
            .compact_blob_index(PersistBlobStore::Values)
            .expect("value index compacts"),
        1
    );

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        pack_len_after_repair
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("compacted lookup succeeds"),
        Some(fresh_location)
    );
    assert_eq!(
        cache
            .read_blob(other_key, stale_location)
            .expect("unreferenced pack record remains readable")
            .as_slice(),
        other_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_classifies_value_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let duplicate_payload = b"duplicate live payload";
    let duplicate_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(duplicate_payload));
    let stale_duplicate_location = cache
        .append_blob(duplicate_key, duplicate_payload)
        .expect("stale duplicate appends");
    let live_duplicate_entry = cache
        .append_blob_indexed(duplicate_key, duplicate_payload)
        .expect("live duplicate appends and indexes");
    let live_payload = b"later live payload";
    let live_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(live_payload));
    let live_entry = cache
        .append_blob_indexed(live_key, live_payload)
        .expect("later live blob appends and indexes");
    let tail_payload = b"unrooted tail payload";
    let tail_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before liveness plan")
        .len();

    let plan = cache
        .plan_blob_pack_liveness(PersistBlobStore::Values)
        .expect("value liveness plan builds");

    assert_eq!(plan.live_roots().len(), 2);
    assert!(plan.live_roots().iter().all(|root| {
        root.source() == PersistBlobLiveRootSource::BlobIndex
            && root.key().store() == PersistBlobStore::Values
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.key() == duplicate_key && root.location() == live_duplicate_entry.location()
    }));
    assert!(
        plan.live_roots()
            .iter()
            .any(|root| root.key() == live_key && root.location() == live_entry.location())
    );
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![live_duplicate_entry.location(), live_entry.location()]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![stale_duplicate_location, tail_location]
    );
    let duplicate_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + duplicate_payload.len() as u64;
    let live_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + live_payload.len() as u64;
    let tail_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + tail_payload.len() as u64;
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.rooted_record_bytes(), duplicate_bytes + live_bytes);
    assert_eq!(plan.unrooted_record_bytes(), duplicate_bytes + tail_bytes);
    assert_eq!(plan.tail_reclaimable_bytes(), tail_bytes);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after liveness plan")
            .len(),
        bytes_before
    );
    assert_eq!(
        cache
            .read_blob(tail_key, tail_location)
            .expect("liveness planning does not trim tail")
            .as_slice(),
        tail_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_plan_maps_value_live_records_to_compacted_offsets() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted value prefix";
    let prefix_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(prefix_payload));
    let prefix_location = cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let first_payload = b"first live value";
    let first_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(first_payload));
    let first_entry = cache
        .append_blob_indexed(first_key, first_payload)
        .expect("first live value appends and indexes");
    let middle_payload = b"unrooted value middle";
    let middle_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(middle_payload));
    let middle_location = cache
        .append_blob(middle_key, middle_payload)
        .expect("unrooted middle appends");
    let second_payload = b"second live value";
    let second_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(second_payload));
    let second_entry = cache
        .append_blob_indexed(second_key, second_payload)
        .expect("second live value appends and indexes");
    let tail_payload = b"unrooted value tail";
    let tail_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before repack plan")
        .len();

    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");

    let first_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + first_payload.len() as u64;
    let second_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + second_payload.len() as u64;
    let first_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64,
        first_payload.len() as u64,
    );
    let second_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + first_bytes,
        second_payload.len() as u64,
    );
    assert_eq!(plan.live_roots().len(), 2);
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| {
                (
                    relocation.key(),
                    relocation.old_location(),
                    relocation.new_location(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (first_key, first_entry.location(), first_new),
            (second_key, second_entry.location(), second_new),
        ]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![prefix_location, middle_location, tail_location]
    );
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        plan.bytes_after(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + first_bytes + second_bytes
    );
    assert_eq!(plan.rooted_record_bytes(), first_bytes + second_bytes);
    assert_eq!(
        plan.unrooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + prefix_payload.len() as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + middle_payload.len() as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + tail_payload.len() as u64
    );
    assert_eq!(
        plan.reclaimable_bytes(),
        plan.bytes_before().saturating_sub(plan.bytes_after())
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after repack plan")
            .len(),
        bytes_before
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_relocates_live_values_and_rewrites_index() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted value prefix";
    let prefix_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(prefix_payload));
    cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let node_payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let node_value_hash = node_payload.value_hash().expect("payload hashes");
    let node_materialized = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &node_payload,
            MaterializationDecision::Materialize,
        )
        .expect("node value materializes");
    let PersistMaterialization::Materialized(node_old_location) = node_materialized else {
        panic!("node value should materialize");
    };
    let middle_payload = b"unrooted value middle";
    let middle_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(middle_payload));
    cache
        .append_blob(middle_key, middle_payload)
        .expect("unrooted middle appends");
    let indexed_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("indexed payload builds");
    let indexed_value_hash = indexed_payload
        .value_hash()
        .expect("indexed payload hashes");
    let indexed_materialized = cache
        .materialize_cached_expression_value_indexed(
            &indexed_payload,
            MaterializationDecision::Materialize,
        )
        .expect("indexed value materializes");
    let PersistMaterialization::Materialized(indexed_old_location) = indexed_materialized else {
        panic!("indexed value should materialize");
    };
    let tail_payload = b"unrooted value tail";
    let tail_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before repack")
        .len();

    let plan = cache
        .repack_value_blob_pack()
        .expect("value blob pack repacks");

    assert!(plan.reclaimable_bytes() > 0);
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after repack")
            .len(),
        plan.bytes_after()
    );
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| relocation.old_location())
            .collect::<Vec<_>>(),
        vec![node_old_location, indexed_old_location]
    );
    let node_new_location = plan.record_relocations()[0].new_location();
    let indexed_new_location = plan.record_relocations()[1].new_location();
    assert_eq!(
        cache
            .lookup_blob_location(PersistBlobKey::for_value(node_value_hash.as_durable_hash()))
            .expect("node value index lookup succeeds"),
        Some(node_new_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(PersistBlobKey::for_value(
                indexed_value_hash.as_durable_hash()
            ))
            .expect("indexed value lookup succeeds"),
        Some(indexed_new_location)
    );
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("node value load succeeds")
            .expect("node value exists"),
        node_payload
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(indexed_value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists"),
        indexed_payload
    );
    assert!(cache.read_blob(tail_key, tail_location).is_err());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_rejects_source_path_as_stage_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"source path as repack stage";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let entry = cache
        .append_blob_indexed(key, payload)
        .expect("indexed value blob appends");
    let location = entry.location();
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    let source_path = cache.value_pack().path().to_path_buf();

    let error = cache
        .value_pack()
        .write_relocated_records_to(source_path.clone(), plan.record_relocations())
        .expect_err("source path as stage pack errors");

    assert!(matches!(
        error,
        PersistBlobPackError::SourceEqualsTemp {
            source_path: actual_source,
            tmp_path,
        } if actual_source == source_path && tmp_path == source_path
    ));
    assert_eq!(
        cache
            .read_blob(key, location)
            .expect("source pack remains readable"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_reclaims_all_unrooted_values() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_payload = b"first unrooted value";
    let first_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(first_payload));
    cache
        .append_blob(first_key, first_payload)
        .expect("first unrooted value appends");
    let second_payload = b"second unrooted value";
    let second_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(second_payload));
    cache
        .append_blob(second_key, second_payload)
        .expect("second unrooted value appends");

    let plan = cache
        .repack_value_blob_pack()
        .expect("unrooted value pack repacks");

    assert!(plan.live_roots().is_empty());
    assert!(plan.record_relocations().is_empty());
    assert_eq!(plan.unrooted_records().len(), 2);
    assert_eq!(plan.bytes_after(), PERSIST_BLOB_PACK_HEADER_LEN as u64);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after empty repack")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert!(
        cache
            .value_index()
            .latest_entries()
            .expect("value index snapshots")
            .is_empty()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_relocates_artifacts_and_rewrites_sidecars() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted file prefix";
    let prefix_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(prefix_payload));
    cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted file prefix appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_payload = b"durable file artifact";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    let file_old_value = file_entry.value();
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let parse_payload = b"durable parse artifact";
    let parse_materialized = cache
        .materialize_parse_artifact(
            parse_key,
            parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("parse artifact materializes");
    let parse_entry = parse_materialized
        .index_entry()
        .expect("parse artifact should materialize");
    let parse_artifact_key = parse_entry.key();
    let parse_old_value = parse_entry.value();
    cache
        .record_parse_artifact(parse_entry)
        .expect("parse artifact mapping records");
    let indexed_payload = b"indexed file blob";
    let indexed_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(indexed_payload));
    let indexed_old_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed file blob appends");
    let tail_payload = b"unrooted file tail";
    let tail_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted file tail appends");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before repack")
        .len();

    let plan = cache
        .repack_file_blob_pack()
        .expect("file blob pack repacks");

    assert!(plan.reclaimable_bytes() > 0);
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after repack")
            .len(),
        plan.bytes_after()
    );
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| relocation.old_location())
            .collect::<Vec<_>>(),
        vec![
            file_old_value.location(),
            parse_old_value.location(),
            indexed_old_entry.location()
        ]
    );
    let file_new_location = plan.record_relocations()[0].new_location();
    let parse_new_location = plan.record_relocations()[1].new_location();
    let indexed_new_location = plan.record_relocations()[2].new_location();
    assert_eq!(
        cache
            .lookup_file_artifact(file_artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(PersistFileArtifactIndexValue::new(
            file_old_value.blob_hash(),
            file_new_location,
        ))
    );
    assert_eq!(
        cache
            .lookup_parse_artifact(parse_artifact_key)
            .expect("parse artifact lookup succeeds"),
        Some(PersistParseArtifactIndexValue::new(
            parse_old_value.blob_hash(),
            parse_new_location,
        ))
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_old_value.blob_key())
            .expect("file blob index lookup succeeds"),
        Some(file_new_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(parse_old_value.blob_key())
            .expect("parse blob index lookup succeeds"),
        Some(parse_new_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(indexed_key)
            .expect("indexed file blob lookup succeeds"),
        Some(indexed_new_location)
    );
    assert_eq!(
        cache
            .read_file_artifact(PersistFileArtifactIndexValue::new(
                file_old_value.blob_hash(),
                file_new_location,
            ))
            .expect("relocated file artifact reads")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_parse_artifact(PersistParseArtifactIndexValue::new(
                parse_old_value.blob_hash(),
                parse_new_location,
            ))
            .expect("relocated parse artifact reads")
            .as_slice(),
        parse_payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(indexed_key)
            .expect("indexed file blob reads")
            .expect("indexed file blob exists")
            .as_slice(),
        indexed_payload
    );
    assert!(cache.read_blob(tail_key, tail_location).is_err());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_rejects_pending_artifact_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            b"pending file artifact",
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");

    let error = cache
        .repack_file_blob_pack()
        .expect_err("pending roots block file repack");

    assert!(matches!(
        error,
        PersistFileBlobPackRepackError::PendingArtifactRoots { roots: 1 }
    ));
    cache
        .record_file_artifact(
            materialized
                .index_entry()
                .expect("pending file artifact should materialize"),
        )
        .expect("pending file artifact records");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_adapter_repacks_value_and_file_packs() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unrooted_value_payload = b"unrooted value before aggregate repack";
    cache
        .append_blob(
            PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unrooted_value_payload)),
            unrooted_value_payload,
        )
        .expect("unrooted value appends");
    let value_payload = CachedExpressionValue::immediate(Value::int(99)).expect("payload builds");
    let value_hash = value_payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(
            &value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value payload materializes");
    let value_bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before aggregate repack")
        .len();

    let unrooted_file_payload = b"unrooted file before aggregate repack";
    cache
        .append_blob(
            PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(unrooted_file_payload)),
            unrooted_file_payload,
        )
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_payload = b"aggregate file artifact";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    let file_blob_hash = file_entry.value().blob_hash();
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let file_bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before aggregate repack")
        .len();

    let repack = cache.repack_blob_packs().expect("both blob packs repack");

    assert!(repack.value_blob_pack().reclaimable_bytes() > 0);
    assert!(repack.file_blob_pack().reclaimable_bytes() > 0);
    assert_eq!(repack.value_blob_pack().bytes_before(), value_bytes_before);
    assert_eq!(repack.file_blob_pack().bytes_before(), file_bytes_before);
    assert_eq!(
        repack.reclaimed_blob_bytes(),
        repack
            .value_blob_pack()
            .reclaimable_bytes()
            .saturating_add(repack.file_blob_pack().reclaimable_bytes())
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after aggregate repack")
            .len(),
        repack.value_blob_pack().bytes_after()
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after aggregate repack")
            .len(),
        repack.file_blob_pack().bytes_after()
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("value payload loads")
            .expect("value payload exists"),
        value_payload
    );
    let relocated_file_value = cache
        .lookup_file_artifact(file_artifact_key)
        .expect("file artifact lookup succeeds")
        .expect("file artifact exists after repack");
    assert_eq!(relocated_file_value.blob_hash(), file_blob_hash);
    assert_eq!(
        cache
            .read_file_artifact(relocated_file_value)
            .expect("file artifact reads after aggregate repack")
            .as_slice(),
        file_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_adapter_reports_file_pack_error_after_value_repack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unrooted_value_payload = b"unrooted value before aggregate failure";
    cache
        .append_blob(
            PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unrooted_value_payload)),
            unrooted_value_payload,
        )
        .expect("unrooted value appends");
    let value_payload = CachedExpressionValue::immediate(Value::int(100)).expect("payload builds");
    let value_hash = value_payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(
            &value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value payload materializes");
    let value_bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before aggregate failure")
        .len();

    let source = b"let y = 2; in y";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            b"pending aggregate file artifact",
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");

    let error = cache
        .repack_blob_packs()
        .expect_err("pending file roots block aggregate repack");

    assert!(matches!(
        error,
        PersistBlobPacksRepackError::FileBlobPack {
            source: PersistFileBlobPackRepackError::PendingArtifactRoots { roots: 1 }
        }
    ));
    assert!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after aggregate failure")
            .len()
            < value_bytes_before
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("value payload loads")
            .expect("value payload exists"),
        value_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_includes_file_artifact_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted file prefix";
    let prefix_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(prefix_payload));
    let prefix_location = cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"file artifact payload";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes without blob index");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let parse_payload = b"parse artifact payload";
    let parse_materialized = cache
        .materialize_parse_artifact(
            parse_key,
            parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("parse artifact materializes without blob index");
    let parse_entry = parse_materialized
        .index_entry()
        .expect("parse artifact should materialize");
    cache
        .record_parse_artifact(parse_entry)
        .expect("parse artifact mapping records");
    let tail_payload = b"unrooted file tail";
    let tail_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before liveness plan")
        .len();

    let plan = cache
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("file liveness plan builds");

    assert_eq!(
        cache
            .lookup_blob_location(file_entry.value().blob_key())
            .expect("blob index lookup succeeds"),
        None,
        "artifact-only file roots should not require blob-index entries"
    );
    assert_eq!(plan.live_roots().len(), 2);
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::FileArtifactIndex
            && root.location() == file_entry.value().location()
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::ParseArtifactIndex
            && root.location() == parse_entry.value().location()
    }));
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![
            file_entry.value().location(),
            parse_entry.value().location()
        ]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![prefix_location, tail_location]
    );
    let prefix_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + prefix_payload.len() as u64;
    let file_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + file_payload.len() as u64;
    let parse_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + parse_payload.len() as u64;
    let tail_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + tail_payload.len() as u64;
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.rooted_record_bytes(), file_bytes + parse_bytes);
    assert_eq!(plan.unrooted_record_bytes(), prefix_bytes + tail_bytes);
    assert_eq!(plan.tail_reclaimable_bytes(), tail_bytes);
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after liveness plan")
            .len(),
        bytes_before
    );
    assert_eq!(
        cache
            .read_file_artifact(file_entry.value())
            .expect("file artifact remains readable")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_parse_artifact(parse_entry.value())
            .expect("parse artifact remains readable")
            .as_slice(),
        parse_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_plan_includes_file_artifact_and_pending_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted file prefix";
    let prefix_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(prefix_payload));
    let prefix_location = cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let indexed_payload = b"indexed file payload";
    let indexed_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(indexed_payload));
    let indexed_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"file artifact payload";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes without blob index");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let pending_parse_payload = b"pending parse artifact payload";
    let pending_parse_materialized = cache
        .materialize_parse_artifact(
            parse_key,
            pending_parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("pending parse artifact materializes");
    let pending_parse_entry = pending_parse_materialized
        .index_entry()
        .expect("pending parse artifact should materialize");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before repack plan")
        .len();

    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Files)
        .expect("file repack plan builds");

    let indexed_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + indexed_payload.len() as u64;
    let file_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + file_payload.len() as u64;
    let pending_parse_bytes =
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + pending_parse_payload.len() as u64;
    let indexed_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64,
        indexed_payload.len() as u64,
    );
    let file_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + indexed_bytes,
        file_payload.len() as u64,
    );
    let pending_parse_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + indexed_bytes + file_bytes,
        pending_parse_payload.len() as u64,
    );
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::BlobIndex
            && root.location() == indexed_entry.location()
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::FileArtifactIndex
            && root.location() == file_entry.value().location()
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::PendingParseArtifact
            && root.location() == pending_parse_entry.value().location()
    }));
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| {
                (
                    relocation.key(),
                    relocation.old_location(),
                    relocation.new_location(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (indexed_key, indexed_entry.location(), indexed_new),
            (
                file_entry.value().blob_key(),
                file_entry.value().location(),
                file_new,
            ),
            (
                pending_parse_entry.value().blob_key(),
                pending_parse_entry.value().location(),
                pending_parse_new,
            ),
        ]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![prefix_location]
    );
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        plan.bytes_after(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + indexed_bytes + file_bytes + pending_parse_bytes
    );
    assert_eq!(plan.unrooted_record_bytes(), {
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + prefix_payload.len() as u64
    });
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after repack plan")
            .len(),
        bytes_before
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_preserves_pending_file_artifact_root() {
    let root = temp_root();
    let writer = PersistCache::open(&root).expect("writer cache opens");
    let maintainer = PersistCache::open(&root).expect("maintainer cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let payload = b"pending file artifact payload";
    let materialized = writer
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    let index_value = index_entry.value();
    let bytes_before = fs::metadata(writer.file_pack().path())
        .expect("file pack metadata before pending trim")
        .len();

    let plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("pending file-artifact liveness plan builds");

    assert_eq!(plan.live_roots().len(), 1);
    assert_eq!(
        plan.live_roots()[0].source(),
        PersistBlobLiveRootSource::PendingFileArtifact
    );
    assert_eq!(plan.live_roots()[0].location(), index_value.location());
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![index_value.location()]
    );
    assert!(plan.unrooted_records().is_empty());
    assert_eq!(plan.tail_reclaimable_bytes(), 0);

    let trim = maintainer
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("pending file-artifact root blocks tail trim");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    writer
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records after trim");
    assert_eq!(
        writer
            .read_file_artifact(index_value)
            .expect("pending file artifact remains readable")
            .as_slice(),
        payload
    );
    let recorded_plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("recorded file-artifact liveness plan builds");
    assert!(recorded_plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::FileArtifactIndex
            && root.location() == index_value.location()
    }));
    assert!(
        !recorded_plan
            .live_roots()
            .iter()
            .any(|root| root.source() == PersistBlobLiveRootSource::PendingFileArtifact)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_preserves_pending_parse_artifact_root() {
    let root = temp_root();
    let writer = PersistCache::open(&root).expect("writer cache opens");
    let maintainer = PersistCache::open(&root).expect("maintainer cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let payload = b"pending parse artifact payload";
    let materialized = writer
        .materialize_parse_artifact(parse_key, payload, MaterializationDecision::Materialize)
        .expect("parse artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("parse artifact should materialize");
    let index_value = index_entry.value();
    let bytes_before = fs::metadata(writer.file_pack().path())
        .expect("file pack metadata before pending trim")
        .len();

    let plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("pending parse-artifact liveness plan builds");

    assert_eq!(plan.live_roots().len(), 1);
    assert_eq!(
        plan.live_roots()[0].source(),
        PersistBlobLiveRootSource::PendingParseArtifact
    );
    assert_eq!(plan.live_roots()[0].location(), index_value.location());
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![index_value.location()]
    );
    assert!(plan.unrooted_records().is_empty());
    assert_eq!(plan.tail_reclaimable_bytes(), 0);

    let trim = maintainer
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("pending parse-artifact root blocks tail trim");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    writer
        .record_parse_artifact(index_entry)
        .expect("parse artifact mapping records after trim");
    assert_eq!(
        writer
            .read_parse_artifact(index_value)
            .expect("pending parse artifact remains readable")
            .as_slice(),
        payload
    );
    let recorded_plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("recorded parse-artifact liveness plan builds");
    assert!(recorded_plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::ParseArtifactIndex
            && root.location() == index_value.location()
    }));
    assert!(
        !recorded_plan
            .live_roots()
            .iter()
            .any(|root| root.source() == PersistBlobLiveRootSource::PendingParseArtifact)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_reclaims_unindexed_tail_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"live payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let live = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization succeeds");
    let PersistMaterialization::Materialized(live_location) = live else {
        panic!("payload should materialize");
    };
    let unindexed_payload = b"unindexed tail payload";
    let unindexed_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unindexed_payload));
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unindexed_payload.len() as u64;

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect("value pack tail trims");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), expected_reclaimed);
    assert_eq!(
        trim.bytes_after(),
        live_location.record_offset()
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after trim")
            .len(),
        trim.bytes_after()
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(unindexed_key, unindexed_location).is_err(),
        "unindexed tail record should be truncated"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_preserves_unindexed_prefix_before_live_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unindexed_payload = b"unindexed prefix payload";
    let unindexed_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unindexed_payload));
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed prefix appends");
    let payload = b"live payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization succeeds");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect("value pack tail trim no-ops");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    assert_eq!(
        cache
            .read_blob(unindexed_key, unindexed_location)
            .expect("unindexed prefix remains readable")
            .as_slice(),
        unindexed_payload
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
fn cache_blob_pack_tail_trim_rejects_stale_latest_index_without_truncating() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let other_payload = b"other payload";
    let other_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(other_payload));
    let wrong_location = cache
        .append_blob(other_key, other_payload)
        .expect("other blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, wrong_location))
        .expect("wrong index entry appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect_err("stale latest entry blocks tail trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after failed trim")
            .len(),
        bytes_before
    );
    assert_eq!(
        cache
            .read_blob(other_key, wrong_location)
            .expect("pack record remains after failed trim")
            .as_slice(),
        other_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_reclaims_empty_root_tail() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"unindexed only payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let location = cache
        .append_blob(key, payload)
        .expect("unindexed value appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect("empty-root tail trims");

    assert_eq!(trim.live_entries(), 0);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), PERSIST_BLOB_PACK_HEADER_LEN as u64);
    assert_eq!(
        trim.reclaimed_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + payload.len() as u64
    );
    assert!(
        cache.read_blob(key, location).is_err(),
        "unindexed value tail should be truncated"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_preserves_file_artifact_index_tail_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let payload = b"file artifact payload";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes without blob index");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    let index_value = index_entry.value();
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    assert_eq!(
        cache
            .lookup_blob_location(index_value.blob_key())
            .expect("blob index lookup succeeds"),
        None,
        "non-indexed artifact materialization should not write blob index roots"
    );
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before trim")
        .len();

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("file pack tail trim preserves artifact root");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("artifact-only file root remains readable")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_preserves_parse_artifact_index_tail_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let payload = b"parse artifact payload";
    let materialized = cache
        .materialize_parse_artifact(parse_key, payload, MaterializationDecision::Materialize)
        .expect("parse artifact materializes without blob index");
    let index_entry = materialized
        .index_entry()
        .expect("parse artifact should materialize");
    let index_value = index_entry.value();
    cache
        .record_parse_artifact(index_entry)
        .expect("parse artifact mapping records");
    assert_eq!(
        cache
            .lookup_blob_location(index_value.blob_key())
            .expect("blob index lookup succeeds"),
        None,
        "non-indexed artifact materialization should not write blob index roots"
    );
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before trim")
        .len();

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("file pack tail trim preserves parse artifact root");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    assert_eq!(
        cache
            .read_parse_artifact(index_value)
            .expect("artifact-only parse root remains readable")
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
fn cache_cached_expression_payload_materialization_reuses_indexed_value_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let first = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("first payload materializes");
    let PersistMaterialization::Materialized(first_location) = first else {
        panic!("payload should materialize");
    };
    let pack_len = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    let index_len = fs::metadata(cache.value_index().path())
        .expect("value index metadata")
        .len();

    let second = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("second payload materializes");

    assert_eq!(second, PersistMaterialization::Materialized(first_location));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        pack_len
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        index_len
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
fn cache_strict_list_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::strict_list(vec![
        CachedExpressionValue::immediate(Value::int(1)).expect("payload builds"),
        CachedExpressionValue::context_string(b"context element".to_vec(), all_context_kinds()),
        CachedExpressionValue::context_path(
            b"/nix/store/context-list-path".to_vec(),
            all_context_kinds(),
        ),
        CachedExpressionValue::strict_list(vec![
            CachedExpressionValue::empty_list(),
            CachedExpressionValue::empty_attrs(),
        ]),
    ]);
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash.as_durable_hash());

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("strict list payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("strict list payload should materialize");
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
            .expect("strict list payload loads")
            .expect("strict list payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_empty_attrs_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::empty_attrs();
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash.as_durable_hash());

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("empty attrset payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("empty attrset payload should materialize");
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
            .expect("empty attrset payload loads")
            .expect("empty attrset payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_strict_attrs_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::strict_attrs(vec![
        (
            b"b".to_vec(),
            CachedExpressionValue::context_string(b"context value".to_vec(), all_context_kinds()),
        ),
        (
            b"a".to_vec(),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("payload builds"),
                CachedExpressionValue::empty_attrs(),
            ]),
        ),
    ])
    .expect("strict attrset payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash.as_durable_hash());

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("strict attrset payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("strict attrset payload should materialize");
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
            .expect("strict attrset payload loads")
            .expect("strict attrset payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_positioned_attrs_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_position = AttrPosition::new(0, Span::new(4, 5));
    let second_position = AttrPosition::new(0, Span::new(8, 9));
    let payload = CachedExpressionValue::source_ordered_positioned_attrs(vec![
        (
            b"c".to_vec(),
            Some(first_position),
            CachedExpressionValue::immediate(Value::int(2)).expect("payload builds"),
        ),
        (
            b"b".to_vec(),
            Some(second_position),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("payload builds"),
            ]),
        ),
    ])
    .expect("positioned attrset payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash.as_durable_hash());

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("positioned attrset payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("positioned attrset payload should materialize");
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
            .expect("positioned attrset payload loads")
            .expect("positioned attrset payload exists"),
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
fn cache_node_value_root_plan_resolves_latest_metadata_links() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let missing_node_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing node"));
    let reuse_only_node_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"reuse-only node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let missing_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"missing value"));
    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    let PersistMaterialization::Materialized(location) = result else {
        panic!("node payload should materialize");
    };
    cache
        .record_node_materialized_value_hash(missing_node_key, missing_value_hash)
        .expect("missing value metadata records");
    cache
        .record_node_materialization_reuse(reuse_only_node_key, MaterializationReuse::new(3, 4))
        .expect("reuse-only metadata records");

    let plan = cache
        .plan_node_value_roots()
        .expect("node value root plan builds");

    assert!(plan.repair_needed());
    assert_eq!(plan.resolved_roots().len(), 1);
    let resolved = plan.resolved_roots()[0];
    assert_eq!(resolved.node_key(), node_key);
    assert_eq!(resolved.value_hash(), value_hash);
    assert_eq!(
        resolved.blob_key(),
        PersistBlobKey::for_value(value_hash.as_durable_hash())
    );
    assert_eq!(resolved.location(), location);
    assert_eq!(plan.missing_roots().len(), 1);
    let missing = plan.missing_roots()[0];
    assert_eq!(missing.node_key(), missing_node_key);
    assert_eq!(missing.value_hash(), missing_value_hash);
    assert_eq!(
        missing.blob_key(),
        PersistBlobKey::for_value(missing_value_hash.as_durable_hash())
    );
    assert!(
        plan.missing_roots()
            .iter()
            .all(|root| root.node_key() != reuse_only_node_key),
        "metadata without a materialized value hash is not a value root"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_value_root_plan_rejects_corrupt_indexed_value_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    let PersistMaterialization::Materialized(location) = result else {
        panic!("node payload should materialize");
    };
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .plan_node_value_roots()
        .expect_err("corrupt value root blocks plan");

    assert!(matches!(
        error,
        PersistNodeValueRootPlanError::Read {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_classifies_value_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let missing_node_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing node"));
    let node_payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let node_value_hash = node_payload.value_hash().expect("payload hashes");
    let node_result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &node_payload,
            MaterializationDecision::Materialize,
        )
        .expect("node payload materializes");
    let PersistMaterialization::Materialized(node_location) = node_result else {
        panic!("node payload should materialize");
    };
    let indexed_payload = CachedExpressionValue::immediate(Value::int(7)).expect("payload builds");
    let indexed_value_hash = indexed_payload.value_hash().expect("payload hashes");
    let indexed_result = cache
        .materialize_cached_expression_value_indexed(
            &indexed_payload,
            MaterializationDecision::Materialize,
        )
        .expect("indexed payload materializes");
    let PersistMaterialization::Materialized(indexed_location) = indexed_result else {
        panic!("indexed payload should materialize");
    };
    let unindexed_payload = b"unindexed value payload";
    let unindexed_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unindexed_payload));
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed value appends");
    let missing_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"missing value"));
    cache
        .record_node_materialized_value_hash(missing_node_key, missing_value_hash)
        .expect("missing node value metadata records");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before reachability plan")
        .len();

    let plan = cache
        .plan_value_blob_reachability()
        .expect("value reachability plan builds");

    assert!(plan.repair_needed());
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.node_roots().len(), 1);
    assert_eq!(plan.node_roots()[0].node_key(), node_key);
    assert_eq!(plan.node_roots()[0].value_hash(), node_value_hash);
    assert_eq!(plan.node_roots()[0].location(), node_location);
    assert_eq!(plan.missing_node_roots().len(), 1);
    assert_eq!(plan.missing_node_roots()[0].node_key(), missing_node_key);
    assert_eq!(
        plan.missing_node_roots()[0].value_hash(),
        missing_value_hash
    );
    assert_eq!(
        plan.node_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![node_location]
    );
    assert_eq!(
        plan.indexed_unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![indexed_location]
    );
    assert_eq!(
        plan.unindexed_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![unindexed_location]
    );
    assert_eq!(
        plan.node_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + node_location.payload_len()
    );
    assert_eq!(
        plan.indexed_unrooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + indexed_location.payload_len()
    );
    assert_eq!(
        plan.unindexed_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unindexed_location.payload_len()
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(indexed_value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists"),
        indexed_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_rejects_corrupt_unindexed_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"corrupt unindexed value";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let location = cache
        .append_blob(key, payload)
        .expect("unindexed value appends");
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .plan_value_blob_reachability()
        .expect_err("corrupt unindexed value blocks plan");

    assert!(matches!(
        error,
        PersistValueBlobReachabilityPlanError::Pack {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_rejects_mismatched_value_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let actual_payload = b"actual indexed payload";
    let actual_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(actual_payload));
    let actual_location = cache
        .append_blob(actual_key, actual_payload)
        .expect("actual value appends");
    let expected_key =
        PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"expected indexed payload"));
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(expected_key, actual_location))
        .expect("mismatched value index entry appends");

    let error = cache
        .plan_value_blob_reachability()
        .expect_err("mismatched indexed value root blocks plan");

    assert!(matches!(
        error,
        PersistValueBlobReachabilityPlanError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_rejects_wrong_store_value_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"file payload"));
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            file_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("wrong-store value index entry appends");

    let error = cache
        .plan_value_blob_reachability()
        .expect_err("wrong-store indexed value root blocks plan");

    assert!(matches!(
        error,
        PersistValueBlobReachabilityPlanError::WrongStoreEntry {
            actual: PersistBlobStore::Files
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_classifies_file_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"durable file artifact";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes without blob index");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let parse_payload = b"durable parse artifact";
    let parse_materialized = cache
        .materialize_parse_artifact(
            parse_key,
            parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("parse artifact materializes without blob index");
    let parse_entry = parse_materialized
        .index_entry()
        .expect("parse artifact should materialize");
    cache
        .record_parse_artifact(parse_entry)
        .expect("parse artifact mapping records");
    let pending_file_source = b"pending file source";
    let pending_file_key = ParseFileKey::for_source("/src/pending-file.nix", pending_file_source);
    let pending_file_parse_key = test_parse_key(pending_file_source);
    let pending_file_payload = b"pending file artifact";
    let pending_file_materialized = cache
        .materialize_file_artifact(
            &pending_file_key,
            pending_file_parse_key,
            pending_file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");
    let pending_file_entry = pending_file_materialized
        .index_entry()
        .expect("pending file artifact should materialize");
    let pending_parse_key = test_parse_key(b"pending parse source");
    let pending_parse_payload = b"pending parse artifact";
    let pending_parse_materialized = cache
        .materialize_parse_artifact(
            pending_parse_key,
            pending_parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("pending parse artifact materializes");
    let pending_parse_entry = pending_parse_materialized
        .index_entry()
        .expect("pending parse artifact should materialize");
    let indexed_payload = b"indexed file blob only";
    let indexed_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(indexed_payload));
    let indexed_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed file blob appends");
    let unindexed_payload = b"unindexed file blob";
    let unindexed_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(unindexed_payload));
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed file blob appends");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before reachability plan")
        .len();

    let plan = cache
        .plan_file_blob_reachability()
        .expect("file reachability plan builds");

    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.file_artifact_roots().len(), 1);
    assert_eq!(
        plan.file_artifact_roots()[0].source(),
        PersistBlobLiveRootSource::FileArtifactIndex
    );
    assert_eq!(
        plan.file_artifact_roots()[0].location(),
        file_entry.value().location()
    );
    assert_eq!(plan.parse_artifact_roots().len(), 1);
    assert_eq!(
        plan.parse_artifact_roots()[0].source(),
        PersistBlobLiveRootSource::ParseArtifactIndex
    );
    assert_eq!(
        plan.parse_artifact_roots()[0].location(),
        parse_entry.value().location()
    );
    assert_eq!(plan.pending_artifact_roots().len(), 2);
    assert!(plan.pending_artifact_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::PendingFileArtifact
            && root.location() == pending_file_entry.value().location()
    }));
    assert!(plan.pending_artifact_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::PendingParseArtifact
            && root.location() == pending_parse_entry.value().location()
    }));
    assert_eq!(plan.blob_index_roots().len(), 1);
    assert_eq!(
        plan.blob_index_roots()[0].location(),
        indexed_entry.location()
    );
    assert_eq!(
        plan.file_artifact_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![file_entry.value().location()]
    );
    assert_eq!(
        plan.parse_artifact_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![parse_entry.value().location()]
    );
    assert_eq!(
        plan.pending_artifact_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![
            pending_file_entry.value().location(),
            pending_parse_entry.value().location()
        ]
    );
    assert_eq!(
        plan.indexed_unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![indexed_entry.location()]
    );
    assert_eq!(
        plan.unindexed_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![unindexed_location]
    );
    assert_eq!(
        plan.file_artifact_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + file_payload.len() as u64
    );
    assert_eq!(
        plan.parse_artifact_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + parse_payload.len() as u64
    );
    assert_eq!(
        plan.pending_artifact_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + pending_file_payload.len() as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + pending_parse_payload.len() as u64
    );
    assert_eq!(
        plan.indexed_unrooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + indexed_payload.len() as u64
    );
    assert_eq!(
        plan.unindexed_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unindexed_payload.len() as u64
    );
    assert_eq!(
        cache
            .read_file_artifact(file_entry.value())
            .expect("file artifact remains readable")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_parse_artifact(parse_entry.value())
            .expect("parse artifact remains readable")
            .as_slice(),
        parse_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_rejects_corrupt_unindexed_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"corrupt unindexed file";
    let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(payload));
    let location = cache
        .append_blob(key, payload)
        .expect("unindexed file blob appends");
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.file_pack().path())
        .expect("file pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .plan_file_blob_reachability()
        .expect_err("corrupt unindexed file blocks plan");

    assert!(matches!(
        error,
        PersistFileBlobReachabilityPlanError::Pack {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_rejects_mismatched_file_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let actual_payload = b"actual indexed file";
    let actual_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(actual_payload));
    let actual_location = cache
        .append_blob(actual_key, actual_payload)
        .expect("actual file blob appends");
    let expected_key =
        PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"expected indexed file"));
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(expected_key, actual_location))
        .expect("mismatched file index entry appends");

    let error = cache
        .plan_file_blob_reachability()
        .expect_err("mismatched indexed file root blocks plan");

    assert!(matches!(
        error,
        PersistFileBlobReachabilityPlanError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_rejects_wrong_store_file_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"value payload"));
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(
            value_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("wrong-store file index entry appends");

    let error = cache
        .plan_file_blob_reachability()
        .expect_err("wrong-store indexed file root blocks plan");

    assert!(matches!(
        error,
        PersistFileBlobReachabilityPlanError::WrongStoreEntry {
            actual: PersistBlobStore::Values
        }
    ));

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
fn cache_cached_expression_node_payload_trace_tombstone_suppresses_older_records() {
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
    cache
        .record_node_trace_tombstone(node_key)
        .expect("trace tombstone records");
    cache
        .record_node_materialized_value_hash(node_key, value_hash)
        .expect("node value relinks");

    let latest = cache
        .lookup_node_trace(node_key)
        .expect("trace lookup succeeds")
        .expect("trace tombstone exists");
    assert!(latest.payload().is_tombstone());

    let mut revalidator = StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("tombstoned trace lookup succeeds"),
        None
    );
    assert_eq!(
        revalidator.calls(),
        0,
        "tombstoned traces must miss before input revalidation"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_tombstone_misses_with_matching_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let input = test_read_file_fingerprint(b"/tmp/source", 7);

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &PersistNodeTracePayload::tombstone())
        .expect("matching-hash trace tombstone records");
    cache
        .record_node_materialized_value_hash(node_key, value_hash)
        .expect("node value relinks");

    let latest = cache
        .lookup_node_trace(node_key)
        .expect("trace lookup succeeds")
        .expect("trace tombstone exists");
    assert_eq!(latest.value_hash(), value_hash);
    assert!(latest.payload().is_tombstone());

    let mut revalidator = StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("matching-hash tombstoned trace lookup succeeds"),
        None
    );
    assert_eq!(
        revalidator.calls(),
        0,
        "matching-hash tombstones must miss before input revalidation"
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
