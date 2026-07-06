//! Tests for routed blob I/O and materialization decisions on the cache.

use super::*;
use crate::attrs::AttrPosition;
use crate::cache::cutoff::CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION;
use crate::cache::{
    CacheableInputFingerprint, CachedExpressionValue, CachedExpressionValuePayloadError,
    ImpureInputFingerprint, ImpureInputIdentity, ImpureInputIdentityHash, ImpureInputKind,
    ImpureInputRevalidator, ValueHash,
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
mod blob_materialization;
mod blob_pack_locks;
mod blob_reachability;
mod blob_sidecars;
mod blob_tail_trim;
mod cached_expression_materialization;
mod direct_artifact_reads;
mod file_blob_repack;
mod metadata_sidecars;
mod node_metadata_io;
mod node_metadata_reuse;
mod storage_maintenance;
mod value_blob_repack;

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

fn test_node_trace_dependency(label: &[u8]) -> PersistNodeMetadataKey {
    test_impure_input_node_key(label)
}

fn test_impure_input_identity_hash(label: &[u8]) -> ImpureInputIdentityHash {
    ImpureInputIdentityHash::from_persisted_hash(DurableBlake3Hash::for_bytes(label))
}

fn test_impure_input_node_key(label: &[u8]) -> PersistNodeMetadataKey {
    PersistNodeMetadataKey::for_impure_input(test_impure_input_identity_hash(label))
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
fn cache_cached_expression_node_payload_load_with_trace_revalidation_hits_matching_trace() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
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
    assert_eq!(
        revalidator.calls(),
        1,
        "matching trace should revalidate its input"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_trace_borrowed_visit_decodes_after_scoped_mapping() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let missing_trace_key = test_impure_input_node_key(b"missing trace");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let trace_payload = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");
    let value_store_lock_path = cache
        .layout()
        .blob_store_lock_path(PersistBlobStore::Values);
    let node_metadata_lock_path = cache.layout().node_metadata_lock_path();
    let node_traces_lock_path = cache.layout().node_traces_lock_path();

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
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");
    cache
        .record_node_materialized_value_hash(missing_trace_key, value_hash)
        .expect("missing-trace node value hash records");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    let observed_hash = cache
        .with_cached_expression_node_value_with_trace_revalidation(
            node_key,
            &mut revalidator,
            |value, dependencies| {
                assert_eq!(value, &payload);
                assert_eq!(dependencies, &[dependency_key]);
                let value_store_guard = AdvisoryFileLock::try_lock(
                    &value_store_lock_path,
                    AdvisoryFileLockMode::Exclusive,
                )
                .expect("trace visitor runs after the value-store lock is released");
                drop(value_store_guard);
                let node_metadata_guard = AdvisoryFileLock::try_lock(
                    &node_metadata_lock_path,
                    AdvisoryFileLockMode::Exclusive,
                )
                .expect("trace visitor runs after the node-metadata lock is released");
                drop(node_metadata_guard);
                let node_traces_guard = AdvisoryFileLock::try_lock(
                    &node_traces_lock_path,
                    AdvisoryFileLockMode::Exclusive,
                )
                .expect("trace visitor runs after the node-traces lock is released");
                drop(node_traces_guard);
                assert_eq!(
                    cache
                        .lookup_node_materialized_value_hash(node_key)
                        .expect("node metadata lookup re-enters from trace visitor"),
                    Some(value_hash)
                );
                assert_eq!(
                    cache
                        .lookup_node_trace(node_key)
                        .expect("node trace lookup re-enters from trace visitor")
                        .expect("node trace exists")
                        .value_hash(),
                    value_hash
                );
                assert_eq!(
                    cache
                        .load_cached_expression_value_indexed(value_hash)
                        .expect("indexed value lookup re-enters from trace visitor")
                        .expect("indexed value exists"),
                    payload
                );
                value.value_hash().expect("visited payload hashes")
            },
        )
        .expect("trace-verified borrowed payload lookup succeeds")
        .expect("trace-verified node value exists");

    assert_eq!(observed_hash, value_hash);
    assert_eq!(revalidator.calls(), 1);
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        2,
        "the top-level value decode and the re-entrant value lookup use scoped mapped reads; the memo-read dependency is proven by an index existence probe without decoding its value"
    );
    let mut missing_trace_revalidator = StaticRevalidator::new(Vec::new());
    assert_eq!(
        cache
            .with_cached_expression_node_value_with_trace_revalidation(
                missing_trace_key,
                &mut missing_trace_revalidator,
                |_, _| panic!("missing trace should not visit payload"),
            )
            .expect("missing trace lookup succeeds"),
        None
    );
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        2,
        "trace misses should not map the value pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_checks_memo_read_dependencies() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let changed_dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 8);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut matching =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut matching)
            .expect("trace-verified payload lookup succeeds"),
        Some(payload)
    );
    assert_eq!(
        matching.calls(),
        1,
        "dependency trace input should be revalidated through the parent hit"
    );

    // The verified-node memo caches the dependency's proven hit for the current
    // run. A changed impure input is only observed on a fresh run, so model the
    // run boundary that discards the memo before re-loading.
    cache.clear_verified_node_trace_memo();

    let mut changed = StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(
        changed_dependency_input,
    )]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut changed)
            .expect("changed dependency trace lookup succeeds"),
        None
    );
    assert_eq!(changed.calls(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_trace_revalidation_rejects_uncacheable_memo_read_dependency() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut revalidator = FixedRevalidator::new(ImpureInputFingerprint::current_time());
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("trace-verified payload lookup succeeds"),
        None,
        "uncacheable memo-read supplier traces must reject the parent hit"
    );
    assert_eq!(
        revalidator.calls(),
        1,
        "supplier trace should be revalidated before rejecting the parent hit"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_rejects_changed_memo_read_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let old_dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("old dependency payload builds");
    let new_dependency_payload =
        CachedExpressionValue::immediate(Value::int(8)).expect("new dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let old_dependency_value_hash = old_dependency_payload
        .value_hash()
        .expect("old dependency payload hashes");
    let new_dependency_value_hash = new_dependency_payload
        .value_hash()
        .expect("new dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, old_dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &old_dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("old dependency payload materializes");
    cache
        .record_node_trace(dependency_key, old_dependency_value_hash, &dependency_trace)
        .expect("old dependency trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &new_dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("new dependency payload materializes");
    cache
        .record_node_trace(dependency_key, new_dependency_value_hash, &dependency_trace)
        .expect("new dependency trace records");

    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("trace-verified payload lookup succeeds"),
        None,
        "parent hit must miss when a memo-read supplier advances to another value hash"
    );
    assert_eq!(
        revalidator.calls(),
        0,
        "supplier value-hash mismatch should reject before input revalidation"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_rejects_key_only_memo_read_dependency() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependencies([dependency_key])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("trace-verified payload lookup succeeds"),
        None,
        "key-only memo-read dependencies do not prove the supplier value observed by the parent"
    );
    assert_eq!(revalidator.calls(), 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_rejects_memo_read_cycles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(node_key, value_hash)])
    .expect("node trace dependency records");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");

    let mut revalidator = StaticRevalidator::new(Vec::new());
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("trace-verified payload lookup succeeds"),
        None,
        "cyclic memo-read dependency proofs should miss instead of accepting themselves"
    );
    assert_eq!(revalidator.calls(), 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_trace_revalidation_misses_without_matching_trace() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
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
    let node_key = test_impure_input_node_key(b"node");
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
    let node_key = test_impure_input_node_key(b"node");
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
    let node_key = test_impure_input_node_key(b"node");
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
    let node_key = test_impure_input_node_key(b"node");
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
    let missing = test_impure_input_node_key(b"missing");
    let reuse_only = test_impure_input_node_key(b"reuse-only");

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
    let value_hash = ValueHash::from_canonical_value_hash(payload_hash);
    let key = PersistBlobKey::for_value(value_hash);
    cache
        .append_blob_indexed(key, &payload)
        .expect("manual non-canonical blob indexes");

    let error = cache
        .load_cached_expression_value_indexed(value_hash)
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
fn cache_trace_revalidation_dependency_missing_value_blob_misses_identically() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    // Link the dependency's value hash and trace but never materialize its value
    // blob, so the dependency check reaches the value-blob existence probe.
    cache
        .record_node_materialized_value_hash(dependency_key, dependency_value_hash)
        .expect("dependency value hash records");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("missing dependency-blob lookup succeeds"),
        None,
        "a dependency whose value blob is absent misses exactly as the decode path did"
    );
    assert_eq!(
        revalidator.calls(),
        1,
        "the dependency input is revalidated before the absent-blob miss"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_trace_revalidation_verified_node_memo_evicts_on_dependency_write() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut matching =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input.clone())]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut matching)
            .expect("initial lookup succeeds"),
        Some(payload),
        "the node and its dependency are a valid hit and the dependency is memoized"
    );

    // Tombstoning the dependency is a status-changing write that must evict the
    // memoized dependency hit, so the next load re-checks and misses.
    cache
        .record_node_trace_tombstone(dependency_key)
        .expect("dependency trace tombstone records");

    let mut after_write =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut after_write)
            .expect("post-write lookup succeeds"),
        None,
        "a memoized dependency hit must not survive a tombstone write to that dependency"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_trace_revalidation_shared_dependency_verified_once_per_run() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_key = test_impure_input_node_key(b"first dependent");
    let second_key = test_impure_input_node_key(b"second dependent");
    let dependency_key = test_impure_input_node_key(b"shared dependency");
    let first_payload = CachedExpressionValue::immediate(Value::int(1)).expect("first payload");
    let second_payload = CachedExpressionValue::immediate(Value::int(2)).expect("second payload");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let first_value_hash = first_payload.value_hash().expect("first hashes");
    let second_value_hash = second_payload.value_hash().expect("second hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/shared", 7);
    let dependent_trace = |dependency_hash| {
        PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
            CacheableInputFingerprint,
        >())
        .expect("dependent trace builds")
        .with_memo_read_dependency_records([(dependency_key, dependency_hash)])
        .expect("dependent trace dependency records")
    };
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    for (key, payload, value_hash) in [
        (first_key, &first_payload, first_value_hash),
        (second_key, &second_payload, second_value_hash),
    ] {
        cache
            .materialize_cached_expression_node_value_indexed(
                key,
                payload,
                MaterializationDecision::Materialize,
            )
            .expect("dependent payload materializes");
        cache
            .record_node_trace(key, value_hash, &dependent_trace(dependency_value_hash))
            .expect("dependent trace records");
    }
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(first_key, &mut revalidator)
            .expect("first dependent lookup succeeds"),
        Some(first_payload)
    );
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(second_key, &mut revalidator)
            .expect("second dependent lookup succeeds"),
        Some(second_payload)
    );
    assert_eq!(
        revalidator.calls(),
        1,
        "the shared dependency is verified once per run, not once per dependent"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_decode_verification_knob_round_trips_and_defaults_off() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    assert!(
        !cache.value_decode_verification(),
        "value decode verification is off by default"
    );
    let verifying = PersistCache::open(&root)
        .expect("cache reopens")
        .with_value_decode_verification(true);
    assert!(
        verifying.value_decode_verification(),
        "the verification knob enables the defensive decode path"
    );

    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("value materializes");

    // Both the trusting default and the verifying handle decode the same value.
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("trusting load succeeds"),
        Some(payload.clone())
    );
    assert_eq!(
        verifying
            .load_cached_expression_value_indexed(value_hash)
            .expect("verifying load succeeds"),
        Some(payload)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_buffered_node_demands_flush_matches_immediate_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let buffered_key = test_impure_input_node_key(b"buffered");
    let immediate_key = test_impure_input_node_key(b"immediate");

    // Three immediate demands establish the reference final counters.
    for _ in 0..3 {
        cache
            .record_node_current_demand(immediate_key)
            .expect("immediate demand records");
    }

    // Buffered demands are coalesced in memory and written nothing until flush.
    for _ in 0..3 {
        cache.buffer_node_current_demand(buffered_key);
    }
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("pre-flush lookup succeeds"),
        None,
        "buffered demand does not touch the sidecar before flush"
    );

    cache
        .flush_buffered_node_demands()
        .expect("demand buffer flush succeeds");
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("buffered lookup succeeds"),
        Some(MaterializationReuse::new(0, 3)),
        "the coalesced flush records the full current-run demand count"
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("buffered lookup succeeds"),
        cache
            .lookup_node_materialization_reuse(immediate_key)
            .expect("immediate lookup succeeds"),
        "buffered flush yields the same final counters as immediate records"
    );

    // A flush with an empty buffer is a no-op.
    cache
        .flush_buffered_node_demands()
        .expect("empty demand buffer flush succeeds");
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("post-empty-flush lookup succeeds"),
        Some(MaterializationReuse::new(0, 3))
    );

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
    let node_key = test_impure_input_node_key(b"node");
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
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

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
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );

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
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

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
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );

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
