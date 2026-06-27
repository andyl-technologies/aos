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
mod blob_materialization;
mod blob_pack_locks;
mod blob_sidecars;
mod blob_tail_trim;
mod cached_expression_materialization;
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
