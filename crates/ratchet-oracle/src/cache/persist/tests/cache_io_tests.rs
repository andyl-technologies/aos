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
use std::sync::{Arc, Barrier};
use std::thread;

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
fn cache_blob_pack_index_entries_are_store_typed() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_payload = b"value payload";
    let value_hash = DurableBlake3Hash::for_bytes(value_payload);
    let value_key = PersistBlobKey::for_value(value_hash);
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");
    let file_payload = b"file payload";
    let file_hash = DurableBlake3Hash::for_bytes(file_payload);
    let file_key = PersistBlobKey::for_file(file_hash);
    let file_location = cache
        .append_blob(file_key, file_payload)
        .expect("file blob appends");

    assert_eq!(
        cache
            .blob_pack_index_entries(PersistBlobStore::Values)
            .expect("value pack scans"),
        vec![PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        cache
            .blob_pack_index_entries(PersistBlobStore::Files)
            .expect("file pack scans"),
        vec![PersistBlobIndexEntry::new(file_key, file_location)]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_index_entries_rejects_corrupt_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"value payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let location = cache.append_blob(key, payload).expect("value blob appends");
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
        .blob_pack_index_entries(PersistBlobStore::Values)
        .expect_err("corrupt value pack scan errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_latest_blob_pack_index_entries_compacts_physical_duplicates() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    assert!(
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Values)
            .expect("empty value pack scans")
            .is_empty()
    );

    let duplicate_payload = b"duplicate payload";
    let duplicate_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(duplicate_payload));
    let first_duplicate = cache
        .append_blob(duplicate_key, duplicate_payload)
        .expect("first duplicate appends");
    let other_payload = b"other payload";
    let other_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(other_payload));
    let other_location = cache
        .append_blob(other_key, other_payload)
        .expect("other blob appends");
    let latest_duplicate = cache
        .append_blob(duplicate_key, duplicate_payload)
        .expect("latest duplicate appends");

    let mut expected = vec![
        PersistBlobIndexEntry::new(duplicate_key, latest_duplicate),
        PersistBlobIndexEntry::new(other_key, other_location),
    ];
    expected.sort_by_key(|entry| entry.key().index_bytes());

    assert_eq!(
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Values)
            .expect("latest value pack entries scan"),
        expected
    );
    assert_eq!(
        cache
            .blob_pack_index_entries(PersistBlobStore::Values)
            .expect("physical value pack entries scan"),
        vec![
            PersistBlobIndexEntry::new(duplicate_key, first_duplicate),
            PersistBlobIndexEntry::new(other_key, other_location),
            PersistBlobIndexEntry::new(duplicate_key, latest_duplicate),
        ],
        "physical scan should keep duplicates for repair tools that need them"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_latest_blob_pack_index_entries_keep_store_namespaces_separate() {
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
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Values)
            .expect("latest value pack entries scan"),
        vec![PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Files)
            .expect("latest file pack entries scan"),
        vec![PersistBlobIndexEntry::new(file_key, file_location)]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_reports_missing_stale_and_dangling_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let exact_payload = b"exact indexed payload";
    let exact_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(exact_payload));
    let exact_entry = cache
        .append_blob_indexed(exact_key, exact_payload)
        .expect("exact indexed payload appends");

    let stale_payload = b"stale duplicate payload";
    let stale_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(stale_payload));
    let stale_current = cache
        .append_blob(stale_key, stale_payload)
        .expect("first stale blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(stale_key, stale_current))
        .expect("stale sidecar entry records");
    let stale_planned = cache
        .append_blob(stale_key, stale_payload)
        .expect("latest stale blob appends");

    let missing_payload = b"missing sidecar payload";
    let missing_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(missing_payload));
    let missing_location = cache
        .append_blob(missing_key, missing_payload)
        .expect("missing-index blob appends");

    let dangling_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"dangling"));
    let dangling_entry = PersistBlobIndexEntry::new(dangling_key, PersistBlobLocation::new(999, 8));
    cache
        .value_index()
        .append_entry(dangling_entry)
        .expect("dangling sidecar entry records");

    let plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("rebuild plan builds");
    let mut planned = vec![
        exact_entry,
        PersistBlobIndexEntry::new(stale_key, stale_planned),
        PersistBlobIndexEntry::new(missing_key, missing_location),
    ];
    planned.sort_by_key(|entry| entry.key().index_bytes());

    assert!(plan.lookup_repair_needed());
    assert_eq!(plan.planned_entries(), planned.as_slice());
    assert_eq!(
        plan.missing_entries(),
        &[PersistBlobIndexEntry::new(missing_key, missing_location)]
    );
    assert_eq!(
        plan.stale_entries(),
        &[PersistBlobIndexStaleEntry::new(
            PersistBlobIndexEntry::new(stale_key, stale_current),
            PersistBlobIndexEntry::new(stale_key, stale_planned),
        )]
    );
    assert_eq!(plan.dangling_entries(), &[dangling_entry]);
    assert_eq!(
        cache
            .lookup_blob_location(stale_key)
            .expect("stale lookup still succeeds"),
        Some(stale_current),
        "planning should not rewrite the sidecar"
    );
    assert_eq!(
        cache
            .lookup_blob_location(missing_key)
            .expect("missing lookup still succeeds"),
        None,
        "planning should not index unindexed physical records"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_keeps_store_namespaces_separate() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"shared namespace payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let value_key = PersistBlobKey::for_value(hash);
    let file_key = PersistBlobKey::for_file(hash);
    let value_entry = cache
        .append_blob_indexed(value_key, payload)
        .expect("value indexed payload appends");
    let file_entry = cache
        .append_blob_indexed(file_key, payload)
        .expect("file indexed payload appends");

    let value_plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("value rebuild plan builds");
    let file_plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Files)
        .expect("file rebuild plan builds");

    assert!(!value_plan.lookup_repair_needed());
    assert_eq!(value_plan.planned_entries(), &[value_entry]);
    assert!(value_plan.missing_entries().is_empty());
    assert!(value_plan.stale_entries().is_empty());
    assert!(value_plan.dangling_entries().is_empty());

    assert!(!file_plan.lookup_repair_needed());
    assert_eq!(file_plan.planned_entries(), &[file_entry]);
    assert!(file_plan.missing_entries().is_empty());
    assert!(file_plan.stale_entries().is_empty());
    assert!(file_plan.dangling_entries().is_empty());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_ignores_duplicate_sidecar_history_for_lookup_repair() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"sidecar duplicate payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let planned_location = cache
        .append_blob(key, payload)
        .expect("planned blob appends");
    let older_location = PersistBlobLocation::new(999, 7);
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, older_location))
        .expect("older sidecar entry records");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, planned_location))
        .expect("newest sidecar entry records");

    let plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("rebuild plan builds");

    assert!(!plan.lookup_repair_needed());
    assert_eq!(
        plan.planned_entries(),
        &[PersistBlobIndexEntry::new(key, planned_location)]
    );
    assert!(plan.missing_entries().is_empty());
    assert!(plan.stale_entries().is_empty());
    assert!(plan.dangling_entries().is_empty());
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64,
        "planning should not canonicalize duplicate sidecar history"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_classifies_wrong_store_sidecar_entry_as_dangling() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"value payload";
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let value_location = cache
        .append_blob(value_key, payload)
        .expect("value blob appends");
    let wrong_store_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"wrong store"));
    let wrong_store_entry =
        PersistBlobIndexEntry::new(wrong_store_key, PersistBlobLocation::new(777, 5));
    cache
        .value_index()
        .append_entry(wrong_store_entry)
        .expect("wrong-store sidecar entry records");

    let plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("rebuild plan builds");

    assert!(plan.lookup_repair_needed());
    assert_eq!(
        plan.planned_entries(),
        &[PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        plan.missing_entries(),
        &[PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert!(plan.stale_entries().is_empty());
    assert_eq!(plan.dangling_entries(), &[wrong_store_entry]);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_rejects_corrupt_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"planned corrupt payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let location = cache.append_blob(key, payload).expect("value blob appends");
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
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect_err("corrupt value pack plan errors");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildPlanError::Pack {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_rejects_malformed_sidecar() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    fs::write(cache.value_index().path(), [0]).expect("malformed index writes");

    let error = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect_err("malformed value index plan errors");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildPlanError::Index {
            source: PersistBlobIndexError::Format {
                source: PersistPackFormatError::ShortBlobIndexEntry { .. },
                ..
            },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_repairs_missing_stale_and_dangling_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let exact_payload = b"rebuild exact indexed payload";
    let exact_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(exact_payload));
    let exact_entry = cache
        .append_blob_indexed(exact_key, exact_payload)
        .expect("exact indexed payload appends");

    let stale_payload = b"rebuild stale duplicate payload";
    let stale_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(stale_payload));
    let stale_current = cache
        .append_blob(stale_key, stale_payload)
        .expect("first stale blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(stale_key, stale_current))
        .expect("stale sidecar entry records");
    let stale_planned = cache
        .append_blob(stale_key, stale_payload)
        .expect("latest stale blob appends");

    let missing_payload = b"rebuild missing sidecar payload";
    let missing_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(missing_payload));
    let missing_location = cache
        .append_blob(missing_key, missing_payload)
        .expect("missing-index blob appends");

    let dangling_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"rebuild dangling"));
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            dangling_key,
            PersistBlobLocation::new(999, 8),
        ))
        .expect("dangling sidecar entry records");

    let plan = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect("blob index rebuilds");
    let mut planned = vec![
        exact_entry,
        PersistBlobIndexEntry::new(stale_key, stale_planned),
        PersistBlobIndexEntry::new(missing_key, missing_location),
    ];
    planned.sort_by_key(|entry| entry.key().index_bytes());

    assert!(plan.lookup_repair_needed());
    assert_eq!(plan.planned_entries(), planned.as_slice());
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("rebuilt value entries scan"),
        planned
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * planned.len()) as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(stale_key)
            .expect("stale lookup succeeds"),
        Some(stale_planned)
    );
    assert_eq!(
        cache
            .lookup_blob_location(missing_key)
            .expect("missing lookup succeeds"),
        Some(missing_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(dangling_key)
            .expect("dangling lookup succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_canonicalizes_duplicate_sidecar_history() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"rebuild duplicate sidecar payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let planned_location = cache
        .append_blob(key, payload)
        .expect("planned blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            key,
            PersistBlobLocation::new(999, 7),
        ))
        .expect("older sidecar entry records");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, planned_location))
        .expect("newest sidecar entry records");

    let plan = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect("blob index rebuilds");

    assert!(!plan.lookup_repair_needed());
    assert_eq!(
        plan.planned_entries(),
        &[PersistBlobIndexEntry::new(key, planned_location)]
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("rebuilt lookup succeeds"),
        Some(planned_location)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_repairs_file_store_sidecar() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"file rebuild payload";
    let file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(payload));
    let file_location = cache
        .append_blob(file_key, payload)
        .expect("file blob appends");
    let wrong_store_entry = PersistBlobIndexEntry::new(
        PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"wrong store")),
        PersistBlobLocation::new(777, 5),
    );
    cache
        .file_index()
        .append_entry(wrong_store_entry)
        .expect("wrong-store file sidecar entry records");

    let plan = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Files)
        .expect("file blob index rebuilds");

    assert!(plan.lookup_repair_needed());
    assert_eq!(
        plan.missing_entries(),
        &[PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(plan.dangling_entries(), &[wrong_store_entry]);
    assert_eq!(
        cache
            .file_index()
            .latest_entries()
            .expect("rebuilt file entries scan"),
        vec![PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_key)
            .expect("file lookup succeeds"),
        Some(file_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(wrong_store_entry.key())
            .expect("wrong store lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_rejects_corrupt_pack_without_rewriting_sidecar() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let indexed_payload = b"surviving indexed payload";
    let indexed_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(indexed_payload));
    let indexed_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed payload appends");
    let corrupt_payload = b"corrupt rebuild payload";
    let corrupt_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(corrupt_payload));
    let corrupt_location = cache
        .append_blob(corrupt_key, corrupt_payload)
        .expect("corrupt-target blob appends");
    let payload_offset = corrupt_location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect_err("corrupt pack rebuild errors");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildError::Plan {
            source: PersistBlobIndexRebuildPlanError::Pack {
                source: PersistBlobPackError::PayloadHashMismatch { .. },
            },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "failed planning should leave the sidecar unchanged"
    );
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("value entries still scan"),
        vec![indexed_entry]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexes_rebuild_from_packs_repairs_value_and_file_sidecars() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_payload = b"all rebuild value payload";
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(value_payload));
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");
    let file_payload = b"all rebuild file payload";
    let file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(file_payload));
    let file_location = cache
        .append_blob(file_key, file_payload)
        .expect("file blob appends");

    let rebuild = cache
        .rebuild_blob_indexes_from_packs()
        .expect("blob indexes rebuild");

    assert!(rebuild.lookup_repair_needed());
    assert_eq!(
        rebuild.value_blob_index().missing_entries(),
        &[PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        rebuild.file_blob_index().missing_entries(),
        &[PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value lookup succeeds"),
        Some(value_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_key)
            .expect("file lookup succeeds"),
        Some(file_location)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexes_rebuild_from_packs_keeps_value_rebuild_when_file_rebuild_fails() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_payload = b"boundary value payload";
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(value_payload));
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");
    let file_payload = b"boundary corrupt file payload";
    let file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(file_payload));
    let file_location = cache
        .append_blob(file_key, file_payload)
        .expect("file blob appends");
    let file_sentinel_entry = PersistBlobIndexEntry::new(
        PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"file sentinel")),
        PersistBlobLocation::new(888, 6),
    );
    cache
        .file_index()
        .append_entry(file_sentinel_entry)
        .expect("file sentinel sidecar entry records");
    let payload_offset = file_location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.file_pack().path())
        .expect("file pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .rebuild_blob_indexes_from_packs()
        .expect_err("file rebuild errors");

    assert!(matches!(
        error,
        PersistBlobIndexesRebuildError::FileBlobIndex {
            source: PersistBlobIndexRebuildError::Plan {
                source: PersistBlobIndexRebuildPlanError::Pack {
                    source: PersistBlobPackError::PayloadHashMismatch { .. },
                },
            },
        }
    ));
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value lookup succeeds"),
        Some(value_location),
        "value sidecar rebuild should remain committed after file rebuild failure"
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_key)
            .expect("file lookup succeeds"),
        None,
        "failed file-side planning should not rewrite the file sidecar"
    );
    assert_eq!(
        cache
            .file_index()
            .latest_entries()
            .expect("file sidecar still scans"),
        vec![file_sentinel_entry],
        "failed file-side planning should preserve existing file sidecar entries"
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
fn cache_file_artifact_index_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for worker in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let source = format!("let x = {worker}; in x");
            let parse_key = test_parse_key(source.as_bytes());
            let realpath = format!("/src/{worker}.nix");
            let file_key = ParseFileKey::for_source(realpath.as_str(), source.as_bytes());
            let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
            let value = PersistFileArtifactIndexValue::new(
                DurableBlake3Hash::for_bytes(format!("artifact-{worker}").as_bytes()),
                PersistBlobLocation::new(
                    PERSIST_BLOB_PACK_HEADER_LEN as u64 + worker as u64,
                    worker as u64,
                ),
            );

            worker_barrier.wait();
            worker_cache
                .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
                .expect("file artifact records");
            (key, value)
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }

    for (key, value) in &recorded {
        assert_eq!(
            cache
                .lookup_file_artifact(*key)
                .expect("file artifact lookup succeeds"),
            Some(*value)
        );
    }
    assert_eq!(
        cache
            .file_artifact_index()
            .latest_entries()
            .expect("latest file artifact entries")
            .len(),
        workers
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * workers) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_index_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_file_artifacts_for_tests()
            .expect("file artifact lock acquires");
        panic!("poison persistent file artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    let error = cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
        .expect_err("poisoned same-root file artifact lock should reject writes");

    assert!(matches!(
        error,
        PersistFileArtifactIndexError::WriteLockPoisoned
    ));
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_fixed_record_indexes_compact_to_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"value payload"));
    let file_blob_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"file payload"));
    let value_first = PersistBlobLocation::new(111, 12);
    let value_latest = PersistBlobLocation::new(222, 34);
    let file_first = PersistBlobLocation::new(333, 56);
    let file_latest = PersistBlobLocation::new(444, 78);

    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_first))
        .expect("first value blob index entry appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_latest))
        .expect("latest value blob index entry appends");
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_blob_key, file_first))
        .expect("first file blob index entry appends");
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_blob_key, file_latest))
        .expect("latest file blob index entry appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_artifact_first = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"first file artifact"),
        PersistBlobLocation::new(555, 90),
    );
    let file_artifact_latest = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"latest file artifact"),
        PersistBlobLocation::new(666, 12),
    );
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            file_artifact_first,
        ))
        .expect("first file artifact entry records");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            file_artifact_latest,
        ))
        .expect("latest file artifact entry records");

    let parse_artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let parse_artifact_first = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"first parse artifact"),
        PersistBlobLocation::new(777, 34),
    );
    let parse_artifact_latest = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"latest parse artifact"),
        PersistBlobLocation::new(888, 56),
    );
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            parse_artifact_first,
        ))
        .expect("first parse artifact entry records");
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            parse_artifact_latest,
        ))
        .expect("latest parse artifact entry records");

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
    );

    assert_eq!(
        cache
            .compact_blob_index(PersistBlobStore::Values)
            .expect("value index compacts"),
        1
    );
    assert_eq!(
        cache
            .compact_blob_index(PersistBlobStore::Files)
            .expect("file index compacts"),
        1
    );
    assert_eq!(
        cache
            .compact_file_artifact_index()
            .expect("file artifact index compacts"),
        1
    );
    assert_eq!(
        cache
            .compact_parse_artifact_index()
            .expect("parse artifact index compacts"),
        1
    );

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value lookup succeeds"),
        Some(value_latest)
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_blob_key)
            .expect("file lookup succeeds"),
        Some(file_latest)
    );
    assert_eq!(
        cache
            .lookup_file_artifact(file_artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(file_artifact_latest)
    );
    assert_eq!(
        cache
            .lookup_parse_artifact(parse_artifact_key)
            .expect("parse artifact lookup succeeds"),
        Some(parse_artifact_latest)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_index_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for worker in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let source = format!("let x = {worker}; in x");
            let parse_key = test_parse_key(source.as_bytes());
            let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
            let value = PersistParseArtifactIndexValue::new(
                DurableBlake3Hash::for_bytes(format!("parse-artifact-{worker}").as_bytes()),
                PersistBlobLocation::new(
                    PERSIST_BLOB_PACK_HEADER_LEN as u64 + worker as u64,
                    worker as u64,
                ),
            );

            worker_barrier.wait();
            worker_cache
                .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, value))
                .expect("parse artifact records");
            (key, value)
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }

    for (key, value) in &recorded {
        assert_eq!(
            cache
                .lookup_parse_artifact(*key)
                .expect("parse artifact lookup succeeds"),
            Some(*value)
        );
    }
    assert_eq!(
        cache
            .parse_artifact_index()
            .latest_entries()
            .expect("latest parse artifact entries")
            .len(),
        workers
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * workers) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_index_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_parse_artifacts_for_tests()
            .expect("parse artifact lock acquires");
        panic!("poison persistent parse artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let value = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"serialized parse artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    let error = cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, value))
        .expect_err("poisoned same-root parse artifact lock should reject writes");

    assert!(matches!(
        error,
        PersistParseArtifactIndexError::WriteLockPoisoned
    ));
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_sidecar_compaction_compacts_all_current_sidecars() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"value payload"));
    let value_latest = PersistBlobLocation::new(222, 34);
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            value_key,
            PersistBlobLocation::new(111, 12),
        ))
        .expect("first value blob index entry appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_latest))
        .expect("latest value blob index entry appends");

    let file_blob_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"file payload"));
    let file_latest = PersistBlobLocation::new(444, 78);
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(
            file_blob_key,
            PersistBlobLocation::new(333, 56),
        ))
        .expect("first file blob index entry appends");
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_blob_key, file_latest))
        .expect("latest file blob index entry appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_artifact_latest = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"latest file artifact"),
        PersistBlobLocation::new(666, 12),
    );
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            PersistFileArtifactIndexValue::new(
                DurableBlake3Hash::for_bytes(b"first file artifact"),
                PersistBlobLocation::new(555, 90),
            ),
        ))
        .expect("first file artifact entry records");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            file_artifact_latest,
        ))
        .expect("latest file artifact entry records");

    let parse_artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let parse_artifact_latest = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"latest parse artifact"),
        PersistBlobLocation::new(888, 56),
    );
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            PersistParseArtifactIndexValue::new(
                DurableBlake3Hash::for_bytes(b"first parse artifact"),
                PersistBlobLocation::new(777, 34),
            ),
        ))
        .expect("first parse artifact entry records");
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            parse_artifact_latest,
        ))
        .expect("latest parse artifact entry records");

    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let node_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"node value"));
    let node_metadata_latest = PersistNodeMetadataIndexValue::with_materialized_value_hash(
        MaterializationReuse::new(3, 4),
        node_value_hash,
    );
    cache
        .record_node_metadata(PersistNodeMetadataIndexEntry::new(
            node_key,
            PersistNodeMetadataIndexValue::new(MaterializationReuse::new(1, 2)),
        ))
        .expect("first node metadata records");
    cache
        .record_node_metadata(PersistNodeMetadataIndexEntry::new(
            node_key,
            node_metadata_latest,
        ))
        .expect("latest node metadata records");

    let trace_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"trace value"));
    let trace_payload = test_node_trace_payload(b"node trace", 1);
    cache
        .record_node_trace(
            node_key,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale trace")),
            &PersistNodeTracePayload::tombstone(),
        )
        .expect("first node trace records");
    cache
        .record_node_trace(node_key, trace_value_hash, &trace_payload)
        .expect("latest node trace records");
    let trace_log_len_before = fs::metadata(cache.node_trace_log().path())
        .expect("node trace log metadata before compaction")
        .len();

    let compaction = cache.compact_sidecars().expect("sidecars compact");
    assert_eq!(compaction.value_blob_index_entries(), 1);
    assert_eq!(compaction.file_blob_index_entries(), 1);
    assert_eq!(compaction.file_artifact_entries(), 1);
    assert_eq!(compaction.parse_artifact_entries(), 1);
    assert_eq!(compaction.node_metadata_entries(), 1);
    assert_eq!(compaction.node_trace_entries(), 1);
    assert_eq!(compaction.total_entries(), 6);

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64
    );
    let trace_log_len_after = fs::metadata(cache.node_trace_log().path())
        .expect("node trace log metadata after compaction")
        .len();
    assert!(
        trace_log_len_after < trace_log_len_before,
        "node trace compaction should rewrite only newest records"
    );
    assert_eq!(
        trace_log_len_after,
        PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64
            + trace_payload.encode().expect("trace payload encodes").len() as u64
    );

    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value blob lookup succeeds"),
        Some(value_latest)
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_blob_key)
            .expect("file blob lookup succeeds"),
        Some(file_latest)
    );
    assert_eq!(
        cache
            .lookup_file_artifact(file_artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(file_artifact_latest)
    );
    assert_eq!(
        cache
            .lookup_parse_artifact(parse_artifact_key)
            .expect("parse artifact lookup succeeds"),
        Some(parse_artifact_latest)
    );
    assert_eq!(
        cache
            .lookup_node_metadata(node_key)
            .expect("node metadata lookup succeeds"),
        Some(node_metadata_latest)
    );
    assert_eq!(
        cache
            .lookup_node_trace(node_key)
            .expect("node trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            node_key,
            trace_value_hash,
            trace_payload,
        ))
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
fn cache_node_trace_log_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for worker in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let subject = format!("input-{worker}");
            let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(
                subject.as_bytes(),
            ));
            let value_subject = format!("value-{worker}");
            let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(
                value_subject.as_bytes(),
            ));
            let payload = test_node_trace_payload(subject.as_bytes(), worker as u8);

            worker_barrier.wait();
            worker_cache
                .record_node_trace(key, value_hash, &payload)
                .expect("node trace records");
            (key, value_hash, payload)
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }

    for (key, value_hash, payload) in &recorded {
        assert_eq!(
            cache
                .lookup_node_trace(*key)
                .expect("node trace lookup succeeds"),
            Some(PersistNodeTraceLogEntry::new(
                *key,
                *value_hash,
                payload.clone()
            ))
        );
    }
    assert_eq!(
        cache
            .node_trace_log()
            .latest_entries()
            .expect("latest trace entries")
            .len(),
        workers
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_trace_log_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_node_traces_for_tests()
            .expect("node trace lock acquires");
        panic!("poison persistent node trace write lock");
    });
    assert!(poisoner.join().is_err());

    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = test_node_trace_payload(b"input", 1);
    let error = cache
        .record_node_trace(key, value_hash, &payload)
        .expect_err("poisoned same-root trace lock should reject writes");

    assert!(matches!(error, PersistNodeTraceLogError::WriteLockPoisoned));
    assert_eq!(
        fs::metadata(cache.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_maintenance_compacts_sidecars_rebuilds_indexes_and_trims_tails() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_payload = b"value live payload";
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(value_payload));
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            value_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("stale value blob index entry appends");
    let value_materialized = cache
        .materialize_blob_indexed(
            value_key,
            value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value blob materializes");
    let PersistMaterialization::Materialized(value_location) = value_materialized else {
        panic!("value blob should materialize");
    };
    let value_tail_payload = b"value tail";
    let value_tail_key =
        PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(value_tail_payload));
    let value_tail_location = cache
        .append_blob(value_tail_key, value_tail_payload)
        .expect("value tail appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"file live payload";
    let file_blob_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(file_payload));
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(
            file_blob_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("stale file blob index entry appends");
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            PersistFileArtifactIndexValue::new(
                DurableBlake3Hash::for_bytes(b"stale file artifact"),
                PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
            ),
        ))
        .expect("stale file artifact entry records");
    let file_materialized = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let file_index_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    let file_index_value = file_index_entry.value();
    let file_tail_payload = b"file tail";
    let file_tail_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(file_tail_payload));
    let file_tail_location = cache
        .append_blob(file_tail_key, file_tail_payload)
        .expect("file tail appends");
    let value_pack_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before maintenance")
        .len();
    let file_pack_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before maintenance")
        .len();

    let maintenance = cache.compact_storage().expect("storage maintenance runs");

    assert_eq!(maintenance.sidecars().value_blob_index_entries(), 1);
    assert_eq!(maintenance.sidecars().file_blob_index_entries(), 1);
    assert_eq!(maintenance.sidecars().file_artifact_entries(), 1);
    assert_eq!(maintenance.sidecars().parse_artifact_entries(), 0);
    assert_eq!(maintenance.sidecars().node_metadata_entries(), 0);
    assert_eq!(maintenance.sidecars().node_trace_entries(), 0);
    assert_eq!(maintenance.sidecars().total_entries(), 3);
    assert!(maintenance.blob_indexes().lookup_repair_needed());
    assert_eq!(
        maintenance
            .blob_indexes()
            .value_blob_index()
            .missing_entries(),
        &[PersistBlobIndexEntry::new(
            value_tail_key,
            value_tail_location
        )]
    );
    assert_eq!(
        maintenance
            .blob_indexes()
            .file_blob_index()
            .missing_entries(),
        &[PersistBlobIndexEntry::new(
            file_tail_key,
            file_tail_location
        )]
    );
    assert_eq!(
        maintenance.value_blob_pack().bytes_before(),
        value_pack_before
    );
    assert_eq!(maintenance.value_blob_pack().reclaimed_bytes(), 0);
    assert_eq!(
        maintenance.file_blob_pack().bytes_before(),
        file_pack_before
    );
    assert_eq!(maintenance.file_blob_pack().reclaimed_bytes(), 0);
    assert_eq!(
        maintenance.reclaimed_blob_bytes(),
        maintenance.value_blob_pack().reclaimed_bytes()
            + maintenance.file_blob_pack().reclaimed_bytes()
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata after maintenance")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata after maintenance")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata after maintenance")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value blob lookup succeeds"),
        Some(value_location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(value_key)
            .expect("indexed value read succeeds")
            .expect("indexed value exists")
            .as_slice(),
        value_payload
    );
    assert_eq!(
        cache
            .read_file_artifact(file_index_value)
            .expect("file artifact remains readable")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(value_tail_key)
            .expect("indexed value tail read succeeds")
            .expect("indexed value tail exists")
            .as_slice(),
        value_tail_payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(file_tail_key)
            .expect("indexed file tail read succeeds")
            .expect("indexed file tail exists")
            .as_slice(),
        file_tail_payload
    );

    let value_pack_after = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata after maintenance")
        .len();
    let file_pack_after = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata after maintenance")
        .len();
    let second_maintenance = cache
        .compact_storage()
        .expect("second storage maintenance runs");
    assert!(!second_maintenance.blob_indexes().lookup_repair_needed());
    assert_eq!(
        second_maintenance.value_blob_pack().bytes_before(),
        value_pack_after
    );
    assert_eq!(
        second_maintenance.value_blob_pack().bytes_after(),
        value_pack_after
    );
    assert_eq!(second_maintenance.value_blob_pack().reclaimed_bytes(), 0);
    assert_eq!(
        second_maintenance.file_blob_pack().bytes_before(),
        file_pack_after
    );
    assert_eq!(
        second_maintenance.file_blob_pack().bytes_after(),
        file_pack_after
    );
    assert_eq!(second_maintenance.file_blob_pack().reclaimed_bytes(), 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_maintenance_value_rebuild_failure_keeps_sidecar_compaction() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_payload = b"corrupt value payload";
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(value_payload));
    let value_location = cache
        .append_blob_indexed(value_key, value_payload)
        .expect("value blob appends")
        .location();
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_location))
        .expect("duplicate value index entry appends");

    let file_payload = b"file live payload";
    let file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(file_payload));
    let file_location = cache
        .append_blob_indexed(file_key, file_payload)
        .expect("file blob appends")
        .location();
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_key, file_location))
        .expect("duplicate file index entry appends");

    let payload_offset = value_location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");
    let value_pack_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before maintenance")
        .len();
    let file_pack_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before maintenance")
        .len();

    let error = cache
        .compact_storage()
        .expect_err("value rebuild failure aborts storage maintenance");

    assert!(matches!(
        error,
        PersistStorageMaintenanceError::BlobIndexes {
            source: PersistBlobIndexesRebuildError::ValueBlobIndex {
                source: PersistBlobIndexRebuildError::Plan {
                    source: PersistBlobIndexRebuildPlanError::Pack {
                        source: PersistBlobPackError::PayloadHashMismatch { .. },
                    },
                },
            },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata after failed maintenance")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "sidecar compaction should remain committed before value rebuild fails"
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata after failed maintenance")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "later sidecar compactions also run before blob-index rebuilds"
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after failed maintenance")
            .len(),
        value_pack_before,
        "failed value rebuild must not truncate the value pack"
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after failed maintenance")
            .len(),
        file_pack_before,
        "file rebuild and trim should not run after value rebuild fails"
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("compacted value index lookup succeeds"),
        Some(value_location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(file_key)
            .expect("indexed file read succeeds")
            .expect("indexed file remains")
            .as_slice(),
        file_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_maintenance_file_trim_failure_keeps_blob_index_rebuilds() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_payload = b"value live payload";
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(value_payload));
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let expected_file_hash = DurableBlake3Hash::for_bytes(b"expected file");
    let wrong_file_payload = b"wrong file payload";
    let wrong_file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(wrong_file_payload));
    let wrong_file_location = cache
        .append_blob(wrong_file_key, wrong_file_payload)
        .expect("wrong file blob appends");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key),
            PersistFileArtifactIndexValue::new(expected_file_hash, wrong_file_location),
        ))
        .expect("wrong file artifact root records");
    let file_pack_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before maintenance")
        .len();

    let error = cache
        .compact_storage()
        .expect_err("file trim failure aborts storage maintenance");

    assert!(matches!(
        error,
        PersistStorageMaintenanceError::FileBlobPack {
            source: PersistBlobPackTrimError::Read {
                source: PersistBlobPackError::RecordHashMismatch { .. },
            },
        }
    ));
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("rebuilt value index lookup succeeds"),
        Some(value_location),
        "value blob-index rebuild should stay committed before file trim fails"
    );
    assert_eq!(
        cache
            .lookup_blob_location(wrong_file_key)
            .expect("rebuilt file index lookup succeeds"),
        Some(wrong_file_location),
        "file blob-index rebuild should stay committed before file trim fails"
    );
    assert_eq!(
        cache
            .read_blob_indexed(value_key)
            .expect("indexed value read succeeds")
            .expect("indexed value remains")
            .as_slice(),
        value_payload
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after failed maintenance")
            .len(),
        file_pack_before,
        "failed file verification must not truncate the file pack"
    );
    assert_eq!(
        cache
            .read_blob(wrong_file_key, wrong_file_location)
            .expect("wrong file record remains after failed trim")
            .as_slice(),
        wrong_file_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_traces_compacts_to_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let other_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"other value"));
    let stale_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale value"));
    let payload = test_node_trace_payload(b"input", 1);
    let stale_payload = test_node_trace_payload(b"stale", 2);
    let other_payload = PersistNodeTracePayload::tombstone();

    cache
        .record_node_trace(key, stale_value_hash, &stale_payload)
        .expect("stale trace records");
    cache
        .record_node_trace(other_key, other_value_hash, &other_payload)
        .expect("other trace records");
    cache
        .record_node_trace(key, value_hash, &payload)
        .expect("latest trace records");
    let before_len = fs::metadata(cache.node_trace_log().path())
        .expect("trace log metadata before compaction")
        .len();

    assert_eq!(cache.compact_node_traces().expect("traces compact"), 2);
    assert!(
        fs::metadata(cache.node_trace_log().path())
            .expect("trace log metadata after compaction")
            .len()
            < before_len
    );
    assert_eq!(
        cache.lookup_node_trace(key).expect("trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(key, value_hash, payload))
    );
    assert_eq!(
        cache
            .lookup_node_trace(other_key)
            .expect("other trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            other_key,
            other_value_hash,
            other_payload
        ))
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
fn cache_node_current_demand_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_cache
                .record_node_current_demand(key)
                .expect("current demand records")
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }
    recorded.sort_by_key(|reuse| reuse.current_run_demands());

    assert_eq!(
        recorded,
        (1..=workers as u64)
            .map(|current_run_demands| MaterializationReuse::new(0, current_run_demands))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(0, workers as u64))
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * workers) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_node_metadata_for_tests()
            .expect("node metadata lock acquires");
        panic!("poison persistent node metadata write lock");
    });
    assert!(poisoner.join().is_err());

    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let error = cache
        .record_node_current_demand(key)
        .expect_err("poisoned same-root metadata lock should reject writes");

    assert!(matches!(
        error,
        PersistNodeMetadataIndexError::WriteLockPoisoned
    ));
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        0
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
