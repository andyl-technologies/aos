//! Unit tests for the shared-arena heap backend seam.
//!
//! These exercise [`EvalHeap`] in shared (parallel) mode directly: allocation
//! routing into the worker's shard, own-shard and cross-shard resolution
//! through every typed getter, per-worker hash-consing, tag-derived domain
//! and generation reporting, and the worker-private cutoff-hash side maps.

use std::sync::Arc;

use super::super::{
    EvalHeap, EvalHeapError, EvalThunk, HeapAllocationDomain, HeapValueHashCacheUpdate,
    SharedHeapArena,
};
use crate::attrs::{AttrEntry, FlatAttrs};
use crate::cache::cutoff::ValueHash;
use crate::compile::IrId;
use crate::heap::HeapGeneration;
use crate::list::NixList;
use crate::string::NixString;
use crate::syntax::SymbolTable;
use crate::value::ValueTag;

/// Builds one shared arena and a shared-mode heap per shard.
fn shared_heaps(workers: usize) -> (Arc<SharedHeapArena>, Vec<EvalHeap>) {
    let arena = Arc::new(SharedHeapArena::new(workers, 1 << 12));
    let heaps = (0..workers)
        .map(|shard| {
            let shard = Arc::clone(arena.shard(shard).expect("shard exists"));
            EvalHeap::with_shared_shard(Arc::clone(&arena), shard)
        })
        .collect();
    (arena, heaps)
}

fn attrs_with_int(value: i64) -> FlatAttrs {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    FlatAttrs::new(
        vec![AttrEntry::new(key, crate::value::Value::int(value))],
        &symbols,
    )
    .expect("attrset builds")
}

/// Every typed shape round-trips through a shared-mode heap's own shard.
#[test]
fn shared_heap_round_trips_every_typed_shape() {
    let (_arena, mut heaps) = shared_heaps(1);
    let heap = &mut heaps[0];
    assert!(heap.uses_shared_arena());

    let string = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("string allocates");
    assert_eq!(
        heap.get_string(string).expect("string resolves").bytes(),
        b"shared"
    );

    let path = heap
        .alloc_path(NixString::from_bytes(b"/shared/path".to_vec()))
        .expect("path allocates");
    assert_eq!(
        heap.get_path(path).expect("path resolves").bytes(),
        b"/shared/path"
    );

    let list = heap
        .alloc_list(NixList::new(vec![string]))
        .expect("list allocates");
    assert_eq!(heap.get_list(list).expect("list resolves").len(), 1);

    let attrs = heap
        .alloc_attrs(0, attrs_with_int(7))
        .expect("attrs allocate");
    assert_eq!(heap.get_attrs(attrs).expect("attrs resolve").len(), 1);
    assert_eq!(
        heap.get_attrs_metadata(attrs)
            .expect("metadata resolves")
            .shape(),
        0
    );

    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("thunk allocates");
    assert!(heap.get_thunk(thunk).is_ok());
    assert!(heap.clone_thunk(thunk).is_ok());

    assert_eq!(heap.len(), 5);
    assert!(!heap.is_empty());
}

/// A worker resolves values another worker allocated into a different shard,
/// through the same typed getters production evaluation uses.
#[test]
fn shared_heaps_resolve_each_others_allocations() {
    let (_arena, mut heaps) = shared_heaps(2);

    let string = heaps[0]
        .alloc_string(NixString::from_bytes(b"from-worker-0".to_vec()))
        .expect("string allocates");
    let thunk = heaps[0]
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("thunk allocates");
    let list = heaps[1]
        .alloc_list(NixList::new(vec![string]))
        .expect("list allocates");

    // Worker 1 dereferences worker 0's allocations (cross-shard probe).
    assert_eq!(
        heaps[1]
            .get_string(string)
            .expect("cross-shard string")
            .bytes(),
        b"from-worker-0"
    );
    assert!(heaps[1].get_thunk(thunk).is_ok());
    assert!(heaps[1].clone_thunk(thunk).is_ok());

    // Worker 0 dereferences worker 1's list, whose element points back into
    // worker 0's shard.
    let resolved = heaps[0].get_list(list).expect("cross-shard list");
    let element = resolved.get(0).expect("element 0");
    assert_eq!(
        heaps[0]
            .get_string(element)
            .expect("element resolves")
            .bytes(),
        b"from-worker-0"
    );
}

/// Per-worker hash-consing still dedupes within one worker's shard, and two
/// workers interning the same content get distinct (content-equal) records.
#[test]
fn shared_hash_cons_is_per_worker() {
    let (_arena, mut heaps) = shared_heaps(2);

    let first = heaps[0]
        .alloc_string(NixString::from_bytes(b"interned".to_vec()))
        .expect("string allocates");
    let second = heaps[0]
        .alloc_string(NixString::from_bytes(b"interned".to_vec()))
        .expect("string allocates");
    assert!(first.raw_eq(second), "same worker interned to one record");
    assert_eq!(heaps[0].len(), 1, "hash-cons hit allocates no new record");

    let other = heaps[1]
        .alloc_string(NixString::from_bytes(b"interned".to_vec()))
        .expect("string allocates");
    assert!(
        !first.raw_eq(other),
        "workers intern independently in their own shards"
    );
    assert_eq!(
        heaps[0]
            .get_string(other)
            .expect("cross-shard resolves")
            .bytes(),
        heaps[0].get_string(first).expect("own resolves").bytes(),
        "distinct records stay content-equal"
    );
}

/// Shared records report the tag-derived allocation domain and generation the
/// serial heap would assign.
#[test]
fn shared_domain_and_generation_mirror_serial_assignment() {
    let (_arena, mut heaps) = shared_heaps(1);
    let heap = &mut heaps[0];

    let string = heap
        .alloc_string(NixString::from_bytes(b"domain".to_vec()))
        .expect("string allocates");
    assert_eq!(
        heap.allocation_domain(string).expect("domain resolves"),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        heap.generation(string).expect("generation resolves"),
        HeapGeneration::Permanent
    );

    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    assert_eq!(
        heap.allocation_domain(thunk).expect("domain resolves"),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        heap.generation(thunk).expect("generation resolves"),
        HeapGeneration::Young
    );
}

/// Typed getters reject wrong-tag handles and unknown pointers exactly like
/// the serial heap.
// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn shared_getters_report_mismatch_and_unknown() {
    let (_arena, mut heaps) = shared_heaps(1);
    let heap = &mut heaps[0];

    let list = heap.alloc_list(NixList::empty()).expect("list allocates");
    // Reuse the list's handle under a string tag: resolvable, wrong record.
    let list_ptr = list.as_list_ptr().expect("list pointer");
    let forged = crate::value::Value::heap(ValueTag::String, list_ptr).expect("forged value");
    assert!(matches!(
        heap.get_string(forged),
        Err(EvalHeapError::RecordTypeMismatch { .. })
    ));

    let unknown = crate::value::Value::heap(
        ValueTag::String,
        std::ptr::NonNull::new(0x1000 as *mut crate::value::HeapObject).expect("non-null"),
    )
    .expect("value builds");
    assert!(matches!(
        heap.get_string(unknown),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
}

/// The worker-private cutoff-hash side maps mirror the serial contract,
/// including the hash-mismatch rejection.
#[test]
fn shared_value_hash_cache_mirrors_serial_contract() {
    let (_arena, mut heaps) = shared_heaps(1);
    let heap = &mut heaps[0];
    let value = heap
        .alloc_string(NixString::from_bytes(b"hashed".to_vec()))
        .expect("string allocates");

    assert_eq!(heap.cached_value_hash(value).expect("cache reads"), None);
    let hash = ValueHash::from_context_free_string_bytes(b"first");
    assert_eq!(
        heap.cache_value_hash(value, hash).expect("cache writes"),
        HeapValueHashCacheUpdate::Inserted
    );
    assert_eq!(
        heap.cache_value_hash(value, hash).expect("cache rewrites"),
        HeapValueHashCacheUpdate::AlreadyPresent
    );
    assert_eq!(
        heap.cached_value_hash(value).expect("cache reads"),
        Some(hash)
    );
    let other = ValueHash::from_context_free_string_bytes(b"second");
    assert!(matches!(
        heap.cache_value_hash(value, other),
        Err(EvalHeapError::ValueHashMismatch { .. })
    ));

    assert_eq!(
        heap.cached_captured_value_hash(value).expect("cache reads"),
        None
    );
    heap.cache_captured_value_hash(value, other)
        .expect("captured cache writes");
    assert_eq!(
        heap.cached_captured_value_hash(value).expect("cache reads"),
        Some(other)
    );
}
