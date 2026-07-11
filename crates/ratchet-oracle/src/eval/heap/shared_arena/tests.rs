//! Cross-worker allocation-and-dereference tests for [`SharedHeapArena`].
//!
//! These tests extend the P2 parallel-force harness
//! ([`super::super::super::parallel_force`]): where P2 forced shared cells whose
//! bodies produced *immediate* values, here every cell body **allocates new heap
//! values into its worker's shard** while **dereferencing values other workers
//! allocated in other shards**. That exercises exactly the cross-worker traffic
//! P3b's scheduler will generate:
//!
//! - a body forces its dependency cells (P2 claim/park/replay protocol);
//! - it resolves each dependency's published [`Value`] *through the shared
//!   arena* - a cross-shard dereference - and reads its content;
//! - it builds a **new** list and string from those cross-worker values and
//!   publishes them into its own shard;
//! - every worker that forces the same root observes the identical value
//!   (exactly-once body) and resolves it to identical content (no torn reads).
//!
//! A seeded yield-injection stress test shuffles thread interleavings across
//! many iterations and asserts the resolved contents are invariant.

use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::eval::parallel_force::shared_parallel_thunk_cells;
use crate::eval::parallel_force::{force_shared_parallel_roots, infinite_recursion_error};
use crate::eval::thunk_registry::ParallelForceCycleRegistry;
use crate::heap::flat::FlatObjectKind;
use crate::list::NixList;
use crate::string::NixString;
use crate::value::Value;

use super::{SharedHeapArena, SharedHeapError};

/// Maps a 1-based [`ParallelThunkWorkerId`](crate::eval::thunk_cas::ParallelThunkWorkerId)
/// raw value to a 0-based shard index.
fn worker_shard(worker_raw: u64, shard_count: usize) -> usize {
    ((worker_raw as usize).saturating_sub(1)) % shard_count
}

/// Basic single-thread round trip: allocate in shard 0, resolve from the arena.
#[test]
fn allocate_and_resolve_single_shard() {
    let arena = SharedHeapArena::new(1, 64);
    let shard = arena.shard(0).expect("shard 0 exists");
    let hello = shard
        .alloc_string(NixString::from_bytes(b"hello".to_vec()))
        .expect("string allocation succeeds");
    let list = shard
        .alloc_list(NixList::new(vec![hello]))
        .expect("list allocation succeeds");

    assert_eq!(
        arena.get_string(hello).expect("string resolves").bytes(),
        b"hello"
    );
    let resolved = arena.get_list(list).expect("list resolves");
    assert_eq!(resolved.len(), 1);
    assert_eq!(
        arena
            .get_string(resolved.get(0).expect("element 0"))
            .expect("element string resolves")
            .bytes(),
        b"hello"
    );
    assert_eq!(arena.published_len(), 2);
}

/// A value allocated in one shard resolves from a different shard's worker.
#[test]
fn cross_shard_resolution() {
    let arena = SharedHeapArena::new(4, 64);
    let from_shard_3 = arena
        .shard(3)
        .expect("shard 3 exists")
        .alloc_string(NixString::from_bytes(b"x86_64-linux".to_vec()))
        .expect("allocation succeeds");

    // Any shard's worker can resolve the shard-3 handle through the arena.
    assert_eq!(
        arena
            .get_string(from_shard_3)
            .expect("cross-shard string resolves")
            .bytes(),
        b"x86_64-linux"
    );
}

/// Production flat publication across shards occupies one Candidate-C index
/// space while the active runtime values still carry native pointers.
#[cfg(all(unix, target_pointer_width = "64"))]
#[test]
fn production_flat_objects_share_one_reservation_index_space() {
    let arena = SharedHeapArena::new(4, 64);
    assert!(arena.uses_flat_reservation());
    let first = arena
        .shard(0)
        .expect("shard 0 exists")
        .publish_flat_string(
            FlatObjectKind::String,
            7,
            NixString::from_bytes(b"first".to_vec()),
        )
        .expect("first string publishes");
    let second = arena
        .shard(3)
        .expect("shard 3 exists")
        .publish_flat_string(
            FlatObjectKind::String,
            8,
            NixString::from_bytes(b"second".to_vec()),
        )
        .expect("second string publishes");
    let reservation = arena
        .flat_reservation
        .as_ref()
        .expect("reservation is retained");
    let first_index = reservation
        .index_for_pointer(first.as_string_ptr().expect("first is a string"))
        .expect("first pointer has an index");
    let second_index = reservation
        .index_for_pointer(second.as_string_ptr().expect("second is a string"))
        .expect("second pointer has an index");

    assert_ne!(first_index, second_index);
    assert_eq!(
        arena.get_string(first).expect("first resolves").bytes(),
        b"first"
    );
    assert_eq!(
        arena.get_string(second).expect("second resolves").bytes(),
        b"second"
    );
    let stats = arena
        .flat_reservation_stats()
        .expect("reservation stats are available");
    assert_eq!(stats.virtual_reserved_bytes as u64, 1_u64 << 32);
    assert!(stats.used_bytes > 0);
}

/// A handle not owned by any shard is a clean error, never a torn read.
#[test]
fn unknown_pointer_is_rejected() {
    let producer = SharedHeapArena::new(1, 16);
    let value = producer
        .shard(0)
        .expect("shard 0")
        .alloc_string(NixString::from_bytes(b"orphan".to_vec()))
        .expect("allocation succeeds");

    let empty = SharedHeapArena::new(1, 16);
    assert!(matches!(
        empty.get_string(value),
        Err(SharedHeapError::UnknownPointer { .. })
    ));
}

/// Resolving a string handle as a list is a typed mismatch, not a bad read.
#[test]
fn type_mismatch_is_rejected() {
    let arena = SharedHeapArena::new(1, 16);
    let string = arena
        .shard(0)
        .expect("shard 0")
        .alloc_string(NixString::from_bytes(b"str".to_vec()))
        .expect("allocation succeeds");
    assert!(matches!(
        arena.get_list(string),
        Err(SharedHeapError::RecordTypeMismatch { .. })
    ));
}

/// A full shard reports [`SharedHeapError::ShardFull`] rather than panicking.
#[test]
fn full_shard_reports_error() {
    let arena = SharedHeapArena::new(1, 2);
    let shard = arena.shard(0).expect("shard 0");
    for _ in 0..shard.capacity() {
        shard
            .alloc_string(NixString::from_bytes(b"x".to_vec()))
            .expect("within capacity");
    }
    assert!(matches!(
        shard.alloc_string(NixString::from_bytes(b"overflow".to_vec())),
        Err(SharedHeapError::ShardFull { .. })
    ));
}

/// Records stay resolvable to their own content across geometric chunk-level
/// boundaries: allocations well past the first chunk land in later, larger
/// chunks whose slot addresses are stable from the moment they are published.
#[test]
fn geometric_chunk_growth_keeps_addresses_stable() {
    // A capacity hint of 4 chunk levels: 256 + 512 + 1024 + 2048 records.
    let arena = SharedHeapArena::new(1, 3000);
    let shard = arena.shard(0).expect("shard 0");
    assert!(shard.capacity() >= 3000);

    let mut allocated = Vec::new();
    for index in 0..3000u32 {
        let bytes = format!("chunk-crossing-{index}").into_bytes();
        let value = shard
            .alloc_string(NixString::from_bytes(bytes.clone()))
            .expect("within capacity");
        allocated.push((value, bytes));
    }
    for (value, bytes) in &allocated {
        assert_eq!(
            arena.get_string(*value).expect("record resolves").bytes(),
            bytes.as_slice()
        );
    }
    assert_eq!(shard.published_len(), 3000);
}

/// The dependency graph the harness forces.
///
/// Cell `i` (for `i > 0`) depends on cells `i - 1` and `i / 2`, so forcing a
/// high root fans out into a shared sub-DAG that different workers race to
/// claim. Every body allocates a fresh value from its dependencies' values.
struct SharedAllocGraph {
    cells: usize,
}

impl SharedAllocGraph {
    fn dependencies(&self, cell: usize) -> Vec<usize> {
        if cell == 0 {
            Vec::new()
        } else {
            let mut deps = vec![cell - 1];
            let half = cell / 2;
            if half != cell - 1 {
                deps.push(half);
            }
            deps
        }
    }

    /// The content the body for `cell` must produce: the concatenation of a
    /// per-cell tag with its dependencies' produced bytes, deterministic and
    /// independent of which worker runs the body.
    fn expected_bytes(&self, cell: usize) -> Vec<u8> {
        let mut bytes = format!("c{cell}").into_bytes();
        for dep in self.dependencies(cell) {
            bytes.push(b'-');
            bytes.extend_from_slice(&self.expected_bytes(dep));
        }
        bytes
    }
}

/// Drives `worker_count` workers over the shared alloc graph and returns, for
/// each root, the resolved bytes every worker observed. Optionally injects
/// seeded yields to shuffle interleavings.
fn run_shared_alloc(
    graph: &SharedAllocGraph,
    worker_count: usize,
    yield_seed: Option<u64>,
) -> Vec<Vec<u8>> {
    let workers = NonZeroUsize::new(worker_count).expect("worker count is nonzero");
    let arena = Arc::new(SharedHeapArena::new(worker_count, 4096));
    let registry = Arc::new(ParallelForceCycleRegistry::new());
    let cells = shared_parallel_thunk_cells(graph.cells, &registry, infinite_recursion_error);
    let roots: Vec<usize> = (0..graph.cells).collect();

    let arena_for_body = Arc::clone(&arena);
    let body = move |forcer: &crate::eval::parallel_force::ParallelSharedGraphForcer<'_>,
                     index: usize|
          -> Result<Value, crate::eval::tree_walk::TreeWalkError> {
        maybe_yield(yield_seed, index);
        let shard_index = worker_shard(forcer.worker().get(), worker_count);
        let shard = arena_for_body
            .shard(shard_index)
            .expect("worker maps to a valid shard");

        // Force dependencies (cross-worker) and dereference their published
        // values through the shared arena (cross-shard reads).
        let mut elements = Vec::new();
        let mut bytes = format!("c{index}").into_bytes();
        for dep in graph.dependencies(index) {
            let dep_value = forcer.force(dep)?;
            maybe_yield(yield_seed, dep);
            let dep_string = arena_for_body
                .get_string(dep_value)
                .expect("dependency value resolves cross-shard");
            bytes.push(b'-');
            bytes.extend_from_slice(dep_string.bytes());
            elements.push(dep_value);
        }

        // Build a NEW list referencing the dependencies' cross-worker values,
        // then publish the cell's own string built from their bytes.
        let _list = shard
            .alloc_list(NixList::new(elements))
            .expect("list allocation succeeds");
        maybe_yield(yield_seed, index);
        let produced = shard
            .alloc_string(NixString::from_bytes(bytes))
            .expect("string allocation succeeds");
        Ok(produced)
    };

    let reports = force_shared_parallel_roots(&cells, &roots, workers, &body)
        .expect("shared force run succeeds");

    // Every worker must have forced every root to the identical value, and each
    // resolves to identical content across all workers.
    let mut resolved_per_root: Vec<Option<Vec<u8>>> = vec![None; graph.cells];
    for report in &reports {
        assert_eq!(report.root_results.len(), graph.cells);
        for (root, result) in report.root_results.iter().enumerate() {
            let value = result.as_ref().expect("root force succeeded");
            let bytes = arena
                .get_string(*value)
                .expect("published root value resolves")
                .bytes()
                .to_vec();
            match &resolved_per_root[root] {
                None => resolved_per_root[root] = Some(bytes),
                Some(previous) => assert_eq!(
                    previous, &bytes,
                    "workers disagreed on root {root} content (torn read or double body)"
                ),
            }
        }
    }
    resolved_per_root
        .into_iter()
        .map(|bytes| bytes.expect("every root resolved"))
        .collect()
}

/// A seeded, cheap pseudo-random yield to shuffle thread interleavings.
fn maybe_yield(seed: Option<u64>, salt: usize) {
    if let Some(seed) = seed {
        // SplitMix64-style mix of the seed and a per-site salt.
        let mut z = seed
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(salt as u64);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        for _ in 0..(z % 4) {
            std::thread::yield_now();
        }
    }
}

/// K workers allocating from and dereferencing each other's shards produce the
/// deterministic, content-defined result for every root.
#[test]
fn cross_worker_allocation_is_exactly_once_and_consistent() {
    let graph = SharedAllocGraph { cells: 24 };
    for &worker_count in &[1usize, 2, 4, 8] {
        let resolved = run_shared_alloc(&graph, worker_count, None);
        for cell in 0..graph.cells {
            assert_eq!(
                resolved[cell],
                graph.expected_bytes(cell),
                "root {cell} content wrong for {worker_count} worker(s)"
            );
        }
    }
}

/// Under seeded yield injection across many iterations, the resolved contents
/// stay invariant - no interleaving produces a torn read or a divergent value.
#[test]
fn seeded_yield_stress_is_deterministic() {
    let graph = SharedAllocGraph { cells: 20 };
    let baseline: Vec<Vec<u8>> = (0..graph.cells).map(|c| graph.expected_bytes(c)).collect();
    for seed in 0..48u64 {
        let worker_count = 2 + (seed as usize % 4);
        let resolved = run_shared_alloc(&graph, worker_count, Some(seed));
        assert_eq!(
            resolved, baseline,
            "seed {seed} ({worker_count} workers) diverged from the content-defined result"
        );
    }
}
