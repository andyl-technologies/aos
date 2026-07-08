//! Production-wiring tests for the shared-arena heap (L2-P3a).
//!
//! These run *real* `TreeWalk` evaluations - not synthetic cells - against the
//! shared heap backend:
//!
//! - the production option path (`parallel_workers = Some(K)`) builds a
//!   shared-arena heap and evaluates real source through it;
//! - K `TreeWalk`s, one per worker thread, adopt one shard each of a single
//!   [`SharedHeapArena`] and dereference values (strings, lists, thunks) that
//!   *other* workers' evaluations freshly allocated;
//! - content-equal values allocated in *different* shards compare equal
//!   through the evaluator's equality path (the pointer-identity fast path
//!   misses cross-shard by construction and must fall through to content
//!   comparison).
//!
//! What deliberately remains for P3b: *forcing* another worker's suspended
//! thunk from a different `TreeWalk` (the thunk body's `EvalNodeRef` names the
//! owning worker's module registry), and cross-worker attr lookup by name
//! (symbol tables are per-evaluator). Here workers force their own thunks and
//! other workers read the forced results through the shared cells.

use std::num::NonZeroUsize;
use std::sync::Barrier;

use super::support::lower;
use super::*;
use crate::eval::heap::SharedHeapArena;

/// Production options for a K-worker parallel evaluation.
fn parallel_options(workers: usize) -> TreeWalkOptions {
    TreeWalkOptions::with_parallel_workers(NonZeroUsize::new(workers))
}

/// The production option path routes evaluation through a shared-arena heap
/// and still evaluates real source correctly (K=1 semantics until P3b).
#[test]
fn parallel_workers_option_builds_shared_heap_and_evaluates() {
    let ir = lower(r#""shared-" + "heap""#);
    let mut walk = TreeWalk::with_options(&ir, parallel_options(4));
    assert!(
        walk.heap.uses_shared_arena(),
        "parallel_workers must install the shared-arena backend"
    );
    let arena = walk
        .heap
        .shared_arena()
        .cloned()
        .expect("shared arena is installed");
    assert_eq!(arena.shard_count(), 4, "one shard per configured worker");

    let value = walk.eval_root().expect("source evaluates");
    assert_eq!(
        walk.heap
            .get_string(value)
            .expect("root string resolves through the shared backend")
            .bytes(),
        b"shared-heap"
    );
    assert!(arena.published_len() > 0, "evaluation allocated into shard 0");
}

/// K production `TreeWalk`s over one shared arena: every worker evaluates real
/// source into its own shard, then dereferences the values every *other*
/// worker allocated - including reading forced thunk results through the
/// shared `Arc` cells.
#[test]
fn k_tree_walks_share_one_arena_and_resolve_each_others_values() {
    const WORKERS: usize = 3;
    let arena = std::sync::Arc::new(SharedHeapArena::new(WORKERS, 1 << 16));
    let published: std::sync::Mutex<Vec<(usize, Value)>> = std::sync::Mutex::new(Vec::new());
    let barrier = Barrier::new(WORKERS);

    std::thread::scope(|scope| {
        for worker in 0..WORKERS {
            let arena = &arena;
            let published = &published;
            let barrier = &barrier;
            scope.spawn(move || {
                // Concatenations force real allocation work per worker; the
                // second element is typically a lazily allocated thunk.
                let source = format!(
                    r#"[ ("worker-" + "{worker}-payload") ("lazy-" + "{worker}") ]"#
                );
                let ir = lower(&source);
                let mut walk = TreeWalk::with_options(&ir, parallel_options(WORKERS));
                let shard =
                    std::sync::Arc::clone(arena.shard(worker).expect("worker shard exists"));
                walk.adopt_shared_heap_shard(std::sync::Arc::clone(arena), shard);

                let root = walk.eval_root().expect("worker source evaluates");
                let root_id = walk.current_ir().root;
                let span = walk.node(root_id).expect("root node").span;

                // Force this worker's own elements so other workers can read
                // the forced results through the shared thunk cells.
                let elements: Vec<Value> = walk
                    .heap
                    .get_list(root)
                    .expect("own list resolves")
                    .iter()
                    .copied()
                    .collect();
                for element in elements {
                    walk.force_value(root_id, span, element)
                        .expect("own element forces");
                }

                published
                    .lock()
                    .expect("publish lock is never poisoned")
                    .push((worker, root));
                barrier.wait();

                let snapshot = published
                    .lock()
                    .expect("read lock is never poisoned")
                    .clone();
                assert_eq!(snapshot.len(), WORKERS, "every worker published a root");
                for (owner, value) in snapshot {
                    // Cross-shard dereference of another worker's fresh list.
                    let list = walk
                        .heap
                        .get_list(value)
                        .expect("cross-worker list resolves");
                    assert_eq!(list.len(), 2);
                    let first = list.get(0).expect("element 0");
                    let second = list.get(1).expect("element 1");

                    // Element 0 was forced by its owner; read it (directly or
                    // through the owner's forced thunk cell).
                    let first = walk
                        .force_value(root_id, span, first)
                        .expect("forced cross-worker element reads back");
                    assert_eq!(
                        walk.heap
                            .get_string(first)
                            .expect("cross-worker string resolves")
                            .bytes(),
                        format!("worker-{owner}-payload").as_bytes()
                    );

                    // Element 1: resolvable regardless of whether the owner's
                    // evaluation left it a direct string or a forced thunk.
                    match second.tag() {
                        ValueTag::Thunk => {
                            walk.heap
                                .clone_thunk(second)
                                .expect("cross-worker thunk record resolves");
                        }
                        ValueTag::String => {
                            walk.heap
                                .get_string(second)
                                .expect("cross-worker string resolves");
                        }
                        other => panic!("unexpected list element tag {other:?}"),
                    }
                }
            });
        }
    });

    for worker in 0..WORKERS {
        assert!(
            arena
                .shard(worker)
                .expect("worker shard exists")
                .published_len()
                > 0,
            "worker {worker} allocated into its own shard"
        );
    }
}

/// Content-equal values allocated in different shards compare equal through
/// the evaluator's equality path: the pointer-identity fast path cannot hit
/// (distinct records), so equality must fall through to content comparison
/// resolved across shards.
#[test]
fn content_equal_values_in_different_shards_compare_equal() {
    let arena = std::sync::Arc::new(SharedHeapArena::new(2, 1 << 16));
    let source = r#"[ ("al" + "pha") ("be" + "ta") ]"#;

    let mut walks: Vec<TreeWalk> = Vec::new();
    let mut roots: Vec<Value> = Vec::new();
    for shard_index in 0..2 {
        let ir = lower(source);
        let mut walk = TreeWalk::with_options(&ir, parallel_options(2));
        let shard = std::sync::Arc::clone(arena.shard(shard_index).expect("shard exists"));
        walk.adopt_shared_heap_shard(std::sync::Arc::clone(&arena), shard);
        let root = walk.eval_root().expect("source evaluates");
        // Force the worker's own elements so equality reads forced results.
        let root_id = walk.current_ir().root;
        let span = walk.node(root_id).expect("root node").span;
        let elements: Vec<Value> = walk
            .heap
            .get_list(root)
            .expect("own list resolves")
            .iter()
            .copied()
            .collect();
        for element in elements {
            walk.force_value(root_id, span, element)
                .expect("own element forces");
        }
        walks.push(walk);
        roots.push(root);
    }

    let (left, right) = (roots[0], roots[1]);
    assert!(
        !left.raw_eq(right),
        "the two workers must have allocated distinct records"
    );

    let walk = &mut walks[0];
    let root_id = walk.current_ir().root;
    let node = *walk.node(root_id).expect("root node");
    assert!(
        walk.values_equal(root_id, &node, left, right, EqualityContext::Direct)
            .expect("cross-shard equality evaluates"),
        "content-equal cross-shard lists compare equal"
    );

    // And a strict inequality control: compare against a different list.
    let other_ir = lower(r#"[ ("al" + "pha") ("de" + "lta") ]"#);
    let mut other_walk = TreeWalk::with_options(&other_ir, parallel_options(2));
    let shard = std::sync::Arc::clone(arena.shard(1).expect("shard exists"));
    other_walk.adopt_shared_heap_shard(std::sync::Arc::clone(&arena), shard);
    let other_root = other_walk.eval_root().expect("other source evaluates");
    let other_root_id = other_walk.current_ir().root;
    let other_span = other_walk.node(other_root_id).expect("root node").span;
    let other_elements: Vec<Value> = other_walk
        .heap
        .get_list(other_root)
        .expect("own list resolves")
        .iter()
        .copied()
        .collect();
    for element in other_elements {
        other_walk
            .force_value(other_root_id, other_span, element)
            .expect("own element forces");
    }
    let walk = &mut walks[0];
    assert!(
        !walk
            .values_equal(root_id, &node, left, other_root, EqualityContext::Direct)
            .expect("cross-shard inequality evaluates"),
        "content-unequal cross-shard lists compare unequal"
    );
}
