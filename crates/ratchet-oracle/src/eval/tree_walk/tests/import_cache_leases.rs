//! Import-cache lease lifecycle and unwind tests.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn begin_miss(
    evaluator: &mut TreeWalk,
    id: IrId,
    span: Span,
    path: &Path,
) -> ImportCacheLeaseToken {
    let result = evaluator
        .begin_cached_import(
            id,
            span,
            path.to_path_buf(),
            path.as_os_str().as_bytes().to_vec(),
            true,
            true,
        )
        .expect("cache miss begins");
    let BeginCachedImport::Miss(token) = result else {
        panic!("fresh path is a cache miss");
    };
    token
}

#[test]
fn import_cache_lease_miss_success_becomes_a_hit() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let path = Path::new("/lease-success.nix");
    let mut evaluator = TreeWalk::new(&ir);

    let token = begin_miss(&mut evaluator, id, span, path);
    assert_eq!(evaluator.active_import_cache_leases.len(), 1);
    assert!(matches!(
        evaluator.import_cache.get(path),
        Some(ImportCacheEntry::Evaluating)
    ));

    let value = evaluator
        .finish_cached_import(token, Ok(Value::int(42)))
        .expect("cache miss finishes");
    assert!(value.raw_eq(Value::int(42)));
    assert!(evaluator.active_import_cache_leases.is_empty());

    let hit = evaluator
        .begin_cached_import(
            id,
            span,
            path.to_path_buf(),
            path.as_os_str().as_bytes().to_vec(),
            true,
            true,
        )
        .expect("ready cache entry loads");
    let BeginCachedImport::Hit(hit) = hit else {
        panic!("completed cache entry is a hit");
    };
    assert!(hit.raw_eq(value));
}

#[test]
fn import_cache_lease_error_removes_evaluating_marker() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let path = Path::new("/lease-error.nix");
    let mut evaluator = TreeWalk::new(&ir);
    let token = begin_miss(&mut evaluator, id, span, path);
    let error = TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, span);

    let returned = evaluator
        .finish_cached_import(token, Err(error))
        .expect_err("loader error propagates");
    assert!(matches!(
        returned.kind(),
        TreeWalkErrorKind::InvalidNodeId { .. }
    ));
    assert!(!evaluator.import_cache.contains_key(path));
    assert!(evaluator.active_import_cache_leases.is_empty());
}

#[test]
fn import_cache_lease_preserves_recursive_import_detection() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let path = Path::new("/lease-recursive.nix");
    let mut evaluator = TreeWalk::new(&ir);
    let token = begin_miss(&mut evaluator, id, span, path);

    let error = evaluator
        .begin_cached_import(
            id,
            span,
            path.to_path_buf(),
            path.as_os_str().as_bytes().to_vec(),
            true,
            true,
        )
        .expect_err("active path is recursive");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::RecursiveImport { .. }
    ));
    assert_eq!(evaluator.active_import_cache_leases.len(), 1);
    evaluator.abort_cached_import(token);
    assert!(!evaluator.import_cache.contains_key(path));
}

#[test]
fn import_cache_lease_panic_removes_evaluating_marker() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let path = PathBuf::from("/lease-panic.nix");
    let mut evaluator = TreeWalk::new(&ir);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _: Result<Value, TreeWalkError> = evaluator.load_cached_import(
            id,
            span,
            path.clone(),
            path.as_os_str().as_bytes().to_vec(),
            true,
            true,
            |_| panic!("injected import loader panic"),
        );
    }));
    assert!(panic.is_err());
    assert!(!evaluator.import_cache.contains_key(&path));
    assert!(evaluator.active_import_cache_leases.is_empty());
}

#[test]
fn import_cache_lease_rejects_a_stale_same_depth_token_without_popping() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let first_path = Path::new("/lease-stale-first.nix");
    let second_path = Path::new("/lease-stale-second.nix");
    let mut evaluator = TreeWalk::new(&ir);

    let stale = begin_miss(&mut evaluator, id, span, first_path);
    evaluator.abort_cached_import(stale);
    let active = begin_miss(&mut evaluator, id, span, second_path);
    assert_eq!(stale.depth(), active.depth());
    assert_ne!(stale.generation(), active.generation());

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = evaluator.finish_cached_import(stale, Ok(Value::int(1)));
    }));
    assert!(panic.is_err());
    assert_eq!(evaluator.active_import_cache_leases.len(), 1);
    assert!(matches!(
        evaluator.import_cache.get(second_path),
        Some(ImportCacheEntry::Evaluating)
    ));

    evaluator.abort_cached_import(active);
    assert!(evaluator.active_import_cache_leases.is_empty());
    assert!(!evaluator.import_cache.contains_key(second_path));
}

#[test]
fn import_cache_lease_generation_exhaustion_precedes_evaluating_marker() {
    let ir = lower("null");
    let id = ir.root;
    let span = ir.arena.node(id).expect("root exists").span;
    let path = Path::new("/lease-generation-exhausted.nix");
    let mut evaluator = TreeWalk::new(&ir);
    evaluator.next_import_cache_lease_generation = u64::MAX;

    let error = evaluator
        .begin_cached_import(
            id,
            span,
            path.to_path_buf(),
            path.as_os_str().as_bytes().to_vec(),
            true,
            true,
        )
        .expect_err("generation exhaustion rejects the miss");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ImportCacheLeaseGenerationExhausted { .. }
    ));
    assert!(evaluator.active_import_cache_leases.is_empty());
    assert!(!evaluator.import_cache.contains_key(path));
}
