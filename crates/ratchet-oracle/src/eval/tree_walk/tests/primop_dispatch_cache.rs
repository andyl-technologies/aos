//! Tests for the per-call-site direct primop resolution cache (RFC-0007 §P4).
//!
//! A lowered [`IrKind::PrimOp`] node resolves its builtin once and reuses the
//! recorded [`BuiltinKind`] on every later evaluation of the same node. These
//! tests pin the observable contract: repeated evaluation of one direct primop
//! node serves from the cache, the reconstructed builtin still computes the
//! byte-identical result, and a direct primop that errors at runtime errors
//! identically whether the first or a cached evaluation raised it.
//!
//! [`IrKind::PrimOp`]: crate::compile::IrKind::PrimOp

use super::support::lower;
use super::*;

#[test]
fn repeated_direct_primop_node_serves_from_the_cache() {
    // `builtins.stringLength s` is one direct StrictUnary primop node inside the
    // fold step lambda; the fold evaluates that node once per list element, so
    // after the first resolution every later step is a cache hit.
    let source = "builtins.foldl' (acc: s: acc + builtins.stringLength s) 0 \
        (builtins.genList (n: \"x\") 100)";
    let ir = lower(source);
    let mut eval = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let value = eval.eval_root().expect("expression evaluates");
    // Each of the 100 one-character elements contributes length 1.
    assert_eq!(value.as_int(), Ok(100));
    assert!(
        eval.primop_builtin_cache.hits() >= 99,
        "expected the stringLength node to serve repeat evaluations from the \
         cache, got {} hits / {} misses",
        eval.primop_builtin_cache.hits(),
        eval.primop_builtin_cache.misses(),
    );
    assert!(
        eval.primop_builtin_cache.misses() >= 1,
        "every distinct primop node resolves once before it can be cached",
    );
}

#[test]
fn cached_direct_primop_reports_runtime_errors_identically_on_repeat() {
    // The mapper body `builtins.head x` is one direct primop node. Folding the
    // mapped list forces `head [ 1 ]` first (resolving and caching the node)
    // and then `head [ ]`, whose empty-list error is raised through the
    // cache-hit path. It must match the error the same node raises on its first
    // (uncached) evaluation.
    let hit_source = "builtins.foldl' (a: x: a + x) 0 \
        (builtins.map (x: builtins.head x) [ [ 1 ] [ ] ])";
    let ir = lower(hit_source);
    let mut eval = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let via_hit = eval
        .eval_root()
        .expect_err("empty-list head aborts evaluation");
    assert!(
        eval.primop_builtin_cache.hits() >= 1,
        "the head node must resolve from the cache on the empty-list element",
    );

    let miss_source = "builtins.foldl' (a: x: a + x) 0 \
        (builtins.map (x: builtins.head x) [ [ ] ])";
    let miss_ir = lower(miss_source);
    let mut miss_eval = TreeWalk::with_options(&miss_ir, TreeWalkOptions::default());
    let via_miss = miss_eval
        .eval_root()
        .expect_err("empty-list head aborts evaluation");

    assert_eq!(
        format!("{:?}", via_hit.kind()),
        format!("{:?}", via_miss.kind()),
        "the empty-list head error must be identical on the cached and uncached paths",
    );
}
