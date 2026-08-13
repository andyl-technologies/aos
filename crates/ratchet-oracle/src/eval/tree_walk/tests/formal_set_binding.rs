//! Tests for the per-pattern formal-set layout cache (RFC-0007 §P4 safe route).
//!
//! A `{ ... }:` lambda's pattern layout (formal names, defaults, alias slot,
//! total slots) is derived once per pattern node and reused on every
//! application. These tests pin the observable contract: a repeatedly-applied
//! lambda derives its layout exactly once and computes byte-identical results,
//! and a missing required formal raises the same error whether the layout is
//! being built (first application) or served from the cache (a later one).

use super::support::lower;
use super::*;

#[test]
fn repeated_formal_set_application_builds_layout_once() {
    // `f` is the only formal-set pattern; `acc:`/`x:`/`n:` are simple lambdas.
    // Applying `f` to every element of a 100-element list derives its layout on
    // the first application and serves it from the cache thereafter.
    let source = "let f = { a, b ? 10 }: a + b; \
        in builtins.foldl' (acc: x: acc + f x) 0 \
        (builtins.genList (n: { a = n; }) 100)";
    let ir = lower(source);
    let mut eval = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let value = eval.eval_root().expect("expression evaluates");
    // Each element binds a = n (0..99) and the default b = 10:
    // sum(0..99) + 100*10 = 4950 + 1000 = 5950.
    assert_eq!(value.as_int(), Ok(5950));
    assert_eq!(
        eval.formal_set_layout_cache.misses(),
        1,
        "the pattern layout must be derived exactly once",
    );
    assert!(
        eval.formal_set_layout_cache.hits() >= 99,
        "later applications must serve the layout from the cache, got {} hits / {} misses",
        eval.formal_set_layout_cache.hits(),
        eval.formal_set_layout_cache.misses(),
    );
}

#[test]
fn cached_formal_set_missing_attr_errors_identically_to_first_application() {
    // Folding `[ { a = 1; } { } ]` applies `f` first to `{ a = 1; }` (which builds
    // and caches the layout) and then to `{ }`, whose missing required formal `a`
    // is raised through the cache-hit path.
    let hit_source = "let f = { a }: a; \
        in builtins.foldl' (acc: x: acc + f x) 0 [ { a = 1; } { } ]";
    let ir = lower(hit_source);
    let mut eval = TreeWalk::with_options(&ir, TreeWalkOptions::default());
    let via_hit = eval
        .eval_root()
        .expect_err("missing required formal aborts evaluation");
    assert!(
        eval.formal_set_layout_cache.hits() >= 1,
        "the second application must be served from the cache",
    );
    let hit_symbol = match via_hit.kind() {
        TreeWalkErrorKind::MissingFormalAttribute { symbol, .. } => symbol,
        other => panic!("expected a missing-formal error, got {other:?}"),
    };
    assert_eq!(
        eval.symbols.resolve(hit_symbol),
        Some(b"a".as_ref()),
        "the cached path must report the missing formal `a`",
    );

    // The same pattern erroring on its first (uncached) application.
    let miss_source = "let f = { a }: a; in f { }";
    let miss_ir = lower(miss_source);
    let mut miss_eval = TreeWalk::with_options(&miss_ir, TreeWalkOptions::default());
    let via_miss = miss_eval
        .eval_root()
        .expect_err("missing required formal aborts evaluation");
    let miss_symbol = match via_miss.kind() {
        TreeWalkErrorKind::MissingFormalAttribute { symbol, .. } => symbol,
        other => panic!("expected a missing-formal error, got {other:?}"),
    };
    assert_eq!(
        miss_eval.symbols.resolve(miss_symbol),
        Some(b"a".as_ref()),
        "the uncached path must report the missing formal `a`",
    );
}
