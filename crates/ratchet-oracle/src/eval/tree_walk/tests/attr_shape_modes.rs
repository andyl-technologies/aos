//! Differential tests for the hidden-class shape strategies (RFC-0007 §09).
//!
//! [`AttrShapeMode`] is a byte-neutral performance strategy: `off`,
//! `transient`, and `record` must render every expression identically,
//! including observable attribute iteration order, `toJSON` output, dynamic
//! keys, `__overrides`, and `//` chains. These tests evaluate an attr-heavy
//! expression battery under all three modes (serially and with a parallel
//! worker pool) and require identical strict renderings, then pin the
//! record-mode behaviors that the mode exists for: shape metadata preserved
//! across same-key-set `//` merges and record select caches serving repeat
//! selects without transient shaped views.

use super::support::lower;
use super::*;

/// Attr-heavy expressions covering the observable surfaces that the shape
/// strategies touch: construction, selection, `//` merges (same-key-set and
/// growing), dynamic keys, `rec` + `__overrides`, iteration order with
/// adversarial key spellings, and attrset builtins.
const ATTR_SURFACE_BATTERY: &[&str] = &[
    // Static literal construction + repeated select through one site.
    "let s = { ip = 1; ptr = 2; tape = [ 3 ]; }; in s.ip + s.ptr + builtins.head s.tape",
    // Same-key-set `//` chain: the lambda-interp state pattern. The final
    // state flows through selects after many shape-preserving updates.
    "let step = s: n: s // { ip = s.ip + 1; }; \
     out = builtins.foldl' step { ip = 0; ptr = 7; tape = \"t\"; } \
       (builtins.genList (n: n) 64); \
     in [ out.ip out.ptr out.tape (builtins.attrNames out) ]",
    // Growing `//` chain with a fresh dynamic key per layer (attr-fixpoint
    // pattern): exercises the general merge and dynamic construction.
    "let merged = builtins.foldl' \
       (acc: n: acc // { \"k${builtins.toString n}\" = n; }) \
       { seed = true; } (builtins.genList (n: n + 1) 32); \
     in [ (builtins.attrNames merged) merged.k7 merged.k31 merged.seed ]",
    // Right operand introduces keys and overrides: mixed merge.
    "let a = { x = 1; y = 2; z = 3; }; b = { y = 20; w = 40; }; \
     in builtins.toJSON (a // b)",
    // Observable iteration order with adversarial spellings (quoted,
    // non-ASCII, shared prefixes) across attrNames/attrValues/toJSON.
    "let s = { zz = 1; \"\\u00e9\" = 2; a = 3; \"a b\" = 4; A = 5; aa = 6; }; \
     in [ (builtins.attrNames s) (builtins.attrValues s) (builtins.toJSON s) ]",
    // rec + __overrides rewires bindings after construction.
    "let s = rec { a = 1; b = a + 1; __overrides = { a = 10; c = 3; }; }; \
     in [ s.a s.b s.c (builtins.attrNames s) ]",
    // Dynamic keys, null-skipped dynamics, and hasAttr/or defaults.
    "let k = \"dyn\"; s = { \"${k}\" = 1; ${null} = 2; static = 3; }; \
     in [ (builtins.attrNames s) (s.dyn or 0) (s ? missing) (s.missing or 99) ]",
    // Attrset builtins over merged results.
    "let base = { a = 1; b = 2; c = 3; }; merged = base // { b = 20; }; \
     in [ (builtins.removeAttrs merged [ \"a\" ]) \
          (builtins.intersectAttrs { b = null; } merged) \
          (builtins.mapAttrs (k: v: v * 2) merged) \
          (builtins.listToAttrs [ { name = \"p\"; value = 1; } { name = \"o\"; value = 2; } ]) ]",
    // Nested selects through merged records (record cache on inner sets).
    "let inner = { hits = 0; }; s = { state = inner; tag = \"x\"; }; \
     bump = s: s // { state = s.state // { hits = s.state.hits + 1; }; }; \
     out = bump (bump (bump s)); in [ out.state.hits out.tag ]",
    // Empty-right and identical-right merges (degenerate same-key-set).
    "let s = { a = 1; b = 2; }; in [ (s // {}) (s // s) ((s // s).a) ]",
    // with-scopes over shaped records.
    "let s = { alpha = 1; beta = 2; }; in with s; alpha + beta",
];

/// Forcing a long `//` thunk chain unwinds one Rust force frame per layer,
/// which outgrows the default 2 MiB test-thread stack under the debug
/// tree-walk; run each case on an evaluation-sized stack like the production
/// worker threads use.
const EVAL_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

fn run_on_eval_stack(body: impl FnOnce() + Send + 'static) {
    let handle = std::thread::Builder::new()
        .name("attr-shape-mode-eval".to_owned())
        .stack_size(EVAL_TEST_STACK_SIZE)
        .spawn(body)
        .expect("attr shape mode eval worker spawns");
    if let Err(payload) = handle.join() {
        std::panic::resume_unwind(payload);
    }
}

fn render_with_mode(source: &str, mode: AttrShapeMode, workers: Option<usize>) -> Vec<u8> {
    let ir = lower(source);
    let mut options = match workers {
        Some(workers) => {
            TreeWalkOptions::with_parallel_workers(std::num::NonZeroUsize::new(workers))
        }
        None => TreeWalkOptions::default(),
    };
    options.set_attr_shape_mode(mode);
    eval_raw_bytes_with_options(&ir, options).expect("expression evaluates")
}

#[test]
fn attr_shape_modes_render_identically_serially() {
    run_on_eval_stack(|| {
        for source in ATTR_SURFACE_BATTERY {
            let baseline = render_with_mode(source, AttrShapeMode::Transient, None);
            for mode in [AttrShapeMode::Off, AttrShapeMode::Record] {
                let rendered = render_with_mode(source, mode, None);
                assert_eq!(
                    String::from_utf8_lossy(&rendered),
                    String::from_utf8_lossy(&baseline),
                    "mode {mode:?} diverged for {source}",
                );
            }
        }
    });
}

#[test]
fn attr_shape_modes_render_identically_with_parallel_pool() {
    run_on_eval_stack(|| {
        for source in ATTR_SURFACE_BATTERY {
            let baseline = render_with_mode(source, AttrShapeMode::Transient, None);
            for mode in [
                AttrShapeMode::Off,
                AttrShapeMode::Transient,
                AttrShapeMode::Record,
            ] {
                let rendered = render_with_mode(source, mode, Some(3));
                assert_eq!(
                    String::from_utf8_lossy(&rendered),
                    String::from_utf8_lossy(&baseline),
                    "parallel mode {mode:?} diverged for {source}",
                );
            }
        }
    });
}

#[test]
fn record_mode_preserves_shape_metadata_across_same_key_merges() {
    run_on_eval_stack(|| {
        // The production `//` path (merge telemetry off) with a same-key-set
        // right operand keeps the left operand's projected shape id, so selects
        // on merge results stay on the record-resident fast path.
        let source = "let s = { ip = 1; ptr = 2; }; in s // { ip = 10; }";
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_attr_shape_mode(AttrShapeMode::Record);
        let mut eval = TreeWalk::with_options(&ir, options);
        eval.set_attr_update_telemetry_enabled(false);
        let merged = eval.eval_root().expect("merge evaluates");
        let metadata = eval
            .heap()
            .get_attrs_metadata(merged)
            .expect("merge result carries attrs metadata");
        assert!(
            metadata.projected_shape().is_some(),
            "same-key-set merge result must keep the left operand's projected shape",
        );

        // A key-introducing merge falls back to the general path with no
        // projected shape (merge results are not re-projected).
        let source = "let s = { ip = 1; }; in s // { fresh = 2; }";
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_attr_shape_mode(AttrShapeMode::Record);
        let mut eval = TreeWalk::with_options(&ir, options);
        eval.set_attr_update_telemetry_enabled(false);
        let merged = eval.eval_root().expect("merge evaluates");
        let metadata = eval
            .heap()
            .get_attrs_metadata(merged)
            .expect("merge result carries attrs metadata");
        assert!(
            metadata.projected_shape().is_none(),
            "key-introducing merge results stay unprojected",
        );

        // The baseline transient mode keeps merge results unprojected even for
        // same-key-set merges (the measured routing policy).
        let source = "let s = { ip = 1; ptr = 2; }; in s // { ip = 10; }";
        let ir = lower(source);
        let mut eval = TreeWalk::with_options(&ir, TreeWalkOptions::default());
        eval.set_attr_update_telemetry_enabled(false);
        let merged = eval.eval_root().expect("merge evaluates");
        let metadata = eval
            .heap()
            .get_attrs_metadata(merged)
            .expect("merge result carries attrs metadata");
        assert!(
            metadata.projected_shape().is_none(),
            "transient-mode merge results stay on the flat select path",
        );
    });
}

#[test]
fn record_mode_serves_repeat_selects_from_the_inline_cache() {
    run_on_eval_stack(|| {
        // One select site iterated over many same-shape records on the
        // production path (merge telemetry off): the same-key-set merges keep
        // one shape id flowing through the site, so after the first resolution
        // every step select is a record-cache hit.
        let source = "let step = s: n: s // { ip = s.ip + 1; }; \
            in (builtins.foldl' step { ip = 0; ptr = 1; } (builtins.genList (n: n) 200)).ip";
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_attr_shape_mode(AttrShapeMode::Record);
        let mut eval = TreeWalk::with_options(&ir, options);
        eval.set_attr_update_telemetry_enabled(false);
        let value = eval.eval_root().expect("expression evaluates");
        assert_eq!(value.as_int(), Ok(200));
        assert!(
            eval.stats.inline_cache_hits >= 199,
            "expected the step select site to serve repeat lookups from the record cache, \
             got {} hits / {} misses",
            eval.stats.inline_cache_hits,
            eval.stats.inline_cache_misses,
        );
    });
}

#[test]
fn off_mode_runs_without_a_shape_table() {
    // `AOS_NIX_SHAPES=off` disables projection: no attrset carries a
    // projected shape id and evaluation still renders identically (covered
    // by the battery above); here we pin the metadata surface.
    let source = "{ a = 1; b = 2; }";
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_attr_shape_mode(AttrShapeMode::Off);
    let mut eval = TreeWalk::with_options(&ir, options);
    let value = eval.eval_root().expect("literal evaluates");
    let metadata = eval
        .heap()
        .get_attrs_metadata(value)
        .expect("literal carries attrs metadata");
    assert!(metadata.projected_shape().is_none());
}
