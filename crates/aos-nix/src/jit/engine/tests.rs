//! Tier-1 engine promote/dispatch tests (moved verbatim from `engine.rs`).

use super::*;

use ratchet_core::Ir;
use ratchet_oracle::cache::input::ImpureInputFingerprint;
use ratchet_oracle::compile::resolve;
use ratchet_oracle::eval::EvalStats;
use ratchet_oracle::eval::tree_walk::{TreeWalkError, TreeWalkOptions};
use ratchet_oracle::syntax::parse_str;

// The Candidate-B one-word bridge is compiled out under the active
// Candidate-C carrier, so its differential stays baseline-only.
#[cfg(not(feature = "candidate_c_value"))]
mod candidate_b;
mod candidate_c;

/// Parses, resolves, and lowers a source program into Core IR.
fn lower(source: &str) -> Ir {
    let parsed = parse_str(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    aos_nix_dialect::nix_lower(resolved).expect("source lowers")
}

/// Evaluates `source` to WHNF through the tree-walk oracle (no JIT engine).
fn eval_oracle(source: &str) -> Value {
    let ir = lower(source);
    TreeWalk::new(&ir).eval_root().expect("oracle evaluates")
}

/// Evaluates `source` with a tier-1 engine installed at `threshold`.
///
/// Returns the forced value and the evaluation stats so callers can assert
/// promotion and dispatch counts.
fn eval_with_engine(source: &str, threshold: u32) -> (Value, EvalStats) {
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    eval.set_tier1_engine(Rc::new(
        NixJitTier1Engine::with_threshold(threshold)
            .expect("engine builds")
            .force_promote(),
    ));
    let value = eval.eval_root().expect("jit evaluation succeeds");
    let stats = eval.stats();
    (value, stats)
}

/// Evaluates `source` at threshold 1 and returns the engine's blacklist histogram.
fn blacklist_histogram_for(source: &str) -> Vec<(String, u32)> {
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    let engine = Rc::new(
        NixJitTier1Engine::with_threshold(1)
            .expect("engine builds")
            .force_promote(),
    );
    eval.set_tier1_engine(engine.clone());
    eval.eval_root().expect("jit evaluation succeeds");
    engine.blacklist_histogram()
}

/// A run that forces unsupported shapes records them in the blacklist histogram.
#[test]
fn blacklist_histogram_records_unsupported_body_kinds() {
    // The `acc ++ [ x ]` accumulator and the `[ x ]` list construction are
    // shapes the tier-1 lowerer does not support, so forcing them blacklists
    // those def-sites and records their kinds.
    let histogram = blacklist_histogram_for(
        "builtins.foldl' (acc: x: acc ++ [ x ]) [ ] (builtins.genList (i: i) 8)",
    );

    assert!(
        !histogram.is_empty(),
        "expected blacklisted shapes to be recorded, got {histogram:?}"
    );
    // Counts are positive and the histogram is sorted most-frequent first.
    assert!(histogram.iter().all(|(_, count)| *count >= 1));
    assert!(histogram.windows(2).all(|pair| pair[0].1 >= pair[1].1));
}

/// The engine never changes a scalar result, at any promotion threshold.
#[test]
fn engine_preserves_scalar_results() {
    let sources = [
        "1 + 2",
        "let x = 40; in x + 2",
        "let f = x: x + 1; in f 10",
        "if 1 < 2 then 10 else 20",
        "builtins.foldl' (a: b: a + b) 0 [ 1 2 3 4 5 ]",
        "let g = x: x * 2; in g 1 + g 2 + g 3",
        "builtins.length (builtins.genList (i: i + 1) 25)",
        // Scalar arithmetic tree shapes: nested arithmetic, subtraction, and
        // integer division exercise the inline `BinOp` lowerer.
        "let a = 2; b = 3; c = 4; in a * b + c",
        "let x = 10; y = 3; in x - y",
        "let a = 20; b = 4; in a / b",
        "let a = 3; b = 5; in if a < b then a else b",
        "builtins.foldl' (a: b: a + b * 2) 0 [ 1 2 3 4 5 ]",
        // Float operands force the inline integer path to deopt to the tree
        // walk, which must still yield the same float result.
        "let x = 1.5; in x + x",
        "let x = 2.0; y = 3; in x * y",
    ];
    for source in sources {
        for threshold in [1_u32, 8] {
            assert_engine_preserves_result(source, threshold);
        }
    }
}

/// Asserts an engine evaluation matches the plain tree walk for `source`.
///
/// Inline scalars compare by raw words. Floats decode through each
/// evaluator's heap before comparing: on the one-word carrier a float
/// boxes into an evaluator-owned arena, so its raw word embeds an
/// evaluator-specific arena domain and raw equality across two
/// evaluators would compare identity, not value.
fn assert_engine_preserves_result(source: &str, threshold: u32) {
    let oracle_ir = lower(source);
    let mut oracle_eval = TreeWalk::new(&oracle_ir);
    let oracle = oracle_eval.eval_root().expect("oracle evaluates");

    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    eval.set_tier1_engine(Rc::new(
        NixJitTier1Engine::with_threshold(threshold)
            .expect("engine builds")
            .force_promote(),
    ));
    let native = eval.eval_root().expect("jit evaluation succeeds");

    let matches = if oracle.tag() == ratchet_value::value::ValueTag::Float {
        let oracle_float = oracle_eval
            .heap()
            .decode_float_value(oracle)
            .expect("oracle float decodes");
        let native_float = eval
            .heap()
            .decode_float_value(native)
            .expect("native float decodes");
        oracle_float.to_bits() == native_float.to_bits()
    } else {
        oracle.raw_eq(native)
    };
    assert!(
        matches,
        "engine changed result of `{source}` at threshold {threshold}: \
         oracle {oracle:?} vs native {native:?}"
    );
}

/// A hot lowerable def-site promotes once and its later instances dispatch,
/// matching the oracle exactly with no deopts.
#[test]
fn hot_def_site_promotes_and_dispatches() {
    // Each `g` call builds `{ r = k; }`, whose `r` binding is a Node thunk
    // with a forced-local-slot body (a lowerable shape). Summing `item.r`
    // across 40 built records forces 40 instances of that one def-site, so
    // with threshold 1 the first instance promotes it and the rest dispatch.
    let source = "let g = k: { r = k; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (i + 1)) 40)";
    let oracle = eval_oracle(source);
    let (native, stats) = eval_with_engine(source, 1);

    assert!(
        oracle.raw_eq(native),
        "engine changed a hot-def-site result: oracle {oracle:?} vs native {native:?}"
    );
    assert!(
        stats.tier1_promoted() >= 1,
        "expected at least one promotion, got {stats:?}"
    );
    assert!(
        stats.tier1_dispatched() >= 1,
        "expected at least one dispatch, got promoted={} dispatched={} deopted={}",
        stats.tier1_promoted(),
        stats.tier1_dispatched(),
        stats.tier1_deopted(),
    );
}

/// Evaluates `source` on the oracle, returning the value and impure-input trace.
fn eval_oracle_with_trace(source: &str) -> (Value, Vec<ImpureInputFingerprint>) {
    let ir = lower(source);
    let mut eval = TreeWalk::new(&ir);
    let value = eval.eval_root().expect("oracle evaluates");
    let trace = eval.impure_input_trace().to_vec();
    (value, trace)
}

/// Evaluates `source` with a tier-1 engine, returning value, trace, and stats.
fn eval_with_engine_traced(
    source: &str,
    threshold: u32,
) -> (Value, Vec<ImpureInputFingerprint>, EvalStats) {
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    eval.set_tier1_engine(Rc::new(
        NixJitTier1Engine::with_threshold(threshold)
            .expect("engine builds")
            .force_promote(),
    ));
    let value = eval.eval_root().expect("jit evaluation succeeds");
    let trace = eval.impure_input_trace().to_vec();
    let stats = eval.stats();
    (value, trace, stats)
}

/// Evaluates `source` on the oracle, returning the possibly-failing result.
fn eval_oracle_result(source: &str) -> Result<Value, TreeWalkError> {
    let ir = lower(source);
    TreeWalk::new(&ir).eval_root()
}

/// Evaluates `source` with a tier-1 engine, returning the possibly-failing result.
fn eval_with_engine_result(source: &str, threshold: u32) -> Result<Value, TreeWalkError> {
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    eval.set_tier1_engine(Rc::new(
        NixJitTier1Engine::with_threshold(threshold)
            .expect("engine builds")
            .force_promote(),
    ));
    eval.eval_root()
}

/// A hot primop def-site promotes and dispatches through `aos_primop_call`,
/// producing the same value as the oracle with the primop off the blacklist.
#[test]
fn hot_primop_def_site_dispatches_through_the_trampoline() {
    // Each `g` call builds `{ r = builtins.mul k 2; }`, whose `r` binding is a
    // Node thunk with a PrimOp body. Summing `item.r` across 40 records forces
    // 40 instances of that one primop def-site, so it promotes and its later
    // instances dispatch through the trampoline back into the tree walk.
    let source = "let g = k: { r = builtins.mul k 2; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (i + 1)) 40)";
    let oracle = eval_oracle(source);
    let (native, stats) = eval_with_engine(source, 1);

    assert!(
        oracle.raw_eq(native),
        "primop dispatch changed a result: oracle {oracle:?} vs native {native:?}"
    );
    assert!(
        stats.tier1_dispatched() >= 1,
        "expected primop dispatch, got promoted={} dispatched={} deopted={}",
        stats.tier1_promoted(),
        stats.tier1_dispatched(),
        stats.tier1_deopted(),
    );
    let histogram = blacklist_histogram_for(source);
    assert!(
        !histogram.iter().any(|(kind, _)| kind == "PrimOp:mul"),
        "the dispatched primop def-site must not be blacklisted, got {histogram:?}"
    );
}

/// By default the engine promotes nothing: it gates every hot def-site,
/// records the gated mass, never dispatches, and the tree walk still produces
/// the oracle's result.
#[test]
fn tiny_bodies_are_gated_out_of_promotion_by_default() {
    // A hot `builtins.mul` primop def-site and a hot `item.r` select def-site,
    // both forced 40 times. With a default engine (promotion off) neither
    // promotes: both are gated and the result is unchanged from the oracle.
    let source = "let g = k: { r = builtins.mul k 2; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (i + 1)) 40)";
    let oracle = eval_oracle(source);

    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    let engine = Rc::new(NixJitTier1Engine::with_threshold(1).expect("engine builds"));
    eval.set_tier1_engine(engine.clone());
    let native = eval.eval_root().expect("jit evaluation succeeds");

    assert!(
        oracle.raw_eq(native),
        "gating a tiny body changed a result: oracle {oracle:?} vs native {native:?}"
    );
    let stats = eval.stats();
    assert_eq!(
        stats.tier1_promoted(),
        0,
        "no tiny body may promote by default, got promoted={}",
        stats.tier1_promoted(),
    );
    let gated = engine.gated_histogram();
    assert!(
        gated.iter().any(|(name, _)| name == "mul"),
        "the hot `mul` primop def-site must be recorded as gated, got {gated:?}"
    );
    // Once gated, the tree walk records the def-site and stops consulting the
    // engine for its later instances (the per-force hook-tax fast path).
    assert!(
        eval.tier1_skipped_def_site_count() >= 1,
        "a gated def-site must be recorded in the tree-walk skip set, got {}",
        eval.tier1_skipped_def_site_count(),
    );
}

/// Under the stats flag the default (gated) engine promotes nothing but still
/// lowers each gated body once to record the profit-cost distribution.
#[test]
fn gated_bodies_record_their_profit_cost_distribution() {
    // A hot `builtins.mul` primop def-site and an `item.r` select def-site,
    // among the many gated bodies this program forces.
    let source = "let g = k: { r = builtins.mul k 2; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (i + 1)) 40)";
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    // Promotion stays off (default gate); only cost recording is on.
    let engine = Rc::new(
        NixJitTier1Engine::with_threshold(1)
            .expect("engine builds")
            .record_gated_cost(),
    );
    eval.set_tier1_engine(engine.clone());
    eval.eval_root().expect("jit evaluation succeeds");

    assert_eq!(
        eval.stats().tier1_promoted(),
        0,
        "the default gate must promote nothing while recording cost"
    );
    assert!(
        engine.gated_lowerable_count() >= 1,
        "at least one gated body must be lowerable, got lowerable={} unlowerable={}",
        engine.gated_lowerable_count(),
        engine.gated_unlowerable_count(),
    );
    let histogram = engine.gated_cost_histogram();
    assert!(
        !histogram.is_empty(),
        "a lowerable gated body must record a cost bucket"
    );
    // The histogram is ascending by native-instruction count and every bucket
    // holds at least one def-site, and their sum equals the lowerable count.
    assert!(histogram.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    assert!(histogram.iter().all(|(_, count)| *count >= 1));
    assert_eq!(
        histogram.iter().map(|(_, count)| count).sum::<u32>(),
        engine.gated_lowerable_count(),
        "every lowerable gated def-site must land in exactly one cost bucket"
    );
}

/// A hot `stringLength` def-site promotes to its native inline body and
/// dispatches, matching the oracle exactly with no deopts for string arguments.
#[test]
fn hot_string_length_def_site_dispatches_through_the_native_inline() {
    // Each `g` builds `{ r = builtins.stringLength s; }` for a string `s`;
    // summing `item.r` across 40 records forces 40 instances of that one
    // `stringLength` def-site, so it promotes to the native inline and its
    // later instances dispatch through `aos_string_length`.
    let source = "let g = s: { r = builtins.stringLength s; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (builtins.toString i)) 40)";
    let oracle = eval_oracle(source);
    let (native, stats) = eval_with_engine(source, 1);

    assert!(
        oracle.raw_eq(native),
        "stringLength inline changed a result: oracle {oracle:?} vs native {native:?}"
    );
    assert!(
        stats.tier1_dispatched() >= 1,
        "expected stringLength inline dispatch, got promoted={} dispatched={} deopted={}",
        stats.tier1_promoted(),
        stats.tier1_dispatched(),
        stats.tier1_deopted(),
    );
    assert_eq!(
        stats.tier1_deopted(),
        0,
        "string arguments must dispatch without deopting, got deopted={}",
        stats.tier1_deopted(),
    );
}

/// A `stringLength` inline whose argument is not a string traps in the leaf
/// helper and deopts to the tree walk, which reproduces the exact oracle error.
#[test]
fn string_length_inline_deopts_on_non_string_and_matches_the_oracle_error() {
    // The first records pass strings, promoting and dispatching the inline;
    // the last record passes an integer, whose forced value is not a string,
    // so `aos_string_length` traps, the engine deopts, and the tree walk raises
    // the identical coercion error.
    let source = "let g = s: { r = builtins.stringLength s; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (if i < 39 then builtins.toString i else i)) 40)";
    let oracle = eval_oracle_result(source);
    let native = eval_with_engine_result(source, 1);

    assert!(
        oracle.is_err(),
        "the fixture must error on the integer stringLength, got {oracle:?}"
    );
    assert_eq!(
        format!("{native:?}"),
        format!("{oracle:?}"),
        "a deopted stringLength trap must reproduce the oracle error"
    );
}

/// A dispatched impure primop records the same impure-input trace as the
/// oracle, the property force-cache cutoff soundness rests on.
#[test]
fn dispatched_impure_primop_records_the_same_trace_as_the_oracle() {
    // `builtins.pathExists` is impure: its tree-walk impl records an impure
    // input fingerprint. Because the trampoline re-enters the tree walk, a
    // dispatched `pathExists` runs that same impl and records the identical
    // trace -- never a native re-implementation that could skip it.
    let source = "let g = k: { r = builtins.pathExists /nonexistent-aos-jit-primop-probe; }; \
         in builtins.foldl' (acc: item: acc || item.r) false \
         (builtins.genList (i: g i) 12)";
    let (oracle_value, oracle_trace) = eval_oracle_with_trace(source);
    let (native_value, native_trace, stats) = eval_with_engine_traced(source, 1);

    assert!(
        oracle_value.raw_eq(native_value),
        "impure primop dispatch changed a result: oracle {oracle_value:?} vs native {native_value:?}"
    );
    assert!(
        stats.tier1_dispatched() >= 1,
        "expected impure primop dispatch, got promoted={} dispatched={} deopted={}",
        stats.tier1_promoted(),
        stats.tier1_dispatched(),
        stats.tier1_deopted(),
    );
    assert!(
        !native_trace.is_empty(),
        "a dispatched impure primop must record impure inputs"
    );
    assert_eq!(
        native_trace, oracle_trace,
        "a dispatched impure primop must record the same trace as the oracle"
    );
}

/// A dispatched primop that traps deopts to the tree walk, which reproduces
/// the exact error the oracle raises.
#[test]
fn dispatched_primop_trap_deopts_and_matches_the_oracle_error() {
    // The `builtins.head k` primop def-site succeeds for the first records --
    // promoting and dispatching it -- then traps on the empty-list instance.
    // The trampoline transfers the trap, the engine deopts, and the tree walk
    // reproduces the exact error, so the JIT and oracle fail identically.
    let source = "let g = k: { r = builtins.head k; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g (if i < 39 then [ i ] else [ ])) 40)";
    let oracle = eval_oracle_result(source);
    let native = eval_with_engine_result(source, 1);

    assert!(
        oracle.is_err(),
        "the fixture must trap on the empty-list head, got {oracle:?}"
    );
    assert_eq!(
        format!("{native:?}"),
        format!("{oracle:?}"),
        "a dispatched primop trap must reproduce the oracle error"
    );
}
