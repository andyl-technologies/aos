//! Tier-2 filter-predicate promotion and dispatch at the strict-filter seam.
//!
//! `builtins.filter` applies its predicate once per element through the
//! generic apply path, so a filter over N elements pays N interpreted applies
//! plus N boolean forces even when the predicate body is a single integer
//! comparison (`x: x < pivot` — quicksort's partition step runs 2N of these
//! per level). The apply-seam harness cannot rescue it for the same reason it
//! cannot rescue fold operators: its per-dispatch setup (context pin, trap
//! scope, environment clone) costs about a microsecond per call.
//!
//! This module hooks the **filter loop itself**
//! ([`Tier1Engine::on_filter_strict`]), mirroring the fold seam
//! ([`tier2_fold`](super::tier2_fold)): the predicate's arity-1 body is
//! compiled once as a native function (see
//! [`ratchet_jit::scan_tier2_unary_predicate`] and
//! [`ratchet_jit::lower_tier2_curried_chain`]) and the loop's element run is
//! handed to [`run_context_finalized_native_filter_loop`], which pins the
//! context and trap scope **once** and then pays one bare native call per
//! element, collecting the kept prefix. The filter loop consults the engine
//! at most twice per filter call, so undecided or blacklisted predicates
//! cost two hash probes per filter, never per element.
//!
//! # Promotion gate
//!
//! A predicate is compiled when the remaining element run is at least
//! [`TIER2_FILTER_MIN_ELEMENTS`] long and its single bare formal scans under
//! the fused grammar with a call-free-inlinable pinned callee set. The
//! quicksort shape — an integer comparison against a `let`-captured pivot —
//! is an environment read against the predicate closure's own captured
//! environment, lowered under the [`JitTier2EnvBoundary::OperatorEnv`]
//! boundary at skew 1 (the unapplied closure's environment misses exactly
//! the one parameter frame). Structural failures blacklist the predicate's
//! def-site; an unforced callee binding is transient and leaves the def-site
//! undecided for the second consult.
//!
//! # Dispatch guards and deopt
//!
//! Per filter call (never per element) the engine re-validates every pinned
//! callee's def-site identity out of the predicate's captured environment
//! and requires the same small `max_call_depth` headroom margin as the fold
//! seam. A native run that deopts at element `k` — an integer guard failure,
//! a forcing error, or a non-boolean predicate result — reports the elements
//! it decided and their kept subsequence; the filter loop re-runs element
//! `k` interpreted, which is sound because the compiled body is pure except
//! for memoizing forces: the re-run observes identical values and reproduces
//! the exact tree-walk result or error (including the boolean type error).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ratchet_core::{IrId, syntax::Span};
use ratchet_jit::{
    JitModuleContextFinalizedBody, JitModuleContextKeepAlive, JitTier2EnvBoundary,
    lower_tier2_curried_chain, scan_tier2_unary_predicate,
};
use ratchet_oracle::eval::heap::EvalLambda;
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_oracle::eval::{Tier2AllAnyHook, Tier2FilterHook};
use ratchet_runtime_ffi::{
    run_context_finalized_native_all_any_loop, run_context_finalized_native_filter_loop,
};
use ratchet_value::value::Value;

use super::NixJitTier1Engine;
use super::tier2_chain::{Tier2ChainCacheRole, Tier2PinIdentity, chain_cache_identity};
use super::tier2_fold::{
    FoldOperatorResolution, TIER2_FOLD_MIN_HEADROOM, fold_def_site_key, fold_pins_still_valid,
};

/// The minimum remaining element run that justifies compiling a predicate.
///
/// Same floor as the fold seam: compilation costs tens of microseconds; a
/// run of this many elements recovers it in the first native pass, and
/// shorter filters simply stay interpreted without deciding the def-site (a
/// later, longer filter of the same predicate may still promote it).
pub(super) const TIER2_FILTER_MIN_ELEMENTS: usize = 8;

/// Mutable filter-seam bookkeeping, guarded by the engine's `RefCell`.
#[derive(Default)]
pub(super) struct Tier2FilterState {
    /// Compiled predicate entries keyed by predicate def-site
    /// (`(module_index << 32) | body_ir_id`).
    entries: HashMap<u64, Rc<NixJitTier2FilterEntry>>,
    /// Predicate def-sites that can never compile as filter predicates.
    blacklist: HashSet<u64>,
}

/// Owns a finalized filter-predicate entry so its native code stays callable.
struct NixJitTier2FilterEntry {
    /// The finalized boundary entry (frozen argv lambda-entry ABI, arity 1).
    body: Rc<JitModuleContextFinalizedBody>,
    /// Keeps the shared JIT module (and thus the entry's code) alive.
    _keep_alive: JitModuleContextKeepAlive,
    /// The pinned callees re-validated per filter call.
    pinned: Vec<Tier2PinIdentity>,
}

/// The outcome of preparing a filter-predicate promotion.
enum FilterPreparation {
    /// The predicate compiled and finalized.
    Ready(Rc<NixJitTier2FilterEntry>),
    /// A callee binding is not forced yet; retry on the next consult.
    Transient,
    /// The predicate can never compile as a filter predicate.
    Structural,
}

impl NixJitTier1Engine {
    /// Implements [`Tier1Engine::on_filter_strict`] for the live engine.
    ///
    /// See the [module docs](self) for the promotion gate and dispatch
    /// guards.
    ///
    /// [`Tier1Engine::on_filter_strict`]: ratchet_oracle::eval::Tier1Engine::on_filter_strict
    pub(super) fn on_filter_strict_impl(
        &self,
        eval: &mut TreeWalk,
        predicate: Value,
        lambda: &EvalLambda,
        elements: &[Value],
        id: IrId,
        span: Span,
    ) -> Tier2FilterHook {
        let _ = predicate;
        if !self.tier2_enabled {
            return filter_continued(false, false);
        }
        let key = fold_def_site_key(lambda);
        let existing = {
            let state = self.tier2_filter.borrow();
            if state.blacklist.contains(&key) {
                return filter_continued(false, false);
            }
            state.entries.get(&key).cloned()
        };
        let (entry, promoted) = match existing {
            Some(entry) => (entry, false),
            None => {
                if elements.len() < TIER2_FILTER_MIN_ELEMENTS {
                    return filter_continued(false, false);
                }
                match self.prepare_tier2_filter(eval, lambda) {
                    FilterPreparation::Ready(entry) => {
                        self.tier2_filter
                            .borrow_mut()
                            .entries
                            .insert(key, Rc::clone(&entry));
                        (entry, true)
                    }
                    FilterPreparation::Transient => return filter_continued(false, false),
                    FilterPreparation::Structural => {
                        self.tier2_filter.borrow_mut().blacklist.insert(key);
                        return filter_continued(false, true);
                    }
                }
            }
        };

        // Per-filter dispatch guards (never per element).
        if !fold_pins_still_valid(eval, lambda, &entry.pinned, 1) {
            return filter_continued(promoted, false);
        }
        if eval.tier2_call_depth_headroom() < TIER2_FOLD_MIN_HEADROOM {
            return filter_continued(promoted, false);
        }

        let env = lambda.env().clone();
        match run_context_finalized_native_filter_loop(eval, id, span, &env, elements, &entry.body)
        {
            Ok(outcome) => Tier2FilterHook::Ran {
                consumed: outcome.consumed(),
                deopted: outcome.deopted(),
                kept: outcome.into_kept(),
                promoted,
            },
            Err(_) => filter_continued(promoted, false),
        }
    }

    /// Runs the filter predicate entry at the strict `all`/`any` loop seam.
    pub(super) fn on_all_any_strict_impl(
        &self,
        eval: &mut TreeWalk,
        predicate: Value,
        lambda: &EvalLambda,
        elements: &[Value],
        short_circuit_on: bool,
        id: IrId,
        span: Span,
    ) -> Tier2AllAnyHook {
        let _ = predicate;
        if !self.tier2_enabled {
            return all_any_continued(false, false);
        }
        let key = fold_def_site_key(lambda);
        let existing = {
            let state = self.tier2_filter.borrow();
            if state.blacklist.contains(&key) {
                return all_any_continued(false, false);
            }
            state.entries.get(&key).cloned()
        };
        let (entry, promoted) = match existing {
            Some(entry) => (entry, false),
            None => {
                if elements.len() < TIER2_FILTER_MIN_ELEMENTS {
                    return all_any_continued(false, false);
                }
                match self.prepare_tier2_filter(eval, lambda) {
                    FilterPreparation::Ready(entry) => {
                        self.tier2_filter
                            .borrow_mut()
                            .entries
                            .insert(key, Rc::clone(&entry));
                        (entry, true)
                    }
                    FilterPreparation::Transient => return all_any_continued(false, false),
                    FilterPreparation::Structural => {
                        self.tier2_filter.borrow_mut().blacklist.insert(key);
                        return all_any_continued(false, true);
                    }
                }
            }
        };
        if !fold_pins_still_valid(eval, lambda, &entry.pinned, 1)
            || eval.tier2_call_depth_headroom() < TIER2_FOLD_MIN_HEADROOM
        {
            return all_any_continued(promoted, false);
        }
        let env = lambda.env().clone();
        match run_context_finalized_native_all_any_loop(
            eval,
            id,
            span,
            &env,
            elements,
            short_circuit_on,
            &entry.body,
        ) {
            Ok(outcome) => Tier2AllAnyHook::Ran {
                consumed: outcome.consumed(),
                short_circuited: outcome.short_circuited(),
                deopted: outcome.deopted(),
                promoted,
            },
            Err(_) => all_any_continued(promoted, false),
        }
    }

    /// Scans, resolves, lowers, and finalizes one filter predicate.
    fn prepare_tier2_filter(&self, eval: &TreeWalk, lambda: &EvalLambda) -> FilterPreparation {
        let Some(ir) = eval.tier1_module_ir(lambda.module()) else {
            return FilterPreparation::Structural;
        };
        let Ok(scan) = scan_tier2_unary_predicate(&ir.arena, &ir.bindings, lambda.pattern(), lambda.body())
        else {
            return FilterPreparation::Structural;
        };
        let resolved = match self.resolve_scanned_operator_callees(eval, lambda, scan) {
            FoldOperatorResolution::Ready(resolved) => resolved,
            FoldOperatorResolution::Transient => return FilterPreparation::Transient,
            FoldOperatorResolution::Structural => return FilterPreparation::Structural,
        };

        // A filter predicate never self-recurses (`self_upval` is `None`;
        // any non-pinned callee chain already failed the resolution above).
        // The filter seam dispatches with the unapplied predicate closure's
        // environment, so env reads translate against `OperatorEnv` (skew 1
        // at arity 1).
        let budget = self.tier2.borrow().budget;
        let env_boundary = JitTier2EnvBoundary::OperatorEnv;
        let Some(cache_identity) = chain_cache_identity(
            Tier2ChainCacheRole::Predicate,
            lambda.pattern(),
            lambda.body(),
            &resolved.scan,
            None,
            &resolved.pinned,
            &resolved.pinned_callees,
            env_boundary,
            &[],
        ) else {
            return FilterPreparation::Structural;
        };
        let cached = {
            let state = self.tier2.borrow();
            state.compiled_cache.as_ref().and_then(|cache| {
                cache.load_chain(
                    ir,
                    &cache_identity,
                    resolved.scan.inner_body(),
                    resolved.scan.arity(),
                    None,
                    budget,
                )
            })
        };
        let cache_hit = cached.is_some();
        let Some(lowering) = cached.or_else(|| {
            lower_tier2_curried_chain(
                &ir.arena,
                &ir.bindings,
                &resolved.scan,
                None,
                &resolved.pinned_callees,
                env_boundary,
                budget,
            )
            .ok()
        }) else {
            return FilterPreparation::Structural;
        };
        if !cache_hit && let Some(cache) = self.tier2.borrow().compiled_cache.as_ref() {
            cache.store_chain(ir, &cache_identity, budget, &lowering);
        }
        let Some((finalized_body, keep_alive)) = self.finalize_tier2_chain(lowering) else {
            return FilterPreparation::Structural;
        };
        FilterPreparation::Ready(Rc::new(NixJitTier2FilterEntry {
            body: Rc::new(finalized_body),
            _keep_alive: keep_alive,
            pinned: resolved.pinned,
        }))
    }
}

/// A `Continued` filter hook with the given promotion/blacklist flags.
const fn filter_continued(promoted: bool, blacklisted: bool) -> Tier2FilterHook {
    Tier2FilterHook::Continued {
        promoted,
        blacklisted,
    }
}

/// A `Continued` all/any hook with the given promotion/blacklist flags.
const fn all_any_continued(promoted: bool, blacklisted: bool) -> Tier2AllAnyHook {
    Tier2AllAnyHook::Continued {
        promoted,
        blacklisted,
    }
}

// These tests exercise tier-2 curried-chain codegen. They run on both carriers
// now that the S4b phase-2 one-word emitters have landed; individual tests that
// still require two-word specifics are gated inline.
#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use ratchet_core::Ir;
    use ratchet_oracle::eval::EvalStats;
    use ratchet_oracle::eval::tree_walk::{TreeWalk, TreeWalkError, TreeWalkOptions};
    use ratchet_oracle::syntax::parse_str;
    use ratchet_value::value::Value;

    use crate::jit::engine::NixJitTier1Engine;

    /// Parses, resolves, and lowers a source program into Core IR.
    fn lower(source: &str) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = ratchet_oracle::compile::resolve(parsed).expect("source resolves");
        let mut ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        ratchet_core::annotate_capture_plans(&mut ir).expect("capture plans annotate");
        ir
    }

    /// Evaluates `source` to WHNF through the tree-walk oracle (no JIT engine).
    fn eval_oracle(source: &str) -> Value {
        let ir = lower(source);
        TreeWalk::new(&ir).eval_root().expect("oracle evaluates")
    }

    /// Evaluates `source` with a default engine installed (tier-2 active).
    fn eval_with_tier2(source: &str) -> (Value, EvalStats) {
        let (result, stats) = eval_with_tier2_result(source);
        (result.expect("tier-2 evaluation succeeds"), stats)
    }

    /// Evaluates `source` with a default engine, returning the raw result.
    fn eval_with_tier2_result(source: &str) -> (Result<Value, TreeWalkError>, EvalStats) {
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_jit_tier1_publish_enabled(true);
        let mut eval = TreeWalk::with_options(&ir, options);
        eval.set_tier1_engine(Rc::new(NixJitTier1Engine::new().expect("engine builds")));
        let result = eval.eval_root();
        let stats = eval.stats();
        (result, stats)
    }

    /// The quicksort partition shape — a comparison against a `let`-captured
    /// pivot, an environment read at the operator boundary — filters
    /// natively and matches the oracle with zero deopts.
    #[test]
    fn pivot_comparison_predicate_filters_natively() {
        let source = "let pivot = 500; in builtins.length \
             (builtins.filter (x: x < pivot) (builtins.genList (i: i * 7) 400))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "filter seam changed a pivot filter: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_promoted() >= 1,
            "the predicate must promote, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the filter must run natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer filter must never deopt, got {stats:?}"
        );
    }

    /// `all` exhausts a long integer run through the shared native predicate.
    #[test]
    fn all_exhausts_natively_and_matches_the_oracle() {
        let source = "let limit = 400; in builtins.all (x: x < limit) \
             (builtins.genList (i: i) limit)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(stats.tier2_dispatched() >= 1, "got {stats:?}");
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// `any` stops at its first true result without evaluating a later error.
    #[test]
    fn any_short_circuit_preserves_laziness() {
        let source = "builtins.any (x: x == 40) \
             (builtins.genList (i: if i == 50 then 1 / 0 else i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(stats.tier2_dispatched() >= 1, "got {stats:?}");
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// A non-integer mid-run deopts and the interpreted suffix still decides.
    #[test]
    fn all_deopts_mid_run_and_resumes_interpreted() {
        let source = "builtins.all (x: x < 40) \
             (builtins.genList (i: if i == 20 then 0.5 else i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(stats.tier2_dispatched() >= 1, "got {stats:?}");
        assert!(stats.tier2_deopted() >= 1, "got {stats:?}");
    }

    /// A closed arithmetic predicate (no environment reads) filters natively
    /// and keeps exactly the oracle's elements, checksum-pinned.
    ///
    /// Baseline-only: the `a * 31 + b` checksum fold over the kept set crosses
    /// the inline `i32` range, so on the one-word carrier the fold operator
    /// boxes each wide result and deopts — the zero-deopt invariant here is
    /// two-word-specific. The filter predicate itself lowers on both carriers
    /// (see [`let_bound_intermediate_predicate_filters_natively`]).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn closed_arithmetic_predicate_keeps_the_same_elements() {
        let source = "builtins.foldl' (a: b: a * 31 + b) 0 \
             (builtins.filter (x: x - (x / 3) * 3 == 1) (builtins.genList (i: i) 200))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "filter seam changed a kept set: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the filter must run natively, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// A predicate with a pinned helper callee inlines it and matches.
    #[test]
    fn predicate_with_pinned_callee_filters_natively() {
        let source = "let mod = a: b: a - b * (a / b); in builtins.length \
             (builtins.filter (x: mod x 7 == 3) (builtins.genList (i: i) 300))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "filter seam changed a helper filter: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the helper filter must run natively, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// A float element mid-run deopts the native loop at that element; the
    /// interpreted resume keeps the oracle's exact element set.
    #[test]
    fn float_element_deopts_mid_run_and_matches_the_oracle() {
        let source = "builtins.length (builtins.filter (x: x < 30) \
             (builtins.genList (i: if i == 40 then 0.5 else i) 64))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "filter deopt changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the integer prefix must run natively, got {stats:?}"
        );
        assert!(
            stats.tier2_deopted() >= 1,
            "the float element must deopt the native loop, got {stats:?}"
        );
    }

    /// A non-boolean predicate result reproduces the oracle's type error
    /// exactly (the native loop deopts and the interpreted re-run errors).
    #[test]
    fn non_boolean_predicate_reproduces_the_oracle_error() {
        let source = "builtins.filter (x: x + 1) (builtins.genList (i: i) 64)";
        let ir = lower(source);
        let oracle = TreeWalk::new(&ir).eval_root();
        let (native, _stats) = eval_with_tier2_result(source);

        assert!(oracle.is_err(), "the fixture must fail the boolean check");
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "a compiled non-boolean predicate must reproduce the oracle error"
        );
    }

    /// A division by zero inside the compiled predicate deopts and the
    /// interpreted re-run reproduces the oracle's error exactly.
    #[test]
    fn predicate_division_by_zero_reproduces_the_oracle_error() {
        let source =
            "builtins.filter (x: 1 / (x - 40) < 1) (builtins.genList (i: i) 64)";
        let ir = lower(source);
        let oracle = TreeWalk::new(&ir).eval_root();
        let (native, _stats) = eval_with_tier2_result(source);

        assert!(oracle.is_err(), "the fixture must divide by zero");
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "a compiled predicate division-by-zero must reproduce the oracle error"
        );
    }

    /// A filter shorter than the promotion floor stays interpreted and
    /// leaves the def-site undecided.
    #[test]
    fn short_filters_stay_interpreted_without_deciding() {
        let source = "builtins.foldl' (a: b: a * 31 + b) 0 \
             (builtins.filter (x: x < 3) (builtins.genList (i: i) 4))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert_eq!(stats.tier2_promoted(), 0, "got {stats:?}");
        assert_eq!(stats.tier2_dispatched(), 0, "got {stats:?}");
    }

    /// The first-class (value-path) filter loop reaches the filter seam too.
    #[test]
    fn first_class_filter_reaches_the_filter_seam() {
        let source = "let keep = builtins.filter; in builtins.length \
             (keep (x: x < 40) (builtins.genList (i: i) 64))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(
            stats.tier2_dispatched() >= 1,
            "the value-path filter must run natively, got {stats:?}"
        );
    }

    /// An out-of-grammar predicate (string body) blacklists once and the
    /// result is unchanged.
    #[test]
    fn out_of_grammar_predicate_blacklists_and_matches() {
        let source = "builtins.length (builtins.filter \
             (x: builtins.substring 0 1 (builtins.toString x) == \"1\") \
             (builtins.genList (i: i) 64))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(
            stats.tier2_blacklisted() >= 1,
            "the string predicate must blacklist, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "a blacklisted predicate never dispatches, got {stats:?}"
        );
    }

    /// A predicate with a `let`-bound intermediate compiles: the binding is
    /// a virtual register over the element parameter and an env read.
    #[test]
    fn let_bound_intermediate_predicate_filters_natively() {
        let source = "let pivot = 900; in builtins.length              (builtins.filter (x: let y = x * x; in y < pivot)               (builtins.genList (i: i) 100))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "let-local predicate changed a filter: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the let-local predicate must run natively, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// The quicksort benchmark shape end to end: both partition predicates
    /// promote, the sort matches the oracle, and nothing deopts.
    ///
    /// Sized so the oracle's interpreted run stays within the debug
    /// test-thread stack (deep `++` spines overflow it well before the
    /// interpreter's own `max_call_depth` — a pre-existing interpreter
    /// limit, unrelated to the filter seam).
    ///
    /// Decoded-core: the closing `mod (acc * 31 + x) 1000000007` fold keeps its
    /// accumulator inline while the wide `acc * 31 + x` intermediate stays
    /// decoded, so the whole shape lowers and runs deopt-free on both carriers.
    #[test]
    fn quicksort_partitions_filter_natively_and_match() {
        let source = "let mod = a: b: a - b * (a / b); \
             lcg = i: mod (1 + (mod (1 + i * 48271) 2147483647) * 48271) 2147483647; \
             qsort = xs: if builtins.length xs < 2 then xs else \
               let pivot = builtins.head xs; rest = builtins.tail xs; in \
               qsort (builtins.filter (x: x < pivot) rest) \
               ++ [pivot] \
               ++ qsort (builtins.filter (x: x >= pivot) rest); \
             sorted = qsort (builtins.genList lcg 96); \
             in builtins.foldl' (acc: x: mod (acc * 31 + x) 1000000007) 0 sorted";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "filter seam changed quicksort: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 2,
            "both partition predicates must run natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer quicksort must never deopt, got {stats:?}"
        );
    }
}
