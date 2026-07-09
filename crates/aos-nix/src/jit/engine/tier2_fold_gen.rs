//! Tier-2 fused list generation at the `foldl'`-over-`genList` seam.
//!
//! Landing 2's fold seam ([`tier2_fold`](super::tier2_fold)) compiles the
//! fold operator but still consumes materialized elements: for
//! `builtins.foldl' op acc (builtins.genList g n)` every element is a `g i`
//! apply-thunk whose forcing round-trips through `aos_force` back into the
//! interpreter — for sum-fold's 1.5M elements that forcing was ~65% of the
//! residual wall. This module compiles the generator INTO the fold loop
//! (see [`ratchet_jit::lower_tier2_fold_genlist`]): the native step receives
//! `(acc, index)`, synthesizes the element from the index in-register, and
//! folds it — no element thunk is ever allocated and no force ever leaves
//! native code.
//!
//! # Where the seam fires
//!
//! The oracle consults [`Tier1Engine::on_foldl_strict_genlist`] only from
//! its fused index loop, which itself replaces the materialized fold only
//! for a **direct** `genList` application in a **direct** `foldl'` node —
//! the one shape where the generated list is a pure local temporary that
//! nothing else can observe (see the oracle's `fold_genlist` module for the
//! unobservability argument). The engine side then only has to prove the
//! *values* match: the generator body is call-free arithmetic over its
//! integer index (validated by `scan_tier2_pinned_callee` with arity 1), so
//! its native emission produces exactly the value the interpreter's forced
//! `g i` thunk would, or deopts.
//!
//! # Promotion, caching, and guards
//!
//! Entries are keyed by the `(operator def-site, generator def-site)` pair:
//! a call-free generator body is environment-free, so generator def-site
//! identity is behavioral identity (the same argument as pinned callees),
//! while the operator's pinned callees are re-validated per fold call
//! exactly like the plain fold seam. Both lambdas must live in the same
//! module (one arena feeds one lowering). Structural failures blacklist the
//! pair; an unforced operator callee binding is transient and retries on the
//! second consult, after one interpreted element has forced it.
//!
//! # Deopt
//!
//! A native run that deopts after generating `k` elements reports
//! `consumed == k`; the oracle's index loop resumes at index
//! `next_index + k`, materializing that element's `g i` thunk on demand and
//! re-running it interpreted — which reproduces the exact tree-walk result
//! or error whether the failure was in the generator (division guard) or in
//! the operator (tag guard, forcing error).
//!
//! [`Tier1Engine::on_foldl_strict_genlist`]: ratchet_oracle::eval::Tier1Engine::on_foldl_strict_genlist

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ratchet_core::{IrId, syntax::Span};
use ratchet_jit::{
    JitModuleContextFinalizedBody, JitModuleContextKeepAlive, lower_tier2_fold_genlist,
    scan_tier2_pinned_callee,
};
use ratchet_oracle::eval::Tier2FoldHook;
use ratchet_oracle::eval::heap::EvalLambda;
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_runtime_ffi::run_context_finalized_native_fold_genlist_loop;
use ratchet_value::value::Value;

use super::NixJitTier1Engine;
use super::tier2_chain::Tier2PinIdentity;
use super::tier2_fold::{
    FoldOperatorResolution, TIER2_FOLD_MIN_ELEMENTS, TIER2_FOLD_MIN_HEADROOM, fold_def_site_key,
    fold_pins_still_valid,
};

/// Mutable fused-generation bookkeeping, guarded by the engine's `RefCell`.
#[derive(Default)]
pub(super) struct Tier2FoldGenState {
    /// Compiled fused entries keyed by `(operator def-site, generator
    /// def-site)` (each `(module_index << 32) | body_ir_id`).
    entries: HashMap<(u64, u64), Rc<NixJitTier2FoldGenEntry>>,
    /// Pairs that can never compile as a fused generated fold.
    blacklist: HashSet<(u64, u64)>,
}

/// Owns a finalized fused fold-generator entry so its code stays callable.
struct NixJitTier2FoldGenEntry {
    /// The finalized boundary entry (frozen argv ABI; argv = `[acc, index]`).
    body: Rc<JitModuleContextFinalizedBody>,
    /// Keeps the shared JIT module (and thus the entry's code) alive.
    _keep_alive: JitModuleContextKeepAlive,
    /// The operator's pinned callees re-validated per fold call.
    pinned: Vec<Tier2PinIdentity>,
}

/// The outcome of preparing one fused promotion.
enum FoldGenPreparation {
    /// The fused operator+generator compiled and finalized.
    Ready(Rc<NixJitTier2FoldGenEntry>),
    /// An operator callee binding is not forced yet; retry next consult.
    Transient,
    /// The pair can never compile fused.
    Structural,
}

impl NixJitTier1Engine {
    /// Implements [`Tier1Engine::on_foldl_strict_genlist`] for the live
    /// engine.
    ///
    /// See the [module docs](self) for the promotion gate and dispatch
    /// guards.
    ///
    /// [`Tier1Engine::on_foldl_strict_genlist`]: ratchet_oracle::eval::Tier1Engine::on_foldl_strict_genlist
    #[allow(clippy::too_many_arguments)]
    pub(super) fn on_foldl_strict_genlist_impl(
        &self,
        eval: &mut TreeWalk,
        op: Value,
        op_lambda: &EvalLambda,
        generator: Value,
        generator_lambda: &EvalLambda,
        accumulator: Value,
        next_index: usize,
        length: usize,
        id: IrId,
        span: Span,
    ) -> Tier2FoldHook {
        let _ = (op, generator);
        if !self.tier2_enabled {
            return fold_gen_continued(false, false);
        }
        let key = (
            fold_def_site_key(op_lambda),
            fold_def_site_key(generator_lambda),
        );
        let remaining = length.saturating_sub(next_index);
        let existing = {
            let state = self.tier2_fold_gen.borrow();
            if state.blacklist.contains(&key) {
                return fold_gen_continued(false, false);
            }
            state.entries.get(&key).cloned()
        };
        let (entry, promoted) = match existing {
            Some(entry) => (entry, false),
            None => {
                if remaining < TIER2_FOLD_MIN_ELEMENTS {
                    return fold_gen_continued(false, false);
                }
                match self.prepare_tier2_fold_gen(eval, op_lambda, generator_lambda) {
                    FoldGenPreparation::Ready(entry) => {
                        self.tier2_fold_gen
                            .borrow_mut()
                            .entries
                            .insert(key, Rc::clone(&entry));
                        (entry, true)
                    }
                    FoldGenPreparation::Transient => return fold_gen_continued(false, false),
                    FoldGenPreparation::Structural => {
                        self.tier2_fold_gen.borrow_mut().blacklist.insert(key);
                        return fold_gen_continued(false, true);
                    }
                }
            }
        };

        // Per-fold dispatch guards (never per element), identical to the
        // plain fold seam: the generator needs no guard beyond its def-site
        // key (call-free bodies are environment-free).
        if !fold_pins_still_valid(eval, op_lambda, &entry.pinned, 2) {
            return fold_gen_continued(promoted, false);
        }
        if eval.tier2_call_depth_headroom() < TIER2_FOLD_MIN_HEADROOM {
            return fold_gen_continued(promoted, false);
        }

        let env = op_lambda.env().clone();
        match run_context_finalized_native_fold_genlist_loop(
            eval,
            id,
            span,
            &env,
            accumulator,
            next_index,
            remaining,
            &entry.body,
        ) {
            Ok(outcome) => Tier2FoldHook::Ran {
                consumed: outcome.consumed(),
                accumulator: outcome.accumulator(),
                deopted: outcome.deopted(),
                promoted,
            },
            Err(_) => fold_gen_continued(promoted, false),
        }
    }

    /// Resolves, lowers, and finalizes one fused operator+generator pair.
    fn prepare_tier2_fold_gen(
        &self,
        eval: &TreeWalk,
        op_lambda: &EvalLambda,
        generator_lambda: &EvalLambda,
    ) -> FoldGenPreparation {
        // One lowering reads one arena: both lambdas must share a module.
        if generator_lambda.module() != op_lambda.module() {
            return FoldGenPreparation::Structural;
        }
        let resolved = match self.resolve_tier2_fold_operator(eval, op_lambda) {
            FoldOperatorResolution::Ready(resolved) => resolved,
            FoldOperatorResolution::Transient => return FoldGenPreparation::Transient,
            FoldOperatorResolution::Structural => return FoldGenPreparation::Structural,
        };
        let Some(ir) = eval.tier1_module_ir(op_lambda.module()) else {
            return FoldGenPreparation::Structural;
        };
        let arena = &ir.arena;
        // The generator must be a single bare formal over a call-free
        // arithmetic body — the same grammar as a pinned callee at arity 1,
        // which also guarantees it reads no environment.
        let Ok(generator_body) = scan_tier2_pinned_callee(
            arena,
            generator_lambda.pattern(),
            generator_lambda.body(),
            1,
        ) else {
            return FoldGenPreparation::Structural;
        };

        let budget = self.tier2.borrow().budget;
        let Ok(lowering) = lower_tier2_fold_genlist(
            arena,
            &ir.bindings,
            &resolved.scan,
            &resolved.pinned_callees,
            generator_body,
            budget,
        ) else {
            return FoldGenPreparation::Structural;
        };
        let Some((finalized_body, keep_alive)) = self.finalize_tier2_chain(lowering) else {
            return FoldGenPreparation::Structural;
        };
        FoldGenPreparation::Ready(Rc::new(NixJitTier2FoldGenEntry {
            body: Rc::new(finalized_body),
            _keep_alive: keep_alive,
            pinned: resolved.pinned,
        }))
    }
}

/// A `Continued` fold hook with the given promotion/blacklist flags.
const fn fold_gen_continued(promoted: bool, blacklisted: bool) -> Tier2FoldHook {
    Tier2FoldHook::Continued {
        promoted,
        blacklisted,
    }
}

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
        aos_nix_dialect::nix_lower(resolved).expect("source lowers")
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

    /// The canonical sum-fold shape — operator with a pinned callee over an
    /// identity generator — fuses, folds natively, and matches the oracle
    /// with zero deopts and zero interpreted element forces on the fused run.
    #[test]
    fn sum_fold_over_genlist_fuses_and_matches_the_oracle() {
        let source = "let mod = a: b: a - b * (a / b); in \
             builtins.foldl' (acc: i: mod (acc + i * i + 2654435761) 1000000007) 0 \
             (builtins.genList (i: i) 500)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "fused genlist fold changed sum-fold: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_promoted() >= 1,
            "the fused pair must promote, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the fused fold must run natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer fused fold must never deopt, got {stats:?}"
        );
    }

    /// A computed generator body runs inside the native loop and matches the
    /// oracle exactly (same wrap and truncation semantics as forced thunks).
    #[test]
    fn computed_generator_body_matches_the_oracle() {
        let source = "builtins.foldl' (a: b: a + b) 0 \
             (builtins.genList (i: i * i - 3 * i + 7) 200)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native), "computed generator diverged");
        assert!(
            stats.tier2_dispatched() >= 1,
            "the computed generator must fuse, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// The negation widening reaches both the generator and the operator.
    #[test]
    fn unary_negation_in_generator_and_operator_matches_the_oracle() {
        let source = "builtins.foldl' (a: b: a - -b) 0 \
             (builtins.genList (i: -i + 3) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native), "negation semantics diverged");
        assert!(
            stats.tier2_dispatched() >= 1,
            "the negating fold must fuse, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// An operator reading a captured integer binding (a general environment
    /// read) fuses and matches the oracle: the read is forced once per native
    /// call out of the operator's own environment.
    #[test]
    fn operator_environment_read_fuses_and_matches_the_oracle() {
        let source = "let scale = 3; offset = 17; in \
             builtins.foldl' (acc: i: acc + i * scale + offset) 0 \
             (builtins.genList (i: i) 100)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "env-read fold diverged: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the env-reading fold must fuse, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// A generator whose guard fails mid-run for an element the operator
    /// never demands deopts natively but the interpreted resume — which never
    /// forces that element — still matches the oracle. This pins the eager
    /// generator-evaluation soundness argument: a generator deopt is never a
    /// committed error.
    #[test]
    fn undemanded_generator_failure_deopts_without_an_error() {
        // `b` is unused, so the interpreter never forces any element and the
        // division by zero at i == 40 never happens interpreted; the fused
        // loop's eager generator hits the division guard, deopts at 40, and
        // the interpreted resume finishes without error.
        let source = "builtins.foldl' (a: b: a + 2) 0 \
             (builtins.genList (i: 100 / (i - 40)) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "eager generator evaluation changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the integer prefix must run natively, got {stats:?}"
        );
        assert!(
            stats.tier2_deopted() >= 1,
            "the undemanded generator failure must deopt, got {stats:?}"
        );
    }

    /// A demanded generator division by zero reproduces the oracle error
    /// byte-for-byte through the deopt-and-rerun path.
    #[test]
    fn demanded_generator_division_by_zero_reproduces_the_oracle_error() {
        let source = "builtins.foldl' (a: b: a + b) 0 \
             (builtins.genList (i: 100 / (i - 40)) 64)";
        let ir = lower(source);
        let oracle = TreeWalk::new(&ir).eval_root();
        let (native, _stats) = eval_with_tier2_result(source);

        assert!(oracle.is_err(), "the fixture must divide by zero");
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "a fused generator division-by-zero must reproduce the oracle error"
        );
    }

    /// A `genList` with a negative length reproduces the oracle error through
    /// the fused argument-evaluation path.
    #[test]
    fn negative_genlist_length_reproduces_the_oracle_error() {
        let source = "builtins.foldl' (a: b: a + b) 0 (builtins.genList (i: i) (0 - 1))";
        let ir = lower(source);
        let oracle = TreeWalk::new(&ir).eval_root();
        let (native, _stats) = eval_with_tier2_result(source);

        assert!(oracle.is_err(), "the fixture must reject a negative length");
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "the fused path must reproduce the negative-length error"
        );
    }

    /// An empty generated list takes the lazy-initial path unchanged.
    ///
    /// The comparison forces the fold's lazy initial value so both sides
    /// yield an inline boolean (an unforced fold-identity thunk would compare
    /// by heap identity, which is meaningless across two evaluators).
    #[test]
    fn empty_genlist_fold_matches_the_oracle() {
        let source = "if builtins.foldl' (a: b: a + b) 41 (builtins.genList (i: i) 0) == 41 \
             then 7 else 9";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert_eq!(stats.tier2_dispatched(), 0, "got {stats:?}");
    }

    /// An out-of-grammar generator (string body) blacklists the pair but the
    /// interpreted index loop still matches the materialized semantics.
    #[test]
    fn out_of_grammar_generator_stays_interpreted_and_matches() {
        let source = "builtins.stringLength \
             (builtins.foldl' (a: b: a + b) \"\" (builtins.genList (i: \"xy\") 64))";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native), "interpreted index loop diverged");
        assert_eq!(
            stats.tier2_dispatched(),
            0,
            "an out-of-grammar pair must never dispatch, got {stats:?}"
        );
    }

    /// A trace inside the generator never fuses: the pair blacklists and the
    /// remaining run falls back to the materialized landing-2 seam, whose
    /// native operator forces each traced element thunk through the
    /// interpreter — so the trace fires per demanded element exactly as an
    /// interpreted fold would fire it, and the value matches the oracle.
    #[test]
    fn effectful_generator_falls_back_to_the_materialized_seam() {
        let source = "builtins.foldl' (a: b: a + b) 0 \
             (builtins.genList (i: builtins.trace \"gen\" i) 16)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(
            stats.tier2_blacklisted() >= 1,
            "the traced pair must blacklist for fusion, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "the materialized fallback must not deopt on an integer fold, got {stats:?}"
        );
    }

    /// A first-class `foldl'` keeps the materialized path (the fusion only
    /// fires on the direct-application shape) and still matches the oracle.
    #[test]
    fn first_class_foldl_over_genlist_keeps_the_materialized_path() {
        let source = "let fold = builtins.foldl'; in \
             fold (a: b: a + b) 0 (builtins.genList (i: i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(
            stats.tier2_dispatched() >= 1,
            "the value-path fold still reaches the plain fold seam, got {stats:?}"
        );
    }
}
