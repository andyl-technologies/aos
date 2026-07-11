//! Tier-2 fold-operator promotion and dispatch at the strict-fold seam.
//!
//! `builtins.foldl'` applies its operator twice per element through a fresh
//! intermediate closure, so a fold over N elements pays 2N interpreted applies
//! plus N closure allocations even when the operator body is three integer
//! instructions. The apply-seam harness cannot rescue it: its per-dispatch
//! setup (context pin, trap scope, environment clone) costs about a
//! microsecond, which a million-element fold cannot pay per element.
//!
//! This module hooks the **fold loop itself** instead
//! ([`Tier1Engine::on_foldl_strict`]): the operator's curried arity-2 chain is
//! compiled once as a fused native function (see
//! [`ratchet_jit::lower_tier2_curried_chain`]) and the loop's element run is
//! handed to [`run_context_finalized_native_fold_loop`], which pins the
//! context and trap scope **once** and then pays one bare native call per
//! element. The fold loop consults the engine at most twice per fold call —
//! before the first element and once after one interpreted iteration (which
//! forces the operator's callee bindings, letting pinned-callee resolution
//! pass) — so undecided or blacklisted operators cost two hash probes per
//! fold, never per element.
//!
//! # Promotion gate
//!
//! A fold operator is compiled when the remaining element run is at least
//! [`TIER2_FOLD_MIN_ELEMENTS`] long and its chain scans to arity 2 with a
//! call-free-inlinable pinned callee set and **no** self-recursion (a
//! self-recursive operator belongs to the apply seam). Structural failures
//! blacklist the operator's def-site; an unforced callee binding is transient
//! and leaves the def-site undecided for the second consult.
//!
//! # Dispatch guards and deopt
//!
//! Per fold call (not per element!) the engine re-resolves every pinned
//! callee out of the operator's captured environment and compares def-site
//! identity (module, pattern, body) with the pin recorded at promotion — a
//! call-free, environment-free pinned body makes def-site identity behavioral
//! identity — and requires a small `max_call_depth` headroom margin (the
//! native loop skips the interpreter's two apply frames per element, the same
//! shallow-skew discipline the apply-seam boundary accepts). A native run
//! that deopts at element `k` (guard failure or forcing error) reports the
//! elements it consumed; the fold loop re-runs element `k` interpreted, which
//! is sound because the compiled body is pure except for memoizing forces —
//! the re-run observes identical values and reproduces the exact tree-walk
//! result or error.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ratchet_core::{IrId, syntax::Span};
use ratchet_jit::{
    JitModuleContextFinalizedBody, JitModuleContextKeepAlive, JitTier2ChainScan,
    JitTier2EnvBoundary, JitTier2PinnedCallee, lower_tier2_curried_chain, scan_tier2_curried_chain,
    scan_tier2_pinned_callee,
};
use ratchet_oracle::eval::Tier2FoldHook;
use ratchet_oracle::eval::heap::EvalLambda;
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_runtime_ffi::run_context_finalized_native_fold_loop;
use ratchet_value::value::Value;

use super::NixJitTier1Engine;
use super::tier2_chain::{Tier2ChainCacheRole, Tier2PinIdentity, chain_cache_identity};

/// The minimum remaining element run that justifies compiling a fold operator.
///
/// Compilation costs tens of microseconds; a run of this many elements
/// recovers it in the first native pass, and shorter folds simply stay
/// interpreted without deciding the def-site (a later, longer fold of the
/// same operator may still promote it).
pub(super) const TIER2_FOLD_MIN_ELEMENTS: usize = 8;

/// The interpreter call-depth headroom required to enter the native loop.
///
/// A compiled fold operator makes no native self-calls, so no recursion
/// budget is needed; this margin covers the interpreter apply frames the
/// native loop skips per element (the same shallow-skew discipline as the
/// apply-seam boundary, which accepts forces running a few frames shallower
/// than the interpreted call would run them).
pub(super) const TIER2_FOLD_MIN_HEADROOM: usize = 16;

/// Mutable fold-seam bookkeeping, guarded by the engine's `RefCell`.
#[derive(Default)]
pub(super) struct Tier2FoldState {
    /// Compiled fold entries keyed by operator def-site
    /// (`(module_index << 32) | outer_body_ir_id`).
    entries: HashMap<u64, Rc<NixJitTier2FoldEntry>>,
    /// Operator def-sites that can never compile as fold operators.
    blacklist: HashSet<u64>,
}

/// Owns a finalized fold-operator entry so its native code stays callable.
struct NixJitTier2FoldEntry {
    /// The finalized boundary entry (frozen argv lambda-entry ABI, arity 2).
    body: Rc<JitModuleContextFinalizedBody>,
    /// Keeps the shared JIT module (and thus the entry's code) alive.
    _keep_alive: JitModuleContextKeepAlive,
    /// The pinned callees re-validated per fold call.
    pinned: Vec<Tier2PinIdentity>,
}

/// The outcome of preparing a fold-operator promotion.
enum FoldPreparation {
    /// The operator compiled and finalized.
    Ready(Rc<NixJitTier2FoldEntry>),
    /// A callee binding is not forced yet; retry on the next consult.
    Transient,
    /// The operator can never compile as a fold operator.
    Structural,
}

/// The outcome of resolving a fold operator's chain and pinned callees.
///
/// Shared between the plain fold seam and the fused `genList` fold seam
/// (see [`tier2_fold_gen`](super::tier2_fold_gen)); the ready payload feeds
/// either lowering.
pub(super) enum FoldOperatorResolution {
    /// The operator scans to arity 2 with every callee site pinned.
    Ready(Box<ResolvedFoldOperator>),
    /// A callee binding is not forced yet; retry on a later consult.
    Transient,
    /// The operator can never compile as a fold operator.
    Structural,
}

/// A fold operator resolved and validated, pending lowering.
pub(super) struct ResolvedFoldOperator {
    /// The operator's arity-2 chain scan.
    pub(super) scan: JitTier2ChainScan,
    /// The pinned callees' def-site identities re-validated per fold call.
    pub(super) pinned: Vec<Tier2PinIdentity>,
    /// The pinned callees' lowering inputs.
    pub(super) pinned_callees: Vec<JitTier2PinnedCallee>,
}

impl NixJitTier1Engine {
    /// Implements [`Tier1Engine::on_foldl_strict`] for the live engine.
    ///
    /// See the [module docs](self) for the promotion gate and dispatch
    /// guards.
    ///
    /// [`Tier1Engine::on_foldl_strict`]: ratchet_oracle::eval::Tier1Engine::on_foldl_strict
    pub(super) fn on_foldl_strict_impl(
        &self,
        eval: &mut TreeWalk,
        op: Value,
        lambda: &EvalLambda,
        accumulator: Value,
        elements: &[Value],
        id: IrId,
        span: Span,
    ) -> Tier2FoldHook {
        let _ = op;
        if !self.tier2_enabled {
            return fold_continued(false, false);
        }
        let key = fold_def_site_key(lambda);
        let existing = {
            let state = self.tier2_fold.borrow();
            if state.blacklist.contains(&key) {
                return fold_continued(false, false);
            }
            state.entries.get(&key).cloned()
        };
        let (entry, promoted) = match existing {
            Some(entry) => (entry, false),
            None => {
                if elements.len() < TIER2_FOLD_MIN_ELEMENTS {
                    return fold_continued(false, false);
                }
                match self.prepare_tier2_fold(eval, lambda) {
                    FoldPreparation::Ready(entry) => {
                        self.tier2_fold
                            .borrow_mut()
                            .entries
                            .insert(key, Rc::clone(&entry));
                        (entry, true)
                    }
                    FoldPreparation::Transient => return fold_continued(false, false),
                    FoldPreparation::Structural => {
                        self.tier2_fold.borrow_mut().blacklist.insert(key);
                        return fold_continued(false, true);
                    }
                }
            }
        };

        // Per-fold dispatch guards (never per element).
        if !fold_pins_still_valid(eval, lambda, &entry.pinned, 2) {
            return fold_continued(promoted, false);
        }
        if eval.tier2_call_depth_headroom() < TIER2_FOLD_MIN_HEADROOM {
            return fold_continued(promoted, false);
        }

        let env = lambda.env().clone();
        match run_context_finalized_native_fold_loop(
            eval,
            id,
            span,
            &env,
            accumulator,
            elements,
            &entry.body,
        ) {
            Ok(outcome) => Tier2FoldHook::Ran {
                consumed: outcome.consumed(),
                accumulator: outcome.accumulator(),
                deopted: outcome.deopted(),
                promoted,
            },
            Err(_) => fold_continued(promoted, false),
        }
    }

    /// Scans, resolves, lowers, and finalizes one fold operator.
    fn prepare_tier2_fold(&self, eval: &TreeWalk, lambda: &EvalLambda) -> FoldPreparation {
        let resolved = match self.resolve_tier2_fold_operator(eval, lambda) {
            FoldOperatorResolution::Ready(resolved) => resolved,
            FoldOperatorResolution::Transient => return FoldPreparation::Transient,
            FoldOperatorResolution::Structural => return FoldPreparation::Structural,
        };
        let Some(ir) = eval.tier1_module_ir(lambda.module()) else {
            return FoldPreparation::Structural;
        };

        // A fold operator must not self-recurse (`self_upval` is `None`, so
        // any non-pinned callee chain already failed the classification
        // above and the lowering below). The fold seam dispatches with the
        // unapplied operator closure's environment, so env reads translate
        // against `OperatorEnv`.
        let budget = self.tier2.borrow().budget;
        let env_boundary = JitTier2EnvBoundary::OperatorEnv;
        let Some(cache_identity) = chain_cache_identity(
            Tier2ChainCacheRole::Fold,
            lambda.pattern(),
            lambda.body(),
            &resolved.scan,
            None,
            &resolved.pinned,
            &resolved.pinned_callees,
            env_boundary,
            &[],
        ) else {
            return FoldPreparation::Structural;
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
            return FoldPreparation::Structural;
        };
        if !cache_hit && let Some(cache) = self.tier2.borrow().compiled_cache.as_ref() {
            cache.store_chain(ir, &cache_identity, budget, &lowering);
        }
        let Some((finalized_body, keep_alive)) = self.finalize_tier2_chain(lowering) else {
            return FoldPreparation::Structural;
        };
        FoldPreparation::Ready(Rc::new(NixJitTier2FoldEntry {
            body: Rc::new(finalized_body),
            _keep_alive: keep_alive,
            pinned: resolved.pinned,
        }))
    }

    /// Resolves one fold operator's chain scan and pinned callees.
    ///
    /// Shared by the plain fold promotion above and the fused `genList`
    /// promotion (see [`tier2_fold_gen`](super::tier2_fold_gen)).
    pub(super) fn resolve_tier2_fold_operator(
        &self,
        eval: &TreeWalk,
        lambda: &EvalLambda,
    ) -> FoldOperatorResolution {
        let Some(ir) = eval.tier1_module_ir(lambda.module()) else {
            return FoldOperatorResolution::Structural;
        };
        let arena = &ir.arena;
        let Ok(scan) = scan_tier2_curried_chain(arena, &ir.bindings, lambda.pattern(), lambda.body())
        else {
            return FoldOperatorResolution::Structural;
        };
        // The fold loop applies exactly two arguments per element.
        if scan.arity() != 2 {
            return FoldOperatorResolution::Structural;
        }
        self.resolve_scanned_operator_callees(eval, lambda, scan)
    }

    /// Resolves a scanned operator's callee sites into pinned callees.
    ///
    /// Every callee site must resolve to a pinned call-free callee out of
    /// the operator's captured environment. Site coordinates are relative to
    /// the inner-body environment (`op.env ++ K-1 parameter frames ++ call
    /// frame` for a chain of arity K); a site depth of at least the arity
    /// (guaranteed by the scan) always lands inside `op.env`, at boundary
    /// frame index `op_frames.len() + K - 1 - depth`. Shared by the fold
    /// seam (K = 2) and the filter seam (K = 1, see
    /// [`tier2_filter`](super::tier2_filter)).
    pub(super) fn resolve_scanned_operator_callees(
        &self,
        eval: &TreeWalk,
        lambda: &EvalLambda,
        scan: JitTier2ChainScan,
    ) -> FoldOperatorResolution {
        let Some(ir) = eval.tier1_module_ir(lambda.module()) else {
            return FoldOperatorResolution::Structural;
        };
        let arena = &ir.arena;
        let arity = scan.arity() as usize;
        let conceptual_len = lambda.env().frame_count() + arity - 1;
        let mut pinned = Vec::new();
        let mut pinned_callees = Vec::new();
        for site in scan.callee_sites() {
            let (depth, slot) = site.upval;
            if depth as usize > conceptual_len || (depth as usize) < arity {
                return FoldOperatorResolution::Structural;
            }
            let index = conceptual_len - depth as usize;
            let Some(raw) = eval.tier2_captured_value_at_index(lambda.env(), index, slot) else {
                return FoldOperatorResolution::Structural;
            };
            let Some(resolved) = eval.tier2_peek_forced(raw) else {
                return FoldOperatorResolution::Transient;
            };
            let Some(pin_lambda) = eval.tier2_clone_lambda(resolved) else {
                return FoldOperatorResolution::Structural;
            };
            if pin_lambda.module() != lambda.module() {
                return FoldOperatorResolution::Structural;
            }
            let Ok(callee_body) = scan_tier2_pinned_callee(
                arena,
                pin_lambda.pattern(),
                pin_lambda.body(),
                site.arity,
            ) else {
                return FoldOperatorResolution::Structural;
            };
            pinned.push(Tier2PinIdentity {
                upval: site.upval,
                pattern: pin_lambda.pattern(),
                body: pin_lambda.body(),
            });
            pinned_callees.push(JitTier2PinnedCallee {
                upval: site.upval,
                arity: site.arity,
                body: callee_body,
            });
        }

        FoldOperatorResolution::Ready(Box::new(ResolvedFoldOperator {
            scan,
            pinned,
            pinned_callees,
        }))
    }
}

/// Encodes a fold operator's def-site key.
///
/// Keyed by the operator's **outer** lambda body node (the inner lambda of
/// the curried chain), so every closure instance of the same source operator
/// shares one compiled entry and one decision. Distinct from the apply-seam
/// keys, which use the innermost body node.
pub(super) fn fold_def_site_key(lambda: &EvalLambda) -> u64 {
    ((lambda.module().index() as u64) << 32) | u64::from(lambda.body().as_u32())
}

/// Re-validates every pinned callee for one fold or filter call.
///
/// Resolves each pin out of the operator instance's captured environment —
/// at the boundary frame index `op_frames.len() + arity - 1 - depth`, the
/// same coordinate translation as
/// [`resolve_scanned_operator_callees`](NixJitTier1Engine::resolve_scanned_operator_callees)
/// — and compares def-site identity with the pin recorded at promotion. Pins
/// may fail transiently for a *different* operator instance whose bindings
/// are not forced yet; the loop then stays interpreted for that call only.
pub(super) fn fold_pins_still_valid(
    eval: &TreeWalk,
    lambda: &EvalLambda,
    pinned: &[Tier2PinIdentity],
    arity: usize,
) -> bool {
    let conceptual_len = lambda.env().frame_count() + arity - 1;
    for pin in pinned {
        let (depth, slot) = pin.upval;
        if depth as usize > conceptual_len || (depth as usize) < arity {
            return false;
        }
        let Some(raw) = eval.tier2_captured_value_at_index(
            lambda.env(),
            conceptual_len - depth as usize,
            slot,
        ) else {
            return false;
        };
        let Some(resolved) = eval.tier2_peek_forced(raw) else {
            return false;
        };
        let Some(pin_lambda) = eval.tier2_clone_lambda(resolved) else {
            return false;
        };
        if pin_lambda.module() != lambda.module()
            || pin_lambda.pattern() != pin.pattern
            || pin_lambda.body() != pin.body
        {
            return false;
        }
    }
    true
}

/// A `Continued` fold hook with the given promotion/blacklist flags.
const fn fold_continued(promoted: bool, blacklisted: bool) -> Tier2FoldHook {
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

    /// The canonical sum-fold operator — with its truncating-modulus helper as
    /// a pinned inlined callee — folds natively and matches the oracle with
    /// zero deopts.
    #[test]
    fn sum_fold_operator_with_pinned_callee_folds_natively() {
        let source = "let mod = a: b: a - b * (a / b); in \
             builtins.foldl' (acc: i: mod (acc + i * i + 2654435761) 1000000007) 0 \
             (builtins.genList (i: i) 500)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "fold seam changed sum-fold: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_promoted() >= 1,
            "the fold operator must promote, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the fold must run natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer fold must never deopt, got {stats:?}"
        );
    }

    /// A plain arithmetic fold operator (no pinned callees) folds natively.
    #[test]
    fn plain_arithmetic_fold_operator_folds_natively() {
        let source = "builtins.foldl' (a: b: a + b) 0 (builtins.genList (i: i * 2) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native), "fold seam changed a plain sum");
        assert!(
            stats.tier2_dispatched() >= 1,
            "the plain sum must run natively, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// A float element mid-run deopts the native loop at that element; the
    /// interpreted resume reproduces the oracle's exact value.
    #[test]
    fn float_element_deopts_mid_run_and_matches_the_oracle() {
        let source = "builtins.foldl' (a: b: a + b) 0 \
             (builtins.genList (i: if i == 40 then 0.5 else i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "fold deopt changed a result: oracle {oracle:?} vs native {native:?}"
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

    /// A division by zero inside the compiled operator deopts and the
    /// interpreted re-run reproduces the oracle's error exactly.
    #[test]
    fn fold_operator_division_by_zero_reproduces_the_oracle_error() {
        let source = "builtins.foldl' (a: b: a + 1 / (b - 40)) 0 (builtins.genList (i: i) 64)";
        let ir = lower(source);
        let oracle = TreeWalk::new(&ir).eval_root();
        let (native, _stats) = eval_with_tier2_result(source);

        assert!(oracle.is_err(), "the fixture must divide by zero");
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "a compiled fold division-by-zero must reproduce the oracle error"
        );
    }

    /// A fold shorter than the promotion floor stays interpreted and leaves
    /// the def-site undecided.
    #[test]
    fn short_folds_stay_interpreted_without_deciding() {
        let source = "builtins.foldl' (a: b: a + b) 0 (builtins.genList (i: i) 4)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert_eq!(stats.tier2_promoted(), 0, "got {stats:?}");
        assert_eq!(stats.tier2_dispatched(), 0, "got {stats:?}");
    }

    /// A fold operator with a `let`-bound intermediate compiles: the binding
    /// becomes a virtual register and the fused genList loop still fires
    /// (the improved sum-fold shape), matching the oracle with zero deopts.
    #[test]
    fn let_bound_intermediate_fold_operator_folds_natively() {
        let source = "builtins.foldl'              (acc: i: let m = acc + i * i + 2654435761;               in m - 1000000007 * (m / 1000000007)) 0              (builtins.genList (i: i) 500)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "let-local fold changed sum-fold: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_promoted() >= 1,
            "the let-local operator must promote, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the let-local fold must run natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer let-local fold must never deopt, got {stats:?}"
        );
    }

    /// Nested dependent lets compile: an inner binding may read an outer
    /// one, and both become virtual registers.
    #[test]
    fn nested_dependent_lets_fold_natively() {
        let source = "builtins.foldl'              (acc: i: let a = acc + i; in let b = a * 3; in b + a) 0              (builtins.genList (i: i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native), "nested-let fold changed a result");
        assert!(
            stats.tier2_dispatched() >= 1,
            "the nested-let fold must run natively, got {stats:?}"
        );
        assert_eq!(stats.tier2_deopted(), 0, "got {stats:?}");
    }

    /// A binding never demanded on the taken path is never computed: its
    /// value would divide by zero on every element, yet the native loop
    /// must match the lazy interpreter with zero deopts.
    #[test]
    fn undemanded_let_binding_is_never_computed() {
        let source = "builtins.foldl'              (acc: i: let d = 1 / (i - i); in if i < 1000 then acc + i else d) 0              (builtins.genList (i: i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "compute-at-first-use changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the guarded fold must run natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an undemanded binding must never be computed (or deopt), got {stats:?}"
        );
    }

    /// A `letrec` self-reference (own-frame read) blacklists the operator;
    /// the interpreted result is unchanged.
    #[test]
    fn letrec_self_reference_blacklists_the_operator() {
        let source = "builtins.foldl'              (acc: i: let a = 1; b = a + i; in acc + b) 0              (builtins.genList (i: i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native), "letrec blacklist changed a result");
        assert!(
            stats.tier2_blacklisted() >= 1,
            "a same-frame sibling read must blacklist, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "a blacklisted operator never dispatches, got {stats:?}"
        );
    }

    /// The first-class (value-path) foldl' loop reaches the fold seam too.
    #[test]
    fn first_class_foldl_reaches_the_fold_seam() {
        let source = "let fold = builtins.foldl'; in \
             fold (a: b: a + b) 0 (builtins.genList (i: i) 64)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(
            stats.tier2_dispatched() >= 1,
            "the value-path fold must run natively, got {stats:?}"
        );
    }
}
