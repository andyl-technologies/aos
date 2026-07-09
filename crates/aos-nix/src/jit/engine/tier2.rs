//! Tier-2 lambda promotion and dispatch for the live JIT engine.
//!
//! Tier-1 (the [`super`] module) promotes thunk bodies at the force seam and
//! is capped at neutral: every lowerable thunk shape is smaller than the
//! per-dispatch harness. Tier-2 promotes *lambda def-sites* at the apply seam
//! and compiles whole self-recursive arithmetic bodies (see
//! [`ratchet_jit::lower_tier2_self_recursive_lambda`]), so one dispatch
//! harness covers an entire native recursion tree — the shape where compiled
//! code beats the tree walk outright.
//!
//! # Promotion gate (honest by default)
//!
//! Unlike tier-1 — whose default gate promotes nothing — tier-2 promotion is
//! on whenever the engine is installed (`AOS_NIX_JIT=1`), because its gate
//! only admits bodies that win by construction. A lambda def-site is promoted
//! when all of the following hold:
//!
//! 1. its apply count crossed [`TIER2_PROMOTION_THRESHOLD`],
//! 2. its body lowers under the tier-2 grammar (anything else blacklists),
//! 3. the body contains at least one direct self-call — the recursion is what
//!    amortizes the boundary harness — and
//! 4. the compiled body's native instruction count clears
//!    [`TIER2_MIN_NATIVE_INSTS`], so the native win is not a trampoline.
//!
//! Package-eval workloads are untouched by construction: their lambdas either
//! have no self-call or fall outside the arithmetic grammar, so every def-site
//! decides to `gated`/`blacklisted` once and the apply path's skip set drops
//! the hook thereafter. `AOS_NIX_JIT_TIER2=0` disables the tier entirely for
//! A/B measurement.
//!
//! # Dispatch guards
//!
//! A published entry dispatches a boundary application only when:
//!
//! - the recorded self-callee upvalue, resolved against the applied closure's
//!   captured environment, is (or is a thunk already forced to) *the applied
//!   closure itself* — the guard that makes the compiled direct self-call
//!   exactly the call the interpreter would perform; and
//! - the interpreter's remaining `max_call_depth` headroom covers the whole
//!   native depth budget, so a natively-completed recursion is one the
//!   interpreter would also have completed (a deeper one deopts and re-runs
//!   interpreted, reproducing the interpreter's own behavior).
//!
//! A failed guard is transient (the self-binding thunk may simply not be
//! forced yet), so it falls through to the interpreted call without gating.
//! Any trap out of the native call — evaluator error during a parameter
//! force, tag-guard deopt, exhausted budget — reports
//! [`Tier2ApplyHook::Deopted`] and the interpreted call re-runs the body;
//! tier-2 bodies are pure apart from the memoizing parameter force, so
//! re-execution reproduces the exact tree-walk result or error.
//!
//! No garbage-collection hazard exists across the native call: the precise
//! sweep only runs at quiescent points (no in-flight force, zero call depth),
//! and native code allocates nothing itself — any allocation happens inside a
//! nested interpreter force, which is never quiescent.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ratchet_core::{IrData, IrId, IrKind, syntax::Span};
use ratchet_jit::{
    JitModuleContext, JitModuleContextFinalizedBody, JitModuleContextKeepAlive,
    TIER2_NATIVE_DEPTH_BUDGET, estimate_tier1_body_cost, lower_tier2_self_recursive_lambda,
};
use ratchet_oracle::eval::heap::EvalLambda;
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_oracle::eval::{OpaqueTier1Slot, Tier2ApplyHook};
use ratchet_runtime_ffi::run_context_finalized_native_lambda_call;
use ratchet_value::value::Value;

use super::NixJitTier1Engine;

/// The apply count at which a lambda def-site is considered for promotion.
pub(super) const TIER2_PROMOTION_THRESHOLD: u32 = 8;

/// The minimum native instruction count a compiled body must clear.
///
/// A self-recursive body below this bound does too little inline work per
/// frame for the native transition to be worth compiling; the canonical `fib`
/// body sits far above it.
pub(super) const TIER2_MIN_NATIVE_INSTS: u32 = 16;

/// Mutable tier-2 promotion bookkeeping, guarded by the engine's `RefCell`.
pub(super) struct Tier2EngineState {
    /// Apply counts keyed by def-site (`(module_index << 32) | body_ir_id`).
    counts: HashMap<u64, u32>,
    /// Def-sites whose bodies failed the tier-2 gate or lowering; never retried.
    blacklist: HashSet<u64>,
    /// Count of declined def-sites keyed by a body-kind signature (diagnostics).
    gated_kinds: HashMap<String, u32>,
    /// The native self-call depth budget compiled into each entry.
    ///
    /// [`TIER2_NATIVE_DEPTH_BUDGET`] in production; tests shrink it so a
    /// budget-exhaustion deopt can be exercised at interpreter-safe depths.
    budget: i64,
}

impl Default for Tier2EngineState {
    fn default() -> Self {
        Self {
            counts: HashMap::new(),
            blacklist: HashSet::new(),
            gated_kinds: HashMap::new(),
            budget: TIER2_NATIVE_DEPTH_BUDGET,
        }
    }
}

/// Owns a finalized tier-2 lambda entry so its native code stays callable.
///
/// Stored type-erased in the evaluator's tier-2 def-site side-table and
/// downcast back at dispatch. Carries the self-callee upvalue coordinates the
/// dispatcher guards on.
struct NixJitTier2DispatchEntry {
    body: Rc<JitModuleContextFinalizedBody>,
    _keep_alive: JitModuleContextKeepAlive,
    /// Body-relative `(depth, slot)` of the self-callee upvalue.
    self_upval: (u32, u32),
}

impl NixJitTier2DispatchEntry {
    fn entry_addr(&self) -> usize {
        self.body.finalized_function().code_ptr().as_ptr() as usize
    }
}

impl NixJitTier1Engine {
    /// Implements [`Tier1Engine::on_lambda_apply`] for the live engine.
    ///
    /// See the [module docs](self) for the promotion gate and dispatch guards.
    ///
    /// [`Tier1Engine::on_lambda_apply`]: ratchet_oracle::eval::Tier1Engine::on_lambda_apply
    pub(super) fn on_lambda_apply_impl(
        &self,
        eval: &mut TreeWalk,
        function: Value,
        lambda: &EvalLambda,
        argument: Value,
        id: IrId,
        span: Span,
    ) -> Tier2ApplyHook {
        if !self.tier2_enabled {
            return gated();
        }
        let key = tier2_def_site_key(lambda);
        if let Some(hook) = self.try_tier2_dispatch(eval, key, function, lambda, argument, id, span)
        {
            return hook;
        }
        self.count_and_maybe_promote_tier2(eval, key, function, lambda)
    }

    /// Attempts to dispatch a published tier-2 entry for this application.
    ///
    /// Returns `None` when no entry is published (the caller falls through to
    /// counting/promotion) and `Some` with the dispatch outcome otherwise. A
    /// failed dispatch guard reports a non-gating `Continued`, since the guard
    /// may pass on a later application.
    fn try_tier2_dispatch(
        &self,
        eval: &mut TreeWalk,
        key: u64,
        function: Value,
        lambda: &EvalLambda,
        argument: Value,
        id: IrId,
        span: Span,
    ) -> Option<Tier2ApplyHook> {
        let (body, self_upval) = {
            let slot = eval.tier2_def_site_slot(key)?;
            if !slot.is_published() {
                return None;
            }
            let entry = slot.owner().downcast_ref::<NixJitTier2DispatchEntry>()?;
            (Rc::clone(&entry.body), entry.self_upval)
        };

        // Guard: the body's self-callee must resolve to the applied closure
        // itself, and the interpreter must have headroom for the full native
        // depth budget.
        if !self_callee_is_this_closure(eval, function, lambda, self_upval) {
            return Some(continued(false, false, false));
        }
        let budget = self.tier2.borrow().budget;
        if (eval.tier2_call_depth_headroom() as i64) < budget {
            return Some(continued(false, false, false));
        }

        // The dispatcher owns an environment clone for the duration of the
        // call; the native body itself reads no environment today, but the
        // frozen ABI carries it for the grammar's future upvalue reads.
        let env = lambda.env().clone();
        match run_context_finalized_native_lambda_call(eval, id, span, &env, argument, &body) {
            Ok(outcome) if !outcome.is_trap() => Some(Tier2ApplyHook::Dispatched(outcome.value())),
            _ => Some(Tier2ApplyHook::Deopted),
        }
    }

    /// Counts one application and promotes the def-site at the threshold.
    fn count_and_maybe_promote_tier2(
        &self,
        eval: &mut TreeWalk,
        key: u64,
        function: Value,
        lambda: &EvalLambda,
    ) -> Tier2ApplyHook {
        {
            let mut state = self.tier2.borrow_mut();
            if state.blacklist.contains(&key) {
                return gated();
            }
            let count = state.counts.entry(key).or_insert(0);
            *count = count.saturating_add(1);
            if *count < TIER2_PROMOTION_THRESHOLD {
                return continued(false, false, false);
            }
        }

        let budget = self.tier2.borrow().budget;
        let Some(lowering) = self.lower_tier2_body(eval, lambda, budget) else {
            return self.blacklist_tier2(eval, key, lambda);
        };
        // Only a self-recursive body amortizes the boundary harness, and only
        // a body with real inline compute beats the transition cost.
        if lowering.self_call_count() == 0
            || !estimate_tier1_body_cost(lowering.inner()).is_profitable(TIER2_MIN_NATIVE_INSTS)
        {
            return self.blacklist_tier2(eval, key, lambda);
        }
        // The dispatch guard requires the self-callee binding to already be
        // this closure; verify once at promotion so a def-site whose binding
        // can never match (e.g. a rebound alias) is not compiled at all. The
        // failure is transient (the binding may simply not be forced yet), so
        // the count resets rather than blacklisting -- the def-site re-lowers
        // at most once per threshold's worth of applications.
        let self_upval = lowering.self_upval();
        if !self_callee_is_this_closure(eval, function, lambda, self_upval) {
            self.tier2.borrow_mut().counts.insert(key, 0);
            return continued(false, false, false);
        }

        let (finalized_body, keep_alive) = {
            let mut context_slot = self.context.borrow_mut();
            if context_slot.is_none() {
                match JitModuleContext::with_candidates(&self.candidates) {
                    Ok(context) => *context_slot = Some(context),
                    Err(_) => {
                        self.tier2.borrow_mut().counts.insert(key, 0);
                        return continued(false, false, false);
                    }
                }
            }
            let Some(context) = context_slot.as_ref() else {
                self.tier2.borrow_mut().counts.insert(key, 0);
                return continued(false, false, false);
            };
            match context.define_and_finalize_tier2_lambda(lowering) {
                Ok(finalized_body) => (finalized_body, context.keep_alive()),
                Err(_) => {
                    self.tier2.borrow_mut().counts.insert(key, 0);
                    return continued(false, false, false);
                }
            }
        };

        let entry = NixJitTier2DispatchEntry {
            body: Rc::new(finalized_body),
            _keep_alive: keep_alive,
            self_upval,
        };
        let entry_addr = entry.entry_addr();
        if eval.install_and_publish_tier2_def_site_slot(
            key,
            OpaqueTier1Slot::new(entry_addr, Box::new(entry)),
        ) {
            continued(true, false, false)
        } else {
            continued(false, false, false)
        }
    }

    /// Lowers a lambda's body under the tier-2 grammar, if possible.
    fn lower_tier2_body(
        &self,
        eval: &TreeWalk,
        lambda: &EvalLambda,
        budget: i64,
    ) -> Option<ratchet_jit::JitTier2LambdaLowering> {
        let ir = eval.tier1_module_ir(lambda.module())?;
        lower_tier2_self_recursive_lambda(&ir.arena, lambda.pattern(), lambda.body(), budget).ok()
    }

    /// Blacklists a def-site whose body failed the tier-2 gate or lowering.
    fn blacklist_tier2(&self, eval: &TreeWalk, key: u64, lambda: &EvalLambda) -> Tier2ApplyHook {
        let kind = tier2_body_kind_signature(eval, lambda);
        let mut state = self.tier2.borrow_mut();
        state.blacklist.insert(key);
        *state.gated_kinds.entry(kind).or_insert(0) += 1;
        continued(false, true, true)
    }

    /// Returns the tier-2 declined-def-site histogram, most frequent first.
    ///
    /// Each entry pairs a lambda body-kind signature with the number of
    /// def-sites the tier-2 gate declined (unsupported shape, no self-call, or
    /// insufficient native compute). Ties break by signature for determinism.
    pub fn tier2_gated_histogram(&self) -> Vec<(String, u32)> {
        let mut entries: Vec<(String, u32)> = self
            .tier2
            .borrow()
            .gated_kinds
            .iter()
            .map(|(kind, count)| (kind.clone(), *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }
}

/// Encodes a lambda closure's def-site counter key.
///
/// Keyed by the lambda *body* node so every closure instance of the same
/// source lambda shares one counter, entry, and decision.
fn tier2_def_site_key(lambda: &EvalLambda) -> u64 {
    ((lambda.module().index() as u64) << 32) | u64::from(lambda.body().as_u32())
}

/// Returns true when the body's self-callee upvalue is the applied closure.
///
/// Resolves the body-relative `(depth, slot)` against the closure's captured
/// frames (`captured_len - depth`) and peeks through an already-forced thunk
/// without forcing anything (an unforced binding simply fails the guard). The
/// comparison is representation-level identity: the exact closure value the
/// interpreter's own callee lookup would produce.
fn self_callee_is_this_closure(
    eval: &TreeWalk,
    function: Value,
    lambda: &EvalLambda,
    self_upval: (u32, u32),
) -> bool {
    let (depth, slot) = self_upval;
    let frames = lambda.env().frames();
    let captured_len = frames.len();
    if depth == 0 || (depth as usize) > captured_len {
        return false;
    }
    let index = captured_len - depth as usize;
    let Some(frame) = frames.get(index) else {
        return false;
    };
    let Ok(raw) = frame.get(slot) else {
        return false;
    };
    let Some(resolved) = eval.tier2_peek_forced(raw) else {
        return false;
    };
    resolved.raw_eq(function)
}

/// Returns a diagnostic body-kind signature for a declined lambda def-site.
fn tier2_body_kind_signature(eval: &TreeWalk, lambda: &EvalLambda) -> String {
    let Some(ir) = eval.tier1_module_ir(lambda.module()) else {
        return "unknown".to_owned();
    };
    let Some(node) = ir.arena.node(lambda.body()).copied() else {
        return "unknown".to_owned();
    };
    match (node.kind, node.data) {
        (IrKind::BinOp, IrData::Binary { op, .. }) => format!("Lambda>BinOp:{op:?}"),
        (kind, _) => format!("Lambda>{kind:?}"),
    }
}

/// A `Continued` hook with the given promotion/blacklist/gate flags.
const fn continued(promoted: bool, blacklisted: bool, gated: bool) -> Tier2ApplyHook {
    Tier2ApplyHook::Continued {
        promoted,
        blacklisted,
        gated,
    }
}

/// A permanently gated `Continued` hook.
const fn gated() -> Tier2ApplyHook {
    continued(false, false, true)
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
        eval_with_tier2_result_and_options(source, TreeWalkOptions::default())
    }

    /// Evaluates `source` with a default engine over caller-supplied options.
    fn eval_with_tier2_result_and_options(
        source: &str,
        mut options: TreeWalkOptions,
    ) -> (Result<Value, TreeWalkError>, EvalStats) {
        let ir = lower(source);
        options.set_jit_tier1_publish_enabled(true);
        let mut eval = TreeWalk::with_options(&ir, options);
        eval.set_tier1_engine(Rc::new(
            NixJitTier1Engine::new().expect("engine builds"),
        ));
        let result = eval.eval_root();
        let stats = eval.stats();
        (result, stats)
    }

    /// The canonical self-recursive fib promotes, dispatches natively, and
    /// matches the oracle exactly with zero deopts.
    #[test]
    fn fib_promotes_dispatches_and_matches_the_oracle() {
        let source =
            "let fib = n: if n < 2 then n else fib (n - 1) + fib (n - 2); in fib 20";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "tier-2 changed fib: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_promoted() >= 1,
            "fib's def-site must promote, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "fib must dispatch natively, got promoted={} dispatched={} deopted={}",
            stats.tier2_promoted(),
            stats.tier2_dispatched(),
            stats.tier2_deopted(),
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer fib must never deopt, got deopted={}",
            stats.tier2_deopted(),
        );
    }

    /// Compiled arithmetic wraps on i64 overflow exactly like the tree walk
    /// (the pinned C++ Nix 2.24 semantics), across the wrap boundary in both
    /// directions and through the multiply path.
    #[test]
    fn compiled_arithmetic_wraps_exactly_like_the_oracle() {
        let sources = [
            // Addition wraps past i64::MAX inside a hot recursive body.
            "let f = n: if n < 1 then 9223372036854775807 + n + 3 \
             else f (n - 1) + 0; in f 16",
            // Subtraction wraps past i64::MIN.
            "let f = n: if n < 1 then (0 - 9223372036854775807) - n - 5 \
             else f (n - 1) + 0; in f 16",
            // Multiplication wraps.
            "let f = n: if n < 1 then 9223372036854775807 * 3 \
             else f (n - 1) + 0; in f 16",
        ];
        for source in sources {
            let oracle = eval_oracle(source);
            let (native, stats) = eval_with_tier2(source);
            assert!(
                oracle.raw_eq(native),
                "wrap semantics diverged for `{source}`: oracle {oracle:?} vs native {native:?}"
            );
            assert!(
                stats.tier2_dispatched() >= 1,
                "the wrap fixture must actually dispatch, got {stats:?}"
            );
        }
    }

    /// A float argument at the boundary fails the integer guard, deopts, and
    /// the interpreted re-run produces the oracle's exact value.
    #[test]
    fn float_boundary_argument_deopts_to_the_tree_walk() {
        let source = "let f = n: if n < 2 then n else f (n - 1) + f (n - 2); \
             in f 15 + builtins.floor (f 2.5)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "float deopt changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the integer calls must dispatch, got {stats:?}"
        );
        assert!(
            stats.tier2_deopted() >= 1,
            "the float boundary call must deopt, got deopted={}",
            stats.tier2_deopted(),
        );
    }

    /// A linear recursion deeper than the native budget deopts at the depth
    /// guard and the interpreted re-run still produces the oracle's value.
    ///
    /// Uses a test-shrunk budget so the interpreted re-run stays at a depth
    /// the debug-build test-thread stack can interpret.
    #[test]
    fn deeper_than_budget_recursion_deopts_and_matches_the_oracle() {
        let source = "let f = n: if n < 1 then 0 else n + f (n - 1); in f 24";
        let oracle = eval_oracle(source);

        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_jit_tier1_publish_enabled(true);
        let mut eval = TreeWalk::with_options(&ir, options);
        let engine = NixJitTier1Engine::new().expect("engine builds");
        engine.tier2.borrow_mut().budget = 8;
        eval.set_tier1_engine(Rc::new(engine));
        let native = eval.eval_root().expect("tier-2 evaluation succeeds");
        let stats = eval.stats();

        assert!(
            oracle.raw_eq(native),
            "depth deopt changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_deopted() >= 1,
            "the over-budget recursion must deopt at the depth guard, got {stats:?}"
        );
    }

    /// With no interpreter headroom for the native budget, tier-2 refuses to
    /// dispatch and the interpreter's own max-call-depth error is reproduced
    /// byte-for-byte.
    #[test]
    fn exhausted_call_depth_reproduces_the_oracle_error() {
        // max_call_depth 20 is far below the production native budget (1024),
        // so the headroom guard refuses every dispatch and the interpreter's
        // own depth error surfaces identically with and without the engine.
        let source = "let f = n: if n < 1 then 0 else n + f (n - 1); in f 60";
        let options = TreeWalkOptions::with_max_call_depth(20);
        let ir = lower(source);
        let oracle = TreeWalk::with_options(&ir, options.clone()).eval_root();
        let (native, stats) = eval_with_tier2_result_and_options(source, options);

        assert!(
            oracle.is_err(),
            "the fixture must exceed the interpreter call depth, got {oracle:?}"
        );
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "tier-2 must reproduce the interpreter's depth error exactly"
        );
        assert_eq!(
            stats.tier2_dispatched(),
            0,
            "no dispatch may happen without native-budget headroom, got {stats:?}"
        );
    }

    /// Division inside a compiled body guards the zero divisor: the deopted
    /// re-run reproduces the oracle's division-by-zero error exactly.
    #[test]
    fn compiled_division_by_zero_reproduces_the_oracle_error() {
        let source =
            "let f = n: if n < 1 then 1 / n else f (n - 1); in f 16";
        let ir = lower(source);
        let oracle = TreeWalk::new(&ir).eval_root();
        let (native, _stats) = eval_with_tier2_result(source);

        assert!(
            oracle.is_err(),
            "the fixture must divide by zero, got {oracle:?}"
        );
        assert_eq!(
            format!("{native:?}"),
            format!("{oracle:?}"),
            "a compiled division-by-zero must reproduce the oracle error"
        );
    }

    /// Non-recursive or non-arithmetic lambdas are declined once and never
    /// dispatched, leaving results untouched.
    #[test]
    fn non_recursive_lambdas_are_declined_and_unchanged() {
        let sources = [
            // No self-call: the map body is arithmetic but not recursive.
            "builtins.foldl' (a: b: a + b) 0 (builtins.genList (i: i * 2) 64)",
            // Outside the grammar: list construction in a recursive body.
            "let f = n: if n < 1 then [ ] else [ n ] ++ f (n - 1); \
             in builtins.length (f 12)",
        ];
        for source in sources {
            let oracle = eval_oracle(source);
            let (native, stats) = eval_with_tier2(source);
            assert!(
                oracle.raw_eq(native),
                "declining changed a result for `{source}`"
            );
            assert_eq!(
                stats.tier2_dispatched(),
                0,
                "a declined def-site must never dispatch for `{source}`, got {stats:?}"
            );
        }
    }

    /// `AOS_NIX_JIT_TIER2=0` (modeled by the disabled flag) gates the seam
    /// entirely: nothing promotes and results are unchanged.
    #[test]
    fn disabled_tier2_promotes_nothing() {
        let source =
            "let fib = n: if n < 2 then n else fib (n - 1) + fib (n - 2); in fib 16";
        let oracle = eval_oracle(source);
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_jit_tier1_publish_enabled(true);
        let mut eval = TreeWalk::with_options(&ir, options);
        let mut engine = NixJitTier1Engine::new().expect("engine builds");
        engine.tier2_enabled = false;
        eval.set_tier1_engine(Rc::new(engine));
        let native = eval.eval_root().expect("evaluation succeeds");
        let stats = eval.stats();

        assert!(oracle.raw_eq(native));
        assert_eq!(stats.tier2_promoted(), 0);
        assert_eq!(stats.tier2_dispatched(), 0);
    }
}
