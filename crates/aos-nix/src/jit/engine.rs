//! Live tier-1 JIT engine driving promotion and dispatch during serial forcing.
//!
//! [`NixJitTier1Engine`] implements [`Tier1Engine`], the hook the tree-walk
//! evaluator consults once per claimed serial force. It owns the JIT policy the
//! oracle cannot (it depends on `ratchet-jit` and `ratchet-runtime-ffi`, which
//! in turn depend on the oracle), so the oracle stays JIT-agnostic and only
//! calls out through the trait.
//!
//! Each consulted force does one of two things:
//!
//! - **Dispatch.** If the forced thunk already has a published
//!   [`OpaqueTier1Slot`], the engine recovers the finalized artifact, passes the
//!   thunk's captured innermost environment frame as the native `env`, and calls
//!   [`run_finalized_native_thunk_call`]. A clean return is handed back as
//!   [`Tier1ForceHook::Dispatched`]; a trap or any error becomes
//!   [`Tier1ForceHook::Deopted`] so the evaluator runs the tree-walk body.
//! - **Promotion.** Otherwise the engine bumps a per-def-site invocation counter
//!   (keyed by the thunk's `(module, root)` IR body). At the threshold it lowers
//!   that body through the tier-1 lowerer; if the shape lowers it compiles,
//!   finalizes, installs, and publishes a slot (reported as
//!   [`Tier1ForceHook::Continued`] with `promoted = true`), and if the shape is
//!   unsupported it blacklists the def-site so it is never retried.
//!
//! Dispatch reads the thunk's innermost captured frame because the tier-1 lowerer
//! resolves `LocalVar { slot }` against the innermost environment frame, exactly
//! as [the tree walk does](ratchet_oracle::eval::TreeWalk); the captured frames
//! are the same `Rc<EvalFrame>` instances the tree-walk body would read, so the
//! native and tree-walk sides observe identical locals.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ratchet_core::{IrId, syntax::Span};
use ratchet_jit::{
    JitCraneliftRegisteredArtifactFinalizationPreflight, JitRuntimeSymbolAddressCandidate,
    jit_cranelift_registered_artifact_finalization_preflight_with_candidates,
    lower_force_aware_tier1_ir_thunk_body_artifact_for_ir,
};
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_oracle::eval::{EvalFrame, EvalNodeRef, OpaqueTier1Slot, Tier1Engine, Tier1ForceHook};
use ratchet_runtime_ffi::run_finalized_native_thunk_call;
use ratchet_value::value::Value;

use crate::jit::{
    NixJitRuntimeSymbolAddressCandidateError, nix_jit_runtime_symbol_address_candidate_preflight,
};

/// The default per-def-site force count at which a thunk body is promoted.
pub const DEFAULT_TIER1_PROMOTION_THRESHOLD: u32 = 8;

/// A live tier-1 JIT engine for the tree-walk evaluator.
///
/// Install one on a [`TreeWalk`] with
/// [`set_tier1_engine`](ratchet_oracle::eval::TreeWalk::set_tier1_engine) after
/// enabling
/// [`jit_tier1_publish_enabled`](ratchet_oracle::eval::TreeWalkOptions::jit_tier1_publish_enabled).
/// The engine holds the registered runtime-symbol address candidates once and
/// keeps per-def-site counters and a blacklist behind a [`RefCell`], since the
/// evaluator consults it through a shared `&self` hook.
pub struct NixJitTier1Engine {
    candidates: Vec<JitRuntimeSymbolAddressCandidate>,
    threshold: u32,
    state: RefCell<EngineState>,
}

/// Mutable per-run promotion bookkeeping guarded by the engine's [`RefCell`].
#[derive(Default)]
struct EngineState {
    /// Force counts keyed by def-site (`(module_index << 32) | root`).
    counts: HashMap<u64, u32>,
    /// Def-sites whose bodies the lowerer rejected; never retried.
    blacklist: HashSet<u64>,
}

impl std::fmt::Debug for NixJitTier1Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NixJitTier1Engine")
            .field("candidate_count", &self.candidates.len())
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

impl NixJitTier1Engine {
    /// Builds a tier-1 engine with the default promotion threshold.
    ///
    /// The engine registers every runtime-symbol address candidate from the
    /// shared preflight so any lowerable body's imports can be finalized.
    ///
    /// # Errors
    ///
    /// Returns [`NixJitRuntimeSymbolAddressCandidateError`] when the runtime
    /// symbol address-candidate preflight cannot be built.
    pub fn new() -> Result<Self, NixJitRuntimeSymbolAddressCandidateError> {
        Self::with_threshold(DEFAULT_TIER1_PROMOTION_THRESHOLD)
    }

    /// Builds a tier-1 engine that promotes a def-site after `threshold` forces.
    ///
    /// A `threshold` of 1 promotes on the first force; larger values defer
    /// promotion until a body proves hot.
    ///
    /// # Errors
    ///
    /// Returns [`NixJitRuntimeSymbolAddressCandidateError`] when the runtime
    /// symbol address-candidate preflight cannot be built.
    pub fn with_threshold(
        threshold: u32,
    ) -> Result<Self, NixJitRuntimeSymbolAddressCandidateError> {
        let preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
        Ok(Self {
            candidates: preflight.address_candidates().to_vec(),
            threshold: threshold.max(1),
            state: RefCell::new(EngineState::default()),
        })
    }

    /// Attempts to dispatch a published tier-1 entry for `thunk`.
    ///
    /// Returns `Some(hook)` when a published slot exists (either a dispatched
    /// value or a deopt), and `None` when no published slot is installed so the
    /// caller should fall through to promotion.
    fn try_dispatch(
        &self,
        eval: &mut TreeWalk,
        thunk: Value,
        id: IrId,
        span: Span,
    ) -> Option<Tier1ForceHook> {
        let key = def_site_key(thunk_body_ref(eval, thunk)?);
        let finalization = published_finalization(eval, key)?;
        let Some(frame) = dispatch_env_frame(eval, thunk) else {
            return Some(Tier1ForceHook::Deopted);
        };
        match run_finalized_native_thunk_call(eval, id, span, &frame, &finalization) {
            Ok(outcome) if !outcome.is_trap() => Some(Tier1ForceHook::Dispatched(outcome.value())),
            _ => Some(Tier1ForceHook::Deopted),
        }
    }

    /// Counts a force of `thunk` and promotes its def-site at the threshold.
    ///
    /// Returns `true` when this call compiled and published a tier-1 entry.
    fn count_and_maybe_promote(&self, eval: &mut TreeWalk, thunk: Value) -> bool {
        let Some(body) = thunk_body_ref(eval, thunk) else {
            return false;
        };
        let key = def_site_key(body);
        {
            let mut state = self.state.borrow_mut();
            if state.blacklist.contains(&key) {
                return false;
            }
            let count = state.counts.entry(key).or_insert(0);
            *count = count.saturating_add(1);
            if *count < self.threshold {
                return false;
            }
        }
        match self.promote(eval, body, key) {
            PromotionResult::Promoted => true,
            PromotionResult::Unsupported => {
                self.state.borrow_mut().blacklist.insert(key);
                false
            }
            PromotionResult::Failed => false,
        }
    }

    /// Lowers, finalizes, installs, and publishes a tier-1 entry for `body`.
    ///
    /// The entry is keyed by `def_site` so every thunk instance of the same IR
    /// body shares it. Installing a def-site entry publishes it unconditionally:
    /// the promoting instance is mid-force (already claimed), and the entry is
    /// valid for all future instances regardless of this one's state.
    fn promote(&self, eval: &mut TreeWalk, body: EvalNodeRef, def_site: u64) -> PromotionResult {
        let Some(artifact) = eval.tier1_module_ir(body.module()).and_then(|ir| {
            lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(ir, body.id()).ok()
        }) else {
            // The IR is missing or the shape is not lowerable today; never retry.
            return PromotionResult::Unsupported;
        };
        let Ok(finalization) =
            jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
                artifact,
                &self.candidates,
            )
        else {
            return PromotionResult::Failed;
        };

        let entry = NixJitTier1DispatchEntry::new(finalization);
        let entry_addr = entry.entry_addr();
        if eval.install_and_publish_tier1_def_site_slot(
            def_site,
            OpaqueTier1Slot::new(entry_addr, Box::new(entry)),
        ) {
            PromotionResult::Promoted
        } else {
            PromotionResult::Failed
        }
    }
}

impl Tier1Engine for NixJitTier1Engine {
    fn on_serial_force(
        &self,
        eval: &mut TreeWalk,
        thunk: Value,
        id: IrId,
        span: Span,
    ) -> Tier1ForceHook {
        if let Some(hook) = self.try_dispatch(eval, thunk, id, span) {
            return hook;
        }
        Tier1ForceHook::Continued {
            promoted: self.count_and_maybe_promote(eval, thunk),
        }
    }
}

/// The outcome of a single promotion attempt.
enum PromotionResult {
    /// A tier-1 entry was compiled, installed, and published.
    Promoted,
    /// The body's shape is not lowerable today; the def-site is blacklisted.
    Unsupported,
    /// Promotion failed for a transient reason (e.g. finalize or publish lost).
    Failed,
}

/// Owns a finalized tier-1 artifact so its native entry stays callable.
///
/// Wrapping the finalization in an [`Rc`] lets the evaluator side-table own the
/// entry type-erased while dispatch clones an independent handle to run the call
/// without aliasing the mutable evaluator borrow.
struct NixJitTier1DispatchEntry {
    finalization: Rc<JitCraneliftRegisteredArtifactFinalizationPreflight>,
}

impl NixJitTier1DispatchEntry {
    /// Wraps a finalized artifact as a shareable tier-1 dispatch entry.
    fn new(finalization: JitCraneliftRegisteredArtifactFinalizationPreflight) -> Self {
        Self {
            finalization: Rc::new(finalization),
        }
    }

    /// Returns the finalized native entry address the dispatcher calls through.
    fn entry_addr(&self) -> usize {
        self.finalization.finalized_function().code_ptr().as_ptr() as usize
    }

    /// Returns an independent shared handle to the finalized artifact.
    fn finalization(&self) -> Rc<JitCraneliftRegisteredArtifactFinalizationPreflight> {
        Rc::clone(&self.finalization)
    }
}

/// Returns the published tier-1 finalization for a def-site key, if any.
fn published_finalization(
    eval: &TreeWalk,
    def_site: u64,
) -> Option<Rc<JitCraneliftRegisteredArtifactFinalizationPreflight>> {
    let slot = eval.tier1_def_site_slot(def_site)?;
    if !slot.is_published() {
        return None;
    }
    let entry = slot.owner().downcast_ref::<NixJitTier1DispatchEntry>()?;
    Some(entry.finalization())
}

/// Returns the environment frame the tier-1 body reads its locals from.
///
/// The tier-1 lowerer resolves `LocalVar { slot }` against the innermost
/// environment frame, so dispatch passes the thunk's captured innermost frame. A
/// body that reads no locals (a constant) ignores the frame; when the capture is
/// empty an owned zero-slot frame is supplied so such bodies can still dispatch.
fn dispatch_env_frame(eval: &TreeWalk, thunk: Value) -> Option<Rc<EvalFrame>> {
    let heap_thunk = eval.heap().get_thunk(thunk).ok()?;
    let env = heap_thunk.env()?;
    match env.frames().last() {
        Some(frame) => Some(Rc::clone(frame)),
        None => EvalFrame::new(0).ok(),
    }
}

/// Returns the `(module, root)` IR body of `thunk`, if it is a lowered node body.
fn thunk_body_ref(eval: &TreeWalk, thunk: Value) -> Option<EvalNodeRef> {
    eval.heap().get_thunk(thunk).ok()?.body_ref()
}

/// Encodes an IR body reference into a stable per-def-site counter key.
fn def_site_key(body: EvalNodeRef) -> u64 {
    ((body.module().index() as u64) << 32) | u64::from(body.id().as_u32())
}

#[cfg(test)]
mod tests {
    use super::*;

    use ratchet_core::Ir;
    use ratchet_oracle::compile::resolve;
    use ratchet_oracle::eval::EvalStats;
    use ratchet_oracle::eval::tree_walk::TreeWalkOptions;
    use ratchet_oracle::syntax::parse_str;

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
            NixJitTier1Engine::with_threshold(threshold).expect("engine builds"),
        ));
        let value = eval.eval_root().expect("jit evaluation succeeds");
        let stats = eval.stats();
        (value, stats)
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
        ];
        for source in sources {
            let oracle = eval_oracle(source);
            for threshold in [1_u32, 8] {
                let (native, _) = eval_with_engine(source, threshold);
                assert!(
                    oracle.raw_eq(native),
                    "engine changed result of `{source}` at threshold {threshold}: \
                     oracle {oracle:?} vs native {native:?}"
                );
            }
        }
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
}
