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

use ratchet_core::{IrData, IrId, IrKind, syntax::Span};
use ratchet_jit::{
    JitCraneliftRegisteredArtifactFinalizationPreflight, JitRuntimeSymbolAddressCandidate,
    jit_cranelift_registered_artifact_finalization_preflight_with_candidates,
    lower_force_aware_tier1_ir_thunk_body_artifact_for_ir_in_module,
};
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_oracle::eval::{EvalEnv, EvalNodeRef, OpaqueTier1Slot, Tier1Engine, Tier1ForceHook};
use ratchet_runtime_ffi::run_finalized_native_thunk_call;
use ratchet_value::value::Value;

use crate::jit::{
    NixJitRuntimeSymbolAddressCandidateError, nix_jit_deopt_address_candidate,
    nix_jit_primop_call_address_candidate, nix_jit_runtime_symbol_address_candidate_preflight,
    nix_jit_upval_get_address_candidate,
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
    /// Count of newly blacklisted def-sites keyed by their body-kind signature.
    ///
    /// This is a diagnostic breakdown of the blacklist by IR shape (e.g.
    /// `"AttrSet"`, `"BinOp:Concat"`, `"Apply"`) so a run can report which shape
    /// families dominate the unsupported def-sites and thus where extending the
    /// tier-1 lowerer would convert the most blacklists into dispatch.
    blacklist_kinds: HashMap<String, u32>,
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
        // `aos_deopt` is a JIT-internal deopt trampoline, not an oracle helper, so
        // it is registered directly rather than through the oracle-driven preflight.
        let mut candidates = preflight.address_candidates().to_vec();
        candidates.push(nix_jit_deopt_address_candidate()?);
        // `aos_upval_get` is a JIT/runtime-FFI standalone upvalue-read wrapper, not
        // an oracle-modeled env-access helper, so it is registered directly like
        // `aos_deopt` rather than through the oracle-driven preflight.
        candidates.push(nix_jit_upval_get_address_candidate()?);
        // `aos_primop_call` is a JIT/runtime-FFI standalone primop-dispatch
        // trampoline that re-enters the tree walk, so it is registered directly
        // like `aos_deopt` rather than through the oracle-driven preflight.
        candidates.push(nix_jit_primop_call_address_candidate()?);
        Ok(Self {
            candidates,
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
        let body = thunk_body_ref(eval, thunk)?;
        let key = def_site_key(body);
        let finalization = published_finalization(eval, key)?;
        // A primop body's native trampoline forces the primop against the
        // dispatched lexical env with empty `with`/scoped-import scopes, which is
        // only faithful when the thunk captured none. A primop thunk that did
        // capture dynamic scopes falls back to the tree walk.
        if primop_dispatch_needs_dynamic_scopes(eval, thunk, body) {
            return Some(Tier1ForceHook::Deopted);
        }
        let Some(env) = dispatch_env(eval, thunk) else {
            return Some(Tier1ForceHook::Deopted);
        };
        match run_finalized_native_thunk_call(eval, id, span, &env, &finalization) {
            Ok(outcome) if !outcome.is_trap() => Some(Tier1ForceHook::Dispatched(outcome.value())),
            _ => Some(Tier1ForceHook::Deopted),
        }
    }

    /// Counts a force of `thunk` and promotes its def-site at the threshold.
    ///
    /// Returns whether this call published a tier-1 entry (`promoted`) and whether
    /// it newly blacklisted the def-site after a failed lowering (`blacklisted`).
    fn count_and_maybe_promote(&self, eval: &mut TreeWalk, thunk: Value) -> PromotionOutcome {
        let Some(body) = thunk_body_ref(eval, thunk) else {
            return PromotionOutcome::none();
        };
        let key = def_site_key(body);
        {
            let mut state = self.state.borrow_mut();
            if state.blacklist.contains(&key) {
                return PromotionOutcome::none();
            }
            let count = state.counts.entry(key).or_insert(0);
            *count = count.saturating_add(1);
            if *count < self.threshold {
                return PromotionOutcome::none();
            }
        }
        match self.promote(eval, body, key) {
            PromotionResult::Promoted => PromotionOutcome {
                promoted: true,
                blacklisted: false,
            },
            PromotionResult::Unsupported => {
                let kind = body_kind_signature(eval, body);
                let mut state = self.state.borrow_mut();
                state.blacklist.insert(key);
                *state.blacklist_kinds.entry(kind).or_insert(0) += 1;
                PromotionOutcome {
                    promoted: false,
                    blacklisted: true,
                }
            }
            PromotionResult::Failed => PromotionOutcome::none(),
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
            lower_force_aware_tier1_ir_thunk_body_artifact_for_ir_in_module(
                ir,
                body.id(),
                body.module().as_u32(),
            )
            .ok()
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

    /// Returns the blacklist broken down by body-kind signature, most frequent first.
    ///
    /// Each entry pairs a body-kind signature (e.g. `"AttrSet"`, `"BinOp:Concat"`)
    /// with the number of distinct def-sites of that shape the lowerer rejected.
    /// Ties break by signature so the ordering is deterministic. This is a
    /// diagnostic view of where the unsupported tier-1 mass lives.
    pub fn blacklist_histogram(&self) -> Vec<(String, u32)> {
        let mut entries: Vec<(String, u32)> = self
            .state
            .borrow()
            .blacklist_kinds
            .iter()
            .map(|(kind, count)| (kind.clone(), *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }
}

impl Drop for NixJitTier1Engine {
    /// Dumps the blacklist-by-kind histogram to stderr when stats dumping is on.
    ///
    /// Gated on `AOS_NIX_EVAL_STATS=1` (read directly here because the engine is
    /// not handed the tree-walk options), this emits a single JSON object beside
    /// the evaluator's [`maybe_dump_eval_stats`](crate::native) output so a run
    /// can be told what the blacklisted def-sites are made of.
    fn drop(&mut self) {
        if std::env::var("AOS_NIX_EVAL_STATS").as_deref() != Ok("1") {
            return;
        }
        let histogram = self.blacklist_histogram();
        if histogram.is_empty() {
            return;
        }
        let body = histogram
            .iter()
            .map(|(kind, count)| format!("\"{kind}\":{count}"))
            .collect::<Vec<_>>()
            .join(",");
        eprintln!("{{\"aos_nix_tier1_blacklist_histogram\":{{{body}}}}}");
    }
}

/// Returns a diagnostic body-kind signature for a blacklisted def-site body.
///
/// The tier-1 lowerer unwraps a single [`IrKind::ThunkAlloc`] before matching on
/// the body shape, so this reports the inner body kind. A binary operator is
/// further qualified by its operator (e.g. `"BinOp:Concat"`), since the lowerer
/// routes operators to different shapes. Absent IR resolves to `"unknown"`.
fn body_kind_signature(eval: &TreeWalk, body: EvalNodeRef) -> String {
    let Some(ir) = eval.tier1_module_ir(body.module()) else {
        return "unknown".to_owned();
    };
    let Some(node) = ir.arena.node(body.id()).copied() else {
        return "unknown".to_owned();
    };
    let (kind, data) = match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(inner)) => match ir.arena.node(inner).copied() {
            Some(inner_node) => (inner_node.kind, inner_node.data),
            None => (node.kind, node.data),
        },
        _ => (node.kind, node.data),
    };
    match (kind, data) {
        (IrKind::BinOp, IrData::Binary { op, .. }) => format!("BinOp:{op:?}"),
        _ => format!("{kind:?}"),
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
        let outcome = self.count_and_maybe_promote(eval, thunk);
        Tier1ForceHook::Continued {
            promoted: outcome.promoted,
            blacklisted: outcome.blacklisted,
        }
    }
}

/// Whether one consulted force promoted its def-site and/or newly blacklisted it.
struct PromotionOutcome {
    promoted: bool,
    blacklisted: bool,
}

impl PromotionOutcome {
    /// Neither promoted nor blacklisted (below threshold, no body, or transient fail).
    const fn none() -> Self {
        Self {
            promoted: false,
            blacklisted: false,
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

/// Returns a dispatch-owned snapshot of the environment the tier-1 body reads.
///
/// The tier-1 lowerer resolves `LocalVar { slot }` against the innermost frame
/// (`aos_env_get`) and `UpvalVar { depth, slot }` against an enclosing frame
/// (`aos_upval_get`), so dispatch must pass the thunk's full captured frame
/// stack, not just its innermost frame.
///
/// The returned [`EvalEnv`] is an owned clone (a `Box<[Rc<EvalFrame>]>` copy, a
/// handful of `Rc` bumps at typical depth). Dispatch keeps this clone alive for
/// the native call so the wrapper decodes a pointer to storage the dispatcher
/// owns. It must never hand the native call a pointer into the evaluator's live
/// environment stack, which nested forcing swaps out mid-dispatch.
fn dispatch_env(eval: &TreeWalk, thunk: Value) -> Option<EvalEnv> {
    let heap_thunk = eval.heap().get_thunk(thunk).ok()?;
    Some(heap_thunk.env()?.clone())
}

/// Returns true when a primop `body`'s thunk captured dynamic scopes.
///
/// The `aos_primop_call` trampoline forces the primop against the dispatched
/// lexical environment with empty `with`/scoped-import scopes (see
/// [`ratchet_oracle::eval::TreeWalk::run_lowered_primop_body`]), which reproduces
/// a tree-walk force only when the thunk captured no such scopes. This guard lets
/// the dispatcher deoptimize the rare primop thunk that did, keeping every other
/// dispatched shape (which never consults dynamic scopes) unaffected.
fn primop_dispatch_needs_dynamic_scopes(eval: &TreeWalk, thunk: Value, body: EvalNodeRef) -> bool {
    if !body_is_primop(eval, body) {
        return false;
    }
    let Ok(heap_thunk) = eval.heap().get_thunk(thunk) else {
        return false;
    };
    let with_nonempty = heap_thunk
        .with_scope_env()
        .is_some_and(|env| !env.scopes().is_empty());
    let scoped_nonempty = heap_thunk
        .scoped_global_env()
        .is_some_and(|env| !env.scopes().is_empty());
    with_nonempty || scoped_nonempty
}

/// Returns true when `body` (through at most one `ThunkAlloc`) is a primop node.
fn body_is_primop(eval: &TreeWalk, body: EvalNodeRef) -> bool {
    let Some(ir) = eval.tier1_module_ir(body.module()) else {
        return false;
    };
    let Some(node) = ir.arena.node(body.id()).copied() else {
        return false;
    };
    match (node.kind, node.data) {
        (IrKind::PrimOp, _) => true,
        (IrKind::ThunkAlloc, IrData::Node(inner)) => ir
            .arena
            .node(inner)
            .is_some_and(|inner_node| inner_node.kind == IrKind::PrimOp),
        _ => false,
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
    use ratchet_oracle::cache::input::ImpureInputFingerprint;
    use ratchet_oracle::compile::resolve;
    use ratchet_oracle::eval::EvalStats;
    use ratchet_oracle::eval::tree_walk::{TreeWalkError, TreeWalkOptions};
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

    /// Evaluates `source` at threshold 1 and returns the engine's blacklist histogram.
    fn blacklist_histogram_for(source: &str) -> Vec<(String, u32)> {
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_jit_tier1_publish_enabled(true);
        let mut eval = TreeWalk::with_options(&ir, options);
        let engine = Rc::new(NixJitTier1Engine::with_threshold(1).expect("engine builds"));
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
            NixJitTier1Engine::with_threshold(threshold).expect("engine builds"),
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
            NixJitTier1Engine::with_threshold(threshold).expect("engine builds"),
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
}
