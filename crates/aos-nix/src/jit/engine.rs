//! Live tier-1 JIT engine driving promotion and dispatch during serial forcing.
//!
//! [`NixJitTier1Engine`] owns promotion policy behind [`Tier1Engine`]. Native
//! success returns [`Tier1ForceHook::Dispatched`]; traps return
//! [`Tier1ForceHook::Deopted`], and unsupported shapes are blacklisted once.
//! Native entries read the tree walk's captured innermost `Rc<EvalFrame>`, so
//! both tiers observe identical `LocalVar { slot }` values.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ratchet_core::{IrData, IrId, IrKind, syntax::Span};
use ratchet_jit::{
    JitClifArtifact, JitModuleContext, JitModuleContextFinalizedBody, JitModuleContextKeepAlive,
    JitRuntimeSymbolAddressCandidate, JitValueAbi, classify_interp_thunk_body,
    lower_force_aware_tier1_ir_thunk_body_artifact_for_ir_in_module,
    lower_string_length_inline_ir_thunk_body_artifact,
};
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_oracle::eval::{EvalEnv, EvalNodeRef, OpaqueTier1Slot, Tier1Engine, Tier1ForceHook};
use ratchet_runtime_ffi::run_context_finalized_native_thunk_call;
use ratchet_value::value::Value;

use crate::jit::{
    NixJitRuntimeSymbolAddressCandidateError, nix_jit_deopt_address_candidate,
    nix_jit_primop_call_address_candidate, nix_jit_runtime_symbol_address_candidate_preflight,
    nix_jit_string_length_address_candidate, nix_jit_upval_get_address_candidate,
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
    /// Whether to record the per-symbol dispatched-primop histogram.
    ///
    /// Sampled once from `AOS_NIX_EVAL_STATS` at construction so the dispatch hot
    /// path pays nothing when stats are off; when on, each dispatched primop is
    /// counted by builtin name (Phase-B inline-candidate naming).
    record_dispatched_kinds: bool,
    /// Whether to estimate and record the profit cost of each gated def-site.
    ///
    /// Sampled once from `AOS_NIX_EVAL_STATS` at construction. When on, the gated
    /// path (the default, promotion off) lowers each gated body once to estimate
    /// its native-instruction count, building the
    /// [`gated_cost_histogram`](Self::gated_cost_histogram) that reports whether
    /// the gated mass contains compound bodies worth profit-promoting. It is a
    /// measurement-only cost paid once per def-site under the stats flag, never on
    /// the hot dispatch path and never when stats are off.
    record_gated_cost: bool,
    /// Whether to promote any def-site at all.
    ///
    /// Off by default, so the tier promotes nothing on the current corpus. Every
    /// tier-1-lowerable shape today (single arithmetic op, attribute select,
    /// upvalue read, primop trampoline, `stringLength` inline) is too small to
    /// beat the per-dispatch harness cost — measured net-negative on wall time —
    /// so promoting it regresses an `AOS_NIX_JIT=1` run. The tier's dispatch,
    /// deopt, and compile machinery stays complete and tested; it simply waits for
    /// profit-based large-body lowering. Forced on by `AOS_NIX_JIT_FORCE_PROMOTE=1`
    /// (to exercise dispatch end to end) or by
    /// [`NixJitTier1Engine::force_promote`] (used by the dispatch differential
    /// tests, which must still promote and dispatch a body).
    force_promote: bool,
    /// The selected one-word literal boundary, or the active two-word ABI.
    literal_value_abi: JitValueAbi,
    /// The shared JIT module every promoted body is finalized into.
    ///
    /// Built lazily on the first promotion (from [`candidates`](Self::candidates))
    /// so a gated run — the default, which promotes nothing — never pays for a
    /// module. Once built, [`promote`](Self::promote) finalizes each body into it
    /// rather than allocating a fresh module per body, amortizing the module setup
    /// across every promotion. It outlives every dispatch entry, and each entry
    /// also holds a keep-alive handle into it, so a body's finalized code stays
    /// callable for the engine's whole life.
    context: RefCell<Option<JitModuleContext>>,
    state: RefCell<EngineState>,
    /// Whether the tier-2 lambda apply seam is active.
    ///
    /// On by default whenever the engine is installed: the tier-2 promotion
    /// gate only admits self-recursive arithmetic bodies whose native win
    /// clears the dispatch harness by construction (see [`tier2`]), so it
    /// cannot regress workloads whose lambdas fall outside that grammar.
    /// `AOS_NIX_JIT_TIER2=0` disables it for A/B measurement.
    tier2_enabled: bool,
    /// Tier-2 per-def-site promotion bookkeeping (see [`tier2`]).
    tier2: RefCell<tier2::Tier2EngineState>,
    /// Tier-2 fold-seam bookkeeping (see [`tier2_fold`]).
    tier2_fold: RefCell<tier2_fold::Tier2FoldState>,
    /// Tier-2 fused-list-generation bookkeeping (see [`tier2_fold_gen`]).
    tier2_fold_gen: RefCell<tier2_fold_gen::Tier2FoldGenState>,
    /// Tier-2 filter-seam bookkeeping (see [`tier2_filter`]).
    tier2_filter: RefCell<tier2_filter::Tier2FilterState>,
}

mod tier2;
mod dispatch_policy;
mod stats_dump;
mod tier2_chain;
mod tier2_filter;
mod tier2_fold;
mod tier2_fold_gen;
mod value_abi;

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
    /// Count of dispatched primop calls keyed by builtin name (`add`, `head`, …).
    ///
    /// Populated only when [`NixJitTier1Engine::record_dispatched_kinds`] is set.
    /// Since PrimOp bodies now dispatch rather than blacklist, this is where the
    /// hot builtins surface — the naming a Phase-B selective-inline pass needs.
    dispatched_kinds: HashMap<String, u64>,
    /// Def-sites the engine declined to promote; kept so they short-circuit like
    /// the blacklist and are never re-considered.
    ///
    /// Because every current tier-1 shape is net-negative on wall time (the
    /// per-dispatch harness exceeds the tiny body's savings), the engine gates
    /// every def-site by default rather than promoting it. The tree walk records
    /// each gated def-site and stops consulting the engine for its later instances
    /// (the per-force hook-tax fast path).
    gated_def_sites: HashSet<u64>,
    /// Count of gated def-sites keyed by a body signature (builtin name for a
    /// primop, else IR body kind).
    ///
    /// Recorded per def-site (at most once each, on the cold promotion path) so a
    /// run can report the gated mass — which shapes the tier is declining to
    /// promote — for the `AOS_NIX_EVAL_STATS` diagnostics.
    gated_kinds: HashMap<String, u32>,
    /// Number of gated def-sites whose native-instruction count equals the key.
    ///
    /// Populated only when [`NixJitTier1Engine::record_gated_cost`] is set, by
    /// lowering each gated (lowerable) body once and estimating its cost. This is
    /// the profit-distribution the profit-promotion heuristic is calibrated
    /// against: a tail of high native-instruction bodies means today's grammar
    /// already lowers compound bodies worth promoting.
    gated_cost_by_native: HashMap<u32, u32>,
    /// Number of gated def-sites the tier-1 lowerer could lower (so a profit pass
    /// could promote them). Counted only under `record_gated_cost`.
    gated_lowerable: u32,
    /// Number of gated def-sites the tier-1 lowerer could not lower (unsupported
    /// shape today). Counted only under `record_gated_cost`.
    gated_unlowerable: u32,
    /// Count of gated interpolation def-sites keyed by fusability signature.
    ///
    /// Populated only under `record_gated_cost`. This sizes the fused-Interp
    /// promotion opportunity: how many of the gated `Interp` bodies are fusable
    /// (and at what fused node counts) versus complex-child, path-fragment,
    /// single-child, or empty. See [`ratchet_jit::InterpFusibility`].
    interp_shape: HashMap<String, u32>,
    /// Count of interpolation-body child nodes keyed by IR kind.
    ///
    /// Populated only under `record_gated_cost`. Breaks down what interpolation
    /// children actually are (e.g. `Select`, `Apply`, `Str`, `LocalVar`), so the
    /// dominant `complex-child` classification can be explained — which shapes a
    /// wider fused grammar would have to force inline to reach real sites.
    interp_child_kinds: HashMap<String, u32>,
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
        // `aos_string_length` is the leaf helper the `stringLength` native inline
        // body calls to read a forced string's byte length; register it directly
        // like the other standalone wrappers so an inline body can be finalized.
        candidates.push(nix_jit_string_length_address_candidate()?);
        Ok(Self {
            candidates,
            threshold: threshold.max(1),
            record_dispatched_kinds: std::env::var("AOS_NIX_EVAL_STATS").as_deref() == Ok("1"),
            record_gated_cost: std::env::var("AOS_NIX_EVAL_STATS").as_deref() == Ok("1"),
            force_promote: std::env::var("AOS_NIX_JIT_FORCE_PROMOTE").as_deref()
                == Ok("1"),
            literal_value_abi: value_abi::configured_literal_value_abi(),
            context: RefCell::new(None),
            state: RefCell::new(EngineState::default()),
            tier2_enabled: std::env::var("AOS_NIX_JIT_TIER2").as_deref() != Ok("0"),
            tier2: RefCell::new(tier2::Tier2EngineState::default()),
            tier2_fold: RefCell::new(tier2_fold::Tier2FoldState::default()),
            tier2_fold_gen: RefCell::new(tier2_fold_gen::Tier2FoldGenState::default()),
            tier2_filter: RefCell::new(tier2_filter::Tier2FilterState::default()),
        })
    }

    /// Enables promotion on this engine, bypassing the default gate.
    ///
    /// The engine otherwise gates every def-site (see
    /// [`force_promote`](Self::force_promote)), so nothing is compiled or
    /// dispatched. The dispatch differential tests must still promote and dispatch
    /// a body, so they opt in through this builder; it is the in-process equivalent
    /// of the `AOS_NIX_JIT_FORCE_PROMOTE=1` escape hatch.
    #[must_use]
    pub fn force_promote(mut self) -> Self {
        self.force_promote = true;
        self
    }

    /// Enables gated-cost recording without the process-global stats env var.
    ///
    /// Mirrors what `AOS_NIX_EVAL_STATS=1` turns on for
    /// [`gated_cost_histogram`](Self::gated_cost_histogram), so a unit test can
    /// exercise the profit-distribution measurement deterministically.
    #[cfg(test)]
    #[cfg_attr(feature = "candidate_c_value", allow(dead_code))]
    #[must_use]
    fn record_gated_cost(mut self) -> Self {
        self.record_gated_cost = true;
        self
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
        let finalized_body = published_body(eval, key)?;
        // A primop body's native trampoline forces the primop against the
        // dispatched lexical env with empty `with`/scoped-import scopes, which is
        // only faithful when the thunk captured none. A primop thunk that did
        // capture dynamic scopes falls back to the tree walk.
        if dispatch_policy::primop_dispatch_needs_dynamic_scopes(eval, thunk, body) {
            return Some(Tier1ForceHook::Deopted);
        }
        let env = match dispatch_env(eval, thunk) {
            Some(env) => env,
            None if finalized_body.artifact().value_abi() != JitValueAbi::Active => {
                EvalEnv::default()
            }
            None => return Some(Tier1ForceHook::Deopted),
        };
        match run_context_finalized_native_thunk_call(eval, id, span, &env, &finalized_body) {
            Ok(outcome) if !outcome.is_trap() => {
                if self.record_dispatched_kinds
                    && let Some(name) = primop_symbol_name(eval, body)
                {
                    *self
                        .state
                        .borrow_mut()
                        .dispatched_kinds
                        .entry(name)
                        .or_insert(0) += 1;
                }
                Some(Tier1ForceHook::Dispatched(outcome.value()))
            }
            _ => Some(Tier1ForceHook::Deopted),
        }
    }

    /// Gates or (when `force_promote` is set) promotes `thunk`'s def-site.
    ///
    /// With promotion off — the default — the def-site is gated on its first
    /// consulted force. With `force_promote` set, the force is counted and the
    /// def-site is promoted once it reaches the threshold.
    ///
    /// Returns whether this call published a tier-1 entry (`promoted`) and whether
    /// it newly blacklisted the def-site after a failed lowering (`blacklisted`).
    fn count_and_maybe_promote(&self, eval: &mut TreeWalk, thunk: Value) -> PromotionOutcome {
        let Some(body) = thunk_body_ref(eval, thunk) else {
            return PromotionOutcome::none();
        };
        let key = def_site_key(body);
        {
            let state = self.state.borrow();
            if state.blacklist.contains(&key) || state.gated_def_sites.contains(&key) {
                // Already decided; re-signal `gated` so the tree walk (which skips
                // consulting a gated def-site) stays consistent if it ever asks.
                return PromotionOutcome::gated();
            }
        }
        // Gate every def-site on its first consulted force when promotion is off
        // (the default): every current tier-1 shape is too small to beat the
        // per-dispatch harness (measured net-negative on wall time), so promoting
        // it regresses the run. Since no shape is worth compiling there is nothing
        // to count toward the threshold — gating immediately lets the tree walk drop
        // the def-site from the force hook after one force instead of `threshold`.
        // Promotion is opt-in through `force_promote` (tests and the
        // `AOS_NIX_JIT_FORCE_PROMOTE` escape hatch) until profit-based large-body
        // lowering makes some body worth compiling.
        if !self.force_promote {
            // Recording is per-def-site (at most once each), not per dispatch.
            let signature = gated_signature(eval, body);
            // Under the stats flag, estimate what promoting this body would cost
            // by lowering it once and censusing its native compute. This is the
            // profit distribution the profit-promotion heuristic is calibrated on;
            // it is skipped entirely (no lowering) when stats are off.
            let gated_cost = if self.record_gated_cost {
                Some(
                    self.lower_body_artifact(eval, body)
                        .map(|artifact| artifact.cost_estimate()),
                )
            } else {
                None
            };
            // Under the stats flag, also classify Interp bodies by fusability to
            // size the fused-Interp promotion opportunity (a candidate grammar
            // extension). This is a static arena inspection, not a lowering.
            let interp = if self.record_gated_cost {
                interp_shape_key(eval, body)
            } else {
                None
            };
            let mut state = self.state.borrow_mut();
            state.gated_def_sites.insert(key);
            *state.gated_kinds.entry(signature).or_insert(0) += 1;
            if let Some((interp_key, child_kinds)) = interp {
                *state.interp_shape.entry(interp_key).or_insert(0) += 1;
                for child_kind in child_kinds {
                    *state.interp_child_kinds.entry(child_kind).or_insert(0) += 1;
                }
            }
            if let Some(cost) = gated_cost {
                match cost {
                    Some(cost) => {
                        state.gated_lowerable = state.gated_lowerable.saturating_add(1);
                        *state
                            .gated_cost_by_native
                            .entry(cost.native_insts())
                            .or_insert(0) += 1;
                    }
                    None => {
                        state.gated_unlowerable = state.gated_unlowerable.saturating_add(1);
                    }
                }
            }
            return PromotionOutcome::gated();
        }
        {
            let mut state = self.state.borrow_mut();
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
                gated: false,
            },
            PromotionResult::Unsupported => {
                let kind = body_kind_signature(eval, body);
                let mut state = self.state.borrow_mut();
                state.blacklist.insert(key);
                *state.blacklist_kinds.entry(kind).or_insert(0) += 1;
                PromotionOutcome {
                    promoted: false,
                    blacklisted: true,
                    gated: true,
                }
            }
            PromotionResult::Failed => PromotionOutcome::none(),
        }
    }

    /// Lowers `body` to a verified CLIF artifact, if its shape is supported today.
    ///
    /// A builtin with a native inline (e.g. `stringLength`) lowers to its
    /// dedicated inline body; every other body uses the shared force-aware lowerer
    /// (which routes remaining primops to the delegating trampoline). Returns
    /// `None` when the IR is missing or the shape is not lowerable. This is the
    /// shared lowering both [`promote`](Self::promote) and the gated-cost
    /// measurement use, so the estimated cost matches what promotion would compile.
    fn lower_body_artifact(&self, eval: &TreeWalk, body: EvalNodeRef) -> Option<JitClifArtifact> {
        let inline_builtin = primop_symbol_name(eval, body)
            .is_some_and(|name| dispatch_policy::primop_has_native_inline(name.as_bytes()));
        eval.tier1_module_ir(body.module()).and_then(|ir| {
            let one_word_literal =
                value_abi::lower_literal(self.literal_value_abi, &ir.arena, body.id());
            if let Some(artifact) = one_word_literal {
                Some(artifact)
            } else if inline_builtin {
                lower_string_length_inline_ir_thunk_body_artifact(&ir.arena, body.id()).ok()
            } else {
                lower_force_aware_tier1_ir_thunk_body_artifact_for_ir_in_module(
                    ir,
                    body.id(),
                    body.module().as_u32(),
                )
                .ok()
            }
        })
    }

    /// Lowers, finalizes, installs, and publishes a tier-1 entry for `body`.
    ///
    /// The entry is keyed by `def_site` so every thunk instance of the same IR
    /// body shares it. Installing a def-site entry publishes it unconditionally:
    /// the promoting instance is mid-force (already claimed), and the entry is
    /// valid for all future instances regardless of this one's state.
    fn promote(&self, eval: &mut TreeWalk, body: EvalNodeRef, def_site: u64) -> PromotionResult {
        let Some(artifact) = self.lower_body_artifact(eval, body) else {
            // The IR is missing or the shape is not lowerable today; never retry.
            return PromotionResult::Unsupported;
        };
        // Finalize the body into the shared module (built lazily on first use), and
        // capture a keep-alive handle so the dispatch entry pins the module's code
        // memory independently of the engine's own `context` slot.
        let (finalized_body, keep_alive) = {
            let mut context_slot = self.context.borrow_mut();
            if context_slot.is_none() {
                match JitModuleContext::with_candidates(&self.candidates) {
                    Ok(context) => *context_slot = Some(context),
                    Err(_) => return PromotionResult::Failed,
                }
            }
            let Some(context) = context_slot.as_ref() else {
                return PromotionResult::Failed;
            };
            match context.define_and_finalize(artifact) {
                Ok(finalized_body) => (finalized_body, context.keep_alive()),
                Err(_) => return PromotionResult::Failed,
            }
        };

        let entry = NixJitTier1DispatchEntry::new(finalized_body, keep_alive);
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

    /// Returns the gated def-site mass by body signature, most frequent first.
    ///
    /// Each entry pairs a body signature (a builtin name like `stringLength` for a
    /// primop, else an IR body kind like `"BinOp:Add"`) with the number of
    /// def-sites the engine declined to promote. Ties break by signature for
    /// determinism. This reports which shapes the tier is gating rather than
    /// promoting; it is always recorded, since gating is the default.
    pub fn gated_histogram(&self) -> Vec<(String, u32)> {
        let mut entries: Vec<(String, u32)> = self
            .state
            .borrow()
            .gated_kinds
            .iter()
            .map(|(kind, count)| (kind.clone(), *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }

    /// Returns the gated-mass profit distribution: native-instruction count to
    /// def-site count, ascending by native count.
    ///
    /// Each entry pairs a native-instruction count (the profit proxy from
    /// [`ratchet_jit::Tier1BodyCost`]) with the number of lowerable gated
    /// def-sites having that count. Only populated when the engine was built with
    /// gated-cost recording on (`AOS_NIX_EVAL_STATS=1`). A tail of high native
    /// counts means today's grammar already lowers compound bodies whose native
    /// compute could beat the per-dispatch harness, so a profit-promotion pass has
    /// candidates. See [`gated_lowerable_count`](Self::gated_lowerable_count) and
    /// [`gated_unlowerable_count`](Self::gated_unlowerable_count) for the totals.
    pub fn gated_cost_histogram(&self) -> Vec<(u32, u32)> {
        let mut entries: Vec<(u32, u32)> = self
            .state
            .borrow()
            .gated_cost_by_native
            .iter()
            .map(|(native, count)| (*native, *count))
            .collect();
        entries.sort_by_key(|entry| entry.0);
        entries
    }

    /// Returns how many gated def-sites the tier-1 lowerer could lower.
    ///
    /// Populated only under `AOS_NIX_EVAL_STATS=1`; these are the def-sites a
    /// profit-promotion pass could consider (their cost is in
    /// [`gated_cost_histogram`](Self::gated_cost_histogram)).
    pub fn gated_lowerable_count(&self) -> u32 {
        self.state.borrow().gated_lowerable
    }

    /// Returns how many gated def-sites the tier-1 lowerer could not lower.
    ///
    /// Populated only under `AOS_NIX_EVAL_STATS=1`; these shapes are outside
    /// today's tier-1 grammar, so no profit pass can promote them without a
    /// lowerer extension.
    pub fn gated_unlowerable_count(&self) -> u32 {
        self.state.borrow().gated_unlowerable
    }

    /// Returns the gated interpolation bodies by fusability signature, most
    /// frequent first.
    ///
    /// Each entry pairs a fusability key (`"fusable:n4"`, `"complex-child"`,
    /// `"path-fragment"`, `"single"`, `"empty"`) with the number of gated
    /// `Interp` def-sites of that shape. Ties break by key for determinism. Only
    /// populated under `AOS_NIX_EVAL_STATS=1`; it sizes the fused-Interp
    /// promotion opportunity — how many interpolation sites a fused lowering
    /// could reach and at what part counts.
    pub fn interp_shape_histogram(&self) -> Vec<(String, u32)> {
        let mut entries: Vec<(String, u32)> = self
            .state
            .borrow()
            .interp_shape
            .iter()
            .map(|(key, count)| (key.clone(), *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }

    /// Returns interpolation child-node kinds by count, most frequent first.
    ///
    /// Each entry pairs an IR kind name (`"Select"`, `"Apply"`, `"Str"`,
    /// `"LocalVar"`, …) with how many interpolation children of that kind were
    /// seen. Only populated under `AOS_NIX_EVAL_STATS=1`; it explains the
    /// `complex-child` mass by naming the child shapes a wider fused grammar
    /// would need to force inline.
    pub fn interp_child_kind_histogram(&self) -> Vec<(String, u32)> {
        let mut entries: Vec<(String, u32)> = self
            .state
            .borrow()
            .interp_child_kinds
            .iter()
            .map(|(key, count)| (key.clone(), *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
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

    /// Returns dispatched primop calls by builtin name, most frequent first.
    ///
    /// Each entry pairs a builtin name (`add`, `head`, `stringLength`, …) with the
    /// number of dispatched calls to it. Ties break by name for determinism. Empty
    /// unless the engine was built with dispatched-kind recording on
    /// (`AOS_NIX_EVAL_STATS=1`). This names the hot builtins a Phase-B selective
    /// native-inline pass should target.
    pub fn dispatched_histogram(&self) -> Vec<(String, u64)> {
        let mut entries: Vec<(String, u64)> = self
            .state
            .borrow()
            .dispatched_kinds
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
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
            gated: outcome.gated,
        }
    }

    fn on_lambda_apply(
        &self,
        eval: &mut TreeWalk,
        function: Value,
        lambda: &ratchet_oracle::eval::heap::EvalLambda,
        argument: Value,
        id: IrId,
        span: Span,
    ) -> ratchet_oracle::eval::Tier2ApplyHook {
        self.on_lambda_apply_impl(eval, function, lambda, argument, id, span)
    }

    fn on_foldl_strict(
        &self,
        eval: &mut TreeWalk,
        op: Value,
        lambda: &ratchet_oracle::eval::heap::EvalLambda,
        accumulator: Value,
        elements: &[Value],
        id: IrId,
        span: Span,
    ) -> ratchet_oracle::eval::Tier2FoldHook {
        self.on_foldl_strict_impl(eval, op, lambda, accumulator, elements, id, span)
    }

    fn on_filter_strict(
        &self,
        eval: &mut TreeWalk,
        predicate: Value,
        lambda: &ratchet_oracle::eval::heap::EvalLambda,
        elements: &[Value],
        id: IrId,
        span: Span,
    ) -> ratchet_oracle::eval::Tier2FilterHook {
        self.on_filter_strict_impl(eval, predicate, lambda, elements, id, span)
    }

    fn on_all_any_strict(
        &self,
        eval: &mut TreeWalk,
        predicate: Value,
        lambda: &ratchet_oracle::eval::heap::EvalLambda,
        elements: &[Value],
        short_circuit_on: bool,
        id: IrId,
        span: Span,
    ) -> ratchet_oracle::eval::Tier2AllAnyHook {
        self.on_all_any_strict_impl(
            eval,
            predicate,
            lambda,
            elements,
            short_circuit_on,
            id,
            span,
        )
    }

    fn on_foldl_strict_genlist(
        &self,
        eval: &mut TreeWalk,
        op: Value,
        op_lambda: &ratchet_oracle::eval::heap::EvalLambda,
        generator: Value,
        generator_lambda: &ratchet_oracle::eval::heap::EvalLambda,
        accumulator: Value,
        next_index: usize,
        length: usize,
        id: IrId,
        span: Span,
    ) -> ratchet_oracle::eval::Tier2FoldHook {
        self.on_foldl_strict_genlist_impl(
            eval,
            op,
            op_lambda,
            generator,
            generator_lambda,
            accumulator,
            next_index,
            length,
            id,
            span,
        )
    }
}

/// Whether one consulted force promoted, blacklisted, or permanently gated its
/// def-site.
struct PromotionOutcome {
    promoted: bool,
    blacklisted: bool,
    /// True when the engine has permanently decided not to dispatch this def-site,
    /// so the tree walk should stop consulting the engine for its instances.
    gated: bool,
}

impl PromotionOutcome {
    /// Neither promoted, blacklisted, nor gated (below threshold, no body, or a
    /// transient failure that may still succeed on a later force).
    const fn none() -> Self {
        Self {
            promoted: false,
            blacklisted: false,
            gated: false,
        }
    }

    /// The def-site was permanently gated (blacklisted or delegate-only skipped).
    const fn gated() -> Self {
        Self {
            promoted: false,
            blacklisted: false,
            gated: true,
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

/// Owns a finalized tier-1 body so its native entry stays callable.
///
/// Wrapping the finalized body in an [`Rc`] lets the evaluator side-table own the
/// entry type-erased while dispatch clones an independent handle to run the call
/// without aliasing the mutable evaluator borrow. The body's code lives in the
/// engine's shared [`JitModuleContext`]; the entry also holds a
/// [`JitModuleContextKeepAlive`] so that module — and thus the body's code memory —
/// outlives the entry regardless of engine teardown order.
struct NixJitTier1DispatchEntry {
    body: Rc<JitModuleContextFinalizedBody>,
    _keep_alive: JitModuleContextKeepAlive,
}

impl NixJitTier1DispatchEntry {
    /// Wraps a finalized body and its module keep-alive as a dispatch entry.
    fn new(body: JitModuleContextFinalizedBody, keep_alive: JitModuleContextKeepAlive) -> Self {
        Self {
            body: Rc::new(body),
            _keep_alive: keep_alive,
        }
    }

    /// Returns the finalized native entry address the dispatcher calls through.
    fn entry_addr(&self) -> usize {
        self.body.finalized_function().code_ptr().as_ptr() as usize
    }

    /// Returns an independent shared handle to the finalized body.
    fn body(&self) -> Rc<JitModuleContextFinalizedBody> {
        Rc::clone(&self.body)
    }
}

/// Returns the published tier-1 finalized body for a def-site key, if any.
fn published_body(
    eval: &TreeWalk,
    def_site: u64,
) -> Option<Rc<JitModuleContextFinalizedBody>> {
    let slot = eval.tier1_def_site_slot(def_site)?;
    if !slot.is_published() {
        return None;
    }
    let entry = slot.owner().downcast_ref::<NixJitTier1DispatchEntry>()?;
    Some(entry.body())
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
    let env = heap_thunk.env()?;
    // The frozen tier-1 env-get ABI walks shared frames only. FV-5 flat
    // captures live inline in the owning closure and require the tree walk's
    // constant-index resolver, so these sites deopt until the runtime ABI
    // grows an inline-capture operand.
    if env.frame_count() != env.frames().len() {
        return None;
    }
    Some(env.clone())
}

/// Returns the dispatched primop's builtin name (`add`, `head`, …), if any.
///
/// Resolves the primop node's `Symbol` (through at most one `ThunkAlloc`) against
/// the evaluator-global table via [`TreeWalk::resolve_symbol`] — not the body
/// module's local IR table — so imported-module builtins name correctly rather
/// than resolving to `?`.
fn primop_symbol_name(eval: &TreeWalk, body: EvalNodeRef) -> Option<String> {
    let ir = eval.tier1_module_ir(body.module())?;
    let node = ir.arena.node(body.id()).copied()?;
    let symbol = match (node.kind, node.data) {
        (IrKind::PrimOp, IrData::PrimOp { symbol, .. }) => symbol,
        (IrKind::ThunkAlloc, IrData::Node(inner)) => {
            let inner_node = ir.arena.node(inner).copied()?;
            match (inner_node.kind, inner_node.data) {
                (IrKind::PrimOp, IrData::PrimOp { symbol, .. }) => symbol,
                _ => return None,
            }
        }
        _ => return None,
    };
    eval.resolve_symbol(symbol)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

/// Returns a diagnostic signature naming a gated def-site's body.
///
/// A primop body is named by its builtin (e.g. `stringLength`, `head`) so the
/// gated-mass histogram distinguishes builtins; any other body falls back to its
/// IR body-kind signature (e.g. `"BinOp:Add"`, `"AttrSet"`). A primop whose name
/// cannot be resolved is reported as `"PrimOp"`.
fn gated_signature(eval: &TreeWalk, body: EvalNodeRef) -> String {
    if body_is_primop(eval, body) {
        primop_symbol_name(eval, body).unwrap_or_else(|| "PrimOp".to_owned())
    } else {
        body_kind_signature(eval, body)
    }
}

/// Returns an interpolation `body`'s fusability key and its child-node kinds, if
/// it is an interpolation.
///
/// Resolves the body's module IR and classifies the interpolation shape with
/// [`classify_interp_thunk_body`], returning `None` for a non-interpolation body
/// (or missing IR) so only `Interp` def-sites are counted. The second tuple
/// element is the census of the body's child kinds (empty for the single-child
/// and empty interpolation forms), used to explain the `complex-child` mass.
fn interp_shape_key(eval: &TreeWalk, body: EvalNodeRef) -> Option<(String, Vec<String>)> {
    let ir = eval.tier1_module_ir(body.module())?;
    let fusibility = classify_interp_thunk_body(&ir.arena, body.id());
    if fusibility == ratchet_jit::InterpFusibility::NotInterp {
        return None;
    }
    // Census both the direct child kinds and, for each `${expr}` coercion
    // wrapper, the inner expression kind (prefixed `in>`) — that inner kind is
    // what a fused grammar would have to force inline.
    let mut child_kinds: Vec<String> = ratchet_jit::interp_child_kinds(&ir.arena, body.id())
        .into_iter()
        .map(|kind| format!("{kind:?}"))
        .collect();
    child_kinds.extend(
        ratchet_jit::interp_child_inner_kinds(&ir.arena, body.id())
            .into_iter()
            .map(|kind| format!("in>{kind:?}")),
    );
    Some((fusibility.histogram_key(), child_kinds))
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

// JIT is off by construction under the Candidate-C variant; re-enabled at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use super::*;

    use ratchet_core::Ir;
    use ratchet_oracle::cache::input::ImpureInputFingerprint;
    use ratchet_oracle::compile::resolve;
    use ratchet_oracle::eval::EvalStats;
    use ratchet_oracle::eval::tree_walk::{TreeWalkError, TreeWalkOptions};
    use ratchet_oracle::syntax::parse_str;

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
}
