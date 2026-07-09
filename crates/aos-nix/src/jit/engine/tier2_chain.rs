//! Tier-2 fused curried-chain promotion and dispatch at the apply seam.
//!
//! The [`tier2`](super::tier2) module promotes single-formal self-recursive
//! lambda bodies. Multi-argument recursions like `tak = x: y: z: ...` fall
//! outside that grammar: the interpreter applies the chain one argument at a
//! time through two intermediate partial-application closures per call, and
//! the self-recursion is an `Apply(Apply(Apply(self, a), b), c)` chain. This
//! module compiles the whole chain as one native function of K arguments (see
//! [`ratchet_jit::lower_tier2_curried_chain`]) and dispatches it at the apply
//! seam of the chain's **innermost** lambda — the first point where every
//! argument is available.
//!
//! # Root discovery and validation
//!
//! The apply seam only knows the innermost lambda's def-site. Promotion
//! discovers the chain root by resolving each candidate callee upvalue out of
//! the applied closure's captured environment: the site whose resolved
//! closure's own curried chain walks back down to exactly this def-site is
//! the self-callee, and the resolved closure is the chain root. Remaining
//! callee sites must resolve to pinned callees — closures whose own chains
//! have call-free arithmetic bodies that the lowering inlines. An unforced
//! candidate binding is a transient failure (the count resets and the seam
//! retries later); any structural mismatch blacklists the def-site.
//!
//! # Dispatch guards
//!
//! A published chain entry dispatches a boundary application only when the
//! partial-application spine the interpreter built is exactly the one the
//! compiled chain fuses:
//!
//! - the applied closure's captured environment ends with the K-1 argument
//!   frames of the outer applications, and the prefix before them is
//!   frame-for-frame (pointer) identical to the resolved chain root's
//!   captured environment — which makes every parameter and self-callee read
//!   inside the native recursion exactly the read the interpreter would
//!   perform;
//! - the self-callee upvalue resolves (through an already-forced binding) to
//!   a closure with the chain root's module, pattern, and body — the def-site
//!   identity that makes the compiled direct self-call the interpreter's
//!   call;
//! - every pinned callee still resolves to a closure with the recorded
//!   def-site identity (a pinned body is call-free and environment-free, so
//!   def-site identity implies behavioral identity); and
//! - the interpreter has `max_call_depth` headroom for the full native depth
//!   budget (the same precondition as the unary tier-2 dispatcher).
//!
//! A failed guard is transient and falls through to the interpreted call
//! without gating. Any trap out of the native call deopts to the interpreted
//! call, which re-runs the body — sound for the same purity argument as the
//! unary tier: compiled chains are pure except for memoizing forces.

use std::rc::Rc;
use std::sync::Arc;

use ratchet_core::{IrArena, IrData, IrId, IrKind};
use ratchet_jit::{
    JitModuleContext, JitModuleContextFinalizedBody, JitModuleContextKeepAlive,
    JitTier2ChainLowering, JitTier2PinnedCallee, TIER2_MAX_CHAIN_ARITY, estimate_tier1_body_cost,
    lower_tier2_curried_chain, scan_tier2_curried_chain, scan_tier2_pinned_callee,
};
use ratchet_oracle::eval::heap::EvalLambda;
use ratchet_oracle::eval::tree_walk::TreeWalk;
use ratchet_oracle::eval::{OpaqueTier1Slot, Tier2ApplyHook};
use ratchet_value::value::Value;

use super::NixJitTier1Engine;
use super::tier2::{TIER2_MIN_NATIVE_INSTS, continued_hook};

/// The def-site identity of a resolved chain root or pinned callee.
///
/// Def-site identity (module-scoped pattern and body nodes) rather than value
/// identity: any closure instance of the same source lambda chain behaves
/// identically for a call-free pinned body, and the chain root's remaining
/// behavioral dependence — its captured environment — is guarded separately
/// by frame-pointer prefix identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Tier2PinIdentity {
    /// Body-relative `(depth, slot)` of the callee upvalue.
    pub(super) upval: (u32, u32),
    /// The callee's root parameter pattern node.
    pub(super) pattern: IrId,
    /// The callee's root body node.
    pub(super) body: IrId,
}

/// Owns a finalized tier-2 fused-chain entry so its native code stays callable.
///
/// Stored type-erased in the evaluator's tier-2 def-site side-table (the same
/// table as the unary entries; dispatch distinguishes the two by downcast)
/// and downcast back at dispatch. Carries every guard input the dispatcher
/// needs.
pub(super) struct NixJitTier2ChainEntry {
    /// The finalized boundary entry (frozen argv lambda-entry ABI).
    pub(super) body: Rc<JitModuleContextFinalizedBody>,
    /// Keeps the shared JIT module (and thus the entry's code) alive.
    pub(super) _keep_alive: JitModuleContextKeepAlive,
    /// The chain arity K.
    pub(super) arity: u32,
    /// Body-relative `(depth, slot)` of the self-callee upvalue.
    pub(super) self_upval: (u32, u32),
    /// The chain root's parameter pattern node (def-site identity guard).
    pub(super) root_pattern: IrId,
    /// The chain root's body node (def-site identity guard).
    pub(super) root_body: IrId,
    /// The pinned callees whose def-site identity is re-checked per dispatch.
    pub(super) pinned: Vec<Tier2PinIdentity>,
}

impl NixJitTier2ChainEntry {
    /// Returns the finalized entry address for the publish-slot record.
    fn entry_addr(&self) -> usize {
        self.body.finalized_function().code_ptr().as_ptr() as usize
    }
}

/// The outcome of preparing a chain promotion for one def-site.
enum ChainPreparation {
    /// The chain resolved, validated, and lowered; ready to finalize.
    Ready(Box<PreparedChain>),
    /// A candidate binding is not forced yet; retry after more applications.
    Transient,
    /// The def-site can never lower as a fused chain.
    Structural,
}

/// A fully resolved and lowered chain, pending finalize-and-publish.
struct PreparedChain {
    self_upval: (u32, u32),
    root_pattern: IrId,
    root_body: IrId,
    pinned: Vec<Tier2PinIdentity>,
    lowering: JitTier2ChainLowering,
}

/// One callee-chain candidate discovered in an innermost chain body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChainHeadCandidate {
    upval: (u32, u32),
    arity: u32,
}

impl NixJitTier1Engine {
    /// Attempts to promote an apply-seam def-site as a fused curried chain.
    ///
    /// Called after the unary tier-2 lowering failed for this def-site; see
    /// the [module docs](self) for the discovery, validation, and gating
    /// rules.
    pub(super) fn promote_tier2_chain(
        &self,
        eval: &mut TreeWalk,
        key: u64,
        lambda: &EvalLambda,
    ) -> Tier2ApplyHook {
        let prepared = match self.prepare_tier2_chain(eval, lambda) {
            ChainPreparation::Ready(prepared) => prepared,
            ChainPreparation::Transient => {
                self.reset_tier2_count(key);
                return continued_hook(false, false, false);
            }
            ChainPreparation::Structural => {
                return self.blacklist_tier2(eval, key, lambda);
            }
        };

        // Only a self-recursive chain amortizes the boundary harness at the
        // apply seam (non-recursive fold operators go through the fold seam),
        // and only a body with real inline compute beats the transition cost.
        if prepared.lowering.self_call_count() == 0
            || !estimate_tier1_body_cost(prepared.lowering.inner())
                .is_profitable(TIER2_MIN_NATIVE_INSTS)
        {
            return self.blacklist_tier2(eval, key, lambda);
        }

        let arity = prepared.lowering.arity();
        let Some((finalized_body, keep_alive)) = self.finalize_tier2_chain(prepared.lowering)
        else {
            self.reset_tier2_count(key);
            return continued_hook(false, false, false);
        };
        let entry = NixJitTier2ChainEntry {
            body: Rc::new(finalized_body),
            _keep_alive: keep_alive,
            arity,
            self_upval: prepared.self_upval,
            root_pattern: prepared.root_pattern,
            root_body: prepared.root_body,
            pinned: prepared.pinned,
        };
        // Verify once at promotion that the dispatch guard passes for the
        // promoting application, so a spine that can never match is not
        // published; the failure is transient, so the count resets.
        if chain_guard_argv(eval, lambda, &entry).is_none() {
            self.reset_tier2_count(key);
            return continued_hook(false, false, false);
        }
        let entry_addr = entry.entry_addr();
        if eval
            .install_and_publish_tier2_def_site_slot(key, OpaqueTier1Slot::new(entry_addr, Box::new(entry)))
        {
            continued_hook(true, false, false)
        } else {
            continued_hook(false, false, false)
        }
    }

    /// Resolves, validates, and lowers one def-site's fused chain.
    fn prepare_tier2_chain(&self, eval: &TreeWalk, lambda: &EvalLambda) -> ChainPreparation {
        let Some(ir) = eval.tier1_module_ir(lambda.module()) else {
            return ChainPreparation::Structural;
        };
        let arena = &ir.arena;
        let mut candidates = Vec::new();
        collect_chain_head_candidates(arena, lambda.body(), &mut candidates);
        if candidates.is_empty() {
            return ChainPreparation::Structural;
        }
        let frames = lambda.env().frames();
        let frame_count = frames.len();

        // Find the self-callee: the candidate whose resolved closure's own
        // curried chain walks back down to exactly this def-site.
        let mut root = None;
        let mut saw_transient = false;
        for candidate in &candidates {
            let (depth, slot) = candidate.upval;
            if depth == 0 || depth as usize > frame_count {
                continue;
            }
            let Ok(raw) = frames[frame_count - depth as usize].get(slot) else {
                continue;
            };
            let Some(resolved) = eval.tier2_peek_forced(raw) else {
                saw_transient = true;
                continue;
            };
            let Some(resolved_lambda) = eval.tier2_clone_lambda(resolved) else {
                continue;
            };
            if resolved_lambda.module() != lambda.module() {
                continue;
            }
            let Ok(scan) = scan_tier2_curried_chain(
                arena,
                resolved_lambda.pattern(),
                resolved_lambda.body(),
            ) else {
                continue;
            };
            if scan.arity() == candidate.arity
                && scan.inner_pattern() == lambda.pattern()
                && scan.inner_body() == lambda.body()
            {
                root = Some((candidate.upval, resolved_lambda, scan));
                break;
            }
        }
        let Some((self_upval, root_lambda, scan)) = root else {
            return if saw_transient {
                ChainPreparation::Transient
            } else {
                ChainPreparation::Structural
            };
        };

        // Classify the remaining callee sites as pinned callees.
        let mut pinned = Vec::new();
        let mut pinned_callees = Vec::new();
        for site in scan.callee_sites() {
            if site.upval == self_upval {
                if site.arity != scan.arity() {
                    return ChainPreparation::Structural;
                }
                continue;
            }
            let (depth, slot) = site.upval;
            if depth as usize > frame_count {
                return ChainPreparation::Structural;
            }
            let Ok(raw) = frames[frame_count - depth as usize].get(slot) else {
                return ChainPreparation::Structural;
            };
            let Some(resolved) = eval.tier2_peek_forced(raw) else {
                return ChainPreparation::Transient;
            };
            let Some(pin_lambda) = eval.tier2_clone_lambda(resolved) else {
                return ChainPreparation::Structural;
            };
            if pin_lambda.module() != lambda.module() {
                return ChainPreparation::Structural;
            }
            let Ok(callee_body) = scan_tier2_pinned_callee(
                arena,
                pin_lambda.pattern(),
                pin_lambda.body(),
                site.arity,
            ) else {
                return ChainPreparation::Structural;
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

        let budget = self.tier2.borrow().budget;
        let Ok(lowering) =
            lower_tier2_curried_chain(arena, &scan, Some(self_upval), &pinned_callees, budget)
        else {
            return ChainPreparation::Structural;
        };
        ChainPreparation::Ready(Box::new(PreparedChain {
            self_upval,
            root_pattern: root_lambda.pattern(),
            root_body: root_lambda.body(),
            pinned,
            lowering,
        }))
    }

    /// Finalizes a chain lowering into the engine's shared JIT module.
    pub(super) fn finalize_tier2_chain(
        &self,
        lowering: JitTier2ChainLowering,
    ) -> Option<(JitModuleContextFinalizedBody, JitModuleContextKeepAlive)> {
        let mut context_slot = self.context.borrow_mut();
        if context_slot.is_none() {
            match JitModuleContext::with_candidates(&self.candidates) {
                Ok(context) => *context_slot = Some(context),
                Err(_) => return None,
            }
        }
        let context = context_slot.as_ref()?;
        match context.define_and_finalize_tier2_chain(lowering) {
            Ok(finalized_body) => Some((finalized_body, context.keep_alive())),
            Err(_) => None,
        }
    }
}

/// Checks every chain dispatch guard and extracts the outer-argument run.
///
/// Returns the argv prefix (chain parameters `0..K-1`, read from the last
/// `K-1` captured argument frames) with the last slot left for the boundary
/// argument, or `None` when any guard fails (see the [module docs](self)).
pub(super) fn chain_guard_argv(
    eval: &TreeWalk,
    lambda: &EvalLambda,
    entry: &NixJitTier2ChainEntry,
) -> Option<[Value; TIER2_MAX_CHAIN_ARITY as usize]> {
    let arity = entry.arity as usize;
    if arity < 2 || arity > TIER2_MAX_CHAIN_ARITY as usize {
        return None;
    }
    let frames = lambda.env().frames();
    let frame_count = frames.len();
    let outer = arity - 1;
    if frame_count < outer {
        return None;
    }
    let prefix_len = frame_count - outer;

    // Self-callee def-site identity.
    let (depth, slot) = entry.self_upval;
    if depth == 0 || depth as usize > frame_count {
        return None;
    }
    let raw = frames[frame_count - depth as usize].get(slot).ok()?;
    let resolved = eval.tier2_peek_forced(raw)?;
    let root = eval.tier2_clone_lambda(resolved)?;
    if root.module() != lambda.module()
        || root.pattern() != entry.root_pattern
        || root.body() != entry.root_body
    {
        return None;
    }
    // Environment-prefix identity: the applied closure's captured frames are
    // the root's captured frames plus the K-1 argument frames.
    let root_frames = root.env().frames();
    if root_frames.len() != prefix_len {
        return None;
    }
    if !root_frames
        .iter()
        .zip(frames[..prefix_len].iter())
        .all(|(left, right)| Arc::ptr_eq(left, right))
    {
        return None;
    }
    // Pinned callee def-site identities.
    for pin in &entry.pinned {
        let (depth, slot) = pin.upval;
        if depth == 0 || depth as usize > frame_count {
            return None;
        }
        let raw = frames[frame_count - depth as usize].get(slot).ok()?;
        let resolved = eval.tier2_peek_forced(raw)?;
        let pin_lambda = eval.tier2_clone_lambda(resolved)?;
        if pin_lambda.module() != lambda.module()
            || pin_lambda.pattern() != pin.pattern
            || pin_lambda.body() != pin.body
        {
            return None;
        }
    }

    let mut argv = [Value::null(); TIER2_MAX_CHAIN_ARITY as usize];
    for (index, argument) in argv.iter_mut().enumerate().take(outer) {
        *argument = frames[prefix_len + index].get(0).ok()?;
    }
    Some(argv)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use ratchet_core::Ir;
    use ratchet_oracle::eval::EvalStats;
    use ratchet_oracle::eval::tree_walk::{TreeWalk, TreeWalkOptions};
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
        let ir = lower(source);
        let mut options = TreeWalkOptions::default();
        options.set_jit_tier1_publish_enabled(true);
        let mut eval = TreeWalk::with_options(&ir, options);
        eval.set_tier1_engine(Rc::new(NixJitTier1Engine::new().expect("engine builds")));
        let result = eval.eval_root().expect("tier-2 evaluation succeeds");
        let stats = eval.stats();
        (result, stats)
    }

    /// The canonical Takeuchi function promotes as an arity-3 fused chain,
    /// dispatches natively, and matches the oracle with zero deopts.
    #[test]
    fn tak_promotes_dispatches_and_matches_the_oracle() {
        let source = "let tak = x: y: z: if y < x then \
             tak (tak (x - 1) y z) (tak (y - 1) z x) (tak (z - 1) x y) \
             else z; in tak 12 6 3";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "fused tak changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_promoted() >= 1,
            "tak's inner def-site must promote, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "tak must dispatch natively, got {stats:?}"
        );
        assert_eq!(
            stats.tier2_deopted(),
            0,
            "an all-integer tak must never deopt, got {stats:?}"
        );
    }

    /// An arity-2 recursion promotes as a fused chain and matches the oracle.
    ///
    /// The fixture forces each level's result (`1 + ...`) so the oracle's
    /// interpreted run stays shallow enough for the debug test-thread stack —
    /// a tail recursion with a lazy accumulator piles up a nested thunk chain
    /// whose final force overflows it (a pre-existing interpreter depth
    /// limit, unrelated to the fused chain). The native side handles far
    /// deeper runs within its 1024-frame budget.
    #[test]
    fn arity_two_accumulator_recursion_promotes_and_matches() {
        let source =
            "let addTo = a: n: if n < 1 then a else 1 + addTo a (n - 1); in addTo 5 16";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(oracle.raw_eq(native));
        assert!(
            stats.tier2_promoted() >= 1,
            "sumTo must promote as a fused chain, got {stats:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "sumTo must dispatch natively, got {stats:?}"
        );
    }

    /// A float argument fails the compiled chain's integer guards, deopts,
    /// and the interpreted re-run reproduces the oracle's exact value.
    #[test]
    fn float_chain_argument_deopts_to_the_tree_walk() {
        let source = "let tak = x: y: z: if y < x then \
             tak (tak (x - 1) y z) (tak (y - 1) z x) (tak (z - 1) x y) \
             else z; in tak 12 6 3 + builtins.floor (tak 6.5 4.5 2.5)";
        let oracle = eval_oracle(source);
        let (native, stats) = eval_with_tier2(source);

        assert!(
            oracle.raw_eq(native),
            "chain float deopt changed a result: oracle {oracle:?} vs native {native:?}"
        );
        assert!(
            stats.tier2_dispatched() >= 1,
            "the integer calls must dispatch, got {stats:?}"
        );
        assert!(
            stats.tier2_deopted() >= 1,
            "the float chain calls must deopt, got {stats:?}"
        );
    }

    /// An escaped partial application still dispatches correctly: the guard
    /// verifies the actual argument-frame spine, and `p 3` is exactly
    /// `sub 10 3` under it.
    #[test]
    fn escaped_partial_application_matches_the_oracle() {
        let source = "let sub = a: n: if n < 1 then a else sub (a - 1) (n - 1); \
             p = sub 10; \
             count = c: k: if k < 1 then c else p 3 + count c (k - 1); \
             in count 0 12";
        let oracle = eval_oracle(source);
        let (native, _stats) = eval_with_tier2(source);
        assert!(
            oracle.raw_eq(native),
            "escaped partial changed a result: oracle {oracle:?} vs native {native:?}"
        );
    }
}

/// Collects `(upvalue, chain-length)` candidates from a chain body.
///
/// A permissive pre-pass for root discovery only: it walks the shapes the
/// fused grammar can contain, flattens every `Apply` chain headed by an
/// upvalue read, and ignores anything else (an unsupported node simply fails
/// the authoritative scan later).
fn collect_chain_head_candidates(
    arena: &IrArena,
    id: IrId,
    candidates: &mut Vec<ChainHeadCandidate>,
) {
    let Some(node) = arena.node(id).copied() else {
        return;
    };
    match (node.kind, node.data) {
        (IrKind::BinOp, IrData::Binary { lhs, rhs, .. }) => {
            collect_chain_head_candidates(arena, lhs, candidates);
            collect_chain_head_candidates(arena, rhs, candidates);
        }
        (
            IrKind::If,
            IrData::Triple {
                first,
                second,
                third,
            },
        ) => {
            collect_chain_head_candidates(arena, first, candidates);
            collect_chain_head_candidates(arena, second, candidates);
            collect_chain_head_candidates(arena, third, candidates);
        }
        (IrKind::ThunkAlloc, IrData::Node(inner)) => {
            collect_chain_head_candidates(arena, inner, candidates);
        }
        (IrKind::Apply, _) => {
            let mut arguments = Vec::new();
            let mut cursor = id;
            loop {
                let Some(chain_node) = arena.node(cursor).copied() else {
                    return;
                };
                match (chain_node.kind, chain_node.data) {
                    (IrKind::Apply, IrData::Pair { first, second }) => {
                        arguments.push(second);
                        cursor = first;
                    }
                    (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
                        let candidate = ChainHeadCandidate {
                            upval: (depth, slot),
                            arity: arguments.len() as u32,
                        };
                        if !candidates.contains(&candidate) {
                            candidates.push(candidate);
                        }
                        break;
                    }
                    _ => break,
                }
            }
            for argument in arguments {
                collect_chain_head_candidates(arena, argument, candidates);
            }
        }
        _ => {}
    }
}
