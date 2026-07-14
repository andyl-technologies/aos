//! The simplifier: a memoized fixpoint of pure IR-to-IR passes.
//!
//! This module owns the *driver* of the RFC-0007 optimization pass catalog
//! (`docs/rfcs/0007-nix-evaluator/26-optimization-pass-catalog.md` §1, §3): a
//! GHC-style Core-to-Core pipeline that runs a set of passes iteratively to a
//! per-phase fixpoint. Each pass is, formally, a pure `IR -> IR` transform that
//! must be *observably transparent* with respect to Nix semantics — the
//! soundness floor of doc 26 §1.
//!
//! # Status: passes registered, flag-gated
//!
//! The stage-1 skeleton (the phased fixpoint driver, the [`SimplifyPass`]
//! contract, the phase ordering, and the pass registry) is complete, and the
//! doc-26 pass set is **registered** ([`REGISTERED_PASSES`]: constant folding,
//! case-of-known, literal-apply beta-reduction, single-use let-inline, and
//! dead-binding elision). The whole set is still **off by default**, gated by
//! `AOS_NIX_SIMPLIFY` at the parse pipeline's persistence seam; while gated,
//! the flag is part of the parse-cache *key* (`ParseCacheFlags::simplify`) so
//! simplify-on and simplify-off processes never share lowered-IR entries.
//! Default-on promotion bumps [`PASS_SET_VERSION`] behind the byte-parity
//! gate; see
//! `docs/rfcs/0007-nix-evaluator/design-notes/simplifier-implementation-plan.md`
//! (§4 staging, §8 decisions).
//!
//! # Where rewrites live
//!
//! Per decision D4 (design note §8), the driver lives here in the `ir` module,
//! alongside the arena, so a rewriting pass can use the arena's crate-internal
//! rewrite primitive without widening its visibility for another crate. The
//! first pass adds that primitive next to [`super::IrArena`]; the driver itself
//! is representation-agnostic and does not touch arena internals.
//!
//! # Cache coherence
//!
//! The driver runs inside the lowering to persistence seam of the parse cache,
//! so the persisted `ir.bin` and its [`super::Ir`] fingerprint reflect the
//! simplified IR. [`PASS_SET_VERSION`] is folded into the parse-cache fingerprint
//! domain (decision D2) so that changing the pass set is a clean cold miss for
//! the fact sidecar, the JIT compiled-body cache, and the source-less eval memo
//! key. While the pass set is empty the version is `0` and is not folded, so the
//! skeleton is a true no-op.

use thiserror::Error;

use super::{
    BetaReduceApply, CaseOfKnown, ConstFold, DeadBindingElim, InlineSingleUse, Ir, IrError,
    annotate_ir,
};

/// The version of the registered simplifier pass set.
///
/// `0` denotes the empty pass set of the stage-1 skeleton. Bump this whenever a
/// pass is added, enabled by default, or changed in a way that can alter its
/// output. It is folded into the parse-cache lowered-IR fingerprint domain (only
/// when non-zero, so version `0` preserves the pre-simplifier fingerprint), which
/// coherently shifts the fact sidecar, JIT compiled-body, and source-less eval
/// memo keys on a pass-set change.
///
/// While a pass is still flag-gated (not yet default-on) *and* the seam persists
/// its simplified output to `ir.bin`, the enable flag must additionally enter the
/// parse-cache *key* (the entry directory), so a flag-on write and a flag-off
/// read cannot collide on the same source-keyed entry. That segregation is
/// unnecessary while the pass set is empty (the driver is the identity regardless
/// of the flag) and is added with the first pass.
pub const PASS_SET_VERSION: u32 = 0;

/// The per-phase fixpoint iteration cap (decision `M-24`).
///
/// A phase that keeps finding work past this many sweeps stops rewriting and
/// yields to the next phase rather than spinning. Non-convergence degrades to
/// "stop rewriting" — the phase yields silently rather than erroring; surfacing
/// it (an eval-stats counter) is deferred to the first pass that can reach the
/// cap, since the empty stage-1 pass set never iterates.
pub const SIMPLIFY_MAX_ITERS: usize = 4;

/// A pass-ordering phase, run gentle to final (doc 26 §3).
///
/// Cheap reductions that *reveal* structure run in [`SimplifyPhase::Gentle`]; the
/// analyses settle and the full interleave runs in [`SimplifyPhase::Main`]; the
/// heuristic, layout-shaping passes run in [`SimplifyPhase::Final`] once the
/// graph is stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SimplifyPhase {
    /// Conservative, cheap reductions that clean the graph for later analyses.
    Gentle,
    /// The full interleave of reductions and analyses.
    Main,
    /// Heuristic, IR-growing, layout-shaping passes.
    Final,
}

impl SimplifyPhase {
    /// The phases in driver order.
    pub const ORDER: [SimplifyPhase; 3] = [Self::Gentle, Self::Main, Self::Final];
}

/// Whether a pass rewrote the IR on one invocation.
///
/// The driver uses this to detect a per-phase fixpoint: a sweep in which every
/// pass reports [`PassOutcome::Unchanged`] is a fixpoint for that phase. The
/// durable end-to-end equivalence proof is external — the byte-identical `.drv`
/// gate and the twice-run [`super::Ir`] fingerprint-equality corpus test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassOutcome {
    /// The pass left the IR unchanged.
    Unchanged,
    /// The pass rewrote the IR.
    Rewritten,
}

/// An error raised while applying a simplifier pass.
#[derive(Debug, Error)]
pub enum SimplifyError {
    /// A pass failed to rewrite the IR — for example, rebuilding the arena
    /// exceeded `u32` node/child addressability.
    #[error("simplifier pass `{pass}` failed to rewrite IR")]
    Pass {
        /// The [`SimplifyPass::name`] of the failing pass.
        pass: &'static str,
        /// The underlying IR construction error.
        #[source]
        source: IrError,
    },
}

/// A single IR-to-IR simplifier pass.
///
/// A pass is a pure transform over the lowered [`super::Ir`]: it may rewrite the
/// arena and side tables in place, but must be *observably transparent* with
/// respect to Nix semantics (doc 26 §1 soundness floor). A pass fires a rewrite
/// only when the licensing fact holds and the node is speculable
/// ([`super::EffectClass::is_speculable`]); it never folds a failing or effectful
/// node eagerly, and never makes a lazy binding strict without a positive proof.
pub trait SimplifyPass {
    /// A stable, human-readable identifier used in diagnostics and stats.
    fn name(&self) -> &'static str;

    /// Whether this pass participates in `phase`.
    fn runs_in(&self, phase: SimplifyPhase) -> bool;

    /// Whether this pass reads analysis facts (`ir.facts`) to make its decisions.
    ///
    /// When any pass in a phase returns `true`, the driver refreshes facts
    /// (`annotate_ir`) before each sweep of that phase, so a pass reads facts
    /// current for the IR it is about to rewrite. Structural passes that inspect
    /// only node shapes (e.g. constant folding) leave this `false` and pay no
    /// analysis cost. Defaults to `false`.
    fn needs_facts(&self) -> bool {
        false
    }

    /// Applies the pass once, rewriting `ir` in place.
    ///
    /// Returns whether the IR changed, so the driver can detect a fixpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SimplifyError`] if the rewrite cannot be represented — for
    /// example, if rebuilding the arena exceeds `u32` addressability.
    fn run(&self, ir: &mut Ir) -> Result<PassOutcome, SimplifyError>;
}

/// The registered simplifier pass set.
///
/// Passes are registered here as they land, each behind the off-by-default
/// `AOS_NIX_SIMPLIFY` gate and its own byte-parity check; [`PASS_SET_VERSION`] is
/// bumped when a pass is promoted to run by default. [`ConstFold`] (doc 26 §2.2)
/// and [`CaseOfKnown`] (doc 26 §2.2, §2.3) are the registered passes; both are
/// sound (observationally invisible), so the registered set preserves every
/// observable result even though it is no longer the identity on IR that
/// contains foldable literals or statically-known conditionals.
pub const REGISTERED_PASSES: &[&dyn SimplifyPass] = &[
    &ConstFold,
    &CaseOfKnown,
    &BetaReduceApply,
    &InlineSingleUse,
    &DeadBindingElim,
];

/// Runs the registered simplifier passes over `ir` to a per-phase fixpoint.
///
/// With the empty stage-1 pass set this is the identity: `ir` is left unchanged.
///
/// # Returns
///
/// `true` when the driver refreshed analysis facts (`annotate_ir`) and left
/// `ir.facts` current at [`IR_ANALYSIS_VERSION`](super::IR_ANALYSIS_VERSION) for
/// the final IR, so a caller may persist them under that version instead of
/// recomputing on warm load; `false` when no fact-reading pass ran.
///
/// # Errors
///
/// Returns [`SimplifyError`] if a registered pass fails to rewrite the IR.
pub fn simplify_ir(ir: &mut Ir) -> Result<bool, SimplifyError> {
    simplify_with_passes(ir, REGISTERED_PASSES)
}

/// Runs `passes` over `ir` to a per-phase fixpoint, gentle to final.
///
/// For each phase in [`SimplifyPhase::ORDER`], the passes registered for that
/// phase are swept repeatedly until a sweep reports no change (a local fixpoint)
/// or the sweep count reaches [`SIMPLIFY_MAX_ITERS`]. A phase with no
/// participating pass is skipped entirely, so an empty pass set performs no work
/// and allocates nothing. Non-convergence degrades to "stop rewriting this
/// phase"; it is never an error.
///
/// When a phase contains a fact-reading pass ([`SimplifyPass::needs_facts`]),
/// the driver refreshes facts (`annotate_ir`) before each sweep so the pass
/// reads facts current for the IR it rewrites, and performs one final refresh so
/// the facts left in `ir.facts` are current for the fully simplified IR (see the
/// return value).
///
/// # Returns
///
/// Whether analysis facts were refreshed and left current (see [`simplify_ir`]).
///
/// # Errors
///
/// Returns [`SimplifyError`] if any pass fails to rewrite the IR.
pub fn simplify_with_passes(
    ir: &mut Ir,
    passes: &[&dyn SimplifyPass],
) -> Result<bool, SimplifyError> {
    let mut refreshed_facts = false;
    for phase in SimplifyPhase::ORDER {
        if !passes.iter().any(|pass| pass.runs_in(phase)) {
            continue;
        }
        let phase_needs_facts = passes
            .iter()
            .any(|pass| pass.runs_in(phase) && pass.needs_facts());
        // Non-convergence degrades to "stop rewriting this phase": the loop
        // exits once it has run `SIMPLIFY_MAX_ITERS` sweeps, never erroring and
        // never spinning unbounded. Surfacing a non-convergence signal (an
        // eval-stats counter) is deferred (design note §4, §8).
        for _ in 0..SIMPLIFY_MAX_ITERS {
            if phase_needs_facts && annotate_ir(ir).is_ok() {
                refreshed_facts = true;
            }
            let mut rewrote = false;
            for pass in passes.iter().filter(|pass| pass.runs_in(phase)) {
                if pass.run(ir)? == PassOutcome::Rewritten {
                    rewrote = true;
                }
            }
            if !rewrote {
                break;
            }
        }
    }
    // Leave `ir.facts` current at `IR_ANALYSIS_VERSION` for the final IR: a
    // fixpoint break already leaves them current, but a `MAX_ITERS` cutoff after
    // a rewrite would not, so refresh once more when any pass read facts.
    if refreshed_facts {
        refreshed_facts = annotate_ir(ir).is_ok();
    }
    Ok(refreshed_facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Ir, lower};
    use crate::scope::resolve;
    use crate::syntax::parse_str;
    use std::cell::Cell;

    fn lower_source(source: &str) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        lower(resolved).expect("source lowers")
    }

    /// A pass that counts its invocations and always reports `outcome`.
    struct CountingPass {
        outcome: PassOutcome,
        phase: SimplifyPhase,
        calls: Cell<usize>,
    }

    impl SimplifyPass for CountingPass {
        fn name(&self) -> &'static str {
            "counting-test-pass"
        }

        fn runs_in(&self, phase: SimplifyPhase) -> bool {
            phase == self.phase
        }

        fn run(&self, _ir: &mut Ir) -> Result<PassOutcome, SimplifyError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.outcome)
        }
    }

    #[test]
    fn empty_pass_set_is_the_identity() {
        let before = lower_source("let x = 1; in x + 2");
        let mut after = before.clone();
        simplify_with_passes(&mut after, &[]).expect("empty simplify succeeds");
        assert_eq!(before.arena.nodes(), after.arena.nodes());
        assert_eq!(before.arena.child_pool(), after.arena.child_pool());
        assert_eq!(before.root, after.root);
    }

    #[test]
    fn unchanged_pass_reaches_fixpoint_in_one_sweep() {
        let mut ir = lower_source("1");
        let pass = CountingPass {
            outcome: PassOutcome::Unchanged,
            phase: SimplifyPhase::Main,
            calls: Cell::new(0),
        };
        simplify_with_passes(&mut ir, &[&pass]).expect("simplify succeeds");
        assert_eq!(pass.calls.get(), 1, "an unchanged pass runs exactly one sweep");
    }

    #[test]
    fn always_rewriting_pass_is_capped_at_max_iters() {
        let mut ir = lower_source("1");
        let pass = CountingPass {
            outcome: PassOutcome::Rewritten,
            phase: SimplifyPhase::Gentle,
            calls: Cell::new(0),
        };
        simplify_with_passes(&mut ir, &[&pass]).expect("simplify succeeds");
        assert_eq!(
            pass.calls.get(),
            SIMPLIFY_MAX_ITERS,
            "a non-converging pass is capped at the iteration limit, not an error"
        );
    }

    #[test]
    fn phase_with_no_pass_is_skipped() {
        let mut ir = lower_source("1");
        let pass = CountingPass {
            outcome: PassOutcome::Rewritten,
            phase: SimplifyPhase::Final,
            calls: Cell::new(0),
        };
        // Only the Final phase has a pass; Gentle and Main are skipped without
        // touching the pass, and Final is capped.
        simplify_with_passes(&mut ir, &[&pass]).expect("simplify succeeds");
        assert_eq!(pass.calls.get(), SIMPLIFY_MAX_ITERS);
    }
}
