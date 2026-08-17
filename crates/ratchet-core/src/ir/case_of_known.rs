//! Case-of-known: fold `if` on a statically-known boolean (doc 26 §2.3).
//!
//! When an `If` node's condition is a `Bool` literal, the conditional collapses
//! to its taken branch: the `If` node is replaced in place (arena-stable
//! [`super::IrArena::set_node`], preserving its `IrId` and span) with a copy of
//! the taken branch's node, and the untaken branch becomes unreachable. This is
//! GHC's case-of-known-constructor specialized to Nix `if`.
//!
//! Dropping the untaken branch is sound even when that branch is effectful or
//! divergent: on the taken path it was never going to be evaluated, so removing
//! it cannot change which expressions are forced (doc 26 §2.3). The folded node
//! inherits the *taken branch's* effect class, not the `If`'s, so a branch that
//! carries an effect keeps it.
//!
//! This first cut folds only `if`. The `Select`/`HasAttr`-on-a-known-`AttrSet`
//! cases (doc 26 §2.3) are deferred: they must reason about dynamic keys
//! (`has_dynamic`), `rec`/`__overrides` assembly order, missing-attribute error
//! observability, and inline-cache site accounting, and they mostly fire only
//! after inlining exposes a constructor at the use site.

use super::{Ir, IrData, IrId, IrKind, PassOutcome, SimplifyError, SimplifyPass, SimplifyPhase};

/// The case-of-known pass (currently `if`-on-known-boolean only).
///
/// See the [module documentation](self) for the fold set and its soundness
/// argument. This is a zero-sized pass with no configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaseOfKnown;

impl SimplifyPass for CaseOfKnown {
    fn name(&self) -> &'static str {
        "case-of-known"
    }

    fn runs_in(&self, phase: SimplifyPhase) -> bool {
        matches!(phase, SimplifyPhase::Main)
    }

    fn run(&self, ir: &mut Ir) -> Result<PassOutcome, SimplifyError> {
        let mut changed = false;
        let node_count = ir.arena.nodes().len();
        for index in 0..node_count {
            let Ok(raw) = u32::try_from(index) else {
                break;
            };
            let id = IrId::new(raw);
            let Some(node) = ir.arena.node(id).copied() else {
                continue;
            };
            if node.kind != IrKind::If || !node.effect.is_speculable() {
                continue;
            }
            let IrData::Triple {
                first: cond,
                second: then_branch,
                third: else_branch,
            } = node.data
            else {
                continue;
            };
            let Some(taken) = taken_branch(ir, cond, then_branch, else_branch) else {
                continue;
            };
            let Some(branch) = ir.arena.node(taken).copied() else {
                continue;
            };
            // The folded node becomes the taken branch, inheriting its kind,
            // effect, and payload; the `If`'s own (pure) effect is discarded.
            if ir
                .arena
                .set_node(id, branch.kind, branch.effect, branch.data)
            {
                changed = true;
            }
        }
        Ok(if changed {
            PassOutcome::Rewritten
        } else {
            PassOutcome::Unchanged
        })
    }
}

/// Returns the branch selected by a known boolean condition, or `None` when the
/// condition is not a `Bool` literal.
fn taken_branch(ir: &Ir, cond: IrId, then_branch: IrId, else_branch: IrId) -> Option<IrId> {
    match ir.arena.node(cond)?.data {
        IrData::Bool(true) => Some(then_branch),
        IrData::Bool(false) => Some(else_branch),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConstFold, lower, simplify_with_passes};
    use crate::scope::resolve;
    use crate::syntax::parse_str;

    fn simplify(source: &str, passes: &[&dyn SimplifyPass]) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        let mut ir = lower(resolved).expect("source lowers");
        simplify_with_passes(&mut ir, passes).expect("simplify succeeds");
        ir
    }

    fn root_data(ir: &Ir) -> IrData {
        ir.arena.node(ir.root).expect("root node exists").data
    }

    #[test]
    fn folds_if_on_known_boolean() {
        assert_eq!(
            root_data(&simplify("if true then 1 else 2", &[&CaseOfKnown])),
            IrData::Int(1)
        );
        assert_eq!(
            root_data(&simplify("if false then 1 else 2", &[&CaseOfKnown])),
            IrData::Int(2)
        );
    }

    #[test]
    fn declines_if_on_unknown_condition() {
        // A variable condition is not a known boolean: the `if` stays intact.
        let ir = simplify("x: if x then 1 else 2", &[&CaseOfKnown]);
        // The lambda body is the `if`; find it and confirm it is still a Triple.
        let has_if = ir
            .arena
            .nodes()
            .iter()
            .any(|node| node.kind == IrKind::If && matches!(node.data, IrData::Triple { .. }));
        assert!(has_if, "an `if` on an unknown condition must not be folded");
    }

    #[test]
    fn constant_folding_exposes_case_of_known() {
        // ConstFold folds `1 < 2` to `true`, which CaseOfKnown then uses to pick
        // the taken branch — the "expose before exploit" interaction.
        let ir = simplify("if 1 < 2 then 10 else 20", &[&ConstFold, &CaseOfKnown]);
        assert_eq!(root_data(&ir), IrData::Int(10));
        let ir = simplify("if 3 > 4 then 10 else 20", &[&ConstFold, &CaseOfKnown]);
        assert_eq!(root_data(&ir), IrData::Int(20));
    }
}
