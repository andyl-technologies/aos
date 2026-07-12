//! Dead-binding value elision (doc 26 §2.4).
//!
//! A `let` binding proven never demanded on any path (cardinality
//! [`Cardinality::Absent`](super::Cardinality)) has its value node replaced in
//! place by `null` through the arena-stable
//! [`super::IrArena::set_node`] primitive. The binding — and its frame slot — is
//! left in place, so the frame layout is unchanged (elision without compaction);
//! slot compaction rides with full beta-reduction (design note §9). The dead
//! value subtree becomes unreachable and is not encoded, compiled, or evaluated.
//!
//! The admittance decision is delegated entirely to the vetted
//! [`dead_binding_elimination_plan`]: a binding is elided only when it is
//! `Absent`, not proven strict, has a static key, and its value edges are safe
//! to omit — the exact set the tree-walk evaluator already skips at runtime, so
//! the IR-level rewrite makes the same parity-safe decision structurally. Because
//! the binding is never demanded, replacing its value with `null` (never forced)
//! is observationally invisible even when the original value was effectful or
//! divergent.

use crate::analysis::{annotate_cardinality, dead_binding_elimination_plan};

use super::{
    EffectClass, Ir, IrData, IrId, IrKind, PassOutcome, SimplifyError, SimplifyPass, SimplifyPhase,
};

/// The dead-binding value-elision pass.
///
/// See the [module documentation](self) for the transform and its soundness
/// argument. This is a zero-sized pass with no configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeadBindingElim;

impl SimplifyPass for DeadBindingElim {
    fn name(&self) -> &'static str {
        "dead-binding-elim"
    }

    fn runs_in(&self, phase: SimplifyPhase) -> bool {
        matches!(phase, SimplifyPhase::Main | SimplifyPhase::Final)
    }

    fn run(&self, ir: &mut Ir) -> Result<PassOutcome, SimplifyError> {
        // Refresh cardinality facts so `Absent` bindings can be proven;
        // conservative facts (many-use, not-demanded strictness) prove nothing.
        // Analysis or plan failure declines the pass.
        if annotate_cardinality(ir).is_err() {
            return Ok(PassOutcome::Unchanged);
        }
        let Ok(plan) = dead_binding_elimination_plan(ir) else {
            return Ok(PassOutcome::Unchanged);
        };
        let targets: Vec<IrId> = plan
            .eliminations()
            .iter()
            .map(|elimination| elimination.value())
            .collect();

        let mut changed = false;
        for value in targets {
            let Some(node) = ir.arena.node(value) else {
                continue;
            };
            if node.kind == IrKind::Null {
                continue;
            }
            if ir
                .arena
                .set_node(value, IrKind::Null, EffectClass::pure(), IrData::None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{lower, simplify_with_passes};
    use crate::scope::resolve;
    use crate::syntax::parse_str;

    fn lower_source(source: &str) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        lower(resolved).expect("source lowers")
    }

    fn frame_slot_counts(ir: &Ir) -> Vec<u32> {
        ir.frames.iter().map(|frame| frame.slot_count).collect()
    }

    fn binding_value_kinds(ir: &Ir) -> Vec<IrKind> {
        let IrData::Let { bindings, .. } = ir.arena.node(ir.root).expect("root is a let").data
        else {
            panic!("root is a let");
        };
        let start = bindings.start as usize;
        let end = start + bindings.len();
        ir.bindings[start..end]
            .iter()
            .map(|binding| ir.arena.node(binding.value).expect("value exists").kind)
            .collect()
    }

    #[test]
    fn elides_absent_binding_value_and_preserves_frame_layout() {
        // `dead` is never demanded; `used` is the result. The dead binding's
        // value is replaced by null; the slot count is unchanged.
        let mut ir = lower_source("let used = 1; dead = 2 + 3; in used");
        let slots_before = frame_slot_counts(&ir);
        simplify_with_passes(&mut ir, &[&DeadBindingElim]).expect("elision succeeds");
        let kinds = binding_value_kinds(&ir);
        assert!(
            kinds.contains(&IrKind::Null),
            "the dead binding's value is elided to null: {kinds:?}"
        );
        assert_eq!(
            slots_before,
            frame_slot_counts(&ir),
            "frame slot layout is unchanged (elision without compaction)"
        );
    }

    #[test]
    fn retains_demanded_bindings() {
        // Both bindings are demanded by the body; nothing is elided.
        let mut ir = lower_source("let a = 1; b = 2; in a + b");
        simplify_with_passes(&mut ir, &[&DeadBindingElim]).expect("simplify succeeds");
        assert!(
            !binding_value_kinds(&ir).contains(&IrKind::Null),
            "a demanded binding must not be elided"
        );
    }
}
