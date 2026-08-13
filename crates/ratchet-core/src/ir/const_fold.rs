//! Constant folding: the first IR-to-IR simplifier pass (doc 26 §2.2).
//!
//! Folds a `BinOp` or `UnaryOp` whose operands are all literal nodes to a single
//! literal, when the operation is *total* for those literals. The fold is
//! observationally invisible: it replaces a node in place through the
//! arena-stable [`super::IrArena::set_node`] primitive (preserving the node's
//! `IrId` and span), and the folded literal evaluates to exactly the value the
//! operation would have produced.
//!
//! This first cut is deliberately conservative — it folds only the cases that
//! are unambiguously total and free of Nix's string-context, numeric-tower, and
//! partiality hazards (design note §2.1):
//!
//! - integer arithmetic `+ - *` over two `Int` literals, declining on overflow;
//! - integer comparisons `< > <= >= == !=` over two `Int` literals;
//! - boolean `&& || ->` and `== !=` over two `Bool` literals;
//! - unary `!` on a `Bool` literal and `-` on an `Int` literal (declining on
//!   `i64::MIN` negation overflow).
//!
//! Everything else declines: division and modulo (partiality/semantics),
//! string/path concatenation (`+` carries string context that must be unioned),
//! list/attrset operators, float operands (numeric tower), and any operand that
//! is not a literal. Declining is always parity-safe: the evaluator computes the
//! same value at runtime. A CLI/system-sensitive builtin can never be a literal
//! operand, so it is unreachable here; the guard for it lives on the passes that
//! propagate builtin values.

use crate::syntax::{BinOpKind, UnaryOpKind};

use super::{Ir, IrData, IrId, IrKind, PassOutcome, SimplifyError, SimplifyPass, SimplifyPhase};

/// The constant-folding pass.
///
/// See the [module documentation](self) for the fold set and its soundness
/// argument. This is a zero-sized pass with no configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConstFold;

impl SimplifyPass for ConstFold {
    fn name(&self) -> &'static str {
        "const-fold"
    }

    fn runs_in(&self, phase: SimplifyPhase) -> bool {
        matches!(phase, SimplifyPhase::Gentle | SimplifyPhase::Main)
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
            // Never fold an effectful node; the fold set only reaches pure
            // arithmetic/logic, but the speculability gate is the binding
            // soundness floor (doc 26 §1).
            if !node.effect.is_speculable() {
                continue;
            }
            let Some((kind, data)) = fold(ir, &node.data) else {
                continue;
            };
            if ir.arena.set_node(id, kind, node.effect, data) {
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

/// Folds one node's payload to a literal `(kind, data)`, or `None` to decline.
///
/// Because operands are visited in arena (allocation) order and lowering emits
/// operands before their parent, a nested expression folds fully in one sweep:
/// an inner node is already a literal by the time its parent is visited.
fn fold(ir: &Ir, data: &IrData) -> Option<(IrKind, IrData)> {
    match *data {
        IrData::Binary { op, lhs, rhs } => fold_binary(ir, op, lhs, rhs),
        IrData::Unary { op, operand } => fold_unary(ir, op, operand),
        _ => None,
    }
}

fn fold_binary(ir: &Ir, op: BinOpKind, lhs: IrId, rhs: IrId) -> Option<(IrKind, IrData)> {
    if let (Some(a), Some(b)) = (int_literal(ir, lhs), int_literal(ir, rhs)) {
        return match op {
            BinOpKind::Add => a.checked_add(b).map(int_node),
            BinOpKind::Sub => a.checked_sub(b).map(int_node),
            BinOpKind::Mul => a.checked_mul(b).map(int_node),
            BinOpKind::Lt => Some(bool_node(a < b)),
            BinOpKind::Gt => Some(bool_node(a > b)),
            BinOpKind::Le => Some(bool_node(a <= b)),
            BinOpKind::Ge => Some(bool_node(a >= b)),
            BinOpKind::Eq => Some(bool_node(a == b)),
            BinOpKind::Ne => Some(bool_node(a != b)),
            _ => None,
        };
    }
    if let (Some(a), Some(b)) = (bool_literal(ir, lhs), bool_literal(ir, rhs)) {
        // `&&`/`||`/`->` short-circuit, but literal operands carry no effect to
        // skip, so folding them is invisible.
        return match op {
            BinOpKind::And => Some(bool_node(a && b)),
            BinOpKind::Or => Some(bool_node(a || b)),
            BinOpKind::Impl => Some(bool_node(!a || b)),
            BinOpKind::Eq => Some(bool_node(a == b)),
            BinOpKind::Ne => Some(bool_node(a != b)),
            _ => None,
        };
    }
    None
}

fn fold_unary(ir: &Ir, op: UnaryOpKind, operand: IrId) -> Option<(IrKind, IrData)> {
    match op {
        UnaryOpKind::Not => bool_literal(ir, operand).map(|value| bool_node(!value)),
        UnaryOpKind::Neg => int_literal(ir, operand)
            .and_then(i64::checked_neg)
            .map(int_node),
    }
}

fn int_literal(ir: &Ir, id: IrId) -> Option<i64> {
    match ir.arena.node(id)?.data {
        IrData::Int(value) => Some(value),
        _ => None,
    }
}

fn bool_literal(ir: &Ir, id: IrId) -> Option<bool> {
    match ir.arena.node(id)?.data {
        IrData::Bool(value) => Some(value),
        _ => None,
    }
}

fn int_node(value: i64) -> (IrKind, IrData) {
    (IrKind::Int, IrData::Int(value))
}

fn bool_node(value: bool) -> (IrKind, IrData) {
    (IrKind::Bool, IrData::Bool(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{lower, render_ir, simplify_with_passes};
    use crate::scope::resolve;
    use crate::syntax::parse_str;

    fn fold_source(source: &str) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        let mut ir = lower(resolved).expect("source lowers");
        simplify_with_passes(&mut ir, &[&ConstFold]).expect("fold succeeds");
        ir
    }

    fn root_data(ir: &Ir) -> IrData {
        ir.arena.node(ir.root).expect("root node exists").data
    }

    #[test]
    fn folds_integer_arithmetic_including_nested() {
        assert_eq!(root_data(&fold_source("1 + 2")), IrData::Int(3));
        assert_eq!(root_data(&fold_source("7 - 2")), IrData::Int(5));
        assert_eq!(root_data(&fold_source("(1 + 2) * 3")), IrData::Int(9));
        assert_eq!(root_data(&fold_source("1 + 2 * 3 - 4")), IrData::Int(3));
        assert_eq!(root_data(&fold_source("- (2 + 3)")), IrData::Int(-5));
    }

    #[test]
    fn folds_integer_comparisons_and_boolean_logic() {
        assert_eq!(root_data(&fold_source("1 < 2")), IrData::Bool(true));
        assert_eq!(root_data(&fold_source("2 <= 2")), IrData::Bool(true));
        assert_eq!(root_data(&fold_source("3 == 4")), IrData::Bool(false));
        assert_eq!(
            root_data(&fold_source("true && false")),
            IrData::Bool(false)
        );
        assert_eq!(root_data(&fold_source("false || true")), IrData::Bool(true));
        assert_eq!(root_data(&fold_source("!false")), IrData::Bool(true));
    }

    #[test]
    fn declines_partial_context_and_non_literal_operations() {
        // Division, string concat, float, non-literal operands, and list concat
        // are left intact: nothing folds to a literal at the root.
        for source in [
            "6 / 2",
            "\"a\" + \"b\"",
            "1.0 + 2.0",
            "let x = 1; in x + 2",
            "[ 1 ] ++ [ 2 ]",
        ] {
            assert!(
                !matches!(
                    root_data(&fold_source(source)),
                    IrData::Int(_) | IrData::Bool(_)
                ),
                "`{source}` must not fold to a literal"
            );
        }
    }

    #[test]
    fn declines_on_integer_overflow() {
        let source = "9223372036854775807 + 1";
        assert!(
            matches!(root_data(&fold_source(source)), IrData::Binary { .. }),
            "overflowing addition must decline, not wrap"
        );
    }

    #[test]
    fn golden_render_folds_arithmetic_root() {
        let parsed = parse_str("1 + 2 * 3").expect("parses");
        let mut ir = lower(resolve(parsed).expect("resolves")).expect("lowers");
        let before = render_ir(&ir);
        simplify_with_passes(&mut ir, &[&ConstFold]).expect("fold succeeds");
        let after = render_ir(&ir);
        assert_ne!(before, after, "the render changes when a fold fires");
        // The root (last-lowered node) becomes the folded literal 7.
        assert!(
            after
                .lines()
                .last()
                .is_some_and(|line| line.contains("Int(7)")),
            "the root folds to Int(7):\n{after}"
        );
    }
}
