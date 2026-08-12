//! Bottom-up per-node totality bits.
//!
//! `total(n)` means: evaluating node `n` in a demand position — including
//! forcing its result to WHNF — is structurally incapable of producing any
//! observable event (throw, abort, failed assert, trace output) or diverging,
//! for every environment. Totality is the S2 upgrade condition: deferred
//! demand stays [`crate::ir::Strictness::Demanded`] unless every intervening
//! step to the serial force point is total and silent.
//!
//! The rules are deliberately shallow and syntactic:
//!
//! - Literals, lambdas, list literals, and static-key attrset literals are
//!   total: their WHNF requires no forcing of interior thunks.
//! - `let` and `with` are total when their bodies are; frame population only
//!   allocates.
//! - A variable is total when it statically resolves (through the frame
//!   stack) to a binding value whose forcing is total; lambda parameters and
//!   `rec` sets with `__overrides` fail closed.
//! - Everything that can raise a type error, call unknown code, or perform
//!   I/O — `if`, application, operators, selection, primops, `assert`,
//!   string interpolation, search paths — is non-total.

use crate::ir::{IrAttrPathSegment, IrData, IrId, IrKind};

use super::frames::{FrameScope, resolve_slot};
use super::{Analysis, StrictnessAnalysisError, for_each_child};

/// Computes totality bits for every node reachable from `root`.
///
/// `stack` is the frame context of `root`; the pass pushes and pops frame
/// scopes as it descends so variable chases resolve against the same static
/// context the demand walk will use.
///
/// # Errors
///
/// Returns [`StrictnessAnalysisError`] when node payloads or side tables are
/// internally inconsistent.
pub(super) fn compute(
    analysis: &mut Analysis<'_>,
    root: IrId,
    stack: &mut Vec<FrameScope>,
) -> Result<bool, StrictnessAnalysisError> {
    if let Some(known) = analysis.totality.get(root.index()).copied().flatten() {
        return Ok(known);
    }
    // Seed in-progress nodes as non-total so resolution cycles fail closed.
    if let Some(slot) = analysis.totality.get_mut(root.index()) {
        *slot = Some(false);
    }
    let node = analysis.node(root)?;

    // Descend into every child first (managing frame scopes), so chases from
    // deeper contexts can read completed bits and every reachable node ends
    // the pass with a computed bit.
    let pushed = push_frame_scope(analysis, root, node)?;
    if let Some(scope) = pushed {
        stack.push(scope);
    }
    // `ir` is a shared reference independent of the `&mut Analysis` borrow,
    // so the recursion can run inside the child enumeration directly.
    let ir = analysis.ir;
    {
        let mut recurse = |child: IrId| compute(analysis, child, stack).map(|_| ());
        for_each_child(ir, root, node, &mut recurse)?;
    }
    if pushed.is_some() {
        stack.pop();
    }

    let total = node_total(analysis, root, node, stack)?;
    if let Some(slot) = analysis.totality.get_mut(root.index()) {
        *slot = Some(total);
    }
    Ok(total)
}

/// Returns the frame scope introduced by `node`, if any.
pub(super) fn push_frame_scope(
    analysis: &Analysis<'_>,
    id: IrId,
    node: crate::ir::IrNode,
) -> Result<Option<FrameScope>, StrictnessAnalysisError> {
    Ok(match node.data {
        IrData::Let { bindings, .. } => Some(FrameScope::for_let(id, bindings)),
        IrData::AttrSet {
            bindings,
            recursive: true,
            ..
        } => Some(FrameScope::for_rec_attrs(analysis, id, bindings)),
        IrData::Lambda { .. } => Some(FrameScope::for_lambda(id)),
        _ => None,
    })
}

fn node_total(
    analysis: &mut Analysis<'_>,
    id: IrId,
    node: crate::ir::IrNode,
    stack: &mut Vec<FrameScope>,
) -> Result<bool, StrictnessAnalysisError> {
    Ok(match node.kind {
        IrKind::Int
        | IrKind::Float
        | IrKind::Bool
        | IrKind::Null
        | IrKind::Str
        | IrKind::Path
        | IrKind::Uri
        | IrKind::Lambda
        | IrKind::List
        | IrKind::Formal
        | IrKind::FormalSet => true,
        IrKind::BuiltinAttr => {
            // Selecting an always-available builtin as a value only allocates.
            let IrData::Symbol(symbol) = node.data else {
                return Ok(false);
            };
            analysis
                .ir
                .symbols
                .resolve(symbol)
                .and_then(crate::builtins::lookup_builtin)
                .is_some_and(|builtin| {
                    matches!(
                        builtin.availability(),
                        crate::builtins::BuiltinAvailability::Always
                    )
                })
        }
        IrKind::ThunkAlloc => {
            // In a demand position the fresh thunk is forced immediately, so
            // totality is the body's.
            let IrData::Node(body) = node.data else {
                return Ok(false);
            };
            analysis.total(body)
        }
        IrKind::Let => {
            let IrData::Let { bindings, body, .. } = node.data else {
                return Ok(false);
            };
            // Binding assembly only allocates; dead-binding preflight and
            // frame population cannot force.
            let _ = bindings;
            analysis.total(body)
        }
        IrKind::With => {
            let IrData::Pair { second, .. } = node.data else {
                return Ok(false);
            };
            analysis.total(second)
        }
        IrKind::AttrSet => {
            let IrData::AttrSet {
                bindings,
                has_dynamic,
                ..
            } = node.data
            else {
                return Ok(false);
            };
            if !has_dynamic {
                true
            } else {
                analysis
                    .bindings(id, bindings)?
                    .iter()
                    .all(|binding| match binding.key {
                        IrAttrPathSegment::Static(_) => true,
                        IrAttrPathSegment::Dynamic(key) => analysis.total(key),
                    })
            }
        }
        IrKind::LocalVar => {
            let IrData::Local { slot } = node.data else {
                return Ok(false);
            };
            var_total(analysis, stack, stack.len().checked_sub(1), slot)?
        }
        IrKind::UpvalVar => {
            let IrData::Upval { depth, slot } = node.data else {
                return Ok(false);
            };
            var_total(
                analysis,
                stack,
                stack.len().checked_sub(1 + depth as usize),
                slot,
            )?
        }
        // Anything that can raise a type error, run unknown code, perform
        // I/O, or emit output fails closed.
        IrKind::GlobalVar
        | IrKind::SearchPath
        | IrKind::Apply
        | IrKind::Select
        | IrKind::HasAttr
        | IrKind::If
        | IrKind::BinOp
        | IrKind::UnaryOp
        | IrKind::Interp
        | IrKind::Assert
        | IrKind::PrimOp => false,
    })
}

/// Returns whether forcing the variable at `(stack[index], slot)` is total.
fn var_total(
    analysis: &mut Analysis<'_>,
    stack: &[FrameScope],
    index: Option<usize>,
    slot: u32,
) -> Result<bool, StrictnessAnalysisError> {
    let Some(index) = index else {
        return Ok(false);
    };
    let Some(scope) = stack.get(index).copied() else {
        return Ok(false);
    };
    let Some(value) = resolve_slot(analysis, scope, slot)? else {
        return Ok(false);
    };
    // The binding value was visited by this pass before the variable that
    // references it only in non-recursive cases; recursive references read
    // the in-progress (false) seed and fail closed.
    Ok(analysis.total(value))
}
