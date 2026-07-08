//! The top-down demand walk assigning per-node facts.
//!
//! Every child position is classified by how the evaluator treats the value
//! produced there:
//!
//! - [`Position::ForcedNow`] — evaluated and forced in the same instant
//!   (strict operands, forced builtin arguments, conditions, dynamic keys).
//!   Eliding a thunk here replaces "allocate then immediately force" with
//!   direct evaluation, a semantic no-op, so the fact is
//!   [`Strictness::DemandedBeforeEffect`] unconditionally.
//! - [`Position::Deferred`] — evaluated now (allocated) but forced later:
//!   apply arguments gated by the callee's parameter summary, and selected
//!   binding values of statically-known attrset literals.
//! - [`Position::EvalOnly`] — evaluated with no forcing claim (list elements,
//!   binding values, lazy builtin arguments). No fact is produced, but the
//!   walk still descends so interior positions earn their own facts.
//!
//! Transparent nodes — `let` bodies, `if` branches, `assert`/`with` bodies,
//! and result-position builtin arguments — return their child's value as
//! their own, so the child inherits the parent's position: if the parent's
//! value is forced immediately by *its* consumer, so is the child's.

use crate::builtins::{ArgDemand, demand_signature, lookup_builtin};
use crate::ir::{IrAttrPathSegment, IrData, IrId, IrKind, Strictness};
use crate::syntax::BinOpKind;

use super::collect::{LambdaArgumentDemand, lambda_argument_demand};
use super::frames::{ChasedCallee, FrameScope, chase_attrset_literal, chase_callee};
use super::{Analysis, StrictnessAnalysisError};

/// How the evaluator treats one child position's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// Evaluated and forced in the same instant.
    ForcedNow,
    /// Evaluated (allocated) now, forced later at the proven level.
    Deferred(Strictness),
    /// Evaluated with no forcing claim.
    EvalOnly,
}

impl Position {
    const fn level(self) -> Strictness {
        match self {
            Self::ForcedNow => Strictness::DemandedBeforeEffect,
            Self::Deferred(level) => level,
            Self::EvalOnly => Strictness::Unknown,
        }
    }
}

/// Runs the demand walk from the module root.
///
/// The module root is forced by its importer (C++ Nix evaluates an imported
/// file to WHNF at the import), so the root starts in a forced position.
pub(super) fn run(analysis: &mut Analysis<'_>) -> Result<(), StrictnessAnalysisError> {
    let mut stack = Vec::new();
    visit(analysis, analysis.ir.root, Position::ForcedNow, &mut stack)
}

fn visit(
    analysis: &mut Analysis<'_>,
    id: IrId,
    position: Position,
    stack: &mut Vec<FrameScope>,
) -> Result<(), StrictnessAnalysisError> {
    analysis.mark(id, position.level());
    let node = analysis.node(id)?;

    match node.kind {
        IrKind::Int
        | IrKind::Float
        | IrKind::Bool
        | IrKind::Null
        | IrKind::Str
        | IrKind::Path
        | IrKind::Uri
        | IrKind::BuiltinAttr
        | IrKind::GlobalVar
        | IrKind::LocalVar
        | IrKind::UpvalVar => Ok(()),
        IrKind::SearchPath => {
            if let IrData::SearchPath {
                search_path: Some(search_path),
                ..
            } = node.data
            {
                visit(analysis, search_path, Position::ForcedNow, stack)?;
            }
            Ok(())
        }
        IrKind::ThunkAlloc => {
            let IrData::Node(body) = node.data else {
                return Ok(());
            };
            // The body executes when the thunk is forced; interior positions
            // earn their own facts relative to that execution.
            visit(analysis, body, Position::EvalOnly, stack)
        }
        IrKind::Lambda => {
            let IrData::Lambda { pattern, body, .. } = node.data else {
                return Ok(());
            };
            visit(analysis, pattern, Position::EvalOnly, stack)?;
            let scope = FrameScope::for_lambda(id);
            stack.push(scope);
            let result = visit(analysis, body, Position::EvalOnly, stack);
            stack.pop();
            result
        }
        IrKind::FormalSet => {
            let IrData::FormalSet { formals, .. } = node.data else {
                return Ok(());
            };
            for formal in analysis.child_ids(id, formals)? {
                visit(analysis, *formal, Position::EvalOnly, stack)?;
            }
            Ok(())
        }
        IrKind::Formal => {
            if let IrData::Formal {
                default: Some(default),
                ..
            } = node.data
            {
                visit(analysis, default, Position::EvalOnly, stack)?;
            }
            Ok(())
        }
        IrKind::List => {
            let IrData::Children(children) = node.data else {
                return Ok(());
            };
            for element in analysis.child_ids(id, children)? {
                visit(analysis, *element, Position::EvalOnly, stack)?;
            }
            Ok(())
        }
        IrKind::AttrSet => {
            let IrData::AttrSet {
                bindings,
                recursive,
                ..
            } = node.data
            else {
                return Ok(());
            };
            let scope = recursive.then(|| FrameScope::for_rec_attrs(analysis, id, bindings));
            if let Some(scope) = scope {
                stack.push(scope);
                // Fan-out hints: slots demanded by sibling values and keys.
                super::collect::collect(analysis, id, super::collect::CollectCtx::Result)?;
            }
            let entries = analysis.bindings(id, bindings)?;
            for binding in entries {
                if let IrAttrPathSegment::Dynamic(key) = binding.key {
                    visit(analysis, key, Position::ForcedNow, stack)?;
                }
                visit(analysis, binding.value, Position::EvalOnly, stack)?;
            }
            if scope.is_some() {
                stack.pop();
            }
            Ok(())
        }
        IrKind::Let => {
            let IrData::Let { bindings, body, .. } = node.data else {
                return Ok(());
            };
            let scope = FrameScope::for_let(id, bindings);
            stack.push(scope);
            // Run the intra-frame demand fixpoint so demanded binding values
            // earn their fan-out hints even when no enclosing collection
            // reaches this frame. The collection context mirrors this let's
            // own position: a forced let forces its transparent body.
            let collect_ctx = if position.level() == Strictness::Unknown {
                super::collect::CollectCtx::Result
            } else {
                super::collect::CollectCtx::Forced
            };
            super::collect::collect(analysis, id, collect_ctx)?;
            let entries = analysis.bindings(id, bindings)?;
            for binding in entries {
                visit(analysis, binding.value, Position::EvalOnly, stack)?;
            }
            let result = visit(analysis, body, position, stack);
            stack.pop();
            result
        }
        IrKind::With => {
            let IrData::Pair {
                first: scope_expr,
                second: body,
            } = node.data
            else {
                return Ok(());
            };
            visit(analysis, scope_expr, Position::EvalOnly, stack)?;
            visit(analysis, body, position, stack)
        }
        IrKind::Assert => {
            let IrData::Pair {
                first: condition,
                second: body,
            } = node.data
            else {
                return Ok(());
            };
            visit(analysis, condition, Position::ForcedNow, stack)?;
            visit(analysis, body, position, stack)
        }
        IrKind::If => {
            let IrData::Triple {
                first: condition,
                second: then_branch,
                third: else_branch,
            } = node.data
            else {
                return Ok(());
            };
            visit(analysis, condition, Position::ForcedNow, stack)?;
            visit(analysis, then_branch, position, stack)?;
            visit(analysis, else_branch, position, stack)
        }
        IrKind::BinOp => {
            let IrData::Binary { op, lhs, rhs } = node.data else {
                return Ok(());
            };
            match op {
                // Both operands are forced the moment they are evaluated;
                // the right side simply may not be evaluated at all.
                BinOpKind::And | BinOpKind::Or | BinOpKind::Impl => {
                    visit(analysis, lhs, Position::ForcedNow, stack)?;
                    visit(analysis, rhs, Position::ForcedNow, stack)
                }
                BinOpKind::PipeRight => {
                    visit(analysis, lhs, Position::EvalOnly, stack)?;
                    visit(analysis, rhs, Position::ForcedNow, stack)
                }
                BinOpKind::PipeLeft => {
                    visit(analysis, lhs, Position::ForcedNow, stack)?;
                    visit(analysis, rhs, Position::EvalOnly, stack)
                }
                BinOpKind::Add
                | BinOpKind::Sub
                | BinOpKind::Mul
                | BinOpKind::Div
                | BinOpKind::Concat
                | BinOpKind::Update
                | BinOpKind::Lt
                | BinOpKind::Gt
                | BinOpKind::Le
                | BinOpKind::Ge
                | BinOpKind::Eq
                | BinOpKind::Ne => {
                    visit(analysis, lhs, Position::ForcedNow, stack)?;
                    visit(analysis, rhs, Position::ForcedNow, stack)
                }
            }
        }
        IrKind::UnaryOp => {
            let IrData::Unary { operand, .. } = node.data else {
                return Ok(());
            };
            visit(analysis, operand, Position::ForcedNow, stack)
        }
        IrKind::Interp => {
            let children: &[IrId] = match node.data {
                IrData::Node(ref child) => std::slice::from_ref(child),
                IrData::Children(children) => analysis.child_ids(id, children)?,
                _ => &[],
            };
            for child in children {
                visit(analysis, *child, Position::ForcedNow, stack)?;
            }
            Ok(())
        }
        IrKind::Select => {
            let IrData::Select {
                receiver,
                path,
                default,
                ..
            } = node.data
            else {
                return Ok(());
            };
            visit(analysis, receiver, Position::ForcedNow, stack)?;
            for segment in analysis.attr_path(id, path)? {
                if let IrAttrPathSegment::Dynamic(segment) = segment {
                    visit(analysis, *segment, Position::ForcedNow, stack)?;
                }
            }
            if let Some(default) = default {
                // The `or` default is the select's value when the key is
                // missing, so it inherits the select's own position.
                visit(analysis, default, position, stack)?;
            }
            mark_selected_literal_bindings(analysis, id, receiver, path, stack)?;
            Ok(())
        }
        IrKind::HasAttr => {
            let IrData::HasAttr { receiver, path, .. } = node.data else {
                return Ok(());
            };
            visit(analysis, receiver, Position::ForcedNow, stack)?;
            for segment in analysis.attr_path(id, path)? {
                if let IrAttrPathSegment::Dynamic(segment) = segment {
                    visit(analysis, *segment, Position::ForcedNow, stack)?;
                }
            }
            Ok(())
        }
        IrKind::Apply => {
            let IrData::Pair {
                first: function,
                second: argument,
            } = node.data
            else {
                return Ok(());
            };
            visit(analysis, function, Position::ForcedNow, stack)?;
            let argument_position = apply_argument_position(analysis, function, position, stack)?;
            visit(analysis, argument, argument_position, stack)
        }
        IrKind::PrimOp => visit_primop(analysis, id, node.data, position, stack),
    }
}

/// Returns the position for one apply argument.
///
/// The callee is chased through the current frame stack to a literal lambda
/// (aliases, `let` bindings, static selection on chased attrset literals) and
/// its parameter summary becomes the argument's deferred level. The window
/// between the argument's allocation and its first force contains only the
/// call machinery — the function expression is evaluated *before* the
/// argument — so the summary level transfers to the argument unchanged. A
/// transparent result-spine summary (`x: x`) transfers the apply's own
/// position instead: the argument is forced exactly when the call's value is.
fn apply_argument_position(
    analysis: &mut Analysis<'_>,
    function: IrId,
    apply_position: Position,
    stack: &[FrameScope],
) -> Result<Position, StrictnessAnalysisError> {
    let lambda = match chase_callee(analysis, stack, function)? {
        ChasedCallee::Lambda(lambda) => lambda,
        ChasedCallee::Unknown => return Ok(Position::EvalOnly),
    };
    Ok(match lambda_argument_demand(analysis, lambda)? {
        LambdaArgumentDemand::Level(level) => Position::Deferred(level),
        LambdaArgumentDemand::IfResultForced(level) => {
            Position::Deferred(level.min(apply_position.level()))
        }
    })
}

/// Marks binding values selected from statically-known attrset literals.
///
/// A fully-static select whose receiver *is* the literal (or a chain of
/// literals) forces the selected value right after the total literal
/// construction, so the binding value earns `DemandedBeforeEffect`. A
/// receiver chased through variables was constructed earlier, so the window
/// back to its allocation is unbounded and the binding value earns only
/// `Demanded`.
fn mark_selected_literal_bindings(
    analysis: &mut Analysis<'_>,
    id: IrId,
    receiver: IrId,
    path: crate::ir::IrAttrPathId,
    stack: &[FrameScope],
) -> Result<(), StrictnessAnalysisError> {
    let segments = analysis.attr_path(id, path)?;
    if segments.is_empty() {
        return Ok(());
    }
    let receiver_is_literal = {
        let node = analysis.node(receiver)?;
        matches!(node.kind, IrKind::AttrSet)
            || matches!(
                (node.kind, node.data),
                (IrKind::ThunkAlloc, IrData::Node(body))
                    if matches!(analysis.node(body).map(|node| node.kind), Ok(IrKind::AttrSet))
            )
    };
    let level = if receiver_is_literal {
        Strictness::DemandedBeforeEffect
    } else {
        Strictness::Demanded
    };

    let mut chase_stack = stack.to_vec();
    let mut current = receiver;
    for segment in segments {
        let IrAttrPathSegment::Static(symbol) = segment else {
            return Ok(());
        };
        let Some(attrset) = chase_attrset_literal(analysis, &mut chase_stack, current)? else {
            return Ok(());
        };
        let node = analysis.node(attrset)?;
        let IrData::AttrSet {
            bindings,
            recursive,
            has_dynamic,
            ..
        } = node.data
        else {
            return Ok(());
        };
        if has_dynamic {
            return Ok(());
        }
        let entries = analysis.bindings(attrset, bindings)?;
        let Some(selected) = entries.iter().find(|binding| {
            matches!(binding.key, IrAttrPathSegment::Static(key) if key == *symbol)
        }) else {
            return Ok(());
        };
        let value = selected.value;
        if recursive {
            let scope = FrameScope::for_rec_attrs(analysis, attrset, bindings);
            if matches!(
                scope.kind,
                super::frames::FrameKind::RecAttrs { opaque: true, .. }
            ) {
                return Ok(());
            }
            chase_stack.push(scope);
        }
        analysis.mark(value, level);
        current = value;
    }
    Ok(())
}

fn visit_primop(
    analysis: &mut Analysis<'_>,
    id: IrId,
    data: IrData,
    position: Position,
    stack: &mut Vec<FrameScope>,
) -> Result<(), StrictnessAnalysisError> {
    match data {
        IrData::PrimOp { symbol, args } => {
            let args = analysis.child_ids(id, args)?;
            let name = analysis
                .ir
                .symbols
                .resolve(symbol)
                .ok_or(StrictnessAnalysisError::InvalidSymbol { id, symbol })?;
            let Some(builtin) = lookup_builtin(name) else {
                for arg in args {
                    visit(analysis, *arg, Position::EvalOnly, stack)?;
                }
                return Ok(());
            };
            let signature = demand_signature(builtin.execution());
            for (index, arg) in args.iter().enumerate() {
                let arg_position = match signature.arg(index) {
                    ArgDemand::Forced => Position::ForcedNow,
                    ArgDemand::ForcedUnderCatch => {
                        // The catch scope makes the elision-vs-lazy behavior
                        // of the argument observable, so no eager license is
                        // granted; the persisted barrier bit records the
                        // catch boundary for relocation consumers (S4).
                        analysis.barriers.push(*arg);
                        Position::EvalOnly
                    }
                    // The builtin returns the argument's value as its own
                    // result, so the position inherits the call's.
                    ArgDemand::Result { .. } => position,
                    ArgDemand::Barred | ArgDemand::Lazy => Position::EvalOnly,
                };
                visit(analysis, *arg, arg_position, stack)?;
            }
            Ok(())
        }
        IrData::DialectNode { argument, .. } => {
            visit(analysis, argument, Position::ForcedNow, stack)
        }
        _ => Ok(()),
    }
}
