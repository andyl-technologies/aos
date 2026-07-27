//! Sparse lexical call-target discovery.
//!
//! This walk tracks only frame-introducing syntax and the source child graph.
//! Unlike the demand walk, it does not inspect builtin symbols, totality, or
//! fact payloads, so it remains valid after an embedding remaps symbols into a
//! process-wide table.

use crate::ir::{IrData, IrId, IrKind};

use super::frames::{ChasedCallee, FrameScope, chase_callee};
use super::{Analysis, KnownCallTarget, StrictnessAnalysisError, for_each_child};

/// Finds applications whose function expressions chase to literal lambdas.
pub(super) fn run(analysis: &mut Analysis<'_>) -> Result<(), StrictnessAnalysisError> {
    let mut stack = Vec::new();
    visit(analysis, analysis.ir.root, &mut stack)
}

fn visit(
    analysis: &mut Analysis<'_>,
    id: IrId,
    stack: &mut Vec<FrameScope>,
) -> Result<(), StrictnessAnalysisError> {
    let node = analysis.node(id)?;
    match node.data {
        IrData::Lambda { pattern, body, .. } => {
            stack.push(FrameScope::for_lambda(id));
            visit(analysis, pattern, stack)?;
            let result = visit(analysis, body, stack);
            stack.pop();
            result
        }
        IrData::Let { bindings, body, .. } => {
            stack.push(FrameScope::for_let(id, bindings));
            let entries = analysis.bindings(id, bindings)?;
            for binding in entries {
                if let crate::ir::IrAttrPathSegment::Dynamic(key) = binding.key {
                    visit(analysis, key, stack)?;
                }
                visit(analysis, binding.value, stack)?;
            }
            let result = visit(analysis, body, stack);
            stack.pop();
            result
        }
        IrData::AttrSet {
            bindings,
            recursive,
            ..
        } if recursive => {
            stack.push(FrameScope::for_rec_attrs(analysis, id, bindings));
            let entries = analysis.bindings(id, bindings)?;
            for binding in entries {
                if let crate::ir::IrAttrPathSegment::Dynamic(key) = binding.key {
                    visit(analysis, key, stack)?;
                }
                visit(analysis, binding.value, stack)?;
            }
            stack.pop();
            Ok(())
        }
        IrData::Pair {
            first: function,
            second: argument,
        } if node.kind == IrKind::Apply => {
            if let ChasedCallee::Lambda(lambda) = chase_callee(analysis, stack, function)? {
                analysis
                    .known_call_targets
                    .push(KnownCallTarget { apply: id, lambda });
            }
            visit(analysis, function, stack)?;
            visit(analysis, argument, stack)
        }
        _ => {
            let mut children = Vec::new();
            for_each_child(analysis.ir, id, node, &mut |child| {
                children.push(child);
                Ok(())
            })?;
            for child in children {
                visit(analysis, child, stack)?;
            }
            Ok(())
        }
    }
}
