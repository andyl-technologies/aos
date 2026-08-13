//! On-demand recovery of resolver frame identities for lowered IR nodes.
//!
//! Runtime Node thunks currently retain captured frame values but not the
//! resolver [`FrameId`] needed to select frame-specialized native code. This
//! analysis reconstructs that identity from immutable IR structure. It stores
//! no per-thunk metadata: an evaluator can cache the result by module and body
//! id alongside a lowered mixed plan.

use std::collections::HashSet;

use thiserror::Error;

use crate::{FrameId, Ir, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId, IrNode};

/// Result of structurally resolving one node's lexical frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrFrameIdentity {
    /// The node is reached under exactly one resolver frame identity.
    Unique(Option<FrameId>),
    /// The shared node is reached under more than one resolver frame identity.
    Ambiguous,
    /// The node is not reachable from the module root.
    Unreachable,
}

/// Reports malformed side-table references encountered during frame recovery.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IrFrameIdentityError {
    /// A traversed node id is outside the immutable node arena.
    #[error("frame recovery references missing IR node {0:?}")]
    InvalidNode(IrId),
    /// A traversed child run is outside the immutable child table.
    #[error("frame recovery found an invalid child run at {0:?}")]
    InvalidChildren(IrId),
    /// A traversed binding run is outside the immutable binding table.
    #[error("frame recovery found an invalid binding run at {0:?}")]
    InvalidBindings(IrId),
    /// A traversed attribute path is outside the immutable path table.
    #[error("frame recovery found an invalid attribute path at {0:?}")]
    InvalidAttrPath(IrId),
    /// A traversed dynamic-scope chain is outside the immutable chain table.
    #[error("frame recovery found an invalid dynamic-scope chain at {0:?}")]
    InvalidWithChain(IrId),
}

/// Recovers the unique resolver frame under which `target` executes.
///
/// The traversal follows deferred Lambda and `ThunkAlloc` bodies as potential
/// later entries while propagating binder frames through `let`, recursive
/// attribute sets, and lambda bodies. Shared nodes reached under distinct
/// frames are reported as ambiguous and must be declined by a native adapter.
///
/// This function allocates only temporary traversal state and adds no runtime
/// bytes to thunk records.
///
/// # Errors
///
/// Returns [`IrFrameIdentityError`] when immutable IR side-table references are
/// malformed.
pub fn resolve_unique_ir_frame(
    ir: &Ir,
    target: IrId,
) -> Result<IrFrameIdentity, IrFrameIdentityError> {
    if ir.arena.node(target).is_none() {
        return Err(IrFrameIdentityError::InvalidNode(target));
    }
    let mut stack = vec![(ir.root, None)];
    let mut visited = HashSet::new();
    let mut identity = None;
    while let Some((id, frame)) = stack.pop() {
        if !visited.insert((id, frame)) {
            continue;
        }
        let node = ir
            .arena
            .node(id)
            .copied()
            .ok_or(IrFrameIdentityError::InvalidNode(id))?;
        if id == target {
            match identity {
                None => identity = Some(frame),
                Some(observed) if observed == frame => {}
                Some(_) => return Ok(IrFrameIdentity::Ambiguous),
            }
        }
        push_frame_children(ir, id, node, frame, &mut stack)?;
    }
    Ok(match identity {
        Some(frame) => IrFrameIdentity::Unique(frame),
        None => IrFrameIdentity::Unreachable,
    })
}

fn push_frame_children(
    ir: &Ir,
    id: IrId,
    node: IrNode,
    frame: Option<FrameId>,
    stack: &mut Vec<(IrId, Option<FrameId>)>,
) -> Result<(), IrFrameIdentityError> {
    match node.data {
        IrData::Lambda {
            pattern,
            body,
            frame: lambda_frame,
        } => {
            let nested = lambda_frame.or(frame);
            stack.extend([(pattern, nested), (body, nested)]);
        }
        IrData::Let {
            bindings,
            body,
            frame: let_frame,
        } => {
            let nested = let_frame.or(frame);
            push_bindings(ir, id, bindings, nested, stack)?;
            stack.push((body, nested));
        }
        IrData::AttrSet {
            bindings,
            recursive,
            frame: attr_frame,
            ..
        } => {
            let nested = if recursive {
                attr_frame.or(frame)
            } else {
                frame
            };
            push_bindings(ir, id, bindings, nested, stack)?;
        }
        _ => {
            for child in direct_children(ir, id, node)? {
                stack.push((child, frame));
            }
        }
    }
    Ok(())
}

fn push_bindings(
    ir: &Ir,
    id: IrId,
    slice: IrBindingSlice,
    frame: Option<FrameId>,
    stack: &mut Vec<(IrId, Option<FrameId>)>,
) -> Result<(), IrFrameIdentityError> {
    let start = slice.start as usize;
    let end = start
        .checked_add(slice.len())
        .ok_or(IrFrameIdentityError::InvalidBindings(id))?;
    let bindings = ir
        .bindings
        .get(start..end)
        .ok_or(IrFrameIdentityError::InvalidBindings(id))?;
    for binding in bindings {
        stack.push((binding.value, frame));
        if let IrAttrPathSegment::Dynamic(dynamic) = binding.key {
            stack.push((dynamic, frame));
        }
    }
    Ok(())
}

fn direct_children(ir: &Ir, id: IrId, node: IrNode) -> Result<Vec<IrId>, IrFrameIdentityError> {
    let mut children = Vec::new();
    match node.data {
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::GlobalVar { .. }
        | IrData::Local { .. }
        | IrData::Upval { .. } => {}
        IrData::SearchPath { search_path, .. } => children.extend(search_path),
        IrData::Node(child) => children.push(child),
        IrData::Pair { first, second } => children.extend([first, second]),
        IrData::Triple {
            first,
            second,
            third,
        } => children.extend([first, second, third]),
        IrData::Children(slice) => push_child_slice(ir, id, slice, &mut children)?,
        IrData::Bindings(slice) => {
            let mut stack = Vec::new();
            push_bindings(ir, id, slice, None, &mut stack)?;
            children.extend(stack.into_iter().map(|(child, _)| child));
        }
        IrData::Binary { lhs, rhs, .. } => children.extend([lhs, rhs]),
        IrData::Unary { operand, .. } => children.push(operand),
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            children.push(receiver);
            children.extend(default);
            push_path_children(ir, id, path.index(), &mut children)?;
        }
        IrData::HasAttr { receiver, path, .. } => {
            children.push(receiver);
            push_path_children(ir, id, path.index(), &mut children)?;
        }
        IrData::PrimOp { args, .. } => push_child_slice(ir, id, args, &mut children)?,
        IrData::DialectNode { argument, .. } => children.push(argument),
        IrData::DialectScopeVar { chain, .. } => {
            let scopes = ir
                .with_chains
                .get(chain as usize)
                .ok_or(IrFrameIdentityError::InvalidWithChain(id))?;
            children.extend(scopes.scopes.iter().copied());
        }
        IrData::FormalSet { formals, .. } => {
            push_child_slice(ir, id, formals, &mut children)?;
        }
        IrData::Formal { default, .. } => children.extend(default),
        IrData::Lambda { .. } | IrData::Let { .. } | IrData::AttrSet { .. } => {}
    }
    for child in &children {
        if ir.arena.node(*child).is_none() {
            return Err(IrFrameIdentityError::InvalidNode(*child));
        }
    }
    Ok(children)
}

fn push_child_slice(
    ir: &Ir,
    id: IrId,
    slice: IrChildSlice,
    children: &mut Vec<IrId>,
) -> Result<(), IrFrameIdentityError> {
    let values = ir
        .arena
        .child_slice(slice)
        .ok_or(IrFrameIdentityError::InvalidChildren(id))?;
    children.extend_from_slice(values);
    Ok(())
}

fn push_path_children(
    ir: &Ir,
    id: IrId,
    path: usize,
    children: &mut Vec<IrId>,
) -> Result<(), IrFrameIdentityError> {
    let path = ir
        .attr_paths
        .get(path)
        .ok_or(IrFrameIdentityError::InvalidAttrPath(id))?;
    for segment in path.iter() {
        if let IrAttrPathSegment::Dynamic(dynamic) = segment {
            children.push(*dynamic);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::parse_str;
    use crate::{lower, resolve};

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    #[test]
    fn recovers_lambda_body_frame_without_thunk_metadata() {
        let ir = lowered("x: x");
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda {
            body,
            frame: Some(frame),
            ..
        } = lambda.data
        else {
            panic!("lambda frame expected");
        };
        assert_eq!(
            resolve_unique_ir_frame(&ir, body).expect("frame recovery succeeds"),
            IrFrameIdentity::Unique(Some(frame))
        );
    }

    #[test]
    fn root_body_has_the_root_frame_identity() {
        let ir = lowered("42");
        assert_eq!(
            resolve_unique_ir_frame(&ir, ir.root).expect("frame recovery succeeds"),
            IrFrameIdentity::Unique(None)
        );
    }
}
