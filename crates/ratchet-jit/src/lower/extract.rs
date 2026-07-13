//! Tier-1 operand/slot extraction helpers (moved from `lower.rs`).

use cranelift_codegen::ir::UserExternalName;
use ratchet_core::{
    Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData,
    IrId, IrInlineCacheSiteId, IrKind, IrNode,
    syntax::{BinOpKind, Symbol},
};
use ratchet_value::value::Value;

use super::*;

pub(crate) fn constant_value_for_root(arena: &IrArena, root: IrId) -> Result<Value, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            constant_value_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => constant_value_for_node(node),
    }
}

pub(crate) fn constant_value_for_body(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        // The one-word carrier can only construct inline-range integers
        // context-free; wider integers box through the evaluator heap.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Int, IrData::Int(value)) => {
            if i32::try_from(value).is_ok() {
                Ok(Value::int(value))
            } else {
                Err(JitLowerError::ArenaBackedConstant {
                    tag: ratchet_value::value::ValueTag::Int,
                })
            }
        }
        // The Candidate-C carrier has no context-free float constructor (floats
        // box through the evaluator heap); the tier-1 JIT is unreachable by
        // construction under that variant, so this arm is dead there.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Float, IrData::Float(_)) => Err(JitLowerError::UnsupportedIrBody {
            kind: IrKind::Float,
        }),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedBodyConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrBody { kind }),
    }
}

pub(crate) fn constant_value_for_node(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        // See constant_value_for_body: inline-range integers only on the
        // one-word carrier.
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Int, IrData::Int(value)) => {
            if i32::try_from(value).is_ok() {
                Ok(Value::int(value))
            } else {
                Err(JitLowerError::ArenaBackedConstant {
                    tag: ratchet_value::value::ValueTag::Int,
                })
            }
        }
        // Dead under the Candidate-C variant (JIT off; no float constructor).
        #[cfg(not(feature = "candidate_c_value"))]
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        #[cfg(feature = "candidate_c_value")]
        (IrKind::Float, IrData::Float(_)) => Err(JitLowerError::UnsupportedIrRoot {
            kind: IrKind::Float,
        }),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrRoot { kind }),
    }
}

pub(crate) fn env_slot_for_root(arena: &IrArena, root: IrId) -> Result<u32, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            env_slot_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => env_slot_for_node(node),
    }
}

pub(crate) fn env_slot_for_body(node: IrNode) -> Result<u32, JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvBody { kind }),
    }
}

pub(crate) fn env_slot_for_node(node: IrNode) -> Result<u32, JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(slot),
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvRoot { kind }),
    }
}

pub(crate) fn upval_depth_slot_for_root(arena: &IrArena, root: IrId) -> Result<(u32, u32), JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            upval_depth_slot_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => upval_depth_slot_for_node(node),
    }
}

pub(crate) fn upval_depth_slot_for_body(node: IrNode) -> Result<(u32, u32), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => Ok((depth, slot)),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvBody { kind }),
    }
}

pub(crate) fn upval_depth_slot_for_node(node: IrNode) -> Result<(u32, u32), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => Ok((depth, slot)),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedEnvRoot { kind }),
    }
}

/// Returns the primop node id for a def-site body `root`, if it is a primop.
///
/// The tier-1 dispatcher hands the lowerer a thunk body node that is either an
/// [`IrKind::PrimOp`] directly or a single [`IrKind::ThunkAlloc`] wrapping one.
/// This unwraps at most one `ThunkAlloc` and returns the inner primop node id,
/// or `None` when the body is any other shape.
pub(crate) fn primop_node_id_for_root(arena: &IrArena, root: IrId) -> Option<IrId> {
    let node = arena.node(root).copied()?;
    match (node.kind, node.data) {
        (IrKind::PrimOp, _) => Some(root),
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body_node = arena.node(body).copied()?;
            (body_node.kind == IrKind::PrimOp).then_some(body)
        }
        _ => None,
    }
}

pub(crate) fn apply_local_slots_for_root(arena: &IrArena, root: IrId) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            apply_local_slots_for_body(arena, body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => apply_local_slots_for_node(arena, node),
    }
}

pub(crate) fn apply_local_slots_for_body(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::Apply, IrData::Pair { first, second }) => Ok((
            apply_local_child_slot(arena, first)?,
            apply_local_child_slot(arena, second)?,
        )),
        (IrKind::Apply, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::Apply,
            data,
            expected: "application pair payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyBody { kind }),
    }
}

pub(crate) fn apply_local_slots_for_node(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::Apply, IrData::Pair { first, second }) => Ok((
            apply_local_child_slot(arena, first)?,
            apply_local_child_slot(arena, second)?,
        )),
        (IrKind::Apply, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::Apply,
            data,
            expected: "application pair payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyRoot { kind }),
    }
}

pub(crate) fn apply_local_child_slot(arena: &IrArena, child: IrId) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = arena
        .node(child)
        .copied()
        .ok_or(JitLowerError::MissingApplyChild { child })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Ok(Tier1SlotOperand::Upval { depth, slot })
        }
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedApplyChild { child, kind }),
    }
}

pub(crate) fn update_local_slots_for_root(arena: &IrArena, root: IrId) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            update_local_slots_for_body(arena, body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => update_local_slots_for_node(arena, node),
    }
}

pub(crate) fn update_local_slots_for_body(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Update,
                lhs,
                rhs,
            },
        ) => Ok((
            update_local_operand_slot(arena, lhs)?,
            update_local_operand_slot(arena, rhs)?,
        )),
        (IrKind::BinOp, IrData::Binary { op, .. }) => {
            Err(JitLowerError::UnsupportedUpdateOp { op })
        }
        (IrKind::BinOp, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::BinOp,
            data,
            expected: "attr update binary payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateBody { kind }),
    }
}

pub(crate) fn update_local_slots_for_node(arena: &IrArena, node: IrNode) -> Result<(Tier1SlotOperand, Tier1SlotOperand), JitLowerError> {
    match (node.kind, node.data) {
        (
            IrKind::BinOp,
            IrData::Binary {
                op: BinOpKind::Update,
                lhs,
                rhs,
            },
        ) => Ok((
            update_local_operand_slot(arena, lhs)?,
            update_local_operand_slot(arena, rhs)?,
        )),
        (IrKind::BinOp, IrData::Binary { op, .. }) => {
            Err(JitLowerError::UnsupportedUpdateOp { op })
        }
        (IrKind::BinOp, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::BinOp,
            data,
            expected: "attr update binary payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateRoot { kind }),
    }
}

pub(crate) fn update_local_operand_slot(
    arena: &IrArena,
    operand: IrId,
) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = arena
        .node(operand)
        .copied()
        .ok_or(JitLowerError::MissingUpdateOperand { operand })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Ok(Tier1SlotOperand::Upval { depth, slot })
        }
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedUpdateOperand { operand, kind }),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AttrLookup {
    pub(crate) receiver: Tier1SlotOperand,
    pub(crate) symbol: Symbol,
    pub(crate) site: IrInlineCacheSiteId,
    pub(crate) default: Option<Value>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttrLookupLowering {
    HasAttr,
    SelectIc,
}

impl AttrLookupLowering {
    const fn expected_kind(self) -> IrKind {
        match self {
            Self::HasAttr => IrKind::HasAttr,
            Self::SelectIc => IrKind::Select,
        }
    }

    pub(crate) const fn symbol_name(self) -> &'static str {
        match self {
            Self::HasAttr => AOS_HAS_ATTR_SYMBOL,
            Self::SelectIc => AOS_SELECT_IC_SYMBOL,
        }
    }

    pub(crate) fn external_name(self) -> UserExternalName {
        match self {
            Self::HasAttr => clif_external_name_for_aos_has_attr(),
            Self::SelectIc => clif_external_name_for_aos_select_ic(),
        }
    }
}

pub(crate) fn attr_lookup_for_root(
    ir: &Ir,
    root: IrId,
    lowering: AttrLookupLowering,
) -> Result<AttrLookup, JitLowerError> {
    let node = ir
        .arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body_node = ir
                .arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            attr_lookup_for_node(ir, body_node, lowering, true)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => attr_lookup_for_node(ir, node, lowering, false),
    }
}

pub(crate) fn attr_lookup_for_node(
    ir: &Ir,
    node: IrNode,
    lowering: AttrLookupLowering,
    is_thunk_body: bool,
) -> Result<AttrLookup, JitLowerError> {
    if node.kind != lowering.expected_kind() {
        if is_thunk_body {
            return Err(JitLowerError::UnsupportedAttrBody { kind: node.kind });
        }
        return Err(JitLowerError::UnsupportedAttrRoot { kind: node.kind });
    }

    match (lowering, node.data) {
        (
            AttrLookupLowering::HasAttr,
            IrData::HasAttr {
                receiver,
                path,
                site,
            },
        ) => attr_lookup(ir, receiver, path, site, None),
        (
            AttrLookupLowering::SelectIc,
            IrData::Select {
                receiver,
                path,
                site,
                default: None,
            },
        ) => attr_lookup(ir, receiver, path, site, None),
        (
            AttrLookupLowering::SelectIc,
            IrData::Select {
                default: Some(default),
                receiver,
                path,
                site,
                ..
            },
        ) => {
            let default_value = constant_value_for_root(&ir.arena, default)
                .map_err(|_| JitLowerError::UnsupportedSelectDefault { default })?;
            attr_lookup(ir, receiver, path, site, Some(default_value))
        }
        (_, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: lowering.expected_kind(),
            data,
            expected: "static attr lookup payload",
        }),
    }
}

pub(crate) fn attr_lookup(
    ir: &Ir,
    receiver: IrId,
    path: IrAttrPathId,
    site: IrInlineCacheSiteId,
    default: Option<Value>,
) -> Result<AttrLookup, JitLowerError> {
    Ok(AttrLookup {
        receiver: attr_receiver_slot(ir, receiver)?,
        symbol: single_static_attr_path_symbol(ir, path)?,
        site,
        default,
    })
}

pub(crate) fn attr_receiver_slot(ir: &Ir, receiver: IrId) -> Result<Tier1SlotOperand, JitLowerError> {
    let node = ir
        .arena
        .node(receiver)
        .copied()
        .ok_or(JitLowerError::MissingAttrReceiver { receiver })?;

    match (node.kind, node.data) {
        (IrKind::LocalVar, IrData::Local { slot }) => Ok(Tier1SlotOperand::Local { slot }),
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            Ok(Tier1SlotOperand::Upval { depth, slot })
        }
        (IrKind::LocalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::LocalVar,
            data,
            expected: "local slot payload",
        }),
        (IrKind::UpvalVar, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::UpvalVar,
            data,
            expected: "upvalue depth/slot payload",
        }),
        (kind, _) => Err(JitLowerError::UnsupportedAttrReceiver { receiver, kind }),
    }
}

pub(crate) fn single_static_attr_path_symbol(ir: &Ir, path: IrAttrPathId) -> Result<Symbol, JitLowerError> {
    let segments = ir
        .attr_paths
        .get(path.index())
        .ok_or(JitLowerError::MissingAttrPath { path })?;

    if segments.len() != 1 {
        return Err(JitLowerError::UnsupportedAttrPathLength {
            path,
            len: segments.len(),
        });
    }

    match segments[0] {
        IrAttrPathSegment::Static(symbol) => Ok(symbol),
        segment => Err(JitLowerError::UnsupportedAttrPathSegment {
            path,
            index: 0,
            segment,
        }),
    }
}
