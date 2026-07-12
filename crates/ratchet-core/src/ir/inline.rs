//! Single-use `let`-binding inlining, arena-stable variant (doc 26 §2.1, cut a).
//!
//! This is the conservative, non-compacting slice of inlining: when a `let`
//! binding is demanded **at most once** (cardinality [`Cardinality::Once`]) and
//! that one use is a same-frame [`IrData::Local`] reference, the use node is
//! replaced in place (arena-stable [`super::IrArena::set_node`]) with a copy of
//! the binding's value node. The binding itself is left in place, so the frame's
//! slot layout is unchanged — no de-Bruijn renumbering, no compaction, and the
//! JIT's frame assumptions cannot shift. The now-unused binding is elided later
//! by dead-binding elimination, and slot compaction rides with full
//! beta-reduction (design note §9, increment 8).
//!
//! # Soundness
//!
//! Cardinality `Once` guarantees the use is reached at most once per frame
//! execution, so moving the (possibly thunk-wrapped) value to the use site
//! neither duplicates work nor loses sharing. Restricting to a *same-frame* use
//! (a `Local` reachable from the binding's frame without crossing a nested
//! `Lambda`/`Let`/recursive-`AttrSet` boundary) means the copied value's own
//! slot references remain valid at the use site with no renumbering. A use that
//! lives inside a nested frame (an `Upval`) is declined.

use super::{
    Cardinality, Ir, IrAttrPathSegment, IrData, IrId, IrNode, PassOutcome, SimplifyError,
    SimplifyPass, SimplifyPhase,
};

/// The single-use same-frame `let`-inline pass.
///
/// See the [module documentation](self) for the transform and its soundness
/// argument. This is a zero-sized pass with no configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InlineSingleUse;

impl SimplifyPass for InlineSingleUse {
    fn name(&self) -> &'static str {
        "inline-single-use"
    }

    fn runs_in(&self, phase: SimplifyPhase) -> bool {
        matches!(phase, SimplifyPhase::Main)
    }

    fn needs_facts(&self) -> bool {
        true
    }

    fn run(&self, ir: &mut Ir) -> Result<PassOutcome, SimplifyError> {
        // Cardinality facts are refreshed by the driver before this sweep (the
        // pass declares `needs_facts`); `is_once` reads them.
        let mut changed = false;
        let node_count = ir.arena.nodes().len();
        for index in 0..node_count {
            let Ok(raw) = u32::try_from(index) else {
                break;
            };
            let let_id = IrId::new(raw);
            let Some(node) = ir.arena.node(let_id).copied() else {
                continue;
            };
            let IrData::Let { bindings, .. } = node.data else {
                continue;
            };
            let binding_ids = binding_value_nodes(ir, bindings);
            for (slot, value) in binding_ids.into_iter().enumerate() {
                let Ok(slot) = u32::try_from(slot) else {
                    break;
                };
                if !is_once(ir, value) {
                    continue;
                }
                if let Some(use_id) = unique_same_frame_use(ir, let_id, slot) {
                    if inline_value_into_use(ir, use_id, value) {
                        changed = true;
                    }
                }
            }
        }
        Ok(if changed {
            PassOutcome::Rewritten
        } else {
            PassOutcome::Unchanged
        })
    }
}

/// Returns the value node id of every binding in `slice`, in slot order.
fn binding_value_nodes(ir: &Ir, slice: super::IrBindingSlice) -> Vec<IrId> {
    let start = slice.start as usize;
    let Some(end) = start.checked_add(slice.len()) else {
        return Vec::new();
    };
    match ir.bindings.get(start..end) {
        Some(bindings) => bindings.iter().map(|binding| binding.value).collect(),
        None => Vec::new(),
    }
}

/// Whether the binding value at `id` is proven demanded at most once.
fn is_once(ir: &Ir, id: IrId) -> bool {
    ir.node_facts(id)
        .is_some_and(|facts| facts.cardinality == Cardinality::Once)
}

/// Finds the single same-frame `Local` reference to `slot` within the `let` node
/// `let_id`'s own frame, or `None` if there is not exactly one.
///
/// The scan walks the `let`'s binding values and body but stops at nested frame
/// boundaries (`Lambda`, nested `Let`, recursive `AttrSet`): a `Local` found
/// before any such boundary references this frame's `slot`. A use that lives in
/// a nested frame appears there as an `Upval` and is intentionally not found.
fn unique_same_frame_use(ir: &Ir, let_id: IrId, slot: u32) -> Option<IrId> {
    let IrData::Let { bindings, body, .. } = ir.arena.node(let_id)?.data else {
        return None;
    };
    let mut uses = Vec::new();
    for value in binding_value_nodes(ir, bindings) {
        collect_same_frame_uses(ir, value, slot, &mut uses);
    }
    collect_same_frame_uses(ir, body, slot, &mut uses);
    match uses.as_slice() {
        [single] => Some(*single),
        _ => None,
    }
}

/// Collects `Local { slot }` reference node ids reachable from `node_id` without
/// crossing a nested frame boundary.
fn collect_same_frame_uses(ir: &Ir, node_id: IrId, slot: u32, out: &mut Vec<IrId>) {
    let Some(node) = ir.arena.node(node_id) else {
        return;
    };
    if let IrData::Local { slot: found } = node.data {
        if found == slot {
            out.push(node_id);
        }
        return;
    }
    for child in scan_children(ir, node) {
        collect_same_frame_uses(ir, child, slot, out);
    }
}

/// Returns the child nodes to descend into for a same-frame scan. Nested frame
/// boundaries (`Lambda`, `Let`, recursive `AttrSet`) yield no children so the
/// scan does not enter a nested scope.
fn scan_children(ir: &Ir, node: &IrNode) -> Vec<IrId> {
    let mut children = Vec::new();
    match node.data {
        IrData::Lambda { .. } | IrData::Let { .. } => {}
        IrData::AttrSet {
            recursive: true, ..
        } => {}
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::GlobalVar { .. }
        | IrData::Local { .. }
        | IrData::Upval { .. }
        | IrData::DialectScopeVar { .. } => {}
        IrData::SearchPath { search_path, .. } => children.extend(search_path),
        IrData::Node(child) => children.push(child),
        IrData::Pair { first, second } => children.extend([first, second]),
        IrData::Triple {
            first,
            second,
            third,
        } => children.extend([first, second, third]),
        IrData::Binary { lhs, rhs, .. } => children.extend([lhs, rhs]),
        IrData::Unary { operand, .. } => children.push(operand),
        IrData::DialectNode { argument, .. } => children.push(argument),
        IrData::Children(slice) | IrData::PrimOp { args: slice, .. } => {
            if let Some(ids) = ir.arena.child_slice(slice) {
                children.extend_from_slice(ids);
            }
        }
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            children.push(receiver);
            children.extend(dynamic_path_segments(ir, path));
            children.extend(default);
        }
        IrData::HasAttr { receiver, path, .. } => {
            children.push(receiver);
            children.extend(dynamic_path_segments(ir, path));
        }
        IrData::Bindings(slice)
        | IrData::AttrSet {
            recursive: false,
            bindings: slice,
            ..
        } => {
            children.extend(binding_children(ir, slice));
        }
        IrData::FormalSet { formals, .. } => {
            if let Some(ids) = ir.arena.child_slice(formals) {
                children.extend_from_slice(ids);
            }
        }
        IrData::Formal { default, .. } => children.extend(default),
    }
    children
}

/// The dynamic (`${...}`) segment nodes of an attribute path; static keys carry
/// no child node.
fn dynamic_path_segments(ir: &Ir, path: super::IrAttrPathId) -> Vec<IrId> {
    match ir.attr_paths.get(path.index()) {
        Some(segments) => segments
            .iter()
            .filter_map(|segment| match segment {
                IrAttrPathSegment::Static(_) => None,
                IrAttrPathSegment::Dynamic(node) => Some(*node),
            })
            .collect(),
        None => Vec::new(),
    }
}

/// The value nodes (and dynamic key nodes) of a binding run.
fn binding_children(ir: &Ir, slice: super::IrBindingSlice) -> Vec<IrId> {
    let start = slice.start as usize;
    let Some(end) = start.checked_add(slice.len()) else {
        return Vec::new();
    };
    let mut children = Vec::new();
    if let Some(bindings) = ir.bindings.get(start..end) {
        for binding in bindings {
            if let IrAttrPathSegment::Dynamic(key) = binding.key {
                children.push(key);
            }
            children.push(binding.value);
        }
    }
    children
}

/// Replaces the use node at `use_id` with a copy of the value node `value`,
/// preserving the use node's span. Returns whether the IR actually changed
/// (a no-op copy — e.g. a self-reference — is skipped so the fixpoint settles).
fn inline_value_into_use(ir: &mut Ir, use_id: IrId, value: IrId) -> bool {
    let Some(source) = ir.arena.node(value).copied() else {
        return false;
    };
    let Some(target) = ir.arena.node(use_id).copied() else {
        return false;
    };
    if target.kind == source.kind && target.data == source.data {
        return false;
    }
    ir.arena.set_node(use_id, source.kind, source.effect, source.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConstFold, lower, simplify_with_passes};
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

    /// Returns the body node of a top-level `let` expression.
    fn let_body(ir: &Ir) -> IrData {
        let IrData::Let { body, .. } = ir.arena.node(ir.root).expect("root is a let").data else {
            panic!("root is a let");
        };
        ir.arena.node(body).expect("body exists").data
    }

    #[test]
    fn inlines_single_same_frame_use_and_preserves_frame_layout() {
        let mut ir = lower_source("let x = 1 + 2; in x");
        let slots_before = frame_slot_counts(&ir);
        // Before: the let body is a LocalVar reference to `x`.
        assert!(matches!(let_body(&ir), IrData::Local { .. }));
        simplify_with_passes(&mut ir, &[&InlineSingleUse]).expect("inline succeeds");
        // After: the use is replaced by a copy of the binding value (a lazy
        // `ThunkAlloc` wrapping `1 + 2`), so it is no longer a LocalVar.
        assert!(
            !matches!(let_body(&ir), IrData::Local { .. }),
            "the single use is replaced by the binding value"
        );
        assert_eq!(
            slots_before,
            frame_slot_counts(&ir),
            "frame slot layout is unchanged (elision without compaction)"
        );
    }

    #[test]
    fn inline_then_fold_composes_for_literal_bindings() {
        // A trivial (literal) binding is not thunked, so inlining `x = 5` into
        // `x + 4` exposes `5 + 4`, which ConstFold folds to 9.
        let mut ir = lower_source("let x = 5; in x + 4");
        simplify_with_passes(&mut ir, &[&InlineSingleUse, &ConstFold]).expect("simplify succeeds");
        assert_eq!(let_body(&ir), IrData::Int(9));
    }

    #[test]
    fn declines_multi_use_binding() {
        // `x` used twice is Many, not Once: not inlined; the body stays a BinOp
        // over two LocalVars.
        let mut ir = lower_source("let x = 1 + 2; in x + x");
        simplify_with_passes(&mut ir, &[&InlineSingleUse]).expect("inline succeeds");
        let IrData::Binary { lhs, rhs, .. } = let_body(&ir) else {
            panic!("body is a binop");
        };
        assert!(matches!(ir.arena.node(lhs).expect("lhs").data, IrData::Local { .. }));
        assert!(matches!(ir.arena.node(rhs).expect("rhs").data, IrData::Local { .. }));
    }

    #[test]
    fn declines_use_inside_nested_lambda() {
        // The single use of `x` is inside a lambda body — a nested frame (Upval),
        // not same-frame — so it is not inlined.
        let mut ir = lower_source("let x = 1 + 2; in (y: x)");
        let before = ir.arena.nodes().to_vec();
        simplify_with_passes(&mut ir, &[&InlineSingleUse]).expect("inline succeeds");
        assert_eq!(
            before,
            ir.arena.nodes(),
            "a nested-frame (upvalue) use must not be inlined"
        );
    }
}
