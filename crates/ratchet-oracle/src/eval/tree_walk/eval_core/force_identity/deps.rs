//! Captured free-variable slot and dependency collection.
//!
//! Walks a cacheable body's IR to enumerate the environment slots, static
//! selects, and has-attr probes its force-cache identity depends on, scoping
//! let-bindings to the reachable subset so unrelated siblings do not widen
//! the capture set.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn captured_free_variable_slots(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
    ) -> Option<BTreeSet<(usize, u32)>> {
        let mut visited = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut stack = vec![(root, 0usize)];
        while let Some((id, nested_frame_count)) = stack.pop() {
            if !visited.insert((id.as_u32(), nested_frame_count)) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    if nested_frame_count > 0 {
                        continue;
                    }
                    let frame_index = captured_frame_count.checked_sub(1)?;
                    slots.insert((frame_index, slot));
                }
                IrData::Upval { depth, slot } => {
                    let depth = depth as usize;
                    if depth < nested_frame_count {
                        continue;
                    }
                    let captured_depth = depth - nested_frame_count;
                    if captured_depth >= captured_frame_count {
                        return None;
                    }
                    slots.insert((captured_frame_count - 1 - captured_depth, slot));
                }
                IrData::Let { bindings, body, .. } => {
                    let nested_frame_count = nested_frame_count.checked_add(1)?;
                    stack.push((body, nested_frame_count));
                    Self::push_reachable_static_binding_values_with_scope(
                        ir,
                        bindings,
                        body,
                        nested_frame_count,
                        &mut stack,
                    )
                    .then_some(())?;
                }
                IrData::Lambda { .. }
                | IrData::FormalSet { .. }
                | IrData::Formal { .. }
                | IrData::AttrSet {
                    recursive: true, ..
                } => {
                    return None;
                }
                IrData::None
                | IrData::Int(_)
                | IrData::Float(_)
                | IrData::Bool(_)
                | IrData::Symbol(_)
                | IrData::GlobalVar { .. }
                | IrData::SearchPath { .. }
                | IrData::Node(_)
                | IrData::Pair { .. }
                | IrData::Triple { .. }
                | IrData::Children(_)
                | IrData::Bindings(_)
                | IrData::Binary { .. }
                | IrData::Unary { .. }
                | IrData::Select { .. }
                | IrData::HasAttr { .. }
                | IrData::PrimOp { .. }
                | IrData::DialectNode { .. }
                | IrData::DialectScopeVar { .. }
                | IrData::AttrSet {
                    recursive: false, ..
                } => {
                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    stack.extend(
                        children
                            .into_iter()
                            .map(|child| (child, nested_frame_count)),
                    );
                }
            }
        }
        Some(slots)
    }

    pub(in crate::eval::tree_walk::eval_core) fn captured_free_variable_dependencies(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        Self::captured_free_variable_dependencies_from(ir, root, captured_frame_count, 0)
    }

    fn captured_free_variable_dependencies_from(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
        initial_nested_frame_count: usize,
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        Self::captured_free_variable_dependencies_from_with_static_scopes(
            ir,
            root,
            captured_frame_count,
            initial_nested_frame_count,
            &[],
        )
    }

    pub(super) fn captured_free_variable_dependencies_from_with_static_scopes(
        ir: &Ir,
        root: IrId,
        captured_frame_count: usize,
        initial_nested_frame_count: usize,
        initial_static_scopes: &[StaticBindingScope],
    ) -> Option<BTreeSet<CapturedFreeVariableDependency>> {
        let mut visited = BTreeSet::new();
        let mut dependencies = BTreeSet::new();
        let mut stack = vec![(
            root,
            initial_nested_frame_count,
            initial_static_scopes.to_vec(),
        )];
        while let Some((id, nested_frame_count, static_scopes)) = stack.pop() {
            if !visited.insert((id.as_u32(), nested_frame_count, static_scopes.clone())) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    if nested_frame_count > 0 {
                        let binding = Self::static_scope_binding(ir, &static_scopes, 0, slot)?;
                        stack.push((binding.value, nested_frame_count, static_scopes));
                        continue;
                    }
                    let frame_index = captured_frame_count.checked_sub(1)?;
                    dependencies.insert(CapturedFreeVariableDependency::Slot { frame_index, slot });
                }
                IrData::Upval { depth, slot } => {
                    let depth = depth as usize;
                    if depth < nested_frame_count {
                        let binding = Self::static_scope_binding(ir, &static_scopes, depth, slot)?;
                        let nested_frame_count = nested_frame_count.checked_sub(depth)?;
                        let static_scopes = static_scopes.get(depth..)?.to_vec();
                        stack.push((binding.value, nested_frame_count, static_scopes));
                        continue;
                    }
                    let captured_depth = depth - nested_frame_count;
                    if captured_depth >= captured_frame_count {
                        return None;
                    }
                    dependencies.insert(CapturedFreeVariableDependency::Slot {
                        frame_index: captured_frame_count - 1 - captured_depth,
                        slot,
                    });
                }
                IrData::Select {
                    receiver,
                    path,
                    default,
                    ..
                } => {
                    if let Some(dependency) = Self::captured_static_select_dependency(
                        ir,
                        receiver,
                        path,
                        default,
                        captured_frame_count,
                        nested_frame_count,
                        &static_scopes,
                    ) {
                        dependencies.insert(dependency);
                        continue;
                    }

                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    Self::extend_dependency_walk_stack(
                        &mut stack,
                        children,
                        nested_frame_count,
                        &static_scopes,
                    )?;
                }
                IrData::HasAttr { receiver, path, .. } => {
                    if let Some(dependency) = Self::captured_static_has_attr_dependency(
                        ir,
                        receiver,
                        path,
                        captured_frame_count,
                        nested_frame_count,
                    ) {
                        dependencies.insert(dependency);
                        continue;
                    }

                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    Self::extend_dependency_walk_stack(
                        &mut stack,
                        children,
                        nested_frame_count,
                        &static_scopes,
                    )?;
                }
                IrData::Let { bindings, body, .. } => {
                    let nested_frame_count = nested_frame_count.checked_add(1)?;
                    let static_scopes = Self::static_scopes_with_scope(&static_scopes, bindings)?;
                    stack.push((body, nested_frame_count, static_scopes.clone()));
                    Self::push_reachable_static_binding_values_with_dependency_scope(
                        ir,
                        bindings,
                        body,
                        nested_frame_count,
                        &static_scopes,
                        &mut stack,
                    )
                    .then_some(())?;
                }
                IrData::Lambda { .. }
                | IrData::FormalSet { .. }
                | IrData::Formal { .. }
                | IrData::AttrSet {
                    recursive: true, ..
                } => {
                    return None;
                }
                IrData::None
                | IrData::Int(_)
                | IrData::Float(_)
                | IrData::Bool(_)
                | IrData::Symbol(_)
                | IrData::GlobalVar { .. }
                | IrData::SearchPath { .. }
                | IrData::Node(_)
                | IrData::Pair { .. }
                | IrData::Triple { .. }
                | IrData::Children(_)
                | IrData::Bindings(_)
                | IrData::Binary { .. }
                | IrData::Unary { .. }
                | IrData::PrimOp { .. }
                | IrData::DialectNode { .. }
                | IrData::DialectScopeVar { .. }
                | IrData::AttrSet {
                    recursive: false, ..
                } => {
                    let mut children = Vec::new();
                    Self::push_ir_children(ir, node, &mut children).then_some(())?;
                    Self::extend_dependency_walk_stack(
                        &mut stack,
                        children,
                        nested_frame_count,
                        &static_scopes,
                    )?;
                }
            }
        }
        Some(dependencies)
    }

    fn captured_static_has_attr_dependency(
        ir: &Ir,
        receiver: IrId,
        path: IrAttrPathId,
        captured_frame_count: usize,
        nested_frame_count: usize,
    ) -> Option<CapturedFreeVariableDependency> {
        let segments = ir.attr_paths.get(path.index())?;
        if segments.is_empty()
            || !segments
                .iter()
                .all(|segment| matches!(segment, IrAttrPathSegment::Static(_)))
        {
            return None;
        }
        let (frame_index, slot) = Self::captured_frame_slot_for_node(
            ir,
            receiver,
            captured_frame_count,
            nested_frame_count,
        )?;
        Some(CapturedFreeVariableDependency::StaticHasAttr {
            frame_index,
            slot,
            path: path.as_u32(),
        })
    }

    fn captured_static_select_dependency(
        ir: &Ir,
        receiver: IrId,
        path: IrAttrPathId,
        default: Option<IrId>,
        captured_frame_count: usize,
        nested_frame_count: usize,
        static_scopes: &[StaticBindingScope],
    ) -> Option<CapturedFreeVariableDependency> {
        let segments = ir.attr_paths.get(path.index())?;
        if segments.is_empty()
            || !segments
                .iter()
                .all(|segment| matches!(segment, IrAttrPathSegment::Static(_)))
        {
            return None;
        }
        let (frame_index, slot) = Self::captured_frame_slot_for_node(
            ir,
            receiver,
            captured_frame_count,
            nested_frame_count,
        )?;
        let default = default.map(|default| DefaultSelectDependency {
            node: default.as_u32(),
            nested_frame_count,
            static_scopes: static_scopes.to_vec().into_boxed_slice(),
        });
        Some(CapturedFreeVariableDependency::StaticSelect {
            frame_index,
            slot,
            path: path.as_u32(),
            default,
        })
    }

    fn captured_frame_slot_for_node(
        ir: &Ir,
        id: IrId,
        captured_frame_count: usize,
        nested_frame_count: usize,
    ) -> Option<(usize, u32)> {
        let node = ir.arena.node(id)?;
        match node.data {
            IrData::Node(child) if node.kind == IrKind::ThunkAlloc => {
                Self::captured_frame_slot_for_node(
                    ir,
                    child,
                    captured_frame_count,
                    nested_frame_count,
                )
            }
            IrData::Local { slot } => {
                if nested_frame_count > 0 {
                    return None;
                }
                Some((captured_frame_count.checked_sub(1)?, slot))
            }
            IrData::Upval { depth, slot } => {
                let depth = depth as usize;
                if depth < nested_frame_count {
                    return None;
                }
                let captured_depth = depth - nested_frame_count;
                if captured_depth >= captured_frame_count {
                    return None;
                }
                Some((captured_frame_count - 1 - captured_depth, slot))
            }
            _ => None,
        }
    }
}
