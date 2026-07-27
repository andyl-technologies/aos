//! Force-cache safety classification and static IR traversal.
//!
//! Decides which IR subtrees are safe to cache (lookup vs. observation
//! safety, speculability, cacheable impure builtin calls) and owns the
//! child-pushing walkers those classifications and the dependency collector
//! iterate the IR with.

use super::*;
use crate::cache::hashing::CacheDigestHasher;

impl TreeWalk {
    pub(super) fn subtree_is_speculable(ir: &Ir, symbols: &SymbolTable, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !node.effect.is_speculable() {
                return false;
            }
            if !Self::node_is_force_cache_lookup_safe(symbols, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_kind_is_force_cache_safe(kind: IrKind) -> bool {
        matches!(
            kind,
            IrKind::Int
                | IrKind::Float
                | IrKind::Bool
                | IrKind::Null
                | IrKind::Str
                | IrKind::Uri
                | IrKind::Path
                | IrKind::LocalVar
                | IrKind::UpvalVar
                | IrKind::List
                | IrKind::AttrSet
                | IrKind::Let
                | IrKind::Assert
                | IrKind::If
                | IrKind::BinOp
                | IrKind::UnaryOp
                | IrKind::Interp
                | IrKind::Select
                | IrKind::HasAttr
                | IrKind::ThunkAlloc
        )
    }

    fn node_is_force_cache_lookup_safe(symbols: &SymbolTable, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_lookup_safe(symbols, node);
        }
        Self::node_kind_is_force_cache_safe(node.kind)
    }

    pub(super) fn subtree_is_force_lookup_safe(ir: &Ir, symbols: &SymbolTable, root: IrId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_lookup_safe(ir, symbols, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    pub(in crate::eval::tree_walk::eval_core) fn node_is_force_lookup_safe(
        ir: &Ir,
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_lookup_safe(symbols, node);
        }
        if node.kind == IrKind::SearchPath {
            return Self::search_path_has_cacheable_origin(ir, node);
        }
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_cache_safe(node.kind);
        }
        node.kind == IrKind::PrimOp
            && Self::primop_has_cacheable_impure_input_trace(ir, symbols, node)
    }

    pub(super) fn subtree_is_force_observation_safe(
        ir: &Ir,
        symbols: &SymbolTable,
        root: IrId,
    ) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id.as_u32()) {
                continue;
            }
            let Some(node) = ir.arena.node(id) else {
                return false;
            };
            if !Self::node_is_force_observation_safe(ir, symbols, node) {
                return false;
            }
            if !Self::push_ir_children(ir, node, &mut stack) {
                return false;
            }
        }
        true
    }

    fn node_is_force_observation_safe(ir: &Ir, symbols: &SymbolTable, node: &IrNode) -> bool {
        if node.kind == IrKind::BuiltinAttr {
            return Self::builtin_attr_is_force_cache_observation_safe(symbols, node);
        }
        if node.kind == IrKind::SearchPath {
            return Self::search_path_has_cacheable_origin(ir, node);
        }
        if node.effect.is_speculable() {
            return Self::node_kind_is_force_observation_safe(node.kind);
        }
        node.kind == IrKind::PrimOp
            && Self::primop_has_cacheable_impure_input_trace(ir, symbols, node)
    }

    fn node_kind_is_force_observation_safe(kind: IrKind) -> bool {
        Self::node_kind_is_force_cache_safe(kind)
    }

    pub(in crate::eval::tree_walk::eval_core) fn builtin_attr_execution(
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> Option<BuiltinExecution> {
        let IrData::Symbol(symbol) = node.data else {
            return None;
        };
        debug_assert!(
            symbols.resolve(symbol).is_some(),
            "force-cache builtin symbol is absent from the live symbol table"
        );
        let builtin = lookup_builtin_by_symbol(symbols, symbol)?;
        Some(builtin.execution())
    }

    fn builtin_attr_is_force_cache_lookup_safe(symbols: &SymbolTable, node: &IrNode) -> bool {
        Self::builtin_attr_execution(symbols, node)
            .is_some_and(Self::builtin_execution_is_force_cache_lookup_safe)
    }

    fn builtin_attr_is_force_cache_observation_safe(symbols: &SymbolTable, node: &IrNode) -> bool {
        Self::builtin_attr_execution(symbols, node)
            .is_some_and(Self::builtin_execution_is_force_cache_observation_safe)
    }

    pub(in crate::eval::tree_walk::eval_core) const fn builtin_execution_is_force_cache_lookup_safe(
        execution: BuiltinExecution,
    ) -> bool {
        matches!(
            execution,
            BuiltinExecution::TrueValue
                | BuiltinExecution::FalseValue
                | BuiltinExecution::NullValue
                | BuiltinExecution::CurrentSystemValue
                | BuiltinExecution::StoreDirValue
                | BuiltinExecution::NixVersionValue
                | BuiltinExecution::LangVersionValue
                | BuiltinExecution::NixPathValue
        )
    }

    pub(in crate::eval::tree_walk::eval_core) const fn builtin_execution_is_force_cache_observation_safe(
        execution: BuiltinExecution,
    ) -> bool {
        Self::builtin_execution_is_force_cache_lookup_safe(execution)
            || matches!(execution, BuiltinExecution::CurrentTimeValue)
    }

    const fn builtin_execution_cache_identity_bytes(
        execution: BuiltinExecution,
    ) -> Option<&'static [u8]> {
        match execution {
            BuiltinExecution::TrueValue => Some(b"true"),
            BuiltinExecution::FalseValue => Some(b"false"),
            BuiltinExecution::NullValue => Some(b"null"),
            BuiltinExecution::CurrentSystemValue => Some(b"current-system"),
            BuiltinExecution::CurrentTimeValue => Some(b"current-time"),
            BuiltinExecution::StoreDirValue => Some(b"store-dir"),
            BuiltinExecution::NixVersionValue => Some(b"nix-version"),
            BuiltinExecution::LangVersionValue => Some(b"lang-version"),
            BuiltinExecution::NixPathValue => Some(b"nix-path"),
            _ => None,
        }
    }

    pub(in crate::eval::tree_walk) fn cache_synthetic_builtin_attr_identity(
        &self,
        site: EvalNodeRef,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(site.module().index())?;
        let site_node = module.ir.arena.node(site.id())?;
        let symbol_name = self
            .symbols
            .resolve(symbol)
            .unwrap_or_else(|| builtin.name());
        let execution = builtin.execution();
        let module_hash = Self::cache_synthetic_builtin_module_identity_hash(module, execution)?;
        let execution_bytes = Self::builtin_execution_cache_identity_bytes(execution)?;
        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_SYNTHETIC_BUILTIN_ATTR_IDENTITY_DOMAIN_VERSION);
        hasher.update(&module_hash.as_bytes());
        hasher.update(&site.id().as_u32().to_le_bytes());
        hasher.update(&site_node.span.start.to_le_bytes());
        hasher.update(&site_node.span.end.to_le_bytes());
        Self::update_cache_identity_chunk(&mut hasher, symbol_name)?;
        Self::update_cache_identity_chunk(&mut hasher, execution_bytes)?;
        Some(CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            site.id(),
        ))
    }

    pub(in crate::eval::tree_walk) fn cache_synthetic_select_identity(
        &self,
        select: EvalNodeRef,
        path: IrAttrPathId,
    ) -> Option<CacheExprIdentity> {
        let module = self.modules.get(select.module().index())?;
        let module_hash = Self::cache_module_identity_hash(module)?;
        let select_node = module.ir.arena.node(select.id())?;
        let segments = module.ir.attr_paths.get(path.index())?;
        if segments.is_empty() {
            return None;
        }

        let mut hasher = CacheDigestHasher::new();
        hasher.update(FORCE_SYNTHETIC_SELECT_IDENTITY_DOMAIN_VERSION);
        hasher.update(&module_hash.as_bytes());
        hasher.update(&select.id().as_u32().to_le_bytes());
        hasher.update(&select_node.span.start.to_le_bytes());
        hasher.update(&select_node.span.end.to_le_bytes());
        let len = u64::try_from(segments.len()).ok()?;
        hasher.update(&len.to_le_bytes());
        for segment in segments.iter().copied() {
            let IrAttrPathSegment::Static(symbol) = segment else {
                return None;
            };
            debug_assert!(
                self.symbols.resolve(symbol).is_some(),
                "force-cache select symbol is absent from the live symbol table"
            );
            let name = self.symbols.resolve(symbol)?;
            Self::update_cache_identity_chunk(&mut hasher, name)?;
        }
        Some(CacheExprIdentity::new(
            CacheExprSourceHash::from_durable_hash(DurableBlake3Hash::from_hasher(hasher)),
            select.id(),
        ))
    }

    fn primop_has_cacheable_impure_input_trace(
        ir: &Ir,
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> bool {
        let IrData::PrimOp { symbol, .. } = node.data else {
            return false;
        };
        debug_assert!(
            symbols.resolve(symbol).is_some(),
            "force-cache primop symbol is absent from the live symbol table"
        );
        match symbols.resolve(symbol) {
            Some(b"findFile") => {
                Self::primop_find_file_has_cacheable_search_path_arg(ir, symbols, node)
            }
            Some(
                b"import" | b"getEnv" | b"hashFile" | b"pathExists" | b"readDir" | b"readFile"
                | b"readFileType",
            ) => true,
            _ => false,
        }
    }

    fn primop_find_file_has_cacheable_search_path_arg(
        ir: &Ir,
        symbols: &SymbolTable,
        node: &IrNode,
    ) -> bool {
        let IrData::PrimOp { args, .. } = node.data else {
            return false;
        };
        let Some(args) = ir.arena.child_slice(args) else {
            return false;
        };
        let Some(first_arg) = args.first() else {
            return false;
        };
        let Some(first_arg) = ir.arena.node(*first_arg) else {
            return false;
        };
        first_arg.kind == IrKind::List
            || Self::node_is_builtin_nix_path_attr(symbols, first_arg)
            || Self::node_is_captured_search_path_value(first_arg)
    }

    fn node_is_builtin_nix_path_attr(symbols: &SymbolTable, node: &IrNode) -> bool {
        node.kind == IrKind::BuiltinAttr
            && Self::builtin_attr_execution(symbols, node) == Some(BuiltinExecution::NixPathValue)
    }

    pub(super) fn search_path_has_cacheable_origin(ir: &Ir, node: &IrNode) -> bool {
        let IrData::SearchPath { search_path, .. } = node.data else {
            return false;
        };
        let Some(search_path) = search_path else {
            return true;
        };
        ir.arena
            .node(search_path)
            .is_some_and(Self::node_is_captured_search_path_value)
    }

    fn node_is_captured_search_path_value(node: &IrNode) -> bool {
        matches!(node.data, IrData::Local { .. } | IrData::Upval { .. })
    }

    pub(in crate::eval::tree_walk::eval_core) fn push_ir_children(
        ir: &Ir,
        node: &IrNode,
        stack: &mut Vec<IrId>,
    ) -> bool {
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. } => {}
            IrData::SearchPath { search_path, .. } => {
                stack.extend(search_path);
            }
            IrData::Node(child) => stack.push(child),
            IrData::Pair { first, second } => {
                stack.push(first);
                stack.push(second);
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                stack.push(first);
                stack.push(second);
                stack.push(third);
            }
            IrData::Children(children) => {
                let Some(children) = ir.arena.child_slice(children) else {
                    return false;
                };
                stack.extend(children.iter().copied());
            }
            IrData::Bindings(bindings) => {
                if !Self::push_binding_children(ir, bindings, stack) {
                    return false;
                }
            }
            IrData::Binary { op, lhs, rhs } => {
                if matches!(op, BinOpKind::PipeLeft | BinOpKind::PipeRight) {
                    return false;
                }
                stack.push(lhs);
                stack.push(rhs);
            }
            IrData::Unary { operand, .. } => stack.push(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                stack.push(receiver);
                stack.extend(default);
                if !Self::push_attr_path_children(ir, path, stack) {
                    return false;
                }
            }
            IrData::HasAttr { receiver, path, .. } => {
                stack.push(receiver);
                if !Self::push_attr_path_children(ir, path, stack) {
                    return false;
                }
            }
            IrData::PrimOp { args, .. } => {
                let Some(args) = ir.arena.child_slice(args) else {
                    return false;
                };
                stack.extend(args.iter().copied());
            }
            IrData::DialectNode { argument, .. } => stack.push(argument),
            IrData::DialectScopeVar { chain, .. } => {
                let Some(chain) = usize::try_from(chain)
                    .ok()
                    .and_then(|index| ir.with_chains.get(index))
                else {
                    return false;
                };
                stack.extend(chain.scopes.iter().copied());
            }
            IrData::Lambda { pattern, body, .. } => {
                stack.push(pattern);
                stack.push(body);
            }
            IrData::Let { bindings, body, .. } => {
                stack.push(body);
                if !Self::push_binding_children(ir, bindings, stack) {
                    return false;
                }
            }
            IrData::AttrSet { bindings, .. } => {
                if !Self::push_binding_children(ir, bindings, stack) {
                    return false;
                }
            }
            IrData::FormalSet { formals, .. } => {
                let Some(formals) = ir.arena.child_slice(formals) else {
                    return false;
                };
                stack.extend(formals.iter().copied());
            }
            IrData::Formal { default, .. } => {
                stack.extend(default);
            }
            IrData::Local { .. } | IrData::Upval { .. } => {}
        }
        true
    }

    fn push_binding_children(ir: &Ir, bindings: IrBindingSlice, stack: &mut Vec<IrId>) -> bool {
        let start = bindings.start as usize;
        let Some(end) = start.checked_add(bindings.len()) else {
            return false;
        };
        let Some(bindings) = ir.bindings.get(start..end) else {
            return false;
        };
        for binding in bindings {
            stack.push(binding.value);
            if let IrAttrPathSegment::Dynamic(segment) = binding.key {
                stack.push(segment);
            }
        }
        true
    }

    fn push_static_binding_values_with_scope(
        ir: &Ir,
        bindings: IrBindingSlice,
        nested_frame_count: usize,
        stack: &mut Vec<(IrId, usize)>,
    ) -> bool {
        let start = bindings.start as usize;
        let Some(end) = start.checked_add(bindings.len()) else {
            return false;
        };
        let Some(bindings) = ir.bindings.get(start..end) else {
            return false;
        };
        for binding in bindings {
            if !matches!(binding.key, IrAttrPathSegment::Static(_)) {
                return false;
            }
            stack.push((binding.value, nested_frame_count));
        }
        true
    }

    pub(super) fn extend_dependency_walk_stack(
        stack: &mut Vec<(IrId, usize, Vec<StaticBindingScope>)>,
        children: Vec<IrId>,
        nested_frame_count: usize,
        static_scopes: &[StaticBindingScope],
    ) -> Option<()> {
        stack.try_reserve_exact(children.len()).ok()?;
        for child in children {
            stack.push((child, nested_frame_count, static_scopes.to_vec()));
        }
        Some(())
    }

    pub(super) fn static_scopes_with_scope(
        parent: &[StaticBindingScope],
        bindings: IrBindingSlice,
    ) -> Option<Vec<StaticBindingScope>> {
        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(parent.len().checked_add(1)?)
            .ok()?;
        scopes.push(StaticBindingScope::from(bindings));
        scopes.extend_from_slice(parent);
        Some(scopes)
    }

    pub(super) fn static_scope_binding<'a>(
        ir: &'a Ir,
        static_scopes: &[StaticBindingScope],
        depth: usize,
        slot: u32,
    ) -> Option<&'a IrBinding> {
        let scope = static_scopes.get(depth)?.as_binding_slice();
        let bindings = Self::binding_slice(ir, scope)?;
        bindings.get(slot as usize)
    }

    pub(super) fn push_reachable_static_binding_values_with_dependency_scope(
        ir: &Ir,
        bindings: IrBindingSlice,
        body: IrId,
        nested_frame_count: usize,
        static_scopes: &[StaticBindingScope],
        stack: &mut Vec<(IrId, usize, Vec<StaticBindingScope>)>,
    ) -> bool {
        let Some(binding_values) = Self::binding_slice(ir, bindings) else {
            return false;
        };
        if !binding_values
            .iter()
            .all(|binding| matches!(binding.key, IrAttrPathSegment::Static(_)))
        {
            return false;
        }
        let Some(reachable) =
            Self::reachable_let_binding_slots_for_dependencies(ir, body, binding_values)
        else {
            stack.extend(
                binding_values
                    .iter()
                    .map(|binding| (binding.value, nested_frame_count, static_scopes.to_vec())),
            );
            return true;
        };
        for slot in reachable {
            let Some(binding) = binding_values.get(slot) else {
                return false;
            };
            stack.push((binding.value, nested_frame_count, static_scopes.to_vec()));
        }
        true
    }

    pub(super) fn push_reachable_static_binding_values_with_scope(
        ir: &Ir,
        bindings: IrBindingSlice,
        body: IrId,
        nested_frame_count: usize,
        stack: &mut Vec<(IrId, usize)>,
    ) -> bool {
        let Some(binding_values) = Self::binding_slice(ir, bindings) else {
            return false;
        };
        if !binding_values
            .iter()
            .all(|binding| matches!(binding.key, IrAttrPathSegment::Static(_)))
        {
            return false;
        }
        let Some(reachable) = Self::reachable_let_binding_slots(ir, body, binding_values) else {
            return Self::push_static_binding_values_with_scope(
                ir,
                bindings,
                nested_frame_count,
                stack,
            );
        };
        for slot in reachable {
            let Some(binding) = binding_values.get(slot) else {
                return false;
            };
            stack.push((binding.value, nested_frame_count));
        }
        true
    }

    fn reachable_let_binding_slots(
        ir: &Ir,
        body: IrId,
        bindings: &[IrBinding],
    ) -> Option<BTreeSet<usize>> {
        let mut reachable = BTreeSet::new();
        let mut visited_nodes = BTreeSet::new();
        let mut stack = vec![body];
        while let Some(id) = stack.pop() {
            if !visited_nodes.insert(id.as_u32()) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    let slot = slot as usize;
                    if slot >= bindings.len() {
                        return None;
                    }
                    if reachable.insert(slot) {
                        stack.push(bindings.get(slot)?.value);
                    }
                }
                IrData::Let { .. }
                | IrData::Lambda { .. }
                | IrData::FormalSet { .. }
                | IrData::Formal { .. }
                | IrData::AttrSet {
                    recursive: true, ..
                } => {
                    return None;
                }
                _ => {
                    let mut children = Vec::new();
                    if !Self::push_ir_children(ir, node, &mut children) {
                        return None;
                    }
                    stack.extend(children);
                }
            }
        }
        Some(reachable)
    }

    fn reachable_let_binding_slots_for_dependencies(
        ir: &Ir,
        body: IrId,
        bindings: &[IrBinding],
    ) -> Option<BTreeSet<usize>> {
        let mut reachable = BTreeSet::new();
        let mut visited_nodes = BTreeSet::new();
        let mut stack = vec![body];
        while let Some(id) = stack.pop() {
            if !visited_nodes.insert(id.as_u32()) {
                continue;
            }
            let node = ir.arena.node(id)?;
            match node.data {
                IrData::Local { slot } => {
                    let slot = slot as usize;
                    if slot >= bindings.len() {
                        return None;
                    }
                    if reachable.insert(slot) {
                        stack.push(bindings.get(slot)?.value);
                    }
                }
                IrData::Select {
                    receiver,
                    path,
                    default: Some(_),
                    ..
                } if Self::attr_path_is_static(ir, path)? => {
                    stack.push(receiver);
                    if !Self::push_attr_path_children(ir, path, &mut stack) {
                        return None;
                    }
                }
                IrData::Let { .. }
                | IrData::Lambda { .. }
                | IrData::FormalSet { .. }
                | IrData::Formal { .. }
                | IrData::AttrSet {
                    recursive: true, ..
                } => {
                    return None;
                }
                _ => {
                    let mut children = Vec::new();
                    if !Self::push_ir_children(ir, node, &mut children) {
                        return None;
                    }
                    stack.extend(children);
                }
            }
        }
        Some(reachable)
    }

    fn attr_path_is_static(ir: &Ir, path: IrAttrPathId) -> Option<bool> {
        let segments = ir.attr_paths.get(path.index())?;
        Some(
            !segments.is_empty()
                && segments
                    .iter()
                    .all(|segment| matches!(segment, IrAttrPathSegment::Static(_))),
        )
    }

    fn binding_slice(ir: &Ir, bindings: IrBindingSlice) -> Option<&[IrBinding]> {
        let start = bindings.start as usize;
        let end = start.checked_add(bindings.len())?;
        ir.bindings.get(start..end)
    }

    fn push_attr_path_children(ir: &Ir, path: IrAttrPathId, stack: &mut Vec<IrId>) -> bool {
        let Some(segments) = ir.attr_paths.get(path.index()) else {
            return false;
        };
        for segment in segments.as_ref() {
            if let IrAttrPathSegment::Dynamic(segment) = segment {
                stack.push(*segment);
            }
        }
        true
    }
}
