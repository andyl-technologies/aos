//! The recursive scope-resolution walk over the parsed AST arena.
//!
//! These methods drive the depth-first traversal that rewrites identifier
//! nodes, pushes lexical frames, and records the `with`, frame, and `inherit`
//! side tables on [`ResolverState`].

use super::*;

const CUR_POS_NAME: &[u8] = b"__curPos";
const NIX_PATH_NAME: &[u8] = b"__nixPath";

impl ResolverState {
    pub(super) fn resolve_node(&mut self, id: NodeId) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Int
            | NodeKind::Float
            | NodeKind::Str
            | NodeKind::Path
            | NodeKind::Uri
            | NodeKind::LocalVar
            | NodeKind::UpvalVar
            | NodeKind::GlobalVar
            | NodeKind::WithVar => Ok(()),
            NodeKind::SearchPath => self.resolve_search_path(id, node),
            NodeKind::Ident => self.resolve_identifier(id, node),
            NodeKind::List => self.resolve_children_payload(node),
            NodeKind::AttrSet => self.resolve_attrset(node),
            NodeKind::RecAttrSet => self.resolve_rec_attrset(id, node),
            NodeKind::Lambda => self.resolve_lambda(id, node),
            NodeKind::FormalSet => self.resolve_formal_set_defaults(node),
            NodeKind::Formal => self.resolve_formal_default(node),
            NodeKind::Apply | NodeKind::With | NodeKind::Assert => {
                if node.kind == NodeKind::With {
                    self.resolve_with(node)
                } else {
                    self.resolve_pair_payload(node)
                }
            }
            NodeKind::IfThenElse => self.resolve_triple_payload(node),
            NodeKind::BinOp => self.resolve_binary_payload(node),
            NodeKind::UnaryOp => self.resolve_unary_payload(node),
            NodeKind::Select => self.resolve_select_payload(node),
            NodeKind::HasAttr => self.resolve_has_attr_payload(node),
            NodeKind::LetIn => self.resolve_let_in(id, node),
            NodeKind::Binding => self.resolve_binding(id, node, BindingResolveMode::Full),
            NodeKind::Inherit => self.resolve_inherit(id, node, BindingResolveMode::Full),
            NodeKind::Interp => self.resolve_interp_payload(node),
            NodeKind::AttrPath => self.resolve_children_payload(node),
        }
    }

    fn resolve_identifier(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let symbol = self.symbol_payload(node)?;
        if self.symbols.resolve(symbol) == Some(CUR_POS_NAME) {
            return self.replace_node(id, NodeKind::GlobalVar, NodeData::Symbol(symbol));
        }
        if let Some((depth, slot, binding_frame)) = self.lookup_symbol(symbol) {
            self.record_captures(binding_frame, slot, node.span)?;
            let data = if depth == 0 {
                NodeData::Local { slot }
            } else {
                NodeData::Upval { depth, slot }
            };
            let kind = if depth == 0 {
                NodeKind::LocalVar
            } else {
                NodeKind::UpvalVar
            };
            return self.replace_node(id, kind, data);
        }

        if self.symbols.resolve(symbol) == Some(NIX_PATH_NAME) {
            return self.replace_node(id, NodeKind::GlobalVar, NodeData::Symbol(symbol));
        }

        if self.is_unshadowable_global_symbol(symbol) {
            return self.replace_node(id, NodeKind::GlobalVar, NodeData::Symbol(symbol));
        }

        if !self.active_withs.is_empty() {
            let chain = self.push_with_chain(node.span)?;
            return self.replace_node(
                id,
                NodeKind::WithVar,
                NodeData::WithVar {
                    symbol,
                    chain: chain.as_u32(),
                },
            );
        }

        if self.is_global_symbol(symbol) {
            return self.replace_node(id, NodeKind::GlobalVar, NodeData::Symbol(symbol));
        }

        if self.options.allow_unresolved_globals() {
            return self.replace_node(id, NodeKind::GlobalVar, NodeData::Symbol(symbol));
        }

        Err(ScopeError::new(
            ScopeErrorKind::UndefinedSymbol(symbol),
            node.span,
        ))
    }

    fn resolve_search_path(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let literal = match node.data {
            NodeData::Symbol(symbol) => symbol,
            NodeData::SearchPath { literal, .. } => literal,
            _ => return Err(self.invalid_shape(node, "search-path payload")),
        };
        let nix_path = self.nix_path_symbol()?;
        let search_path = if let Some((depth, slot, binding_frame)) = self.lookup_symbol(nix_path) {
            self.record_captures(binding_frame, slot, node.span)?;
            let data = if depth == 0 {
                NodeData::Local { slot }
            } else {
                NodeData::Upval { depth, slot }
            };
            let kind = if depth == 0 {
                NodeKind::LocalVar
            } else {
                NodeKind::UpvalVar
            };
            Some(self.push_synthetic_node(kind, node.span, data)?)
        } else {
            None
        };

        self.replace_node(
            id,
            NodeKind::SearchPath,
            NodeData::SearchPath {
                literal,
                search_path,
            },
        )
    }

    fn resolve_let_in(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let NodeData::LetIn { bindings, body } = node.data else {
            return Err(self.invalid_shape(node, "let-in payload"));
        };
        let binding_ids = self.child_ids(bindings)?;
        for binding in &binding_ids {
            self.resolve_let_binding_target(*binding)?;
        }
        let slots = self.collect_binding_symbols(&binding_ids)?;
        self.push_frame(id, slots, true, false, node.span)?;
        for binding in binding_ids {
            self.resolve_binding_node(binding, BindingResolveMode::ValueOnly)?;
        }
        self.resolve_node(body)?;
        self.pop_frame();
        Ok(())
    }

    fn resolve_lambda(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let NodeData::Pair {
            first: pattern,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "lambda pair"));
        };
        let slots = self.collect_lambda_symbols(pattern)?;
        self.push_frame(id, slots, false, true, node.span)?;
        self.resolve_lambda_pattern(pattern)?;
        self.resolve_node(body)?;
        self.pop_frame();
        Ok(())
    }

    fn resolve_attrset(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Children(bindings) = node.data else {
            return Err(self.invalid_shape(node, "attribute-set bindings"));
        };
        for binding in self.child_ids(bindings)? {
            self.resolve_node(binding)?;
        }
        Ok(())
    }

    fn resolve_rec_attrset(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let NodeData::Children(bindings) = node.data else {
            return Err(self.invalid_shape(node, "recursive attribute-set bindings"));
        };
        let binding_ids = self.child_ids(bindings)?;
        for binding in &binding_ids {
            self.resolve_bare_inherit_source_before_self_frame(*binding)?;
        }
        let slots = self.collect_binding_symbols(&binding_ids)?;
        self.push_frame(id, slots, true, false, node.span)?;
        for binding in &binding_ids {
            self.resolve_binding_node(*binding, BindingResolveMode::PathOnly)?;
        }
        for binding in binding_ids {
            self.resolve_binding_node(binding, BindingResolveMode::ValueOnly)?;
        }
        self.pop_frame();
        Ok(())
    }

    fn resolve_with(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Pair {
            first: scrutinee,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "with pair"));
        };
        self.resolve_node(scrutinee)?;
        self.mark_with_in_active_frames();
        self.active_withs.push(scrutinee);
        self.resolve_node(body)?;
        self.active_withs.pop();
        Ok(())
    }

    fn resolve_binding_node(
        &mut self,
        id: NodeId,
        mode: BindingResolveMode,
    ) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Binding => self.resolve_binding(id, node, mode),
            NodeKind::Inherit => self.resolve_inherit(id, node, mode),
            _ => Err(self.invalid_shape(node, "binding or inherit group")),
        }
    }

    fn resolve_bare_inherit_source_before_self_frame(
        &mut self,
        id: NodeId,
    ) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        let NodeKind::Binding = node.kind else {
            return Ok(());
        };
        let NodeData::Binding { path, value } = node.data else {
            return Err(self.invalid_shape(node, "binding payload"));
        };
        let value_node = self.node(value)?;
        if value_node.kind != NodeKind::Inherit {
            return Ok(());
        }
        let NodeData::Inherit { from, .. } = value_node.data else {
            return Err(self.invalid_shape(value_node, "inherit payload"));
        };
        if from.is_some() {
            return Ok(());
        }
        self.ensure_static_inherit_names(path)?;
        self.resolve_inherit(id, value_node, BindingResolveMode::PathOnly)
    }

    fn resolve_let_binding_target(&mut self, id: NodeId) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Binding => {
                let NodeData::Binding { path, value } = node.data else {
                    return Err(self.invalid_shape(node, "binding payload"));
                };
                if self.node(value)?.kind == NodeKind::Inherit {
                    self.resolve_binding(id, node, BindingResolveMode::PathOnly)
                } else {
                    self.ensure_static_let_path(path)
                }
            }
            NodeKind::Inherit => self.resolve_inherit(id, node, BindingResolveMode::PathOnly),
            _ => Err(self.invalid_shape(node, "binding or inherit group")),
        }
    }

    fn resolve_binding(
        &mut self,
        id: NodeId,
        node: Node,
        mode: BindingResolveMode,
    ) -> Result<(), ScopeError> {
        let NodeData::Binding { path, value } = node.data else {
            return Err(self.invalid_shape(node, "binding payload"));
        };
        let value_node = self.node(value)?;
        if value_node.kind == NodeKind::Inherit {
            self.ensure_static_inherit_names(path)?;
            return self.resolve_inherit(id, value_node, mode);
        }
        if matches!(
            mode,
            BindingResolveMode::Full | BindingResolveMode::PathOnly
        ) {
            self.resolve_attr_path_dynamic(path)?;
        }
        if matches!(
            mode,
            BindingResolveMode::Full | BindingResolveMode::ValueOnly
        ) {
            self.resolve_node(value)?;
        }
        Ok(())
    }

    fn resolve_inherit(
        &mut self,
        id: NodeId,
        node: Node,
        mode: BindingResolveMode,
    ) -> Result<(), ScopeError> {
        let NodeData::Inherit { from, names } = node.data else {
            return Err(self.invalid_shape(node, "inherit payload"));
        };
        self.ensure_static_inherit_names(names)?;

        if matches!(mode, BindingResolveMode::PathOnly)
            && from.is_none()
            && self
                .node_inherits
                .get(id.index())
                .and_then(|group| *group)
                .is_some()
        {
            return Ok(());
        }

        match (mode, from) {
            (BindingResolveMode::Full, None) => {
                self.add_bare_inherit_resolution(id, node.span, names, false)
            }
            (BindingResolveMode::PathOnly, None) => {
                self.add_bare_inherit_resolution(id, node.span, names, true)
            }
            (BindingResolveMode::Full | BindingResolveMode::ValueOnly, Some(from)) => {
                self.resolve_node(from)?;
                self.add_from_inherit_resolution(id, node.span, from, names)
            }
            (BindingResolveMode::PathOnly, Some(_)) | (BindingResolveMode::ValueOnly, None) => {
                Ok(())
            }
        }
    }

    fn resolve_lambda_pattern(&mut self, pattern: NodeId) -> Result<(), ScopeError> {
        let node = self.node(pattern)?;
        match node.kind {
            NodeKind::Ident => Ok(()),
            NodeKind::FormalSet => self.resolve_formal_set_defaults(node),
            _ => Err(self.invalid_shape(node, "lambda pattern")),
        }
    }

    fn resolve_formal_set_defaults(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::FormalSet { formals, .. } = node.data else {
            return Err(self.invalid_shape(node, "formal set payload"));
        };
        for formal in self.child_ids(formals)? {
            self.resolve_formal_default(self.node(formal)?)?;
        }
        Ok(())
    }

    fn resolve_formal_default(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Formal { default, .. } = node.data else {
            return Err(self.invalid_shape(node, "formal payload"));
        };
        if let Some(default) = default {
            self.resolve_node(default)?;
        }
        Ok(())
    }

    fn resolve_pair_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Pair { first, second } = node.data else {
            return Err(self.invalid_shape(node, "pair payload"));
        };
        self.resolve_node(first)?;
        self.resolve_node(second)
    }

    fn resolve_triple_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "triple payload"));
        };
        self.resolve_node(first)?;
        self.resolve_node(second)?;
        self.resolve_node(third)
    }

    fn resolve_binary_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Binary { lhs, rhs, .. } = node.data else {
            return Err(self.invalid_shape(node, "binary payload"));
        };
        self.resolve_node(lhs)?;
        self.resolve_node(rhs)
    }

    fn resolve_unary_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Unary { operand, .. } = node.data else {
            return Err(self.invalid_shape(node, "unary payload"));
        };
        self.resolve_node(operand)
    }

    fn resolve_select_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Select {
            receiver,
            path,
            default,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "select payload"));
        };
        self.resolve_node(receiver)?;
        self.resolve_attr_path_dynamic(path)?;
        if let Some(default) = default {
            self.resolve_node(default)?;
        }
        Ok(())
    }

    fn resolve_has_attr_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::HasAttr { receiver, path } = node.data else {
            return Err(self.invalid_shape(node, "has-attr payload"));
        };
        self.resolve_node(receiver)?;
        self.resolve_attr_path_dynamic(path)
    }

    fn resolve_interp_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        match node.data {
            NodeData::Node(child) => self.resolve_node(child),
            NodeData::Children(children) => {
                for child in self.child_ids(children)? {
                    self.resolve_node(child)?;
                }
                Ok(())
            }
            NodeData::None | NodeData::Symbol(_) => Ok(()),
            _ => Err(self.invalid_shape(node, "interpolation payload")),
        }
    }

    fn resolve_children_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Children(children) = node.data else {
            return Err(self.invalid_shape(node, "children payload"));
        };
        for child in self.child_ids(children)? {
            self.resolve_node(child)?;
        }
        Ok(())
    }

    fn resolve_attr_path_dynamic(&mut self, path: ChildSlice) -> Result<(), ScopeError> {
        for segment in self.child_ids(path)? {
            let node = self.node(segment)?;
            if node.kind == NodeKind::Interp {
                self.resolve_interp_payload(node)?;
            }
        }
        Ok(())
    }

    fn ensure_static_let_path(&self, path: ChildSlice) -> Result<(), ScopeError> {
        for segment in self.child_ids(path)? {
            let node = self.node(segment)?;
            if node.kind == NodeKind::Interp && self.static_attr_symbol(segment)?.is_none() {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicLetBinding,
                    node.span,
                ));
            }
        }
        Ok(())
    }

    fn ensure_static_inherit_names(&self, names: ChildSlice) -> Result<(), ScopeError> {
        for name in self.child_ids(names)? {
            let node = self.node(name)?;
            if self.static_attr_symbol(name)?.is_none() {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicInheritTarget,
                    node.span,
                ));
            }
        }
        Ok(())
    }

    fn add_bare_inherit_resolution(
        &mut self,
        node: NodeId,
        span: Span,
        names: ChildSlice,
        shift_sources: bool,
    ) -> Result<(), ScopeError> {
        let mut sources = Vec::new();
        for name in self.child_ids(names)? {
            let name_node = self.node(name)?;
            let Some(target) = self.static_attr_symbol(name)? else {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicInheritTarget,
                    name_node.span,
                ));
            };
            let source = self.push_synthetic_node(
                NodeKind::Ident,
                name_node.span,
                NodeData::Symbol(target),
            )?;
            self.resolve_node(source)?;
            if shift_sources {
                self.shift_resolved_reference_past_pending_frame(source)?;
            }
            sources.push(InheritSource { target, source });
        }
        self.push_inherit_resolution(
            node,
            InheritResolution {
                from: None,
                sources: sources.into_boxed_slice(),
            },
            span,
        )?;
        Ok(())
    }

    fn shift_resolved_reference_past_pending_frame(
        &mut self,
        id: NodeId,
    ) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::LocalVar => {
                let NodeData::Local { slot } = node.data else {
                    return Err(self.invalid_shape(node, "local payload"));
                };
                self.replace_node(id, NodeKind::UpvalVar, NodeData::Upval { depth: 1, slot })
            }
            NodeKind::UpvalVar => {
                let NodeData::Upval { depth, slot } = node.data else {
                    return Err(self.invalid_shape(node, "upvalue payload"));
                };
                let depth = depth
                    .checked_add(1)
                    .ok_or_else(|| ScopeError::new(ScopeErrorKind::TooManyUpvalues, node.span))?;
                self.replace_node(id, NodeKind::UpvalVar, NodeData::Upval { depth, slot })
            }
            NodeKind::WithVar | NodeKind::GlobalVar => Ok(()),
            _ => Err(self.invalid_shape(node, "resolved inherit source")),
        }
    }

    fn add_from_inherit_resolution(
        &mut self,
        node: NodeId,
        span: Span,
        from: NodeId,
        names: ChildSlice,
    ) -> Result<(), ScopeError> {
        let mut sources = Vec::new();
        for name in self.child_ids(names)? {
            let name_node = self.node(name)?;
            let Some(target) = self.static_attr_symbol(name)? else {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicInheritTarget,
                    name_node.span,
                ));
            };
            let attr = self.push_synthetic_node(
                NodeKind::Ident,
                name_node.span,
                NodeData::Symbol(target),
            )?;
            let path = self
                .arena
                .push_child_slice(&[attr])
                .map_err(ScopeError::from_ast)?;
            let source = self.push_synthetic_node(
                NodeKind::Select,
                self.join_span(self.node(from)?.span, name_node.span),
                NodeData::Select {
                    receiver: from,
                    path,
                    default: None,
                },
            )?;
            sources.push(InheritSource { target, source });
        }
        self.push_inherit_resolution(
            node,
            InheritResolution {
                from: Some(from),
                sources: sources.into_boxed_slice(),
            },
            span,
        )?;
        Ok(())
    }

    fn collect_binding_symbols(&self, bindings: &[NodeId]) -> Result<Vec<Symbol>, ScopeError> {
        let mut slots = Vec::new();
        for binding in bindings {
            let node = self.node(*binding)?;
            match node.kind {
                NodeKind::Binding => {
                    let NodeData::Binding { path, .. } = node.data else {
                        return Err(self.invalid_shape(node, "binding payload"));
                    };
                    if let Some(symbol) = self.first_static_attr_symbol(path)? {
                        push_unique(&mut slots, symbol);
                    }
                }
                NodeKind::Inherit => {
                    let NodeData::Inherit { names, .. } = node.data else {
                        return Err(self.invalid_shape(node, "inherit payload"));
                    };
                    for name in self.child_ids(names)? {
                        if let Some(symbol) = self.static_attr_symbol(name)? {
                            push_unique(&mut slots, symbol);
                        }
                    }
                }
                _ => return Err(self.invalid_shape(node, "binding or inherit group")),
            }
        }
        Ok(slots)
    }

    fn collect_lambda_symbols(&self, pattern: NodeId) -> Result<Vec<Symbol>, ScopeError> {
        let node = self.node(pattern)?;
        match node.kind {
            NodeKind::Ident => Ok(vec![self.symbol_payload(node)?]),
            NodeKind::FormalSet => {
                let NodeData::FormalSet { formals, alias, .. } = node.data else {
                    return Err(self.invalid_shape(node, "formal set payload"));
                };
                let mut slots = Vec::new();
                for formal in self.child_ids(formals)? {
                    let formal = self.node(formal)?;
                    let NodeData::Formal { name, .. } = formal.data else {
                        return Err(self.invalid_shape(formal, "formal payload"));
                    };
                    push_unique(&mut slots, name);
                }
                if let Some(alias) = alias {
                    push_unique(&mut slots, alias);
                }
                Ok(slots)
            }
            _ => Err(self.invalid_shape(node, "lambda pattern")),
        }
    }

    fn first_static_attr_symbol(&self, path: ChildSlice) -> Result<Option<Symbol>, ScopeError> {
        let Some(first) = self.child_ids(path)?.first().copied() else {
            return Ok(None);
        };
        self.static_attr_symbol(first)
    }

    fn static_attr_symbol(&self, id: NodeId) -> Result<Option<Symbol>, ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Ident | NodeKind::Str => Ok(Some(self.symbol_payload(node)?)),
            NodeKind::Interp => {
                let NodeData::Node(child) = node.data else {
                    return Ok(None);
                };
                let child = self.node(child)?;
                if child.kind == NodeKind::Str {
                    Ok(Some(self.symbol_payload(child)?))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn nix_path_symbol(&mut self) -> Result<Symbol, ScopeError> {
        self.symbols
            .intern(NIX_PATH_NAME)
            .map_err(ScopeError::from_ast)
    }
}
