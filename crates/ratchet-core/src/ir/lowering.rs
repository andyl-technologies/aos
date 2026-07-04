//! The IR lowering walk: AST nodes to fixed-stride arena IR.
//!
//! Owns [`IrLowerer`], the stateful pass that consumes a [`ResolvedAst`] and
//! emits the [`Ir`] artifact, materializing thunks at lazy positions and
//! moving variable-arity payloads into side tables.

use super::*;

impl IrLowerer {
    pub(super) fn new(resolved: ResolvedAst, options: IrLowerOptions) -> Self {
        Self {
            resolved,
            options,
            arena: IrArena::new(),
            lowered_nodes: BTreeMap::new(),
            attr_paths: Vec::new(),
            bindings: Vec::new(),
            shapes: Vec::new(),
            with_chains: Vec::new(),
            with_chain_map: BTreeMap::new(),
            inherit_from_thunks: BTreeMap::new(),
            inline_cache_sites: 0,
        }
    }

    pub(super) fn lower(mut self) -> Result<Ir, IrError> {
        let root = self.lower_expr(self.resolved.root)?;
        let frames = self.resolved.scopes.frames().to_vec().into_boxed_slice();
        let facts = IrFacts::conservative(self.arena.nodes().len());
        Ok(Ir {
            root,
            arena: self.arena,
            facts,
            symbols: self.resolved.symbols,
            frames,
            with_chains: self.with_chains.into_boxed_slice(),
            attr_paths: self.attr_paths.into_boxed_slice(),
            bindings: self.bindings.into_boxed_slice(),
            shapes: self.shapes.into_boxed_slice(),
        })
    }

    pub(super) fn lower_expr(&mut self, id: NodeId) -> Result<IrId, IrError> {
        let node = self.node(id)?;
        let lowered = match node.kind {
            NodeKind::Int => {
                let NodeData::Int(value) = node.data else {
                    return Err(self.invalid_shape(node, "integer payload"));
                };
                self.push(IrKind::Int, node.span, IrData::Int(value))
            }
            NodeKind::Float => {
                let NodeData::Float(value) = node.data else {
                    return Err(self.invalid_shape(node, "float payload"));
                };
                self.push(IrKind::Float, node.span, IrData::Float(value))
            }
            NodeKind::Str => self.lower_symbol_node(node, IrKind::Str),
            NodeKind::Path => self.lower_symbol_node(node, IrKind::Path),
            NodeKind::SearchPath => self.lower_search_path(node),
            NodeKind::Uri => self.lower_symbol_node(node, IrKind::Uri),
            NodeKind::LocalVar => {
                let NodeData::Local { slot } = node.data else {
                    return Err(self.invalid_shape(node, "local payload"));
                };
                self.push(IrKind::LocalVar, node.span, IrData::Local { slot })
            }
            NodeKind::UpvalVar => {
                let NodeData::Upval { depth, slot } = node.data else {
                    return Err(self.invalid_shape(node, "upvalue payload"));
                };
                self.push(IrKind::UpvalVar, node.span, IrData::Upval { depth, slot })
            }
            NodeKind::GlobalVar => self.lower_global(node),
            NodeKind::WithVar => self.lower_dynamic_scope_var(node),
            NodeKind::List => self.lower_list(node),
            NodeKind::AttrSet => self.lower_attrset(id, node, false),
            NodeKind::RecAttrSet => self.lower_attrset(id, node, true),
            NodeKind::Lambda => self.lower_lambda(id, node),
            NodeKind::FormalSet => self.lower_formal_set(node),
            NodeKind::Formal => self.lower_formal(node),
            NodeKind::Apply => self.lower_apply(node),
            NodeKind::Select => self.lower_select(node),
            NodeKind::HasAttr => self.lower_has_attr(node),
            NodeKind::LetIn => self.lower_let(id, node),
            NodeKind::With => self.lower_with(node),
            NodeKind::Assert => self.lower_pair(node, IrKind::Assert, LazySecond::No),
            NodeKind::IfThenElse => self.lower_if(node),
            NodeKind::BinOp => self.lower_binary(node),
            NodeKind::UnaryOp => self.lower_unary(node),
            NodeKind::Interp => self.lower_interp(node),
            NodeKind::Binding | NodeKind::Inherit | NodeKind::Ident | NodeKind::AttrPath => {
                Err(self.invalid_shape(node, "lowerable expression"))
            }
        }?;
        self.lowered_nodes.insert(id, lowered);
        Ok(lowered)
    }

    pub(super) fn lower_symbol_node(&mut self, node: Node, kind: IrKind) -> Result<IrId, IrError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.invalid_shape(node, "symbol payload"));
        };
        self.push(kind, node.span, IrData::Symbol(symbol))
    }

    pub(super) fn lower_search_path(&mut self, node: Node) -> Result<IrId, IrError> {
        let (literal, search_path) = match node.data {
            NodeData::Symbol(symbol) => (symbol, None),
            NodeData::SearchPath {
                literal,
                search_path,
            } => {
                let lowered = search_path
                    .map(|search_path| self.lower_expr(search_path))
                    .transpose()?;
                (literal, lowered)
            }
            _ => return Err(self.invalid_shape(node, "search-path payload")),
        };
        self.push(
            IrKind::SearchPath,
            node.span,
            IrData::SearchPath {
                literal,
                search_path,
            },
        )
    }

    pub(super) fn lower_global(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.invalid_shape(node, "global symbol payload"));
        };
        if self.options.dynamic_builtin_scope() {
            return self.push_global_var(node.span, symbol);
        }
        match self.resolved.symbols.resolve(symbol) {
            Some(b"true") => self.push(IrKind::Bool, node.span, IrData::Bool(true)),
            Some(b"false") => self.push(IrKind::Bool, node.span, IrData::Bool(false)),
            Some(b"null") => self.push(IrKind::Null, node.span, IrData::None),
            _ => self.push_global_var(node.span, symbol),
        }
    }

    fn push_global_var(&mut self, span: Span, symbol: Symbol) -> Result<IrId, IrError> {
        let site = self.next_inline_cache_site(span)?;
        self.push(IrKind::GlobalVar, span, IrData::GlobalVar { site, symbol })
    }

    pub(super) fn lower_dynamic_scope_var(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::WithVar { symbol, chain } = node.data else {
            return Err(self.invalid_shape(node, "with-var payload"));
        };
        if self.with_chain_statically_selects_builtins(chain, symbol, node.span)? {
            return self.push(IrKind::BuiltinAttr, node.span, IrData::Symbol(symbol));
        }
        let Some(op) = (self.options.dynamic_scope_var_op())() else {
            return Err(IrError::new(
                IrErrorKind::UnsupportedDialectOp {
                    operation: "dynamic scope variable",
                },
                node.span,
            ));
        };
        let chain = self.lower_with_chain(chain, node.span)?;
        let site = self.next_inline_cache_site(node.span)?;
        self.push_with_effect(
            IrKind::PrimOp,
            node.span,
            (self.options.dialect_op_effect_of())(op),
            IrData::DialectScopeVar {
                op,
                site,
                symbol,
                chain,
            },
        )
    }

    fn with_chain_statically_selects_builtins(
        &self,
        chain: u32,
        symbol: Symbol,
        span: Span,
    ) -> Result<bool, IrError> {
        if self.options.dynamic_builtin_scope() {
            return Ok(false);
        }
        if !self
            .resolved
            .symbols
            .resolve(symbol)
            .is_some_and(is_known_builtin_attr)
        {
            return Ok(false);
        }
        let resolver_chain = self
            .resolved
            .scopes
            .with_chains()
            .get(chain as usize)
            .ok_or_else(|| IrError::new(IrErrorKind::InvalidWithChain { chain }, span))?;
        let Some(scope) = resolver_chain.scopes.first() else {
            return Ok(false);
        };
        let scope_node = self.node(*scope)?;
        if scope_node.kind != NodeKind::GlobalVar {
            return Ok(false);
        }
        let NodeData::Symbol(scope_symbol) = scope_node.data else {
            return Err(self.invalid_shape(scope_node, "global symbol payload"));
        };
        Ok(self.resolved.symbols.resolve(scope_symbol) == Some(b"builtins"))
    }

    pub(super) fn lower_with_chain(&mut self, chain: u32, span: Span) -> Result<u32, IrError> {
        if let Some(lowered) = self.with_chain_map.get(&chain).copied() {
            return Ok(lowered);
        }
        let raw = u32::try_from(self.with_chains.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let resolver_chain = self
            .resolved
            .scopes
            .with_chains()
            .get(chain as usize)
            .ok_or_else(|| IrError::new(IrErrorKind::InvalidWithChain { chain }, span))?;
        let mut scopes = Vec::new();
        for scope in resolver_chain.scopes.iter().copied() {
            let lowered = self.lowered_nodes.get(&scope).copied().ok_or_else(|| {
                IrError::new(IrErrorKind::UnloweredWithScope { chain, scope }, span)
            })?;
            scopes.push(lowered);
        }
        self.with_chains
            .push(IrWithChain::new(scopes.into_boxed_slice()));
        self.with_chain_map.insert(chain, raw);
        Ok(raw)
    }

    pub(super) fn lower_list(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Children(elements) = node.data else {
            return Err(self.invalid_shape(node, "list children"));
        };
        let mut lowered = Vec::new();
        for child in self.child_ids(elements)? {
            lowered.push(self.lower_lazy(child)?);
        }
        let children = self.arena.push_child_slice(&lowered, node.span)?;
        self.push(IrKind::List, node.span, IrData::Children(children))
    }

    pub(super) fn lower_attrset(
        &mut self,
        ast_id: NodeId,
        node: Node,
        recursive: bool,
    ) -> Result<IrId, IrError> {
        let NodeData::Children(bindings) = node.data else {
            return Err(self.invalid_shape(node, "attrset bindings"));
        };
        let mut has_dynamic = false;
        let bindings = self.lower_bindings(bindings, &mut has_dynamic)?;
        let shape = self.push_shape_for_bindings(bindings, node.span)?;
        let frame = if recursive {
            self.resolved.scopes.frame_for_node(ast_id)
        } else {
            None
        };
        self.push(
            IrKind::AttrSet,
            node.span,
            IrData::AttrSet {
                shape,
                bindings,
                recursive,
                has_dynamic,
                frame,
            },
        )
    }

    pub(super) fn lower_lambda(&mut self, ast_id: NodeId, node: Node) -> Result<IrId, IrError> {
        let NodeData::Pair {
            first: pattern,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "lambda pair"));
        };
        let pattern = self.lower_pattern(pattern)?;
        let body = self.lower_expr(body)?;
        let frame = self.resolved.scopes.frame_for_node(ast_id);
        self.push(
            IrKind::Lambda,
            node.span,
            IrData::Lambda {
                pattern,
                body,
                frame,
            },
        )
    }

    pub(super) fn lower_formal_set(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::FormalSet {
            formals,
            ellipsis,
            alias,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "formal-set payload"));
        };
        let mut lowered = Vec::new();
        for formal in self.child_ids(formals)? {
            lowered.push(self.lower_expr(formal)?);
        }
        let formals = self.arena.push_child_slice(&lowered, node.span)?;
        self.push(
            IrKind::FormalSet,
            node.span,
            IrData::FormalSet {
                formals,
                ellipsis,
                alias,
            },
        )
    }

    pub(super) fn lower_pattern(&mut self, id: NodeId) -> Result<IrId, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Ident => {
                let NodeData::Symbol(name) = node.data else {
                    return Err(self.invalid_shape(node, "identifier pattern symbol"));
                };
                self.push(
                    IrKind::Formal,
                    node.span,
                    IrData::Formal {
                        name,
                        default: None,
                    },
                )
            }
            NodeKind::FormalSet => self.lower_formal_set(node),
            _ => Err(self.invalid_shape(node, "lambda pattern")),
        }
    }

    pub(super) fn lower_formal(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Formal { name, default } = node.data else {
            return Err(self.invalid_shape(node, "formal payload"));
        };
        let default = default
            .map(|default| self.lower_lazy(default))
            .transpose()?;
        self.push(IrKind::Formal, node.span, IrData::Formal { name, default })
    }

    pub(super) fn lower_pair(
        &mut self,
        node: Node,
        kind: IrKind,
        lazy_second: LazySecond,
    ) -> Result<IrId, IrError> {
        let NodeData::Pair { first, second } = node.data else {
            return Err(self.invalid_shape(node, "pair payload"));
        };
        let first = self.lower_expr(first)?;
        let second = if lazy_second == LazySecond::Yes {
            self.lower_lazy(second)?
        } else {
            self.lower_expr(second)?
        };
        self.push(kind, node.span, IrData::Pair { first, second })
    }

    pub(super) fn lower_with(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Pair {
            first: scope,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "with pair"));
        };
        let lowered_scope = self.lower_lazy(scope)?;
        self.lowered_nodes.insert(scope, lowered_scope);
        let body = self.lower_expr(body)?;
        self.push(
            IrKind::With,
            node.span,
            IrData::Pair {
                first: lowered_scope,
                second: body,
            },
        )
    }

    pub(super) fn lower_apply(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Pair {
            first: function,
            second: argument,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "application pair"));
        };
        if let Some((_symbol, op)) = self.builtin_dialect_op_ref(function)? {
            let argument = self.lower_expr(argument)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                (self.options.dialect_op_effect_of())(op),
                IrData::DialectNode { op, argument },
            );
        }
        if let Some((symbol, effect)) = self.strict_unary_primop_ref(function)? {
            let argument = self.lower_expr(argument)?;
            let args = self.arena.push_child_slice(&[argument], node.span)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                effect,
                IrData::PrimOp { symbol, args },
            );
        }
        if let Some((symbol, effect)) = self.lazy_unary_primop_ref(function)? {
            let argument = self.lower_lazy(argument)?;
            let args = self.arena.push_child_slice(&[argument], node.span)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                effect,
                IrData::PrimOp { symbol, args },
            );
        }
        if let Some((symbol, effect, first_argument)) =
            self.strict_lazy_binary_primop_ref(function)?
        {
            let first_argument = self.lower_expr(first_argument)?;
            let second_argument = self.lower_lazy(argument)?;
            let args = self
                .arena
                .push_child_slice(&[first_argument, second_argument], node.span)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                effect,
                IrData::PrimOp { symbol, args },
            );
        }
        if let Some((symbol, effect, first_argument)) =
            self.lazy_strict_binary_primop_ref(function)?
        {
            let first_argument = self.lower_lazy(first_argument)?;
            let second_argument = self.lower_expr(argument)?;
            let args = self
                .arena
                .push_child_slice(&[first_argument, second_argument], node.span)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                effect,
                IrData::PrimOp { symbol, args },
            );
        }
        if let Some((symbol, effect, first_argument)) = self.strict_binary_primop_ref(function)? {
            let first_argument = self.lower_expr(first_argument)?;
            let second_argument = self.lower_expr(argument)?;
            let args = self
                .arena
                .push_child_slice(&[first_argument, second_argument], node.span)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                effect,
                IrData::PrimOp { symbol, args },
            );
        }
        if let Some((symbol, effect, first_argument, second_argument)) =
            self.strict_ternary_primop_ref(function)?
        {
            let first_argument = self.lower_expr(first_argument)?;
            let second_argument = self.lower_expr(second_argument)?;
            let third_argument = self.lower_expr(argument)?;
            let args = self.arena.push_child_slice(
                &[first_argument, second_argument, third_argument],
                node.span,
            )?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                effect,
                IrData::PrimOp { symbol, args },
            );
        }
        self.lower_pair(node, IrKind::Apply, LazySecond::Yes)
    }

    pub(super) fn lower_select(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Select {
            receiver,
            path,
            default,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "select payload"));
        };
        if let Some(symbol) = self.static_builtin_select_symbol(receiver, path, default)? {
            return self.push(IrKind::BuiltinAttr, node.span, IrData::Symbol(symbol));
        }
        let receiver = self.lower_expr(receiver)?;
        let path = self.lower_attr_path(path)?;
        let default = default
            .map(|default| self.lower_lazy(default))
            .transpose()?;
        let site = self.next_inline_cache_site(node.span)?;
        self.push(
            IrKind::Select,
            node.span,
            IrData::Select {
                site,
                receiver,
                path,
                default,
            },
        )
    }

    pub(super) fn static_builtin_select_symbol(
        &self,
        receiver: NodeId,
        path: ChildSlice,
        default: Option<NodeId>,
    ) -> Result<Option<Symbol>, IrError> {
        if self.options.dynamic_builtin_scope() || default.is_some() {
            return Ok(None);
        }
        let receiver = self.node(receiver)?;
        if receiver.kind != NodeKind::GlobalVar || !self.symbol_payload_is(receiver, b"builtins") {
            return Ok(None);
        }
        let segments = self.child_ids(path)?;
        let Some(segment) = segments.first().copied() else {
            return Ok(None);
        };
        if segments.len() != 1 {
            return Ok(None);
        }
        let segment = self.node(segment)?;
        if !matches!(segment.kind, NodeKind::Ident | NodeKind::Str) {
            return Ok(None);
        }
        let NodeData::Symbol(symbol) = segment.data else {
            return Err(self.invalid_shape(segment, "attribute symbol payload"));
        };
        let Some(name) = self.resolved.symbols.resolve(symbol) else {
            return Ok(None);
        };
        Ok(lookup_builtin(name).is_some().then_some(symbol))
    }

    pub(super) fn lower_has_attr(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::HasAttr { receiver, path } = node.data else {
            return Err(self.invalid_shape(node, "has-attr payload"));
        };
        let receiver = self.lower_expr(receiver)?;
        let path = self.lower_attr_path(path)?;
        let site = self.next_inline_cache_site(node.span)?;
        self.push(
            IrKind::HasAttr,
            node.span,
            IrData::HasAttr {
                site,
                receiver,
                path,
            },
        )
    }

    pub(super) fn lower_let(&mut self, ast_id: NodeId, node: Node) -> Result<IrId, IrError> {
        let NodeData::LetIn { bindings, body } = node.data else {
            return Err(self.invalid_shape(node, "let payload"));
        };
        let mut has_dynamic = false;
        let bindings = self.lower_bindings(bindings, &mut has_dynamic)?;
        let body = self.lower_expr(body)?;
        let frame = self.resolved.scopes.frame_for_node(ast_id);
        self.push(
            IrKind::Let,
            node.span,
            IrData::Let {
                bindings,
                body,
                frame,
            },
        )
    }

    pub(super) fn lower_if(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "if payload"));
        };
        let first = self.lower_expr(first)?;
        let second = self.lower_expr(second)?;
        let third = self.lower_expr(third)?;
        self.push(
            IrKind::If,
            node.span,
            IrData::Triple {
                first,
                second,
                third,
            },
        )
    }

    pub(super) fn lower_binary(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Binary { op, lhs, rhs } = node.data else {
            return Err(self.invalid_shape(node, "binary payload"));
        };
        let (lhs, rhs) = match op {
            BinOpKind::PipeRight => (self.lower_lazy(lhs)?, self.lower_expr(rhs)?),
            BinOpKind::PipeLeft => (self.lower_expr(lhs)?, self.lower_lazy(rhs)?),
            _ => (self.lower_expr(lhs)?, self.lower_expr(rhs)?),
        };
        self.push(IrKind::BinOp, node.span, IrData::Binary { op, lhs, rhs })
    }

    pub(super) fn lower_unary(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Unary { op, operand } = node.data else {
            return Err(self.invalid_shape(node, "unary payload"));
        };
        let operand = self.lower_expr(operand)?;
        self.push(IrKind::UnaryOp, node.span, IrData::Unary { op, operand })
    }

    pub(super) fn lower_interp(&mut self, node: Node) -> Result<IrId, IrError> {
        match node.data {
            NodeData::Node(child) => {
                let child = self.lower_expr(child)?;
                self.push(IrKind::Interp, node.span, IrData::Node(child))
            }
            NodeData::Children(children) => {
                let mut lowered = Vec::new();
                for child in self.child_ids(children)? {
                    lowered.push(self.lower_expr(child)?);
                }
                let children = self.arena.push_child_slice(&lowered, node.span)?;
                self.push(IrKind::Interp, node.span, IrData::Children(children))
            }
            NodeData::None | NodeData::Symbol(_) => {
                self.push(IrKind::Interp, node.span, IrData::None)
            }
            _ => Err(self.invalid_shape(node, "interpolation payload")),
        }
    }

    pub(super) fn lower_bindings(
        &mut self,
        slice: ChildSlice,
        has_dynamic: &mut bool,
    ) -> Result<IrBindingSlice, IrError> {
        let mut lowered = Vec::new();
        for binding in self.child_ids(slice)? {
            if let Some(binding) = self.lower_binding(binding, has_dynamic)? {
                lowered.push(binding);
            }
        }
        self.push_binding_slice(&lowered)
    }

    pub(super) fn lower_binding(
        &mut self,
        id: NodeId,
        has_dynamic: &mut bool,
    ) -> Result<Option<IrBinding>, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Binding => {
                let NodeData::Binding { path, value } = node.data else {
                    return Err(self.invalid_shape(node, "binding payload"));
                };
                let (key, position) = self.lower_binding_key(path)?;
                if matches!(key, IrAttrPathSegment::Dynamic(_)) {
                    *has_dynamic = true;
                }
                let value = if let Some(inherit) = self.resolved.scopes.inherit_for_node(id) {
                    let resolution = self
                        .resolved
                        .scopes
                        .inherit_resolution(inherit)
                        .ok_or_else(|| {
                            IrError::new(IrErrorKind::InvalidInheritSource, node.span)
                        })?;
                    let Some(source) = resolution.sources.first() else {
                        return Err(IrError::new(IrErrorKind::InvalidInheritSource, node.span));
                    };
                    match resolution.from {
                        Some(from) => self.lower_inherit_from_source(from, source.source)?,
                        None => self.lower_lazy(source.source)?,
                    }
                } else {
                    self.lower_lazy(value)?
                };
                Ok(Some(IrBinding {
                    key,
                    position,
                    value,
                }))
            }
            NodeKind::Inherit => Ok(None),
            _ => Err(self.invalid_shape(node, "binding node")),
        }
    }

    pub(super) fn lower_binding_key(
        &mut self,
        path: ChildSlice,
    ) -> Result<(IrAttrPathSegment, Option<Span>), IrError> {
        let segments = self.child_ids(path)?;
        let Some(segment) = segments.first().copied() else {
            return Err(IrError::new(
                IrErrorKind::InvalidBindingKey,
                Span::default(),
            ));
        };
        let span = self.node(segment)?.span;
        if segments.len() != 1 {
            return Err(IrError::new(IrErrorKind::InvalidBindingKey, span));
        }
        let key = self.lower_attr_segment(segment)?;
        let position = Some(span);
        Ok((key, position))
    }

    pub(super) fn lower_attr_path(&mut self, path: ChildSlice) -> Result<IrAttrPathId, IrError> {
        let mut segments = Vec::new();
        for segment in self.child_ids(path)? {
            segments.push(self.lower_attr_segment(segment)?);
        }
        let raw = u32::try_from(self.attr_paths.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, Span::default()))?;
        let id = IrAttrPathId::new(raw);
        self.attr_paths.push(segments.into_boxed_slice());
        Ok(id)
    }

    pub(super) fn lower_attr_segment(&mut self, id: NodeId) -> Result<IrAttrPathSegment, IrError> {
        if let Some(symbol) = self.static_attr_symbol(id)? {
            return Ok(IrAttrPathSegment::Static(symbol));
        }

        let node = self.node(id)?;
        match node.kind {
            NodeKind::Interp => Ok(IrAttrPathSegment::Dynamic(self.lower_expr(id)?)),
            _ => Err(self.invalid_shape(node, "attribute path segment")),
        }
    }

    pub(super) fn static_attr_symbol(&self, id: NodeId) -> Result<Option<Symbol>, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Ident | NodeKind::Str => {
                let NodeData::Symbol(symbol) = node.data else {
                    return Err(self.invalid_shape(node, "static attr symbol"));
                };
                Ok(Some(symbol))
            }
            NodeKind::Interp => {
                let NodeData::Node(child) = node.data else {
                    return Ok(None);
                };
                let child = self.node(child)?;
                if child.kind == NodeKind::Str {
                    let NodeData::Symbol(symbol) = child.data else {
                        return Err(self.invalid_shape(child, "static attr symbol"));
                    };
                    Ok(Some(symbol))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    pub(super) fn lower_inherit_from_source(
        &mut self,
        from: NodeId,
        source: NodeId,
    ) -> Result<IrId, IrError> {
        let node = self.node(source)?;
        let NodeData::Select {
            receiver,
            path,
            default,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "inherit source select"));
        };
        if receiver != from {
            return Err(IrError::new(IrErrorKind::InvalidInheritSource, node.span));
        }
        let receiver = self.lower_inherit_from_thunk(from)?;
        let path = self.lower_attr_path(path)?;
        let default = default
            .map(|default| self.lower_lazy(default))
            .transpose()?;
        let site = self.next_inline_cache_site(node.span)?;
        let select = self.push(
            IrKind::Select,
            node.span,
            IrData::Select {
                site,
                receiver,
                path,
                default,
            },
        )?;
        self.wrap_lazy(select, source)
    }

    pub(super) fn lower_inherit_from_thunk(&mut self, from: NodeId) -> Result<IrId, IrError> {
        if let Some(thunk) = self.inherit_from_thunks.get(&from).copied() {
            return Ok(thunk);
        }
        let thunk = self.lower_lazy(from)?;
        self.inherit_from_thunks.insert(from, thunk);
        Ok(thunk)
    }

    pub(super) fn lower_lazy(&mut self, id: NodeId) -> Result<IrId, IrError> {
        let lowered = self.lower_expr(id)?;
        self.wrap_lazy(lowered, id)
    }

    pub(super) fn wrap_lazy(&mut self, lowered: IrId, ast_id: NodeId) -> Result<IrId, IrError> {
        let node = self.arena.node(lowered).copied().ok_or_else(|| {
            IrError::new(IrErrorKind::InvalidNodeId(ast_id.as_u32()), Span::default())
        })?;
        if is_trivial_value(node.kind) {
            return Ok(lowered);
        }
        self.push(IrKind::ThunkAlloc, node.span, IrData::Node(lowered))
    }

    pub(super) fn next_inline_cache_site(
        &mut self,
        span: Span,
    ) -> Result<IrInlineCacheSiteId, IrError> {
        let site = IrInlineCacheSiteId::new(self.inline_cache_sites);
        self.inline_cache_sites = self
            .inline_cache_sites
            .checked_add(1)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManyInlineCacheSites, span))?;
        Ok(site)
    }

    pub(super) fn push(&mut self, kind: IrKind, span: Span, data: IrData) -> Result<IrId, IrError> {
        let effect = (self.options.effect_of())(kind);
        self.arena.push_node(kind, span, effect, data)
    }

    pub(super) fn push_with_effect(
        &mut self,
        kind: IrKind,
        span: Span,
        effect: EffectClass,
        data: IrData,
    ) -> Result<IrId, IrError> {
        self.arena.push_node(kind, span, effect, data)
    }

    pub(super) fn push_binding_slice(
        &mut self,
        bindings: &[IrBinding],
    ) -> Result<IrBindingSlice, IrError> {
        let span = Span::default();
        let start = u32::try_from(self.bindings.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let len = u32::try_from(bindings.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        start
            .checked_add(len)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        self.bindings.extend_from_slice(bindings);
        Ok(IrBindingSlice::new(start, len))
    }

    pub(super) fn push_shape_for_bindings(
        &mut self,
        bindings: IrBindingSlice,
        span: Span,
    ) -> Result<IrShapeId, IrError> {
        let raw = u32::try_from(self.shapes.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let start = bindings.start as usize;
        let end = start
            .checked_add(bindings.len())
            .ok_or_else(|| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let binding_run = self
            .bindings
            .get(start..end)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let keys = binding_run
            .iter()
            .filter_map(|binding| match binding.key {
                IrAttrPathSegment::Static(symbol) => Some(symbol),
                IrAttrPathSegment::Dynamic(_) => None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let id = IrShapeId::new(raw);
        self.shapes.push(IrShape::new(keys));
        Ok(id)
    }

    pub(super) fn node(&self, id: NodeId) -> Result<Node, IrError> {
        self.resolved.arena.node(id).copied().ok_or_else(|| {
            IrError::new(
                IrErrorKind::InvalidNodeId(id.as_u32()),
                Span::new(u32::MAX, u32::MAX),
            )
        })
    }

    pub(super) fn child_ids(&self, slice: ChildSlice) -> Result<Vec<NodeId>, IrError> {
        Ok(self
            .resolved
            .arena
            .child_slice(slice)
            .map_err(IrError::from)?
            .to_vec())
    }

    pub(super) fn invalid_shape(&self, node: Node, expected: &'static str) -> IrError {
        IrError::new(
            IrErrorKind::InvalidNodeShape {
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }
}
