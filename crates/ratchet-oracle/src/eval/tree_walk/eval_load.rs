//! Import source loading, path remapping, and global-scope wiring.

use super::*;

impl TreeWalk {
    pub(super) fn parse_cache_import_error(
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        source_bytes: &[u8],
        source: ParseCacheError,
    ) -> TreeWalkError {
        let path = path.to_vec();
        match source {
            ParseCacheError::Parse { source } => {
                let span = source.span();
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportParse {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    span,
                )
                .with_source(EvalErrorSource::new(path, source_bytes.to_vec()))
            }
            ParseCacheError::Scope { source } => {
                let span = source.span();
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    span,
                )
                .with_source(EvalErrorSource::new(path, source_bytes.to_vec()))
            }
            ParseCacheError::LowerIr { source } => {
                let span = source.span();
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportLower {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    span,
                )
                .with_source(EvalErrorSource::new(path, source_bytes.to_vec()))
            }
            other => TreeWalkError::new(
                TreeWalkErrorKind::ImportParse {
                    id: argument,
                    path,
                    message: other.to_string(),
                },
                argument_span,
            ),
        }
    }

    pub(super) fn load_and_eval_text_store_import(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Result<Value, TreeWalkError> {
        let source = self
            .text_store
            .get(path)
            .cloned()
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FileRead {
                        id: argument,
                        path: path.to_vec(),
                        message: "text store path is missing".to_owned(),
                    },
                    argument_span,
                )
            })?
            .contents;
        let base = Path::new(OsStr::from_bytes(path))
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .as_os_str()
            .as_bytes()
            .to_vec();
        self.load_and_eval_import_bytes(
            id,
            span,
            argument,
            argument_span,
            path,
            &base,
            &source,
            global_scope,
        )
    }

    pub(super) fn load_and_eval_import_bytes(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        _argument_span: Span,
        path: &[u8],
        base: &[u8],
        source: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Result<Value, TreeWalkError> {
        let parsed = parse_bytes_with_symbols(source, self.symbols.clone()).map_err(|error| {
            let span = error.span();
            TreeWalkError::new(
                TreeWalkErrorKind::ImportParse {
                    id: argument,
                    path: path.to_vec(),
                    message: error.to_string(),
                },
                span,
            )
            .with_source(EvalErrorSource::new(path.to_vec(), source.to_vec()))
        })?;
        let resolved = if global_scope.is_scoped() {
            ScopeResolver::with_options(ResolverOptions::with_unresolved_globals()).resolve(parsed)
        } else {
            resolve(parsed)
        }
        .map_err(|error| {
            let span = error.span();
            TreeWalkError::new(
                TreeWalkErrorKind::ImportScope {
                    id: argument,
                    path: path.to_vec(),
                    message: error.to_string(),
                },
                span,
            )
            .with_source(EvalErrorSource::new(path.to_vec(), source.to_vec()))
        })?;
        let mut ir = if global_scope.is_scoped() {
            nix_lower_with_options(resolved, IrLowerOptions::with_dynamic_builtin_scope())
        } else {
            nix_lower(resolved)
        }
        .map_err(|error| {
            let span = error.span();
            TreeWalkError::new(
                TreeWalkErrorKind::ImportLower {
                    id: argument,
                    path: path.to_vec(),
                    message: error.to_string(),
                },
                span,
            )
            .with_source(EvalErrorSource::new(path.to_vec(), source.to_vec()))
        })?;
        // Adopt the freshly lowered symbol table as the live table without a
        // clone; the module keeps the emptied husk and reads `self.symbols`.
        self.symbols = std::mem::take(&mut ir.symbols);
        self.load_and_eval_import_ir(id, span, path, base, source, ir, global_scope)
    }

    pub(super) fn load_and_eval_import_ir(
        &mut self,
        id: IrId,
        span: Span,
        path: &[u8],
        base: &[u8],
        source: &[u8],
        ir: Ir,
        global_scope: ImportGlobalScope,
    ) -> Result<Value, TreeWalkError> {
        self.reserve_suspended_env_root_frame(id, span)?;
        // The live symbol table (`self.symbols`) has already been advanced to the
        // superset covering this module's symbols by the caller: the fresh-parse
        // path moves the lowered table in with `mem::take`, and the cached-import
        // path interns directly into it during remapping. The module therefore
        // stores an empty per-module table and every runtime symbol lookup reads
        // `self.symbols` instead, avoiding a per-import clone of the whole table.
        let root = ir.root;
        let module =
            self.push_module(id, span, ir, base.to_vec(), path.to_vec(), source.to_vec())?;
        let imported_scoped_globals = self.import_scoped_globals(id, span, global_scope)?;
        let saved_env = std::mem::take(&mut self.env);
        let saved_with_scopes = std::mem::take(&mut self.with_scopes);
        let saved_scoped_globals =
            std::mem::replace(&mut self.scoped_globals, imported_scoped_globals);
        self.push_suspended_env_roots(saved_env, saved_with_scopes, saved_scoped_globals);
        let result = self.with_current_module(module, |eval| eval.eval_node(root));
        if let Some(saved) = self.pop_suspended_env_roots() {
            self.env = saved.env;
            self.with_scopes = saved.with_scopes;
            self.scoped_globals = saved.scoped_globals;
        } else {
            debug_assert!(false, "suspended env root stack is unbalanced");
        }
        result
    }

    pub(super) fn remap_cached_import_ir(
        &mut self,
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        ir: Ir,
    ) -> Result<Ir, TreeWalkError> {
        let mut symbol_map = Vec::new();
        symbol_map
            .try_reserve_exact(ir.symbols.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: "failed to allocate cached import symbol remap".to_owned(),
                    },
                    argument_span,
                )
            })?;
        // Intern the cached file-local symbols directly into the live table
        // rather than cloning it first. Interning is append-only, so ids stay
        // stable; if a later step fails, the extra symbols left in the live
        // table are harmless and never invalidate previously interned ids.
        for bytes in ir.symbols.symbols() {
            let symbol = self.symbols.intern(bytes).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: format!("failed to remap cached import symbol: {source}"),
                    },
                    argument_span,
                )
            })?;
            symbol_map.push(symbol);
        }

        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(ir.arena.nodes().len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: "failed to allocate cached import IR nodes".to_owned(),
                    },
                    argument_span,
                )
            })?;
        for node in ir.arena.nodes() {
            nodes.push(IrNode::new(
                node.kind,
                node.span,
                node.effect,
                Self::remap_cached_ir_data(argument, argument_span, path, &symbol_map, node.data)?,
            ));
        }

        let mut attr_paths = Vec::new();
        attr_paths
            .try_reserve_exact(ir.attr_paths.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: "failed to allocate cached import attr paths".to_owned(),
                    },
                    argument_span,
                )
            })?;
        for attr_path in ir.attr_paths.as_ref() {
            let mut segments = Vec::new();
            segments.try_reserve_exact(attr_path.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: "failed to allocate cached import attr path".to_owned(),
                    },
                    argument_span,
                )
            })?;
            for segment in attr_path.as_ref() {
                segments.push(Self::remap_cached_ir_attr_path_segment(
                    argument,
                    argument_span,
                    path,
                    &symbol_map,
                    *segment,
                )?);
            }
            attr_paths.push(segments.into_boxed_slice());
        }

        let mut bindings = Vec::new();
        bindings.try_reserve_exact(ir.bindings.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ImportScope {
                    id: argument,
                    path: path.to_vec(),
                    message: "failed to allocate cached import bindings".to_owned(),
                },
                argument_span,
            )
        })?;
        for binding in ir.bindings.as_ref() {
            bindings.push(IrBinding {
                key: Self::remap_cached_ir_attr_path_segment(
                    argument,
                    argument_span,
                    path,
                    &symbol_map,
                    binding.key,
                )?,
                position: binding.position,
                value: binding.value,
            });
        }

        let mut shapes = Vec::new();
        shapes.try_reserve_exact(ir.shapes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ImportScope {
                    id: argument,
                    path: path.to_vec(),
                    message: "failed to allocate cached import shapes".to_owned(),
                },
                argument_span,
            )
        })?;
        for shape in ir.shapes.as_ref() {
            let mut keys = Vec::new();
            keys.try_reserve_exact(shape.keys.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: "failed to allocate cached import shape keys".to_owned(),
                    },
                    argument_span,
                )
            })?;
            for key in shape.keys.as_ref() {
                keys.push(Self::remap_cached_symbol(
                    argument,
                    argument_span,
                    path,
                    &symbol_map,
                    *key,
                )?);
            }
            shapes.push(IrShape::new(keys.into_boxed_slice()));
        }

        Ok(Ir {
            root: ir.root,
            arena: IrArena::from_raw_parts(nodes, ir.arena.child_pool().to_vec()),
            facts: ir.facts,
            // The remapped symbols now live in `self.symbols`; the module reads
            // that live table, so its per-module table is intentionally empty.
            symbols: SymbolTable::new(),
            frames: ir.frames,
            with_chains: ir.with_chains,
            attr_paths: attr_paths.into_boxed_slice(),
            bindings: bindings.into_boxed_slice(),
            shapes: shapes.into_boxed_slice(),
        })
    }

    pub(super) fn remap_cached_ir_data(
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        symbol_map: &[Symbol],
        data: IrData,
    ) -> Result<IrData, TreeWalkError> {
        match data {
            IrData::Symbol(symbol) => Ok(IrData::Symbol(Self::remap_cached_symbol(
                argument,
                argument_span,
                path,
                symbol_map,
                symbol,
            )?)),
            IrData::GlobalVar { site, symbol } => Ok(IrData::GlobalVar {
                site,
                symbol: Self::remap_cached_symbol(
                    argument,
                    argument_span,
                    path,
                    symbol_map,
                    symbol,
                )?,
            }),
            IrData::PrimOp { symbol, args } => Ok(IrData::PrimOp {
                symbol: Self::remap_cached_symbol(
                    argument,
                    argument_span,
                    path,
                    symbol_map,
                    symbol,
                )?,
                args,
            }),
            IrData::DialectScopeVar {
                op,
                site,
                symbol,
                chain,
            } => Ok(IrData::DialectScopeVar {
                op,
                site,
                symbol: Self::remap_cached_symbol(
                    argument,
                    argument_span,
                    path,
                    symbol_map,
                    symbol,
                )?,
                chain,
            }),
            IrData::FormalSet {
                formals,
                ellipsis,
                alias,
            } => Ok(IrData::FormalSet {
                formals,
                ellipsis,
                alias: alias
                    .map(|symbol| {
                        Self::remap_cached_symbol(argument, argument_span, path, symbol_map, symbol)
                    })
                    .transpose()?,
            }),
            IrData::Formal { name, default } => Ok(IrData::Formal {
                name: Self::remap_cached_symbol(argument, argument_span, path, symbol_map, name)?,
                default,
            }),
            other => Ok(other),
        }
    }

    pub(super) fn remap_cached_ir_attr_path_segment(
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        symbol_map: &[Symbol],
        segment: IrAttrPathSegment,
    ) -> Result<IrAttrPathSegment, TreeWalkError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => Ok(IrAttrPathSegment::Static(
                Self::remap_cached_symbol(argument, argument_span, path, symbol_map, symbol)?,
            )),
            IrAttrPathSegment::Dynamic(node) => Ok(IrAttrPathSegment::Dynamic(node)),
        }
    }

    pub(super) fn remap_cached_symbol(
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        symbol_map: &[Symbol],
        symbol: Symbol,
    ) -> Result<Symbol, TreeWalkError> {
        symbol_map
            .get(symbol.as_u32() as usize)
            .copied()
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportScope {
                        id: argument,
                        path: path.to_vec(),
                        message: "cached import artifact references an invalid symbol".to_owned(),
                    },
                    argument_span,
                )
            })
    }

    pub(super) fn import_scoped_globals(
        &self,
        id: IrId,
        span: Span,
        global_scope: ImportGlobalScope,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut scoped_globals = Vec::new();
        if let ImportGlobalScope::Scoped(scope) = global_scope {
            scoped_globals.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Env {
                        id,
                        source: EvalEnvError::ScopedGlobalCaptureAllocationFailed { scopes: 1 },
                    },
                    span,
                )
            })?;
            scoped_globals.push(scope);
        }
        Ok(scoped_globals)
    }

    pub(super) fn alloc_reflected_context_group(
        &mut self,
        id: IrId,
        span: Span,
        group: ReflectedContextGroup,
    ) -> Result<Value, TreeWalkError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(3).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: 3 },
                },
                span,
            )
        })?;
        if group.path_flag {
            let symbol = self.intern_builtin_attr_symbol(id, b"path", span)?;
            entries.push(AttrEntry::new(symbol, Value::bool(true)));
        }
        if group.all_outputs {
            let symbol = self.intern_builtin_attr_symbol(id, b"allOutputs", span)?;
            entries.push(AttrEntry::new(symbol, Value::bool(true)));
        }
        if !group.outputs.is_empty() {
            let mut outputs = Vec::new();
            outputs
                .try_reserve_exact(group.outputs.len())
                .map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: group.outputs.len(),
                        },
                        span,
                    )
                })?;
            for output in group.outputs {
                let value = self.with_transient_value_stack_roots(
                    id,
                    span,
                    outputs.as_mut_slice(),
                    |eval| eval.alloc_static_string(id, span, &output),
                )?;
                outputs.push(value);
            }
            let outputs = self.alloc_tree_walk_list(id, span, NixList::new(outputs))?;
            let symbol = self.intern_builtin_attr_symbol(id, b"outputs", span)?;
            entries.push(AttrEntry::new(symbol, outputs));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn copy_bytes_for_node(
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut copied = Vec::new();
        copied.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        copied.extend_from_slice(bytes);
        Ok(copied)
    }

    pub(super) fn absolute_path_bytes_for_node(
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let raw = Path::new(OsStr::from_bytes(bytes));
        if !raw.is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: Self::copy_bytes_for_node(id, span, bytes)?,
                },
                span,
            ));
        }
        let path = Self::normalize_path(raw.to_path_buf());
        Self::copy_bytes_for_node(id, span, path.as_os_str().as_bytes())
    }

    pub(super) fn path_literal_bytes_for_node(
        &self,
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        self.path_literal_bytes_for_module_node(self.current_module, id, span, bytes)
    }

    pub(super) fn path_literal_bytes_for_module_node(
        &self,
        module: EvalModuleId,
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        if let Some(suffix) = bytes.strip_prefix(b"~/") {
            return self.home_path_literal_bytes_for_node(id, span, bytes, suffix);
        }
        if Path::new(OsStr::from_bytes(bytes)).is_absolute() {
            return Self::absolute_path_bytes_for_node(id, span, bytes);
        }
        let Some(base) = self.module_path_literal_base(module, span)? else {
            return Self::absolute_path_bytes_for_node(id, span, bytes);
        };
        join_path_literal(id, span, base, bytes)
    }

    pub(super) fn home_path_literal_bytes_for_node(
        &self,
        id: IrId,
        span: Span,
        bytes: &[u8],
        suffix: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Pure {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::HomePathNotAllowed {
                    id,
                    path: Self::copy_bytes_for_node(id, span, bytes)?,
                    mode: self.options.eval_mode(),
                },
                span,
            ));
        }
        let Some(home_dir) = self.options.home_dir() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::HomePathUnavailable {
                    id,
                    path: Self::copy_bytes_for_node(id, span, bytes)?,
                },
                span,
            ));
        };
        join_path_literal(id, span, home_dir, suffix)
    }

    pub(super) fn normalize_path(path: PathBuf) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop() && !normalized.has_root() {
                        normalized.push("..");
                    }
                }
                Component::Normal(part) => normalized.push(part),
                Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
            }
        }
        if normalized.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            normalized
        }
    }

    pub(super) fn extend_bytes_for_node(
        id: IrId,
        span: Span,
        target: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Result<(), TreeWalkError> {
        let len = target.len().checked_add(bytes.len()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        target.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        target.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn eval_store_path_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        if self.options.eval_mode() == EvalMode::Pure {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StorePathPureEval { id },
                span,
            ));
        }
        let result = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let full_path =
                Self::absolute_path_bytes_for_node(argument, argument_span, string.bytes())?;
            self.check_filesystem_path_access(argument, argument_span, &full_path)?;
            let Some(root) = store_path_root(&full_path, self.options.store_dir()) else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StorePathNotInStore {
                        id: argument,
                        path: full_path,
                    },
                    argument_span,
                ));
            };
            let root = Self::copy_bytes_for_node(argument, argument_span, root)?;
            let store_context =
                StringContext::singleton(ContextElement::opaque_path(root).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
            let context = string.context().union(&store_context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;
            NixString::new(full_path, context)
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_to_path_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let bytes =
                Self::absolute_path_bytes_for_node(argument, argument_span, string.bytes())?;
            let context = string
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                })?;
            NixString::new(bytes, context)
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_add_drv_output_dependencies_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let context = string.context();
            if context.len() != 1 {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextElementCount {
                        id: argument,
                        len: context.len(),
                    },
                    argument_span,
                ));
            }
            let Some(element) = context.elements().first() else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextElementCount {
                        id: argument,
                        len: 0,
                    },
                    argument_span,
                ));
            };
            if let ContextKind::SingleOutput = element.kind() {
                let output = element.output().ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidStringContext { id: argument },
                        argument_span,
                    )
                })?;
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextDerivationOutput {
                        id: argument,
                        output: Self::copy_bytes_for_node(argument, argument_span, output)?,
                    },
                    argument_span,
                ));
            }
            let path = Self::copy_bytes_for_node(argument, argument_span, element.path())?;
            if !path.ends_with(b".drv") {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextPathNotDerivation { id: argument, path },
                    argument_span,
                ));
            }
            let bytes = Self::copy_bytes_for_node(argument, argument_span, string.bytes())?;
            let element = ContextElement::deep_derivation(path).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let context = StringContext::singleton(element).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            NixString::new(bytes, context)
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_unsafe_discard_output_dependency_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut elements = Vec::new();
            elements
                .try_reserve_exact(string.context().len())
                .map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source: NixStringError::ContextAllocationFailed {
                                len: string.context().len(),
                            },
                        },
                        argument_span,
                    )
                })?;
            for element in string.context() {
                let path = Self::copy_bytes_for_node(argument, argument_span, element.path())?;
                let rewritten = match element.kind() {
                    ContextKind::OpaquePath | ContextKind::DeepDerivation => {
                        ContextElement::opaque_path(path)
                    }
                    ContextKind::SingleOutput => {
                        let output = element.output().ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::InvalidStringContext { id: argument },
                                argument_span,
                            )
                        })?;
                        ContextElement::single_output(
                            path,
                            Self::copy_bytes_for_node(argument, argument_span, output)?,
                        )
                    }
                }
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                elements.push(rewritten);
            }
            let bytes = Self::copy_bytes_for_node(argument, argument_span, string.bytes())?;
            NixString::new(bytes, StringContext::new(elements))
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_unsafe_discard_string_context_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            string.discard_context().map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_string_length_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let string = self.heap.get_string(string).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(Value::int(string.len() as i64))
    }
}
