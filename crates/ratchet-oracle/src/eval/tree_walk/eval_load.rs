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
        argument_span: Span,
        path: &[u8],
        base: &[u8],
        source: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Result<Value, TreeWalkError> {
        if self.shared.is_some() {
            return self.load_and_eval_import_bytes_shared(
                id,
                span,
                argument,
                argument_span,
                path,
                base,
                source,
                global_scope,
            );
        }
        // Move the live symbol table into the parser instead of cloning it: the
        // grown superset becomes the new live table below, so the pre-parse table
        // is discarded on success and cloning it only to drop it dominated cold
        // eval. Import parse/scope/lower errors are non-catchable, so aborting
        // with an emptied `self.symbols` is sound: eval unwinds to the top.
        let live_symbols = std::mem::take(&mut self.symbols);
        let parse_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
        let parsed = parse_bytes_with_symbols(source, live_symbols).map_err(|error| {
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
        if let Some(timer) = parse_timer {
            self.add_front_end_parse_nanos(timer);
        }
        let resolve_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
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
        if let Some(timer) = resolve_timer {
            self.add_front_end_resolve_nanos(timer);
        }
        let lower_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
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
        if let Some(timer) = lower_timer {
            self.add_front_end_lower_nanos(timer);
        }
        // Fresh imports need capture plans plus the demand/escape facts used
        // across module boundaries. Durable-cache refreshes additionally own
        // full per-node cardinality and escape analysis. Failures remain
        // conservative.
        let annotate_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
        let _ = annotate_import_ir(&mut ir);
        if let Some(timer) = annotate_timer {
            self.add_front_end_annotate_nanos(timer);
        }
        // Adopt the freshly lowered symbol table as the live table without a
        // clone; the module keeps the emptied husk and reads `self.symbols`.
        self.symbols = std::mem::take(&mut ir.symbols);
        self.load_and_eval_import_ir(id, span, path, base, source, ir, global_scope)
    }
    /// Parallel-mode fresh import load: parse into an isolated table, then remap.
    ///
    /// Under a shared demand pool the live symbol table is a prefix replica of the
    /// shared symbol log, so the serial fast path (seeding the parser with the live
    /// table and adopting the grown superset) would fork the replica outside the
    /// log. Instead the module is parsed and lowered with an isolated symbol table
    /// via [`Self::parse_lower_import_isolated`], then remapped through the same
    /// [`TreeWalk::remap_cached_import_ir`] path cached imports use, whose interning
    /// runs through the shared-log choke point. Parsing happens outside any shared
    /// lock, so concurrent imports of different files still parse in parallel.
    #[allow(clippy::too_many_arguments)]
    fn load_and_eval_import_bytes_shared(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        base: &[u8],
        source: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Result<Value, TreeWalkError> {
        // Adopt a speculatively parsed IR if the pool's producer already parsed
        // this file (RFC-0007 S2/S3): a hit skips parse/resolve/lower. The stored
        // IR is isolated and already annotated, so it feeds `remap` exactly like a
        // fresh parse. Empty (and thus a no-op miss) unless the speculation
        // producer is running, so serial and speculation-off evals are unchanged.
        let ir = match self.take_speculative_import_parse(path, source, global_scope) {
            Some(ir) => ir,
            None => self.parse_lower_import_isolated(argument, path, source, global_scope)?,
        };
        let ir = self.remap_cached_import_ir(argument, argument_span, path, ir)?;
        self.load_and_eval_import_ir(id, span, path, base, source, ir, global_scope)
    }
    /// Adopts a speculatively parsed IR for an import, if the pool's speculation
    /// store holds one keyed by this file's realpath and content hash.
    ///
    /// Returns `None` when not under a parallel pool, for a scoped import, or when
    /// nothing was speculated for this file (the common case), leaving the caller
    /// to parse. Scoped imports (`scopedImport`) are never adopted: the producer
    /// only ever lowers the ordinary global-scope form, so a scoped import must
    /// parse itself to get the dynamic-builtin-scope lowering.
    fn take_speculative_import_parse(
        &self,
        path: &[u8],
        source: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Option<Ir> {
        if global_scope.is_scoped() {
            return None;
        }
        let shared = self.shared.as_ref()?;
        let key = ParseFileKey::for_source(Path::new(OsStr::from_bytes(path)), source);
        shared.speculation.get(&key)
    }
    /// Parses, resolves, lowers, and annotates `source` into an *isolated* symbol
    /// table, returning the fresh IR.
    ///
    /// The IR's file-local symbols must be remapped into the live table (via
    /// [`TreeWalk::remap_cached_import_ir`]) before the module can be evaluated.
    /// Because parsing runs against a private `SymbolTable::new()` rather than the
    /// live table, this is the reusable front-end unit the pooled import path and
    /// the speculative parse-ahead scheduler (RFC-0007 §S2) build on: parsing never
    /// fabricates symbol ids on the live table, and under a demand pool concurrent
    /// imports of different files parse in parallel with no shared lock. The serial
    /// no-pool path deliberately keeps its faster `mem::take` fast path (measured
    /// +2-7% cold via this remap, with no K=1 speculation benefit — the S1
    /// fallback). Carries the `AOS_NIX_EVAL_STATS` front-end timers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if parsing, scope resolution, or IR lowering of the
    /// imported source fails.
    fn parse_lower_import_isolated(
        &mut self,
        argument: IrId,
        path: &[u8],
        source: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Result<Ir, TreeWalkError> {
        let parse_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
        let parsed = parse_bytes_with_symbols(source, SymbolTable::new()).map_err(|error| {
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
        if let Some(timer) = parse_timer {
            self.add_front_end_parse_nanos(timer);
        }
        let resolve_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
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
        if let Some(timer) = resolve_timer {
            self.add_front_end_resolve_nanos(timer);
        }
        let lower_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
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
        if let Some(timer) = lower_timer {
            self.add_front_end_lower_nanos(timer);
        }
        let annotate_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
        let _ = annotate_import_ir(&mut ir);
        if let Some(timer) = annotate_timer {
            self.add_front_end_annotate_nanos(timer);
        }
        Ok(ir)
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
        let work = self.begin_import_module(id, span, path, base, source, ir, global_scope)?;
        self.run_import_module_with(work, |eval, work| {
            eval.eval_import_module_root_with_demand_machine_or_oracle(work.root, path)
        })
    }

    /// Registers an imported module and installs its isolated evaluation context.
    ///
    /// All fallible lease-stack reservations happen before module publication
    /// or environment mutation. Once this returns, `work.token` owns the current
    /// module plus exactly one suspended environment frame and must be passed to
    /// [`Self::finish_import_module`] or [`Self::abort_import_module`].
    ///
    /// # Errors
    ///
    /// Returns a module-registration, scoped-global, suspended-root allocation,
    /// context-lease allocation, or lease-generation exhaustion diagnostic.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_import_module(
        &mut self,
        id: IrId,
        span: Span,
        path: &[u8],
        base: &[u8],
        source: &[u8],
        ir: Ir,
        global_scope: ImportGlobalScope,
    ) -> Result<ImportModuleWork, TreeWalkError> {
        // Per-import module setup: registering the lowered module (with its path,
        // base, and source copies) and swapping in its evaluation scopes, before
        // the module body is evaluated. This is the tail-of-pipeline import work
        // the front_end_*_nanos timers do not cover (RFC-0007 §P1 import-cost
        // attribution). It ends before the body eval, so it excludes nested
        // imports and stays non-overlapping with the other import timers.
        let module_setup_timer = self.options.eval_stats_dump().then(std::time::Instant::now);
        self.reserve_suspended_env_root_frame(id, span)?;
        let lease_count = self
            .active_import_module_leases
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportModuleLeaseAllocationFailed {
                        id,
                        leases: usize::MAX,
                    },
                    span,
                )
            })?;
        self.active_import_module_leases
            .try_reserve(1)
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportModuleLeaseAllocationFailed {
                        id,
                        leases: lease_count,
                    },
                    span,
                )
            })?;
        let generation = self
            .next_import_module_lease_generation
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ImportModuleLeaseGenerationExhausted { id },
                    span,
                )
            })?;
        // The live symbol table (`self.symbols`) has already been advanced to the
        // superset covering this module's symbols by the caller: the fresh-parse
        // path moves the lowered table in with `mem::take`, and the cached-import
        // path interns directly into it during remapping. The module therefore
        // stores an empty per-module table and every runtime symbol lookup reads
        // `self.symbols` instead, avoiding a per-import clone of the whole table.
        let root = ir.root;
        let module =
            self.push_module(id, span, ir, base.to_vec(), path.to_vec(), source.to_vec())?;
        self.emit_weak_liveness_import_milestone();
        let imported_scoped_globals = self.import_scoped_globals(id, span, global_scope)?;
        let saved_env = self.swap_env_frames(Vec::new());
        let saved_with_scopes = std::mem::take(&mut self.with_scopes);
        let saved_scoped_globals =
            std::mem::replace(&mut self.scoped_globals, imported_scoped_globals);
        let suspended_env_depth = self.suspended_env_roots.len();
        self.push_suspended_env_roots(saved_env, saved_with_scopes, saved_scoped_globals);
        if let Some(timer) = module_setup_timer {
            self.add_import_module_setup_nanos(timer);
        }

        // `with_current_module` formerly installed this switch immediately
        // before body evaluation. Keep it after the setup timer so telemetry
        // retains the same boundary.
        let saved_module = self.current_module;
        self.current_module = module;
        self.next_import_module_lease_generation = generation;
        let token = ImportModuleLeaseToken::new(self.active_import_module_leases.len(), generation);
        self.active_import_module_leases
            .push(ActiveImportModuleLease {
                token,
                module,
                saved_module,
                suspended_env_depth,
            });
        Ok(ImportModuleWork {
            token,
            module,
            root,
        })
    }

    /// Runs one imported-module continuation with Result and panic cleanup.
    ///
    /// This remains the oracle wrapper used by `load_and_eval_import_ir`.
    /// Demand-machine execution can consume the begin/finish seam directly in
    /// a later stage without replaying module loading.
    ///
    /// # Errors
    ///
    /// Returns the continuation error after restoring the displaced module,
    /// lexical environment, dynamic `with` scopes, and scoped globals.
    ///
    /// # Panics
    ///
    /// Resumes a panic raised by `run` after restoring the imported-module
    /// context. Panics on an internally stale or out-of-order lease token.
    pub(super) fn run_import_module_with(
        &mut self,
        work: ImportModuleWork,
        run: impl FnOnce(&mut Self, ImportModuleWork) -> Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(self, work)));
        match result {
            Ok(result) => self.finish_import_module(work.token, result),
            Err(payload) => {
                self.abort_import_module(work.token);
                std::panic::resume_unwind(payload);
            }
        }
    }

    /// Finishes the innermost imported-module context lease.
    ///
    /// A source-less error is associated with the imported module before the
    /// current-module switch is restored, matching evaluation under
    /// `with_current_module`.
    ///
    /// # Errors
    ///
    /// Returns the continuation error supplied in `result`.
    ///
    /// # Panics
    ///
    /// Panics if `token` is stale or is not the innermost active module lease.
    pub(super) fn finish_import_module(
        &mut self,
        token: ImportModuleLeaseToken,
        result: Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        let result = result.map_err(|error| self.error_with_current_source(error));
        self.restore_import_module_context(token);
        result
    }

    /// Restores one imported-module context while a panic is unwinding.
    ///
    /// # Panics
    ///
    /// Panics if `token` is stale or is not the innermost active module lease.
    pub(super) fn abort_import_module(&mut self, token: ImportModuleLeaseToken) {
        self.restore_import_module_context(token);
    }

    /// Restores the context recorded by the innermost module lease.
    fn restore_import_module_context(&mut self, token: ImportModuleLeaseToken) {
        let Some(active) = self.active_import_module_leases.last().copied() else {
            unreachable!("active imported-module lease stack is unbalanced");
        };
        assert_eq!(
            active.token, token,
            "imported-module lease token is stale or out of order"
        );
        debug_assert_eq!(active.module, self.current_module);
        debug_assert_eq!(token.depth(), self.active_import_module_leases.len() - 1);
        debug_assert_eq!(token.generation(), active.token.generation());
        assert_eq!(
            self.suspended_env_roots.len(),
            active.suspended_env_depth + 1,
            "imported-module suspended environment stack is unbalanced"
        );

        // Preserve the old nested-wrapper order: `with_current_module`
        // restored the caller module before load_and_eval_import_ir restored
        // the displaced lexical and dynamic environments.
        self.current_module = active.saved_module;
        let Some(saved) = self.pop_suspended_env_roots() else {
            unreachable!("checked suspended imported environment disappeared");
        };
        self.restore_env_frames(saved.env);
        self.with_scopes = saved.with_scopes;
        self.scoped_globals = saved.scoped_globals;
        let Some(popped) = self.active_import_module_leases.pop() else {
            unreachable!("checked imported-module lease disappeared");
        };
        debug_assert_eq!(popped.token, token);
    }
    pub(super) fn remap_cached_import_ir(
        &mut self,
        argument: IrId,
        argument_span: Span,
        path: &[u8],
        mut ir: Ir,
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
            let symbol = self.intern_symbol_for_eval(bytes).map_err(|source| {
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
        Self::remap_call_summary_symbols(
            argument,
            argument_span,
            path,
            &symbol_map,
            &mut ir.facts,
        )?;
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
        _id: IrId,
        _span: Span,
        global_scope: ImportGlobalScope,
    ) -> Result<EvalScopedGlobalEnv, TreeWalkError> {
        let mut scoped_globals = EvalScopedGlobalEnv::default();
        if let ImportGlobalScope::Scoped(scope) = global_scope {
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
}

mod primops;
