//! Heap allocation, value interning, and attrset/path materialization helpers.

use super::*;
use crate::eval::{
    TreeWalkParallelThunkForceOutcome, TreeWalkThunkAllocationContext, TreeWalkThunkAllocationPlan,
    tree_walk_thunk_allocation_plan,
};
#[cfg(test)]
use crate::runtime::alloc::RuntimeAllocationEntryPoint;
use crate::runtime::barrier::runtime_thunk_resolve_write_barrier_with_card_table;

const TREE_WALK_GC_STRESS_ALLOCATION_SITE_PROMOTE_AFTER_SURVIVALS: u32 = 2;

impl TreeWalk {
    pub(super) fn attr_value_by_name(
        &mut self,
        id: IrId,
        attrs_value: Value,
        name: &[u8],
        span: Span,
    ) -> Result<Option<Value>, TreeWalkError> {
        let symbol = self.intern_symbol_for_eval(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })?;
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(attrs.get(symbol))
    }

    pub(super) fn context_free_string_bytes(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let string = self
            .heap
            .get_string(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if string.has_context() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StringContextNotAllowed { id, op },
                span,
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(string.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: string.len(),
                },
                span,
            )
        })?;
        bytes.extend_from_slice(string.bytes());
        Ok(bytes)
    }

    pub(super) fn coerce_to_filesystem_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let path = self.coerce_to_path_string(id, span, value)?;
        self.validate_filesystem_path_context(id, span, &path, op)?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok(bytes)
    }

    pub(super) fn coerce_to_filesystem_or_text_store_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<(Vec<u8>, bool), TreeWalkError> {
        let path = self.coerce_to_path_string(id, span, value)?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        if self.text_store_path_has_allowed_context(&path) {
            return Ok((bytes, true));
        }
        self.validate_filesystem_path_context(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok((bytes, false))
    }

    pub(super) fn text_store_path_has_allowed_context(&self, path: &NixString) -> bool {
        if !self.text_store.contains_key(path.bytes()) {
            return false;
        }
        path.context().iter().all(|element| {
            element.kind() == ContextKind::OpaquePath && element.path() == path.bytes()
        })
    }

    pub(super) fn coerce_to_path_string(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let path = if value.tag() == ValueTag::Path {
            self.clone_path_value(id, span, value)?
        } else {
            let string = self.coerce_to_string(id, value, span)?;
            self.clone_string_value(id, span, string)?
        };
        if !Path::new(OsStr::from_bytes(path.bytes())).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: Self::copy_bytes_for_node(id, span, path.bytes())?,
                },
                span,
            ));
        }
        Ok(path)
    }

    pub(super) fn validate_filesystem_path_context(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        let normalized_path = normalize_absolute_path_bytes(path.bytes());
        for element in path.context().iter() {
            if element.kind() != ContextKind::OpaquePath {
                continue;
            }
            if !element.path().starts_with(b"/") {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
            let normalized_context_path = normalize_absolute_path_bytes(element.path());
            if !path_is_under_root(&normalized_path, &normalized_context_path) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_ifd_path_context(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        for element in path.context().iter() {
            if element.kind() == ContextKind::OpaquePath {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn realize_import_from_derivation(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        for element in path.context().iter() {
            match element.kind() {
                ContextKind::OpaquePath => {}
                ContextKind::SingleOutput | ContextKind::DeepDerivation => {
                    let request = IfdRealization {
                        path: path.bytes(),
                        drv_path: element.path(),
                        output_name: element.output(),
                        context_kind: element.kind(),
                        op,
                    };
                    let Some(realizer) = &self.ifd_realizer else {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedImportFromDerivation {
                                id,
                                op,
                                detail: Box::new(IfdErrorDetail::new(
                                    path.bytes().to_vec(),
                                    element.path().to_vec(),
                                    element.output().map(<[u8]>::to_vec),
                                    element.kind(),
                                    None,
                                )),
                            },
                            span,
                        ));
                    };
                    self.materialize_ifd_derivation(id, span, path, element, op)?;
                    realizer.realize(request).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ImportFromDerivation {
                                id,
                                op,
                                detail: Box::new(IfdErrorDetail::new(
                                    path.bytes().to_vec(),
                                    element.path().to_vec(),
                                    element.output().map(<[u8]>::to_vec),
                                    element.kind(),
                                    Some(source.message().to_owned()),
                                )),
                            },
                            span,
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn materialize_ifd_derivation(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        let Some(path_in_store) = self.strip_configured_store_dir(element.path()) else {
            return Ok(());
        };
        let Ok(drv_path) = nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store)
        else {
            return Ok(());
        };
        if !self.known_derivations.contains_key(&drv_path) {
            return Ok(());
        }
        let mut visited = BTreeSet::new();
        self.materialize_known_derivation_closure(
            id,
            span,
            path,
            element,
            op,
            &drv_path,
            &mut visited,
        )
    }

    pub(super) fn materialize_known_derivation_closure(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
        drv_path: &nix_compat::store_path::StorePath<String>,
        visited: &mut BTreeSet<nix_compat::store_path::StorePath<String>>,
    ) -> Result<(), TreeWalkError> {
        if !visited.insert(drv_path.clone()) {
            return Ok(());
        }
        let Some(known) = self.known_derivations.get(drv_path) else {
            return Ok(());
        };
        let input_derivations: Vec<_> =
            known.derivation.input_derivations.keys().cloned().collect();
        for input in input_derivations {
            self.materialize_known_derivation_closure(
                id, span, path, element, op, &input, visited,
            )?;
        }

        let Some(known) = self.known_derivations.get(drv_path) else {
            return Ok(());
        };
        let bytes = self
            .known_derivation_aterm_bytes(drv_path, known)
            .map_err(|source| {
                self.ifd_materialization_error(id, span, path, element, op, source.to_string())
            })?;
        let absolute_path =
            PathBuf::from(OsStr::from_bytes(&self.store_path_absolute_bytes(drv_path)));
        materialize_drv(&absolute_path, &bytes).map_err(|source| {
            self.ifd_materialization_error(id, span, path, element, op, source.to_string())
        })
    }

    pub(super) fn ifd_materialization_error(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
        message: String,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::ImportFromDerivation {
                id,
                op,
                detail: Box::new(IfdErrorDetail::new(
                    path.bytes().to_vec(),
                    element.path().to_vec(),
                    element.output().map(<[u8]>::to_vec),
                    element.kind(),
                    Some(format!(
                        "failed to materialize native derivation for IFD: {message}"
                    )),
                )),
            },
            span,
        )
    }

    pub(super) fn check_filesystem_path_access(
        &self,
        id: IrId,
        span: Span,
        path: &[u8],
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Impure {
            return Ok(());
        }
        if !Path::new(OsStr::from_bytes(path)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: path.to_vec(),
                },
                span,
            ));
        }
        let normalized = normalize_absolute_path_bytes(path);
        if self.options.path_is_allowed(&normalized) {
            if let Some(resolved) = canonicalize_policy_path(path)
                && !self.options.resolved_path_is_allowed(&resolved)
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::PathAccessDenied {
                        id,
                        path: resolved,
                        mode: self.options.eval_mode(),
                    },
                    span,
                ));
            }
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::PathAccessDenied {
                id,
                path: normalized,
                mode: self.options.eval_mode(),
            },
            span,
        ))
    }

    pub(super) fn eval_attr_name(
        &mut self,
        id: IrId,
        segment: IrAttrPathSegment,
        null_policy: DynamicAttrNullPolicy,
        span: Span,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => {
                if self.symbols.resolve(symbol).is_none() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol { id, symbol },
                        span,
                    ));
                }
                Ok(Some(symbol))
            }
            IrAttrPathSegment::Dynamic(dynamic) => {
                self.eval_dynamic_attr_name(self.dynamic_attr_expression(dynamic)?, null_policy)
            }
        }
    }

    pub(super) fn dynamic_attr_expression(&self, dynamic: IrId) -> Result<IrId, TreeWalkError> {
        let node = self.node(dynamic)?;
        if node.kind == IrKind::Interp
            && let IrData::Node(child) = node.data
        {
            return Ok(child);
        }
        Ok(dynamic)
    }

    pub(super) fn eval_dynamic_attr_name(
        &mut self,
        expression: IrId,
        null_policy: DynamicAttrNullPolicy,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        let span = self.node(expression)?.span;
        let value = self.eval_node(expression)?;
        match value.tag() {
            ValueTag::Null if null_policy == DynamicAttrNullPolicy::SkipNull => Ok(None),
            ValueTag::String => self
                .intern_context_free_string_value(expression, value, span, "dynamic attribute name")
                .map(Some),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: expression,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn intern_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = {
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(string.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: string.len(),
                    },
                    span,
                )
            })?;
            bytes.extend_from_slice(string.bytes());
            bytes
        };
        self.intern_attr_name_bytes(id, &bytes)
    }

    pub(super) fn intern_context_free_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
        op: &'static str,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = self.context_free_string_bytes(id, span, value, op)?;
        self.intern_attr_name_bytes(id, &bytes)
    }

    pub(super) fn intern_attr_name_bytes(
        &mut self,
        id: IrId,
        bytes: &[u8],
    ) -> Result<Symbol, TreeWalkError> {
        self.intern_symbol_for_eval(bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })
    }

    pub(super) fn eval_list(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Children(children) = node.data else {
            return Err(self.invalid_payload(id, node, "list children"));
        };
        let children = self
            .current_ir()
            .arena
            .child_slice(children)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidChildSlice {
                        id,
                        slice: children,
                    },
                    node.span,
                )
            })?
            .to_vec();
        let mut elements = Vec::new();
        elements.try_reserve_exact(children.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: children.len(),
                },
                node.span,
            )
        })?;
        let result = if self.can_admit_gc_stress_root_accumulator_allocation_safepoints(id) {
            (|| {
                for child in children.iter().copied() {
                    let value = self.with_transient_value_stack_roots(
                        id,
                        node.span,
                        elements.as_mut_slice(),
                        |eval| {
                            eval.with_gc_stress_accumulator_allocation_node(child, |eval| {
                                eval.eval_lazy_node(child)
                            })
                        },
                    )?;
                    elements.push(value);
                }
                Ok(())
            })()
        } else {
            self.begin_gc_stress_composite_accumulator();
            let result = (|| {
                for child in children.iter().copied() {
                    elements.push(self.eval_lazy_node(child)?);
                }
                Ok(())
            })();
            self.end_gc_stress_composite_accumulator();
            result
        };
        result?;
        self.alloc_tree_walk_list(id, node.span, NixList::new(elements))
    }

    pub(super) fn eval_local_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Local { slot } = node.data else {
            return Err(self.invalid_payload(id, node, "local payload"));
        };
        let Some(frame) = self.env.last() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingEnvironment { id },
                node.span,
            ));
        };
        frame
            .get(slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    pub(super) fn eval_upval_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Upval { depth, slot } = node.data else {
            return Err(self.invalid_payload(id, node, "upvalue payload"));
        };
        let depth = depth as usize;
        if depth >= self.env.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidUpvalueDepth {
                    id,
                    depth,
                    frames: self.env.len(),
                },
                node.span,
            ));
        }
        let index = self.env.len() - 1 - depth;
        self.env[index]
            .get(slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    pub(super) fn eval_lazy_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        if node.kind == IrKind::ThunkAlloc {
            return self.eval_thunk_alloc(id, &node);
        }
        self.eval_node(id)
    }

    pub(super) fn eval_nested_equality_operand(
        &mut self,
        id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        match node.kind {
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            _ => self.eval_node(id),
        }
    }

    pub(super) fn eval_thunk_alloc(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Node(_) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        let context = self.thunk_allocation_context();
        let plan =
            tree_walk_thunk_allocation_plan(self.current_ir(), id, context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::ThunkAllocation { id, source }, node.span)
            })?;
        match plan {
            TreeWalkThunkAllocationPlan::UpdateSlot(update) => {
                self.alloc_update_thunk_from_plan(update.thunk(), update.body(), node.span)
            }
            TreeWalkThunkAllocationPlan::SingleEntry(single_entry) => self
                .alloc_single_entry_thunk_from_plan(
                    single_entry.thunk(),
                    single_entry.body(),
                    node.span,
                ),
            TreeWalkThunkAllocationPlan::Omit(omitted) => {
                self.alloc_update_thunk_from_plan(omitted.thunk(), omitted.body(), node.span)
            }
            TreeWalkThunkAllocationPlan::ElideToWhnf(elision) => {
                self.increment_thunks_elided();
                self.eval_node(elision.body())
            }
        }
    }

    fn thunk_allocation_context(&self) -> TreeWalkThunkAllocationContext {
        if self.order_sensitive_binding_depth > 0 {
            TreeWalkThunkAllocationContext::OrderSensitiveBindingAssembly
        } else {
            TreeWalkThunkAllocationContext::DemandPosition
        }
    }

    fn alloc_update_thunk_from_plan(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_thunk_for_node(id, body, span)?;
        let region_plan = self.region_plan_for_allocation(id, RegionRuntimeTier::OneShotArena);
        self.record_source_thunk_region_plan_decision(region_plan);
        Ok(value)
    }

    fn alloc_single_entry_thunk_from_plan(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let thunk = self.thunk_for_node(id, body, span)?.into_single_entry();
        let value = self.alloc_tree_walk_thunk(id, span, thunk)?;
        let region_plan = self.region_plan_for_allocation(id, RegionRuntimeTier::OneShotArena);
        self.record_source_thunk_region_plan_decision(region_plan);
        Ok(value)
    }

    pub(super) fn begin_order_sensitive_binding_assembly(&mut self) {
        self.order_sensitive_binding_depth = self.order_sensitive_binding_depth.saturating_add(1);
        self.begin_gc_stress_composite_accumulator();
    }

    pub(super) fn end_order_sensitive_binding_assembly(&mut self) {
        self.order_sensitive_binding_depth = self.order_sensitive_binding_depth.saturating_sub(1);
        self.end_gc_stress_composite_accumulator();
    }

    fn begin_gc_stress_composite_accumulator(&mut self) {
        self.active_composite_accumulator_depth =
            self.active_composite_accumulator_depth.saturating_add(1);
    }

    fn end_gc_stress_composite_accumulator(&mut self) {
        self.active_composite_accumulator_depth =
            self.active_composite_accumulator_depth.saturating_sub(1);
    }

    pub(super) fn with_gc_stress_composite_accumulator_suspended<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let suspended = self.active_composite_accumulator_depth > 0;
        if suspended {
            self.end_gc_stress_composite_accumulator();
        }
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                if suspended {
                    self.begin_gc_stress_composite_accumulator();
                }
                std::panic::resume_unwind(payload);
            }
        };
        if suspended {
            self.begin_gc_stress_composite_accumulator();
        }
        result
    }

    pub(super) fn with_gc_stress_accumulator_allocation_node<T>(
        &mut self,
        id: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let previous = self
            .active_gc_stress_accumulator_allocation_node
            .replace(id);
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                self.active_gc_stress_accumulator_allocation_node = previous;
                std::panic::resume_unwind(payload);
            }
        };
        self.active_gc_stress_accumulator_allocation_node = previous;
        result
    }

    pub(super) fn with_gc_stress_primop_arg_root_admission<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.active_gc_stress_primop_arg_root_admission_depth = self
            .active_gc_stress_primop_arg_root_admission_depth
            .saturating_add(1);
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                self.active_gc_stress_primop_arg_root_admission_depth = self
                    .active_gc_stress_primop_arg_root_admission_depth
                    .saturating_sub(1);
                std::panic::resume_unwind(payload);
            }
        };
        self.active_gc_stress_primop_arg_root_admission_depth = self
            .active_gc_stress_primop_arg_root_admission_depth
            .saturating_sub(1);
        result
    }

    pub(super) fn alloc_thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let thunk = self.thunk_for_node(id, body, span)?;
        let value = self.alloc_tree_walk_thunk(id, span, thunk)?;
        Ok(value)
    }

    fn thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<EvalThunk, TreeWalkError> {
        self.node(body)?;
        let env = self.capture_env(id, span)?;
        let with_env = self.capture_with_env(id, span)?;
        let scoped_globals = self.capture_scoped_global_env(id, span)?;
        Ok(EvalThunk::with_captures(
            self.current_module,
            body,
            env,
            with_env,
            scoped_globals,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_apply_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::apply(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                argument_id,
                argument,
            ),
        )?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_apply2_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        first_argument_id: IrId,
        first_argument_span: Span,
        first_argument: Value,
        second_argument_id: IrId,
        second_argument_span: Span,
        second_argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::apply2(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                first_argument_id,
                first_argument_span,
                first_argument,
                self.current_module,
                second_argument_id,
                second_argument_span,
                second_argument,
            ),
        )?;
        Ok(value)
    }

    pub(super) fn alloc_select_thunk(
        &mut self,
        id: IrId,
        span: Span,
        select_id: IrId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::select(self.current_module, select_id, receiver, path),
        )?;
        Ok(value)
    }

    pub(super) fn alloc_builtin_attr_thunk(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Result<Value, TreeWalkError> {
        let value =
            self.alloc_tree_walk_thunk(id, span, EvalThunk::builtin_attr(symbol, builtin))?;
        Ok(value)
    }

    pub(super) fn alloc_tree_walk_thunk(
        &mut self,
        id: IrId,
        span: Span,
        thunk: EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_thunk_allocation_safepoint(id, &thunk);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot);
        let value = self
            .heap
            .alloc_thunk(self.admit_parallel_thunk_payload_cell(id, span, thunk))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.increment_thunks_allocated();
        if dispatch_gc_stress_safepoint {
            self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                RuntimeAllocatorTier::TierAOneShot,
                previous_poll,
                value,
                true,
            )
        } else {
            Ok(value)
        }
    }

    pub(super) fn alloc_tree_walk_lambda(
        &mut self,
        id: IrId,
        span: Span,
        lambda: EvalLambda,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_lambda_allocation_safepoint(id, &lambda);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot);
        let value = self
            .heap
            .alloc_lambda(lambda)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if dispatch_gc_stress_safepoint {
            self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                RuntimeAllocatorTier::TierAOneShot,
                previous_poll,
                value,
                false,
            )
        } else {
            Ok(value)
        }
    }

    pub(super) fn alloc_tree_walk_primop(
        &mut self,
        id: IrId,
        span: Span,
        primop: EvalPrimOp,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_primop_allocation_safepoint(id, &primop);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot);
        let value = self
            .heap
            .alloc_primop(primop)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if dispatch_gc_stress_safepoint {
            self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                RuntimeAllocatorTier::TierAOneShot,
                previous_poll,
                value,
                false,
            )
        } else {
            Ok(value)
        }
    }

    pub(super) fn alloc_tree_walk_string(
        &mut self,
        id: IrId,
        span: Span,
        string: NixString,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let value = self
            .heap
            .alloc_string(string)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocString,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }
    }

    pub(super) fn alloc_replayed_payload_string(
        &mut self,
        origin: Option<EvalNodeRef>,
        string: NixString,
    ) -> Option<Value> {
        let Some(origin) = origin else {
            return self.heap.alloc_string(string).ok();
        };
        if origin.module() != self.current_module {
            return self.heap.alloc_string(string).ok();
        }
        let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
        self.alloc_tree_walk_string(origin.id(), span, string).ok()
    }

    pub(super) fn alloc_replayed_payload_path(
        &mut self,
        origin: Option<EvalNodeRef>,
        path: NixString,
    ) -> Option<Value> {
        let Some(origin) = origin else {
            return self.heap.alloc_path(path).ok();
        };
        if origin.module() != self.current_module {
            return self.heap.alloc_path(path).ok();
        }
        let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
        self.alloc_tree_walk_path(origin.id(), span, path).ok()
    }

    pub(super) fn alloc_replayed_payload_list(
        &mut self,
        origin: Option<EvalNodeRef>,
        list: NixList,
    ) -> Option<Value> {
        let Some(origin) = origin else {
            return self.heap.alloc_list(list).ok();
        };
        if origin.module() != self.current_module {
            return self.heap.alloc_list(list).ok();
        }
        let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
        self.alloc_tree_walk_list(origin.id(), span, list).ok()
    }

    pub(super) fn alloc_tree_walk_string_with_attr_entry_roots(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        string: NixString,
    ) -> Result<Value, TreeWalkError> {
        self.with_attr_entry_value_roots(id, span, entries, |eval| {
            eval.alloc_tree_walk_string(id, span, string)
        })
    }

    pub(super) fn with_attr_entry_value_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if entries.is_empty() {
            return body(self);
        }

        let mut roots = Vec::new();
        roots.try_reserve_exact(entries.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: entries.len(),
                    },
                },
                span,
            )
        })?;
        roots.extend(entries.iter().map(|entry| entry.value));

        let result = self.with_transient_value_stack_roots(id, span, &mut roots, body)?;
        for (entry, root) in entries.iter_mut().zip(roots) {
            entry.value = root;
        }
        Ok(result)
    }

    pub(super) fn alloc_tree_walk_path(
        &mut self,
        id: IrId,
        span: Span,
        path: NixString,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let value = self
            .heap
            .alloc_path(path)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocString,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }
    }

    pub(super) fn alloc_tree_walk_list(
        &mut self,
        id: IrId,
        span: Span,
        list: NixList,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(test)]
        {
            self.tree_walk_list_wrapper_calls = self.tree_walk_list_wrapper_calls.saturating_add(1);
        }
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_list_allocation_safepoint(id, &list);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let value = self
            .heap
            .alloc_list(list)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocList,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }
    }

    #[cfg(test)]
    pub(in crate::eval::tree_walk) const fn tree_walk_list_wrapper_calls(&self) -> usize {
        self.tree_walk_list_wrapper_calls
    }

    #[cfg(test)]
    fn record_gc_stress_permanent_root_allocation_dispatch(
        &mut self,
        entrypoint: RuntimeAllocationEntryPoint,
    ) {
        self.gc_stress_permanent_root_allocation_dispatches
            .push(entrypoint);
    }

    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn gc_stress_permanent_root_allocation_dispatches(
        &self,
    ) -> &[RuntimeAllocationEntryPoint] {
        &self.gc_stress_permanent_root_allocation_dispatches
    }

    pub(super) fn alloc_tree_walk_attrs_with_projected_shape_metadata(
        &mut self,
        id: IrId,
        span: Span,
        shape: u32,
        repr: AttrSetReprKind,
        projected_shape: Option<ShapeId>,
        attrs: FlatAttrs,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_attrs_allocation_safepoint(id, &attrs);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let value = self
            .heap
            .alloc_attrs_with_projected_shape_metadata(shape, repr, projected_shape, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocAttrs,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }
    }

    fn can_dispatch_gc_stress_lambda_allocation_safepoint(
        &self,
        id: IrId,
        lambda: &EvalLambda,
    ) -> bool {
        self.can_dispatch_gc_stress_root_allocation_safepoint(id)
            && Self::is_gc_stress_uncaptured_lambda(lambda)
    }

    fn can_dispatch_gc_stress_thunk_allocation_safepoint(
        &self,
        id: IrId,
        thunk: &EvalThunk,
    ) -> bool {
        self.can_dispatch_gc_stress_root_allocation_safepoint(id)
            && Self::is_gc_stress_uncaptured_node_thunk(thunk)
    }

    fn can_dispatch_gc_stress_primop_allocation_safepoint(
        &self,
        id: IrId,
        primop: &EvalPrimOp,
    ) -> bool {
        self.can_dispatch_gc_stress_root_allocation_safepoint(id) && primop.args().is_empty()
    }

    fn can_dispatch_gc_stress_permanent_list_allocation_safepoint(
        &self,
        id: IrId,
        list: &NixList,
    ) -> bool {
        self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id)
            && list
                .iter()
                .copied()
                .all(|value| self.can_dispatch_gc_stress_permanent_composite_field(value))
    }

    fn can_dispatch_gc_stress_permanent_attrs_allocation_safepoint(
        &self,
        id: IrId,
        attrs: &FlatAttrs,
    ) -> bool {
        self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id)
            && matches!(self.node(id), Ok(node) if node.kind == IrKind::AttrSet)
            && attrs
                .iter_by_symbol()
                .all(|entry| self.can_dispatch_gc_stress_permanent_composite_field(entry.value))
    }

    fn can_dispatch_gc_stress_permanent_root_allocation_safepoint(&self, id: IrId) -> bool {
        self.active_root_eval_node == Some(id)
            && self.can_dispatch_gc_stress_ambient_allocation_safepoint()
    }

    fn can_dispatch_gc_stress_permanent_composite_field(&self, value: Value) -> bool {
        match value.tag() {
            ValueTag::Lambda => matches!(
                self.heap.get_lambda(value),
                Ok(lambda) if Self::is_gc_stress_uncaptured_lambda(lambda)
            ),
            ValueTag::Primop => matches!(
                self.heap.get_primop(value),
                Ok(primop) if primop.args().is_empty()
            ),
            ValueTag::Thunk => matches!(
                self.heap.get_thunk(value),
                Ok(thunk) if Self::is_gc_stress_uncaptured_node_thunk(thunk)
            ),
            _ => true,
        }
    }

    fn is_gc_stress_uncaptured_lambda(lambda: &EvalLambda) -> bool {
        lambda.env().frames().is_empty()
            && lambda.with_scope_env().scopes().is_empty()
            && lambda.scoped_global_env().scopes().is_empty()
    }

    fn is_gc_stress_uncaptured_node_thunk(thunk: &EvalThunk) -> bool {
        matches!(
            thunk.kind(),
            EvalThunkKind::Node {
                env,
                with_env,
                scoped_globals,
                ..
            } if env.frames().is_empty()
                && with_env.scopes().is_empty()
                && scoped_globals.scopes().is_empty()
        )
    }

    fn can_dispatch_gc_stress_root_allocation_safepoint(&self, id: IrId) -> bool {
        (self.active_root_eval_node == Some(id)
            || self.active_gc_stress_accumulator_allocation_node == Some(id))
            && self.can_dispatch_gc_stress_ambient_allocation_safepoint()
    }

    pub(super) fn can_admit_gc_stress_root_accumulator_allocation_safepoints(
        &self,
        id: IrId,
    ) -> bool {
        self.active_root_eval_node == Some(id)
            && self.can_dispatch_gc_stress_ambient_allocation_safepoint()
    }

    fn can_dispatch_gc_stress_ambient_allocation_safepoint(&self) -> bool {
        self.active_root_eval_node.is_some()
            && self.env.is_empty()
            && self.with_scopes.is_empty()
            && self.scoped_globals.is_empty()
            && self.active_composite_accumulator_depth == 0
            && self.suspended_env_roots.is_empty()
            && self.active_force_roots.is_empty()
            && self.can_dispatch_gc_stress_active_primop_arg_roots()
            && self.import_cache.is_empty()
            && self.can_dispatch_gc_stress_interned_roots()
    }

    fn can_dispatch_gc_stress_active_primop_arg_roots(&self) -> bool {
        if self.active_primop_arg_roots.is_empty() && self.active_primop_arg_frames.is_empty() {
            return true;
        }
        self.active_gc_stress_primop_arg_root_admission_depth > 0
            && self.can_dispatch_gc_stress_admitted_active_primop_arg_roots()
    }

    fn can_dispatch_gc_stress_admitted_active_primop_arg_roots(&self) -> bool {
        let [frame] = self.active_primop_arg_frames.as_slice() else {
            return false;
        };
        if frame.start != 0 || frame.len != self.active_primop_arg_roots.len() {
            return false;
        }
        self.active_primop_arg_roots
            .iter()
            .all(|arg| self.can_dispatch_gc_stress_admitted_active_primop_arg_root(arg.value()))
    }

    fn can_dispatch_gc_stress_admitted_active_primop_arg_root(&self, value: Value) -> bool {
        if value.as_heap_ptr().is_err() {
            return true;
        }
        self.transient_value_stack_roots
            .iter()
            .any(|root| root.raw_eq(value))
    }

    fn can_dispatch_gc_stress_interned_roots(&self) -> bool {
        let Ok(roots) = self.heap.interned_root_set() else {
            return false;
        };
        roots
            .roots()
            .iter()
            .all(|root| matches!(root.value().tag(), ValueTag::String | ValueTag::Path))
    }

    fn apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
        &mut self,
        id: IrId,
        span: Span,
        previous_poll: Option<AllocationCollectorPoll>,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let Some(current_poll) =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared)
        else {
            return Ok(value);
        };
        if Some(current_poll) == previous_poll {
            return Ok(value);
        }
        let original_card_table = self
            .thunk_resolve_card_table
            .try_clone()
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id,
                        source: EvalHeapError::GenerationalGc(source),
                    },
                    span,
                )
            })?;
        self.mark_gc_stress_allocation_source_card(id, span, value)?;
        let result = self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
            id,
            span,
            RuntimeAllocatorTier::PermanentShared,
            previous_poll,
            value,
            false,
        );
        if result.is_err() {
            self.thunk_resolve_card_table = original_card_table;
        }
        result
    }

    fn mark_gc_stress_allocation_source_card(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let ptr = value.as_heap_ptr().map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::Value(source),
                },
                span,
            )
        })?;
        let source = GcHeapAddress::new(ptr.as_ptr() as usize).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::GenerationalGc(source),
                },
                span,
            )
        })?;
        self.thunk_resolve_card_table
            .mark_source(source)
            .map(|_| ())
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id,
                        source: EvalHeapError::GenerationalGc(source),
                    },
                    span,
                )
            })
    }

    fn apply_gc_stress_allocation_safepoint_to_just_allocated_value(
        &mut self,
        id: IrId,
        span: Span,
        tier: RuntimeAllocatorTier,
        previous_poll: Option<AllocationCollectorPoll>,
        value: Value,
        install_forwarding_slots: bool,
    ) -> Result<Value, TreeWalkError> {
        let Some(current_poll) = self.last_allocation_collector_poll_for_tier(tier) else {
            return Ok(value);
        };
        if Some(current_poll) == previous_poll {
            return Ok(value);
        }

        let registered_roots = self.transient_value_stack_roots.len();
        let total_roots = registered_roots.checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: registered_roots,
                },
                span,
            )
        })?;
        let mut transient_roots = Vec::new();
        transient_roots
            .try_reserve_exact(total_roots)
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: total_roots,
                    },
                    span,
                )
            })?;
        transient_roots.extend_from_slice(&self.transient_value_stack_roots);
        transient_roots.push(value);

        let promotion_policy = MinorGcPromotionPolicy::new(
            TREE_WALK_GC_STRESS_ALLOCATION_SITE_PROMOTE_AFTER_SURVIVALS,
        );
        let writeback_result = if install_forwarding_slots {
            self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
                current_poll,
                promotion_policy,
                &mut transient_roots,
            )
            .map(|_| ())
        } else {
            self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
                current_poll,
                promotion_policy,
                &mut transient_roots,
            )
            .map(|_| ())
        };
        writeback_result.map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::GcStressAllocationSafepoint { id, source },
                span,
            )
        })?;
        for (registered_root, updated_root) in self
            .transient_value_stack_roots
            .iter_mut()
            .zip(transient_roots.iter().copied())
        {
            *registered_root = updated_root;
        }
        Ok(transient_roots
            .get(registered_roots)
            .copied()
            .unwrap_or(value))
    }

    fn last_allocation_collector_poll_for_tier(
        &self,
        tier: RuntimeAllocatorTier,
    ) -> Option<AllocationCollectorPoll> {
        match tier {
            RuntimeAllocatorTier::TierAOneShot => self
                .heap
                .allocation_safepoints()
                .last_safepoint_collector_poll(),
            RuntimeAllocatorTier::PermanentShared => self
                .heap
                .permanent_allocation_safepoints()
                .last_safepoint_collector_poll(),
        }
    }

    fn admit_parallel_thunk_payload_cell(
        &self,
        id: IrId,
        span: Span,
        thunk: EvalThunk,
    ) -> EvalThunk {
        if self.options.parallel_thunk_payloads_enabled() {
            thunk.with_parallel_payload_cell(
                TreeWalkError::new(TreeWalkErrorKind::ParallelThunkClaimDropped { id }, span),
                self.parallel_force_registry.clone(),
            )
        } else {
            thunk
        }
    }

    pub(crate) fn force_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = match classify_whnf_tag_fast_path(value) {
            WhnfTagFastPath::AlreadyWhnf(value) => return Ok(value),
            WhnfTagFastPath::RequiresThunkProtocol(value) => value,
        };
        let forced_payload = value.payload_bits();
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if let Some(parallel_cell) = thunk.parallel_payload_cell() {
            return self.force_parallel_payload_thunk(
                id,
                span,
                value,
                forced_payload,
                &thunk,
                parallel_cell,
            );
        }
        self.force_serial_thunk_value(id, span, value, forced_payload, &thunk)
    }

    fn force_parallel_payload_thunk(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        forced_payload: u64,
        thunk: &EvalThunk,
        parallel_cell: &TreeWalkParallelThunkCell,
    ) -> Result<Value, TreeWalkError> {
        // Fast path: a serial-cell `Forced` observation is release-published by
        // the forcing worker before the parallel cell's own terminal publish,
        // and the cached value is immutable after publication, so an
        // acquire-load hit here replays the exact result the parallel cell
        // would hand back - without the payload mutex or the payload clone.
        // Repeated forces of already-forced thunks dominate the parallel-mode
        // force mix, so this removes the largest single-worker overhead of the
        // shared backend (L2-P4 item 4). Failed forces never reach `Forced`,
        // so error replay still flows through the payload cell below.
        if let Some(value) = thunk.cell().cached_value().map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
        })? {
            return self.replay_parallel_payload_terminal_result(forced_payload, Ok(value));
        }
        if let Some(result) = parallel_cell.checked_terminal_result().map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::ParallelThunkPayload { id, source }, span)
        })? {
            return self.replay_parallel_payload_terminal_result(forced_payload, result);
        }

        let worker = self.options.parallel_thunk_worker_id();
        let body_ran = std::cell::Cell::new(false);
        // Claim-wait diagnostics (stats runs only): time slow-path forces
        // that resolve without running the body - i.e. waits on a claim
        // another worker owns, plus racy terminal replays. Gated on the
        // stats dump so production parallel runs skip the per-force clock.
        let wait_started = (self.shared.is_some() && self.options.eval_stats_dump())
            .then(std::time::Instant::now);
        let outcome = parallel_cell
            .force_or_wait_with(worker, || {
                body_ran.set(true);
                self.force_serial_thunk_value(id, span, source_thunk, forced_payload, thunk)
            })
            .map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::ParallelThunkPayload { id, source }, span)
            })?;
        if let Some(started) = wait_started
            && !body_ran.get()
            && let Some(shared) = self.shared.as_ref()
        {
            shared.record_claim_wait(started.elapsed());
        }
        match outcome {
            TreeWalkParallelThunkForceOutcome::Ready(result) => {
                if body_ran.get() {
                    result
                } else {
                    self.replay_parallel_payload_terminal_result(forced_payload, result)
                }
            }
            TreeWalkParallelThunkForceOutcome::SelfCycle { .. } => Err(TreeWalkError::new(
                TreeWalkErrorKind::Force {
                    id,
                    source: ForceError::InfiniteRecursion,
                },
                span,
            )),
        }
    }

    fn replay_parallel_payload_terminal_result(
        &mut self,
        forced_payload: u64,
        result: Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        // Replaying a result another worker published is a foreign-value
        // ingestion point: refresh the shared-context prefix replicas so all
        // symbols, modules, and derivation surfaces reachable from the
        // replayed value (or error) resolve locally. The publishing edge of
        // the parallel cell happens-before this call, so the shared logs are
        // never stale here.
        self.sync_shared_context();
        match result {
            Ok(value) => {
                self.unmark_lazy_identity_thunk_payload(forced_payload);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    fn force_serial_thunk_value(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        forced_payload: u64,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        if thunk.is_single_entry_force_storage() {
            return self.force_single_entry_thunk_value(
                id,
                span,
                source_thunk,
                forced_payload,
                thunk,
            );
        }
        match thunk
            .cell()
            .begin_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            ForceClaim::AlreadyForced(value) => {
                self.unmark_lazy_identity_thunk_payload(forced_payload);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            ForceClaim::Claimed(guard) => {
                self.push_active_force_root(id, span, source_thunk)?;
                let result = self.force_claimed_thunk_with_tier1(
                    id,
                    span,
                    source_thunk,
                    forced_payload,
                    thunk,
                    guard,
                );
                self.pop_active_force_root(source_thunk);
                result
            }
        }
    }

    /// Consults the optional tier-1 engine before running the tree-walk body.
    ///
    /// When an engine is installed it is asked once whether this claimed thunk
    /// has published tier-1 native code to dispatch. On a successful dispatch the
    /// native value is published through the normal
    /// [`finish_forced_value`](Self::finish_forced_value) path. On a deopt (native
    /// code trapped or errored) or when the engine declines, evaluation falls
    /// through to the existing memoized tree-walk body. The engine borrows `&mut
    /// self`; the shared thunk `Rc` and its [`ForceGuard`] never borrow `self`, so
    /// the engine is free to re-enter forcing and mutate the heap while dispatching.
    fn force_claimed_thunk_with_tier1(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        forced_payload: u64,
        thunk: &EvalThunk,
        guard: ForceGuard<'_>,
    ) -> Result<Value, TreeWalkError> {
        if let Some(engine) = self.tier1_engine.clone() {
            // Fast path: a thunk with no lowerable IR body can never dispatch, and
            // a def-site the engine has already gated will never dispatch again.
            // Both are recognized from a cheap `body_ref` field read, so skip the
            // engine hook (and its heap-record and side-table lookups) entirely.
            // This is byte-identical to consulting the engine, which would do
            // nothing for either case, but removes the per-force hook tax from the
            // common cold-thunk path.
            let def_site = thunk.body_ref();
            let consult = match def_site {
                Some(def_site) => !self.tier1_skipped_def_sites.contains(&def_site),
                None => false,
            };
            if consult {
                match engine.on_serial_force(self, source_thunk, id, span) {
                    Tier1ForceHook::Dispatched(value) => {
                        self.increment_tier1_dispatched();
                        let value =
                            self.finish_forced_value(id, span, source_thunk, guard, value)?;
                        self.unmark_lazy_identity_thunk_payload(forced_payload);
                        return Ok(value);
                    }
                    Tier1ForceHook::Deopted => self.increment_tier1_deopted(),
                    Tier1ForceHook::Continued {
                        promoted,
                        blacklisted,
                        gated,
                    } => {
                        if promoted {
                            self.increment_tier1_promoted();
                        }
                        if blacklisted {
                            self.increment_tier1_blacklisted();
                        }
                        if gated && let Some(def_site) = def_site {
                            self.tier1_skipped_def_sites.insert(def_site);
                        }
                    }
                }
            }
        }
        self.force_claimed_thunk_with_memo(id, span, source_thunk, forced_payload, thunk, guard)
    }

    fn force_single_entry_thunk_value(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        forced_payload: u64,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        self.push_active_force_root(id, span, source_thunk)?;
        let result = (|| -> Result<Value, TreeWalkError> {
            self.increment_thunks_forced();
            self.eval_thunk_body(id, span, thunk)
        })();
        self.pop_active_force_root(source_thunk);
        let value = result?;
        self.unmark_lazy_identity_thunk_payload(forced_payload);
        Ok(value)
    }

    pub(super) fn force_memoized_claimed_thunk(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        forced_payload: u64,
        thunk: &EvalThunk,
        guard: ForceGuard<'_>,
    ) -> Result<Value, TreeWalkError> {
        // When no forced-expression cache is observable, every step below (subject
        // content hashing, memoization-demand recording, payload hashing on
        // observation) is a no-op that still pays for the hashes. Skip straight to
        // the body force. This is behaviorally identical to the cached path with an
        // always-`Admit` decision and disabled lookup/observe, but avoids the
        // hashing measured to dominate cache-off evaluation.
        if !self.force_cache_active {
            self.increment_thunks_forced();
            let value = self.eval_thunk_body(id, span, thunk)?;
            let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
            self.unmark_lazy_identity_thunk_payload(forced_payload);
            return Ok(value);
        }
        let cache_subject =
            self.force_cache_subject_for_thunk(EvalNodeRef::new(self.current_module, id), thunk);
        let memoization_decision = cache_subject
            .as_ref()
            .map(|subject| self.record_force_cache_memoization_demand(subject))
            .unwrap_or(MemoizationDecision::Admit);
        let memoization_admitted = memoization_decision == MemoizationDecision::Admit;
        if memoization_admitted
            && let Some(value) = self.lookup_forced_inline_expression_result(cache_subject.clone())
        {
            let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
            self.unmark_lazy_identity_thunk_payload(forced_payload);
            return Ok(value);
        }

        let thunks_forced_before = self.stats.thunks_forced;
        self.increment_thunks_forced();
        let impure_trace_cursor = memoization_admitted.then(|| self.impure_input_trace_cursor());
        let active_force_cache_node = memoization_admitted
            .then(|| self.active_force_cache_node_for_subject(cache_subject.as_ref()))
            .flatten();
        if let Some(node) = active_force_cache_node {
            self.active_memo_read_nodes
                .push(ActiveMemoReadNode::new(node));
        }
        let result = self.eval_thunk_body(id, span, thunk);
        let active_force_cache_node = if active_force_cache_node.is_some() {
            let popped = self.active_memo_read_nodes.pop();
            debug_assert_eq!(
                popped.as_ref().map(ActiveMemoReadNode::node),
                active_force_cache_node
            );
            popped
        } else {
            None
        };
        let value = result?;
        let impure_trace =
            impure_trace_cursor.map(|cursor| self.force_cache_impure_input_trace_segment(cursor));
        let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
        if let Some(active_force_cache_node) = active_force_cache_node {
            let dependency = active_force_cache_node.node();
            self.replace_active_memo_reads(active_force_cache_node);
            self.record_enclosing_memo_read(dependency);
        }
        self.unmark_lazy_identity_thunk_payload(forced_payload);
        if let Some(subject) = &cache_subject {
            self.record_forced_expression_demand(subject);
        }
        if let Some(impure_trace) = impure_trace {
            let scale_eval_work_by_payload = !impure_trace.trace.is_empty();
            let eval_work_units = self
                .stats
                .thunks_forced
                .saturating_sub(thunks_forced_before);
            self.observe_forced_inline_expression_result_with_eval_work_units(
                cache_subject,
                value,
                impure_trace,
                Some(eval_work_units),
                scale_eval_work_by_payload,
            );
        }
        Ok(value)
    }

    pub(super) fn eval_thunk_body(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        match thunk.kind() {
            EvalThunkKind::Node {
                body,
                env,
                with_env,
                scoped_globals,
            } => {
                let thunk_env = self.clone_env_frames(id, env, span)?;
                let thunk_with_env = self.clone_with_scopes(id, with_env, span)?;
                let thunk_scoped_globals = self.clone_scoped_globals(id, scoped_globals, span)?;
                self.reserve_suspended_env_root_frame(id, span)?;
                let saved_env = self.swap_env_frames(thunk_env);
                let saved_with_scopes = std::mem::replace(&mut self.with_scopes, thunk_with_env);
                let saved_scoped_globals =
                    std::mem::replace(&mut self.scoped_globals, thunk_scoped_globals);
                self.push_suspended_env_roots(saved_env, saved_with_scopes, saved_scoped_globals);
                let result =
                    self.with_current_module(body.module(), |eval| eval.eval_node(body.id()));
                if let Some(saved) = self.pop_suspended_env_roots() {
                    self.restore_env_frames(saved.env);
                    self.with_scopes = saved.with_scopes;
                    self.scoped_globals = saved.scoped_globals;
                } else {
                    debug_assert!(false, "suspended env root stack is unbalanced");
                }
                result
            }
            EvalThunkKind::Apply {
                function,
                function_span,
                function_value,
                argument,
                argument_value,
            } => self.with_current_module(function.module(), |eval| {
                eval.apply_lambda_value(
                    id,
                    span,
                    function.id(),
                    *function_value,
                    *function_span,
                    argument.id(),
                    *argument_value,
                )
            }),
            EvalThunkKind::Apply2 {
                function,
                function_span,
                function_value,
                first_argument,
                first_argument_span,
                first_argument_value,
                second_argument,
                second_argument_span,
                second_argument_value,
            } => self.with_current_module(function.module(), |eval| {
                eval.apply_lambda_value_2(
                    id,
                    span,
                    function.id(),
                    *function_value,
                    *function_span,
                    first_argument.id(),
                    *first_argument_span,
                    *first_argument_value,
                    second_argument.id(),
                    *second_argument_span,
                    *second_argument_value,
                )
            }),
            EvalThunkKind::Select {
                select,
                receiver,
                path,
            } => self.with_current_module(select.module(), |eval| {
                let node = *eval.node(select.id())?;
                let span = node.span;
                let IrData::Select { site, .. } = node.data else {
                    return Err(eval.invalid_payload(select.id(), &node, "select payload"));
                };
                // Lowering builds select thunks from the same select node whose
                // site id owns the payload path. Preserve that site so forced
                // select thunks share the active static-segment flat IC.
                let value = eval.eval_select_from_value(
                    select.id(),
                    span,
                    *receiver,
                    *path,
                    Some(site),
                    None,
                    true,
                )?;
                eval.force_node_result(select.id(), span, value)
            }),
            EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                (*builtin).select(self, id, span, *symbol)
            }
        }
    }

    pub(super) fn finish_forced_value(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        guard: ForceGuard<'_>,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let tier = self.options.thunk_resolve_barrier_tier();
        if tier == GenerationalGcTier::OneShotArena {
            // Default tier: the one-shot arena barrier is `DisabledThunkResolveBarrier`,
            // whose `before_publish_forced` is a no-op. `ForceGuard::finish` publishes
            // with exactly that barrier, so take it directly and skip the vtable
            // lookup, function-pointer call, and `RuntimeThunkResolveBarrier` enum
            // construction on the hottest evaluator event.
            return guard.finish(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
            });
        }
        let mut barrier = runtime_thunk_resolve_write_barrier_with_card_table(
            tier,
            &self.heap,
            source_thunk,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
        )
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        guard
            .finish_with_barrier(value, &mut barrier)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))
    }
}
