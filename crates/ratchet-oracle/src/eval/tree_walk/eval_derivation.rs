//! Evaluation of `derivation`/`derivationStrict` and derivation attribute handling.

use super::*;

mod aterm_cache;
mod demand_fanout;
mod name_value;
mod static_outputs;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistSideRecordRuntimeObservation {
    Accepted(DemandNodeId),
    Rejected,
    Skipped,
}

impl TreeWalk {
    pub(super) fn invalid_payload(
        &self,
        id: IrId,
        node: &IrNode,
        expected: &'static str,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::InvalidPayload {
                id,
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }

    pub(super) fn clone_attr_entries(
        id: IrId,
        span: Span,
        attrs: &FlatAttrs,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let entries = attrs.entries_by_symbol();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(entries.len()).map_err(|_| {
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
        cloned.extend_from_slice(entries);
        Ok(cloned)
    }

    pub(super) fn clone_attr_entries_source_order(
        id: IrId,
        span: Span,
        attrs: &FlatAttrs,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(attrs.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: attrs.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend(attrs.iter_source_order().copied());
        Ok(cloned)
    }

    pub(super) fn clone_attr_entries_lexicographic(
        id: IrId,
        span: Span,
        attrs: &FlatAttrs,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(attrs.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: attrs.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend(attrs.iter_lexicographic().copied());
        Ok(cloned)
    }

    pub(super) fn clone_list_elements(
        id: IrId,
        span: Span,
        list: &NixList,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let elements = list.as_slice();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        cloned.extend_from_slice(elements);
        Ok(cloned)
    }

    pub(super) fn eval_derivation_wrapper_lambda(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        self.load_and_eval_import_bytes(
            id,
            span,
            id,
            span,
            DERIVATION_INTERNAL_PATH,
            b"/",
            DERIVATION_INTERNAL_SOURCE.as_bytes(),
            ImportGlobalScope::Fresh,
        )
    }

    pub(super) fn eval_derivation_wrapper_call(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_value: Value,
    ) -> Result<Value, TreeWalkError> {
        let wrapper = self.eval_derivation_wrapper_lambda(id, span)?;
        self.apply_lambda_value(id, span, id, wrapper, span, argument, argument_value)
    }

    pub(super) fn eval_derivation_strict(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::DialectNode { argument, .. } = node.data else {
            return Err(self.invalid_payload(id, node, "derivationStrict argument payload"));
        };
        let argument_span = self.node(argument)?.span;
        self.eval_derivation_strict_argument(id, node.span, argument, argument_span)
    }

    pub(super) fn eval_derivation_strict_argument(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
    ) -> Result<Value, TreeWalkError> {
        let trace_cursor = self.impure_input_trace_cursor();
        let result = self.with_active_derivation_trace_cursor(trace_cursor, |eval| {
            eval.with_active_derivation_aterm_memo_read_node(id, |eval| {
                let value = eval.eval_node(argument)?;
                eval.eval_derivation_strict_value_inner(id, span, argument, argument_span, value)
            })
        });
        if result.is_ok() {
            let trace = self.impure_input_trace_segment(trace_cursor);
            self.invalidate_derivation_side_records_for_uncacheable_trace(id, &trace);
        }
        result
    }

    pub(super) fn eval_derivation_strict_value(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let trace_cursor = self.impure_input_trace_cursor();
        let result = self.with_active_derivation_trace_cursor(trace_cursor, |eval| {
            eval.with_active_derivation_aterm_memo_read_node(id, |eval| {
                eval.eval_derivation_strict_value_inner(id, span, argument, argument_span, value)
            })
        });
        if result.is_ok() {
            let trace = self.impure_input_trace_segment(trace_cursor);
            self.invalidate_derivation_side_records_for_uncacheable_trace(id, &trace);
        }
        result
    }

    fn invalidate_derivation_side_records_for_uncacheable_trace(
        &mut self,
        id: IrId,
        trace: &ImpureInputTraceSegment,
    ) {
        // Derivation side records do not retain verifying traces yet, so any
        // incomplete or uncacheable input observed while building the .drv must
        // make the side records unavailable for same-runtime reuse.
        if Self::derivation_side_record_trace_is_persistable(trace) {
            return;
        }
        let derivation_aterm_subject = self.derivation_aterm_cache_subject_for_current_node(id);
        let static_outputs_subject =
            self.static_derivation_outputs_cache_subject_for_current_node(id);
        if let Some((identity, free_var_value_hashes)) = &derivation_aterm_subject {
            self.clear_persist_derivation_aterm_path(*identity, free_var_value_hashes);
        }
        if let Some((identity, free_var_value_hashes)) = &static_outputs_subject {
            self.clear_persist_static_derivation_output_paths(*identity, free_var_value_hashes);
        }
        let subjects = [derivation_aterm_subject, static_outputs_subject];
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping uncacheable derivation runtime side-record invalidation"
            );
            return;
        };
        for (identity, free_var_value_hashes) in subjects.into_iter().flatten() {
            if let Err(error) = cache.invalidate_inline_expression_payload(
                identity,
                free_var_value_hashes.iter().copied(),
            ) {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator uncacheable derivation side-record invalidation failed"
                );
            }
        }
    }

    fn active_derivation_side_record_trace_is_persistable(&self) -> bool {
        let Some(cursor) = self.active_derivation_trace_cursors.last().copied() else {
            return true;
        };
        let trace = self.impure_input_trace_segment(cursor);
        Self::derivation_side_record_trace_is_persistable(&trace)
    }

    fn derivation_side_record_trace_is_persistable(trace: &ImpureInputTraceSegment) -> bool {
        trace.complete
            && trace
                .trace
                .iter()
                .all(|fingerprint| fingerprint.as_cacheable().is_some())
    }

    fn with_active_derivation_trace_cursor<T>(
        &mut self,
        cursor: ImpureInputTraceCursor,
        evaluate: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.active_derivation_trace_cursors.push(cursor);
        let result = evaluate(self);
        let popped = self.active_derivation_trace_cursors.pop();
        debug_assert_eq!(popped, Some(cursor));
        result
    }

    pub(in crate::eval::tree_walk) fn with_active_derivation_aterm_memo_read_node<T>(
        &mut self,
        id: IrId,
        evaluate: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let active_memo_read_node =
            self.active_derivation_aterm_memo_read_node_for_current_node(id);
        if let Some(node) = active_memo_read_node {
            self.active_memo_read_nodes
                .push(ActiveMemoReadNode::new(node));
        }
        let result = evaluate(self);
        let active_memo_read_node = if active_memo_read_node.is_some() {
            let popped = self.active_memo_read_nodes.pop();
            debug_assert_eq!(
                popped.as_ref().map(ActiveMemoReadNode::node),
                active_memo_read_node
            );
            popped
        } else {
            None
        };
        let result = result?;
        if let Some(active_memo_read_node) = active_memo_read_node {
            let dependency = active_memo_read_node.node();
            if self.replace_active_memo_reads(active_memo_read_node) {
                self.clear_persist_derivation_side_records_for_current_node(id);
            }
            self.record_enclosing_memo_read(dependency);
        }
        Ok(result)
    }

    fn clear_persist_derivation_side_records_for_current_node(&mut self, id: IrId) {
        let derivation_aterm_subject = self.derivation_aterm_cache_subject_for_current_node(id);
        let static_outputs_subject =
            self.static_derivation_outputs_cache_subject_for_current_node(id);
        if let Some((identity, free_var_value_hashes)) = &derivation_aterm_subject {
            self.clear_persist_derivation_aterm_path(*identity, free_var_value_hashes);
        }
        if let Some((identity, free_var_value_hashes)) = &static_outputs_subject {
            self.clear_persist_static_derivation_output_paths(*identity, free_var_value_hashes);
        }
    }

    fn eval_derivation_strict_value_inner(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_demanded_value(argument, argument_span, value)?;
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "attrs",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let entries = {
            let attrs = self.heap.get_attrs(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            Self::clone_attr_entries_lexicographic(argument, argument_span, attrs)?
        };

        // Parallel fan-out (L2-P5): every attribute value below is forced
        // unconditionally and every non-scalar attribute is string-coerced, so
        // entry values publish as force or coercion demand that helper workers
        // execute ahead of this serial loop - unfolding the dependency closure
        // transitively (see `demand_fanout`).
        self.publish_derivation_entry_fanout(&entries);

        let mut derivation = nix_compat::derivation::Derivation::default();
        let mut context = StringContext::empty();
        let name = self.derivation_name_value(id, span, argument, argument_span, &entries)?;
        let mut builder = None;
        let mut system = None;
        let mut outputs_seen = false;
        let structured_attrs =
            self.derivation_structured_attrs_value(id, span, argument, argument_span, &entries)?;
        let structured_attrs_enabled = structured_attrs == Some(true);
        let mut structured_json = StructuredAttrsJson::new();
        if !structured_attrs_enabled {
            derivation
                .environment
                .insert("name".to_owned(), name.clone().into());
        }
        let ignore_nulls =
            self.derivation_ignore_nulls_value(id, span, argument, argument_span, &entries)?;
        let mut output_hash = None;
        let mut output_hash_algo = None;
        let mut output_hash_mode = None;
        let mut content_addressed = false;
        let mut impure = false;

        for entry in entries {
            let key = {
                let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: argument,
                            symbol: entry.key,
                        },
                        argument_span,
                    )
                })?;
                Self::copy_bytes_for_node(argument, argument_span, key)?
            };

            let value = self.force_value(argument, argument_span, entry.value)?;
            // Parallel fan-out (L2-P3b): list-valued non-special attributes
            // are string-coerced element by element below; publish the
            // elements so helpers can instantiate independent dependency
            // subtrees while this loop coerces serially.
            if self.shared.is_some() && value.tag() == ValueTag::List {
                self.publish_derivation_list_fanout(&key, value);
            }
            if key == NAME_ATTR {
                if structured_attrs_enabled {
                    Self::write_structured_json_string_field(
                        id,
                        span,
                        &mut structured_json,
                        &key,
                        &name,
                    )?;
                }
                continue;
            }
            if key == IGNORE_NULLS_ATTR
                || (structured_attrs_enabled && key == STRUCTURED_ATTRS_ATTR)
            {
                continue;
            }
            if ignore_nulls && value.tag() == ValueTag::Null {
                continue;
            }
            if key == CONTENT_ADDRESSED_ATTR && self.expect_bool(id, value, span)? {
                content_addressed = true;
                continue;
            }
            if key == IMPURE_ATTR && self.expect_bool(id, value, span)? {
                impure = true;
                continue;
            }

            if key == ARGS_ATTR {
                let (arguments, value_context) =
                    self.derivation_args_value(id, span, argument, argument_span, value)?;
                context = context.union(&value_context).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                })?;
                derivation.arguments = arguments;
                continue;
            }
            if structured_attrs_enabled && key == OUTPUTS_ATTR {
                let (outputs, output_names, value_context) =
                    self.derivation_outputs_list_value(id, span, argument, argument_span, value)?;
                context = context.union(&value_context).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                })?;
                Self::write_structured_json_string_list_field(
                    id,
                    span,
                    &mut structured_json,
                    &key,
                    &output_names,
                )?;
                outputs_seen = true;
                derivation.outputs = outputs;
                continue;
            }
            if structured_attrs_enabled {
                match key.as_slice() {
                    BUILDER_ATTR => {
                        let (bytes, value_context) =
                            self.derivation_string_value(id, span, argument, argument_span, value)?;
                        context = context.union(&value_context).map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                        })?;
                        let env_value =
                            Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                        Self::write_structured_json_string_field(
                            id,
                            span,
                            &mut structured_json,
                            &key,
                            &env_value,
                        )?;
                        builder = Some(env_value);
                    }
                    SYSTEM_ATTR => {
                        let bytes = self.derivation_context_free_string_value(
                            id,
                            span,
                            argument,
                            argument_span,
                            value,
                        )?;
                        let env_value =
                            Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                        Self::write_structured_json_string_field(
                            id,
                            span,
                            &mut structured_json,
                            &key,
                            &env_value,
                        )?;
                        system = Some(env_value);
                    }
                    OUTPUT_HASH_ATTR | OUTPUT_HASH_ALGO_ATTR | OUTPUT_HASH_MODE_ATTR => {
                        let bytes = self.derivation_context_free_string_value(
                            id,
                            span,
                            argument,
                            argument_span,
                            value,
                        )?;
                        let env_value =
                            Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                        Self::write_structured_json_string_field(
                            id,
                            span,
                            &mut structured_json,
                            &key,
                            &env_value,
                        )?;
                        match key.as_slice() {
                            OUTPUT_HASH_ATTR => output_hash = Some(env_value),
                            OUTPUT_HASH_ALGO_ATTR => output_hash_algo = Some(env_value),
                            OUTPUT_HASH_MODE_ATTR => output_hash_mode = Some(env_value),
                            _ => {}
                        }
                    }
                    _ => {
                        self.write_structured_json_value_field(
                            id,
                            span,
                            argument,
                            argument_span,
                            &mut structured_json,
                            &key,
                            value,
                            &mut context,
                        )?;
                    }
                }
                continue;
            }

            let rendered =
                self.derivation_to_string_value(id, span, argument, argument_span, value)?;
            let (bytes, value_context) = rendered.into_parts();
            context = context.union(&value_context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;

            let env_key = Self::derivation_utf8_string(id, span, "environment name", &key)?;
            match key.as_slice() {
                BUILDER_ATTR => {
                    let env_value =
                        Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                    derivation
                        .environment
                        .insert(env_key, env_value.clone().into());
                    builder = Some(env_value);
                }
                SYSTEM_ATTR => {
                    let env_value =
                        Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                    derivation
                        .environment
                        .insert(env_key, env_value.clone().into());
                    system = Some(env_value);
                }
                OUTPUTS_ATTR => {
                    let env_value =
                        Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                    derivation
                        .environment
                        .insert(env_key, env_value.clone().into());
                    outputs_seen = true;
                    derivation.outputs =
                        Self::derivation_outputs_value(id, span, &bytes, &env_value)?;
                }
                OUTPUT_HASH_ATTR | OUTPUT_HASH_ALGO_ATTR | OUTPUT_HASH_MODE_ATTR => {
                    let env_value =
                        Self::derivation_utf8_string(id, span, "environment value", &bytes)?;
                    if key.as_slice() == OUTPUT_HASH_ATTR {
                        output_hash = Some(env_value.clone());
                    } else if key.as_slice() == OUTPUT_HASH_ALGO_ATTR {
                        output_hash_algo = Some(env_value.clone());
                    } else if key.as_slice() == OUTPUT_HASH_MODE_ATTR {
                        output_hash_mode = Some(env_value.clone());
                    }
                    derivation.environment.insert(env_key, env_value.into());
                }
                _ => {
                    derivation.environment.insert(env_key, bytes.into());
                }
            }
        }

        derivation.builder =
            builder.ok_or_else(|| self.missing_derivation_strict_attr(id, span, BUILDER_ATTR))?;
        derivation.system =
            system.ok_or_else(|| self.missing_derivation_strict_attr(id, span, SYSTEM_ATTR))?;
        if !outputs_seen {
            derivation
                .outputs
                .insert("out".to_owned(), nix_compat::derivation::Output::default());
        }
        Self::validate_derivation_strict_name_suffix(id, span, &name)?;
        Self::configure_derivation_fixed_output(
            id,
            span,
            &mut derivation,
            output_hash.as_deref(),
            output_hash_algo.as_deref(),
            output_hash_mode.as_deref(),
        )?;
        let deferred_output_resolution = if output_hash.is_none() {
            if content_addressed && impure {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: "derivation cannot be both content-addressed and impure"
                            .to_owned(),
                    },
                    span,
                ));
            }
            if content_addressed {
                Some(DerivationOutputResolution::FloatingCa(
                    Self::configure_derivation_floating_ca_output(
                        id,
                        span,
                        output_hash_algo.as_deref(),
                        output_hash_mode.as_deref(),
                    )?,
                ))
            } else if impure {
                Some(DerivationOutputResolution::Impure(
                    Self::configure_derivation_floating_ca_output(
                        id,
                        span,
                        output_hash_algo.as_deref(),
                        output_hash_mode.as_deref(),
                    )?,
                ))
            } else {
                None
            }
        } else {
            None
        };
        for output_name in derivation.outputs.keys() {
            let env_value = if deferred_output_resolution.is_some() {
                Self::derivation_output_placeholder(id, span, output_name.as_bytes())?
            } else {
                Vec::new()
            };
            derivation
                .environment
                .insert(output_name.clone(), env_value.into());
        }
        if structured_attrs_enabled {
            derivation
                .environment
                .insert("__json".to_owned(), structured_json.finish().into());
        }
        self.add_derivation_context_inputs(id, span, &mut derivation, &context)?;

        self.validate_derivation_strict_before_paths(id, span, &derivation)?;
        let input_hashes = self.known_derivation_hashes_for_inputs(id, span, &derivation)?;
        let (known_hash, drv_path, output_resolution, aterm_bytes) =
            if let Some(output_resolution) = deferred_output_resolution {
                match output_resolution {
                    DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                        let path_result = self.calculate_derivation_path_with_aterm_cache_result(
                            id,
                            span,
                            &name,
                            &derivation,
                            DerivationOutputResolution::FloatingCa(floating_ca_output),
                        )?;
                        let known_hash = path_result
                            .hash_derivation_modulo
                            .filter(|_| !input_hashes.has_deferred)
                            .unwrap_or_else(|| {
                                self.hash_floating_ca_derivation_modulo_with_inputs(
                                    &derivation,
                                    floating_ca_output,
                                    &input_hashes.hashes,
                                )
                            });
                        (
                            known_hash,
                            path_result.path,
                            DerivationOutputResolution::FloatingCa(floating_ca_output),
                            path_result.aterm_bytes,
                        )
                    }
                    DerivationOutputResolution::Impure(impure_output) => {
                        let known_hash = Self::impure_derivation_hash_modulo();
                        let path_result = self.calculate_derivation_path_with_aterm_cache_result(
                            id,
                            span,
                            &name,
                            &derivation,
                            DerivationOutputResolution::Impure(impure_output),
                        )?;
                        (
                            known_hash,
                            path_result.path,
                            DerivationOutputResolution::Impure(impure_output),
                            path_result.aterm_bytes,
                        )
                    }
                    DerivationOutputResolution::StaticPaths
                    | DerivationOutputResolution::DeferredPlaceholders => unreachable!(
                        "deferred derivation output setup only produces floating or impure outputs"
                    ),
                }
            } else if input_hashes.has_deferred && !Self::derivation_has_fixed_output(&derivation) {
                let known_hash = self.hash_derivation_modulo_with_inputs(
                    id,
                    span,
                    &derivation,
                    &input_hashes.hashes,
                )?;
                let drv_path = self.calculate_derivation_path(id, span, &name, &derivation)?;
                (
                    known_hash,
                    drv_path,
                    DerivationOutputResolution::DeferredPlaceholders,
                    None,
                )
            } else {
                let known_hash = self.resolve_static_derivation_outputs_with_cache(
                    id,
                    span,
                    &name,
                    &mut derivation,
                    &input_hashes,
                )?;
                let path_result = self.calculate_derivation_path_with_aterm_cache_result(
                    id,
                    span,
                    &name,
                    &derivation,
                    DerivationOutputResolution::StaticPaths,
                )?;
                (
                    known_hash,
                    path_result.path,
                    DerivationOutputResolution::StaticPaths,
                    path_result.aterm_bytes,
                )
            };
        self.remember_derivation(
            id,
            span,
            drv_path.clone(),
            &derivation,
            known_hash,
            output_resolution,
            aterm_bytes.clone(),
        );
        self.observe_derivation_aterm_expression(
            id,
            span,
            &drv_path,
            &derivation,
            known_hash,
            output_resolution,
            aterm_bytes.as_deref(),
        );
        self.alloc_derivation_strict_result(id, span, &derivation, &drv_path, output_resolution)
    }

    pub(super) fn derivation_ignore_nulls_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        entries: &[AttrEntry],
    ) -> Result<bool, TreeWalkError> {
        for entry in entries {
            let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: attrs_id,
                        symbol: entry.key,
                    },
                    attrs_span,
                )
            })?;
            if key != IGNORE_NULLS_ATTR {
                continue;
            }

            let value = self.force_value(attrs_id, attrs_span, entry.value)?;
            return self.expect_bool(id, value, span);
        }

        Ok(false)
    }

    pub(super) fn derivation_structured_attrs_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        entries: &[AttrEntry],
    ) -> Result<Option<bool>, TreeWalkError> {
        for entry in entries {
            let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: attrs_id,
                        symbol: entry.key,
                    },
                    attrs_span,
                )
            })?;
            if key != STRUCTURED_ATTRS_ATTR {
                continue;
            }

            let value = self.force_value(attrs_id, attrs_span, entry.value)?;
            return self.expect_bool(id, value, span).map(Some);
        }

        Ok(None)
    }

    pub(super) fn derivation_args_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<(Vec<String>, StringContext), TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "list",
                    actual: value.tag(),
                },
                value_span,
            ));
        }

        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: value_id,
                        source,
                    },
                    value_span,
                )
            })?;
            Self::clone_list_elements(value_id, value_span, list)?
        };
        let mut arguments = Vec::new();
        arguments.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: value_id,
                    len: elements.len(),
                },
                value_span,
            )
        })?;
        let mut context = StringContext::empty();
        for element in elements {
            let value = self.force_value(value_id, value_span, element)?;
            let rendered =
                self.derivation_to_string_value(id, span, value_id, value_span, value)?;
            let (bytes, value_context) = rendered.into_parts();
            context = context.union(&value_context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;
            arguments.push(Self::derivation_utf8_string(id, span, "argument", &bytes)?);
        }

        Ok((arguments, context))
    }

    pub(super) fn derivation_string_value(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<(Vec<u8>, StringContext), TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "string",
                    actual: value.tag(),
                },
                value_span,
            ));
        }

        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: value_id,
                    source,
                },
                value_span,
            )
        })?;
        let bytes = Self::copy_bytes_for_node(id, span, string.bytes())?;
        let context = StringContext::empty()
            .union(string.context())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok((bytes, context))
    }

    pub(super) fn derivation_context_free_string_value(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "string",
                    actual: value.tag(),
                },
                value_span,
            ));
        }

        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: value_id,
                    source,
                },
                value_span,
            )
        })?;
        if string.has_context() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StringContextNotAllowed {
                    id: value_id,
                    op: "derivationStrict",
                },
                value_span,
            ));
        }
        Self::copy_bytes_for_node(id, span, string.bytes())
    }

    pub(super) fn derivation_outputs_value(
        id: IrId,
        span: Span,
        bytes: &[u8],
        env_value: &str,
    ) -> Result<BTreeMap<String, nix_compat::derivation::Output>, TreeWalkError> {
        let mut outputs = BTreeMap::new();
        for output in bytes
            .split(|byte| Self::is_derivation_outputs_separator(*byte))
            .filter(|output| !output.is_empty())
        {
            let output_name = Self::derivation_utf8_string(id, span, "output name", output)?;
            Self::validate_derivation_strict_declared_output_name(id, span, &output_name)?;
            if outputs
                .insert(
                    output_name.clone(),
                    nix_compat::derivation::Output::default(),
                )
                .is_some()
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!("duplicate derivation output {output_name:?}"),
                    },
                    span,
                ));
            }
        }

        if outputs.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!(
                        "derivation cannot have an empty set of outputs from {env_value:?}"
                    ),
                },
                span,
            ));
        }

        Ok(outputs)
    }
}
