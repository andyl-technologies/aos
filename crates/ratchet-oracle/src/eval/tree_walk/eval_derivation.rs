//! Evaluation of `derivation`/`derivationStrict` and derivation attribute handling.

use super::*;
use crate::cache::{
    CachedDerivationAtermPath, CachedStaticDerivationOutputPathsPayload, PersistBlobKey,
};

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
        let value = self.eval_node(argument)?;
        self.eval_derivation_strict_value(id, node.span, argument, argument_span, value)
    }

    pub(super) fn eval_derivation_strict_value(
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
            if key == CONTENT_ADDRESSED_ATTR {
                if self.expect_bool(id, value, span)? {
                    content_addressed = true;
                    continue;
                }
            }
            if key == IMPURE_ATTR {
                if self.expect_bool(id, value, span)? {
                    impure = true;
                    continue;
                }
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
        let (known_hash, drv_path, output_resolution) =
            if let Some(output_resolution) = deferred_output_resolution {
                match output_resolution {
                    DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                        let known_hash = self.hash_floating_ca_derivation_modulo_with_inputs(
                            &derivation,
                            floating_ca_output,
                            &input_hashes.hashes,
                        );
                        let drv_path = self.calculate_derivation_path_with_aterm_cache(
                            id,
                            span,
                            &name,
                            &derivation,
                            DerivationOutputResolution::FloatingCa(floating_ca_output),
                        )?;
                        (
                            known_hash,
                            drv_path,
                            DerivationOutputResolution::FloatingCa(floating_ca_output),
                        )
                    }
                    DerivationOutputResolution::Impure(impure_output) => {
                        let known_hash = Self::impure_derivation_hash_modulo();
                        let drv_path = self.calculate_derivation_path_with_aterm_cache(
                            id,
                            span,
                            &name,
                            &derivation,
                            DerivationOutputResolution::Impure(impure_output),
                        )?;
                        (
                            known_hash,
                            drv_path,
                            DerivationOutputResolution::Impure(impure_output),
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
                )
            } else {
                let known_hash = self.resolve_static_derivation_outputs_with_cache(
                    id,
                    span,
                    &name,
                    &mut derivation,
                    &input_hashes,
                )?;
                let drv_path = self.calculate_derivation_path_with_aterm_cache(
                    id,
                    span,
                    &name,
                    &derivation,
                    DerivationOutputResolution::StaticPaths,
                )?;
                (
                    known_hash,
                    drv_path,
                    DerivationOutputResolution::StaticPaths,
                )
            };
        self.remember_derivation(
            id,
            span,
            drv_path.clone(),
            &derivation,
            known_hash,
            output_resolution,
        );
        self.observe_derivation_aterm_expression(
            id,
            span,
            &drv_path,
            &derivation,
            output_resolution,
        );
        self.alloc_derivation_strict_result(id, span, &derivation, &drv_path, output_resolution)
    }

    fn resolve_static_derivation_outputs_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &mut nix_compat::derivation::Derivation,
        input_hashes: &KnownDerivationInputHashes,
    ) -> Result<DerivationHashModulo, TreeWalkError> {
        let pre_output_aterm =
            self.derivation_aterm_bytes_with_input_hashes(derivation, &input_hashes.hashes);
        if let Some((cached, persistent_hit, identity, free_var_value_hashes)) =
            self.lookup_static_derivation_output_paths_for_current_node(id, &pre_output_aterm)
        {
            if let Some(known_hash) =
                self.apply_static_derivation_output_paths_from_cache(id, name, derivation, &cached)
            {
                if persistent_hit {
                    self.observe_persist_static_derivation_output_paths_runtime_hit(
                        identity,
                        &free_var_value_hashes,
                        &pre_output_aterm,
                        cached,
                    );
                }
                return Ok(known_hash);
            }
        }

        let hash =
            self.hash_derivation_modulo_with_inputs(id, span, derivation, &input_hashes.hashes)?;
        self.calculate_output_paths(id, span, name, derivation, &hash)?;
        let known_hash =
            self.hash_derivation_modulo_with_inputs(id, span, derivation, &input_hashes.hashes)?;
        self.observe_static_derivation_output_paths(id, &pre_output_aterm, derivation, known_hash);
        Ok(known_hash)
    }

    fn lookup_static_derivation_output_paths_for_current_node(
        &mut self,
        id: IrId,
        pre_output_aterm: &[u8],
    ) -> Option<(
        CachedDerivationOutputPaths,
        bool,
        CacheExprIdentity,
        Vec<DurableBlake3Hash>,
    )> {
        if !self.eval_cache_runtime_enabled() {
            return None;
        }
        let (identity, free_var_value_hashes) =
            self.static_derivation_outputs_cache_subject_for_current_node(id)?;
        if let Some(paths) = {
            let Ok(cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping static derivation output path lookup"
                );
                return None;
            };
            match cache.lookup_static_derivation_output_paths(
                identity,
                free_var_value_hashes.iter().copied(),
                pre_output_aterm,
            ) {
                Ok(paths) => paths,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator static derivation output path lookup failed"
                    );
                    None
                }
            }
        } {
            return Some((paths, false, identity, free_var_value_hashes));
        }
        let paths = self.lookup_persist_static_derivation_output_paths(
            identity,
            &free_var_value_hashes,
            pre_output_aterm,
        )?;
        Some((paths, true, identity, free_var_value_hashes))
    }

    fn lookup_persist_static_derivation_output_paths(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        pre_output_aterm: &[u8],
    ) -> Option<CachedDerivationOutputPaths> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        self.open_persist_eval_cache();
        let persist_cache = self.persist_cache.as_ref()?;
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        let value_hash = match persist_cache.lookup_node_materialized_value_hash(key) {
            Ok(Some(value_hash)) => value_hash,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output metadata lookup failed"
                );
                return None;
            }
        };
        let payload_bytes = match persist_cache
            .read_blob_indexed(PersistBlobKey::for_value(value_hash.as_durable_hash()))
        {
            Ok(Some(payload_bytes)) => payload_bytes,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload read failed"
                );
                return None;
            }
        };
        let payload = match CachedStaticDerivationOutputPathsPayload::decode_persistent_payload(
            &payload_bytes,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload decode failed"
                );
                return None;
            }
        };
        let actual = payload.value_hash();
        if actual != value_hash {
            tracing::warn!(
                target: "aos_nix::cache",
                expected = ?value_hash,
                actual = ?actual,
                "tree-walk evaluator persistent static derivation output payload hash mismatch"
            );
            return None;
        }
        if payload.pre_output_aterm_bytes() != pre_output_aterm {
            return None;
        }
        Some(payload.into_output_paths())
    }

    fn observe_persist_static_derivation_output_paths_runtime_hit(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent static derivation output runtime observation"
            );
            return;
        };
        if let Err(error) = cache
            .observe_static_derivation_output_paths(
                identity,
                free_var_value_hashes.iter().copied(),
                pre_output_aterm,
                output_paths,
            )
            .map(|_| ())
        {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent static derivation output runtime observation failed"
            );
        }
    }

    fn apply_static_derivation_output_paths_from_cache(
        &mut self,
        id: IrId,
        name: &str,
        derivation: &mut nix_compat::derivation::Derivation,
        cached: &CachedDerivationOutputPaths,
    ) -> Option<DerivationHashModulo> {
        let mut output_paths = BTreeMap::new();
        for cached_path in cached.output_paths() {
            let output_name = match std::str::from_utf8(cached_path.name()) {
                Ok(output_name) => output_name.to_owned(),
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        node = ?id,
                        error = %error,
                        "tree-walk evaluator cached static derivation output name was not UTF-8"
                    );
                    return None;
                }
            };
            if !derivation.outputs.contains_key(&output_name) {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    "tree-walk evaluator cached static derivation output path had an unknown output"
                );
                return None;
            }
            let Some(path_in_store) = self.strip_configured_store_dir(cached_path.path()) else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    path = %String::from_utf8_lossy(cached_path.path()),
                    "tree-walk evaluator cached static derivation output path was outside the configured store dir"
                );
                return None;
            };
            let path = match nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store)
            {
                Ok(path) => path,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        node = ?id,
                        output = %output_name,
                        path = %String::from_utf8_lossy(cached_path.path()),
                        error = %error,
                        "tree-walk evaluator cached static derivation output path was invalid"
                    );
                    return None;
                }
            };
            let expected_name = Self::output_path_name(name, &output_name);
            if path.name().as_str() != expected_name.as_str() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    expected = %expected_name,
                    actual = %path.name().as_str(),
                    "tree-walk evaluator cached static derivation output path had the wrong output name"
                );
                return None;
            }
            if output_paths.insert(output_name, path).is_some() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    "tree-walk evaluator cached static derivation output path repeated an output"
                );
                return None;
            }
        }
        if output_paths.len() != derivation.outputs.len() {
            tracing::warn!(
                target: "aos_nix::cache",
                node = ?id,
                expected = derivation.outputs.len(),
                actual = output_paths.len(),
                "tree-walk evaluator cached static derivation output paths had the wrong output count"
            );
            return None;
        }

        for (output_name, path) in output_paths {
            let env_value = self.store_path_absolute_bytes(&path).into();
            let Some(output) = derivation.outputs.get_mut(&output_name) else {
                return None;
            };
            if output.path.is_some() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    output = %output_name,
                    "tree-walk evaluator cached static derivation output path targeted an already resolved output"
                );
                return None;
            }
            output.path = Some(path);
            derivation.environment.insert(output_name, env_value);
        }
        self.increment_static_derivation_output_path_reuses();
        Some(DerivationHashModulo(cached.hash_derivation_modulo()))
    }

    fn observe_static_derivation_output_paths(
        &mut self,
        id: IrId,
        pre_output_aterm: &[u8],
        derivation: &nix_compat::derivation::Derivation,
        known_hash: DerivationHashModulo,
    ) {
        if !self.eval_cache_runtime_enabled() {
            return;
        }
        let Some((identity, free_var_value_hashes)) =
            self.static_derivation_outputs_cache_subject_for_current_node(id)
        else {
            return;
        };
        let Some(output_paths) =
            self.static_derivation_output_paths_payload(derivation, known_hash)
        else {
            return;
        };
        let observed = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping static derivation output path observation"
                );
                return;
            };
            match cache.observe_static_derivation_output_paths(
                identity,
                free_var_value_hashes.iter().copied(),
                pre_output_aterm,
                output_paths.clone(),
            ) {
                Ok(_) => true,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator static derivation output path observation failed"
                    );
                    false
                }
            }
        };
        if observed {
            self.materialize_persist_static_derivation_output_paths(
                identity,
                &free_var_value_hashes,
                pre_output_aterm,
                output_paths,
            );
        }
    }

    fn materialize_persist_static_derivation_output_paths(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let pre_output_aterm = match try_clone_bytes(pre_output_aterm) {
            Ok(pre_output_aterm) => pre_output_aterm,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload allocation failed"
                );
                return;
            }
        };
        let payload = CachedStaticDerivationOutputPathsPayload::new(pre_output_aterm, output_paths);
        let value_hash = payload.value_hash();
        let payload_bytes = match payload.encode_persistent_payload() {
            Ok(payload_bytes) => payload_bytes,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent static derivation output payload encode failed"
                );
                return;
            }
        };
        if let Err(error) = persist_cache.materialize_blob_indexed(
            PersistBlobKey::for_value(value_hash.as_durable_hash()),
            &payload_bytes,
            MaterializationDecision::Materialize,
        ) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent static derivation output payload write failed"
            );
            return;
        }
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        if let Err(error) = persist_cache.record_node_materialized_value_hash(key, value_hash) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent static derivation output metadata write failed"
            );
        }
    }

    fn static_derivation_output_paths_payload(
        &self,
        derivation: &nix_compat::derivation::Derivation,
        known_hash: DerivationHashModulo,
    ) -> Option<CachedDerivationOutputPaths> {
        let mut output_paths = Vec::new();
        output_paths
            .try_reserve_exact(derivation.outputs.len())
            .ok()?;
        for (output_name, output) in &derivation.outputs {
            let path = output.path.as_ref()?;
            output_paths.push(CachedDerivationOutputPath::new(
                output_name.as_bytes().to_vec(),
                self.store_path_absolute_bytes(path),
            ));
        }
        Some(CachedDerivationOutputPaths::new(known_hash.0, output_paths))
    }

    fn calculate_derivation_path_with_aterm_cache(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let aterm = match output_resolution {
            DerivationOutputResolution::StaticPaths => self.derivation_aterm_bytes(derivation),
            DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                self.floating_ca_derivation_aterm_bytes(derivation, floating_ca_output, None)
            }
            DerivationOutputResolution::Impure(impure_output) => {
                self.impure_derivation_aterm_bytes(derivation, impure_output, None)
            }
            DerivationOutputResolution::DeferredPlaceholders => {
                return self.calculate_derivation_path(id, span, name, derivation);
            }
        };
        if let Some(path) = self.lookup_derivation_aterm_path_for_current_node(id, name, &aterm) {
            return Ok(path);
        }
        self.calculate_derivation_path_from_aterm(id, span, name, derivation, &aterm)
    }

    fn lookup_derivation_aterm_path_for_current_node(
        &mut self,
        id: IrId,
        name: &str,
        aterm: &[u8],
    ) -> Option<nix_compat::store_path::StorePath<String>> {
        if !self.eval_cache_runtime_enabled() {
            return None;
        }
        let (identity, free_var_value_hashes) =
            self.derivation_aterm_cache_subject_for_current_node(id)?;
        let (path_bytes, persistent_hit) = if let Some(path_bytes) = {
            let Ok(cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping derivation ATerm path lookup"
                );
                return None;
            };
            match cache.lookup_derivation_aterm_path(
                identity,
                free_var_value_hashes.iter().copied(),
                aterm,
            ) {
                Ok(path_bytes) => path_bytes,
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator derivation ATerm path lookup failed"
                    );
                    None
                }
            }
        } {
            (path_bytes, false)
        } else {
            (
                self.lookup_persist_derivation_aterm_path(identity, &free_var_value_hashes, aterm)?,
                true,
            )
        };
        let Some(path_in_store) = self.strip_configured_store_dir(&path_bytes) else {
            tracing::warn!(
                target: "aos_nix::cache",
                node = ?id,
                path = %String::from_utf8_lossy(&path_bytes),
                "tree-walk evaluator derivation ATerm cached path was outside the configured store dir"
            );
            return None;
        };
        let path = match nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store) {
            Ok(path) => path,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    node = ?id,
                    path = %String::from_utf8_lossy(&path_bytes),
                    error = %error,
                    "tree-walk evaluator derivation ATerm cached path was invalid"
                );
                return None;
            }
        };
        let expected_name = format!("{name}.drv");
        if path.name().as_str() != expected_name.as_str() {
            tracing::warn!(
                target: "aos_nix::cache",
                node = ?id,
                expected = %expected_name,
                actual = %path.name().as_str(),
                "tree-walk evaluator derivation ATerm cached path had the wrong derivation name"
            );
            return None;
        }
        if persistent_hit {
            self.observe_persist_derivation_aterm_path_runtime_hit(
                identity,
                &free_var_value_hashes,
                aterm,
                &path_bytes,
            );
        }
        self.increment_derivation_aterm_path_reuses();
        Some(path)
    }

    fn lookup_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        aterm: &[u8],
    ) -> Option<Vec<u8>> {
        if !self.options.eval_cache_enabled() {
            return None;
        }
        self.open_persist_eval_cache();
        let persist_cache = self.persist_cache.as_ref()?;
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        let value_hash = match persist_cache.lookup_node_materialized_value_hash(key) {
            Ok(Some(value_hash)) => value_hash,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path metadata lookup failed"
                );
                return None;
            }
        };
        let payload_bytes = match persist_cache
            .read_blob_indexed(PersistBlobKey::for_value(value_hash.as_durable_hash()))
        {
            Ok(Some(payload_bytes)) => payload_bytes,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload read failed"
                );
                return None;
            }
        };
        let payload = match CachedDerivationAtermPath::decode_persistent_payload(&payload_bytes) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload decode failed"
                );
                return None;
            }
        };
        let actual = payload.value_hash();
        if actual != value_hash {
            tracing::warn!(
                target: "aos_nix::cache",
                expected = ?value_hash,
                actual = ?actual,
                "tree-walk evaluator persistent derivation ATerm path payload hash mismatch"
            );
            return None;
        }
        if payload.aterm_bytes() != aterm {
            return None;
        }
        try_clone_bytes(payload.path_bytes()).ok()
    }

    fn observe_persist_derivation_aterm_path_runtime_hit(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        aterm: &[u8],
        path: &[u8],
    ) {
        let Ok(mut cache) = self.eval_cache.lock() else {
            tracing::warn!(
                target: "aos_nix::cache",
                "tree-walk evaluator cache lock was poisoned; skipping persistent derivation ATerm path runtime observation"
            );
            return;
        };
        if let Err(error) = cache
            .observe_derivation_aterm_expression_path(
                identity,
                free_var_value_hashes.iter().copied(),
                aterm,
                path,
            )
            .map(|_| ())
        {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent derivation ATerm path runtime observation failed"
            );
        }
    }

    fn observe_derivation_aterm_expression(
        &mut self,
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) {
        if !self.eval_cache_runtime_enabled() {
            return;
        }
        let Some((identity, free_var_value_hashes)) =
            self.derivation_aterm_cache_subject_for_current_node(id)
        else {
            return;
        };
        let aterm = match self.derivation_aterm_bytes_for_observation(
            id,
            span,
            drv_path,
            derivation,
            output_resolution,
        ) {
            Ok(aterm) => aterm,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator derivation ATerm cache observation failed to serialize"
                );
                return;
            }
        };
        let drv_path_bytes = self.store_path_absolute_bytes(drv_path);
        let (observed, early_cutoff) = {
            let Ok(mut cache) = self.eval_cache.lock() else {
                tracing::warn!(
                    target: "aos_nix::cache",
                    "tree-walk evaluator cache lock was poisoned; skipping derivation ATerm observation"
                );
                return;
            };
            match cache.observe_derivation_aterm_expression_path(
                identity,
                free_var_value_hashes.iter().copied(),
                &aterm,
                &drv_path_bytes,
            ) {
                Ok(Some(reconsideration)) => {
                    (true, reconsideration.decision() == CutoffDecision::CutOff)
                }
                Ok(None) => (true, false),
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::cache",
                        error = %error,
                        "tree-walk evaluator derivation ATerm cache observation failed"
                    );
                    (false, false)
                }
            }
        };
        if observed {
            self.materialize_persist_derivation_aterm_path(
                identity,
                &free_var_value_hashes,
                &aterm,
                &drv_path_bytes,
            );
        }
        if early_cutoff {
            self.increment_early_cutoffs();
        }
    }

    fn materialize_persist_derivation_aterm_path(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: &[DurableBlake3Hash],
        aterm: &[u8],
        drv_path: &[u8],
    ) {
        if !self.options.eval_cache_enabled() {
            return;
        }
        self.open_persist_eval_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let aterm = match try_clone_bytes(aterm) {
            Ok(aterm) => aterm,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload allocation failed"
                );
                return;
            }
        };
        let drv_path = match try_clone_bytes(drv_path) {
            Ok(drv_path) => drv_path,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload allocation failed"
                );
                return;
            }
        };
        let payload = CachedDerivationAtermPath::new(aterm, drv_path);
        let value_hash = payload.value_hash();
        let payload_bytes = match payload.encode_persistent_payload() {
            Ok(payload_bytes) => payload_bytes,
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator persistent derivation ATerm path payload encode failed"
                );
                return;
            }
        };
        if let Err(error) = persist_cache.materialize_blob_indexed(
            PersistBlobKey::for_value(value_hash.as_durable_hash()),
            &payload_bytes,
            MaterializationDecision::Materialize,
        ) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent derivation ATerm path payload write failed"
            );
            return;
        }
        let key =
            PersistNodeMetadataKey::for_expression(identity, free_var_value_hashes.iter().copied());
        if let Err(error) = persist_cache.record_node_materialized_value_hash(key, value_hash) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator persistent derivation ATerm path metadata write failed"
            );
        }
    }

    fn derivation_aterm_bytes_for_observation(
        &self,
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
        output_resolution: DerivationOutputResolution,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match output_resolution {
            DerivationOutputResolution::StaticPaths => Ok(self.derivation_aterm_bytes(derivation)),
            DerivationOutputResolution::FloatingCa(floating_ca_output) => {
                Ok(self.floating_ca_derivation_aterm_bytes(derivation, floating_ca_output, None))
            }
            DerivationOutputResolution::Impure(impure_output) => {
                Ok(self.impure_derivation_aterm_bytes(derivation, impure_output, None))
            }
            DerivationOutputResolution::DeferredPlaceholders => {
                self.deferred_placeholder_derivation_aterm_bytes(id, span, drv_path, derivation)
            }
        }
    }

    pub(super) fn derivation_name_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        entries: &[AttrEntry],
    ) -> Result<String, TreeWalkError> {
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
            if key != NAME_ATTR {
                continue;
            }

            let value = self.force_value(attrs_id, attrs_span, entry.value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: attrs_id,
                        expected: "string",
                        actual: value.tag(),
                    },
                    attrs_span,
                ));
            }
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            if string.has_context() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed {
                        id: attrs_id,
                        op: "derivationStrict",
                    },
                    attrs_span,
                ));
            }
            let bytes = Self::copy_bytes_for_node(attrs_id, attrs_span, string.bytes())?;
            let name = Self::derivation_utf8_string(id, span, "derivation name", &bytes)?;
            Self::validate_derivation_strict_name(id, span, &name)?;
            return Ok(name);
        }

        Err(self.missing_derivation_strict_attr(id, span, NAME_ATTR))
    }

    pub(super) fn validate_derivation_strict_name(
        id: IrId,
        span: Span,
        name: &str,
    ) -> Result<(), TreeWalkError> {
        if let Some(reason) = Self::derivation_strict_name_error_reason(name) {
            return Err(Self::invalid_derivation_strict_name_error(id, span, reason));
        }

        Ok(())
    }

    pub(super) fn derivation_strict_name_error_reason(name: &str) -> Option<String> {
        if name.is_empty() {
            return Some("name must not be empty".to_owned());
        }
        if name.len() > DERIVATION_NAME_MAX_LEN {
            return Some(format!(
                "name '{name}' must be no longer than {DERIVATION_NAME_MAX_LEN} characters"
            ));
        }
        if name == "." || name == ".." {
            return Some(format!("name '{name}' is not valid"));
        }
        if name.starts_with(".-") {
            return Some(format!(
                "name '{name}' is not valid: first dash-separated component must not be '.'"
            ));
        }
        if name.starts_with("..-") {
            return Some(format!(
                "name '{name}' is not valid: first dash-separated component must not be '..'"
            ));
        }
        for character in name.chars() {
            if !Self::is_derivation_name_char(character) {
                return Some(format!(
                    "name '{name}' contains illegal character '{}'",
                    character
                ));
            }
        }

        None
    }

    pub(super) fn is_derivation_name_char(character: char) -> bool {
        character.is_ascii() && Self::is_derivation_name_byte(character as u8)
    }

    pub(super) fn is_derivation_name_byte(byte: u8) -> bool {
        matches!(
            byte,
            b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'+'
                | b'-'
                | b'.'
                | b'_'
                | b'?'
                | b'='
        )
    }

    pub(super) fn validate_derivation_strict_name_suffix(
        id: IrId,
        span: Span,
        name: &str,
    ) -> Result<(), TreeWalkError> {
        if name.ends_with(DERIVATION_EXTENSION) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!(
                        "derivation names are allowed to end in '{DERIVATION_EXTENSION}' only if they produce a single derivation file"
                    ),
                },
                span,
            ));
        }

        Ok(())
    }

    pub(super) fn invalid_derivation_strict_name_error(
        id: IrId,
        span: Span,
        reason: String,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::DerivationStrict {
                id,
                message: format!(
                    "invalid derivation name: {reason}. Please pass a different 'name'."
                ),
            },
            span,
        )
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
