//! Value-to-string coercion, path resolution, and Nix search-path lookups.

use super::*;

impl TreeWalk {
    pub(super) fn derivation_output_placeholder(
        id: IrId,
        span: Span,
        output_name: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let input_len = PLACEHOLDER_HASH_PREFIX
            .len()
            .checked_add(output_name.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut input = Vec::new();
        input.try_reserve_exact(input_len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed { id, len: input_len },
                span,
            )
        })?;
        input.extend_from_slice(PLACEHOLDER_HASH_PREFIX);
        input.extend_from_slice(output_name);
        Self::slash_prefixed_nix_base32_sha256(id, span, &input)
    }

    pub(super) fn downstream_output_placeholder(
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        output_name: &str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let drv_name: &str = drv_path.name().as_ref();
        let base_name = drv_name.strip_suffix(".drv").ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!("derivation path name {drv_name:?} does not end in .drv"),
                },
                span,
            )
        })?;
        let output_path_name = if output_name == "out" {
            base_name.to_owned()
        } else {
            format!("{base_name}-{output_name}")
        };
        let drv_hash = Self::encode_nix_base32(id, span, drv_path.digest())?;
        let input_len = UPSTREAM_OUTPUT_PLACEHOLDER_HASH_PREFIX
            .len()
            .checked_add(drv_hash.len())
            .and_then(|len| len.checked_add(1))
            .and_then(|len| len.checked_add(output_path_name.len()))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut input = Vec::new();
        input.try_reserve_exact(input_len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed { id, len: input_len },
                span,
            )
        })?;
        input.extend_from_slice(UPSTREAM_OUTPUT_PLACEHOLDER_HASH_PREFIX);
        input.extend_from_slice(&drv_hash);
        input.push(b':');
        input.extend_from_slice(output_path_name.as_bytes());
        Self::slash_prefixed_nix_base32_sha256(id, span, &input)
    }

    pub(super) fn slash_prefixed_nix_base32_sha256(
        id: IrId,
        span: Span,
        input: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let digest = Self::nix_sha256_digest(input);
        Self::slash_prefixed_nix_base32_sha256_digest(id, span, digest)
    }

    pub(super) fn slash_prefixed_nix_base32_sha256_digest(
        id: IrId,
        span: Span,
        digest: NixSha256Digest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let encoded = Self::encode_nix_base32(id, span, digest.as_bytes())?;
        let len = encoded.len().checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        bytes.push(b'/');
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    pub(super) fn eval_if(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "if payload"));
        };
        let selected = if self.eval_bool_node(first)? {
            second
        } else {
            third
        };
        self.eval_node(selected)
    }

    pub(super) fn eval_assert(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair { first, second } = node.data else {
            return Err(self.invalid_payload(id, node, "assert payload"));
        };
        if self.eval_bool_node(first)? {
            self.eval_node(second)
        } else {
            Err(TreeWalkError::new(
                TreeWalkErrorKind::AssertionFailed { id },
                node.span,
            ))
        }
    }

    pub(super) fn eval_unary(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Unary { op, operand } = node.data else {
            return Err(self.invalid_payload(id, node, "unary payload"));
        };
        match op {
            UnaryOpKind::Not => Ok(Value::bool(!self.eval_bool_node(operand)?)),
            UnaryOpKind::Neg => self.eval_numeric_negation(id, node, operand),
        }
    }

    pub(super) fn eval_binary(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Binary { op, lhs, rhs } = node.data else {
            return Err(self.invalid_payload(id, node, "binary payload"));
        };
        match op {
            BinOpKind::And => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                } else {
                    Ok(Value::bool(false))
                }
            }
            BinOpKind::Or => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(true))
                } else {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                }
            }
            BinOpKind::Impl => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                } else {
                    Ok(Value::bool(true))
                }
            }
            BinOpKind::Add => self.eval_add(id, node, lhs, rhs),
            BinOpKind::Sub => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Sub, lhs, rhs),
            BinOpKind::Mul => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Mul, lhs, rhs),
            BinOpKind::Div => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Div, lhs, rhs),
            BinOpKind::Lt => self.eval_comparison(id, node, ComparisonOp::Lt, lhs, rhs),
            BinOpKind::Gt => self.eval_comparison(id, node, ComparisonOp::Gt, lhs, rhs),
            BinOpKind::Le => self.eval_comparison(id, node, ComparisonOp::Le, lhs, rhs),
            BinOpKind::Ge => self.eval_comparison(id, node, ComparisonOp::Ge, lhs, rhs),
            BinOpKind::Eq => self.eval_equality(id, node, lhs, rhs, false),
            BinOpKind::Ne => self.eval_equality(id, node, lhs, rhs, true),
            BinOpKind::Concat => self.eval_list_concat(id, node, lhs, rhs),
            BinOpKind::Update => self.eval_attr_update(id, node, lhs, rhs),
            BinOpKind::PipeRight => self.eval_apply_expression(id, node.span, rhs, lhs),
            BinOpKind::PipeLeft => self.eval_apply_expression(id, node.span, lhs, rhs),
        }
    }

    pub(super) fn eval_string(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "string symbol payload"));
        };
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                node.span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.alloc_tree_walk_string(id, node.span, NixString::from_bytes(owned))
    }

    pub(super) fn eval_path(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "path symbol payload"));
        };
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let path = self.path_literal_bytes_for_node(id, node.span, bytes)?;
        self.alloc_tree_walk_path(id, node.span, NixString::from_bytes(path))
    }

    pub(super) fn eval_search_path(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        if self.options.reject_ambient_search_path() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedAmbientSearchPath {
                    id,
                    feature: "configured Nix search path lookup",
                },
                node.span,
            ));
        }
        let IrData::SearchPath {
            literal,
            search_path,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "search-path symbol payload"));
        };
        let lookup = self.symbols.resolve(literal).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id,
                    symbol: literal,
                },
                node.span,
            )
        })?;
        let lookup = Self::copy_bytes_for_node(id, node.span, lookup)?;
        let lookup = search_path_literal_lookup(id, node.span, &lookup)?;
        let (entries, origin) = if let Some(search_path) = search_path {
            let value = self.eval_node(search_path)?;
            (
                self.search_path_entries_from_value(search_path, node.span, value)?,
                FindFileLookupOrigin::LexicalSearchPath,
            )
        } else {
            (
                self.visible_nix_path()
                    .iter()
                    .map(|entry| ResolvedSearchPathEntry {
                        prefix: entry.prefix().to_vec(),
                        path: entry.path().to_vec(),
                    })
                    .collect::<Vec<_>>(),
                FindFileLookupOrigin::AmbientSearchPath,
            )
        };
        self.find_file_in_entries(id, node.span, &entries, lookup, origin)
    }

    pub(super) fn eval_nix_path_value(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if self.options.reject_ambient_search_path() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedAmbientSearchPath {
                    id,
                    feature: "builtins.nixPath",
                },
                span,
            ));
        }
        let entries = self.visible_nix_path().to_vec();
        let mut values = Vec::new();
        let value_capacity = entries.len().checked_add(2).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: entries.len(),
                },
                span,
            )
        })?;
        values.try_reserve_exact(value_capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: value_capacity,
                },
                span,
            )
        })?;
        let path_key = self.intern_builtin_attr_symbol(id, PATH_ATTR, span)?;
        let prefix_key = self.intern_builtin_attr_symbol(id, PREFIX_ATTR, span)?;

        for entry in entries {
            let path =
                self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                    eval.alloc_static_string(id, span, entry.path())
                })?;
            let entry_root_start = values.len();
            values.push(path);
            let prefix =
                self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                    eval.alloc_static_string(id, span, entry.prefix())
                })?;
            let path = values[entry_root_start];
            values.truncate(entry_root_start);
            let attrs = FlatAttrs::new(
                vec![
                    AttrEntry::new(path_key, path),
                    AttrEntry::new(prefix_key, prefix),
                ],
                &self.symbols,
            )
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
            let entry_root_start = values.len();
            values.push(path);
            values.push(prefix);
            let attrs =
                self.with_transient_value_stack_roots(id, span, values.as_mut_slice(), |eval| {
                    eval.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
                })?;
            values.truncate(entry_root_start);
            values.push(attrs);
        }

        self.alloc_tree_walk_list(id, span, NixList::new(values))
    }

    pub(super) fn eval_find_file_primop(
        &mut self,
        id: IrId,
        span: Span,
        search_path_id: IrId,
        search_path_span: Span,
        search_path: Value,
        lookup_id: IrId,
        lookup_span: Span,
        lookup: Value,
    ) -> Result<Value, TreeWalkError> {
        let entries =
            self.search_path_entries_from_value(search_path_id, search_path_span, search_path)?;
        let lookup = self.context_free_string_bytes(lookup_id, lookup_span, lookup, "findFile")?;
        self.find_file_in_entries(
            id,
            span,
            &entries,
            &lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
    }

    pub(super) fn search_path_entries_from_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<ResolvedSearchPathEntry>, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "list",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let list = self
            .heap
            .get_list(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let elements = Self::clone_list_elements(id, span, list)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let element = self.force_value(id, span, element)?;
            let element = self.force_lazy_foldl_initial_value(id, span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    span,
                ));
            }
            let path = self.required_attr_value_by_name(id, element, PATH_ATTR, span)?;
            let path = self.force_value(id, span, path)?;
            let path = self.coerce_to_search_path_bytes(id, span, path, "findFile")?;
            let prefix =
                if let Some(prefix) = self.attr_value_by_name(id, element, PREFIX_ATTR, span)? {
                    let prefix = self.force_value(id, span, prefix)?;
                    self.context_free_string_bytes(id, span, prefix, "findFile")?
                } else {
                    Vec::new()
                };
            entries.push(ResolvedSearchPathEntry { prefix, path });
        }
        Ok(entries)
    }

    pub(super) fn coerce_to_search_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if value.tag() == ValueTag::Path {
            let path = self.clone_path_value(id, span, value)?;
            return Self::copy_bytes_for_node(id, span, path.bytes());
        }
        let string = self.coerce_to_string(id, value, span)?;
        self.context_free_string_bytes(id, span, string, op)
    }

    pub(super) fn find_file_in_entries(
        &mut self,
        id: IrId,
        span: Span,
        entries: &[ResolvedSearchPathEntry],
        lookup: &[u8],
        origin: FindFileLookupOrigin,
    ) -> Result<Value, TreeWalkError> {
        let cache_key = FindFileCacheKey::new(
            self.options.search_path_base(),
            self.options.corepkgs_path(),
            entries,
            lookup,
            origin,
        );
        if let Some(cached) = self.find_file_cache.get(&cache_key).cloned() {
            self.find_file_cache_hits = self.find_file_cache_hits.saturating_add(1);
            return self.find_file_cached_result(id, span, cached, lookup, origin);
        }
        self.find_file_cache_misses = self.find_file_cache_misses.saturating_add(1);
        let mut trace = Vec::new();
        let mut trace_cacheable = true;

        for entry in entries {
            let Some(suffix) = search_path_suffix(entry.prefix.as_slice(), lookup) else {
                continue;
            };
            let candidate = join_search_path(
                id,
                span,
                self.options.search_path_base(),
                entry.path.as_slice(),
                suffix,
            )?;
            self.check_find_file_candidate_access(id, span, &candidate, origin)?;
            match fs::metadata(Path::new(OsStr::from_bytes(&candidate))) {
                Ok(_) => {
                    trace_cacheable &=
                        self.record_find_file_candidate_probe(&mut trace, &candidate, true);
                    if trace_cacheable {
                        self.find_file_cache.insert(
                            cache_key,
                            FindFileCacheEntry::Hit {
                                path: candidate.clone(),
                                trace,
                            },
                        );
                    }
                    return self.alloc_find_file_path(id, span, candidate);
                }
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    trace_cacheable &=
                        self.record_find_file_candidate_probe(&mut trace, &candidate, false);
                    continue;
                }
                Err(source) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::PathStat {
                            id,
                            path: candidate,
                            message: source.to_string(),
                        },
                        span,
                    ));
                }
            }
        }
        if matches!(
            origin,
            FindFileLookupOrigin::AmbientSearchPath | FindFileLookupOrigin::LexicalSearchPath
        ) && let Some(corepkgs_path) = self.options.corepkgs_path()
            && let Some(suffix) = search_path_suffix(b"nix", lookup)
        {
            let candidate = join_search_path(id, span, b"/", corepkgs_path, suffix)?;
            self.check_find_file_candidate_access(id, span, &candidate, origin)?;
            match fs::metadata(Path::new(OsStr::from_bytes(&candidate))) {
                Ok(_) => {
                    trace_cacheable &=
                        self.record_find_file_candidate_probe(&mut trace, &candidate, true);
                    if trace_cacheable {
                        self.find_file_cache.insert(
                            cache_key,
                            FindFileCacheEntry::Hit {
                                path: candidate.clone(),
                                trace,
                            },
                        );
                    }
                    return self.alloc_find_file_path(id, span, candidate);
                }
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    trace_cacheable &=
                        self.record_find_file_candidate_probe(&mut trace, &candidate, false);
                }
                Err(source) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::PathStat {
                            id,
                            path: candidate,
                            message: source.to_string(),
                        },
                        span,
                    ));
                }
            }
        }
        if trace_cacheable {
            self.find_file_cache
                .insert(cache_key, FindFileCacheEntry::Miss { trace });
        }
        self.find_file_not_found(id, span, lookup, origin)
    }

    fn record_find_file_candidate_probe(
        &mut self,
        trace: &mut Vec<ImpureInputFingerprint>,
        candidate: &[u8],
        exists: bool,
    ) -> bool {
        let fingerprint = match ImpureInputFingerprint::path_exists_with_mode(
            candidate,
            ImpureInputMode::FindFileCandidate,
            exists,
        ) {
            Ok(fingerprint) => fingerprint,
            Err(_) => {
                self.mark_impure_input_trace_incomplete();
                return false;
            }
        };
        if trace.try_reserve_exact(1).is_err() {
            self.mark_impure_input_trace_incomplete();
            return false;
        }
        trace.push(fingerprint.clone());
        self.record_impure_input(fingerprint);
        true
    }

    pub(super) fn check_find_file_candidate_access(
        &self,
        id: IrId,
        span: Span,
        candidate: &[u8],
        origin: FindFileLookupOrigin,
    ) -> Result<(), TreeWalkError> {
        match (origin, self.options.eval_mode()) {
            (FindFileLookupOrigin::ExplicitSearchPath, EvalMode::Pure) => Ok(()),
            _ => self.check_filesystem_path_access(id, span, candidate),
        }
    }

    pub(super) fn find_file_cached_result(
        &mut self,
        id: IrId,
        span: Span,
        cached: FindFileCacheEntry,
        lookup: &[u8],
        origin: FindFileLookupOrigin,
    ) -> Result<Value, TreeWalkError> {
        match cached {
            FindFileCacheEntry::Hit { path, trace } => {
                for fingerprint in trace {
                    self.record_impure_input(fingerprint);
                }
                self.alloc_find_file_path(id, span, path)
            }
            FindFileCacheEntry::Miss { trace } => {
                for fingerprint in trace {
                    self.record_impure_input(fingerprint);
                }
                self.find_file_not_found(id, span, lookup, origin)
            }
        }
    }

    pub(super) fn alloc_find_file_path(
        &mut self,
        id: IrId,
        span: Span,
        path: Vec<u8>,
    ) -> Result<Value, TreeWalkError> {
        self.alloc_tree_walk_path(id, span, NixString::from_bytes(path))
    }

    pub(super) fn find_file_not_found(
        &self,
        id: IrId,
        span: Span,
        lookup: &[u8],
        origin: FindFileLookupOrigin,
    ) -> Result<Value, TreeWalkError> {
        Err(TreeWalkError::new(
            TreeWalkErrorKind::SearchPathNotFound {
                id,
                lookup: lookup.to_vec(),
                ambient: matches!(
                    origin,
                    FindFileLookupOrigin::AmbientSearchPath
                        | FindFileLookupOrigin::LexicalSearchPath
                ),
            },
            span,
        ))
    }

    pub(super) fn eval_interp(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        match node.data {
            IrData::Node(child) => {
                let span = self.node(child)?.span;
                let value = self.eval_node(child)?;
                self.coerce_to_interpolation_string(child, value, span)
            }
            IrData::Children(children) => {
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
                if self.interp_children_have_path_fragments(&children)? {
                    return self.eval_path_interp(id, node, &children);
                }
                let Some((first, rest)) = children.split_first() else {
                    return self.alloc_tree_walk_string(id, node.span, NixString::default());
                };
                let first_span = self.node(*first)?.span;
                let first_string = {
                    let value = self.eval_node(*first)?;
                    self.coerce_to_interpolation_string(*first, value, first_span)?
                };
                // Accumulate into a Rust-owned string. The running result is then
                // not a garbage-collectable heap value held across the per-child
                // `eval_node` (and its safepoints), and its byte buffer grows in
                // place instead of the pairwise `concat` re-copying the whole
                // prefix on every fragment. The result is byte-for-byte identical
                // to the left-associated `concat` fold it replaces.
                let mut accumulator = self.heap.get_string(first_string).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?.clone();
                for child in rest {
                    let child_span = self.node(*child)?.span;
                    let next = {
                        let value = self.eval_node(*child)?;
                        self.coerce_to_interpolation_string(*child, value, child_span)?
                    };
                    let next = self.heap.get_string(next).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                    })?;
                    accumulator.append_in_place(next).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::String { id, source }, node.span)
                    })?;
                }
                self.alloc_tree_walk_string(id, node.span, accumulator)
            }
            IrData::None => self.alloc_tree_walk_string(id, node.span, NixString::default()),
            IrData::Symbol(symbol) => {
                let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
                })?;
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ByteAllocationFailed {
                            id,
                            len: bytes.len(),
                        },
                        node.span,
                    )
                })?;
                owned.extend_from_slice(bytes);
                self.alloc_tree_walk_string(id, node.span, NixString::from_bytes(owned))
            }
            _ => Err(self.invalid_payload(id, node, "interpolation payload")),
        }
    }

    pub(super) fn interp_children_have_path_fragments(
        &self,
        children: &[IrId],
    ) -> Result<bool, TreeWalkError> {
        for child in children {
            if self.node(*child)?.kind == IrKind::Path {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn eval_path_interp(
        &mut self,
        id: IrId,
        node: &IrNode,
        children: &[IrId],
    ) -> Result<Value, TreeWalkError> {
        let mut bytes = Vec::new();
        for child in children {
            let child_node = *self.node(*child)?;
            if child_node.kind == IrKind::Path {
                let IrData::Symbol(symbol) = child_node.data else {
                    return Err(self.invalid_payload(*child, &child_node, "path symbol payload"));
                };
                let raw = self.symbols.resolve(symbol).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol { id: *child, symbol },
                        child_node.span,
                    )
                })?;
                let fragment = Self::copy_bytes_for_node(*child, child_node.span, raw)?;
                bytes.try_reserve_exact(fragment.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ByteAllocationFailed {
                            id,
                            len: bytes.len().saturating_add(fragment.len()),
                        },
                        node.span,
                    )
                })?;
                bytes.extend_from_slice(&fragment);
                continue;
            }

            let expression = if child_node.kind == IrKind::Interp {
                match child_node.data {
                    IrData::Node(expression) => expression,
                    _ => *child,
                }
            } else {
                *child
            };
            let expression_span = self.node(expression)?.span;
            let value = self.eval_node(expression)?;
            let value = self.force_demanded_value(expression, expression_span, value)?;
            let fragment =
                self.coerce_to_path_interpolation_fragment(expression, expression_span, value)?;
            bytes.try_reserve_exact(fragment.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: bytes.len().saturating_add(fragment.len()),
                    },
                    node.span,
                )
            })?;
            bytes.extend_from_slice(&fragment);
        }

        let path = self.path_literal_bytes_for_node(id, node.span, &bytes)?;
        self.alloc_tree_walk_path(id, node.span, NixString::from_bytes(path))
    }

    pub(super) fn coerce_to_path_interpolation_fragment(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if value.tag() == ValueTag::Path {
            let path = self.clone_path_value(id, span, value)?;
            return Self::copy_bytes_for_node(id, span, path.bytes());
        }

        let value = self.coerce_to_string(id, value, span)?;
        self.context_free_string_bytes(id, span, value, "path interpolation")
    }

    pub(super) fn coerce_to_interpolation_string(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        match value.tag() {
            ValueTag::String => Ok(value),
            ValueTag::Path => {
                let path = self.source_path_store_string(id, span, value)?;
                self.alloc_tree_walk_string(id, span, path)
            }
            ValueTag::Attrs => self.coerce_attrs_to_interpolation_string(id, value, span),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn coerce_attrs_to_interpolation_string(
        &mut self,
        id: IrId,
        attrs_value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if let Some(hook) = self.attr_value_by_name(id, attrs_value, TO_STRING_ATTR, span)? {
            let hook = self.force_value(id, span, hook)?;
            let value = self.apply_lambda_value(id, span, id, hook, span, id, attrs_value)?;
            return self.coerce_to_interpolation_string(id, value, span);
        }

        if let Some(out_path) = self.attr_value_by_name(id, attrs_value, OUT_PATH_ATTR, span)? {
            let value = self.force_value(id, span, out_path)?;
            return self.coerce_to_interpolation_string(id, value, span);
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::Type {
                id,
                expected: "string",
                actual: ValueTag::Attrs,
            },
            span,
        ))
    }

    pub(super) fn coerce_to_string(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        match value.tag() {
            ValueTag::String => Ok(value),
            ValueTag::Path => {
                let path = self.clone_path_value(id, span, value)?;
                self.alloc_tree_walk_string(id, span, path)
            }
            ValueTag::Attrs => self.coerce_attrs_to_string(id, value, span),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn coerce_attrs_to_string(
        &mut self,
        id: IrId,
        attrs_value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if let Some(hook) = self.attr_value_by_name(id, attrs_value, TO_STRING_ATTR, span)? {
            let hook = self.force_value(id, span, hook)?;
            let value = self.apply_lambda_value(id, span, id, hook, span, id, attrs_value)?;
            return self.coerce_to_string(id, value, span);
        }

        if let Some(out_path) = self.attr_value_by_name(id, attrs_value, OUT_PATH_ATTR, span)? {
            let value = self.force_value(id, span, out_path)?;
            return self.coerce_to_string(id, value, span);
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::Type {
                id,
                expected: "string",
                actual: ValueTag::Attrs,
            },
            span,
        ))
    }
}
