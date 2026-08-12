//! Path-builtin evaluation: reads, filtering, and source-path fetching.

use super::*;

impl TreeWalk {
    pub(super) fn context_from_reflected_attrs(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<StringContext, TreeWalkError> {
        let path_key = self.intern_builtin_attr_symbol(id, b"path", span)?;
        let all_outputs_key = self.intern_builtin_attr_symbol(id, b"allOutputs", span)?;
        let outputs_key = self.intern_builtin_attr_symbol(id, b"outputs", span)?;
        let reflected_entries = {
            let attrs = self.heap.get_attrs_view(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
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
            for entry in attrs.iter_source_order() {
                let path = self.symbols.resolve(entry.key).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id,
                            symbol: entry.key,
                        },
                        span,
                    )
                })?;
                entries.push((Self::copy_bytes_for_node(id, span, path)?, entry.value));
            }
            entries
        };

        let mut elements = Vec::new();
        for (path, entry_value) in reflected_entries {
            if !is_valid_store_path(&path, self.options.store_dir()) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextKeyNotStorePath {
                        id,
                        path: path.clone(),
                    },
                    span,
                ));
            }
            let entry_value = self.force_value(id, span, entry_value)?;
            let entry_value = self.force_lazy_foldl_initial_value(id, span, entry_value)?;
            if entry_value.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: entry_value.tag(),
                    },
                    span,
                ));
            }
            let (path_marker, all_outputs_marker, outputs_marker) = {
                let attrs = self.heap.get_attrs_view(entry_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                (
                    attrs.get(path_key),
                    attrs.get(all_outputs_key),
                    attrs.get(outputs_key),
                )
            };

            if let Some(marker) = path_marker {
                let marker = self.force_value(id, span, marker)?;
                if self.expect_bool(id, marker, span)? {
                    elements.push(ContextElement::opaque_path(path.clone()).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                    })?);
                }
            }
            if let Some(marker) = all_outputs_marker {
                let marker = self.force_value(id, span, marker)?;
                if self.expect_bool(id, marker, span)? {
                    if !path.ends_with(b".drv") {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::StringContextPathNotDerivation {
                                id,
                                path: path.clone(),
                            },
                            span,
                        ));
                    }
                    elements.push(ContextElement::deep_derivation(path.clone()).map_err(
                        |source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span),
                    )?);
                }
            }
            if let Some(marker) = outputs_marker {
                let marker = self.force_value(id, span, marker)?;
                if marker.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "list",
                            actual: marker.tag(),
                        },
                        span,
                    ));
                }
                let outputs = {
                    let list = self.heap.get_list_view(marker).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    let mut outputs = Vec::new();
                    outputs.try_reserve_exact(list.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: list.len(),
                            },
                            span,
                        )
                    })?;
                    outputs.extend(list.iter());
                    outputs
                };
                if !outputs.is_empty() && !path.ends_with(b".drv") {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::StringContextPathNotDerivation {
                            id,
                            path: path.clone(),
                        },
                        span,
                    ));
                }
                for output in outputs {
                    let output = self.force_value(id, span, output)?;
                    let output =
                        self.context_free_string_bytes(id, span, output, "appendContext")?;
                    elements.push(ContextElement::single_output(path.clone(), output).map_err(
                        |source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span),
                    )?);
                }
            }
        }
        Ok(StringContext::new(elements))
    }

    pub(super) fn eval_get_env_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let name = self.context_free_string_bytes(argument, argument_span, value, "getEnv")?;
        if self.options.eval_mode() == EvalMode::Pure {
            return self.alloc_static_string(id, span, b"");
        }
        let observed = self.options.env_var(&name);
        let env_value = observed.unwrap_or_default().to_vec();
        self.record_impure_input_result(ImpureInputFingerprint::get_env(&name, observed));
        self.alloc_static_string(id, span, &env_value)
    }

    pub(super) fn eval_path_exists_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let must_be_dir = self.path_exists_requires_directory(argument, argument_span, value)?;
        let (path, is_text_store) = self.coerce_to_filesystem_or_text_store_path_bytes(
            argument,
            argument_span,
            value,
            "pathExists",
        )?;
        if is_text_store {
            return Ok(Value::bool(true));
        }
        let metadata = if must_be_dir {
            fs::metadata(Path::new(OsStr::from_bytes(&path)))
        } else {
            fs::symlink_metadata(Path::new(OsStr::from_bytes(
                path_without_trailing_path_markers(&path),
            )))
        };
        let exists = match metadata {
            Ok(metadata) => Ok(!must_be_dir || metadata.is_dir()),
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(false)
            }
            Err(source) => Err(TreeWalkError::new(
                TreeWalkErrorKind::PathStat {
                    id: argument,
                    path: path.clone(),
                    message: source.to_string(),
                },
                argument_span,
            )),
        }?;
        let mode = if must_be_dir {
            ImpureInputMode::RequireDirectory
        } else {
            ImpureInputMode::Default
        };
        self.record_impure_input_result(ImpureInputFingerprint::path_exists_with_mode(
            &path, mode, exists,
        ));
        Ok(Value::bool(exists))
    }

    pub(super) fn path_exists_requires_directory(
        &self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Ok(false);
        }
        let string = self.heap.get_string_view(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(path_exists_requires_directory(string.bytes()))
    }

    pub(super) fn eval_read_dir_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let path =
            self.coerce_to_filesystem_path_bytes(argument, argument_span, value, "readDir")?;
        self.check_filesystem_path_access(argument, argument_span, &path)?;
        let entries = fs::read_dir(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::DirectoryRead {
                    id: argument,
                    path: path.clone(),
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        let mut attrs = Vec::new();
        let mut trace_entries = Vec::new();
        let mut trace_entries_complete = self.impure_input_trace_complete;
        // RFC-0007 S6: when the speculation producer is running, collect this
        // directory's `.nix` entry names so its importable modules can be
        // speculatively parsed. Seeded only after the impure fingerprint below.
        let collect_speculation = self
            .shared
            .as_ref()
            .is_some_and(|shared| shared.speculation_frontier.is_some());
        let mut speculation_seeds: Vec<Vec<u8>> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DirectoryRead {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
            let file_name = entry.file_name();
            let name = file_name.as_bytes();
            if collect_speculation && name.ends_with(b".nix") {
                speculation_seeds.push(name.to_vec());
            }
            let trace_name = if trace_entries_complete {
                let mut trace_name = Vec::new();
                if trace_name.try_reserve_exact(name.len()).is_ok() {
                    trace_name.extend_from_slice(name);
                    Some(trace_name)
                } else {
                    trace_entries_complete = false;
                    None
                }
            } else {
                None
            };
            let symbol = self.intern_symbol_for_eval(name).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SymbolIntern {
                        id,
                        source: source.kind().clone(),
                    },
                    span,
                )
            })?;
            let file_type = entry.file_type().map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DirectoryRead {
                        id: argument,
                        path: entry.path().as_os_str().as_bytes().to_vec(),
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
            if let Some(trace_name) = trace_name {
                if trace_entries.try_reserve_exact(1).is_ok() {
                    trace_entries.push((trace_name, Self::file_type_for_impure_input(file_type)));
                } else {
                    trace_entries_complete = false;
                }
            }
            let value = self.alloc_static_string(id, span, file_type_name(file_type))?;
            attrs.push(AttrEntry::new(symbol, value));
        }
        // `readDir` is generated data, so it has no source order to preserve.
        // Canonicalizing here makes replayable attrset payloads deterministic.
        attrs.sort_unstable_by(|left, right| {
            let left_name = self.symbols.resolve(left.key).unwrap_or(&[]);
            let right_name = self.symbols.resolve(right.key).unwrap_or(&[]);
            left_name
                .cmp(right_name)
                .then_with(|| left.key.cmp(&right.key))
        });
        let attrs = FlatAttrs::new(attrs, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        if trace_entries_complete {
            self.record_impure_input_result(ImpureInputFingerprint::read_dir(
                &path,
                trace_entries
                    .iter()
                    .map(|(name, file_type)| DirEntryInput::new(name.as_slice(), *file_type)),
            ));
        } else {
            self.mark_impure_input_trace_incomplete();
        }
        // Seed speculation only after the impure fingerprint is recorded, so the
        // prefetch rides the listing the eval actually obtained (RFC-0007 S6).
        if collect_speculation {
            if let Some(shared) = self.shared.as_ref() {
                super::speculation::seed_read_dir_entries(&path, &speculation_seeds, shared);
            }
        }
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_read_file_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let (path, is_text_store) = self.coerce_to_filesystem_or_text_store_path_bytes(
            argument,
            argument_span,
            value,
            "readFile",
        )?;
        if is_text_store {
            let entry = self.text_store.get(&path).cloned().ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FileRead {
                        id: argument,
                        path: path.clone(),
                        message: "text store path is missing".to_owned(),
                    },
                    argument_span,
                )
            })?;
            if entry.contents.contains(&0) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::FileReadContainsNul { id: argument, path },
                    argument_span,
                ));
            }
            return self.alloc_tree_walk_string(
                id,
                span,
                NixString::new(entry.contents, entry.references),
            );
        }
        let contents = fs::read(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FileRead {
                    id: argument,
                    path: path.clone(),
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        if contents.contains(&0) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FileReadContainsNul { id: argument, path },
                argument_span,
            ));
        }
        self.record_impure_input_result(ImpureInputFingerprint::read_file(&path, &contents));
        // C++ Nix `prim_readFile` returns the content with string-context for the
        // store paths referenced *in that content* (a syntactic scan). Match it so
        // e.g. `readFile "${cc}/nix-support/dynamic-linker"` carries the glibc
        // reference, which derivations built from it then record as an input
        // source. Without this the read string is context-free and such inputs
        // are dropped, diverging from C++ Nix.
        let context = self.read_file_content_context(id, span, &contents)?;
        self.alloc_tree_walk_string(id, span, NixString::new(contents, context))
    }

    /// Builds the string-context for a `builtins.readFile` result.
    ///
    /// Matches C++ Nix `prim_readFile`: the result string carries an
    /// [`ContextKind::OpaquePath`] element for every distinct store path that
    /// appears in the file content, located by a syntactic scan for
    /// `<store_dir>/<hash>-<name>` references.
    fn read_file_content_context(
        &self,
        id: IrId,
        span: Span,
        content: &[u8],
    ) -> Result<StringContext, TreeWalkError> {
        let store_dir = self.options.store_dir();
        if store_dir.is_empty() {
            return Ok(StringContext::new(Vec::new()));
        }
        let mut elements: Vec<ContextElement> = Vec::new();
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut index = 0;
        while index + store_dir.len() <= content.len() {
            if content[index..].starts_with(store_dir)
                && let Some(root) = store_path_root(&content[index..], store_dir)
            {
                let consumed = root.len();
                let root = root.to_vec();
                if seen.insert(root.clone()) {
                    let element = ContextElement::opaque_path(root).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                    })?;
                    elements.push(element);
                }
                index += consumed;
                continue;
            }
            index += 1;
        }
        Ok(StringContext::new(elements))
    }

    pub(super) fn eval_read_file_type_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let (path, is_text_store) = self.coerce_to_filesystem_or_text_store_path_bytes(
            argument,
            argument_span,
            value,
            "readFileType",
        )?;
        if is_text_store {
            return self.alloc_static_string(id, span, b"regular");
        }
        let stat_path = path_without_trailing_path_markers(&path);
        let file_type =
            fs::symlink_metadata(Path::new(OsStr::from_bytes(stat_path))).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::PathStat {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
        let file_type = file_type.file_type();
        self.record_impure_input_result(ImpureInputFingerprint::read_file_type(
            &path,
            Self::file_type_for_impure_input(file_type),
        ));
        self.alloc_static_string(id, span, file_type_name(file_type))
    }

    pub(super) fn eval_path_primop(
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
                    expected: "set",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        self.validate_path_primop_attrs(argument, argument_span, value)?;

        let path_value =
            self.required_attr_value_by_name(argument, value, PATH_ATTR, argument_span)?;
        let path_value = self.force_value(argument, argument_span, path_value)?;
        let source_path = self.source_path_argument_bytes(argument, argument_span, path_value)?;

        let name = if let Some(name_value) =
            self.attr_value_by_name(argument, value, NAME_ATTR, argument_span)?
        {
            let name_value = self.force_value(argument, argument_span, name_value)?;
            self.context_free_string_bytes(argument, argument_span, name_value, "path")?
        } else {
            self.default_source_path_name(argument, argument_span, &source_path)?
        };
        let name = Self::source_path_store_name(argument, argument_span, &source_path, &name)?;

        let recursive = if let Some(recursive_value) =
            self.attr_value_by_name(argument, value, RECURSIVE_ATTR, argument_span)?
        {
            let recursive_value = self.force_value(argument, argument_span, recursive_value)?;
            self.expect_bool(argument, recursive_value, argument_span)?
        } else {
            true
        };

        let filter = if let Some(filter_value) =
            self.attr_value_by_name(argument, value, FILTER_ATTR, argument_span)?
        {
            let filter_value = self.force_demanded_value(argument, argument_span, filter_value)?;
            Some(SourcePathFilter {
                function: self.ensure_applicable_value(argument, argument_span, filter_value)?,
                id: argument,
                span: argument_span,
            })
        } else {
            None
        };

        let expected_sha256 = if let Some(hash_value) =
            self.attr_value_by_name(argument, value, SHA256_ATTR, argument_span)?
        {
            let hash_value = self.force_value(argument, argument_span, hash_value)?;
            let hash =
                self.context_free_string_bytes(argument, argument_span, hash_value, "path")?;
            let digest = self.decode_convert_hash(
                argument,
                argument_span,
                &hash,
                Some(HashStringAlgorithm::Sha256),
            )?;
            Some(digest.as_nix_sha256().ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::HashAlgorithmMismatch {
                        id: argument,
                        hash: hash.clone(),
                        expected: b"sha256".to_vec(),
                    },
                    argument_span,
                )
            })?)
        } else {
            None
        };

        let path = self.source_path_store_string_from_bytes(
            argument,
            argument_span,
            &source_path,
            name,
            recursive,
            expected_sha256,
            filter.as_ref(),
        )?;
        self.alloc_tree_walk_string(id, span, path)
    }

    pub(super) fn eval_filter_source_primop(
        &mut self,
        id: IrId,
        span: Span,
        filter_id: IrId,
        filter_span: Span,
        filter_value: Value,
        path_id: IrId,
        path_span: Span,
        path_value: Value,
    ) -> Result<Value, TreeWalkError> {
        let source_path = self.source_path_argument_bytes(path_id, path_span, path_value)?;
        let name = self.default_source_path_name(path_id, path_span, &source_path)?;
        let name = Self::source_path_store_name(path_id, path_span, &source_path, &name)?;
        let filter_value = self.force_demanded_value(filter_id, filter_span, filter_value)?;
        let filter = SourcePathFilter {
            function: self.ensure_applicable_value(filter_id, filter_span, filter_value)?,
            id: filter_id,
            span: filter_span,
        };
        let path = self.source_path_store_string_from_bytes(
            path_id,
            path_span,
            &source_path,
            name,
            true,
            None,
            Some(&filter),
        )?;
        self.alloc_tree_walk_string(id, span, path)
    }

    pub(super) fn eval_fetchurl_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let args = self.fetchurl_arguments(argument, argument_span, value)?;
        if self.options.eval_mode() == EvalMode::Pure && args.expected_sha256.is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchUrlHashRequired {
                    id: argument,
                    url: args.url,
                    mode: EvalMode::Pure,
                },
                argument_span,
            ));
        }

        let parsed = Self::parse_fetchurl_url(argument, argument_span, &args.url)?;
        self.check_fetchurl_access(argument, argument_span, &args.url, &parsed)?;

        let expected_path = if let Some(expected) = args.expected_sha256 {
            let path = self.fetchurl_store_path_from_digest(
                argument,
                argument_span,
                &args.url,
                &args.name,
                expected,
            )?;
            if self.fetchurl_can_reuse_store_path(
                argument,
                argument_span,
                &args.url,
                &parsed,
                &path,
            )? {
                return self.alloc_fetcher_result_path_value(id, span, path);
            }
            Some(path)
        } else {
            None
        };

        let contents = self.fetchurl_bytes(argument, argument_span, &args.url, &parsed)?;
        let digest = Self::nix_sha256_digest(&contents);
        if let Some(expected) = args.expected_sha256
            && expected != digest
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchUrlHashMismatch {
                    id: argument,
                    url: args.url,
                    expected: expected.as_bytes().to_vec(),
                    actual: digest.as_bytes().to_vec(),
                },
                argument_span,
            ));
        }

        let path = match expected_path {
            Some(path) => path,
            None => self.fetchurl_store_path_from_digest(
                argument,
                argument_span,
                &args.url,
                &args.name,
                digest,
            )?,
        };
        let entry = TextStoreEntry {
            contents,
            references: StringContext::empty(),
        };
        self.publish_text_store_entry(&path, &entry);
        self.text_store.insert(path.clone(), entry);
        self.alloc_fetcher_result_path_value(id, span, path)
    }

    pub(super) fn eval_fetch_git_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let args = self.fetch_git_arguments(argument, argument_span, value)?;
        if self.options.eval_mode() == EvalMode::Pure && args.rev.is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchGitRevRequired {
                    id: argument,
                    url: args.url,
                    mode: EvalMode::Pure,
                },
                argument_span,
            ));
        }

        let canonical_uri = Self::fetch_git_canonical_uri(&args);
        self.check_fetch_git_access(argument, argument_span, &canonical_uri)?;

        let temp_dir = Self::fetch_git_temp_dir(argument, argument_span, &args.url)?;
        let checkout_dir = temp_dir.join("checkout");
        let exported_dir = temp_dir.join("exported");
        let result = self.eval_fetch_git_into_store(
            argument,
            argument_span,
            args,
            &checkout_dir,
            &exported_dir,
        );
        let _ = fs::remove_dir_all(&temp_dir);
        let result = result?;
        self.alloc_fetch_git_result(id, span, result)
    }

    pub(super) fn eval_fetch_mercurial_primop(
        &mut self,
        call: BuiltinCall,
        argument: IrId,
        argument_span: Span,
        value: Option<Value>,
    ) -> Result<Value, TreeWalkError> {
        let value = match value {
            Some(value) => value,
            None => self.eval_node(argument)?,
        };
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let args = self.fetch_mercurial_arguments(argument, argument_span, value)?;
        if self.options.eval_mode() == EvalMode::Pure && args.rev.is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchMercurialRevRequired {
                    id: argument,
                    url: args.url,
                    mode: EvalMode::Pure,
                },
                argument_span,
            ));
        }

        unsupported_primop(call)
    }

    pub(super) fn fetch_mercurial_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchMercurialArguments, TreeWalkError> {
        if value.tag() == ValueTag::String {
            let url = self.context_free_string_bytes(id, span, value, "fetchMercurial")?;
            return Ok(FetchMercurialArguments { url, rev: None });
        }
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "set or string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        self.validate_fetch_mercurial_attrs(id, span, value)?;

        let url_value = self.required_attr_value_by_name(id, value, URL_ATTR, span)?;
        let url_value = self.force_value(id, span, url_value)?;
        let url = self.context_free_string_bytes(id, span, url_value, "fetchMercurial")?;

        if let Some(name_value) = self.attr_value_by_name(id, value, NAME_ATTR, span)? {
            let name_value = self.force_value(id, span, name_value)?;
            let _ = self.context_free_string_bytes(id, span, name_value, "fetchMercurial")?;
        }

        let rev = if let Some(rev_value) = self.attr_value_by_name(id, value, REV_ATTR, span)? {
            let rev_value = self.force_value(id, span, rev_value)?;
            Some(self.context_free_string_bytes(id, span, rev_value, "fetchMercurial")?)
        } else {
            None
        };

        Ok(FetchMercurialArguments { url, rev })
    }

    pub(super) fn validate_fetch_mercurial_attrs(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let attrs = self
            .heap
            .get_attrs_view(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        for entry in attrs.iter_lexicographic() {
            let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id,
                        symbol: entry.key,
                    },
                    span,
                )
            })?;
            if !matches!(key, URL_ATTR | NAME_ATTR | REV_ATTR) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedFetchMercurialAttr {
                        id,
                        attr: key.to_vec(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }
}
