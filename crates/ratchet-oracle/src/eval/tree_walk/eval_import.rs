//! `fetchurl`/`import`/`fetchClosure` evaluation and import loading.

use super::*;

mod fetch_tarball;

impl TreeWalk {
    pub(super) fn fetchurl_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchUrlArguments, TreeWalkError> {
        if value.tag() == ValueTag::String {
            let url = self.context_free_string_bytes(id, span, value, "fetchurl")?;
            let name = self.fetchurl_default_store_name(id, span, &url)?;
            let name = Self::fetchurl_store_name(id, span, &url, &name)?.to_owned();
            return Ok(FetchUrlArguments {
                url,
                name,
                expected_sha256: None,
            });
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
        self.validate_fetchurl_attrs(id, span, value)?;

        let url_value = self.required_attr_value_by_name(id, value, URL_ATTR, span)?;
        let url_value = self.force_value(id, span, url_value)?;
        let url = self.context_free_string_bytes(id, span, url_value, "fetchurl")?;

        let name = if let Some(name_value) = self.attr_value_by_name(id, value, NAME_ATTR, span)? {
            let name_value = self.force_value(id, span, name_value)?;
            self.context_free_string_bytes(id, span, name_value, "fetchurl")?
        } else {
            self.fetchurl_default_store_name(id, span, &url)?
        };
        let name = Self::fetchurl_store_name(id, span, &url, &name)?.to_owned();

        let expected_sha256 = if let Some(hash_value) =
            self.attr_value_by_name(id, value, SHA256_ATTR, span)?
        {
            let hash_value = self.force_value(id, span, hash_value)?;
            let hash = self.context_free_string_bytes(id, span, hash_value, "fetchurl")?;
            if hash.is_empty() {
                self.emit_warning_output(id, span, EMPTY_FETCHURL_SHA256_WARNING.to_vec())?;
                Some(NixSha256Digest::from_bytes([0_u8; 32]))
            } else {
                let digest =
                    self.decode_convert_hash(id, span, &hash, Some(HashStringAlgorithm::Sha256))?;
                Some(digest.as_nix_sha256().ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::HashAlgorithmMismatch {
                            id,
                            hash: hash.clone(),
                            expected: b"sha256".to_vec(),
                        },
                        span,
                    )
                })?)
            }
        } else {
            None
        };

        Ok(FetchUrlArguments {
            url,
            name,
            expected_sha256,
        })
    }

    pub(super) fn validate_fetchurl_attrs(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let attrs = self
            .heap
            .get_attrs(value)
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
            if !matches!(key, URL_ATTR | NAME_ATTR | SHA256_ATTR) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedFetchUrlAttr {
                        id,
                        attr: key.to_vec(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn fetchurl_default_store_name(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut end = url.len();
        while end > 0 && url[end - 1] == b'/' {
            end -= 1;
        }
        let trimmed = &url[..end];
        let start = trimmed
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(0, |index| index.saturating_add(1));
        let name = &trimmed[start..];
        if name.is_empty() {
            return Ok(b"source".to_vec());
        }
        Self::copy_bytes_for_node(id, span, name)
    }

    pub(super) fn fetchurl_store_name<'a>(
        id: IrId,
        span: Span,
        url: &[u8],
        name: &'a [u8],
    ) -> Result<&'a str, TreeWalkError> {
        nix_compat::store_path::validate_name(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchUrlStoreName {
                    id,
                    url: url.to_vec(),
                    name: name.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn fetchurl_store_path_from_digest(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        name: &str,
        digest: NixSha256Digest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let fixed_digest = Self::flat_source_fixed_output_digest(id, span, digest)?;
        self.store_path_bytes_from_fingerprint_parts(
            id,
            span,
            url,
            b"output:out",
            name,
            fixed_digest,
        )
    }

    pub(super) fn alloc_fetcher_result_path_value(
        &mut self,
        id: IrId,
        span: Span,
        path: Vec<u8>,
    ) -> Result<Value, TreeWalkError> {
        let string = Self::fetchurl_path_string(id, span, path)?;
        self.alloc_tree_walk_string(id, span, string)
    }

    pub(super) fn alloc_fetcher_attrset_path_value(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        path: Vec<u8>,
    ) -> Result<Value, TreeWalkError> {
        let string = Self::fetchurl_path_string(id, span, path)?;
        self.alloc_tree_walk_string_with_attr_entry_roots(id, span, entries, string)
    }

    fn fetchurl_path_string(
        id: IrId,
        span: Span,
        path: Vec<u8>,
    ) -> Result<NixString, TreeWalkError> {
        let context = StringContext::singleton(ContextElement::opaque_path(path.clone()).map_err(
            |source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span),
        )?)
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(NixString::new(path, context))
    }

    pub(super) fn parse_fetchurl_url(
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<Url, TreeWalkError> {
        let url_text = std::str::from_utf8(url).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchUrl {
                    id,
                    url: url.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })?;
        Url::parse(url_text).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchUrl {
                    id,
                    url: url.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn fetchurl_can_reuse_store_path(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
        store_path: &[u8],
    ) -> Result<bool, TreeWalkError> {
        if self.text_store.contains_key(store_path) {
            return Ok(true);
        }
        if !Path::new(OsStr::from_bytes(store_path)).exists() {
            return Ok(false);
        }
        if parsed.scheme() != "file" {
            return Ok(true);
        }

        let source_path = Self::fetchurl_file_path(id, span, url, parsed)?;
        Ok(!source_path.exists())
    }

    pub(super) fn fetchurl_file_path(
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
    ) -> Result<PathBuf, TreeWalkError> {
        parsed.to_file_path().map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchUrl {
                    id,
                    url: url.to_vec(),
                    message: "file URL cannot be converted to a local path".to_owned(),
                },
                span,
            )
        })
    }

    pub(super) fn check_fetchurl_access(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
    ) -> Result<(), TreeWalkError> {
        match parsed.scheme() {
            "file" if self.options.eval_mode() == EvalMode::Restricted => {
                let path = Self::fetchurl_file_path(id, span, url, parsed)?;
                if !self.options.uri_is_allowed(url) {
                    self.check_filesystem_path_access(id, span, path.as_os_str().as_bytes())?;
                }
            }
            "http" | "https"
                if self.options.eval_mode() == EvalMode::Restricted
                    && !self.options.uri_is_allowed(url) =>
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::FetchUrlAccessDenied {
                        id,
                        url: url.to_vec(),
                        mode: EvalMode::Restricted,
                    },
                    span,
                ));
            }
            _ => {}
        }

        Ok(())
    }

    pub(super) fn fetchurl_bytes(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match parsed.scheme() {
            "file" => {
                let path = Self::fetchurl_file_path(id, span, url, parsed)?;
                let bytes = path.as_os_str().as_bytes();
                if self.options.eval_mode() == EvalMode::Restricted
                    && !self.options.uri_is_allowed(url)
                {
                    self.check_filesystem_path_access(id, span, bytes)?;
                }
                fs::read(&path).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::FetchUrl {
                            id,
                            url: url.to_vec(),
                            message: source.to_string(),
                        },
                        span,
                    )
                })
            }
            "http" | "https" => {
                let client = reqwest::blocking::Client::builder()
                    .no_gzip()
                    .no_brotli()
                    .no_zstd()
                    .no_deflate()
                    .build()
                    .map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::FetchUrl {
                                id,
                                url: url.to_vec(),
                                message: source.to_string(),
                            },
                            span,
                        )
                    })?;
                let response = client
                    .get(parsed.as_str())
                    .header(reqwest::header::ACCEPT_ENCODING, "identity")
                    .send()
                    .map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::FetchUrl {
                                id,
                                url: url.to_vec(),
                                message: source.to_string(),
                            },
                            span,
                        )
                    })?;
                let response = response.error_for_status().map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::FetchUrl {
                            id,
                            url: url.to_vec(),
                            message: source.to_string(),
                        },
                        span,
                    )
                })?;
                response
                    .bytes()
                    .map(|bytes| bytes.to_vec())
                    .map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::FetchUrl {
                                id,
                                url: url.to_vec(),
                                message: source.to_string(),
                            },
                            span,
                        )
                    })
            }
            scheme => Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchUrl {
                    id,
                    url: url.to_vec(),
                    message: format!("unsupported URL scheme {scheme:?}"),
                },
                span,
            )),
        }
    }

    pub(super) fn validate_path_primop_attrs(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let attrs = self
            .heap
            .get_attrs(value)
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
            if !matches!(
                key,
                PATH_ATTR | NAME_ATTR | FILTER_ATTR | RECURSIVE_ATTR | SHA256_ATTR
            ) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedSourcePathAttr {
                        id,
                        attr: key.to_vec(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn eval_to_file_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        name_span: Span,
        name_value: Value,
        contents_id: IrId,
        contents_span: Span,
        force_contents: impl FnOnce(&mut Self) -> Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        let name = self.context_free_string_bytes(name_id, name_span, name_value, "toFile")?;
        let contents_value = force_contents(self)?;
        if contents_value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: contents_id,
                    expected: "string",
                    actual: contents_value.tag(),
                },
                contents_span,
            ));
        }

        let (contents, references, reference_context) = {
            let string = self.heap.get_string(contents_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: contents_id,
                        source,
                    },
                    contents_span,
                )
            })?;
            let contents = Self::copy_bytes_for_node(contents_id, contents_span, string.bytes())?;
            let mut references = BTreeSet::new();
            for element in string.context() {
                if element.kind() != ContextKind::OpaquePath {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::ToFileDerivationReference {
                            id: contents_id,
                            name: name.clone(),
                            reference: element.path().to_vec(),
                            kind: element.kind(),
                            output: element.output().map(Vec::from),
                        },
                        contents_span,
                    ));
                }
                let reference = self.store_path_absolute_bytes(&self.context_store_path(
                    contents_id,
                    contents_span,
                    element.path(),
                )?);
                references.insert(reference);
            }
            let reference_context =
                string
                    .context()
                    .union(&StringContext::empty())
                    .map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::String {
                                id: contents_id,
                                source,
                            },
                            contents_span,
                        )
                    })?;
            (contents, references, reference_context)
        };

        let name_str = Self::to_file_store_path_name(id, name_span, &name)?;
        let store_path = self
            .build_text_path(id, span, name_str, &contents, references)
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ToFilePath {
                        id,
                        name: name.clone(),
                        message: source.to_string(),
                    },
                    span,
                )
            })?;
        let path = self.store_path_absolute_bytes(&store_path);
        let context = StringContext::singleton(ContextElement::opaque_path(path.clone()).map_err(
            |source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span),
        )?)
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        self.text_store.insert(
            path.clone(),
            TextStoreEntry {
                contents,
                references: reference_context,
            },
        );
        self.alloc_tree_walk_string(id, span, NixString::new(path, context))
    }

    pub(super) fn to_file_store_path_name(
        id: IrId,
        span: Span,
        name: &[u8],
    ) -> Result<&str, TreeWalkError> {
        let name_str = nix_compat::store_path::validate_name(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::ToFilePath {
                    id,
                    name: name.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })?;
        let first_component = name_str.split('-').next().unwrap_or_default();
        if matches!(first_component, "." | "..") {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ToFilePath {
                    id,
                    name: name.to_vec(),
                    message: "first dash-separated component must not be '.' or '..'".to_owned(),
                },
                span,
            ));
        }
        Ok(name_str)
    }

    pub(super) fn load_cached_import(
        &mut self,
        argument: IrId,
        argument_span: Span,
        cache_path: PathBuf,
        diagnostic_path: Vec<u8>,
        current_force_cache_trace_complete: bool,
        allow_empty_impure_trace: bool,
        load: impl FnOnce(&mut Self) -> Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        if !current_force_cache_trace_complete {
            self.mark_force_cache_impure_input_trace_incomplete();
        }
        match self.import_cache.get(&cache_path).cloned() {
            Some(ImportCacheEntry::Ready {
                value,
                trace,
                force_cache_trace_complete,
            }) => {
                if let Some(trace) = trace {
                    for fingerprint in trace {
                        self.record_impure_input(fingerprint);
                    }
                } else {
                    self.mark_impure_input_trace_incomplete();
                }
                if !force_cache_trace_complete {
                    self.mark_force_cache_impure_input_trace_incomplete();
                }
                return Ok(value);
            }
            Some(ImportCacheEntry::Evaluating) => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::RecursiveImport {
                        id: argument,
                        path: diagnostic_path,
                    },
                    argument_span,
                ));
            }
            None => {}
        }

        self.import_cache
            .insert(cache_path.clone(), ImportCacheEntry::Evaluating);
        self.increment_imports_evaluated();
        let trace_cursor = self.impure_input_trace_cursor();
        let result = load(self);
        match result {
            Ok(value) => {
                let trace = self.impure_input_trace_segment(trace_cursor);
                let force_cache_trace_complete = self
                    .force_cache_impure_input_trace_segment(trace_cursor)
                    .complete;
                let trace =
                    if trace.complete && (allow_empty_impure_trace || !trace.trace.is_empty()) {
                        Some(trace.trace)
                    } else {
                        self.mark_impure_input_trace_incomplete();
                        None
                    };
                self.import_cache.insert(
                    cache_path,
                    ImportCacheEntry::Ready {
                        value,
                        trace,
                        force_cache_trace_complete,
                    },
                );
                Ok(value)
            }
            Err(error) => {
                self.import_cache.remove(&cache_path);
                Err(error)
            }
        }
    }

    pub(super) fn eval_import_primop(
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
            "import",
        )?;
        if is_text_store {
            let cache_path = PathBuf::from(OsStr::from_bytes(&path));
            let text_path = path.clone();
            return self.load_cached_import(
                argument,
                argument_span,
                cache_path,
                path,
                false,
                true,
                |eval| {
                    eval.load_and_eval_text_store_import(
                        id,
                        span,
                        argument,
                        argument_span,
                        &text_path,
                        ImportGlobalScope::Fresh,
                    )
                },
            );
        }
        let (target_path, realpath) = self.import_paths(argument, argument_span, &path)?;
        let path_literal_base = Self::import_path_literal_base(&target_path);
        let trace_import = self.import_target_is_force_cache_traceable(&target_path);
        let realpath_bytes = realpath.as_os_str().as_bytes().to_vec();
        let import_path = realpath.clone();
        self.load_cached_import(
            argument,
            argument_span,
            realpath,
            realpath_bytes,
            trace_import,
            false,
            |eval| {
                eval.load_and_eval_import(
                    id,
                    span,
                    argument,
                    argument_span,
                    &import_path,
                    &path_literal_base,
                    trace_import,
                    ImportGlobalScope::Fresh,
                )
            },
        )
    }

    pub(super) fn eval_scoped_import_primop(
        &mut self,
        id: IrId,
        span: Span,
        scope: IrId,
        scope_span: Span,
        scope_value: Value,
        argument: IrId,
        argument_span: Span,
        argument_value: Value,
    ) -> Result<Value, TreeWalkError> {
        let scope_value = self.force_lazy_foldl_initial_value(scope, scope_span, scope_value)?;
        if scope_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: scope,
                    expected: "attrs",
                    actual: scope_value.tag(),
                },
                scope_span,
            ));
        }
        let (path, is_text_store) = self.coerce_to_filesystem_or_text_store_path_bytes(
            argument,
            argument_span,
            argument_value,
            "scopedImport",
        )?;
        if is_text_store {
            return self.load_and_eval_text_store_import(
                id,
                span,
                argument,
                argument_span,
                &path,
                ImportGlobalScope::Scoped(scope_value),
            );
        }
        let (target_path, realpath) = self.import_paths(argument, argument_span, &path)?;
        let path_literal_base = Self::import_path_literal_base(&target_path);
        let trace_import = self.import_target_is_force_cache_traceable(&target_path);
        self.load_and_eval_import(
            id,
            span,
            argument,
            argument_span,
            &realpath,
            &path_literal_base,
            trace_import,
            ImportGlobalScope::Scoped(scope_value),
        )
    }

    pub(super) fn import_paths(
        &self,
        argument: IrId,
        argument_span: Span,
        path: &[u8],
    ) -> Result<(PathBuf, PathBuf), TreeWalkError> {
        self.check_filesystem_path_access(argument, argument_span, path)?;
        let target = self.import_target_path(argument, argument_span, path)?;
        self.check_filesystem_path_access(argument, argument_span, target.as_os_str().as_bytes())?;
        let realpath = fs::canonicalize(&target).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FileRead {
                    id: argument,
                    path: target.as_os_str().as_bytes().to_vec(),
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        Ok((target, realpath))
    }

    pub(super) fn import_path_literal_base(target: &Path) -> Vec<u8> {
        target
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .as_os_str()
            .as_bytes()
            .to_vec()
    }

    fn import_target_is_force_cache_traceable(&mut self, target: &Path) -> bool {
        let mut prefix = PathBuf::new();
        for component in target.components() {
            prefix.push(component.as_os_str());
            if self.import_traceable_nonsymlink_prefixes.contains(&prefix) {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&prefix) else {
                return false;
            };
            if metadata.file_type().is_symlink() {
                return false;
            }
            // The store is immutable during evaluation, so record this confirmed
            // non-symlink prefix and skip the `lstat` on every later import that
            // shares it.
            self.import_traceable_nonsymlink_prefixes
                .insert(prefix.clone());
        }
        true
    }

    pub(super) fn import_target_path(
        &self,
        id: IrId,
        span: Span,
        path: &[u8],
    ) -> Result<PathBuf, TreeWalkError> {
        let requested = Path::new(OsStr::from_bytes(path));
        let metadata = fs::metadata(requested).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::PathStat {
                    id,
                    path: path.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })?;
        if metadata.is_dir() {
            return Ok(requested.join("default.nix"));
        }
        Ok(requested.to_path_buf())
    }

    pub(super) fn load_and_eval_import(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        realpath: &Path,
        path_literal_base: &[u8],
        trace_import: bool,
        global_scope: ImportGlobalScope,
    ) -> Result<Value, TreeWalkError> {
        let path = realpath.as_os_str().as_bytes().to_vec();
        let source = fs::read(realpath).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FileRead {
                    id: argument,
                    path: path.clone(),
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        self.record_impure_input_result(ImpureInputFingerprint::import(&path, &source));
        if !trace_import {
            self.mark_force_cache_impure_input_trace_incomplete();
        }
        if let Some(cached) = self.load_parse_cached_import(
            argument,
            argument_span,
            realpath,
            &path,
            &source,
            global_scope,
        )? {
            if cached.hit {
                self.import_parse_cache_hits += 1;
            } else {
                self.import_parse_cache_misses += 1;
            }

            let ir = self.remap_cached_import_ir(argument, argument_span, &path, cached.ir)?;
            return self.load_and_eval_import_ir(
                id,
                span,
                &path,
                path_literal_base,
                &source,
                ir,
                global_scope,
            );
        }
        self.load_and_eval_import_bytes(
            id,
            span,
            argument,
            argument_span,
            &path,
            path_literal_base,
            &source,
            global_scope,
        )
    }

    pub(super) fn load_parse_cached_import(
        &mut self,
        argument: IrId,
        argument_span: Span,
        realpath: &Path,
        path: &[u8],
        source: &[u8],
        global_scope: ImportGlobalScope,
    ) -> Result<Option<CachedParse>, TreeWalkError> {
        if global_scope.is_scoped() {
            return Ok(None);
        }

        if let Some(mut cached) = self.load_persist_cached_import(realpath, source) {
            self.refresh_and_materialize_persist_cached_import(realpath, source, &mut cached);
            return Ok(Some(cached));
        }

        let Some(cache) = &self.parse_cache else {
            return Ok(None);
        };

        let source_hint = Some(realpath.to_string_lossy().into_owned());
        let mut cached = cache
            .load_or_parse_bytes(source, source_hint)
            .map_err(|error| {
                Self::parse_cache_import_error(argument, argument_span, path, source, error)
            })?;
        self.refresh_and_materialize_persist_cached_import(realpath, source, &mut cached);
        Ok(Some(cached))
    }

    fn load_persist_cached_import(
        &mut self,
        realpath: &Path,
        source: &[u8],
    ) -> Option<CachedParse> {
        self.open_persist_import_cache();
        let cache = self.parse_cache.as_ref()?;
        let persist_cache = self.persist_cache.as_ref()?;
        persist_cache
            .load_parse_cache_source_from_index(cache, realpath, source)
            .ok()
            .flatten()
    }

    fn materialize_persist_cached_import(
        &mut self,
        realpath: &Path,
        source: &[u8],
        cached: &CachedParse,
    ) {
        if !cached.stored {
            return;
        }
        self.open_persist_import_cache();
        let Some(persist_cache) = &self.persist_cache else {
            return;
        };
        let file_key = ParseFileKey::for_source(realpath, source);
        let _ = persist_cache.materialize_parse_artifact_entry_indexed(
            &file_key,
            cached.key,
            &cached.entry,
            MaterializationDecision::Materialize,
        );
    }

    fn refresh_and_materialize_persist_cached_import(
        &mut self,
        realpath: &Path,
        source: &[u8],
        cached: &mut CachedParse,
    ) {
        let _ = cached.refresh_and_store_facts();
        self.materialize_persist_cached_import(realpath, source, cached);
    }

    fn open_persist_import_cache(&mut self) {
        if self.parse_cache.is_none() {
            return;
        }
        self.open_persist_eval_cache();
    }
}
