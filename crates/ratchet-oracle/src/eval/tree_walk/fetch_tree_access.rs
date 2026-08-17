//! Access checks, metadata, and flake-ref URL parsing for `fetchTree`.

use super::*;

impl TreeWalk {
    pub(super) fn fetch_tree_subdir_root(
        id: IrId,
        span: Span,
        input: &[u8],
        root: &Path,
        dir: Option<&[u8]>,
    ) -> Result<PathBuf, TreeWalkError> {
        let Some(dir) = dir.filter(|dir| !dir.is_empty()) else {
            return Ok(root.to_path_buf());
        };
        let mut selected = root.to_path_buf();
        for component in Path::new(OsStr::from_bytes(dir)).components() {
            match component {
                Component::CurDir => {}
                Component::Normal(name) => {
                    selected.push(name);
                    let metadata = fs::symlink_metadata(&selected)
                        .map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
                    if !metadata.is_dir() {
                        return Err(Self::fetch_tree_error(
                            id,
                            span,
                            input,
                            "fetchTree dir must select a directory",
                        ));
                    }
                }
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(Self::fetch_tree_error(
                        id,
                        span,
                        input,
                        "fetchTree dir must be a relative path inside the fetched tree",
                    ));
                }
            }
        }
        Ok(selected)
    }

    pub(super) fn check_fetch_tree_path_access(
        &self,
        id: IrId,
        span: Span,
        path: &[u8],
    ) -> Result<(), TreeWalkError> {
        if !Path::new(OsStr::from_bytes(path)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: path.to_vec(),
                },
                span,
            ));
        }
        if self.options.eval_mode() != EvalMode::Impure {
            self.check_filesystem_path_access(id, span, path)?;
        }
        Ok(())
    }

    pub(super) fn check_fetch_tree_url_access(
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
                    TreeWalkErrorKind::FetchTreeAccessDenied {
                        id,
                        input: url.to_vec(),
                        mode: EvalMode::Restricted,
                    },
                    span,
                ));
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn check_fetch_tree_git_access(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Restricted
            && !self.options.uri_is_allowed(canonical_uri)
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTreeAccessDenied {
                    id,
                    input: canonical_uri.to_vec(),
                    mode: EvalMode::Restricted,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn check_fetch_tree_forge_access(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Restricted
            && !self.options.uri_is_allowed(canonical_uri)
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTreeAccessDenied {
                    id,
                    input: canonical_uri.to_vec(),
                    mode: EvalMode::Restricted,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn parse_fetch_tree_url(
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<Url, TreeWalkError> {
        let text = std::str::from_utf8(url)
            .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
        Url::parse(text).map_err(|source| Self::fetch_tree_error(id, span, url, source))
    }

    pub(super) fn fetch_tree_url_bytes(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match parsed.scheme() {
            "file" => {
                let path = Self::fetchurl_file_path(id, span, url, parsed)?;
                if self.options.eval_mode() == EvalMode::Restricted
                    && !self.options.uri_is_allowed(url)
                {
                    self.check_filesystem_path_access(id, span, path.as_os_str().as_bytes())?;
                }
                fs::read(&path).map_err(|source| Self::fetch_tree_error(id, span, url, source))
            }
            "http" | "https" => {
                #[cfg(test)]
                if let Some(response) = self.options.fetch_tree_url_responses.get(url) {
                    return Ok(response.clone());
                }
                #[cfg(test)]
                if !self.options.fetch_tree_url_responses.is_empty() {
                    return Err(Self::fetch_tree_error(
                        id,
                        span,
                        url,
                        "missing test fetchTree URL response",
                    ));
                }

                let client = reqwest::blocking::Client::builder()
                    .no_gzip()
                    .no_brotli()
                    .no_zstd()
                    .no_deflate()
                    .build()
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
                let response = client
                    .get(parsed.as_str())
                    .header(reqwest::header::ACCEPT_ENCODING, "identity")
                    .send()
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
                let response = response
                    .error_for_status()
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
                response
                    .bytes()
                    .map(|bytes| bytes.to_vec())
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))
            }
            scheme => Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: url.to_vec(),
                    message: format!("unsupported URL scheme {scheme:?}"),
                },
                span,
            )),
        }
    }

    pub(super) fn check_fetch_tree_hash(
        id: IrId,
        span: Span,
        input: &[u8],
        expected: Option<NixSha256Digest>,
        actual: &NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        if let Some(expected) = expected
            && expected != *actual
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTreeHashMismatch {
                    id,
                    input: input.to_vec(),
                    expected: expected.as_bytes().to_vec(),
                    actual: actual.as_bytes().to_vec(),
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn check_fetch_tree_last_modified(
        id: IrId,
        span: Span,
        input: &[u8],
        expected: Option<i64>,
        actual: i64,
    ) -> Result<(), TreeWalkError> {
        if let Some(expected) = expected
            && expected != actual
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
                    id,
                    input: input.to_vec(),
                    expected,
                    actual,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn check_fetch_tree_rev_count(
        id: IrId,
        span: Span,
        input: &[u8],
        expected: usize,
        actual: usize,
    ) -> Result<(), TreeWalkError> {
        if expected == actual {
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchTreeRevCountMismatch {
                id,
                input: input.to_vec(),
                expected,
                actual,
            },
            span,
        ))
    }

    pub(super) fn fetch_tree_last_modified(
        id: IrId,
        span: Span,
        input: &[u8],
        path: &Path,
    ) -> Result<i64, TreeWalkError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
        let mut last_modified = Self::fetch_tree_metadata_modified(id, span, input, &metadata)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)
                .map_err(|source| Self::fetch_tree_error(id, span, input, source))?
            {
                let entry =
                    entry.map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
                let child_modified =
                    Self::fetch_tree_last_modified(id, span, input, &entry.path())?;
                last_modified = last_modified.max(child_modified);
            }
        }
        Ok(last_modified)
    }

    pub(super) fn fetch_tree_metadata_modified(
        id: IrId,
        span: Span,
        input: &[u8],
        metadata: &fs::Metadata,
    ) -> Result<i64, TreeWalkError> {
        let modified = metadata
            .modified()
            .map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
        let duration = modified
            .duration_since(UNIX_EPOCH)
            .map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
        i64::try_from(duration.as_secs()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: input.to_vec(),
                    message: "lastModified does not fit in Nix int".to_owned(),
                },
                span,
            )
        })
    }

    pub(super) fn fetch_tree_store_path_from_digest(
        &self,
        id: IrId,
        span: Span,
        input: &[u8],
        digest: NixSha256Digest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        self.store_path_bytes_from_fingerprint_parts(id, span, input, b"source", "source", digest)
    }

    pub(super) fn materialize_fetch_tree_store_path(
        &mut self,
        id: IrId,
        span: Span,
        input: &[u8],
        source: &Path,
        store_path: &[u8],
        digest: NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        let target = Path::new(OsStr::from_bytes(store_path));
        if target.exists() {
            return self.validate_fetch_tree_store_path_digest(id, span, input, store_path, digest);
        }
        let Some(parent) = target.parent() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: input.to_vec(),
                    message: format!("store path has no parent: {}", target.display()),
                },
                span,
            ));
        };
        fs::create_dir_all(parent)
            .map_err(|source| Self::fetch_tree_error(id, span, input, source))?;

        let temp_target = Self::fetch_tarball_temp_store_path(id, span, input, parent, target)?;
        if let Err(source) = Self::copy_fetch_tarball_tree(source, &temp_target) {
            Self::remove_fetch_tarball_temp_path(&temp_target);
            return Err(Self::fetch_tree_error(id, span, input, source));
        }
        match fs::rename(&temp_target, target) {
            Ok(()) => Ok(()),
            Err(source) => {
                Self::remove_fetch_tarball_temp_path(&temp_target);
                if target.exists() {
                    self.validate_fetch_tree_store_path_digest(
                        id, span, input, store_path, digest,
                    )?;
                    return Ok(());
                }
                Err(Self::fetch_tree_error(id, span, input, source))
            }
        }
    }

    pub(super) fn validate_fetch_tree_store_path_digest(
        &mut self,
        id: IrId,
        span: Span,
        input: &[u8],
        store_path: &[u8],
        expected: NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        let actual =
            self.source_path_nar_sha256(id, span, Path::new(OsStr::from_bytes(store_path)), None)?;
        if actual == expected {
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchTreeHashMismatch {
                id,
                input: input.to_vec(),
                expected: expected.as_bytes().to_vec(),
                actual: actual.as_bytes().to_vec(),
            },
            span,
        ))
    }

    pub(super) fn alloc_fetch_tree_result(
        &mut self,
        id: IrId,
        span: Span,
        result: FetchTreeResult,
    ) -> Result<Value, TreeWalkError> {
        let out_path_symbol = self.intern_builtin_attr_symbol(id, OUT_PATH_ATTR, span)?;
        let nar_hash_symbol = self.intern_builtin_attr_symbol(id, NAR_HASH_ATTR, span)?;
        let last_modified_symbol = self.intern_builtin_attr_symbol(id, LAST_MODIFIED_ATTR, span)?;
        let last_modified_date_symbol =
            self.intern_builtin_attr_symbol(id, LAST_MODIFIED_DATE_ATTR, span)?;
        let rev_symbol = self.intern_builtin_attr_symbol(id, REV_ATTR, span)?;
        let short_rev_symbol = self.intern_builtin_attr_symbol(id, SHORT_REV_ATTR, span)?;
        let dirty_rev_symbol = self.intern_builtin_attr_symbol(id, DIRTY_REV_ATTR, span)?;
        let dirty_short_rev_symbol =
            self.intern_builtin_attr_symbol(id, DIRTY_SHORT_REV_ATTR, span)?;
        let rev_count_symbol = self.intern_builtin_attr_symbol(id, REV_COUNT_ATTR, span)?;
        let submodules_symbol = self.intern_builtin_attr_symbol(id, SUBMODULES_ATTR, span)?;

        let mut entries = Vec::new();
        let nar_hash = self.alloc_static_string_with_attr_entry_roots(
            id,
            span,
            &mut entries,
            &result.nar_hash,
        )?;
        entries.push(AttrEntry::new(nar_hash_symbol, nar_hash));
        let out_path =
            self.alloc_fetcher_attrset_path_value(id, span, &mut entries, result.out_path)?;
        entries.push(AttrEntry::new(out_path_symbol, out_path));

        if let Some(last_modified) = result.last_modified {
            let last_modified = self.runtime_int_value(id, span, last_modified)?;
            entries.push(AttrEntry::new(last_modified_symbol, last_modified));
        }
        if let Some(last_modified_date) = result.last_modified_date {
            let last_modified_date = self.alloc_static_string_with_attr_entry_roots(
                id,
                span,
                &mut entries,
                &last_modified_date,
            )?;
            entries.push(AttrEntry::new(
                last_modified_date_symbol,
                last_modified_date,
            ));
        }
        if let Some(rev) = result.rev {
            let short_rev_len = rev.len().min(7);
            let rev_value =
                self.alloc_static_string_with_attr_entry_roots(id, span, &mut entries, &rev)?;
            entries.push(AttrEntry::new(rev_symbol, rev_value));
            let short_rev = self.alloc_static_string_with_attr_entry_roots(
                id,
                span,
                &mut entries,
                &rev[..short_rev_len],
            )?;
            entries.push(AttrEntry::new(short_rev_symbol, short_rev));
        }
        if let Some(dirty_rev) = result.dirty_rev {
            let dirty_rev =
                self.alloc_static_string_with_attr_entry_roots(id, span, &mut entries, &dirty_rev)?;
            entries.push(AttrEntry::new(dirty_rev_symbol, dirty_rev));
        }
        if let Some(dirty_short_rev) = result.dirty_short_rev {
            let dirty_short_rev = self.alloc_static_string_with_attr_entry_roots(
                id,
                span,
                &mut entries,
                &dirty_short_rev,
            )?;
            entries.push(AttrEntry::new(dirty_short_rev_symbol, dirty_short_rev));
        }
        if let Some(rev_count) = result.rev_count {
            let rev_count = i64::try_from(rev_count).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FetchTree {
                        id,
                        input: Vec::new(),
                        message: "revision count does not fit in Nix int".to_owned(),
                    },
                    span,
                )
            })?;
            let rev_count = self.runtime_int_value(id, span, rev_count)?;
            entries.push(AttrEntry::new(rev_count_symbol, rev_count));
        }
        if let Some(submodules) = result.submodules {
            entries.push(AttrEntry::new(submodules_symbol, Value::bool(submodules)));
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn fetch_tree_error(
        id: IrId,
        span: Span,
        input: &[u8],
        source: impl std::fmt::Display,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::FetchTree {
                id,
                input: input.to_vec(),
                message: source.to_string(),
            },
            span,
        )
    }

    pub(super) fn eval_parse_flake_ref_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let flake_ref =
            self.context_free_string_bytes(argument, argument_span, value, "parseFlakeRef")?;
        let attrs = Self::parse_flake_ref_attrs(argument, argument_span, &flake_ref)?;
        self.alloc_flake_ref_attrs(id, span, attrs)
    }

    pub(super) fn eval_flake_ref_to_string_primop(
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
        let attrs = self.flake_ref_attrs_from_value(argument, argument_span, value)?;
        let flake_ref = self.flake_ref_attrs_to_string(argument, argument_span, &attrs)?;
        self.alloc_static_string(id, span, &flake_ref)
    }

    pub(super) fn parse_flake_ref_attrs(
        id: IrId,
        span: Span,
        input: &[u8],
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let text = std::str::from_utf8(input)
            .map_err(|source| Self::flake_ref_error(id, span, input, source))?;
        if let Some(attrs) = Self::parse_indirect_flake_id_ref(id, span, input, text, false)? {
            return Ok(attrs);
        }
        if let Ok(url) = Url::parse(text) {
            if url.fragment().is_some_and(|fragment| !fragment.is_empty()) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "unexpected fragment in flake reference",
                ));
            }
            return Self::parse_flake_ref_url(id, span, input, &url);
        }
        Self::parse_absolute_path_flake_ref(id, span, input, text)
    }

    pub(super) fn parse_indirect_flake_id_ref(
        id: IrId,
        span: Span,
        input: &[u8],
        text: &str,
        explicit_flake_scheme: bool,
    ) -> Result<Option<FlakeRefAttrs>, TreeWalkError> {
        let (without_fragment, fragment) = match text.split_once('#') {
            Some((base, fragment)) => (base, fragment),
            None => (text, ""),
        };
        if !fragment.is_empty() {
            return Err(Self::flake_ref_error(
                id,
                span,
                input,
                "unexpected fragment in flake reference",
            ));
        }
        if without_fragment.contains('?') {
            return Ok(None);
        }
        let mut parts = without_fragment.splitn(2, '/');
        let Some(flake_id) = parts.next() else {
            return Ok(None);
        };
        if !Self::is_flake_id(flake_id.as_bytes()) {
            return Ok(None);
        }

        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(b"indirect".to_vec()),
        );
        attrs.insert(
            ID_ATTR.to_vec(),
            FlakeRefAttrValue::String(flake_id.as_bytes().to_vec()),
        );

        if let Some(rest) = parts.next() {
            if rest.is_empty() {
                return Ok(None);
            }
            if Self::is_git_rev(rest.as_bytes()) {
                attrs.insert(
                    REV_ATTR.to_vec(),
                    FlakeRefAttrValue::String(rest.as_bytes().to_vec()),
                );
            } else if let Some((reference, rev)) = Self::split_ref_and_rev(rest) {
                attrs.insert(
                    REF_ATTR.to_vec(),
                    FlakeRefAttrValue::String(reference.as_bytes().to_vec()),
                );
                attrs.insert(
                    REV_ATTR.to_vec(),
                    FlakeRefAttrValue::String(rev.as_bytes().to_vec()),
                );
            } else if Self::is_flake_ref_name(rest.as_bytes()) {
                attrs.insert(
                    REF_ATTR.to_vec(),
                    FlakeRefAttrValue::String(rest.as_bytes().to_vec()),
                );
            } else if explicit_flake_scheme {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "invalid indirect flake reference",
                ));
            } else {
                return Ok(None);
            }
        }

        Ok(Some(attrs))
    }

    pub(super) fn parse_flake_ref_url(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let query = Self::decode_flake_ref_query(id, span, input, url.query())?;
        let dir = query.get(DIR_ATTR).cloned();
        let scheme = url.scheme();
        let mut attrs = match scheme {
            "flake" => {
                let path = Self::percent_decode_flake_ref_component(url.path())
                    .map_err(|message| Self::flake_ref_error(id, span, input, message))?;
                let path = std::str::from_utf8(&path)
                    .map_err(|source| Self::flake_ref_error(id, span, input, source))?;
                Self::parse_indirect_flake_id_ref(id, span, input, path, true)?.ok_or_else(
                    || Self::flake_ref_error(id, span, input, "invalid indirect flake reference"),
                )?
            }
            "github" | "gitlab" | "sourcehut" => {
                Self::parse_forge_flake_ref_url(id, span, input, url, &query)?
            }
            "git" | "git+http" | "git+https" | "git+ssh" | "git+file" => {
                Self::parse_git_flake_ref_url(id, span, input, url, &query)?
            }
            "path" => Self::parse_path_flake_ref_url(id, span, input, url, &query)?,
            _ => {
                let Some(input_type) = Self::curl_flake_ref_url_type(url) else {
                    return Err(Self::flake_ref_error(
                        id,
                        span,
                        input,
                        format!("unsupported flake reference scheme '{scheme}'"),
                    ));
                };
                Self::parse_curl_flake_ref_url(id, span, input, url, &query, input_type)?
            }
        };
        if let Some(dir) = dir {
            attrs.insert(DIR_ATTR.to_vec(), FlakeRefAttrValue::String(dir));
        }
        Ok(attrs)
    }

    pub(super) fn parse_forge_flake_ref_url(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
        query: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let path = Self::percent_decode_flake_ref_component(url.path())
            .map_err(|message| Self::flake_ref_error(id, span, input, message))?;
        let path = std::str::from_utf8(&path)
            .map_err(|source| Self::flake_ref_error(id, span, input, source))?;
        let segments = path
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if segments.len() < 2 {
            return Err(Self::flake_ref_error(
                id,
                span,
                input,
                "forge flake reference requires owner and repo",
            ));
        }

        let mut rev = None;
        let mut reference = None;
        if segments.len() == 3 {
            let candidate = segments[2];
            if Self::is_git_rev(candidate.as_bytes()) {
                rev = Some(candidate.as_bytes().to_vec());
            } else if Self::is_flake_ref_name(candidate.as_bytes()) {
                reference = Some(candidate.as_bytes().to_vec());
            } else {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "invalid forge branch, tag, or revision",
                ));
            }
        } else if segments.len() > 3 {
            let candidate = segments[2..].join("/");
            if !Self::is_flake_ref_name(candidate.as_bytes()) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "invalid forge branch or tag",
                ));
            }
            reference = Some(candidate.into_bytes());
        }

        if let Some(query_rev) = query.get(REV_ATTR) {
            if rev.is_some() {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "flake reference contains multiple commit hashes",
                ));
            }
            if !Self::is_git_rev(query_rev) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "invalid forge commit hash",
                ));
            }
            rev = Some(query_rev.clone());
        }
        if let Some(query_ref) = query.get(REF_ATTR) {
            if !Self::is_flake_ref_name(query_ref) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "invalid forge branch or tag",
                ));
            }
            if reference.is_some() {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    input,
                    "flake reference contains multiple branch or tag names",
                ));
            }
            reference = Some(query_ref.clone());
        }
        if reference.is_some() && rev.is_some() {
            return Err(Self::flake_ref_error(
                id,
                span,
                input,
                "flake reference contains both a commit hash and a branch or tag",
            ));
        }

        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(url.scheme().as_bytes().to_vec()),
        );
        attrs.insert(
            OWNER_ATTR.to_vec(),
            FlakeRefAttrValue::String(segments[0].as_bytes().to_vec()),
        );
        attrs.insert(
            REPO_ATTR.to_vec(),
            FlakeRefAttrValue::String(segments[1].as_bytes().to_vec()),
        );
        if let Some(reference) = reference {
            attrs.insert(REF_ATTR.to_vec(), FlakeRefAttrValue::String(reference));
        }
        if let Some(rev) = rev {
            attrs.insert(REV_ATTR.to_vec(), FlakeRefAttrValue::String(rev));
        }
        if let Some(host) = query.get(HOST_ATTR) {
            if !Self::is_forge_host(host) {
                return Err(Self::flake_ref_error(id, span, input, "invalid forge host"));
            }
            attrs.insert(HOST_ATTR.to_vec(), FlakeRefAttrValue::String(host.clone()));
        }
        if let Some(nar_hash) = query.get(NAR_HASH_ATTR) {
            attrs.insert(
                NAR_HASH_ATTR.to_vec(),
                FlakeRefAttrValue::String(nar_hash.clone()),
            );
        }
        Ok(attrs)
    }

    pub(super) fn parse_git_flake_ref_url(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
        query: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(b"git".to_vec()),
        );

        let mut url_query = BTreeMap::new();
        for (name, value) in query {
            match name.as_slice() {
                REV_ATTR | REF_ATTR | NAR_HASH_ATTR | KEYTYPE_ATTR | PUBLIC_KEY_ATTR
                | PUBLIC_KEYS_ATTR => {
                    attrs.insert(name.clone(), FlakeRefAttrValue::String(value.clone()));
                }
                SHALLOW_ATTR | SUBMODULES_ATTR | EXPORT_IGNORE_ATTR | ALL_REFS_ATTR
                | VERIFY_COMMIT_ATTR => {
                    attrs.insert(name.clone(), FlakeRefAttrValue::Bool(value == b"1"));
                }
                _ => {
                    url_query.insert(name.clone(), value.clone());
                }
            }
        }

        if let Some(FlakeRefAttrValue::String(reference)) = attrs.get(REF_ATTR)
            && Self::is_bad_git_ref(reference)
        {
            return Err(Self::flake_ref_error(id, span, input, "invalid Git ref"));
        }

        let url = Self::flake_ref_url_with_scheme_and_query(
            id,
            span,
            input,
            url,
            Self::flake_ref_transport_scheme(url.scheme()),
            url_query,
            BTreeMap::new(),
        )?;
        attrs.insert(URL_ATTR.to_vec(), FlakeRefAttrValue::String(url));
        Ok(attrs)
    }

    pub(super) fn parse_path_flake_ref_url(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
        query: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        if url.has_host() {
            return Err(Self::flake_ref_error(
                id,
                span,
                input,
                "path flake reference must not have an authority",
            ));
        }
        let path = Self::percent_decode_flake_ref_component(url.path())
            .map_err(|message| Self::flake_ref_error(id, span, input, message))?;
        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(b"path".to_vec()),
        );
        attrs.insert(PATH_ATTR.to_vec(), FlakeRefAttrValue::String(path));
        for (name, value) in query {
            match name.as_slice() {
                REV_ATTR | NAR_HASH_ATTR => {
                    attrs.insert(name.clone(), FlakeRefAttrValue::String(value.clone()));
                }
                REV_COUNT_ATTR | LAST_MODIFIED_ATTR => {
                    attrs.insert(
                        name.clone(),
                        FlakeRefAttrValue::Int(Self::parse_flake_ref_u64(
                            id, span, input, value, name,
                        )?),
                    );
                }
                _ => {
                    return Err(Self::flake_ref_error(
                        id,
                        span,
                        input,
                        format!(
                            "path flake reference has unsupported parameter '{}'",
                            String::from_utf8_lossy(name)
                        ),
                    ));
                }
            }
        }
        Ok(attrs)
    }

    pub(super) fn parse_curl_flake_ref_url(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
        query: &BTreeMap<Vec<u8>, Vec<u8>>,
        input_type: &[u8],
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let mut attrs = FlakeRefAttrs::new();
        let mut url_query = query.clone();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(input_type.to_vec()),
        );
        if let Some(nar_hash) = url_query.remove(NAR_HASH_ATTR) {
            attrs.insert(NAR_HASH_ATTR.to_vec(), FlakeRefAttrValue::String(nar_hash));
        }
        if let Some(rev) = url_query.remove(REV_ATTR) {
            attrs.insert(REV_ATTR.to_vec(), FlakeRefAttrValue::String(rev));
        }
        if let Some(rev_count) = url_query.remove(REV_COUNT_ATTR)
            && let Ok(rev_count) =
                Self::parse_flake_ref_u64(id, span, input, &rev_count, REV_COUNT_ATTR)
        {
            attrs.insert(REV_COUNT_ATTR.to_vec(), FlakeRefAttrValue::Int(rev_count));
        }
        if let Some(last_modified) = url_query.remove(LAST_MODIFIED_ATTR)
            && let Ok(last_modified) =
                Self::parse_flake_ref_u64(id, span, input, &last_modified, LAST_MODIFIED_ATTR)
        {
            attrs.insert(
                LAST_MODIFIED_ATTR.to_vec(),
                FlakeRefAttrValue::Int(last_modified),
            );
        }
        for attr in [TYPE_ATTR, URL_ATTR, NAME_ATTR, UNPACK_ATTR] {
            url_query.remove(attr);
        }
        let url = Self::flake_ref_url_with_scheme_and_query(
            id,
            span,
            input,
            url,
            Self::flake_ref_transport_scheme(url.scheme()),
            url_query,
            BTreeMap::new(),
        )?;
        attrs.insert(URL_ATTR.to_vec(), FlakeRefAttrValue::String(url));
        Ok(attrs)
    }
}
