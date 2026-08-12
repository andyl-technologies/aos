//! Validation and extraction of `fetchTree` attributes and verified-fetch handling.

use super::*;

impl TreeWalk {
    pub(super) fn validate_fetch_tree_attrs(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        allowed: &[&[u8]],
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
            if !allowed.contains(&key) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedFetchTreeAttr {
                        id,
                        attr: key.to_vec(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn fetch_tree_git_verified_fetch_query(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, TreeWalkError> {
        let keytype = self.optional_fetch_tree_string_attr(id, span, value, KEYTYPE_ATTR)?;
        let mut query = BTreeMap::new();
        if let Some(public_keys) = self.attr_value_by_name(id, value, PUBLIC_KEYS_ATTR, span)? {
            let public_keys = self.force_value(id, span, public_keys)?;
            let mut keys = self.fetch_tree_public_key_entries_from_value(id, span, public_keys)?;
            if let Some(public_key) =
                self.optional_fetch_tree_string_attr(id, span, value, PUBLIC_KEY_ATTR)?
            {
                keys.push(GitPublicKeyEntry {
                    keytype: keytype.unwrap_or_else(|| b"ssh-ed25519".to_vec()),
                    key: public_key,
                });
            }
            Self::insert_git_public_key_entries_query_update(id, span, &keys, &mut query)?;
        } else if let Some(public_key) =
            self.optional_fetch_tree_string_attr(id, span, value, PUBLIC_KEY_ATTR)?
        {
            query.insert(
                KEYTYPE_ATTR.to_vec(),
                keytype.unwrap_or_else(|| b"ssh-ed25519".to_vec()),
            );
            query.insert(PUBLIC_KEY_ATTR.to_vec(), public_key);
        }

        if self.optional_fetch_tree_bool_attr(id, span, value, VERIFY_COMMIT_ATTR, false)? {
            return Err(Self::fetch_tree_verified_fetches_unsupported(
                id,
                span,
                VERIFY_COMMIT_ATTR,
            ));
        }

        Ok(query)
    }

    pub(super) fn fetch_tree_public_key_entries_from_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<GitPublicKeyEntry>, TreeWalkError> {
        match value.tag() {
            ValueTag::String => {
                let public_keys = self.context_free_string_bytes(id, span, value, "fetchTree")?;
                Self::git_public_key_entries_from_json(id, span, &public_keys)
            }
            ValueTag::List => self.fetch_tree_public_key_entries(id, span, value),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "list or string",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn fetch_tree_public_key_entries(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<GitPublicKeyEntry>, TreeWalkError> {
        let values = {
            let list = self.heap.get_list_view(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            list.iter().collect::<Vec<_>>()
        };
        let mut keys = Vec::new();
        keys.try_reserve_exact(values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: values.len(),
                },
                span,
            )
        })?;
        for value in values {
            let value = self.force_value(id, span, value)?;
            let value = self.force_lazy_foldl_initial_value(id, span, value)?;
            if value.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: value.tag(),
                    },
                    span,
                ));
            }
            keys.push(GitPublicKeyEntry {
                keytype: self.required_fetch_tree_public_key_attr(id, span, value, TYPE_ATTR)?,
                key: self.required_fetch_tree_public_key_attr(id, span, value, KEY_ATTR)?,
            });
        }
        Ok(keys)
    }

    pub(super) fn required_fetch_tree_public_key_attr(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        name: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let attr = self.required_attr_value_by_name(id, value, name, span)?;
        let attr = self.force_value(id, span, attr)?;
        self.context_free_string_bytes(id, span, attr, "fetchTree")
    }

    pub(super) fn fetch_tree_verified_fetches_unsupported(
        id: IrId,
        span: Span,
        _input: &[u8],
    ) -> TreeWalkError {
        Self::unsupported_fetch_tree_feature(id, span, "verified git fetches")
    }

    pub(super) fn unsupported_fetch_tree_feature(
        id: IrId,
        span: Span,
        feature: &'static str,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedFetchTreeFeature { id, feature },
            span,
        )
    }

    pub(super) fn fetch_tree_path_argument_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        let path = self.coerce_to_path_string(id, span, value)?;
        self.validate_ifd_path_context(id, span, &path, "fetchTree")?;
        let bytes =
            Self::copy_bytes_for_node(id, span, path_without_trailing_path_markers(path.bytes()))?;
        if !Path::new(OsStr::from_bytes(&bytes)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute { id, path: bytes },
                span,
            ));
        }
        self.realize_import_from_derivation(id, span, &path, "fetchTree")?;
        Ok(bytes)
    }

    pub(super) fn required_fetch_tree_url(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let url_value = self.required_attr_value_by_name(id, value, URL_ATTR, span)?;
        let url_value = self.force_value(id, span, url_value)?;
        self.context_free_string_bytes(id, span, url_value, "fetchTree")
    }

    pub(super) fn optional_fetch_tree_string_attr(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        attr: &[u8],
    ) -> Result<Option<Vec<u8>>, TreeWalkError> {
        let Some(attr_value) = self.attr_value_by_name(id, value, attr, span)? else {
            return Ok(None);
        };
        let attr_value = self.force_value(id, span, attr_value)?;
        self.context_free_string_bytes(id, span, attr_value, "fetchTree")
            .map(Some)
    }

    pub(super) fn optional_fetch_tree_int_attr(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        attr: &[u8],
    ) -> Result<Option<i64>, TreeWalkError> {
        let Some(attr_value) = self.attr_value_by_name(id, value, attr, span)? else {
            return Ok(None);
        };
        let attr_value = self.force_value(id, span, attr_value)?;
        self.expect_int(id, attr_value, span).map(Some)
    }

    pub(super) fn optional_fetch_tree_usize_attr(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        attr: &[u8],
    ) -> Result<Option<usize>, TreeWalkError> {
        let Some(value) = self.optional_fetch_tree_int_attr(id, span, value, attr)? else {
            return Ok(None);
        };
        usize::try_from(value).map(Some).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: attr.to_vec(),
                    message: "fetchTree integer attribute must be non-negative".to_owned(),
                },
                span,
            )
        })
    }

    pub(super) fn optional_fetch_tree_bool_attr(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        attr: &[u8],
        default: bool,
    ) -> Result<bool, TreeWalkError> {
        let Some(attr_value) = self.attr_value_by_name(id, value, attr, span)? else {
            return Ok(default);
        };
        let attr_value = self.force_value(id, span, attr_value)?;
        self.expect_bool(id, attr_value, span)
    }

    pub(super) fn optional_fetch_tree_nar_hash_attr(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Option<NixSha256Digest>, TreeWalkError> {
        let Some(hash) = self.optional_fetch_tree_string_attr(id, span, value, NAR_HASH_ATTR)?
        else {
            return Ok(None);
        };
        self.decode_fetch_tree_nar_hash(id, span, &hash).map(Some)
    }

    pub(super) fn decode_fetch_tree_nar_hash(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
    ) -> Result<NixSha256Digest, TreeWalkError> {
        let digest = self.decode_convert_hash(id, span, hash, Some(HashStringAlgorithm::Sha256))?;
        digest.as_nix_sha256().ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::HashAlgorithmMismatch {
                    id,
                    hash: hash.to_vec(),
                    expected: b"sha256".to_vec(),
                },
                span,
            )
        })
    }

    pub(super) fn check_fetch_tree_locked(
        &self,
        id: IrId,
        span: Span,
        args: &FetchTreeArguments,
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() != EvalMode::Pure {
            return Ok(());
        }
        let locked = match args {
            FetchTreeArguments::Path {
                expected_nar_hash, ..
            }
            | FetchTreeArguments::File {
                expected_nar_hash, ..
            }
            | FetchTreeArguments::Tarball {
                expected_nar_hash, ..
            } => expected_nar_hash.is_some(),
            FetchTreeArguments::Forge {
                expected_nar_hash, ..
            } => expected_nar_hash.is_some(),
            FetchTreeArguments::Git { args, .. } => args.rev.is_some(),
        };
        if locked {
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchTreeLockedInputRequired {
                id,
                input: Self::fetch_tree_input(args),
                mode: EvalMode::Pure,
            },
            span,
        ))
    }

    pub(super) fn fetch_tree_input(args: &FetchTreeArguments) -> Vec<u8> {
        match args {
            FetchTreeArguments::Path { path, .. } => path.clone(),
            FetchTreeArguments::File { url, .. } | FetchTreeArguments::Tarball { url, .. } => {
                url.clone()
            }
            FetchTreeArguments::Forge { canonical_uri, .. } => canonical_uri.clone(),
            FetchTreeArguments::Git { args, .. } => Self::fetch_tree_git_canonical_uri(args),
        }
    }

    pub(super) fn fetch_tree_git_canonical_uri(args: &FetchGitArguments) -> Vec<u8> {
        let mut uri = Vec::new();
        uri.extend_from_slice(b"git+");
        uri.extend_from_slice(&args.url);
        let mut separator = if Self::fetch_git_url_has_query(&args.url) {
            b'&'
        } else {
            b'?'
        };
        let mut push_param =
            |uri: &mut Vec<u8>, key: &[u8], value: Option<&[u8]>, percent_encode: bool| {
                uri.push(separator);
                separator = b'&';
                if percent_encode {
                    uri.extend_from_slice(&Self::percent_encode_flake_ref_query(key));
                } else {
                    uri.extend_from_slice(key);
                }
                if let Some(value) = value {
                    uri.push(b'=');
                    if percent_encode {
                        uri.extend_from_slice(&Self::percent_encode_flake_ref_query(value));
                    } else {
                        uri.extend_from_slice(value);
                    }
                }
            };
        for (key, value) in &args.extra_query {
            push_param(&mut uri, key, Some(value), true);
        }
        if let Some(rev) = &args.rev {
            push_param(&mut uri, b"rev", Some(rev), false);
        }
        if let Some(reference) = &args.reference {
            push_param(&mut uri, b"ref", Some(reference), false);
        }
        if args.shallow {
            push_param(&mut uri, b"shallow", Some(b"1"), false);
        }
        if args.submodules {
            push_param(&mut uri, b"submodules", Some(b"1"), false);
        }
        if args.export_ignore {
            push_param(&mut uri, b"exportIgnore", Some(b"1"), false);
        }
        uri
    }

    pub(super) fn eval_fetch_tree_path(
        &mut self,
        id: IrId,
        span: Span,
        path: Vec<u8>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    ) -> Result<FetchTreeResult, TreeWalkError> {
        self.check_fetch_tree_path_access(id, span, &path)?;
        let source = Path::new(OsStr::from_bytes(&path));
        let digest = self.source_path_nar_sha256(id, span, source, None)?;
        Self::check_fetch_tree_hash(id, span, &path, expected_nar_hash, &digest)?;
        let last_modified = Self::fetch_tree_last_modified(id, span, &path, source)?;
        Self::check_fetch_tree_last_modified(
            id,
            span,
            &path,
            expected_last_modified,
            last_modified,
        )?;
        let last_modified_date = Self::format_fetch_git_date(id, span, &path, last_modified)?;
        let nar_hash = Self::encode_convert_hash_digest(
            id,
            span,
            ConvertHashFormat::Sri,
            &NixHashDigest::from_nix_sha256(digest),
        )?;
        let out_path = self.fetch_tree_store_path_from_digest(id, span, &path, digest)?;
        self.materialize_fetch_tree_store_path(id, span, &path, source, &out_path, digest)?;
        Ok(FetchTreeResult {
            out_path,
            nar_hash,
            last_modified: Some(last_modified),
            last_modified_date: Some(last_modified_date),
            rev,
            dirty_rev: None,
            dirty_short_rev: None,
            rev_count,
            submodules: None,
        })
    }

    pub(super) fn eval_fetch_tree_file(
        &mut self,
        id: IrId,
        span: Span,
        url: Vec<u8>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    ) -> Result<FetchTreeResult, TreeWalkError> {
        let parsed = Self::parse_fetch_tree_url(id, span, &url)?;
        self.check_fetch_tree_url_access(id, span, &url, &parsed)?;
        let contents = self.fetch_tree_url_bytes(id, span, &url, &parsed)?;
        let temp_dir = Self::fetch_tarball_temp_dir(id, span, &url)?;
        let source = temp_dir.join("source");
        let write_result = fs::write(&source, contents)
            .map_err(|source| Self::fetch_tree_error(id, span, &url, source));
        if let Err(error) = write_result {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(error);
        }
        let result = self.eval_fetch_tree_materialized_file(
            id,
            span,
            url,
            &source,
            expected_nar_hash,
            rev,
            rev_count,
        );
        let _ = fs::remove_dir_all(&temp_dir);
        let mut result = result?;
        if let Some(last_modified) = expected_last_modified {
            result.last_modified = Some(last_modified);
            result.last_modified_date = Some(Self::format_fetch_git_date(
                id,
                span,
                b"fetchTree",
                last_modified,
            )?);
        }
        Ok(result)
    }

    pub(super) fn eval_fetch_tree_materialized_file(
        &mut self,
        id: IrId,
        span: Span,
        url: Vec<u8>,
        source: &Path,
        expected_nar_hash: Option<NixSha256Digest>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    ) -> Result<FetchTreeResult, TreeWalkError> {
        let digest = self.source_path_nar_sha256(id, span, source, None)?;
        Self::check_fetch_tree_hash(id, span, &url, expected_nar_hash, &digest)?;
        let nar_hash = Self::encode_convert_hash_digest(
            id,
            span,
            ConvertHashFormat::Sri,
            &NixHashDigest::from_nix_sha256(digest),
        )?;
        let out_path = self.fetch_tree_store_path_from_digest(id, span, &url, digest)?;
        self.materialize_fetch_tree_store_path(id, span, &url, source, &out_path, digest)?;
        Ok(FetchTreeResult {
            out_path,
            nar_hash,
            last_modified: None,
            last_modified_date: None,
            rev,
            dirty_rev: None,
            dirty_short_rev: None,
            rev_count,
            submodules: None,
        })
    }

    pub(super) fn eval_fetch_tree_tarball(
        &mut self,
        id: IrId,
        span: Span,
        url: Vec<u8>,
        transport_url: Vec<u8>,
        dir: Option<Vec<u8>>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        last_modified_from_lock: bool,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
        check_url_access: bool,
    ) -> Result<FetchTreeResult, TreeWalkError> {
        let parsed = Self::parse_fetch_tree_url(id, span, &transport_url)?;
        if check_url_access {
            self.check_fetch_tree_url_access(id, span, &url, &parsed)?;
        }
        let contents = self.fetch_tree_url_bytes(id, span, &transport_url, &parsed)?;
        let temp_dir = Self::fetch_tarball_temp_dir(id, span, &url)?;
        let unpack_dir = temp_dir.join("unpacked");
        if let Err(source) = fs::create_dir(&unpack_dir) {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(Self::fetch_tree_error(id, span, &url, source));
        }
        let unpacked_root = match Self::unpack_fetch_tarball_archive(
            id,
            span,
            &url,
            &parsed,
            &contents,
            &unpack_dir,
        )
        .and_then(|()| Self::fetch_tarball_unpacked_root(id, span, &url, &unpack_dir))
        {
            Ok(root) => root,
            Err(error) => {
                let _ = fs::remove_dir_all(&temp_dir);
                return Err(error);
            }
        };

        let result = (|| {
            let source_root =
                Self::fetch_tree_subdir_root(id, span, &url, &unpacked_root, dir.as_deref())?;
            let digest = self.source_path_nar_sha256(id, span, &source_root, None)?;
            Self::check_fetch_tree_hash(id, span, &url, expected_nar_hash, &digest)?;
            let observed_last_modified =
                Self::fetch_tree_last_modified(id, span, &url, &source_root)?;
            let last_modified = if last_modified_from_lock {
                expected_last_modified.unwrap_or(observed_last_modified)
            } else {
                Self::check_fetch_tree_last_modified(
                    id,
                    span,
                    &url,
                    expected_last_modified,
                    observed_last_modified,
                )?;
                observed_last_modified
            };
            let last_modified_date = Self::format_fetch_git_date(id, span, &url, last_modified)?;
            let nar_hash = Self::encode_convert_hash_digest(
                id,
                span,
                ConvertHashFormat::Sri,
                &NixHashDigest::from_nix_sha256(digest),
            )?;
            let out_path = self.fetch_tree_store_path_from_digest(id, span, &url, digest)?;
            self.materialize_fetch_tree_store_path(
                id,
                span,
                &url,
                &source_root,
                &out_path,
                digest,
            )?;
            Ok(FetchTreeResult {
                out_path,
                nar_hash,
                last_modified: Some(last_modified),
                last_modified_date: Some(last_modified_date),
                rev,
                dirty_rev: None,
                dirty_short_rev: None,
                rev_count,
                submodules: None,
            })
        })();
        let _ = fs::remove_dir_all(&temp_dir);
        result
    }

    pub(super) fn eval_fetch_tree_forge(
        &mut self,
        id: IrId,
        span: Span,
        canonical_uri: Vec<u8>,
        archive_url: Vec<u8>,
        dir: Option<Vec<u8>>,
        check_archive_url_access: bool,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Vec<u8>,
    ) -> Result<FetchTreeResult, TreeWalkError> {
        self.check_fetch_tree_forge_access(id, span, &canonical_uri)?;
        if check_archive_url_access {
            let parsed = Self::parse_fetch_tree_url(id, span, &archive_url)?;
            self.check_fetch_tree_url_access(id, span, &archive_url, &parsed)?;
        }
        self.eval_fetch_tree_tarball(
            id,
            span,
            canonical_uri,
            archive_url,
            dir,
            expected_nar_hash,
            expected_last_modified,
            false,
            Some(rev),
            None,
            false,
        )
    }

    pub(super) fn eval_fetch_tree_git(
        &mut self,
        id: IrId,
        span: Span,
        args: FetchGitArguments,
        dir: Option<Vec<u8>>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        expected_rev_count: Option<usize>,
        dirty_rev: Option<Vec<u8>>,
        dirty_short_rev: Option<Vec<u8>>,
    ) -> Result<FetchTreeResult, TreeWalkError> {
        let canonical_uri = Self::fetch_tree_git_canonical_uri(&args);
        self.check_fetch_tree_git_access(id, span, &canonical_uri)?;

        let mut checkout_args = args.clone();
        if checkout_args.shallow
            && Self::fetch_git_local_worktree_path(Self::fetch_git_transport_url(&checkout_args))
                .is_some()
        {
            checkout_args.shallow = false;
        }
        let temp_dir = Self::fetch_git_temp_dir(id, span, &checkout_args.url)?;
        let checkout_dir = temp_dir.join("checkout");
        let exported_dir = temp_dir.join("exported");
        let result =
            self.eval_fetch_git_into_store(id, span, checkout_args, &checkout_dir, &exported_dir);
        let _ = fs::remove_dir_all(&temp_dir);
        let result = result?;
        let result =
            self.reroot_fetch_tree_git_result(id, span, &args.url, result, dir.as_deref())?;

        if let Some(expected) = expected_nar_hash {
            let actual = self.decode_fetch_tree_nar_hash(id, span, &result.nar_hash)?;
            Self::check_fetch_tree_hash(id, span, &args.url, Some(expected), &actual)?;
        }
        Self::check_fetch_tree_last_modified(
            id,
            span,
            &args.url,
            expected_last_modified,
            result.last_modified,
        )?;
        if let Some(expected) = expected_rev_count {
            Self::check_fetch_tree_rev_count(id, span, &args.url, expected, result.rev_count)?;
        }

        let dirty = result.dirty_rev.is_some();
        let locked_dirty = dirty_rev.is_some();
        let rev_count = if !dirty
            && !locked_dirty
            && (args.rev.is_none() || !args.shallow || expected_rev_count.is_some())
        {
            Some(result.rev_count)
        } else {
            None
        };
        Ok(FetchTreeResult {
            out_path: result.out_path,
            nar_hash: result.nar_hash,
            last_modified: Some(result.last_modified),
            last_modified_date: Some(result.last_modified_date),
            rev: (!dirty && !locked_dirty).then(|| result.rev.into_bytes()),
            dirty_rev: dirty_rev.or_else(|| result.dirty_rev.map(String::into_bytes)),
            dirty_short_rev: dirty_short_rev
                .or_else(|| result.dirty_short_rev.map(String::into_bytes)),
            rev_count,
            submodules: Some(result.submodules),
        })
    }

    pub(super) fn reroot_fetch_tree_git_result(
        &mut self,
        id: IrId,
        span: Span,
        input: &[u8],
        mut result: FetchGitResult,
        dir: Option<&[u8]>,
    ) -> Result<FetchGitResult, TreeWalkError> {
        let Some(dir) = dir.filter(|dir| !dir.is_empty()) else {
            return Ok(result);
        };
        let store_root = Path::new(OsStr::from_bytes(&result.out_path));
        let source_root = Self::fetch_tree_subdir_root(id, span, input, store_root, Some(dir))?;
        let digest = self.source_path_nar_sha256(id, span, &source_root, None)?;
        result.nar_hash = Self::encode_convert_hash_digest(
            id,
            span,
            ConvertHashFormat::Sri,
            &NixHashDigest::from_nix_sha256(digest),
        )?;
        result.out_path = self.fetch_tree_store_path_from_digest(id, span, input, digest)?;
        self.materialize_fetch_tree_store_path(
            id,
            span,
            input,
            &source_root,
            &result.out_path,
            digest,
        )?;
        Ok(result)
    }
}
