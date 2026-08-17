//! Git worktree copying (filtered checkout export) and the `fetchTree`
//! flake-ref argument parsers.

use super::*;

impl TreeWalk {
    pub(super) fn copy_fetch_git_worktree(
        id: IrId,
        span: Span,
        url: &[u8],
        repo: &git2::Repository,
        source: &Path,
        target: &Path,
        export_ignore: bool,
        relative: &Path,
        is_root: bool,
    ) -> Result<bool, TreeWalkError> {
        if export_ignore
            && !is_root
            && Self::fetch_git_export_ignored(id, span, url, repo, relative)?
        {
            return Ok(false);
        }

        let metadata = fs::symlink_metadata(source)
            .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            fs::create_dir(target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            let mut copied_child = false;
            let mut had_entry = false;
            for entry in fs::read_dir(source)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?
            {
                let entry = entry.map_err(|source| Self::fetch_git_error(id, span, url, source))?;
                if entry.file_name().as_bytes() == b".git" {
                    continue;
                }
                had_entry = true;
                let child_relative = if relative.as_os_str().is_empty() {
                    PathBuf::from(entry.file_name())
                } else {
                    relative.join(entry.file_name())
                };
                if Self::copy_fetch_git_worktree(
                    id,
                    span,
                    url,
                    repo,
                    &entry.path(),
                    &target.join(entry.file_name()),
                    export_ignore,
                    &child_relative,
                    false,
                )? {
                    copied_child = true;
                }
            }
            // Keep a directory that copied a child, is the worktree root, or was
            // genuinely empty in the source. An uninitialized submodule appears as
            // an empty directory and C++ Nix retains it in the NAR (changing the
            // store hash), so dropping it diverges — e.g. firecracker's micro-http
            // fetchGit keeps an empty `rust-vmm-ci` submodule directory. Only
            // remove a directory whose entries all dropped out via export-ignore.
            if copied_child || is_root || !had_entry {
                fs::set_permissions(target, metadata.permissions())
                    .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
                return Ok(true);
            }
            fs::remove_dir(target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            return Ok(false);
        }
        if file_type.is_file() {
            fs::copy(source, target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            fs::set_permissions(target, metadata.permissions())
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            return Ok(true);
        }
        if file_type.is_symlink() {
            let link = fs::read_link(source)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            std::os::unix::fs::symlink(link, target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            return Ok(true);
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGit {
                id,
                url: url.to_vec(),
                message: "unsupported git worktree entry type".to_owned(),
            },
            span,
        ))
    }

    pub(super) fn copy_fetch_git_dirty_worktree(
        id: IrId,
        span: Span,
        url: &[u8],
        repo: &git2::Repository,
        source: &Path,
        target: &Path,
        export_ignore: bool,
        relative: &Path,
        excluded_paths: &BTreeSet<Vec<u8>>,
        is_root: bool,
    ) -> Result<bool, TreeWalkError> {
        if !is_root && Self::fetch_git_path_is_excluded(relative, excluded_paths) {
            return Ok(false);
        }
        if export_ignore
            && !is_root
            && Self::fetch_git_export_ignored(id, span, url, repo, relative)?
        {
            return Ok(false);
        }

        let metadata = fs::symlink_metadata(source)
            .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            fs::create_dir(target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            let mut copied_child = false;
            let mut had_entry = false;
            for entry in fs::read_dir(source)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?
            {
                let entry = entry.map_err(|source| Self::fetch_git_error(id, span, url, source))?;
                if entry.file_name().as_bytes() == b".git" {
                    continue;
                }
                had_entry = true;
                let child_relative = if relative.as_os_str().is_empty() {
                    PathBuf::from(entry.file_name())
                } else {
                    relative.join(entry.file_name())
                };
                if Self::copy_fetch_git_dirty_worktree(
                    id,
                    span,
                    url,
                    repo,
                    &entry.path(),
                    &target.join(entry.file_name()),
                    export_ignore,
                    &child_relative,
                    excluded_paths,
                    false,
                )? {
                    copied_child = true;
                }
            }
            // A genuinely-empty source directory (e.g. an uninitialized submodule)
            // is retained by C++ Nix; only a directory emptied by exclusion is
            // dropped. See `copy_fetch_git_worktree`.
            if copied_child || is_root || !had_entry {
                fs::set_permissions(target, metadata.permissions())
                    .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
                return Ok(true);
            }
            fs::remove_dir(target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            return Ok(false);
        }
        if file_type.is_file() {
            fs::copy(source, target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            fs::set_permissions(target, metadata.permissions())
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            return Ok(true);
        }
        if file_type.is_symlink() {
            let link = fs::read_link(source)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            std::os::unix::fs::symlink(link, target)
                .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
            return Ok(true);
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGit {
                id,
                url: url.to_vec(),
                message: "unsupported git worktree entry type".to_owned(),
            },
            span,
        ))
    }

    pub(super) fn fetch_git_export_ignored(
        id: IrId,
        span: Span,
        url: &[u8],
        repo: &git2::Repository,
        relative: &Path,
    ) -> Result<bool, TreeWalkError> {
        let flags = git2::AttrCheckFlags::FILE_THEN_INDEX | git2::AttrCheckFlags::NO_SYSTEM;
        let value = repo
            .get_attr_bytes(relative, "export-ignore", flags)
            .map_err(|source| Self::fetch_git_error(id, span, url, source))?;
        Ok(matches!(
            git2::AttrValue::from_bytes(value),
            git2::AttrValue::True
        ))
    }

    pub(super) fn fetch_git_path_is_excluded(
        path: &Path,
        excluded_paths: &BTreeSet<Vec<u8>>,
    ) -> bool {
        let bytes = path.as_os_str().as_bytes();
        excluded_paths.iter().any(|excluded| {
            bytes == excluded.as_slice()
                || excluded
                    .strip_suffix(b"/")
                    .is_some_and(|stripped| bytes == stripped)
                || excluded.ends_with(b"/") && bytes.starts_with(excluded.as_slice())
                || bytes
                    .strip_prefix(excluded.as_slice())
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
        })
    }

    pub(super) fn fetch_git_error(
        id: IrId,
        span: Span,
        url: &[u8],
        source: impl std::fmt::Display,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::FetchGit {
                id,
                url: url.to_vec(),
                message: source.to_string(),
            },
            span,
        )
    }

    pub(super) fn eval_fetch_tree_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let args = self.fetch_tree_arguments(argument, argument_span, value)?;
        self.check_fetch_tree_locked(argument, argument_span, &args)?;
        let result = match args {
            FetchTreeArguments::Path {
                path,
                expected_nar_hash,
                expected_last_modified,
                rev,
                rev_count,
            } => self.eval_fetch_tree_path(
                argument,
                argument_span,
                path,
                expected_nar_hash,
                expected_last_modified,
                rev,
                rev_count,
            )?,
            FetchTreeArguments::File {
                url,
                expected_nar_hash,
                expected_last_modified,
                rev,
                rev_count,
                ..
            } => self.eval_fetch_tree_file(
                argument,
                argument_span,
                url,
                expected_nar_hash,
                expected_last_modified,
                rev,
                rev_count,
            )?,
            FetchTreeArguments::Tarball {
                url,
                transport_url,
                dir,
                expected_nar_hash,
                expected_last_modified,
                last_modified_from_lock,
                rev,
                rev_count,
            } => self.eval_fetch_tree_tarball(
                argument,
                argument_span,
                url,
                transport_url,
                dir,
                expected_nar_hash,
                expected_last_modified,
                last_modified_from_lock,
                rev,
                rev_count,
                true,
            )?,
            FetchTreeArguments::Forge {
                canonical_uri,
                archive_url,
                dir,
                check_archive_url_access,
                expected_nar_hash,
                expected_last_modified,
                rev,
            } => self.eval_fetch_tree_forge(
                argument,
                argument_span,
                canonical_uri,
                archive_url,
                dir,
                check_archive_url_access,
                expected_nar_hash,
                expected_last_modified,
                rev,
            )?,
            FetchTreeArguments::Git {
                args,
                dir,
                expected_nar_hash,
                expected_last_modified,
                expected_rev_count,
                dirty_rev,
                dirty_short_rev,
            } => self.eval_fetch_tree_git(
                argument,
                argument_span,
                args,
                dir,
                expected_nar_hash,
                expected_last_modified,
                expected_rev_count,
                dirty_rev,
                dirty_short_rev,
            )?,
        };
        self.alloc_fetch_tree_result(id, span, result)
    }

    pub(super) fn fetch_tree_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        if value.tag() == ValueTag::String {
            let input = self.context_free_string_bytes(id, span, value, "fetchTree")?;
            if input.starts_with(b"/") {
                return Err(Self::fetch_tree_error(
                    id,
                    span,
                    &input,
                    "fetchTree string argument must be a URL-style flake reference",
                ));
            }
            let attrs = Self::parse_flake_ref_attrs(id, span, &input)?;
            return self.fetch_tree_flake_ref_arguments(id, span, &input, &attrs);
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
        if self
            .attr_value_by_name(id, value, NAME_ATTR, span)?
            .is_some()
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedFetchTreeAttr {
                    id,
                    attr: NAME_ATTR.to_vec(),
                },
                span,
            ));
        }

        let type_value = self.required_attr_value_by_name(id, value, TYPE_ATTR, span)?;
        let type_value = self.force_value(id, span, type_value)?;
        let input_type = self.context_free_string_bytes(id, span, type_value, "fetchTree")?;
        match input_type.as_slice() {
            b"indirect" => self.fetch_tree_indirect_arguments(id, span, value),
            b"path" => self.fetch_tree_path_arguments(id, span, value),
            b"file" => self.fetch_tree_file_arguments(id, span, value),
            b"tarball" => self.fetch_tree_tarball_arguments(id, span, value),
            b"git" => self.fetch_tree_git_arguments(id, span, value),
            b"github" | b"gitlab" | b"sourcehut" => {
                self.fetch_tree_forge_arguments(id, span, value, &input_type)
            }
            _ => Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: input_type,
                    message: "unsupported fetchTree input type".to_owned(),
                },
                span,
            )),
        }
    }

    fn fetch_tree_indirect_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.validate_fetch_tree_attrs(
            id,
            span,
            value,
            &[TYPE_ATTR, ID_ATTR, REF_ATTR, REV_ATTR, DIR_ATTR],
        )?;
        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(b"indirect".to_vec()),
        );

        let id_value = self.required_attr_value_by_name(id, value, ID_ATTR, span)?;
        let id_value = self.force_value(id, span, id_value)?;
        attrs.insert(
            ID_ATTR.to_vec(),
            FlakeRefAttrValue::String(self.context_free_string_bytes(
                id,
                span,
                id_value,
                "fetchTree",
            )?),
        );
        if let Some(reference) = self.optional_fetch_tree_string_attr(id, span, value, REF_ATTR)? {
            attrs.insert(REF_ATTR.to_vec(), FlakeRefAttrValue::String(reference));
        }
        if let Some(rev) = self.optional_fetch_tree_string_attr(id, span, value, REV_ATTR)? {
            attrs.insert(REV_ATTR.to_vec(), FlakeRefAttrValue::String(rev));
        }
        if let Some(dir) = self.optional_fetch_tree_string_attr(id, span, value, DIR_ATTR)? {
            attrs.insert(DIR_ATTR.to_vec(), FlakeRefAttrValue::String(dir));
        }
        let input = self.flake_ref_attrs_to_string(id, span, &attrs)?;
        self.fetch_tree_flake_ref_arguments(id, span, &input, &attrs)
    }

    pub(super) fn fetch_tree_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        input: &[u8],
        attrs: &FlakeRefAttrs,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.fetch_tree_flake_ref_arguments_with_resolution_depth(id, span, input, attrs, 0)
    }

    fn fetch_tree_flake_ref_arguments_with_resolution_depth(
        &self,
        id: IrId,
        span: Span,
        input: &[u8],
        attrs: &FlakeRefAttrs,
        resolution_depth: usize,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        let input_type = Self::required_flake_ref_string_attr(id, span, attrs, TYPE_ATTR)?;
        if attrs.contains_key(DIR_ATTR)
            && !matches!(
                input_type,
                b"indirect" | b"tarball" | b"git" | b"github" | b"gitlab" | b"sourcehut"
            )
        {
            return Err(Self::fetch_tree_error(
                id,
                span,
                input,
                "fetchTree string references with dir metadata are supported only for tarball, git, and forge inputs",
            ));
        }
        match input_type {
            b"indirect" => self.fetch_tree_indirect_flake_ref_arguments(
                id,
                span,
                input,
                attrs,
                resolution_depth,
            ),
            b"path" => self.fetch_tree_path_flake_ref_arguments(id, span, attrs),
            b"file" => self.fetch_tree_file_flake_ref_arguments(id, span, attrs),
            b"tarball" => self.fetch_tree_tarball_flake_ref_arguments(id, span, attrs),
            b"git" => self.fetch_tree_git_flake_ref_arguments(id, span, input, attrs),
            b"github" | b"gitlab" | b"sourcehut" => {
                self.fetch_tree_forge_flake_ref_arguments(id, span, input_type, attrs)
            }
            _ => Err(Self::fetch_tree_error(
                id,
                span,
                input_type,
                "unsupported fetchTree string flake reference type",
            )),
        }
    }

    fn fetch_tree_indirect_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        input: &[u8],
        attrs: &FlakeRefAttrs,
        resolution_depth: usize,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        if resolution_depth >= MAX_FLAKE_REF_RESOLUTION_DEPTH {
            return Err(Self::fetch_tree_error(
                id,
                span,
                input,
                "indirect fetchTree flake reference resolution depth exceeded",
            ));
        }
        let indirect = self.flake_ref_attrs_to_string(id, span, attrs)?;
        let Some(target) = self.options.flake_ref_resolution(&indirect) else {
            return Err(Self::fetch_tree_error(
                id,
                span,
                &indirect,
                "unresolved indirect fetchTree flake reference",
            ));
        };
        let target_attrs = Self::parse_flake_ref_attrs(id, span, target)?;
        self.fetch_tree_flake_ref_arguments_with_resolution_depth(
            id,
            span,
            target,
            &target_attrs,
            resolution_depth + 1,
        )
    }

    pub(super) fn fetch_tree_path_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                PATH_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
            ],
        )?;
        let path = Self::required_flake_ref_string_attr(id, span, attrs, PATH_ATTR)?.to_vec();
        if !Path::new(OsStr::from_bytes(&path)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute { id, path },
                span,
            ));
        }
        Ok(FetchTreeArguments::Path {
            path,
            expected_nar_hash: self.optional_flake_ref_nar_hash_attr(id, span, attrs)?,
            expected_last_modified: Self::optional_flake_ref_i64_attr(
                id,
                span,
                attrs,
                LAST_MODIFIED_ATTR,
            )?,
            rev: Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)?
                .map(ToOwned::to_owned),
            rev_count: Self::optional_flake_ref_usize_attr(id, span, attrs, REV_COUNT_ATTR)?,
        })
    }

    pub(super) fn fetch_tree_file_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                URL_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
            ],
        )?;
        Ok(FetchTreeArguments::File {
            url: Self::required_flake_ref_string_attr(id, span, attrs, URL_ATTR)?.to_vec(),
            expected_nar_hash: self.optional_flake_ref_nar_hash_attr(id, span, attrs)?,
            expected_last_modified: Self::optional_flake_ref_i64_attr(
                id,
                span,
                attrs,
                LAST_MODIFIED_ATTR,
            )?,
            rev: Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)?
                .map(ToOwned::to_owned),
            rev_count: Self::optional_flake_ref_usize_attr(id, span, attrs, REV_COUNT_ATTR)?,
        })
    }

    pub(super) fn fetch_tree_tarball_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                URL_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
                DIR_ATTR,
            ],
        )?;
        let url = Self::required_flake_ref_string_attr(id, span, attrs, URL_ATTR)?;
        let dir =
            Self::optional_flake_ref_string_attr(id, span, attrs, DIR_ATTR)?.map(ToOwned::to_owned);
        let transport_url = Self::fetch_tree_transport_url_without_dir(id, span, url)?;
        Ok(FetchTreeArguments::Tarball {
            url: url.to_vec(),
            transport_url,
            dir,
            expected_nar_hash: self.optional_flake_ref_nar_hash_attr(id, span, attrs)?,
            expected_last_modified: Self::optional_flake_ref_i64_attr(
                id,
                span,
                attrs,
                LAST_MODIFIED_ATTR,
            )?,
            last_modified_from_lock: true,
            rev: Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)?
                .map(ToOwned::to_owned),
            rev_count: Self::optional_flake_ref_usize_attr(id, span, attrs, REV_COUNT_ATTR)?,
        })
    }

    pub(super) fn fetch_tree_forge_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        input_type: &[u8],
        attrs: &FlakeRefAttrs,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                OWNER_ATTR,
                REPO_ATTR,
                REF_ATTR,
                REV_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                HOST_ATTR,
                b"treeHash",
                DIR_ATTR,
            ],
        )?;
        let reference = Self::optional_flake_ref_string_attr(id, span, attrs, REF_ATTR)?;
        let rev = Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)?;
        if reference.is_some() && rev.is_some() {
            return Err(Self::unsupported_fetch_tree_feature(
                id,
                span,
                "forge reference resolution",
            ));
        }
        let expected_nar_hash = self.optional_flake_ref_nar_hash_attr(id, span, attrs)?;
        let expected_last_modified =
            Self::optional_flake_ref_i64_attr(id, span, attrs, LAST_MODIFIED_ATTR)?;
        let reference =
            reference.or_else(|| (input_type == b"sourcehut" && rev.is_none()).then_some(b"HEAD"));
        if let Some(reference) = reference {
            let canonical_uri =
                self.fetch_tree_unresolved_forge_canonical_uri(id, span, input_type, attrs)?;
            self.check_fetch_tree_forge_access(id, span, &canonical_uri)?;
            if self.options.eval_mode() == EvalMode::Pure {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::FetchTreeLockedInputRequired {
                        id,
                        input: canonical_uri,
                        mode: EvalMode::Pure,
                    },
                    span,
                ));
            }
            if !matches!(input_type, b"github" | b"gitlab" | b"sourcehut") {
                return Err(Self::unsupported_fetch_tree_feature(
                    id,
                    span,
                    "forge reference resolution",
                ));
            }
            let owner = Self::required_flake_ref_string_attr(id, span, attrs, OWNER_ATTR)?;
            let repo = Self::required_flake_ref_string_attr(id, span, attrs, REPO_ATTR)?;
            Self::validate_forge_path_segment(id, span, owner, "fetchTree forge owner is invalid")?;
            Self::validate_forge_path_segment(id, span, repo, "fetchTree forge repo is invalid")?;
            if !Self::is_flake_ref_name(reference) {
                return Err(Self::fetch_tree_error(
                    id,
                    span,
                    reference,
                    "fetchTree forge ref is invalid",
                ));
            }
            let host = Self::optional_flake_ref_string_attr(id, span, attrs, HOST_ATTR)?;
            let check_archive_url_access = host.is_some_and(|host| {
                Self::default_forge_host(input_type)
                    .is_none_or(|default_host| host != default_host.as_bytes())
            });
            if let Some(host) = host
                && !Self::is_forge_host(host)
            {
                return Err(Self::fetch_tree_error(
                    id,
                    span,
                    host,
                    "fetchTree forge host is invalid",
                ));
            }
            let rev = self.resolve_fetch_tree_forge_ref(
                id,
                span,
                &canonical_uri,
                input_type,
                owner,
                repo,
                host,
                reference,
                check_archive_url_access,
            )?;
            let archive_url =
                Self::fetch_tree_forge_archive_url(id, span, input_type, owner, repo, host, &rev)?;
            let dir = Self::optional_flake_ref_string_attr(id, span, attrs, DIR_ATTR)?
                .map(ToOwned::to_owned);

            return Ok(FetchTreeArguments::Forge {
                canonical_uri,
                archive_url,
                dir,
                check_archive_url_access,
                expected_nar_hash,
                expected_last_modified,
                rev,
            });
        }
        let Some(rev) = rev else {
            let canonical_uri =
                self.fetch_tree_unresolved_forge_canonical_uri(id, span, input_type, attrs)?;
            self.check_fetch_tree_forge_access(id, span, &canonical_uri)?;
            return Err(Self::unsupported_fetch_tree_feature(
                id,
                span,
                "forge inputs without a resolved rev",
            ));
        };
        let rev = self.canonical_flake_ref_rev(id, span, rev)?;
        let owner = Self::required_flake_ref_string_attr(id, span, attrs, OWNER_ATTR)?;
        let repo = Self::required_flake_ref_string_attr(id, span, attrs, REPO_ATTR)?;
        Self::validate_forge_path_segment(id, span, owner, "fetchTree forge owner is invalid")?;
        Self::validate_forge_path_segment(id, span, repo, "fetchTree forge repo is invalid")?;
        let host = Self::optional_flake_ref_string_attr(id, span, attrs, HOST_ATTR)?;
        let check_archive_url_access = host.is_some_and(|host| {
            Self::default_forge_host(input_type)
                .is_none_or(|default_host| host != default_host.as_bytes())
        });
        if let Some(host) = host
            && !Self::is_forge_host(host)
        {
            return Err(Self::fetch_tree_error(
                id,
                span,
                host,
                "fetchTree forge host is invalid",
            ));
        }
        let canonical_uri = self.fetch_tree_forge_canonical_uri(id, span, input_type, attrs)?;
        let archive_url =
            Self::fetch_tree_forge_archive_url(id, span, input_type, owner, repo, host, &rev)?;
        let dir =
            Self::optional_flake_ref_string_attr(id, span, attrs, DIR_ATTR)?.map(ToOwned::to_owned);

        Ok(FetchTreeArguments::Forge {
            canonical_uri,
            archive_url,
            dir,
            check_archive_url_access,
            expected_nar_hash,
            expected_last_modified,
            rev,
        })
    }

    pub(super) fn fetch_tree_forge_canonical_uri(
        &self,
        id: IrId,
        span: Span,
        input_type: &[u8],
        attrs: &FlakeRefAttrs,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut extra_query = BTreeMap::new();
        if let Some(dir) = Self::optional_flake_ref_string_attr(id, span, attrs, DIR_ATTR)? {
            extra_query.insert(DIR_ATTR.to_vec(), dir.to_vec());
        }
        self.forge_flake_ref_to_string(id, span, attrs, input_type, extra_query)
    }

    pub(super) fn fetch_tree_unresolved_forge_canonical_uri(
        &self,
        id: IrId,
        span: Span,
        input_type: &[u8],
        attrs: &FlakeRefAttrs,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let owner = Self::required_flake_ref_string_attr(id, span, attrs, OWNER_ATTR)?;
        let repo = Self::required_flake_ref_string_attr(id, span, attrs, REPO_ATTR)?;
        let mut path = Vec::new();
        path.extend_from_slice(owner);
        path.push(b'/');
        path.extend_from_slice(repo);
        if let Some(reference) = Self::optional_flake_ref_string_attr(id, span, attrs, REF_ATTR)? {
            path.push(b'/');
            path.extend_from_slice(reference);
        }

        let mut query = BTreeMap::new();
        if let Some(nar_hash) =
            Self::optional_flake_ref_string_attr(id, span, attrs, NAR_HASH_ATTR)?
        {
            query.insert(
                NAR_HASH_ATTR.to_vec(),
                self.canonical_flake_ref_nar_hash(id, span, nar_hash)?,
            );
        }
        let mut out = input_type.to_vec();
        out.push(b':');
        out.extend_from_slice(&Self::percent_encode_flake_ref_path(&path));
        Self::append_flake_ref_query(&mut out, &query);
        Ok(out)
    }
}
