//! Git fetcher: argument parsing, cloning, checkout, and worktree handling.

use super::*;

impl TreeWalk {
    pub(super) fn eval_fetch_git_into_store(
        &mut self,
        argument: IrId,
        argument_span: Span,
        args: FetchGitArguments,
        checkout_dir: &Path,
        exported_dir: &Path,
    ) -> Result<FetchGitResult, TreeWalkError> {
        if let Some(result) =
            self.eval_dirty_fetch_git_local_worktree(argument, argument_span, &args, exported_dir)?
        {
            return Ok(result);
        }

        let repo = Self::fetch_git_clone(argument, argument_span, &args, checkout_dir)?;
        if args.reference.is_some() {
            Self::fetch_git_reference(argument, argument_span, &args, &repo)?;
        }
        if args.all_refs {
            Self::fetch_git_all_refs(argument, argument_span, &args, &repo)?;
        }
        let (rev, rev_count, last_modified, last_modified_date) =
            Self::fetch_git_checkout_commit(argument, argument_span, &args, &repo)?;
        if args.submodules {
            Self::update_fetch_git_submodules(argument, argument_span, &args, &repo)?;
        }

        Self::copy_fetch_git_worktree(
            argument,
            argument_span,
            &args.url,
            &repo,
            checkout_dir,
            exported_dir,
            args.export_ignore,
            Path::new(""),
            true,
        )?;

        let digest = self.source_path_nar_sha256(argument, argument_span, exported_dir, None)?;
        let nar_hash = Self::encode_convert_hash_digest(
            argument,
            argument_span,
            ConvertHashFormat::Sri,
            &NixHashDigest::from_nix_sha256(digest),
        )?;
        let out_path = self.fetch_git_store_path_from_digest(
            argument,
            argument_span,
            &args.url,
            &args.name,
            digest,
        )?;
        self.materialize_fetch_git_store_path(
            argument,
            argument_span,
            &args.url,
            &args.name,
            exported_dir,
            &out_path,
            digest,
        )?;

        Ok(FetchGitResult {
            out_path,
            rev,
            dirty_rev: None,
            dirty_short_rev: None,
            rev_count,
            last_modified,
            last_modified_date,
            nar_hash,
            submodules: args.submodules,
        })
    }

    pub(super) fn eval_dirty_fetch_git_local_worktree(
        &mut self,
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        exported_dir: &Path,
    ) -> Result<Option<FetchGitResult>, TreeWalkError> {
        if args.rev.is_some() {
            return Ok(None);
        }
        let Some(local_path) =
            Self::fetch_git_local_worktree_path(Self::fetch_git_transport_url(args))
        else {
            return Ok(None);
        };
        let Ok(repo) = git2::Repository::open(&local_path) else {
            return Ok(None);
        };
        let (dirty, excluded_paths) = Self::fetch_git_dirty_status(id, span, args, &repo)?;
        if !dirty {
            return Ok(None);
        }

        let head_commit = repo
            .head()
            .and_then(|head| head.peel_to_commit())
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let head_rev = head_commit.id().to_string();
        let dirty_rev = format!("{head_rev}-dirty");
        let dirty_short_rev = format!("{}-dirty", &head_rev[..7]);
        let time = head_commit.time();
        let last_modified = time.seconds();
        let last_modified_date = Self::format_fetch_git_date(id, span, &args.url, last_modified)?;
        drop(head_commit);

        Self::copy_fetch_git_dirty_worktree(
            id,
            span,
            &args.url,
            &repo,
            &local_path,
            exported_dir,
            args.export_ignore,
            Path::new(""),
            &excluded_paths,
            true,
        )?;

        let digest = self.source_path_nar_sha256(id, span, exported_dir, None)?;
        let nar_hash = Self::encode_convert_hash_digest(
            id,
            span,
            ConvertHashFormat::Sri,
            &NixHashDigest::from_nix_sha256(digest),
        )?;
        let out_path =
            self.fetch_git_store_path_from_digest(id, span, &args.url, &args.name, digest)?;
        self.materialize_fetch_git_store_path(
            id,
            span,
            &args.url,
            &args.name,
            exported_dir,
            &out_path,
            digest,
        )?;

        Ok(Some(FetchGitResult {
            out_path,
            rev: "0000000000000000000000000000000000000000".to_owned(),
            dirty_rev: Some(dirty_rev),
            dirty_short_rev: Some(dirty_short_rev),
            rev_count: 0,
            last_modified,
            last_modified_date,
            nar_hash,
            submodules: args.submodules,
        }))
    }

    pub(super) fn fetch_git_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchGitArguments, TreeWalkError> {
        if value.tag() == ValueTag::String {
            let url = self.context_free_string_bytes(id, span, value, "fetchGit")?;
            let name = Self::fetch_git_store_name(id, span, &url, b"source")?.to_owned();
            return Ok(FetchGitArguments {
                url,
                transport_url: None,
                name,
                rev: None,
                reference: None,
                submodules: false,
                shallow: false,
                all_refs: false,
                export_ignore: true,
                extra_query: BTreeMap::new(),
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
        self.validate_fetch_git_attrs(id, span, value)?;

        let url_value = self.required_attr_value_by_name(id, value, URL_ATTR, span)?;
        let url_value = self.force_value(id, span, url_value)?;
        let url = self.context_free_string_bytes(id, span, url_value, "fetchGit")?;

        let name = if let Some(name_value) = self.attr_value_by_name(id, value, NAME_ATTR, span)? {
            let name_value = self.force_value(id, span, name_value)?;
            self.context_free_string_bytes(id, span, name_value, "fetchGit")?
        } else {
            b"source".to_vec()
        };
        let name = Self::fetch_git_store_name(id, span, &url, &name)?.to_owned();

        let rev = if let Some(rev_value) = self.attr_value_by_name(id, value, REV_ATTR, span)? {
            let rev_value = self.force_value(id, span, rev_value)?;
            Some(self.context_free_string_bytes(id, span, rev_value, "fetchGit")?)
        } else {
            None
        };
        let reference =
            if let Some(ref_value) = self.attr_value_by_name(id, value, REF_ATTR, span)? {
                let ref_value = self.force_value(id, span, ref_value)?;
                Some(self.context_free_string_bytes(id, span, ref_value, "fetchGit")?)
            } else {
                None
            };
        let submodules =
            self.optional_fetch_git_bool_attr(id, span, value, SUBMODULES_ATTR, false)?;
        let shallow = self.optional_fetch_git_bool_attr(id, span, value, SHALLOW_ATTR, false)?;
        let all_refs = self.optional_fetch_git_bool_attr(id, span, value, ALL_REFS_ATTR, false)?;
        let export_ignore = !submodules;

        Ok(FetchGitArguments {
            url,
            transport_url: None,
            name,
            rev,
            reference,
            submodules,
            shallow,
            all_refs,
            export_ignore,
            extra_query: BTreeMap::new(),
        })
    }

    pub(super) fn optional_fetch_git_bool_attr(
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

    pub(super) fn validate_fetch_git_attrs(
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
                URL_ATTR
                    | NAME_ATTR
                    | REV_ATTR
                    | REF_ATTR
                    | SUBMODULES_ATTR
                    | SHALLOW_ATTR
                    | ALL_REFS_ATTR
            ) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedFetchGitAttr {
                        id,
                        attr: key.to_vec(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn fetch_git_store_name<'a>(
        id: IrId,
        span: Span,
        url: &[u8],
        name: &'a [u8],
    ) -> Result<&'a str, TreeWalkError> {
        nix_compat::store_path::validate_name(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchGitStoreName {
                    id,
                    url: url.to_vec(),
                    name: name.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn fetch_git_store_path_from_digest(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        name: &str,
        digest: NixSha256Digest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        self.store_path_bytes_from_fingerprint_parts(id, span, url, b"source", name, digest)
    }

    pub(super) fn fetch_git_canonical_uri(args: &FetchGitArguments) -> Vec<u8> {
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
        if let Some(reference) = &args.reference {
            push_param(&mut uri, b"ref", Some(reference), false);
        }
        for (key, value) in &args.extra_query {
            push_param(&mut uri, key, Some(value), true);
        }
        if args.export_ignore {
            push_param(&mut uri, b"exportIgnore", Some(b"1"), false);
        }
        if let Some(rev) = &args.rev {
            push_param(&mut uri, b"rev", Some(rev), false);
        }
        if args.shallow {
            push_param(&mut uri, b"shallow", Some(b"1"), false);
        }
        if args.submodules {
            push_param(&mut uri, b"submodules", Some(b"1"), false);
        }
        uri
    }

    pub(super) fn fetch_git_transport_url(args: &FetchGitArguments) -> &[u8] {
        args.transport_url.as_deref().unwrap_or(&args.url)
    }

    pub(super) fn fetch_git_url_has_query(url: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(url) else {
            return false;
        };
        Url::parse(text).is_ok_and(|url| url.query().is_some())
    }

    pub(super) fn check_fetch_git_access(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Restricted
            && !self.options.uri_is_allowed(canonical_uri)
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchGitAccessDenied {
                    id,
                    url: canonical_uri.to_vec(),
                    mode: EvalMode::Restricted,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn fetch_git_temp_dir(
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<PathBuf, TreeWalkError> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..128 {
            let index = FETCH_GIT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("aos-nix-fetch-git-{pid}-{index}"));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(Self::fetch_git_error(id, span, url, source)),
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGit {
                id,
                url: url.to_vec(),
                message: "could not allocate a unique temporary checkout directory".to_owned(),
            },
            span,
        ))
    }

    pub(super) fn fetch_git_local_worktree_path(url: &[u8]) -> Option<PathBuf> {
        let text = std::str::from_utf8(url).ok()?;
        if let Ok(parsed) = Url::parse(text)
            && parsed.scheme() == "file"
        {
            return parsed.to_file_path().ok();
        }
        let path = Path::new(text);
        path.is_absolute().then(|| path.to_path_buf())
    }

    pub(super) fn fetch_git_dirty_status(
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        repo: &git2::Repository,
    ) -> Result<(bool, BTreeSet<Vec<u8>>), TreeWalkError> {
        let mut options = git2::StatusOptions::new();
        options
            .show(git2::StatusShow::IndexAndWorkdir)
            .include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(true)
            .recurse_ignored_dirs(true)
            .update_index(true);
        let statuses = repo
            .statuses(Some(&mut options))
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let mut dirty = false;
        let mut excluded_paths = BTreeSet::new();
        for entry in statuses.iter() {
            let status = entry.status();
            let path = entry.path_bytes().to_vec();
            let excluded = status.is_ignored() || (status.is_wt_new() && !status.is_index_new());
            if excluded {
                excluded_paths.insert(path);
                continue;
            }
            if status != git2::Status::CURRENT {
                dirty = true;
            }
        }
        Ok((dirty, excluded_paths))
    }

    pub(super) fn fetch_git_clone(
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        checkout_dir: &Path,
    ) -> Result<git2::Repository, TreeWalkError> {
        let url = Self::fetch_git_utf8(id, span, &args.url, Self::fetch_git_transport_url(args))?;
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(Self::fetch_git_fetch_options(args.shallow));
        builder.with_checkout(Self::fetch_git_checkout_builder());
        if let Some(reference) = &args.reference {
            let reference = Self::fetch_git_utf8(id, span, &args.url, reference)?;
            if let Some(branch) = Self::fetch_git_clone_branch(id, span, &args.url, reference)? {
                builder.branch(&branch);
            }
        }
        builder
            .clone(url, checkout_dir)
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))
    }

    pub(super) fn fetch_git_reference(
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        repo: &git2::Repository,
    ) -> Result<(), TreeWalkError> {
        let Some(reference) = &args.reference else {
            return Ok(());
        };
        let reference = Self::fetch_git_utf8(id, span, &args.url, reference)?;
        let mut remote = repo
            .find_remote("origin")
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let mut fetch_options = Self::fetch_git_fetch_options(args.shallow);
        remote
            .fetch(&[reference], Some(&mut fetch_options), Some("fetchGit ref"))
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))
    }

    pub(super) fn fetch_git_all_refs(
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        repo: &git2::Repository,
    ) -> Result<(), TreeWalkError> {
        let mut remote = repo
            .find_remote("origin")
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let mut fetch_options = Self::fetch_git_fetch_options(args.shallow);
        remote
            .fetch(
                &["+refs/*:refs/remotes/origin/*"],
                Some(&mut fetch_options),
                Some("fetchGit allRefs"),
            )
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))
    }

    pub(super) fn fetch_git_checkout_commit(
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        repo: &git2::Repository,
    ) -> Result<(String, usize, i64, Vec<u8>), TreeWalkError> {
        let oid = if let Some(rev) = &args.rev {
            let rev = Self::fetch_git_utf8(id, span, &args.url, rev)?;
            git2::Oid::from_str(rev)
                .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?
        } else if let Some(reference) = &args.reference {
            let reference = Self::fetch_git_utf8(id, span, &args.url, reference)?;
            Self::fetch_git_oid_for_reference(id, span, &args.url, repo, reference)?
        } else {
            repo.head()
                .and_then(|head| head.peel_to_commit())
                .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?
                .id()
        };

        let object = repo
            .find_object(oid, Some(git2::ObjectType::Commit))
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let mut checkout = Self::fetch_git_checkout_builder();
        repo.checkout_tree(&object, Some(&mut checkout))
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        repo.set_head_detached(oid)
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        drop(object);

        let commit = repo
            .find_commit(oid)
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let time = commit.time();
        let last_modified = time.seconds();
        let last_modified_date = Self::format_fetch_git_date(id, span, &args.url, last_modified)?;
        drop(commit);

        let mut revwalk = repo
            .revwalk()
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        revwalk
            .push(oid)
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
        let mut rev_count = 0usize;
        for walked in revwalk {
            walked.map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
            rev_count = rev_count.checked_add(1).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FetchGit {
                        id,
                        url: args.url.clone(),
                        message: "revision count overflowed usize".to_owned(),
                    },
                    span,
                )
            })?;
        }

        Ok((
            oid.to_string(),
            rev_count,
            last_modified,
            last_modified_date,
        ))
    }

    pub(super) fn update_fetch_git_submodules(
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        repo: &git2::Repository,
    ) -> Result<(), TreeWalkError> {
        for mut submodule in repo
            .submodules()
            .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?
        {
            let mut options = git2::SubmoduleUpdateOptions::new();
            options.checkout(Self::fetch_git_checkout_builder());
            // Submodules pin a SPECIFIC recorded commit (the gitlink), which is
            // usually not the tip of any branch. A shallow (`depth(1)`) fetch only
            // retrieves branch tips, so the pinned commit is missing and
            // `submodule.update` fails with "object not found" (e.g. edk2 with
            // `submodules = true; shallow = true;`). Always fetch submodule history
            // in full so the recorded commit is available. This does not affect
            // the `.drv` output: the checked-out tree (and thus its NAR hash and
            // store path) is determined by the recorded commit, not the fetch depth.
            options.fetch(Self::fetch_git_fetch_options(false));
            submodule
                .update(true, Some(&mut options))
                .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
            let sub_repo = submodule
                .open()
                .map_err(|source| Self::fetch_git_error(id, span, &args.url, source))?;
            Self::update_fetch_git_submodules(id, span, args, &sub_repo)?;
        }
        Ok(())
    }

    pub(super) fn fetch_git_fetch_options(shallow: bool) -> git2::FetchOptions<'static> {
        let mut options = git2::FetchOptions::new();
        options.download_tags(git2::AutotagOption::All);
        if shallow {
            options.depth(1);
        }
        options
    }

    pub(super) fn fetch_git_checkout_builder() -> git2::build::CheckoutBuilder<'static> {
        let mut checkout = git2::build::CheckoutBuilder::new();
        checkout.force().remove_untracked(true).update_index(true);
        checkout
    }

    pub(super) fn fetch_git_utf8<'a>(
        id: IrId,
        span: Span,
        url: &[u8],
        bytes: &'a [u8],
    ) -> Result<&'a str, TreeWalkError> {
        std::str::from_utf8(bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchGit {
                    id,
                    url: url.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn fetch_git_clone_branch(
        id: IrId,
        span: Span,
        url: &[u8],
        reference: &str,
    ) -> Result<Option<String>, TreeWalkError> {
        if reference.as_bytes().contains(&0) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchGit {
                    id,
                    url: url.to_vec(),
                    message: "git ref contains NUL byte".to_owned(),
                },
                span,
            ));
        }
        Ok(reference.strip_prefix("refs/heads/").map(ToOwned::to_owned))
    }

    pub(super) fn fetch_git_oid_for_reference(
        id: IrId,
        span: Span,
        url: &[u8],
        repo: &git2::Repository,
        reference: &str,
    ) -> Result<git2::Oid, TreeWalkError> {
        match repo
            .revparse_single(reference)
            .and_then(|object| object.peel_to_commit())
        {
            Ok(commit) => Ok(commit.id()),
            Err(reference_error) => match repo
                .revparse_single("FETCH_HEAD")
                .and_then(|object| object.peel_to_commit())
            {
                Ok(commit) => Ok(commit.id()),
                Err(fetch_head_error) => Err(Self::fetch_git_error(
                    id,
                    span,
                    url,
                    format!(
                        "could not resolve git ref {reference:?}: {reference_error}; FETCH_HEAD fallback failed: {fetch_head_error}"
                    ),
                )),
            },
        }
    }

    pub(super) fn format_fetch_git_date(
        id: IrId,
        span: Span,
        _url: &[u8],
        seconds: i64,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let days = seconds.div_euclid(86_400);
        let seconds_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = Self::civil_date_from_unix_days(days);
        let hour = seconds_of_day / 3_600;
        let minute = (seconds_of_day % 3_600) / 60;
        let second = seconds_of_day % 60;
        let formatted = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}");
        Self::copy_bytes_for_node(id, span, formatted.as_bytes())
    }

    pub(super) fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = mp + if mp < 10 { 3 } else { -9 };
        if month <= 2 {
            year += 1;
        }
        (year, month, day)
    }

    pub(super) fn alloc_fetch_git_result(
        &mut self,
        id: IrId,
        span: Span,
        result: FetchGitResult,
    ) -> Result<Value, TreeWalkError> {
        let out_path_symbol = self.intern_builtin_attr_symbol(id, OUT_PATH_ATTR, span)?;
        let rev_symbol = self.intern_builtin_attr_symbol(id, REV_ATTR, span)?;
        let short_rev_symbol = self.intern_builtin_attr_symbol(id, SHORT_REV_ATTR, span)?;
        let dirty_rev_symbol = self.intern_builtin_attr_symbol(id, DIRTY_REV_ATTR, span)?;
        let dirty_short_rev_symbol =
            self.intern_builtin_attr_symbol(id, DIRTY_SHORT_REV_ATTR, span)?;
        let rev_count_symbol = self.intern_builtin_attr_symbol(id, REV_COUNT_ATTR, span)?;
        let last_modified_symbol = self.intern_builtin_attr_symbol(id, LAST_MODIFIED_ATTR, span)?;
        let last_modified_date_symbol =
            self.intern_builtin_attr_symbol(id, LAST_MODIFIED_DATE_ATTR, span)?;
        let nar_hash_symbol = self.intern_builtin_attr_symbol(id, NAR_HASH_ATTR, span)?;
        let submodules_symbol = self.intern_builtin_attr_symbol(id, SUBMODULES_ATTR, span)?;

        let rev_count = i64::try_from(result.rev_count).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchGit {
                    id,
                    url: Vec::new(),
                    message: "revision count does not fit in Nix int".to_owned(),
                },
                span,
            )
        })?;
        let mut entries = Vec::new();
        entries.push(AttrEntry::new(
            last_modified_symbol,
            Value::int(result.last_modified),
        ));
        let last_modified_date = self.alloc_static_string_with_attr_entry_roots(
            id,
            span,
            &mut entries,
            &result.last_modified_date,
        )?;
        entries.push(AttrEntry::new(
            last_modified_date_symbol,
            last_modified_date,
        ));
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
        let rev = self.alloc_static_string_with_attr_entry_roots(
            id,
            span,
            &mut entries,
            result.rev.as_bytes(),
        )?;
        entries.push(AttrEntry::new(rev_symbol, rev));
        entries.push(AttrEntry::new(rev_count_symbol, Value::int(rev_count)));
        let short_rev_len = result.rev.len().min(7);
        let short_rev = self.alloc_static_string_with_attr_entry_roots(
            id,
            span,
            &mut entries,
            &result.rev.as_bytes()[..short_rev_len],
        )?;
        entries.push(AttrEntry::new(short_rev_symbol, short_rev));
        entries.push(AttrEntry::new(
            submodules_symbol,
            Value::bool(result.submodules),
        ));
        if let Some(dirty_rev) = result.dirty_rev {
            let dirty_rev = self.alloc_static_string_with_attr_entry_roots(
                id,
                span,
                &mut entries,
                dirty_rev.as_bytes(),
            )?;
            entries.push(AttrEntry::new(dirty_rev_symbol, dirty_rev));
        }
        if let Some(dirty_short_rev) = result.dirty_short_rev {
            let dirty_short_rev = self.alloc_static_string_with_attr_entry_roots(
                id,
                span,
                &mut entries,
                dirty_short_rev.as_bytes(),
            )?;
            entries.push(AttrEntry::new(dirty_short_rev_symbol, dirty_short_rev));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }
}
