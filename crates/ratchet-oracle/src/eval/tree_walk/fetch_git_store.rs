//! Store materialization and locked-input reuse for fetched git worktrees.
//!
//! Materialization writes checkouts into the Nix store directly or, when the
//! store is not writable, registers them through the daemon
//! (`nix-store --add-fixed --recursive sha256`). A successful direct write
//! into the default `/nix/store` is additionally registered through the same
//! daemon command on a best-effort basis, so the store's path database agrees
//! with the on-disk tree wherever a daemon is reachable.
//!
//! # Locked-input reuse records
//!
//! A `fetchGit` call pinned to a `rev` is fully locked: the commit hash
//! determines the exported tree, so the NAR digest, store path, `revCount`,
//! and `lastModified` observed by one evaluation hold for every later one.
//! C++ Nix memoizes exactly this in its fetcher cache and answers later calls
//! with an `isValidPath` lookup instead of a clone; without an equivalent the
//! native evaluator re-cloned multi-gigabyte submodule trees (edk2,
//! firecracker) on every evaluation. The native evaluator mirrors C++ Nix
//! with one small JSON record per locked input, stored under the reuse-record
//! directory (see [`TreeWalk::fetch_git_reuse_record_dir`]) in a file named
//! by the SHA-256 of the canonical key:
//!
//! ```json
//! {
//!   "version": 1,
//!   "storeDir": "/nix/store",
//!   "name": "source",
//!   "rev": "5c2254d6cf4f32a668d0d8e57ba20bebad9d4fba",
//!   "submodules": false,
//!   "exportIgnore": true,
//!   "shallow": false,
//!   "storePath": "/nix/store/...-source",
//!   "revCount": 3,
//!   "lastModified": 1700000000,
//!   "narHash": "sha256-..."
//! }
//! ```
//!
//! The key covers everything that shapes the exported tree or its observable
//! metadata: the store directory, store name, canonical lowercase rev, and
//! the `submodules`/`exportIgnore`/`shallow` flags. Like C++ Nix's fetcher
//! cache it deliberately excludes the URL — a commit hash pins the same
//! content from any remote. Records are advisory: a hit is honored only after
//! the store path (recomputed from the recorded NAR digest, never trusted
//! verbatim) exists and is either valid in the store's path database or
//! re-hashes to the recorded digest; anything else falls through to a full
//! fetch, which rewrites the record. Writes go through a temp file plus
//! `rename`, so concurrent evaluators race benignly: both fetch, both write
//! identical bytes, and the last rename wins.

use super::*;

/// Environment variable controlling the locked-`fetchGit` reuse-record
/// directory: unset selects the default cache location, `""`/`"0"` disables
/// reuse records, and any other value is used as the directory path.
const FETCH_GIT_REUSE_CACHE_ENV: &[u8] = b"AOS_NIX_FETCH_GIT_CACHE";

/// Schema version of the on-disk reuse record (bumped on format changes so
/// stale records are ignored rather than misread).
const FETCH_GIT_REUSE_RECORD_VERSION: u64 = 1;

impl TreeWalk {
    pub(super) fn materialize_fetch_git_store_path(
        &mut self,
        id: IrId,
        span: Span,
        url: &[u8],
        name: &str,
        source: &Path,
        store_path: &[u8],
        digest: NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        let target = Path::new(OsStr::from_bytes(store_path));
        if target.exists() {
            return self.validate_fetch_git_store_path_digest(id, span, url, store_path, digest);
        }
        let Some(parent) = target.parent() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchGit {
                    id,
                    url: url.to_vec(),
                    message: format!("store path has no parent: {}", target.display()),
                },
                span,
            ));
        };
        if let Err(source_error) = fs::create_dir_all(parent) {
            if Self::is_store_write_denied(&source_error) {
                return self.register_fetch_git_via_daemon(
                    id, span, url, name, source, store_path, digest,
                );
            }
            return Err(Self::fetch_git_error(id, span, url, source_error));
        }

        let temp_target = Self::fetch_git_temp_store_path(id, span, url, parent, target)?;
        if let Err(source_error) = Self::copy_fetch_tarball_tree(source, &temp_target) {
            Self::remove_fetch_tarball_temp_path(&temp_target);
            if Self::is_store_write_denied(&source_error) {
                return self.register_fetch_git_via_daemon(
                    id, span, url, name, source, store_path, digest,
                );
            }
            return Err(Self::fetch_git_error(id, span, url, source_error));
        }
        match fs::rename(&temp_target, target) {
            Ok(()) => {
                self.register_direct_fetch_git_store_write(id, span, url, name, target, store_path);
                Ok(())
            }
            Err(source_error) => {
                Self::remove_fetch_tarball_temp_path(&temp_target);
                if target.exists() {
                    self.validate_fetch_git_store_path_digest(id, span, url, store_path, digest)?;
                    return Ok(());
                }
                if Self::is_store_write_denied(&source_error) {
                    return self.register_fetch_git_via_daemon(
                        id, span, url, name, source, store_path, digest,
                    );
                }
                Err(Self::fetch_git_error(id, span, url, source_error))
            }
        }
    }

    /// Reports whether `error` indicates the Nix store could not be written
    /// directly — the store is conventionally root-owned and only mutable
    /// through the daemon, so unprivileged evaluators see `EACCES`/`EPERM`
    /// (mapped to [`io::ErrorKind::PermissionDenied`]) or `EROFS` (raw os error
    /// 30, which lacks a stable [`io::ErrorKind`] across toolchains).
    fn is_store_write_denied(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::PermissionDenied
            || matches!(error.raw_os_error(), Some(libc_erofs) if libc_erofs == 30)
    }

    /// Registers a fetched git worktree in the store through the Nix daemon when
    /// a direct write is denied.
    ///
    /// This mirrors C++ Nix, which stages the checkout under a user-writable
    /// cache and inserts it via the daemon's `AddToStore` rather than writing
    /// `/nix/store` directly. The filtered tree is copied under a staging
    /// directory named exactly `name`, so `nix-store --add-fixed --recursive
    /// sha256` derives the same `/nix/store/<hash>-<name>` path that
    /// [`Self::fetch_git_store_path_from_digest`] computed; the registered path
    /// is asserted equal to `store_path` and its NAR digest re-validated.
    fn register_fetch_git_via_daemon(
        &mut self,
        id: IrId,
        span: Span,
        url: &[u8],
        name: &str,
        source: &Path,
        store_path: &[u8],
        digest: NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        let staging = Self::fetch_git_add_staging_dir(id, span, url)?;
        let staged = staging.join(name);
        let outcome = (|| {
            Self::copy_fetch_tarball_tree(source, &staged)
                .map_err(|source_error| Self::fetch_git_error(id, span, url, source_error))?;
            // `nix-store --add-fixed` rejects paths whose components include a
            // symlink (e.g. macOS resolves `$TMPDIR` under `/var` -> `/private/var`),
            // so resolve the staged path; canonicalization preserves the final
            // `name` component and never alters the NAR digest.
            let staged = fs::canonicalize(&staged)
                .map_err(|source_error| Self::fetch_git_error(id, span, url, source_error))?;
            let registered = Self::nix_store_add_fixed(&staged)
                .map_err(|source_error| Self::fetch_git_error(id, span, url, source_error))?;
            if registered.as_os_str().as_bytes() != store_path {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::FetchGit {
                        id,
                        url: url.to_vec(),
                        message: format!(
                            "nix-store registered {} but expected {}",
                            registered.display(),
                            String::from_utf8_lossy(store_path),
                        ),
                    },
                    span,
                ));
            }
            Ok(())
        })();
        let _ = fs::remove_dir_all(&staging);
        outcome?;
        self.store_validity_checker.record_valid(store_path);
        self.validate_fetch_git_store_path_digest(id, span, url, store_path, digest)
    }

    /// Registers a directly-written fetchGit store path with the daemon on a
    /// best-effort basis.
    ///
    /// A direct filesystem write into the default store (possible for
    /// single-user installs or root) leaves the path absent from the store's
    /// path database, so `nix-store --check-validity` — and therefore the
    /// locked-input reuse fast path — reports it invalid forever. This stages
    /// a copy of the just-written tree and registers it through the same
    /// `nix-store --add-fixed --recursive sha256` command the write-denied
    /// path uses; the daemon recomputes the NAR hash from the staged content,
    /// so the registration is honest by construction. All failures (most
    /// commonly: no daemon is running, which is the normal state on hosts
    /// where the store is directly writable) are swallowed — the write itself
    /// already succeeded, and reuse then falls back to NAR re-hashing.
    fn register_direct_fetch_git_store_write(
        &mut self,
        id: IrId,
        span: Span,
        url: &[u8],
        name: &str,
        target: &Path,
        store_path: &[u8],
    ) {
        if self.options.store_dir() != DEFAULT_STORE_DIR {
            return;
        }
        if self.nix_store_reports_valid_path(store_path) {
            return;
        }
        let Ok(staging) = Self::fetch_git_add_staging_dir(id, span, url) else {
            return;
        };
        let staged = staging.join(name);
        let outcome = (|| -> io::Result<()> {
            Self::copy_fetch_tarball_tree(target, &staged)?;
            let staged = fs::canonicalize(&staged)?;
            let registered = Self::nix_store_add_fixed(&staged)?;
            if registered.as_os_str().as_bytes() != store_path {
                return Err(io::Error::other(
                    "nix-store --add-fixed registered an unexpected path",
                ));
            }
            Ok(())
        })();
        let _ = fs::remove_dir_all(&staging);
        if outcome.is_ok() {
            self.store_validity_checker.record_valid(store_path);
        }
    }

    /// Allocates a unique staging directory outside the store for daemon-side
    /// registration of a fetched git worktree.
    fn fetch_git_add_staging_dir(
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<PathBuf, TreeWalkError> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..128 {
            let index = FETCH_GIT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("aos-nix-fetch-git-add-{pid}-{index}"));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(source_error) if source_error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(source_error) => {
                    return Err(Self::fetch_git_error(id, span, url, source_error));
                }
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGit {
                id,
                url: url.to_vec(),
                message: "could not allocate a unique temporary staging directory".to_owned(),
            },
            span,
        ))
    }

    /// Registers `path` as a recursive (NAR) fixed-output store object via the
    /// Nix daemon and returns the resulting store path.
    ///
    /// The hardened environment matches [`Self::nix_store_validity_command`] so
    /// the subprocess never re-enters the native evaluator or reads ambient Nix
    /// configuration.
    fn nix_store_add_fixed(path: &Path) -> io::Result<PathBuf> {
        let output = std::process::Command::new("nix-store")
            .args(["--store", "daemon", "--add-fixed", "--recursive", "sha256"])
            .arg(path)
            .env("HOME", "/var/empty")
            .env("XDG_CONFIG_HOME", "/var/empty/.config")
            .env("XDG_CONFIG_DIRS", "/var/empty")
            .env("NIX_USER_CONF_FILES", "")
            .env_remove("AOS_NIX_NATIVE")
            .env_remove("AOS_NIX_NATIVE_VERIFY")
            .env_remove("NIX_REMOTE")
            .env_remove("NIX_CONFIG")
            .env_remove("NIX_CONF_DIR")
            .env_remove("NIX_STORE_DIR")
            .env_remove("NIX_STATE_DIR")
            .env_remove("NIX_LOG_DIR")
            .stderr(std::process::Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "nix-store --add-fixed exited with {}",
                output.status
            )));
        }
        let registered = String::from_utf8(output.stdout)
            .map_err(|_| io::Error::other("nix-store --add-fixed emitted a non-UTF-8 path"))?;
        Ok(PathBuf::from(registered.trim()))
    }

    pub(super) fn validate_fetch_git_store_path_digest(
        &mut self,
        id: IrId,
        span: Span,
        url: &[u8],
        store_path: &[u8],
        expected: NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        let actual =
            self.source_path_nar_sha256(id, span, Path::new(OsStr::from_bytes(store_path)), None)?;
        if actual == expected {
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGitHashMismatch {
                id,
                url: url.to_vec(),
                expected: expected.as_bytes().to_vec(),
                actual: actual.as_bytes().to_vec(),
            },
            span,
        ))
    }

    pub(super) fn fetch_git_temp_store_path(
        id: IrId,
        span: Span,
        url: &[u8],
        parent: &Path,
        target: &Path,
    ) -> Result<PathBuf, TreeWalkError> {
        let name = target.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchGit {
                    id,
                    url: url.to_vec(),
                    message: format!("store path has no file name: {}", target.display()),
                },
                span,
            )
        })?;
        let pid = std::process::id();
        for _ in 0..128 {
            let index = FETCH_GIT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp = parent.join(format!(".{name}.tmp-{pid}-{index}"));
            if !temp.exists() {
                return Ok(temp);
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGit {
                id,
                url: url.to_vec(),
                message: "could not allocate a unique temporary store path".to_owned(),
            },
            span,
        ))
    }

    /// Answers a rev-locked `fetchGit` from its durable reuse record, without
    /// touching the network or libgit2.
    ///
    /// Returns `Ok(None)` — falling through to a full fetch — unless all of
    /// the following hold: the call is pinned to a well-formed 40-hex `rev`,
    /// a reuse-record directory is configured (see
    /// [`Self::fetch_git_reuse_record_dir`]), a record for the canonical key
    /// exists and echoes the key fields, the store path recomputed from the
    /// recorded NAR digest matches the recorded one, and that path exists in
    /// the store and is either valid per the store's path database or NAR
    /// re-hashes to the recorded digest. Malformed or mismatched records are
    /// ignored (and later overwritten by the fetch), never trusted.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] only for failures of the evaluator's own
    /// machinery on the hit path (store-path fingerprinting, NAR hashing of
    /// an existing store path, or date formatting) — a missing or corrupt
    /// record is a miss, not an error.
    pub(super) fn reuse_fetch_git_locked_result(
        &mut self,
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
    ) -> Result<Option<FetchGitResult>, TreeWalkError> {
        let Some(rev) = args.rev.as_deref().and_then(Self::fetch_git_locked_rev) else {
            return Ok(None);
        };
        let Some(record_path) = self.fetch_git_reuse_record_path(id, span, args, &rev)? else {
            return Ok(None);
        };
        let Ok(bytes) = fs::read(&record_path) else {
            return Ok(None);
        };
        let Ok(record) = serde_json::from_slice::<JsonValue>(&bytes) else {
            return Ok(None);
        };
        if !self.fetch_git_reuse_record_matches_key(&record, args, &rev) {
            return Ok(None);
        }
        let Some(nar_hash) = record.get("narHash").and_then(JsonValue::as_str) else {
            return Ok(None);
        };
        let Ok(digest) = self.decode_fetch_tree_nar_hash(id, span, nar_hash.as_bytes()) else {
            return Ok(None);
        };
        let Some(rev_count) = record
            .get("revCount")
            .and_then(JsonValue::as_u64)
            .and_then(|count| usize::try_from(count).ok())
        else {
            return Ok(None);
        };
        let Some(last_modified) = record.get("lastModified").and_then(JsonValue::as_i64) else {
            return Ok(None);
        };

        // Never trust the recorded store path: recompute it from the digest
        // and require the record to agree.
        let out_path =
            self.fetch_git_store_path_from_digest(id, span, &args.url, &args.name, digest)?;
        if record
            .get("storePath")
            .and_then(JsonValue::as_str)
            .is_none_or(|recorded| recorded.as_bytes() != out_path.as_slice())
        {
            return Ok(None);
        }
        if !self.fetch_git_can_reuse_store_path(id, span, &out_path, digest)? {
            return Ok(None);
        }

        let nar_hash = Self::encode_convert_hash_digest(
            id,
            span,
            ConvertHashFormat::Sri,
            &NixHashDigest::from_nix_sha256(digest),
        )?;
        let last_modified_date = Self::format_fetch_git_date(id, span, &args.url, last_modified)?;
        Ok(Some(FetchGitResult {
            out_path,
            rev,
            dirty_rev: None,
            dirty_short_rev: None,
            rev_count,
            last_modified,
            last_modified_date,
            nar_hash,
            submodules: args.submodules,
        }))
    }

    /// Writes the reuse record for a freshly fetched, rev-resolved worktree.
    ///
    /// Best-effort by design: any failure (no record directory configured, a
    /// non-UTF-8 store dir or path, an I/O error) leaves the evaluation
    /// result untouched and simply forfeits reuse for a later run. Dirty
    /// local-worktree results never reach this method; results are keyed by
    /// the *resolved* rev, so an unpinned `fetchGit { url, ref }` fetch also
    /// seeds the record a later rev-pinned call can hit.
    pub(super) fn record_fetch_git_locked_result(
        &self,
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        result: &FetchGitResult,
    ) {
        if result.dirty_rev.is_some() || result.dirty_short_rev.is_some() {
            return;
        }
        let Some(rev) = Self::fetch_git_locked_rev(result.rev.as_bytes()) else {
            return;
        };
        let Ok(Some(record_path)) = self.fetch_git_reuse_record_path(id, span, args, &rev) else {
            return;
        };
        let (Ok(store_dir), Ok(store_path), Ok(nar_hash)) = (
            std::str::from_utf8(self.options.store_dir()),
            std::str::from_utf8(&result.out_path),
            std::str::from_utf8(&result.nar_hash),
        ) else {
            return;
        };
        let Ok(rev_count) = u64::try_from(result.rev_count) else {
            return;
        };
        let record = serde_json::json!({
            "version": FETCH_GIT_REUSE_RECORD_VERSION,
            "storeDir": store_dir,
            "name": args.name,
            "rev": rev,
            "submodules": args.submodules,
            "exportIgnore": args.export_ignore,
            "shallow": args.shallow,
            "storePath": store_path,
            "revCount": rev_count,
            "lastModified": result.last_modified,
            "narHash": nar_hash,
        });
        let Ok(bytes) = serde_json::to_vec(&record) else {
            return;
        };
        let Some(parent) = record_path.parent() else {
            return;
        };
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        let temp = parent.join(format!(
            ".{}.tmp-{}-{}",
            record_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            std::process::id(),
            FETCH_GIT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        if fs::write(&temp, &bytes).is_err() {
            let _ = fs::remove_file(&temp);
            return;
        }
        if fs::rename(&temp, &record_path).is_err() {
            let _ = fs::remove_file(&temp);
        }
    }

    /// Reports whether an existing store path can stand in for a locked
    /// fetchGit result with the given expected NAR digest.
    ///
    /// Mirrors the fetchTarball reuse policy: a path that the default store's
    /// path database calls valid is trusted outright (the cheap path on
    /// daemon-managed hosts); otherwise the tree is NAR re-hashed and must
    /// match the expected digest exactly.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] when NAR-hashing the existing path fails
    /// (for example an unreadable entry).
    fn fetch_git_can_reuse_store_path(
        &mut self,
        id: IrId,
        span: Span,
        store_path: &[u8],
        digest: NixSha256Digest,
    ) -> Result<bool, TreeWalkError> {
        if !Path::new(OsStr::from_bytes(store_path)).exists() {
            return Ok(false);
        }
        if self.can_trust_existing_fetch_tarball_store_path(store_path) {
            return Ok(true);
        }
        self.fetch_tarball_store_path_matches_digest(id, span, store_path, digest)
    }

    /// Canonicalizes a rev into the locked lowercase 40-hex form, or `None`
    /// for anything that is not a full commit hash.
    fn fetch_git_locked_rev(rev: &[u8]) -> Option<String> {
        if rev.len() != 40 || !rev.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        String::from_utf8(rev.to_ascii_lowercase()).ok()
    }

    /// Resolves the reuse-record directory, if reuse records are enabled.
    ///
    /// `AOS_NIX_FETCH_GIT_CACHE` (from the evaluator's configured
    /// environment) takes precedence: empty or `0` disables records, any
    /// other value is the directory. Otherwise the default follows the C++
    /// Nix fetcher-cache convention: `$XDG_CACHE_HOME/aos-nix/fetch-git-v1`,
    /// falling back to `$HOME/.cache/aos-nix/fetch-git-v1`. Without any of
    /// these (as in hermetic tests, which configure no environment) records
    /// are disabled.
    pub(super) fn fetch_git_reuse_record_dir(&self) -> Option<PathBuf> {
        if let Some(value) = self.options.env_var(FETCH_GIT_REUSE_CACHE_ENV) {
            let trimmed = value.trim_ascii();
            if trimmed.is_empty() || trimmed == b"0" {
                return None;
            }
            return Some(PathBuf::from(OsStr::from_bytes(trimmed)));
        }
        if let Some(xdg) = self.options.env_var(b"XDG_CACHE_HOME")
            && xdg.starts_with(b"/")
        {
            return Some(Path::new(OsStr::from_bytes(xdg)).join("aos-nix/fetch-git-v1"));
        }
        if let Some(home) = self.options.env_var(b"HOME")
            && home.starts_with(b"/")
        {
            return Some(Path::new(OsStr::from_bytes(home)).join(".cache/aos-nix/fetch-git-v1"));
        }
        None
    }

    /// Computes the reuse-record file path for a locked fetchGit key, or
    /// `None` when reuse records are disabled.
    ///
    /// The file name is the lowercase SHA-256 hex of the canonical key bytes,
    /// which cover the store directory, store name, canonical rev, and the
    /// `submodules`/`exportIgnore`/`shallow` flags (see the module docs).
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if hex-encoding the key digest fails to
    /// allocate.
    fn fetch_git_reuse_record_path(
        &self,
        id: IrId,
        span: Span,
        args: &FetchGitArguments,
        rev: &str,
    ) -> Result<Option<PathBuf>, TreeWalkError> {
        let Some(dir) = self.fetch_git_reuse_record_dir() else {
            return Ok(None);
        };
        let mut key = Vec::new();
        key.extend_from_slice(b"aos-nix-fetch-git-reuse:1\nstoreDir:");
        key.extend_from_slice(self.options.store_dir());
        key.extend_from_slice(b"\nname:");
        key.extend_from_slice(args.name.as_bytes());
        key.extend_from_slice(b"\nrev:");
        key.extend_from_slice(rev.as_bytes());
        key.extend_from_slice(
            format!(
                "\nsubmodules:{}\nexportIgnore:{}\nshallow:{}\n",
                u8::from(args.submodules),
                u8::from(args.export_ignore),
                u8::from(args.shallow),
            )
            .as_bytes(),
        );
        let digest = Self::nix_sha256_digest(&key);
        let hex = Self::lower_hex_bytes(id, span, digest.as_bytes())?;
        let mut file_name = String::from_utf8(hex).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchGit {
                    id,
                    url: args.url.clone(),
                    message: "reuse record key digest is not valid UTF-8".to_owned(),
                },
                span,
            )
        })?;
        file_name.push_str(".json");
        Ok(Some(dir.join(file_name)))
    }

    /// Reports whether a parsed reuse record echoes the canonical key it was
    /// looked up under, guarding against hash collisions and corruption.
    fn fetch_git_reuse_record_matches_key(
        &self,
        record: &JsonValue,
        args: &FetchGitArguments,
        rev: &str,
    ) -> bool {
        record.get("version").and_then(JsonValue::as_u64)
            == Some(FETCH_GIT_REUSE_RECORD_VERSION)
            && record
                .get("storeDir")
                .and_then(JsonValue::as_str)
                .is_some_and(|dir| dir.as_bytes() == self.options.store_dir())
            && record.get("name").and_then(JsonValue::as_str) == Some(args.name.as_str())
            && record.get("rev").and_then(JsonValue::as_str) == Some(rev)
            && record.get("submodules").and_then(JsonValue::as_bool) == Some(args.submodules)
            && record.get("exportIgnore").and_then(JsonValue::as_bool) == Some(args.export_ignore)
            && record.get("shallow").and_then(JsonValue::as_bool) == Some(args.shallow)
    }
}
