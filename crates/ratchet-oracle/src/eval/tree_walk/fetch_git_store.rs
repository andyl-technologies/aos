//! Store materialization for fetched git worktrees: writing checkouts into
//! the Nix store directly or, when the store is not writable, registering
//! them through the daemon (`nix-store --add-fixed`).

use super::*;

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
            Ok(()) => Ok(()),
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
        self.validate_fetch_git_store_path_digest(id, span, url, store_path, digest)
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
        if actual.as_slice() == expected.as_bytes() {
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchGitHashMismatch {
                id,
                url: url.to_vec(),
                expected: expected.as_bytes().to_vec(),
                actual: actual.to_vec(),
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
}
