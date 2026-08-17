//! Fetch-tarball store-path materialization helpers.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn materialize_fetch_tarball_store_path(
        &mut self,
        id: IrId,
        span: Span,
        url: &[u8],
        source: &Path,
        store_path: &[u8],
        digest: NixSha256Digest,
    ) -> Result<(), TreeWalkError> {
        let target = Path::new(OsStr::from_bytes(store_path));
        if target.exists() {
            return self
                .validate_fetch_tarball_store_path_digest(id, span, url, store_path, digest);
        }
        let Some(parent) = target.parent() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTarball {
                    id,
                    url: url.to_vec(),
                    message: format!("store path has no parent: {}", target.display()),
                },
                span,
            ));
        };
        fs::create_dir_all(parent)
            .map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;

        let temp_target = Self::fetch_tarball_temp_store_path(id, span, url, parent, target)?;
        if let Err(source) = Self::copy_fetch_tarball_tree(source, &temp_target) {
            Self::remove_fetch_tarball_temp_path(&temp_target);
            return Err(Self::fetch_tarball_error(id, span, url, source));
        }
        match fs::rename(&temp_target, target) {
            Ok(()) => Ok(()),
            Err(source) => {
                Self::remove_fetch_tarball_temp_path(&temp_target);
                if target.exists() {
                    self.validate_fetch_tarball_store_path_digest(
                        id, span, url, store_path, digest,
                    )?;
                    return Ok(());
                }
                Err(Self::fetch_tarball_error(id, span, url, source))
            }
        }
    }

    pub(in crate::eval::tree_walk) fn fetch_tarball_store_path_matches_digest(
        &mut self,
        id: IrId,
        span: Span,
        store_path: &[u8],
        expected: NixSha256Digest,
    ) -> Result<bool, TreeWalkError> {
        let actual =
            self.source_path_nar_sha256(id, span, Path::new(OsStr::from_bytes(store_path)), None)?;
        Ok(actual == expected)
    }

    pub(in crate::eval::tree_walk) fn validate_fetch_tarball_store_path_digest(
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
            TreeWalkErrorKind::FetchTarballHashMismatch {
                id,
                url: url.to_vec(),
                expected: expected.as_bytes().to_vec(),
                actual: actual.as_bytes().to_vec(),
            },
            span,
        ))
    }

    pub(in crate::eval::tree_walk) fn fetch_tarball_temp_store_path(
        id: IrId,
        span: Span,
        url: &[u8],
        parent: &Path,
        target: &Path,
    ) -> Result<PathBuf, TreeWalkError> {
        let name = target.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchTarball {
                    id,
                    url: url.to_vec(),
                    message: format!("store path has no file name: {}", target.display()),
                },
                span,
            )
        })?;
        let pid = std::process::id();
        for _ in 0..128 {
            let index = FETCH_TARBALL_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp = parent.join(format!(".{name}.tmp-{pid}-{index}"));
            if !temp.exists() {
                return Ok(temp);
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchTarball {
                id,
                url: url.to_vec(),
                message: "could not allocate a unique temporary store path".to_owned(),
            },
            span,
        ))
    }

    pub(in crate::eval::tree_walk) fn remove_fetch_tarball_temp_path(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_dir() {
            let _ = fs::remove_dir_all(path);
        } else {
            let _ = fs::remove_file(path);
        }
    }

    pub(in crate::eval::tree_walk) fn copy_fetch_tarball_tree(
        source: &Path,
        target: &Path,
    ) -> io::Result<()> {
        let metadata = fs::symlink_metadata(source)?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            fs::create_dir(target)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                Self::copy_fetch_tarball_tree(&entry.path(), &target.join(entry.file_name()))?;
            }
            fs::set_permissions(target, metadata.permissions())?;
            return Ok(());
        }
        if file_type.is_file() {
            fs::copy(source, target)?;
            fs::set_permissions(target, metadata.permissions())?;
            return Ok(());
        }
        if file_type.is_symlink() {
            let link = fs::read_link(source)?;
            std::os::unix::fs::symlink(link, target)?;
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported tarball entry type",
        ))
    }

    pub(in crate::eval::tree_walk) fn fetch_tarball_error(
        id: IrId,
        span: Span,
        url: &[u8],
        source: impl std::fmt::Display,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::FetchTarball {
                id,
                url: url.to_vec(),
                message: source.to_string(),
            },
            span,
        )
    }
}
