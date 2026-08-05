//! Owned filesystem path lifecycle helpers for cache roots.
//!
//! Cache roots often own a small set of directories and sidecar paths whose
//! lifecycle is coordinated by higher-level schema policy. This module owns the
//! generic filesystem operations for creating those directories and discarding
//! owned paths without following symlinks.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// A set of filesystem paths owned by a cache root.
#[derive(Clone, Debug)]
pub struct OwnedPaths {
    paths: Vec<PathBuf>,
}

impl OwnedPaths {
    /// Creates an owned-path set from `paths`.
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
        }
    }

    /// Returns the owned paths in caller-supplied order.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Ensures every owned path exists as a directory.
    ///
    /// Paths are created in caller-supplied order.
    ///
    /// # Errors
    ///
    /// Returns [`OwnedPathError::CreateDir`] if a directory cannot be created.
    pub fn ensure_dirs(&self) -> Result<(), OwnedPathError> {
        for path in &self.paths {
            fs::create_dir_all(path).map_err(|source| OwnedPathError::CreateDir {
                path: path.clone(),
                source,
            })?;
        }
        Ok(())
    }

    /// Removes every existing owned path.
    ///
    /// Directories are removed recursively. Non-directories, including symlinks,
    /// are removed as files. Missing paths are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`OwnedPathError::Remove`] if metadata cannot be inspected or an
    /// existing path cannot be removed.
    pub fn discard_existing(&self) -> Result<(), OwnedPathError> {
        for path in &self.paths {
            remove_existing(path)?;
        }
        Ok(())
    }
}

/// An owned-path lifecycle operation failed.
#[derive(Debug, Error)]
pub enum OwnedPathError {
    /// An owned directory could not be created.
    #[error("failed to create owned cache directory {path:?}")]
    CreateDir {
        /// The path that could not be created.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// An owned path could not be removed.
    #[error("failed to remove owned cache path {path:?}")]
    Remove {
        /// The path that could not be removed.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
}

fn remove_existing(path: &Path) -> Result<(), OwnedPathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path).map_err(|source| OwnedPathError::Remove {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => fs::remove_file(path).map_err(|source| OwnedPathError::Remove {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(OwnedPathError::Remove {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let nonce = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ratchet-cache-owned-paths-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn owned_paths_ensure_dirs_creates_all_directories() {
        let root = temp_path("ensure-dirs");
        let paths = OwnedPaths::new([root.join("nodes"), root.join("values"), root.join("files")]);

        paths.ensure_dirs().expect("directories create");

        for path in paths.paths() {
            assert!(path.is_dir());
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owned_paths_discard_existing_removes_directories_and_files() {
        let root = temp_path("discard");
        let dir = root.join("dir");
        let file = root.join("file");
        fs::create_dir_all(dir.join("nested")).expect("nested dir creates");
        fs::write(&file, b"payload").expect("file writes");
        let paths = OwnedPaths::new([dir.clone(), file.clone(), root.join("missing")]);

        paths.discard_existing().expect("paths discard");

        assert!(!dir.exists());
        assert!(!file.exists());
        assert!(!root.join("missing").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owned_paths_discard_existing_removes_symlink_without_following() {
        let root = temp_path("discard-symlink");
        let target = root.join("target");
        let link = root.join("link");
        fs::create_dir_all(&target).expect("target creates");
        fs::write(target.join("keep"), b"payload").expect("target file writes");
        std::os::unix::fs::symlink(&target, &link).expect("symlink creates");
        let paths = OwnedPaths::new([link.clone()]);

        paths.discard_existing().expect("link discards");

        assert!(!link.exists());
        assert!(target.join("keep").is_file());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owned_paths_discard_existing_ignores_missing_paths() {
        let path = temp_path("missing");
        let paths = OwnedPaths::new([path]);

        paths.discard_existing().expect("missing path is ignored");
    }
}
