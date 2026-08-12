//! Staged file replacement helpers for cache maintenance.
//!
//! Repack and compaction operations often write replacement files to staging
//! paths before swapping several current files into place. This module owns the
//! generic filesystem choreography for that swap: stale backups are removed,
//! current targets are moved to backups, staged files are installed, and
//! ordinary failures trigger best-effort backup restoration.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// One staged file replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReplacement {
    target: PathBuf,
    staged: PathBuf,
    backup: PathBuf,
}

impl FileReplacement {
    /// Creates a staged replacement for `target`.
    pub fn new(target: PathBuf, staged: PathBuf, backup: PathBuf) -> Self {
        Self {
            target,
            staged,
            backup,
        }
    }

    /// Returns the current file path that will be replaced.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Returns the staged replacement path.
    pub fn staged(&self) -> &Path {
        &self.staged
    }

    /// Returns the backup path used while replacing the target.
    pub fn backup(&self) -> &Path {
        &self.backup
    }
}

/// An ordered set of staged file replacements.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileReplacementSet {
    replacements: Vec<FileReplacement>,
}

impl FileReplacementSet {
    /// Creates a replacement set from `replacements`.
    pub fn new(replacements: impl IntoIterator<Item = FileReplacement>) -> Self {
        Self {
            replacements: replacements.into_iter().collect(),
        }
    }

    /// Returns replacements in caller-supplied order.
    pub fn replacements(&self) -> &[FileReplacement] {
        &self.replacements
    }

    /// Replaces every target with its staged file.
    ///
    /// Replacement order is caller-supplied order. If an operation fails after
    /// one or more targets have been moved to backup paths, earlier backups are
    /// restored in caller-supplied order before returning the error. Staged and
    /// backup cleanup after success or failure is best-effort.
    ///
    /// # Errors
    ///
    /// Returns [`FileReplacementError`] if a stale backup cannot be removed, a
    /// target cannot be moved to its backup, a staged file cannot be installed,
    /// or a backup cannot be restored after an earlier failure.
    pub fn replace_all(&self) -> Result<(), FileReplacementError> {
        for (index, replacement) in self.replacements.iter().enumerate() {
            if let Err(source) = remove_file_if_exists(&replacement.backup) {
                self.cleanup_staged();
                return Err(FileReplacementError::RemoveBackup {
                    index,
                    path: replacement.backup.clone(),
                    source,
                });
            }
        }

        let mut backed_up = 0;
        for (index, replacement) in self.replacements.iter().enumerate() {
            if let Err(source) = fs::rename(&replacement.target, &replacement.backup) {
                let restore_error = self.restore_backups(backed_up).err();
                self.cleanup_staged();
                if let Some(error) = restore_error {
                    return Err(error);
                }
                return Err(FileReplacementError::BackupTarget {
                    index,
                    target: replacement.target.clone(),
                    backup: replacement.backup.clone(),
                    source,
                });
            }
            backed_up += 1;
        }

        for (index, replacement) in self.replacements.iter().enumerate() {
            if let Err(source) = fs::rename(&replacement.staged, &replacement.target) {
                let restore_error = self.restore_backups(backed_up).err();
                self.cleanup_staged();
                if let Some(error) = restore_error {
                    return Err(error);
                }
                return Err(FileReplacementError::InstallStaged {
                    index,
                    staged: replacement.staged.clone(),
                    target: replacement.target.clone(),
                    source,
                });
            }
        }

        self.cleanup_staged();
        self.cleanup_backups();
        Ok(())
    }

    /// Removes staged files, ignoring missing files and other cleanup errors.
    pub fn cleanup_staged(&self) {
        for replacement in &self.replacements {
            let _ = fs::remove_file(&replacement.staged);
        }
    }

    /// Removes backup files, ignoring missing files and other cleanup errors.
    pub fn cleanup_backups(&self) {
        for replacement in &self.replacements {
            let _ = fs::remove_file(&replacement.backup);
        }
    }

    fn restore_backups(&self, count: usize) -> Result<(), FileReplacementError> {
        for (index, replacement) in self.replacements.iter().take(count).enumerate() {
            if let Err(source) = remove_file_if_exists(&replacement.target) {
                return Err(FileReplacementError::RemoveTargetBeforeRestore {
                    index,
                    target: replacement.target.clone(),
                    backup: replacement.backup.clone(),
                    source,
                });
            }
            fs::rename(&replacement.backup, &replacement.target).map_err(|source| {
                FileReplacementError::RestoreBackup {
                    index,
                    target: replacement.target.clone(),
                    backup: replacement.backup.clone(),
                    source,
                }
            })?;
        }
        Ok(())
    }
}

/// A staged file replacement operation failed.
#[derive(Debug, Error)]
pub enum FileReplacementError {
    /// A stale backup file could not be removed before replacement.
    #[error("failed to remove stale backup file {path:?} for replacement {index}")]
    RemoveBackup {
        /// The caller-supplied replacement index.
        index: usize,
        /// The backup path that could not be removed.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// A target file could not be moved to its backup path.
    #[error("failed to move target file {target:?} to backup {backup:?} for replacement {index}")]
    BackupTarget {
        /// The caller-supplied replacement index.
        index: usize,
        /// The target path that could not be backed up.
        target: PathBuf,
        /// The backup path that should have received the target.
        backup: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// A staged file could not be moved to its target path.
    #[error("failed to move staged file {staged:?} to target {target:?} for replacement {index}")]
    InstallStaged {
        /// The caller-supplied replacement index.
        index: usize,
        /// The staged path that should have replaced the target.
        staged: PathBuf,
        /// The target path that should have received the staged file.
        target: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// A partially installed target could not be removed before backup restore.
    #[error(
        "failed to remove target file {target:?} before restoring backup {backup:?} for replacement {index}"
    )]
    RemoveTargetBeforeRestore {
        /// The caller-supplied replacement index.
        index: usize,
        /// The target path that could not be removed.
        target: PathBuf,
        /// The backup path that should have been restored.
        backup: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// A backup file could not be restored to its target path.
    #[error(
        "failed to restore backup file {backup:?} to target {target:?} for replacement {index}"
    )]
    RestoreBackup {
        /// The caller-supplied replacement index.
        index: usize,
        /// The target path that should have been restored.
        target: PathBuf,
        /// The backup path that could not be restored.
        backup: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
}

impl FileReplacementError {
    /// Returns the caller-supplied replacement index that failed.
    pub const fn index(&self) -> usize {
        match self {
            Self::RemoveBackup { index, .. }
            | Self::BackupTarget { index, .. }
            | Self::InstallStaged { index, .. }
            | Self::RemoveTargetBeforeRestore { index, .. }
            | Self::RestoreBackup { index, .. } => *index,
        }
    }
}

fn remove_file_if_exists(path: &Path) -> Result<(), io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_root(name: &str) -> PathBuf {
        let nonce = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ratchet-cache-file-replace-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("file writes");
    }

    #[test]
    fn file_replacement_set_replaces_targets_and_removes_backups() {
        let root = temp_root("replace");
        fs::create_dir_all(&root).expect("root creates");
        let first = FileReplacement::new(
            root.join("first"),
            root.join("first.stage"),
            root.join("first.backup"),
        );
        let second = FileReplacement::new(
            root.join("second"),
            root.join("second.stage"),
            root.join("second.backup"),
        );
        write(first.target(), b"old first");
        write(second.target(), b"old second");
        write(first.staged(), b"new first");
        write(second.staged(), b"new second");
        write(first.backup(), b"stale first backup");
        write(second.backup(), b"stale second backup");
        let replacements = FileReplacementSet::new([first.clone(), second.clone()]);

        replacements.replace_all().expect("files replace");

        assert_eq!(fs::read(first.target()).expect("first reads"), b"new first");
        assert_eq!(
            fs::read(second.target()).expect("second reads"),
            b"new second"
        );
        assert!(!first.staged().exists());
        assert!(!second.staged().exists());
        assert!(!first.backup().exists());
        assert!(!second.backup().exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_replacement_set_restores_backups_when_target_backup_fails() {
        let root = temp_root("backup-fails");
        fs::create_dir_all(&root).expect("root creates");
        let first = FileReplacement::new(
            root.join("first"),
            root.join("first.stage"),
            root.join("first.backup"),
        );
        let second = FileReplacement::new(
            root.join("second"),
            root.join("second.stage"),
            root.join("second.backup"),
        );
        write(first.target(), b"old first");
        write(first.staged(), b"new first");
        write(second.staged(), b"new second");
        let replacements = FileReplacementSet::new([first.clone(), second.clone()]);

        let error = replacements
            .replace_all()
            .expect_err("missing second target fails");

        assert!(matches!(
            error,
            FileReplacementError::BackupTarget { index: 1, .. }
        ));
        assert_eq!(fs::read(first.target()).expect("first reads"), b"old first");
        assert!(!first.staged().exists());
        assert!(!second.staged().exists());
        assert!(!first.backup().exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_replacement_set_restores_backups_when_stage_install_fails() {
        let root = temp_root("stage-fails");
        fs::create_dir_all(&root).expect("root creates");
        let first = FileReplacement::new(
            root.join("first"),
            root.join("first.stage"),
            root.join("first.backup"),
        );
        let second = FileReplacement::new(
            root.join("second"),
            root.join("second.stage"),
            root.join("second.backup"),
        );
        write(first.target(), b"old first");
        write(second.target(), b"old second");
        write(first.staged(), b"new first");
        let replacements = FileReplacementSet::new([first.clone(), second.clone()]);

        let error = replacements
            .replace_all()
            .expect_err("missing second stage fails");

        assert!(matches!(
            error,
            FileReplacementError::InstallStaged { index: 1, .. }
        ));
        assert_eq!(fs::read(first.target()).expect("first reads"), b"old first");
        assert_eq!(
            fs::read(second.target()).expect("second reads"),
            b"old second"
        );
        assert!(!first.staged().exists());
        assert!(!second.staged().exists());
        assert!(!first.backup().exists());
        assert!(!second.backup().exists());

        let _ = fs::remove_dir_all(root);
    }
}
