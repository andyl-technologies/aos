//! Reads one protected record without changing its ordered physical checks.
//!
//! Native bindings can execute this fixed read-only recipe in one worker. The
//! request carries no callback, descriptor, mutation or publication authority.
//! Parent observations retain their duplicates and original error priority;
//! unsafe parent or leaf metadata is rejected before reading any record body.

use super::{StoreErrorKind, StoreFailure};
use std::path::{Path, PathBuf};

/// Carries a fixed read-only protected-record recipe derived by the backend.
///
/// Its private fields and constructor prevent external callers from replacing
/// validation with a callback. The recipe establishes neither exclusion nor
/// selected-state authority; its caller retains the complete resolver fences.
pub struct NativeProtectedRead {
    path: PathBuf,
    parents: Vec<PathBuf>,
    owner: u32,
}

/// Holds exact bytes and final metadata, or an explicitly observed absence.
///
/// This read data grants no actor, publication or physical collection authority.
pub struct NativeProtectedRecord {
    bytes: Option<Vec<u8>>,
    metadata: Option<std::fs::Metadata>,
}

impl NativeProtectedRead {
    /// Derives every ordered duplicate from an already registered control key.
    pub(crate) fn for_record(control: &Path, key: &str, owner: u32) -> Self {
        let mut parent = control.to_owned();
        let mut parents = Vec::new();
        if let Some(relative) = Path::new(key).parent() {
            for part in relative.components() {
                parent.push(part);
                parents.push(parent.clone());
                parents.push(parent.clone());
            }
        }

        Self {
            path: control.join(key),
            parents,
            owner,
        }
    }

    /// Executes every fixed observation and body read on the current worker.
    ///
    /// # Errors
    /// Preserves parent/leaf policy rejection, named/descriptor replacement and
    /// exact metadata or body failures before constructing observed read data.
    #[cfg(all(feature = "tokio", unix))]
    pub(super) fn execute(self) -> Result<NativeProtectedRecord, StoreFailure> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        // The previous batch observed all entries before validation. Keep that
        // order, including duplicate stats and errors after an earlier failure.
        let observations: Vec<_> = self.parents.iter().map(std::fs::symlink_metadata).collect();
        let mut observations = observations.into_iter();
        while let Some(existence) = observations.next() {
            match existence {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(NativeProtectedRecord::absent());
                }
                Err(error) => return Err(io_failure(error)),
                Ok(_) => {
                    let metadata = observations
                        .next()
                        .ok_or_else(changed)?
                        .map_err(io_failure)?;
                    check_directory(&metadata, self.owner)?;
                }
            }
        }

        let before = match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(NativeProtectedRecord::absent());
            }
            Err(error) => return Err(io_failure(error)),
            Ok(metadata) => metadata,
        };
        check_record(&before, self.owner)?;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(io_failure)?;
        let opened = file.metadata().map_err(io_failure)?;
        check_record(&opened, self.owner)?;
        if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
            return Err(changed());
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io_failure)?;

        let after = std::fs::symlink_metadata(&self.path).map_err(io_failure)?;
        check_record(&after, self.owner)?;
        let final_opened = file.metadata().map_err(io_failure)?;
        check_record(&final_opened, self.owner)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino())
            || (opened.dev(), opened.ino()) != (final_opened.dev(), final_opened.ino())
        {
            return Err(changed());
        }

        Ok(NativeProtectedRecord {
            bytes: Some(bytes),
            metadata: Some(after),
        })
    }
}

impl NativeProtectedRecord {
    #[cfg(all(feature = "tokio", unix))]
    fn absent() -> Self {
        Self {
            bytes: None,
            metadata: None,
        }
    }

    /// Consumes exact read data without inferring any selected authority.
    pub(crate) fn into_parts(self) -> (Option<Vec<u8>>, Option<std::fs::Metadata>) {
        (self.bytes, self.metadata)
    }
}

/// Checks the exact configured owner and private protected-directory policy.
///
/// # Errors
/// Returns `Unsupported` for another owner, mode, node kind or unavailable
/// platform metadata, matching the scalar protected-record path.
pub(crate) fn check_directory(
    metadata: &std::fs::Metadata,
    owner: u32,
) -> Result<(), StoreFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.mode() & 0o777 == 0o700
        {
            return Ok(());
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, owner);

    Err(StoreFailure::new(StoreErrorKind::Unsupported))
}

/// Checks the exact owner, mode and single-link protected regular-file policy.
///
/// # Errors
/// Returns `Unsupported` for another owner, mode, link count, node kind or
/// unavailable platform metadata, matching the scalar protected-record path.
pub(crate) fn check_record(metadata: &std::fs::Metadata, owner: u32) -> Result<(), StoreFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600
        {
            return Ok(());
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, owner);

    Err(StoreFailure::new(StoreErrorKind::Unsupported))
}

#[cfg(all(feature = "tokio", unix))]
fn changed() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(super::CorruptSubject::RefName(
        "publication".into(),
    )))
}

#[cfg(all(feature = "tokio", unix))]
/// Maps native I/O through the registered filesystem error taxonomy.
pub(super) fn io_failure(error: std::io::Error) -> StoreFailure {
    let kind = match error.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem => {
            StoreErrorKind::ReadOnly
        }
        std::io::ErrorKind::StorageFull => StoreErrorKind::Capacity,
        std::io::ErrorKind::Unsupported => StoreErrorKind::Unsupported,
        _ => StoreErrorKind::Unavailable { retry_after: None },
    };
    StoreFailure::with_source(kind, error)
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
