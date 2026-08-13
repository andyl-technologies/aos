//! Safe `.drv` file materialization helpers.

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

/// A failure while installing a native `.drv` file into the configured store.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct DrvMaterializationError {
    message: String,
}

impl DrvMaterializationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Writes `bytes` to `path` without leaving partial final-path contents behind.
///
/// # Errors
///
/// Returns [`DrvMaterializationError`] when the destination path has no parent
/// or file name, the parent directory cannot be created, existing file contents
/// conflict with `bytes`, or temporary-file creation, sync, hard-link, or cleanup
/// fails.
pub fn materialize_drv(path: &Path, bytes: &[u8]) -> Result<(), DrvMaterializationError> {
    let parent = path.parent().ok_or_else(|| {
        DrvMaterializationError::new(format!(
            "native derivation path has no parent directory: {}",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|source| {
        DrvMaterializationError::new(format!(
            "failed to create native derivation parent {}: {source}",
            parent.display()
        ))
    })?;

    match fs::read(path) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(DrvMaterializationError::new(format!(
                "refusing to overwrite existing derivation {} with different contents",
                path.display()
            )));
        }
        Err(source) if source.kind() == ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DrvMaterializationError::new(format!(
                "failed to read existing native derivation {}: {source}",
                path.display()
            )));
        }
    }

    let temp_path = write_temp_drv(parent, path, bytes)?;
    match fs::hard_link(&temp_path, path) {
        Ok(()) => fs::remove_file(&temp_path).map_err(|source| {
            DrvMaterializationError::new(format!(
                "failed to remove temporary native derivation {}: {source}",
                temp_path.display()
            ))
        })?,
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            let existing = fs::read(path).map_err(|source| {
                DrvMaterializationError::new(format!(
                    "failed to read concurrently-created native derivation {}: {source}",
                    path.display()
                ))
            })?;
            let remove_result = fs::remove_file(&temp_path);
            if existing == bytes {
                remove_result.map_err(|source| {
                    DrvMaterializationError::new(format!(
                        "failed to remove temporary native derivation {}: {source}",
                        temp_path.display()
                    ))
                })?;
                return Ok(());
            }
            let _ = remove_result;
            return Err(DrvMaterializationError::new(format!(
                "refusing to overwrite concurrently-created derivation {} with different contents",
                path.display()
            )));
        }
        Err(source) => {
            let _ = fs::remove_file(&temp_path);
            return Err(DrvMaterializationError::new(format!(
                "failed to install native derivation {} from {}: {source}",
                path.display(),
                temp_path.display()
            )));
        }
    }
    Ok(())
}

fn write_temp_drv(
    parent: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<PathBuf, DrvMaterializationError> {
    for attempt in 0..100 {
        let temp_path = temp_drv_path(parent, final_path, attempt)?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(DrvMaterializationError::new(format!(
                        "failed to write temporary native derivation {}: {source}",
                        temp_path.display()
                    )));
                }
                return Ok(temp_path);
            }
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(DrvMaterializationError::new(format!(
                    "failed to create temporary native derivation {}: {source}",
                    temp_path.display()
                )));
            }
        }
    }

    Err(DrvMaterializationError::new(format!(
        "failed to allocate temporary native derivation path for {}",
        final_path.display()
    )))
}

fn temp_drv_path(
    parent: &Path,
    final_path: &Path,
    attempt: u32,
) -> Result<PathBuf, DrvMaterializationError> {
    let file_name = final_path.file_name().ok_or_else(|| {
        DrvMaterializationError::new(format!(
            "native derivation path has no file name: {}",
            final_path.display()
        ))
    })?;
    let mut temp_name = Vec::new();
    temp_name.push(b'.');
    temp_name.extend_from_slice(file_name.as_bytes());
    temp_name.extend_from_slice(format!(".{}.{}.tmp", std::process::id(), attempt).as_bytes());
    Ok(parent.join(OsString::from_vec(temp_name)))
}
