//! Durable native storage claims keyed by logical effect identity.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_contract::Sha256Digest;
use serde::{Serialize, de::DeserializeOwned};

/// Holds an exclusive storage-domain mutation lock.
pub struct Lock {
    _file: File,
}

impl Lock {
    /// Acquires a domain lock without blocking beyond the process deadline.
    ///
    /// # Errors
    /// Returns an error for an unsafe state root or an occupied lock.
    pub fn acquire(root: &Path) -> Result<Self> {
        ensure!(root.is_absolute(), "state root is not absolute");
        let mut current = PathBuf::from("/");
        for component in root.components().skip(1) {
            ensure!(
                matches!(component, std::path::Component::Normal(_)),
                "state path is not normalized"
            );
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "state root crosses a non-directory"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)?
                }
                Err(error) => return Err(error.into()),
            }
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(root.join("mutation.lock"))?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self { _file: file })
    }
}

fn path(root: &Path, id: &str) -> PathBuf {
    root.join(format!(
        "{}.json",
        Sha256Digest::of_bytes(id.as_bytes()).hex()
    ))
}

/// Reads a bounded claim for a logical effect.
///
/// # Errors
/// Returns an error for malformed records or failed filesystem access.
pub fn read<T: DeserializeOwned>(root: &Path, id: &str) -> Result<Option<T>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path(root, id))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        file.metadata()?.is_file(),
        "storage claim is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "storage claim exceeds byte bound");
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Atomically persists a claim before or after a native mutation.
///
/// # Errors
/// Returns an error if serialization or durable publication fails.
pub fn write<T: Serialize>(root: &Path, id: &str, value: &T) -> Result<()> {
    let destination = path(root, id);
    let temporary = destination.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 65536, "storage claim exceeds byte bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating storage claim temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Durably removes a logical effect's ownership receipt.
///
/// # Errors
/// Returns an error when removal or synchronization fails.
pub fn remove(root: &Path, id: &str) -> Result<()> {
    match fs::remove_file(path(root, id)) {
        Ok(()) => File::open(root)?
            .sync_all()
            .context("synchronizing claim removal"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
