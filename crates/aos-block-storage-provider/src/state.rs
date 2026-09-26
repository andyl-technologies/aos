//! Bounded atomic runtime ownership markers for storage providers.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ResourceReference;
use aos_contract::Sha256Digest;
use serde::{Serialize, de::DeserializeOwned};

const MAX_MARKER_BYTES: usize = 64 * 1024;

/// Reads one bounded canonical marker for an exact resource.
///
/// # Errors
///
/// Returns an error when the marker path, bytes, or canonical document is invalid.
pub fn read<T: DeserializeOwned>(
    root: &Path,
    domain: &str,
    target: &ResourceReference,
) -> Result<Option<T>> {
    let path = marker_path(root, domain, target)?;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("opening storage ownership marker"),
    };
    let mut bytes = Vec::new();
    file.take(MAX_MARKER_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_MARKER_BYTES,
        "storage ownership marker is oversized"
    );
    aos_contract::canonical::from_slice(&bytes, "storage ownership marker").map(Some)
}

/// Atomically writes one canonical marker for an exact resource.
///
/// # Errors
///
/// Returns an error when the marker cannot be encoded, persisted, or renamed.
pub fn write<T: Serialize>(
    root: &Path,
    domain: &str,
    target: &ResourceReference,
    marker: &T,
) -> Result<()> {
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let path = marker_path(root, domain, target)?;
    let temporary = path.with_extension("tmp");
    let bytes = aos_contract::canonical::canonical_json(&serde_json::to_value(marker)?)?;
    ensure!(
        bytes.len() <= MAX_MARKER_BYTES,
        "storage ownership marker is oversized"
    );
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

/// Removes one exact ownership marker when present.
///
/// # Errors
///
/// Returns an error when an existing marker cannot be removed.
pub fn remove(root: &Path, domain: &str, target: &ResourceReference) -> Result<()> {
    match fs::remove_file(marker_path(root, domain, target)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("removing storage ownership marker"),
    }
}

fn marker_path(root: &Path, domain: &str, target: &ResourceReference) -> Result<PathBuf> {
    let digest = Sha256Digest::of_canonical(domain, &target.resource)?;
    Ok(root.join(digest.hex()))
}
