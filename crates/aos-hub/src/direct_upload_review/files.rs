//! Bounded selected report reads and protected reviewer-key custody.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use anyhow::{ensure, Result};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

use super::selection::ReviewedFile;

pub(super) const DOCUMENT_LIMIT: u64 = 64 * 1024;
const OBSERVATION_LIMIT: u64 = 64 * 1024 * 1024;
const INSTALLED_FILE_LIMIT: u64 = 16 * 1024 * 1024 * 1024;

fn open_regular(path: &Path) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("review input cannot be opened"))?;
    ensure!(
        file.metadata()
            .map_err(|_| anyhow::anyhow!("review input metadata unavailable"))?
            .is_file(),
        "review input must be a regular file"
    );
    Ok(file)
}

pub(super) fn read_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_regular(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("review input cannot be read"))?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "review input exceeds its bound"
    );
    Ok(bytes)
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn selected_bytes(base: &Path, selected: &ReviewedFile, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(&selected.sha256),
        "reviewed file commitment invalid"
    );
    let bytes = read_bytes(&base.join(&selected.path), limit)?;
    ensure!(
        digest(&bytes) == selected.sha256,
        "reviewed file changed or was substituted"
    );
    Ok(bytes)
}

pub(super) fn selected_document<T: DeserializeOwned>(
    base: &Path,
    selected: &ReviewedFile,
) -> Result<T> {
    serde_json::from_slice(&selected_bytes(base, selected, DOCUMENT_LIMIT)?)
        .map_err(|_| anyhow::anyhow!("reviewed document is not a closed supported format"))
}

pub(super) fn selected_observation(base: &Path, selected: &ReviewedFile) -> Result<Vec<u8>> {
    selected_bytes(base, selected, OBSERVATION_LIMIT)
}

pub(super) fn selected_installed_file(base: &Path, selected: &ReviewedFile) -> Result<u64> {
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(&selected.sha256),
        "installed file commitment invalid"
    );
    let mut file = open_regular(&base.join(&selected.path))?.take(INSTALLED_FILE_LIMIT + 1);
    let mut buffer = [0u8; 64 * 1024];
    let mut hash = Sha256::new();
    let mut size = 0u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| anyhow::anyhow!("installed file cannot be read"))?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| anyhow::anyhow!("installed file size overflows"))?;
        ensure!(
            size <= INSTALLED_FILE_LIMIT,
            "installed file exceeds its bound"
        );
        hash.update(&buffer[..count]);
    }
    ensure!(
        hex::encode(hash.finalize()) == selected.sha256,
        "installed file changed or was substituted"
    );
    Ok(size)
}

pub(super) fn public_key(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("reviewer public verifier malformed"))?;
    let public = text.strip_suffix('\n').unwrap_or(text);
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(public),
        "reviewer public verifier malformed"
    );
    Ok(public.to_owned())
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| anyhow::anyhow!("review output cannot be created"))?;
    temporary
        .write_all(bytes)
        .map_err(|_| anyhow::anyhow!("review output cannot be written"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| anyhow::anyhow!("review output cannot be synchronized"))?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("review output already exists or cannot be installed"))?;
    Ok(())
}
