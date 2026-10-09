//! Bounded native saved-copy relocation manifests from sealed image custody.
//!
//! The private native helper receives only the complete supplementary file
//! roster already authenticated by the captured image. SHA-256 measurements
//! bind the helper's reads to the same bytes as the canonical content references.
//! The original source root remains inert text and is never opened.
//!
//! The operational file uses the following versioned, tab-delimited format:
//!
//! ```text
//! crucible-saved-files-v1
//! /historical/removed/ckpt_owner_files
//! /private/imported/ckpt_owner_files
//! <sha256>\t<decimal-length>\t<basename>
//! ```

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use crucible_node_contract::Validate;
use sha2::{Digest, Sha256};

use crate::{
    ProviderError,
    gem5::{Gem5CapturedArtifactRole, Gem5LaunchArtifact},
};

const MAXIMUM_FILES: usize = 4096;
const MAXIMUM_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

pub(crate) fn write<Source: crate::gem5::images::Gem5ImageSource, Prefix>(
    image: &crate::gem5::images::Gem5CapturedModelImage<Source, Prefix>,
    target: &Path,
    temporary: &Path,
) -> Result<PathBuf, ProviderError> {
    let source = root_text(image.source_supplementary_files_root())?;
    let target_text = root_text(target)?;
    let prefix = target.file_name().ok_or(ProviderError::Frame(
        "native saved-copy directory basename omitted",
    ))?;
    let mut files = BTreeMap::new();

    for file in image.artifact_inventory() {
        if file.role != Gem5CapturedArtifactRole::Image {
            continue;
        }
        let Ok(leaf) = file.relative.strip_prefix(prefix) else {
            continue;
        };
        let name = leaf_text(leaf)?;
        if file.artifact.path != target.join(name)
            || files.len() >= MAXIMUM_FILES
            || files.insert(name.to_owned(), file.artifact).is_some()
        {
            return Err(ProviderError::Correlation(
                "native saved-copy roster geometry differs",
            ));
        }
    }

    if files.is_empty() {
        return Err(ProviderError::Frame("native saved-copy roster is empty"));
    }
    check_directory_roster(target, &files)?;

    // Count the complete representation before reserving its buffer or opening
    // the manifest. Artifact bodies are streamed through a fixed-size buffer.
    let maximum = files.keys().try_fold(
        "crucible-saved-files-v1\n".len() + source.len() + target_text.len() + 2,
        |bytes, name| {
            bytes
                .checked_add(64 + 1 + 20 + 1 + name.len() + 1)
                .filter(|total| *total <= MAXIMUM_MANIFEST_BYTES)
                .ok_or(ProviderError::ResourceExhausted(
                    "native saved-copy manifest bytes",
                ))
        },
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(maximum)
        .map_err(|_| ProviderError::ResourceExhausted("native saved-copy manifest buffer"))?;
    writeln!(bytes, "crucible-saved-files-v1\n{source}\n{target_text}")?;
    for (name, artifact) in &files {
        let digest = hash_sealed_file(artifact)?;
        writeln!(bytes, "{digest}\t{}\t{name}", artifact.content.length.get())?;
    }
    check_directory_roster(target, &files)?;

    let destination = temporary.join("saved-files.manifest");
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&destination)?;
    manifest.write_all(&bytes)?;
    manifest.sync_all()?;
    Ok(destination)
}

fn root_text(path: &Path) -> Result<&str, ProviderError> {
    let text = path.to_str().ok_or(ProviderError::Frame(
        "native saved-copy root is not portable text",
    ))?;
    if !text.starts_with('/')
        || text.len() > 4095
        || text[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || text
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t'))
    {
        return Err(ProviderError::Frame("native saved-copy root is not normal"));
    }
    Ok(text)
}

fn leaf_text(path: &Path) -> Result<&str, ProviderError> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(ProviderError::Frame("native saved-copy leaf is not normal"));
    };
    let text = name.to_str().ok_or(ProviderError::Frame(
        "native saved-copy leaf is not portable text",
    ))?;
    if components.next().is_some()
        || text.len() > 255
        || text
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t'))
    {
        return Err(ProviderError::Frame(
            "native saved-copy leaf is not bounded",
        ));
    }
    Ok(text)
}

fn check_directory_roster(
    target: &Path,
    files: &BTreeMap<String, &Gem5LaunchArtifact>,
) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(target)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
        || fs::canonicalize(target)? != target
    {
        return Err(ProviderError::Correlation(
            "native saved-copy directory is not private canonical custody",
        ));
    }
    let mut count = 0usize;
    for entry in fs::read_dir(target)? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_str().ok_or(ProviderError::Frame(
            "native saved-copy directory entry is not portable",
        ))?;
        if !files.contains_key(text) || !entry.file_type()?.is_file() {
            return Err(ProviderError::Correlation(
                "native saved-copy directory differs from complete sealed roster",
            ));
        }
        count += 1;
        if count > files.len() {
            return Err(ProviderError::Correlation(
                "native saved-copy directory has excess entries",
            ));
        }
    }
    if count != files.len() {
        return Err(ProviderError::Correlation(
            "native saved-copy directory omits a sealed entry",
        ));
    }
    Ok(())
}

fn hash_sealed_file(artifact: &Gem5LaunchArtifact) -> Result<String, ProviderError> {
    artifact.content.validate()?;
    if artifact.content.length.get() > MAXIMUM_FILE_BYTES
        || artifact.content.hash.algorithm != "blake3-256"
        || artifact.content.hash.domain != "cnp.blob.v1"
        || artifact.content.media_type != "application/octet-stream"
    {
        return Err(ProviderError::Frame(
            "native saved-copy content scope differs",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(
            i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).map_err(|_| {
                ProviderError::Frame("native nofollow open flag is unrepresentable")
            })?,
        )
        .open(&artifact.path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.nlink() != 1
        || before.permissions().mode() & 0o777 != 0o600
        || before.len() != artifact.content.length.get()
    {
        return Err(ProviderError::Correlation(
            "native saved-copy file custody differs",
        ));
    }
    let mut canonical = blake3::Hasher::new();
    canonical.update(b"CNP/1\0");
    canonical.update(&11_u32.to_be_bytes());
    canonical.update(b"cnp.blob.v1");
    canonical.update(&before.len().to_be_bytes());
    let mut digest = Sha256::new();
    let mut remaining = before.len();
    let mut buffer = [0_u8; 65536];
    while remaining > 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ProviderError::ResourceExhausted("native saved-copy read extent"))?;
        let count = file.read(&mut buffer[..maximum])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "native saved-copy stream was truncated",
            ));
        }
        canonical.update(&buffer[..count]);
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if file.read(&mut buffer[..1])? != 0
        || canonical.finalize().to_hex().as_str() != artifact.content.hash.digest
        || metadata_identity(&before) != metadata_identity(&file.metadata()?)
    {
        return Err(ProviderError::Correlation(
            "native saved-copy bytes changed or differ from original seal",
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn metadata_identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
    )
}

#[cfg(test)]
#[path = "saved_files_manifest_tests.rs"]
mod tests;
