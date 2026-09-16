//! Provider-neutral disk-image publication inspection.
//!
//! The registry authenticates disk bytes and an opaque provider-owned artifact
//! contract. It does not interpret boot media, slot, recovery, verification, or
//! filesystem fields inside that contract.

use crate::registry::parse::{
    ImageArtifactContractDocumentReference, ImageArtifactContractReference, ImageCompression,
    ImageDelivery, ImageStoreReference, ImageTarget,
};
use crate::registry_ops::images::files::{
    ValidatedImageDirectory, ValidatedImageFile, file_identity, open_canonical_store_regular_file,
    open_stable_regular_file_at_with_links, sha256_open_file, validate_lower_sha256,
    validate_single_filename, verify_stable_regular_file,
};
use crate::registry_ops::store_paths::{StorePathInfo, store_dir_from_store_path};
use crate::types::validate_package_name;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::PathBuf;

/// A fully validated provider-neutral disk-image publication input.
pub(in crate::registry_ops) struct PublishedImage {
    pub(in crate::registry_ops) format: String,
    /// Canonical directory store output interpreted by the selected provider.
    pub(in crate::registry_ops) payload: StorePathInfo,
    /// Canonical regular-file store output containing the disk encoding.
    pub(in crate::registry_ops) store: StorePathInfo,
    /// Canonical regular-file store output containing the artifact contract.
    pub(in crate::registry_ops) info_store: StorePathInfo,
    pub(in crate::registry_ops) delivery: ImageDelivery,
    /// Pinned provider artifact directory retained through commit.
    pub(in crate::registry_ops) directory: ValidatedImageDirectory,
    /// Exact validated disk store output retained through commit.
    pub(in crate::registry_ops) disk: ValidatedImageFile,
    /// Exact validated contract store output retained through commit.
    pub(in crate::registry_ops) image_info: ValidatedImageFile,
    /// Contract copy in the provider artifact set, retained to detect replacement.
    pub(in crate::registry_ops) producer_image_info: ValidatedImageFile,
}

/// Provider-neutral delivery envelope projected from the selected contract.
///
/// Unknown fields remain opaque. The selected image package validates their
/// schema before publishing this store output.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProducerImageInfo {
    schema_version: u32,
    name: String,
    version: String,
    architecture: String,
    platform: String,
    format: String,
    filename: String,
    media_type: String,
    compression: ImageCompression,
    byte_size: u64,
    sha256: String,
    logical_disk_sha256: String,
    compatible_targets: Vec<ImageTarget>,
}

const MAX_IMAGE_INFO_BYTES: u64 = 1024 * 1024;

/// Validates generic artifact identities without interpreting provider fields.
pub(in crate::registry_ops) fn inspect_published_image(
    format: &str,
    payload: StorePathInfo,
    disk_store: StorePathInfo,
    info_store: StorePathInfo,
    contract_schema: &str,
    name: &str,
    release: &str,
    platform: &str,
) -> Result<PublishedImage> {
    if store_dir_from_store_path(&payload.path).is_none() {
        bail!("published image artifact set must be a canonical Nix store path");
    }
    let root_path = PathBuf::from(&payload.path);
    let canonical_payload = fs::canonicalize(&root_path)
        .with_context(|| format!("canonicalizing image artifact set {}", payload.path))?;
    if canonical_payload != root_path {
        bail!("published image artifact set must not traverse aliases or symlinks");
    }

    let root_meta = fs::symlink_metadata(&root_path)
        .with_context(|| format!("inspecting image artifact set {}", root_path.display()))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        bail!("published image artifact set must be a real directory");
    }
    let root_handle = rustix::fs::open(
        &root_path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening image artifact set {}", root_path.display()))?;
    let root_file = fs::File::from(root_handle);
    let root_identity = file_identity(&root_file.metadata()?);
    if file_identity(&root_meta) != root_identity {
        bail!("image artifact set identity changed while opening");
    }

    let info_path = root_path.join("image-info.json");
    let (mut info_file, info_identity) =
        open_stable_regular_file_at_with_links(&root_file, "image-info.json", &info_path, true)?;
    if info_identity.len == 0 || info_identity.len > MAX_IMAGE_INFO_BYTES {
        bail!("image artifact contract size is outside its bound");
    }
    let mut info_bytes = Vec::with_capacity(info_identity.len as usize);
    (&mut info_file)
        .take(MAX_IMAGE_INFO_BYTES + 1)
        .read_to_end(&mut info_bytes)
        .with_context(|| format!("reading image artifact contract {}", info_path.display()))?;
    if info_bytes.len() as u64 != info_identity.len {
        bail!("image artifact contract length changed while it was read");
    }
    verify_stable_regular_file(&info_path, &info_file, &info_identity)?;

    let producer: ProducerImageInfo = serde_json::from_slice(&info_bytes)
        .with_context(|| format!("parsing delivery envelope in {}", info_path.display()))?;
    if producer.schema_version != 2 {
        bail!("image delivery schemaVersion must be 2");
    }
    let public_text =
        std::str::from_utf8(&info_bytes).context("image artifact contract is not UTF-8")?;
    if public_text.contains("/nix/store/")
        || public_text.contains("/aos/store/")
        || public_text.contains("file://")
    {
        bail!("image artifact contract contains a private build or filesystem path");
    }
    validate_package_name(&producer.name).context("validating image contract package name")?;
    if producer.name != name
        || producer.version != release
        || producer.platform != platform
        || producer.format != format
    {
        bail!("image delivery envelope disagrees with its signed package identity");
    }
    let architecture = platform
        .split_once('-')
        .map(|(architecture, _)| architecture)
        .filter(|architecture| !architecture.is_empty())
        .context("published platform has no architecture component")?;
    if producer.architecture != architecture {
        bail!("image delivery envelope architecture disagrees with its platform");
    }
    validate_single_filename(&producer.filename, "image filename")?;
    validate_lower_sha256(&producer.logical_disk_sha256, "logical disk")?;

    let payload_image_path = root_path.join(&producer.filename);
    let (mut payload_image_file, payload_image_identity) = open_stable_regular_file_at_with_links(
        &root_file,
        &producer.filename,
        &payload_image_path,
        true,
    )?;
    let payload_sha256 = sha256_open_file(&mut payload_image_file, &payload_image_path)?;
    verify_stable_regular_file(
        &payload_image_path,
        &payload_image_file,
        &payload_image_identity,
    )?;

    let (mut image_file, image_identity, image_path) =
        open_canonical_store_regular_file(&disk_store, "image disk")?;
    let actual_sha256 = sha256_open_file(&mut image_file, &image_path)?;
    verify_stable_regular_file(&image_path, &image_file, &image_identity)?;
    if payload_image_identity.len != image_identity.len || payload_sha256 != actual_sha256 {
        bail!("image artifact disk does not match the explicit disk store output");
    }
    if producer.byte_size != image_identity.len || producer.sha256 != actual_sha256 {
        bail!("image delivery envelope disagrees with the disk byte identity");
    }

    let (mut canonical_info_file, canonical_info_identity, canonical_info_path) =
        open_canonical_store_regular_file(&info_store, "image artifact contract")?;
    let mut published_info_bytes = Vec::with_capacity(canonical_info_identity.len as usize);
    (&mut canonical_info_file)
        .take(MAX_IMAGE_INFO_BYTES + 1)
        .read_to_end(&mut published_info_bytes)
        .with_context(|| format!("reading image contract {}", canonical_info_path.display()))?;
    verify_stable_regular_file(
        &canonical_info_path,
        &canonical_info_file,
        &canonical_info_identity,
    )?;
    if published_info_bytes != info_bytes {
        bail!("explicit image contract output does not match the provider artifact set");
    }
    let info_sha256 = sha256_hex(&published_info_bytes);
    canonical_info_file.seek(SeekFrom::Start(0))?;

    let delivery = ImageDelivery {
        schema_version: producer.schema_version,
        release: release.to_string(),
        platform: producer.platform,
        architecture: producer.architecture,
        logical_image_id: producer.logical_disk_sha256.clone(),
        logical_disk_sha256: producer.logical_disk_sha256,
        filename: producer.filename,
        object_key: String::new(),
        media_type: producer.media_type,
        compression: producer.compression,
        byte_size: producer.byte_size,
        sha256: producer.sha256,
        compatible_targets: producer.compatible_targets,
        artifact_contract: ImageArtifactContractReference {
            schema: contract_schema.to_string(),
            document: ImageArtifactContractDocumentReference {
                filename: "image-info.json".to_string(),
                object_key: String::new(),
                store_path: info_store.path.clone(),
                nar_hash: info_store.nar_hash.clone(),
                nar_size: info_store.nar_size,
                media_type: "application/vnd.aos.image-info+json".to_string(),
                byte_size: published_info_bytes.len() as u64,
                sha256: info_sha256,
            },
            artifacts: Some(ImageStoreReference {
                store_path: payload.path.clone(),
                nar_hash: payload.nar_hash.clone(),
                nar_size: payload.nar_size,
            }),
        },
    };
    delivery
        .validate(format, release, platform)
        .with_context(|| format!("validating image delivery contract for {format}"))?;

    Ok(PublishedImage {
        format: format.to_string(),
        payload,
        store: disk_store,
        info_store,
        delivery,
        directory: ValidatedImageDirectory {
            path: root_path,
            file: root_file,
            identity: root_identity,
        },
        disk: ValidatedImageFile {
            path: image_path,
            file: image_file,
            identity: image_identity,
            path_bound: true,
        },
        image_info: ValidatedImageFile {
            path: canonical_info_path,
            file: canonical_info_file,
            identity: canonical_info_identity,
            path_bound: true,
        },
        producer_image_info: ValidatedImageFile {
            path: info_path,
            file: info_file,
            identity: info_identity,
            path_bound: true,
        },
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    format!("{:x}", Sha256::digest(bytes))
}

impl PublishedImage {
    pub(in crate::registry_ops) fn recheck_for_commit(&self) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.directory.path)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || file_identity(&path_metadata) != self.directory.identity
            || file_identity(&self.directory.file.metadata()?) != self.directory.identity
        {
            bail!("image artifact set identity changed before commit");
        }
        self.disk.recheck()?;
        self.image_info.recheck()?;
        self.producer_image_info.recheck()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

pub(super) mod files;

pub(super) mod receipts;
