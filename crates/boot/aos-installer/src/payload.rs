//! The signed release payload carried by installer media.
//!
//! The payload partition (GPT label `aos-payload`) holds the compressed raw
//! disk, its image metadata, and a manifest signed with the release's Secure
//! Boot db key. Nothing else may be present:
//!
//! ```text
//! aos-payload/
//! ├── installer-payload.json       manifest below
//! ├── installer-payload.json.sig   detached SHA-256 signature, db key
//! ├── aos-<system>.img.zst         compressed raw GPT disk
//! ├── image-info.json              provider image metadata
//! └── image-delivery.json          delivery metadata
//! ```
//!
//! ```json
//! {
//!   "schema": "aos.installer-payload/v1",
//!   "release": "2026.10.2",
//!   "architecture": "x86_64",
//!   "platform": "x86_64-linux",
//!   "disk": { "byte_size": 4294967296, "sha256": "<logical disk digest>" },
//!   "components": [
//!     { "id": "disk-image", "path": "aos-server.img.zst", "byte_size": 1, "sha256": "..." },
//!     { "id": "image-info", "path": "image-info.json", "byte_size": 1, "sha256": "..." },
//!     { "id": "image-delivery", "path": "image-delivery.json", "byte_size": 1, "sha256": "..." }
//!   ]
//! }
//! ```
//!
//! Verification order matters: the manifest signature is checked before the
//! manifest is parsed, every component is hashed before any metadata is read,
//! and the metadata must agree with the signed logical-disk identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_boot_media::digest::{self, is_canonical};
use aos_boot_media::trust::DbTrust;
use aos_boot_media::Tools;
use serde::Deserialize;

/// Manifest file name inside the payload directory.
pub const MANIFEST: &str = "installer-payload.json";
/// Detached manifest signature file name.
pub const SIGNATURE: &str = "installer-payload.json.sig";

const SCHEMA: &str = "aos.installer-payload/v1";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_DISK_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Component identities and their byte bounds, in manifest order.
const COMPONENTS: [(&str, u64); 3] = [
    ("disk-image", MAX_DISK_IMAGE_BYTES),
    ("image-info", MAX_METADATA_BYTES),
    ("image-delivery", MAX_METADATA_BYTES),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    release: String,
    architecture: String,
    platform: String,
    disk: DiskIdentity,
    components: Vec<ComponentEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskIdentity {
    byte_size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentEntry {
    id: String,
    path: String,
    byte_size: u64,
    sha256: String,
}

/// A payload whose signature, members, and digests have all been verified.
#[derive(Debug)]
pub struct VerifiedPayload {
    /// Signed release identity.
    pub release: String,
    /// Compressed raw disk image.
    pub disk_image: PathBuf,
    /// Exact size of the decompressed raw disk.
    pub disk_byte_size: u64,
    /// SHA-256 of the decompressed raw disk.
    pub disk_sha256: String,
}

/// Verifies the mounted payload directory against the db trust snapshot.
///
/// `platform` is the installer's own `AOS_PLATFORM`; the payload must target
/// the same platform and the running architecture.
///
/// # Errors
///
/// Returns an error for an unauthorized or malformed manifest, missing or
/// extra files, a component size or digest mismatch, an incompatible
/// architecture or platform, or metadata that disagrees with the signed disk
/// identity.
pub fn verify(
    tools: &Tools,
    trust: &DbTrust,
    directory: &Path,
    platform: &str,
) -> Result<VerifiedPayload> {
    let manifest_path = directory.join(MANIFEST);
    let signature_path = directory.join(SIGNATURE);
    digest::bounded_regular(&manifest_path, MAX_MANIFEST_BYTES)?;
    digest::bounded_regular(&signature_path, MAX_SIGNATURE_BYTES)?;
    trust
        .verify_detached_signature(tools, &manifest_path, &signature_path)
        .context("installer payload manifest is not signed by an authorized db key")?;

    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .context("installer payload manifest is malformed")?;
    let components = validate_manifest(&manifest, std::env::consts::ARCH, platform)?;
    verify_exact_directory(directory, &components)?;
    for (id, maximum) in COMPONENTS {
        let entry = &components[id];
        let path = directory.join(&entry.path);
        digest::bounded_regular(&path, maximum)?;
        digest::verify_file(tools, &path, entry.byte_size, &entry.sha256)
            .with_context(|| format!("installer payload component {id}"))?;
    }

    let info = read_json(&directory.join(&components["image-info"].path))?;
    let delivery = read_json(&directory.join(&components["image-delivery"].path))?;
    check_metadata(&manifest, &info, &delivery)?;

    let disk_image = directory.join(&components["disk-image"].path);
    Ok(VerifiedPayload {
        release: manifest.release.clone(),
        disk_image,
        disk_byte_size: manifest.disk.byte_size,
        disk_sha256: manifest.disk.sha256.clone(),
    })
}

fn validate_manifest<'a>(
    manifest: &'a Manifest,
    architecture: &str,
    platform: &str,
) -> Result<BTreeMap<&'a str, &'a ComponentEntry>> {
    ensure!(
        manifest.schema == SCHEMA,
        "unsupported installer payload schema '{}'",
        manifest.schema
    );
    ensure!(
        portable(&manifest.release, 128),
        "installer payload release identity is malformed"
    );
    ensure!(
        manifest.architecture == architecture,
        "installer payload targets {}, but this machine is {architecture}",
        manifest.architecture
    );
    ensure!(
        manifest.platform == platform,
        "installer payload targets platform {}, but the installer is {platform}",
        manifest.platform
    );
    ensure!(
        manifest.disk.byte_size > 0 && is_canonical(&manifest.disk.sha256),
        "installer payload logical disk identity is malformed"
    );

    let mut components = BTreeMap::new();
    for entry in &manifest.components {
        ensure!(
            portable(&entry.path, 128) && !entry.path.starts_with('.'),
            "installer payload component path '{}' is not a plain file name",
            entry.path
        );
        ensure!(
            entry.byte_size > 0 && is_canonical(&entry.sha256),
            "installer payload component {} has a malformed size or digest",
            entry.id
        );
        if components.insert(entry.id.as_str(), entry).is_some() {
            bail!("installer payload component {} is duplicated", entry.id);
        }
    }
    let expected = COMPONENTS.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>();
    ensure!(
        components.keys().copied().collect::<BTreeSet<_>>() == expected,
        "installer payload must contain exactly the disk-image, image-info, and image-delivery components"
    );
    Ok(components)
}

fn verify_exact_directory(
    directory: &Path,
    components: &BTreeMap<&str, &ComponentEntry>,
) -> Result<()> {
    let mut expected = components
        .values()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    expected.insert(MANIFEST.to_owned());
    expected.insert(SIGNATURE.to_owned());

    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("installer payload contains a non-UTF-8 file name")?;
        // mkfs.ext4 creates lost+found; it is the only tolerated extra entry.
        if name == "lost+found" && entry.file_type()?.is_dir() {
            continue;
        }
        ensure!(
            entry.file_type()?.is_file(),
            "installer payload contains a symlink, directory, or special node: {name}"
        );
        actual.insert(name.to_owned());
    }
    ensure!(
        actual == expected,
        "installer payload has missing or unaccounted files"
    );
    Ok(())
}

fn check_metadata(
    manifest: &Manifest,
    info: &serde_json::Value,
    delivery: &serde_json::Value,
) -> Result<()> {
    let delivery_size = delivery
        .get("virtualSizeBytes")
        .and_then(serde_json::Value::as_u64);
    let delivery_digest = delivery
        .get("logicalDiskSha256")
        .and_then(serde_json::Value::as_str);
    let info_digest = info
        .pointer("/disk/logical/sha256")
        .and_then(serde_json::Value::as_str);
    ensure!(
        delivery_size == Some(manifest.disk.byte_size)
            && delivery_digest == Some(manifest.disk.sha256.as_str())
            && info_digest == Some(manifest.disk.sha256.as_str()),
        "image metadata disagrees with the signed logical disk identity"
    );
    ensure!(
        delivery.get("format").and_then(serde_json::Value::as_str) == Some("raw"),
        "installer payload disk is not a raw image"
    );
    Ok(())
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("{} is not JSON", path.display()))
}

fn portable(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{Manifest, check_metadata, validate_manifest, verify_exact_directory};
    use serde_json::json;
    use std::fs;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn manifest() -> Manifest {
        serde_json::from_value(json!({
            "schema": "aos.installer-payload/v1",
            "release": "2026.10.2",
            "architecture": "x86_64",
            "platform": "x86_64-linux",
            "disk": {"byte_size": 4096, "sha256": DIGEST},
            "components": [
                {"id": "disk-image", "path": "aos-server.img.zst", "byte_size": 10, "sha256": DIGEST},
                {"id": "image-info", "path": "image-info.json", "byte_size": 10, "sha256": DIGEST},
                {"id": "image-delivery", "path": "image-delivery.json", "byte_size": 10, "sha256": DIGEST}
            ]
        }))
        .expect("fixture manifest parses")
    }

    #[test]
    fn a_complete_manifest_for_this_machine_is_accepted() {
        let manifest = manifest();
        let components = validate_manifest(&manifest, "x86_64", "x86_64-linux")
            .expect("fixture manifest is valid");
        assert_eq!(components.len(), 3);
    }

    #[test]
    fn architecture_platform_and_component_set_are_enforced() {
        let manifest = manifest();
        assert!(validate_manifest(&manifest, "aarch64", "x86_64-linux").is_err());
        assert!(validate_manifest(&manifest, "x86_64", "aarch64-linux").is_err());

        let mut traversal = self::manifest();
        traversal.components[0].path = "../escape".into();
        assert!(validate_manifest(&traversal, "x86_64", "x86_64-linux").is_err());

        let mut missing = self::manifest();
        missing.components.pop();
        assert!(validate_manifest(&missing, "x86_64", "x86_64-linux").is_err());
    }

    #[test]
    fn metadata_must_agree_with_the_signed_disk() {
        let manifest = manifest();
        let info = json!({"disk": {"logical": {"sha256": DIGEST}}});
        let delivery = json!({"format": "raw", "virtualSizeBytes": 4096, "logicalDiskSha256": DIGEST});
        assert!(check_metadata(&manifest, &info, &delivery).is_ok());

        let resized = json!({"format": "raw", "virtualSizeBytes": 8192, "logicalDiskSha256": DIGEST});
        assert!(check_metadata(&manifest, &info, &resized).is_err());
        let qcow2 = json!({"format": "qcow2", "virtualSizeBytes": 4096, "logicalDiskSha256": DIGEST});
        assert!(check_metadata(&manifest, &info, &qcow2).is_err());
    }

    #[test]
    fn unaccounted_payload_files_are_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let manifest = manifest();
        let components = validate_manifest(&manifest, "x86_64", "x86_64-linux")
            .expect("fixture manifest is valid");
        for name in [
            "installer-payload.json",
            "installer-payload.json.sig",
            "aos-server.img.zst",
            "image-info.json",
            "image-delivery.json",
        ] {
            fs::write(directory.path().join(name), b"x").expect("write fixture");
        }
        fs::create_dir(directory.path().join("lost+found")).expect("lost+found");
        assert!(verify_exact_directory(directory.path(), &components).is_ok());

        fs::write(directory.path().join("extra"), b"x").expect("write extra");
        assert!(verify_exact_directory(directory.path(), &components).is_err());
    }
}
