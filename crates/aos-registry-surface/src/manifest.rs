//! The registry package-manifest (`package.toml`) schema.
//!
//! These are the pure, deserialize-only structs describing a registry's
//! `packages/<letter>/<name>.toml` documents: the `[package]` header, its
//! `[[versions]]`, and each version's per-platform artifacts and pre-compiled
//! images. They carry no I/O and no dependency on the package manager itself,
//! so they live in this wasm-clean surface crate (RFC-0004 Phase 5) and are
//! shared by `aos-package` (which re-exports them and provides the directory
//! parsers), the registry hub's `Database`/indexer, and the Cloudflare Worker.
//!
//! ```toml
//! [package]
//! name = "curl"
//! description = "command-line URL transfer tool"
//! license = "curl"
//! maintainer = "aos-core"
//!
//! [[versions]]
//! version = "8.7.1"
//!
//! [versions.platforms.x86_64-linux]
//! store_path = "/aos/store/…-curl-8.7.1"
//! nar_hash = "sha256:…"
//! nar_size = 1234
//! closure_size = 5678
//! source_drv = "/aos/store/…-curl-8.7.1.drv"
//! source_nar_hash = "sha256:…"
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Computes the deterministic identity of a registry's signed image catalog.
///
/// The digest is domain-separated and length-frames every field, so it cannot
/// be replayed across registry identities or reinterpreted through ambiguous
/// concatenation. Object order does not affect the result.
#[must_use]
pub fn image_catalog_digest<'a, I>(registry: &str, objects: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str, u64, &'a str)>,
{
    let mut objects = objects.into_iter().collect::<Vec<_>>();
    objects.sort_unstable();
    let mut hasher = Sha256::new();
    hash_catalog_field(&mut hasher, b"aos.signed-image-catalog.v1");
    hash_catalog_field(&mut hasher, registry.as_bytes());
    for (key, role, byte_size, sha256) in objects {
        hash_catalog_field(&mut hasher, key.as_bytes());
        hash_catalog_field(&mut hasher, role.as_bytes());
        hasher.update(byte_size.to_be_bytes());
        hash_catalog_field(&mut hasher, sha256.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn hash_catalog_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Top-level package TOML file from a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageToml {
    /// The `[package]` header with name and descriptive metadata.
    pub package: PackageHeader,
    /// All published `[[versions]]` entries, oldest layout order preserved.
    #[serde(default)]
    pub versions: Vec<VersionEntry>,
}

/// The `[package]` header section of a package TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageHeader {
    /// Package name; must match the TOML file's basename.
    pub name: String,
    /// One-line human-readable description, searched by `apm search`.
    pub description: String,
    /// Optional upstream homepage URL.
    #[serde(default)]
    pub homepage: Option<String>,
    /// SPDX-style license identifier.
    pub license: String,
    /// Maintainer name or team handle.
    pub maintainer: String,
    /// Whether this package is a system toplevel (sysroot).
    #[serde(default)]
    pub sysroot: bool,
}

/// One `[[versions]]` entry of a package TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionEntry {
    /// Version string; semver when possible, calver otherwise.
    pub version: String,
    /// Previous version in the version chain (for sysroot packages).
    #[serde(default)]
    pub previous: Option<String>,
    /// Per-platform artifacts, keyed by platform triple
    /// (e.g. `x86_64-linux` or `aarch64-darwin`).
    #[serde(default)]
    pub platforms: HashMap<String, PlatformEntry>,
}

/// A `[versions.platforms.<platform>]` artifact entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformEntry {
    /// Absolute store path of the installable `out` output.
    pub store_path: String,
    /// Additional retained derivation outputs, keyed by Nix output name.
    ///
    /// These paths are authenticated release and static-cache roots. Package
    /// installation continues to select [`Self::store_path`]; build consumers
    /// may resolve development and tool outputs explicitly from this map.
    #[serde(default)]
    pub named_outputs: BTreeMap<String, String>,
    /// NAR hash of the output (`sha256:...`).
    ///
    /// Legacy (pre-RFC-0005) field: newer registries publish the hash in
    /// the `store/` graph instead, and consumers backfill it from there.
    #[serde(default)]
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    ///
    /// Legacy (pre-RFC-0005) field, superseded by the `store/` graph like
    /// `nar_hash`.
    #[serde(default)]
    pub nar_size: u64,
    /// Total uncompressed size of the runtime closure in bytes.
    pub closure_size: u64,
    /// Store path of the derivation that produced the output.
    pub source_drv: String,
    /// NAR hash of the source derivation closure.
    pub source_nar_hash: String,
    /// Store path hashes of direct runtime references, or a structural feature
    /// gate for authenticated package metadata.
    #[serde(default)]
    pub references: ReferenceField,
    /// Pre-compiled images (only for sysroot packages).
    #[serde(default)]
    pub images: Vec<ImageEntry>,
    /// Minimum package metadata format required to safely consume this entry.
    #[serde(default, rename = "min-format")]
    pub min_format: Option<u32>,
    /// Feature flags a consumer must understand before installing this entry.
    #[serde(default, rename = "requires-features")]
    pub requires_features: Vec<String>,
    /// Digest used as the package-root input to TPM measurements.
    #[serde(default)]
    pub root_digest: Option<String>,
    /// dm-verity Merkle root hash for this package root.
    #[serde(default)]
    pub root_hash: Option<String>,
    /// Registry-served PKCS#7 signature over `root_hash`.
    #[serde(default)]
    pub root_hash_sig: Option<String>,
    /// Registry-served in-toto/SLSA provenance attestation reference.
    #[serde(default)]
    pub provenance: Option<String>,
    /// Golden package measurement tuple.
    #[serde(default)]
    pub measurement: Option<String>,
    /// Canonical RFC-0016 package documentation store object.
    #[serde(default)]
    pub documentation: Option<DocumentationArtifactMeta>,
    /// Authenticated package contract and its exact selector bindings.
    #[serde(default)]
    pub contract: Option<PackageContractMeta>,
}

impl PlatformEntry {
    /// Collects this entry's runtime integrity, attestation, and provenance
    /// facts into an [`AttestationMeta`].
    pub fn attestation(&self) -> AttestationMeta {
        AttestationMeta {
            root_digest: self.root_digest.clone(),
            root_hash: self.root_hash.clone(),
            root_hash_sig: self.root_hash_sig.clone(),
            provenance: self.provenance.clone(),
            measurement: self.measurement.clone(),
        }
    }
}

/// Store path hashes of a platform entry's direct runtime references, or a
/// structural feature gate for authenticated package metadata.
///
/// Old clients that expected a plain list reject the structural gate form,
/// which is the intended fail-closed behavior for gated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReferenceField {
    /// Legacy list of direct store-path hashes.
    Hashes(Vec<String>),
    /// Structural gate table that old clients reject because they expected a list.
    Gate(ReferenceGate),
}

impl Default for ReferenceField {
    fn default() -> Self {
        Self::Hashes(Vec::new())
    }
}

impl ReferenceField {
    /// Returns the direct store-path hashes regardless of representation.
    pub fn hashes(&self) -> &[String] {
        match self {
            Self::Hashes(hashes) => hashes,
            Self::Gate(gate) => &gate.hashes,
        }
    }

    /// Returns the structural gate's minimum metadata format, if any.
    pub fn min_format(&self) -> Option<u32> {
        match self {
            Self::Hashes(_) => None,
            Self::Gate(gate) => gate.min_format,
        }
    }

    /// Returns the structural gate's required feature flags, if any.
    pub fn requires_features(&self) -> &[String] {
        match self {
            Self::Hashes(_) => &[],
            Self::Gate(gate) => &gate.requires_features,
        }
    }

    /// Returns whether the references are expressed as a structural gate table.
    pub fn is_gate(&self) -> bool {
        matches!(self, Self::Gate(_))
    }
}

/// A structural references feature-gate table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceGate {
    /// Store path hashes of direct runtime references.
    #[serde(default)]
    pub hashes: Vec<String>,
    /// Minimum package metadata format required to safely consume this entry.
    #[serde(default, rename = "min-format")]
    pub min_format: Option<u32>,
    /// Feature flags a consumer must understand before installing this entry.
    #[serde(default, rename = "requires-features")]
    pub requires_features: Vec<String>,
}

/// A pre-compiled image entry within a platform entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEntry {
    /// Image format identifier (e.g. `qcow2`).
    pub format: String,
    /// Absolute store path of the image artifact.
    pub store_path: String,
    /// NAR hash of the image (`sha256:...`).
    pub nar_hash: String,
    /// Uncompressed NAR size of the image in bytes.
    pub nar_size: u64,
    /// Immutable direct-download contract signed with the containing release.
    ///
    /// Catalog entries written before schema v1 omit this field. They remain
    /// installable through their signed NAR/store metadata, but are not eligible
    /// for direct disk-byte discovery until republished with delivery metadata.
    #[serde(
        default = "ImageDelivery::store_only",
        skip_serializing_if = "ImageDelivery::is_store_only"
    )]
    pub delivery: ImageDelivery,
}

impl ImageEntry {
    /// Validates this image's immutable direct-delivery contract against its
    /// signed containing release and platform.
    ///
    /// # Errors
    ///
    /// Returns an error when the contract is incomplete, internally
    /// inconsistent, path-unsafe, or does not match its signed parent.
    pub fn validate_delivery(&self, release: &str, platform: &str) -> anyhow::Result<()> {
        crate::store::store_path_hash(&self.store_path)
            .context("validating signed image store path")?;
        anyhow::ensure!(self.nar_size > 0, "image NAR size must be non-zero");
        crate::store::NarBytes::from_hash(&self.nar_hash, self.nar_size)
            .context("validating signed image NAR identity")?;
        let delivery = &self.delivery;
        anyhow::ensure!(
            !delivery.is_store_only(),
            "legacy store-only image has no direct-delivery contract"
        );
        delivery.validate(&self.format, release, platform)?;
        Ok(())
    }
}

/// Immutable artifact-delivery metadata signed inside an [`ImageEntry`].
///
/// The containing version and platform remain authoritative. The duplicated
/// identity fields below make resolved API objects self-describing and are
/// required to match their parents. Mutable channel membership is deliberately
/// not included: a signed channel payload resolves to the signed release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageDelivery {
    /// Delivery contract version.
    pub schema_version: u32,
    /// Signed logical release identity, equal to the containing version.
    pub release: String,
    /// Complete platform triple, equal to the containing platform key.
    pub platform: String,
    /// Architecture component derived from [`ImageDelivery::platform`].
    pub architecture: String,
    /// Stable identity shared by every encoding of the same logical disk.
    pub logical_image_id: String,
    /// SHA-256 of the canonical raw logical disk shared by all encodings.
    pub logical_disk_sha256: String,
    /// Exact useful filename assigned when the restored store output is copied.
    pub filename: String,
    /// Legacy content-addressed object key for direct disk bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub object_key: String,
    /// Media type of the encoded disk-image bytes.
    pub media_type: String,
    /// Compression applied to the disk-image encoding.
    pub compression: ImageCompression,
    /// Exact number of encoded disk-image bytes.
    pub byte_size: u64,
    /// Lowercase hexadecimal SHA-256 of the encoded disk-image bytes.
    pub sha256: String,
    /// End-user targets compatible with this image encoding.
    pub compatible_targets: Vec<ImageTarget>,
    /// Provider-owned boot artifact contract and immutable artifact location.
    pub artifact_contract: ImageArtifactContractReference,
}

impl ImageDelivery {
    /// Returns the internal marker used when reading pre-delivery catalogs.
    ///
    /// This value is never a valid direct-download contract and is omitted
    /// again when serialized. Current producers must emit schema v2 metadata.
    #[must_use]
    pub fn store_only() -> Self {
        Self {
            schema_version: 0,
            release: String::new(),
            platform: String::new(),
            architecture: String::new(),
            logical_image_id: String::new(),
            logical_disk_sha256: String::new(),
            filename: String::new(),
            object_key: String::new(),
            media_type: String::new(),
            compression: ImageCompression::None,
            byte_size: 0,
            sha256: String::new(),
            compatible_targets: Vec::new(),
            artifact_contract: ImageArtifactContractReference::empty(),
        }
    }

    /// Returns whether this value represents a pre-delivery store-only entry.
    #[must_use]
    pub fn is_store_only(&self) -> bool {
        self.schema_version == 0
    }

    /// Returns whether the artifact uses the unified Nix-cache data plane.
    #[must_use]
    pub fn is_store_backed(&self) -> bool {
        self.schema_version == 2
    }
}

impl ImageDelivery {
    /// Validates the complete contract against its signed parent identity.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown format mappings, unsafe paths, invalid
    /// digests or sizes, target/media mismatches, or parent identity drift.
    pub fn validate(&self, format: &str, release: &str, platform: &str) -> anyhow::Result<()> {
        use anyhow::{bail, ensure};

        ensure!(
            matches!(self.schema_version, 1 | 2),
            "unsupported image delivery schema"
        );
        ensure!(
            self.release == release,
            "image release does not match containing version"
        );
        ensure!(
            self.platform == platform,
            "image platform does not match containing platform"
        );
        let architecture = platform
            .split_once('-')
            .map(|(architecture, _)| architecture)
            .filter(|architecture| !architecture.is_empty())
            .ok_or_else(|| anyhow::anyhow!("image platform has no architecture component"))?;
        ensure!(
            self.architecture == architecture,
            "image architecture does not match containing platform"
        );
        validate_image_filename(&self.filename)?;
        validate_sha256(&self.logical_image_id, "logical image")?;
        validate_sha256(&self.logical_disk_sha256, "logical disk")?;
        validate_sha256(&self.sha256, "image")?;
        ensure!(self.byte_size > 0, "image byte size must be non-zero");
        if self.schema_version == 1 {
            ensure!(
                self.object_key == immutable_image_object_key(&self.sha256, &self.filename),
                "image object key is not the canonical content-addressed key"
            );
        } else {
            ensure!(
                self.object_key.is_empty(),
                "store-backed image must not declare a direct object key"
            );
        }
        let (extension, media_type, targets): (&str, &str, &[ImageTarget]) = match format {
            "raw" => (
                "img.zst",
                "application/vnd.aos.disk-image.raw+zstd",
                &[ImageTarget::BareMetal],
            ),
            "qcow2" => (
                "qcow2",
                "application/vnd.aos.disk-image.qcow2",
                &[ImageTarget::QemuKvm, ImageTarget::Openstack],
            ),
            "vmdk" => ("vmdk", "application/x-vmdk", &[ImageTarget::Vmware]),
            "vhd" => (
                "vhd",
                "application/vnd.aos.disk-image.vhd",
                &[ImageTarget::HyperV],
            ),
            _ => bail!("unsupported direct image format '{format}'"),
        };
        if format == "raw" {
            ensure!(
                self.compression == ImageCompression::Zstd,
                "raw image must use zstd delivery compression"
            );
        } else {
            ensure!(
                self.compression == ImageCompression::None,
                "converted disk images must not declare outer compression"
            );
        }
        ensure!(
            self.filename.ends_with(&format!(".{extension}")),
            "image filename extension does not match format"
        );
        ensure!(
            self.media_type == media_type,
            "image media type does not match format"
        );
        ensure!(
            self.compatible_targets.as_slice() == targets,
            "image compatible targets do not match format"
        );
        self.artifact_contract
            .validate(self.schema_version, &self.sha256)?;
        Ok(())
    }
}

/// Opaque provider-owned contract for the boot artifacts carried by an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageArtifactContractReference {
    /// Provider-owned schema identifier used to select a compatible consumer.
    pub schema: String,
    /// Immutable contract document containing provider-specific artifact facts.
    pub document: ImageArtifactContractDocumentReference,
    /// Store-backed artifact set interpreted by the selected provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<ImageStoreReference>,
}

impl ImageArtifactContractReference {
    fn empty() -> Self {
        Self {
            schema: String::new(),
            document: ImageArtifactContractDocumentReference {
                filename: String::new(),
                object_key: String::new(),
                store_path: String::new(),
                nar_hash: String::new(),
                nar_size: 0,
                media_type: String::new(),
                byte_size: 0,
                sha256: String::new(),
            },
            artifacts: None,
        }
    }

    fn validate(&self, delivery_schema: u32, image_sha256: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.schema.is_empty()
                && self.schema.len() <= 128
                && self.schema.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
                }),
            "image artifact contract schema is not a bounded portable identifier"
        );
        self.document.validate(delivery_schema, image_sha256)?;
        if delivery_schema == 2 {
            self.artifacts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("store-backed image lacks an artifact set"))?
                .validate("image artifact contract")?;
        } else {
            anyhow::ensure!(
                self.artifacts.is_none(),
                "direct image contract must not declare a store-backed artifact set"
            );
        }
        Ok(())
    }
}

/// Authenticated identity of one artifact in the unified Nix-cache data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageStoreReference {
    /// Canonical Nix store path restored from the cache.
    pub store_path: String,
    /// Hash of the artifact's uncompressed NAR.
    pub nar_hash: String,
    /// Size of the artifact's uncompressed NAR in bytes.
    pub nar_size: u64,
}

impl ImageStoreReference {
    /// Validates the complete Nix store identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the store path, hash, or size is malformed.
    pub fn validate(&self, label: &str) -> anyhow::Result<()> {
        crate::store::store_path_hash(&self.store_path)
            .with_context(|| format!("validating {label} store path"))?;
        anyhow::ensure!(self.nar_size > 0, "{label} NAR size must be non-zero");
        crate::store::NarBytes::from_hash(&self.nar_hash, self.nar_size)
            .with_context(|| format!("validating {label} NAR identity"))?;
        Ok(())
    }
}

/// Compression applied to encoded disk-image bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageCompression {
    /// No outer compression; the bytes are the named disk encoding.
    None,
    /// Zstandard compression of the complete named disk encoding.
    Zstd,
}

/// End-user execution or installation target for an AOS system image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageTarget {
    /// A physical disk written directly from a raw image.
    BareMetal,
    /// QEMU or KVM virtual machines.
    QemuKvm,
    /// OpenStack virtual machines.
    Openstack,
    /// VMware or vSphere virtual machines.
    Vmware,
    /// Microsoft Hyper-V virtual machines.
    HyperV,
}

/// Content-bound reference to a provider-owned image artifact contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageArtifactContractDocumentReference {
    /// Exact metadata filename.
    pub filename: String,
    /// Legacy content-addressed object key for direct metadata bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub object_key: String,
    /// Canonical Nix store path containing the metadata as one regular file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub store_path: String,
    /// Signed NAR hash of [`ImageArtifactContractDocumentReference::store_path`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nar_hash: String,
    /// Exact uncompressed NAR size of [`ImageArtifactContractDocumentReference::store_path`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub nar_size: u64,
    /// Media type of the metadata document.
    pub media_type: String,
    /// Exact metadata byte length.
    pub byte_size: u64,
    /// Lowercase hexadecimal SHA-256 of the metadata bytes.
    pub sha256: String,
}

impl ImageArtifactContractDocumentReference {
    fn validate(&self, schema_version: u32, image_sha256: &str) -> anyhow::Result<()> {
        use anyhow::ensure;

        validate_image_filename(&self.filename)?;
        ensure!(
            !self.media_type.is_empty()
                && self.media_type.len() <= 128
                && self.media_type.is_ascii()
                && self.media_type.contains('/')
                && !self
                    .media_type
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace()),
            "invalid image artifact contract media type"
        );
        ensure!(
            self.byte_size > 0,
            "image artifact contract byte size must be non-zero"
        );
        validate_sha256(&self.sha256, "image artifact contract")?;
        if schema_version == 1 {
            ensure!(
                self.object_key
                    == immutable_image_contract_object_key(
                        image_sha256,
                        &self.sha256,
                        &self.filename,
                    ),
                "image artifact contract object key is not canonical"
            );
            ensure!(
                self.store_path.is_empty() && self.nar_hash.is_empty() && self.nar_size == 0,
                "direct image artifact contract must not declare store delivery"
            );
        } else {
            ensure!(
                self.object_key.is_empty(),
                "store-backed image artifact contract must not declare a direct object key"
            );
            crate::store::store_path_hash(&self.store_path)
                .context("validating image artifact contract store path")?;
            ensure!(
                self.nar_size > 0,
                "image artifact contract NAR size must be non-zero"
            );
            crate::store::NarBytes::from_hash(&self.nar_hash, self.nar_size)
                .context("validating image artifact contract NAR identity")?;
        }
        Ok(())
    }
}

/// Returns the canonical immutable object key for direct disk-image bytes.
pub fn immutable_image_object_key(sha256: &str, filename: &str) -> String {
    format!("images/sha256/{sha256}/{filename}")
}

/// Returns the canonical immutable object key for an image artifact contract.
pub fn immutable_image_contract_object_key(
    image_sha256: &str,
    contract_sha256: &str,
    filename: &str,
) -> String {
    format!("images/sha256/{image_sha256}/contracts/{contract_sha256}/{filename}")
}

fn validate_sha256(value: &str, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} SHA-256 must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn validate_image_filename(filename: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !filename.is_empty() && filename.len() <= 128,
        "image filename must contain between 1 and 128 ASCII bytes"
    );
    anyhow::ensure!(
        filename.is_ascii()
            && filename.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
            })
            && filename
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && !filename.contains(".."),
        "image filename must be a portable ASCII basename"
    );
    let stem = filename.split('.').next().unwrap_or_default();
    anyhow::ensure!(
        !matches!(
            stem.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ),
        "image filename uses a reserved portable basename"
    );
    Ok(())
}

#[cfg(test)]
mod image_delivery_tests {
    use super::*;

    #[test]
    fn catalog_digest_binds_registry_and_is_order_independent() {
        let first = [
            ("images/b", "disk", 2, "b"),
            ("images/a", "image-info", 1, "a"),
        ];
        let reversed = [first[1], first[0]];
        let digest = image_catalog_digest("andyl", first);
        assert_eq!(digest, image_catalog_digest("andyl", reversed));
        assert_ne!(digest, image_catalog_digest("another", first));
        assert_ne!(
            digest,
            image_catalog_digest("andyl", [("images/b", "disk", 3, "b"), first[1]])
        );
    }

    fn delivery(format: &str) -> ImageDelivery {
        let image_sha256 = "a".repeat(64);
        let info_sha256 = "b".repeat(64);
        let (extension, media_type, targets) = match format {
            "raw" => (
                "img.zst",
                "application/vnd.aos.disk-image.raw+zstd",
                vec![ImageTarget::BareMetal],
            ),
            "qcow2" => (
                "qcow2",
                "application/vnd.aos.disk-image.qcow2",
                vec![ImageTarget::QemuKvm, ImageTarget::Openstack],
            ),
            "vmdk" => ("vmdk", "application/x-vmdk", vec![ImageTarget::Vmware]),
            "vhd" => (
                "vhd",
                "application/vnd.aos.disk-image.vhd",
                vec![ImageTarget::HyperV],
            ),
            other => panic!("unsupported fixture format {other}"),
        };
        let filename = format!("aos-server.{extension}");
        ImageDelivery {
            schema_version: 1,
            release: "2026.08".to_string(),
            platform: "x86_64-linux".to_string(),
            architecture: "x86_64".to_string(),
            logical_image_id: "c".repeat(64),
            logical_disk_sha256: image_sha256.clone(),
            filename: filename.clone(),
            object_key: immutable_image_object_key(&image_sha256, &filename),
            media_type: media_type.to_string(),
            compression: if format == "raw" {
                ImageCompression::Zstd
            } else {
                ImageCompression::None
            },
            byte_size: 4096,
            sha256: image_sha256.clone(),
            compatible_targets: targets,
            artifact_contract: ImageArtifactContractReference {
                schema: "aos.test-image/v1".to_string(),
                document: ImageArtifactContractDocumentReference {
                    filename: "image-info.json".to_string(),
                    object_key: immutable_image_contract_object_key(
                        &image_sha256,
                        &info_sha256,
                        "image-info.json",
                    ),
                    store_path: String::new(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    media_type: "application/vnd.aos.image-info+json".to_string(),
                    byte_size: 512,
                    sha256: info_sha256,
                },
                artifacts: None,
            },
        }
    }

    fn package_with_images(images: &str) -> String {
        format!(
            r#"[package]
name = "server"
description = "test"
license = "MIT"
maintainer = "test"
sysroot = true

[[versions]]
version = "2026.08"

[versions.platforms.x86_64-linux]
store_path = "/aos/store/server"
closure_size = 1
source_drv = ""
source_nar_hash = ""
{images}
"#
        )
    }

    fn raw_image_block(with_delivery: bool) -> String {
        #[derive(Serialize)]
        struct DeliveryWrapper<'a> {
            delivery: &'a ImageDelivery,
        }
        let image = delivery("raw");
        let base = r#"
[[versions.platforms.x86_64-linux.images]]
format = "raw"
store_path = "/aos/store/00000000000000000000000000000000-server-raw"
nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
nar_size = 1
"#;
        if with_delivery {
            let encoded = toml::to_string(&DeliveryWrapper { delivery: &image })
                .unwrap()
                .replace(
                    "[delivery]",
                    "[versions.platforms.x86_64-linux.images.delivery]",
                )
                .replace(
                    "[delivery.artifact_contract]",
                    "[versions.platforms.x86_64-linux.images.delivery.artifact_contract]",
                )
                .replace(
                    "[delivery.artifact_contract.document]",
                    "[versions.platforms.x86_64-linux.images.delivery.artifact_contract.document]",
                );
            format!("{base}\n{}", encoded)
        } else {
            base.to_string()
        }
    }

    #[test]
    fn every_supported_format_has_one_canonical_target_mapping() {
        for format in ["raw", "qcow2", "vmdk", "vhd"] {
            delivery(format)
                .validate(format, "2026.08", "x86_64-linux")
                .unwrap();
        }
    }

    #[test]
    fn delivery_contract_round_trips_without_losing_integrity_fields() {
        let original = delivery("qcow2");
        let encoded = toml::to_string(&original).unwrap();
        let decoded: ImageDelivery = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn store_backed_delivery_requires_metadata_nar_identity_and_no_direct_keys() {
        let mut image = delivery("qcow2");
        image.schema_version = 2;
        image.object_key.clear();
        image.artifact_contract.document.object_key.clear();
        image.artifact_contract.document.store_path =
            "/nix/store/11111111111111111111111111111111-image-info".to_string();
        image.artifact_contract.document.nar_hash =
            "sha256:1111111111111111111111111111111111111111111111111111".to_string();
        image.artifact_contract.document.nar_size = 512;
        image.artifact_contract.artifacts = Some(ImageStoreReference {
            store_path: "/nix/store/22222222222222222222222222222222-image-artifacts".to_string(),
            nar_hash: format!("sha256:{}", "2".repeat(52)),
            nar_size: 4096,
        });
        image.validate("qcow2", "2026.08", "x86_64-linux").unwrap();

        image.object_key = immutable_image_object_key(&image.sha256, &image.filename);
        assert!(image.validate("qcow2", "2026.08", "x86_64-linux").is_err());
    }

    #[test]
    fn store_backed_delivery_authenticates_artifact_contract_identity() {
        let mut image = delivery("raw");
        image.schema_version = 2;
        image.object_key.clear();
        image.artifact_contract.document.object_key.clear();
        image.artifact_contract.document.store_path =
            "/nix/store/11111111111111111111111111111111-image-info".to_string();
        image.artifact_contract.document.nar_hash = format!("sha256:{}", "1".repeat(52));
        image.artifact_contract.document.nar_size = 512;
        image.artifact_contract.artifacts = Some(ImageStoreReference {
            store_path: "/nix/store/22222222222222222222222222222222-update-payload".to_string(),
            nar_hash: format!("sha256:{}", "2".repeat(52)),
            nar_size: 4096,
        });
        image.validate("raw", "2026.08", "x86_64-linux").unwrap();

        image.artifact_contract.artifacts.as_mut().unwrap().nar_size = 0;
        assert!(image.validate("raw", "2026.08", "x86_64-linux").is_err());
    }

    #[test]
    fn delivery_contract_rejects_path_traversal_and_tampering() {
        let mut traversal = delivery("raw");
        traversal.filename = "../server.img".to_string();
        assert!(
            traversal
                .validate("raw", "2026.08", "x86_64-linux")
                .is_err()
        );

        let mut tampered = delivery("raw");
        tampered.sha256 = "A".repeat(64);
        assert!(tampered.validate("raw", "2026.08", "x86_64-linux").is_err());

        let mut wrong_target = delivery("qcow2");
        wrong_target.compatible_targets = vec![ImageTarget::BareMetal];
        assert!(
            wrong_target
                .validate("qcow2", "2026.08", "x86_64-linux")
                .is_err()
        );

        let mut uncompressed_raw = delivery("raw");
        uncompressed_raw.compression = ImageCompression::None;
        assert!(
            uncompressed_raw
                .validate("raw", "2026.08", "x86_64-linux")
                .is_err()
        );

        let mut compressed_qcow2 = delivery("qcow2");
        compressed_qcow2.compression = ImageCompression::Zstd;
        assert!(
            compressed_qcow2
                .validate("qcow2", "2026.08", "x86_64-linux")
                .is_err()
        );
    }

    #[test]
    fn delivery_contract_rejects_parent_identity_drift() {
        let contract = delivery("vmdk");
        assert!(
            contract
                .validate("vmdk", "2026.09", "x86_64-linux")
                .is_err()
        );
        assert!(
            contract
                .validate("vmdk", "2026.08", "aarch64-linux")
                .is_err()
        );
    }

    #[test]
    fn shared_parser_accepts_store_only_entries_but_rejects_duplicate_formats() {
        let without_delivery = raw_image_block(false);
        let legacy = package_with_images(&without_delivery);
        let parsed = parse_package_file(&legacy).unwrap();
        let image = &parsed.versions[0].platforms["x86_64-linux"].images[0];
        assert!(image.delivery.is_store_only());
        assert!(!toml::to_string(&parsed).unwrap().contains("delivery"));

        let duplicate = package_with_images(&format!("{without_delivery}{without_delivery}"));
        assert!(parse_package_file(&duplicate).is_err());

        let direct = raw_image_block(true);
        let mixed = package_with_images(&format!("{without_delivery}{direct}"));
        assert!(parse_package_file(&mixed).is_err());
    }

    #[test]
    fn shared_parser_validates_named_output_identity() {
        let valid = package_with_images(
            r#"
[versions.platforms.x86_64-linux.named_outputs]
dev = "/aos/store/server-dev"
tools = "/aos/store/server-tools"
"#,
        );
        let parsed = parse_package_file(&valid).expect("valid named outputs");
        assert_eq!(
            parsed.versions[0].platforms["x86_64-linux"]
                .named_outputs
                .len(),
            2
        );

        let reserved = valid.replace("dev =", "out =");
        assert!(parse_package_file(&reserved).is_err());

        let repeated = valid.replace("/aos/store/server-dev", "/aos/store/server");
        assert!(parse_package_file(&repeated).is_err());
    }

    #[test]
    fn shared_parser_requires_one_logical_identity_across_encodings() {
        let raw = raw_image_block(true);
        let qcow2 = raw_image_block(true)
            .replace("format = \"raw\"", "format = \"qcow2\"")
            .replace("server-raw", "server-qcow2")
            .replace("aos-server.img.zst", "aos-server.qcow2")
            .replace(
                "application/vnd.aos.disk-image.raw+zstd",
                "application/vnd.aos.disk-image.qcow2",
            )
            .replace("compression = \"zstd\"", "compression = \"none\"")
            .replace(
                "compatible_targets = [\"bare-metal\"]",
                "compatible_targets = [\"qemu-kvm\", \"openstack\"]",
            );
        assert!(parse_package_file(&package_with_images(&format!("{raw}{qcow2}"))).is_ok());

        let drifted = qcow2.replace(
            &format!("logical_image_id = \"{}\"", "c".repeat(64)),
            &format!("logical_image_id = \"{}\"", "e".repeat(64)),
        );
        let error =
            parse_package_file(&package_with_images(&format!("{raw}{drifted}"))).unwrap_err();
        assert!(format!("{error:#}").contains("different logical identities"));
    }

    #[test]
    fn filename_policy_rejects_header_and_url_ambiguity() {
        for filename in [
            "server%2fescape.img",
            "server;attachment.img",
            "server?.img",
            "server#.img",
            "server\".img",
            "sérver.img",
            "CON.img",
        ] {
            let mut contract = delivery("raw");
            contract.filename = filename.to_string();
            contract.object_key = immutable_image_object_key(&contract.sha256, filename);
            assert!(contract.validate("raw", "2026.08", "x86_64-linux").is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// RFC-0001 package metadata
// ---------------------------------------------------------------------------
//
// These pure serde structs and their inherent helpers moved here from
// `aos-package`'s `types` module (RFC-0004 Phase 5) so the wasm-clean indexer
// and the Cloudflare Worker can deserialize the RFC-0001 package metadata
// that the producer publishes. `aos-package` re-exports the shared types.

/// A pre-compiled image format entry within a sysroot package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SysrootImageEntry {
    /// Image format identifier (e.g. `qcow2`, `raw`), matched against
    /// `apm install --image <FMT>`.
    pub format: String,
    /// Store path containing the image file.
    pub store_path: String,
    /// Hash of the image's uncompressed NAR: `"sha256:..."`.
    pub nar_hash: String,
    /// Size of the image's uncompressed NAR in bytes.
    pub nar_size: u64,
    /// Immutable direct-download contract from the signed image catalog.
    #[serde(
        default = "ImageDelivery::store_only",
        skip_serializing_if = "ImageDelivery::is_store_only"
    )]
    pub delivery: ImageDelivery,
}

/// Registry-published runtime integrity, attestation, and provenance facts.
///
/// These are catalog facts, not runtime authority. The registry distributes
/// signed root hashes and provenance references, while dm-verity is enforced by
/// the kernel against the platform keyring and TPM measurements are verified by
/// a fleet verifier against the golden tuple.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationMeta {
    /// Digest used as the package-root input to the TPM measurement tuple.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_digest: Option<String>,
    /// dm-verity Merkle root hash for the package root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
    /// Registry-served PKCS#7 signature over [`AttestationMeta::root_hash`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash_sig: Option<String>,
    /// Registry-served in-toto/SLSA provenance attestation reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// Golden package measurement tuple extended into the package-set PCR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement: Option<String>,
}

impl AttestationMeta {
    /// Returns whether no attestation facts are declared.
    pub fn is_empty(&self) -> bool {
        self.root_digest.is_none()
            && self.root_hash.is_none()
            && self.root_hash_sig.is_none()
            && self.provenance.is_none()
            && self.measurement.is_none()
    }
}

// ---------------------------------------------------------------------------
// Committed root config (`registry.toml`)
// ---------------------------------------------------------------------------

use anyhow::{Context, Result, bail};

use crate::stack::{self, StackNode};

/// The committed `registry.toml` root configuration.
///
/// Lives at the repository root; carries the registry's display metadata and
/// the unified `[caches]` cache stack (RFC-0004) — the single source of truth
/// for which binary caches the registry advertises to consumers. A pure,
/// deserialize-only schema with no I/O, so the wasm-clean indexer and the
/// Cloudflare Worker share it with `aos-package`'s native git-CLI path (which
/// re-exports it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootConfig {
    /// The `[registry]` metadata table.
    pub registry: RegistryRootMeta,
    /// The committed `[support]` release-train support policy, copied
    /// verbatim from the qualification contract's `support` export.
    ///
    /// Absent registries make no support statement; the public browser then
    /// falls back to treating the newest two stable trains as supported. See
    /// [`crate::support`] for the schema and its invariants.
    #[serde(
        default,
        deserialize_with = "deserialize_support",
        skip_serializing_if = "Option::is_none"
    )]
    pub support: Option<crate::support::SupportPolicy>,
    /// The committed `[caches]` cache stack: the binary caches every consumer
    /// of this registry should use, in preference order.
    ///
    /// Absent when the registry advertises no caches. The hard-cutover schema
    /// accepts only the `[caches]` stack table; array-shaped cache lists are a
    /// schema error. Resolve the effective list with
    /// [`RegistryRootConfig::cache_entries`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caches: Option<CachesConfig>,
}

/// The committed `[caches]` stack table.
///
/// The table-only representation deliberately rejects an array during TOML
/// deserialization. There is no legacy list branch after the topology cutover.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CachesConfig(pub toml::map::Map<String, toml::Value>);

impl RegistryRootConfig {
    /// Returns the flattened `(url, priority)` list consumers resolve.
    ///
    /// The stack is parsed and flattened with [`stack::to_priority_caches`]
    /// (priority descending by depth-first order, base `100`). A malformed
    /// stack yields an empty list rather than panicking — callers log the
    /// omission.
    #[must_use]
    pub fn cache_entries(&self) -> Vec<CacheEntry> {
        match &self.caches {
            None => Vec::new(),
            Some(CachesConfig(value)) => {
                match stack::parse_cache_stack(toml::Value::Table(value.clone())) {
                    Ok(node) => stack::to_priority_caches(&node, default_cache_priority())
                        .into_iter()
                        .map(|(url, priority)| CacheEntry { url, priority })
                        .collect(),
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    /// Returns the parsed cache stack when `[caches]` is in stack form.
    ///
    /// `None` for an absent or malformed stack — mirror validation treats a
    /// missing or unparseable stack as "no mirror groups to enforce" rather
    /// than panicking.
    #[must_use]
    pub fn cache_stack(&self) -> Option<StackNode> {
        match &self.caches {
            Some(CachesConfig(value)) => {
                stack::parse_cache_stack(toml::Value::Table(value.clone())).ok()
            }
            _ => None,
        }
    }
}

/// Registry metadata in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootMeta {
    /// Canonical registry name.
    pub name: String,
    /// Optional one-line human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional longer README-style preamble (a paragraph or three), shown
    /// above the registry home. Blank lines separate paragraphs.
    #[serde(default)]
    pub readme: Option<String>,
    /// Exact release initially selected by the public registry browser.
    ///
    /// This preference does not change package-manager tracking or channel
    /// assignments. When absent, the browser prefers the highest verified
    /// non-prerelease version, then the highest verified prerelease.
    #[serde(
        default,
        deserialize_with = "deserialize_default_release",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_release: Option<String>,
    /// Whether the producer records content addresses in the `store/`
    /// realisation graph (RFC-0005), so the registry serves both
    /// input-addressed and content-addressed consumers. Default `true`;
    /// set `false` for a pure input-addressed registry.
    #[serde(default = "default_content_addressed")]
    pub content_addressed: bool,
}

/// Validates the committed support policy when reading registry metadata.
fn deserialize_support<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<crate::support::SupportPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<crate::support::SupportPolicy>::deserialize(deserializer)?;
    if let Some(policy) = &value {
        policy.validate().map_err(serde::de::Error::custom)?;
    }
    Ok(value)
}

/// Validates the optional browser preference when reading committed metadata.
fn deserialize_default_release<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(version) = &value {
        semver::Version::parse(version).map_err(serde::de::Error::custom)?;
    }
    Ok(value)
}

/// Serde default for [`RegistryRootMeta::content_addressed`].
fn default_content_addressed() -> bool {
    true
}

/// A binary cache entry in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Base URL of the binary cache.
    pub url: String,
    /// Cache selection priority — higher is tried first (default 100).
    #[serde(default = "default_cache_priority")]
    pub priority: u32,
}

/// Serde default for [`CacheEntry::priority`].
fn default_cache_priority() -> u32 {
    100
}

// ---------------------------------------------------------------------------
// Committed trust roster (`keys.toml`)
// ---------------------------------------------------------------------------

/// The `keys.toml` schema version this build reads and writes.
pub const KEYS_TOML_SCHEMA: u32 = 1;

/// A currently active registry signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterKey {
    /// Human-chosen stable identifier used by revocation entries.
    pub id: String,
    /// Key in `registry:Ed25519:<base64>` form.
    pub key: String,
}

/// A planned retired key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedKey {
    /// Identifier of the roster key being revoked.
    pub id: String,
    /// Retired public key, retained for historical provenance verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// First transparency sequence that must not trust this retired key.
    #[serde(
        default,
        rename = "provenance-before-sequence",
        skip_serializing_if = "Option::is_none"
    )]
    pub provenance_before_sequence: Option<u64>,
    /// First package-contract sequence that must not trust this retired key.
    #[serde(
        default,
        rename = "package-contract-before-sequence",
        skip_serializing_if = "Option::is_none"
    )]
    pub package_contract_before_sequence: Option<u64>,
    /// Optional human-readable revocation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Trust roster stored as the committed tree file `keys.toml`.
///
/// A pure, serde-only schema (no I/O, no key parsing) so the wasm-clean
/// indexer can deserialize a committed roster and extend its trusted set;
/// `aos-package` re-exports this and layers the native load/validate/pin
/// helpers on top.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysToml {
    /// Schema version; must equal [`KEYS_TOML_SCHEMA`].
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// Currently active signing keys (`[[keys]]` in the file).
    #[serde(default, rename = "keys")]
    pub active: Vec<RosterKey>,
    /// Keys declared revoked (`[[revoked]]` in the file).
    #[serde(default)]
    pub revoked: Vec<RevokedKey>,
}

impl Default for KeysToml {
    fn default() -> Self {
        Self {
            schema: KEYS_TOML_SCHEMA,
            active: Vec::new(),
            revoked: Vec::new(),
        }
    }
}

/// Serde default for [`KeysToml::schema`].
fn default_schema() -> u32 {
    KEYS_TOML_SCHEMA
}

// ---------------------------------------------------------------------------
// Package name validation and document parsing
// ---------------------------------------------------------------------------

/// Validate a registry package name for path and schema safety.
///
/// Package names form the `packages/<bucket>/<name>.toml` path and embed in
/// store path names, require an alphanumeric leading character so bucketing
/// stays stable, and reject anything that could be interpreted as a path,
/// shell word, or TOML delimiter.
///
/// # Errors
///
/// Returns an error when `name` is empty, starts with a non-alphanumeric
/// character, or contains any byte outside ASCII letters, digits, `+`, `.`,
/// `_`, `=`, and `-`.
pub fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("package name must not be empty");
    }

    if !name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric())
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '_' | '=' | '-'))
    {
        bail!(
            "invalid package name '{name}': use only ASCII letters, digits, '+', '.', '_', '=' and '-', starting with a letter or digit"
        );
    }

    Ok(())
}

/// Return the registry package bucket for a validated package name.
///
/// Package metadata files live under `packages/<bucket>/<name>.toml`, where
/// the bucket is the lowercase first ASCII character of the package name.
/// Call [`validate_package_name`] before using this for path construction.
#[must_use]
pub fn package_name_bucket(name: &str) -> String {
    name.chars()
        .next()
        .map(|ch| ch.to_ascii_lowercase().to_string())
        .unwrap_or_else(|| "_".to_string())
}

/// Parse a whole committed package TOML document, validating its declared name.
///
/// Unlike a flatten-to-newest install resolver, this returns the complete
/// file: every version and every platform entry, exactly as committed —
/// the unflattened view the registry hub's indexer needs.
///
/// # Errors
///
/// Returns an error if `content` is not valid package TOML or the declared
/// package name is not path-safe.
pub fn parse_package_file(content: &str) -> Result<PackageToml> {
    let toml: PackageToml = toml::from_str(content).context("invalid package TOML")?;
    validate_package_name(&toml.package.name)?;
    for version in &toml.versions {
        for (platform, entry) in &version.platforms {
            let mut output_paths = HashSet::from([entry.store_path.as_str()]);
            for (output, store_path) in &entry.named_outputs {
                if output == "out"
                    || output.is_empty()
                    || output.len() > 256
                    || !output.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
                    })
                {
                    bail!(
                        "release '{}' platform '{}' contains invalid named output '{}'",
                        version.version,
                        platform,
                        output
                    );
                }
                if !store_path.starts_with('/')
                    || store_path.ends_with('/')
                    || store_path.contains("//")
                    || store_path.split('/').any(|part| matches!(part, "." | ".."))
                {
                    bail!(
                        "release '{}' platform '{}' named output '{}' has an invalid store path",
                        version.version,
                        platform,
                        output
                    );
                }
                if !output_paths.insert(store_path) {
                    bail!(
                        "release '{}' platform '{}' repeats output store path '{}'",
                        version.version,
                        platform,
                        store_path
                    );
                }
            }

            let mut formats = HashSet::new();
            for image in &entry.images {
                if !formats.insert(image.format.as_str()) {
                    bail!(
                        "release '{}' platform '{}' contains duplicate '{}' image encodings",
                        version.version,
                        platform,
                        image.format
                    );
                }
                if !image.delivery.is_store_only() {
                    image
                        .validate_delivery(&version.version, platform)
                        .with_context(|| {
                            format!(
                                "validating image '{}' for release '{}' platform '{}'",
                                image.format, version.version, platform
                            )
                        })?;
                }
            }
            let direct_images = entry
                .images
                .iter()
                .filter(|image| !image.delivery.is_store_only())
                .collect::<Vec<_>>();
            if !direct_images.is_empty() {
                let Some(first_image) = direct_images.first().copied() else {
                    continue;
                };
                let first = &first_image.delivery;
                for image in direct_images.iter().skip(1).copied() {
                    let delivery = &image.delivery;
                    anyhow::ensure!(
                        delivery.logical_image_id == first.logical_image_id,
                        "release '{}' platform '{}' image encodings have different logical identities",
                        version.version,
                        platform
                    );
                    anyhow::ensure!(
                        delivery.artifact_contract.schema == first.artifact_contract.schema
                            && delivery.artifact_contract.artifacts
                                == first.artifact_contract.artifacts,
                        "release '{}' platform '{}' image encodings have different artifact contracts",
                        version.version,
                        platform
                    );
                    // The provider contract document may bind format-specific
                    // metadata while every encoding shares one artifact set.
                }
            }
        }
    }
    Ok(toml)
}

#[cfg(test)]
mod root_config_tests {
    use super::*;

    const META: &str = r#"
        [registry]
        name = "example"
    "#;

    #[test]
    fn support_policy_parses_and_fails_closed() {
        let src = format!(
            "{META}\n[support.default]\nkind = \"standard\"\nsuperseded_after_trains = 3\n\n[support.trains.\"2026.9\"]\nkind = \"lts\"\nsupported_until = \"2028-09-30\"\n"
        );
        let cfg: RegistryRootConfig = toml::from_str(&src).unwrap();
        let policy = cfg.support.unwrap();
        assert_eq!(policy.default.superseded_after_trains, 3);
        assert_eq!(policy.trains.len(), 1);
        assert_eq!(policy.kind((2026, 9)), crate::support::SupportKind::Lts);
        let absent: RegistryRootConfig = toml::from_str(META).unwrap();
        assert!(absent.support.is_none());
        // An LTS train without an end date is a schema error, not a warning.
        let broken = format!("{META}\n[support.trains.\"2026.9\"]\nkind = \"lts\"\n");
        assert!(toml::from_str::<RegistryRootConfig>(&broken).is_err());
    }

    #[test]
    fn single_endpoint_stack_parses_and_flattens() {
        let src = format!("{META}\n[caches]\nendpoint = \"https://only\"\n");
        let cfg: RegistryRootConfig = toml::from_str(&src).unwrap();
        assert!(matches!(cfg.caches, Some(CachesConfig(_))));
        let entries = cfg.cache_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://only");
        assert_eq!(entries[0].priority, 100);
        assert_eq!(
            cfg.cache_stack(),
            Some(StackNode::Endpoint("https://only".into()))
        );
    }

    #[test]
    fn try_stack_flattens_to_descending_priority() {
        let src = format!(
            "{META}\n[caches]\nkind = \"try\"\nmembers = [{{ endpoint = \"https://a\" }}, {{ endpoint = \"https://b\" }}]\n"
        );
        let cfg: RegistryRootConfig = toml::from_str(&src).unwrap();
        let entries = cfg.cache_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            (entries[0].url.as_str(), entries[0].priority),
            ("https://a", 100)
        );
        assert_eq!(
            (entries[1].url.as_str(), entries[1].priority),
            ("https://b", 99)
        );
        assert!(matches!(cfg.cache_stack(), Some(StackNode::Try(_))));
    }

    #[test]
    fn absent_caches_yields_empty() {
        let cfg: RegistryRootConfig = toml::from_str(META).unwrap();
        assert!(cfg.caches.is_none());
        assert!(cfg.cache_entries().is_empty());
        assert!(cfg.cache_stack().is_none());
    }

    #[test]
    fn array_shaped_caches_are_rejected_at_the_schema_boundary() {
        let source =
            format!("{META}\n[[caches]]\nurl = \"https://removed.example\"\npriority = 100\n");
        assert!(toml::from_str::<RegistryRootConfig>(&source).is_err());
    }
}

// ---------------------------------------------------------------------------
// Configuration-module schema represented as pure manifest data.
// ---------------------------------------------------------------------------

/// Signed identity of a canonical package-documentation Nix store object.
///
/// The object is one non-executable regular-file NAR with no references. Its
/// JSON bytes describe this exact package version/platform, but deliberately do
/// not repeat the store path so prose never creates a retention edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationArtifactMeta {
    /// Closed canonical document format identifier.
    pub format: String,
    /// Store path of the single-file documentation object.
    pub store_path: String,
    /// Hash of the uncompressed NAR.
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: u64,
    /// SHA-256 digest of the exact canonical JSON file bytes.
    pub document_sha256: String,
    /// Exact canonical JSON file size in bytes.
    pub document_size: u64,
    /// Digest over configuration semantics, excluding explanatory prose.
    pub semantic_schema_sha256: String,
    /// Direct references. Version 1 requires this to be empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Authenticated metadata for one symbolic package contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContractMeta {
    /// Exact reference-free regular file containing the canonical projection.
    pub document: PackageContractDocumentMeta,
    /// Exact primary package artifact supplied to the projection resolver.
    pub payload: PackageContractArtifactMeta,
    /// Exact build-source artifact supplied to the projection resolver.
    pub source: PackageContractArtifactMeta,
    /// Exact release output bindings for every symbolic selector.
    pub selectors: Vec<PackageContractSelectorMeta>,
    /// Registry-relative dedicated DSSE statement for this contract.
    pub provenance: String,
}

/// Authenticates the exact regular file carrying a symbolic package contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContractDocumentMeta {
    /// Store path of the regular-file contract object.
    pub store_path: String,
    /// Hash of the uncompressed regular-file NAR.
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: u64,
    /// SHA-256 digest of the exact canonical document bytes.
    pub document_sha256: String,
    /// Exact canonical document byte length.
    pub document_size: u64,
    /// Direct references; package contract documents require an empty set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Binds one symbolic package output selector to an authenticated artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContractSelectorMeta {
    /// Package name, or `self` for the contract owner.
    pub package: String,
    /// Selected package output name.
    pub output: String,
    /// Exact selected artifact and its complete authenticated closure.
    pub artifact: PackageContractArtifactMeta,
}

/// Retains one selected package artifact and its complete authenticated closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContractArtifactMeta {
    /// Domain-specific content identity derived from the selected artifact.
    pub content: String,
    /// Exact store path copied from the package manifest.
    pub store_path: String,
    /// Exact NAR identity copied from the package manifest.
    pub nar_hash: String,
    /// Uncompressed artifact NAR size in bytes.
    pub nar_size: u64,
    /// Domain-separated digest of the complete ordered closure catalog.
    pub closure_digest: String,
    /// Complete sorted closure, including the artifact root.
    pub closure: Vec<PackageContractClosureMemberMeta>,
}

/// Describes one exact realized member of a selected artifact closure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContractClosureMemberMeta {
    /// Exact realized Nix store path.
    pub store_path: String,
    /// Hash of the member's uncompressed NAR.
    pub nar_hash: String,
    /// Uncompressed member NAR size in bytes.
    pub nar_size: u64,
    /// Sorted direct references as exact 32-character Nix store hashes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}
