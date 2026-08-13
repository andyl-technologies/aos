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
    /// (e.g. `x86_64-linux`).
    #[serde(default)]
    pub platforms: HashMap<String, PlatformEntry>,
}

/// A `[versions.platforms.<platform>]` artifact entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformEntry {
    /// Absolute store path of the built output.
    pub store_path: String,
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
    /// Store path hashes of direct runtime references, or a structural
    /// RFC-0001 gate table for permission-bearing packages.
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
    /// Optional RFC-0001 service exposure metadata.
    #[serde(default)]
    pub expose: Option<ExposeMeta>,
    /// Store artifact carrying rendered RFC-0001 unit files and manifest.
    #[serde(default)]
    pub expose_artifact: Option<ExposeArtifactMeta>,
    /// Signed RFC-0001 permission manifest.
    #[serde(default)]
    pub permissions: PermissionsMeta,
    /// Signed fleet BPF-LSM policy metadata.
    #[serde(default)]
    pub bpf_lsm: Option<BpfLsmPolicyMeta>,
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
    /// Configuration-only module output and its declared interface.
    #[serde(default)]
    pub config_module: Option<ConfigModuleMeta>,
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
/// structural RFC-0001 gate table for permission-bearing packages.
///
/// Old clients that expected a plain list reject the structural gate form,
/// which is the intended fail-closed behavior for permission-bearing packages.
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

/// A structural RFC-0001 references gate table.
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

/// An SBAT component/generation pair from a UKI's PE `.sbat` section
/// (RFC-0006).
///
/// Each line of the `.sbat` CSV names a boot component and the *generation*
/// number an `sbat` revocation compares against; the registry records these so
/// the fleet can enforce a per-component revocation floor at download time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbatEntry {
    /// SBAT component identifier (the first CSV column, e.g. `aos`).
    pub component: String,
    /// SBAT generation number; a higher number supersedes a lower one.
    pub generation: u32,
}

/// Stable A/B slot named by a UKI carried in a sysroot image artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UkiSlot {
    /// The UKI whose measured command line selects `root-a`.
    A,
    /// The UKI whose measured command line selects `root-b`.
    B,
}

/// Slot-specific Secure Boot and measured-boot facts for one UKI.
///
/// A/B UKIs have different measured command lines because each names a
/// different root and verity partition. Consequently their PCR-11 values are
/// distinct even when they carry identical kernel, initrd, and root bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SysrootUkiEntry {
    /// Root slot selected by this UKI's measured command line.
    pub slot: UkiSlot,
    /// Relative path to the UKI inside the image store artifact.
    pub path: String,
    /// Lowercase hex SHA-256 of the Authenticode signer leaf certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sb_signer_cert_sha256: Option<String>,
    /// SBAT component/generation pairs read from this UKI's `.sbat` section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sbat: Vec<SbatEntry>,
    /// Predicted PCR-11 for this exact UKI's measured PE sections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pcr11: Option<String>,
}

/// A pre-compiled image entry within a platform entry.
///
/// The trailing Secure Boot fields (RFC-0006) are populated only for signed
/// UKIs/images and are optional for unsigned publishes.
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
    /// Lowercase hex SHA-256 of the signer leaf cert, when signed.
    #[serde(default)]
    pub sb_signer_cert_sha256: Option<String>,
    /// SBAT component/generation pairs from the image's `.sbat` section.
    #[serde(default)]
    pub sbat: Vec<SbatEntry>,
    /// Predicted PCR-11 for the image's UKI, when measured.
    #[serde(default)]
    pub expected_pcr11: Option<String>,
    /// Slot-specific UKI facts for an A/B image payload.
    #[serde(default)]
    pub ukis: Vec<SysrootUkiEntry>,
    /// Relative path inside `store_path` to the root filesystem image.
    #[serde(default)]
    pub root_image: Option<String>,
    /// Relative path inside `store_path` to the separate dm-verity hash tree.
    #[serde(default)]
    pub root_verity: Option<String>,
    /// dm-verity root hash for `root_image`.
    #[serde(default)]
    pub root_hash: Option<String>,
    /// Relative path inside `store_path` to the PKCS#7 root-hash signature.
    #[serde(default)]
    pub root_hash_sig: Option<String>,
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
        let delivery = &self.delivery;
        anyhow::ensure!(
            !delivery.is_store_only(),
            "legacy store-only image has no direct-delivery contract"
        );
        delivery.validate(&self.format, release, platform)?;
        anyhow::ensure!(
            self.sb_signer_cert_sha256 == delivery.uki.signer_cert_sha256,
            "top-level and delivery UKI signer facts disagree"
        );
        anyhow::ensure!(
            self.sbat == delivery.uki.sbat,
            "top-level and delivery SBAT facts disagree"
        );
        anyhow::ensure!(
            self.expected_pcr11 == delivery.uki.expected_pcr11,
            "top-level and delivery PCR-11 facts disagree"
        );
        Ok(())
    }
}

/// Immutable direct-delivery metadata signed inside an [`ImageEntry`].
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
    /// SHA-256 of the root filesystem payload embedded in the logical disk.
    pub rootfs_sha256: String,
    /// Exact useful filename returned by direct downloads.
    pub filename: String,
    /// Content-addressed immutable object key for the disk bytes.
    pub object_key: String,
    /// Media type of the bytes at [`ImageDelivery::object_key`].
    pub media_type: String,
    /// Compression applied to the disk-image encoding.
    pub compression: ImageCompression,
    /// Exact number of bytes served by a complete download.
    pub byte_size: u64,
    /// Lowercase hexadecimal SHA-256 of the served disk-image bytes.
    pub sha256: String,
    /// End-user targets compatible with this image encoding.
    pub compatible_targets: Vec<ImageTarget>,
    /// Immutable identity of the UKI embedded in this logical disk.
    pub uki: ImageUkiIdentity,
    /// Separately content-bound canonical producer metadata.
    pub image_info: ImageInfoReference,
}

impl ImageDelivery {
    /// Returns the internal marker used when reading pre-delivery catalogs.
    ///
    /// This value is never a valid direct-download contract and is omitted
    /// again when serialized. Producers must emit schema v1 metadata.
    #[must_use]
    pub fn store_only() -> Self {
        Self {
            schema_version: 0,
            release: String::new(),
            platform: String::new(),
            architecture: String::new(),
            logical_image_id: String::new(),
            logical_disk_sha256: String::new(),
            rootfs_sha256: String::new(),
            filename: String::new(),
            object_key: String::new(),
            media_type: String::new(),
            compression: ImageCompression::None,
            byte_size: 0,
            sha256: String::new(),
            compatible_targets: Vec::new(),
            uki: ImageUkiIdentity {
                filename: String::new(),
                esp_path: String::new(),
                byte_size: 0,
                sha256: String::new(),
                verification: ImageVerificationState::Unsigned,
                signer_cert_sha256: None,
                sbat: Vec::new(),
                measured: false,
                expected_pcr11: None,
            },
            image_info: ImageInfoReference {
                filename: String::new(),
                object_key: String::new(),
                media_type: String::new(),
                byte_size: 0,
                sha256: String::new(),
            },
        }
    }

    /// Returns whether this value represents a pre-delivery store-only entry.
    #[must_use]
    pub fn is_store_only(&self) -> bool {
        self.schema_version == 0
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
            self.schema_version == 1,
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
        validate_sha256(&self.rootfs_sha256, "root filesystem")?;
        validate_sha256(&self.sha256, "image")?;
        ensure!(self.byte_size > 0, "image byte size must be non-zero");
        ensure!(
            self.object_key == immutable_image_object_key(&self.sha256, &self.filename),
            "image object key is not the canonical content-addressed key"
        );
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
        self.uki.validate()?;
        self.image_info.validate(&self.sha256)
    }
}

/// Immutable boot payload identity shared by all encodings of one image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageUkiIdentity {
    /// Portable basename of the UKI file.
    pub filename: String,
    /// Portable relative path at which the UKI is installed in the ESP.
    pub esp_path: String,
    /// Exact UKI byte length.
    pub byte_size: u64,
    /// Lowercase hexadecimal SHA-256 of the UKI bytes.
    pub sha256: String,
    /// Secure Boot verification state, separate from registry release trust.
    pub verification: ImageVerificationState,
    /// Lowercase hexadecimal SHA-256 of the Authenticode signer certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_cert_sha256: Option<String>,
    /// SBAT component generations extracted from the exact embedded UKI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sbat: Vec<SbatEntry>,
    /// Whether the UKI declares measured-boot policy.
    #[serde(default)]
    pub measured: bool,
    /// Predicted PCR-11 for the exact embedded UKI when measured boot is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pcr11: Option<String>,
}

impl ImageUkiIdentity {
    fn validate(&self) -> anyhow::Result<()> {
        validate_image_filename(&self.filename)?;
        anyhow::ensure!(
            self.filename.ends_with(".efi"),
            "UKI filename must end in .efi"
        );
        anyhow::ensure!(self.byte_size > 0, "UKI byte size must be non-zero");
        validate_sha256(&self.sha256, "UKI")?;
        validate_portable_image_path(&self.esp_path, "UKI ESP path")?;
        anyhow::ensure!(
            self.esp_path.ends_with(&format!("/{}", self.filename)),
            "UKI ESP path does not end in its filename"
        );
        match self.verification {
            ImageVerificationState::Unsigned => {
                anyhow::ensure!(
                    self.signer_cert_sha256.is_none() && self.sbat.is_empty(),
                    "unsigned UKI must not carry signer or SBAT facts"
                );
            }
            ImageVerificationState::SignedUnverified | ImageVerificationState::PolicyVerified => {
                let signer = self
                    .signer_cert_sha256
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("signed UKI must carry a signer digest"))?;
                validate_sha256(signer, "UKI signer certificate")?;
                anyhow::ensure!(
                    !self.sbat.is_empty(),
                    "signed UKI must carry SBAT generations"
                );
                let mut components = HashSet::new();
                anyhow::ensure!(
                    self.sbat.iter().all(|entry| {
                        !entry.component.is_empty()
                            && entry.component.is_ascii()
                            && entry.generation > 0
                            && components.insert(entry.component.as_str())
                    }),
                    "UKI SBAT components must be unique, non-empty ASCII with non-zero generations"
                );
            }
        }
        if self.measured {
            let pcr = self
                .expected_pcr11
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("measured UKI must carry expected PCR-11"))?;
            validate_sha256(pcr, "UKI expected PCR-11")?;
        } else {
            anyhow::ensure!(
                self.expected_pcr11.is_none(),
                "unmeasured UKI must not carry expected PCR-11"
            );
        }
        Ok(())
    }
}

/// Verification state of an image's boot payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageVerificationState {
    /// The UKI carries no Authenticode signature.
    Unsigned,
    /// The UKI is signed, but no committed active-certificate policy verified it.
    SignedUnverified,
    /// The UKI was verified against the committed active-certificate policy.
    PolicyVerified,
}

/// Compression applied to directly served disk-image bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageCompression {
    /// No outer compression; the object bytes are the named disk encoding.
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

/// Content-bound reference to the producer's `image-info.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageInfoReference {
    /// Exact metadata filename.
    pub filename: String,
    /// Content-addressed immutable object key for the metadata bytes.
    pub object_key: String,
    /// Media type of the metadata document.
    pub media_type: String,
    /// Exact metadata byte length.
    pub byte_size: u64,
    /// Lowercase hexadecimal SHA-256 of the metadata bytes.
    pub sha256: String,
}

impl ImageInfoReference {
    fn validate(&self, image_sha256: &str) -> anyhow::Result<()> {
        use anyhow::ensure;

        ensure!(
            self.filename == "image-info.json",
            "invalid image-info filename"
        );
        ensure!(
            self.media_type == "application/vnd.aos.image-info+json",
            "invalid image-info media type"
        );
        ensure!(self.byte_size > 0, "image-info byte size must be non-zero");
        validate_sha256(&self.sha256, "image-info")?;
        ensure!(
            self.object_key == immutable_image_info_object_key(image_sha256, &self.sha256),
            "image-info object key is not the canonical content-addressed key"
        );
        Ok(())
    }
}

/// Returns the canonical immutable object key for direct disk-image bytes.
pub fn immutable_image_object_key(sha256: &str, filename: &str) -> String {
    format!("images/sha256/{sha256}/{filename}")
}

/// Returns the canonical immutable object key for an image metadata document.
pub fn immutable_image_info_object_key(image_sha256: &str, info_sha256: &str) -> String {
    format!("images/sha256/{image_sha256}/metadata/{info_sha256}/image-info.json")
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

fn validate_portable_image_path(path: &str, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !path.is_empty() && path.len() <= 256 && path.is_ascii() && !path.contains('\\'),
        "{label} must be a portable relative path"
    );
    for component in path.split('/') {
        anyhow::ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                }),
            "{label} must be a portable relative path"
        );
    }
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
            rootfs_sha256: "f".repeat(64),
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
            uki: ImageUkiIdentity {
                filename: "aos-server.efi".to_string(),
                esp_path: "EFI/Linux/aos-server.efi".to_string(),
                byte_size: 1024,
                sha256: "d".repeat(64),
                verification: ImageVerificationState::Unsigned,
                signer_cert_sha256: None,
                sbat: Vec::new(),
                measured: false,
                expected_pcr11: None,
            },
            image_info: ImageInfoReference {
                filename: "image-info.json".to_string(),
                object_key: immutable_image_info_object_key(&image_sha256, &info_sha256),
                media_type: "application/vnd.aos.image-info+json".to_string(),
                byte_size: 512,
                sha256: info_sha256,
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
store_path = "/aos/store/server-raw"
nar_hash = "sha256:nar"
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
                    "[delivery.uki]",
                    "[versions.platforms.x86_64-linux.images.delivery.uki]",
                )
                .replace(
                    "[delivery.image_info]",
                    "[versions.platforms.x86_64-linux.images.delivery.image_info]",
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
    fn delivery_contract_rejects_path_traversal_and_tampering() {
        let mut traversal = delivery("raw");
        traversal.filename = "../server.img".to_string();
        assert!(traversal
            .validate("raw", "2026.08", "x86_64-linux")
            .is_err());

        let mut tampered = delivery("raw");
        tampered.sha256 = "A".repeat(64);
        assert!(tampered.validate("raw", "2026.08", "x86_64-linux").is_err());

        let mut wrong_target = delivery("qcow2");
        wrong_target.compatible_targets = vec![ImageTarget::BareMetal];
        assert!(wrong_target
            .validate("qcow2", "2026.08", "x86_64-linux")
            .is_err());

        let mut uncompressed_raw = delivery("raw");
        uncompressed_raw.compression = ImageCompression::None;
        assert!(uncompressed_raw
            .validate("raw", "2026.08", "x86_64-linux")
            .is_err());

        let mut compressed_qcow2 = delivery("qcow2");
        compressed_qcow2.compression = ImageCompression::Zstd;
        assert!(compressed_qcow2
            .validate("qcow2", "2026.08", "x86_64-linux")
            .is_err());
    }

    #[test]
    fn delivery_contract_rejects_parent_identity_drift() {
        let contract = delivery("vmdk");
        assert!(contract
            .validate("vmdk", "2026.09", "x86_64-linux")
            .is_err());
        assert!(contract
            .validate("vmdk", "2026.08", "aarch64-linux")
            .is_err());
    }

    #[test]
    fn uki_verification_facts_are_closed_and_state_dependent() {
        let mut contract = delivery("raw");
        contract.uki.verification = ImageVerificationState::SignedUnverified;
        assert!(contract.validate("raw", "2026.08", "x86_64-linux").is_err());

        contract.uki.signer_cert_sha256 = Some("9".repeat(64));
        contract.uki.sbat = vec![SbatEntry {
            component: "aos".to_string(),
            generation: 1,
        }];
        assert!(contract.validate("raw", "2026.08", "x86_64-linux").is_ok());

        contract.uki.measured = true;
        assert!(contract.validate("raw", "2026.08", "x86_64-linux").is_err());
        contract.uki.expected_pcr11 = Some("8".repeat(64));
        assert!(contract.validate("raw", "2026.08", "x86_64-linux").is_ok());

        contract.uki.verification = ImageVerificationState::Unsigned;
        assert!(contract.validate("raw", "2026.08", "x86_64-linux").is_err());
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

    #[test]
    fn delivery_accepts_sd_boot_counting_suffix() {
        let mut contract = delivery("raw");
        contract.uki.filename = "aos-server+3.efi".to_string();
        contract.uki.esp_path = "EFI/Linux/aos-server+3.efi".to_string();
        contract
            .validate("raw", "2026.08", "x86_64-linux")
            .expect("sd-boot counting filename");
    }
}

// ---------------------------------------------------------------------------
// RFC-0001 package metadata (expose, permissions, attestation)
// ---------------------------------------------------------------------------
//
// These pure serde structs and their inherent helpers moved here from
// `aos-package`'s `types` module (RFC-0004 Phase 5) so the wasm-clean indexer
// and the Cloudflare Worker can deserialize the expanded RFC-0001 package
// metadata the producer publishes. `aos-package` re-exports every type below
// so `aos_package::types::{ExposeMeta, …}` paths are unchanged.

/// Prefixes treated as host system locations for confinement classification.
const SYSTEM_LOCATION_PREFIXES: &[&str] = &[
    "/boot", "/etc", "/lib", "/lib64", "/nix", "/sbin", "/usr", "/var",
];

fn is_false(value: &bool) -> bool {
    !*value
}

fn has_system_location_prefix(path: &str) -> bool {
    SYSTEM_LOCATION_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

/// A pre-compiled image format entry within a sysroot package version.
///
/// The direct-delivery contract is mandatory after the topology cutover. The
/// trailing Secure Boot compatibility fields mirror the exact nested UKI
/// identity and remain optional only when that identity makes no such claim.
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
    /// Lowercase hex SHA-256 of the signer leaf certificate found in the
    /// PE's Authenticode certificate table; the db cert this image must
    /// chain to. `None` for unsigned images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sb_signer_cert_sha256: Option<String>,
    /// SBAT component/generation pairs read from the PE `.sbat` section.
    /// Empty when the image carries no `.sbat` section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sbat: Vec<SbatEntry>,
    /// ukify/`systemd-measure`-predicted TPM PCR-11 value for this UKI
    /// (hex). See [`SysrootImageEntry`] callers and RFC-0006
    /// `registry-catalog.md` for the prediction-scope caveat: this records
    /// the UKI's own contribution, not the full sd-boot phase sequence.
    /// `None` when `systemd-measure` was unavailable at publish time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pcr11: Option<String>,
    /// Slot-specific UKI paths and measured-boot facts for A/B updates.
    ///
    /// This is empty for legacy single-UKI images. New A/B image publishers
    /// record exactly one `a` and one `b` entry and consumers select by slot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ukis: Vec<SysrootUkiEntry>,
    /// Relative path inside [`SysrootImageEntry::store_path`] to the root
    /// filesystem image consumed by `RootImage=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_image: Option<String>,
    /// Relative path inside [`SysrootImageEntry::store_path`] to the separate
    /// dm-verity hash tree consumed by `RootVerity=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_verity: Option<String>,
    /// dm-verity root hash for [`SysrootImageEntry::root_image`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
    /// Relative path inside [`SysrootImageEntry::store_path`] to the PKCS#7
    /// signature consumed by `RootHashSignature=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash_sig: Option<String>,
}

/// RFC-0001 service exposure metadata carried by registry package metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeMeta {
    /// Systemd target that is the package activation handle.
    pub target: String,
    /// Unit files rendered for this package and pulled in by the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Container/root artifacts attached to the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<SysrootImageEntry>,
    /// Package names that must be installed atomically with this package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Package-scoped config declarations and hot-reload policy.
    #[serde(default, skip_serializing_if = "ExposeConfigMeta::is_empty")]
    pub config: ExposeConfigMeta,
    /// Typed capabilities this package offers to other packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<ProvidedCapabilityMeta>,
    /// Typed capabilities this package consumes from other packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<RequiredCapabilityMeta>,
}

/// RFC-0001 package config metadata signed with exposure metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeConfigMeta {
    /// Structured config artifacts `apm` validates and materializes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ConfigArtifactMeta>,
    /// TPM2/systemd credential declarations consumed by package units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialMeta>,
}

impl ExposeConfigMeta {
    /// Returns whether the package declares no config inputs.
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty() && self.credentials.is_empty()
    }

    /// Returns whether config metadata asks runtime reconciliation to touch units.
    pub fn has_unit_reconciliation(&self) -> bool {
        self.artifacts
            .iter()
            .any(|artifact| !artifact.units.is_empty())
    }
}

/// Structured config artifact materialized from host desired-package config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigArtifactMeta {
    /// Stable artifact name inside the package config namespace.
    pub name: String,
    /// Absolute `/etc` path where `apm` materializes the artifact.
    pub path: String,
    /// Serialization format for the materialized artifact.
    pub format: ConfigArtifactFormat,
    /// Field names that must be present in desired config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Field names that may be present in desired config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional: Vec<String>,
    /// Service units whose config changes should reconcile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Whether changed content reloads, restarts, or leaves units untouched.
    #[serde(default, skip_serializing_if = "ConfigReloadPolicy::is_default")]
    pub reload: ConfigReloadPolicy,
}

/// Materialized config artifact serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigArtifactFormat {
    /// systemd-compatible `KEY=VALUE` environment file.
    Env,
    /// JSON object.
    Json,
    /// TOML table.
    Toml,
}

/// Config-change reconciliation policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigReloadPolicy {
    /// Restart affected units on content change.
    #[default]
    Restart,
    /// Reload affected units on content change, falling back to restart if unsupported.
    Reload,
    /// Materialize the artifact without service reconciliation.
    None,
}

impl ConfigReloadPolicy {
    fn is_default(policy: &Self) -> bool {
        *policy == Self::Restart
    }
}

/// TPM2/systemd credential declaration for an exposed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMeta {
    /// systemd credential name.
    pub name: String,
    /// Optional host-side credstore source path for fail-closed loading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional inline systemd encrypted credential payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// Service units expected to consume this credential.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Whether the credential is expected to be TPM2/systemd encrypted.
    #[serde(default, rename = "encrypted", skip_serializing_if = "is_false")]
    pub encrypted: bool,
}

/// Typed package capability kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    /// A provider-owned directory exposed read-only to consumers.
    Directory,
    /// A provider service namespace joined by consumer units.
    Namespace,
    /// Socket/fd-passing capability routed through generated systemd drop-ins.
    Socket,
}

/// Capability a package exposes to other packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidedCapabilityMeta {
    /// Capability name unique within the provider package.
    pub name: String,
    /// Capability materialization kind.
    pub kind: CapabilityKind,
    /// Provider path for [`CapabilityKind::Directory`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Provider unit for [`CapabilityKind::Namespace`] or future socket routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// Capability a package consumes from another installed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCapabilityMeta {
    /// Provider package name.
    pub provider: String,
    /// Capability name on the provider package.
    pub name: String,
    /// Expected capability kind.
    pub kind: CapabilityKind,
    /// Consumer unit that receives the generated route drop-in.
    pub unit: String,
}

/// Store metadata for rendered RFC-0001 exposure artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeArtifactMeta {
    /// Store path containing `units/` and `manifest.json`.
    pub store_path: String,
    /// NAR hash of the rendered expose artifact.
    pub nar_hash: String,
    /// Uncompressed NAR size of the rendered expose artifact in bytes.
    pub nar_size: u64,
}

/// Signed metadata for fleet-managed BPF-LSM policy artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpfLsmPolicyMeta {
    /// BPF-LSM policies carried by this package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<BpfLsmPolicyArtifactMeta>,
}

impl BpfLsmPolicyMeta {
    /// Returns whether the package declares no BPF-LSM policies.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
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

/// One BPF-LSM policy artifact carried by a signed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BpfLsmPolicyArtifactMeta {
    /// Stable policy name used for host policy selection and bpffs pins.
    pub name: String,
    /// Relative JSON policy path inside the package root.
    pub policy: String,
    /// Relative BPF object path inside the package root.
    pub object: String,
    /// BPF program names expected in the object and policy JSON.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<String>,
}

/// Signed RFC-0001 package permission manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsMeta {
    /// Linux capabilities requested by the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Package network mode; absent means the default private mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPermission>,
    /// TCP ports the package may bind under Landlock/eBPF network policy.
    #[serde(default, rename = "tcp-bind", skip_serializing_if = "Vec::is_empty")]
    pub tcp_bind: Vec<u16>,
    /// TCP ports the package may connect to under Landlock/eBPF network policy.
    #[serde(default, rename = "tcp-connect", skip_serializing_if = "Vec::is_empty")]
    pub tcp_connect: Vec<u16>,
    /// Device nodes requested by the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    /// Host paths requested by the package.
    #[serde(default, rename = "host-paths", skip_serializing_if = "Vec::is_empty")]
    pub host_paths: Vec<HostPathPermission>,
    /// Whether the package requests cgroup controller delegation.
    #[serde(default, rename = "cgroup-delegate", skip_serializing_if = "is_false")]
    pub cgroup_delegate: bool,
    /// Whether the package requests host-root-equivalent users.
    #[serde(default, rename = "privileged-users", skip_serializing_if = "is_false")]
    pub privileged_users: bool,
    /// Host-fulfilled kernel modules requested by the package.
    #[serde(
        default,
        rename = "kernel-modules",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub kernel_modules: Vec<String>,
    /// Named syscall profile requested by the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<SyscallProfile>,
    /// Generated SELinux/AppArmor label requested by the package.
    #[serde(
        default,
        rename = "security-label",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_label: Option<String>,
    /// Computed package confinement summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confinement: Option<ConfinementMeta>,
}

impl PermissionsMeta {
    /// Returns whether the manifest carries no explicit permission requests.
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
            && self.network.is_none()
            && self.tcp_bind.is_empty()
            && self.tcp_connect.is_empty()
            && self.devices.is_empty()
            && self.host_paths.is_empty()
            && !self.cgroup_delegate
            && !self.privileged_users
            && self.kernel_modules.is_empty()
            && self.syscalls.is_none()
            && self.security_label.is_none()
            && self.confinement.is_none()
    }

    /// Returns whether the manifest requests host-policy-admitted grants.
    pub fn requires_policy_admission(&self) -> bool {
        self.network
            .is_some_and(|network| network != NetworkPermission::Private)
            || !self.tcp_bind.is_empty()
            || !self.tcp_connect.is_empty()
            || !self.capabilities.is_empty()
            || !self.devices.is_empty()
            || !self.host_paths.is_empty()
            || self.cgroup_delegate
            || self.privileged_users
            || !self.kernel_modules.is_empty()
            || self
                .syscalls
                .is_some_and(|syscalls| syscalls != SyscallProfile::Restricted)
    }

    /// Returns whether this manifest needs host policy for a package name.
    pub fn requires_policy_admission_for_package(&self, package_name: &str) -> bool {
        self.requires_policy_admission()
            || self
                .security_label
                .as_ref()
                .is_some_and(|label| label != &format!("aos-pkg-{package_name}"))
    }

    /// Returns whether this manifest carries explicit Landlock/eBPF policy.
    pub fn has_network_policy(&self) -> bool {
        !self.tcp_bind.is_empty() || !self.tcp_connect.is_empty() || !self.host_paths.is_empty()
    }

    /// Computes the RFC-0001 confinement summary from permission grants.
    pub fn computed_confinement(&self) -> ConfinementMeta {
        let network = self.network.unwrap_or(NetworkPermission::Private);
        let syscall_profile = self.syscalls.unwrap_or(SyscallProfile::Restricted);
        let mut holes = Vec::new();

        if network != NetworkPermission::Private {
            holes.push(format!("network:{}", network.as_manifest_str()));
        }
        holes.extend(self.tcp_bind.iter().map(|port| format!("tcp-bind:{port}")));
        holes.extend(
            self.tcp_connect
                .iter()
                .map(|port| format!("tcp-connect:{port}")),
        );
        holes.extend(
            self.capabilities
                .iter()
                .map(|capability| format!("capability:{capability}")),
        );
        holes.extend(self.devices.iter().map(|device| format!("device:{device}")));
        holes.extend(self.host_paths.iter().map(|host_path| {
            format!(
                "host-path:{}:{}",
                host_path.mode.as_manifest_str(),
                host_path.path
            )
        }));
        if self.cgroup_delegate {
            holes.push("cgroup-delegate".into());
        }
        if self.privileged_users {
            holes.push("privileged-users".into());
        }
        if syscall_profile != SyscallProfile::Restricted {
            holes.push(format!("syscalls:{}", syscall_profile.as_manifest_str()));
        }

        let root_equivalent = self
            .capabilities
            .iter()
            .any(|capability| capability == "CAP_SYS_ADMIN")
            || self.privileged_users
            || self.host_paths.iter().any(|host_path| {
                host_path.mode == HostPathMode::Rw && has_system_location_prefix(&host_path.path)
            });

        let class = if root_equivalent {
            ConfinementClass::Unconfined
        } else if holes.is_empty() {
            ConfinementClass::Sandboxed
        } else {
            ConfinementClass::SandboxedWithHoles
        };
        let label = if class == ConfinementClass::SandboxedWithHoles {
            format!("sandboxed-with-holes ({})", holes.join(", "))
        } else {
            class.as_manifest_str().to_string()
        };

        ConfinementMeta {
            class,
            label,
            holes,
        }
    }
}

/// Computed RFC-0001 package confinement summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinementMeta {
    /// Coarse confinement class computed from generated unit permissions.
    pub class: ConfinementClass,
    /// Human-readable confinement label shown by package tools.
    pub label: String,
    /// Permission holes that prevent the package from being fully sandboxed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holes: Vec<String>,
}

/// Coarse RFC-0001 package confinement class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfinementClass {
    /// Generated units have the default sandbox and no explicit holes.
    Sandboxed,
    /// Generated units keep the default sandbox but include explicit holes.
    SandboxedWithHoles,
    /// Generated units request root-equivalent or host-level privileges.
    Unconfined,
}

impl ConfinementClass {
    fn as_manifest_str(self) -> &'static str {
        match self {
            ConfinementClass::Sandboxed => "sandboxed",
            ConfinementClass::SandboxedWithHoles => "sandboxed-with-holes",
            ConfinementClass::Unconfined => "unconfined",
        }
    }
}

/// RFC-0001 package network mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPermission {
    /// Inbound-only private namespace with host-owned socket activation.
    Private,
    /// Private namespace with an outbound veth path.
    PrivateOutbound,
    /// Host network namespace.
    Host,
}

impl NetworkPermission {
    fn as_manifest_str(self) -> &'static str {
        match self {
            NetworkPermission::Private => "private",
            NetworkPermission::PrivateOutbound => "private-outbound",
            NetworkPermission::Host => "host",
        }
    }
}

/// Host path permission requested by a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPathPermission {
    /// Absolute host path to bind into the package.
    pub path: String,
    /// Whether the bind is read-only or read-write.
    pub mode: HostPathMode,
}

/// Host path access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostPathMode {
    /// Read-only host path bind.
    ReadOnly,
    /// Read-write host path bind.
    Rw,
}

impl HostPathMode {
    fn as_manifest_str(self) -> &'static str {
        match self {
            HostPathMode::ReadOnly => "read-only",
            HostPathMode::Rw => "rw",
        }
    }
}

/// Named syscall profile pinned to systemd syscall groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyscallProfile {
    /// Minimal syscall profile for tightly sandboxed services.
    Restricted,
    /// Systemd's `@system-service` syscall group profile.
    SystemService,
    /// Privileged syscall profile for infrastructure packages.
    Privileged,
}

impl SyscallProfile {
    fn as_manifest_str(self) -> &'static str {
        match self {
            SyscallProfile::Restricted => "restricted",
            SyscallProfile::SystemService => "system-service",
            SyscallProfile::Privileged => "privileged",
        }
    }
}

// ---------------------------------------------------------------------------
// Committed root config (`registry.toml`)
// ---------------------------------------------------------------------------

use anyhow::{bail, Context, Result};

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
    /// Whether the producer records content addresses in the `store/`
    /// realisation graph (RFC-0005), so the registry serves both
    /// input-addressed and content-addressed consumers. Default `true`;
    /// set `false` for a pure input-addressed registry.
    #[serde(default = "default_content_addressed")]
    pub content_addressed: bool,
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
                        delivery.uki == first.uki
                            && image.sb_signer_cert_sha256
                                == first_image.sb_signer_cert_sha256
                            && image.sbat == first_image.sbat
                            && image.expected_pcr11 == first_image.expected_pcr11,
                        "release '{}' platform '{}' image encodings have different UKI or Secure Boot facts",
                        version.version,
                        platform
                    );
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

/// Stores metadata for a package's second `config` output.
///
/// The `config` output is a store-path NAR carrying the package's config-only
/// Nix module (`module.nix` at its root) plus any relative-imported private
/// `.nix`. Its identity is content-addressed exactly like
/// [`ExposeArtifactMeta`]: a store path, the uncompressed NAR hash, and the NAR
/// size, plus the module's *direct* store references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOutputMeta {
    /// Store path of the `config` output (contains `module.nix` at its root).
    pub store_path: String,
    /// Hash of the uncompressed `config`-output NAR: `"sha256:…"`.
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: u64,
    /// Store-path hashes of the `config` output's *direct* references.
    ///
    /// The enforced invariant is **no `.drv`** (see `validate_config_output_meta`):
    /// the config module is config-only and must not pull store objects into
    /// evaluation. Trusted companion outputs have an empty reference set;
    /// runtime output strings are injected separately from authenticated
    /// resolution metadata.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

/// Configuration-module interface declared by a package.
///
/// Carries the second [`ConfigOutputMeta`] output, the declared option surface
/// (the package's `provides`, computed by an options-only eval at publish), the
/// shared roots it owns or contributes to, and its base-lib ABI compatibility
/// range. The presence of this block on a `PackageMeta` is gated behind
/// `FEATURE_CONFIG_MODULE_V1` and requires DSSE provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigModuleMeta {
    /// The `config` output store metadata.
    pub config_output: ConfigOutputMeta,
    /// Exact base library used for the publish-time options-only evaluation.
    ///
    /// New publishers always populate this binding. It remains optional so
    /// registries produced before the binding was introduced stay readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_base_lib: Option<ConfigOutputMeta>,
    /// Exact runtime dependency outputs exposed to the module by name.
    ///
    /// Publishers authenticate these paths as members of the package runtime
    /// closure. Evaluators pass only this map, rather than an ambient package
    /// set, so interpolation remains builder-free and reproducible.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependency_outputs: BTreeMap<String, String>,
    /// Base-lib ABI range this module is compatible with (inclusive).
    pub module_abi_compat: ModuleAbiCompat,
    /// Option paths this module *declares* (its `provides`), computed by an
    /// options-only eval in isolation. Sorted, deduplicated. These become the
    /// registry inverted-index keys for this `package@version`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declares: Vec<String>,
    /// Sorted option declaration paths paired with their stable type
    /// descriptions from the options-only evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declaration_schema: Vec<ConfigOptionDeclaration>,
    /// Conservative option accesses found by the publish-time Nix-source scan.
    ///
    /// These paths pre-close the resolver working set. They are an
    /// over-approximation only; error-driven resolve/eval remains the backstop
    /// for computed attribute access that cannot be represented statically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Shared roots this module declares exclusive ownership of (e.g.
    /// `firewall`, `nginx`). Each carries its own interface ABI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owns_roots: Vec<OwnedRoot>,
    /// Foreign shared roots this module contributes into, restricted to the
    /// owner-declared contributable sub-paths (F3-B).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributes: Vec<RootContribution>,
    /// Capability tokens this module *sets* (write-provider index entries),
    /// e.g. `system.capabilities.dns-resolver`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides_capabilities: Vec<String>,
}

/// One mechanically derived option declaration in a config module's schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOptionDeclaration {
    /// Full dotted option path.
    pub path: String,
    /// Stable type description exported by the module engine.
    pub type_signature: String,
}

/// Inclusive base-lib ABI compatibility range for a config module.
///
/// The resolver refuses the module unless `min <= running_image_abi <= max`.
/// This is the configuration analogue of the SBAT revocation floor: a monotonic
/// integer band, gated pre-eval and fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAbiCompat {
    /// Lowest `module_abi` this module supports.
    pub min: u32,
    /// Highest `module_abi` this module supports.
    pub max: u32,
}

impl ModuleAbiCompat {
    /// Returns whether `abi` lies within the inclusive `[min, max]` band.
    pub fn admits(&self, abi: u32) -> bool {
        self.min <= abi && abi <= self.max
    }
}

/// A shared root a package owns, plus its own interface ABI and the sub-paths
/// non-owners may contribute into (F3-B capability-scoped surface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRoot {
    /// Root segment, e.g. `firewall`, `nginx`.
    pub root: String,
    /// Independent interface ABI for this shared root.
    pub interface_abi: u32,
    /// Owner-declared contributable sub-paths (relative to the root), e.g.
    /// `virtualHosts`, `upstreams`. Owner-only paths (`enable`, globals) are
    /// excluded. A non-owner write outside these is rejected at publish.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributable: Vec<String>,
}

/// A foreign-root contribution declared by a non-owner package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootContribution {
    /// The shared root being contributed into, e.g. `nginx`.
    pub root: String,
    /// Exact interface ABI expected from the installed owner of `root`.
    ///
    /// Contributions are capabilities issued against a particular owner
    /// interface. They are never admitted across an owner ABI upgrade without
    /// being republished against the new ABI.
    pub interface_abi: u32,
    /// Sub-paths (relative to `root`) this package writes; each MUST be within
    /// the owner's `contributable` set, checked at resolve.
    pub paths: Vec<String>,
}

impl<'de> Deserialize<'de> for RootContribution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireContribution {
            root: String,
            #[serde(default)]
            interface_abi: Option<u32>,
            paths: Vec<String>,
        }

        let wire = WireContribution::deserialize(deserializer)?;
        let interface_abi = wire.interface_abi.ok_or_else(|| {
            serde::de::Error::custom(format!(
                "legacy contribution metadata for root '{}' has no interface_abi; republish the package with contributes[].interfaceAbi set to the owner's interface ABI",
                wire.root
            ))
        })?;
        Ok(Self {
            root: wire.root,
            interface_abi,
            paths: wire.paths,
        })
    }
}

#[cfg(test)]
mod config_module_compat_tests {
    use super::ConfigModuleMeta;

    #[test]
    fn legacy_config_module_metadata_defaults_new_publish_bindings() {
        let legacy = serde_json::json!({
            "config_output": {
                "store_path": "/nix/store/0000000000000000000000000000000a-web-config",
                "nar_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "nar_size": 1
            },
            "module_abi_compat": { "min": 1, "max": 1 },
            "declares": ["web.enable"],
            "owns_roots": [],
            "contributes": [],
            "provides_capabilities": []
        });

        let parsed: ConfigModuleMeta =
            serde_json::from_value(legacy).expect("legacy config-module metadata parses");

        assert!(parsed.requires.is_empty());
        assert!(parsed.declaration_schema.is_empty());
        assert!(parsed.evaluation_base_lib.is_none());
    }

    #[test]
    fn legacy_nonempty_contribution_requires_explicit_migration() {
        let legacy = serde_json::json!({
            "root": "nginx",
            "paths": ["virtualHosts.example"]
        });

        let error = serde_json::from_value::<super::RootContribution>(legacy)
            .expect_err("legacy contribution must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("legacy contribution metadata"),
            "{message}"
        );
        assert!(message.contains("interface_abi"), "{message}");
        assert!(message.contains("republish"), "{message}");
    }
}
