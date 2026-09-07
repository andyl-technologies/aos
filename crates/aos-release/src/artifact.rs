//! Immutable release artifact identities and bundle-path relationships.
//!
//! Artifact records use this shape:
//!
//! ```json
//! {"id":"package/example/x86_64-linux","kind":"package-nar",
//!  "platform":"x86_64-linux","path":"packages/example.nar.zst",
//!  "size_bytes":123,"sha256":"sha256:...","media_type":"application/x-nix-nar",
//!  "compression":"zstd","relationships":[]}
//! ```

use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::digest::Sha256Digest;
use crate::platform::Platform;

/// Maximum exact file size representable by the integer-only I-JSON contract.
pub const MAX_ARTIFACT_SIZE: u64 = 9_007_199_254_740_991;

/// A normalized relative path beneath a captured release bundle.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BundlePath(String);

impl BundlePath {
    /// Parses a bundle-relative path without platform-dependent normalization.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, absolute, backslash-containing, repeated
    /// separator, current-directory, parent-directory, control-character, or
    /// overlong paths.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 {
            bail!("bundle path must contain 1 through 4096 bytes");
        }
        if value.starts_with('/') || value.ends_with('/') || value.contains("//") {
            bail!("bundle path must be normalized and relative: {value}");
        }
        if value.contains('\\') || value.chars().any(char::is_control) {
            bail!("bundle path contains a forbidden character: {value}");
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        {
            bail!("bundle path contains a forbidden component: {value}");
        }
        Ok(Self(value))
    }

    /// Returns the exact normalized path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BundlePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for BundlePath {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BundlePath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Closed kinds of files admitted to a release bundle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// Signed OCI multi-platform index included in a qualified release.
    OciIndex,
    /// OCI manifest for one exact Linux platform.
    OciManifest,
    /// OCI configuration or layer blob for a platform manifest.
    OciBlob,
    /// Frozen canonical release plan.
    ReleasePlan,
    /// Nix archive containing a package or dependency output.
    PackageNar,
    /// Signed Nix cache narinfo metadata.
    NarInfo,
    /// Registry catalog or Git object.
    RegistryObject,
    /// TUF root, delegated targets, snapshot, or timestamp metadata.
    TufMetadata,
    /// Authenticated package documentation.
    Documentation,
    /// Complete corresponding source or source archive.
    Source,
    /// Signed build provenance.
    Provenance,
    /// SPDX JSON software bill of materials.
    Sbom,
    /// License text or machine-readable license inventory.
    License,
    /// Public qualification or policy evidence.
    Evidence,
    /// A realized AOS system toplevel.
    SystemToplevel,
    /// Canonical finalized logical disk before delivery encoding.
    LogicalDisk,
    /// Raw disk delivery encoding.
    RawImage,
    /// QCOW2 disk delivery encoding.
    Qcow2Image,
    /// VMDK disk delivery encoding.
    VmdkImage,
    /// Dynamic VHD disk delivery encoding.
    VhdImage,
    /// Normal unified kernel image.
    Uki,
    /// Recovery unified kernel image.
    RecoveryUki,
    /// Signed recovery artifact set.
    RecoveryBundle,
    /// Re-derived final image metadata.
    ImageMetadata,
    /// Firmware enrollment or rotation artifact.
    FirmwareEnrollment,
}

impl ArtifactKind {
    /// Returns whether this kind is valid only for a Linux platform.
    #[must_use]
    pub const fn is_linux_image(self) -> bool {
        matches!(
            self,
            Self::SystemToplevel
                | Self::LogicalDisk
                | Self::RawImage
                | Self::Qcow2Image
                | Self::VmdkImage
                | Self::VhdImage
                | Self::Uki
                | Self::RecoveryUki
                | Self::RecoveryBundle
                | Self::ImageMetadata
                | Self::FirmwareEnrollment
        )
    }
}

/// Delivery compression applied to the exact file bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    /// Bytes are not compressed.
    None,
    /// Bytes use deterministic Zstandard compression.
    Zstd,
    /// Bytes use deterministic gzip compression.
    Gzip,
    /// Bytes use XZ compression.
    Xz,
}

/// A typed edge between two logical artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRelationship {
    /// Closed relationship meaning.
    pub relation: ArtifactRelation,
    /// Logical id of the related artifact.
    pub target: String,
}

/// Closed relationship meanings used by final-byte verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRelation {
    /// Final signed bytes were derived from this unsigned predecessor.
    Finalizes,
    /// Delivery encoding reconstructs this logical disk.
    Encodes,
    /// The target is signed Nix cache metadata authenticating this NAR.
    AuthenticatedBy,
    /// Evidence verifies this artifact.
    Verifies,
    /// Artifact contains this dependency or source.
    Contains,
    /// Artifact is distributed under the target license record.
    LicensedBy,
    /// The target is complete corresponding source for this artifact.
    CorrespondingSource,
    /// The target documents this artifact.
    Documents,
}

/// One exact regular file in the closed release bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    /// Stable logical identity unique within the release.
    pub id: String,
    /// Closed artifact kind.
    pub kind: ArtifactKind,
    /// Target identity, absent only for truly target-independent metadata.
    pub platform: Option<Platform>,
    /// System variant for image artifacts.
    pub system_variant: Option<String>,
    /// Exact regular-file path below the bundle root.
    pub path: BundlePath,
    /// Exact file length.
    pub size_bytes: u64,
    /// SHA-256 over exact file bytes.
    pub sha256: Sha256Digest,
    /// Exact public media type.
    pub media_type: String,
    /// Delivery compression.
    pub compression: Compression,
    /// Nix derivation path when the artifact is a derivation output.
    pub derivation: Option<String>,
    /// Nix output name when the artifact is a derivation output.
    pub output: Option<String>,
    /// Nix store path when the artifact has a realized store identity.
    pub store_path: Option<String>,
    /// NAR identity when the artifact represents a store path.
    pub nar_hash: Option<Sha256Digest>,
    /// Typed relationships to other logical artifacts.
    pub relationships: Vec<ArtifactRelationship>,
}

impl ArtifactRecord {
    /// Validates shape and platform-specific invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, sizes, media types, Nix field
    /// combinations, image platforms, variants, or relationship targets.
    pub fn validate(&self) -> Result<()> {
        require_identifier(&self.id, "artifact id")?;
        if self.size_bytes > MAX_ARTIFACT_SIZE {
            bail!("artifact {} exceeds the exact I-JSON size limit", self.id);
        }
        if self.media_type.trim().is_empty()
            || !self.media_type.is_ascii()
            || self.media_type.chars().any(char::is_whitespace)
        {
            bail!("artifact {} has an invalid media type", self.id);
        }
        if self.kind.is_linux_image() {
            let platform = self
                .platform
                .ok_or_else(|| anyhow::anyhow!("image artifact {} lacks a platform", self.id))?;
            if !platform.supports_images() {
                bail!("Darwin artifact {} cannot have image kind", self.id);
            }
            let variant = self.system_variant.as_deref().unwrap_or_default();
            require_identifier(variant, "system variant")?;
        } else if self.system_variant.is_some() {
            bail!(
                "non-image artifact {} cannot name a system variant",
                self.id
            );
        }

        let nix_fields = [
            self.derivation.is_some(),
            self.output.is_some(),
            self.store_path.is_some(),
            self.nar_hash.is_some(),
        ];
        if nix_fields.iter().any(|present| *present) && !nix_fields.iter().all(|present| *present) {
            bail!("artifact {} has an incomplete Nix identity", self.id);
        }
        if let (Some(derivation), Some(output), Some(store_path)) =
            (&self.derivation, &self.output, &self.store_path)
        {
            require_store_path(derivation, true)?;
            require_identifier(output, "artifact output name")?;
            require_store_path(store_path, false)?;
        }
        for relationship in &self.relationships {
            require_identifier(&relationship.target, "artifact relationship target")?;
        }
        Ok(())
    }
}

/// Validates one canonical Nix store path without consulting the store.
///
/// # Errors
///
/// Returns an error unless the path has an exact Nix base-32 store hash, a
/// conservative name component, and the requested derivation suffix policy.
pub fn require_store_path(value: &str, derivation: bool) -> Result<()> {
    let Some(tail) = value.strip_prefix("/nix/store/") else {
        bail!("Nix store path must begin with /nix/store/");
    };
    let Some((hash, name)) = tail.split_once('-') else {
        bail!("Nix store path lacks its name separator");
    };
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    if hash.len() != 32 || !hash.bytes().all(|byte| NIX_BASE32.contains(&byte)) {
        bail!("Nix store path has an invalid store hash");
    }
    require_identifier(name, "Nix store path name")?;
    if derivation != name.ends_with(".drv") {
        bail!("Nix store path derivation suffix does not match its field");
    }
    Ok(())
}

/// Validates a stable public identifier used by the release schemas.
///
/// # Errors
///
/// Returns an error when the value is empty, overlong, non-ASCII, or contains
/// characters outside the conservative public identifier alphabet.
pub fn require_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 {
        bail!("{label} must contain 1 through 256 bytes");
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
    }) {
        bail!("{label} contains a forbidden character: {value}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_paths_reject_aliases_and_traversal() {
        for invalid in [
            "",
            "/absolute",
            "../escape",
            "a/../b",
            "a//b",
            "a\\b",
            "a/./b",
        ] {
            assert!(BundlePath::parse(invalid).is_err(), "accepted {invalid}");
        }
        assert!(BundlePath::parse("packages/a.nar.zst").is_ok());
    }
}
