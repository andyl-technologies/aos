//! Finalized image-set identity and relationship contract.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use aos_release::artifact::{BundlePath, Compression, require_identifier};
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use aos_release::signing::SignatureResponseV1;
use serde::{Deserialize, Serialize};

use crate::assembly::UnsignedImageAssemblyV1;

/// Schema for one complete finalized architecture image set.
pub const FINALIZED_IMAGE_SET_V1: &str = "aos.image.finalized-set/v1";

/// Closed finalized output kinds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FinalizedImageKind {
    /// Uncompressed canonical logical disk.
    LogicalDisk,
    /// Zstandard-compressed raw disk.
    Raw,
    /// QCOW2 disk encoding.
    Qcow2,
    /// VMDK disk encoding.
    Vmdk,
    /// Dynamic VHD disk encoding.
    Vhd,
    /// Normal slot-A UKI.
    UkiA,
    /// Normal slot-B UKI.
    UkiB,
    /// Recovery slot-A UKI.
    RecoveryUkiA,
    /// Recovery slot-B UKI.
    RecoveryUkiB,
    /// Signed recovery bundle.
    RecoveryBundle,
    /// Final image metadata.
    Metadata,
}

impl FinalizedImageKind {
    /// Complete selected-provider artifact inventory.
    pub const ALL: [Self; 11] = [
        Self::LogicalDisk,
        Self::Raw,
        Self::Qcow2,
        Self::Vmdk,
        Self::Vhd,
        Self::UkiA,
        Self::UkiB,
        Self::RecoveryUkiA,
        Self::RecoveryUkiB,
        Self::RecoveryBundle,
        Self::Metadata,
    ];

    /// Returns the stable artifact id assigned to this output kind.
    #[must_use]
    pub const fn artifact_id(self) -> &'static str {
        match self {
            Self::LogicalDisk => "logical-disk",
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
            Self::Vmdk => "vmdk",
            Self::Vhd => "vhd",
            Self::UkiA => "uki-a",
            Self::UkiB => "uki-b",
            Self::RecoveryUkiA => "recovery-uki-a",
            Self::RecoveryUkiB => "recovery-uki-b",
            Self::RecoveryBundle => "recovery-bundle",
            Self::Metadata => "metadata",
        }
    }

    /// Returns the provider-owned release projection for this output kind.
    #[must_use]
    pub fn publication(self) -> ImageArtifactPublicationV1 {
        let (role, media_type, compression, encodes) = match self {
            Self::LogicalDisk => (
                "aos.systemd.image-artifact.logical-disk/v1",
                "application/vnd.aos.logical-disk.raw",
                Compression::None,
                None,
            ),
            Self::Raw => (
                "aos.systemd.image-artifact.raw-delivery/v1",
                "application/vnd.aos.disk-image.raw+zstd",
                Compression::Zstd,
                Some("logical-disk"),
            ),
            Self::Qcow2 => (
                "aos.systemd.image-artifact.qcow2-delivery/v1",
                "application/vnd.aos.disk-image.qcow2",
                Compression::None,
                Some("logical-disk"),
            ),
            Self::Vmdk => (
                "aos.systemd.image-artifact.vmdk-delivery/v1",
                "application/vnd.vmware.vmdk",
                Compression::None,
                Some("logical-disk"),
            ),
            Self::Vhd => (
                "aos.systemd.image-artifact.vhd-delivery/v1",
                "application/vnd.microsoft.vhd",
                Compression::None,
                Some("logical-disk"),
            ),
            Self::UkiA => (
                "aos.systemd.image-artifact.boot-payload-a/v1",
                "application/vnd.aos.uki",
                Compression::None,
                None,
            ),
            Self::UkiB => (
                "aos.systemd.image-artifact.boot-payload-b/v1",
                "application/vnd.aos.uki",
                Compression::None,
                None,
            ),
            Self::RecoveryUkiA => (
                "aos.systemd.image-artifact.recovery-payload-a/v1",
                "application/vnd.aos.uki",
                Compression::None,
                None,
            ),
            Self::RecoveryUkiB => (
                "aos.systemd.image-artifact.recovery-payload-b/v1",
                "application/vnd.aos.uki",
                Compression::None,
                None,
            ),
            Self::RecoveryBundle => (
                "aos.systemd.image-artifact.recovery-set/v1",
                "application/vnd.aos.recovery-bundle.v1+tar+zstd",
                Compression::Zstd,
                None,
            ),
            Self::Metadata => (
                "aos.systemd.image-artifact.metadata/v1",
                "application/vnd.aos.image-metadata.v1+json",
                Compression::None,
                None,
            ),
        };

        ImageArtifactPublicationV1 {
            role: role.to_owned(),
            media_type: media_type.to_owned(),
            compression,
            encodes: encodes.map(str::to_owned),
        }
    }
}

/// Provider-authored release projection for one finalized image artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageArtifactPublicationV1 {
    /// Opaque semantic role interpreted by the selected image provider.
    pub role: String,
    /// Public media type of the exact artifact bytes.
    pub media_type: String,
    /// Delivery compression already applied to the artifact bytes.
    pub compression: Compression,
    /// Provider-local artifact id reconstructed by this encoding, when any.
    pub encodes: Option<String>,
}

/// Exact final output bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedImageArtifactV1 {
    /// Stable artifact id.
    pub id: String,
    /// Closed artifact purpose.
    pub kind: FinalizedImageKind,
    /// Provider-authored projection into the generic release inventory.
    pub publication: ImageArtifactPublicationV1,
    /// Relative path beneath the finalized image-set root.
    pub path: BundlePath,
    /// Exact byte length.
    pub size_bytes: u64,
    /// Exact SHA-256 identity.
    pub sha256: Sha256Digest,
    /// Logical-disk digest reconstructed from this format, when applicable.
    pub reconstructed_logical_disk: Option<Sha256Digest>,
}

/// Complete externally finalized output for one unsigned assembly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedImageSetV1 {
    /// Exact schema identifier.
    pub schema_version: String,
    /// Digest of the canonical unsigned assembly manifest.
    pub assembly_digest: Sha256Digest,
    /// Exact Linux target.
    pub platform: Platform,
    /// Public system variant.
    pub system_variant: String,
    /// Every required output, sorted by id.
    pub artifacts: Vec<FinalizedImageArtifactV1>,
    /// Audited external signing responses accepted during finalization.
    pub signing_operations: Vec<SignatureResponseV1>,
}

impl FinalizedImageSetV1 {
    /// Validates output closure and four-format logical-disk equivalence.
    ///
    /// # Errors
    ///
    /// Returns an error for identity drift, missing/duplicate outputs, empty
    /// artifacts, or any disk encoding that does not reconstruct the declared
    /// logical disk.
    pub fn validate(&self, assembly: &UnsignedImageAssemblyV1) -> Result<()> {
        assembly.validate()?;
        let expected = Sha256Digest::of_canonical(&assembly.schema_version, assembly)?;
        if self.schema_version != FINALIZED_IMAGE_SET_V1
            || self.assembly_digest != expected
            || self.platform != assembly.platform
            || self.system_variant != assembly.system_variant
            || self
                .artifacts
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            bail!("finalized image set differs from its unsigned assembly");
        }
        require_identifier(&self.system_variant, "system variant")?;
        let mut kinds = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for artifact in &self.artifacts {
            require_identifier(&artifact.id, "finalized image artifact id")?;
            if artifact.id != artifact.kind.artifact_id()
                || artifact.publication != artifact.kind.publication()
                || artifact.size_bytes == 0
                || !kinds.insert(artifact.kind)
                || !paths.insert(artifact.path.as_str())
            {
                bail!("finalized image set contains a mislabeled, empty, or duplicate artifact");
            }
        }
        for artifact in &self.artifacts {
            if let Some(encoded) = artifact.publication.encodes.as_deref()
                && !self
                    .artifacts
                    .iter()
                    .any(|candidate| candidate.id == encoded)
            {
                bail!("finalized image artifact encodes an absent provider artifact");
            }
        }
        for required in FinalizedImageKind::ALL {
            if !kinds.contains(&required) {
                bail!("finalized image set lacks required {required:?} output");
            }
        }
        let logical = self
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == FinalizedImageKind::LogicalDisk)
            .map(|artifact| artifact.sha256)
            .ok_or_else(|| anyhow::anyhow!("logical disk is absent"))?;
        for artifact in self.artifacts.iter().filter(|artifact| {
            matches!(
                artifact.kind,
                FinalizedImageKind::Raw
                    | FinalizedImageKind::Qcow2
                    | FinalizedImageKind::Vmdk
                    | FinalizedImageKind::Vhd
            )
        }) {
            if artifact.reconstructed_logical_disk != Some(logical) {
                bail!("disk encoding does not reconstruct the finalized logical disk");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_publication_roles_are_unique_and_domain_separated() {
        let mut roles = BTreeSet::new();

        for kind in FinalizedImageKind::ALL {
            let publication = kind.publication();
            assert!(publication.role.contains('/'));
            assert!(roles.insert(publication.role));
        }
    }
}
