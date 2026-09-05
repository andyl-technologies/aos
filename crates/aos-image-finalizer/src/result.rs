//! Finalized image-set identity and relationship contract.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use aos_release::artifact::BundlePath;
use aos_release::artifact::require_identifier;
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

/// Exact final output bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedImageArtifactV1 {
    /// Stable artifact id.
    pub id: String,
    /// Closed artifact purpose.
    pub kind: FinalizedImageKind,
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
            if artifact.size_bytes == 0
                || !kinds.insert(artifact.kind)
                || !paths.insert(artifact.path.as_str())
            {
                bail!("finalized image set contains an empty or duplicate artifact kind");
            }
        }
        for required in [
            FinalizedImageKind::LogicalDisk,
            FinalizedImageKind::Raw,
            FinalizedImageKind::Qcow2,
            FinalizedImageKind::Vmdk,
            FinalizedImageKind::Vhd,
            FinalizedImageKind::UkiA,
            FinalizedImageKind::UkiB,
            FinalizedImageKind::RecoveryUkiA,
            FinalizedImageKind::RecoveryUkiB,
            FinalizedImageKind::RecoveryBundle,
            FinalizedImageKind::Metadata,
        ] {
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
