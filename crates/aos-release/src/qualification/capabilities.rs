//! Built image capabilities and their binding to signed artifact metadata.
//!
//! Capability inventories describe available code, never successful hardware
//! execution. Runtime observations must independently satisfy the target scope.
//!
//! ```text
//! image-info.json/v2 -> capabilities -> kernel configuration + stage inventories
//! stage inventories: runtime, initrd, recovery-a, recovery-b
//! ```

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::environment::{BootStage, EnvironmentProfile};
use crate::artifact::{ArtifactKind, BundlePath};
use crate::digest::Sha256Digest;
use crate::manifest::ReleaseManifestV1;

/// Exact bytes of a driver or firmware file available at one boot stage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFile {
    /// Path relative to the module or firmware directory inside the image.
    pub path: BundlePath,
    /// Digest of the final file, including any appended module signature.
    pub sha256: Sha256Digest,
}

/// Files actually available in one reconstructed filesystem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageCapabilities {
    /// Driver names mapped to their module files.
    pub modules: BTreeMap<String, CapabilityFile>,
    /// Firmware names mapped to their installed bytes.
    pub firmware: BTreeMap<String, CapabilityFile>,
}

/// Build-derived capability inventory embedded in final image metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageCapabilities {
    /// Exact inventory schema.
    pub schema_version: String,
    /// Kernel release whose modules and configuration are recorded.
    pub kernel_release: String,
    /// Hash of the resolved kernel configuration captured by the Nix build.
    pub kernel_config_digest: Sha256Digest,
    /// Resolved configuration values, including disabled options as `n`.
    pub kernel_options: BTreeMap<String, String>,
    /// Driver names compiled into this kernel, from its modules.builtin file.
    pub builtin_drivers: Vec<String>,
    /// Exact runtime, initrd and both recovery filesystem inventories.
    pub stages: BTreeMap<String, StageCapabilities>,
}

impl ImageCapabilities {
    /// Computes the canonical identity recorded by execution inventories.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical("aos.image.capabilities/v1", self)
    }

    /// Checks built availability at every stage required by the target.
    ///
    /// # Errors
    /// Returns an error for malformed inventories, absent kernel options,
    /// missing drivers or unavailable firmware at a required stage.
    pub fn satisfies(&self, scope: &EnvironmentProfile) -> Result<()> {
        if self.schema_version != "aos.image.capabilities/v1"
            || self.kernel_release.trim().is_empty()
            || self.stages.keys().map(String::as_str).collect::<Vec<_>>()
                != ["initrd", "recovery-a", "recovery-b", "runtime"]
            || self
                .builtin_drivers
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            bail!("invalid built image capability inventory");
        }
        for (key, value) in &scope.kernel_options {
            if self.kernel_options.get(key) != Some(value) {
                bail!("built image does not satisfy kernel option {key}={value}");
            }
        }
        for device in &scope.devices {
            let stages: &[&str] = match device.stage {
                BootStage::Runtime => &["runtime"],
                BootStage::Initrd => &["initrd"],
                BootStage::Recovery => &["recovery-a", "recovery-b"],
            };
            for name in stages {
                let stage = self
                    .stages
                    .get(*name)
                    .ok_or_else(|| anyhow::anyhow!("missing stage {name}"))?;
                if !self.builtin_drivers.contains(&device.driver)
                    && !stage.modules.contains_key(&device.driver)
                {
                    bail!("driver {} is unavailable in {name}", device.driver);
                }
                for firmware in &device.firmware {
                    if !stage.firmware.contains_key(firmware) {
                        bail!("firmware {firmware} is unavailable in {name}");
                    }
                }
            }
        }
        Ok(())
    }
}

/// Retained final metadata whose bytes are bound by a subject artifact record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidence {
    /// ImageMetadata artifact included in this case's exact subject set.
    pub metadata_artifact: String,
    /// Complete canonical metadata value, never an unbound capability extract.
    pub metadata: serde_json::Value,
}

impl CapabilityEvidence {
    /// Verifies metadata against the manifest and returns its capabilities.
    ///
    /// # Errors
    /// Returns an error for an unrelated artifact, byte drift, an unsupported
    /// metadata schema or absent/malformed capability data.
    pub fn verify(
        &self,
        manifest: &ReleaseManifestV1,
        subjects: &[String],
    ) -> Result<ImageCapabilities> {
        let artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.id == self.metadata_artifact)
            .ok_or_else(|| anyhow::anyhow!("capability metadata artifact is absent"))?;
        let bytes = crate::canonical::canonical_json(&self.metadata)?;
        if artifact.kind != ArtifactKind::ImageMetadata
            || !subjects.contains(&artifact.id)
            || artifact.sha256 != Sha256Digest::of_bytes(&bytes)
            || artifact.size_bytes != u64::try_from(bytes.len())?
            || self
                .metadata
                .get("schema_version")
                .and_then(serde_json::Value::as_str)
                != Some("aos.image.metadata/v2")
        {
            bail!("capability metadata differs from the exact image subject");
        }
        Ok(serde_json::from_value(
            self.metadata
                .get("capabilities")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("image metadata lacks built capabilities"))?,
        )?)
    }
}
