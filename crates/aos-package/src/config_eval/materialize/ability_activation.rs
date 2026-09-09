//! Version-3 manifest inputs for native structured ability activation.
//!
//! The manifest embeds one descriptor with independently retained sidecars and
//! exact package coordinates:
//!
//! ```json
//! {"authenticated_policy_set":{"document":"policy.json","document_sha256":"sha256:...","document_size":1,"nar_hash":"sha256:...","nar_size":1,"store_path":"/nix/store/...-policy"},"desired_state":{"document":"desired.json","document_sha256":"sha256:...","document_size":1,"nar_hash":"sha256:...","nar_size":1,"store_path":"/nix/store/...-desired"},"packages":[{"ability_nar_hash":"sha256:...","ability_store_path":"/nix/store/...-ability","manifest_sha256":"sha256:...","name":"nginx","package_digest":"sha256:...","platform":"x86_64-linux","registry":"reference","runtime_nar_hash":"sha256:...","runtime_nar_size":1,"runtime_store_path":"/nix/store/...-nginx","version":"1.0.0"}],"required_features":["abilities-v1","ability-effects-v1"],"schema":"aos.ability.activation-input/v1"}
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use super::{validate_canonical_store_path, validate_content_sha256};
use crate::config_eval::runtime::RuntimePackagePin;

/// Pins all immutable inputs from which native ability activation is specialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityActivationInput {
    /// Carries `aos.ability.activation-input/v1`.
    pub schema: String,
    /// Requires the complete manifest and structured-effect semantics.
    pub required_features: Vec<String>,
    /// Canonical desired-state input, without deployment current observations.
    pub desired_state: PinnedAbilitySidecar,
    /// Independently authenticated planning-policy provenance.
    pub authenticated_policy_set: PinnedAbilitySidecar,
    /// Exact selected package coordinates whose ability companions form the catalog.
    pub packages: Vec<AbilityPackageCoordinate>,
}

impl AbilityActivationInput {
    /// Current immutable activation-input descriptor schema.
    pub const SCHEMA: &'static str = "aos.ability.activation-input/v1";

    pub(super) fn validate(
        &self,
        package_outputs: &BTreeMap<String, RuntimePackagePin>,
    ) -> Result<()> {
        use crate::types::{FEATURE_ABILITIES_V1, FEATURE_ABILITY_EFFECTS_V1};

        if self.schema != Self::SCHEMA {
            bail!(
                "unsupported ability activation input schema {:?}",
                self.schema
            );
        }
        let required = vec![
            FEATURE_ABILITIES_V1.to_string(),
            FEATURE_ABILITY_EFFECTS_V1.to_string(),
        ];
        if self.required_features != required {
            bail!(
                "ability activation requires exact abilities-v1 and ability-effects-v1 feature gates"
            );
        }
        self.desired_state.validate("desired state")?;
        self.authenticated_policy_set
            .validate("authenticated policy set")?;

        if self
            .packages
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            bail!("ability activation package coordinates are not strictly canonical");
        }
        let expected = package_outputs
            .iter()
            .filter_map(|(name, package)| {
                package
                    .ability
                    .as_ref()
                    .map(|ability| (name, package, ability))
            })
            .collect::<Vec<_>>();
        if expected.len() != self.packages.len() {
            bail!("ability activation coordinates do not cover selected ability packages");
        }
        for (coordinate, (name, package, ability)) in self.packages.iter().zip(expected) {
            if coordinate.name != *name
                || coordinate.version != package.version
                || coordinate.platform != package.platform
                || coordinate.registry != package.registry
                || coordinate.runtime_store_path != package.store_path
                || coordinate.runtime_nar_hash != package.nar_hash
                || coordinate.runtime_nar_size != package.nar_size
                || coordinate.ability_store_path != ability.store_path
                || coordinate.ability_nar_hash != ability.nar_hash
                || coordinate.manifest_sha256 != ability.manifest_sha256
                || coordinate.package_digest != ability.package_digest
            {
                bail!(
                    "ability activation coordinate for {:?} differs from authenticated packageOutputs",
                    coordinate.name
                );
            }
        }
        Ok(())
    }
}

/// Identifies one immutable canonical JSON document inside a retained store output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedAbilitySidecar {
    /// Store output containing the document.
    pub store_path: String,
    /// Hash of the uncompressed output NAR.
    pub nar_hash: String,
    /// Uncompressed output NAR size.
    pub nar_size: u64,
    /// Sorted direct store-path hash references of the output.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Safe relative path of the canonical JSON document in the output.
    pub document: String,
    /// SHA-256 digest of the exact canonical document bytes.
    pub document_sha256: String,
    /// Exact canonical document byte length.
    pub document_size: u64,
}

impl PinnedAbilitySidecar {
    fn validate(&self, label: &str) -> Result<()> {
        validate_canonical_store_path(&self.store_path)
            .with_context(|| format!("invalid ability {label} store path"))?;
        let canonical_nar =
            crate::registry::store::NarBytes::from_hash(&self.nar_hash, self.nar_size)?.nar_hash();
        if canonical_nar != self.nar_hash || self.nar_size == 0 {
            bail!("ability {label} has a noncanonical or empty NAR identity");
        }
        validate_content_sha256(&self.document_sha256)
            .with_context(|| format!("invalid ability {label} document digest"))?;
        if self.document_size == 0
            || self.document_size > aos_ability_model::ABILITY_LIMITS_V1.max_document_bytes
        {
            bail!("ability {label} document size is outside the bounded contract");
        }
        let document = Path::new(&self.document);
        if document.is_absolute()
            || document.as_os_str().is_empty()
            || document
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("ability {label} document path is unsafe");
        }
        if self.references.windows(2).any(|pair| pair[0] >= pair[1])
            || self.references.iter().any(|reference| {
                reference.len() != 32
                    || !reference.bytes().all(|byte| {
                        byte.is_ascii_digit()
                            || matches!(byte, b'a'..=b'd' | b'f'..=b'n' | b'p'..=b's' | b'v'..=b'z')
                    })
            })
        {
            bail!("ability {label} store references are not canonical");
        }
        Ok(())
    }
}

/// Binds one selected runtime package to its authenticated ability companion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityPackageCoordinate {
    /// Selected package name.
    pub name: String,
    /// Selected package version.
    pub version: String,
    /// Selected target platform.
    pub platform: String,
    /// Registry or measured image origin.
    pub registry: String,
    /// Exact selected runtime output.
    pub runtime_store_path: String,
    /// Exact selected runtime output NAR identity.
    pub runtime_nar_hash: String,
    /// Exact selected runtime output uncompressed NAR size.
    pub runtime_nar_size: u64,
    /// Exact ability companion output.
    pub ability_store_path: String,
    /// Exact companion NAR identity.
    pub ability_nar_hash: String,
    /// Exact companion manifest byte identity.
    pub manifest_sha256: String,
    /// Semantic package-document identity.
    pub package_digest: String,
}
