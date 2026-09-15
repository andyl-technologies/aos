//! Manifest inputs for native structured ability activation.
//!
//! The manifest embeds one descriptor with independently retained sidecars and
//! exact package coordinates. The canonical shape is:
//!
//! ```json
//! {"authenticated_policy_set":{"document":"policy.json","document_sha256":"sha256:...","document_size":1,"nar_hash":"sha256:<52-nix-base32-chars>","nar_size":1,"store_path":"/nix/store/...-policy"},"desired_state":{"document":"desired.json","document_sha256":"sha256:...","document_size":1,"nar_hash":"sha256:<52-nix-base32-chars>","nar_size":1,"store_path":"/nix/store/...-desired"},"packages":[{"ability_nar_hash":"sha256:...","ability_store_path":"/nix/store/...-ability","activation_revision":"sha256:...","manifest_sha256":"sha256:...","name":"nginx","package_digest":"sha256:...","platform":"x86_64-linux","registry":"reference","runtime_nar_hash":"sha256:...","runtime_nar_size":1,"runtime_store_path":"/nix/store/...-nginx","version":"1.0.0"}],"required_features":["abilities-v1","ability-effects-v1","native-platform-policy-v1","native-resource-map-v1"],"schema":"aos.contract.activation-input/v1"}
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_ability_model::VersionedDocument as _;
use serde::{Deserialize, Serialize};

use super::{package_activation_revision, validate_canonical_store_path, validate_content_sha256};
use crate::config_eval::runtime::RuntimePackagePin;

/// Pins all immutable inputs from which native ability activation is specialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityActivationInput {
    /// Carries a supported activation-input schema discriminator.
    pub schema: String,
    /// Requires the complete manifest and structured-effect semantics.
    pub required_features: Vec<String>,
    /// Canonical desired-state input, without deployment current observations.
    pub desired_state: PinnedAbilitySidecar,
    /// Independently authenticated planning-policy provenance.
    pub authenticated_policy_set: PinnedAbilitySidecar,
    /// Exact selected package coordinates whose ability companions form the catalog.
    pub packages: Vec<PackageContractCoordinate>,
    /// Retains exact bindings, resources, and observer inputs from the final module fixed point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_point: Option<crate::config_eval::ability_rounds::AbilityFixedPointProjection>,
}

impl AbilityActivationInput {
    /// Current immutable activation-input descriptor schema.
    pub const SCHEMA: &'static str = "aos.contract.activation-input/v1";

    /// Validates the activation descriptor independently of package enrichment.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, feature sequence, sidecar descriptor,
    /// package-coordinate order, or retained fixed point is invalid.
    pub(crate) fn validate_descriptor(&self) -> Result<()> {
        use crate::types::{FEATURE_ABILITIES_V1, FEATURE_ABILITY_EFFECTS_V1};

        if self.schema != Self::SCHEMA {
            bail!(
                "unsupported ability activation input schema {:?}",
                self.schema
            );
        }
        let planning_features = vec![
            FEATURE_ABILITIES_V1.to_string(),
            FEATURE_ABILITY_EFFECTS_V1.to_string(),
        ];
        let execution_features = vec![
            FEATURE_ABILITIES_V1.to_string(),
            FEATURE_ABILITY_EFFECTS_V1.to_string(),
            "native-resource-map-v1".to_string(),
        ];
        let platform_execution_features = vec![
            FEATURE_ABILITIES_V1.to_string(),
            FEATURE_ABILITY_EFFECTS_V1.to_string(),
            "native-platform-policy-v1".to_string(),
            "native-resource-map-v1".to_string(),
        ];
        if self.required_features != planning_features
            && self.required_features != execution_features
            && self.required_features != platform_execution_features
        {
            bail!(
                "ability activation requires the exact planning or native-execution feature sequence"
            );
        }
        self.desired_state.validate("desired state")?;
        self.authenticated_policy_set
            .validate("authenticated policy set")?;
        if let Some(fixed_point) = &self.fixed_point {
            fixed_point
                .validate()
                .map_err(anyhow::Error::new)
                .context("validating retained ability fixed point")?;
        }

        if self
            .packages
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            bail!("ability activation package coordinates are not strictly canonical");
        }
        Ok(())
    }

    /// Validates immutable sidecars and package activation coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error when sidecars, package coordinates, or the final
    /// checked binding authority are invalid or inconsistent.
    pub(crate) fn validate(
        &self,
        package_outputs: &BTreeMap<String, RuntimePackagePin>,
    ) -> Result<()> {
        self.validate_descriptor()?;
        self.fixed_point
            .as_ref()
            .context("native ability activation has no retained final fixed point")?
            .validate_checked_planning()
            .map_err(anyhow::Error::new)
            .context("validating retained checked binding authority")?;

        let expected = package_outputs
            .iter()
            .filter_map(|(name, package)| {
                package
                    .contract
                    .as_ref()
                    .map(|ability| (name, package, ability))
            })
            .collect::<Vec<_>>();
        if expected.len() != self.packages.len() {
            bail!("ability activation coordinates do not cover selected ability packages");
        }
        for (coordinate, (name, package, ability)) in self.packages.iter().zip(expected) {
            let resolved = super::super::static_packages::resolve(
                name,
                &package.version,
                &package.platform,
                &package.store_path,
                &package.nar_hash,
                ability,
            )?;
            if coordinate.name != *name
                || coordinate.version != package.version
                || coordinate.platform != package.platform
                || coordinate.registry != package.registry
                || coordinate.runtime_store_path != package.store_path
                || coordinate.runtime_nar_hash != package.nar_hash
                || coordinate.runtime_nar_size != package.nar_size
                || coordinate.contract_store_path != resolved.manifest_store_path
                || coordinate.contract_nar_hash != resolved.manifest_nar_hash
                || coordinate.contract_document_sha256 != resolved.manifest_digest.to_string()
            {
                bail!(
                    "ability activation coordinate for {:?} differs from authenticated packageOutputs",
                    coordinate.name
                );
            }
            if coordinate.package_digest != resolved.document.content_digest()?.to_string() {
                bail!(
                    "ability activation package digest for {:?} differs from its authenticated contract",
                    coordinate.name
                );
            }
            let expected_revision = package_activation_revision(name, package)?;
            if coordinate.activation_revision.is_empty() {
                bail!(
                    "ability activation revision for {:?} is missing",
                    coordinate.name
                );
            }
            if !coordinate.activation_revision.is_empty()
                && coordinate.activation_revision != expected_revision
            {
                bail!(
                    "ability activation revision for {:?} differs from its authenticated package content and rendered configuration",
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
    /// Nix base32 NAR identity as `sha256:` plus exactly 52 base32 characters.
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
    pub(crate) fn validate(&self, label: &str) -> Result<()> {
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
pub struct PackageContractCoordinate {
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
    /// Exact package contract document.
    pub contract_store_path: String,
    /// Exact package contract document NAR identity.
    pub contract_nar_hash: String,
    /// Exact package contract document byte identity.
    pub contract_document_sha256: String,
    /// Semantic package-document identity.
    pub package_digest: String,
    /// Content-derived runtime, ability, unit, and configuration identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub activation_revision: String,
}
