//! Bounded private deployment state over one authenticated package ability reference.
//!
//! The overlay contains stable plan, binding, and observation identities. It
//! cannot represent configuration values, grants, secrets, endpoints, logs, or
//! executable instructions. Hub authenticates the reporting principal and adds
//! receipt and expiry times outside these reporter-authored canonical bytes.
//!
//! ```json
//! {"deployment":"production","observations":[],"package":{"manifest_sha256":"sha256:<digest>","package":"nginx","package_digest":"sha256:<digest>","platform":"x86_64-linux","registry_commit":"<commit>","version":"1.0"},"plan":{"environment":{"authority":"fleet","key":"production","stage":"host"},"exports":[],"plan":"sha256:<digest>","policy_revision":"sha256:<digest>","state":"planned"},"reported_at_unix_seconds":1,"required_features":["ability-deployment-overlay-v1"],"schema":"aos.package-ability-deployment-overlay/v1","sequence":1,"valid_for_seconds":60}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    ABILITY_LIMITS_V1, EnvironmentId, InstanceId, InterfaceKey, LocalKey, PlanId, RequiredFeature,
    ResourceId, RevisionId, TransactionId, VersionedDocument, decode_canonical, encode_canonical,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{DocumentationError, PackageAbilityReference, Result};

/// Exact schema discriminator for a private package deployment overlay.
pub const ABILITY_DEPLOYMENT_OVERLAY_SCHEMA: &str = "aos.package-ability-deployment-overlay/v1";

/// Required semantic feature for the version-1 deployment overlay.
pub const ABILITY_DEPLOYMENT_OVERLAY_FEATURE: &str = "ability-deployment-overlay-v1";

/// Maximum canonical deployment overlay size admitted by version 1.
pub const MAX_ABILITY_DEPLOYMENT_OVERLAY_BYTES: usize = 1024 * 1024;

/// Maximum reporter-selected validity period admitted by version 1.
pub const MAX_ABILITY_DEPLOYMENT_VALID_FOR_SECONDS: u64 = 300;

/// Returns the deployment-overlay semantics implemented by this reader.
///
/// # Errors
///
/// Returns an error if the built-in feature identifier is invalid.
pub fn ability_deployment_supported_features() -> Result<BTreeSet<RequiredFeature>> {
    [ABILITY_DEPLOYMENT_OVERLAY_FEATURE]
        .into_iter()
        .map(|feature| RequiredFeature::new(feature).map_err(invalid_model))
        .collect()
}

/// Pins the exact signed registry reference described by an overlay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityDeploymentPackage {
    /// Names the registry commit that authenticated the package reference.
    pub registry_commit: String,
    /// Names the package inside that commit.
    pub package: LocalKey,
    /// Preserves the exact selected package version.
    pub version: String,
    /// Preserves the exact selected platform.
    pub platform: String,
    /// Pins the exact canonical package manifest bytes.
    pub manifest_sha256: Sha256Digest,
    /// Pins the package manifest's domain-separated semantic identity.
    pub package_digest: Sha256Digest,
}

/// Names the lifecycle state asserted for one exact plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbilityDeploymentPlanState {
    /// The plan is validated but has not begun candidate work.
    Planned,
    /// Candidate work completed without selecting live state.
    Prepared,
    /// The deployment selected the plan as live state.
    Committed,
    /// The deployment recorded a definite plan failure.
    Failed,
    /// The deployment cannot yet determine the plan's final outcome.
    Uncertain,
}

/// Records the exact package export selected by a deployment plan.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityDeploymentExport {
    /// Names the export inside the exact package reference.
    pub export: LocalKey,
    /// Pins the interface name, ABI, and descriptor identity.
    pub interface: InterfaceKey,
    /// Pins the implementation artifact declared by the package reference.
    pub implementation: Sha256Digest,
    /// Identifies the selected provider instance, when resolution selected one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<InstanceId>,
    /// Lists selected logical resources in canonical order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceId>,
    /// Pins the selected binding revision, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_revision: Option<RevisionId>,
}

/// Carries stable identities and state for one exact deployment plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityDeploymentPlan {
    /// Identifies the target deployment environment.
    pub environment: EnvironmentId,
    /// Identifies the exact canonical binding and effect plan.
    pub plan: PlanId,
    /// Pins the policy revision used to validate the plan.
    pub policy_revision: RevisionId,
    /// Identifies a live execution transaction, when one has begun.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionId>,
    /// States the reporter's current plan lifecycle assertion.
    pub state: AbilityDeploymentPlanState,
    /// Lists package export selections in `(export, provider)` order.
    pub exports: Vec<AbilityDeploymentExport>,
}

/// Names the current observation state for one planned export.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbilityDeploymentObservationState {
    /// The planned provider was observed available.
    Available,
    /// The planned provider was observed failed.
    Failed,
    /// The last observation no longer describes the selected revision.
    Stale,
    /// The reporter has no verified observation for the selected export.
    Unverified,
}

/// Carries optional bounded evidence about one planned export.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityDeploymentObservation {
    /// Names the export inside the package reference and plan projection.
    pub export: LocalKey,
    /// Identifies the package instance that was observed.
    pub instance: InstanceId,
    /// States the reporter's current observation.
    pub state: AbilityDeploymentObservationState,
    /// Pins the observed content revision, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<RevisionId>,
    /// Lists immutable evidence-object digests in canonical order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Sha256Digest>,
    /// Records the reporter's wall-clock observation time.
    pub observed_at_unix_seconds: u64,
}

/// Supplies a reporter-authored private overlay for one package reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAbilityDeploymentOverlay {
    /// Carries [`ABILITY_DEPLOYMENT_OVERLAY_SCHEMA`].
    pub schema: String,
    /// Names required overlay semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Names the admin-enrolled deployment reporter slot.
    pub deployment: LocalKey,
    /// Increases strictly for every accepted report in this slot.
    pub sequence: u64,
    /// Pins the exact authenticated package reference described here.
    pub package: AbilityDeploymentPackage,
    /// Carries the selected plan's identities and state.
    pub plan: AbilityDeploymentPlan,
    /// Carries optional per-selection runtime observations in canonical order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<AbilityDeploymentObservation>,
    /// Records the reporter's wall-clock report time.
    pub reported_at_unix_seconds: u64,
    /// Requests a bounded lifetime from Hub receipt time.
    pub valid_for_seconds: u64,
}

impl VersionedDocument for PackageAbilityDeploymentOverlay {
    const SCHEMA: &'static str = ABILITY_DEPLOYMENT_OVERLAY_SCHEMA;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }
}

impl PackageAbilityDeploymentOverlay {
    /// Decodes and validates exact canonical deployment-overlay JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, unsupported, invalid, or
    /// oversized bytes.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ABILITY_DEPLOYMENT_OVERLAY_BYTES {
            return Err(invalid(
                "ability deployment overlay exceeds the 1 MiB limit",
            ));
        }
        let supported = ability_deployment_supported_features()?;
        let overlay: Self =
            decode_canonical(bytes, ABILITY_LIMITS_V1, &supported).map_err(invalid_model)?;
        overlay.validate()?;
        if overlay.canonical_json()? != bytes {
            return Err(invalid("ability deployment overlay is not canonical JSON"));
        }
        Ok(overlay)
    }

    /// Encodes the validated overlay as exact canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical encoding fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = encode_canonical(self).map_err(invalid_model)?;
        if bytes.len() > MAX_ABILITY_DEPLOYMENT_OVERLAY_BYTES {
            return Err(invalid(
                "ability deployment overlay exceeds the 1 MiB limit",
            ));
        }
        Ok(bytes)
    }

    /// Validates bounds, canonical order, and plan/observation references.
    ///
    /// # Errors
    ///
    /// Returns an error when the overlay is internally inconsistent or exceeds
    /// the version-1 bounds.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ABILITY_DEPLOYMENT_OVERLAY_SCHEMA {
            return Err(invalid("unsupported ability deployment overlay schema"));
        }
        if self.required_features.len() != 1
            || self.required_features[0].as_str() != ABILITY_DEPLOYMENT_OVERLAY_FEATURE
        {
            return Err(invalid("unsupported ability deployment overlay features"));
        }
        if self.sequence == 0 || self.reported_at_unix_seconds == 0 {
            return Err(invalid(
                "deployment sequence and report time must be positive",
            ));
        }
        if !(1..=MAX_ABILITY_DEPLOYMENT_VALID_FOR_SECONDS).contains(&self.valid_for_seconds) {
            return Err(invalid(
                "deployment overlay validity exceeds the version-1 bound",
            ));
        }
        validate_anchor(&self.package)?;

        let max_items = ABILITY_LIMITS_V1.max_collection_items as usize;
        if self.plan.exports.len() > max_items || self.observations.len() > max_items {
            return Err(invalid(
                "ability deployment overlay exceeds its collection limit",
            ));
        }
        if self.plan.exports.windows(2).any(|pair| {
            (&pair[0].export, &pair[0].provider) >= (&pair[1].export, &pair[1].provider)
        }) {
            return Err(invalid("deployment exports are not in canonical order"));
        }
        if self.observations.windows(2).any(|pair| {
            (&pair[0].export, &pair[0].instance) >= (&pair[1].export, &pair[1].instance)
        }) {
            return Err(invalid(
                "deployment observations are not in canonical order",
            ));
        }

        let planned_exports = self
            .plan
            .exports
            .iter()
            .map(|export| ((&export.export, export.provider.as_ref()), export))
            .collect::<BTreeMap<_, _>>();
        for export in &self.plan.exports {
            if export.resources.len() > max_items {
                return Err(invalid(
                    "deployment export resources exceed their collection limit",
                ));
            }
            ensure_strictly_sorted(&export.resources, "deployment export resources")?;
        }
        for observation in &self.observations {
            let selection = (&observation.export, Some(&observation.instance));
            if !planned_exports.contains_key(&selection) {
                if self
                    .plan
                    .exports
                    .iter()
                    .any(|planned| planned.export == observation.export)
                {
                    return Err(invalid(
                        "deployment observation does not match a selected export provider",
                    ));
                }
                return Err(invalid("deployment observation names an unplanned export"));
            }
            if observation.observed_at_unix_seconds == 0
                || observation.observed_at_unix_seconds > self.reported_at_unix_seconds
            {
                return Err(invalid("deployment observation has an invalid report time"));
            }
            if observation.evidence.len() > max_items {
                return Err(invalid(
                    "deployment observation evidence exceeds its collection limit",
                ));
            }
            ensure_strictly_sorted(&observation.evidence, "deployment observation evidence")?;
        }
        Ok(())
    }

    /// Verifies every anchored export against one authenticated package reference.
    ///
    /// # Errors
    ///
    /// Returns an error when a package identity or export identity differs from
    /// the authenticated reference.
    pub fn validate_against_reference(
        &self,
        registry_commit: &str,
        platform: &str,
        reference: &PackageAbilityReference,
    ) -> Result<()> {
        self.validate()?;
        if self.package.registry_commit != registry_commit
            || self.package.package != reference.package
            || self.package.version != reference.version
            || self.package.platform != platform
            || self.package.manifest_sha256 != reference.manifest_sha256
            || self.package.package_digest != reference.package_digest
        {
            return Err(invalid(
                "deployment overlay does not match its package reference",
            ));
        }

        let mut reference_exports = BTreeMap::new();
        for export in &reference.exports {
            let interface = export.interface.interface_key().map_err(invalid_model)?;
            if reference_exports
                .insert(&export.name, (interface, export.implementation))
                .is_some()
            {
                return Err(invalid("package reference repeats an export identity"));
            }
        }
        for planned in &self.plan.exports {
            let Some((interface, implementation)) = reference_exports.get(&planned.export) else {
                return Err(invalid(
                    "deployment overlay names an unknown package export",
                ));
            };
            if &planned.interface != interface || planned.implementation != *implementation {
                return Err(invalid(
                    "deployment overlay export identity does not match its reference",
                ));
            }
        }
        Ok(())
    }
}

fn validate_anchor(anchor: &AbilityDeploymentPackage) -> Result<()> {
    let valid_commit = anchor.registry_commit.len() == 64
        && anchor
            .registry_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid_commit {
        return Err(invalid("deployment overlay has an invalid registry commit"));
    }
    for (label, value) in [
        ("package version", &anchor.version),
        ("platform", &anchor.platform),
    ] {
        if value.is_empty() || value.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes {
            return Err(invalid(format!(
                "deployment overlay has an invalid {label}"
            )));
        }
    }
    Ok(())
}

fn ensure_strictly_sorted<T: Ord>(items: &[T], label: &str) -> Result<()> {
    if items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!("{label} are not in canonical order")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> DocumentationError {
    DocumentationError::Invalid(message.into())
}

fn invalid_model(error: impl std::fmt::Display) -> DocumentationError {
    invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{ExecutionStage, InterfaceName};

    use super::*;

    fn key(value: &str) -> LocalKey {
        LocalKey::new(value).unwrap()
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn environment() -> EnvironmentId {
        EnvironmentId {
            authority: key("fleet"),
            key: key("production"),
            stage: ExecutionStage::Host,
        }
    }

    fn instance(name: &str) -> InstanceId {
        InstanceId {
            environment: environment(),
            key: key(name),
        }
    }

    fn overlay() -> PackageAbilityDeploymentOverlay {
        let provider = instance("nginx-edge");
        let export = AbilityDeploymentExport {
            export: key("virtual-host"),
            interface: InterfaceKey {
                name: InterfaceName::new("aos.nginx.virtual-host").unwrap(),
                abi: std::num::NonZeroU32::new(1).unwrap(),
                descriptor: digest(3),
            },
            implementation: digest(4),
            provider: Some(provider.clone()),
            resources: Vec::new(),
            binding_revision: Some(RevisionId(digest(5))),
        };
        PackageAbilityDeploymentOverlay {
            schema: ABILITY_DEPLOYMENT_OVERLAY_SCHEMA.to_string(),
            required_features: ability_deployment_supported_features()
                .unwrap()
                .into_iter()
                .collect(),
            deployment: key("production"),
            sequence: 1,
            package: AbilityDeploymentPackage {
                registry_commit: "a".repeat(64),
                package: key("nginx"),
                version: "1.0".to_string(),
                platform: "x86_64-linux".to_string(),
                manifest_sha256: digest(1),
                package_digest: digest(2),
            },
            plan: AbilityDeploymentPlan {
                environment: environment(),
                plan: PlanId(digest(6)),
                policy_revision: RevisionId(digest(7)),
                transaction: Some(TransactionId(key("activation-1"))),
                state: AbilityDeploymentPlanState::Committed,
                exports: vec![export],
            },
            observations: vec![AbilityDeploymentObservation {
                export: key("virtual-host"),
                instance: provider,
                state: AbilityDeploymentObservationState::Available,
                revision: Some(RevisionId(digest(8))),
                evidence: vec![digest(9)],
                observed_at_unix_seconds: 99,
            }],
            reported_at_unix_seconds: 100,
            valid_for_seconds: 60,
        }
    }

    #[test]
    fn rejects_duplicate_export_selection_identity() {
        let mut overlay = overlay();
        let mut duplicate = overlay.plan.exports[0].clone();
        duplicate.implementation = digest(10);
        overlay.plan.exports.push(duplicate);

        let error = overlay.validate().unwrap_err().to_string();

        assert!(error.contains("deployment exports are not in canonical order"));
    }

    #[test]
    fn accepts_distinct_provider_selections_for_one_export() {
        let mut overlay = overlay();
        let mut second = overlay.plan.exports[0].clone();
        second.provider = Some(instance("nginx-west"));
        overlay.plan.exports.push(second);

        overlay.validate().unwrap();
    }

    #[test]
    fn rejects_conflicting_observations_for_one_export() {
        let mut overlay = overlay();
        let mut duplicate = overlay.observations[0].clone();
        duplicate.state = AbilityDeploymentObservationState::Failed;
        overlay.observations.push(duplicate);

        let error = overlay.validate().unwrap_err().to_string();

        assert!(error.contains("deployment observations are not in canonical order"));
    }

    #[test]
    fn rejects_observation_for_another_instance() {
        let mut overlay = overlay();
        overlay.observations[0].instance = instance("other");

        let error = overlay.validate().unwrap_err().to_string();

        assert!(error.contains("does not match a selected export provider"));
    }

    #[test]
    fn rejects_observation_for_an_unresolved_selection() {
        let mut overlay = overlay();
        overlay.plan.exports[0].provider = None;

        let error = overlay.validate().unwrap_err().to_string();

        assert!(error.contains("does not match a selected export provider"));
    }
}
