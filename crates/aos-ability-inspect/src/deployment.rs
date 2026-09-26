//! Derives a bounded deployment report from a semantically checked effect plan.
//!
//! The projection records only selections the plan proves. Runtime state and
//! observations require separate execution evidence and are never inferred from
//! a planned binding.

use std::collections::BTreeMap;

use aos_ability_model::{VersionedDocument, encode_canonical};
use aos_ability_validate::CheckedEffectPlan;
use aos_doc_model::{
    ABILITY_DEPLOYMENT_OVERLAY_SCHEMA, AbilityDeploymentExport, AbilityDeploymentPackage,
    AbilityDeploymentPlan, AbilityDeploymentPlanState, PackageAbilityDeploymentOverlay,
    PackageAbilityReference, ability_deployment_supported_features,
};
use thiserror::Error;

/// Identifies the authenticated registry reference and reporter slot for one report.
#[derive(Clone, Debug)]
pub struct DeploymentReportContext {
    /// Names the exact indexed registry commit containing the package reference.
    pub registry_commit: String,
    /// Names the platform of that indexed package reference.
    pub platform: String,
    /// Names the enrolled Hub deployment reporter slot.
    pub deployment: aos_ability_model::LocalKey,
    /// Advances strictly beyond the last accepted report in that slot.
    pub sequence: u64,
    /// Records the reporter's current Unix time in seconds.
    pub reported_at_unix_seconds: u64,
    /// Requests a bounded report lifetime in seconds.
    pub valid_for_seconds: u64,
}

/// Reports a disagreement between checked plan evidence and a package reference.
#[derive(Debug, Error)]
pub enum DeploymentProjectionError {
    /// The reference is malformed or cannot be canonically encoded.
    #[error("package reference is invalid: {0}")]
    Reference(#[source] aos_doc_model::DocumentationError),
    /// The plan does not retain the exact package manifest named by the reference.
    #[error("checked plan does not contain the exact referenced package manifest")]
    MissingPackage,
    /// The referenced platform differs from the checked plan's platform.
    #[error("package reference platform differs from the checked plan platform")]
    PlatformMismatch,
    /// The projected overlay violates the shared document contract.
    #[error("projected deployment overlay is invalid: {0}")]
    Overlay(#[source] aos_doc_model::DocumentationError),
    /// The package manifest cannot be canonically encoded.
    #[error("checked package manifest cannot be canonically encoded: {0}")]
    Manifest(#[source] aos_ability_model::document::DocumentError),
}

/// Projects one package's planned provider selections from checked plan evidence.
///
/// Every public alias for a selected implementation is included. Aliases are
/// package declarations, while the binding plan selects exact interface and
/// implementation identities rather than spelling a package-local alias.
/// The caller must authenticate the package reference through its registry;
/// matching its manifest identity to the plan does not verify a signature.
///
/// # Errors
///
/// Returns an error when the reference, package manifest, platform, or
/// resulting bounded overlay disagrees with the checked plan.
pub fn planned_deployment_overlay(
    plan: &CheckedEffectPlan,
    reference: &PackageAbilityReference,
    context: DeploymentReportContext,
) -> Result<PackageAbilityDeploymentOverlay, DeploymentProjectionError> {
    reference
        .canonical_json()
        .map_err(DeploymentProjectionError::Reference)?;

    let binding_plan = plan.binding_plan();
    let platform = &binding_plan.environment().platform;
    let expected_platform = format!(
        "{}-{}",
        platform.architecture.as_str(),
        platform.system.as_str()
    );
    if context.platform != expected_platform {
        return Err(DeploymentProjectionError::PlatformMismatch);
    }

    let package = binding_plan
        .packages()
        .iter()
        .find(|package| {
            package.package.name == reference.package
                && package.package.version == reference.version
                && package.content_digest().ok() == Some(reference.package_digest)
        })
        .ok_or(DeploymentProjectionError::MissingPackage)?;
    let manifest = encode_canonical(package).map_err(DeploymentProjectionError::Manifest)?;
    if aos_contract::Sha256Digest::of_bytes(&manifest) != reference.manifest_sha256 {
        return Err(DeploymentProjectionError::MissingPackage);
    }

    let mut exports = BTreeMap::new();
    for binding in binding_plan
        .bindings()
        .iter()
        .filter(|binding| binding.provider_package == Some(reference.package_digest))
    {
        let matching = reference.exports.iter().filter(|export| {
            export.interface == binding.interface
                && export.implementation == binding.implementation.descriptor
        });
        for export in matching {
            exports
                .entry((export.name.clone(), binding.provider.clone()))
                .or_insert_with(|| AbilityDeploymentExport {
                    export: export.name.clone(),
                    interface: export.interface.clone(),
                    implementation: export.implementation,
                    provider: Some(binding.provider.clone()),
                    resources: Vec::new(),
                    binding_revision: None,
                });
        }
    }

    let overlay = PackageAbilityDeploymentOverlay {
        schema: ABILITY_DEPLOYMENT_OVERLAY_SCHEMA.to_string(),
        required_features: ability_deployment_supported_features()
            .map_err(DeploymentProjectionError::Overlay)?
            .into_iter()
            .collect(),
        deployment: context.deployment,
        sequence: context.sequence,
        package: AbilityDeploymentPackage {
            registry_commit: context.registry_commit.clone(),
            package: reference.package.clone(),
            version: reference.version.clone(),
            platform: context.platform.clone(),
            manifest_sha256: reference.manifest_sha256,
            package_digest: reference.package_digest,
        },
        plan: AbilityDeploymentPlan {
            environment: binding_plan.environment().environment.clone(),
            plan: plan.id(),
            policy_revision: binding_plan.document().policy_revision,
            transaction: None,
            state: AbilityDeploymentPlanState::Planned,
            exports: exports.into_values().collect(),
        },
        observations: Vec::new(),
        reported_at_unix_seconds: context.reported_at_unix_seconds,
        valid_for_seconds: context.valid_for_seconds,
    };
    overlay
        .validate_against_reference(&context.registry_commit, &context.platform, reference)
        .map_err(DeploymentProjectionError::Overlay)?;
    Ok(overlay)
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{LocalKey, encode_canonical};
    use aos_ability_validate::test_support::checked_stateful_owner_effect_plan;
    use aos_ability_validate::{
        AbilityContractData, CheckedAbilityContract, validate_ability_contract,
    };
    use aos_doc_model::PackageAbilityReference;

    use super::*;

    fn fixture_reference(plan: &CheckedEffectPlan) -> PackageAbilityReference {
        let package = &plan.binding_plan().packages()[0];
        let manifest = encode_canonical(package).expect("fixture package manifest");
        let retained_interfaces = plan
            .interfaces()
            .values()
            .map(|interface| encode_canonical(interface).expect("fixture interface"))
            .collect::<Vec<_>>();
        let checked = validate_ability_contract(AbilityContractData::PackageSource {
            manifest: &manifest,
            retained_interfaces: &retained_interfaces,
        })
        .expect("fixture package contract");
        let CheckedAbilityContract::PackageSource(checked) = checked else {
            panic!("fixture must validate as a package contract");
        };
        PackageAbilityReference::from_checked_contract(&checked).expect("fixture reference")
    }

    fn context() -> DeploymentReportContext {
        DeploymentReportContext {
            registry_commit: "a".repeat(64),
            platform: "x86_64-linux".to_string(),
            deployment: LocalKey::new("production").expect("deployment key"),
            sequence: 1,
            reported_at_unix_seconds: 100,
            valid_for_seconds: 60,
        }
    }

    #[test]
    fn projects_only_checked_package_selections_as_planned() {
        let plan = checked_stateful_owner_effect_plan();
        let reference = fixture_reference(&plan);

        let overlay = planned_deployment_overlay(&plan, &reference, context())
            .expect("checked plan must project");

        assert_eq!(overlay.plan.state, AbilityDeploymentPlanState::Planned);
        assert_eq!(overlay.plan.plan, plan.id());
        assert_eq!(overlay.plan.exports.len(), 2);
        assert!(
            overlay
                .plan
                .exports
                .iter()
                .all(|export| export.provider.is_some())
        );
        assert!(overlay.observations.is_empty());
    }

    #[test]
    fn rejects_a_reference_for_another_platform() {
        let plan = checked_stateful_owner_effect_plan();
        let reference = fixture_reference(&plan);
        let mut report = context();
        report.platform = "aarch64-linux".to_string();

        let error = planned_deployment_overlay(&plan, &reference, report)
            .expect_err("platform mismatch must fail");

        assert!(matches!(error, DeploymentProjectionError::PlatformMismatch));
    }

    #[test]
    fn rejects_a_reference_for_other_manifest_bytes() {
        let plan = checked_stateful_owner_effect_plan();
        let mut reference = fixture_reference(&plan);
        reference.manifest_sha256 = aos_contract::Sha256Digest::of_bytes(b"other manifest");

        let error = planned_deployment_overlay(&plan, &reference, context())
            .expect_err("manifest mismatch must fail");

        assert!(matches!(error, DeploymentProjectionError::MissingPackage));
    }
}
