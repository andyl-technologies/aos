//! Read-only retained-generation activation probes.
//!
//! A probe authenticates the same retained inputs used by rollback while the
//! caller holds the system switch lock. Cross-ABI checks evaluate retained
//! source in a temporary workspace, but no probe repairs state, publishes
//! credentials, opens a transaction journal, or changes boot state.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::Serialize;

use crate::config::ApmConfig;
use crate::config_eval::activation::ActivateConfigParams;
use crate::config_eval::materialize::ConfigManifest;
use crate::types::{ConfigGeneration, ImageGeneration, ReactivationPlan};

use super::{SystemTransitionMode, image_rollout};

/// Exact schema discriminator for retained-target activation reports.
pub const RETAINED_ACTIVATABILITY_SCHEMA: &str = "aos.retained-activatability/v1";

const MAX_REASON_DETAIL_BYTES: usize = 4 * 1024;

/// Selects the retained generation axis being assessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetainedTargetKind {
    /// A mutable configuration generation under the running image.
    Configuration,
    /// A bootable immutable image generation.
    Image,
}

/// Names the transition that would reactivate a retained target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetainedActivationMode {
    /// Reactivates retained configuration under the same module ABI.
    Direct,
    /// Re-evaluates retained source inputs under the running module ABI.
    Reevaluate,
    /// Selects an authenticated image for the next boot.
    BootSelection,
}

/// Identifies a failed prerequisite without relying on prose matching.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivatabilityReasonCode {
    /// The retained generation manifest is missing, malformed, or tampered.
    ManifestInvalid,
    /// A retained immutable artifact is absent or has an invalid identity.
    ArtifactUnavailable,
    /// Current operator or platform authority does not admit the target.
    CurrentAuthorityRejected,
    /// A required live provider cannot be reacquired in its exact scope.
    ProviderUnavailable,
    /// A referenced credential cannot be resolved under current policy.
    CredentialUnavailable,
    /// Retained and running state-format contracts are incompatible.
    StateFormatIncompatible,
    /// The target cannot be rebound across the current module ABI.
    ModuleAbiIncompatible,
    /// The authenticated boot artifact is absent or no longer selectable.
    BootArtifactUnavailable,
    /// A current or recoverable transition owns the target resource.
    TransitionInProgress,
}

/// Carries one stable failure code with bounded operator detail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatabilityReason {
    /// Gives automation a stable prerequisite category.
    pub code: ActivatabilityReasonCode,
    /// Explains the exact failed check without claiming successful activation.
    pub detail: String,
}

/// Reports whether one retained generation can be activated under live policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedActivatabilityReport {
    schema: String,
    target_kind: RetainedTargetKind,
    generation: u32,
    mode: RetainedActivationMode,
    activatable: bool,
    reasons: Vec<ActivatabilityReason>,
}

impl RetainedActivatabilityReport {
    fn new(
        target_kind: RetainedTargetKind,
        generation: u32,
        mode: RetainedActivationMode,
        mut reasons: Vec<ActivatabilityReason>,
    ) -> Self {
        reasons.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.detail.cmp(&right.detail))
        });
        reasons.dedup();
        Self {
            schema: RETAINED_ACTIVATABILITY_SCHEMA.to_string(),
            target_kind,
            generation,
            mode,
            activatable: reasons.is_empty(),
            reasons,
        }
    }

    /// Reports whether every current prerequisite passed.
    #[must_use]
    pub const fn is_activatable(&self) -> bool {
        self.activatable
    }

    /// Returns stable fail-closed reasons in canonical order.
    #[must_use]
    pub fn reasons(&self) -> &[ActivatabilityReason] {
        &self.reasons
    }

    /// Encodes the report as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        aos_contract::canonical::to_vec(self)
    }

    /// Converts a blocked report into an operational refusal.
    ///
    /// # Errors
    ///
    /// Returns an error containing every structured reason when any current
    /// prerequisite failed.
    pub fn require_activatable(&self) -> Result<()> {
        if self.activatable {
            return Ok(());
        }
        let details = self
            .reasons
            .iter()
            .map(|reason| format!("{:?}: {}", reason.code, reason.detail))
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "retained {:?} generation {} is not currently activatable: {details}",
            self.target_kind,
            self.generation
        )
    }
}

/// Authenticates a retained configuration and its current activation inputs.
pub(super) fn configuration(
    config: &ApmConfig,
    profile: &Path,
    target: &ConfigGeneration,
    running: &ImageGeneration,
) -> RetainedActivatabilityReport {
    let mut reasons = Vec::new();
    let mode = match target.reactivation_plan(running.module_abi) {
        Ok(ReactivationPlan::DirectReactivate) => RetainedActivationMode::Direct,
        Ok(ReactivationPlan::CrossAbiReEval(_)) => RetainedActivationMode::Reevaluate,
        Err(error) => {
            push_reason(
                &mut reasons,
                ActivatabilityReasonCode::ModuleAbiIncompatible,
                error,
            );
            RetainedActivationMode::Reevaluate
        }
    };

    let source_manifest = load_manifest(profile, target).map_err(|error| {
        push_reason(
            &mut reasons,
            ActivatabilityReasonCode::ManifestInvalid,
            error,
        );
    });
    if mode == RetainedActivationMode::Reevaluate {
        validate_reevaluation_artifacts(target).unwrap_or_else(|error| {
            push_reason(
                &mut reasons,
                ActivatabilityReasonCode::ArtifactUnavailable,
                error,
            );
        });
    }

    if let Ok(source_manifest) = source_manifest {
        if source_manifest.module_abi != target.module_abi_pinned
            || source_manifest.inputs.base_lib.store_path != target.base_lib_ref
        {
            reasons.push(ActivatabilityReason {
                code: ActivatabilityReasonCode::ModuleAbiIncompatible,
                detail: bounded_detail(format!(
                    "retained manifest ABI/base-library binding differs from configuration generation {}",
                    target.number
                )),
            });
        }

        let activation_manifest = if mode == RetainedActivationMode::Reevaluate {
            match reevaluate_manifest(profile, target, running) {
                Ok(manifest) => Some(manifest),
                Err(error) => {
                    push_reason(
                        &mut reasons,
                        ActivatabilityReasonCode::ModuleAbiIncompatible,
                        error,
                    );
                    None
                }
            }
        } else {
            Some(source_manifest)
        };

        let Some(manifest) = activation_manifest else {
            return RetainedActivatabilityReport::new(
                RetainedTargetKind::Configuration,
                target.number,
                mode,
                reasons,
            );
        };
        if manifest.module_abi != running.module_abi {
            reasons.push(ActivatabilityReason {
                code: ActivatabilityReasonCode::ModuleAbiIncompatible,
                detail: bounded_detail(format!(
                    "activation manifest ABI {} differs from running ABI {}",
                    manifest.module_abi, running.module_abi
                )),
            });
        }

        if let Err(error) = crate::credential_artifact::reconcile_secret_refs(
            &config.settings,
            &crate::credential_artifact::aos_root_path(),
            &manifest.credentials,
        ) {
            push_reason(
                &mut reasons,
                ActivatabilityReasonCode::CredentialUnavailable,
                error,
            );
        }

        if manifest.inputs.ability_activation.is_some() {
            let params = ActivateConfigParams {
                profile: profile.to_path_buf(),
                running_image: Some(running.clone()),
                ..ActivateConfigParams::default()
            };
            crate::config_eval::preflight_retained_manifest(&params, &manifest).unwrap_or_else(
                |error| {
                    let code = match error {
                        crate::config_eval::RetainedNativePreflightError::CurrentAuthority(_) => {
                            ActivatabilityReasonCode::CurrentAuthorityRejected
                        }
                        crate::config_eval::RetainedNativePreflightError::Artifact(_) => {
                            ActivatabilityReasonCode::ArtifactUnavailable
                        }
                        crate::config_eval::RetainedNativePreflightError::Provider(_) => {
                            ActivatabilityReasonCode::ProviderUnavailable
                        }
                    };
                    reasons.push(ActivatabilityReason {
                        code,
                        detail: bounded_detail(format!("{error:#}")),
                    });
                },
            );
        } else if mode == RetainedActivationMode::Direct {
            super::validate_direct_reactivation(target, running, &manifest_path(profile, target))
                .unwrap_or_else(|error| {
                    push_reason(
                        &mut reasons,
                        ActivatabilityReasonCode::ModuleAbiIncompatible,
                        error,
                    );
                });
        }
    }

    RetainedActivatabilityReport::new(
        RetainedTargetKind::Configuration,
        target.number,
        mode,
        reasons,
    )
}

/// Authenticates a retained image, boot artifact, and compatibility boundary.
pub(super) fn image(
    image_profile: &Path,
    system_profile: &Path,
    target: &ImageGeneration,
    transition_mode: SystemTransitionMode,
    drain: bool,
) -> RetainedActivatabilityReport {
    let mut reasons = Vec::new();
    if let Err(error) =
        super::resolve_installed_uki_entry(Path::new(super::BOOT_ROOT), &target.uki_path)
    {
        push_reason(
            &mut reasons,
            ActivatabilityReasonCode::BootArtifactUnavailable,
            error,
        );
    }
    let qualified = image_rollout::is_qualified_image_rollout(transition_mode, drain);
    image_rollout::probe_image_selection(
        image_profile,
        system_profile,
        Path::new(&target.toplevel),
        qualified,
    )
    .unwrap_or_else(|error| {
        let detail = format!("{error:#}");
        let code = if detail.contains("state version") || detail.contains("state-version") {
            ActivatabilityReasonCode::StateFormatIncompatible
        } else if detail.contains("rollout") || detail.contains("transaction") {
            ActivatabilityReasonCode::TransitionInProgress
        } else if detail.contains("executor") || detail.contains("toplevel") {
            ActivatabilityReasonCode::ArtifactUnavailable
        } else {
            ActivatabilityReasonCode::CurrentAuthorityRejected
        };
        reasons.push(ActivatabilityReason {
            code,
            detail: bounded_detail(detail),
        });
    });

    RetainedActivatabilityReport::new(
        RetainedTargetKind::Image,
        target.number,
        RetainedActivationMode::BootSelection,
        reasons,
    )
}

fn load_manifest(profile: &Path, target: &ConfigGeneration) -> Result<ConfigManifest> {
    let path = super::validate_generation_manifest(profile, target)?;
    let manifest = crate::config_eval::activation::load_config_manifest(&path)?;
    manifest.validate()?;
    Ok(manifest)
}

fn reevaluate_manifest(
    profile: &Path,
    target: &ConfigGeneration,
    running: &ImageGeneration,
) -> Result<ConfigManifest> {
    let ReactivationPlan::CrossAbiReEval(inputs) = target.reactivation_plan(running.module_abi)?
    else {
        bail!("configuration generation does not require cross-ABI reevaluation");
    };
    let workspace = tempfile::tempdir().context("creating rollback probe workspace")?;
    let eval_root = workspace.path().join("eval");
    let output = workspace.path().join("manifest.json");
    let source = super::validate_generation_manifest(profile, target)?;
    let current = super::load_generation_state_readonly(profile)?.current;
    crate::config_eval::reeval_cross_abi(
        &inputs,
        Path::new(&running.evaluator_ref),
        &source,
        eval_root,
        output.clone(),
        0,
        Some(current),
    )?;
    let manifest = crate::config_eval::activation::load_config_manifest(&output)?;
    manifest.validate()?;
    Ok(manifest)
}

fn manifest_path(profile: &Path, target: &ConfigGeneration) -> std::path::PathBuf {
    profile.join(format!("gen-{}/manifest.json", target.number))
}

fn validate_reevaluation_artifacts(target: &ConfigGeneration) -> Result<()> {
    let paths = target
        .config_module_paths
        .iter()
        .map(String::as_str)
        .chain([
            target.host_nix_ref.as_str(),
            target.facts_ref.as_str(),
            target.base_lib_ref.as_str(),
            target.evaluator_ref.as_str(),
        ]);
    for path in paths {
        crate::config_eval::materialize::validate_canonical_store_path(path)
            .with_context(|| format!("validating retained input {path}"))?;
        if !Path::new(path).exists() {
            bail!("retained activation input is unavailable: {path}");
        }
    }
    Ok(())
}

fn push_reason(
    reasons: &mut Vec<ActivatabilityReason>,
    code: ActivatabilityReasonCode,
    error: anyhow::Error,
) {
    reasons.push(ActivatabilityReason {
        code,
        detail: bounded_detail(format!("{error:#}")),
    });
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() <= MAX_REASON_DETAIL_BYTES {
        return detail;
    }
    let boundary = detail
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX_REASON_DETAIL_BYTES)
        .last()
        .unwrap_or(0);
    detail.truncate(boundary);
    detail.push_str("...");
    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_generation() -> ConfigGeneration {
        ConfigGeneration {
            number: 7,
            image_gen_parent: 2,
            module_abi_pinned: 1,
            manifest_hash: "sha256:manifest".to_string(),
            config_module_closure: "sha256:closure".to_string(),
            config_module_paths: vec![format!("/nix/store/{}-missing-module", "0".repeat(32))],
            config_module_packages: vec!["example@1".to_string()],
            host_nix_ref: format!("/nix/store/{}-missing-host", "1".repeat(32)),
            host_nix_commit: None,
            facts_hash: "sha256:facts".to_string(),
            facts_ref: format!("/nix/store/{}-missing-facts", "2".repeat(32)),
            base_lib_ref: format!("/nix/store/{}-missing-base", "3".repeat(32)),
            evaluator_ref: format!("/nix/store/{}-missing-evaluator", "4".repeat(32)),
            created_at: "2026-09-11T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn blocked_reports_preserve_stable_reason_order() {
        let report = RetainedActivatabilityReport::new(
            RetainedTargetKind::Configuration,
            7,
            RetainedActivationMode::Direct,
            vec![
                ActivatabilityReason {
                    code: ActivatabilityReasonCode::ProviderUnavailable,
                    detail: "manager disappeared".to_string(),
                },
                ActivatabilityReason {
                    code: ActivatabilityReasonCode::CredentialUnavailable,
                    detail: "credential was revoked".to_string(),
                },
            ],
        );

        assert!(!report.is_activatable());
        assert_eq!(
            report.reasons()[0].code,
            ActivatabilityReasonCode::ProviderUnavailable
                .min(ActivatabilityReasonCode::CredentialUnavailable)
        );
        assert!(report.require_activatable().is_err());
    }

    #[test]
    fn successful_reports_are_activatable() {
        let report = RetainedActivatabilityReport::new(
            RetainedTargetKind::Image,
            3,
            RetainedActivationMode::BootSelection,
            Vec::new(),
        );

        assert!(report.is_activatable());
        report.require_activatable().unwrap();
    }

    #[test]
    fn reason_details_are_bounded_at_utf8_boundaries() {
        let detail = "é".repeat(MAX_REASON_DETAIL_BYTES);
        let bounded = bounded_detail(detail);

        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.len() <= MAX_REASON_DETAIL_BYTES + 3);
        assert!(bounded.ends_with("..."));
    }

    #[test]
    fn reevaluation_requires_every_retained_artifact() {
        let error = validate_reevaluation_artifacts(&retained_generation())
            .expect_err("missing retained inputs must block activatability");

        assert!(error.to_string().contains("unavailable"));
    }
}
