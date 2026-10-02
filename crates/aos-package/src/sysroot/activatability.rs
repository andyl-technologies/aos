//! Read-only retained-generation activation probes.
//!
//! A probe authenticates the retained native desired state and exact immutable
//! inputs used by rollback. It does not repair journals, execute handlers, or
//! change boot state; successful admission does not establish live host health.

use std::path::Path;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::profile::{Generation, Profile};
use crate::types::ImageGeneration;

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
    /// Reconciles authenticated retained desired state as a new native transaction.
    Reconcile,
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
    profile: &Profile,
    target: &Generation,
) -> RetainedActivatabilityReport {
    let mut reasons = Vec::new();
    if let Err(error) = crate::install::native::probe_rollback(profile, target) {
        push_reason(
            &mut reasons,
            ActivatabilityReasonCode::CurrentAuthorityRejected,
            error,
        );
    }
    RetainedActivatabilityReport::new(
        RetainedTargetKind::Configuration,
        target.number,
        RetainedActivationMode::Reconcile,
        reasons,
    )
}

/// Authenticates a retained image and its compatibility boundary.
pub(super) fn image(
    image_profile: &Path,
    system_profile: &Path,
    target: &ImageGeneration,
    transition_mode: SystemTransitionMode,
    drain: bool,
) -> RetainedActivatabilityReport {
    let mut reasons = Vec::new();
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

    #[test]
    fn blocked_reports_preserve_stable_reason_order() {
        let report = RetainedActivatabilityReport::new(
            RetainedTargetKind::Configuration,
            7,
            RetainedActivationMode::Reconcile,
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
}
