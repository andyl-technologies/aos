//! Checked-plan lookup for the package-owned image rollout backend.
//!
//! The generic validators authenticate the complete package, binding, and
//! effect graph. This module extracts the rollout request from the exact
//! resource revision selected by that fixed point. It does not rediscover the
//! selected implementation through a copied handler-path catalog.

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::AbilityValue;
use aos_ability_validate::CheckedEffectPlan;

use super::ImageRolloutRequest;

const ROLLOUT_RESOURCE_KIND: &str = "aos.image-rollout";

/// Extracts the native rollout request from one fully checked effect plan.
///
/// # Errors
///
/// Returns an error unless the checked fixed point contains exactly one desired
/// image-rollout revision and at least one checked operation targets it.
pub(crate) fn authenticate_single_image_rollout_fragment(
    plan: &CheckedEffectPlan,
) -> Result<ImageRolloutRequest> {
    let revisions = plan
        .document()
        .desired_revisions
        .iter()
        .filter(|revision| revision.kind.as_str() == ROLLOUT_RESOURCE_KIND)
        .collect::<Vec<_>>();
    let [revision] = revisions.as_slice() else {
        anyhow::bail!("retained transaction must contain one exact image-rollout revision")
    };

    let operations = plan
        .operations()
        .iter()
        .filter(|operation| operation.target.resource == revision.resource)
        .collect::<Vec<_>>();
    ensure!(
        !operations.is_empty(),
        "retained transaction contains no operation for its image-rollout revision"
    );

    decode_request(&revision.value)
}

fn decode_request(value: &AbilityValue) -> Result<ImageRolloutRequest> {
    serde_json::from_value(value.as_json().clone()).context("decoding retained rollout request")
}
