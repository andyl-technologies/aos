//! Boot-time lookup for the retained image-rollout transaction.
//!
//! The generic validators authenticate the complete package, binding, and
//! effect graph. This module identifies the package-owned native rollout
//! handler from those checked records and extracts its one exact request.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{AbilityValue, BindingId, Operation, ValueExpression, VersionedDocument};
use aos_ability_validate::CheckedEffectPlan;

use crate::sysroot::image_rollout::AbRolloutRequest;

const ROLLOUT_HANDLER_ENTRY_POINT: &str = "libexec/aos-image-rollout-provider";

/// Extracts the native rollout request from one fully checked effect plan.
///
/// # Errors
///
/// Returns an error unless exactly one checked binding selects the authenticated
/// package handler, every operation for its resource uses that binding, and all
/// of those operations carry the same literal request.
pub(super) fn authenticate_single_image_rollout_fragment(
    plan: &CheckedEffectPlan,
) -> Result<AbRolloutRequest> {
    let rollout_operations = plan
        .operations()
        .iter()
        .filter_map(|operation| {
            operation_uses_rollout_handler(plan, operation)
                .transpose()
                .map(|result| result.map(|_| operation))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !rollout_operations.is_empty(),
        "retained transaction contains no authenticated rollout handler operation"
    );

    let bindings = rollout_operations
        .iter()
        .map(|operation| operation.binding.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        bindings.len() == 1,
        "retained transaction contains ambiguous rollout handler bindings"
    );
    let resources = rollout_operations
        .iter()
        .map(|operation| operation.target.resource.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        resources.len() == 1,
        "rollout handler operations do not target exactly one resource"
    );
    let resource = resources
        .first()
        .context("rollout handler operations have no target resource")?;
    ensure!(
        plan.operations().iter().all(|operation| {
            operation.target.resource != *resource || bindings.contains(&operation.binding)
        }),
        "rollout handler resource is shared with another binding"
    );

    let mut request = None;
    for operation in rollout_operations {
        let ValueExpression::Literal { value } = &operation.inputs else {
            anyhow::bail!("rollout handler request is not an exact literal")
        };
        let operation_request = decode_request(value)?;
        if let Some(expected) = &request {
            ensure!(
                expected == &operation_request,
                "rollout handler operations carry different requests"
            );
        } else {
            request = Some(operation_request);
        }
    }

    request.context("retained transaction contains no rollout handler request")
}

fn operation_uses_rollout_handler(
    plan: &CheckedEffectPlan,
    operation: &Operation,
) -> Result<Option<BindingId>> {
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .context("checked rollout operation has no checked binding")?;
    let Some(package_digest) = binding.provider_package else {
        return Ok(None);
    };
    let Some(handler_key) = &binding.implementation.handler else {
        return Ok(None);
    };
    let package = plan
        .binding_plan()
        .packages()
        .iter()
        .find(|package| package.content_digest().ok() == Some(package_digest))
        .context("checked rollout binding package is absent")?;
    let handler = package
        .implementation
        .handlers
        .get(handler_key)
        .context("checked rollout binding handler is absent from its package")?;

    Ok((handler.entry_point == ROLLOUT_HANDLER_ENTRY_POINT).then(|| operation.binding.clone()))
}

fn decode_request(value: &AbilityValue) -> Result<AbRolloutRequest> {
    serde_json::from_value(value.as_json().clone()).context("decoding retained rollout request")
}
