//! Boot-time verification for the retained image-rollout transaction.
//!
//! This narrow verifier is outside generic handler selection. It authenticates
//! the released boot-commit graph before the boot substrate commits a slot.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{EffectPlanDocument, InterfaceDocument, PlanNodeKey, ValueExpression};
use aos_ability_plan::{AbRolloutRequest, lower_ab_rollout_fragment};

/// Authenticates the sole image-rollout fragment inside a checked plan.
///
/// # Errors
///
/// Returns an error unless the document contains exactly one rollout resource,
/// one literal request, and the exact released lifecycle graph.
pub(super) fn authenticate_single_image_rollout_fragment(
    document: &EffectPlanDocument,
    interface: &InterfaceDocument,
) -> Result<AbRolloutRequest> {
    let rollout_interface = interface
        .interface_key()
        .context("identifying the authenticated rollout interface")?;
    let rollout_operations = document
        .operations
        .iter()
        .filter(|operation| operation.interface == rollout_interface)
        .collect::<Vec<_>>();
    ensure!(
        !rollout_operations.is_empty(),
        "boot commit transaction has no rollout operations"
    );
    let resources = rollout_operations
        .iter()
        .map(|operation| operation.target.resource.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        resources.len() == 1,
        "boot commit transaction does not contain exactly one rollout resource"
    );
    let resource = resources
        .first()
        .context("boot commit transaction has no rollout resource")?;
    ensure!(
        document.operations.iter().all(|operation| {
            operation.target.resource != *resource || operation.interface == rollout_interface
        }),
        "boot commit rollout resource is shared with a non-rollout operation"
    );

    let mut request = None;
    for operation in &rollout_operations {
        let ValueExpression::Literal { value } = &operation.inputs else {
            anyhow::bail!("boot commit rollout request is not an exact literal")
        };
        let operation_request: AbRolloutRequest = serde_json::from_value(value.as_json().clone())
            .context("decoding retained rollout request")?;
        if let Some(expected) = &request {
            ensure!(
                expected == &operation_request,
                "boot commit transaction contains different rollout requests"
            );
        } else {
            request = Some(operation_request);
        }
    }
    let request = request.context("boot commit transaction has no rollout request")?;
    let retain = rollout_operations
        .iter()
        .find(|operation| operation.key.key.as_str() == "retain")
        .context("boot commit rollout graph has no retention operation")?;
    let expected = lower_ab_rollout_fragment(retain, interface)
        .context("lowering the expected boot commit rollout graph")?;
    ensure!(
        rollout_operations.len() == expected.operations.len()
            && rollout_operations
                .iter()
                .zip(&expected.operations)
                .all(|(actual, expected)| *actual == expected),
        "boot commit rollout operations differ from the released lifecycle graph"
    );

    let nodes = expected
        .operations
        .iter()
        .map(|operation| PlanNodeKey::Operation {
            key: operation.key.clone(),
        })
        .chain(expected.decisions.iter().map(|decision| PlanNodeKey::Decision {
            key: decision.key.clone(),
        }))
        .chain(expected.merges.iter().map(|merge| PlanNodeKey::Merge {
            key: merge.key.clone(),
        }))
        .collect::<BTreeSet<_>>();
    let actual_decisions = document
        .decisions
        .iter()
        .filter(|decision| nodes.contains(&PlanNodeKey::Decision { key: decision.key.clone() }))
        .collect::<Vec<_>>();
    let actual_merges = document
        .merges
        .iter()
        .filter(|merge| nodes.contains(&PlanNodeKey::Merge { key: merge.key.clone() }))
        .collect::<Vec<_>>();
    let actual_edges = document
        .edges
        .iter()
        .filter(|edge| nodes.contains(&edge.from) || nodes.contains(&edge.to))
        .collect::<Vec<_>>();
    ensure!(
        actual_decisions.len() == expected.decisions.len()
            && actual_decisions.iter().zip(&expected.decisions).all(|(actual, expected)| *actual == expected)
            && actual_merges.len() == expected.merges.len()
            && actual_merges.iter().zip(&expected.merges).all(|(actual, expected)| *actual == expected)
            && actual_edges.len() == expected.edges.len()
            && actual_edges.iter().zip(&expected.edges).all(|(actual, expected)| *actual == expected),
        "boot commit rollout control flow differs from the released lifecycle graph"
    );
    Ok(request)
}
