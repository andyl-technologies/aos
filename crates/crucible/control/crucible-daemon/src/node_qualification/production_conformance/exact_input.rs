//! Collects full-cut exact completions with original native staging and producer lineage.
//!
//! This separate format preserves the legacy exact no-input refusal. Every
//! present staged cut, including an empty one, reads its actual source-owned
//! native receipt through the same original runtime before constructing a report.

use super::{
    ExactCompletionCase, ExactCompletionObservation, QualificationError, exact::InputView,
    protocol, staging,
};
use crucible_engine::node_contract::{
    OperationRequest, OperationToken, OriginalInputEvidence, OriginalInputLineageLimits,
    OriginalRuntimeWitness, ProgressEvidence, StopReason, WorldActivation,
};
use crucible_node_format::{Bytes, ContentRef, U64, canonical};
use serde::Serialize;
use std::collections::BTreeSet;

pub(super) fn collect(
    runtime: &mut OriginalRuntimeWitness,
    expected_activation: Option<&WorldActivation>,
    token: &OperationToken,
    case: &ExactCompletionCase,
) -> Result<
    (
        ExactCompletionObservation,
        bool,
        Option<OriginalInputEvidence>,
    ),
    QualificationError,
> {
    let ceiling = usize::try_from(case.maximum_bytes)
        .map_err(|_| QualificationError::Refused("exact input snapshot address-space ceiling"))?;
    // Reject a foreign timing family before calling any native receipt reader.
    // Rechecking after that reader preserves the same original window custody.
    {
        let original = runtime
            .original_completed_operation(token)
            .map_err(native_failure)?;
        if expected_activation
            .is_some_and(|expected| !original.admission().activation().same_authority(expected))
            || !original.admission().token().same_authority(token)
            || !lawful_permission(original.admission().request(), &original.outcome().progress)
        {
            return Err(QualificationError::Refused(
                "original exact input permission unavailable",
            ));
        }
    }
    let default_limits = OriginalInputLineageLimits::default();
    let native_input = runtime
        .original_input_evidence(
            token,
            OriginalInputLineageLimits {
                maximum_bytes: ceiling.min(default_limits.maximum_bytes),
                ..default_limits
            },
        )
        .map_err(native_failure)?;
    let original = runtime
        .original_completed_operation(token)
        .map_err(native_failure)?;
    let admission = original.admission();
    if expected_activation.is_some_and(|expected| !admission.activation().same_authority(expected))
        || !admission.token().same_authority(token)
        || original.outcome().node != token.route().node
    {
        return Err(QualificationError::Refused(
            "foreign exact input original authority",
        ));
    }
    let lawful = lawful_permission(admission.request(), &original.outcome().progress);
    if !lawful {
        return Err(QualificationError::Refused(
            "original lacks matching exact input closure",
        ));
    }
    let staged = original.staged_inputs().map_err(native_failure)?;
    let staging = match (staged, native_input.as_ref()) {
        (Some(staged), Some(evidence)) => Some(staging::StagedView::new(staged, evidence)),
        (None, None) => None,
        _ => {
            return Err(QualificationError::Refused(
                "original staged receipt unavailable",
            ));
        }
    };
    let input = admission.inputs().map(InputView::from);
    let input_ref = reference(&input, ceiling)?;
    let matches = admission.request() == &case.request
        && original.outcome() == &case.outcome
        && original.acknowledged() == case.acknowledged
        && input_ref == case.input;
    let scheduling = original
        .outcome()
        .scheduling
        .as_ref()
        .ok_or(QualificationError::Refused(
            "complete original scheduling unavailable",
        ))?;
    let count = scheduling
        .bounds
        .len()
        .checked_add(scheduling.publications.len())
        .and_then(|n| n.checked_add(scheduling.external_inputs.len()))
        .and_then(|n| n.checked_add(6))
        .ok_or(QualificationError::Refused(
            "exact input proof count overflow",
        ))?;
    if count > 4096
        || scheduling
            .external_inputs
            .iter()
            .any(|inventory| !inventory.inputs.is_empty())
    {
        return Err(QualificationError::Refused(
            "unsupported exact input external-input scope",
        ));
    }
    let mut references = BTreeSet::from([&scheduling.proof_ref]);
    references.extend(scheduling.bounds.iter().map(|bound| &bound.proof_ref));
    references.extend(
        scheduling
            .publications
            .iter()
            .map(|publication| &publication.payload),
    );
    references.extend(
        scheduling
            .external_inputs
            .iter()
            .map(|inventory| &inventory.proof_ref),
    );
    if let Some(progress) = &scheduling.input_progress {
        references.insert(&progress.proof_ref);
    }
    let body_bytes = references.iter().try_fold(0u64, |total, reference| {
        total
            .checked_add(reference.length.get())
            .ok_or(QualificationError::Refused(
                "exact input proof bytes overflow",
            ))
    })?;
    let snapshot = (
        "crucible.original-exact-completion.v2",
        admission.request(),
        staging::activation_view(admission.activation()),
        input,
        staging,
        original.outcome(),
        original.acknowledged(),
    );
    // Count borrowed producer bytes and native Stage closure before JSON Value
    // construction or any completion-body copy. Source Stage retrieval already
    // reserved the same total ceiling before its own native body copies.
    let snapshot_bytes = protocol::encoded_size(&snapshot, ceiling)?;
    if body_bytes
        .checked_add(snapshot_bytes as u64)
        .is_none_or(|n| n > case.maximum_bytes)
    {
        return Err(QualificationError::Refused(
            "whole exact input witness byte ceiling",
        ));
    }
    let bytes = canonical_bytes(&snapshot)?;
    let snapshot_ref = canonical::content_ref(&bytes, "application/json")?;
    let references: Vec<_> = references.into_iter().cloned().collect();
    let objects = runtime
        .operation_evidence(token, &references, U64::new(body_bytes))
        .map_err(native_failure)?;
    Ok((
        ExactCompletionObservation {
            schema: "crucible.original-exact-witness.v2",
            case: case.case.clone(),
            snapshot: Bytes::new(bytes),
            snapshot_ref,
            objects,
        },
        matches,
        native_input,
    ))
}

fn lawful_permission(request: &OperationRequest, progress: &ProgressEvidence) -> bool {
    match (request, progress) {
        (
            OperationRequest::ExactRun { start, limit, .. }
            | OperationRequest::BoundarySettle { start, limit },
            ProgressEvidence::Exact { reached, stop },
        ) => {
            start <= reached
                && reached <= limit
                && (*reached != *limit || *stop == StopReason::HorizonPark)
                && *stop != StopReason::Unclassified
        }
        _ => false,
    }
}

fn reference<T: Serialize>(
    value: &Option<T>,
    ceiling: usize,
) -> Result<Option<ContentRef>, QualificationError> {
    value
        .as_ref()
        .map(|view| {
            protocol::precharge(view, ceiling)?;
            canonical::content_ref(&canonical_bytes(view)?, "application/json").map_err(Into::into)
        })
        .transpose()
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, QualificationError> {
    canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?,
    )
    .map_err(Into::into)
}

fn native_failure(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(format!("original exact input witness: {error}"))
}
