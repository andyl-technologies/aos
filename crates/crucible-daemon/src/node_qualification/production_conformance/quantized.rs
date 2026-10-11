//! Collects actual original quantized closure and complete staged producer custody.
//!
//! This format remains separate from exact timing evidence. Collection does not
//! close, poll, publish, acknowledge or replace the original native window.

use std::collections::BTreeSet;

use crucible::node_contract::{
    OperationOutcome, OperationRequest, OperationToken, OriginalInputEvidence,
    OriginalInputLineageLimits, OriginalRuntimeWitness, ProgressEvidence, WorldActivation,
};
use crucible::node_scheduling::InputPayload;
use crucible_node_contract::{Bytes, ContentRef, U64, canonical};
use serde::Serialize;

use super::{QualificationError, exact::InputView, protocol, staging};

/// Declares the complete source-installed original quantized and staging oracle.
pub struct QuantizedCompletionCase {
    /// Names the original realized-provider case in complete coverage.
    pub case: String,
    /// Binds the independent source, fixture revision and complete expected property.
    pub oracle: ContentRef,
    /// Declares the exact original QuantumBegin permission, including budget.
    pub request: OperationRequest,
    /// Declares every physical, logical, output, input and closure outcome field.
    pub outcome: OperationOutcome,
    /// Binds the complete original frozen input view, or explicit absence.
    pub input: Option<ContentRef>,
    /// Binds complete original staging, producer bodies and native ACK closure.
    pub staging: Option<ContentRef>,
    /// Requires the actual runtime-retained publication ACK disposition.
    pub acknowledged: bool,
    /// Bounds aggregate serialized snapshot and completion proof bodies before reads.
    pub maximum_bytes: u64,
}

/// Retains a complete original quantized witness without issuing class authority.
#[derive(Serialize)]
pub struct QuantizedCompletionObservation {
    /// Selects this independent quantized collection format.
    pub schema: &'static str,
    /// Names the actual original case without a substituted retry.
    pub case: String,
    /// Retains full permission, activation, staging, outcome and ACK snapshot bytes.
    pub snapshot: Bytes,
    /// Binds those exact canonical original snapshot bytes.
    pub snapshot_ref: ContentRef,
    /// Binds the complete embedded staging view, or explicit absence.
    pub staging_ref: Option<ContentRef>,
    /// Retains all four original closure bodies and every scheduling body once.
    pub objects: Vec<InputPayload>,
}

pub(super) fn collect(
    runtime: &mut OriginalRuntimeWitness,
    expected_activation: Option<&WorldActivation>,
    token: &OperationToken,
    case: &QuantizedCompletionCase,
) -> Result<
    (
        QuantizedCompletionObservation,
        bool,
        Option<OriginalInputEvidence>,
    ),
    QualificationError,
> {
    let ceiling = usize::try_from(case.maximum_bytes)
        .map_err(|_| QualificationError::Refused("quantized snapshot address-space ceiling"))?;
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
                "original quantized permission unavailable",
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
            "foreign quantized original authority",
        ));
    }
    let lawful = lawful_permission(admission.request(), &original.outcome().progress);
    if !lawful {
        return Err(QualificationError::Refused(
            "original lacks matching quantized closure",
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
    let staging_ref = reference(&staging, ceiling)?;
    let matches = admission.request() == &case.request
        && original.outcome() == &case.outcome
        && original.acknowledged() == case.acknowledged
        && input_ref == case.input
        && staging_ref == case.staging;
    let ProgressEvidence::Quantized { closure, .. } = &original.outcome().progress else {
        return Err(QualificationError::Refused(
            "original quantized closure unavailable",
        ));
    };
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
            "quantized proof count overflow",
        ))?;
    if count > 4096
        || scheduling
            .external_inputs
            .iter()
            .any(|inventory| !inventory.inputs.is_empty())
    {
        return Err(QualificationError::Refused(
            "unsupported quantized external-input scope",
        ));
    }
    let mut references = BTreeSet::from([
        &closure.close_receipt,
        &closure.output_inventory,
        &closure.pending_inventory,
        &closure.clock_evidence,
        &scheduling.proof_ref,
    ]);
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
                "quantized proof bytes overflow",
            ))
    })?;
    let snapshot = (
        "crucible.original-quantized-completion.v1",
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
            "whole quantized witness byte ceiling",
        ));
    }
    let bytes = canonical_bytes(&snapshot)?;
    let snapshot_ref = canonical::content_ref(&bytes, "application/json")?;
    let references: Vec<_> = references.into_iter().cloned().collect();
    let objects = runtime
        .operation_evidence(token, &references, U64::new(body_bytes))
        .map_err(native_failure)?;
    Ok((
        QuantizedCompletionObservation {
            schema: "crucible.original-quantized-witness.v1",
            case: case.case.clone(),
            snapshot: Bytes::new(bytes),
            snapshot_ref,
            staging_ref,
            objects,
        },
        matches,
        native_input,
    ))
}

pub(super) fn lawful_permission(request: &OperationRequest, progress: &ProgressEvidence) -> bool {
    match (request, progress) {
        (
            OperationRequest::QuantumBegin {
                window,
                start,
                end,
                input_batch,
                ..
            },
            ProgressEvidence::Quantized {
                window: actual,
                publication,
                closure,
                ..
            },
        ) => {
            window == actual
                && start < end
                && publication == end
                && input_batch == &closure.input_batch
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
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )
    .map_err(Into::into)
}

fn native_failure(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(format!("original quantized witness: {error}"))
}

#[cfg(test)]
#[path = "quantized_tests.rs"]
mod tests;
