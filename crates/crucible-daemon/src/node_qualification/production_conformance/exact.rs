//! Reads actual original exact completion custody and all associated body rows.
//!
//! This reader neither polls native execution nor publishes or acknowledges an
//! output. Its snapshot is evidence data; installed source policy must establish
//! that the independently expected values cover the claimed physical property.

use std::collections::BTreeSet;

use crucible::node_contract::{
    OperationOutcome, OperationRequest, OperationToken, OriginalRuntimeWitness, ProgressEvidence,
    StopReason, WorldActivation,
};
use crucible::node_scheduling::{InputPayload, RuntimeInputBatch};
use crucible_node_contract::{Bytes, ContentRef, U64, canonical};
use serde::Serialize;

use super::{QualificationError, protocol};

/// Declares a source-installed complete exact outcome and original input oracle.
pub struct ExactCompletionCase {
    /// Names the original predeclared realized-provider case.
    pub case: String,
    /// Binds the independent expected property, source and fixture revision.
    pub oracle: ContentRef,
    /// Declares the complete expected original runtime permission.
    pub request: OperationRequest,
    /// Declares every expected outcome field, output byte and causal coordinate.
    pub outcome: OperationOutcome,
    /// Binds the complete original frozen input view, or explicit absence.
    pub input: Option<ContentRef>,
    /// Requires the actual runtime-retained output ACK disposition.
    pub acknowledged: bool,
    /// Reserves a total snapshot and proof-body ceiling before native readback.
    pub maximum_bytes: u64,
}

/// Retains original completion bytes and its complete authenticated body closure.
#[derive(Serialize)]
pub struct ExactCompletionObservation {
    /// Selects this independent original-runtime collection format.
    pub schema: &'static str,
    /// Names the actual original case without a substituted retry.
    pub case: String,
    /// Retains full permission, activation, input, outcome and ACK snapshot bytes.
    pub snapshot: Bytes,
    /// Binds those exact canonical original snapshot bytes.
    pub snapshot_ref: ContentRef,
    /// Retains every original scheduling/producer/input/output body once.
    pub objects: Vec<InputPayload>,
}

#[derive(Serialize)]
pub(super) struct InputView<'a> {
    node: &'a crucible_node_contract::Id,
    stage: &'a crucible_node_contract::Id,
    batch: &'a crucible_node_contract::Id,
    owners: &'a [crucible::node_contract::OwnerIdentity],
    cutoff: crucible_node_contract::Position,
    inventory: &'a ContentRef,
    deliveries: &'a [crucible::node_scheduling::event::Delivery],
    payloads: &'a [InputPayload],
}

impl<'a> From<&'a RuntimeInputBatch> for InputView<'a> {
    fn from(input: &'a RuntimeInputBatch) -> Self {
        Self {
            node: input.node(),
            stage: input.stage_operation(),
            batch: input.batch(),
            owners: input.owners(),
            cutoff: input.cutoff(),
            inventory: input.inventory(),
            deliveries: input.deliveries(),
            payloads: input.payloads(),
        }
    }
}

pub(super) fn collect(
    runtime: &mut OriginalRuntimeWitness,
    expected_activation: Option<&WorldActivation>,
    token: &OperationToken,
    case: &ExactCompletionCase,
) -> Result<(ExactCompletionObservation, bool), QualificationError> {
    let ceiling = usize::try_from(case.maximum_bytes)
        .map_err(|_| QualificationError::Refused("exact snapshot address-space ceiling"))?;
    let original = runtime
        .original_completed_operation(token)
        .map_err(native_failure)?;
    let admission = original.admission();
    if expected_activation.is_some_and(|expected| !admission.activation().same_authority(expected))
        || !admission.token().same_authority(token)
        || original.outcome().node != token.route().node
    {
        return Err(QualificationError::Refused(
            "foreign exact original authority",
        ));
    }
    let (start, limit) = match admission.request() {
        OperationRequest::ExactRun { start, limit, .. }
        | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
        _ => {
            return Err(QualificationError::Refused(
                "original permission is not exact",
            ));
        }
    };
    let ProgressEvidence::Exact { reached, stop } = original.outcome().progress else {
        return Err(QualificationError::Refused(
            "original lacks exact reached evidence",
        ));
    };
    let lawful = reached >= start
        && reached <= limit
        && (reached != limit || stop == StopReason::HorizonPark)
        && stop != StopReason::Unclassified;
    let input = admission.inputs().map(InputView::from);
    if input
        .as_ref()
        .is_some_and(|view| !view.deliveries.is_empty())
    {
        return Err(QualificationError::Refused(
            "original producer-lineage witness unavailable",
        ));
    }
    let mut matches = lawful
        && admission.request() == &case.request
        && original.outcome() == &case.outcome
        && original.acknowledged() == case.acknowledged;
    if let Some(view) = &input {
        protocol::precharge(view, ceiling)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(view).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        matches &= case.input.as_ref() == Some(&reference);
    } else {
        matches &= case.input.is_none();
    }

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
        .and_then(|n| n.checked_add(2))
        .ok_or(QualificationError::Refused("exact proof count overflow"))?;
    if count > 4096
        || scheduling
            .external_inputs
            .iter()
            .any(|inventory| !inventory.inputs.is_empty())
    {
        return Err(QualificationError::Refused(
            "unsupported exact external-input witness scope",
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
            .ok_or(QualificationError::Refused("exact proof bytes overflow"))
    })?;

    let record = admission.activation().record();
    let activation_view = (
        record.generation,
        &record.activation_id,
        &record.world_binding_hash,
        &record.owners,
        record.boundary,
    );
    let snapshot = (
        "crucible.original-exact-completion.v1",
        admission.request(),
        activation_view,
        input,
        original.outcome(),
        original.acknowledged(),
    );
    // Count the borrowed whole snapshot before constructing any Value/Vec or
    // copying original model/input/output bodies.
    let snapshot_bytes = protocol::encoded_size(&snapshot, ceiling)?;
    if body_bytes
        .checked_add(snapshot_bytes as u64)
        .is_none_or(|n| n > case.maximum_bytes)
    {
        return Err(QualificationError::Refused(
            "whole exact witness byte ceiling",
        ));
    }
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&snapshot).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let snapshot_ref = canonical::content_ref(&bytes, "application/json")?;
    let references: Vec<_> = references.into_iter().cloned().collect();
    let objects = runtime
        .operation_evidence(token, &references, U64::new(body_bytes))
        .map_err(native_failure)?;
    Ok((
        ExactCompletionObservation {
            schema: "crucible.original-exact-witness.v1",
            case: case.case.clone(),
            snapshot: Bytes::new(bytes),
            snapshot_ref,
            objects,
        },
        matches,
    ))
}

fn native_failure(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(format!("original exact witness: {error}"))
}
