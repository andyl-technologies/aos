//! Compares complete historical Controller Delete and capacity relations.
//!
//! Three whole recipes share the canonical Operation, Gate, Effect and metadata
//! codecs. They compare supplied transaction DATA without accessing a Journal,
//! reserving capacity, admitting a Delete, activating ownership or establishing
//! currentness. Native owners select original rows and retain protected writer,
//! projection, grant, clock and COMMIT readback responsibilities.

use aos_sandbox_model::{OperationId, RecordNamespace};

use super::delete_batch::{self as codec, DeleteBatchViewV1};
use super::effect_history::{
    EffectHistoryDataError, EffectLedgerRecord, EffectState, decode_effect, encode_effect,
};
use super::operation::{MAXIMUM_EFFECTS, OPERATION_RECORD_V2_BYTES, decode_operation, effect_key};
use super::ownership_gate::{
    OwnershipGateDataErrorV1, OwnershipGateStatusV1, decode_ownership_gate, encode_ownership_gate,
};
use super::project_admission_metadata::{
    ProjectAdmissionMetadataV1 as ProjectAdmissionMetadata,
    ProjectAdmissionPhaseV1 as ProjectAdmissionPhase,
};
use super::public_operation::{
    OperationState, PublicOperationAuthorizationV1, PublicOperationDataError,
};
use super::transaction::{JournalRecord, JournalTransaction};
use crate::public_api::public_mutation_context::InvalidPublicMutationContext;
use crate::publication::PublicationHistoryError;

/// Reports passive Delete metadata refusals with their original static classifications.
///
/// These causes contain DATA only. Native Delete admission flattens every refusal
/// at its established malformed-transaction frontier after its current-map checks.
#[derive(Debug, thiserror::Error)]
pub enum DeleteAdmissionHistoryErrorV1 {
    /// The original public request differs from the canonical batch.
    #[error(transparent)]
    Batch(#[from] super::lifecycle_model::LifecycleModelError),
    /// An Effect, request context or complete Delete relation is invalid.
    #[error(transparent)]
    Effect(#[from] EffectHistoryDataError),
    /// Operation metadata or its authorization scope is invalid.
    #[error(transparent)]
    Operation(#[from] PublicOperationDataError),
    /// The complete historical ownership Gate is invalid.
    #[error(transparent)]
    Gate(#[from] OwnershipGateDataErrorV1),
    /// The checked publication draft cannot bind the selected template.
    #[error(transparent)]
    Publication(#[from] PublicationHistoryError),
}

impl From<InvalidPublicMutationContext> for DeleteAdmissionHistoryErrorV1 {
    fn from(error: InvalidPublicMutationContext) -> Self {
        Self::Effect(EffectHistoryDataError::InvalidPlan(error.reason()))
    }
}

/// Reports the two original Controller capacity relation refusal categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ControllerCapacityHistoryErrorV1 {
    /// A predecessor, successor key, complete Effect or metadata join is invalid.
    #[error("protected historical capacity relation is invalid")]
    ProtectedBoundary,
    /// Capacity identities, allowed phases or the complete expected successor differ.
    #[error("historical capacity successor does not match its preflight")]
    AuthorityPreflightMismatch,
}

/// Validates the complete atomic Delete admission-metadata relation.
///
/// The checked batch supplies the original root, graph and request commitments.
/// `local_start` selects the ungated (4) or Pending-Gate (5) row layout;
/// `effects_start` must follow all batch-local rows and their handoff marker.
/// Success compares historical DATA only and grants no Delete or append authority.
///
/// # Errors
///
/// Refuses offset/count bounds, malformed or substituted Operation/Idempotency/
/// Authorization rows, runtime intents, invalid Pending Gates, noncanonical or
/// reordered Effects, differing complete bound plans, and any count other than
/// exactly one matching Delete Effect. Canonical codec refusals retain their causes.
pub fn validate_delete_batch_admission_records_v1(
    batch: DeleteBatchViewV1<'_>,
    transaction: &JournalTransaction,
    local_start: usize,
    effects_start: usize,
) -> Result<(), DeleteAdmissionHistoryErrorV1> {
    use crate::public_api::PublicOperationMethodV1;
    let invalid = || {
        DeleteAdmissionHistoryErrorV1::Effect(EffectHistoryDataError::CorruptLedger(
            "invalid Delete batch admission metadata",
        ))
    };
    let records = transaction.records();
    let expected_effects_start = local_start
        .checked_add(batch.count(0))
        .and_then(|offset| offset.checked_add(batch.count(2)))
        .and_then(|offset| offset.checked_add(1))
        .ok_or_else(invalid)?;
    if !matches!(local_start, 4 | 5)
        || effects_start != expected_effects_start
        || effects_start >= records.len()
        || records.len() - effects_start > MAXIMUM_EFFECTS
    {
        return Err(invalid());
    }
    let operation_id = batch.operation();
    let operation_row = records.get(1).ok_or_else(invalid)?;
    let idempotency = records.get(2).ok_or_else(invalid)?;
    let authorization = records.get(3).ok_or_else(invalid)?;
    if operation_row.namespace() != RecordNamespace::Operation
        || operation_row.key() != operation_id.as_bytes()
        || operation_row
            .value()
            .is_none_or(|bytes| bytes.len() != OPERATION_RECORD_V2_BYTES)
        || idempotency.namespace() != RecordNamespace::Idempotency
        || idempotency.key().is_empty()
        || idempotency.key().len() > 128
        || idempotency.value().is_none_or(|bytes| bytes.len() != 48)
        || authorization.namespace() != RecordNamespace::PublicOperationAuthorization
        || authorization.key() != operation_id.as_bytes()
        || authorization
            .value()
            .is_none_or(|bytes| bytes.len() > 64 * 1024 + 68)
    {
        return Err(invalid());
    }

    let operation = decode_operation(operation_row.value().ok_or_else(invalid)?)?;
    let public = operation.public_operation().ok_or_else(invalid)?;
    let root = &batch.bytes()[65..81];
    let root_row = batch
        .rows(0)
        .find(|row| row[0] == 1 && &row[1..17] == root)
        .ok_or_else(invalid)?;
    let idempotency_value = idempotency.value().ok_or_else(invalid)?;
    if operation.runtime_intent_digest().is_some()
        || operation.ownership_gated() != (local_start == 5)
        || operation.state()
            != if local_start == 5 {
                OperationState::OwnershipPending
            } else {
                OperationState::Accepted
            }
        || operation.effect_count() as usize != records.len() - effects_start
        || operation.effect_count() == 0
        || public.method() != PublicOperationMethodV1::DeleteSandbox
        || public.accepted_generation() != codec::raw64(&root_row[60..68])
        || idempotency_value[..32] != batch.request_digest()
        || idempotency_value[32..] != operation_id.as_bytes()[..]
    {
        return Err(invalid());
    }
    let scope = PublicOperationAuthorizationV1::decode(authorization.value().ok_or_else(invalid)?)?;
    if scope.project() != batch.project()
        || scope.resource_kind() != aos_sandbox_model::ResourceKind::Sandbox
        || !matches!(scope.selector(), aos_sandbox_model::Selector::Resource { resource }
            if resource.as_bytes().as_slice() == root)
    {
        return Err(invalid());
    }
    let gate = if local_start == 5 {
        let gate_row = records.get(4).ok_or_else(invalid)?;
        let gate = decode_delete_gate(gate_row, operation_id, batch, idempotency)?;
        Some(gate)
    } else {
        None
    };

    let mut delete_effects = 0_usize;
    for (step, row) in records[effects_start..].iter().enumerate() {
        let step = u32::try_from(step).map_err(|_| invalid())?;
        if row.namespace() != RecordNamespace::Effect || row.key() != effect_key(operation_id, step)
        {
            return Err(invalid());
        }
        validate_delete_effect_record(
            row,
            &gate,
            operation_id,
            step,
            batch,
            root,
            &mut delete_effects,
        )?;
    }
    if delete_effects != 1 {
        return Err(invalid());
    }
    // Runtime-authority pending rows require the separate existing runtime
    // owner/codec join. They are unsupported here, not certified by raw bytes.
    Ok(())
}

/// Holds one original Gate across Journal row checks without exposing its plan.
struct DeleteGateHistoryV1(OwnershipGateStatusV1);

/// Decodes and compares the complete original Delete ownership-gate row.
///
/// # Errors
///
/// Returns the original passive codec classification for a mismatched row,
/// Pending tag, metadata or canonical encoding.
fn decode_delete_gate(
    gate_row: &JournalRecord,
    operation_id: OperationId,
    batch: DeleteBatchViewV1<'_>,
    idempotency: &JournalRecord,
) -> Result<DeleteGateHistoryV1, DeleteAdmissionHistoryErrorV1> {
    let invalid = || {
        DeleteAdmissionHistoryErrorV1::Effect(EffectHistoryDataError::CorruptLedger(
            "invalid Delete batch admission metadata",
        ))
    };
    if gate_row.namespace() != RecordNamespace::OwnershipGate
        || gate_row.key() != operation_id.as_bytes()
    {
        return Err(invalid());
    }
    let gate = decode_ownership_gate(gate_row.value().ok_or_else(invalid)?)
        .map_err(DeleteAdmissionHistoryErrorV1::from)?;
    let OwnershipGateStatusV1::Pending(plan) = &gate else {
        return Err(invalid());
    };
    if plan.operation_id() != operation_id
        || plan.request_digest() != batch.request_digest()
        || plan.idempotency_key().as_bytes() != idempotency.key()
        || encode_ownership_gate(&gate)
            .map_err(DeleteAdmissionHistoryErrorV1::from)?
            .as_slice()
            != gate_row.value().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    Ok(DeleteGateHistoryV1(gate))
}

/// Holds the decoded prior once while the complete relation selects its successor.
struct OriginalCapacityEffectHistoryV1(EffectLedgerRecord);

/// Preserves the prior decode before the caller inspects transaction records.
///
/// # Errors
///
/// Returns ProtectedBoundary when the original Effect bytes fail decoding.
fn decode_capacity_effect_history(
    bytes: &[u8],
) -> Result<OriginalCapacityEffectHistoryV1, ControllerCapacityHistoryErrorV1> {
    let prior =
        decode_effect(bytes).map_err(|_| ControllerCapacityHistoryErrorV1::ProtectedBoundary)?;
    Ok(OriginalCapacityEffectHistoryV1(prior))
}

/// Compares the next row only after the caller's original row/key frontier.
///
/// # Errors
///
/// Returns ProtectedBoundary for an absent or malformed next value, differing
/// plan/state/dispatch, or absent project-admission metadata.
fn compare_capacity_effect_history(
    prior: OriginalCapacityEffectHistoryV1,
    next: &JournalRecord,
) -> Result<(ProjectAdmissionMetadata, ProjectAdmissionMetadata), ControllerCapacityHistoryErrorV1>
{
    let prior = prior.0.into_parts();
    let next = decode_effect(
        next.value()
            .ok_or(ControllerCapacityHistoryErrorV1::ProtectedBoundary)?,
    )
    .map_err(|_| ControllerCapacityHistoryErrorV1::ProtectedBoundary)?
    .into_parts();
    if next.0 != prior.0 || next.1 != prior.1 || next.2 != prior.2 {
        return Err(ControllerCapacityHistoryErrorV1::ProtectedBoundary);
    }
    Ok((
        prior
            .3
            .ok_or(ControllerCapacityHistoryErrorV1::ProtectedBoundary)?,
        next.3
            .ok_or(ControllerCapacityHistoryErrorV1::ProtectedBoundary)?,
    ))
}

/// Validates the complete per-row Delete Effect relation with original errors.
///
/// # Errors
///
/// Returns the original passive history/context or publication refusal when
/// the complete Effect, request, Gate template, or bound-plan relation is invalid.
fn validate_delete_effect_record(
    row: &JournalRecord,
    gate: &Option<DeleteGateHistoryV1>,
    operation_id: OperationId,
    step: u32,
    batch: DeleteBatchViewV1<'_>,
    root: &[u8],
    delete_effects: &mut usize,
) -> Result<(), DeleteAdmissionHistoryErrorV1> {
    use crate::public_api::PublicOperationMethodV1;

    let invalid = || {
        DeleteAdmissionHistoryErrorV1::Effect(EffectHistoryDataError::CorruptLedger(
            "invalid Delete batch admission metadata",
        ))
    };
    let effect = decode_effect(row.value().ok_or_else(invalid)?)
        .map_err(DeleteAdmissionHistoryErrorV1::from)?;
    if effect.state() != &EffectState::Planned
        || effect.dispatch().is_some()
        || effect.project_admission().is_some()
        || encode_effect(&effect)
            .map_err(DeleteAdmissionHistoryErrorV1::from)?
            .as_slice()
            != row.value().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    if effect.plan().public_mutation_method() == Some(PublicOperationMethodV1::DeleteSandbox) {
        let context = effect
            .plan()
            .public_mutation_context()
            .map_err(DeleteAdmissionHistoryErrorV1::from)?
            .ok_or_else(invalid)?;
        let crate::public_api::request::DormantSandboxRequestKindV1::Delete(request) = context
            .validated_request()
            .map_err(DeleteAdmissionHistoryErrorV1::from)?
        else {
            return Err(invalid());
        };
        if context.project() != batch.project() || request.sandbox_id.as_slice() != root {
            return Err(invalid());
        }
        if batch.version() == 2 {
            batch.require_public_request_v2(&request)?;
        } else if request.expected_plan_digest.as_slice() != batch.graph_plan().as_slice()
            || request.cascade != (batch.flags() & 1 != 0)
            || request.force != (batch.flags() & 2 != 0)
        {
            // Historical V1 keeps its established mandatory expectation.
            return Err(invalid());
        }
        // The original counter advances before this decoded Effect is dropped.
        // Keep it inside the relation instead of returning a deferred Boolean.
        *delete_effects += 1;
    } else {
        let binding = effect.plan().authority().ok_or_else(invalid)?;
        let Some(DeleteGateHistoryV1(OwnershipGateStatusV1::Pending(gate))) = gate.as_ref() else {
            return Err(invalid());
        };
        if crate::publication::bind_authority_publication_effect(
            gate.publication_draft(),
            binding.template_digest(),
        )
        .map_err(DeleteAdmissionHistoryErrorV1::from)?
        .into_inner(operation_id, step)
        .map_err(DeleteAdmissionHistoryErrorV1::from)?
            != *effect.plan()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Compares a complete Controller capacity-transfer history and its successor.
///
/// Native callers supply the original predecessor bytes and sole derived Effect
/// key. The prior is decoded before scanning the same complete transaction.
/// Success admits neither a reservation nor a protected append.
///
/// # Errors
///
/// Refuses malformed or missing Effect/metadata DATA, multiple or substituted
/// successors, changed Plan/State/dispatch, capacity identity mismatch, invalid
/// phase transitions, or any change beyond the complete expected metadata.
pub fn validate_controller_capacity_transfer_v1(
    prior: &[u8],
    key: &[u8; 20],
    transaction: &JournalTransaction,
    old_capacity: [u8; 32],
    new_capacity: [u8; 32],
) -> Result<(), ControllerCapacityHistoryErrorV1> {
    let (prior, next) = capacity_effect_transition(prior, key, transaction)?;
    if prior.capacity_id() != old_capacity || next.capacity_id() != new_capacity {
        return Err(ControllerCapacityHistoryErrorV1::AuthorityPreflightMismatch);
    }
    let mut expected = prior.clone();
    expected.set_historical_capacity_id(new_capacity);
    match (prior.phase(), next.phase()) {
        (ProjectAdmissionPhase::Prepared, ProjectAdmissionPhase::DispatchAuthorized) => {
            expected.set_historical_phase(ProjectAdmissionPhase::DispatchAuthorized);
        }
        (
            ProjectAdmissionPhase::DispatchAuthorized,
            ProjectAdmissionPhase::AcceptedRootTerminal,
        ) => {
            expected.set_historical_phase(ProjectAdmissionPhase::AcceptedRootTerminal);
            expected.set_historical_challenge(next.challenge());
            expected.set_historical_terminal(next.terminal());
        }
        _ => return Err(ControllerCapacityHistoryErrorV1::AuthorityPreflightMismatch),
    }
    if next != expected {
        return Err(ControllerCapacityHistoryErrorV1::AuthorityPreflightMismatch);
    }
    Ok(())
}

/// Compares a complete accepted Controller history with its retirement successor.
///
/// The supplied predecessor/key retain their Native selection. The recipe checks
/// complete Effect and metadata equality and the two-row settlement shape; it
/// authenticates no Root terminal/floor and consumes no capacity grant.
///
/// # Errors
///
/// Refuses malformed or substituted history, differing Plan/State/dispatch,
/// absent metadata, an unaccepted prior, changed capacity or metadata, or any
/// transaction shape other than the original two-row settlement.
pub fn validate_controller_capacity_settlement_v1(
    prior: &[u8],
    key: &[u8; 20],
    transaction: &JournalTransaction,
    capacity: [u8; 32],
) -> Result<(), ControllerCapacityHistoryErrorV1> {
    let (prior, next) = capacity_effect_transition(prior, key, transaction)?;
    let expected_phase = ProjectAdmissionPhase::RootRetired;
    let expected_floor = next.retired_floor();
    let mut expected = prior.clone();
    expected.set_historical_phase(expected_phase);
    expected.set_historical_retired_floor(expected_floor);
    if prior.phase() != ProjectAdmissionPhase::AcceptedRootTerminal
        || prior.capacity_id() != capacity
        || next != expected
        || transaction.records().len() != 2
    {
        return Err(ControllerCapacityHistoryErrorV1::AuthorityPreflightMismatch);
    }
    Ok(())
}

fn capacity_effect_transition(
    prior: &[u8],
    key: &[u8; 20],
    transaction: &JournalTransaction,
) -> Result<(ProjectAdmissionMetadata, ProjectAdmissionMetadata), ControllerCapacityHistoryErrorV1>
{
    let prior = decode_capacity_effect_history(prior)?;
    let mut effects = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::Effect);
    let next = effects
        .next()
        .ok_or(ControllerCapacityHistoryErrorV1::ProtectedBoundary)?;
    if next.key() != *key || effects.next().is_some() {
        return Err(ControllerCapacityHistoryErrorV1::ProtectedBoundary);
    }
    compare_capacity_effect_history(prior, next)
}

#[cfg(test)]
mod tests;
