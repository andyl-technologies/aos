//! Cross-validates runtime-authority audit records against the operation ledger.
//!
//! These read-only checks do not construct a reconciler or load the runtime
//! store recursively. Historical decisions retain their exact activated gate;
//! the runtime store separately validates revision chains and current heads.

use super::*;
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityPendingV1};
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::crosslinks as runtime_crosslinks;

fn project_crosslink_error(
    error: runtime_crosslinks::RuntimeCrosslinkDataErrorV1,
) -> ReconcilerError {
    use runtime_crosslinks::RuntimeCrosslinkDataErrorV1 as D;
    match error {
        D::RuntimeHistory(error) => ReconcilerError::RuntimeAuthority(error.into()),
        D::InvalidPlan(reason) => ReconcilerError::InvalidPlan(reason),
        D::CorruptLedger(reason) => ReconcilerError::CorruptLedger(reason),
        D::InvalidExecutorOutput(reason) => ReconcilerError::InvalidExecutorOutput(reason),
        D::PublicOperationClock => ReconcilerError::PublicOperationClock,
        D::PublicOperationSequenceExhausted => ReconcilerError::PublicOperationSequenceExhausted,
        D::Publication(error) => ReconcilerError::AuthorityPublication(error.into()),
    }
}

pub(crate) fn validate_runtime_authority_pending(
    journal: &Journal,
    pending: &RuntimeAuthorityPendingV1,
) -> Result<(), ReconcilerError> {
    journal
        .runtime_history_read_v1()
        .pending_links(pending.historical_data_v1())
        .map_err(project_crosslink_error)
}

/// Requires revocation to name one exact, canonical, assignment-scoped Stop.
pub(super) fn validate_intent_effects(
    state: RuntimeAuthorityStateV1,
    operation: OperationId,
    draft: &AuthorityPublicationDraftV1,
    effects: &[EffectPlan],
) -> Result<(), ReconcilerError> {
    runtime_crosslinks::validate_intent_effects(state, operation, draft, effects)
        .map_err(project_crosslink_error)
}

pub(crate) fn validate_runtime_authority_operations(
    journal: &Journal,
) -> Result<(), ReconcilerError> {
    journal
        .runtime_history_read_v1()
        .operation_links()
        .map_err(project_crosslink_error)
}

pub(crate) fn validate_runtime_authority_binding(
    journal: &Journal,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), ReconcilerError> {
    journal
        .runtime_history_read_v1()
        .binding_links(binding.historical_data_v1())
        .map_err(project_crosslink_error)
}

/// Recovers the exact activated claim after validating the binding's cross-links.
pub(crate) fn runtime_authority_claim(
    journal: &Journal,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<OwnershipClaimV1, ReconcilerError> {
    journal.ensure_protected_authority()?;
    validate_runtime_authority_binding(journal, binding)?;
    let gate = runtime_gate(journal, binding.operation())?;
    Ok(gate_plan(&gate).claim().clone())
}

fn gate_plan(gate: &OwnershipGateStatusV1) -> &OwnershipGatePlanV1 {
    runtime_crosslinks::gate_plan(gate)
}

fn runtime_gate(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<OwnershipGateStatusV1, ReconcilerError> {
    runtime_crosslinks::runtime_gate(journal.historical_read_view_v1(), operation_id)
        .map_err(project_crosslink_error)
}
