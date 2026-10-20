//! Reads the closed accepted execution family through one protected graph.
//!
//! Create-only specification callers keep their original strict facade. The
//! paid lifecycle reader additionally accepts exact Control/Cancel pairs, while
//! preserving their current operation identity and the original cold checks.
//! Borrowed history remains DATA and cannot supply a native effect permission.

use aos_sandbox_core::OperationId;
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
use crate::{Journal, RecordNamespace};
use super::{ReconcilerError, OperationState, decode_operation, decode_effect, effect_key,
    recovered_public_operation_resource_v1};

/// Reads the exact accepted CreateExecution effect from protected operation custody.
///
/// A canceled or permanently blocked operation cannot produce a specification.
/// This readback is nonauthorizing after the journal borrow ends.
///
/// # Errors
///
/// Returns an error if the protected operation/effect graph is corrupt or its
/// public method and retained request disagree.
pub(crate) fn accepted_create_execution_effect_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError> {
    accepted_execution_effect_engine_v3(journal, operation_id, AcceptedExecutionFamilyV3::Create)
}

/// Reads one exact accepted execution lifecycle request from the same graph.
///
/// The closed method/request pairs include Create, Control and Cancel only.
/// A current Control operation remains distinct from the original Create; this
/// borrowed DATA supplies neither a specification nor a native effect grant.
///
/// # Errors
/// Returns the original protected graph/canonical request errors. Canceled,
/// blocked, unrelated or non-single-effect operations supply no accepted input.
pub(crate) fn accepted_execution_effect_from_journal_v3(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError> {
    accepted_execution_effect_engine_v3(journal, operation_id, AcceptedExecutionFamilyV3::Lifecycle)
}

/// Reads a pending public Stop only for its separately funded lifecycle owner.
///
/// This delegates the same full protected accepted-graph decoder. It grants
/// neither executionC18 nor a Source mutation/native effect permission.
pub(crate) fn accepted_stop_effect_from_journal_v4(journal: &Journal, operation: OperationId)
    -> Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError> {
    accepted_execution_effect_engine_v3(journal, operation, AcceptedExecutionFamilyV3::Stop)
}

#[derive(Clone, Copy)]
enum AcceptedExecutionFamilyV3 {
    Create,
    Lifecycle,
    Stop,
}

fn accepted_execution_effect_engine_v3(
    journal: &Journal,
    operation_id: OperationId,
    family: AcceptedExecutionFamilyV3,
) -> Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError> {
    if recovered_public_operation_resource_v1(journal, operation_id)?.is_none() {
        return Ok(None);
    }
    let bytes = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger(
            "accepted Create operation is absent",
        ))?;
    let operation = decode_operation(bytes)?;
    if operation.effect_count() != 1
        || !matches!(
            operation.state(),
            OperationState::Accepted | OperationState::Applying | OperationState::Succeeded
        )
    {
        return Ok(None);
    }
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger(
            "accepted Create effect is absent",
        ))?;
    let effect = decode_effect(effect_bytes).map_err(ReconcilerError::from)?;
    use aos_sandbox_protocol::public_api::PublicOperationMethodV1 as Method;
    let method = effect.plan().public_mutation_method();
    let accepted = match family {
        AcceptedExecutionFamilyV3::Create => method == Some(Method::CreateExecution),
        AcceptedExecutionFamilyV3::Lifecycle => matches!(method,
            Some(Method::CreateExecution | Method::ControlExecution | Method::CancelExecution)),
        AcceptedExecutionFamilyV3::Stop => method == Some(Method::StopSandbox)
            && matches!(operation.state(), OperationState::Accepted | OperationState::Applying),
    };
    if !accepted {
        return Ok(None);
    }
    let context = effect
        .plan()
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
        .ok_or(ReconcilerError::CorruptLedger(
            "accepted Create context is absent",
        ))?;
    use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1 as Request;
    let request = context.validated_request().map_err(ReconcilerError::from)?;
    if !matches!(
        (method, &request),
        (Some(Method::CreateExecution), Request::Exec(_))
            | (Some(Method::ControlExecution), Request::ExecutionControl(_))
            | (Some(Method::CancelExecution), Request::CancelExec(_))
            | (Some(Method::StopSandbox), Request::Stop(_))
    ) {
        return Err(ReconcilerError::CorruptLedger(
            "accepted Create request has another method",
        ));
    }
    if matches!(family, AcceptedExecutionFamilyV3::Lifecycle | AcceptedExecutionFamilyV3::Stop) {
        // The genuine C18 entry pays before this sole decoder. Recheck an
        // already accepted request before any new Source/Host/native effect;
        // accepted history may predate the target's Delete tombstone.
        journal.require_public_mutation_targets_live_v2(context.project(), &request)?;
    }
    Ok(Some(context))
}


/// Prices only the shared accepted graph's complete decoder/projection models.
///
/// Genuine callers independently price their own native/Source scopes and
/// typed borrower headers before entering this same accepted graph engine.
/// This is passive representation DATA, not a declared receiving purpose.
pub(crate) fn accepted_public_effect_models_receiving_bytes_v4(
    controller: &Journal,
) -> Option<usize> {
    accepted_public_effect_models_receiving_bytes_retaining_v4(controller).ok()
}

// The Stop original retains the native held-extent error. Existing C18 keeps
// its established Option adapter, while both callers use this one formula.
pub(crate) fn accepted_public_effect_models_receiving_bytes_retaining_v4(
    controller: &Journal,
) -> Result<usize, crate::controller_resource_reservation::ResourceReservationErrorV1> {
    use aos_sandbox_protocol::domain_ledger::effect_history::EffectLedgerRecord;
    use aos_sandbox_protocol::domain_ledger::operation::MAXIMUM_EFFECTS;
    use aos_proto::aos::sandbox::v1::Feature;
    use crate::controller_resource_reservation::ResourceReservationErrorV1;
    use std::mem::size_of;

    let encoded = usize::try_from(controller.held_materialized_encoding_bytes_v1()?)
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let bytes = (|| {
        let effects = MAXIMUM_EFFECTS.checked_mul(size_of::<EffectLedgerRecord>())?;
        let atom = size_of::<buffa::UnknownField>()
            .checked_add(size_of::<Feature>())?
            .checked_add(size_of::<Vec<u8>>())?;
        encoded.checked_mul(atom)?.checked_mul(8)?.checked_add(effects)?
            .checked_add(aos_sandbox_protocol::domain_ledger::delete_batch::new_use::
                public_mutation_new_use_receiving_bytes_v2())
    })();
    bytes.ok_or(ResourceReservationErrorV1::Conflict)
}
