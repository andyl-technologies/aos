//! Rejoins a retained original Nix Start carrier to the real Controller ledger.
//!
//! This private readback proves exact durable admission lineage only. It does
//! not reconstruct a startup, lease verifier, session or physical floor owner.

use super::*;
use crate::controller_query::PublicOperationMethodV1;
use crate::production_operation_compiler::NixStartAdmissionCarrierV2;

mod continuation;

/// Keeps decoded ledger data within one immutable readback, not a custody permit.
struct DecodedNixStartLedgerV2 {
    operation: OperationRecord,
    effect: EffectLedgerRecord,
    context: PublicMutationEffectV1,
}

pub(crate) fn accepted_nix_start_admission_v2(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<NixStartAdmissionCarrierV2>, ReconcilerError> {
    let readback = accepted_nix_start_readback_v2(journal, operation_id)?;
    Ok(readback.and_then(|readback| readback.context.nix_start().cloned()))
}

/// Retains decoded records only after the full original admission checks.
fn accepted_nix_start_readback_v2(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<DecodedNixStartLedgerV2>, ReconcilerError> {
    journal.validate_held_protected_names()?;
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes()) else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation else {
        return Ok(None);
    };
    if public.method() != PublicOperationMethodV1::StartSandbox {
        return Ok(None);
    }
    let effect_bytes = journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("missing retained Start effect"))?;
    let effect = decode_effect(effect_bytes)?;
    let context = effect.plan.public_mutation_context()?
        .ok_or(ReconcilerError::CorruptLedger("missing retained Start context"))?;
    let Some(carrier) = context.nix_start() else {
        return Ok(None);
    };
    let admission = recovered_public_operation_admission_v1(journal, operation_id)?
        .ok_or(ReconcilerError::CorruptLedger("missing retained Start authorization"))?;
    let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(context.canonical_request())
        .map_err(|_| ReconcilerError::CorruptLedger("invalid original Start request"))?;
    let expected_effect = EffectPlan::authorized_public_mutation(
        PublicOperationMethodV1::StartSandbox, context.clone(),
    )?;
    if operation.effect_count != 1 || operation.ownership_gated || operation.runtime_intent_digest.is_some()
        || effect.plan != expected_effect
        || !matches!(request.request(), crate::cli_model::DormantSandboxRequestKindV1::Start(_))
        || carrier.operation() != operation_id
        || admission.method() != PublicOperationMethodV1::StartSandbox
        || admission.project() != context.project()
        || admission.accepted_wall_seconds() != context.accepted_wall_seconds()
        || public.accepted_generation() != carrier.original_generation().checked_add(1)
            .ok_or(ReconcilerError::CorruptLedger("invalid Start generation"))?
        || admission.authorization().resource_kind() != request.resource_kind()
        || request.selector() != Some(admission.authorization().selector())
        || journal.check_idempotency(request.idempotency_key(), carrier.request_digest())
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(ReconcilerError::CorruptLedger("retained Nix Start lineage disagrees"));
    }
    // accept_inner does not compare every nonlocal Effect on replay. This exact
    // readback does so before the compiler is permitted to reconstruct a plan.
    journal.validate_held_protected_names()?;
    Ok(Some(DecodedNixStartLedgerV2 {
        operation,
        effect,
        context,
    }))
}

pub(super) fn require_exact_nix_replay_plan_v2(
    journal: &Journal,
    operation_id: OperationId,
    plan: &OperationPlan,
) -> Result<(), ReconcilerError> {
    let recorded = journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .map(decode_effect).transpose()?;
    let recorded_nix = recorded.as_ref().map(|effect| effect.plan.public_mutation_context())
        .transpose()?.flatten().is_some_and(|context| context.has_retained_nix_start());
    let planned_nix = plan.effects.first().map(EffectPlan::public_mutation_context)
        .transpose()?.flatten().is_some_and(|context| context.has_retained_nix_start());
    if !recorded_nix && !planned_nix {
        return Ok(());
    }
    let carrier = accepted_nix_start_admission_v2(journal, operation_id)?
        .ok_or(ReconcilerError::IdempotencyConflict)?;
    let recorded = recorded.ok_or(ReconcilerError::IdempotencyConflict)?;
    let (desired_key, desired_value) = carrier.desired();
    if plan.operation_id != operation_id
        || plan.effects.len() != 1
        || plan.effects[0] != recorded.plan
        || plan.request_digest != carrier.request_digest()
        || plan.desired_key != desired_key
        || plan.desired_value != desired_value
    {
        return Err(ReconcilerError::IdempotencyConflict);
    }
    Ok(())
}
