//! Builds canonical admission rows for the sole ordinary and closed Delete callers.
//!
//! This model recipe performs no append and supplies no financial or native
//! permission. Its callers retain their own preflight, original payer, exact
//! transaction identity and final crossing. Ownership-gated construction uses
//! the same current protected store and validation as ordinary admission.

use super::*;

/// Constructs the existing ordered admission rows after the caller has paid.
pub(crate) fn prepare_admission_records_v1(
    journal: &mut Journal,
    plan: &OperationPlan,
) -> Result<Vec<JournalRecord>, ReconcilerError> {
    prepare_admission_records_engine_v3(Some(journal), plan)
}

// The only journal-free branch below is the finite Delete model recipe. It
// cannot enter ownership construction, native append or admission preflight.
fn prepare_admission_records_engine_v3(
    mut journal: Option<&mut Journal>, plan: &OperationPlan,
) -> Result<Vec<JournalRecord>, ReconcilerError> {
    let effect_count = u32::try_from(plan.effects.len())
        .map_err(|_| ReconcilerError::InvalidPlan("too many effects"))?;
    let mut records = Vec::with_capacity(
        plan.effects.len()
            + plan.local_records.len()
            + 3
            + usize::from(plan.ownership_gate.is_some())
            + usize::from(plan.public_operation.is_some()),
    );
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        plan.desired_key.clone(),
        plan.desired_value.clone(),
    ));
    let operation = OperationRecord::new(
        if plan.effects.is_empty() && !plan.local_records.is_empty() {
            OperationState::Succeeded
        } else if plan.ownership_gate.is_some() {
            OperationState::OwnershipPending
        } else {
            OperationState::Accepted
        },
        effect_count,
        plan.ownership_gate.is_some(),
        plan.runtime_authority.as_ref().map(RuntimeAuthorityIntentV1::digest),
        plan.public_operation.as_ref().map(|public| {
            if plan.effects.is_empty() {
                public.durable_completed()
            } else {
                public.durable()
            }
        }),
    );
    let operation = match plan.accepted_start {
        Some(origin) => operation.with_accepted_start_origin_v1(origin),
        None => operation,
    };
    records.push(JournalRecord::put(
        RecordNamespace::Operation,
        plan.operation_id.into_bytes().to_vec(),
        encode_operation_record(operation),
    ));
    records.push(JournalRecord::idempotency(
        &plan.idempotency_key,
        plan.request_digest,
        plan.operation_id,
    ));
    if let Some(public) = &plan.public_operation {
        records.push(JournalRecord::put(
            RecordNamespace::PublicOperationAuthorization,
            plan.operation_id.into_bytes().to_vec(),
            public.authorization().encode()?,
        ));
    }
    if let Some(gate) = &plan.ownership_gate {
        let journal = journal.as_deref_mut().ok_or(ReconcilerError::InvalidPlan(
            "ownership admission requires its original protected journal"))?;
        if plan.runtime_authority.is_none()
            && journal
                .records(RecordNamespace::RuntimeAuthority)
                .next()
                .is_some()
            && RuntimeAuthorityStore::load(
                journal,
                RuntimeAuthorityLimits::default(),
            )?
            .current(gate.publication_draft().manifest().manifest().sandbox())?
            .is_some()
        {
            return Err(ReconcilerError::InvalidPlan(
                "a current runtime holder requires an explicit successor intent",
            ));
        }
        records.push(JournalRecord::put(
            RecordNamespace::OwnershipGate,
            plan.operation_id.into_bytes().to_vec(),
            encode_ownership_gate(&OwnershipGateStatusV1::Pending(gate.clone()))?,
        ));
        if let Some(intent) = &plan.runtime_authority {
            records.extend(
                RuntimeAuthorityStore::load(
                    journal,
                    RuntimeAuthorityLimits::default(),
                )?
                .prepare_pending(
                    plan.operation_id,
                    plan.request_digest,
                    gate.publication_draft(),
                    intent,
                )?,
            );
        }
    }
    records.extend(plan.local_records.iter().cloned());
    for (index, effect) in plan.effects.iter().enumerate() {
        let step = u32::try_from(index)
            .map_err(|_| ReconcilerError::InvalidPlan("too many effects"))?;
        records.push(JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(plan.operation_id, step).to_vec(),
            encode_effect(&EffectLedgerRecord::from_parts((
                effect.clone(),
                EffectState::Planned,
                None,
                None,
            )))
            .map_err(ReconcilerError::from)?,
        ));
    }
    Ok(records)
}

/// Builds the exact batch transaction from its genuine pending authorization.
///
/// This is a paid model recipe only. The caller must separately join the
/// completed preparatory Root exchange and the actual C17 native append loan.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_delete_admission_transaction_v3(
    journal: &mut Journal,
    fence: &crate::journal::SourceDeletePendingFenceV1<'_, '_, '_, '_>,
) -> Result<(OperationPlan, JournalTransaction), Box<dyn std::error::Error + Send + Sync>> {
    use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;

    let batch = DeleteBatchViewV1::decode(fence.batch_bytes()?)?;
    let authorized = fence.authorization();
    let plan = prepare_delete_admission_plan_data_v3(batch, authorized.request(), authorized.caller(),
        authorized.project(), authorized.accepted_wall_seconds(), fence.original_public_request_data_v3(),
        fence.native_position_data_v1()?)?;
    let records = prepare_admission_records_v1(journal, &plan)?;
    let transaction = JournalTransaction::new(batch.transaction(), records)?;
    Ok((plan, transaction))
}

/// Rebuilds only the canonical model of the exact independently checked Delete.
///
/// The actual Root observer calls this under its paid native COMMIT boundary.
/// These DATA create no admission, protected decision, prior-state owner or IO.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_delete_admission_comparison_data_v3(
    batch: aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1<'_>,
    request: &aos_sandbox_protocol::public_api::mutation::ResolvedPublicMutationRequestV1,
    caller: aos_sandbox_core::PrincipalId, project: aos_sandbox_core::ProjectId,
    accepted_wall_seconds: i64, original_public_request: &[u8], source_pending: &[u8;64],
) -> Result<(OperationPlan, JournalTransaction), Box<dyn std::error::Error + Send + Sync>> {
    let plan = prepare_delete_admission_plan_data_v3(batch, request, caller, project,
        accepted_wall_seconds, original_public_request, source_pending)?;
    let records = prepare_admission_records_engine_v3(None, &plan)?;
    let transaction = JournalTransaction::new(batch.transaction(), records)?;
    Ok((plan, transaction))
}

#[cfg(target_os = "linux")]
fn prepare_delete_admission_plan_data_v3(
    batch: aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1<'_>,
    request: &aos_sandbox_protocol::public_api::mutation::ResolvedPublicMutationRequestV1,
    caller: aos_sandbox_core::PrincipalId, project: aos_sandbox_core::ProjectId,
    accepted_wall_seconds: i64, original_public_request: &[u8], source_pending: &[u8;64],
) -> Result<OperationPlan, Box<dyn std::error::Error + Send + Sync>> {
    use aos_sandbox_protocol::domain_ledger::delete_batch as codec;
    use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
    let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Delete(delete) = request.request() else {
        return Err(JournalError::ProtectedBoundary.into());
    };
    batch.require_public_request_v2(delete)?;
    if batch.project() != project {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let effect = PublicMutationEffectV1::new(caller, project,
        accepted_wall_seconds, original_public_request.to_vec())?
        .into_plan(PublicOperationMethodV1::DeleteSandbox)?;
    let authorization = PublicOperationAuthorizationV1::new(project,
        request.resource_kind(), request.selector().ok_or(JournalError::ProtectedBoundary)?.clone())?;
    let public = PublicOperationAdmissionV1::new(PublicOperationMethodV1::DeleteSandbox,
        batch.root_successor_generation_data_v2()?, batch.operation().into_bytes(),
        accepted_wall_seconds, authorization)?;
    let mut plan = OperationPlan::new(batch.operation(), request.idempotency_key().clone(),
        batch.request_digest(), codec::batch_key(batch.project(), batch.operation()),
        batch.bytes().to_vec(), vec![effect])?.with_public_operation(public)?;
    plan.local_records = batch.admission_local_records_data_v2(source_pending)?;
    Ok(plan)
}
