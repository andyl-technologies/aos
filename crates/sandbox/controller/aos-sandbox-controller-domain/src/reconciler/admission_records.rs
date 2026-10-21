//! Builds native admission rows through the sole canonical DATA schedule.
//!
//! Actual ownership/runtime store access stays here at its original lexical
//! frontier. Closed Delete reconstructs only portable DATA below this boundary.

use super::*;
use aos_sandbox_protocol::domain_ledger::delete_admission_comparison::{
    DeleteAdmissionComparisonErrorV3, DeleteAdmissionComparisonFailureV3, DeleteAdmissionPlanDataV3,
};

/// Constructs the existing ordered rows after the actual caller has paid.
pub(crate) fn prepare_admission_records_v1(
    journal: &mut Journal,
    plan: &OperationPlan,
) -> Result<Vec<JournalRecord>, ReconcilerError> {
    aos_sandbox_protocol::prepare_admission_records_data_v3! {
        plan: plan, records: records,
        ownership_gated: plan.ownership_gate.is_some(),
        runtime_digest: plan.runtime_authority.as_ref().map(RuntimeAuthorityIntentV1::digest),
        accepted_start: plan.accepted_start,
        invalid: ReconcilerError::InvalidPlan,
        effect_error: ReconcilerError::from,
        ownership_records: {
                if let Some(gate) = &plan.ownership_gate {
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
        }
    }
}

pub(crate) fn comparison_error_to_legacy_v3(
    failure: DeleteAdmissionComparisonFailureV3,
) -> Box<dyn std::error::Error + Send + Sync> {
    let (cause, retained) = failure.into_parts_v3();
    let original = match cause {
        DeleteAdmissionComparisonErrorV3::Boundary => JournalError::ProtectedBoundary.into(),
        DeleteAdmissionComparisonErrorV3::InvalidPlan(reason) => {
            ReconcilerError::InvalidPlan(reason).into()
        }
        DeleteAdmissionComparisonErrorV3::Effects(cause) => ReconcilerError::from(cause).into(),
        DeleteAdmissionComparisonErrorV3::PublicPlan(cause) => cause.into(),
        DeleteAdmissionComparisonErrorV3::PublicRecords(cause) => {
            ReconcilerError::from(cause).into()
        }
        DeleteAdmissionComparisonErrorV3::Batch(cause) => cause.into(),
        DeleteAdmissionComparisonErrorV3::Transaction(cause) => cause.into(),
    };
    // The original helper boxed its cause while these pure locals were alive.
    drop(retained);
    original
}

pub(crate) fn from_delete_plan_data_v3(data: DeleteAdmissionPlanDataV3) -> OperationPlan {
    let parts = data.into_parts_v3();
    OperationPlan {
        operation_id: parts.operation_id,
        idempotency_key: parts.idempotency_key,
        request_digest: parts.request_digest,
        desired_key: parts.desired_key,
        desired_value: parts.desired_value,
        effects: parts.effects,
        ownership_gate: None,
        runtime_authority: None,
        public_operation: parts.public_operation,
        accepted_start: None,
        local_records: parts.local_records,
    }
}

/// Rebuilds exact DATA under the same genuine pending authorization.
///
/// This result cannot replace preparatory Root or the actual C17 append loan.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_delete_admission_transaction_v3(
    fence: &crate::journal::SourceDeletePendingFenceV1<'_, '_, '_, '_>,
) -> Result<(OperationPlan, JournalTransaction), Box<dyn std::error::Error + Send + Sync>> {
    use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;
    let batch = DeleteBatchViewV1::decode(fence.batch_bytes()?)?;
    let authorized = fence.authorization();
    let (plan, transaction) =
        aos_sandbox_protocol::domain_ledger::delete_admission_comparison::prepare_delete_admission_comparison_data_v3(
            batch, authorized.request(), authorized.caller(), authorized.project(),
            authorized.accepted_wall_seconds(), fence.original_public_request_data_v3(),
            fence.native_position_data_v1()?,
        ).map_err(comparison_error_to_legacy_v3)?;
    Ok((from_delete_plan_data_v3(plan), transaction))
}

/// Prices additional lower DATA/control and upper move/error bridge planes.
#[must_use]
pub(crate) fn delete_comparison_forwarding_control_bytes_v3() -> Option<usize> {
    use std::mem::size_of;
    aos_sandbox_protocol::domain_ledger::delete_admission_comparison::receiving_control_bytes_v3()?
        .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::delete_admission_comparison::DeleteAdmissionPlanPartsDataV3>().checked_mul(3)?)?
        .checked_add(size_of::<OperationPlan>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(OperationPlan, JournalTransaction), Box<dyn std::error::Error + Send + Sync>>>().checked_mul(3)?)?
        .checked_add(size_of::<DeleteAdmissionPlanDataV3>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(DeleteAdmissionPlanDataV3, JournalTransaction),
            Box<dyn std::error::Error + Send + Sync>>>().checked_mul(2)?)?
        .checked_add(size_of::<DeleteAdmissionComparisonErrorV3>().checked_mul(3)?)?
        .checked_add(size_of::<Box<dyn std::error::Error + Send + Sync>>().checked_mul(3)?)?
        .checked_add(size_of::<DeleteAdmissionComparisonFailureV3>().checked_mul(3)?)?
        .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::delete_admission_comparison::DeleteAdmissionComparisonRetainedDataV3>().checked_mul(3)?)?
        .checked_add(size_of::<(DeleteAdmissionComparisonErrorV3,
            aos_sandbox_protocol::domain_ledger::delete_admission_comparison::DeleteAdmissionComparisonRetainedDataV3)>().checked_mul(3)?)
}
