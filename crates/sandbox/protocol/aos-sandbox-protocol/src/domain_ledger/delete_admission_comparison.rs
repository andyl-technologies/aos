//! Rebuilds exact Delete admission plan and transaction comparison DATA.
//!
//! These values retain canonical desired/effect/local rows only. They cannot
//! enter ownership construction, append, native currentness or authorization.

use super::{
    JournalTransactionDataError,
    delete_batch::{self as codec, DeleteBatchViewV1},
    effect_history::{
        EffectHistoryDataError, EffectLedgerRecord, EffectPlan, EffectState,
        PublicMutationEffectHistoryV1, encode_effect,
    },
    lifecycle_model::LifecycleModelError,
    operation::{MAXIMUM_EFFECTS, OperationRecord, effect_key, encode_operation_record},
    public_operation::{
        OperationState, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
        PublicOperationDataError,
    },
    transaction::{IdempotencyKey, JournalRecord, JournalTransaction},
};
use crate::public_api::{
    PublicOperationMethodV1, mutation::ResolvedPublicMutationRequestV1,
    public_mutation_context::PublicMutationContextV1,
};
use aos_sandbox_model::{OperationId, PrincipalId, ProjectId, RecordNamespace};

/// Retains the precise canonical refusal before any native effect.
#[derive(Debug, thiserror::Error)]
pub enum DeleteAdmissionComparisonErrorV3 {
    /// The independently supplied request and batch identities differ.
    #[error("protected journal storage boundary is invalid")]
    Boundary,
    /// The canonical plan exceeds its original bounds.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// Effect construction or encoding failed through its original codec.
    #[error(transparent)]
    Effects(#[from] EffectHistoryDataError),
    /// Public plan DATA failed before record construction.
    #[error(transparent)]
    PublicPlan(PublicOperationDataError),
    /// Public authorization encoding failed inside the record schedule.
    #[error(transparent)]
    PublicRecords(#[from] PublicOperationDataError),
    /// Batch/request or local-row DATA failed.
    #[error(transparent)]
    Batch(#[from] LifecycleModelError),
    /// Canonical transaction construction failed.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
}

/// Retains the exact pure-model locals until the caller projects its cause.
///
/// The caller constructs its original owning error before dropping this DATA.
/// No native journal, authority, decision or financial receipt is retained.
#[derive(Debug)]
pub struct DeleteAdmissionComparisonRetainedDataV3 {
    _stage: RetainedComparisonStageV3,
}

#[derive(Debug)]
enum RetainedComparisonStageV3 {
    None,
    Effect {
        _effect: EffectPlan,
    },
    Authorization {
        _authorization: PublicOperationAuthorizationV1,
        _effect: EffectPlan,
    },
    Public {
        _public: PublicOperationAdmissionV1,
    },
    Plan {
        _plan: DeleteAdmissionPlanDataV3,
    },
}

/// Carries a typed refusal and the pure locals that outlive its projection.
#[derive(Debug)]
pub struct DeleteAdmissionComparisonFailureV3 {
    cause: DeleteAdmissionComparisonErrorV3,
    retained: DeleteAdmissionComparisonRetainedDataV3,
}

impl std::fmt::Display for DeleteAdmissionComparisonFailureV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl std::error::Error for DeleteAdmissionComparisonFailureV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.cause)
    }
}

impl DeleteAdmissionComparisonFailureV3 {
    /// Transfers the precise cause and its ordered pure-model disposal debt.
    ///
    /// The caller must project the cause into its owning error first, then
    /// drop the returned retained DATA at the former helper-return frontier.
    #[must_use]
    pub fn into_parts_v3(
        self,
    ) -> (
        DeleteAdmissionComparisonErrorV3,
        DeleteAdmissionComparisonRetainedDataV3,
    ) {
        (self.cause, self.retained)
    }
}

fn failed_v3(
    cause: DeleteAdmissionComparisonErrorV3,
    stage: RetainedComparisonStageV3,
) -> DeleteAdmissionComparisonFailureV3 {
    DeleteAdmissionComparisonFailureV3 {
        cause,
        retained: DeleteAdmissionComparisonRetainedDataV3 { _stage: stage },
    }
}

/// Owns only the finite Delete plan's portable desired/effect/local DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteAdmissionPlanDataV3 {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
    desired_key: Vec<u8>,
    desired_value: Vec<u8>,
    effects: Vec<EffectPlan>,
    public_operation: Option<PublicOperationAdmissionV1>,
    local_records: Vec<JournalRecord>,
}

/// Transfers the same owned allocations into an upper ordinary plan.
///
/// These are untrusted plan DATA, not a protected decision or admission loan.
pub struct DeleteAdmissionPlanPartsDataV3 {
    /// The recorded operation identity.
    pub operation_id: OperationId,
    /// The original idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// The exact request commitment.
    pub request_digest: [u8; 32],
    /// The desired-state record key.
    pub desired_key: Vec<u8>,
    /// The canonical batch bytes.
    pub desired_value: Vec<u8>,
    /// The existing ordered portable effect plans.
    pub effects: Vec<EffectPlan>,
    /// The original public operation metadata.
    pub public_operation: Option<PublicOperationAdmissionV1>,
    /// The exact batch/source companion records.
    pub local_records: Vec<JournalRecord>,
}

impl DeleteAdmissionPlanDataV3 {
    /// Returns the recorded operation identity without authorizing it.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Moves the original allocations without cloning or revalidating them.
    #[must_use]
    pub fn into_parts_v3(self) -> DeleteAdmissionPlanPartsDataV3 {
        DeleteAdmissionPlanPartsDataV3 {
            operation_id: self.operation_id,
            idempotency_key: self.idempotency_key,
            request_digest: self.request_digest,
            desired_key: self.desired_key,
            desired_value: self.desired_value,
            effects: self.effects,
            public_operation: self.public_operation,
            local_records: self.local_records,
        }
    }

    fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        effects: Vec<EffectPlan>,
    ) -> Result<Self, DeleteAdmissionComparisonErrorV3> {
        crate::require_operation_plan_shape_data_v3!(
            operation_id,
            desired_key,
            desired_value,
            effects,
            DeleteAdmissionComparisonErrorV3::InvalidPlan
        );
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects,
            public_operation: None,
            local_records: Vec::new(),
        })
    }

    fn with_public_operation(
        mut self,
        public: PublicOperationAdmissionV1,
    ) -> Result<Self, DeleteAdmissionComparisonErrorV3> {
        let maximum_effects = MAXIMUM_EFFECTS - 1;
        crate::require_public_operation_shape_data_v3!(
            self.effects,
            self.local_records,
            self.public_operation,
            maximum_effects,
            DeleteAdmissionComparisonErrorV3::InvalidPlan
        );
        self.public_operation = Some(public);
        Ok(self)
    }
}

/// Rebuilds the exact independently checked Delete model and ordered transaction.
///
/// # Errors
/// Preserves original request/batch, public/effect, plan and record/transaction order.
pub fn prepare_delete_admission_comparison_data_v3(
    batch: DeleteBatchViewV1<'_>,
    request: &ResolvedPublicMutationRequestV1,
    caller: PrincipalId,
    project: ProjectId,
    accepted_wall_seconds: i64,
    original_public_request: &[u8],
    source_pending: &[u8; 64],
) -> Result<(DeleteAdmissionPlanDataV3, JournalTransaction), DeleteAdmissionComparisonFailureV3> {
    use DeleteAdmissionComparisonErrorV3 as Cause;
    use RetainedComparisonStageV3 as Retained;

    let crate::public_api::request::DormantSandboxRequestKindV1::Delete(delete) = request.request()
    else {
        return Err(failed_v3(Cause::Boundary, Retained::None));
    };
    batch
        .require_public_request_v2(delete)
        .map_err(|cause| failed_v3(Cause::Batch(cause), Retained::None))?;
    if batch.project() != project {
        return Err(failed_v3(Cause::Boundary, Retained::None));
    }
    let plain = PublicMutationContextV1::new(
        caller,
        project,
        accepted_wall_seconds,
        original_public_request.to_vec(),
    )
    .map_err(|cause| failed_v3(Cause::InvalidPlan(cause.reason()), Retained::None))?;
    let effect = EffectPlan::from_public_mutation_context(
        PublicOperationMethodV1::DeleteSandbox,
        PublicMutationEffectHistoryV1::from_plain(plain),
    )
    .map_err(|cause| failed_v3(Cause::Effects(cause), Retained::None))?;

    let resource_kind = request.resource_kind();
    let selector = match request.selector() {
        Some(selector) => selector.clone(),
        None => {
            return Err(failed_v3(
                Cause::Boundary,
                Retained::Effect { _effect: effect },
            ));
        }
    };
    let authorization = match PublicOperationAuthorizationV1::new(project, resource_kind, selector)
    {
        Ok(authorization) => authorization,
        Err(cause) => {
            return Err(failed_v3(
                Cause::PublicPlan(cause),
                Retained::Effect { _effect: effect },
            ));
        }
    };
    let generation = match batch.root_successor_generation_data_v2() {
        Ok(generation) => generation,
        Err(cause) => {
            return Err(failed_v3(
                Cause::Batch(cause),
                Retained::Authorization {
                    _authorization: authorization,
                    _effect: effect,
                },
            ));
        }
    };
    let public = match PublicOperationAdmissionV1::new(
        PublicOperationMethodV1::DeleteSandbox,
        generation,
        batch.operation().into_bytes(),
        accepted_wall_seconds,
        authorization,
    ) {
        Ok(public) => public,
        Err(cause) => {
            return Err(failed_v3(
                Cause::PublicPlan(cause),
                Retained::Effect { _effect: effect },
            ));
        }
    };
    let plan = match DeleteAdmissionPlanDataV3::new(
        batch.operation(),
        request.idempotency_key().clone(),
        batch.request_digest(),
        codec::batch_key(batch.project(), batch.operation()),
        batch.bytes().to_vec(),
        vec![effect],
    ) {
        Ok(plan) => plan,
        Err(cause) => return Err(failed_v3(cause, Retained::Public { _public: public })),
    };
    let mut plan = plan
        .with_public_operation(public)
        .map_err(|cause| failed_v3(cause, Retained::None))?;
    plan.local_records = match batch.admission_local_records_data_v2(source_pending) {
        Ok(records) => records,
        Err(cause) => {
            return Err(failed_v3(
                Cause::Batch(cause),
                Retained::Plan { _plan: plan },
            ));
        }
    };
    let records = match prepare_records_v3(&plan) {
        Ok(records) => records,
        Err(cause) => return Err(failed_v3(cause, Retained::Plan { _plan: plan })),
    };
    let transaction = match JournalTransaction::new(batch.transaction(), records) {
        Ok(transaction) => transaction,
        Err(cause) => {
            return Err(failed_v3(
                Cause::Transaction(cause),
                Retained::Plan { _plan: plan },
            ));
        }
    };
    Ok((plan, transaction))
}

// The former generic engine call is the same one paid model return here;
// only the impossible Journal ownership branch is absent from this DATA owner.
fn prepare_records_v3(
    plan: &DeleteAdmissionPlanDataV3,
) -> Result<Vec<JournalRecord>, DeleteAdmissionComparisonErrorV3> {
    crate::prepare_admission_records_data_v3! {
        plan: plan, records: records, ownership_gated: false, runtime_digest: None,
        accepted_start: None, invalid: DeleteAdmissionComparisonErrorV3::InvalidPlan,
        effect_error: DeleteAdmissionComparisonErrorV3::Effects, ownership_records: {}
    }
}

/// Prices the real portable comparison owners and function forwarding controls.
///
/// This Memory-only DATA quote grants no payment, native entry or authority.
#[must_use]
pub fn receiving_control_bytes_v3() -> Option<usize> {
    use std::mem::size_of;
    size_of::<DeleteAdmissionPlanDataV3>()
        .checked_mul(3)?
        .checked_add(
            size_of::<
                Result<
                    (DeleteAdmissionPlanDataV3, JournalTransaction),
                    DeleteAdmissionComparisonFailureV3,
                >,
            >()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Result<DeleteAdmissionPlanDataV3, DeleteAdmissionComparisonErrorV3>>()
                .checked_mul(6)?,
        )?
        .checked_add(size_of::<Vec<JournalRecord>>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<Vec<JournalRecord>, DeleteAdmissionComparisonErrorV3>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                DeleteBatchViewV1<'_>,
                &ResolvedPublicMutationRequestV1,
                PrincipalId,
                ProjectId,
                i64,
                &[u8],
                &[u8; 64],
            )>()
            .checked_mul(2)?,
        )
        .and_then(|bytes| {
            bytes.checked_add(size_of::<DeleteAdmissionComparisonFailureV3>().checked_mul(3)?)
        })
        .and_then(|bytes| bytes.checked_add(size_of::<RetainedComparisonStageV3>().checked_mul(3)?))
        .and_then(|bytes| {
            bytes.checked_add(
                size_of::<(DeleteAdmissionComparisonErrorV3, RetainedComparisonStageV3)>()
                    .checked_mul(2)?,
            )
        })
}
