//! Canonical runtime identities and method selection for trusted invocation.

use aos_ability_model::{MethodReference, Operation, OperationId, TransactionId};
use aos_contract::Sha256Digest;

use crate::adapter::InvocationPurpose;

const OPERATION_IDEMPOTENCY_KEY_DOMAIN: &str = "aos.ability.operation-idempotency-key/v1";
const COMPENSATION_IDEMPOTENCY_KEY_DOMAIN: &str = "aos.ability.compensation-idempotency-key/v1";

pub(super) fn method(operation: &Operation, purpose: InvocationPurpose) -> Option<MethodReference> {
    match purpose {
        InvocationPurpose::Effect => Some(MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        }),
        InvocationPurpose::Reconcile | InvocationPurpose::ReconcileCompensation => {
            operation.recovery.reconcile.clone()
        }
        InvocationPurpose::Cancel => operation.recovery.cancel.clone(),
        InvocationPurpose::Compensate => operation.recovery.compensate.clone(),
    }
}

pub(super) fn operation_idempotency_key(
    transaction: &TransactionId,
    operation: &OperationId,
) -> anyhow::Result<Sha256Digest> {
    Sha256Digest::of_canonical(OPERATION_IDEMPOTENCY_KEY_DOMAIN, &(transaction, operation))
}

pub(super) fn compensation_idempotency_key(
    transaction: &TransactionId,
    operation: &OperationId,
) -> anyhow::Result<Sha256Digest> {
    Sha256Digest::of_canonical(
        COMPENSATION_IDEMPOTENCY_KEY_DOMAIN,
        &(transaction, operation),
    )
}
