//! Checks the sole purpose-closed Stop residual companion during ledger reads.
//!
//! These historical comparisons grant no containment, currentness or terminal
//! append permission. A terminal emitter separately requires the genuine
//! current protected Source witness and actual same-operation CAS owners.

use super::*;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    LifecycleEffectReceiptDataV1, StopResidualLifecycleReceiptDataV4,
    decode_lifecycle_effect_receipt_v1,
};
use aos_sandbox_protocol::public_api::{
    PublicOperationMethodV1, request::DormantSandboxRequestKindV1,
};

pub(super) fn classify(operation: OperationId, plan: &EffectPlan, receipt: &EffectReceipt)
    -> Result<Option<StopResidualLifecycleReceiptDataV4>, ReconcilerError> {
    // A damaged selected version cannot fall back to ordinary success. Other
    // existing receipt families keep their own decoders and byte semantics.
    if !receipt.as_bytes().starts_with(b"AOSLIF04") {
        return Ok(None);
    }
    let LifecycleEffectReceiptDataV1::StopResidual(residual) =
        decode_lifecycle_effect_receipt_v1(receipt.as_bytes(), [0; 16])
            .map_err(ReconcilerError::from)?
    else {
        return Err(invalid());
    };
    if residual.operation_v4() != operation
        || plan.public_mutation_method() != Some(PublicOperationMethodV1::StopSandbox)
        || plan.authority().is_some()
    {
        return Err(invalid());
    }
    let context = plan.public_mutation_context().map_err(ReconcilerError::from)?
        .ok_or_else(invalid)?;
    if !matches!(context.validated_request().map_err(ReconcilerError::from)?,
        DormantSandboxRequestKindV1::Stop(_)) {
        return Err(invalid());
    }
    Ok(Some(residual))
}

fn invalid() -> ReconcilerError {
    ReconcilerError::CorruptLedger("invalid closed Stop residual relation")
}
