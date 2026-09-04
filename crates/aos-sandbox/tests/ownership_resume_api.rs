//! Verifies that ownership-gated admission is reachable through the public API.

use aos_sandbox::{
    AuthorityPublicationDraftV1, EffectPlan, IdempotencyKey, OperationPlan, OwnershipClaimV1,
    ReconcilerError,
};
use aos_sandbox_core::OperationId;

#[test]
#[allow(clippy::type_complexity)]
fn downstream_code_can_name_the_safe_gated_constructor() {
    let constructor: fn(
        OperationId,
        IdempotencyKey,
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
        Vec<EffectPlan>,
        OwnershipClaimV1,
        AuthorityPublicationDraftV1,
    ) -> Result<OperationPlan, ReconcilerError> = OperationPlan::ownership_gated;

    let _ = constructor;
}
