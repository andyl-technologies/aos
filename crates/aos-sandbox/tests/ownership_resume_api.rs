//! Verifies that ownership-gated admission is reachable through the public API.

use aos_sandbox::{
    AuthorityPublicationDraftV1, IdempotencyKey, OperationPlan,  ReconcilerError,
};
use aos_sandbox_core::OperationId;
use aos_sandbox_protocol::publication::AuthorityBoundEffectPlanV1;

#[test]
#[allow(clippy::type_complexity)]
fn downstream_code_can_name_the_safe_gated_constructor() {
    let constructor: fn(
        OperationId,
        IdempotencyKey,
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
        Vec<AuthorityBoundEffectPlanV1>,
        OwnershipClaimV1,
        AuthorityPublicationDraftV1,
    ) -> Result<OperationPlan, ReconcilerError> = OperationPlan::ownership_gated;

    let _ = constructor;
}

use aos_sandbox_ownership_protocol::{OwnershipClaimV1};
