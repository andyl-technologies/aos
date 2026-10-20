//! Owns existing drain reconciliation request assembly for the Coordinator.
//!
//! Actual native drain admission, Guardian/evidence verification, currentness,
//! durable write/recovery and effect factories remain with the local owner.

use aos_sandbox_controller_domain::local_inventory::ProtectedMultiNodeAuthorityOwnerV1;
use aos_sandbox_controller_domain::local_inventory::protocol::AuthenticatedNodeSessionV1;
use aos_sandbox_controller_domain::local_inventory::remote::{
    ProtectedMultiNodeUpdateErrorV1, ProtectedOutboundNodeRequestV1,
};
use aos_sandbox_model::NodeRequestBodyV1;

/// Assembles the current drain request over its actual native readback loan.
///
/// # Errors
///
/// Preserves the original missing-state, replay, session and native issuer cause.
pub fn prepare_current_drain_request(
    owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
    session: &AuthenticatedNodeSessionV1,
) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
    let scope = owner.begin_drain_request_once_v1()?;
    let body = NodeRequestBodyV1::ReconcileDrain(Box::new(scope.directive_v1().clone()));
    scope.prepare_once_v1(session, body)
}
