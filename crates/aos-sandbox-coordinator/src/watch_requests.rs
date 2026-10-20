//! Owns bootstrap/resume/gap/compaction request selection for remote watch.
//!
//! Actual fixed bindings, protected replay, authenticated gap custody and the
//! native outbound session issuer remain genuine local loans. This module adds
//! no service registration, stream, listener, retry or worker.

use aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1;
use aos_sandbox::local_inventory::protocol::AuthenticatedNodeSessionV1;
use aos_sandbox::local_inventory::remote::{
    ProtectedMultiNodeUpdateErrorV1, ProtectedOutboundNodeRequestV1, ProtectedWatchResyncRequiredV1,
};
use aos_sandbox_core::{
    InvalidMultiNodeProtocol, MAX_WATCH_EVENTS, NodeRequestBodyV1, NodeWatchBindingV1,
};

/// Selects a complete-inventory request using the native fixed watch binding.
///
/// # Errors
///
/// Preserves the original native binding, session and outbound issuer refusal.
pub fn prepare_watch_bootstrap_request(
    owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
    session: &AuthenticatedNodeSessionV1,
) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
    let scope = owner.begin_watch_bootstrap_request_once_v1(session)?;
    let body = NodeRequestBodyV1::RelistAssignments {
        binding: scope.binding_v1(),
    };
    scope.prepare_once_v1(body)
}

/// Selects the existing next bounded batch after actual current watch replay.
///
/// # Errors
///
/// Preserves the original replay, session-binding, event-bound and native refusal.
pub fn prepare_watch_resume_request(
    owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
    session: &AuthenticatedNodeSessionV1,
) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
    let scope = owner.begin_watch_resume_request_once_v1(session)?;
    let maximum_events = u16::try_from(MAX_WATCH_EVENTS)
        .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
    let after = scope
        .cursor_v1()
        .ok_or(InvalidMultiNodeProtocol::WatchBindingMismatch)?;
    scope
        .prepare_once_v1(NodeRequestBodyV1::Watch {
            after,
            maximum_events,
        })
        .map_err(Into::into)
}

/// Selects the old same-policy relist with the actual current cursor as its floor.
///
/// # Errors
///
/// Preserves the original replay, binding, floor-constructor and native refusal.
pub fn prepare_watch_compaction_resync_request(
    owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
    session: &AuthenticatedNodeSessionV1,
) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
    let scope = owner.begin_watch_compaction_request_once_v1(session)?;
    let binding = scope.binding_v1();
    let current = scope
        .cursor_v1()
        .ok_or(InvalidMultiNodeProtocol::WatchBindingMismatch)?;
    let next = NodeWatchBindingV1::new(
        binding.coordinator_epoch(),
        current.event_sequence(),
        current.last_event_uid(),
        current.event_sequence(),
        binding.query_digest(),
        binding.authorization_digest(),
        binding.audience_digest(),
        binding.disclosure_domain_digest(),
        binding.schema(),
    )?;
    scope
        .prepare_once_v1(NodeRequestBodyV1::RelistAssignments { binding: next })
        .map_err(Into::into)
}

/// Consumes the actual carrier-authenticated gap into its exact relist request.
///
/// # Errors
///
/// Preserves the original gap/session-binding and native outbound refusal.
pub fn prepare_watch_resync_request(
    owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
    session: &AuthenticatedNodeSessionV1,
    resync: ProtectedWatchResyncRequiredV1,
) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
    let scope = owner.begin_watch_resync_request_once_v1(session, resync)?;
    let body = NodeRequestBodyV1::RelistAssignments {
        binding: scope.binding_v1(),
    };
    scope.prepare_once_v1(body)
}
