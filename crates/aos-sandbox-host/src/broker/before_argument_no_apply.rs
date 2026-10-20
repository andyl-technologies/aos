//! Joins the explicit early branch to the same Host grant admission engine.
//!
//! This module supplies only the exact request/semantic tuple. Its parent
//! performs the existing durable HostState handoff, fence admission and final
//! effect check. The actual paid preadmission Host original must remain held;
//! this module supplies no substitute native opener or receiving fallback.

use super::*;
use aos_sandbox_core::ExecutionId;
use aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2;
use aos_sandbox_protocol::semantics::host_execution_argument::{
    host_before_argument_no_apply_grant_v2, host_before_argument_no_apply_query_grant_v2,
};

pub(super) type BeforeArgumentGrantTupleV2 = (
    aos_sandbox_protocol::ValidatedHeader,
    [u8; 16],
    ExecutionId,
    ObjectDigest,
    HostExactGrantSemanticsV1,
    HostAction,
    HostExecutionGrantRequestV1,
);

pub(super) fn prepare_before_argument_no_apply_v2(
    authenticated: &AuthenticatedBrokerMethodRequestV1,
    assignment: BrokerAssignment,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    protected_boot: [u8; 16],
) -> Result<BeforeArgumentGrantTupleV2> {
    let original = authenticated
        .host_before_argument_no_apply_data_v2()
        .ok_or(HostError::Fence("Host early no-Apply source is absent"))?;
    let source = original.source();
    let fields = source.fields();
    if fields.node
        != *claim
            .currentness()
            .runtime()
            .currentness()
            .node()
            .as_bytes()
        || (!original.is_query() && fields.host_boot != protected_boot)
        || original.exact_body() != authenticated.exact_body()
    {
        return Err(HostError::Fence(
            "Host early no-Apply current source differs",
        ));
    }

    let (semantics, action, request) = if !original.is_query()
        && authenticated.method() == BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
    {
        (
            host_before_argument_no_apply_grant_v2(assignment, authenticated.request_id(), source)
                .map_err(|_| HostError::Fence("Host early no-Apply grant differs"))?,
            HostAction::TerminalNoApply,
            HostExecutionGrantRequestV1::TerminalBeforeArgumentNoApply(original.clone()),
        )
    } else if original.is_query()
        && authenticated.method() == BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
    {
        (
            host_before_argument_no_apply_query_grant_v2(
                assignment,
                authenticated.request_id(),
                source,
            )
            .map_err(|_| HostError::Fence("Host early no-Apply query grant differs"))?,
            HostAction::QueryNoApply,
            HostExecutionGrantRequestV1::QueryBeforeArgumentNoApply(original.clone()),
        )
    } else {
        return Err(HostError::Fence("Host early no-Apply method differs"));
    };

    Ok((
        *original.header(),
        fields.create_operation,
        ExecutionId::from_bytes(fields.execution),
        source.digest(),
        HostExactGrantSemanticsV1::Argument(semantics),
        action,
        request,
    ))
}

impl HostExecutionGrantReservationV1 {
    /// Appends the early closure only after this exact HostState grant admitted.
    ///
    /// The actual caller retains its paid Host native interval and completes
    /// this SAME sealed HostState handoff with the exact response before any
    /// signed outcome escapes. No generic native-owner open is performed here.
    ///
    /// # Errors
    /// Rejects another branch/request/current runtime or uncertain append.
    pub fn commit_before_argument_no_apply_v2(
        &self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
    ) -> std::result::Result<
        ClosedBeforeArgumentNoApplyRecordV2,
        aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerErrorV1,
    > {
        if !matches!(
            self.request,
            HostExecutionGrantRequestV1::TerminalBeforeArgumentNoApply(_)
        ) || !self.matches(
            authenticated.method(),
            authenticated.request_id(),
            authenticated.exact_body(),
            claim,
        ) || self.session_binding != authenticated.session_binding()
            || self.signed_request_digest != authenticated.signed_request_digest()
        {
            return Err(aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        claim.commit_host_before_argument_no_apply_v2(authenticated, &self.intersection)
    }

    /// Reads historical early closure from this exact authenticated query grant.
    ///
    /// # Errors
    /// Rejects another branch/request/current runtime or unavailable history.
    pub fn query_before_argument_no_apply_v2(
        &self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
    ) -> std::result::Result<
        Option<ClosedBeforeArgumentNoApplyRecordV2>,
        aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerErrorV1,
    > {
        if !matches!(
            self.request,
            HostExecutionGrantRequestV1::QueryBeforeArgumentNoApply(_)
        ) || !self.matches(
            authenticated.method(),
            authenticated.request_id(),
            authenticated.exact_body(),
            claim,
        ) || self.session_binding != authenticated.session_binding()
            || self.signed_request_digest != authenticated.signed_request_digest()
        {
            return Err(aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        claim.query_host_before_argument_no_apply_v2(authenticated, &self.intersection)
    }
}
