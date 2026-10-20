//! Rejoins an exact completed Host preparation under the existing State writer.
//!
//! State already authenticates each Host request and its completed outcome
//! digest. Accept matches that actual entry, the same Controller Session and
//! current Host/Agent coordinates before the sole Guest challenge engine runs.
//! No extra preparation journal, imported key or caller-selected owner exists.

use aos_sandbox_controller_domain::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_broker::BrokerEffectStatusV1;
use aos_sandbox_model::{BrokerAssignment, BrokerVerb, ObjectDigest};
use aos_sandbox_protocol::host_execution_argument::preparation::HostArgumentPreparationV2;
use aos_sandbox_protocol::semantics::host_execution_argument::host_execution_argument_prepare_grant_v2;

use super::no_apply_handoff::host_execution_receipt_digest;
use super::{DurableExecution, HostAction, HostState};
use crate::authorization::HostAuthorityV1;
use crate::{HostError, Result};

impl HostState {
    /// Reserves one preparation identity without treating a missing row as authority.
    pub(crate) fn has_other_argument_preparation_v2(
        &self,
        execution: aos_sandbox_model::ExecutionId,
        request_id: [u8; 16],
    ) -> bool {
        self.requests.values().any(|request| {
            request.request_id != request_id
                && matches!(request.action, 11 | 15 | 16)
                && matches!(
                    &request.execution,
                    DurableExecution::HostExecutionHandoff(handoff)
                        if handoff.execution_id == *execution.as_bytes()
                )
        })
    }

    /// Reports an existing Accept, including an ambiguous or failed attempt.
    pub(crate) fn has_other_argument_accept_v2(
        &self,
        execution: aos_sandbox_model::ExecutionId,
        request_id: [u8; 16],
    ) -> bool {
        self.requests.values().any(|request| {
            request.request_id != request_id
                && request.action == HostAction::AcceptExecutionArgumentV2.code()
                && matches!(
                    &request.execution,
                    DurableExecution::HostExecutionHandoff(handoff)
                        if handoff.execution_id == *execution.as_bytes()
                )
        })
    }

    /// Verifies the exact preparation against its actual authenticated State entry.
    ///
    /// This is called while the same HostBroker still owns its fixed State
    /// writer. The opaque reservation can proceed only after Agent/currentness
    /// validation compares these coordinates again at the Guest crossing.
    pub(crate) fn require_completed_argument_preparation_v2(
        &self,
        authority: &HostAuthorityV1,
        preparation: &HostArgumentPreparationV2,
        accepted_source: &ControllerExecutionArgumentAttemptV1,
        assignment: BrokerAssignment,
        controller_session: [u8; 32],
        agent_session: [u8; 32],
        runtime_handle: ObjectDigest,
        host_cut: ObjectDigest,
        host_effect_epoch: u64,
    ) -> Result<()> {
        self.validate_authenticated(authority)?;
        preparation.require_accept_source(&accepted_source.canonical_bytes())
            .map_err(|_| mismatch())?;
        if !preparation.matches_observed(
            &controller_session, &agent_session, runtime_handle.as_bytes(), host_cut.as_bytes(),
        ) || preparation.host_effect_epoch() != host_effect_epoch {
            return Err(mismatch());
        }
        let proposed = ControllerExecutionArgumentAttemptV1::decode_canonical(
            preparation.proposed_source(),
        ).map_err(|_| mismatch())?;
        let request_id = proposed.request_id();
        let request = self.requests.get(&request_id).ok_or_else(mismatch)?;
        let DurableExecution::HostExecutionHandoff(handoff) = &request.execution else {
            return Err(mismatch());
        };
        let semantics = host_execution_argument_prepare_grant_v2(
            assignment, request_id, preparation.proposed_source(),
        ).map_err(|_| mismatch())?;
        let effect = authority.open_effect(&request_id, &request.effect)?;
        if request.action != HostAction::PrepareExecutionArgumentV2.code()
            || effect.verb() != BrokerVerb::HostPrepareExecutionArgumentV2
            || effect.status() != BrokerEffectStatusV1::Complete
            || effect.request_digest() != semantics.commitment().digest()
            || handoff.semantic_commitment != *semantics.commitment().digest().as_bytes()
            || handoff.source_commitment != *proposed.record_digest().as_bytes()
            || handoff.operation_id != *proposed.create_operation().as_bytes()
            || handoff.execution_id != *proposed.execution().as_bytes()
            || handoff.runtime_handle != *runtime_handle.as_bytes()
            || handoff.session_binding != controller_session
            || handoff.signed_request_digest != preparation.signed_prepare_request()
        {
            return Err(mismatch());
        }

        // The completed native Host entry authenticates the response digest.
        // Caller-carried preparation bytes are accepted only by exact equality
        // with that digest, never merely by their structural checksum.
        let receipt = host_execution_receipt_digest(request_id, preparation.canonical_bytes());
        if request.receipt.as_deref() != Some(receipt.as_slice())
            || effect.receipt() != receipt.as_slice()
        {
            return Err(mismatch());
        }
        Ok(())
    }
}

fn mismatch() -> HostError {
    HostError::Fence("Host argument preparation is absent, changed or not complete")
}
