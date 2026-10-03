//! Authenticated HostState join for one completed method-39 no-Apply handoff.
//!
//! The protected runtime marker is checked separately by its journal owner.
//! This module binds that marker to HostState's authenticated original source,
//! terminal grant, exact completed response, and sealed handoff record.

use aos_proto::aos::sandbox::local::v1::TerminalHostExecutionArgumentNoApplyResponseV1;
use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_broker::BrokerEffectStatusV1;
use aos_sandbox_core::{BrokerAssignment, BrokerVerb, ObjectDigest};
use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV1;
use aos_sandbox_protocol::semantics::host_execution_argument_no_apply_grant_v1;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{DurableExecution, HostAction, HostState};
use crate::authorization::HostAuthorityV1;
use crate::{HostError, Result};

const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.host.execution-reservation-receipt.v1\0";

/// Hashes one exact Host execution response for durable reservation completion.
pub(crate) fn host_execution_receipt_digest(request_id: [u8; 16], outcome: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(RECEIPT_DOMAIN)
        .chain_update(request_id)
        .chain_update((outcome.len() as u64).to_be_bytes())
        .chain_update(outcome)
        .finalize()
        .into()
}

impl HostState {
    /// Finds any retained terminal handoff for this Create, including a pending one.
    ///
    /// The caller must authenticate this HostState snapshot first. A foreign
    /// source commitment still blocks treating the Create as absent.
    pub(crate) fn has_terminal_no_apply_handoff_for_create(
        &self,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
    ) -> bool {
        self.requests.values().any(|request| {
            request.action == HostAction::TerminalNoApply.code()
                && matches!(
                    &request.execution,
                    DurableExecution::HostExecutionHandoff(handoff)
                        if handoff.operation_id == operation_id
                            && handoff.execution_id == execution_id
                )
        })
    }

    /// Rejoins a protected no-Apply marker to the exact completed signed Host grant.
    ///
    /// # Errors
    ///
    /// Rejects a stale, incomplete, foreign, or unauthenticated HostState
    /// request, or a marker whose canonical response differs from its receipt.
    pub(crate) fn completed_no_apply_handoff_digest(
        &self,
        authority: &HostAuthorityV1,
        source: &ControllerExecutionArgumentAttemptV1,
        marker: HostExecutionNoApplyRecordV1,
        assignment: BrokerAssignment,
        runtime_handle: ObjectDigest,
    ) -> Result<ObjectDigest> {
        self.validate_authenticated(authority)?;
        let fields = marker.fields();
        let request = self
            .requests
            .get(&fields.terminal_request_id)
            .ok_or(HostError::Fence("Host terminal no-Apply handoff is absent"))?;
        let DurableExecution::HostExecutionHandoff(handoff) = &request.execution else {
            return Err(HostError::Fence(
                "Host terminal no-Apply handoff is invalid",
            ));
        };
        let receipt = request.receipt.as_deref().ok_or(HostError::Fence(
            "Host terminal no-Apply outcome is pending",
        ))?;
        let semantics = host_execution_argument_no_apply_grant_v1(
            assignment,
            fields.terminal_request_id,
            &source.canonical_bytes(),
            fields.original_session_binding,
            fields.original_signed_request_digest,
        )
        .map_err(|_| HostError::Fence("Host terminal no-Apply semantics changed"))?;
        let effect = authority.open_effect(&fields.terminal_request_id, &request.effect)?;
        if request.action != HostAction::TerminalNoApply.code()
            || effect.verb() != BrokerVerb::HostTerminalNoApply
            || effect.status() != BrokerEffectStatusV1::Complete
            || effect.request_digest() != semantics.commitment().digest()
            || handoff.semantic_commitment != *semantics.commitment().digest().as_bytes()
            || handoff.source_commitment != *source.record_digest().as_bytes()
            || handoff.operation_id != *source.create_operation().as_bytes()
            || handoff.execution_id != *source.execution().as_bytes()
            || handoff.runtime_handle != *runtime_handle.as_bytes()
            || handoff.session_binding != fields.terminal_session_binding
            || handoff.signed_request_digest != fields.terminal_signed_request_digest
            || fields.original_request_id != source.request_id()
            || fields.create_operation_id != *source.create_operation().as_bytes()
            || fields.execution_id != *source.execution().as_bytes()
            || fields.source_record_digest != *source.record_digest().as_bytes()
            || fields.assignment_digest != *source.assignment_digest().as_bytes()
            || fields.host_boot_id != source.host_boot_id()
            || fields.runtime_handle != *runtime_handle.as_bytes()
        {
            return Err(HostError::Fence("Host terminal no-Apply identity changed"));
        }

        let response = TerminalHostExecutionArgumentNoApplyResponseV1 {
            canonical_record: marker.encode_canonical().to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let expected_receipt = host_execution_receipt_digest(fields.terminal_request_id, &response);
        if receipt != expected_receipt.as_slice() {
            return Err(HostError::Fence("Host terminal no-Apply receipt changed"));
        }

        let authenticated = authority.open_execution_record(
            &fields.terminal_request_id,
            &request.execution_authentication,
        )?;
        let digest: [u8; 32] = authenticated
            .try_into()
            .map_err(|_| HostError::Fence("Host terminal no-Apply handoff is malformed"))?;
        if digest == [0; 32] {
            return Err(HostError::Fence("Host terminal no-Apply handoff is zero"));
        }
        Ok(ObjectDigest::from_bytes(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::host_execution_receipt_digest;

    #[test]
    fn completion_receipt_binds_request_and_exact_response_bytes() {
        let digest = host_execution_receipt_digest([1; 16], &[2, 3]);
        assert_ne!(digest, host_execution_receipt_digest([4; 16], &[2, 3]));
        assert_ne!(digest, host_execution_receipt_digest([1; 16], &[2, 3, 0]));
        assert_ne!(digest, host_execution_receipt_digest([1; 16], &[3, 2]));
    }
}
