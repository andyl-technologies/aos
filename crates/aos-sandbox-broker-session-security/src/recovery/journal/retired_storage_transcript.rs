//! Shares pure exact Storage predecessor comparisons for both endpoint roles.
//!
//! Actual role-specific positive retirement constructors stay in their owning
//! modules. These fixed coordinates/checkpoint DATA cannot create a native
//! admission, live peer, payer, endpoint or completed transport disposition.

use super::*;
use aos_sandbox_broker_session_protocol::{BrokerSessionPeerBindingV1, BrokerSessionProtectedBindingsV1};

/// Retains a consume-only predecessor on the same protected Journal owner.
///
/// The actual Journal retains the complete immutable signed history. This
/// private value holds only the original checkpoint and terminal coordinates;
/// it never owns another request, outcome or traffic-state copy. Only actual
/// positive Session transport disposal installs it. A historical row, decoded
/// digest or fresh HELLO cannot construct this predecessor.
pub(super) struct RetiredStorageTranscriptV1 {
    pub(super) endpoint: BrokerSessionDurableEndpointV1,
    pub(super) protected_generation: u64,
    pub(super) protected_head: [u8; 32],
    pub(super) protected_bindings: BrokerSessionProtectedBindingsV1,
    pub(super) peer_binding: BrokerSessionPeerBindingV1,
    pub(super) session_binding: [u8; 32],
    pub(super) checkpoint: HistoricalSessionCheckpointV1,
    pub(super) first_request: Option<RetiredStorageFirstRequestV1>,
    pub(super) phase: RetiredStorageTranscriptPhaseV1,
}

pub(super) struct RetiredStorageFirstRequestV1 {
    pub(super) signed_digest: [u8; 32],
    pub(super) request_id: [u8; 16],
    pub(super) session_binding: [u8; 32],
    pub(super) client_sequence: u64,
}

impl RetiredStorageFirstRequestV1 {
    pub(super) fn matches(&self, request: &AuthenticatedBrokerMethodRequestV1) -> bool {
        self.signed_digest == request.signed_request_digest()
            && self.request_id == request.request_id()
            && self.session_binding == request.session_binding()
            && self.client_sequence == request.client_sequence()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RetiredStorageTranscriptPhaseV1 {
    Pending,
    Attempted,
    Consumed,
}

impl RetiredStorageTranscriptV1 {
    pub(super) fn require_exact_predecessor(
        &self,
        current: &StoredProtocolHistoryV1,
        history: &BrokerSessionDurableHistoryV1,
        next: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.checkpoint.context();
        let old = self.checkpoint.verify()?;
        if self.phase != RetiredStorageTranscriptPhaseV1::Pending
            || next.session_binding() == self.session_binding
            || old.session_binding() != self.session_binding
            || next.protocol() != BrokerSessionProtocolV1::Storage
            || old.protocol() != BrokerSessionProtocolV1::Storage
            || next.broker_process() != old.broker_process()
            || next.audience()
                != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || current.protocol != BrokerSessionProtocolV1::Storage
            || current.endpoint != self.endpoint
            || current.generation != self.protected_generation
            || current.current_head != self.protected_head
            || current.endpoint_publication != self.protected_bindings.endpoint_publication()
            || current.checkpoint.as_ref() != Some(&self.checkpoint)
            || current.protected_bindings(context)? != self.protected_bindings
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let head = history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if history.head_commitment() != self.protected_head
            || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.endpoint() != self.endpoint
            || head.session_binding() != self.session_binding
            || head.peer_binding() != self.peer_binding
            || head.protected_bindings() != self.protected_bindings
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        // Reuse the complete historical signature/linkage engine over the
        // SAME Journal's immutable bytes. The exact captured terminal head
        // preserves its already-validated domain semantics; no second domain
        // request/outcome model or disposed live peer is reconstructed here.
        // The caller pays checkpoint, row and canonical-envelope growth before
        // reading/decoding this history under its genuine operation original.
        let traffic = reconstruct_traffic(history, &old, context)?;
        if traffic.has_outstanding_request() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    pub(super) fn matches_completed_initialization(
        &self,
        recovery: &ProtectedBrokerSessionInitializationRecoveryV1,
    ) -> bool {
        self.phase == RetiredStorageTranscriptPhaseV1::Attempted
            && recovery.expected_generation == self.protected_generation
            && recovery.expected_head == self.protected_head
            && recovery.expected_publication == self.protected_bindings.endpoint_publication()
            && recovery.transcript.session_binding() != self.session_binding
            && recovery.target.protocol == BrokerSessionProtocolV1::Storage
            && recovery.target.endpoint == self.endpoint
            && recovery.target.generation.checked_sub(1) == Some(self.protected_generation)
    }
}
