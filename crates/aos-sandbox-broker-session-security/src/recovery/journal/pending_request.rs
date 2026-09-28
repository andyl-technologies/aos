//! Live custody of an exact nonterminal authenticated broker request.
//!
//! The token borrows the real protected journal writer, original signed request,
//! retained transcript, and pinned connection peer. It cannot be decoded from
//! stored bytes or constructed from a terminal receipt. Higher-level Mount
//! composition must independently join its original Controller authorization,
//! Mount reservation, Host worker, and kernel objects before granting content.

use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurablePhaseV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};

use super::{
    BrokerSessionSecurityError, ProtectedBrokerSessionJournalSnapshotV1,
    ProtectedBrokerSessionJournalV1, reopen_current, request_matches_head,
};

/// Holds only the authenticated pending-request writer cut, not effect authority.
#[must_use = "retain this writer cut through the associated pending dispatch"]
pub(crate) struct ProtectedPendingBrokerRequestCutV1<'owner> {
    journal: &'owner mut ProtectedBrokerSessionJournalV1,
    request: &'owner AuthenticatedBrokerMethodRequestV1,
    transcript: &'owner VerifiedBrokerSessionTranscriptV1,
    peer: &'owner ConnectionPeerIdentity,
    original: ProtectedBrokerSessionJournalSnapshotV1,
}

impl<'owner> ProtectedPendingBrokerRequestCutV1<'owner> {
    /// Captures currentness only from the concrete broker journal owner.
    pub(super) fn capture(
        journal: &'owner mut ProtectedBrokerSessionJournalV1,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        peer: &'owner ConnectionPeerIdentity,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if journal.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Self::capture_pending(journal, request, transcript, peer)
    }

    /// Borrows either original endpoint of the exact closed FUSE-3 intent.
    pub(super) fn capture_fuse_intent(
        journal: &'owner mut ProtectedBrokerSessionJournalV1,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        peer: &'owner ConnectionPeerIdentity,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::MountFuse
            || request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1
            || !transcript.negotiated_methods().contains(&request.method())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Self::capture_pending(journal, request, transcript, peer)
    }

    /// Borrows only the two original endpoints of pending Host method 49.
    pub(super) fn capture_host_worker_comparison(
        journal: &'owner mut ProtectedBrokerSessionJournalV1,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        peer: &'owner ConnectionPeerIdentity,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host
            || request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1
            || !transcript.negotiated_methods().contains(&request.method())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Self::capture_pending(journal, request, transcript, peer)
    }

    fn capture_pending(
        journal: &'owner mut ProtectedBrokerSessionJournalV1,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        peer: &'owner ConnectionPeerIdentity,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let original = current_pending_snapshot(journal, request, transcript, peer)?;
        Ok(Self {
            journal,
            request,
            transcript,
            peer,
            original,
        })
    }

    /// Replays the same protected head under the still-held writer and peer.
    ///
    /// Expiry denies new dispatch; it does not erase an uncertain request or
    /// release any Mount/Cache obligations retained by the surrounding flight.
    pub(crate) fn recheck(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let current =
            current_pending_snapshot(self.journal, self.request, self.transcript, self.peer)?;
        if current != self.original {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    /// Joins pending custody to the original peer's actual fixed Mount service.
    pub(crate) fn recheck_mount_worker_peer(
        &mut self,
        verifier: &aos_sandbox_host::peer::ControllerPeerVerifier,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.recheck()?;
        verifier
            .verify_mount_broker(self.peer)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.recheck()
    }

    /// Borrows the exact already-authenticated request for comparison only.
    pub(crate) const fn request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        self.request
    }

    /// Returns the held head's comparison commitment without exporting authority.
    pub(crate) const fn head_commitment(&self) -> [u8; 32] {
        self.original.current_head
    }
}

fn current_pending_snapshot(
    journal: &mut ProtectedBrokerSessionJournalV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    connection_peer: &ConnectionPeerIdentity,
) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
    crate::dormant_handshake::check_production_deadline(request.deadline_boottime_nanoseconds())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let endpoint = journal.endpoint.role();
    let direction = match endpoint {
        BrokerSessionDurableEndpointV1::Client => AuthenticatedBrokerRequestDirectionV1::ClientSend,
        BrokerSessionDurableEndpointV1::Broker => {
            AuthenticatedBrokerRequestDirectionV1::ServerReceive
        }
    };
    if request.direction() != direction {
        return Err(BrokerSessionSecurityError::Currentness);
    }

    let context = journal.current_context(transcript)?;
    let peer = journal.observe_peer(transcript, connection_peer)?;
    let (history, _, snapshot) = reopen_current(journal, transcript, &context, &peer)?;
    let head = history
        .head()
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    if head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || !request_matches_head(request, head, direction)
        || !peer.matches_request_for_endpoint(endpoint, request, &context)
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }

    // Full signed replay and the protected-state sandwich are not substitutes
    // for re-observing the actual peer execution after the filesystem reads.
    let after_peer = journal.observe_peer(transcript, connection_peer)?;
    if after_peer.binding(endpoint, transcript, &context)? != head.peer_binding() {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    journal.endpoint.revalidate()?;
    crate::dormant_handshake::check_production_deadline(request.deadline_boottime_nanoseconds())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    Ok(snapshot)
}
