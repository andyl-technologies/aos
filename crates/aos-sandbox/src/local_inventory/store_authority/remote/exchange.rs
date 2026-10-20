//! Protected remote carrier exchange and capability update orchestration.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

use crate::local_inventory::carrier_authority::{
    ProtectedCoordinatorChannelOriginalV1, ProtectedCoordinatorRequestOriginalV1,
};
use aos_sandbox_coordinator_protocol::aos::sandbox::coordinator::v1 as coordinator_wire;
use aos_sandbox_coordinator_protocol::session_binding::CanonicalCoordinatorHandshakeV1;

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Authenticates exact canonical handshake DATA against fixed native trust.
    ///
    /// The same protected clock and key remain the sole issuer. Canonical DATA
    /// does not authenticate itself or supply its own trust policy/currentness.
    ///
    /// # Errors
    ///
    /// Returns the actual protected clock, signature, session or trust failure.
    pub fn authenticate_coordinator_channel_once_v1(
        &mut self,
        handshake: CanonicalCoordinatorHandshakeV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedCoordinatorChannelOriginalV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        ProtectedCoordinatorChannelOriginalV1::authenticate_handshake_v1(
            handshake,
            canonical_signature,
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
            current_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Borrows this actual owner and its exact fixed-trust channel for one turn.
    ///
    /// # Errors
    ///
    /// Returns the original native clock or channel/trust affinity failure.
    pub fn borrow_coordinator_channel_once_v1<'owner, 'channel>(
        &'owner mut self,
        channel: &'channel ProtectedCoordinatorChannelOriginalV1,
    ) -> Result<ProtectedCoordinatorChannelScopeV1<'owner, 'channel>, ProtectedMultiNodeUpdateErrorV1>
    {
        let current_unix_seconds = self.observe_current_time()?;
        channel.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        if !channel.session_v1().is_current_at(current_unix_seconds) {
            return Err(InvalidMultiNodeProtocol::SessionMismatch.into());
        }
        Ok(ProtectedCoordinatorChannelScopeV1 {
            owner: self,
            channel,
            current_unix_seconds,
        })
    }

    /// Consumes the singular channel into one actual native response turn.
    ///
    /// # Errors
    ///
    /// Returns the original native clock or channel/trust affinity failure.
    pub fn begin_coordinator_response_once_v1<'owner>(
        &'owner mut self,
        channel: ProtectedCoordinatorChannelOriginalV1,
    ) -> Result<ProtectedCoordinatorResponseScopeV1<'owner>, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        channel.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        Ok(ProtectedCoordinatorResponseScopeV1 {
            owner: self,
            channel,
            current_unix_seconds,
        })
    }

    /// Issues one transport session from an exact protected expected row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the row belongs to this
    /// owner and the exact canonical frame matches its protected context.
    pub fn issue_carrier_session(
        &mut self,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        frame: &CanonicalNodeFrameV1<'_>,
        authenticated_channel_binding: [u8; 32],
    ) -> Result<AuthenticatedNodeSessionV1, InvalidMultiNodeProtocol> {
        let verified_at_unix_seconds = self
            .observe_current_time()
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        if !self
            .store
            .backend
            .protects_record(&protected_expected.record)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        issue_session_from_protected_channel(
            &protected_expected.record,
            frame,
            authenticated_channel_binding,
            self.bootstrap.maximum_request_bytes,
            self.bootstrap.maximum_response_bytes,
            verified_at_unix_seconds,
        )
    }

    /// Builds an authenticated capability request without dispatching it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the session belongs to this
    /// fixed protected owner and remains current at the durable clock floor.
    pub fn prepare_capability_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::GetCapabilities,
            b"get-capabilities",
        )
    }

    pub(in crate::local_inventory::store_authority) fn prepare_outbound_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
        body: NodeRequestBodyV1,
        purpose: &[u8],
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        let current_unix_seconds = self
            .observe_current_time()
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        let context = self.store.backend.authenticated_context;
        if session.node() != context.node()
            || session.lineage() != context.lineage()
            || session.binding_digest() != context.carrier_binding_digest()
            || session.audience_digest() != context.audience_digest()
            || session.disclosure_domain_digest() != context.disclosure_domain_digest()
            || session.coordinator_epoch() != context.coordinator_epoch()
            || session.replay_fence() != context.replay_fence()
            || !session.is_current_at(current_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let operation = protected_outbound_operation(
            self.clock.config_digest,
            self.store.backend.protected_root_digest,
            context,
            current_unix_seconds,
            purpose,
        )?;
        let codec = CanonicalNodeSemanticCodecV1::new();
        let canonical_frame = CanonicalNodeFrameV1::encode_request(
            &body,
            session.version(),
            context.carrier_binding_digest(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            operation,
            self.bootstrap.maximum_request_bytes,
            &codec,
        )?;
        let frame =
            CanonicalNodeFrameV1::decode(&canonical_frame, self.bootstrap.maximum_request_bytes)?;
        let envelope = NodeRequestEnvelopeV1::from_canonical_frame(
            session,
            &frame,
            current_unix_seconds,
            &codec,
        )?;
        Ok(ProtectedOutboundNodeRequestV1 {
            envelope,
            canonical_frame,
        })
    }

    /// Decodes one response under the same protected expected identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for a protected-store mismatch,
    /// stale session, frame mismatch, request mismatch, or invalid body.
    pub fn authenticate_carrier_response(
        &mut self,
        session: AuthenticatedNodeSessionV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        request: &NodeRequestEnvelopeV1,
        frame: &CanonicalNodeFrameV1<'_>,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        let verified_at_unix_seconds = self
            .observe_current_time()
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        if !self
            .store
            .backend
            .protects_record(&protected_expected.record)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let grant = issue_response_from_protected_channel(
            session,
            &protected_expected.record,
            frame,
            verified_at_unix_seconds,
        )?;
        NodeResponseEnvelopeV1::from_authenticated_carrier(
            grant,
            request,
            frame,
            verified_at_unix_seconds,
            codec,
        )
    }

    /// Commits one advancing authenticated capability response.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response is
    /// current for this protected owner and advances the exact durable
    /// capability projection without boot, sequence, or carrier equivocation.
    pub fn commit_capability_update(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        let observation = response.validated_capabilities()?;
        let context = self.store.backend.authenticated_context;
        if !observation.is_current_at(verified_at_unix_seconds)
            || observation.audience_node() != context.node()
            || observation.audience_digest() != context.audience_digest()
            || observation.disclosure_domain_digest() != context.disclosure_domain_digest()
            || observation.carrier_binding_digest() != context.carrier_binding_digest()
            || observation.coordinator_epoch() != context.coordinator_epoch()
            || observation.replay_fence() != context.replay_fence()
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let state = CapabilityJournalStateV1::from_authenticated_observation(&observation)?;
        let reducers = replay_protected_store_semantics(
            &self.store.backend.history,
            self.store.backend.storage_domain_digest,
            self.store.backend.replay_fence,
            context,
        )?;
        let current = reducers
            .get(&MultiNodeJournalDomainV1::Capability)
            .and_then(MultiNodeJournalReducerV1::restored_projection)
            .and_then(|state| match state {
                MultiNodeReducerStateV1::Capability(state) => Some(state),
                _ => None,
            })
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if !current.admits_successor(&state) {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let (sequence, predecessor_digest) = self
            .store
            .backend
            .next_domain_boundary(MultiNodeJournalDomainV1::Capability)?;
        let payload = crate::local_inventory::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::Capability(state),
        )?;
        let payload_digest = payload.digest();
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Capability,
            response.request(),
            sequence,
            predecessor_digest,
            payload_digest,
            payload,
            JournalEffectStateV1::Committed,
            observation.evidence_binding_digest(),
        )?;
        self.store
            .commit_record_once(record, verified_at_unix_seconds)
            .map_err(Into::into)
    }

    /// Resolves only an exact ambiguous capability update by protected readback.
    #[must_use]
    pub fn resolve_capability_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Capability {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Issues placement evidence from the exact current authenticated update.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay and
    /// a fresh clock sample prove that `response` is the current capability
    /// projection. The returned value remains scheduling evidence only.
    #[cfg(feature = "multi-node")]
    pub fn issue_current_placement_candidate(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<PlacementCandidateV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let observation = response.validated_capabilities()?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Capability)? {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current.snapshot() != observation.snapshot()
            || current.evidence().canonical_frame_digest()
                != observation.canonical_observation_digest()
            || !observation.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        Ok(PlacementCandidateV1::from_authenticated_observation(
            observation,
        ))
    }

    pub(in crate::local_inventory::store_authority) fn validate_response_context(
        &self,
        response: &NodeResponseEnvelopeV1,
        verified_at_unix_seconds: u64,
    ) -> Result<(), ProtectedMultiNodeUpdateErrorV1> {
        let context = self.store.backend.authenticated_context;
        if response.authenticated_context() != context
            || response.node() != context.node()
            || !response.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch.into());
        }
        Ok(())
    }
}

pub(in crate::local_inventory::store_authority) fn protected_outbound_operation(
    config_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
    current_unix_seconds: u64,
    purpose: &[u8],
) -> Result<OperationId, InvalidMultiNodeProtocol> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-outbound-operation.v1\0")
        .chain_update(config_digest.as_bytes())
        .chain_update(protected_root_digest.as_bytes())
        .chain_update(protected_context_digest(context).as_bytes())
        .chain_update(current_unix_seconds.to_be_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    let mut operation = [0; 16];
    operation.copy_from_slice(&digest[..16]);
    if operation == [0; 16] {
        return Err(InvalidMultiNodeProtocol::Unspecified);
    }
    Ok(OperationId::from_bytes(operation))
}

/// Holds the genuine owner and channel borrows across one native transport turn.
///
/// Construction samples the actual protected clock and checks fixed trust.
/// Request sealing consumes this turn; response encoding keeps its actual
/// owner borrow resident until the Coordinator finishes the same operation.
pub struct ProtectedCoordinatorChannelScopeV1<'owner, 'channel> {
    owner: &'owner mut ProtectedMultiNodeAuthorityOwnerV1,
    channel: &'channel ProtectedCoordinatorChannelOriginalV1,
    current_unix_seconds: u64,
}

impl ProtectedCoordinatorChannelScopeV1<'_, '_> {
    /// Borrows immutable DATA from the actual native-authenticated session.
    #[must_use]
    pub fn session_v1(&self) -> &AuthenticatedNodeSessionV1 {
        self.channel.session_v1()
    }

    /// Projects the existing native session into canonical generated DATA.
    ///
    /// This is the same public wire content already carried by each generated
    /// exchange. It reveals no grant constructor, key or native authority.
    #[must_use]
    pub fn session_binding_data_v1(&self) -> coordinator_wire::AuthenticatedSessionBinding {
        self.channel.session_binding_data_v1()
    }

    /// Seals exact generated request bytes using the actual private parser.
    ///
    /// # Errors
    ///
    /// Returns the original canonical, session, limit or semantic refusal.
    pub fn seal_generated_request_once_v1(
        self,
        bytes: &[u8],
    ) -> Result<
        (
            coordinator_wire::CoordinatorNodeRequest,
            ProtectedCoordinatorRequestOriginalV1,
        ),
        InvalidMultiNodeProtocol,
    > {
        self.channel
            .seal_generated_request_v1(bytes, self.current_unix_seconds)
    }

    /// Authenticates exact inbound bytes with the same native key and clock.
    ///
    /// # Errors
    ///
    /// Returns the original signature, session, canonical or semantic refusal.
    pub fn accept_generated_request_once_v1(
        self,
        bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeRequestEnvelopeV1, InvalidMultiNodeProtocol> {
        self.channel.accept_request_with_protected_owner(
            bytes,
            canonical_signature,
            &self.owner.bootstrap.canonical_trust_policy,
            &self.owner.bootstrap.public_key,
            self.current_unix_seconds,
        )
    }

    /// Checks the exact current request/body relation before response growth.
    ///
    /// # Errors
    ///
    /// Returns the original session, request correlation or body refusal.
    pub fn require_response_body_v1(
        &self,
        request: &NodeRequestEnvelopeV1,
        body: &NodeResponseBodyV1,
    ) -> Result<(), InvalidMultiNodeProtocol> {
        self.channel
            .require_response_semantics_v1(request, body, self.current_unix_seconds)
    }
}

/// Retains the actual owner borrow and consumes one singular native channel.
///
/// The resulting response evidence can only be constructed by the original
/// private signature/session/parser grant chain, never by a DATA constructor.
pub struct ProtectedCoordinatorResponseScopeV1<'owner> {
    owner: &'owner mut ProtectedMultiNodeAuthorityOwnerV1,
    channel: ProtectedCoordinatorChannelOriginalV1,
    current_unix_seconds: u64,
}

impl ProtectedCoordinatorResponseScopeV1<'_> {
    /// Authenticates and consumes the exact original request/response exchange.
    ///
    /// # Errors
    ///
    /// Returns the original signature, size, correlation, canonical, semantic
    /// or private grant refusal while preserving its actual typed cause.
    pub fn accept_generated_response_once_v1(
        self,
        request: &ProtectedCoordinatorRequestOriginalV1,
        bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        self.channel.accept_response_with_protected_owner(
            request,
            bytes,
            canonical_signature,
            &self.owner.bootstrap.canonical_trust_policy,
            &self.owner.bootstrap.public_key,
            self.current_unix_seconds,
        )
    }
}
