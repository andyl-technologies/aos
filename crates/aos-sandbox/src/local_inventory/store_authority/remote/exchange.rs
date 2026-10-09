//! Protected remote carrier exchange and capability update orchestration.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Authenticates a dormant transport against fixed protected trust state.
    ///
    /// The caller supplies only the peer's detached signature. The trust policy,
    /// pinned key, and current time are loaded and observed by this owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when protected time, trust
    /// state, the signature, or the exact handshake binding fails closed.
    #[cfg(feature = "multi-node")]
    pub fn authenticate_dormant_transport(
        &mut self,
        handshake: DormantTransportHandshakeV1,
        canonical_signature: &[u8],
    ) -> Result<DormantAuthenticatedCoordinatorNodeTransportV1, ProtectedMultiNodeUpdateErrorV1>
    {
        let current_unix_seconds = self.observe_current_time()?;
        handshake
            .authenticate_with_protected_owner(
                canonical_signature,
                &self.bootstrap.canonical_trust_policy,
                &self.bootstrap.public_key,
                current_unix_seconds,
            )
            .map_err(Into::into)
    }

    /// Prepares a current generated request under protected time.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when protected time or the
    /// authenticated session/request semantics are invalid.
    #[cfg(feature = "multi-node")]
    pub fn prepare_dormant_exchange(
        &mut self,
        transport: &DormantAuthenticatedCoordinatorNodeTransportV1,
        request: OperationId,
        body: &NodeRequestBodyV1,
    ) -> Result<DormantOutboundExchangeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .prepare_exchange_at_protected_time(request, body, current_unix_seconds)
            .map_err(Into::into)
    }

    /// Authenticates one inbound request with protected trust and time.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the exact request is
    /// signed by the fixed pin and current under the protected clock.
    #[cfg(feature = "multi-node")]
    pub fn accept_dormant_request(
        &mut self,
        transport: &DormantAuthenticatedCoordinatorNodeTransportV1,
        request_bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeRequestEnvelopeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .accept_request_with_protected_owner(
                request_bytes,
                canonical_signature,
                &self.bootstrap.canonical_trust_policy,
                &self.bootstrap.public_key,
                current_unix_seconds,
            )
            .map_err(Into::into)
    }

    /// Prepares a typed response under protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when the request is stale or
    /// the response is not its exact typed answer.
    #[cfg(feature = "multi-node")]
    pub fn prepare_dormant_response(
        &mut self,
        transport: &DormantAuthenticatedCoordinatorNodeTransportV1,
        request: &NodeRequestEnvelopeV1,
        body: &NodeResponseBodyV1,
    ) -> Result<DormantOutboundResponseV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .prepare_response_at_protected_time(request, body, current_unix_seconds)
            .map_err(Into::into)
    }

    /// Authenticates one exact response using only protected trust and time.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the fixed pin signed
    /// the canonical response and it exactly answers the retained request.
    #[cfg(feature = "multi-node")]
    pub fn accept_dormant_response(
        &mut self,
        transport: DormantAuthenticatedCoordinatorNodeTransportV1,
        request: &DormantOutboundExchangeV1,
        response_bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeResponseEnvelopeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .accept_response_with_protected_owner(
                request,
                response_bytes,
                canonical_signature,
                &self.bootstrap.canonical_trust_policy,
                &self.bootstrap.public_key,
                current_unix_seconds,
            )
            .map_err(Into::into)
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
