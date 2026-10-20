//! Authenticated current-session transitions on the original protected journal.
//!
//! Initial and successor requests, terminal comparisons, outcome commit and exact
//! recovery use the resident journal, its floor/endpoint custody and peer checks.
//! The parent retains schema/storage operations and all fields; these inherent
//! recipes neither introduce a second owner nor detach the original loans.

use super::*;

impl ProtectedBrokerSessionJournalV1 {
    /// Installs the first request under exact absence or qualified terminal CAS.
    ///
    /// A method-specific current-catalog binding is retained when the signed
    /// request carries one. Other valid first methods use their nonzero signed
    /// semantic commitment as a type-separated placeholder. A publication's
    /// successor catalog is installed only with its successful terminal result.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation for a wrong endpoint, stale peer,
    /// mismatched transcript, invalid semantic binding, an unqualified current-
    /// process history, or a nonterminal old-process head. Terminal history may
    /// be replaced only by a new signed initial request under the exact monotone
    /// predecessor CAS. Same-process replacement additionally requires this
    /// actual owner's private positively retired transcript predecessor. Native
    /// or readback failure retains the whole exact target for recovery.
    pub fn initialize_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        checkpoint: &HistoricalSessionCheckpointV1,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        self.initialize_request_with_storage_receiving_v2(request, transcript, connection_peer, checkpoint, None)
    }

    pub(super) fn initialize_request_with_storage_receiving_v2(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1, transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity, checkpoint: &HistoricalSessionCheckpointV1,
        mut receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        self.require_retired_storage_initial_request_v1(request)?;
        self.require_floor_method_with_storage_receiving_v2(request.method(), receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;
        let context = self.current_context_with_storage_receiving_v2(transcript, None, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?.into_ordinary();
        let peer = self.observe_peer_with_storage_receiving_v3(transcript, connection_peer, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        if super::super::endpoint_for_request(request) != self.endpoint.role() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let before = self.read_optional_with_storage_receiving_v2(transcript.protocol(), receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;
        if before.is_none()
            && request.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let current_catalog = request
            .catalog_binding()
            .unwrap_or_else(|| request.semantic_commitment());
        if current_catalog.iter().all(|byte| *byte == 0) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let endpoint_publication = self.endpoint_publication(transcript.protocol())?;
        let stable_endpoint_identity = self.stable_endpoint_identity(transcript.protocol())?;
        let (expected_generation, expected_head, expected_publication) = match before.as_ref() {
            None => (0, [0; 32], [0; 32]),
            Some(current) => {
                let history = current.history_model()?;
                let head = history
                    .head()
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                if current.stable_endpoint_identity != stable_endpoint_identity {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                if current.endpoint_publication == endpoint_publication {
                    if !self.require_retired_storage_rollover_v1(current, &history, transcript)? {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    // Consume this actual private predecessor before any archive,
                    // target preparation or CAS effect. Failure never rearms it.
                    self.mark_retired_storage_rollover_attempted_v1();
                }
                if request.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
                    let coordinates =
                        RecoverStorageInventoryRequestV1::decode_from_slice(request.exact_body())
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let group_id: [u8; 16] = coordinates
                        .group_request_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let group_digest: [u8; 32] = coordinates
                        .group_request_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let inventory_id: [u8; 16] = coordinates
                        .inventory_request_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let inventory_digest: [u8; 32] = coordinates
                        .inventory_request_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let client_head: [u8; 32] = coordinates
                        .client_original_head
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let archived = if head.method()
                        == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                    {
                        self.archive_original_storage_inventory(
                            group_id,
                            group_digest,
                            inventory_id,
                            inventory_digest,
                        )?
                    } else if head.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
                    {
                        // A recovery control request has no physical effect. It may be
                        // retried across a crash, but only for the exact old status.
                        let records = history.records();
                        if records.len() > 2
                            || records.first().is_none_or(|first| {
                                first.method()
                                    != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
                                    || first.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
                            })
                        {
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                        let first = records
                            .first()
                            .ok_or(BrokerSessionSecurityError::Currentness)?;
                        let original = decode_canonical_request_v1(first.request_packet())
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        let previous = RecoverStorageInventoryRequestV1::decode_from_slice(
                            &original.message().body,
                        )
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        if previous.group_request_id != coordinates.group_request_id
                            || previous.group_request_digest != coordinates.group_request_digest
                            || previous.inventory_request_id != coordinates.inventory_request_id
                            || previous.inventory_request_digest
                                != coordinates.inventory_request_digest
                            || previous.client_original_head != coordinates.client_original_head
                        {
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                        self.archived_storage_inventory_head(
                            group_id,
                            group_digest,
                            inventory_id,
                            inventory_digest,
                        )?
                    } else {
                        return Err(BrokerSessionSecurityError::Currentness);
                    };
                    if self.endpoint.role() == BrokerSessionDurableEndpointV1::Client
                        && client_head != archived.original_head
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    if (head.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                        && archived.original_head != current.current_head)
                        || self.read_optional_with_storage_receiving_v2(BrokerSessionProtocolV1::Storage, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))? != before
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                } else {
                    if head.phase() != BrokerSessionDurablePhaseV1::Terminal {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    if request.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                        && head.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                    {
                        match self.endpoint.role() {
                            BrokerSessionDurableEndpointV1::Broker => {
                                self.archive_terminal_storage_group_for_status(current)?;
                            }
                            BrokerSessionDurableEndpointV1::Client => {
                                if self.read_atomic_storage_archive(head.request_id())?
                                    != Some(current.clone())
                                {
                                    return Err(BrokerSessionSecurityError::Currentness);
                                }
                            }
                        }
                    }
                    if let Some(first) = history.records().first() {
                        if first.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
                            self.require_storage_inventory_abandonment_successor(
                                &history,
                                request.method(),
                            )?;
                        }
                    }
                }
                (
                    current.generation,
                    current.current_head,
                    current.endpoint_publication,
                )
            }
        };
        let empty = ProtectedBrokerSessionJournalSnapshotV1::new(
            expected_generation,
            endpoint_publication,
            current_catalog,
            [0; 32],
            None,
        )?;
        let write = ProtectedBrokerRequestWriteV1::prepare_initial_from_snapshot(
            request, &context, transcript, &peer, &empty,
        )?;
        let target = StoredProtocolHistoryV1::from_request_write_for_purpose_v2(
            self.purpose,
            transcript.protocol(),
            self.endpoint.role(),
            stable_endpoint_identity,
            endpoint_publication,
            current_catalog,
            write,
            Some(checkpoint.clone()),
        )?;
        let recovery = ProtectedBrokerSessionInitializationRecoveryV1 {
            expected_generation,
            expected_head,
            expected_publication,
            target,
            transcript: transcript.clone(),
        };
        Ok(self.install_initial_with_storage_receiving_v2(recovery, connection_peer, receiving))
    }

    /// Reopens the exact protected broker-side outcome gate.
    ///
    /// # Errors
    ///
    /// Returns an error unless full canonical replay, endpoint custody, peer
    /// identity, catalog binding, transcript, request, and current head agree.
    pub fn reopen_broker_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<super::super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError>
    {
        self.reopen_broker_outcome_with_storage_receiving_v3(request, transcript, connection_peer, None)
    }

    pub(super) fn reopen_broker_outcome_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<super::super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError> {
        self.require_floor_method_with_storage_receiving_v2(request.method(), receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;

        let context = self.current_context_with_storage_receiving_v2(transcript, None, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?.into_ordinary();
        let peer = self.observe_peer_with_storage_receiving_v3(transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        let recovery = ProtectedBrokerOutcomeGateRecoveryV1::reopen_broker_outcome_with_storage_receiving_v3(
            self, request, transcript, &context, &peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2),
        )?;
        let after_peer = self.observe_peer_with_storage_receiving_v3(transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        if recovery.gate.currentness.peer_binding
            != after_peer.binding(self.endpoint.role(), transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(recovery.into_gate())
    }

    /// Revalidates one exact protected terminal broker outcome for immediate use.
    ///
    /// The returned token holds this journal's unique mutable borrow, preventing
    /// another in-process recovery or advancement from superseding the checked
    /// head during the associated effect-authority handoff.
    ///
    /// # Errors
    ///
    /// Returns an error unless endpoint custody, peer identity, transcript,
    /// protected bindings, generation, head, request, and outcome packet still
    /// match the authority captured by protected admission.
    pub fn revalidate_broker_outcome<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>, BrokerSessionSecurityError> {
        self.validate_broker_outcome(&owner, connection_peer)?;
        Ok(ProtectedBrokerOutcomeCurrentV1 {
            authority: self,
            connection_peer,
            owner,
        })
    }

    /// Retains the original execution owner on every failed terminal check.
    ///
    /// The successful value is the existing sole-journal loan, not a new
    /// authority class. Only the original Controller Host client can enter;
    /// the same complete validator checks its protected floor and terminal.
    ///
    /// # Errors
    ///
    /// Returns the original owner and actual error for another endpoint or
    /// method, or any failed protected terminal and live-peer validation.
    pub(crate) fn retain_execution_outcome_current<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeCurrentV1<'authority>,
        (
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
            BrokerSessionSecurityError,
        ),
    > {
        self.retain_execution_outcome_current_inner_v1(owner, connection_peer, None)
    }

    pub(crate) fn retain_execution_outcome_current_with_post_v1<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
        post: &mut super::client_session_continuation::ExecutionClientPostOriginalV1,
        socket: std::os::fd::RawFd,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>,
        (ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError)>
    {
        self.retain_execution_outcome_current_inner_v1(owner, connection_peer, Some((post, socket)))
    }

    pub(crate) fn retain_execution_outcome_current_inner_v1<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
        post: Option<(&mut super::client_session_continuation::ExecutionClientPostOriginalV1, std::os::fd::RawFd)>,
    ) -> Result<
        ProtectedBrokerOutcomeCurrentV1<'authority>,
        (
            ProtectedBrokerOutcomeCurrentnessOwnerV1,
            BrokerSessionSecurityError,
        ),
    > {
        let selected = match (owner.transcript.protocol(), owner.request.method()) {
            // This is read/currentness validation of the already authenticated
            // Runtime outcome. It neither admits nor dispatches its effect.
            (BrokerSessionProtocolV1::Host, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME) =>
                Some(ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient),
            (BrokerSessionProtocolV1::Host, BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
                | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2) =>
                    Some(ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient),
            (BrokerSessionProtocolV1::Storage,
                BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
                | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1) =>
                    Some(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient),
            _ => None,
        };
        let checked = match selected {
            Some(selected) if self.directory == Path::new(fixed_endpoint(selected).journal_root)
                && self.endpoint.role() == BrokerSessionDurableEndpointV1::Client
                && owner.request.direction() == AuthenticatedBrokerRequestDirectionV1::ClientSend =>
                    match post {
                        Some((post, socket)) => post.cover_terminal_once_v1(self, &owner.transcript, socket)
                            .and_then(|()| post.observe_terminal_before_v1(self, &owner, connection_peer)),
                        None => self.validate_broker_outcome(&owner, connection_peer),
                    },
            _ => Err(BrokerSessionSecurityError::Currentness),
        };
        if let Err(error) = checked {
            return Err((owner, error));
        }
        Ok(ProtectedBrokerOutcomeCurrentV1 {
            authority: self,
            connection_peer,
            owner,
        })
    }

    /// Compares only the original Controller Storage Inventory terminal.
    pub(crate) fn compare_atomic_snapshot_predecessor_v3(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_storage_inventory_predecessor_v1(owner)?;
        self.validate_broker_outcome(owner, connection_peer)
    }

    pub(super) fn require_storage_inventory_predecessor_v1(
        &self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let endpoint =
            fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if self.directory != Path::new(endpoint.journal_root)
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience() != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || owner.request.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        Ok(())
    }

    /// Compares only the original Storage-client Host48 terminal under its held owner.
    pub(crate) fn compare_host_storage_output_outcome_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let endpoint = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostClient);
        if self.directory != Path::new(endpoint.journal_root)
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Host
            || owner.transcript.audience() != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_STORAGE_BROKER
            || owner.request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            || owner.request.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_broker_outcome(owner, connection_peer)
    }

    pub(crate) fn compare_original_storage_output_outcome_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let endpoint =
            fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if self.directory != Path::new(endpoint.journal_root)
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience()
                != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || owner.request.method()
                != BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_broker_outcome(owner, connection_peer)
    }

    pub(super) fn compare_original_capture_candidate_outcome(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if self.directory != Path::new(fixed.journal_root)
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience() != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || owner.request.method() != BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.method() != owner.request.method()
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || !owner.transcript.negotiated_methods().contains(&owner.request.method())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_broker_outcome(owner, peer)
    }

    /// Compares the actual Storage-server terminal, not a copied readback permit.
    pub(crate) fn compare_storage_output_server_terminal_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let endpoint = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        if self.directory != Path::new(endpoint.journal_root)
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience()
                != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || !matches!(
                owner.request.method(),
                BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
            )
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_broker_outcome(owner, connection_peer)
    }

    pub(super) fn revalidate_broker_replay(
        &mut self,
        replay: ProtectedBrokerOutcomeReplayV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeReplayV1,
        (BrokerSessionSecurityError, ProtectedBrokerOutcomeReplayV1),
    > {
        match self.validate_broker_outcome(&replay.currentness_owner, connection_peer) {
            Ok(()) => Ok(replay),
            Err(error) => Err((error, replay)),
        }
    }

    pub(super) fn revalidate_broker_committed(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeCommittedAdvancementV1,
        (
            BrokerSessionSecurityError,
            ProtectedBrokerOutcomeCommittedAdvancementV1,
        ),
    > {
        match self.validate_broker_outcome(&committed.currentness_owner, connection_peer) {
            Ok(()) => Ok(committed),
            Err(error) => Err((error, committed)),
        }
    }

    pub(in crate::recovery) fn validate_broker_outcome(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.validate_broker_outcome_with_originals(owner, connection_peer, None)
    }

    // The signed original terminal or two durable abandonment markers must
    // settle the old request before another inventory can be sent.
    fn require_storage_inventory_abandonment_successor(
        &mut self,
        history: &BrokerSessionDurableHistoryV1,
        method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        let records = history.records();
        let first = records
            .first()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if method != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || records.len() != 2
            || first.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || first.method() != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            || records[1].phase() != BrokerSessionDurablePhaseV1::Terminal
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let canonical = decode_canonical_request_v1(first.request_packet())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let coordinates =
            RecoverStorageInventoryRequestV1::decode_from_slice(&canonical.message().body)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let inventory_id: [u8; 16] = coordinates
            .inventory_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let group_id: [u8; 16] = coordinates
            .group_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let group_digest: [u8; 32] = coordinates
            .group_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let inventory_digest: [u8; 32] = coordinates
            .inventory_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let client_head: [u8; 32] = coordinates
            .client_original_head
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let stored = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let verified_history = stored.history_model()?;
        if verified_history != *history {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        reconstruct_traffic(&verified_history, &transcript, checkpoint.context())?;
        let response = decode_canonical_response_v1(
            records[1]
                .outcome_packet()
                .ok_or(BrokerSessionSecurityError::Currentness)?,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if response.message().error.as_option().is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let decision = decode_storage_inventory_recovery_response_v1(
            &response.message().body,
            first.maximum_response_bytes(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if let ValidatedStorageInventoryRecoveryResponseV1::OriginalTerminal {
            packet,
            broker_head,
            archive_digest,
        } = decision
        {
            let archived = self.archived_storage_inventory_head(
                group_id,
                group_digest,
                inventory_id,
                inventory_digest,
            )?;
            if archived.original_head != client_head
                && self.endpoint.role() == BrokerSessionDurableEndpointV1::Client
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            match self.endpoint.role() {
                BrokerSessionDurableEndpointV1::Broker
                    if archived.terminal_packet.as_deref() == Some(packet.as_slice())
                        && archived.original_head == broker_head
                        && archived.archive_digest == archive_digest
                        && decode_canonical_response_v1(&packet)
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?
                            .message()
                            .error
                            .as_option()
                            .is_none() => {}
                BrokerSessionDurableEndpointV1::Client => {
                    self.verify_original_storage_inventory_terminal(
                        group_id,
                        group_digest,
                        inventory_id,
                        inventory_digest,
                        &packet,
                    )?;
                }
                _ => return Err(BrokerSessionSecurityError::Currentness),
            }
            return Ok(());
        }
        let marker = self.read_storage_inventory_abandonment(inventory_id)?;
        if !exact_storage_inventory_abandonment_marker(
            marker.as_ref(),
            self.endpoint.role(),
            group_id,
            group_digest,
            inventory_digest,
            client_head,
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_storage_inventory_abandonments()?;
        Ok(())
    }

    /// Appends one authenticated successor request after a terminal head.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation unless canonical full replay selects
    /// the exact terminal predecessor and the protected endpoint, peer,
    /// transcript, catalog, generation, head, and revision all remain current.
    pub fn append_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.append_request_with_storage_receiving_v3(request, transcript, connection_peer, None)
    }

    pub(super) fn append_request_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.require_floor_method_with_storage_receiving_v2(request.method(), receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;

        let context = self.current_context_with_storage_receiving_v2(transcript, None, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?.into_ordinary();
        let peer = self.observe_peer_with_storage_receiving_v3(transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        let write = ProtectedBrokerRequestWriteV1::prepare_successor_with_storage_receiving_v3(
            self, request, &context, transcript, &peer, receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2),
        )?;
        let current = self
            .read_optional_with_storage_receiving_v2(transcript.protocol(), receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = current.history_model()?;
        if history.records().first().is_some_and(|first| {
            first.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
        }) {
            self.require_storage_inventory_abandonment_successor(&history, request.method())?;
        }
        if current.generation != write.expected_generation()
            || current.current_head != write.expected_head()
            || current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .revision()
                != write.expected_revision()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let recovery = ProtectedBrokerRequestCommitRecoveryV1 {
            expected_generation: write.expected_generation(),
            expected_head: write.expected_head(),
            expected_revision: write.expected_revision(),
            target: StoredProtocolHistoryV1::from_request_write(
                transcript.protocol(),
                current.endpoint,
                current.stable_endpoint_identity,
                current.endpoint_publication,
                write.current_catalog()?,
                write,
                current.checkpoint.clone(),
            )?,
            transcript: transcript.clone(),
        };
        Ok(self.install_successor_with_storage_receiving_v3(recovery, connection_peer, receiving))
    }

    /// Commits one exact pending outcome and confirms canonical readback.
    ///
    /// Every post-preflight failure retains the pending advancement inside an
    /// explicit recovery token. The co-owned authenticated session reopens this
    /// fixed storage before classifying the exact predecessor or replacement.
    #[must_use]
    pub(crate) fn commit_broker_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.commit_outcome_with_storage_receiving_v3(pending, connection_peer, None)
    }

    pub(super) fn commit_outcome_with_storage_receiving_v3(&mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        match self.try_commit_outcome(&pending, connection_peer, receiving) {
            Ok(readback) => match pending.confirm_committed_preserving(readback) {
                Ok(committed) => ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                Err((error, pending)) => ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                    error,
                    recovery: ProtectedBrokerOutcomeCommitRecoveryV1 { pending },
                },
            },
            Err(error) => ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                error,
                recovery: ProtectedBrokerOutcomeCommitRecoveryV1 { pending },
            },
        }
    }

    /// Resolves an interrupted outcome commit against a freshly opened owner.
    #[must_use]
    pub(crate) fn recover_broker_outcome_commit(
        &mut self,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.commit_broker_outcome(recovery.pending, connection_peer)
    }

    /// Resolves an interrupted initial install by exact target or absence.
    #[must_use]
    pub fn recover_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        self.install_initial(recovery, connection_peer)
    }

    /// Resolves an interrupted successor-request append.
    #[must_use]
    pub fn recover_request_commit(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        self.install_successor(recovery, connection_peer)
    }

    fn install_initial(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        self.install_initial_with_storage_receiving_v2(recovery, connection_peer, None)
    }

    fn install_initial_with_storage_receiving_v2(&mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1, connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        let target = &recovery.target;
        let result = (|| {
            let history = target.history_model()?;
            let method = history
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .method();
            self.require_floor_method_with_storage_receiving_v2(method, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;

            self.validate_recovery_peer_with_storage_receiving_v2(target, &recovery.transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;
            match self.read_optional_with_storage_receiving_v2(target.protocol, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))? {
                Some(current) if current == *target => return Ok(()),
                Some(current)
                    if current.generation == recovery.expected_generation
                        && current.current_head == recovery.expected_head
                        && current.endpoint_publication == recovery.expected_publication
                        && current.stable_endpoint_identity == target.stable_endpoint_identity => {}
                None if recovery.expected_generation == 0
                    && recovery.expected_head == [0; 32]
                    && recovery.expected_publication == [0; 32] => {}
                _ => return Err(BrokerSessionSecurityError::Currentness),
            }
            self.commit_stored_with_storage_receiving_v2(target, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;
            self.validate_recovery_peer_with_storage_receiving_v2(target, &recovery.transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;
            if !matches!(self.read_optional_with_storage_receiving_v2(target.protocol, receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?, Some(current) if current == *target)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.mark_retired_storage_rollover_consumed_v1(&recovery);
                ProtectedBrokerSessionInitializationResultV1::Initialized
            },
            Err(error) => {
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery }
            }
        }
    }

    fn install_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        self.install_successor_with_storage_receiving_v3(recovery, connection_peer, None)
    }

    fn install_successor_with_storage_receiving_v3(&mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        let target = &recovery.target;
        let result = (|| {
            let history = target.history_model()?;
            let method = history
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .method();
            self.require_floor_method_with_storage_receiving_v2(method, receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;

            self.validate_recovery_peer_with_storage_receiving_v2(target, &recovery.transcript, connection_peer,
                receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
            let current = self
                .read_optional_with_storage_receiving_v2(target.protocol, receiving.as_mut()
                    .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            if current == *target {
                return Ok(());
            }
            let head = current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .clone();
            if current.generation != recovery.expected_generation
                || current.current_head != recovery.expected_head
                || head.revision() != recovery.expected_revision
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            self.commit_stored_with_storage_receiving_v2(target, receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
            self.validate_recovery_peer_with_storage_receiving_v2(target, &recovery.transcript, connection_peer,
                receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
            if !matches!(self.read_optional_with_storage_receiving_v2(target.protocol, receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?, Some(current) if current == *target)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        match result {
            Ok(()) => ProtectedBrokerRequestCommitResultV1::Committed,
            Err(error) => {
                ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery }
            }
        }
    }

    fn try_commit_outcome(
        &mut self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerOutcomeCommitReadbackV1, BrokerSessionSecurityError> {
        self.require_floor_method_with_storage_receiving_v2(pending.outcome.request().method(), receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;

        let context = self.current_context_with_storage_receiving_v2(&pending.transcript, None, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?.into_ordinary();
        let before_peer = self.observe_peer_with_storage_receiving_v3(&pending.transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        if before_peer.binding(self.endpoint.role(), &pending.transcript, &context)?
            != pending.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let protocol = pending.transcript.protocol();
        let current = self
            .read_optional_with_storage_receiving_v2(protocol, receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let replacement = StoredProtocolHistoryV1::from_pending_outcome(&current, pending)?;
        if current.generation == replacement.generation
            && current.current_head == replacement.current_head
            && current.history == replacement.history
        {
            return self.confirm_pending(pending, connection_peer, receiving);
        }
        let current_history = current.history_model()?;
        let current_record = current_history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if current.generation != pending.durable_cas.expected_generation
            || current.current_head != pending.durable_cas.expected_head
            || current.endpoint_publication != pending.protected_bindings.endpoint_publication()
            || current.current_catalog != current_record.protected_bindings().current_catalog()
            || current_record.revision() != pending.durable_cas.expected_revision
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.commit_stored_with_storage_receiving_v2(&replacement, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        self.confirm_pending(pending, connection_peer, receiving)
    }

    fn confirm_pending(
        &mut self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerOutcomeCommitReadbackV1, BrokerSessionSecurityError> {
        let peer = self.observe_peer_with_storage_receiving_v3(&pending.transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        let readback =
            ProtectedBrokerOutcomeCommitReadbackV1::confirm_after_cas_with_storage_receiving_v3(self, pending, &peer,
                receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        let context = self.current_context_with_storage_receiving_v2(&pending.transcript, None, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?.into_ordinary();
        let after_peer = self.observe_peer_with_storage_receiving_v3(&pending.transcript, connection_peer, receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        if after_peer.binding(self.endpoint.role(), &pending.transcript, &context)?
            != pending.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(readback)
    }
}

impl ProtectedBrokerOutcomeCurrentV1<'_> {
    /// Rechecks exact terminal custody and the lifecycle transport's final floor.
    ///
    /// # Errors
    /// Rejects a changed protected terminal, endpoint, live peer, or floor.
    pub(crate) fn revalidate_lifecycle_attestation(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate()?;
        self.authority.endpoint.revalidate()?;
        self.authority.require_floor_current()
    }

    pub(crate) fn revalidate_stop_inventory_attestation_v5(&mut self,
        post: &mut super::client_session_continuation::ExecutionClientPostOriginalV1,
        original: &mut crate::host_stop_inventory::StopAttestationCheckV5,
        after: bool,
    ) -> Result<(), BrokerSessionSecurityError> {
        if original.terminal.is_some() { return Err(BrokerSessionSecurityError::Currentness); }
        original.terminal = Some(if after {
            post.observe_terminal_after_v1(self.authority, &self.owner, self.connection_peer)
        } else {
            post.observe_terminal_before_v1(self.authority, &self.owner, self.connection_peer)
        });
        // Each after destination was prepaid independently. Preserve the
        // terminal result before entering the endpoint and floor posts so a
        // later refusal cannot replace it or suppress another owed check.
        if !after && !matches!(original.terminal, Some(Ok(()))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.endpoint = Some(self.authority.endpoint.revalidate_into_v1(&mut original.endpoint_native));
        if !after && !matches!(original.endpoint, Some(Ok(()))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.floor = Some(self.authority.require_floor_current());
        if matches!(original.terminal, Some(Ok(())))
            && matches!(original.endpoint, Some(Ok(())))
            && matches!(original.floor, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        }
    }

    pub(crate) fn sign_stop_inventory_attestation_v5(&mut self, message: &[u8; 32],
        original: &mut crate::host_stop_inventory::StopAttestationSignatureV5,
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.authority.endpoint.sign_stop_inventory_retaining_v5(message, original)
    }

    /// Signs a lifecycle attestation while retaining the exact terminal writer.
    ///
    /// # Errors
    /// Rejects a stale protected terminal or peer before or after the existing
    /// endpoint signer. A signing failure keeps precedence over a failed post.
    pub(crate) fn sign_lifecycle_bootstrap_attestation(
        &mut self,
        message: &[u8; 32],
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.revalidate_lifecycle_attestation()?;
        let signed = self
            .authority
            .endpoint
            .sign_lifecycle_bootstrap_attestation(message);
        let post = self.revalidate_lifecycle_attestation();
        let signature = signed?;
        post?;
        Ok(signature)
    }
}

#[cfg(test)]
mod stop_attestation_post_tests {
    use super::super::lifecycle_test_fixture::LifecycleTerminalFixture;
    use crate::host_stop_inventory::{HostStopInventoryAttestationOriginalV5, StopAttestationCheckV5};
    use crate::{BrokerSessionSecurityError, ExecutionClientPostOriginalV1};

    #[test]
    fn terminal_after_refusal_still_observes_distinct_endpoint_and_floor() {
        let mut fixture = LifecycleTerminalFixture::new();
        let mut post = ExecutionClientPostOriginalV1::default();
        let mut attestation = HostStopInventoryAttestationOriginalV5::default();
        let mut current = fixture.current();

        assert!(current.revalidate_stop_inventory_attestation_v5(
            &mut post, &mut attestation.after, true,
        ).is_err());

        assert!(matches!(attestation.after.terminal, Some(Err(_))));
        assert!(matches!(attestation.after.endpoint, Some(Ok(()))));
        assert!(matches!(attestation.after.floor, Some(Ok(()))));
        let terminal = attestation.after.terminal.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(attestation.failure_with_post_v5(&post).unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(), terminal));
    }

    #[test]
    fn endpoint_after_refusal_still_observes_floor_and_keeps_terminal_cause() {
        let mut fixture = LifecycleTerminalFixture::new();
        let client_path = fixture.client_path.clone();
        let mut post = ExecutionClientPostOriginalV1::default();
        let mut attestation = HostStopInventoryAttestationOriginalV5::default();
        let mut current = fixture.current();
        LifecycleTerminalFixture::replace_client_key(&client_path);

        assert!(current.revalidate_stop_inventory_attestation_v5(
            &mut post, &mut attestation.after, true,
        ).is_err());

        assert!(matches!(attestation.after.terminal, Some(Err(_))));
        assert!(matches!(attestation.after.endpoint, Some(Err(_))));
        assert!(attestation.after.endpoint_native.failure().is_some());
        assert!(matches!(attestation.after.floor, Some(Ok(()))));
        let terminal = attestation.after.terminal.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(attestation.failure_with_post_v5(&post).unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(), terminal));
    }

    #[test]
    fn before_refusal_keeps_unentered_following_checks_absent() {
        let mut fixture = LifecycleTerminalFixture::new();
        let client_path = fixture.client_path.clone();
        let mut post = ExecutionClientPostOriginalV1::default();
        let mut original = StopAttestationCheckV5::default();
        let mut current = fixture.current();
        LifecycleTerminalFixture::replace_client_key(&client_path);

        assert!(current.revalidate_stop_inventory_attestation_v5(
            &mut post, &mut original, false,
        ).is_err());

        assert!(matches!(original.terminal, Some(Err(_))));
        assert!(original.endpoint.is_none());
        assert!(original.floor.is_none());
    }
}
