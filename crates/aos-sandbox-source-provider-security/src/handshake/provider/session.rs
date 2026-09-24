//! Current ingress admission, replay, death proof, and private signing seams.

use super::*;

impl CurrentProviderIngressSessionV1 {
    /// Signs an Unavailable observation on this new carrier after caller-owned
    /// protected attempt verification and authenticated Storage readback.
    ///
    /// # Errors
    ///
    /// Closes the session for stale custody, peer, or query binding.
    #[doc(hidden)]
    pub fn sign_recovery_unavailable(
        &mut self,
        query: &RecoveryCurrentnessQueryV1,
        signed_plan_digest: aos_sandbox_core::ObjectDigest,
    ) -> Result<SignedRecoveryUnavailableV1, SourceProviderSecurityError> {
        self.revalidate()?;
        if query.session_binding() != self.session.binding()
            || query.authorities().0
                != self
                    .custody
                    .inner()
                    .provider_authority()
                    .authority()
                    .authority_id()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let response = {
            let inner = self.custody.inner();
            SignedRecoveryUnavailableV1::sign(
                query,
                signed_plan_digest,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        }
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.revalidate()?;
        Ok(response)
    }

    /// Sends an already signed Unavailable response without advancing an Acquire.
    ///
    /// # Errors
    ///
    /// Closes the session if the response or current peer is stale.
    #[doc(hidden)]
    pub fn send_recovery_unavailable(
        &mut self,
        query: &RecoveryCurrentnessQueryV1,
        response: &SignedRecoveryUnavailableV1,
    ) -> Result<bool, SourceProviderSecurityError> {
        self.revalidate()?;
        let inner = self.custody.inner();
        let signer = inner.provider_authority().traffic_signer();
        let public_key = inner.outcome_key().signing_key().verifying_key();
        if query.session_binding() != self.session.binding()
            || response
                .verify_for_query(query, signer, public_key.as_bytes())
                .is_err()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        match self.carrier.send(&response.to_canonical_bytes()) {
            Ok(()) => {
                self.revalidate()?;
                Ok(true)
            }
            Err(CarrierFailureV1::Retryable) => Ok(false),
            Err(CarrierFailureV1::Fatal(error)) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }

    /// Signs one exact protected historical Inventory readback on this carrier.
    ///
    /// The caller must obtain `persisted` from the current Provider journal.
    /// An absent completion is signed only as non-authorizing Unavailable.
    ///
    /// # Errors
    ///
    /// Closes the session for changed custody, query, or protected completion.
    #[doc(hidden)]
    pub fn sign_inventory_readback(
        &mut self,
        query: &InventoryReadbackQueryV1,
        completed: Option<(Vec<u8>, crate::PersistedProviderOutcomeV1)>,
    ) -> Result<SignedInventoryReadbackV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let current = self.current_projection()?;
        if query.session_binding() != self.session.binding()
            || query.authorities().0
                != self
                    .custody
                    .inner()
                    .provider_authority()
                    .authority()
                    .authority_id()
            || query.authorities().1 != current.holder().authority_id()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let completed = completed
            .map(|(response, persisted)| {
                if persisted.method
                    != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
                    || persisted.signed_request_digest
                        != *query.signed_request_digest().as_bytes()
                    || persisted.response_digest
                        != *aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                            aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory,
                            &response,
                        )
                        .as_bytes()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                Ok((response, persisted.completed_at_seconds, persisted.deadline_seconds))
            })
            .transpose()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        let answer = {
            let inner = self.custody.inner();
            SignedInventoryReadbackV1::sign(
                query,
                completed,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        }
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.revalidate()?;
        Ok(answer)
    }

    /// Sends only the signed descriptor-free Inventory readback answer.
    ///
    /// # Errors
    ///
    /// Closes the session for changed peer, answer, signer, or carrier.
    #[doc(hidden)]
    pub fn send_inventory_readback(
        &mut self,
        query: &InventoryReadbackQueryV1,
        answer: &SignedInventoryReadbackV1,
    ) -> Result<bool, SourceProviderSecurityError> {
        self.revalidate()?;
        let inner = self.custody.inner();
        if query.session_binding() != self.session.binding()
            || answer
                .verify_for_query(
                    query,
                    inner.provider_authority().traffic_signer(),
                    &inner.outcome_key().signing_key().verifying_key().to_bytes(),
                )
                .is_err()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        match self.carrier.send(&answer.to_canonical_bytes()) {
            Ok(()) => {
                self.revalidate()?;
                Ok(true)
            }
            Err(CarrierFailureV1::Retryable) => Ok(false),
            Err(CarrierFailureV1::Fatal(error)) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }

    /// Receives only a descriptor-free catalog challenge on this current session.
    ///
    /// # Errors
    ///
    /// Closes the session on a malformed control record or stale peer custody.
    #[doc(hidden)]
    pub fn receive_current_catalog_query(
        &mut self,
    ) -> Result<Option<CatalogCurrentnessQueryV1>, SourceProviderSecurityError> {
        let Some(packet) = self.receive_current_request_packet()? else {
            return Ok(None);
        };
        let query = CatalogCurrentnessQueryV1::from_canonical_bytes(&packet).map_err(|_| {
            poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            )
        })?;
        if query.session_binding() != self.session.binding() {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        Ok(Some(query))
    }

    /// Signs the exact current protected catalog head for one live challenge.
    ///
    /// # Errors
    ///
    /// Closes the session if the journal snapshot, protected custody, scope,
    /// challenge, or provider outcome key is stale.
    #[doc(hidden)]
    pub fn sign_current_catalog_response(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_catalog: &crate::ProtectedCurrentCatalogPublicationV1,
        query: &CatalogCurrentnessQueryV1,
        publication_digest: aos_sandbox_core::ObjectDigest,
    ) -> Result<SignedCatalogCurrentnessV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let projection = current_catalog.projection();
        let (provider, namespace) = projection.scope();
        if !current_catalog.validate_current(journal)
            || query.session_binding() != self.session.binding()
            || provider != self.custody.inner().provider_authority().authority()
            || namespace != self.custody.inner().route().resource_namespace_digest()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            SignedCatalogCurrentnessV1::sign(
                query,
                projection.catalog_head(),
                projection.floor(),
                projection.head_commitment(),
                publication_digest,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        };
        self.revalidate()?;
        signed.map_err(|_| {
            poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            )
        })
    }

    /// Attempts one send of a previously signed current catalog response.
    ///
    /// `Ok(false)` retains a retryable nonblocking send. The caller must keep
    /// the exact query, response, and protected current-head capability until
    /// the packet is sent or the session is closed.
    ///
    /// # Errors
    ///
    /// Closes the session for stale custody, journal head, signer, or carrier.
    #[doc(hidden)]
    pub fn send_current_catalog_response(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_catalog: &crate::ProtectedCurrentCatalogPublicationV1,
        query: &CatalogCurrentnessQueryV1,
        response: &SignedCatalogCurrentnessV1,
    ) -> Result<bool, SourceProviderSecurityError> {
        self.revalidate()?;
        let inner = self.custody.inner();
        let signer = inner.provider_authority().traffic_signer();
        let public_key = inner.outcome_key().signing_key().verifying_key();
        if !current_catalog.validate_current(journal)
            || response
                .verify_for_query(query, signer, public_key.as_bytes())
                .is_err()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        match self.carrier.send(&response.to_canonical_bytes()) {
            Ok(()) => {
                self.revalidate()?;
                Ok(true)
            }
            Err(CarrierFailureV1::Retryable) => Ok(false),
            Err(CarrierFailureV1::Fatal(error)) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }

    /// Captures the exact predecessor identity before one fallible receive.
    ///
    /// The move-only checkpoint grants no carrier or signing authority. It may
    /// only seed an explicit fixed recovery handshake if this session is later
    /// fatally closed.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] if current protected custody or
    /// peer execution is already stale.
    #[doc(hidden)]
    pub fn prepare_ingress_reopen_checkpoint(
        &mut self,
    ) -> Result<ProviderIngressReopenCheckpointV1, SourceProviderSecurityError> {
        Ok(ProviderIngressReopenCheckpointV1 {
            predecessor: self.current_projection()?,
        })
    }

    /// Receives one descriptor-free request from the authenticated Root-Mount peer.
    ///
    /// `Ok(None)` retains the live session when the nonblocking carrier has no
    /// complete packet. Returned bytes are the exact packet observed on the
    /// authenticated session and are the only bytes the provider ledger should
    /// admit for this exchange.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session for a
    /// fatal carrier failure or a peer-execution change.
    #[doc(hidden)]
    pub fn receive_current_request_packet(
        &mut self,
    ) -> Result<Option<Vec<u8>>, SourceProviderSecurityError> {
        self.revalidate()?;
        let received = match self.carrier.receive_zero_descriptors(MAXIMUM_FRAME_BYTES) {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return Ok(None),
            Err(CarrierFailureV1::Fatal(error)) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let crate::carrier::ReceivedSourceProviderRecordV1 {
            payload,
            descriptors,
            execution,
        } = received;
        if !descriptors.is_empty() || !execution.has_same_execution(&self.root_mount_execution) {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        self.revalidate()?;
        Ok(Some(payload))
    }

    /// Returns the retained session binding without granting transport authority.
    #[must_use]
    #[doc(hidden)]
    pub const fn retained_session_binding(&self) -> aos_sandbox_core::ObjectDigest {
        self.session.binding()
    }

    /// Authenticates one legacy provider-ledger migration under this live owner.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the carrier, protected
    /// custody, fixed namespace-41 snapshot, catalog, provenance, and signed
    /// migration manifest are all exact and current.
    #[doc(hidden)]
    pub fn authorize_fixed_provider_ledger_migration_v1(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        catalog_publication: crate::VerifiedCatalogPublicationV1,
        provenance: aos_sandbox_source_provider_ledger::migration::SupplementalV2MigrationProvenanceV1,
        canonical_manifest: &[u8],
    ) -> Result<crate::AuthorizedV2MigrationPlanV1, SourceProviderSecurityError> {
        self.revalidate()?;
        crate::migration::authorize_v2_migration_plan_v1(
            &mut self.custody,
            journal,
            journal_snapshot,
            catalog_publication,
            provenance,
            canonical_manifest,
        )
    }

    /// Consumes one authenticated migration plan at the same live owner.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] after expiry or any custody,
    /// catalog, journal-instance, snapshot, or configuration drift.
    #[doc(hidden)]
    pub fn consume_fixed_provider_ledger_migration_v1(
        &mut self,
        authorization: crate::AuthorizedV2MigrationPlanV1,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<crate::AuthorizedV2MigrationInstallPartsV1, SourceProviderSecurityError> {
        self.revalidate()?;
        authorization.consume_for_install(&mut self.custody, journal)
    }

    /// Seals the exact current catalog head under this fixed live owner.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody, session,
    /// namespace-41 snapshot, publication, or catalog/authority lineage.
    #[doc(hidden)]
    pub fn authorize_fixed_current_catalog_publication_v1(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        publication: crate::VerifiedCatalogPublicationV1,
    ) -> Result<crate::ProtectedCurrentCatalogPublicationV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let configuration = self.revalidated_provider_configuration()?;
        crate::catalog::authorize_current_catalog_publication_v1(
            &configuration,
            journal,
            journal_snapshot,
            publication,
        )
    }

    /// Authenticates one exact fixed-journal AOSMSA01-to-AOSMSA02 migration.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless both fixed journals,
    /// snapshots, catalog head, supplemental graph, manifest, and live custody
    /// are exact and current.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_fixed_mount_source_state_migration_v2(
        &mut self,
        provider_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        provider_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        mount_journal: &aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
        mount_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        current_catalog: crate::ProtectedCurrentCatalogPublicationV1,
        supplemental_v2_records: &[(Vec<u8>, Vec<u8>)],
        canonical_manifest: &[u8],
    ) -> Result<crate::AuthorizedMountSourceStateMigrationV2, SourceProviderSecurityError> {
        self.revalidate()?;
        crate::migration::authorize_mount_source_state_migration_v2(
            &mut self.custody,
            provider_journal,
            provider_snapshot,
            mount_journal,
            mount_snapshot,
            current_catalog,
            supplemental_v2_records,
            canonical_manifest,
        )
    }

    /// Installs one exact authenticated fixed-journal Mount migration.
    #[must_use]
    #[doc(hidden)]
    pub fn install_fixed_mount_source_state_migration_v2(
        &mut self,
        provider_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        mount_journal: &mut aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
        authorization: crate::AuthorizedMountSourceStateMigrationV2,
    ) -> crate::MountSourceStateMigrationInstallOutcomeV2 {
        crate::migration::install_mount_source_state_migration_v2(
            &mut self.custody,
            provider_journal,
            mount_journal,
            authorization,
        )
    }

    /// Resolves or retries one exact fixed-journal Mount migration.
    #[must_use]
    #[doc(hidden)]
    pub fn recover_fixed_mount_source_state_migration_v2(
        &mut self,
        provider_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        mount_journal: &mut aos_sandbox::MountSourceMigrationJournalAuthorityV2<'_>,
        recovery: crate::MountSourceStateMigrationRecoveryV2,
    ) -> crate::MountSourceStateMigrationInstallOutcomeV2 {
        crate::migration::recover_mount_source_state_migration_v2(
            &mut self.custody,
            provider_journal,
            mount_journal,
            recovery,
        )
    }

    /// Produces the current non-secret provider configuration projection.
    ///
    /// This purpose-limited projection lets the fixed provider-ledger owner
    /// authenticate its namespace-41 bootstrap or replay without extracting
    /// custody or a signing key from this live session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// protected custody or peer-process continuity changed.
    #[doc(hidden)]
    pub fn revalidated_provider_configuration(
        &mut self,
    ) -> Result<crate::RevalidatedProviderConfigurationV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        crate::RevalidatedProviderConfigurationV1::capture(&mut self.custody, now)
    }

    /// Consumes an authenticated request into one exact durable-reservation authorization.
    ///
    /// The live session revalidates custody and proves that the request still
    /// belongs to this carrier before the protected journal reservation is
    /// bound. The returned value is move-only, has no scalar accessors, and
    /// can be used only by the sealed completion facade.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when custody, session,
    /// protected journal, reservation bytes, or response sequence changed.
    pub fn authorize_reserved_request(
        &mut self,
        current: super::CurrentProviderRequestV1,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: &[u8],
        attempt_record: &[u8],
        response_sequence: u64,
    ) -> Result<super::ProviderOutcomeAuthorizationV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let projection = match current.verified() {
            aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(value) => {
                value.ingress_projection()
            }
            aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Release(value) => {
                value.ingress_projection()
            }
            aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Inventory(value) => {
                value.ingress_projection()
            }
        };
        if projection.session_binding() != self.session.binding()
            || projection.provider_process_instance() != self.session.provider_process_instance()
            || projection.root_mount_process_instance()
                != self.session.root_mount_process_instance()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        current.authorize_reserved(
            journal,
            journal_snapshot,
            attempt_key,
            attempt_record,
            response_sequence,
        )
    }

    /// Consumes and sends one exact response proven durably committed.
    ///
    /// The carrier accepts exactly one `SourceRoot` descriptor for a complete
    /// Acquire response and no descriptor for every other response shape.
    /// Journal and live-session currentness are revalidated immediately before
    /// the SCM_RIGHTS handoff.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale durability authority,
    /// response substitution, session drift, descriptor-shape mismatch, or
    /// carrier failure.
    pub fn send_committed_reply(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        committed: super::CommittedProviderOutcomeV1,
        source_root: Option<crate::ProviderSourceRootHandoffV1>,
    ) -> Result<(), SourceProviderSecurityError> {
        journal
            .validate_source_provider_authority_snapshot(&committed.committed_snapshot)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let response = committed
            .response
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if committed.artifact_commitment
            != aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                committed.method,
                &response,
            )
            || !journal_retains_exact_artifact(journal, &response)?
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let response_identity = validate_send_response_with_source_root(
            committed.method,
            &response,
            source_root.as_ref(),
        )?;
        if response_identity != (committed.session_binding, committed.response_sequence)
            || committed.session_binding != self.session.binding()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.revalidate()?;
        if let Some(source_root) = source_root.as_ref() {
            if let Err(error) = source_root.revalidate() {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        }
        if let Err(failure) = self.carrier.send_optional_source_root(
            &response,
            source_root
                .as_ref()
                .map(crate::ProviderSourceRootHandoffV1::descriptor),
        ) {
            let error = match failure {
                CarrierFailureV1::Retryable => SourceProviderSecurityError::SessionContinuity,
                CarrierFailureV1::Fatal(error) => error,
            };
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        if let Some(source_root) = source_root.as_ref() {
            if let Err(error) = source_root.revalidate() {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        }
        self.revalidate()
    }

    /// Authorizes one exact recovered response for a single carrier handoff.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale replay authority,
    /// noncanonical response bytes, session drift, an invalid descriptor
    /// shape, or carrier failure.
    pub fn authorize_recovered_reply(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: &[u8],
        response: Vec<u8>,
        has_source_root: bool,
    ) -> Result<RevalidatedProviderReplayV1, SourceProviderSecurityError> {
        journal
            .validate_source_provider_authority_snapshot(&snapshot)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let attempt_bytes = journal
            .get(attempt_key)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let attempt = match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
            attempt_key,
            attempt_bytes,
        ) {
            Ok(aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Attempt(
                attempt,
            )) => attempt,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        if attempt.state != aos_sandbox_source_provider_ledger::ProviderAttemptStateV1::Completed
            || attempt.completed_response != response
            || attempt.response_digest
                != Some(
                    aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                        attempt.method,
                        &response,
                    ),
                )
            || !journal_retains_exact_artifact(journal, &response)?
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let (method, response_identity) = classify_send_response(&response, has_source_root)?;
        let projection = self.current_projection()?;
        if method != attempt.method
            || response_identity
                != (
                    attempt.session_binding,
                    attempt
                        .response_sequence
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?,
                )
            || response_identity.0 != projection.session_binding
            || attempt.provider != projection.provider
            || attempt.holder != projection.holder
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(RevalidatedProviderReplayV1 {
            snapshot,
            method,
            response_sequence: response_identity.1,
            session_binding: response_identity.0,
            response,
            has_source_root,
        })
    }

    /// Authorizes deadline-independent Mount recovery of one persisted response.
    ///
    /// The protected Provider attempt must be exactly Completed, retain the
    /// supplied canonical response and artifact, and prove that its request was
    /// admitted before the exclusive deadline. The returned value carries no
    /// send or signing authority.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody or journal,
    /// another attempt state, response substitution, or invalid deadline facts.
    #[doc(hidden)]
    pub fn authorize_persisted_mount_outcome(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        snapshot: &aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: &[u8],
        response: &[u8],
    ) -> Result<crate::PersistedProviderOutcomeV1, SourceProviderSecurityError> {
        self.revalidate()?;
        journal
            .validate_source_provider_authority_snapshot(snapshot)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let attempt_bytes = journal
            .get(attempt_key)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let attempt = match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
            attempt_key,
            attempt_bytes,
        ) {
            Ok(aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Attempt(
                attempt,
            )) => attempt,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        let response_digest =
            aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                attempt.method,
                response,
            );
        if attempt.state != aos_sandbox_source_provider_ledger::ProviderAttemptStateV1::Completed
            || attempt.completed_response != response
            || attempt.response_digest != Some(response_digest)
            || attempt.completed_at_seconds.is_none_or(|completed| {
                completed < attempt.verified_at_seconds || completed >= attempt.deadline_seconds
            })
            || !journal_retains_exact_artifact(journal, response)?
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.revalidate()?;
        Ok(crate::PersistedProviderOutcomeV1 {
            method: attempt.method,
            signed_request_digest: *attempt.signed_request_digest.as_bytes(),
            response_digest: *response_digest.as_bytes(),
            completed_at_seconds: attempt
                .completed_at_seconds
                .ok_or(SourceProviderSecurityError::SessionContinuity)?,
            deadline_seconds: attempt.deadline_seconds,
        })
    }

    /// Consumes an exact replay authorization at the SCM_RIGHTS boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for journal/session drift,
    /// descriptor-role substitution, or carrier failure.
    pub fn send_revalidated_reply(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        replay: RevalidatedProviderReplayV1,
        source_root: Option<crate::ProviderSourceRootHandoffV1>,
    ) -> Result<(), SourceProviderSecurityError> {
        journal
            .validate_source_provider_authority_snapshot(&replay.snapshot)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if replay.has_source_root != source_root.is_some()
            || replay.session_binding != self.session.binding()
            || validate_send_response_with_source_root(
                replay.method,
                &replay.response,
                source_root.as_ref(),
            )? != (replay.session_binding, replay.response_sequence)
            || !journal_retains_exact_artifact(journal, &replay.response)?
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.revalidate()?;
        if let Some(source_root) = source_root.as_ref() {
            if let Err(error) = source_root.revalidate() {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        }
        if let Err(failure) = self.carrier.send_optional_source_root(
            &replay.response,
            source_root
                .as_ref()
                .map(crate::ProviderSourceRootHandoffV1::descriptor),
        ) {
            let error = match failure {
                CarrierFailureV1::Retryable => SourceProviderSecurityError::SessionContinuity,
                CarrierFailureV1::Fatal(error) => error,
            };
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        if let Some(source_root) = source_root.as_ref() {
            if let Err(error) = source_root.revalidate() {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        }
        self.revalidate()
    }

    /// Proves a retained provider execution exited or belongs to an earlier boot.
    ///
    /// The proof is minted only while current custody is live and the exact
    /// immutable AOSSPL session record remains present at the supplied
    /// protected-journal snapshot. No scalar-only death constructor exists.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody/journal state,
    /// a substituted session record, ambiguous identities, or a same-boot
    /// execution whose exit or PID reuse cannot be proven.
    pub fn prove_recovered_execution_dead(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: &aos_sandbox::ProtectedJournalSnapshot,
        retained_session_key: &[u8],
        retained_session_record: &[u8],
        old_boot_id: [u8; 16],
        old_provider_process_id: u32,
        old_provider_start_time_ticks: u64,
        old_provider_process_instance: [u8; 16],
        old_provider_execution_digest: aos_sandbox_core::ObjectDigest,
    ) -> Result<crate::DeadProviderExecutionV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let retained = match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
            retained_session_key,
            retained_session_record,
        ) {
            Ok(aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Session(
                value,
            ))
            | Ok(
                aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::SessionHistory(
                    value,
                ),
            ) => value,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        if retained_session_key.is_empty()
            || retained_session_record.is_empty()
            || old_boot_id == [0; 16]
            || old_provider_process_id == 0
            || old_provider_start_time_ticks == 0
            || old_provider_process_instance == [0; 16]
            || old_provider_execution_digest.as_bytes() == &[0; 32]
            || retained.boot_id != old_boot_id
            || retained.provider_process_id != old_provider_process_id
            || retained.provider_start_time_ticks != old_provider_start_time_ticks
            || retained.provider_process_instance != old_provider_process_instance
            || retained.provider_execution_commitment != old_provider_execution_digest
            || journal
                .validate_source_provider_authority_snapshot(journal_snapshot)
                .is_err()
            || journal.get(retained_session_key).ok().flatten() != Some(retained_session_record)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        crate::DeadProviderExecutionV1::establish_from_current_custody(
            old_boot_id,
            old_provider_process_id,
            old_provider_start_time_ticks,
            old_provider_process_instance,
            old_provider_execution_digest,
        )
    }

    /// Borrows a purpose-specific signer bound to one durable reservation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when the journal reservation,
    /// live custody, or authenticated session is no longer current.
    pub fn provider_outcome_facade<'session, 'journal, 'authority, 'authorization>(
        &'session mut self,
        journal: &'journal aos_sandbox::ProtectedJournalAuthority<'authority>,
        authorization: &'authorization super::ProviderOutcomeAuthorizationV1,
    ) -> Result<
        ProviderOwnerSecurityFacadeV1<'session, 'journal, 'authority, 'authorization>,
        SourceProviderSecurityError,
    > {
        validate_authorization_journal(journal, authorization)?;
        self.revalidate()?;
        if authorization.session_binding != self.session.binding()
            || authorization.provider_process_instance != self.session.provider_process_instance()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        Ok(ProviderOwnerSecurityFacadeV1 {
            session: self,
            journal,
            authorization,
        })
    }

    /// Returns a freshly revalidated non-secret session identity projection.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// protected custody or peer-process continuity changed.
    pub fn current_projection(
        &mut self,
    ) -> Result<CurrentProviderSessionProjectionV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let inner = self.custody.inner();
        Ok(CurrentProviderSessionProjectionV1 {
            provider: inner.provider_authority().authority().clone(),
            holder: inner.root_authority().authority().clone(),
            session_binding: self.session.binding(),
            root_process_instance: self.session.root_mount_process_instance(),
            provider_process_instance: self.session.provider_process_instance(),
        })
    }

    /// Consumes and closes this session as evidence for exact replacement.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] if the session is no longer
    /// current or the replacement binding is sentinel or unchanged.
    pub fn supersede(
        mut self,
        replacement_session_binding: aos_sandbox_core::ObjectDigest,
    ) -> Result<ProviderSessionSupersessionEvidenceV1, SourceProviderSecurityError> {
        let projection = self.current_projection()?;
        if replacement_session_binding.as_bytes() == &[0; 32]
            || replacement_session_binding == projection.session_binding
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        self.carrier.close();
        Ok(ProviderSessionSupersessionEvidenceV1 {
            provider_id: projection.provider.authority_id(),
            holder_id: projection.holder.authority_id(),
            prior_session_binding: projection.session_binding,
            replacement_session_binding,
            prior_root_process_instance: projection.root_process_instance,
        })
    }

    /// Signs one export lease after revalidating current provider custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody changed or the lease does not name the current provider.
    pub(super) fn sign_current_export_lease(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        lease: SourceExportLeaseV1,
    ) -> Result<SignedSourceExportLeaseV1, SourceProviderSecurityError> {
        validate_authorization_journal(journal, authorization)?;
        self.revalidate()?;
        let now_seconds = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        let lease_duration = lease
            .expires_seconds()
            .checked_sub(lease.issued_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok());
        if authorization.method
            != aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            || !authorization_authority_is_current(authorization, now_seconds)
            || lease.issued_seconds() > now_seconds
            || now_seconds >= lease.expires_seconds()
            || lease.expires_seconds() > authorization.request_deadline_seconds
            || lease.expires_seconds() > authorization.current_valid_until_seconds
            || lease_duration.is_none_or(|seconds| {
                seconds == 0
                    || seconds > aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_LEASE_SECONDS
            })
            || lease.request_id() != authorization.request_id
            || lease.request_digest() != authorization.typed_request_digest
            || lease.provider() != &authorization.provider
            || lease.holder_authority_id() != authorization.holder.authority_id()
            || lease.holder_generation() != authorization.holder.authority_generation()
            || lease.holder_authority_digest() != authorization.holder.authority_digest()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            sign_export_lease(
                lease,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        };
        self.finish_signature(signed)
    }

    /// Signs one Acquire receipt after revalidating current provider custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody changed or the receipt lineage is invalid.
    pub(super) fn sign_current_provider_receipt(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        receipt: SourceProviderReceiptV1,
    ) -> Result<SignedSourceProviderReceiptV1, SourceProviderSecurityError> {
        validate_authorization_journal(journal, authorization)?;
        self.revalidate()?;
        let now_seconds = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        let nested_lease =
            SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if authorization.method
            != aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            || !authorization_authority_is_current(authorization, now_seconds)
            || receipt.request_id() != authorization.request_id
            || receipt.request_digest() != authorization.typed_request_digest
            || Some(receipt.acquisition_id()) != authorization.acquisition_id
            || receipt.provider_process_instance() != authorization.provider_process_instance
            || digest_signed_export_lease(&nested_lease) != receipt.lease_digest()
            || nested_lease.subject().provider() != &authorization.provider
            || nested_lease.signer().authority_id() != authorization.provider.authority_id()
            || nested_lease.signer().authority_generation()
                != authorization.provider.authority_generation()
            || nested_lease.signer().authority_digest() != authorization.provider.authority_digest()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            sign_provider_receipt(
                receipt,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        };
        self.finish_signature(signed)
    }

    /// Signs one Release receipt after revalidating current provider custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody changed or the receipt does not name the current provider.
    pub(super) fn sign_current_release_receipt(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        receipt: SourceReleaseReceiptV1,
    ) -> Result<SignedSourceReleaseReceiptV1, SourceProviderSecurityError> {
        validate_authorization_journal(journal, authorization)?;
        self.revalidate()?;
        let now_seconds = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        if authorization.method
            != aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            || !authorization_authority_is_current(authorization, now_seconds)
            || receipt.request_id() != authorization.request_id
            || receipt.request_digest() != authorization.typed_request_digest
            || receipt.provider() != &authorization.provider
            || Some(receipt.lease_id()) != authorization.lease_id
            || Some(receipt.lease_digest()) != authorization.lease_digest
            || receipt.provider_process_instance() != authorization.provider_process_instance
            || receipt.released_seconds() < 0
            || receipt.released_seconds() > now_seconds
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            sign_release_receipt(
                receipt,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        };
        self.finish_signature(signed)
    }

    /// Signs one holder inventory after revalidating current provider custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody changed or the inventory does not name the current provider.
    pub(super) fn sign_current_inventory(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        inventory: SourceProviderInventoryV1,
    ) -> Result<SignedSourceProviderInventoryV1, SourceProviderSecurityError> {
        validate_authorization_journal(journal, authorization)?;
        self.revalidate()?;
        let now_seconds = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        if authorization.method
            != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            || !authorization_authority_is_current(authorization, now_seconds)
            || inventory.request_id() != authorization.request_id
            || inventory.request_digest() != authorization.typed_request_digest
            || inventory.provider() != &authorization.provider
            || inventory.holder_authority_id() != authorization.holder.authority_id()
            || inventory.holder_generation() != authorization.holder.authority_generation()
            || inventory.holder_authority_digest() != authorization.holder.authority_digest()
            || inventory.provider_process_instance() != authorization.provider_process_instance
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            sign_inventory(
                inventory,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        };
        self.finish_signature(signed)
    }

    /// Signs one response status bound to this exact live ingress session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody changed or the status names another session or execution.
    pub(super) fn sign_current_response_status(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        status: SourceProviderResponseStatusV1,
    ) -> Result<(SignedSourceProviderStatusV1, i64), SourceProviderSecurityError> {
        validate_authorization_journal(journal, authorization)?;
        self.revalidate()?;
        let now_seconds = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        if status.method() != authorization.method
            || !authorization_authority_is_current(authorization, now_seconds)
            || now_seconds >= authorization.request_deadline_seconds
            || status.request_id() != authorization.request_id
            || status.signed_request_digest() != authorization.signed_request_digest
            || status.session_binding() != authorization.session_binding
            || status.provider_process_instance() != authorization.provider_process_instance
            || status.response_sequence() != authorization.response_sequence
            || status.session_binding() != self.session.binding()
            || status.provider_process_instance() != self.session.provider_process_instance()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            sign_response_status(
                status,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        };
        self.finish_signature(signed)
            .map(|signed| (signed, now_seconds))
    }

    /// Verifies one request against freshly revalidated custody and execution.
    ///
    /// The sequence expectation must come from a current protected journal
    /// head. This method binds it to live custody, retained peer execution,
    /// current boot identity, and protected route and trust state.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// currentness, process continuity, or protocol verification fails.
    pub fn verify_current_request(
        &mut self,
        signed_request: &SignedSourceProviderRequestV1,
        sequence_expectation: ProviderRequestSequenceExpectationV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
    ) -> Result<super::CurrentProviderRequestV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        let root_identity = process_identity(&self.root_mount_execution)
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        let inner = self.custody.inner();
        let maximum_deadline = match now.checked_add(MAXIMUM_CURRENT_REQUEST_LIFETIME_SECONDS) {
            Some(value) => value,
            None => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let context = ProviderRequestVerificationContextV1::new(
            now,
            maximum_deadline,
            inner.manifest().node_id(),
            inner.execution().boot_id(),
            inner.manifest().revocation_digest(),
            root_identity,
            sequence_expectation,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity);
        let context = match context {
            Ok(context) => context,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let verified = verify_provider_request(
            signed_request,
            &self.session,
            inner.trust(),
            inner.root_authority(),
            inner.provider_authority(),
            inner.route(),
            &context,
            descriptor_roles,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity);
        match verified {
            Ok(verified) => {
                let provider_execution = self.custody.inner().execution().baseline();
                Ok(super::CurrentProviderRequestV1 {
                    verified,
                    provider_process_id: provider_execution.pid,
                    provider_start_time_ticks: provider_execution.start_time_ticks,
                })
            }
            Err(error) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            })
            .and_then(|_| {
                (self.session.root_mount_process_instance() != [0; 16]
                    && self.session.provider_process_instance()
                        == self.custody.inner().process_instance())
                .then_some(())
                .ok_or(SourceProviderSecurityError::SessionContinuity)
            });
        if let Err(error) = result {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        Ok(())
    }

    fn finish_signature<T>(
        &mut self,
        result: Result<T, aos_sandbox_source_provider_protocol::SourceProviderSignatureError>,
    ) -> Result<T, SourceProviderSecurityError> {
        result.map_err(|_| {
            poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            )
        })
    }
}
