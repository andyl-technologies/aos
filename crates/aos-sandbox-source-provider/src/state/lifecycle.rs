//! Initialization, session installation, and protected-head advancement.

use super::*;

impl<'a> ProviderLedgerV1<'a> {
    /// Atomically initializes an empty dedicated SourceProvider namespace.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for nonempty state, invalid protected
    /// configuration, graph validation failure, or an ambiguous commit.
    pub(crate) fn initialize(
        mut journal: ProtectedJournalAuthority<'a>,
        configuration: ProtectedProviderConfigurationV1,
    ) -> Result<Self, ProviderLedgerError> {
        journal.validate_source_provider_authority()?;
        if !journal.is_materialized_empty()? {
            return Err(ProviderLedgerError::InvalidTransition(
                "SourceProvider authority journal is not empty",
            ));
        }
        if configuration.catalog_generation != configuration.catalog_floor_generation
            || configuration.catalog_digest != configuration.catalog_floor_digest
            || configuration.predecessor_catalog_generation != 0
            || configuration.predecessor_catalog_digest.as_bytes() != &[0; 32]
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let empty_acquisitions = std::collections::BTreeMap::new();
        let empty_releases = std::collections::BTreeMap::new();
        let (inventory_state_digest, active_lease_count) =
            crate::inventory::global_inventory_state_digest(
                configuration.provider.authority_id(),
                configuration.catalog_generation,
                configuration.catalog_digest,
                &empty_acquisitions,
                &empty_releases,
                configuration
                    .limits()
                    .maximum_inventory_tombstones_per_holder(),
            )?;
        let authority = AuthorityHeadRecordV1 {
            revision: 1,
            state: crate::ProviderAuthorityStateV1::AcquireClosed,
            provider: configuration.provider.clone(),
            trust_generation: configuration.trust_generation,
            trust_digest: configuration.trust_digest,
            revocation_generation: configuration.revocation_generation,
            revocation_digest: configuration.revocation_digest,
            valid_from_seconds: configuration.valid_from_seconds,
            valid_until_seconds: configuration.valid_until_seconds,
            route_id: configuration.route_id,
            route_generation: configuration.route_generation,
            route_digest: configuration.route_digest,
            resource_namespace_digest: configuration.resource_namespace_digest,
            proof_class_capabilities: configuration.proof_class_capabilities,
            supports_recursive: configuration.supports_recursive,
            supports_kernel_coupled: configuration.supports_kernel_coupled,
            provider_hello_signer: configuration.provider_hello_signer.clone(),
            provider_outcome_signer: configuration.provider_outcome_signer.clone(),
            catalog_generation: configuration.catalog_generation,
            catalog_digest: configuration.catalog_digest,
            inventory_generation: 1,
            inventory_state_digest,
            last_lease_issue_generation: 0,
            last_release_generation: 0,
            active_lease_count,
        };
        let catalog = CatalogHeadRecordV1 {
            revision: 1,
            provider: configuration.provider.clone(),
            resource_namespace_digest: configuration.resource_namespace_digest,
            catalog_generation: configuration.catalog_generation,
            catalog_digest: configuration.catalog_digest,
            publisher_authority_id: configuration.publisher_authority_id,
            publication_generation: configuration.publication_generation,
            publication_receipt_digest: configuration.publication_receipt_digest,
            predecessor_catalog_generation: configuration.predecessor_catalog_generation,
            predecessor_catalog_digest: configuration.predecessor_catalog_digest,
            catalog_floor_generation: configuration.catalog_floor_generation,
            catalog_floor_digest: configuration.catalog_floor_digest,
            publication_seconds: configuration.publication_seconds,
            publication_trust_generation: configuration.publication_trust_generation,
            publication_trust_digest: configuration.publication_trust_digest,
            publication_revocation_generation: configuration.publication_revocation_generation,
            publication_revocation_digest: configuration.publication_revocation_digest,
            publisher_signer: configuration.publisher_signer.clone(),
            canonical_publication: configuration.canonical_catalog_publication.clone(),
        };
        configuration.validate_heads(&authority, &catalog)?;
        let authority_bytes = crate::format::encode_authority(&authority);
        let catalog_bytes = crate::format::encode_catalog(&catalog);
        for (key, bytes) in [
            (
                crate::format::authority_key(authority.provider.authority_id()),
                authority_bytes.as_slice(),
            ),
            (
                crate::format::catalog_key(
                    catalog.provider.authority_id(),
                    catalog.catalog_generation,
                ),
                catalog_bytes.as_slice(),
            ),
        ] {
            let decoded = crate::format::decode_record(&key, bytes)?;
            if crate::format::encode_decoded_record(&decoded) != bytes {
                return Err(ProviderLedgerError::Corrupt(
                    "initial record failed canonical round trip",
                ));
            }
        }
        let authority_key = crate::format::authority_key(authority.provider.authority_id());
        let catalog_key =
            crate::format::catalog_key(catalog.provider.authority_id(), catalog.catalog_generation);
        crate::recovery::recover_records(
            [
                (authority_key.as_slice(), authority_bytes.as_slice()),
                (catalog_key.as_slice(), catalog_bytes.as_slice()),
            ],
            &configuration,
        )?;
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.source-provider.initialize.v1\0");
        hasher.update(crate::format::record_digest(&authority_bytes)?.as_bytes());
        hasher.update(crate::format::record_digest(&catalog_bytes)?.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&digest[..16]);
        if transaction_id == [0; 16] {
            return Err(ProviderLedgerError::Corrupt(
                "zero initialization transaction identity",
            ));
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    crate::format::authority_key(authority.provider.authority_id()),
                    authority_bytes,
                ),
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    crate::format::catalog_key(
                        catalog.provider.authority_id(),
                        catalog.catalog_generation,
                    ),
                    catalog_bytes,
                ),
            ],
        )?;
        let preflight = journal.preflight_transactions(std::slice::from_ref(&transaction))?;
        journal.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        journal.commit(&transaction)?;
        let recovered = crate::recovery::recover(&journal, &configuration)?;
        Ok(Self {
            journal,
            configuration,
            recovered,
            current_sessions: BTreeMap::new(),
            pending_acquisitions: BTreeMap::new(),
            pending_releases: BTreeMap::new(),
            recovery_authorizations: BTreeMap::new(),
            pending_recovery_bridge: None,
            poisoned: false,
        })
    }

    /// Recovers and validates one exclusively owned protected provider journal.
    ///
    /// Recovery restores no descriptor, pidfd, signer handle, backend token,
    /// session transport, or effect permission. Protected configuration must
    /// exactly match the current durable authority and catalog heads.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for malformed durable bytes, an invalid
    /// graph, exceeded bounds, rollback, equivocation, or configuration drift.
    pub(crate) fn recover(
        journal: ProtectedJournalAuthority<'a>,
        configuration: ProtectedProviderConfigurationV1,
    ) -> Result<Self, ProviderLedgerError> {
        journal.validate_source_provider_authority()?;
        let recovered = crate::recovery::recover(&journal, &configuration)?;
        Ok(Self::from_validated_recovery(
            journal,
            configuration,
            recovered,
        ))
    }

    pub(crate) fn from_validated_recovery(
        journal: ProtectedJournalAuthority<'a>,
        configuration: ProtectedProviderConfigurationV1,
        recovered: RecoveredProviderLedgerV1,
    ) -> Self {
        Self {
            journal,
            configuration,
            recovered,
            current_sessions: BTreeMap::new(),
            pending_acquisitions: BTreeMap::new(),
            pending_releases: BTreeMap::new(),
            recovery_authorizations: BTreeMap::new(),
            pending_recovery_bridge: None,
            poisoned: false,
        }
    }

    /// Installs one live security-branded session under runtime ownership.
    ///
    /// Replacing a live holder session consumes and closes the prior carrier;
    /// its move-only supersession evidence is retained until the first durable
    /// request transaction advances the holder's current-session head.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] if current security custody cannot be
    /// revalidated or the session names another provider authority.
    pub fn install_current_session(
        &mut self,
        mut session: CurrentProviderIngressSessionV1,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let journal_snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&journal_snapshot)?;
        let projection = session.current_projection()?;
        if projection.provider() != &self.configuration.provider {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let holder_id = projection.holder().authority_id();
        let replacement_binding = projection.session_binding();
        // A replacement over descriptor-bearing history remains quarantined.
        // Admission promotes it only after exact predecessor death or a
        // durable revocation fence is established.
        let supersession = match self.current_sessions.remove(&holder_id) {
            Some(previous) => Some(previous.session.supersede(replacement_binding)?),
            None => None,
        };
        self.current_sessions.insert(
            holder_id,
            InstalledProviderSessionV1 {
                session,
                supersession,
                recovered_execution_death: None,
            },
        );
        Ok(())
    }

    pub(crate) fn install_recovery_successor_session(
        &mut self,
        mut session: CurrentProviderIngressSessionV1,
        supersession: ProviderSessionSupersessionEvidenceV1,
        recovered_execution_death: Option<
            aos_sandbox_source_provider_security::DeadProviderExecutionV1,
        >,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let projection = session.current_projection()?;
        if projection.provider() != &self.configuration.provider {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let holder_id = projection.holder().authority_id();
        if self.current_sessions.contains_key(&holder_id) {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        self.current_sessions.insert(
            holder_id,
            InstalledProviderSessionV1 {
                session,
                supersession: Some(supersession),
                recovered_execution_death,
            },
        );
        Ok(())
    }

    /// Atomically advances authenticated trust, signer, validity, and catalog heads.
    ///
    /// Historical catalog records remain immutable. Equal generations must
    /// retain their exact digest; a new catalog must name the prior current
    /// catalog as its predecessor. The durable authority state is preserved;
    /// this dormant API cannot activate or retire the provider.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for rollback, equivocation, invalid
    /// predecessor linkage, stale journal authority, or commit failure.
    pub(crate) fn advance_protected_configuration(
        &mut self,
        session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        canonical_catalog_publication: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let limits = self.configuration.limits();
        let before_custody = session
            .revalidated_provider_configuration()?
            .require_history_extension(self.configuration.trust_history())?
            .reconcile_issuance_history(&self.configuration.historical_public_keys)?;
        let before_catalog = verify_catalog_for_transition(
            &before_custody,
            &self.configuration,
            canonical_catalog_publication,
        )?;
        let next = ProtectedProviderConfigurationV1::from_revalidated_projections(
            before_custody,
            before_catalog,
            limits,
        )?;
        let expected_digest = next.deployment_digest();
        self.advance_revalidated_configuration(next, self.recovered.authority.state)?;

        let postcommit = (|| {
            let after_custody = session
                .revalidated_provider_configuration()?
                .require_history_extension(self.configuration.trust_history())?
                .reconcile_issuance_history(&self.configuration.historical_public_keys)?;
            let after_catalog = verify_catalog_for_transition(
                &after_custody,
                &self.configuration,
                canonical_catalog_publication,
            )?;
            let after = ProtectedProviderConfigurationV1::from_revalidated_projections(
                after_custody,
                after_catalog,
                limits,
            )?;
            if after.deployment_digest() != expected_digest
                || !after.matches_authority_and_catalog(
                    &self.recovered.authority,
                    &self.recovered.catalog,
                )
            {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }
            Ok(())
        })();
        if postcommit.is_err() {
            self.poisoned = true;
        }
        postcommit
    }

    fn advance_revalidated_configuration(
        &mut self,
        next: ProtectedProviderConfigurationV1,
        next_state: crate::ProviderAuthorityStateV1,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let retained_graph = !self.recovered.sessions.is_empty()
            || !self.recovered.session_history.is_empty()
            || !self.recovered.attempts.is_empty()
            || !self.recovered.acquisitions.is_empty()
            || !self.recovered.releases.is_empty();
        if retained_graph
            && (!self.configuration.same_frozen_authority(&next)
                || next_state != self.recovered.authority.state)
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider identity, route, capabilities, limits, and state are frozen while graph history is retained",
            ));
        }
        let current = &self.recovered.authority;
        if self.configuration.trust_history.len() > next.trust_history.len()
            || &next.trust_history[..self.configuration.trust_history.len()]
                != self.configuration.trust_history.as_slice()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let same_provider = next.provider == current.provider;
        let monotone_trust = monotone_head(
            current.trust_generation,
            current.trust_digest,
            next.trust_generation,
            next.trust_digest,
        );
        let monotone_revocation = monotone_head(
            current.revocation_generation,
            current.revocation_digest,
            next.revocation_generation,
            next.revocation_digest,
        );
        let monotone_route = current.route_id == next.route_id
            && monotone_head(
                current.route_generation,
                current.route_digest,
                next.route_generation,
                next.route_digest,
            );
        let monotone_catalog = monotone_head(
            current.catalog_generation,
            current.catalog_digest,
            next.catalog_generation,
            next.catalog_digest,
        );
        let monotone_validity = next.valid_from_seconds >= current.valid_from_seconds
            && next.valid_until_seconds >= current.valid_until_seconds;
        let monotone_hello_signer =
            monotone_signer(&current.provider_hello_signer, &next.provider_hello_signer);
        let monotone_outcome_signer = monotone_signer(
            &current.provider_outcome_signer,
            &next.provider_outcome_signer,
        );
        if !same_provider
            || !monotone_trust
            || !monotone_revocation
            || !monotone_route
            || !monotone_catalog
            || !monotone_validity
            || !monotone_hello_signer
            || !monotone_outcome_signer
            || (current.state == crate::ProviderAuthorityStateV1::Retired
                && next_state != crate::ProviderAuthorityStateV1::Retired)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let floor_changed = next.catalog_floor_generation
            != self.configuration.catalog_floor_generation
            || next.catalog_floor_digest != self.configuration.catalog_floor_digest;
        if next.resource_namespace_digest != current.resource_namespace_digest
            || next.catalog_floor_generation < self.configuration.catalog_floor_generation
            || (next.catalog_floor_generation == self.configuration.catalog_floor_generation
                && next.catalog_floor_digest != self.configuration.catalog_floor_digest)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        if floor_changed {
            let anchor = if next.catalog_floor_generation == next.catalog_generation {
                (next.catalog_generation, next.catalog_digest)
            } else {
                self.recovered
                    .catalog_history
                    .get(&next.catalog_floor_generation)
                    .map(|catalog| (catalog.catalog_generation, catalog.catalog_digest))
                    .ok_or(ProviderLedgerError::InvalidTransition(
                        "catalog floor anchor is not retained",
                    ))?
            };
            if anchor != (next.catalog_floor_generation, next.catalog_floor_digest)
                || self.recovered.acquisitions.values().any(|acquisition| {
                    acquisition.catalog_generation < next.catalog_floor_generation
                })
                || retained_inventory_catalog_below(
                    &self.recovered.attempts,
                    next.catalog_floor_generation,
                )?
            {
                return Err(ProviderLedgerError::InvalidTransition(
                    "catalog floor is still referenced by retained state or artifacts",
                ));
            }
        }
        if next_state == crate::ProviderAuthorityStateV1::Retired
            && (!self.recovered.recovery_work.is_empty()
                || self.recovered.acquisitions.values().any(|record| {
                    matches!(
                        record.state,
                        crate::ProviderAcquisitionStateV1::Applying
                            | crate::ProviderAcquisitionStateV1::Pending
                            | crate::ProviderAcquisitionStateV1::Active
                            | crate::ProviderAcquisitionStateV1::Releasing
                    )
                }))
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "retirement requires an empty effect and lease graph",
            ));
        }
        if self
            .configuration
            .historical_public_keys
            .iter()
            .any(|entry| {
                !next
                    .historical_public_keys
                    .iter()
                    .any(|candidate| authenticated_historical_key_transition(entry, candidate))
            })
        {
            return Err(ProviderLedgerError::Equivocation);
        }

        let mut authority = current.clone();
        authority.revision =
            authority
                .revision
                .checked_add(1)
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "authority revision exhausted",
                ))?;
        authority.state = next_state;
        authority.provider = next.provider.clone();
        authority.trust_generation = next.trust_generation;
        authority.trust_digest = next.trust_digest;
        authority.revocation_generation = next.revocation_generation;
        authority.revocation_digest = next.revocation_digest;
        authority.valid_from_seconds = next.valid_from_seconds;
        authority.valid_until_seconds = next.valid_until_seconds;
        authority.route_generation = next.route_generation;
        authority.route_digest = next.route_digest;
        authority.resource_namespace_digest = next.resource_namespace_digest;
        authority.proof_class_capabilities = next.proof_class_capabilities;
        authority.supports_recursive = next.supports_recursive;
        authority.supports_kernel_coupled = next.supports_kernel_coupled;
        authority.provider_hello_signer = next.provider_hello_signer.clone();
        authority.provider_outcome_signer = next.provider_outcome_signer.clone();
        authority.catalog_generation = next.catalog_generation;
        authority.catalog_digest = next.catalog_digest;

        let catalog = CatalogHeadRecordV1 {
            revision: if next.catalog_generation == self.recovered.catalog.catalog_generation {
                self.recovered.catalog.revision.checked_add(1).ok_or(
                    ProviderLedgerError::InvalidTransition("catalog revision exhausted"),
                )?
            } else {
                1
            },
            provider: next.provider.clone(),
            resource_namespace_digest: next.resource_namespace_digest,
            catalog_generation: next.catalog_generation,
            catalog_digest: next.catalog_digest,
            publisher_authority_id: next.publisher_authority_id,
            publication_generation: next.publication_generation,
            publication_receipt_digest: next.publication_receipt_digest,
            predecessor_catalog_generation: next.predecessor_catalog_generation,
            predecessor_catalog_digest: next.predecessor_catalog_digest,
            catalog_floor_generation: next.catalog_floor_generation,
            catalog_floor_digest: next.catalog_floor_digest,
            publication_seconds: next.publication_seconds,
            publication_trust_generation: next.publication_trust_generation,
            publication_trust_digest: next.publication_trust_digest,
            publication_revocation_generation: next.publication_revocation_generation,
            publication_revocation_digest: next.publication_revocation_digest,
            publisher_signer: next.publisher_signer.clone(),
            canonical_publication: next.canonical_catalog_publication.clone(),
        };
        next.validate_heads(&authority, &catalog)?;
        let catalog_head_changed =
            catalog.catalog_generation != self.recovered.catalog.catalog_generation;
        if !catalog_head_changed
            && (catalog.catalog_digest != self.recovered.catalog.catalog_digest
                || catalog.publisher_authority_id != self.recovered.catalog.publisher_authority_id
                || catalog.publication_generation != self.recovered.catalog.publication_generation
                || catalog.publication_receipt_digest
                    != self.recovered.catalog.publication_receipt_digest
                || catalog.predecessor_catalog_generation
                    != self.recovered.catalog.predecessor_catalog_generation
                || catalog.predecessor_catalog_digest
                    != self.recovered.catalog.predecessor_catalog_digest)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let catalog_record_changed = catalog_head_changed || floor_changed;
        if catalog_record_changed {
            authority.inventory_generation = authority.inventory_generation.checked_add(1).ok_or(
                ProviderLedgerError::InvalidTransition("inventory generation exhausted"),
            )?;
            let (digest, active_count) = crate::inventory::global_inventory_state_digest(
                authority.provider.authority_id(),
                authority.catalog_generation,
                authority.catalog_digest,
                &self.recovered.acquisitions,
                &self.recovered.releases,
                next.limits().maximum_inventory_tombstones_per_holder(),
            )?;
            authority.inventory_state_digest = digest;
            authority.active_lease_count = active_count;
        }
        if catalog_head_changed
            && (catalog.predecessor_catalog_generation != self.recovered.catalog.catalog_generation
                || catalog.predecessor_catalog_digest != self.recovered.catalog.catalog_digest)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let maximum_catalog_deletes = crate::limits::MAXIMUM_TRANSACTION_RECORDS
            .saturating_sub(1 + usize::from(catalog_record_changed));
        let catalogs_to_delete: Vec<u64> = self
            .recovered
            .catalog_history
            .keys()
            .copied()
            .filter(|generation| *generation < next.catalog_floor_generation)
            .take(maximum_catalog_deletes)
            .collect();
        let projected_catalog_count = self
            .recovered
            .catalog_history
            .len()
            .saturating_sub(catalogs_to_delete.len())
            .saturating_add(usize::from(catalog_head_changed));
        if projected_catalog_count > crate::limits::MAXIMUM_RETAINED_CATALOG_HEADS {
            return Err(ProviderLedgerError::LimitExceeded("retained catalog heads"));
        }
        let mut records = vec![(
            crate::format::authority_key(authority.provider.authority_id()),
            Some(crate::format::encode_authority(&authority)),
        )];
        if catalog_record_changed {
            records.push((
                crate::format::catalog_key(
                    catalog.provider.authority_id(),
                    catalog.catalog_generation,
                ),
                Some(crate::format::encode_catalog(&catalog)),
            ));
        }
        for generation in &catalogs_to_delete {
            records.push((
                crate::format::catalog_key(authority.provider.authority_id(), *generation),
                None,
            ));
        }
        crate::transaction::commit_mutations_with_configuration(
            self,
            b"advance-protected-configuration",
            records,
            &next,
        )?;
        self.recovered.authority = authority;
        for generation in catalogs_to_delete {
            self.recovered.catalog_history.remove(&generation);
        }
        if catalog_record_changed {
            self.recovered
                .catalog_history
                .insert(catalog.catalog_generation, catalog.clone());
            self.recovered.catalog = catalog;
        }
        self.configuration = next;
        // Any protected transition invalidates all live custody projections.
        // Durable historical sessions remain available only for replay and
        // recovery validation.
        self.current_sessions.clear();
        self.pending_acquisitions.clear();
        self.pending_releases.clear();
        self.recovery_authorizations.clear();
        Ok(())
    }
}
