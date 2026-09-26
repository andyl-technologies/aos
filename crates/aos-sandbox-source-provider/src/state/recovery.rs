//! Recovery observation, continuation, and completion owner paths.

use super::*;

impl<'a> ProviderLedgerV1<'a> {
    /// Opens dormant provider authority by explicitly initializing or recovering it.
    ///
    /// An empty, exclusively claimed namespace is initialized atomically with
    /// its Authority and Catalog records. Any nonempty namespace is recovered
    /// without mutation. Both paths derive configuration only from freshly
    /// revalidated security custody and an authenticated catalog publication;
    /// this entry point creates no listener, route advertisement, or backend.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for an ambiguous namespace state,
    /// custody or catalog drift, invalid durable records, or any mismatch
    /// between the protected configuration and recovered current heads.
    pub(crate) fn open_from_protected_custody(
        journal: ProtectedJournalAuthority<'a>,
        custody: &mut aos_sandbox_source_provider_security::ProtectedProviderCustodyV1,
        canonical_catalog_publication: &[u8],
        limits: ProviderLedgerLimits,
    ) -> Result<Self, ProviderLedgerError> {
        journal.validate_source_provider_authority()?;
        if journal.is_materialized_empty()? {
            return Self::initialize_from_protected_custody(
                journal,
                custody,
                canonical_catalog_publication,
                limits,
            );
        }

        let before_custody = custody.revalidated_configuration()?;
        let before_catalog = aos_sandbox_source_provider_security::verify_catalog_publication(
            &before_custody,
            canonical_catalog_publication,
        )?;
        let configuration = ProtectedProviderConfigurationV1::from_revalidated_projections(
            before_custody,
            before_catalog,
            limits,
        )?;
        let expected_configuration_digest = configuration.deployment_digest();
        let ledger = Self::recover(journal, configuration)?;

        let after_custody = custody.revalidated_configuration().map_err(|error| {
            custody.close_after_ambiguous_durable_transition();
            ProviderLedgerError::from(error)
        })?;
        let after_catalog = aos_sandbox_source_provider_security::verify_catalog_publication(
            &after_custody,
            canonical_catalog_publication,
        )
        .map_err(|error| {
            custody.close_after_ambiguous_durable_transition();
            ProviderLedgerError::from(error)
        })?;
        let after_configuration = ProtectedProviderConfigurationV1::from_revalidated_projections(
            after_custody,
            after_catalog,
            limits,
        )?;
        if after_configuration.deployment_digest() != expected_configuration_digest
            || !after_configuration.matches_authority_and_catalog(
                &ledger.recovered.authority,
                &ledger.recovered.catalog,
            )
        {
            custody.close_after_ambiguous_durable_transition();
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(ledger)
    }

    /// Initializes dormant provider authority from live protected custody.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for custody drift, an invalid catalog,
    /// nonempty authority state, or an ambiguous durable initialization.
    pub(crate) fn initialize_from_protected_custody(
        journal: ProtectedJournalAuthority<'a>,
        custody: &mut aos_sandbox_source_provider_security::ProtectedProviderCustodyV1,
        canonical_catalog_publication: &[u8],
        limits: ProviderLedgerLimits,
    ) -> Result<Self, ProviderLedgerError> {
        journal.validate_source_provider_authority()?;
        let before_custody = custody.revalidated_configuration()?;
        let before_catalog = aos_sandbox_source_provider_security::verify_catalog_publication(
            &before_custody,
            canonical_catalog_publication,
        )?;
        let configuration = ProtectedProviderConfigurationV1::from_revalidated_projections(
            before_custody,
            before_catalog,
            limits,
        )?;
        let expected_configuration_digest = configuration.deployment_digest();
        let ledger = match Self::initialize(journal, configuration) {
            Ok(ledger) => ledger,
            Err(error) => {
                custody.close_after_ambiguous_durable_transition();
                return Err(error);
            }
        };

        let after_custody = match custody.revalidated_configuration() {
            Ok(configuration) => configuration,
            Err(error) => {
                custody.close_after_ambiguous_durable_transition();
                return Err(error.into());
            }
        };
        let after_catalog = match aos_sandbox_source_provider_security::verify_catalog_publication(
            &after_custody,
            canonical_catalog_publication,
        ) {
            Ok(catalog) => catalog,
            Err(error) => {
                custody.close_after_ambiguous_durable_transition();
                return Err(error.into());
            }
        };
        let after_configuration =
            match ProtectedProviderConfigurationV1::from_revalidated_projections(
                after_custody,
                after_catalog,
                limits,
            ) {
                Ok(configuration) => configuration,
                Err(error) => {
                    custody.close_after_ambiguous_durable_transition();
                    return Err(error);
                }
            };
        if after_configuration.deployment_digest() != expected_configuration_digest
            || !after_configuration.matches_authority_and_catalog(
                &ledger.recovered.authority,
                &ledger.recovered.catalog,
            )
        {
            custody.close_after_ambiguous_durable_transition();
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(ledger)
    }

    /// Establishes opaque same-boot or cross-boot death for one retained provider session.
    ///
    /// The proof is derived inside current security custody from the exact
    /// immutable session record at a protected journal snapshot. It grants no
    /// effect or signing authority by itself.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the retained session or current
    /// replacement session is absent, currentness changed, or exact execution
    /// death cannot be established.
    pub fn prove_recovered_session_execution_dead(
        &mut self,
        holder_id: [u8; 16],
        retained_session_binding: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let provider_id = self.recovered.authority.provider.authority_id();
        let retained = self
            .recovered
            .session_history
            .get(&(provider_id, holder_id, retained_session_binding))
            .cloned()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "unknown retained provider session",
            ))?;
        let key =
            crate::format::session_history_key(provider_id, holder_id, retained_session_binding);
        let record = crate::format::encode_session_history(&retained);
        let snapshot = self.journal.snapshot()?;
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("no current replacement session"),
        )?;
        let current = match installed.session.current_projection() {
            Ok(current) => current,
            Err(error) => {
                self.current_sessions.insert(holder_id, installed);
                return Err(error.into());
            }
        };
        if current.provider().authority_id() != provider_id
            || current.holder().authority_id() != holder_id
            || current.session_binding() == retained_session_binding
        {
            self.current_sessions.insert(holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        let death = installed.session.prove_recovered_execution_dead(
            &self.journal,
            &snapshot,
            &key,
            &record,
            retained.boot_id,
            retained.provider_process_id,
            retained.provider_start_time_ticks,
            retained.provider_process_instance,
            retained.provider_execution_commitment,
        );
        installed.recovered_execution_death = match death {
            Ok(death) => Some(death),
            Err(error) => {
                self.current_sessions.insert(holder_id, installed);
                return Err(error.into());
            }
        };
        self.current_sessions.insert(holder_id, installed);
        Ok(())
    }

    /// Performs observation-only handling for any retained recovery item.
    ///
    /// The method reconstructs immutable plans from the current graph and
    /// never recreates an effect permit, signing authorization, cached reply,
    /// or descriptor-delivery authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, currentness loss,
    /// incomplete lineage, unavailable backend state, or contradiction. A
    /// contradiction poisons the runtime before its best-effort Faulted write.
    pub fn observe_recovery_work<B: SourceProviderBackendV1>(
        &mut self,
        work: ProviderRecoveryWorkV1,
        backend: &mut B,
    ) -> Result<crate::recovery::ProviderRecoveryObservationV1, ProviderLedgerError> {
        self.ensure_open()?;
        let before = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&before)?;
        if !self.recovered.recovery_work.contains(&work) {
            return Err(ProviderLedgerError::InvalidTransition(
                "stale recovery work",
            ));
        }

        let observation = match work {
            ProviderRecoveryWorkV1::ObserveApplying {
                acquisition_id,
                effect_id,
            } => {
                self.observe_recovery_acquire(acquisition_id, Some(effect_id), None, backend)?
            }
            ProviderRecoveryWorkV1::ObservePending {
                acquisition_id,
                backend_id,
            } => {
                self.observe_recovery_acquire(acquisition_id, None, Some(backend_id), backend)?
            }
            ProviderRecoveryWorkV1::ObserveReleasing {
                acquisition_id,
                effect_id,
            } => {
                let acquisition = self
                    .recovered
                    .acquisitions
                    .values()
                    .find(|value| value.acquisition_id == acquisition_id)
                    .cloned()
                    .ok_or(ProviderLedgerError::Corrupt("recovery release acquisition"))?;
                let release = self
                    .recovered
                    .releases
                    .values()
                    .find(|value| value.acquisition_id == acquisition_id)
                    .cloned()
                    .ok_or(ProviderLedgerError::Corrupt("recovery release intent"))?;
                let attempt = self
                    .recovered
                    .attempts
                    .values()
                    .find(|value| value.attempt_digest == release.effect_attempt_digest)
                    .cloned()
                    .ok_or(ProviderLedgerError::Corrupt("recovery Release effect attempt"))?;
                if release.effect_id != effect_id {
                    return Err(ProviderLedgerError::Equivocation);
                }
                let plan = crate::ReleasePlanV1 {
                    provider_id: acquisition.provider.authority_id(),
                    holder_id: acquisition.holder.authority_id(),
                    session_binding: attempt.session_binding,
                    attempt_digest: attempt.attempt_digest,
                    acquisition_id,
                    effect_id,
                    lease_id: release.lease_id,
                    lease_digest: release.lease_digest,
                    backend_id: release.backend_id,
                    acquired_evidence: crate::backend::acquired_evidence(&acquisition)?,
                };
                let backend_observation = backend.observe_release(&plan);
                match self.poison_backend_result(acquisition_id, backend_observation)? {
                    crate::ReleaseObservationV1::StillPresent => {
                        let snapshot = self.journal.snapshot()?;
                        crate::recovery::ProviderRecoveryObservationV1::ReleaseStillPresent(
                            crate::recovery::RecoveryReleaseStillPresentV1 {
                                acquisition_id,
                                effect_id,
                                snapshot,
                            },
                        )
                    }
                    crate::ReleaseObservationV1::Released(_) => {
                        crate::recovery::ProviderRecoveryObservationV1::ReleaseApplied
                    }
                    crate::ReleaseObservationV1::Conflict => {
                        self.record_backend_conflict(acquisition_id)?;
                        return Err(ProviderLedgerError::BackendConflict);
                    }
                }
            }
            ProviderRecoveryWorkV1::ObserveAcquireRebind { acquisition_id, .. }
            | ProviderRecoveryWorkV1::ReopenActive { acquisition_id, .. } => {
                let acquisition = self
                    .recovered
                    .acquisitions
                    .values()
                    .find(|value| value.acquisition_id == acquisition_id)
                    .cloned()
                    .ok_or(ProviderLedgerError::Corrupt("recovery active acquisition"))?;
                let snapshot = crate::ActiveAcquisitionSnapshotV1::from_record(&acquisition)?;
                let backend_observation = backend.reopen_active(&snapshot);
                match self.poison_backend_result(acquisition_id, backend_observation)? {
                    crate::ReopenObservationV1::Reopened(reopened)
                        if snapshot.matches_reopened(&reopened) =>
                    {
                        self.poison_backend_result(
                            acquisition_id,
                            reopened.revalidate_physical(),
                        )?;
                        drop(reopened);
                        crate::recovery::ProviderRecoveryObservationV1::ActiveReopened
                    }
                    crate::ReopenObservationV1::Unavailable => {
                        crate::recovery::ProviderRecoveryObservationV1::Unavailable
                    }
                    crate::ReopenObservationV1::Reopened(_)
                    | crate::ReopenObservationV1::Conflict => {
                        self.record_backend_conflict(acquisition_id)?;
                        return Err(ProviderLedgerError::BackendConflict);
                    }
                }
            }
            ProviderRecoveryWorkV1::ObserveInventoryReservation { .. } => {
                crate::recovery::ProviderRecoveryObservationV1::InventoryRequiresAuthenticatedCompletion
            }
        };
        self.journal
            .validate_source_provider_authority_snapshot(&before)?;
        Ok(observation)
    }

    fn observe_recovery_acquire<B: SourceProviderBackendV1>(
        &mut self,
        acquisition_id: ObjectDigest,
        expected_effect_id: Option<[u8; 16]>,
        expected_backend_id: Option<[u8; 32]>,
        backend: &mut B,
    ) -> Result<crate::recovery::ProviderRecoveryObservationV1, ProviderLedgerError> {
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|value| value.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery acquisition"))?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == acquisition.current_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery Acquire attempt"))?;
        let effect_attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == acquisition.effect_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery Acquire effect attempt",
            ))?;
        if expected_effect_id.is_some_and(|value| value != acquisition.effect_id)
            || expected_backend_id.is_some_and(|value| value != acquisition.backend_id)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let plan = crate::AcquirePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: effect_attempt.session_binding,
            attempt_digest: effect_attempt.attempt_digest,
            acquisition_id,
            effect_id: acquisition.effect_id,
            normalized_intent_digest: acquisition.normalized_intent.digest(),
            kernel_coupled: acquisition.normalized_intent.kernel_coupled(),
            backend_id: acquisition.backend_id,
        };
        let backend_observation = backend.observe_acquire(&plan);
        match self.poison_backend_result(acquisition_id, backend_observation)? {
            crate::AcquireObservationV1::NotApplied => {
                let snapshot = self.journal.snapshot()?;
                Ok(
                    crate::recovery::ProviderRecoveryObservationV1::AcquireNotApplied(
                        crate::recovery::RecoveryAcquireNotAppliedV1 {
                            acquisition_id,
                            effect_id: acquisition.effect_id,
                            snapshot,
                        },
                    ),
                )
            }
            crate::AcquireObservationV1::Applied(observed) => {
                let selection = crate::acquire::validate_backend_selection(
                    self,
                    &acquisition,
                    &attempt,
                    &observed,
                );
                self.poison_backend_result(acquisition_id, selection)?;
                self.poison_backend_result(acquisition_id, observed.revalidate_physical())?;
                drop(observed);
                Ok(crate::recovery::ProviderRecoveryObservationV1::AcquireApplied)
            }
            crate::AcquireObservationV1::Conflict => {
                self.record_backend_conflict(acquisition_id)?;
                Err(ProviderLedgerError::BackendConflict)
            }
        }
    }

    /// Reissues one exact recovered acquire effect after absence and death proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] unless the observation is current, the
    /// durable effect remains Applying, the prior provider execution is proven
    /// dead, an exact replay installed fresh request authorization, and worst-
    /// case completion capacity is available.
    pub fn reissue_recovered_acquire(
        &mut self,
        absent: crate::RecoveryAcquireNotAppliedV1,
    ) -> Result<crate::DurableAcquireEffectPermitV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&absent.snapshot)?;
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|value| value.acquisition_id == absent.acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery acquire"))?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == acquisition.current_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery acquire attempt"))?;
        let effect_attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == acquisition.effect_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery acquire effect attempt",
            ))?;
        let session = self
            .recovered
            .session_history
            .get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
                effect_attempt.session_binding,
            ))
            .ok_or(ProviderLedgerError::Corrupt("recovery acquire session"))?;
        let death_matches = self
            .current_sessions
            .get(&acquisition.holder.authority_id())
            .ok_or(ProviderLedgerError::InvalidTransition(
                "fresh quarantined recovery session required",
            ))?
            .recovered_execution_death
            .as_ref()
            .is_some_and(|death| {
                death.matches(
                    session.boot_id,
                    session.provider_process_id,
                    session.provider_start_time_ticks,
                    session.provider_process_instance,
                )
            });
        if acquisition.state != crate::ProviderAcquisitionStateV1::Applying
            || acquisition.effect_id != absent.effect_id
            || attempt.state != crate::ProviderAttemptStateV1::Reserved
            || !death_matches
            || !self
                .recovery_authorizations
                .contains_key(&attempt.attempt_digest)
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "recovered acquire is not exclusively reissuable",
            ));
        }
        let reservation_digest = recovery_effect_digest(
            b"reissue-acquire",
            acquisition.acquisition_id,
            acquisition.effect_id,
            attempt.attempt_digest,
        );
        let completion_capacity = crate::transaction::preflight_completion_capacity(
            &self.journal,
            b"complete-recovered-acquire",
            reservation_digest,
            crate::limits::MAXIMUM_ACQUIRE_COMPLETION_BYTES,
        )?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let authorization = self
            .recovery_authorizations
            .remove(&attempt.attempt_digest)
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        Ok(crate::DurableAcquireEffectPermitV1 {
            plan: crate::AcquirePlanV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                session_binding: effect_attempt.session_binding,
                attempt_digest: effect_attempt.attempt_digest,
                acquisition_id: acquisition.acquisition_id,
                effect_id: acquisition.effect_id,
                normalized_intent_digest: acquisition.normalized_intent.digest(),
                kernel_coupled: acquisition.normalized_intent.kernel_coupled(),
                backend_id: acquisition.backend_id,
            },
            completion_session_binding: attempt.session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot: snapshot,
            completion_capacity,
            signing_authorization: authorization,
        })
    }

    /// Reissues one exact recovered release effect after presence and death proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] unless the observation is current, the
    /// durable release remains Releasing, the prior provider execution is
    /// proven dead, an exact replay installed fresh request authorization,
    /// and worst-case completion capacity is available.
    pub fn reissue_recovered_release(
        &mut self,
        present: crate::RecoveryReleaseStillPresentV1,
    ) -> Result<crate::DurableReleaseEffectPermitV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&present.snapshot)?;
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|value| value.acquisition_id == present.acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery release acquisition"))?;
        let release = self
            .recovered
            .releases
            .values()
            .find(|value| value.acquisition_id == present.acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery release intent"))?;
        let effect_attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == release.effect_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery release effect attempt",
            ))?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == release.attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery release current attempt",
            ))?;
        let session = self
            .recovered
            .session_history
            .get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
                effect_attempt.session_binding,
            ))
            .ok_or(ProviderLedgerError::Corrupt("recovery release session"))?;
        let death_matches = self
            .current_sessions
            .get(&acquisition.holder.authority_id())
            .ok_or(ProviderLedgerError::InvalidTransition(
                "fresh quarantined recovery session required",
            ))?
            .recovered_execution_death
            .as_ref()
            .is_some_and(|death| {
                death.matches(
                    session.boot_id,
                    session.provider_process_id,
                    session.provider_start_time_ticks,
                    session.provider_process_instance,
                )
            });
        if acquisition.state != crate::ProviderAcquisitionStateV1::Releasing
            || release.state != crate::ProviderReleaseStateV1::Intent
            || release.effect_id != present.effect_id
            || acquisition.release_effect_id != Some(present.effect_id)
            || attempt.state != crate::ProviderAttemptStateV1::Reserved
            || !death_matches
            || !self
                .recovery_authorizations
                .contains_key(&attempt.attempt_digest)
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "recovered release is not exclusively reissuable",
            ));
        }
        let reservation_digest = recovery_effect_digest(
            b"reissue-release",
            acquisition.acquisition_id,
            release.effect_id,
            attempt.attempt_digest,
        );
        let completion_capacity = crate::transaction::preflight_completion_capacity(
            &self.journal,
            b"complete-release",
            reservation_digest,
            crate::limits::MAXIMUM_RELEASE_COMPLETION_BYTES,
        )?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let acquired_evidence = crate::backend::acquired_evidence(&acquisition)?;
        let authorization = self
            .recovery_authorizations
            .remove(&attempt.attempt_digest)
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        Ok(crate::DurableReleaseEffectPermitV1 {
            plan: crate::ReleasePlanV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                session_binding: effect_attempt.session_binding,
                attempt_digest: effect_attempt.attempt_digest,
                acquisition_id: acquisition.acquisition_id,
                effect_id: release.effect_id,
                lease_id: release.lease_id,
                lease_digest: release.lease_digest,
                backend_id: release.backend_id,
                acquired_evidence,
            },
            completion_session_binding: attempt.session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot: snapshot,
            completion_capacity,
            signing_authorization: authorization,
        })
    }

    pub(crate) fn consume_recovered_execution_death(
        &mut self,
        holder_id: [u8; 16],
    ) -> Result<(), ProviderLedgerError> {
        self.current_sessions
            .get_mut(&holder_id)
            .ok_or(ProviderLedgerError::RuntimePoisoned)?
            .recovered_execution_death
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        Ok(())
    }

    /// Resumes an exact recovered Inventory reservation without effect authority.
    ///
    /// The returned permit authorizes reopen-only inventory construction. It
    /// exists only after an exact request replay has installed fresh current
    /// signing authorization and after completion capacity is re-preflighted.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, a nonreserved attempt,
    /// missing current authorization, session drift, or unavailable capacity.
    pub fn resume_recovered_inventory(
        &mut self,
        work: ProviderRecoveryWorkV1,
    ) -> Result<crate::DurableInventoryPermitV1, ProviderLedgerError> {
        self.ensure_open()?;
        if !self.recovered.recovery_work.contains(&work) {
            return Err(ProviderLedgerError::InvalidTransition(
                "stale Inventory recovery work",
            ));
        }
        let attempt_digest = match work {
            ProviderRecoveryWorkV1::ObserveInventoryReservation { attempt_digest } => {
                attempt_digest
            }
            _ => {
                return Err(ProviderLedgerError::InvalidTransition(
                    "recovery work is not Inventory",
                ));
            }
        };
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("recovery Inventory attempt"))?;
        let holder_id = attempt.holder.authority_id();
        let session = self
            .recovered
            .sessions
            .get(&(attempt.provider.authority_id(), holder_id))
            .ok_or(ProviderLedgerError::Corrupt("recovery Inventory session"))?;
        if attempt.method != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            || attempt.state != crate::ProviderAttemptStateV1::Reserved
            || attempt.holder.authority_id() != holder_id
            || session.session_binding != attempt.session_binding
            || session.pending_attempt_digest != Some(attempt_digest)
            || !self.recovery_authorizations.contains_key(&attempt_digest)
        {
            return Err(ProviderLedgerError::Corrupt(
                "recovery Inventory reservation graph",
            ));
        }
        let reservation_digest = recovery_effect_digest(
            b"resume-inventory",
            attempt.operation_intent_digest,
            [0; 16],
            attempt.attempt_digest,
        );
        let completion_capacity = crate::transaction::preflight_completion_capacity(
            &self.journal,
            b"complete-inventory",
            reservation_digest,
            crate::limits::MAXIMUM_INVENTORY_COMPLETION_BYTES,
        )?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let authorization = self
            .recovery_authorizations
            .remove(&attempt_digest)
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        Ok(crate::DurableInventoryPermitV1 {
            holder_id,
            session_binding: attempt.session_binding,
            attempt_digest,
            reservation_digest,
            journal_snapshot: snapshot,
            completion_capacity,
            signing_authorization: authorization,
        })
    }

    /// Completes an already-applied recovered Acquire after fresh observation.
    ///
    /// This path cannot execute the backend. It observes the exact durable
    /// effect again, consumes fresh exact-replay authorization, and passes an
    /// internal completion-only permit directly to the owner reducer.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, absent or contradictory
    /// backend state, missing current authorization, session drift, or failure
    /// to durably commit the terminal response.
    pub fn complete_recovered_acquire_applied<B: SourceProviderBackendV1>(
        &mut self,
        work: ProviderRecoveryWorkV1,
        backend: &mut B,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        if !self.recovered.recovery_work.contains(&work) {
            return Err(ProviderLedgerError::InvalidTransition(
                "stale Acquire recovery work",
            ));
        }
        let (acquisition_id, effect_id) = match work {
            ProviderRecoveryWorkV1::ObserveApplying {
                acquisition_id,
                effect_id,
            } => (acquisition_id, effect_id),
            _ => {
                return Err(ProviderLedgerError::InvalidTransition(
                    "recovery work is not Applying",
                ));
            }
        };
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|value| value.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery acquisition"))?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == acquisition.current_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery Acquire attempt"))?;
        let effect_attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == acquisition.effect_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery Acquire effect attempt",
            ))?;
        if acquisition.state != crate::ProviderAcquisitionStateV1::Applying
            || acquisition.effect_id != effect_id
            || attempt.state != crate::ProviderAttemptStateV1::Reserved
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "recovered Acquire is not completable",
            ));
        }
        let plan = crate::AcquirePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: effect_attempt.session_binding,
            attempt_digest: effect_attempt.attempt_digest,
            acquisition_id,
            effect_id,
            normalized_intent_digest: acquisition.normalized_intent.digest(),
            kernel_coupled: acquisition.normalized_intent.kernel_coupled(),
            backend_id: acquisition.backend_id,
        };
        let backend_observation = backend.observe_acquire(&plan);
        let observed = match self.poison_backend_result(acquisition_id, backend_observation)? {
            crate::AcquireObservationV1::Applied(observed) => observed,
            crate::AcquireObservationV1::NotApplied => {
                return Err(ProviderLedgerError::Unavailable);
            }
            crate::AcquireObservationV1::Conflict => {
                self.record_backend_conflict(acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
        };
        let selection =
            crate::acquire::validate_backend_selection(self, &acquisition, &attempt, &observed);
        self.poison_backend_result(acquisition_id, selection)?;
        self.poison_backend_result(acquisition_id, observed.revalidate_physical())?;
        if !self
            .recovery_authorizations
            .contains_key(&attempt.attempt_digest)
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "fresh authenticated replay authorization required",
            ));
        }
        let reservation_digest = recovery_effect_digest(
            b"complete-observed-acquire",
            acquisition_id,
            effect_id,
            attempt.attempt_digest,
        );
        let completion_capacity = crate::transaction::preflight_completion_capacity(
            &self.journal,
            b"complete-acquire",
            reservation_digest,
            crate::limits::MAXIMUM_ACQUIRE_COMPLETION_BYTES,
        )?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let authorization = self
            .recovery_authorizations
            .remove(&attempt.attempt_digest)
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let permit = crate::DurableAcquireEffectPermitV1 {
            plan,
            completion_session_binding: attempt.session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot: snapshot,
            completion_capacity,
            signing_authorization: authorization,
        };
        let holder_id = acquisition.holder.authority_id();
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current recovery session"),
        )?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != attempt.session_binding {
            self.current_sessions.insert(holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        let result =
            crate::acquire::complete_acquire(self, permit, observed, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result
    }

    /// Completes an already-applied recovered Release after fresh observation.
    ///
    /// This path never recreates execution authority and accepts only the
    /// backend's exact sealed terminal observation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, a nonterminal backend
    /// observation, missing current authorization, session drift, or failure
    /// to durably commit the tombstone and exact response.
    pub fn complete_recovered_release_applied<B: SourceProviderBackendV1>(
        &mut self,
        work: ProviderRecoveryWorkV1,
        backend: &mut B,
    ) -> Result<(DurableProviderReplyV1, crate::DurableReleaseTombstoneV1), ProviderLedgerError>
    {
        self.ensure_open()?;
        if !self.recovered.recovery_work.contains(&work) {
            return Err(ProviderLedgerError::InvalidTransition(
                "stale Release recovery work",
            ));
        }
        let (acquisition_id, effect_id) = match work {
            ProviderRecoveryWorkV1::ObserveReleasing {
                acquisition_id,
                effect_id,
            } => (acquisition_id, effect_id),
            _ => {
                return Err(ProviderLedgerError::InvalidTransition(
                    "recovery work is not Releasing",
                ));
            }
        };
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|value| value.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery release acquisition"))?;
        let release = self
            .recovered
            .releases
            .values()
            .find(|value| value.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("recovery release intent"))?;
        let effect_attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == release.effect_attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery Release effect attempt",
            ))?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|value| value.attempt_digest == release.attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery Release current attempt",
            ))?;
        if acquisition.state != crate::ProviderAcquisitionStateV1::Releasing
            || release.state != crate::ProviderReleaseStateV1::Intent
            || release.effect_id != effect_id
            || attempt.state != crate::ProviderAttemptStateV1::Reserved
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "recovered Release is not completable",
            ));
        }
        let plan = crate::ReleasePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: effect_attempt.session_binding,
            attempt_digest: effect_attempt.attempt_digest,
            acquisition_id,
            effect_id,
            lease_id: release.lease_id,
            lease_digest: release.lease_digest,
            backend_id: release.backend_id,
            acquired_evidence: crate::backend::acquired_evidence(&acquisition)?,
        };
        let backend_observation = backend.observe_release(&plan);
        let observed = match self.poison_backend_result(acquisition_id, backend_observation)? {
            crate::ReleaseObservationV1::Released(observed) => observed,
            crate::ReleaseObservationV1::StillPresent => {
                return Err(ProviderLedgerError::Unavailable);
            }
            crate::ReleaseObservationV1::Conflict => {
                self.record_backend_conflict(acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
        };
        if !self
            .recovery_authorizations
            .contains_key(&attempt.attempt_digest)
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "fresh authenticated replay authorization required",
            ));
        }
        let reservation_digest = recovery_effect_digest(
            b"complete-observed-release",
            acquisition_id,
            effect_id,
            attempt.attempt_digest,
        );
        let completion_capacity = crate::transaction::preflight_completion_capacity(
            &self.journal,
            b"complete-release",
            reservation_digest,
            crate::limits::MAXIMUM_RELEASE_COMPLETION_BYTES,
        )?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let authorization = self
            .recovery_authorizations
            .remove(&attempt.attempt_digest)
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let permit = crate::DurableReleaseEffectPermitV1 {
            plan,
            completion_session_binding: attempt.session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot: snapshot,
            completion_capacity,
            signing_authorization: authorization,
        };
        let holder_id = acquisition.holder.authority_id();
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current recovery session"),
        )?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != attempt.session_binding {
            self.current_sessions.insert(holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        let result =
            crate::release::complete_release(self, permit, observed, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result
    }
}
