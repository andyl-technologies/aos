//! Fixed Mount owner custody for SourceProvider exchanges and recovery.
//!
//! The same owner retains exact request, reply, SourceRoot and postcommit
//! capabilities while borrowing its original protected journal. Live reply
//! consumption, captured historical recovery and persisted historical recovery
//! keep separate authentication paths; none redispatches a historical request.
//! Table-level reservation and atomic reducers remain in their focused modules.
//! Manager startup and handoff custody remain with the parent owner.

use super::FixedMountSourceAcquisitionOwnerV2;
use super::RetainedSourcePostcommitRecoveryV2;
use super::format::state_error;
use super::lifecycle::SourceAcquisitionPostcommitOutcomeV2;
use super::model::{
    ProviderAttemptStateV2, ProviderMethodV2, ProviderStatusV2, SourceAcquisitionPhaseV2,
};
use super::outcome::{ConsumedProviderOutcomeV2, RecoveredProviderOutcomeConsumptionV2};
use super::reservation::ReservedProviderQueryV2;
use crate::Result;

impl<'journal> FixedMountSourceAcquisitionOwnerV2<'journal> {
    /// Reserves and sends one read-only Inventory on the separate provider session.
    ///
    /// A cold or live attempt must be resolved before a new query. The request
    /// is table-derived and durably reserved before its atomic carrier send;
    /// no in-process provider owner or backend transport is accepted.
    ///
    /// # Errors
    ///
    /// Rejects unresolved recovery, a nonidle provider head, stale custody,
    /// failed reservation, or an incomplete send. Send recovery remains owned
    /// by this value until the caller restarts or retries the exact reservation.
    #[doc(hidden)]
    pub fn prepare_and_send_remote_inventory(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        if self.has_cold_provider_recovery()
            || self.runtime.pending_provider.is_some()
            || self.runtime.pending_provider_send.is_some()
            || self.runtime.pending_remote_inventory_outcome.is_some()
            || self
                .runtime
                .pending_inventory_recovery_replacement
                .is_some()
        {
            return Err(state_error(
                "remote Inventory requires an idle provider head",
            ));
        }

        let sent = root
            .with_current_session(|session| {
                let (holder, provider, deadline) = session
                    .current_authority_scope_v2()
                    .map_err(|_| state_error("Root-Mount provider session is stale"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        Ok(table
                            .prepare_and_reserve_inventory_v2(
                                journal, session, holder, provider, None, deadline,
                            )?
                            .send(journal, session))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        match sent {
            Ok(sent) => {
                self.runtime.pending_provider = Some(sent);
                Ok(())
            }
            Err(recovery) => {
                self.runtime.pending_provider_send = Some(recovery);
                Err(state_error("remote Inventory send requires exact retry"))
            }
        }
    }

    /// Advances the exact signed, descriptor-free remote Inventory reply.
    ///
    /// `Ok(false)` preserves the sent request without retransmission. A
    /// verified reply is retained across an ambiguous Mount journal commit;
    /// callers must not start another query until exact recovery completes.
    ///
    /// # Errors
    ///
    /// Rejects a missing request, changed session, bad descriptor role or
    /// signature, or failed protected commit. The durable Reserved row remains
    /// the crash-recovery boundary when a response cannot be read back.
    #[doc(hidden)]
    pub fn advance_remote_inventory(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<bool> {
        self.require_no_original_native_flight()?;
        let sent = self
            .runtime
            .pending_provider
            .take()
            .ok_or_else(|| state_error("no remote Inventory request is outstanding"))?;
        let attempt_id = sent.attempt_id();
        let verified = match self.runtime.pending_remote_inventory_outcome.take() {
            Some(verified) => verified,
            None => {
                let (_, authorization) = sent.security_parts();
                let received = root
                    .with_current_session(|session| {
                        session.advance_remote_inventory_outcome_v2(authorization)
                    })
                    .map_err(|_| state_error("Root-Mount provider session is not current"))
                    .and_then(|value| {
                        value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
                    })
                    .and_then(|value| {
                        value.map_err(|_| state_error("remote Inventory reply was rejected"))
                    });
                match received {
                    Ok(Some(verified)) => verified,
                    Ok(None) => {
                        self.runtime.pending_provider = Some(sent);
                        return Ok(false);
                    }
                    Err(error) => {
                        self.runtime.pending_provider = Some(sent);
                        return Err(error);
                    }
                }
            }
        };

        let committed = root
            .with_current_session(|session| {
                session
                    .current_authority_scope_v2()
                    .map_err(|_| state_error("Root-Mount provider session is stale"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.consume_remote_inventory_outcome_v2(journal, attempt_id, &verified)
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        if let Err(error) = committed {
            self.runtime.pending_provider = Some(sent);
            self.runtime.pending_remote_inventory_outcome = Some(verified);
            return Err(error);
        }
        Ok(true)
    }

    /// Reauthenticates one old Reserved Inventory through protected remote readback.
    ///
    /// The old signed request is never sent on the successor carrier. Provider
    /// may attest only its exact protected Completed response; Mount then runs
    /// the existing historical response verifier against namespace 40 before
    /// committing the disposition. `Ok(false)` retains the old Reserved row.
    /// A commit that completed before a crash is terminal on journal replay.
    ///
    /// # Errors
    ///
    /// Rejects a non-Inventory barrier, signed Unavailable, stale session,
    /// mismatched protected history, or ambiguous commit. An ambiguous commit
    /// requires restart and exact journal replay, not a new Inventory send.
    #[doc(hidden)]
    pub fn advance_remote_cold_inventory_readback(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<bool> {
        self.require_no_original_native_flight()?;
        if self.runtime.pending_provider.is_some() || self.runtime.pending_provider_send.is_some() {
            return Err(state_error("live provider custody must be resolved first"));
        }
        let signed = self.cold_reserved_provider_request()?;
        if signed.method() != aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
        {
            return Err(state_error("oldest cold attempt is not Inventory"));
        }
        let attempt_id = *self
            .runtime
            .cold_pending_attempts
            .first()
            .ok_or_else(|| state_error("cold Inventory barrier is absent"))?;
        let attempt = self
            .runtime
            .table
            .provider_attempts
            .get(&attempt_id)
            .ok_or_else(|| state_error("cold Inventory attempt is absent"))?;
        let provider_id = attempt.scope.provider_authority_id;
        let holder_id = attempt.scope.holder_authority_id;
        let signed_request_digest =
            aos_sandbox_source_provider_protocol::digest_signed_request(&signed);
        let attempt_record_digest =
            aos_sandbox_core::ObjectDigest::from_bytes(attempt.record_digest);
        let progress = root
            .with_current_session(|session| {
                session.advance_inventory_readback(
                    provider_id,
                    holder_id,
                    signed_request_digest,
                    attempt_record_digest,
                )
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))?
            .map_err(|_| state_error("remote Inventory readback was rejected"))?;
        let captured = match progress {
            aos_sandbox_source_provider_security::InventoryReadbackProgressV1::Pending => {
                return Ok(false);
            }
            aos_sandbox_source_provider_security::InventoryReadbackProgressV1::Unavailable => {
                return Err(state_error("Provider did not prove a completed Inventory"));
            }
            aos_sandbox_source_provider_security::InventoryReadbackProgressV1::Completed(
                captured,
            ) => captured,
        };
        let recovered = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.recover_and_consume_provider_outcome_v2(
                            journal, None, session, attempt_id, captured,
                        )
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        self.retain_recovered_provider_outcome(
            [0; 32],
            ProviderMethodV2::Inventory,
            recovered,
            "Inventory cannot retain SourceRoot postcommit custody",
        )?;
        Ok(true)
    }

    /// Retries the exact request whose first carrier send did not complete.
    ///
    /// # Errors
    ///
    /// Returns an error and restores the same move-only reservation when the
    /// current protected session, journal readback, or carrier remains unavailable.
    #[doc(hidden)]
    pub fn retry_pending_provider_send(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        let recovery = self
            .runtime
            .pending_provider_send
            .take()
            .ok_or_else(|| state_error("no SourceProvider send recovery is retained"))?;
        let mut retained = Some(recovery);
        let sent = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|_table, authority| {
                    authority.with_authority(|journal| {
                        let recovery = retained.take().ok_or_else(|| {
                            state_error("SourceProvider send recovery was already consumed")
                        })?;
                        Ok(recovery.retry(journal, session))
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        match sent {
            Ok(Ok(sent)) => {
                self.runtime.pending_provider = Some(sent);
                Ok(())
            }
            Ok(Err(recovery)) => {
                self.runtime.pending_provider_send = Some(recovery);
                Err(state_error("SourceProvider request send remains pending"))
            }
            Err(error) => {
                if let Some(recovery) = retained {
                    self.runtime.pending_provider_send = Some(recovery);
                }
                Err(error)
            }
        }
    }

    /// Consumes the exact response for the owner-retained sent request.
    ///
    /// Any Complete Acquire SourceRoot stays in this fixed owner rather than
    /// being returned as a raw descriptor or dropped after broker success.
    ///
    /// # Errors
    ///
    /// Returns an error when no request is outstanding or protected response,
    /// catalog, journal, descriptor, or session validation fails.
    #[doc(hidden)]
    pub fn consume_sent_provider_outcome(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        let sent = self
            .runtime
            .pending_provider
            .take()
            .ok_or_else(|| state_error("no SourceProvider request is outstanding"))?;
        let (acquisition_id, provider_method) = self
            .runtime
            .table
            .provider_attempts
            .get(&sent.attempt_id())
            .map(|attempt| (attempt.owner.owner_id(), attempt.method))
            .ok_or_else(|| state_error("outstanding SourceProvider attempt is absent"))?;
        let consumed = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.consume_provider_outcome_v2(journal, catalog_journal, session, &sent)
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let consumed = match consumed {
            Ok(consumed) => consumed,
            Err(error) => {
                self.runtime.pending_provider = Some(sent);
                return Err(error);
            }
        };
        match consumed {
            ConsumedProviderOutcomeV2::WithoutSourceRoot { outcome } => {
                if provider_method == ProviderMethodV2::Release
                    && outcome.status()
                        == aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.runtime
                        .retained_terminal_release_outcomes
                        .insert(acquisition_id, outcome);
                } else if outcome.status()
                    != aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.runtime
                        .retained_noncomplete_dispositions
                        .insert((acquisition_id, provider_method.tag()), outcome);
                }
            }
            ConsumedProviderOutcomeV2::CompleteAcquire { postcommit } => match postcommit {
                SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                    self.runtime
                        .retained_source_roots
                        .insert(acquisition_id, source_root);
                }
                SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                    self.runtime.retained_postcommit_recovery.push(
                        RetainedSourcePostcommitRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_acquire_terminal: None,
                        },
                    );
                    return Err(state_error("SourceRoot postcommit recovery is required"));
                }
            },
        }
        Ok(())
    }

    /// Receives and resumes the next durable provider attempt after cold reopen.
    ///
    /// The attempt and historical session are selected exclusively from the
    /// recovered namespace-40 graph. No request is rebuilt or redispatched;
    /// the current protected Root-Mount carrier captures the provider's exact
    /// response and the historical recovery verifier binds it to that attempt.
    ///
    /// # Errors
    ///
    /// Returns an error unless a queued durable attempt awaits an outcome, the
    /// protected carrier supplies its canonical response, and historical trust,
    /// journal, catalog, and descriptor recovery all agree.
    #[doc(hidden)]
    pub fn recover_cold_provider_outcome(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        if self.runtime.pending_provider.is_some() {
            return Err(state_error(
                "live SourceProvider response custody must be resumed directly",
            ));
        }
        let attempt_id = self
            .runtime
            .cold_pending_attempts
            .first()
            .copied()
            .ok_or_else(|| state_error("no durable SourceProvider attempt awaits recovery"))?;
        let attempt = self
            .runtime
            .table
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| {
                matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    || (matches!(
                        attempt.method,
                        ProviderMethodV2::Acquire | ProviderMethodV2::Release
                    ) && matches!(
                        attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed { .. }
                    ))
            })
            .ok_or_else(|| state_error("cold recovery barrier differs from durable state"))?;
        let acquisition_id = attempt.owner.owner_id();
        let provider_method = attempt.method;
        let complete_acquire_requires_startup_manager = provider_method
            == ProviderMethodV2::Acquire
            && matches!(
                attempt.state,
                ProviderAttemptStateV2::DispositionConsumed {
                    status: ProviderStatusV2::Complete,
                    ..
                }
            )
            && self
                .runtime
                .table
                .acquisitions
                .get(&acquisition_id)
                .is_some_and(|row| row.phase != SourceAcquisitionPhaseV2::PendingQuery);
        if complete_acquire_requires_startup_manager {
            return Err(state_error(
                "cold held SourceRoot requires protected manager startup custody",
            ));
        }
        let method = match provider_method {
            ProviderMethodV2::Acquire => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            }
            ProviderMethodV2::Release => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            }
            ProviderMethodV2::Inventory => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            }
        };
        let recovered = root
            .with_current_session(|session| {
                let captured = session
                    .capture_mount_provider_recovery_outcome_v2(method)
                    .map_err(|_| state_error("protected recovery receive failed"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.recover_and_consume_provider_outcome_v2(
                            journal,
                            Some(catalog_journal),
                            session,
                            attempt_id,
                            captured,
                        )
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        self.retain_recovered_provider_outcome(
            acquisition_id,
            provider_method,
            recovered,
            "cold-recovered SourceRoot postcommit recovery is required",
        )
    }

    /// Reauthenticates a replay-validated persisted Provider outcome.
    ///
    /// Provider bytes and any reopened SourceRoot remain nonauthorizing until
    /// the current Root-Mount owner binds them to the exact oldest protected
    /// attempt and historical session. This path performs no carrier receive
    /// and never sends a historical response on a successor session.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical Provider evidence, cold-order drift,
    /// failed historical authentication, or ambiguous SourceRoot postcommit.
    #[doc(hidden)]
    pub fn recover_persisted_cold_provider_outcome(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        historical: aos_sandbox_source_provider::FixedProviderHistoricalOutcomeV1,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        if self.runtime.pending_provider.is_some() {
            return Err(state_error(
                "live SourceProvider response custody must be resumed directly",
            ));
        }
        let attempt_id = self
            .runtime
            .cold_pending_attempts
            .first()
            .copied()
            .ok_or_else(|| state_error("no durable SourceProvider attempt awaits recovery"))?;
        let attempt = self
            .runtime
            .table
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| {
                matches!(
                    attempt.state,
                    ProviderAttemptStateV2::Reserved
                        | ProviderAttemptStateV2::DispositionConsumed { .. }
                )
            })
            .ok_or_else(|| state_error("cold recovery barrier differs from durable state"))?;
        let acquisition_id = attempt.owner.owner_id();
        let provider_method = attempt.method;
        let method = match provider_method {
            ProviderMethodV2::Acquire => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire
            }
            ProviderMethodV2::Release => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Release
            }
            ProviderMethodV2::Inventory => {
                aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            }
        };
        let (response, source_root, persisted) = historical
            .into_security_parts()
            .map_err(|_| state_error("persisted Provider SourceRoot revalidation failed"))?;
        let recovered = root
            .with_current_session(|session| {
                let captured = session
                    .capture_persisted_mount_provider_outcome_v2(
                        method,
                        response,
                        source_root,
                        persisted,
                    )
                    .map_err(|_| state_error("persisted Provider outcome capture failed"))?;
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        table.recover_and_consume_provider_outcome_v2(
                            journal,
                            Some(catalog_journal),
                            session,
                            attempt_id,
                            captured,
                        )
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))?
            .ok_or_else(|| state_error("Root-Mount provider handshake is pending"))??;
        self.retain_recovered_provider_outcome(
            acquisition_id,
            provider_method,
            recovered,
            "persisted SourceRoot postcommit recovery is required",
        )
    }

    // Both recovery paths reach this custody update only after their distinct
    // carrier or persisted-evidence checks have produced an authenticated result.
    fn retain_recovered_provider_outcome(
        &mut self,
        acquisition_id: [u8; 32],
        provider_method: ProviderMethodV2,
        recovered: RecoveredProviderOutcomeConsumptionV2,
        postcommit_error: &'static str,
    ) -> Result<()> {
        self.runtime.cold_pending_attempts.remove(0);
        match recovered {
            RecoveredProviderOutcomeConsumptionV2::WithoutSourceRoot { outcome } => {
                if provider_method == ProviderMethodV2::Release
                    && outcome.status()
                        == aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.runtime.retained_terminal_release_outcomes
                        .insert(acquisition_id, outcome);
                } else if outcome.status()
                    != aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                {
                    self.runtime.retained_noncomplete_dispositions
                        .insert((acquisition_id, provider_method.tag()), outcome);
                }
            }
            RecoveredProviderOutcomeConsumptionV2::CompleteAcquire { postcommit } => {
                match postcommit {
                    SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                        self.runtime.retained_source_roots
                            .insert(acquisition_id, source_root);
                    }
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                        self.runtime.retained_postcommit_recovery
                            .push(RetainedSourcePostcommitRecoveryV2 {
                                acquisition_id,
                                recovery,
                                startup_acquire_terminal: None,
                            });
                        return Err(state_error(postcommit_error));
                    }
                }
            }
            RecoveredProviderOutcomeConsumptionV2::RetainedSourceRoot { source_root } => {
                match source_root {
                    aos_sandbox_source_provider_security::RecoveredRetainedMountSourceRootV2::Releasing(
                        authority,
                    ) => self.runtime.retained_release_authorities.push(authority),
                    source_root => {
                        self.runtime.retained_source_roots.insert(
                            acquisition_id,
                            aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::StartupAdopted(
                                source_root,
                            ),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolves one retained SourceRoot postcommit ambiguity by readback.
    ///
    /// A successful retained source is restored to this owner. A successful
    /// Release reservation is sent through the same current Root-Mount session
    /// and its response verifier and release authority remain here. Any still
    /// ambiguous seal is reinserted without re-executing the provider effect.
    ///
    /// # Errors
    ///
    /// Returns an error when no recovery exists, the fixed session or journal
    /// is stale, resealing remains ambiguous, or a recovered Release cannot be
    /// correlated and sent through its exact reservation.
    #[doc(hidden)]
    pub fn resolve_next_postcommit_recovery(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        if let Some(retained) = self.runtime.retained_postcommit_recovery.last()
            && let Some(terminal) = retained.startup_acquire_terminal
            && self.exact_complete_terminal_attempt(
                retained.acquisition_id,
                ProviderMethodV2::Acquire,
            )? != Some(terminal)
        {
            return Err(state_error(
                "startup SourceRoot recovery terminal lineage differs",
            ));
        }
        let retained_recovery = self
            .runtime
            .retained_postcommit_recovery
            .pop()
            .ok_or_else(|| state_error("no SourceRoot postcommit recovery is retained"))?;
        let acquisition_id = retained_recovery.acquisition_id;
        let startup_acquire_terminal = retained_recovery.startup_acquire_terminal;
        let recovery = retained_recovery.recovery;
        let mut unentered_recovery = Some(recovery);
        let resolved = root
            .with_current_session(|session| {
                self.with_source_acquisition_authority(|table, authority| {
                    authority.with_authority(|journal| {
                        let recovery = unentered_recovery.take().ok_or_else(|| {
                            state_error("SourceRoot postcommit recovery was already consumed")
                        })?;
                        match table.reseal_source_root_postcommit_v2(journal, session, recovery) {
                            SourceAcquisitionPostcommitOutcomeV2::Success(
                                aos_sandbox_source_provider_security::SourceRootPostcommitSuccessV2::Releasing(
                                    committed,
                                ),
                            ) => {
                                let (release_authority, reservation) = committed.into_parts();
                                let attempt_id = table
                                    .provider_attempts
                                    .values()
                                    .find(|attempt| {
                                        attempt.owner.owner_id() == acquisition_id
                                            && attempt.method == ProviderMethodV2::Release
                                            && matches!(
                                                attempt.state,
                                                ProviderAttemptStateV2::Reserved
                                            )
                                    })
                                    .map(|attempt| attempt.attempt_id)
                                    .ok_or_else(|| {
                                        state_error(
                                            "recovered provider Release attempt is absent",
                                        )
                                    })?;
                                let send = ReservedProviderQueryV2::from_reserved(
                                    attempt_id,
                                    reservation,
                                )
                                .send(journal, session);
                                Ok(Ok((None, Some((send, release_authority)))))
                            }
                            SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                                Ok(Ok((Some(source_root), None)))
                            }
                            SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(recovery) => {
                                Ok(Err(recovery))
                            }
                        }
                    })
                })
            })
            .map_err(|_| state_error("Root-Mount provider session is not current"))
            .and_then(|value| {
                value.ok_or_else(|| state_error("Root-Mount provider handshake is pending"))
            })
            .and_then(core::convert::identity);
        let resolved = match resolved {
            Ok(resolved) => resolved,
            Err(error) => {
                if let Some(recovery) = unentered_recovery {
                    self.runtime.retained_postcommit_recovery.push(
                        RetainedSourcePostcommitRecoveryV2 {
                            acquisition_id,
                            recovery,
                            startup_acquire_terminal,
                        },
                    );
                }
                return Err(error);
            }
        };
        match resolved {
            Ok((source_root, sent_release)) => {
                if let Some(source_root) = source_root {
                    self.runtime
                        .retained_source_roots
                        .insert(acquisition_id, source_root);
                    if let Some(terminal) = startup_acquire_terminal {
                        self.resolve_superseded_cold_attempt(terminal);
                    }
                }
                if let Some((send, release_authority)) = sent_release {
                    self.runtime
                        .retained_release_authorities
                        .push(release_authority);
                    match send {
                        Ok(sent) => self.runtime.pending_provider = Some(sent),
                        Err(recovery) => self.runtime.pending_provider_send = Some(recovery),
                    }
                }
                Ok(())
            }
            Err(recovery) => {
                self.runtime.retained_postcommit_recovery.push(
                    RetainedSourcePostcommitRecoveryV2 {
                        acquisition_id,
                        recovery,
                        startup_acquire_terminal,
                    },
                );
                Err(state_error(
                    "SourceRoot postcommit recovery remains ambiguous",
                ))
            }
        }
    }
}
