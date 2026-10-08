//! Protected remote assignment commit, recovery, and sealed effect handoff.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Opens a monotonic evidence-verifier child by consuming its protected row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] unless the row belongs to this exact
    /// protected owner and retains a current authenticated verifier context.
    pub fn open_evidence_session(
        &mut self,
        protected_record: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<ProtectedMultiNodeEvidenceSessionV1, InvalidMultiNodeJournal> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !self.store.backend.protects_record(&protected_record.record) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let integration = ProtectedEvidenceIntegrationV1::from_protected_record(
            protected_record.record,
            verified_at_unix_seconds,
        )?;
        Ok(ProtectedMultiNodeEvidenceSessionV1 { integration })
    }

    /// Issues a crate-internal evidence grant under a freshly advanced clock floor.
    pub(in crate::local_inventory) fn issue_verified_evidence_once<T>(
        &mut self,
        session: &mut ProtectedMultiNodeEvidenceSessionV1,
        value: T,
    ) -> Result<
        crate::local_inventory::evidence_authority::VerifierEvidenceGrantV1<T>,
        InvalidMultiNodeJournal,
    > {
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = session.integration.context();
        if context != self.store.backend.authenticated_context {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        session
            .integration
            .issue_once(value, context, verified_at_unix_seconds)
    }

    /// Verifies and commits one exact prepared assignment transition.
    ///
    /// The detached signature is canonical-decoded under fixed bounds against
    /// the trust policy and signer key retained by the protected bootstrap. The
    /// signer must also be the live carrier binding committed by
    /// `protected_expected`; no scalar key digest can substitute for it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAssignmentWriteErrorV1`] for a protected-row,
    /// reducer, session, signature, policy, or persistence mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_verified_assignment_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        session: AuthenticatedNodeSessionV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedAssignmentWriteOutcomeV1, ProtectedAssignmentWriteErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !self
            .store
            .backend
            .protects_record(&protected_expected.record)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?
            .intent()
            .clone();
        let plan = AssignmentObservationReducerV1::new(intent.clone())
            .issue_effect_plan(record.operation())?;
        let carrier = verify_assignment_contract_from_protected_channel(
            &session,
            &protected_expected.record,
            &intent,
            authority,
            canonical_signature,
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
            verified_at_unix_seconds,
        )?;
        let outcome = self
            .store
            .backend
            .authority_session()?
            .commit_assignment_record_once(record, &plan, carrier, verified_at_unix_seconds)?;
        Ok(match outcome {
            ProtectedAssignmentCommitOutcomeV1::Committed(committed) => {
                ProtectedAssignmentWriteOutcomeV1::Committed(committed)
            }
            ProtectedAssignmentCommitOutcomeV1::RecoveryRequired { recovery, carrier } => {
                ProtectedAssignmentWriteOutcomeV1::RecoveryRequired(
                    ProtectedAssignmentRecoveryRequiredV1 { recovery, carrier },
                )
            }
        })
    }

    /// Converts one current committed assignment into a dormant effect handoff.
    ///
    /// The method replays the complete protected history, obtains the reducer's
    /// exact semantic grant, reauthenticates the assignment signature and live
    /// carrier at the freshly advanced clock floor, and stops before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAssignmentWriteErrorV1`] when the committed row is no
    /// longer current or any reducer, carrier, signature, or authority binding
    /// differs from the protected history.
    pub fn prepare_verified_assignment_effect_handoff(
        &mut self,
        committed: ProtectedAssignmentStoreCommitV1,
        session: AuthenticatedNodeSessionV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedAssignmentEffectReadyV1, ProtectedAssignmentWriteErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !self.store.backend.protects_record(committed.record()) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let record = committed.record().record();
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?
            .intent()
            .clone();
        let plan = AssignmentObservationReducerV1::new(intent.clone())
            .issue_effect_plan(record.operation())?;
        let reducers = replay_protected_store_semantics(
            &self.store.backend.history,
            self.store.backend.storage_domain_digest,
            self.store.backend.replay_fence,
            self.store.backend.authenticated_context,
        )?;
        let assignment_reducer = reducers
            .get(&MultiNodeJournalDomainV1::Assignment)
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let semantic_grant = assignment_reducer.issue_assignment_effect_grant(plan)?;
        let effect_time_carrier = verify_assignment_contract_from_protected_channel(
            &session,
            committed.record(),
            &intent,
            authority,
            canonical_signature,
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
            verified_at_unix_seconds,
        )?;
        let handoff = committed.into_publication().into_effect_handoff(
            semantic_grant,
            effect_time_carrier,
            verified_at_unix_seconds,
        )?;
        Ok(ProtectedAssignmentEffectReadyV1 { handoff })
    }

    /// Resolves one assignment write only through exact protected readback.
    #[must_use]
    pub fn resolve_assignment_write(
        &mut self,
        pending: ProtectedAssignmentRecoveryRequiredV1,
    ) -> ProtectedAssignmentWriteResolutionV1 {
        if let Err(reason) = self.observe_current_time() {
            return ProtectedAssignmentWriteResolutionV1::RecoveryRequired {
                recovery: pending,
                reason,
            };
        }
        let resolution = match self.store.backend.authority_session() {
            Ok(mut session) => {
                session.resolve_ambiguous_assignment(pending.recovery, pending.carrier)
            }
            Err(reason) => {
                return ProtectedAssignmentWriteResolutionV1::RecoveryRequired {
                    recovery: pending,
                    reason,
                };
            }
        };
        match resolution {
            ProtectedAssignmentResolutionV1::Committed(committed) => {
                ProtectedAssignmentWriteResolutionV1::Committed(committed)
            }
            ProtectedAssignmentResolutionV1::RecoveryRequired {
                recovery,
                carrier,
                reason,
            } => ProtectedAssignmentWriteResolutionV1::RecoveryRequired {
                recovery: ProtectedAssignmentRecoveryRequiredV1 { recovery, carrier },
                reason,
            },
        }
    }
}

impl<'a> ProtectedStoreAuthoritySessionV1<'a> {
    /// Persists one assignment record under its exact authenticated carrier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] unless the record contains the exact
    /// node/epoch/assignment selected by the carrier contract, its lease and
    /// signature binding is current, and the protected receipt echoes that
    /// singular contract.
    pub(in crate::local_inventory::store_authority) fn commit_assignment_record_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        plan: &AssignmentEffectPlanV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedAssignmentCommitOutcomeV1, InvalidMultiNodeJournal> {
        let assignment = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let intent = assignment.intent();
        if record.domain() != crate::local_inventory::journal::MultiNodeJournalDomainV1::Assignment
            || record.payload_digest() != intent.assignment_digest()
            || record.state_payload().assignment_digest() != Some(carrier.assignment_digest())
            || !plan.matches(record.operation(), intent, record.effect_digest())
            || intent.node() != carrier.node()
            || intent.epoch() != carrier.assignment_epoch()
            || carrier.peer_identity_digest().as_bytes() == &[0; 32]
            || carrier.lease_generation() == 0
            || carrier.lease_digest().as_bytes() == &[0; 32]
            || carrier.signature_digest().as_bytes() == &[0; 32]
            || carrier.replay_fence() != self.replay_fence
            || !carrier.is_current_for(intent, verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }

        let canonical_bytes = record.encode_canonical();
        let domain = record.domain();
        let carrier_digest = carrier.digest();
        let grant = self.persist_once(
            domain,
            ProtectedStoreObjectKindV1::Record,
            Some(record.operation()),
            &canonical_bytes,
            verified_at_unix_seconds,
            Some(carrier_digest),
            Some(&carrier),
        )?;
        let (grant, recovery) = match grant {
            ProtectedStorePersistOutcomeV1::Committed { grant, recovery } => (grant, recovery),
            ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery) => {
                return Ok(ProtectedAssignmentCommitOutcomeV1::RecoveryRequired {
                    recovery,
                    carrier,
                });
            }
        };
        if grant.context() != carrier.context() {
            self.reopen_ambiguous(&recovery);
            return Ok(ProtectedAssignmentCommitOutcomeV1::RecoveryRequired { recovery, carrier });
        }
        let record = match ProtectedJournalRecordV1::from_authority_commit(
            &canonical_bytes,
            grant,
            verified_at_unix_seconds,
        ) {
            Ok(record) => record,
            Err(_) => {
                self.reopen_ambiguous(&recovery);
                return Ok(ProtectedAssignmentCommitOutcomeV1::RecoveryRequired {
                    recovery,
                    carrier,
                });
            }
        };
        Ok(ProtectedAssignmentCommitOutcomeV1::Committed(
            ProtectedAssignmentStoreCommitV1 { record, carrier },
        ))
    }

    /// Resolves an interrupted assignment write without losing carrier authority.
    pub(in crate::local_inventory::store_authority) fn resolve_ambiguous_assignment(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
    ) -> ProtectedAssignmentResolutionV1 {
        if recovery.authority_binding_digest != Some(carrier.digest()) {
            return ProtectedAssignmentResolutionV1::RecoveryRequired {
                recovery,
                carrier,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        let verified_at_unix_seconds = recovery.verified_at_unix_seconds;
        let canonical_bytes = recovery.canonical_bytes.clone();
        let grant = match self.try_resolve_ambiguous(&recovery, Some(&carrier)) {
            Ok(grant) => grant,
            Err(reason) => {
                return ProtectedAssignmentResolutionV1::RecoveryRequired {
                    recovery,
                    carrier,
                    reason,
                };
            }
        };
        let record = match ProtectedJournalRecordV1::from_authority_commit(
            &canonical_bytes,
            grant,
            verified_at_unix_seconds,
        ) {
            Ok(record) => record,
            Err(reason) => {
                self.reopen_ambiguous(&recovery);
                return ProtectedAssignmentResolutionV1::RecoveryRequired {
                    recovery,
                    carrier,
                    reason,
                };
            }
        };
        ProtectedAssignmentResolutionV1::Committed(ProtectedAssignmentStoreCommitV1 {
            record,
            carrier,
        })
    }
}
