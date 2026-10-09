//! Protected remote assignment commit, recovery, and sealed effect handoff.
//!
//! This selected child retains the original protected-store enclosure. It
//! does not expose a backend, signer, or independent authority constructor.

use super::*;

use crate::local_inventory::assignment::{
    AssignmentEffectPlanV1, AssignmentObservationReducerV1, InvalidAssignmentModel,
};
use crate::local_inventory::carrier_authority::{
    AuthenticatedAssignmentCarrierContractV1, verify_assignment_contract_from_protected_channel,
};
use crate::local_inventory::journal::AssignmentEffectSemanticGrantV1;

/// Couples an assignment journal record to its authenticated carrier contract.
///
/// The wrapper is singular. It is the only value in this module that allows a
/// future publisher to retain peer, node, epoch, assignment, lease, detached
/// signature, and replay binding alongside the durable record.
#[must_use]
pub struct ProtectedAssignmentStoreCommitV1 {
    record: ProtectedJournalRecordV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Retains exact assignment authority across an outcome-unknown store write.
#[must_use]
pub struct ProtectedAssignmentRecoveryRequiredV1 {
    recovery: ProtectedStoreRecoveryRequiredV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Reports a protected assignment write without discarding ambiguity state.
#[must_use]
pub enum ProtectedAssignmentWriteOutcomeV1 {
    /// The exact protected assignment row was read back after commit.
    Committed(ProtectedAssignmentStoreCommitV1),
    /// The exact transaction and carrier authority must be recovered.
    RecoveryRequired(ProtectedAssignmentRecoveryRequiredV1),
}

/// Reports recovery of one protected assignment write.
#[must_use]
pub enum ProtectedAssignmentWriteResolutionV1 {
    /// The exact protected assignment row was authenticated as committed.
    Committed(ProtectedAssignmentStoreCommitV1),
    /// Recovery remains indeterminate or found a conflicting current value.
    RecoveryRequired {
        /// Retains the exact transaction and carrier authority for another observation.
        recovery: ProtectedAssignmentRecoveryRequiredV1,
        /// Describes the fail-closed recovery classification.
        reason: InvalidMultiNodeJournal,
    },
}

/// Reports protected assignment verification or persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedAssignmentWriteErrorV1 {
    /// Carrier, signature, trust-policy, or protected identity verification failed.
    #[error("protected assignment carrier verification failed: {0}")]
    Protocol(#[from] InvalidMultiNodeProtocol),
    /// Assignment intent or reducer plan construction failed.
    #[error("protected assignment reducer planning failed: {0}")]
    Assignment(#[from] InvalidAssignmentModel),
    /// Protected storage or canonical replay validation failed.
    #[error("protected assignment journal write failed: {0}")]
    Journal(#[from] InvalidMultiNodeJournal),
}

/// Allows publication only after the exact assignment store commit completed.
#[must_use]
pub(in crate::local_inventory::store_authority) struct ProtectedAssignmentPublicationV1 {
    record: ProtectedJournalRecordV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Carries an exact prepared multi-node effect after durable publication.
#[must_use]
pub(in crate::local_inventory::store_authority) struct ProtectedAssignmentEffectHandoffV1 {
    publication: ProtectedAssignmentPublicationV1,
    semantic_grant: AssignmentEffectSemanticGrantV1,
    effect_time_carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Retains a current, reducer-authorized assignment effect without dispatching it.
#[must_use]
pub struct ProtectedAssignmentEffectReadyV1 {
    handoff: ProtectedAssignmentEffectHandoffV1,
}

pub(in crate::local_inventory::store_authority) enum ProtectedAssignmentCommitOutcomeV1 {
    Committed(ProtectedAssignmentStoreCommitV1),
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
    },
}

pub(in crate::local_inventory::store_authority) enum ProtectedAssignmentResolutionV1 {
    Committed(ProtectedAssignmentStoreCommitV1),
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
        reason: InvalidMultiNodeJournal,
    },
}

impl ProtectedAssignmentStoreCommitV1 {
    /// Returns the exact protected assignment journal record.
    #[must_use]
    pub fn record(&self) -> &ProtectedJournalRecordV1 {
        &self.record
    }

    /// Consumes the readback-confirmed commit into a publication typestate.
    pub(in crate::local_inventory::store_authority) fn into_publication(
        self,
    ) -> ProtectedAssignmentPublicationV1 {
        ProtectedAssignmentPublicationV1 {
            record: self.record,
            carrier: self.carrier,
        }
    }
}

impl ProtectedAssignmentPublicationV1 {
    /// Releases only the reducer-authorized effect under current assignment authority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::InvalidRecoveryTransition`] unless the
    /// semantic grant names this exact protected row and a current effect-time
    /// carrier preserves its peer, assignment, and lease authority.
    pub(in crate::local_inventory::store_authority) fn into_effect_handoff(
        self,
        semantic_grant: AssignmentEffectSemanticGrantV1,
        effect_time_carrier: AuthenticatedAssignmentCarrierContractV1,
        effect_time_unix_seconds: u64,
    ) -> Result<ProtectedAssignmentEffectHandoffV1, InvalidMultiNodeJournal> {
        let record = self.record.record();
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?
            .intent();
        if record.domain() != crate::local_inventory::journal::MultiNodeJournalDomainV1::Assignment
            || record.effect_state()
                != crate::local_inventory::journal::JournalEffectStateV1::EffectPrepared
            || record.payload_digest() != semantic_grant.payload_digest()
            || semantic_grant.intent() != intent
            || !semantic_grant.matches(record.operation(), intent, record.effect_digest())
            || record.digest() != semantic_grant.record_digest()
            || self.record.receipt_commitment() != semantic_grant.receipt_commitment()
            || self.record.authority_binding_digest()
                != Some(semantic_grant.authority_binding_digest())
            || self.record.authority_binding_digest() != Some(self.carrier.digest())
            || !effect_time_carrier.matches_assignment_and_lease_of(&self.carrier)
            || effect_time_carrier.replay_fence() != self.carrier.replay_fence()
            || effect_time_carrier.verified_at_unix_seconds() != effect_time_unix_seconds
            || !effect_time_carrier.is_current_for(intent, effect_time_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::InvalidRecoveryTransition);
        }
        Ok(ProtectedAssignmentEffectHandoffV1 {
            publication: self,
            semantic_grant,
            effect_time_carrier,
        })
    }
}

impl ProtectedAssignmentEffectHandoffV1 {
    /// Returns the exact typed assignment intent selected by the reducer plan.
    pub(in crate::local_inventory::store_authority) fn intent(
        &self,
    ) -> &crate::local_inventory::assignment::AssignmentIntentV1 {
        self.semantic_grant.intent()
    }

    /// Returns the exact durable operation identity.
    pub(in crate::local_inventory::store_authority) fn operation(&self) -> OperationId {
        self.semantic_grant.operation()
    }

    /// Returns the exact durable effect commitment.
    pub(in crate::local_inventory::store_authority) fn effect_digest(&self) -> ObjectDigest {
        self.semantic_grant.effect_digest()
    }

    /// Returns the carrier contract that authenticated the durable row.
    pub(in crate::local_inventory::store_authority) fn carrier_contract_digest(
        &self,
    ) -> ObjectDigest {
        self.publication.carrier.digest()
    }

    /// Returns the current carrier contract checked at effect handoff time.
    pub(in crate::local_inventory::store_authority) fn effect_time_carrier_contract_digest(
        &self,
    ) -> ObjectDigest {
        self.effect_time_carrier.digest()
    }

    /// Returns the reducer-issued semantic authority retained by the handoff.
    pub(in crate::local_inventory::store_authority) fn semantic_authority_binding_digest(
        &self,
    ) -> ObjectDigest {
        self.semantic_grant.authority_binding_digest()
    }
}

impl ProtectedAssignmentEffectReadyV1 {
    /// Returns the exact reducer-selected assignment intent.
    #[must_use]
    pub fn intent(&self) -> &crate::local_inventory::assignment::AssignmentIntentV1 {
        self.handoff.intent()
    }

    /// Returns the exact durable operation identity.
    #[must_use]
    pub fn operation(&self) -> OperationId {
        self.handoff.operation()
    }

    /// Returns the exact durable effect commitment.
    #[must_use]
    pub fn effect_digest(&self) -> ObjectDigest {
        self.handoff.effect_digest()
    }

    /// Returns the carrier commitment persisted with the assignment row.
    #[must_use]
    pub fn carrier_contract_digest(&self) -> ObjectDigest {
        self.handoff.carrier_contract_digest()
    }

    /// Returns the freshly reauthenticated effect-time carrier commitment.
    #[must_use]
    pub fn effect_time_carrier_contract_digest(&self) -> ObjectDigest {
        self.handoff.effect_time_carrier_contract_digest()
    }

    /// Returns the reducer-issued semantic authority commitment.
    #[must_use]
    pub fn semantic_authority_binding_digest(&self) -> ObjectDigest {
        self.handoff.semantic_authority_binding_digest()
    }
}

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
