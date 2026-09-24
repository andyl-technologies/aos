//! Verified SourceProvider outcome consumption for AOSMSA02.
//!
//! Only the move-only verifier retained after an actual carrier send can reach
//! this module. One atomic transaction consumes the attempt, advances the
//! provider response head, and replaces its exact acquisition owner or
//! Inventory floor.

use std::collections::BTreeMap;

use aos_sandbox::journal::{JournalTransaction, ProtectedJournalAuthority};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::{
    MountSourcePhysicalProofV1, SourceRealizationBindingV1,
    mount_source_acquisition_state::{
        protocol_acquire_verification_floor_v2, selection_floor_snapshot_v2,
    },
    mount_source_physical_proof_digest_v1, mount_source_proof_class_from_provider_v1,
    mount_source_realization_handle_v1,
};
use aos_sandbox_source_provider_protocol::{
    InventoryLeaseStateV1, SignedSourceExportLeaseV1, SignedSourceProviderInventoryV1,
    SignedSourceProviderReceiptV1, SignedSourceReleaseReceiptV1, SourceProviderMethod,
    SourceProviderStatus, SourceRootObservationV1, SourceSelectionFloorV1, decode_acquire_response,
    decode_inventory_response, decode_release_response, digest_inventory, digest_provider_proof,
    digest_signed_export_lease, provider_resource_commitment_v1, response_result_digest_v1,
    source_root_descriptor_commitment_v1,
};
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, ProviderSourceRootHandoffV1,
    ReceivedMountProviderOutcomePartsV2, RecoveredMountProviderOutcomePartsV2,
    RecoveredMountProviderOutcomeV2, RecoveredRetainedMountSourceRootV2,
    RetainedRootRecoveryAuthorizationV2, VerifiedMountProviderOutcomeV2,
};

use super::SourceAcquisitionTableV2;
use super::checkpoint::hash_exact;
use super::format::{
    MutationTagV2, provider_attempt_key, provider_session_key, put_record, state_error,
    transaction_id,
};
use super::lifecycle::SourceAcquisitionPostcommitOutcomeV2;
use super::model::*;
use super::projection::{projection_entries, projection_from_entries, reproduce_reconciliation};
use super::reservation::{SentProviderQueryV2, sealed_attempt, sealed_head, sealed_row};
use super::transition::{
    MutationIdentityV2, commit_mutation, next_revision, prepare_mutation, record_ref,
};
use crate::Result;

/// Classifies one durably consumed provider outcome by descriptor custody.
pub(crate) enum ConsumedProviderOutcomeV2 {
    /// The exact outcome carried no SourceRoot descriptor.
    WithoutSourceRoot {
        outcome: VerifiedMountProviderOutcomeV2,
    },
    /// A Complete Acquire committed together with its sealed SourceRoot custody.
    CompleteAcquire {
        postcommit: SourceAcquisitionPostcommitOutcomeV2,
    },
}

/// Classifies one recovered disposition by reopened descriptor custody.
pub(crate) enum RecoveredProviderOutcomeConsumptionV2 {
    /// The exact recovered outcome required no SourceRoot descriptor.
    WithoutSourceRoot {
        outcome: VerifiedMountProviderOutcomeV2,
    },
    /// A recovered Complete Acquire committed with exact reopened custody.
    CompleteAcquire {
        postcommit: SourceAcquisitionPostcommitOutcomeV2,
    },
    /// Existing manager custody was rebound across an authenticated provider death.
    RetainedSourceRoot {
        source_root: RecoveredRetainedMountSourceRootV2,
    },
}

struct PreparedProviderDispositionV2 {
    transaction: JournalTransaction,
    tentative: SourceAcquisitionTableV2,
}

impl SourceAcquisitionTableV2 {
    /// Confirms that retained authenticated evidence equals the durable lineage tail.
    ///
    /// # Errors
    ///
    /// Returns an error when the acquisition, method lineage, attempt, or
    /// canonical provider response cannot be reproduced exactly.
    pub(crate) fn retained_disposition_matches_v2(
        &self,
        acquisition_id: [u8; 32],
        method: ProviderMethodV2,
        outcome: &VerifiedMountProviderOutcomeV2,
    ) -> Result<bool> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("retained disposition owner is absent"))?;
        let reference = match method {
            ProviderMethodV2::Acquire => row.acquire_lineage.tail,
            ProviderMethodV2::Release => {
                row.release_lineage
                    .as_ref()
                    .map(|lineage| lineage.tail)
                    .ok_or_else(|| state_error("retained Release lineage is absent"))?
            }
            ProviderMethodV2::Inventory => {
                return Err(state_error("Inventory has no acquisition disposition"));
            }
        };
        let attempt = self
            .provider_attempts
            .get(&reference.id)
            .filter(|attempt| {
                attempt.revision == reference.revision
                    && attempt.record_digest == reference.record_digest
                    && attempt.method == method
                    && attempt.owner.owner_id() == acquisition_id
            })
            .ok_or_else(|| state_error("retained disposition attempt is absent"))?;
        let decoded = decode_disposition(method, outcome.canonical_response())?;
        let ProviderAttemptStateV2::DispositionConsumed {
            response_sequence,
            verification_anchor,
            status,
            signed_status,
            signed_status_digest,
            signed_result,
            signed_result_digest,
        } = &attempt.state
        else {
            return Ok(false);
        };
        Ok(protocol_status(outcome.status())? == *status
            && *response_sequence == decoded.response_sequence
            && *verification_anchor == outcome.verification_anchor()
            && *status == decoded.status
            && signed_status == &decoded.signed_status
            && *signed_status_digest == decoded.signed_status_digest
            && signed_result == &decoded.signed_result
            && *signed_result_digest == decoded.signed_result_digest)
    }

    /// Reauthenticates and consumes one outcome retained across a Mount crash.
    ///
    /// The table supplies the exact immutable attempt and session records to
    /// the protected verifier. Caller-provided bytes cannot reach the reducer
    /// unless current trust revalidates the complete historical signature and
    /// request/result graph.
    ///
    /// # Errors
    ///
    /// Returns an error unless the attempt is exactly Reserved or retains the
    /// same consumed disposition, protected currentness and historical trust
    /// admit the response, and any required atomic mutation validates and
    /// commits. Complete Acquire also requires exact reopened SourceRoot custody.
    #[doc(hidden)]
    pub(crate) fn recover_and_consume_provider_outcome_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        catalog_journal: &ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        attempt_id: [u8; 32],
        captured: aos_sandbox_source_provider_security::CapturedMountProviderRecoveryOutcomeV2,
    ) -> Result<RecoveredProviderOutcomeConsumptionV2> {
        let attempt = self
            .provider_attempts
            .get(&attempt_id)
            .cloned()
            .ok_or_else(|| state_error("recovered provider outcome attempt is absent"))?;
        if !matches!(
            &attempt.state,
            ProviderAttemptStateV2::Reserved | ProviderAttemptStateV2::DispositionConsumed { .. }
        ) {
            return Err(state_error(
                "recovered provider outcome attempt is not consumable",
            ));
        }
        let retained_session = self
            .provider_sessions
            .get(&attempt.session_id)
            .filter(|value| value.record_digest == attempt.session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("recovered provider outcome session is absent"))?;
        let retained_root =
            self.retained_root_recovery_authorization(journal, session, &attempt)?;
        let attempt_record =
            materialized_record(StoredRecordV2::ProviderQueryAttempt { value: attempt })?;
        let session_record = materialized_record(StoredRecordV2::ProviderSession {
            value: retained_session.clone(),
        })?;
        let recovered = session
            .recover_mount_provider_outcome_v2(
                journal,
                catalog_journal,
                journal.snapshot()?,
                provider_attempt_key(attempt_id),
                attempt_record,
                provider_session_key(retained_session.session_id),
                session_record,
                captured,
            )
            .map_err(|_| state_error("protected provider outcome recovery failed"))?;
        if let Some(authorization) = retained_root {
            let source_root = session
                .recover_retained_mount_source_root_v2(journal, authorization, recovered)
                .map_err(|_| state_error("retained SourceRoot recovery failed"))?;
            Ok(RecoveredProviderOutcomeConsumptionV2::RetainedSourceRoot { source_root })
        } else {
            self.consume_recovered_provider_outcome_v2(journal, session, attempt_id, recovered)
        }
    }

    fn retained_root_recovery_authorization(
        &self,
        journal: &ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        attempt: &SourceProviderQueryAttemptV2,
    ) -> Result<Option<RetainedRootRecoveryAuthorizationV2>> {
        let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
            return Ok(None);
        };
        let Some(row) = self.acquisitions.get(&acquisition_id) else {
            return Err(state_error("recovered Acquire owner is absent"));
        };
        let effective_phase = if row.phase == SourceAcquisitionPhaseV2::Faulted {
            row.faulted_from
        } else {
            Some(row.phase)
        };
        if !matches!(
            effective_phase,
            Some(
                SourceAcquisitionPhaseV2::DescriptorCustodied
                    | SourceAcquisitionPhaseV2::Active
                    | SourceAcquisitionPhaseV2::Consumed
                    | SourceAcquisitionPhaseV2::Releasing
            )
        ) {
            return Ok(None);
        }
        let row_record = materialized_record(StoredRecordV2::Acquisition { value: row.clone() })?;
        session
            .authorize_retained_mount_source_root_recovery_v2(
                journal,
                journal.snapshot()?,
                super::format::acquisition_key(acquisition_id),
                row_record,
            )
            .map(Some)
            .map_err(|_| state_error("retained SourceRoot recovery authorization failed"))
    }

    /// Consumes a post-crash outcome reauthenticated against protected history.
    ///
    /// # Errors
    ///
    /// Returns an error unless the recovered verifier names the exact Reserved
    /// or already-consumed attempt, any required atomic completion validates,
    /// and Complete Acquire custody seals against the committed record.
    #[doc(hidden)]
    pub(crate) fn consume_recovered_provider_outcome_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        attempt_id: [u8; 32],
        recovered: RecoveredMountProviderOutcomeV2,
    ) -> Result<RecoveredProviderOutcomeConsumptionV2> {
        let already_consumed = self
            .provider_attempts
            .get(&attempt_id)
            .is_some_and(|attempt| {
                matches!(
                    &attempt.state,
                    ProviderAttemptStateV2::DispositionConsumed { .. }
                )
            });
        let observation = recovered.source_root_observation().cloned();

        match recovered.into_parts() {
            RecoveredMountProviderOutcomePartsV2::WithoutSourceRoot(outcome) => {
                if !already_consumed {
                    if self
                        .consume_verified_provider_outcome_v2(journal, attempt_id, &outcome, None)?
                        .is_some()
                    {
                        return Err(state_error(
                            "provider outcome without a SourceRoot deferred an Acquire commit",
                        ));
                    }
                }
                Ok(RecoveredProviderOutcomeConsumptionV2::WithoutSourceRoot { outcome })
            }
            RecoveredMountProviderOutcomePartsV2::CompleteAcquire {
                outcome,
                source_root,
            } => {
                let prepared = if already_consumed {
                    let observation = observation.as_ref().ok_or_else(|| {
                        state_error("recovered Complete Acquire lacks SourceRoot observation")
                    })?;
                    self.validate_committed_acquire_observation(attempt_id, observation)?;
                    self.committed_acquire_readback(attempt_id)?
                } else {
                    self.consume_verified_provider_outcome_v2(
                        journal,
                        attempt_id,
                        &outcome,
                        observation.as_ref(),
                    )?
                    .ok_or_else(|| {
                        state_error("recovered Complete Acquire did not defer its atomic commit")
                    })?
                };
                let committed = session.commit_reopened_mount_source_root_v2(
                    journal,
                    prepared.transaction,
                    outcome,
                    source_root,
                );
                let committed = self.retain_source_root_postcommit(journal, committed);
                Ok(RecoveredProviderOutcomeConsumptionV2::CompleteAcquire {
                    postcommit: committed,
                })
            }
        }
    }

    fn validate_committed_acquire_observation(
        &self,
        attempt_id: [u8; 32],
        observation: &SourceRootObservationV1,
    ) -> Result<()> {
        let attempt = self
            .provider_attempts
            .get(&attempt_id)
            .ok_or_else(|| state_error("committed Acquire attempt is absent"))?;
        let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
            return Err(state_error(
                "reopened SourceRoot names a non-Acquire attempt",
            ));
        };
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("committed Acquire owner is absent"))?;
        let evidence = row
            .evidence
            .as_ref()
            .filter(|evidence| evidence.acquire_attempt.id == attempt_id)
            .ok_or_else(|| state_error("committed Acquire evidence is absent"))?;
        if row.phase != SourceAcquisitionPhaseV2::PendingQuery
            || row.acquire_terminal_attempt != Some(evidence.acquire_attempt)
            || row.descriptor_custody_digest.is_some()
            || !matches!(&row.recovery, AcquisitionRecoveryV2::Ready)
            || !observation_matches_evidence(observation, evidence)
        {
            return Err(state_error(
                "reopened SourceRoot differs from pending committed Acquire custody",
            ));
        }
        Ok(())
    }

    fn committed_acquire_readback(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<PreparedProviderDispositionV2> {
        let attempt = self
            .provider_attempts
            .get(&attempt_id)
            .cloned()
            .ok_or_else(|| state_error("committed Acquire attempt is absent"))?;
        let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
            return Err(state_error("committed provider attempt is not Acquire"));
        };
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("committed Acquire owner is absent"))?;
        let head = self.head_for_row(row)?;
        let transaction = JournalTransaction::new(
            transaction_id(
                MutationTagV2::ConsumeOutcome,
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
                self.holder_sequence_revision(row.scope.holder_authority_id),
                head.revision,
                Some(acquisition_id),
                Some(row.revision),
                Some(attempt_id),
                Some(attempt.revision),
                None,
            ),
            vec![put_record(&StoredRecordV2::ProviderQueryAttempt {
                value: attempt,
            })?],
        )?;
        Ok(PreparedProviderDispositionV2 {
            transaction,
            tentative: self.clone(),
        })
    }

    /// Verifies and durably consumes the exact outcome for one sent attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when live provider custody rejects the response, the
    /// durable attempt/head no longer match the verifier, the result graph is
    /// inconsistent, a fixed bound is exceeded, or the atomic commit fails.
    #[doc(hidden)]
    pub(crate) fn consume_provider_outcome_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        catalog_journal: &ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<ConsumedProviderOutcomeV2> {
        let (attempt_id, authorization) = sent.security_parts();
        let received = session
            .receive_and_verify_provider_outcome_v2(catalog_journal, authorization)
            .map_err(|_| state_error("SourceProvider outcome verification failed"))?;
        let observation = received.source_root_observation().cloned();

        match received.into_parts() {
            ReceivedMountProviderOutcomePartsV2::WithoutSourceRoot(outcome) => {
                if self
                    .consume_verified_provider_outcome_v2(journal, attempt_id, &outcome, None)?
                    .is_some()
                {
                    return Err(state_error(
                        "provider outcome without a SourceRoot deferred an Acquire commit",
                    ));
                }
                Ok(ConsumedProviderOutcomeV2::WithoutSourceRoot { outcome })
            }
            ReceivedMountProviderOutcomePartsV2::CompleteAcquire {
                outcome,
                source_root,
            } => {
                let prepared = self
                    .consume_verified_provider_outcome_v2(
                        journal,
                        attempt_id,
                        &outcome,
                        observation.as_ref(),
                    )?
                    .ok_or_else(|| {
                        state_error("Complete Acquire did not defer its atomic commit")
                    })?;
                let committed = session.commit_received_mount_source_root_v2(
                    journal,
                    prepared.transaction,
                    outcome,
                    source_root,
                );
                let committed = self.retain_source_root_postcommit(journal, committed);
                Ok(ConsumedProviderOutcomeV2::CompleteAcquire {
                    postcommit: committed,
                })
            }
        }
    }

    fn consume_verified_provider_outcome_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        attempt_id: [u8; 32],
        verified: &VerifiedMountProviderOutcomeV2,
        source_root_observation: Option<&SourceRootObservationV1>,
    ) -> Result<Option<PreparedProviderDispositionV2>> {
        let current_attempt = self
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| matches!(&attempt.state, ProviderAttemptStateV2::Reserved))
            .cloned()
            .ok_or_else(|| state_error("provider outcome does not name a Reserved attempt"))?;
        let identity = (
            current_attempt.scope.holder_authority_id,
            current_attempt.scope.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt
                    == Some(RecordRefV2 {
                        id: current_attempt.attempt_id,
                        revision: current_attempt.revision,
                        record_digest: current_attempt.record_digest,
                    })
            })
            .cloned()
            .ok_or_else(|| state_error("provider outcome does not own the current head"))?;
        let session_record = self
            .provider_sessions
            .get(&current_attempt.session_id)
            .filter(|session| session.record_digest == current_attempt.session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("provider outcome session is absent"))?;
        let verified_status = verified.status();
        let response = verified.canonical_response();
        let disposition = decode_disposition(current_attempt.method, response)?;
        if disposition.response_sequence != current_attempt.request_sequence
            || disposition.status != protocol_status(verified_status)?
        {
            return Err(state_error(
                "verified provider outcome differs from its durable attempt",
            ));
        }

        let mut next_attempt = current_attempt.clone();
        next_attempt.revision = 2;
        next_attempt.state = ProviderAttemptStateV2::DispositionConsumed {
            response_sequence: disposition.response_sequence,
            verification_anchor: verified.verification_anchor(),
            status: disposition.status,
            signed_status: disposition.signed_status,
            signed_status_digest: disposition.signed_status_digest,
            signed_result: disposition.signed_result,
            signed_result_digest: disposition.signed_result_digest,
        };
        next_attempt.record_digest = [0; 32];
        let next_attempt = sealed_attempt(next_attempt)?;
        let terminal_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: next_attempt.clone(),
        })?;

        match current_attempt.method {
            ProviderMethodV2::Acquire | ProviderMethodV2::Release => {
                let complete_acquire = current_attempt.method == ProviderMethodV2::Acquire
                    && disposition.status == ProviderStatusV2::Complete;
                let prepared = self.prepare_acquisition_disposition(
                    current_head,
                    session_record,
                    next_attempt,
                    terminal_ref,
                    source_root_observation,
                )?;
                if complete_acquire {
                    Ok(Some(prepared))
                } else {
                    journal.commit(&prepared.transaction)?;
                    *self = prepared.tentative;
                    Ok(None)
                }
            }
            ProviderMethodV2::Inventory => {
                if source_root_observation.is_some() {
                    return Err(state_error("Inventory outcome carried a SourceRoot"));
                }
                self.consume_inventory_disposition(
                    journal,
                    current_head,
                    next_attempt,
                    terminal_ref,
                )?;
                Ok(None)
            }
        }
    }

    fn prepare_acquisition_disposition(
        &self,
        current_head: SourceProviderHeadV2,
        session: SourceProviderSessionV2,
        next_attempt: SourceProviderQueryAttemptV2,
        terminal_ref: RecordRefV2,
        source_root_observation: Option<&SourceRootObservationV1>,
    ) -> Result<PreparedProviderDispositionV2> {
        let acquisition_id = next_attempt.owner.owner_id();
        let current_row = self
            .acquisitions
            .get(&acquisition_id)
            .cloned()
            .ok_or_else(|| state_error("provider disposition acquisition owner is absent"))?;
        let mut next_row = current_row.clone();
        next_row.revision = next_revision(current_row.revision)?;
        match next_attempt.method {
            ProviderMethodV2::Acquire => {
                next_row.acquire_lineage.tail = terminal_ref;
                if consumed_status(&next_attempt)? == ProviderStatusV2::Complete {
                    next_row.acquire_terminal_attempt = Some(terminal_ref);
                    let evidence = acquire_evidence(&next_row, &next_attempt, &session)?;
                    let observation = source_root_observation.ok_or_else(|| {
                        state_error("Complete Acquire lacks observed SourceRoot custody")
                    })?;
                    if !observation_matches_evidence(observation, &evidence) {
                        return Err(state_error(
                            "observed SourceRoot differs from Complete Acquire evidence",
                        ));
                    }
                    next_row.evidence = Some(evidence);
                } else if source_root_observation.is_some() {
                    return Err(state_error(
                        "noncomplete Acquire outcome carried a SourceRoot",
                    ));
                }
            }
            ProviderMethodV2::Release => {
                if source_root_observation.is_some() {
                    return Err(state_error("Release outcome carried a SourceRoot"));
                }
                let lineage = next_row
                    .release_lineage
                    .as_mut()
                    .ok_or_else(|| state_error("provider Release owner lacks a lineage"))?;
                lineage.tail = terminal_ref;
                if consumed_status(&next_attempt)? == ProviderStatusV2::Complete {
                    let release_generation = release_generation(&next_attempt)?;
                    next_row.release_terminal_attempt = Some(terminal_ref);
                    next_row.release_proof = Some(ReleaseProofV2::ProviderReceipt {
                        attempt: terminal_ref,
                        release_generation,
                    });
                }
            }
            ProviderMethodV2::Inventory => {
                return Err(state_error(
                    "Inventory disposition has an acquisition owner",
                ));
            }
        }
        next_row.record_digest = [0; 32];
        let next_row = sealed_row(next_row)?;

        let mut next_rows = self.acquisitions.clone();
        next_rows.insert(acquisition_id, next_row.clone());
        let next_head = completed_head(&current_head, &self.acquisitions, &next_rows)?;
        let next_head = sealed_head(next_head)?;
        let tag = MutationTagV2::ConsumeOutcome;
        let (transaction, tentative) = prepare_mutation(
            self,
            MutationIdentityV2 {
                tag,
                holder_id: next_head.scope.holder_authority_id,
                provider_id: next_head.scope.provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&next_head.scope.holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: Some(acquisition_id),
                next_row_revision: Some(next_row.revision),
                attempt_id: Some(next_attempt.attempt_id),
                next_attempt_revision: Some(next_attempt.revision),
                session_id: None,
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: next_attempt,
                },
                StoredRecordV2::Acquisition { value: next_row },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )?;
        Ok(PreparedProviderDispositionV2 {
            transaction,
            tentative,
        })
    }

    fn consume_inventory_disposition(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        current_head: SourceProviderHeadV2,
        next_attempt: SourceProviderQueryAttemptV2,
        terminal_ref: RecordRefV2,
    ) -> Result<()> {
        if current_head.recovery_barrier.is_some()
            && consumed_status(&next_attempt)? == ProviderStatusV2::Complete
        {
            return self.complete_recovery_inventory(
                journal,
                current_head,
                next_attempt,
                terminal_ref,
            );
        }

        let mut next_head = completed_head(&current_head, &self.acquisitions, &self.acquisitions)?;
        next_head.last_inventory_attempt = Some(terminal_ref);
        if let Some(barrier) = next_head.recovery_barrier.as_mut() {
            barrier.recovery_inventory_tail = Some(terminal_ref);
        }
        if consumed_status(&next_attempt)? == ProviderStatusV2::Complete {
            let inventory = consumed_inventory(&next_attempt)?;
            next_head.inventory_observation_ordinal = current_head
                .inventory_observation_ordinal
                .checked_add(1)
                .ok_or_else(|| {
                    state_error("provider Inventory observation ordinal is exhausted")
                })?;
            next_head.inventory_floor = Some(InventoryFloorV2 {
                attempt: terminal_ref,
                provider_authority_generation: inventory.provider().authority_generation(),
                provider_authority_digest: *inventory.provider().authority_digest().as_bytes(),
                provider_outcome_signer_digest: self
                    .provider_sessions
                    .get(&next_attempt.session_id)
                    .ok_or_else(|| state_error("Inventory outcome session is absent"))?
                    .signers[3]
                    .public_key_fingerprint,
                inventory_generation: inventory.inventory_generation(),
                inventory_digest: *digest_inventory(&inventory).as_bytes(),
                catalog_generation: inventory.catalog_generation(),
                catalog_digest: *inventory.catalog_digest().as_bytes(),
                signed_result_digest: consumed_result_digest(&next_attempt),
            });
            let mut attempts = self.provider_attempts.clone();
            attempts.insert(next_attempt.attempt_id, next_attempt.clone());
            next_head.last_reconciliation = Some(reproduce_reconciliation(
                &next_head,
                &attempts,
                &self.acquisitions,
            )?);
        }
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::CompleteInventory,
                holder_id: next_head.scope.holder_authority_id,
                provider_id: next_head.scope.provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&next_head.scope.holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: None,
                next_row_revision: None,
                attempt_id: Some(next_attempt.attempt_id),
                next_attempt_revision: Some(next_attempt.revision),
                session_id: None,
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: next_attempt,
                },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )
    }

    fn complete_recovery_inventory(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        current_head: SourceProviderHeadV2,
        next_inventory_attempt: SourceProviderQueryAttemptV2,
        inventory_ref: RecordRefV2,
    ) -> Result<()> {
        let barrier = current_head
            .recovery_barrier
            .as_ref()
            .ok_or_else(|| state_error("recovery Inventory lacks a provider barrier"))?;
        let current_root = self
            .provider_attempts
            .get(&barrier.root_attempt.id)
            .filter(|attempt| {
                attempt.revision == barrier.root_attempt.revision
                    && attempt.record_digest == barrier.root_attempt.record_digest
                    && matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::AbandonedIndeterminate {
                            resolution: None,
                            ..
                        }
                    )
            })
            .cloned()
            .ok_or_else(|| state_error("recovery Inventory root is not unresolved"))?;
        if !matches!(
            &next_inventory_attempt.intent,
            ProviderIntentV2::Inventory { value }
                if value.recovery_root_attempt_id == Some(current_root.attempt_id)
        ) {
            return Err(state_error("recovery Inventory does not join its root"));
        }

        let inventory = consumed_inventory(&next_inventory_attempt)?;
        let inventory_digest = *digest_inventory(&inventory).as_bytes();
        let inventory_ordinal = current_head
            .inventory_observation_ordinal
            .checked_add(1)
            .ok_or_else(|| state_error("provider Inventory observation ordinal is exhausted"))?;
        let target =
            classify_recovery_target(self, &current_root, &next_inventory_attempt, &inventory)?;
        let mut next_rows = self.acquisitions.clone();
        let acquisition_id = recovery_owner_id(current_root.owner);

        if let Some(acquisition_id) = acquisition_id {
            let current_row = self
                .acquisitions
                .get(&acquisition_id)
                .cloned()
                .ok_or_else(|| state_error("recovery Inventory owner row is absent"))?;
            let mut projected_row = current_row.clone();
            if matches!(target, RecoveryTargetV2::ProviderTerminal) {
                let acquisition_predecessor = next_inventory_attempt
                    .inventory_correlations
                    .as_ref()
                    .and_then(|correlations| {
                        correlations
                            .entries
                            .iter()
                            .find(|entry| entry.mount_acquisition_id == acquisition_id)
                    })
                    .map(|entry| entry.acquisition_record)
                    .ok_or_else(|| {
                        state_error("recovery Inventory lacks its reserved acquisition")
                    })?;
                projected_row.release_proof = Some(ReleaseProofV2::ProviderInventory {
                    attempt: inventory_ref,
                    acquisition_predecessor,
                    inventory_digest,
                    inventory_observation_ordinal: inventory_ordinal,
                    projection_epoch: current_head
                        .current_projection_epoch
                        .checked_add(1)
                        .ok_or_else(|| state_error("provider projection epoch is exhausted"))?,
                });
            }
            next_rows.insert(acquisition_id, projected_row);
        }

        let mut next_head = completed_head(&current_head, &self.acquisitions, &next_rows)?;
        next_head.inventory_observation_ordinal = inventory_ordinal;
        next_head.inventory_floor = Some(inventory_floor(
            self,
            &next_inventory_attempt,
            inventory_ref,
            &inventory,
        )?);
        next_head.last_inventory_attempt = Some(inventory_ref);
        next_head.recovery_barrier = None;
        let mut next_attempts = self.provider_attempts.clone();
        next_attempts.insert(
            next_inventory_attempt.attempt_id,
            next_inventory_attempt.clone(),
        );
        let reconciliation = reproduce_reconciliation(&next_head, &next_attempts, &next_rows)?;
        let reconciliation_digest = super::projection::reconciliation_commitment(&reconciliation);
        next_head.last_reconciliation = Some(reconciliation);

        let proof = RecoveryInventoryProofV2 {
            inventory_attempt: inventory_ref,
            inventory_digest,
            inventory_observation_ordinal: inventory_ordinal,
            projection_epoch: next_head.current_projection_epoch,
            projection_digest: next_head.current_projection_digest,
            reconciliation: next_head
                .last_reconciliation
                .clone()
                .ok_or_else(|| state_error("recovery reconciliation was not retained"))?,
            reconciliation_digest,
        };
        let resolution = recovery_resolution(current_root.method, target, proof)?;
        let mut next_root = current_root.clone();
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            dead_execution,
            successor_session_id,
            recovery_root_attempt_id,
            outcome_may_exist,
            ..
        } = current_root.state
        else {
            return Err(state_error("recovery root is not abandoned"));
        };
        next_root.revision = 3;
        next_root.state = ProviderAttemptStateV2::AbandonedIndeterminate {
            dead_execution,
            successor_session_id,
            recovery_root_attempt_id,
            outcome_may_exist,
            resolution: Some(resolution),
        };
        next_root.record_digest = [0; 32];
        let next_root = sealed_attempt(next_root)?;
        let next_root_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: next_root.clone(),
        })?;

        let next_row = acquisition_id
            .map(|acquisition_id| {
                let mut row = next_rows
                    .get(&acquisition_id)
                    .cloned()
                    .ok_or_else(|| state_error("recovery owner row was not projected"))?;
                row.revision = next_revision(row.revision)?;
                match current_root.method {
                    ProviderMethodV2::Acquire => row.acquire_lineage.tail = next_root_ref,
                    ProviderMethodV2::Release => {
                        row.release_lineage
                            .as_mut()
                            .ok_or_else(|| state_error("recovery Release lineage is absent"))?
                            .tail = next_root_ref;
                    }
                    ProviderMethodV2::Inventory => {
                        return Err(state_error(
                            "Inventory recovery root has an acquisition owner",
                        ));
                    }
                }
                row.recovery = match target {
                    RecoveryTargetV2::Retry => AcquisitionRecoveryV2::RetryPermitted {
                        root_attempt: next_root_ref,
                    },
                    RecoveryTargetV2::ProviderTerminal => AcquisitionRecoveryV2::Ready,
                    RecoveryTargetV2::Conflict => AcquisitionRecoveryV2::Conflict {
                        inventory_attempt: inventory_ref,
                        reconciliation_digest,
                        conflict_digest: proof.reconciliation.conflict_digest,
                    },
                    RecoveryTargetV2::InventoryReconciled => {
                        return Err(state_error("acquisition recovery resolved as Inventory"));
                    }
                };
                row.record_digest = [0; 32];
                sealed_row(row)
            })
            .transpose()?;

        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        let mut records = vec![
            StoredRecordV2::ProviderQueryAttempt {
                value: next_inventory_attempt,
            },
            StoredRecordV2::ProviderQueryAttempt { value: next_root },
        ];
        if let Some(row) = next_row {
            records.push(StoredRecordV2::Acquisition { value: row });
        }
        records.push(StoredRecordV2::ProviderHead {
            value: next_head.clone(),
        });
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::RecoveryCompletion,
                holder_id: next_head.scope.holder_authority_id,
                provider_id: next_head.scope.provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&next_head.scope.holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id,
                next_row_revision: acquisition_id.and_then(|id| {
                    self.acquisitions
                        .get(&id)
                        .and_then(|row| row.revision.checked_add(1))
                }),
                attempt_id: Some(inventory_ref.id),
                next_attempt_revision: Some(inventory_ref.revision),
                session_id: None,
            },
            records,
        )
    }
}

fn observation_matches_evidence(
    observation: &SourceRootObservationV1,
    evidence: &SourceAcquisitionEvidenceV2,
) -> bool {
    observation.kernel_boot_id() == evidence.source_kernel_boot_id
        && observation.device() == evidence.source_device
        && observation.inode() == evidence.source_inode
        && observation.unique_mount_id() == evidence.source_unique_mount_id
        && *source_root_descriptor_commitment_v1(observation).as_bytes()
            == evidence.descriptor_commitment
}

fn materialized_record(record: StoredRecordV2) -> Result<Vec<u8>> {
    put_record(&record)?
        .value()
        .map(ToOwned::to_owned)
        .ok_or_else(|| state_error("AOSMSA02 record materialized as a delete"))
}

#[derive(Clone, Copy)]
enum RecoveryTargetV2 {
    Retry,
    ProviderTerminal,
    Conflict,
    InventoryReconciled,
}

fn recovery_owner_id(owner: ProviderQueryOwnerV2) -> Option<[u8; 32]> {
    match owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id } => Some(acquisition_id),
        ProviderQueryOwnerV2::Inventory => None,
    }
}

fn classify_recovery_target(
    table: &SourceAcquisitionTableV2,
    root: &SourceProviderQueryAttemptV2,
    inventory_attempt: &SourceProviderQueryAttemptV2,
    inventory: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
) -> Result<RecoveryTargetV2> {
    let Some(acquisition_id) = recovery_owner_id(root.owner) else {
        return Ok(RecoveryTargetV2::InventoryReconciled);
    };
    let row = table
        .acquisitions
        .get(&acquisition_id)
        .ok_or_else(|| state_error("recovery target row is absent"))?;
    let correlation = inventory_attempt
        .inventory_correlations
        .as_ref()
        .and_then(|correlations| {
            correlations
                .entries
                .iter()
                .find(|entry| entry.mount_acquisition_id == acquisition_id)
        })
        .ok_or_else(|| state_error("recovery Inventory omitted its target correlation"))?;
    if correlation.provider_acquisition != row.provider_acquisition
        || correlation.acquisition_record.id != row.acquisition_id
        || correlation.acquisition_record.revision > row.revision
        || row.evidence.as_ref().map(|evidence| evidence.lease_id) != correlation.lease_id
        || row
            .evidence
            .as_ref()
            .map(|evidence| evidence.signed_lease_digest)
            != correlation.signed_lease_digest
        || (root.method == ProviderMethodV2::Acquire
            && correlation.expectation != InventoryCorrelationExpectationV2::AbsentOrMatchingActive)
        || (root.method == ProviderMethodV2::Release
            && correlation.expectation
                != InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent)
    {
        return Err(state_error(
            "recovery Inventory target differs from its reserved correlation",
        ));
    }
    let entry = inventory.entries().iter().find(|entry| {
        entry.acquisition_id().as_bytes() == &row.provider_acquisition.acquisition_id
    });
    if entry.is_some_and(|entry| {
        correlation
            .lease_id
            .is_some_and(|lease_id| entry.lease_id() != lease_id)
            || correlation
                .signed_lease_digest
                .is_some_and(|digest| entry.lease_digest().as_bytes() != &digest)
    }) {
        return Ok(RecoveryTargetV2::Conflict);
    }
    let evidence_matches = row.evidence.as_ref().is_some_and(|evidence| {
        entry.is_some_and(|entry| {
            super::projection::inventory_entry_matches_evidence(entry, evidence)
        })
    });

    match root.method {
        ProviderMethodV2::Acquire => {
            if entry.is_none()
                || entry.is_some_and(|entry| {
                    entry.state() == InventoryLeaseStateV1::Active && evidence_matches
                })
            {
                Ok(RecoveryTargetV2::Retry)
            } else {
                Ok(RecoveryTargetV2::Conflict)
            }
        }
        ProviderMethodV2::Release => {
            if entry.is_none()
                || entry.is_some_and(|entry| {
                    entry.state() == InventoryLeaseStateV1::Released && evidence_matches
                })
            {
                Ok(RecoveryTargetV2::ProviderTerminal)
            } else if entry.is_some_and(|entry| {
                matches!(
                    entry.state(),
                    InventoryLeaseStateV1::Active | InventoryLeaseStateV1::Reaping
                ) && evidence_matches
            }) {
                Ok(RecoveryTargetV2::Retry)
            } else {
                Ok(RecoveryTargetV2::Conflict)
            }
        }
        ProviderMethodV2::Inventory => Ok(RecoveryTargetV2::InventoryReconciled),
    }
}

fn recovery_resolution(
    method: ProviderMethodV2,
    target: RecoveryTargetV2,
    proof: RecoveryInventoryProofV2,
) -> Result<RecoveryResolutionV2> {
    match (method, target) {
        (ProviderMethodV2::Acquire, RecoveryTargetV2::Retry) => {
            Ok(RecoveryResolutionV2::RetryAcquireSameIntent { proof })
        }
        (ProviderMethodV2::Release, RecoveryTargetV2::Retry) => {
            Ok(RecoveryResolutionV2::RetryReleaseSameIntent { proof })
        }
        (ProviderMethodV2::Release, RecoveryTargetV2::ProviderTerminal) => {
            Ok(RecoveryResolutionV2::ProviderTerminalObserved { proof })
        }
        (ProviderMethodV2::Inventory, RecoveryTargetV2::InventoryReconciled) => {
            Ok(RecoveryResolutionV2::InventoryReconciled { proof })
        }
        (_, RecoveryTargetV2::Conflict) => Ok(RecoveryResolutionV2::Conflict {
            conflict_digest: proof.reconciliation.conflict_digest,
            proof,
        }),
        _ => Err(state_error("recovery resolution contradicts its method")),
    }
}

fn inventory_floor(
    table: &SourceAcquisitionTableV2,
    attempt: &SourceProviderQueryAttemptV2,
    reference: RecordRefV2,
    inventory: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
) -> Result<InventoryFloorV2> {
    Ok(InventoryFloorV2 {
        attempt: reference,
        provider_authority_generation: inventory.provider().authority_generation(),
        provider_authority_digest: *inventory.provider().authority_digest().as_bytes(),
        provider_outcome_signer_digest: table
            .provider_sessions
            .get(&attempt.session_id)
            .ok_or_else(|| state_error("Inventory outcome session is absent"))?
            .signers[3]
            .public_key_fingerprint,
        inventory_generation: inventory.inventory_generation(),
        inventory_digest: *digest_inventory(inventory).as_bytes(),
        catalog_generation: inventory.catalog_generation(),
        catalog_digest: *inventory.catalog_digest().as_bytes(),
        signed_result_digest: consumed_result_digest(attempt),
    })
}

struct DecodedDispositionV2 {
    response_sequence: u64,
    status: ProviderStatusV2,
    signed_status: Vec<u8>,
    signed_status_digest: [u8; 32],
    signed_result: Vec<u8>,
    signed_result_digest: [u8; 32],
}

fn decode_disposition(method: ProviderMethodV2, response: &[u8]) -> Result<DecodedDispositionV2> {
    let (status, signed_status, signed_result) = match method {
        ProviderMethodV2::Acquire => {
            let decoded = decode_acquire_response(response)
                .map_err(|_| state_error("verified Acquire response is invalid"))?;
            (
                decoded.status(),
                decoded.signed_status().to_canonical_bytes(),
                decoded
                    .signed_receipt()
                    .map_or_else(Vec::new, ToOwned::to_owned),
            )
        }
        ProviderMethodV2::Release => {
            let decoded = decode_release_response(response)
                .map_err(|_| state_error("verified Release response is invalid"))?;
            (
                decoded.status(),
                decoded.signed_status().to_canonical_bytes(),
                decoded
                    .signed_receipt()
                    .map_or_else(Vec::new, ToOwned::to_owned),
            )
        }
        ProviderMethodV2::Inventory => {
            let decoded = decode_inventory_response(response)
                .map_err(|_| state_error("verified Inventory response is invalid"))?;
            (
                decoded.status(),
                decoded.signed_status().to_canonical_bytes(),
                decoded
                    .signed_inventory()
                    .map_or_else(Vec::new, ToOwned::to_owned),
            )
        }
    };
    let envelope =
        aos_sandbox_source_provider_protocol::SignedSourceProviderStatusV1::from_canonical_bytes(
            &signed_status,
        )
        .map_err(|_| state_error("verified provider status is invalid"))?;
    let status = protocol_status(status)?;
    let method = match method {
        ProviderMethodV2::Acquire => SourceProviderMethod::Acquire,
        ProviderMethodV2::Release => SourceProviderMethod::Release,
        ProviderMethodV2::Inventory => SourceProviderMethod::Inventory,
    };
    Ok(DecodedDispositionV2 {
        response_sequence: envelope.subject().response_sequence(),
        status,
        signed_status_digest: hash_exact(&signed_status),
        signed_result_digest: *response_result_digest_v1(
            method,
            envelope.subject().status(),
            (!signed_result.is_empty()).then_some(signed_result.as_slice()),
        )
        .as_bytes(),
        signed_status,
        signed_result,
    })
}

fn protocol_status(status: SourceProviderStatus) -> Result<ProviderStatusV2> {
    match status {
        SourceProviderStatus::Complete => Ok(ProviderStatusV2::Complete),
        SourceProviderStatus::Pending => Ok(ProviderStatusV2::Pending),
        SourceProviderStatus::Rejected => Ok(ProviderStatusV2::Rejected),
        SourceProviderStatus::Unavailable => Ok(ProviderStatusV2::Unavailable),
    }
}

fn consumed_status(attempt: &SourceProviderQueryAttemptV2) -> Result<ProviderStatusV2> {
    match &attempt.state {
        ProviderAttemptStateV2::DispositionConsumed { status, .. } => Ok(*status),
        ProviderAttemptStateV2::Reserved
        | ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. } => {
            Err(state_error("provider attempt is not disposition-consumed"))
        }
    }
}

fn consumed_result_digest(attempt: &SourceProviderQueryAttemptV2) -> [u8; 32] {
    match &attempt.state {
        ProviderAttemptStateV2::DispositionConsumed {
            signed_result_digest,
            ..
        } => *signed_result_digest,
        ProviderAttemptStateV2::Reserved
        | ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. } => [0; 32],
    }
}

fn completed_head(
    current: &SourceProviderHeadV2,
    current_rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    next_rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
) -> Result<SourceProviderHeadV2> {
    let next_response_sequence = current
        .next_response_sequence
        .checked_add(1)
        .ok_or_else(|| state_error("SourceProvider response sequence is exhausted"))?;
    if current.pending_attempt.is_none() || next_response_sequence != current.next_request_sequence
    {
        return Err(state_error("SourceProvider response head is not reachable"));
    }
    let current_entries = projection_entries(current.scope, current_rows);
    let next_entries = projection_entries(current.scope, next_rows);
    let mut next = current.clone();
    next.revision = next_revision(current.revision)?;
    next.next_response_sequence = next_response_sequence;
    next.pending_attempt = None;
    if current_entries != next_entries {
        let epoch = current
            .current_projection_epoch
            .checked_add(1)
            .ok_or_else(|| state_error("SourceProvider projection epoch is exhausted"))?;
        let projection = projection_from_entries(current.scope, epoch, &next_entries)?;
        next.current_projection_epoch = epoch;
        next.current_projection_digest = projection.digest;
        next.last_reconciliation = None;
    }
    next.record_digest = [0; 32];
    Ok(next)
}

fn acquire_evidence(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
) -> Result<SourceAcquisitionEvidenceV2> {
    let ProviderAttemptStateV2::DispositionConsumed {
        verification_anchor,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error("Complete Acquire attempt is not consumed"));
    };
    let signed_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Complete Acquire receipt is invalid"))?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())
            .map_err(|_| state_error("Complete Acquire export lease is invalid"))?;
    let lease = signed_lease.subject();
    let resource = lease.resource();
    let proof_digest = digest_provider_proof(lease.proof());
    let resource_commitment = provider_resource_commitment_v1(resource, proof_digest);
    let mount_proof = mount_source_proof_class_from_provider_v1(lease.proof());
    let proof_class = match mount_proof {
        aos_sandbox_protocol::MountSourceProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV2::ImmutableTree
        }
        aos_sandbox_protocol::MountSourceProofClassV1::LocalLive => {
            SourceAcquisitionProofClassV2::LocalLive
        }
        aos_sandbox_protocol::MountSourceProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV2::BestEffortReplica
        }
    };
    if proof_class == SourceAcquisitionProofClassV2::LocalLive {
        let binding = SourceRealizationBindingV1::from_canonical_bytes(&row.source_binding)
            .map_err(|_| state_error("Complete Acquire source binding is invalid"))?;
        if !binding.matches_local_live_provider_proof(lease.proof()) {
            return Err(state_error(
                "Complete Acquire live grant differs from its View source",
            ));
        }
    }
    let physical = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: row.source_binding_digest,
        proof_class: mount_proof,
        provider_authority_id: lease.provider().authority_id(),
        provider_authority_generation: lease.provider().authority_generation(),
        provider_authority_digest: *lease.provider().authority_digest().as_bytes(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_commitment.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        kernel_boot_id: receipt.kernel_boot_id(),
        device: receipt.device(),
        inode: receipt.inode(),
        unique_mount_id: receipt.unique_mount_id(),
    });
    let observation = SourceRootObservationV1::new(
        receipt.kernel_boot_id(),
        receipt.device(),
        receipt.inode(),
        receipt.unique_mount_id(),
        true,
        true,
        true,
    )
    .map_err(|_| state_error("Complete Acquire descriptor observation is invalid"))?;
    let descriptor = source_root_descriptor_commitment_v1(&observation);
    let selection_floor = SourceSelectionFloorV1::new(
        ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
        session.scope.provider_authority_id,
        session.scope.route_id,
        resource.clone(),
        signed_lease.signer().clone(),
        lease.lease_id(),
        digest_signed_export_lease(&signed_lease),
        lease.proof().class_code(),
        proof_digest,
        resource_commitment,
        session.trust_generation,
        ObjectDigest::from_bytes(session.trust_digest),
        session.revocation_generation,
        ObjectDigest::from_bytes(session.revocation_digest),
    )
    .map_err(|_| state_error("Complete Acquire selection floor is invalid"))?;
    let (catalog_floor, requested_selection_floor) = protocol_acquire_verification_floor_v2(
        attempt
            .acquire_verification_floor
            .as_ref()
            .ok_or_else(|| state_error("Complete Acquire lacks its pre-I/O verification floor"))?,
    )
    .map_err(|_| state_error("Complete Acquire verification floor is invalid"))?;
    if requested_selection_floor
        .as_ref()
        .is_some_and(|floor| floor != &selection_floor)
    {
        return Err(state_error(
            "Complete Acquire changes its pre-I/O selection floor",
        ));
    }
    let selection = selection_floor_snapshot_v2(&selection_floor);
    Ok(SourceAcquisitionEvidenceV2 {
        acquire_attempt: RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        },
        outcome_verification_anchor: *verification_anchor,
        provider_acquisition: row.provider_acquisition,
        session_id: session.session_id,
        provider_outcome_signer_digest: session.signers[3].public_key_fingerprint,
        historical_lease_signer: HistoricalLeaseSignerV2 {
            signer: session.signers[3].clone(),
            catalog_floor_provider_authority_id: catalog_floor.provider_authority_id(),
            catalog_floor_resource_namespace_digest: *catalog_floor
                .resource_namespace_digest()
                .as_bytes(),
            minimum_catalog_generation: catalog_floor.minimum_catalog_generation(),
            minimum_catalog_digest: *catalog_floor.minimum_catalog_digest().as_bytes(),
            selection_floor: selection,
            selection_floor_digest: *selection_floor.digest().as_bytes(),
        },
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_commitment.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        provider_selection_generation: resource.selection_generation(),
        provider_selection_digest: *resource.selection_digest().as_bytes(),
        provider_proof_class: lease.proof().class_code(),
        proof_class,
        provider_proof_digest: *proof_digest.as_bytes(),
        lease_id: lease.lease_id(),
        signed_lease_digest: *digest_signed_export_lease(&signed_lease).as_bytes(),
        lease_issued_seconds: lease.issued_seconds(),
        lease_expires_seconds: lease.expires_seconds(),
        source_realization_handle: mount_source_realization_handle_v1(
            row.source_binding_digest,
            physical,
        ),
        source_physical_proof_digest: physical,
        source_kernel_boot_id: receipt.kernel_boot_id(),
        source_device: receipt.device(),
        source_inode: receipt.inode(),
        source_unique_mount_id: receipt.unique_mount_id(),
        descriptor_commitment: *descriptor.as_bytes(),
    })
}

fn release_generation(attempt: &SourceProviderQueryAttemptV2) -> Result<u64> {
    let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } = &attempt.state else {
        return Err(state_error("Complete Release attempt is not consumed"));
    };
    let receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Complete Release receipt is invalid"))?;
    Ok(receipt.subject().release_generation())
}

fn consumed_inventory(
    attempt: &SourceProviderQueryAttemptV2,
) -> Result<aos_sandbox_source_provider_protocol::SourceProviderInventoryV1> {
    let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } = &attempt.state else {
        return Err(state_error("Complete Inventory attempt is not consumed"));
    };
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Complete Inventory is invalid"))?;
    Ok(signed.subject().clone())
}
