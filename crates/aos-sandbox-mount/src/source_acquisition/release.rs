//! AOSMSA02 Release admission and provider-request reservation.
//!
//! The exact Mount Release body, dominating teardown fence, predecessor CAS,
//! lease evidence, and pre-reservation acquisition witness are committed before
//! the security-owned carrier can send the provider request.

use aos_sandbox::journal::{JournalTransaction, ProtectedJournalAuthority};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::{
    LiveValidatedReleaseMountSourceAcquisitionRequest, mount_source_acquisition_request_digest_v1,
};
use aos_sandbox_source_provider_protocol::{
    ReleaseSourceRequestV1, SignedSourceProviderRequestV1, SourceProviderAuthorityV1,
    SourceProviderMethod, decode_release_request, digest_release_request,
};
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, PreparedMountProviderRequestV2,
    PreparedMountSourceReleaseV2,
};

use super::SourceAcquisitionTableV2;
use super::format::{
    MutationTagV2, acquisition_key, attempt_id, intent_digest, provider_head_key,
    provider_session_key, put_record, request_id, state_error,
};
use super::lifecycle::SourceAcquisitionPostcommitOutcomeV2;
use super::model::*;
use super::projection::{projection_entries, projection_from_entries};
use super::reservation::{sealed_attempt, sealed_head, sealed_row};
use super::security::session_from_request;
use super::transition::{
    MutationIdentityV2, acquisition_predecessor, next_revision, prepare_mutation, record_ref,
};
use crate::Result;

/// Retains both the sole provider send permit and the exact SourceRoot Release authority.
#[doc(hidden)]
pub(crate) struct ReservedReleaseProviderQueryV2 {
    postcommit: SourceAcquisitionPostcommitOutcomeV2,
}

/// Returns precommit Release custody to the fixed owner after a failed reservation.
pub(crate) struct RetainedReleasePreparationFailureV2 {
    error: crate::MountError,
    prepared_release: PreparedMountSourceReleaseV2,
}

impl ReservedReleaseProviderQueryV2 {
    pub(super) fn into_postcommit(self) -> SourceAcquisitionPostcommitOutcomeV2 {
        self.postcommit
    }
}

impl RetainedReleasePreparationFailureV2 {
    pub(super) fn into_parts(self) -> (crate::MountError, PreparedMountSourceReleaseV2) {
        (self.error, self.prepared_release)
    }
}

impl SourceAcquisitionTableV2 {
    /// Begins one exact controller-authorized Release and reserves provider I/O.
    ///
    /// # Errors
    ///
    /// Returns an error for stale controller CAS, a nondominating fence,
    /// missing lease/custody evidence, unresolved provider recovery, a nonidle
    /// head, current-holder mismatch, invalid protected preparation, or commit.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub(crate) fn prepare_and_begin_release_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        live_request: &LiveValidatedReleaseMountSourceAcquisitionRequest,
        mount_request: Vec<u8>,
        provider_deadline_seconds: i64,
        prepared_release: PreparedMountSourceReleaseV2,
    ) -> std::result::Result<ReservedReleaseProviderQueryV2, RetainedReleasePreparationFailureV2>
    {
        let (transaction, prepared) = match self.prepare_release_reservation_v2(
            journal,
            session,
            live_request,
            mount_request,
            provider_deadline_seconds,
            &prepared_release,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(RetainedReleasePreparationFailureV2 {
                    error,
                    prepared_release,
                });
            }
        };
        let postcommit = session.commit_mount_source_release_v2(
            journal,
            transaction,
            prepared_release,
            prepared,
        );
        let postcommit = self.retain_source_root_postcommit(journal, postcommit);
        Ok(ReservedReleaseProviderQueryV2 { postcommit })
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_release_reservation_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        live_request: &LiveValidatedReleaseMountSourceAcquisitionRequest,
        mount_request: Vec<u8>,
        provider_deadline_seconds: i64,
        prepared_release: &PreparedMountSourceReleaseV2,
    ) -> Result<(JournalTransaction, PreparedMountProviderRequestV2)> {
        let request = live_request.request();
        let acquisition_id = *request.acquisition_id().as_bytes();
        let current_row = self
            .acquisitions
            .get(&acquisition_id)
            .filter(|row| {
                row.revision == request.expected_revision()
                    && row.record_digest == *request.expected_record_digest().as_bytes()
            })
            .cloned()
            .ok_or_else(|| state_error("Mount Release compare-and-swap failed"))?;
        let evidence = current_row
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("Mount Release lacks Complete Acquire evidence"))?;
        let custody = prepared_release.projection();
        let loss_matches = match custody.manager_custody_loss() {
            None => current_row.manager_custody_loss.is_none(),
            Some(loss) => {
                current_row.manager_custody_loss.is_none()
                    && loss.subject.acquisition_id == current_row.acquisition_id
                    && loss.subject.acquisition_revision == current_row.revision
                    && loss.subject.acquisition_record_digest == current_row.record_digest
            }
        };
        let effective_phase = if current_row.phase == SourceAcquisitionPhaseV2::Faulted {
            current_row
                .faulted_from
                .ok_or_else(|| state_error("faulted Release predecessor lacks origin"))?
        } else {
            current_row.phase
        };
        if !matches!(
            effective_phase,
            SourceAcquisitionPhaseV2::PendingQuery
                | SourceAcquisitionPhaseV2::DescriptorCustodied
                | SourceAcquisitionPhaseV2::Active
                | SourceAcquisitionPhaseV2::Consumed
        ) || current_row.release.is_some()
            || !matches!(&current_row.recovery, AcquisitionRecoveryV2::Ready)
            || mount_source_acquisition_request_digest_v1(&mount_request)
                != request.request_digest()
            || custody.mount_acquisition_id() != Some(acquisition_id)
            || custody.provider_acquisition()
                != (
                    evidence.provider_acquisition.acquisition_id,
                    evidence.provider_acquisition.acquisition_sequence,
                )
            || custody.lease()
                != (
                    evidence.lease_id,
                    ObjectDigest::from_bytes(evidence.signed_lease_digest),
                )
            || custody.descriptor_commitment().as_bytes() != &evidence.descriptor_commitment
            || custody.source_realization_handle() != Some(evidence.source_realization_handle)
            || custody.manager_custody() != current_row.manager_custody
            || !loss_matches
            || custody.lifecycle_commitment().as_bytes() == &[0; 32]
        {
            return Err(state_error("Mount Release predecessor is not releasable"));
        }
        let identity = (
            current_row.scope.holder_authority_id,
            current_row.scope.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.recovery_barrier.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .cloned()
            .ok_or_else(|| state_error("Mount Release requires an idle provider head"))?;
        let head_record = put_record(&StoredRecordV2::ProviderHead {
            value: current_head.clone(),
        })?
        .value()
        .ok_or_else(|| state_error("provider head materialized as a delete"))?
        .to_vec();
        let plan = session
            .current_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(identity.0, identity.1),
                head_record,
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected Release session planning failed"))?;
        let projected = super::security::session_from_projection(
            plan.session(),
            self.provider_sessions
                .get(&current_head.current_session_id)
                .and_then(|stored| stored.predecessor_session_id),
        )?;
        if projected.session_id != current_head.current_session_id
            || projected.record_digest != current_head.current_session_record_digest
        {
            return Err(state_error(
                "current Release session differs from retained provider acquisition",
            ));
        }
        let historical_holder = projected.root_mount_authority_generation
            != current_row.provider_acquisition.holder_authority_generation
            || projected.root_mount_authority_digest
                != current_row.provider_acquisition.holder_authority_digest;
        if historical_holder
            && projected.root_mount_authority_generation
                <= current_row.provider_acquisition.holder_authority_generation
        {
            return Err(state_error(
                "current Release holder does not dominate retained acquisition authority",
            ));
        }

        let release = MountOperationV2 {
            operation_id: *request.header().request_id(),
            request_digest: *request.request_digest().as_bytes(),
        };
        let authority = ReleaseAuthorityV2 {
            sandbox_id: *request.fence().sandbox_id(),
            incarnation_id: *request.fence().incarnation_id(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: *request.fence().assignment_digest(),
            expected_revision: request.expected_revision(),
            expected_record_digest: *request.expected_record_digest().as_bytes(),
        };
        let intent = ProviderIntentV2::Release {
            value: ReleaseIntentV2 {
                scope: current_row.scope,
                acquisition_id,
                provider_acquisition: current_row.provider_acquisition,
                mount_request: mount_request.clone(),
                mount_operation: release,
                authority,
                lease_id: evidence.lease_id,
                signed_lease_digest: evidence.signed_lease_digest,
                provider_resource_id: evidence.provider_resource_id,
                provider_resource_digest: evidence.provider_resource_digest,
                provider_proof_digest: evidence.provider_proof_digest,
                descriptor_commitment: evidence.descriptor_commitment,
            },
        };
        let immutable_intent_digest = intent_digest(&intent)?;
        let mut attempt = SourceProviderQueryAttemptV2 {
            attempt_id: [0; 32],
            revision: 1,
            scope: current_row.scope,
            method: ProviderMethodV2::Release,
            owner: ProviderQueryOwnerV2::Release { acquisition_id },
            intent,
            provider_acquisition: Some(current_row.provider_acquisition),
            immutable_intent_digest,
            lineage_root_attempt_id: [0; 32],
            previous_attempt_id: None,
            attempt_number: 1,
            session_id: projected.session_id,
            session_record_digest: projected.record_digest,
            signer_set_commitment: projected.signer_set_commitment,
            trust_digest: projected.trust_digest,
            revocation_digest: projected.revocation_digest,
            route_digest: projected.route_digest,
            process_execution_digest: projected.provider_execution.process_execution_digest,
            normalized_acquire_intent: None,
            acquire_verification_floor: None,
            inventory_correlations: None,
            request_id: [0; 16],
            request_sequence: current_head.next_request_sequence,
            signed_request: Vec::new(),
            signed_request_digest: [0; 32],
            owner_predecessor_revision: current_row.revision,
            owner_predecessor_digest: current_row.record_digest,
            owner_predecessor: Some(acquisition_predecessor(&current_row)),
            state: ProviderAttemptStateV2::Reserved,
            record_digest: [0; 32],
        };
        attempt.attempt_id = attempt_id(&attempt);
        attempt.lineage_root_attempt_id = attempt.attempt_id;
        attempt.request_id = request_id(attempt.attempt_id);
        let provider_request = ReleaseSourceRequestV1::new(
            ObjectDigest::from_bytes(projected.session_binding),
            attempt.request_sequence,
            attempt.request_id,
            ObjectDigest::from_bytes(current_row.provider_acquisition.acquisition_id),
            projected.scope.holder_authority_id,
            projected.root_mount_authority_generation,
            ObjectDigest::from_bytes(projected.root_mount_authority_digest),
            evidence.lease_id,
            ObjectDigest::from_bytes(evidence.signed_lease_digest),
            provider_deadline_seconds.min(projected.current_valid_until_seconds),
        )
        .map_err(|_| state_error("table-derived provider Release request is invalid"))?;
        let prepared = if historical_holder {
            let acquire_session_id = current_row
                .evidence
                .as_ref()
                .ok_or_else(|| state_error("historical Release lacks Acquire evidence"))?
                .session_id;
            let predecessor_session = self
                .provider_sessions
                .get(&acquire_session_id)
                .cloned()
                .ok_or_else(|| state_error("historical Release session is absent"))?;
            let predecessor_holder = SourceProviderAuthorityV1::new(
                predecessor_session.scope.holder_authority_id,
                predecessor_session.root_mount_authority_generation,
                ObjectDigest::from_bytes(predecessor_session.root_mount_authority_digest),
            )
            .map_err(|_| state_error("historical Release holder authority is invalid"))?;
            let authorization = session
                .authorize_historical_mount_release_v2(
                    journal,
                    journal.snapshot()?,
                    acquisition_key(acquisition_id),
                    materialized_record(StoredRecordV2::Acquisition {
                        value: current_row.clone(),
                    })?,
                    provider_session_key(predecessor_session.session_id),
                    materialized_record(StoredRecordV2::ProviderSession {
                        value: predecessor_session.clone(),
                    })?,
                    predecessor_holder,
                    ObjectDigest::from_bytes(current_row.provider_acquisition.acquisition_id),
                    current_row.provider_acquisition.acquisition_sequence,
                    evidence.lease_id,
                    ObjectDigest::from_bytes(evidence.signed_lease_digest),
                    predecessor_session.authenticated_at_seconds,
                    predecessor_session.trust_generation,
                    ObjectDigest::from_bytes(predecessor_session.trust_digest),
                    predecessor_session.revocation_generation,
                    ObjectDigest::from_bytes(predecessor_session.revocation_digest),
                    predecessor_session.signed_root_mount_hello.clone(),
                )
                .map_err(|_| state_error("historical acquisition authorization failed"))?;
            session
                .prepare_historical_release_v2(journal, plan, provider_request, authorization)
                .map_err(|_| state_error("protected historical Release preparation failed"))?
        } else {
            session
                .prepare_release_v2(
                    journal,
                    plan,
                    provider_request,
                    current_row.provider_acquisition.acquisition_sequence,
                )
                .map_err(|_| state_error("protected provider Release preparation failed"))?
        };
        let request_projection = prepared.projection();
        let signed_request = SignedSourceProviderRequestV1::from_canonical_bytes(
            prepared.canonical_signed_request(),
        )
        .map_err(|_| state_error("prepared Release envelope is invalid"))?;
        let decoded = decode_release_request(signed_request.subject())
            .map_err(|_| state_error("prepared Release body is invalid"))?;
        if request_projection.method() != SourceProviderMethod::Release
            || request_projection.request_identity()
                != (attempt.request_id, attempt.request_sequence)
            || request_projection.expected_response_sequence()
                != current_head.next_response_sequence
            || request_projection.acquisition_identity()
                != Some((
                    ObjectDigest::from_bytes(current_row.provider_acquisition.acquisition_id),
                    current_row.provider_acquisition.acquisition_sequence,
                ))
            || digest_release_request(&decoded) != request_projection.request_digests().1
        {
            return Err(state_error(
                "prepared Release differs from table-derived request",
            ));
        }
        if session_from_request(request_projection, projected.predecessor_session_id)? != projected
        {
            return Err(state_error("prepared Release changes the current session"));
        }
        attempt.signed_request = prepared.canonical_signed_request().to_vec();
        attempt.signed_request_digest = *request_projection.request_digests().2.as_bytes();
        let attempt = sealed_attempt(attempt)?;
        let attempt_reference = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        })?;

        let mut next_row = current_row.clone();
        next_row.revision = next_revision(current_row.revision)?;
        next_row.phase = SourceAcquisitionPhaseV2::Releasing;
        next_row.release = Some(release);
        next_row.mount_release_request = Some(mount_request);
        next_row.release_authority = Some(authority);
        next_row.release_from_phase = Some(effective_phase);
        next_row.release_intent_digest = Some(immutable_intent_digest);
        next_row.release_lineage = Some(QueryLineageV2 {
            root: attempt_reference,
            tail: attempt_reference,
            next_attempt_number: 2,
        });
        next_row.manager_custody_loss = custody.manager_custody_loss();
        if current_row.phase == SourceAcquisitionPhaseV2::Faulted {
            next_row.retained_faulted_from = current_row.faulted_from;
            next_row.retained_fault_digest = current_row.fault_digest;
            next_row.faulted_from = None;
            next_row.fault_digest = None;
        }
        let mut next_rows = self.acquisitions.clone();
        next_rows.insert(acquisition_id, next_row.clone());
        let epoch = current_head
            .current_projection_epoch
            .checked_add(1)
            .ok_or_else(|| state_error("SourceProvider projection epoch is exhausted"))?;
        let entries = projection_entries(current_head.scope, &next_rows);
        let projection = projection_from_entries(current_head.scope, epoch, &entries)?;
        next_row.release_inventory_fence = Some(ReleaseInventoryFenceV2 {
            inventory_observation_floor: current_head.inventory_observation_ordinal,
            projection_epoch: epoch,
            projection_digest: projection.digest,
            projection_entries: entries,
        });
        next_row.record_digest = [0; 32];
        let next_row = sealed_row(next_row)?;
        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.next_request_sequence = current_head
            .next_request_sequence
            .checked_add(1)
            .ok_or_else(|| state_error("SourceProvider request sequence is exhausted"))?;
        next_head.pending_attempt = Some(attempt_reference);
        next_head.current_projection_epoch = epoch;
        next_head.current_projection_digest = projection.digest;
        next_head.last_reconciliation = None;
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        let (transaction, _tentative) = prepare_mutation(
            self,
            MutationIdentityV2 {
                tag: MutationTagV2::BeginRelease,
                holder_id: identity.0,
                provider_id: identity.1,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&identity.0)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: Some(acquisition_id),
                next_row_revision: Some(next_row.revision),
                attempt_id: Some(attempt.attempt_id),
                next_attempt_revision: Some(attempt.revision),
                session_id: None,
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: attempt.clone(),
                },
                StoredRecordV2::Acquisition {
                    value: next_row.clone(),
                },
                StoredRecordV2::ProviderHead {
                    value: next_head.clone(),
                },
            ],
        )?;
        Ok((transaction, prepared))
    }
}
