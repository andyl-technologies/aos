//! Same-intent AOSMSA02 Acquire retries.
//!
//! A retry retains the Mount identity, holder-wide sequence, immutable intent,
//! and exact predecessor witness. A newer holder authority may rederive the
//! provider ID without consuming another holder sequence.

use aos_sandbox::journal::ProtectedJournalAuthority;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::mount_source_acquisition_state::acquire_verification_floor_v2;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, NormalizedAcquisitionIntentV2, ReleaseSourceRequestV1,
    SourceProviderAuthorityV1, SourceProviderMethod, SourceUseV1, digest_logical_binding_bytes,
    source_acquisition_id_v2,
};
use aos_sandbox_source_provider_security::{
    AuthorizedMountAcquireVerificationFloorV2, CurrentRootMountSourceProviderSessionV1,
};

use super::SourceAcquisitionTableV2;
use super::format::{
    MutationTagV2, acquisition_key, attempt_id, provider_head_key, provider_session_key,
    put_record, request_id, state_error,
};
use super::model::*;
use super::projection::{projection_entries, projection_from_entries};
use super::reservation::{
    ReservedProviderQueryV2, confirm_reservation, sealed_attempt, sealed_head, sealed_row,
};
use super::security::{session_from_projection, session_from_request};
use super::transition::{
    MutationIdentityV2, acquisition_predecessor, commit_mutation, next_revision, record_ref,
};
use crate::Result;

impl SourceAcquisitionTableV2 {
    /// Reserves another authenticated Acquire for the same immutable intent.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact tail is retryable, recovery permits
    /// retry, the holder sequence remains allocated, the current session
    /// dominates the provider mapping, and the atomic reservation succeeds.
    #[doc(hidden)]
    pub(crate) fn prepare_and_reserve_acquire_retry_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        catalog_journal: &ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_record_digest: [u8; 32],
        verification_floor: AuthorizedMountAcquireVerificationFloorV2,
        provider_deadline_seconds: i64,
    ) -> Result<ReservedProviderQueryV2> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .filter(|row| {
                row.revision == expected_revision
                    && row.record_digest == expected_record_digest
                    && row.phase == SourceAcquisitionPhaseV2::PendingQuery
                    && row.evidence.is_none()
            })
            .cloned()
            .ok_or_else(|| state_error("Acquire retry row is not retryable"))?;
        let tail = self
            .provider_attempts
            .get(&row.acquire_lineage.tail.id)
            .filter(|attempt| {
                attempt.revision == row.acquire_lineage.tail.revision
                    && attempt.record_digest == row.acquire_lineage.tail.record_digest
                    && attempt.method == ProviderMethodV2::Acquire
                    && attempt.owner == ProviderQueryOwnerV2::Acquire { acquisition_id }
                    && !matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::Reserved
                            | ProviderAttemptStateV2::DispositionConsumed {
                                status: ProviderStatusV2::Complete,
                                ..
                            }
                    )
            })
            .cloned()
            .ok_or_else(|| state_error("Acquire retry predecessor is not retryable"))?;
        if !(matches!(&row.recovery, AcquisitionRecoveryV2::Ready)
            || matches!(
                &row.recovery,
                AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                    if *root_attempt == row.acquire_lineage.tail
            ))
        {
            return Err(state_error("Acquire retry lacks a recovery permit"));
        }
        let identity = (
            row.scope.holder_authority_id,
            row.scope.provider_authority_id,
        );
        let head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.recovery_barrier.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .cloned()
            .ok_or_else(|| state_error("Acquire retry requires an idle provider head"))?;
        let head_record = put_record(&StoredRecordV2::ProviderHead {
            value: head.clone(),
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
                head.next_request_sequence,
                head.next_response_sequence,
            )
            .map_err(|_| state_error("protected Acquire retry planning failed"))?;
        let predecessor_session = self
            .provider_sessions
            .get(&head.current_session_id)
            .and_then(|value| value.predecessor_session_id);
        let projected = session_from_projection(plan.session(), predecessor_session)?;
        if projected.session_id != head.current_session_id
            || projected.record_digest != head.current_session_record_digest
            || projected.scope != head.scope
        {
            return Err(state_error(
                "Acquire retry session differs from current head",
            ));
        }
        let provider_acquisition =
            successor_provider_identity(row.provider_acquisition, &projected)?;
        if self.holder_sequences.get(&identity.0).is_none_or(|floor| {
            floor.last_allocated_acquisition_sequence < provider_acquisition.acquisition_sequence
        }) {
            return Err(state_error(
                "Acquire retry sequence is not durably allocated",
            ));
        }
        let root = self
            .provider_attempts
            .get(&row.acquire_lineage.root.id)
            .ok_or_else(|| state_error("Acquire retry root is absent"))?;
        let intent = root.intent.clone();
        let stable = match &intent {
            ProviderIntentV2::Acquire { value } => value.clone(),
            _ => return Err(state_error("Acquire retry root has wrong intent")),
        };
        let number = tail
            .attempt_number
            .checked_add(1)
            .ok_or_else(|| state_error("Acquire retry number is exhausted"))?;
        let mut attempt = retry_attempt(
            &row,
            &tail,
            &head,
            &projected,
            intent,
            provider_acquisition,
            number,
        );
        attempt.attempt_id = attempt_id(&attempt);
        attempt.request_id = request_id(attempt.attempt_id);
        let provider_request = AcquireSourceRequestV1::new_v2(
            ObjectDigest::from_bytes(projected.session_binding),
            attempt.request_sequence,
            attempt.request_id,
            provider_acquisition.acquisition_sequence,
            stable.prospective_mount_template.clone(),
            ObjectDigest::from_bytes(stable.prospective_mount_template_digest),
            SourceUseV1::MountCreate,
            projected.node_id,
            projected.kernel_boot_id,
            provider_acquisition.holder_authority_id,
            provider_acquisition.holder_authority_generation,
            ObjectDigest::from_bytes(provider_acquisition.holder_authority_digest),
            stable.source_binding.clone(),
            digest_logical_binding_bytes(&stable.source_binding),
            provider_deadline_seconds.min(projected.current_valid_until_seconds),
            stable.requested_lease_seconds,
            ObjectDigest::from_bytes(projected.revocation_digest),
            stable.recursive,
            stable.requested_maximum_submounts,
            stable.kernel_coupled,
        )
        .map_err(|_| state_error("table-derived Acquire retry is invalid"))?;
        let normalized = NormalizedAcquisitionIntentV2::from_acquire_request(
            &provider_request,
            plan.session().authority_trust()[1].authority().clone(),
            plan.session().authority_trust()[0].authority().clone(),
            projected.node_id,
            projected.kernel_boot_id,
            projected.scope.route_id,
            projected.route_generation,
            ObjectDigest::from_bytes(projected.route_digest),
            ObjectDigest::from_bytes(projected.scope.resource_namespace_digest),
            projected.revocation_generation,
            ObjectDigest::from_bytes(projected.revocation_digest),
        )
        .map_err(|_| state_error("table-derived Acquire retry normalization is invalid"))?;
        let prepared = session
            .prepare_acquire_v2(
                journal,
                catalog_journal,
                plan,
                provider_request,
                normalized,
                verification_floor,
            )
            .map_err(|_| state_error("protected Acquire retry preparation failed"))?;
        let request_projection = prepared.projection();
        if request_projection.method() != SourceProviderMethod::Acquire
            || request_projection.request_identity()
                != (attempt.request_id, attempt.request_sequence)
            || request_projection.acquisition_identity()
                != Some((
                    ObjectDigest::from_bytes(provider_acquisition.acquisition_id),
                    provider_acquisition.acquisition_sequence,
                ))
            || session_from_request(request_projection, predecessor_session)? != projected
        {
            return Err(state_error("prepared Acquire retry differs"));
        }
        let normalized_bytes = request_projection
            .normalized_intent()
            .ok_or_else(|| state_error("prepared Acquire retry lacks normalization"))?;
        let normalized_digest = request_projection
            .request_digests()
            .0
            .ok_or_else(|| state_error("prepared Acquire retry lacks normalization digest"))?;
        let (catalog_floor, selection_floor, current_catalog_head_commitment) = request_projection
            .verification_floors()
            .ok_or_else(|| state_error("prepared Acquire retry lacks verification floors"))?;
        attempt.normalized_acquire_intent = Some(AttemptNormalizedAcquireV2 {
            bytes: normalized_bytes.to_vec(),
            digest: *normalized_digest.as_bytes(),
            maximum_lease_expiry_seconds: request_projection
                .deadline_seconds()
                .min(projected.current_valid_until_seconds),
        });
        attempt.acquire_verification_floor = Some(acquire_verification_floor_v2(
            catalog_floor,
            selection_floor,
            Some(*current_catalog_head_commitment.as_bytes()),
        ));
        attempt.signed_request = prepared.canonical_signed_request().to_vec();
        attempt.signed_request_digest = *request_projection.request_digests().2.as_bytes();
        let attempt = sealed_attempt(attempt)?;
        let attempt_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        })?;

        let mut next_row = row.clone();
        next_row.revision = next_revision(row.revision)?;
        next_row.provider_acquisition = provider_acquisition;
        next_row.acquire_lineage.tail = attempt_ref;
        next_row.acquire_lineage.next_attempt_number = number
            .checked_add(1)
            .ok_or_else(|| state_error("Acquire lineage number is exhausted"))?;
        next_row.recovery = AcquisitionRecoveryV2::Ready;
        next_row.record_digest = [0; 32];
        let next_row = sealed_row(next_row)?;
        let mut rows = self.acquisitions.clone();
        rows.insert(acquisition_id, next_row.clone());
        let current_entries = projection_entries(head.scope, &self.acquisitions);
        let next_entries = projection_entries(head.scope, &rows);
        let mut next_head = head.clone();
        next_head.revision = next_revision(head.revision)?;
        next_head.next_request_sequence = head
            .next_request_sequence
            .checked_add(1)
            .ok_or_else(|| state_error("provider request sequence is exhausted"))?;
        next_head.pending_attempt = Some(attempt_ref);
        if current_entries != next_entries {
            let epoch = head
                .current_projection_epoch
                .checked_add(1)
                .ok_or_else(|| state_error("provider projection epoch is exhausted"))?;
            let projection = projection_from_entries(head.scope, epoch, &next_entries)?;
            next_head.current_projection_epoch = epoch;
            next_head.current_projection_digest = projection.digest;
            next_head.last_reconciliation = None;
        }
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::ReserveRetry,
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
                StoredRecordV2::Acquisition { value: next_row },
                StoredRecordV2::ProviderHead {
                    value: next_head.clone(),
                },
            ],
        )?;
        confirm_reservation(journal, prepared, &attempt, &next_head)
    }
}

impl SourceAcquisitionTableV2 {
    /// Reserves another authenticated Release for the retained Release intent.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact Release tail is retryable, recovery
    /// permits retry, the current session still names the lease holder, and
    /// the attempt/row/head reservation commits atomically.
    #[doc(hidden)]
    pub(crate) fn prepare_and_reserve_release_retry_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_record_digest: [u8; 32],
        provider_deadline_seconds: i64,
    ) -> Result<ReservedProviderQueryV2> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .filter(|row| {
                row.revision == expected_revision
                    && row.record_digest == expected_record_digest
                    && (row.phase == SourceAcquisitionPhaseV2::Releasing
                        || (row.phase == SourceAcquisitionPhaseV2::Faulted
                            && row.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing)))
                    && row.release_proof.is_none()
            })
            .cloned()
            .ok_or_else(|| state_error("Release retry row is not retryable"))?;
        let lineage = row
            .release_lineage
            .as_ref()
            .ok_or_else(|| state_error("Release retry lineage is absent"))?;
        let tail = self
            .provider_attempts
            .get(&lineage.tail.id)
            .filter(|attempt| {
                attempt.revision == lineage.tail.revision
                    && attempt.record_digest == lineage.tail.record_digest
                    && attempt.method == ProviderMethodV2::Release
                    && !matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::Reserved
                            | ProviderAttemptStateV2::DispositionConsumed {
                                status: ProviderStatusV2::Complete,
                                ..
                            }
                    )
            })
            .cloned()
            .ok_or_else(|| state_error("Release retry predecessor is not retryable"))?;
        if !(matches!(&row.recovery, AcquisitionRecoveryV2::Ready)
            || matches!(
                &row.recovery,
                AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                    if *root_attempt == lineage.tail
            ))
        {
            return Err(state_error("Release retry lacks a recovery permit"));
        }
        let identity = (
            row.scope.holder_authority_id,
            row.scope.provider_authority_id,
        );
        let head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.recovery_barrier.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .cloned()
            .ok_or_else(|| state_error("Release retry requires an idle provider head"))?;
        let head_record = put_record(&StoredRecordV2::ProviderHead {
            value: head.clone(),
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
                head.next_request_sequence,
                head.next_response_sequence,
            )
            .map_err(|_| state_error("protected Release retry planning failed"))?;
        let predecessor_session = self
            .provider_sessions
            .get(&head.current_session_id)
            .and_then(|value| value.predecessor_session_id);
        let projected = session_from_projection(plan.session(), predecessor_session)?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("Release retry lacks Acquire evidence"))?;
        if projected.session_id != head.current_session_id
            || projected.record_digest != head.current_session_record_digest
        {
            return Err(state_error(
                "Release retry session differs from current head",
            ));
        }
        let historical_holder = projected.root_mount_authority_generation
            != row.provider_acquisition.holder_authority_generation
            || projected.root_mount_authority_digest
                != row.provider_acquisition.holder_authority_digest;
        if historical_holder
            && projected.root_mount_authority_generation
                <= row.provider_acquisition.holder_authority_generation
        {
            return Err(state_error(
                "Release retry holder does not dominate retained acquisition authority",
            ));
        }
        let root = self
            .provider_attempts
            .get(&lineage.root.id)
            .ok_or_else(|| state_error("Release retry root is absent"))?;
        let intent = root.intent.clone();
        if !matches!(intent, ProviderIntentV2::Release { .. }) {
            return Err(state_error("Release retry root has wrong intent"));
        }
        let number = tail
            .attempt_number
            .checked_add(1)
            .ok_or_else(|| state_error("Release retry number is exhausted"))?;
        let mut attempt = SourceProviderQueryAttemptV2 {
            attempt_id: [0; 32],
            revision: 1,
            scope: row.scope,
            method: ProviderMethodV2::Release,
            owner: ProviderQueryOwnerV2::Release { acquisition_id },
            intent,
            provider_acquisition: Some(row.provider_acquisition),
            immutable_intent_digest: row
                .release_intent_digest
                .ok_or_else(|| state_error("Release retry lacks intent digest"))?,
            lineage_root_attempt_id: lineage.root.id,
            previous_attempt_id: Some(tail.attempt_id),
            attempt_number: number,
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
            request_sequence: head.next_request_sequence,
            signed_request: Vec::new(),
            signed_request_digest: [0; 32],
            owner_predecessor_revision: row.revision,
            owner_predecessor_digest: row.record_digest,
            owner_predecessor: Some(acquisition_predecessor(&row)),
            state: ProviderAttemptStateV2::Reserved,
            record_digest: [0; 32],
        };
        attempt.attempt_id = attempt_id(&attempt);
        attempt.request_id = request_id(attempt.attempt_id);
        let provider_request = ReleaseSourceRequestV1::new(
            ObjectDigest::from_bytes(projected.session_binding),
            attempt.request_sequence,
            attempt.request_id,
            ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
            projected.scope.holder_authority_id,
            projected.root_mount_authority_generation,
            ObjectDigest::from_bytes(projected.root_mount_authority_digest),
            evidence.lease_id,
            ObjectDigest::from_bytes(evidence.signed_lease_digest),
            provider_deadline_seconds.min(projected.current_valid_until_seconds),
        )
        .map_err(|_| state_error("table-derived Release retry is invalid"))?;
        let prepared = if historical_holder {
            let acquire_session_id = evidence.session_id;
            let acquire_session = self
                .provider_sessions
                .get(&acquire_session_id)
                .cloned()
                .ok_or_else(|| state_error("historical Release retry session is absent"))?;
            let predecessor_holder = SourceProviderAuthorityV1::new(
                acquire_session.scope.holder_authority_id,
                acquire_session.root_mount_authority_generation,
                ObjectDigest::from_bytes(acquire_session.root_mount_authority_digest),
            )
            .map_err(|_| state_error("historical Release retry holder is invalid"))?;
            let authorization = session
                .authorize_historical_mount_release_v2(
                    journal,
                    journal.snapshot()?,
                    acquisition_key(acquisition_id),
                    materialized_record(StoredRecordV2::Acquisition { value: row.clone() })?,
                    provider_session_key(acquire_session.session_id),
                    materialized_record(StoredRecordV2::ProviderSession {
                        value: acquire_session.clone(),
                    })?,
                    predecessor_holder,
                    ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
                    row.provider_acquisition.acquisition_sequence,
                    evidence.lease_id,
                    ObjectDigest::from_bytes(evidence.signed_lease_digest),
                    acquire_session.authenticated_at_seconds,
                    acquire_session.trust_generation,
                    ObjectDigest::from_bytes(acquire_session.trust_digest),
                    acquire_session.revocation_generation,
                    ObjectDigest::from_bytes(acquire_session.revocation_digest),
                    acquire_session.signed_root_mount_hello.clone(),
                )
                .map_err(|_| state_error("historical Release retry authorization failed"))?;
            session
                .prepare_historical_release_v2(journal, plan, provider_request, authorization)
                .map_err(|_| state_error("protected historical Release retry failed"))?
        } else {
            session
                .prepare_release_v2(
                    journal,
                    plan,
                    provider_request,
                    row.provider_acquisition.acquisition_sequence,
                )
                .map_err(|_| state_error("protected Release retry preparation failed"))?
        };
        let request_projection = prepared.projection();
        if request_projection.method() != SourceProviderMethod::Release
            || request_projection.request_identity()
                != (attempt.request_id, attempt.request_sequence)
            || request_projection.acquisition_identity()
                != Some((
                    ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
                    row.provider_acquisition.acquisition_sequence,
                ))
            || session_from_request(request_projection, predecessor_session)? != projected
        {
            return Err(state_error("prepared Release retry differs"));
        }
        attempt.signed_request = prepared.canonical_signed_request().to_vec();
        attempt.signed_request_digest = *request_projection.request_digests().2.as_bytes();
        let attempt = sealed_attempt(attempt)?;
        let attempt_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        })?;
        let mut next_row = row.clone();
        next_row.revision = next_revision(row.revision)?;
        next_row.phase = SourceAcquisitionPhaseV2::Releasing;
        let next_lineage = next_row
            .release_lineage
            .as_mut()
            .ok_or_else(|| state_error("Release retry lineage disappeared"))?;
        next_lineage.tail = attempt_ref;
        next_lineage.next_attempt_number = number
            .checked_add(1)
            .ok_or_else(|| state_error("Release lineage number is exhausted"))?;
        next_row.recovery = AcquisitionRecoveryV2::Ready;
        if row.phase == SourceAcquisitionPhaseV2::Faulted {
            next_row.retained_faulted_from = row.faulted_from;
            next_row.retained_fault_digest = row.fault_digest;
            next_row.faulted_from = None;
            next_row.fault_digest = None;
        }
        next_row.record_digest = [0; 32];
        let next_row = sealed_row(next_row)?;
        let mut next_head = head.clone();
        next_head.revision = next_revision(head.revision)?;
        next_head.next_request_sequence = head
            .next_request_sequence
            .checked_add(1)
            .ok_or_else(|| state_error("provider request sequence is exhausted"))?;
        next_head.pending_attempt = Some(attempt_ref);
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::ReserveRetry,
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
                StoredRecordV2::Acquisition { value: next_row },
                StoredRecordV2::ProviderHead {
                    value: next_head.clone(),
                },
            ],
        )?;
        confirm_reservation(journal, prepared, &attempt, &next_head)
    }
}

fn materialized_record(record: StoredRecordV2) -> Result<Vec<u8>> {
    put_record(&record)?
        .value()
        .map(ToOwned::to_owned)
        .ok_or_else(|| state_error("AOSMSA02 record materialized as a delete"))
}

fn successor_provider_identity(
    current: ProviderAcquisitionIdentityV2,
    session: &SourceProviderSessionV2,
) -> Result<ProviderAcquisitionIdentityV2> {
    if session.scope.holder_authority_id != current.holder_authority_id
        || session.root_mount_authority_generation < current.holder_authority_generation
        || (session.root_mount_authority_generation == current.holder_authority_generation
            && session.root_mount_authority_digest != current.holder_authority_digest)
    {
        return Err(state_error(
            "Acquire retry holder authority does not dominate",
        ));
    }
    if session.root_mount_authority_generation == current.holder_authority_generation {
        return Ok(current);
    }
    Ok(ProviderAcquisitionIdentityV2 {
        holder_authority_id: current.holder_authority_id,
        holder_authority_generation: session.root_mount_authority_generation,
        holder_authority_digest: session.root_mount_authority_digest,
        acquisition_sequence: current.acquisition_sequence,
        acquisition_id: *source_acquisition_id_v2(
            current.holder_authority_id,
            session.root_mount_authority_generation,
            ObjectDigest::from_bytes(session.root_mount_authority_digest),
            current.acquisition_sequence,
        )
        .as_bytes(),
    })
}

#[allow(clippy::too_many_arguments)]
fn retry_attempt(
    row: &SourceAcquisitionRowV2,
    predecessor: &SourceProviderQueryAttemptV2,
    head: &SourceProviderHeadV2,
    session: &SourceProviderSessionV2,
    intent: ProviderIntentV2,
    provider_acquisition: ProviderAcquisitionIdentityV2,
    attempt_number: u64,
) -> SourceProviderQueryAttemptV2 {
    SourceProviderQueryAttemptV2 {
        attempt_id: [0; 32],
        revision: 1,
        scope: row.scope,
        method: ProviderMethodV2::Acquire,
        owner: ProviderQueryOwnerV2::Acquire {
            acquisition_id: row.acquisition_id,
        },
        intent,
        provider_acquisition: Some(provider_acquisition),
        immutable_intent_digest: row.acquire_intent_digest,
        lineage_root_attempt_id: row.acquire_lineage.root.id,
        previous_attempt_id: Some(predecessor.attempt_id),
        attempt_number,
        session_id: session.session_id,
        session_record_digest: session.record_digest,
        signer_set_commitment: session.signer_set_commitment,
        trust_digest: session.trust_digest,
        revocation_digest: session.revocation_digest,
        route_digest: session.route_digest,
        process_execution_digest: session.provider_execution.process_execution_digest,
        normalized_acquire_intent: None,
        acquire_verification_floor: None,
        inventory_correlations: None,
        request_id: [0; 16],
        request_sequence: head.next_request_sequence,
        signed_request: Vec::new(),
        signed_request_digest: [0; 32],
        owner_predecessor_revision: row.revision,
        owner_predecessor_digest: row.record_digest,
        owner_predecessor: Some(acquisition_predecessor(row)),
        state: ProviderAttemptStateV2::Reserved,
        record_digest: [0; 32],
    }
}
