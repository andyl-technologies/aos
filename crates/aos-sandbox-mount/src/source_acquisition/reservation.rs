//! Pre-I/O AOSMSA02 provider-request reservations.
//!
//! The security crate prepares and signs one exact request without sending it.
//! Mount first commits the corresponding Attempt, owner, and Head records;
//! only an opaque post-commit confirmation can then reach the carrier.

use aos_sandbox::journal::{ProtectedJournalAuthority, ProtectedJournalSnapshot};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::{
    LiveValidatedAcquireMountSourceRequest, decode_historical_acquire_mount_source_request,
    mount_source_acquisition_state::acquire_verification_floor_v2,
};
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, NormalizedAcquisitionIntentV2, SourceProviderMethod, SourceUseV1,
    digest_logical_binding_bytes,
};
use aos_sandbox_source_provider_security::{
    AuthorizedMountAcquireVerificationFloorV2, CurrentRootMountSourceProviderSessionV1,
    PreparedMountProviderRequestV2, ReservedMountProviderRequestV2, SentMountProviderRequestV2,
};

use super::SourceAcquisitionTableV2;
use super::format::{
    MutationTagV2, attempt_id, intent_digest, provider_attempt_key, provider_head_key, put_record,
    request_id, state_error,
};
use super::model::*;
use super::projection::{projection_entries, projection_from_entries};
use super::security::{session_from_projection, session_from_request};
use super::transition::{MutationIdentityV2, commit_mutation, next_revision, record_ref, seal};
use crate::Result;

/// Retains the sole send authority for one durably Reserved provider attempt.
pub(crate) struct ReservedProviderQueryV2 {
    attempt_id: [u8; 32],
    reservation: ReservedMountProviderRequestV2,
}

/// Retains the sole verifier for one provider request handed to the carrier.
pub(crate) struct SentProviderQueryV2 {
    attempt_id: [u8; 32],
    sent: SentMountProviderRequestV2,
}

impl core::fmt::Debug for ReservedProviderQueryV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReservedProviderQueryV2([durable send authority])")
    }
}

impl core::fmt::Debug for SentProviderQueryV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SentProviderQueryV2([outcome authority])")
    }
}

impl ReservedProviderQueryV2 {
    /// Sends the exact request after rechecking its protected journal records.
    pub(crate) fn send(
        self,
        journal: &ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<SentProviderQueryV2> {
        let sent = session
            .send_reserved_mount_request_v2(journal, self.reservation)
            .map_err(|_| state_error("SourceProvider reserved request send failed"))?;
        Ok(SentProviderQueryV2 {
            attempt_id: self.attempt_id,
            sent,
        })
    }
}

impl SentProviderQueryV2 {
    pub(super) fn into_security_parts(
        self,
    ) -> (
        [u8; 32],
        aos_sandbox_source_provider_security::AuthorizedMountProviderOutcomeV2,
    ) {
        (self.attempt_id, self.sent.into_outcome_authorization())
    }
}

impl SourceAcquisitionTableV2 {
    /// Plans, signs, and durably reserves one fresh provider Acquire.
    ///
    /// The holder/provider IDs only select a possible durable head. The
    /// protected session plan supplies and rechecks every authority, route,
    /// trust, process, signer, and sequence fact before signing or commit.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale journal snapshot, a mismatched protected
    /// session, an invalid Mount admission, exhausted holder sequence, invalid
    /// deadline, failed signature preparation, or failed atomic reservation.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub(crate) fn prepare_and_admit_acquire_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        catalog_journal: &ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
        live_request: &LiveValidatedAcquireMountSourceRequest,
        mount_request: Vec<u8>,
        mount_plan_digest: [u8; 32],
        ownership_lease_digest: [u8; 32],
        verification_floor: AuthorizedMountAcquireVerificationFloorV2,
        provider_deadline_seconds: i64,
    ) -> Result<ReservedProviderQueryV2> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self.provider_heads.get(&identity).cloned();
        if current_head.as_ref().is_some_and(|head| {
            head.pending_attempt.is_some()
                || head.recovery_barrier.is_some()
                || head.next_request_sequence != head.next_response_sequence
        }) {
            return Err(state_error("fresh Acquire requires an idle provider head"));
        }
        let head_key = provider_head_key(holder_authority_id, provider_authority_id);
        let snapshot = journal.snapshot()?;
        let plan = match current_head.as_ref() {
            Some(head) => {
                let head_record = put_record(&StoredRecordV2::ProviderHead {
                    value: head.clone(),
                })?
                .value()
                .ok_or_else(|| state_error("provider head materialized as a delete"))?
                .to_vec();
                session
                    .current_mount_provider_session_plan_v2(
                        journal,
                        snapshot,
                        head_key,
                        head_record,
                        head.next_request_sequence,
                        head.next_response_sequence,
                    )
                    .map_err(|_| state_error("protected provider session planning failed"))?
            }
            None => session
                .initial_mount_provider_session_plan_v2(journal, snapshot, head_key)
                .map_err(|_| state_error("initial protected provider session planning failed"))?,
        };
        let predecessor_session_id = current_head
            .as_ref()
            .and_then(|head| self.provider_sessions.get(&head.current_session_id))
            .and_then(|stored| stored.predecessor_session_id);
        let projected_session = session_from_projection(plan.session(), predecessor_session_id)?;
        if projected_session.scope.holder_authority_id != holder_authority_id
            || projected_session.scope.provider_authority_id != provider_authority_id
        {
            return Err(state_error(
                "protected provider session differs from selected stable head",
            ));
        }
        let mount = live_request.request();
        let holder_sequence = self.holder_sequences.get(&holder_authority_id);
        let acquisition_sequence =
            holder_sequence.map_or(1, |value| value.next_acquisition_sequence);
        let provider_acquisition = ProviderAcquisitionIdentityV2 {
            holder_authority_id,
            holder_authority_generation: projected_session.root_mount_authority_generation,
            holder_authority_digest: projected_session.root_mount_authority_digest,
            acquisition_sequence,
            acquisition_id: *aos_sandbox_source_provider_protocol::source_acquisition_id_v2(
                holder_authority_id,
                projected_session.root_mount_authority_generation,
                ObjectDigest::from_bytes(projected_session.root_mount_authority_digest),
                acquisition_sequence,
            )
            .as_bytes(),
        };
        let provider_intent = ProviderIntentV2::Acquire {
            value: acquire_intent(
                projected_session.scope,
                mount,
                mount_request.clone(),
                mount_plan_digest,
                ownership_lease_digest,
            ),
        };
        let immutable_intent_digest = intent_digest(&provider_intent)?;
        let request_sequence = plan.sequences().0;
        let planned_attempt_id = attempt_id_for_plan(
            *mount.acquisition_id().as_bytes(),
            provider_intent,
            provider_acquisition,
            immutable_intent_digest,
            &projected_session,
            request_sequence,
        );
        let source_binding = mount.source_binding().canonical_bytes();
        let request = AcquireSourceRequestV1::new_v2(
            ObjectDigest::from_bytes(projected_session.session_binding),
            request_sequence,
            request_id(planned_attempt_id),
            acquisition_sequence,
            mount.prospective_mount_template().to_vec(),
            mount.prospective_mount_template_digest(),
            SourceUseV1::MountCreate,
            projected_session.node_id,
            projected_session.kernel_boot_id,
            holder_authority_id,
            projected_session.root_mount_authority_generation,
            ObjectDigest::from_bytes(projected_session.root_mount_authority_digest),
            source_binding.clone(),
            digest_logical_binding_bytes(&source_binding),
            provider_deadline_seconds.min(projected_session.current_valid_until_seconds),
            mount.requested_lease_seconds(),
            ObjectDigest::from_bytes(projected_session.revocation_digest),
            mount.recursive(),
            mount.requested_maximum_submounts(),
            mount.kernel_coupled(),
        )
        .map_err(|_| state_error("table-derived provider Acquire request is invalid"))?;
        let normalized = NormalizedAcquisitionIntentV2::from_acquire_request(
            &request,
            plan.session().authority_trust()[1].authority().clone(),
            plan.session().authority_trust()[0].authority().clone(),
            projected_session.node_id,
            projected_session.kernel_boot_id,
            projected_session.scope.route_id,
            projected_session.route_generation,
            ObjectDigest::from_bytes(projected_session.route_digest),
            ObjectDigest::from_bytes(projected_session.scope.resource_namespace_digest),
            projected_session.revocation_generation,
            ObjectDigest::from_bytes(projected_session.revocation_digest),
        )
        .map_err(|_| state_error("table-derived provider Acquire normalization is invalid"))?;
        let prepared = session
            .prepare_acquire_v2(
                journal,
                catalog_journal,
                plan,
                request,
                normalized,
                verification_floor,
            )
            .map_err(|_| state_error("protected provider Acquire preparation failed"))?;
        self.admit_acquire_v2(
            journal,
            live_request,
            mount_request,
            mount_plan_digest,
            ownership_lease_digest,
            prepared,
        )
    }

    /// Commits a fresh Acquire intent and exact prepared provider request.
    ///
    /// This dormant entry point is crate-private until the Mount service owns
    /// the protected session, assignment, and journal scheduling composition.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/equivocating Mount request, a reused holder
    /// sequence, a noncurrent prepared session, an invalid derived request ID,
    /// a count/materialization bound, or any journal/confirmation failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_acquire_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_request: &LiveValidatedAcquireMountSourceRequest,
        mount_request: Vec<u8>,
        mount_plan_digest: [u8; 32],
        ownership_lease_digest: [u8; 32],
        prepared: PreparedMountProviderRequestV2,
    ) -> Result<ReservedProviderQueryV2> {
        let historical = decode_historical_acquire_mount_source_request(&mount_request)?;
        if historical.request() != live_request.request()
            || mount_plan_digest == [0; 32]
            || ownership_lease_digest == [0; 32]
        {
            return Err(state_error(
                "fresh source acquisition differs from live Mount admission",
            ));
        }
        let mount = live_request.request();
        let projection = prepared.projection();
        if projection.method() != SourceProviderMethod::Acquire {
            return Err(state_error("prepared provider request is not Acquire"));
        }
        let scope = super::security::scope_from_request(projection);
        let identity = (scope.holder_authority_id, scope.provider_authority_id);
        let current_head = self.provider_heads.get(&identity);
        let predecessor_session_id = current_head
            .and_then(|head| self.provider_sessions.get(&head.current_session_id))
            .and_then(|stored| stored.predecessor_session_id);
        let projected_session = session_from_request(projection, predecessor_session_id)?;
        let session = match current_head {
            Some(head) => self
                .provider_sessions
                .get(&head.current_session_id)
                .filter(|stored| {
                    stored.session_id == projected_session.session_id
                        && stored.scope == projected_session.scope
                        && stored.session_binding == projected_session.session_binding
                        && stored.signer_set_commitment == projected_session.signer_set_commitment
                        && stored.trust_digest == projected_session.trust_digest
                        && stored.revocation_digest == projected_session.revocation_digest
                        && stored.route_digest == projected_session.route_digest
                        && stored.provider_execution.process_execution_digest
                            == projected_session
                                .provider_execution
                                .process_execution_digest
                })
                .cloned()
                .ok_or_else(|| {
                    state_error("fresh Acquire session projection differs from current head")
                })?,
            None => projected_session,
        };
        if current_head.is_some_and(|head| {
            head.pending_attempt.is_some()
                || head.recovery_barrier.is_some()
                || head.current_session_id != session.session_id
                || head.current_session_record_digest != session.record_digest
        }) {
            return Err(state_error(
                "fresh Acquire requires the exact current idle provider session",
            ));
        }
        if self
            .acquisitions
            .contains_key(mount.acquisition_id().as_bytes())
        {
            return Err(state_error(
                "fresh Mount acquisition identity is already retained",
            ));
        }

        let (provider_acquisition, holder_sequence) = allocate_provider_acquisition(
            self.holder_sequences.get(&scope.holder_authority_id),
            projection,
        )?;
        let provider_intent = ProviderIntentV2::Acquire {
            value: acquire_intent(
                scope,
                mount,
                mount_request.clone(),
                mount_plan_digest,
                ownership_lease_digest,
            ),
        };
        let immutable_intent_digest = intent_digest(&provider_intent)?;
        let (_, request_sequence) = projection.request_identity();
        let normalized_bytes = projection
            .normalized_intent()
            .ok_or_else(|| state_error("prepared Acquire lacks normalized intent"))?;
        let normalized_digest = projection
            .request_digests()
            .0
            .ok_or_else(|| state_error("prepared Acquire lacks normalized intent digest"))?;
        let normalized = NormalizedAcquisitionIntentV2::from_canonical_bytes(normalized_bytes)
            .map_err(|_| state_error("prepared Acquire normalization is invalid"))?;
        let (catalog_floor, selection_floor, current_catalog_head_commitment) = projection
            .verification_floors()
            .ok_or_else(|| state_error("prepared Acquire lacks verification floors"))?;
        let maximum_lease_expiry_seconds = projection
            .deadline_seconds()
            .min(session.current_valid_until_seconds);
        let mut attempt = SourceProviderQueryAttemptV2 {
            attempt_id: [0; 32],
            revision: 1,
            scope,
            method: ProviderMethodV2::Acquire,
            owner: ProviderQueryOwnerV2::Acquire {
                acquisition_id: *mount.acquisition_id().as_bytes(),
            },
            intent: provider_intent,
            provider_acquisition: Some(provider_acquisition),
            immutable_intent_digest,
            lineage_root_attempt_id: [0; 32],
            previous_attempt_id: None,
            attempt_number: 1,
            session_id: session.session_id,
            session_record_digest: session.record_digest,
            signer_set_commitment: session.signer_set_commitment,
            trust_digest: session.trust_digest,
            revocation_digest: session.revocation_digest,
            route_digest: session.route_digest,
            process_execution_digest: session.provider_execution.process_execution_digest,
            normalized_acquire_intent: Some(AttemptNormalizedAcquireV2 {
                bytes: normalized.to_canonical_bytes(),
                digest: *normalized_digest.as_bytes(),
                maximum_lease_expiry_seconds,
            }),
            acquire_verification_floor: Some(acquire_verification_floor_v2(
                catalog_floor,
                selection_floor,
                Some(*current_catalog_head_commitment.as_bytes()),
            )),
            inventory_correlations: None,
            request_id: [0; 16],
            request_sequence,
            signed_request: prepared.canonical_signed_request().to_vec(),
            signed_request_digest: *projection.request_digests().2.as_bytes(),
            owner_predecessor_revision: 0,
            owner_predecessor_digest: [0; 32],
            owner_predecessor: None,
            state: ProviderAttemptStateV2::Reserved,
            record_digest: [0; 32],
        };
        attempt.attempt_id = attempt_id(&attempt);
        attempt.lineage_root_attempt_id = attempt.attempt_id;
        attempt.request_id = request_id(attempt.attempt_id);
        if projection.request_identity() != (attempt.request_id, attempt.request_sequence)
            || projection.expected_response_sequence() != attempt.request_sequence
            || projection.acquisition_identity()
                != Some((
                    ObjectDigest::from_bytes(provider_acquisition.acquisition_id),
                    provider_acquisition.acquisition_sequence,
                ))
        {
            return Err(state_error(
                "prepared Acquire differs from table-derived attempt identity",
            ));
        }
        let attempt = sealed_attempt(attempt)?;
        let attempt_reference = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        })?;
        let row = sealed_row(initial_row(
            mount,
            mount_request,
            mount_plan_digest,
            ownership_lease_digest,
            provider_acquisition,
            scope,
            immutable_intent_digest,
            attempt_reference,
        ))?;

        let mut next_rows = self.acquisitions.clone();
        next_rows.insert(row.acquisition_id, row.clone());
        let head = match current_head {
            Some(head) => reserve_existing_head(head, &next_rows, attempt_reference)?,
            None => {
                super::transition::initial_provider_head(&session, &next_rows, attempt_reference)?
            }
        };
        let head = sealed_head(head)?;
        let holder_sequence = sealed_holder_sequence(holder_sequence)?;
        let mut records = vec![
            StoredRecordV2::HolderSequence {
                value: holder_sequence.clone(),
            },
            StoredRecordV2::ProviderQueryAttempt {
                value: attempt.clone(),
            },
            StoredRecordV2::Acquisition { value: row.clone() },
            StoredRecordV2::ProviderHead {
                value: head.clone(),
            },
        ];
        if !self.provider_sessions.contains_key(&session.session_id) {
            records.push(StoredRecordV2::ProviderSession {
                value: session.clone(),
            });
        }
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::InitialAdmission,
                holder_id: scope.holder_authority_id,
                provider_id: scope.provider_authority_id,
                next_holder_sequence_revision: holder_sequence.revision,
                next_head_revision: head.revision,
                acquisition_id: Some(row.acquisition_id),
                next_row_revision: Some(row.revision),
                attempt_id: Some(attempt.attempt_id),
                next_attempt_revision: Some(attempt.revision),
                session_id: Some(session.session_id),
            },
            records,
        )?;
        confirm_reservation(journal, prepared, &attempt, &head)
    }
}

fn attempt_id_for_plan(
    mount_acquisition_id: [u8; 32],
    intent: ProviderIntentV2,
    provider_acquisition: ProviderAcquisitionIdentityV2,
    immutable_intent_digest: [u8; 32],
    session: &SourceProviderSessionV2,
    request_sequence: u64,
) -> [u8; 32] {
    let attempt = SourceProviderQueryAttemptV2 {
        attempt_id: [0; 32],
        revision: 1,
        scope: session.scope,
        method: ProviderMethodV2::Acquire,
        owner: ProviderQueryOwnerV2::Acquire {
            acquisition_id: mount_acquisition_id,
        },
        intent,
        provider_acquisition: Some(provider_acquisition),
        immutable_intent_digest,
        lineage_root_attempt_id: [0; 32],
        previous_attempt_id: None,
        attempt_number: 1,
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
        request_sequence,
        signed_request: Vec::new(),
        signed_request_digest: [0; 32],
        owner_predecessor_revision: 0,
        owner_predecessor_digest: [0; 32],
        owner_predecessor: None,
        state: ProviderAttemptStateV2::Reserved,
        record_digest: [0; 32],
    };
    attempt_id(&attempt)
}

fn allocate_provider_acquisition(
    current: Option<&HolderSequenceV2>,
    projection: &aos_sandbox_source_provider_security::MountProviderRequestProjectionV2,
) -> Result<(ProviderAcquisitionIdentityV2, HolderSequenceV2)> {
    let (provider_id, sequence) = projection
        .acquisition_identity()
        .ok_or_else(|| state_error("prepared Acquire lacks provider acquisition identity"))?;
    let holder = projection.holder();
    let expected_sequence = current.map_or(1, |value| value.next_acquisition_sequence);
    if sequence != expected_sequence {
        return Err(state_error(
            "fresh Acquire does not consume the holder-wide next sequence",
        ));
    }
    let next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| state_error("holder acquisition sequence is exhausted"))?;
    let revision = current.map_or(Ok(1), |value| next_revision(value.revision))?;
    Ok((
        ProviderAcquisitionIdentityV2 {
            holder_authority_id: holder.authority_id(),
            holder_authority_generation: holder.authority_generation(),
            holder_authority_digest: *holder.authority_digest().as_bytes(),
            acquisition_sequence: sequence,
            acquisition_id: *provider_id.as_bytes(),
        },
        HolderSequenceV2 {
            revision,
            holder_authority_id: holder.authority_id(),
            last_allocated_acquisition_sequence: sequence,
            next_acquisition_sequence: next_sequence,
            record_digest: [0; 32],
        },
    ))
}

fn acquire_intent(
    scope: ProviderScopeV2,
    request: &aos_sandbox_protocol::ValidatedAcquireMountSourceRequest,
    mount_request: Vec<u8>,
    mount_plan_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
) -> AcquireIntentV2 {
    let source_binding = request.source_binding().canonical_bytes();
    AcquireIntentV2 {
        scope,
        acquisition_id: *request.acquisition_id().as_bytes(),
        mount_request,
        mount_request_digest: *request.request_digest().as_bytes(),
        assignment: assignment(request),
        mount_plan_digest,
        ownership_lease_digest,
        prospective_mount_template: request.prospective_mount_template().to_vec(),
        prospective_mount_template_digest: *request.prospective_mount_template_digest().as_bytes(),
        source_binding_digest: *digest_logical_binding_bytes(&source_binding).as_bytes(),
        source_binding,
        requested_lease_seconds: request.requested_lease_seconds(),
        requested_maximum_submounts: request.requested_maximum_submounts(),
        recursive: request.recursive(),
        kernel_coupled: request.kernel_coupled(),
    }
}

fn assignment(request: &aos_sandbox_protocol::ValidatedAcquireMountSourceRequest) -> AssignmentV2 {
    AssignmentV2 {
        sandbox_id: *request.fence().sandbox_id(),
        incarnation_id: *request.fence().incarnation_id(),
        assignment_epoch: request.fence().assignment_epoch(),
        desired_generation: request.fence().desired_generation(),
        assignment_digest: *request.fence().assignment_digest(),
        namespace_generation: request.prospective_namespace_generation(),
    }
}

#[allow(clippy::too_many_arguments)]
fn initial_row(
    request: &aos_sandbox_protocol::ValidatedAcquireMountSourceRequest,
    mount_request: Vec<u8>,
    mount_plan_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
    provider_acquisition: ProviderAcquisitionIdentityV2,
    scope: ProviderScopeV2,
    acquire_intent_digest: [u8; 32],
    attempt: RecordRefV2,
) -> SourceAcquisitionRowV2 {
    let source_binding = request.source_binding().canonical_bytes();
    SourceAcquisitionRowV2 {
        acquisition_id: *request.acquisition_id().as_bytes(),
        provider_acquisition,
        revision: 1,
        phase: SourceAcquisitionPhaseV2::PendingQuery,
        scope,
        acquire: MountOperationV2 {
            operation_id: *request.header().request_id(),
            request_digest: *request.request_digest().as_bytes(),
        },
        mount_acquire_request: mount_request,
        acquire_intent_digest,
        acquire_lineage: QueryLineageV2 {
            root: attempt,
            tail: attempt,
            next_attempt_number: 2,
        },
        acquire_terminal_attempt: None,
        release: None,
        mount_release_request: None,
        release_authority: None,
        release_from_phase: None,
        release_intent_digest: None,
        release_lineage: None,
        release_terminal_attempt: None,
        release_inventory_fence: None,
        assignment: assignment(request),
        prospective_mount_template: request.prospective_mount_template().to_vec(),
        prospective_mount_template_digest: *request.prospective_mount_template_digest().as_bytes(),
        source_binding_digest: *digest_logical_binding_bytes(&source_binding).as_bytes(),
        source_binding,
        mount_plan_digest,
        ownership_lease_digest,
        evidence: None,
        manager_custody: None,
        manager_custody_loss: None,
        descriptor_custody_digest: None,
        positive_custody_digest: None,
        consumption: None,
        release_proof: None,
        negative_custody_digest: None,
        faulted_from: None,
        fault_digest: None,
        retained_faulted_from: None,
        retained_fault_digest: None,
        recovery: AcquisitionRecoveryV2::Ready,
        record_digest: [0; 32],
    }
}

fn reserve_existing_head(
    current: &SourceProviderHeadV2,
    rows: &std::collections::BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    attempt: RecordRefV2,
) -> Result<SourceProviderHeadV2> {
    if current.pending_attempt.is_some()
        || current.recovery_barrier.is_some()
        || current.next_request_sequence != current.next_response_sequence
    {
        return Err(state_error(
            "SourceProvider head is not ready for reservation",
        ));
    }
    let next_sequence = current
        .next_request_sequence
        .checked_add(1)
        .ok_or_else(|| state_error("SourceProvider request sequence is exhausted"))?;
    let entries = projection_entries(current.scope, rows);
    let projection = projection_from_entries(
        current.scope,
        current
            .current_projection_epoch
            .checked_add(1)
            .ok_or_else(|| state_error("SourceProvider projection epoch is exhausted"))?,
        &entries,
    )?;
    let mut next = current.clone();
    next.revision = next_revision(current.revision)?;
    next.next_request_sequence = next_sequence;
    next.pending_attempt = Some(attempt);
    next.current_projection_epoch = projection.epoch;
    next.current_projection_digest = projection.digest;
    next.last_reconciliation = None;
    next.record_digest = [0; 32];
    Ok(next)
}

pub(super) fn sealed_attempt(
    value: SourceProviderQueryAttemptV2,
) -> Result<SourceProviderQueryAttemptV2> {
    match seal(StoredRecordV2::ProviderQueryAttempt { value })? {
        StoredRecordV2::ProviderQueryAttempt { value } => Ok(value),
        _ => Err(state_error("sealed provider attempt changed record kind")),
    }
}

pub(super) fn sealed_row(value: SourceAcquisitionRowV2) -> Result<SourceAcquisitionRowV2> {
    match seal(StoredRecordV2::Acquisition { value })? {
        StoredRecordV2::Acquisition { value } => Ok(value),
        _ => Err(state_error("sealed acquisition changed record kind")),
    }
}

pub(super) fn sealed_head(value: SourceProviderHeadV2) -> Result<SourceProviderHeadV2> {
    match seal(StoredRecordV2::ProviderHead { value })? {
        StoredRecordV2::ProviderHead { value } => Ok(value),
        _ => Err(state_error("sealed provider head changed record kind")),
    }
}

fn sealed_holder_sequence(value: HolderSequenceV2) -> Result<HolderSequenceV2> {
    match seal(StoredRecordV2::HolderSequence { value })? {
        StoredRecordV2::HolderSequence { value } => Ok(value),
        _ => Err(state_error("sealed holder sequence changed record kind")),
    }
}

pub(super) fn confirm_reservation(
    journal: &mut ProtectedJournalAuthority<'_>,
    prepared: PreparedMountProviderRequestV2,
    attempt: &SourceProviderQueryAttemptV2,
    head: &SourceProviderHeadV2,
) -> Result<ReservedProviderQueryV2> {
    let attempt_record = put_record(&StoredRecordV2::ProviderQueryAttempt {
        value: attempt.clone(),
    })?;
    let head_record = put_record(&StoredRecordV2::ProviderHead {
        value: head.clone(),
    })?;
    let snapshot: ProtectedJournalSnapshot = journal.snapshot()?;
    let reservation = prepared
        .confirm_protected_reservation(
            journal,
            snapshot,
            provider_attempt_key(attempt.attempt_id),
            attempt_record
                .value()
                .ok_or_else(|| state_error("provider attempt reservation is a delete"))?
                .to_vec(),
            provider_head_key(
                head.scope.holder_authority_id,
                head.scope.provider_authority_id,
            ),
            head_record
                .value()
                .ok_or_else(|| state_error("provider head reservation is a delete"))?
                .to_vec(),
        )
        .map_err(|_| state_error("SourceProvider reservation confirmation failed"))?;
    Ok(ReservedProviderQueryV2 {
        attempt_id: attempt.attempt_id,
        reservation,
    })
}
