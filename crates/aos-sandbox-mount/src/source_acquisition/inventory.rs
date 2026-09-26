//! AOSMSA02 Inventory planning and durable reservation.
//!
//! Inventory is table-derived from the exact retained provider floor. A new
//! observation may follow a Complete observation in the same bounded lineage.
//! At the lineage bound, the next root retains the exact prior Head witness as
//! a verifier-bound floor checkpoint; immutable attempts are never rewritten
//! or evicted, and the Head still names the latest observation tail.

use aos_sandbox::journal::ProtectedJournalAuthority;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    InventoryLeaseStateV1, InventorySourceRequestV1, SignedSourceProviderInventoryV1,
    SignedSourceProviderRequestV1, SourceProviderAuthorityV1, SourceProviderMethod,
    decode_inventory_request, digest_inventory, digest_inventory_request,
};
use aos_sandbox_source_provider_security::CurrentRootMountSourceProviderSessionV1;

use super::SourceAcquisitionTableV2;
use super::format::{
    MAXIMUM_LINEAGE_ATTEMPTS, MutationTagV2, acquisition_key, attempt_id, intent_digest,
    inventory_correlation_set_v2, materialized_record, provider_head_key, provider_session_key,
    put_record, request_id, state_error,
};
use super::model::*;
use super::projection::{
    inventory_correlation_for_row_v2, inventory_entry_matches_evidence, projection_entries,
    projection_from_entries,
};
use super::reservation::{
    ReservedProviderQueryV2, confirm_reservation, sealed_attempt, sealed_head,
};
use super::security::session_from_request;
use super::transition::{
    MutationIdentityV2, commit_mutation, next_revision, provider_head_predecessor, record_ref,
};
use crate::Result;

impl SourceAcquisitionTableV2 {
    /// Plans and reserves the next authenticated provider Inventory request.
    ///
    /// A recovery barrier restricts this operation to its exact recovery root.
    /// Otherwise the request extends the ordinary per-head observation lineage.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or nonidle head, a mismatched recovery
    /// root, an exhausted lineage/sequence, stale protected state, invalid
    /// prepared request, or failed atomic reservation.
    #[doc(hidden)]
    pub(crate) fn prepare_and_reserve_inventory_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
        recovery_root_attempt_id: Option<[u8; 32]>,
        provider_deadline_seconds: i64,
    ) -> Result<ReservedProviderQueryV2> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .cloned()
            .ok_or_else(|| state_error("Inventory requires an idle provider head"))?;
        match (&current_head.recovery_barrier, recovery_root_attempt_id) {
            (None, None) => {}
            (Some(barrier), Some(root)) if barrier.root_attempt.id == root => {}
            _ => {
                return Err(state_error(
                    "Inventory recovery root differs from the provider barrier",
                ));
            }
        }

        let head_key = provider_head_key(holder_authority_id, provider_authority_id);
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
                head_key,
                head_record,
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected Inventory session planning failed"))?;
        let projected = super::security::session_from_projection(
            plan.session(),
            self.provider_sessions
                .get(&current_head.current_session_id)
                .and_then(|stored| stored.predecessor_session_id),
        )?;
        if projected.session_id != current_head.current_session_id
            || projected.record_digest != current_head.current_session_record_digest
            || projected.scope != current_head.scope
        {
            return Err(state_error(
                "protected Inventory session differs from current head",
            ));
        }

        let mut correlation_entries = self
            .acquisitions
            .values()
            .filter(|row| row.scope == current_head.scope)
            .filter_map(inventory_correlation_for_row_v2)
            .collect::<Vec<_>>();
        correlation_entries.sort_by_key(|entry| entry.provider_acquisition.acquisition_id);
        let inventory_correlations = inventory_correlation_set_v2(correlation_entries)?;
        let intent = ProviderIntentV2::Inventory {
            value: InventoryIntentV2 {
                scope: current_head.scope,
                known_inventory_generation: current_head
                    .inventory_floor
                    .as_ref()
                    .map(|floor| floor.inventory_generation),
                known_inventory_digest: current_head
                    .inventory_floor
                    .as_ref()
                    .map(|floor| floor.inventory_digest),
                known_catalog_generation: current_head
                    .inventory_floor
                    .as_ref()
                    .map(|floor| floor.catalog_generation),
                known_catalog_digest: current_head
                    .inventory_floor
                    .as_ref()
                    .map(|floor| floor.catalog_digest),
                known_observation_ordinal: current_head.inventory_observation_ordinal,
                recovery_root_attempt_id,
                correlation_digest: inventory_correlations.digest,
            },
        };
        let immutable_intent_digest = intent_digest(&intent)?;
        let predecessor = inventory_predecessor(self, &current_head, recovery_root_attempt_id)?;
        let compact_completed_prefix = recovery_root_attempt_id.is_none()
            && predecessor
                .is_some_and(|attempt| attempt.attempt_number == MAXIMUM_LINEAGE_ATTEMPTS as u64);
        let (lineage_root_attempt_id, previous_attempt_id, attempt_number) =
            lineage_coordinates(predecessor, compact_completed_prefix)?;
        let stored_session = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .ok_or_else(|| state_error("Inventory current session is absent"))?;
        let mut draft = inventory_attempt(
            &current_head,
            stored_session,
            intent,
            immutable_intent_digest,
            lineage_root_attempt_id,
            previous_attempt_id,
            attempt_number,
        );
        draft.attempt_id = attempt_id(&draft);
        if draft.lineage_root_attempt_id == [0; 32] {
            draft.lineage_root_attempt_id = draft.attempt_id;
        }
        draft.request_id = request_id(draft.attempt_id);
        let request = InventorySourceRequestV1::new(
            ObjectDigest::from_bytes(projected.session_binding),
            current_head.next_request_sequence,
            draft.request_id,
            holder_authority_id,
            projected.root_mount_authority_generation,
            ObjectDigest::from_bytes(projected.root_mount_authority_digest),
            current_head
                .inventory_floor
                .as_ref()
                .map(|floor| ObjectDigest::from_bytes(floor.inventory_digest)),
            provider_deadline_seconds.min(projected.current_valid_until_seconds),
        )
        .map_err(|_| state_error("table-derived provider Inventory request is invalid"))?;
        let historical = historical_inventory_authorizations(
            self,
            journal,
            session,
            current_head.scope,
            &projected,
        )?;
        let prepared = if historical.is_empty() {
            session
                .prepare_inventory_v2(journal, plan, request, inventory_correlations.clone())
                .map_err(|_| state_error("protected provider Inventory preparation failed"))?
        } else {
            session
                .prepare_historical_inventory_v2(
                    journal,
                    plan,
                    request,
                    inventory_correlations.clone(),
                    historical,
                )
                .map_err(|_| state_error("protected historical Inventory preparation failed"))?
        };
        let request_projection = prepared.projection();
        let signed_request = SignedSourceProviderRequestV1::from_canonical_bytes(
            prepared.canonical_signed_request(),
        )
        .map_err(|_| state_error("prepared Inventory envelope is invalid"))?;
        let decoded_request = decode_inventory_request(signed_request.subject())
            .map_err(|_| state_error("prepared Inventory body is invalid"))?;
        if request_projection.method() != SourceProviderMethod::Inventory
            || request_projection.request_identity()
                != (draft.request_id, current_head.next_request_sequence)
            || request_projection.expected_response_sequence()
                != current_head.next_response_sequence
            || request_projection.acquisition_identity().is_some()
            || request_projection.normalized_intent().is_some()
            || request_projection.inventory_correlations() != Some(&inventory_correlations)
            || digest_inventory_request(&decoded_request) != request_projection.request_digests().1
        {
            return Err(state_error(
                "prepared Inventory differs from table-derived request",
            ));
        }
        let projected_session =
            session_from_request(request_projection, projected.predecessor_session_id)?;
        if projected_session != projected {
            return Err(state_error(
                "prepared Inventory changes the protected session projection",
            ));
        }

        draft.signed_request = prepared.canonical_signed_request().to_vec();
        draft.signed_request_digest = *request_projection.request_digests().2.as_bytes();
        draft.inventory_correlations = Some(inventory_correlations);
        let attempt = sealed_attempt(draft)?;
        let attempt_reference = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: attempt.clone(),
        })?;
        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.next_request_sequence = current_head
            .next_request_sequence
            .checked_add(1)
            .ok_or_else(|| state_error("provider request sequence is exhausted"))?;
        next_head.pending_attempt = Some(attempt_reference);
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::ReserveRetry,
                holder_id: holder_authority_id,
                provider_id: provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: None,
                next_row_revision: None,
                attempt_id: Some(attempt.attempt_id),
                next_attempt_revision: Some(attempt.revision),
                session_id: None,
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: attempt.clone(),
                },
                StoredRecordV2::ProviderHead {
                    value: next_head.clone(),
                },
            ],
        )?;
        confirm_reservation(journal, prepared, &attempt, &next_head)
    }

    /// Retains a fresh Inventory observation proving one Release terminal.
    ///
    /// # Errors
    ///
    /// Returns an error unless the current Complete Inventory postdates the
    /// row's Release fence and shows the exact lease absent or matching
    /// Released, or if the row/head replacement cannot commit atomically.
    #[doc(hidden)]
    pub(crate) fn record_inventory_release_proof_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_record_digest: [u8; 32],
    ) -> Result<()> {
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
            .ok_or_else(|| state_error("Inventory Release proof row is not current"))?;
        let fence = row
            .release_inventory_fence
            .as_ref()
            .ok_or_else(|| state_error("Inventory Release proof lacks its fence"))?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("Inventory Release proof lacks lease evidence"))?;
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
                    && head.inventory_observation_ordinal > fence.inventory_observation_floor
                    && head.last_reconciliation.as_ref().is_some_and(|value| {
                        value.projection_epoch == head.current_projection_epoch
                            && value.projection_digest == head.current_projection_digest
                    })
            })
            .cloned()
            .ok_or_else(|| state_error("Inventory Release proof is not fresh"))?;
        let floor = head
            .inventory_floor
            .as_ref()
            .ok_or_else(|| state_error("Inventory Release proof lacks a floor"))?;
        let inventory_attempt = self
            .provider_attempts
            .get(&floor.attempt.id)
            .filter(|attempt| {
                attempt.revision == floor.attempt.revision
                    && attempt.record_digest == floor.attempt.record_digest
            })
            .ok_or_else(|| state_error("Inventory Release proof attempt is absent"))?;
        let ProviderAttemptStateV2::DispositionConsumed {
            status: ProviderStatusV2::Complete,
            signed_result,
            ..
        } = &inventory_attempt.state
        else {
            return Err(state_error("Inventory Release proof is not Complete"));
        };
        let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
            .map_err(|_| state_error("Inventory Release proof bytes are invalid"))?;
        let acquisition_predecessor = inventory_attempt
            .inventory_correlations
            .as_ref()
            .and_then(|correlations| {
                correlations
                    .entries
                    .iter()
                    .find(|entry| entry.mount_acquisition_id == row.acquisition_id)
            })
            .map(|entry| entry.acquisition_record)
            .ok_or_else(|| state_error("Inventory Release proof lacks its reserved row"))?;
        if digest_inventory(signed.subject()).as_bytes() != &floor.inventory_digest {
            return Err(state_error("Inventory Release proof digest differs"));
        }
        let entry = signed.subject().entries().iter().find(|entry| {
            entry.acquisition_id().as_bytes() == &row.provider_acquisition.acquisition_id
        });
        if entry.is_some_and(|entry| {
            entry.state() != InventoryLeaseStateV1::Released
                || !inventory_entry_matches_evidence(entry, evidence)
        }) {
            return Err(state_error(
                "Inventory Release proof does not show exact terminality",
            ));
        }

        let mut next_row = row.clone();
        next_row.revision = next_revision(row.revision)?;
        next_row.release_proof = Some(ReleaseProofV2::ProviderInventory {
            attempt: floor.attempt,
            acquisition_predecessor,
            inventory_digest: floor.inventory_digest,
            inventory_observation_ordinal: head.inventory_observation_ordinal,
            projection_epoch: head.current_projection_epoch,
        });
        next_row.record_digest = [0; 32];
        let next_row = super::reservation::sealed_row(next_row)?;
        let mut rows = self.acquisitions.clone();
        rows.insert(acquisition_id, next_row.clone());
        let epoch = head
            .current_projection_epoch
            .checked_add(1)
            .ok_or_else(|| state_error("provider projection epoch is exhausted"))?;
        let projection =
            projection_from_entries(head.scope, epoch, &projection_entries(head.scope, &rows))?;
        let mut next_head = head.clone();
        next_head.revision = next_revision(head.revision)?;
        next_head.current_projection_epoch = epoch;
        next_head.current_projection_digest = projection.digest;
        next_head.last_reconciliation = None;
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::FinishRelease,
                holder_id: identity.0,
                provider_id: identity.1,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&identity.0)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: Some(acquisition_id),
                next_row_revision: Some(next_row.revision),
                attempt_id: None,
                next_attempt_revision: None,
                session_id: None,
            },
            vec![
                StoredRecordV2::Acquisition { value: next_row },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )
    }
}

fn historical_inventory_authorizations(
    table: &SourceAcquisitionTableV2,
    journal: &ProtectedJournalAuthority<'_>,
    session: &mut CurrentRootMountSourceProviderSessionV1,
    scope: ProviderScopeV2,
    current_session: &SourceProviderSessionV2,
) -> Result<Vec<aos_sandbox_source_provider_security::HistoricalMountInventoryAuthorizationV2>> {
    let mut authorizations = Vec::new();
    for row in table
        .acquisitions
        .values()
        .filter(|row| row.scope == scope && row.evidence.is_some())
    {
        let mapping = row.provider_acquisition;
        let is_current = current_session.root_mount_authority_generation
            == mapping.holder_authority_generation
            && current_session.root_mount_authority_digest == mapping.holder_authority_digest;
        if is_current {
            continue;
        }
        if current_session.root_mount_authority_generation <= mapping.holder_authority_generation {
            return Err(state_error(
                "Inventory holder does not dominate retained acquisition authority",
            ));
        }
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("historical Inventory row lost its evidence"))?;
        let predecessor_session = table
            .provider_sessions
            .get(&evidence.session_id)
            .ok_or_else(|| state_error("historical Inventory session is absent"))?;
        let predecessor_holder = SourceProviderAuthorityV1::new(
            predecessor_session.scope.holder_authority_id,
            predecessor_session.root_mount_authority_generation,
            ObjectDigest::from_bytes(predecessor_session.root_mount_authority_digest),
        )
        .map_err(|_| state_error("historical Inventory holder is invalid"))?;
        let authorization = session
            .authorize_historical_mount_inventory_v2(
                journal,
                journal.snapshot()?,
                acquisition_key(row.acquisition_id),
                materialized_record(StoredRecordV2::Acquisition { value: row.clone() })?,
                provider_session_key(predecessor_session.session_id),
                materialized_record(StoredRecordV2::ProviderSession {
                    value: predecessor_session.clone(),
                })?,
                predecessor_holder,
                ObjectDigest::from_bytes(mapping.acquisition_id),
                mapping.acquisition_sequence,
                evidence.lease_id,
                ObjectDigest::from_bytes(evidence.signed_lease_digest),
                predecessor_session.authenticated_at_seconds,
                predecessor_session.trust_generation,
                ObjectDigest::from_bytes(predecessor_session.trust_digest),
                predecessor_session.revocation_generation,
                ObjectDigest::from_bytes(predecessor_session.revocation_digest),
                predecessor_session.signed_root_mount_hello.clone(),
            )
            .map_err(|_| state_error("historical Inventory authorization failed"))?;
        authorizations.push(authorization);
    }
    Ok(authorizations)
}

fn inventory_predecessor<'a>(
    table: &'a SourceAcquisitionTableV2,
    head: &SourceProviderHeadV2,
    recovery_root: Option<[u8; 32]>,
) -> Result<Option<&'a SourceProviderQueryAttemptV2>> {
    let reference = match recovery_root {
        Some(_) => head
            .recovery_barrier
            .as_ref()
            .and_then(|barrier| barrier.recovery_inventory_tail),
        None => head.last_inventory_attempt,
    };
    reference
        .map(|reference| {
            table
                .provider_attempts
                .get(&reference.id)
                .filter(|attempt| {
                    attempt.revision == reference.revision
                        && attempt.record_digest == reference.record_digest
                        && attempt.method == ProviderMethodV2::Inventory
                })
                .ok_or_else(|| state_error("Inventory predecessor attempt is absent"))
        })
        .transpose()
}

fn lineage_coordinates(
    predecessor: Option<&SourceProviderQueryAttemptV2>,
    compact_completed_prefix: bool,
) -> Result<([u8; 32], Option<[u8; 32]>, u64)> {
    if compact_completed_prefix {
        return Ok(([0; 32], None, 1));
    }
    match predecessor {
        Some(attempt) => Ok((
            attempt.lineage_root_attempt_id,
            Some(attempt.attempt_id),
            attempt
                .attempt_number
                .checked_add(1)
                .ok_or_else(|| state_error("Inventory attempt number is exhausted"))?,
        )),
        None => Ok(([0; 32], None, 1)),
    }
}

#[allow(clippy::too_many_arguments)]
fn inventory_attempt(
    head: &SourceProviderHeadV2,
    session: &SourceProviderSessionV2,
    intent: ProviderIntentV2,
    immutable_intent_digest: [u8; 32],
    lineage_root_attempt_id: [u8; 32],
    previous_attempt_id: Option<[u8; 32]>,
    attempt_number: u64,
) -> SourceProviderQueryAttemptV2 {
    SourceProviderQueryAttemptV2 {
        attempt_id: [0; 32],
        revision: 1,
        scope: head.scope,
        method: ProviderMethodV2::Inventory,
        owner: ProviderQueryOwnerV2::Inventory,
        intent,
        provider_acquisition: None,
        immutable_intent_digest,
        lineage_root_attempt_id,
        previous_attempt_id,
        attempt_number,
        session_id: head.current_session_id,
        session_record_digest: head.current_session_record_digest,
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
        owner_predecessor_revision: head.revision,
        owner_predecessor_digest: head.record_digest,
        owner_predecessor: Some(provider_head_predecessor(head)),
        state: ProviderAttemptStateV2::Reserved,
        record_digest: [0; 32],
    }
}
