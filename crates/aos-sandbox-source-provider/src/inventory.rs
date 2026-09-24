//! Durable inventory projection, reservation, and completion ordering.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    InventoryLeaseStateV1, InventorySourceResponseV1, SourceProviderInventoryEntryV1,
    SourceProviderInventoryV1, SourceProviderMethod, SourceProviderResponseStatusV1,
    SourceProviderStatus, SourceResourceV1, VerifiedProviderInventoryRequestV1,
    VerifiedProviderRequestSequenceV1, digest_inventory, digest_inventory_request,
    empty_descriptor_set_commitment_v1, encode_inventory_response, response_result_digest_v1,
};
use aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1;
use sha2::{Digest as _, Sha256};

use crate::backend::{
    ActiveAcquisitionSnapshotV1, DurableProviderReplyV1, ReopenObservationV1, ReopenedSourceRootV1,
    SourceProviderBackendV1,
};
use crate::format::{
    attempt_key, encode_attempt, encode_session, encode_session_history, session_history_key,
    session_key,
};
use crate::ledger::artifact::response_artifact_digest;
use crate::limits::MAXIMUM_INVENTORY_COMPLETION_BYTES;
use crate::model::{
    AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1, ReleaseKeyV1, ReleaseRecordV1,
};
use crate::state::ProviderLedgerV1;
use crate::transaction::{
    authorize_current_reservation, classify_attempt, commit_records, confirm_current_after_commit,
    confirm_current_session_after_commit, preflight_completion_capacity, prepare_session,
    reserve_session, reserved_attempt, validate_projection, validate_session_capacity,
};
use crate::{ProviderAdmissionDispositionV1, ProviderLedgerError};

const INVENTORY_STATE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.inventory-state.v1\0";
const INVENTORY_RESERVE_PURPOSE: &[u8] = b"reserve-inventory";
const INVENTORY_COMPLETE_PURPOSE: &[u8] = b"complete-inventory";

/// Grants exactly one authoritative inventory revalidation after reservation sync.
pub struct DurableInventoryPermitV1 {
    pub(crate) holder_id: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) attempt_digest: ObjectDigest,
    pub(crate) reservation_digest: ObjectDigest,
    pub(crate) journal_snapshot: ProtectedJournalSnapshot,
    pub(crate) completion_capacity: crate::transaction::CompletionCapacityV1,
    pub(crate) signing_authorization:
        aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1,
}

impl core::fmt::Debug for DurableInventoryPermitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableInventoryPermitV1([redacted])")
    }
}

impl ProviderLedgerV1<'_> {
    /// Completes one reserved Inventory from freshly reopened exact sources.
    ///
    /// Every Active and Reaping acquisition for the holder must have one exact
    /// sealed reopen observation. The signed inventory is derived only from the
    /// recovered durable projection and returned only after completion sync.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for a missing or contradictory reopen,
    /// invalid retained graph, signing or model failure, limits, or sync failure.
    pub fn complete_inventory(
        &mut self,
        permit: DurableInventoryPermitV1,
        reopened: Vec<ReopenedSourceRootV1>,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        for observation in &reopened {
            self.poison_backend_result(
                observation.acquisition_id,
                observation.revalidate_physical(),
            )?;
        }
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let holder_id = permit.holder_id;
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current completion session"),
        )?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != permit.session_binding {
            self.current_sessions.insert(holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        if let Some(acquisition_id) = conflicting_reopen(self, holder_id, &reopened) {
            self.current_sessions.insert(holder_id, installed);
            self.record_backend_conflict(acquisition_id)?;
            return Err(ProviderLedgerError::BackendConflict);
        }
        let result = complete_inventory(self, permit, reopened, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        result
    }

    /// Reopens every required source through the sealed backend and completes Inventory.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when any exact source cannot be reopened,
    /// conflicts with retained evidence, or inventory completion fails.
    pub fn execute_inventory<B: SourceProviderBackendV1>(
        &mut self,
        permit: DurableInventoryPermitV1,
        backend: &mut B,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let snapshots = active_snapshots(self, permit.holder_id)?;
        let mut reopened = Vec::with_capacity(snapshots.len());
        for snapshot in &snapshots {
            let observation = backend.reopen_active(snapshot);
            match self.poison_backend_result(snapshot.acquisition_id, observation)? {
                ReopenObservationV1::Reopened(observation)
                    if observation.acquisition_id == snapshot.acquisition_id
                        && observation.source_root == snapshot.source_root =>
                {
                    reopened.push(observation);
                }
                ReopenObservationV1::Reopened(_) => {
                    self.record_backend_conflict(snapshot.acquisition_id)?;
                    return Err(ProviderLedgerError::BackendConflict);
                }
                ReopenObservationV1::Unavailable => return Err(ProviderLedgerError::Unavailable),
                ReopenObservationV1::Conflict => {
                    self.record_backend_conflict(snapshot.acquisition_id)?;
                    return Err(ProviderLedgerError::BackendConflict);
                }
            }
        }
        let holder_id = permit.holder_id;
        self.with_current_completion_session(
            holder_id,
            permit.session_binding,
            |ledger, custody| complete_inventory(ledger, permit, reopened, custody),
        )
    }

    /// Durably completes a reserved Inventory with a non-success disposition.
    ///
    /// This path is used when complete authoritative reopen is impossible. It
    /// never omits an unavailable active lease while claiming a complete
    /// inventory.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for `Complete`, a mismatched permit,
    /// invalid state, signing or model failure, limits, or sync failure.
    pub fn complete_inventory_disposition(
        &mut self,
        permit: DurableInventoryPermitV1,
        status: SourceProviderStatus,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let holder_id = permit.holder_id;
        self.with_current_completion_session(
            holder_id,
            permit.session_binding,
            |ledger, custody| complete_inventory_disposition(ledger, permit, status, custody),
        )
    }
}

fn complete_inventory_disposition(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableInventoryPermitV1,
    status: SourceProviderStatus,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    if status == SourceProviderStatus::Complete {
        return Err(ProviderLedgerError::InvalidTransition(
            "Complete Inventory requires an authoritative projection",
        ));
    }
    let attempt_key_value = ledger
        .recovered
        .attempts
        .keys()
        .find(|key| {
            ledger
                .recovered
                .attempts
                .get(*key)
                .is_some_and(|attempt| attempt.attempt_digest == permit.attempt_digest)
        })
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown inventory permit",
        ))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing inventory attempt"))?;
    let session_identity = (
        attempt.provider.authority_id(),
        attempt.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing inventory session"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.method != SourceProviderMethod::Inventory
        || attempt.holder.authority_id() != permit.holder_id
        || session.pending_attempt_digest != Some(attempt.attempt_digest)
        || permit.reservation_digest.as_bytes() == &[0; 32]
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    session.revision =
        session
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "session revision exhausted",
            ))?;
    session.pending_attempt_digest = None;
    session.last_completed_attempt_digest = Some(attempt.attempt_digest);
    session.next_response_sequence = session.next_response_sequence.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("response sequence exhausted"),
    )?;
    let _derived_records = vec![(
        session_key(session_identity.0, session_identity.1),
        Some(encode_session(&session)),
    )];
    let committed_session_binding = session.session_binding;
    let plan = aos_sandbox_source_provider_ledger::InventoryStatusCompletionPlanV1::new(
        attempt_key(&attempt_key_value),
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_inventory_status_completion(plan, status)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    confirm_current_after_commit(ledger)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(DurableProviderReplyV1 {
        response: Vec::new(),
        source_root: None,
        durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed_outcome),
    })
}

fn active_snapshots(
    ledger: &ProviderLedgerV1<'_>,
    holder_id: [u8; 16],
) -> Result<Vec<ActiveAcquisitionSnapshotV1>, ProviderLedgerError> {
    ledger
        .recovered
        .acquisitions
        .values()
        .filter(|record| {
            record.holder.authority_id() == holder_id
                && matches!(
                    record.state,
                    ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing
                )
        })
        .map(|record| {
            Ok(ActiveAcquisitionSnapshotV1 {
                provider_id: record.provider.authority_id(),
                holder_id: record.holder.authority_id(),
                acquisition_id: record.acquisition_id,
                effect_id: record.effect_id,
                backend_lineage_digest: record.backend_lineage_digest,
                lease_id: record
                    .lease_id
                    .ok_or(ProviderLedgerError::Corrupt("active lease ID"))?,
                lease_digest: record
                    .lease_digest
                    .ok_or(ProviderLedgerError::Corrupt("active lease digest"))?,
                backend_id: record.backend_id,
                evidence: record
                    .backend_evidence
                    .clone()
                    .ok_or(ProviderLedgerError::Corrupt("active backend evidence"))?,
                reopen_identity: record
                    .reopen_identity
                    .clone()
                    .ok_or(ProviderLedgerError::Corrupt("active reopen identity"))?,
                source_root: record
                    .source_root
                    .ok_or(ProviderLedgerError::Corrupt("active source-root identity"))?,
            })
        })
        .collect()
}

pub(crate) fn reserve_inventory(
    ledger: &mut ProviderLedgerV1<'_>,
    security_session: &mut CurrentProviderIngressSessionV1,
    current_request: aos_sandbox_source_provider_security::CurrentProviderRequestV1,
) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
    let provider_execution_identity = current_request.provider_execution_identity();
    let verified = match current_request.verified() {
        aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Inventory(value) => value,
        _ => return Err(ProviderLedgerError::Equivocation),
    };
    let projection = verified.ingress_projection();
    let existing_session = validate_projection(ledger, projection)?;
    validate_session_capacity(ledger, &existing_session, projection)?;
    let request = verified.request();
    let attempt_evidence = verified.attempt();
    let root_record_signer = projection.ordered_signers()[1].clone();
    let attempt_key_value = AttemptKeyV1 {
        provider_id: projection.provider_authority().authority_id(),
        holder_id: projection.root_mount_authority().authority_id(),
        root_record_key_id: root_record_signer.key_id(),
        method: SourceProviderMethod::Inventory as u8,
        request_id: attempt_evidence.request_id(),
    };
    if let Some(disposition) = classify_attempt(
        ledger,
        &attempt_key_value,
        attempt_evidence.attempt_digest(),
        attempt_evidence.signed_request_digest(),
        digest_inventory_request(request),
        attempt_evidence.canonical_signed_request(),
    )? {
        if matches!(
            &disposition,
            ProviderAdmissionDispositionV1::Recover(_)
                | ProviderAdmissionDispositionV1::CachedRecovery { .. }
        ) {
            let retained = ledger
                .recovered
                .attempts
                .get(&attempt_key_value)
                .cloned()
                .ok_or(ProviderLedgerError::Corrupt(
                    "missing retained Inventory attempt",
                ))?;
            let response_sequence = ledger
                .recovered
                .sessions
                .get(&(
                    retained.provider.authority_id(),
                    retained.holder.authority_id(),
                ))
                .ok_or(ProviderLedgerError::Corrupt(
                    "missing retained Inventory session",
                ))?
                .next_response_sequence;
            let signing_authorization = authorize_current_reservation(
                security_session,
                current_request,
                ledger,
                &attempt_key_value,
                &retained,
                response_sequence,
            )?;
            ledger
                .recovery_authorizations
                .insert(retained.attempt_digest, signing_authorization);
        }
        return Ok(disposition);
    }
    let next_request_sequence = match verified.sequence() {
        VerifiedProviderRequestSequenceV1::Fresh(advance) => {
            if advance.accepted_sequence() != request.sequence()
                || advance.attempt_digest() != attempt_evidence.attempt_digest()
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            advance.next_sequence()
        }
        VerifiedProviderRequestSequenceV1::ExactReplay(_) => {
            return Err(ProviderLedgerError::Equivocation);
        }
    };
    if let Some(known_digest) = request.known_inventory_digest() {
        let known = ledger.recovered.attempts.values().any(|attempt| {
            attempt.holder.authority_id() == request.holder_authority_id()
                && attempt.holder.authority_generation() == request.holder_generation()
                && attempt.holder.authority_digest() == request.holder_authority_digest()
                && attempt.provider == *projection.provider_authority()
                && attempt.method == SourceProviderMethod::Inventory
                && attempt.state == ProviderAttemptStateV1::Completed
                && aos_sandbox_source_provider_protocol::decode_inventory_response(
                    &attempt.completed_response,
                )
                .ok()
                .and_then(|response| {
                    response.signed_inventory().and_then(|bytes| {
                        aos_sandbox_source_provider_protocol::SignedSourceProviderInventoryV1::from_canonical_bytes(bytes)
                            .ok()
                    })
                })
                .is_some_and(|inventory| digest_inventory(inventory.subject()) == known_digest)
        });
        if !known {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    if ledger
        .recovered
        .attempts
        .len()
        .saturating_add(ledger.recovered.acquisitions.len())
        .saturating_add(ledger.recovered.releases.len())
        .checked_add(1)
        .is_none_or(|count| count > ledger.configuration.limits().maximum_retained_identities())
    {
        return Err(ProviderLedgerError::LimitExceeded("retained identities"));
    }
    let attempt = reserved_attempt(
        projection.provider_authority().clone(),
        projection.root_mount_authority().clone(),
        root_record_signer,
        SourceProviderMethod::Inventory,
        attempt_evidence.request_id(),
        attempt_evidence.signed_request_digest(),
        digest_inventory_request(request),
        verified.inventory_intent_digest(),
        0,
        attempt_evidence.attempt_digest(),
        projection.session_binding(),
        request.sequence(),
        request.deadline_seconds(),
        projection.verified_at_seconds(),
        projection.current_valid_until_seconds(),
        projection.proof_class_capabilities(),
        projection.supports_recursive(),
        projection.supports_kernel_coupled(),
        projection.root_mount_process_instance(),
        projection.provider_process_instance(),
        projection.signer_set_commitment(),
        ledger.pending_recovery_bridge.as_ref(),
        attempt_evidence.canonical_signed_request().to_vec(),
    );
    let recovery_predecessor = existing_session.as_ref().and_then(|session| {
        (session.session_binding != projection.session_binding())
            .then_some(session.pending_attempt_digest)
            .flatten()
    });
    let recovery_predecessor = recovery_predecessor
        .map(|digest| {
            let key = ledger
                .recovered
                .attempts
                .keys()
                .find(|key| {
                    ledger
                        .recovered
                        .attempts
                        .get(*key)
                        .is_some_and(|value| value.attempt_digest == digest)
                })
                .cloned()
                .ok_or(ProviderLedgerError::Corrupt(
                    "Inventory continuation predecessor",
                ))?;
            let mut predecessor = ledger.recovered.attempts.get(&key).cloned().ok_or(
                ProviderLedgerError::Corrupt("Inventory continuation predecessor"),
            )?;
            if predecessor.method != SourceProviderMethod::Inventory
                || predecessor.state != ProviderAttemptStateV1::Reserved
            {
                return Err(ProviderLedgerError::InvalidTransition(
                    "only reserved Inventory may be superseded without an effect",
                ));
            }
            predecessor.revision = predecessor.revision.checked_add(1).ok_or(
                ProviderLedgerError::InvalidTransition("attempt revision exhausted"),
            )?;
            predecessor.state = ProviderAttemptStateV1::Retired;
            Ok((key, predecessor))
        })
        .transpose()?;
    let (session, _persist_history) = prepare_session(
        ledger,
        projection,
        provider_execution_identity,
        existing_session,
        request.sequence(),
    )?;
    let session = reserve_session(session, next_request_sequence, attempt.attempt_digest)?;
    let mut records = vec![
        (attempt_key(&attempt_key_value), encode_attempt(&attempt)),
        (
            session_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
            ),
            encode_session(&session),
        ),
    ];
    records.push((
        session_history_key(
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        ),
        encode_session_history(&session),
    ));
    if let Some((predecessor_key, predecessor)) = &recovery_predecessor {
        records.push((attempt_key(predecessor_key), encode_attempt(predecessor)));
    }
    let reservation_digest = commit_records(ledger, INVENTORY_RESERVE_PURPOSE, records)?;
    let journal_snapshot = ledger.journal.snapshot()?;
    let authorization_attempt = attempt.clone();
    let authorization_key = attempt_key_value.clone();
    let response_sequence = session.next_response_sequence;
    let holder_id = projection.root_mount_authority().authority_id();
    let committed_session_binding = projection.session_binding();
    let committed_holder_id = request.holder_authority_id();
    ledger
        .recovered
        .attempts
        .insert(attempt_key_value, attempt.clone());
    if let Some((predecessor_key, predecessor)) = recovery_predecessor {
        ledger
            .recovered
            .attempts
            .insert(predecessor_key, predecessor);
    }
    ledger.recovered.sessions.insert(
        (
            session.provider.authority_id(),
            session.holder.authority_id(),
        ),
        session.clone(),
    );
    ledger.recovered.session_history.insert(
        (
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        ),
        session,
    );
    let signing_authorization = authorize_current_reservation(
        security_session,
        current_request,
        ledger,
        &authorization_key,
        &authorization_attempt,
        response_sequence,
    )?;
    ledger.refresh_recovery_work();
    let completion_capacity = preflight_completion_capacity(
        &ledger.journal,
        INVENTORY_COMPLETE_PURPOSE,
        reservation_digest,
        MAXIMUM_INVENTORY_COMPLETION_BYTES,
    )?;
    Ok(ProviderAdmissionDispositionV1::Inventory(
        DurableInventoryPermitV1 {
            holder_id: committed_holder_id,
            session_binding: committed_session_binding,
            attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot,
            completion_capacity,
            signing_authorization,
        },
    ))
}

pub(crate) fn complete_inventory(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableInventoryPermitV1,
    reopened: Vec<ReopenedSourceRootV1>,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    let attempt_key_value = ledger
        .recovered
        .attempts
        .keys()
        .find(|key| {
            ledger
                .recovered
                .attempts
                .get(*key)
                .is_some_and(|attempt| attempt.attempt_digest == permit.attempt_digest)
        })
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown inventory permit",
        ))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing inventory attempt"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.method != SourceProviderMethod::Inventory
        || attempt.holder.authority_id() != permit.holder_id
        || permit.reservation_digest.as_bytes() == &[0; 32]
    {
        return Err(ProviderLedgerError::InvalidTransition(
            "inventory attempt is not reserved",
        ));
    }
    validate_reopened(ledger, permit.holder_id, &reopened)?;
    let entries = holder_inventory_projection(
        &ledger.recovered.acquisitions,
        &ledger.recovered.releases,
        permit.holder_id,
        ledger
            .configuration
            .limits()
            .maximum_inventory_tombstones_per_holder(),
        ledger
            .configuration
            .limits()
            .maximum_inventory_entries_per_holder(),
    )?;
    let protocol_entries = entries
        .iter()
        .map(|entry| {
            let resource = SourceResourceV1::new(
                entry.resource_namespace_digest,
                entry.resource_id,
                entry.resource_generation,
                entry.resource_digest,
                entry.catalog_generation,
                entry.catalog_digest,
                entry.selection_generation,
                entry.selection_digest,
            )?;
            SourceProviderInventoryEntryV1::new(
                entry.lease_id,
                entry.lease_digest,
                entry.acquisition_id,
                match entry.state {
                    InventoryProjectionStateV1::Active => InventoryLeaseStateV1::Active,
                    InventoryProjectionStateV1::Reaping => InventoryLeaseStateV1::Reaping,
                    InventoryProjectionStateV1::Released => InventoryLeaseStateV1::Released,
                },
                resource,
                entry.proof_class,
                entry.proof_digest,
                entry.resource_commitment,
            )
            .map_err(ProviderLedgerError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inventory = SourceProviderInventoryV1::new(
        attempt.request_id,
        attempt.typed_request_digest,
        attempt.holder.authority_id(),
        attempt.holder.authority_generation(),
        attempt.holder.authority_digest(),
        attempt.provider.clone(),
        attempt.provider_process_instance,
        ledger.recovered.catalog.catalog_generation,
        ledger.recovered.catalog.catalog_digest,
        ledger.recovered.authority.inventory_generation,
        protocol_entries,
    )?;
    for observation in &reopened {
        let physical = observation.revalidate_physical();
        ledger.poison_backend_result(observation.acquisition_id, physical)?;
    }
    let session_identity = (
        attempt.provider.authority_id(),
        attempt.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing inventory session"))?;
    if session.pending_attempt_digest != Some(attempt.attempt_digest) {
        return Err(ProviderLedgerError::Corrupt("inventory pending graph"));
    }
    session.revision =
        session
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "session revision exhausted",
            ))?;
    session.pending_attempt_digest = None;
    session.last_completed_attempt_digest = Some(attempt.attempt_digest);
    session.next_response_sequence = session.next_response_sequence.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("response sequence exhausted"),
    )?;
    let _derived_records = vec![(
        session_key(session_identity.0, session_identity.1),
        Some(encode_session(&session)),
    )];
    let committed_session_binding = session.session_binding;
    let plan = aos_sandbox_source_provider_ledger::InventoryCompletionPlanV1::new(attempt_key(
        &attempt_key_value,
    ))
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_inventory_completion(plan, inventory)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    drop(reopened);
    confirm_current_after_commit(ledger)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(DurableProviderReplyV1 {
        response: Vec::new(),
        source_root: None,
        durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed_outcome),
    })
}

fn validate_reopened(
    ledger: &ProviderLedgerV1<'_>,
    holder_id: [u8; 16],
    reopened: &[ReopenedSourceRootV1],
) -> Result<(), ProviderLedgerError> {
    let required: Vec<&AcquisitionRecordV1> = ledger
        .recovered
        .acquisitions
        .values()
        .filter(|record| {
            record.holder.authority_id() == holder_id
                && matches!(
                    record.state,
                    ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing
                )
        })
        .collect();
    if required.len() != reopened.len() {
        return Err(ProviderLedgerError::Unavailable);
    }
    let mut seen = BTreeSet::new();
    for observation in reopened {
        if !seen.insert(observation.acquisition_id) {
            return Err(ProviderLedgerError::BackendConflict);
        }
        let record = required
            .iter()
            .find(|record| record.acquisition_id == observation.acquisition_id)
            .ok_or(ProviderLedgerError::BackendConflict)?;
        if record.source_root != Some(observation.source_root)
            || record.backend_id != observation.backend_id
            || record.backend_evidence.as_ref() != Some(&observation.backend_evidence)
            || record.reopen_identity.as_ref() != Some(&observation.reopen_identity)
        {
            return Err(ProviderLedgerError::BackendConflict);
        }
    }
    Ok(())
}

fn conflicting_reopen(
    ledger: &ProviderLedgerV1<'_>,
    holder_id: [u8; 16],
    reopened: &[ReopenedSourceRootV1],
) -> Option<ObjectDigest> {
    let required: Vec<&AcquisitionRecordV1> = ledger
        .recovered
        .acquisitions
        .values()
        .filter(|record| {
            record.holder.authority_id() == holder_id
                && matches!(
                    record.state,
                    ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing
                )
        })
        .collect();
    if required.len() != reopened.len() {
        return None;
    }

    let mut seen = BTreeSet::new();
    for observation in reopened {
        if !seen.insert(observation.acquisition_id) {
            return required
                .iter()
                .find(|record| record.acquisition_id == observation.acquisition_id)
                .map(|record| record.acquisition_id)
                .or_else(|| required.first().map(|record| record.acquisition_id));
        }
        let Some(record) = required
            .iter()
            .find(|record| record.acquisition_id == observation.acquisition_id)
        else {
            return required.first().map(|record| record.acquisition_id);
        };
        if record.source_root != Some(observation.source_root)
            || record.backend_id != observation.backend_id
            || record.backend_evidence.as_ref() != Some(&observation.backend_evidence)
            || record.reopen_identity.as_ref() != Some(&observation.reopen_identity)
        {
            return Some(record.acquisition_id);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum InventoryProjectionStateV1 {
    Active = 1,
    Reaping = 2,
    Released = 3,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct InventoryProjectionEntryV1 {
    pub(crate) provider_id: [u8; 16],
    pub(crate) holder_id: [u8; 16],
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) state: InventoryProjectionStateV1,
    pub(crate) resource_namespace_digest: ObjectDigest,
    pub(crate) resource_id: [u8; 32],
    pub(crate) resource_generation: u64,
    pub(crate) resource_digest: ObjectDigest,
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_digest: ObjectDigest,
    pub(crate) selection_generation: u64,
    pub(crate) selection_digest: ObjectDigest,
    pub(crate) proof_class: u8,
    pub(crate) proof_digest: ObjectDigest,
    pub(crate) resource_commitment: ObjectDigest,
    pub(crate) release_generation: u64,
}

pub(crate) fn global_inventory_state_digest(
    provider_id: [u8; 16],
    current_catalog_generation: u64,
    current_catalog_digest: ObjectDigest,
    acquisitions: &BTreeMap<AcquisitionKeyV1, AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, ReleaseRecordV1>,
    maximum_tombstones_per_holder: usize,
) -> Result<(ObjectDigest, u64), ProviderLedgerError> {
    let mut entries = inventory_projection(acquisitions, releases, maximum_tombstones_per_holder)?;
    entries.sort_by_key(|entry| entry.lease_id);

    let mut leases = BTreeSet::new();
    let mut acquisition_ids = BTreeSet::new();
    for entry in &entries {
        if !leases.insert(entry.lease_id) || !acquisition_ids.insert(entry.acquisition_id) {
            return Err(ProviderLedgerError::Corrupt(
                "duplicate inventory lease or acquisition",
            ));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_STATE_DOMAIN);
    hasher.update(provider_id);
    hasher.update(current_catalog_generation.to_be_bytes());
    hasher.update(current_catalog_digest.as_bytes());
    hasher.update((entries.len() as u32).to_be_bytes());
    for entry in &entries {
        hasher.update(entry.provider_id);
        hasher.update(entry.holder_id);
        hasher.update(entry.lease_id);
        hasher.update(entry.lease_digest.as_bytes());
        hasher.update(entry.acquisition_id.as_bytes());
        hasher.update([entry.state as u8]);
        hasher.update([0; 7]);
        hasher.update(entry.resource_namespace_digest.as_bytes());
        hasher.update(entry.resource_id);
        hasher.update(entry.resource_generation.to_be_bytes());
        hasher.update(entry.resource_digest.as_bytes());
        hasher.update(entry.catalog_generation.to_be_bytes());
        hasher.update(entry.catalog_digest.as_bytes());
        hasher.update(entry.selection_generation.to_be_bytes());
        hasher.update(entry.selection_digest.as_bytes());
        hasher.update([entry.proof_class]);
        hasher.update([0; 7]);
        hasher.update(entry.proof_digest.as_bytes());
        hasher.update(entry.resource_commitment.as_bytes());
        hasher.update(entry.release_generation.to_be_bytes());
    }
    let active_count = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.state,
                InventoryProjectionStateV1::Active | InventoryProjectionStateV1::Reaping
            )
        })
        .count() as u64;
    Ok((
        ObjectDigest::from_bytes(hasher.finalize().into()),
        active_count,
    ))
}

pub(crate) fn holder_inventory_projection(
    acquisitions: &BTreeMap<AcquisitionKeyV1, AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, ReleaseRecordV1>,
    holder_id: [u8; 16],
    maximum_tombstones: usize,
    maximum_entries: usize,
) -> Result<Vec<InventoryProjectionEntryV1>, ProviderLedgerError> {
    let mut entries = inventory_projection(acquisitions, releases, maximum_tombstones)?;
    entries.retain(|entry| entry.holder_id == holder_id);
    entries.sort_by_key(|entry| entry.lease_id);
    if entries.len() > maximum_entries
        || !entries
            .windows(2)
            .all(|pair| pair[0].lease_id < pair[1].lease_id)
    {
        return Err(ProviderLedgerError::LimitExceeded(
            "holder inventory entries",
        ));
    }
    Ok(entries)
}

fn inventory_projection(
    acquisitions: &BTreeMap<AcquisitionKeyV1, AcquisitionRecordV1>,
    releases: &BTreeMap<ReleaseKeyV1, ReleaseRecordV1>,
    maximum_tombstones_per_holder: usize,
) -> Result<Vec<InventoryProjectionEntryV1>, ProviderLedgerError> {
    let mut newest_released: BTreeMap<([u8; 16], [u8; 16]), Vec<&AcquisitionRecordV1>> =
        BTreeMap::new();
    let mut entries = Vec::new();

    for acquisition in acquisitions.values() {
        match acquisition.state {
            ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing => {
                entries.push(project(acquisition, releases)?);
            }
            ProviderAcquisitionStateV1::Released => {
                newest_released
                    .entry((
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                    ))
                    .or_default()
                    .push(acquisition);
            }
            ProviderAcquisitionStateV1::Applying
            | ProviderAcquisitionStateV1::Pending
            | ProviderAcquisitionStateV1::Faulted => {}
        }
    }
    for tombstones in newest_released.values_mut() {
        tombstones.sort_by_key(|record| {
            let key = ReleaseKeyV1 {
                provider_id: record.provider.authority_id(),
                holder_id: record.holder.authority_id(),
                acquisition_id: record.acquisition_id,
            };
            std::cmp::Reverse(
                releases
                    .get(&key)
                    .map_or(0, |release| release.release_generation),
            )
        });
        for record in tombstones.iter().take(maximum_tombstones_per_holder) {
            entries.push(project(record, releases)?);
        }
    }
    Ok(entries)
}

fn project(
    acquisition: &AcquisitionRecordV1,
    releases: &BTreeMap<ReleaseKeyV1, ReleaseRecordV1>,
) -> Result<InventoryProjectionEntryV1, ProviderLedgerError> {
    let lease_id = acquisition.lease_id.ok_or(ProviderLedgerError::Corrupt(
        "inventoried acquisition lacks lease",
    ))?;
    let lease_digest = acquisition
        .lease_digest
        .ok_or(ProviderLedgerError::Corrupt(
            "inventoried acquisition lacks lease digest",
        ))?;
    let state = match acquisition.state {
        ProviderAcquisitionStateV1::Active => InventoryProjectionStateV1::Active,
        ProviderAcquisitionStateV1::Releasing => InventoryProjectionStateV1::Reaping,
        ProviderAcquisitionStateV1::Released => InventoryProjectionStateV1::Released,
        _ => {
            return Err(ProviderLedgerError::Corrupt(
                "non-inventoried acquisition state",
            ));
        }
    };
    let release_generation = if state == InventoryProjectionStateV1::Active {
        0
    } else {
        releases
            .get(&ReleaseKeyV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                acquisition_id: acquisition.acquisition_id,
            })
            .ok_or(ProviderLedgerError::Corrupt("inventoried release lineage"))?
            .release_generation
    };
    Ok(InventoryProjectionEntryV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        lease_id,
        lease_digest,
        acquisition_id: acquisition.acquisition_id,
        state,
        resource_namespace_digest: acquisition.resource_namespace_digest,
        resource_id: acquisition.resource_id,
        resource_generation: acquisition.resource_generation,
        resource_digest: acquisition.resource_digest,
        catalog_generation: acquisition.catalog_generation,
        catalog_digest: acquisition.catalog_digest,
        selection_generation: acquisition.selection_generation,
        selection_digest: acquisition.selection_digest,
        proof_class: acquisition.proof_class,
        proof_digest: acquisition.proof_digest,
        resource_commitment: acquisition.resource_commitment,
        release_generation,
    })
}
