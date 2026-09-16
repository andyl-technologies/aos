//! Release reservation, backend execution boundary, and durable tombstones.

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ReleaseSourceResponseV1, SourceProviderMethod, SourceProviderResponseStatusV1,
    SourceProviderStatus, SourceReleaseReceiptV1, VerifiedProviderReleaseRequestV1,
    VerifiedProviderRequestSequenceV1, digest_release_request, digest_signed_release_receipt,
    empty_descriptor_set_commitment_v1, encode_release_response, response_result_digest_v1,
};
use aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1;

use crate::backend::{
    BackendEvidenceStateV1, DurableProviderReplyV1, DurableReleaseEffectPermitV1,
    DurableReleaseTombstoneV1, ObservedBackendReleaseV1, ReleaseObservationV1, ReleasePlanV1,
    SourceProviderBackendV1,
};
use crate::format::{
    acquisition_key, attempt_key, authority_key, encode_acquisition, encode_attempt,
    encode_authority, encode_release, encode_session, encode_session_history, record_digest,
    release_key, session_history_key, session_key,
};
use crate::inventory::global_inventory_state_digest;
use crate::ledger::artifact::response_artifact_digest;
use crate::limits::MAXIMUM_RELEASE_COMPLETION_BYTES;
use crate::model::{
    AcquisitionKeyV1, AttemptKeyV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
    ProviderAuthorityStateV1, ProviderReleaseStateV1, ReleaseKeyV1, ReleaseRecordV1,
};
use crate::state::ProviderLedgerV1;
use crate::transaction::{
    authorize_current_reservation, classify_attempt, commit_records, confirm_current_after_commit,
    confirm_current_session_after_commit, preflight_completion_capacity, prepare_session,
    reserve_session, reserved_attempt, validate_projection, validate_session_capacity,
};
use crate::{ProviderAdmissionDispositionV1, ProviderLedgerError};

const RELEASE_RESERVE_PURPOSE: &[u8] = b"reserve-release";
const RELEASE_COMPLETE_PURPOSE: &[u8] = b"complete-release";

pub(crate) struct LivePendingReleaseV1 {
    plan: ReleasePlanV1,
    completion_session_binding: ObjectDigest,
    completion_attempt_digest: ObjectDigest,
    reservation_digest: ObjectDigest,
}

impl ProviderLedgerV1<'_> {
    /// Observes, executes when still present, and durably completes one Release.
    ///
    /// The backend receives no signer and can execute only by consuming the
    /// synced reservation permit. The exact response is returned only after the
    /// tombstone, acquisition, attempt, authority, and session update syncs.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for backend conflict, invalid lineage,
    /// signing or model failure, limits, or completion sync failure.
    pub fn execute_release<B: SourceProviderBackendV1>(
        &mut self,
        permit: DurableReleaseEffectPermitV1,
        backend: &mut B,
    ) -> Result<(DurableProviderReplyV1, DurableReleaseTombstoneV1), ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let acquisition_id = permit.plan.acquisition_id;
        let observation = backend.observe_release(&permit.plan);
        let (permit, observed) = match self.poison_backend_result(acquisition_id, observation)? {
            ReleaseObservationV1::StillPresent => {
                let executed = backend.execute_release(permit);
                self.poison_backend_result(acquisition_id, executed)?
            }
            ReleaseObservationV1::Released(observed) => (permit, observed),
            ReleaseObservationV1::Conflict => {
                self.record_backend_conflict(permit.plan.acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
        };
        let holder_id = permit.plan.holder_id;
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current completion session"),
        )?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != permit.completion_session_binding {
            self.current_sessions.insert(holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        let result = complete_release(self, permit, observed, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result
    }

    /// Durably completes a reserved Release without a terminal receipt.
    ///
    /// `Pending` and `Unavailable` retain the immutable response disposition
    /// while the separate acquisition effect remains Reaping for recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for a terminal status, a mismatched permit,
    /// invalid lineage, signing or model failure, limits, or sync failure.
    pub fn complete_release_disposition(
        &mut self,
        permit: DurableReleaseEffectPermitV1,
        status: SourceProviderStatus,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let holder_id = permit.plan.holder_id;
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current completion session"),
        )?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != permit.completion_session_binding {
            self.current_sessions.insert(holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        let result = complete_release_disposition(self, permit, status, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        result
    }

    /// Observes and durably terminalizes one live Pending release.
    ///
    /// This path never reissues backend execution authority. It may consume
    /// only an exact already-released observation after the original request
    /// was freshly reauthenticated. The cached Pending response is not
    /// rewritten; the tombstone is a separate durable effect progression.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when no live continuation exists, the
    /// journal or custody changed, release remains unavailable, backend facts
    /// conflict, signing fails, or the tombstone transaction cannot sync.
    pub fn observe_pending_release<B: SourceProviderBackendV1>(
        &mut self,
        acquisition_id: ObjectDigest,
        backend: &mut B,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let progress = self.pending_releases.remove(&acquisition_id).ok_or(
            ProviderLedgerError::InvalidTransition("no live Pending release continuation"),
        )?;
        let current_snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&current_snapshot)?;
        let completion_capacity = preflight_completion_capacity(
            &self.journal,
            b"complete-pending-release",
            progress.reservation_digest,
            MAXIMUM_RELEASE_COMPLETION_BYTES,
        )?;
        completion_capacity.validate(&self.journal)?;
        let holder_id = progress.plan.holder_id;
        let current = self
            .current_sessions
            .get_mut(&holder_id)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "missing current Pending release session",
            ))?
            .session
            .current_projection()?;
        if current.session_binding() != progress.completion_session_binding {
            return Err(ProviderLedgerError::Equivocation);
        }

        let observation = backend.observe_release(&progress.plan);
        let observed = match self.poison_backend_result(acquisition_id, observation) {
            Ok(ReleaseObservationV1::Released(observed)) => observed,
            Ok(ReleaseObservationV1::StillPresent) => {
                self.pending_releases.insert(acquisition_id, progress);
                return Err(ProviderLedgerError::Unavailable);
            }
            Ok(ReleaseObservationV1::Conflict) => {
                self.record_backend_conflict(acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
            Err(error) => {
                self.pending_releases.insert(acquisition_id, progress);
                return Err(error);
            }
        };
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current Pending release session"),
        )?;
        let result = complete_pending_release(self, progress, observed, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result
    }
}

fn complete_release_disposition(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableReleaseEffectPermitV1,
    status: SourceProviderStatus,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    if !matches!(
        status,
        SourceProviderStatus::Pending | SourceProviderStatus::Unavailable
    ) {
        return Err(ProviderLedgerError::InvalidTransition(
            "Release effect disposition must remain explicitly unresolved",
        ));
    }
    let pending_plan = (status == SourceProviderStatus::Pending).then(|| {
        (
            permit.plan.clone(),
            permit.completion_session_binding,
            permit.completion_attempt_digest,
        )
    });
    if pending_plan.is_some()
        && ledger
            .pending_releases
            .contains_key(&permit.plan.acquisition_id)
    {
        return Err(ProviderLedgerError::InvalidTransition(
            "duplicate live Pending release continuation",
        ));
    }
    let reservation_digest = permit.reservation_digest;
    let acquisition_key_value = ledger
        .recovered
        .acquisitions
        .keys()
        .find(|key| key.acquisition_id == permit.plan.acquisition_id)
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown release permit",
        ))?;
    let mut acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing releasing acquisition",
        ))?;
    let release_key_value = ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    };
    let mut release = ledger
        .recovered
        .releases
        .get(&release_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release intent"))?;
    if acquisition.state != ProviderAcquisitionStateV1::Releasing
        || release.state != ProviderReleaseStateV1::Intent
        || !permit.plan.matches_effect_release(&acquisition, &release)
        || permit.reservation_digest.as_bytes() == &[0; 32]
    {
        return Err(ProviderLedgerError::Equivocation);
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
                .is_some_and(|attempt| attempt.attempt_digest == release.attempt_digest)
        })
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release attempt"))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release attempt"))?;
    let session_identity = (
        acquisition.provider.authority_id(),
        acquisition.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release session"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.session_binding != permit.completion_session_binding
        || attempt.attempt_digest != permit.completion_attempt_digest
        || session.pending_attempt_digest != Some(attempt.attempt_digest)
    {
        return Err(ProviderLedgerError::Corrupt("release pending graph"));
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
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition revision exhausted",
            ))?;
    release.revision =
        release
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "release revision exhausted",
            ))?;
    release.acquisition_record_digest = record_digest(&encode_acquisition(&acquisition))?;
    let _derived_records = vec![
        (
            acquisition_key(&acquisition_key_value),
            Some(encode_acquisition(&acquisition)),
        ),
        (
            session_key(session_identity.0, session_identity.1),
            Some(encode_session(&session)),
        ),
        (
            release_key(&release_key_value),
            Some(encode_release(&release)),
        ),
    ];
    let committed_session_binding = session.session_binding;
    let plan = aos_sandbox_source_provider_ledger::ReleaseStatusCompletionPlanV1::new(attempt_key(
        &attempt_key_value,
    ))
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_release_status_completion(plan, status)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    if let Some((plan, completion_session_binding, completion_attempt_digest)) = pending_plan {
        ledger.pending_releases.insert(
            plan.acquisition_id,
            LivePendingReleaseV1 {
                plan,
                completion_session_binding,
                completion_attempt_digest,
                reservation_digest,
            },
        );
    }
    confirm_current_after_commit(ledger)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(DurableProviderReplyV1 {
        response: Vec::new(),
        source_root: None,
        durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed_outcome),
    })
}

fn complete_pending_release(
    ledger: &mut ProviderLedgerV1<'_>,
    progress: LivePendingReleaseV1,
    observed: ObservedBackendReleaseV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<(), ProviderLedgerError> {
    let current_snapshot = ledger.journal.snapshot()?;
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&current_snapshot)?;
    let completion_capacity = preflight_completion_capacity(
        &ledger.journal,
        b"complete-pending-release",
        progress.reservation_digest,
        MAXIMUM_RELEASE_COMPLETION_BYTES,
    )?;
    completion_capacity.validate(&ledger.journal)?;
    let acquisition_key_value = ledger
        .recovered
        .acquisitions
        .keys()
        .find(|key| key.acquisition_id == progress.plan.acquisition_id)
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown Pending release acquisition",
        ))?;
    let mut acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Pending release acquisition",
        ))?;
    let acquired_evidence = acquisition
        .backend_evidence
        .as_ref()
        .ok_or(ProviderLedgerError::Corrupt("missing acquired evidence"))?;
    let release_key_value = ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    };
    let mut release = ledger
        .recovered
        .releases
        .get(&release_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Pending release intent",
        ))?;
    if acquisition.state != ProviderAcquisitionStateV1::Releasing
        || release.state != ProviderReleaseStateV1::Intent
        || progress.reservation_digest.as_bytes() == &[0; 32]
        || !progress.plan.matches_effect_release(&acquisition, &release)
        || observed.backend_id != progress.plan.backend_id
        || observed.lineage_digest != progress.plan.lineage_digest()
        || observed.evidence.state() != BackendEvidenceStateV1::Released
        || observed.evidence.class() != acquired_evidence.class()
        || observed.evidence.backend_authority_id() != acquired_evidence.backend_authority_id()
        || observed.evidence.backend_generation() != acquired_evidence.backend_generation()
        || observed.evidence.backend_digest() != acquired_evidence.backend_digest()
        || observed.evidence.predecessor_observation_generation()?
            != acquired_evidence.observation_generation()
        || observed.evidence.predecessor_observation_digest()?
            != acquired_evidence.observation_digest()
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let attempt = ledger
        .recovered
        .attempts
        .values()
        .find(|attempt| attempt.attempt_digest == release.attempt_digest)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Pending release attempt",
        ))?;
    if attempt.state != ProviderAttemptStateV1::Completed
        || !matches!(
            attempt.status,
            Some(SourceProviderStatus::Pending | SourceProviderStatus::Unavailable)
        )
        || attempt.session_binding != progress.completion_session_binding
        || attempt.attempt_digest != progress.completion_attempt_digest
        || observed.released_seconds < attempt.verified_at_seconds
        || observed.released_seconds >= ledger.recovered.authority.valid_until_seconds
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let signing_authorization = ledger
        .recovery_authorizations
        .remove(&attempt.attempt_digest)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "fresh authenticated Pending release continuation required",
        ))?;
    let receipt = SourceReleaseReceiptV1::new(
        attempt.request_id,
        attempt.typed_request_digest,
        release.lease_id,
        release.lease_digest,
        release.provider.clone(),
        attempt.provider_process_instance,
        release.release_generation,
        observed.released_seconds,
    )?;
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = ProviderAcquisitionStateV1::Released;
    let acquisition_bytes = encode_acquisition(&acquisition);
    let mut authority = ledger.recovered.authority.clone();
    authority.revision =
        authority
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "authority revision exhausted",
            ))?;
    authority.inventory_generation = authority.inventory_generation.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("inventory generation exhausted"),
    )?;
    let _derived_records = vec![
        (
            acquisition_key(&acquisition_key_value),
            Some(acquisition_bytes),
        ),
        (
            authority_key(authority.provider.authority_id()),
            Some(encode_authority(&authority)),
        ),
    ];
    let committed_session_binding = progress.completion_session_binding;
    let observation_digest = observed.evidence.observation_digest();
    let release_patch = aos_sandbox_source_provider_ledger::ReleaseCompletionPatchV1::new(
        release_key(&release_key_value),
        observed.evidence.encode(),
        observation_digest,
        observed.released_seconds,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let tombstones = ledger
        .configuration
        .limits()
        .maximum_inventory_tombstones_per_holder();
    let plan = aos_sandbox_source_provider_ledger::ReleaseRecoveryCompletionPlanV1::new(
        release_patch,
        tombstones,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &signing_authorization)?
        .prepare_release_recovery_completion(plan, receipt)?;
    let _committed_outcome =
        crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    confirm_current_after_commit(ledger)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(())
}

pub(crate) fn reserve_release(
    ledger: &mut ProviderLedgerV1<'_>,
    security_session: &mut CurrentProviderIngressSessionV1,
    current_request: aos_sandbox_source_provider_security::CurrentProviderRequestV1,
) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
    let provider_execution_identity = current_request.provider_execution_identity();
    let verified = match current_request.verified() {
        aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Release(value) => value,
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
        method: SourceProviderMethod::Release as u8,
        request_id: attempt_evidence.request_id(),
    };
    if let Some(disposition) = classify_attempt(
        ledger,
        &attempt_key_value,
        attempt_evidence.attempt_digest(),
        attempt_evidence.signed_request_digest(),
        digest_release_request(request),
        attempt_evidence.canonical_signed_request(),
    )? {
        let resumes_terminal = matches!(
            &disposition,
            ProviderAdmissionDispositionV1::CachedRecovery { .. }
        );
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
                    "missing retained Release attempt",
                ))?;
            let response_sequence = ledger
                .recovered
                .sessions
                .get(&(
                    retained.provider.authority_id(),
                    retained.holder.authority_id(),
                ))
                .ok_or(ProviderLedgerError::Corrupt(
                    "missing retained Release session",
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
            if resumes_terminal {
                let release = ledger
                    .recovered
                    .releases
                    .values()
                    .find(|record| record.attempt_digest == retained.attempt_digest)
                    .cloned()
                    .ok_or(ProviderLedgerError::Corrupt(
                        "nonterminal Release has no durable intent",
                    ))?;
                let acquisition = ledger
                    .recovered
                    .acquisitions
                    .values()
                    .find(|record| record.acquisition_id == release.acquisition_id)
                    .ok_or(ProviderLedgerError::Corrupt(
                        "nonterminal Release has no acquisition",
                    ))?;
                let effect_attempt = ledger
                    .recovered
                    .attempts
                    .values()
                    .find(|attempt| attempt.attempt_digest == release.effect_attempt_digest)
                    .ok_or(ProviderLedgerError::Corrupt(
                        "nonterminal Release has no effect attempt",
                    ))?;
                let plan = ReleasePlanV1 {
                    provider_id: release.provider.authority_id(),
                    holder_id: release.holder.authority_id(),
                    session_binding: effect_attempt.session_binding,
                    attempt_digest: effect_attempt.attempt_digest,
                    acquisition_id: release.acquisition_id,
                    effect_id: release.effect_id,
                    lease_id: release.lease_id,
                    lease_digest: release.lease_digest,
                    backend_id: release.backend_id,
                    acquired_evidence: crate::backend::acquired_evidence(acquisition)?,
                };
                if !plan.matches_effect_release(acquisition, &release) {
                    return Err(ProviderLedgerError::Corrupt(
                        "nonterminal Release recovery plan",
                    ));
                }
                ledger.pending_releases.insert(
                    release.acquisition_id,
                    LivePendingReleaseV1 {
                        plan,
                        completion_session_binding: retained.session_binding,
                        completion_attempt_digest: retained.attempt_digest,
                        reservation_digest: release.backend_lineage_digest,
                    },
                );
            }
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
    let acquisition_key_value = AcquisitionKeyV1 {
        provider_id: projection.provider_authority().authority_id(),
        holder_id: projection.root_mount_authority().authority_id(),
        acquisition_id: request.acquisition_id(),
    };
    let mut acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Equivocation)?;
    let exact_holder = acquisition.holder.authority_id() == request.holder_authority_id()
        && acquisition.holder.authority_generation() == request.holder_generation()
        && acquisition.holder.authority_digest() == request.holder_authority_digest();
    let recovery_holder = ledger
        .pending_recovery_bridge
        .as_ref()
        .is_some_and(|bridge| {
            ledger.recovered.attempts.values().any(|predecessor| {
                predecessor.attempt_digest == bridge.old_attempt_digest
                    && predecessor.session_binding == bridge.old_session_binding
                    && predecessor.provider == acquisition.provider
                    && predecessor.holder == acquisition.holder
                    && predecessor.acquisition_sequence == acquisition.acquisition_sequence
                    && acquisition.current_attempt_digest == predecessor.attempt_digest
            }) && acquisition.holder.authority_id() == request.holder_authority_id()
                && request.holder_generation() > acquisition.holder.authority_generation()
                && request.holder_authority_digest() != acquisition.holder.authority_digest()
        });
    if acquisition.lease_id != Some(request.lease_id())
        || acquisition.lease_digest != Some(request.lease_digest())
        || (!exact_holder && !recovery_holder)
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let additional_identities = match acquisition.state {
        ProviderAcquisitionStateV1::Releasing => 1,
        ProviderAcquisitionStateV1::Active => 2,
        _ => return Err(ProviderLedgerError::Equivocation),
    };
    let retained_identities = ledger
        .recovered
        .attempts
        .len()
        .saturating_add(ledger.recovered.acquisitions.len())
        .saturating_add(ledger.recovered.releases.len());
    if retained_identities
        .checked_add(additional_identities)
        .is_none_or(|count| count > ledger.configuration.limits().maximum_retained_identities())
    {
        return Err(ProviderLedgerError::LimitExceeded("retained identities"));
    }
    if acquisition.state == ProviderAcquisitionStateV1::Releasing {
        return reserve_release_continuation(
            ledger,
            security_session,
            current_request,
            attempt_key_value,
            acquisition,
            existing_session,
            next_request_sequence,
        );
    }
    let release_key_value = ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    };
    if ledger.recovered.releases.contains_key(&release_key_value) {
        return Err(ProviderLedgerError::Equivocation);
    }
    let release_generation = ledger
        .recovered
        .authority
        .last_release_generation
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "release generation exhausted",
        ))?;
    let effect_id = derive_release_effect_id(
        acquisition.acquisition_id,
        attempt_evidence.attempt_digest(),
        release_generation,
    )?;
    let attempt = reserved_attempt(
        projection.provider_authority().clone(),
        projection.root_mount_authority().clone(),
        root_record_signer,
        SourceProviderMethod::Release,
        attempt_evidence.request_id(),
        attempt_evidence.signed_request_digest(),
        digest_release_request(request),
        verified.release_intent_digest(),
        acquisition.acquisition_sequence,
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
    let (session, _persist_history) = prepare_session(
        ledger,
        projection,
        provider_execution_identity,
        existing_session,
        request.sequence(),
    )?;
    let session = reserve_session(session, next_request_sequence, attempt.attempt_digest)?;
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = ProviderAcquisitionStateV1::Releasing;
    acquisition.current_attempt_digest = attempt.attempt_digest;
    acquisition.release_effect_id = Some(effect_id);
    let acquisition_bytes = encode_acquisition(&acquisition);
    let release_plan = ReleasePlanV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        session_binding: projection.session_binding(),
        attempt_digest: acquisition.current_attempt_digest,
        acquisition_id: acquisition.acquisition_id,
        effect_id,
        lease_id: request.lease_id(),
        lease_digest: request.lease_digest(),
        backend_id: acquisition.backend_id,
        acquired_evidence: crate::backend::acquired_evidence(&acquisition)?,
    };
    let release = ReleaseRecordV1 {
        revision: 1,
        state: ProviderReleaseStateV1::Intent,
        provider: acquisition.provider.clone(),
        holder: acquisition.holder.clone(),
        acquisition_id: acquisition.acquisition_id,
        acquisition_sequence: acquisition.acquisition_sequence,
        lease_id: request.lease_id(),
        lease_digest: request.lease_digest(),
        effect_id,
        release_generation,
        effect_attempt_digest: attempt.attempt_digest,
        attempt_digest: attempt.attempt_digest,
        backend_id: acquisition.backend_id,
        backend_lineage_digest: release_plan.lineage_digest(),
        backend_evidence: None,
        release_observation_digest: None,
        released_seconds: None,
        receipt_digest: None,
        signed_receipt: Vec::new(),
        acquisition_record_digest: record_digest(&acquisition_bytes)?,
    };
    let mut authority = ledger.recovered.authority.clone();
    authority.revision =
        authority
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "authority revision exhausted",
            ))?;
    authority.last_release_generation = release_generation;
    authority.inventory_generation = authority.inventory_generation.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("inventory generation exhausted"),
    )?;
    let mut projected_acquisitions = ledger.recovered.acquisitions.clone();
    projected_acquisitions.insert(acquisition_key_value.clone(), acquisition.clone());
    let mut projected_releases = ledger.recovered.releases.clone();
    projected_releases.insert(release_key_value.clone(), release.clone());
    let (inventory_digest, active_count) = global_inventory_state_digest(
        authority.provider.authority_id(),
        authority.catalog_generation,
        authority.catalog_digest,
        &projected_acquisitions,
        &projected_releases,
        ledger
            .configuration
            .limits()
            .maximum_inventory_tombstones_per_holder(),
    )?;
    authority.inventory_state_digest = inventory_digest;
    authority.active_lease_count = active_count;
    let mut records = vec![
        (attempt_key(&attempt_key_value), encode_attempt(&attempt)),
        (acquisition_key(&acquisition_key_value), acquisition_bytes),
        (release_key(&release_key_value), encode_release(&release)),
        (
            authority_key(authority.provider.authority_id()),
            encode_authority(&authority),
        ),
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
    let reservation_digest = commit_records(ledger, RELEASE_RESERVE_PURPOSE, records)?;
    let journal_snapshot = ledger.journal.snapshot()?;
    let authorization_attempt = attempt.clone();
    let authorization_key = attempt_key_value.clone();
    let response_sequence = session.next_response_sequence;
    let holder_id = projection.root_mount_authority().authority_id();
    let completion_session_binding = projection.session_binding();
    ledger.recovered.attempts.insert(attempt_key_value, attempt);
    ledger
        .recovered
        .acquisitions
        .insert(acquisition_key_value, acquisition.clone());
    ledger.recovered.releases.insert(release_key_value, release);
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
    ledger.recovered.authority = authority;
    ledger.refresh_recovery_work();
    let completion_capacity = preflight_completion_capacity(
        &ledger.journal,
        RELEASE_COMPLETE_PURPOSE,
        reservation_digest,
        MAXIMUM_RELEASE_COMPLETION_BYTES,
    )?;
    Ok(ProviderAdmissionDispositionV1::Release(
        DurableReleaseEffectPermitV1 {
            plan: release_plan,
            completion_session_binding,
            completion_attempt_digest: authorization_attempt.attempt_digest,
            reservation_digest,
            journal_snapshot,
            completion_capacity,
            signing_authorization,
        },
    ))
}

fn reserve_release_continuation(
    ledger: &mut ProviderLedgerV1<'_>,
    security_session: &mut CurrentProviderIngressSessionV1,
    current_request: aos_sandbox_source_provider_security::CurrentProviderRequestV1,
    attempt_key_value: AttemptKeyV1,
    mut acquisition: crate::model::AcquisitionRecordV1,
    existing_session: Option<crate::model::HolderSessionHeadRecordV1>,
    next_request_sequence: u64,
) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
    let provider_execution_identity = current_request.provider_execution_identity();
    let verified = match current_request.verified() {
        aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Release(value) => value,
        _ => return Err(ProviderLedgerError::Equivocation),
    };
    let projection = verified.ingress_projection();
    let request = verified.request();
    let attempt_evidence = verified.attempt();
    let release_key_value = ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    };
    let mut release = ledger
        .recovered
        .releases
        .get(&release_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Release continuation intent",
        ))?;
    let predecessor_key = ledger
        .recovered
        .attempts
        .keys()
        .find(|key| {
            ledger
                .recovered
                .attempts
                .get(*key)
                .is_some_and(|attempt| attempt.attempt_digest == release.attempt_digest)
        })
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Release continuation attempt",
        ))?;
    let mut predecessor = ledger
        .recovered
        .attempts
        .get(&predecessor_key)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Release continuation attempt",
        ))?;
    if release.state != ProviderReleaseStateV1::Intent
        || acquisition.current_attempt_digest != predecessor.attempt_digest
        || !matches!(
            (predecessor.state, predecessor.status),
            (ProviderAttemptStateV1::Reserved, None)
                | (
                    ProviderAttemptStateV1::Completed,
                    Some(SourceProviderStatus::Pending | SourceProviderStatus::Unavailable)
                )
        )
        || predecessor.operation_intent_digest != verified.release_intent_digest()
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let effect_attempt = ledger
        .recovered
        .attempts
        .values()
        .find(|attempt| attempt.attempt_digest == release.effect_attempt_digest)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Release effect attempt",
        ))?;
    let attempt = reserved_attempt(
        projection.provider_authority().clone(),
        projection.root_mount_authority().clone(),
        projection.ordered_signers()[1].clone(),
        SourceProviderMethod::Release,
        attempt_evidence.request_id(),
        attempt_evidence.signed_request_digest(),
        digest_release_request(request),
        verified.release_intent_digest(),
        acquisition.acquisition_sequence,
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
    let (session, persist_history) = prepare_session(
        ledger,
        projection,
        provider_execution_identity,
        existing_session,
        request.sequence(),
    )?;
    if !persist_history {
        return Err(ProviderLedgerError::InvalidTransition(
            "Release continuation requires a superseding session",
        ));
    }
    let session = reserve_session(session, next_request_sequence, attempt.attempt_digest)?;
    if predecessor.state == ProviderAttemptStateV1::Reserved {
        predecessor.revision =
            predecessor
                .revision
                .checked_add(1)
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "attempt revision exhausted",
                ))?;
        predecessor.state = ProviderAttemptStateV1::Retired;
    }
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition revision exhausted",
            ))?;
    acquisition.current_attempt_digest = attempt.attempt_digest;
    let acquisition_bytes = encode_acquisition(&acquisition);
    release.revision =
        release
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "release revision exhausted",
            ))?;
    release.attempt_digest = attempt.attempt_digest;
    release.acquisition_record_digest = record_digest(&acquisition_bytes)?;
    let effect_plan = ReleasePlanV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        session_binding: effect_attempt.session_binding,
        attempt_digest: effect_attempt.attempt_digest,
        acquisition_id: acquisition.acquisition_id,
        effect_id: release.effect_id,
        lease_id: release.lease_id,
        lease_digest: release.lease_digest,
        backend_id: release.backend_id,
        acquired_evidence: crate::backend::acquired_evidence(&acquisition)?,
    };
    if effect_plan.lineage_digest() != release.backend_lineage_digest
        || !effect_plan.matches_effect_release(&acquisition, &release)
    {
        return Err(ProviderLedgerError::Corrupt("Release effect lineage"));
    }
    let mut records = vec![
        (attempt_key(&attempt_key_value), encode_attempt(&attempt)),
        (
            session_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
            ),
            encode_session(&session),
        ),
        (
            session_history_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
                session.session_binding,
            ),
            encode_session_history(&session),
        ),
        (
            acquisition_key(&AcquisitionKeyV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                acquisition_id: acquisition.acquisition_id,
            }),
            acquisition_bytes,
        ),
        (release_key(&release_key_value), encode_release(&release)),
    ];
    if predecessor.state == ProviderAttemptStateV1::Retired {
        records.push((attempt_key(&predecessor_key), encode_attempt(&predecessor)));
    }
    let reservation_digest = commit_records(ledger, b"reserve-release-continuation", records)?;
    let journal_snapshot = ledger.journal.snapshot()?;
    let response_sequence = session.next_response_sequence;
    let completion_session_binding = session.session_binding;
    let holder_id = acquisition.holder.authority_id();
    ledger
        .recovered
        .attempts
        .insert(attempt_key_value.clone(), attempt.clone());
    ledger
        .recovered
        .attempts
        .insert(predecessor_key, predecessor);
    ledger.recovered.acquisitions.insert(
        AcquisitionKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id,
            acquisition_id: acquisition.acquisition_id,
        },
        acquisition,
    );
    ledger.recovered.releases.insert(release_key_value, release);
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
        &attempt_key_value,
        &attempt,
        response_sequence,
    )?;
    ledger.refresh_recovery_work();
    let completion_capacity = preflight_completion_capacity(
        &ledger.journal,
        RELEASE_COMPLETE_PURPOSE,
        reservation_digest,
        MAXIMUM_RELEASE_COMPLETION_BYTES,
    )?;
    Ok(ProviderAdmissionDispositionV1::Release(
        DurableReleaseEffectPermitV1 {
            plan: effect_plan,
            completion_session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot,
            completion_capacity,
            signing_authorization,
        },
    ))
}

pub(crate) fn complete_release(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableReleaseEffectPermitV1,
    observed: ObservedBackendReleaseV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<(DurableProviderReplyV1, DurableReleaseTombstoneV1), ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    let acquisition_key_value = ledger
        .recovered
        .acquisitions
        .keys()
        .find(|key| key.acquisition_id == permit.plan.acquisition_id)
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown release permit",
        ))?;
    let mut acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing releasing acquisition",
        ))?;
    let acquired_evidence = acquisition
        .backend_evidence
        .as_ref()
        .ok_or(ProviderLedgerError::Corrupt("missing acquired evidence"))?;
    let release_key_value = ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    };
    let mut release = ledger
        .recovered
        .releases
        .get(&release_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release intent"))?;
    if acquisition.state != ProviderAcquisitionStateV1::Releasing
        || permit.reservation_digest.as_bytes() == &[0; 32]
        || release.state != ProviderReleaseStateV1::Intent
        || !permit.plan.matches_effect_release(&acquisition, &release)
        || observed.backend_id != permit.plan.backend_id
        || observed.lineage_digest != permit.plan.lineage_digest()
        || observed.evidence.state() != BackendEvidenceStateV1::Released
        || observed.evidence.class() != acquired_evidence.class()
        || observed.evidence.backend_authority_id() != acquired_evidence.backend_authority_id()
        || observed.evidence.backend_generation() != acquired_evidence.backend_generation()
        || observed.evidence.backend_digest() != acquired_evidence.backend_digest()
        || observed.evidence.predecessor_observation_generation()?
            != acquired_evidence.observation_generation()
        || observed.evidence.predecessor_observation_digest()?
            != acquired_evidence.observation_digest()
        || observed.released_seconds < 0
    {
        return Err(ProviderLedgerError::BackendConflict);
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
                .is_some_and(|attempt| attempt.attempt_digest == release.attempt_digest)
        })
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release attempt"))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release attempt"))?;
    if observed.released_seconds < attempt.verified_at_seconds
        || observed.released_seconds >= attempt.current_valid_until_seconds
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let session_identity = (
        acquisition.provider.authority_id(),
        acquisition.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing release session"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.session_binding != permit.completion_session_binding
        || attempt.attempt_digest != permit.completion_attempt_digest
        || session.pending_attempt_digest != Some(attempt.attempt_digest)
    {
        return Err(ProviderLedgerError::Corrupt("release pending graph"));
    }
    let receipt = SourceReleaseReceiptV1::new(
        attempt.request_id,
        attempt.typed_request_digest,
        release.lease_id,
        release.lease_digest,
        release.provider.clone(),
        attempt.provider_process_instance,
        release.release_generation,
        observed.released_seconds,
    )?;
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = ProviderAcquisitionStateV1::Released;
    let acquisition_bytes = encode_acquisition(&acquisition);
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
    let mut authority = ledger.recovered.authority.clone();
    authority.revision =
        authority
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "authority revision exhausted",
            ))?;
    authority.inventory_generation = authority.inventory_generation.checked_add(1).ok_or(
        ProviderLedgerError::InvalidTransition("inventory generation exhausted"),
    )?;
    let _derived_records = vec![
        (
            acquisition_key(&acquisition_key_value),
            Some(acquisition_bytes),
        ),
        (
            authority_key(authority.provider.authority_id()),
            Some(encode_authority(&authority)),
        ),
        (
            session_key(session_identity.0, session_identity.1),
            Some(encode_session(&session)),
        ),
    ];
    let committed_session_binding = session.session_binding;
    let observation_digest = observed.evidence.observation_digest();
    let release_patch = aos_sandbox_source_provider_ledger::ReleaseCompletionPatchV1::new(
        release_key(&release_key_value),
        observed.evidence.encode(),
        observation_digest,
        observed.released_seconds,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let tombstones = ledger
        .configuration
        .limits()
        .maximum_inventory_tombstones_per_holder();
    let plan = aos_sandbox_source_provider_ledger::ReleaseCompletionPlanV1::new(
        attempt_key(&attempt_key_value),
        release_patch,
        tombstones,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_release_completion(plan, receipt)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    confirm_current_after_commit(ledger)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok((
        DurableProviderReplyV1 {
            response: Vec::new(),
            source_root: None,
            durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed_outcome),
        },
        DurableReleaseTombstoneV1 {
            acquisition_id: acquisition.acquisition_id,
            lease_id: permit.plan.lease_id,
            release_generation: ledger.recovered.authority.last_release_generation,
        },
    ))
}

pub(crate) fn derive_release_effect_id(
    acquisition_id: ObjectDigest,
    attempt_digest: ObjectDigest,
    release_generation: u64,
) -> Result<[u8; 16], ProviderLedgerError> {
    aos_sandbox_source_provider_ledger::identity::release_effect_id_v1(
        acquisition_id,
        attempt_digest,
        release_generation,
    )
    .ok_or(ProviderLedgerError::Corrupt("zero release effect ID"))
}
