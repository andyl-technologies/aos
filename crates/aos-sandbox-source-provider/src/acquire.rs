//! Acquire reservation, backend execution boundary, and durable completion.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceResponseV1, SignedSourceExportLeaseV1, SourceExportLeaseV1,
    SourceProviderDescriptorRole, SourceProviderMethod, SourceProviderReceiptV1,
    SourceProviderResponseStatusV1, SourceProviderStatus, SourceRootObservationV1,
    VerifiedProviderAcquireRequestV1, VerifiedProviderRequestSequenceV1, digest_acquire_request,
    digest_provider_proof, digest_signed_export_lease, empty_descriptor_set_commitment_v1,
    encode_acquire_response, provider_resource_commitment_v1, response_result_digest_v1,
    source_root_descriptor_commitment_v1,
};
use aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1;

use crate::NormalizedAcquisitionIntentV1;
use crate::ProviderLedgerError;
use crate::backend::{
    AcquireObservationV1, BackendEvidenceStateV1, DurableAcquireEffectPermitV1,
    DurableProviderReplyV1, ObservedBackendAcquisitionV1, ReopenedSourceRootV1,
    SourceProviderBackendV1,
};
use crate::format::{
    acquisition_key, attempt_key, authority_key, encode_acquisition, encode_attempt,
    encode_authority, encode_session, encode_session_history, session_history_key, session_key,
};
use crate::inventory::global_inventory_state_digest;
use crate::ledger::artifact::response_artifact_digest;
use crate::limits::MAXIMUM_ACQUIRE_COMPLETION_BYTES;
use crate::model::{
    AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, LeaseLineageV1,
    ProviderAcquisitionStateV1, ProviderAttemptStateV1, ProviderAuthorityStateV1,
};
use crate::state::ProviderLedgerV1;
use crate::transaction::{
    authorize_current_reservation, classify_attempt, commit_records, confirm_current_after_commit,
    confirm_current_session_after_commit, preflight_completion_capacity, prepare_session,
    reserve_session, reserved_attempt, validate_projection, validate_session_capacity,
};
use crate::{DurableAcquireRebindPermitV1, DurableAcquireReplayV1, ProviderAdmissionDispositionV1};

#[path = "acquire/completion.rs"]
mod completion;
#[path = "acquire/reservation.rs"]
mod reservation;
#[path = "acquire/validation.rs"]
mod validation;

pub(crate) use completion::complete_acquire;
pub(crate) use reservation::reserve_acquire;
pub(crate) use validation::{
    derive_acquire_effect_id, derive_backend_plan_id, derive_lease_id, validate_backend_selection,
};
use validation::{enforce_acquire_limits, normalized_intent};

const ACQUIRE_RESERVE_PURPOSE: &[u8] = b"reserve-acquire";
const ACQUIRE_COMPLETE_PURPOSE: &[u8] = b"complete-acquire";

enum RebindSourceV1 {
    Active(ReopenedSourceRootV1),
    Pending(ObservedBackendAcquisitionV1),
}

impl RebindSourceV1 {
    fn source_root(&self) -> crate::SourceRootIdentityV1 {
        match self {
            Self::Active(value) => value.source_root,
            Self::Pending(value) => value.source_root,
        }
    }

    fn descriptor_observation(&self) -> SourceRootObservationV1 {
        match self {
            Self::Active(value) => value.descriptor_observation.clone(),
            Self::Pending(value) => value.descriptor_observation.clone(),
        }
    }

    fn observed_seconds(&self) -> i64 {
        match self {
            Self::Active(value) => value.observed_seconds,
            Self::Pending(value) => value.observed_seconds,
        }
    }

    fn revalidate_physical(&self) -> Result<(), ProviderLedgerError> {
        match self {
            Self::Active(value) => value.revalidate_physical(),
            Self::Pending(value) => value.revalidate_physical(),
        }
    }

    fn into_physical_root(self) -> crate::ProviderPhysicalSourceRootV1 {
        match self {
            Self::Active(value) => value.into_physical_root(),
            Self::Pending(value) => value.into_physical_root(),
        }
    }
}

fn execute_recovered_acquire_effect<B: SourceProviderBackendV1>(
    permit: DurableAcquireRebindPermitV1,
    effect_plan: crate::AcquirePlanV1,
    backend: &mut B,
    expected_acquisition_id: ObjectDigest,
) -> Result<(DurableAcquireRebindPermitV1, ObservedBackendAcquisitionV1), ProviderLedgerError> {
    let DurableAcquireRebindPermitV1 {
        holder_id,
        session_binding,
        acquisition_id,
        attempt_digest,
        pending_claim,
        reservation_digest,
        journal_snapshot,
        completion_capacity,
        signing_authorization,
    } = permit;
    if acquisition_id != expected_acquisition_id
        || effect_plan.acquisition_id != expected_acquisition_id
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let effect_permit = DurableAcquireEffectPermitV1 {
        plan: effect_plan,
        completion_session_binding: session_binding,
        completion_attempt_digest: attempt_digest,
        reservation_digest,
        journal_snapshot,
        completion_capacity,
        signing_authorization,
    };
    let (effect_permit, observed) = backend.execute_acquire(effect_permit)?;
    let DurableAcquireEffectPermitV1 {
        plan: _,
        completion_session_binding: _,
        completion_attempt_digest: _,
        reservation_digest,
        journal_snapshot,
        completion_capacity,
        signing_authorization,
    } = effect_permit;
    Ok((
        DurableAcquireRebindPermitV1 {
            holder_id,
            session_binding,
            acquisition_id,
            attempt_digest,
            pending_claim,
            reservation_digest,
            journal_snapshot,
            completion_capacity,
            signing_authorization,
        },
        observed,
    ))
}

impl ProviderLedgerV1<'_> {
    /// Rebinds one exact active acquisition to a superseding live session.
    ///
    /// The backend is reopened without recreating effect authority. Completion
    /// issues a new lease for the rebind request and durably supersedes the
    /// prior lease while its exact signed bytes remain in historical attempts.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale journal state, backend
    /// mismatch, missing current custody, signing failure, or commit failure.
    pub fn execute_acquire_rebind<B: SourceProviderBackendV1>(
        &mut self,
        permit: DurableAcquireRebindPermitV1,
        backend: &mut B,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|record| {
                record.acquisition_id == permit.acquisition_id
                    && matches!(
                        record.state,
                        ProviderAcquisitionStateV1::Applying
                            | ProviderAcquisitionStateV1::Active
                            | ProviderAcquisitionStateV1::Pending
                    )
            })
            .cloned()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "stale acquisition rebind",
            ))?;
        if permit.pending_claim
            != matches!(
                acquisition.state,
                ProviderAcquisitionStateV1::Applying | ProviderAcquisitionStateV1::Pending
            )
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let (permit, source) = if permit.pending_claim {
            let prior_attempt = self
                .recovered
                .attempts
                .values()
                .find(|attempt| attempt.attempt_digest == acquisition.effect_attempt_digest)
                .ok_or(ProviderLedgerError::Corrupt("Pending rebind predecessor"))?;
            let plan = crate::AcquirePlanV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                session_binding: prior_attempt.session_binding,
                attempt_digest: prior_attempt.attempt_digest,
                acquisition_id: acquisition.acquisition_id,
                effect_id: acquisition.effect_id,
                normalized_intent_digest: acquisition.normalized_intent.digest(),
                backend_id: acquisition.backend_id,
            };
            let observation = backend.observe_acquire(&plan);
            match self.poison_backend_result(permit.acquisition_id, observation)? {
                AcquireObservationV1::Applied(observed) => {
                    (permit, RebindSourceV1::Pending(observed))
                }
                AcquireObservationV1::NotApplied => {
                    let executed = execute_recovered_acquire_effect(
                        permit,
                        plan,
                        backend,
                        acquisition.acquisition_id,
                    );
                    let (permit, observed) =
                        self.poison_backend_result(acquisition.acquisition_id, executed)?;
                    (permit, RebindSourceV1::Pending(observed))
                }
                AcquireObservationV1::Conflict => {
                    self.record_backend_conflict(permit.acquisition_id)?;
                    return Err(ProviderLedgerError::BackendConflict);
                }
            }
        } else {
            let snapshot = active_snapshot(&acquisition)?;
            let observation = backend.reopen_active(&snapshot);
            match self.poison_backend_result(permit.acquisition_id, observation)? {
                crate::ReopenObservationV1::Reopened(observation)
                    if observation.acquisition_id == snapshot.acquisition_id
                        && observation.source_root == snapshot.source_root =>
                {
                    (permit, RebindSourceV1::Active(observation))
                }
                crate::ReopenObservationV1::Unavailable => {
                    return Err(ProviderLedgerError::Unavailable);
                }
                crate::ReopenObservationV1::Reopened(_) | crate::ReopenObservationV1::Conflict => {
                    self.record_backend_conflict(permit.acquisition_id)?;
                    return Err(ProviderLedgerError::BackendConflict);
                }
            }
        };
        let mut installed = self.current_sessions.remove(&permit.holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("missing current rebind session"),
        )?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != permit.session_binding {
            self.current_sessions.insert(permit.holder_id, installed);
            return Err(ProviderLedgerError::Equivocation);
        }
        let holder_id = permit.holder_id;
        let acquisition_id = permit.acquisition_id;
        let result =
            complete_acquire_rebind(self, permit, acquisition, source, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result
    }

    /// Observes, executes when still unapplied, and durably completes one Acquire.
    ///
    /// Backend execution receives the move-only permit only after its reservation
    /// transaction has synchronized. A contradictory observation faults closed.
    /// Response bytes and the live source descriptor become available only after
    /// the completion transaction synchronizes.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for backend conflict, invalid retained
    /// state, signing or model failure, limits, or completion sync failure.
    pub fn execute_acquire<B: SourceProviderBackendV1>(
        &mut self,
        permit: DurableAcquireEffectPermitV1,
        backend: &mut B,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let acquisition_id = permit.plan.acquisition_id;
        let observation = backend.observe_acquire(&permit.plan);
        let (permit, observed) = match self.poison_backend_result(acquisition_id, observation)? {
            AcquireObservationV1::NotApplied => {
                let executed = backend.execute_acquire(permit);
                self.poison_backend_result(acquisition_id, executed)?
            }
            AcquireObservationV1::Applied(observed) => (permit, observed),
            AcquireObservationV1::Conflict => {
                self.record_backend_conflict(permit.plan.acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
        };
        let holder_id = permit.plan.holder_id;
        let result = self.with_current_completion_session(
            holder_id,
            permit.completion_session_binding,
            |ledger, custody| complete_acquire(ledger, permit, observed, custody),
        );
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result
    }

    /// Durably completes a reserved Acquire without a descriptor-bearing result.
    ///
    /// This consumes the reservation permit without invoking backend execution.
    /// `Pending` is valid only when the provider already retains a durable
    /// unresolved operation; `Rejected` and `Unavailable` fault the acquisition
    /// identity closed so it cannot be silently repurposed.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for `Complete`, a mismatched permit,
    /// invalid state, signing or model failure, limits, or sync failure.
    pub fn complete_acquire_disposition(
        &mut self,
        permit: DurableAcquireEffectPermitV1,
        status: SourceProviderStatus,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        permit.completion_capacity.validate(&self.journal)?;
        let holder_id = permit.plan.holder_id;
        self.with_current_completion_session(
            holder_id,
            permit.completion_session_binding,
            |ledger, custody| complete_acquire_disposition(ledger, permit, status, custody),
        )
    }

    /// Freshly reopens the exact active source before returning a cached Acquire response.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the replay is stale, the backend
    /// cannot reopen the exact retained source, or observation conflicts.
    pub fn execute_acquire_replay<B: SourceProviderBackendV1>(
        &mut self,
        replay: DurableAcquireReplayV1,
        backend: &mut B,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&replay.journal_snapshot)?;
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|record| {
                record.acquisition_id == replay.acquisition_id
                    && record.state == ProviderAcquisitionStateV1::Active
            })
            .ok_or(ProviderLedgerError::InvalidTransition(
                "stale Acquire replay",
            ))?
            .clone();
        let snapshot = crate::ActiveAcquisitionSnapshotV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
            effect_id: acquisition.effect_id,
            backend_lineage_digest: acquisition.backend_lineage_digest,
            lease_id: acquisition
                .lease_id
                .ok_or(ProviderLedgerError::Corrupt("active replay lease ID"))?,
            lease_digest: acquisition
                .lease_digest
                .ok_or(ProviderLedgerError::Corrupt("active replay lease digest"))?,
            backend_id: acquisition.backend_id,
            evidence: acquisition
                .backend_evidence
                .clone()
                .ok_or(ProviderLedgerError::Corrupt("active replay evidence"))?,
            reopen_identity: acquisition
                .reopen_identity
                .clone()
                .ok_or(ProviderLedgerError::Corrupt("active replay identity"))?,
            source_root: acquisition
                .source_root
                .ok_or(ProviderLedgerError::Corrupt("active replay source root"))?,
        };
        let observation = backend.reopen_active(&snapshot);
        let reopened = match self.poison_backend_result(replay.acquisition_id, observation)? {
            crate::ReopenObservationV1::Reopened(reopened) => reopened,
            crate::ReopenObservationV1::Unavailable => {
                return Err(ProviderLedgerError::Unavailable);
            }
            crate::ReopenObservationV1::Conflict => {
                self.record_backend_conflict(replay.acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
        };
        if reopened.acquisition_id != replay.acquisition_id
            || reopened.source_root != snapshot.source_root
            || reopened.backend_id != snapshot.backend_id
            || reopened.backend_evidence != snapshot.evidence
            || reopened.reopen_identity != snapshot.reopen_identity
        {
            self.record_backend_conflict(replay.acquisition_id)?;
            return Err(ProviderLedgerError::BackendConflict);
        }
        self.poison_backend_result(replay.acquisition_id, reopened.revalidate_physical())?;
        self.journal
            .validate_source_provider_authority_snapshot(&replay.journal_snapshot)?;
        Ok(DurableProviderReplyV1 {
            response: replay.response,
            source_root: Some(reopened.into_physical_root()),
            durability: crate::backend::DurableReplyAuthorityV1::RevalidatedReplay {
                snapshot: replay.journal_snapshot,
                attempt_key: replay.attempt_key,
            },
        })
    }
}

fn complete_acquire_disposition(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableAcquireEffectPermitV1,
    status: SourceProviderStatus,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    if status == SourceProviderStatus::Complete {
        return Err(ProviderLedgerError::InvalidTransition(
            "Complete Acquire requires backend acquisition evidence",
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
            .pending_acquisitions
            .contains_key(&permit.plan.acquisition_id)
    {
        return Err(ProviderLedgerError::InvalidTransition(
            "duplicate live Pending observation token",
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
            "unknown acquire permit",
        ))?;
    let mut acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing applying acquisition"))?;
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || !permit.plan.matches_effect_acquisition(&acquisition)
        || permit.reservation_digest.as_bytes() == &[0; 32]
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let attempt_key_value =
        ledger
            .recovered
            .attempts
            .keys()
            .find(|key| {
                ledger.recovered.attempts.get(*key).is_some_and(|attempt| {
                    attempt.attempt_digest == acquisition.current_attempt_digest
                })
            })
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("missing acquire attempt"))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing acquire attempt"))?;
    let session_identity = (
        acquisition.provider.authority_id(),
        acquisition.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing acquire session"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.session_binding != permit.completion_session_binding
        || attempt.attempt_digest != permit.completion_attempt_digest
        || session.pending_attempt_digest != Some(attempt.attempt_digest)
    {
        return Err(ProviderLedgerError::Corrupt("acquire pending graph"));
    }
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = if status == SourceProviderStatus::Pending {
        ProviderAcquisitionStateV1::Pending
    } else {
        ProviderAcquisitionStateV1::Faulted
    };
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
    let _derived_records = vec![
        (
            acquisition_key(&acquisition_key_value),
            Some(encode_acquisition(&acquisition)),
        ),
        (
            session_key(session_identity.0, session_identity.1),
            Some(encode_session(&session)),
        ),
    ];
    let committed_session_binding = session.session_binding;
    let plan = aos_sandbox_source_provider_ledger::AcquireStatusCompletionPlanV1::new(attempt_key(
        &attempt_key_value,
    ))
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_acquire_status_completion(plan, status)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    if let Some((plan, completion_session_binding, completion_attempt_digest)) = pending_plan {
        ledger.pending_acquisitions.insert(
            plan.acquisition_id,
            crate::pending::LivePendingAcquisitionV1 {
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

pub(crate) fn active_snapshot(
    acquisition: &AcquisitionRecordV1,
) -> Result<crate::ActiveAcquisitionSnapshotV1, ProviderLedgerError> {
    Ok(crate::ActiveAcquisitionSnapshotV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
        effect_id: acquisition.effect_id,
        backend_lineage_digest: acquisition.backend_lineage_digest,
        lease_id: acquisition
            .lease_id
            .ok_or(ProviderLedgerError::Corrupt("active lease ID"))?,
        lease_digest: acquisition
            .lease_digest
            .ok_or(ProviderLedgerError::Corrupt("active lease digest"))?,
        backend_id: acquisition.backend_id,
        evidence: acquisition
            .backend_evidence
            .clone()
            .ok_or(ProviderLedgerError::Corrupt("active backend evidence"))?,
        reopen_identity: acquisition
            .reopen_identity
            .clone()
            .ok_or(ProviderLedgerError::Corrupt("active reopen identity"))?,
        source_root: acquisition
            .source_root
            .ok_or(ProviderLedgerError::Corrupt("active source root"))?,
    })
}

fn complete_acquire_rebind(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: DurableAcquireRebindPermitV1,
    mut acquisition: AcquisitionRecordV1,
    source: RebindSourceV1,
    custody: &mut CurrentProviderIngressSessionV1,
) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
    let acquisition_key_value = AcquisitionKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    };
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
        .ok_or(ProviderLedgerError::Corrupt("missing rebind attempt"))?;
    let mut attempt = ledger
        .recovered
        .attempts
        .get(&attempt_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing rebind attempt"))?;
    let session_identity = (
        acquisition.provider.authority_id(),
        acquisition.holder.authority_id(),
    );
    let mut session = ledger
        .recovered
        .sessions
        .get(&session_identity)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing rebind session"))?;
    let source_root = source.source_root();
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.session_binding != permit.session_binding
        || session.pending_attempt_digest != Some(attempt.attempt_digest)
        || permit.pending_claim
            != matches!(
                acquisition.state,
                ProviderAcquisitionStateV1::Applying | ProviderAcquisitionStateV1::Pending
            )
    {
        return Err(ProviderLedgerError::Corrupt("rebind graph"));
    }
    let (resource, proof, proof_digest, resource_commitment) = match &source {
        RebindSourceV1::Active(reopened) => {
            let signed_prior_lease =
                SignedSourceExportLeaseV1::from_canonical_bytes(&acquisition.signed_lease)
                    .map_err(|_| ProviderLedgerError::Corrupt("active rebind lease"))?;
            let prior_lease_digest = acquisition
                .lease_digest
                .ok_or(ProviderLedgerError::Corrupt("active rebind lease digest"))?;
            if signed_prior_lease.subject().provider() != &acquisition.provider
                || reopened.acquisition_id != acquisition.acquisition_id
                || reopened.backend_id != acquisition.backend_id
                || acquisition.backend_evidence.as_ref() != Some(&reopened.backend_evidence)
                || acquisition.reopen_identity.as_ref() != Some(&reopened.reopen_identity)
                || Some(source_root) != acquisition.source_root
                || digest_signed_export_lease(&signed_prior_lease) != prior_lease_digest
            {
                return Err(ProviderLedgerError::Corrupt("active rebind lineage"));
            }
            (
                signed_prior_lease.subject().resource().clone(),
                signed_prior_lease.subject().proof().clone(),
                acquisition.proof_digest,
                acquisition.resource_commitment,
            )
        }
        RebindSourceV1::Pending(observed) => {
            let prior_attempt = ledger
                .recovered
                .attempts
                .values()
                .find(|candidate| candidate.attempt_digest == acquisition.effect_attempt_digest)
                .ok_or(ProviderLedgerError::Corrupt("Pending rebind predecessor"))?;
            let prior_plan = crate::AcquirePlanV1 {
                provider_id: acquisition.provider.authority_id(),
                holder_id: acquisition.holder.authority_id(),
                session_binding: prior_attempt.session_binding,
                attempt_digest: prior_attempt.attempt_digest,
                acquisition_id: acquisition.acquisition_id,
                effect_id: acquisition.effect_id,
                normalized_intent_digest: acquisition.normalized_intent.digest(),
                backend_id: acquisition.backend_id,
            };
            if observed.lineage_digest != prior_plan.lineage_digest()
                || observed.backend_id != acquisition.backend_id
                || acquisition.lease_id.is_some()
                || !acquisition.signed_lease.is_empty()
            {
                return Err(ProviderLedgerError::BackendConflict);
            }
            validate_backend_selection(ledger, &acquisition, &attempt, observed)?;
            let proof_digest = digest_provider_proof(&observed.proof);
            (
                observed.resource.clone(),
                observed.proof.clone(),
                proof_digest,
                provider_resource_commitment_v1(&observed.resource, proof_digest),
            )
        }
    };
    source.revalidate_physical()?;
    let lease_generation = ledger
        .recovered
        .authority
        .last_lease_issue_generation
        .checked_add(1)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "lease generation exhausted",
        ))?;
    let lease_id = derive_lease_id(
        acquisition.acquisition_id,
        lease_generation,
        acquisition.backend_id,
    )?;
    let issued_seconds = source.observed_seconds();
    let requested_expiry = issued_seconds
        .checked_add(acquisition.normalized_intent.requested_lease_seconds() as i64)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "rebind lease time overflow",
        ))?;
    let expires_seconds = requested_expiry
        .min(attempt.deadline_seconds)
        .min(attempt.current_valid_until_seconds);
    if expires_seconds <= issued_seconds {
        return Err(ProviderLedgerError::InvalidTransition(
            "rebind lease has no valid horizon",
        ));
    }
    let lease = SourceExportLeaseV1::new(
        lease_id,
        attempt.request_id,
        attempt.typed_request_digest,
        acquisition.holder.authority_id(),
        acquisition.holder.authority_generation(),
        acquisition.holder.authority_digest(),
        acquisition.provider.clone(),
        resource,
        proof,
        acquisition.normalized_intent.binding_digest(),
        issued_seconds,
        expires_seconds,
        acquisition.normalized_intent.holder_revocation_digest(),
    )?;
    source.revalidate_physical()?;
    let descriptor_observation = source.descriptor_observation();
    let descriptor_commitment = source_root_descriptor_commitment_v1(&descriptor_observation);
    if acquisition.lease_history.len() >= crate::limits::MAXIMUM_LEASE_HISTORY_PER_ACQUISITION {
        return Err(ProviderLedgerError::LimitExceeded(
            "acquisition lease history",
        ));
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
    authority.last_lease_issue_generation = lease_generation;
    let _derived_records = vec![
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
    let (backend_evidence, reopen_identity) = match &source {
        RebindSourceV1::Active(_) => (None, None),
        RebindSourceV1::Pending(observed) => (
            Some(observed.evidence.encode()),
            Some(observed.reopen_identity.encode().to_vec()),
        ),
    };
    let source_root_identity = aos_sandbox_source_provider_ledger::SourceRootIdentityV1::new(
        source_root.kernel_boot_id,
        source_root.device,
        source_root.inode,
        source_root.unique_mount_id,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let acquire_patch = aos_sandbox_source_provider_ledger::AcquireCompletionPatchV1::new(
        acquisition_key(&acquisition_key_value),
        attempt.attempt_digest,
        lease_generation,
        proof_digest,
        resource_commitment,
        backend_evidence,
        reopen_identity,
        source_root_identity,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let tombstones = ledger
        .configuration
        .limits()
        .maximum_inventory_tombstones_per_holder();
    let plan = aos_sandbox_source_provider_ledger::AcquireCompletionPlanV1::rebind(
        attempt_key(&attempt_key_value),
        acquire_patch,
        tombstones,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let receipt_facts = aos_sandbox_source_provider_security::AcquireReceiptFactsV1::new(
        acquisition.acquisition_id,
        source_root.kernel_boot_id,
        source_root.device,
        source_root.inode,
        source_root.unique_mount_id,
        proof_digest,
        descriptor_commitment,
    )?;
    let builder = custody
        .provider_outcome_facade(&ledger.journal, &permit.signing_authorization)?
        .prepare_acquire_completion(plan, lease, receipt_facts)?;
    let committed_outcome = crate::transaction::commit_sealed_completion(ledger, custody, builder)?;
    let committed_snapshot = ledger.journal.snapshot()?;
    source.revalidate_physical()?;
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&committed_snapshot)?;
    confirm_current_session_after_commit(custody, committed_session_binding)?;
    Ok(DurableProviderReplyV1 {
        response: Vec::new(),
        source_root: Some(source.into_physical_root()),
        durability: crate::backend::DurableReplyAuthorityV1::Fresh(committed_outcome),
    })
}
