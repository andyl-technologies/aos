//! Fresh-session bridges for retained recovery lineages.
//!
//! A bridge is derived only after observation of current durable recovery work.
//! It binds the new authenticated request to the exact old attempt, immutable
//! session, and opaque execution-death, revocation, or never-delivered Pending
//! fence. The bridge grants no backend, journal, signing, descriptor, or send
//! authority by itself.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderDescriptorRole, SourceProviderMethod,
    decode_acquire_request, decode_inventory_request, decode_release_request,
};
use sha2::{Digest as _, Sha256};

use crate::{
    ProviderAdmissionDispositionV1, ProviderLedgerError, ProviderLedgerV1,
    ProviderRecoveryObservationV1, ProviderRecoveryWorkV1, SourceProviderBackendV1,
};

/// Carries one observation-first recovery continuation into a fresh session.
pub struct ProviderRecoveryContinuationV1 {
    work: ProviderRecoveryWorkV1,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    method: SourceProviderMethod,
    old_attempt_digest: ObjectDigest,
    old_session_binding: ObjectDigest,
    journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pending_descriptor_was_never_authorized: bool,
}

pub(crate) struct RecoveryBridgeLinkV1 {
    pub(crate) old_attempt_digest: ObjectDigest,
    pub(crate) old_session_binding: ObjectDigest,
    pub(crate) fence_digest: ObjectDigest,
    pub(crate) fence_class: u8,
    pub(crate) revocation_generation: u64,
    pub(crate) revocation_digest: ObjectDigest,
}

impl core::fmt::Debug for ProviderRecoveryContinuationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderRecoveryContinuationV1([redacted])")
    }
}

impl ProviderLedgerV1<'_> {
    pub(crate) fn restage_recovery_after_failed_continuation(
        &self,
        predecessor: &ProviderRecoveryWorkV1,
        fresh_request: &SignedSourceProviderRequestV1,
    ) -> Result<(ProviderRecoveryWorkV1, bool), ProviderLedgerError> {
        let (_, acquisition_id) = recovery_request_identity(fresh_request)?;
        let mut matching = self.recovered.recovery_work.iter().filter(|work| {
            recovery_work_method(work) == fresh_request.method()
                && recovery_work_matches_acquisition(work, acquisition_id)
        });
        let successor = matching
            .next()
            .cloned()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "failed recovery continuation has no durable successor work",
            ))?;
        if matching.next().is_some() {
            return Err(ProviderLedgerError::Equivocation);
        }
        let canonical = fresh_request.to_canonical_bytes();
        let fresh_was_committed = self
            .recovered
            .attempts
            .values()
            .any(|attempt| attempt.signed_request == canonical);
        if !fresh_was_committed && &successor != predecessor {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok((successor, fresh_was_committed))
    }

    pub(crate) fn validate_recovery_request_candidate(
        &self,
        work: &ProviderRecoveryWorkV1,
        signed_request: &SignedSourceProviderRequestV1,
    ) -> Result<(), ProviderLedgerError> {
        let attempt = recovery_attempt(self, work)?;
        let (session_binding, acquisition_id) = recovery_request_identity(signed_request)?;
        if signed_request.method() != attempt.method
            || signed_request.signer().authority_id() != attempt.holder.authority_id()
            || session_binding == attempt.session_binding
            || !recovery_work_matches_acquisition(work, acquisition_id)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok(())
    }

    /// Observes exact recovery work and binds it to a move-only continuation.
    ///
    /// No live backend observation is retained. A later request must arrive on
    /// a freshly authenticated session and must name the same durable method
    /// and acquisition lineage before it can reserve a new attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when work is stale, observation fails,
    /// its immutable attempt/session lineage is incomplete, or currentness is
    /// lost while the continuation is constructed.
    pub fn observe_recovery_continuation<B: SourceProviderBackendV1>(
        &mut self,
        work: ProviderRecoveryWorkV1,
        backend: &mut B,
    ) -> Result<
        (
            ProviderRecoveryObservationV1,
            ProviderRecoveryContinuationV1,
        ),
        ProviderLedgerError,
    > {
        let observation = self.observe_recovery_work(work.clone(), backend)?;
        let continuation = self.recovery_continuation(work)?;
        Ok((observation, continuation))
    }

    /// Authenticates and durably sequences a fresh-session recovery request.
    ///
    /// The request is admitted through the ordinary owner facade after the
    /// exact predecessor session is fenced. The resulting attempt records all
    /// three bridge commitments; the old session never signs the new result.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for stale work, wrong method or holder,
    /// same-session reuse, missing predecessor death/revocation, an invalid
    /// never-delivered Pending claim, authentication failure, or reservation
    /// failure.
    pub fn verify_and_admit_recovery_request(
        &mut self,
        continuation: ProviderRecoveryContinuationV1,
        signed_request: &SignedSourceProviderRequestV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
    ) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&continuation.journal_snapshot)?;
        if !self.recovered.recovery_work.contains(&continuation.work)
            || signed_request.method() != continuation.method
            || signed_request.signer().authority_id() != continuation.holder_id
            || self.recovered.authority.provider.authority_id() != continuation.provider_id
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let (new_binding, acquisition_id) = recovery_request_identity(signed_request)?;
        if new_binding == continuation.old_session_binding
            || !recovery_work_matches_acquisition(&continuation.work, acquisition_id)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let old_session = self
            .recovered
            .session_history
            .get(&(
                continuation.provider_id,
                continuation.holder_id,
                continuation.old_session_binding,
            ))
            .ok_or(ProviderLedgerError::Corrupt(
                "recovery bridge predecessor session",
            ))?;
        let installed = self
            .current_sessions
            .get_mut(&continuation.holder_id)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "fresh quarantined recovery session required",
            ))?;
        let current = installed.session.current_projection()?;
        if current.session_binding() != new_binding
            || current.provider().authority_id() != continuation.provider_id
            || current.holder().authority_id() != continuation.holder_id
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let exact_revocation_fence = self
            .configuration
            .exact_session_revocation_fence(old_session)
            .ok();
        let (fence_class, fence_digest) =
            if installed.supersession.as_ref().is_some_and(|evidence| {
                evidence.provider_id() == continuation.provider_id
                    && evidence.holder_id() == continuation.holder_id
                    && evidence.prior_session_binding() == continuation.old_session_binding
                    && evidence.replacement_session_binding() == new_binding
                    && evidence.prior_root_process_instance() == old_session.root_process_instance
            }) {
                (
                    4,
                    recovery_supersession_fence_digest(
                        installed
                            .supersession
                            .as_ref()
                            .ok_or(ProviderLedgerError::RuntimePoisoned)?,
                    ),
                )
            } else if installed
                .recovered_execution_death
                .as_ref()
                .is_some_and(|death| {
                    death.matches(
                        old_session.boot_id,
                        old_session.provider_process_id,
                        old_session.provider_start_time_ticks,
                        old_session.provider_process_instance,
                    )
                })
            {
                (
                    1,
                    recovery_fence_digest(
                        b"execution-death",
                        old_session,
                        new_binding,
                        self.recovered.authority.revocation_generation,
                        self.recovered.authority.revocation_digest,
                    ),
                )
            } else if let Some(fence) = exact_revocation_fence {
                (
                    2,
                    recovery_revocation_fence_digest(
                        fence.consume_for(old_session)?,
                        old_session,
                        new_binding,
                    ),
                )
            } else if continuation.pending_descriptor_was_never_authorized {
                (
                    3,
                    recovery_fence_digest(
                        b"pending-descriptor-not-authorized",
                        old_session,
                        new_binding,
                        self.recovered.authority.revocation_generation,
                        self.recovered.authority.revocation_digest,
                    ),
                )
            } else {
                return Err(ProviderLedgerError::InvalidTransition(
                    "recovery predecessor execution is not fenced",
                ));
            };
        self.pending_recovery_bridge = Some(RecoveryBridgeLinkV1 {
            old_attempt_digest: continuation.old_attempt_digest,
            old_session_binding: continuation.old_session_binding,
            fence_digest,
            fence_class,
            revocation_generation: self.recovered.authority.revocation_generation,
            revocation_digest: self.recovered.authority.revocation_digest,
        });
        let result = self.verify_and_admit_request(signed_request, descriptor_roles);
        self.pending_recovery_bridge = None;
        result
    }

    fn recovery_continuation(
        &self,
        work: ProviderRecoveryWorkV1,
    ) -> Result<ProviderRecoveryContinuationV1, ProviderLedgerError> {
        self.ensure_open()?;
        if !self.recovered.recovery_work.contains(&work) {
            return Err(ProviderLedgerError::InvalidTransition(
                "stale recovery work",
            ));
        }
        let attempt = recovery_attempt(self, &work)?;
        let pending_descriptor_was_never_authorized = self
            .recovered
            .acquisitions
            .values()
            .find(|acquisition| acquisition.current_attempt_digest == attempt.attempt_digest)
            .is_some_and(|acquisition| {
                acquisition.state == crate::ProviderAcquisitionStateV1::Pending
                    && attempt.descriptor_commitment
                        == aos_sandbox_source_provider_protocol::empty_descriptor_set_commitment_v1(
                        )
            });
        Ok(ProviderRecoveryContinuationV1 {
            work,
            provider_id: attempt.provider.authority_id(),
            holder_id: attempt.holder.authority_id(),
            method: attempt.method,
            old_attempt_digest: attempt.attempt_digest,
            old_session_binding: attempt.session_binding,
            journal_snapshot: self.journal.snapshot()?,
            pending_descriptor_was_never_authorized,
        })
    }
}

fn recovery_attempt<'ledger>(
    ledger: &'ledger ProviderLedgerV1<'_>,
    work: &ProviderRecoveryWorkV1,
) -> Result<&'ledger crate::model::AttemptRecordV1, ProviderLedgerError> {
    let digest = match work {
        ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, .. }
        | ProviderRecoveryWorkV1::ObservePending { acquisition_id, .. }
        | ProviderRecoveryWorkV1::ReopenActive { acquisition_id, .. } => ledger
            .recovered
            .acquisitions
            .values()
            .find(|value| value.acquisition_id == *acquisition_id)
            .map(|value| value.current_attempt_digest),
        ProviderRecoveryWorkV1::ObserveAcquireRebind { attempt_digest, .. }
        | ProviderRecoveryWorkV1::ObserveInventoryReservation { attempt_digest } => {
            Some(*attempt_digest)
        }
        ProviderRecoveryWorkV1::ObserveReleasing { acquisition_id, .. } => ledger
            .recovered
            .releases
            .values()
            .find(|value| value.acquisition_id == *acquisition_id)
            .map(|value| value.effect_attempt_digest),
    }
    .ok_or(ProviderLedgerError::Corrupt("recovery bridge attempt link"))?;
    ledger
        .recovered
        .attempts
        .values()
        .find(|attempt| attempt.attempt_digest == digest)
        .ok_or(ProviderLedgerError::Corrupt("recovery bridge attempt"))
}

fn recovery_request_identity(
    signed: &SignedSourceProviderRequestV1,
) -> Result<(ObjectDigest, Option<ObjectDigest>), ProviderLedgerError> {
    match signed.method() {
        SourceProviderMethod::Acquire => {
            let value = decode_acquire_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            Ok((value.session_binding(), Some(value.acquisition_id())))
        }
        SourceProviderMethod::Release => {
            let value = decode_release_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            Ok((value.session_binding(), Some(value.acquisition_id())))
        }
        SourceProviderMethod::Inventory => {
            let value = decode_inventory_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            Ok((value.session_binding(), None))
        }
        SourceProviderMethod::Hello => Err(ProviderLedgerError::Equivocation),
    }
}

fn recovery_work_matches_acquisition(
    work: &ProviderRecoveryWorkV1,
    request_acquisition_id: Option<ObjectDigest>,
) -> bool {
    match work {
        ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, .. }
        | ProviderRecoveryWorkV1::ObserveAcquireRebind { acquisition_id, .. }
        | ProviderRecoveryWorkV1::ObservePending { acquisition_id, .. }
        | ProviderRecoveryWorkV1::ObserveReleasing { acquisition_id, .. }
        | ProviderRecoveryWorkV1::ReopenActive { acquisition_id, .. } => {
            request_acquisition_id == Some(*acquisition_id)
        }
        ProviderRecoveryWorkV1::ObserveInventoryReservation { .. } => {
            request_acquisition_id.is_none()
        }
    }
}

fn recovery_supersession_fence_digest(
    evidence: &aos_sandbox_source_provider_security::ProviderSessionSupersessionEvidenceV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.session-supersession.v1\0");
    hasher.update(evidence.provider_id());
    hasher.update(evidence.holder_id());
    hasher.update(evidence.prior_session_binding().as_bytes());
    hasher.update(evidence.replacement_session_binding().as_bytes());
    hasher.update(evidence.prior_root_process_instance());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn recovery_work_method(work: &ProviderRecoveryWorkV1) -> SourceProviderMethod {
    match work {
        ProviderRecoveryWorkV1::ObserveApplying { .. }
        | ProviderRecoveryWorkV1::ObserveAcquireRebind { .. }
        | ProviderRecoveryWorkV1::ObservePending { .. }
        | ProviderRecoveryWorkV1::ReopenActive { .. } => SourceProviderMethod::Acquire,
        ProviderRecoveryWorkV1::ObserveReleasing { .. } => SourceProviderMethod::Release,
        ProviderRecoveryWorkV1::ObserveInventoryReservation { .. } => {
            SourceProviderMethod::Inventory
        }
    }
}

pub(crate) fn recovery_fence_digest(
    class: &[u8],
    old: &crate::model::HolderSessionHeadRecordV1,
    new_binding: ObjectDigest,
    current_revocation_generation: u64,
    current_revocation_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.recovery-continuation-fence.v1\0");
    hasher.update((class.len() as u32).to_be_bytes());
    hasher.update(class);
    hasher.update(old.provider.authority_id());
    hasher.update(old.holder.authority_id());
    hasher.update(old.session_binding.as_bytes());
    hasher.update(new_binding.as_bytes());
    hasher.update(old.provider_execution_commitment.as_bytes());
    hasher.update(old.revocation_generation.to_be_bytes());
    hasher.update(old.revocation_digest.as_bytes());
    hasher.update(current_revocation_generation.to_be_bytes());
    hasher.update(current_revocation_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn recovery_revocation_fence_digest(
    exact_fence: ObjectDigest,
    old: &crate::model::HolderSessionHeadRecordV1,
    new_binding: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.recovery-exact-revocation-fence.v1\0");
    hasher.update(exact_fence.as_bytes());
    hasher.update(old.session_binding.as_bytes());
    hasher.update(new_binding.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
