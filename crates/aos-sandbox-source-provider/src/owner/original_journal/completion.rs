//! SAME-original challenge spend and canonical six-row Complete readback.
//!
//! This driver ends at a resident phase-4 checkpoint. It retains the Storage
//! child, both subjects, original mount/observer and one SAME-mount handoff
//! duplicate. It does not sign Provider3, send Complete or SourceRoot, relay,
//! settle, reconstruct a hot owner from replay, or restore a deadline.

use super::*;
use super::producer::{
    OriginalProducerAppendV5 as Append, OriginalProducerClosureGuardV5,
    OriginalProducerErrorV5, owner_transaction_v5,
};
use aos_sandbox::JournalRecord;
use aos_sandbox_source_provider_protocol::{
    SourceExportLeaseV1, SourceProviderProofV1, digest_provider_proof,
    provider_resource_commitment_v1,
    native_held_completion::suffix::NativeHeldCompletionSuffixV1,
};
use aos_sandbox_source_provider_security::{
    OriginalProviderCompletionSignaturesV5, ProviderSourceRootHandoffV1,
};
use crate::backend::{BackendEvidenceClassV1, BackendEvidenceV1, ProviderPhysicalSourceRootV1, ReopenIdentityV1};
use crate::ledger::{
    completion::{AcquireCompletionPatchV1, AcquireCompletionPlanV1, FinalizedCompletionV1},
    format::{acquisition_key, attempt_key, authority_key, decode_record, session_key},
    model::{AcquisitionKeyV1, AttemptKeyV1, DecodedRecordV1},
    native_completion::{NativeAcquireCompletionStateV2, native_completion_key_v2},
    native_held_completion::{SourceNativeHeldStepV1, propose_native_held_transition_v1},
};
use crate::owner::FixedProviderOriginalCompletionProgressV5 as Progress;
use crate::zfs_hold_challenge::{StagedOriginalZfsHoldSpendV5, current_seconds};

mod held;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CompletionStageV5 {
    Headroom,
    CommitSpend,
    PrepareSpent,
    CommitSpent,
    RetainHandoff,
    PrepareLease,
    SignLease,
    SignReceipt,
    SignStatus,
    PrepareComplete,
    CommitComplete,
    CompleteHeld,
    Closed,
}

enum CompletionFailureV5 {
    Boundary(OriginalProducerErrorV5),
    Duplicate,
    Handoff,
    Signatures,
}

/// Contains no admission constructor; only the genuine prepared owner parks it.
pub(super) struct OriginalSourceCompletionV5 {
    stage: CompletionStageV5,
    spend: Option<StagedOriginalZfsHoldSpendV5>,
    duplicate: Option<Result<ProviderPhysicalSourceRootV1, ProviderLedgerError>>,
    handoff: Option<Result<ProviderSourceRootHandoffV1, ProviderLedgerError>>,
    signatures: Option<OriginalProviderCompletionSignaturesV5>,
    phase3: Option<SourceNativeHeldCompletionRecordV1>,
    phase4: Option<SourceNativeHeldCompletionRecordV1>,
    lease: Option<SourceExportLeaseV1>,
    plan: Option<AcquireCompletionPlanV1>,
    finalized: Option<FinalizedCompletionV1>,
    before: Vec<(Vec<u8>, Vec<u8>)>,
    after: Vec<(Vec<u8>, Vec<u8>)>,
    failure: Option<CompletionFailureV5>,
    held: Option<held::OriginalSourceHeldV5>,
}

impl OriginalSourceCompletionV5 {
    fn pending() -> Self {
        Self {
            stage: CompletionStageV5::Headroom,
            spend: None,
            duplicate: None,
            handoff: None,
            signatures: None,
            phase3: None,
            phase4: None,
            lease: None,
            plan: None,
            finalized: None,
            before: Vec::new(),
            after: Vec::new(),
            failure: None,
            held: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        (|| match self.failure.as_ref()? {
            CompletionFailureV5::Boundary(cause) => Some(cause),
            CompletionFailureV5::Duplicate => self.duplicate.as_ref()?.as_ref().err().map(|cause| cause as _),
            CompletionFailureV5::Handoff => self.handoff.as_ref()?.as_ref().err().map(|cause| cause as _),
            CompletionFailureV5::Signatures => self.signatures.as_ref()?.failure(),
        })().or_else(|| self.held.as_ref()?.failure())
    }
}

// Abort before a short original-resource loan can unwind a moved temporary.
// Callee-local pre-return custody and allocator prefixes remain separate gaps.
struct OriginalCompletionCrossingV5;

impl Drop for OriginalCompletionCrossingV5 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Advances only the genuine original pair through resident Complete readback.
    ///
    /// This observation-only path does not expose Complete, Provider3, a
    /// SourceRoot descriptor, a retry, recovery, relay, settlement or send permit.
    #[doc(hidden)]
    pub fn advance_original_native_completion_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Progress {
        if self.original_ingress.producer_closed_v5() {
            return Progress::Closed;
        }
        let mut guard = OriginalProducerClosureGuardV5 {
            owner: self,
            completed: false,
        };
        let _crossing = OriginalCompletionCrossingV5;
        let result = guard.owner.advance_original_completion_inner_v5(publication, rows);
        match result {
            Ok(progress) => {
                guard.completed = progress != Progress::Closed;
                progress
            }
            Err(cause) => {
                if let Ok(completion) = guard.owner.original_completion_mut_v5() {
                    if completion.failure.is_none() {
                        completion.failure = Some(CompletionFailureV5::Boundary(cause));
                    }
                    completion.stage = CompletionStageV5::Closed;
                } else {
                    guard.owner.original_ingress.retain_producer_failure_v5(cause);
                }
                Progress::Closed
            }
        }
    }

    /// Borrows the actual resident first cause without releasing any original.
    #[must_use]
    pub fn original_completion_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original_storage_offer_failure_v5().or_else(|| self.original_completion_v5().ok()?.failure())
    }

    fn original_completion_v5(&self) -> Result<&OriginalSourceCompletionV5, ProviderLedgerError> {
        self.original_source_producer_v5()?.original_completion.as_ref().ok_or(ProviderLedgerError::Unavailable)
    }

    fn original_completion_mut_v5(&mut self) -> Result<&mut OriginalSourceCompletionV5, ProviderLedgerError> {
        self.original_source_producer_mut_v5()?.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn require_original_completion_current_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_offer_current_v5()?;
        let completion = self.original_completion_v5()?;
        if completion.stage == CompletionStageV5::Closed || completion.failure.is_some() {
            return Err(ProviderLedgerError::RuntimePoisoned.into());
        }
        let expiry = completion.lease.as_ref().map(|lease| lease.validity().1);
        self.original_ingress.borrowed_clock_v5()?.revalidate(expiry)?;
        Ok(())
    }

    fn advance_original_completion_inner_v5(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Result<Progress, OriginalProducerErrorV5> {
        if !self.original_source_producer_v5().is_ok_and(|producer| producer.original_completion.is_some()) {
            match self.advance_original_storage_offer_v5(publication, rows) {
                crate::owner::FixedProviderOriginalStorageOfferProgressV5::Pending => return Ok(Progress::Pending),
                crate::owner::FixedProviderOriginalStorageOfferProgressV5::Closed => return Ok(Progress::Closed),
                crate::owner::FixedProviderOriginalStorageOfferProgressV5::StoragePrepared => {}
            }
            if !self.original_offer_v5()?.is_prepared() {
                return Err(ProviderLedgerError::Equivocation.into());
            }
            self.original_source_producer_mut_v5()?.original_completion = Some(OriginalSourceCompletionV5::pending());
        }
        self.require_original_completion_current_v5()?;
        let stage = self.original_completion_v5()?.stage;
        match stage {
            CompletionStageV5::Headroom => {
                self.prepare_original_spend_v5()?;
                self.original_completion_mut_v5()?.stage = CompletionStageV5::CommitSpend;
            }
            CompletionStageV5::CommitSpend => {
                let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
                    return Err(ProviderLedgerError::Unavailable.into());
                };
                let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
                let receipt_expiry = producer.storage_offer.as_ref().ok_or(ProviderLedgerError::Unavailable)?.reply()?.receipt().receipt().validity().1;
                let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
                self.hold_challenges.commit_original_spend_v5(
                    completion.spend.as_mut().ok_or(ProviderLedgerError::Unavailable)?,
                    self.original_ingress.borrowed_clock_v5()?, receipt_expiry,
                )?;
                // The real new challenge prefix is captured only AFTER Spent.
                let history = self.hold_challenges.original_history_v5()?;
                self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.complete_source_original_replay_v5(&history)?;
                completion.stage = CompletionStageV5::PrepareSpent;
            }
            CompletionStageV5::PrepareSpent => {
                self.prepare_original_spent_checkpoint_v5()?;
                self.original_completion_mut_v5()?.stage = CompletionStageV5::CommitSpent;
            }
            CompletionStageV5::CommitSpent => {
                self.append_original_producer_step_v5(Append::ChallengeSpent)?;
                self.require_original_completion_readback_v5(Append::ChallengeSpent)?;
                let completion = self.original_completion_mut_v5()?;
                completion.before.clear();
                completion.after.clear();
                completion.stage = CompletionStageV5::RetainHandoff;
            }
            CompletionStageV5::RetainHandoff => {
                self.retain_original_completion_handoff_v5()?;
                if self.original_completion_v5()?.failure.is_some() {
                    return Ok(Progress::Closed);
                }
                self.original_completion_mut_v5()?.stage = CompletionStageV5::PrepareLease;
            }
            CompletionStageV5::PrepareLease => {
                self.prepare_original_completion_subjects_v5()?;
                self.original_completion_mut_v5()?.stage = CompletionStageV5::SignLease;
            }
            CompletionStageV5::SignLease | CompletionStageV5::SignReceipt | CompletionStageV5::SignStatus => {
                self.sign_original_completion_v5(stage)?;
                if self.original_completion_v5()?.failure.is_some() {
                    return Ok(Progress::Closed);
                }
                self.original_completion_mut_v5()?.stage = match stage {
                    CompletionStageV5::SignLease => CompletionStageV5::SignReceipt,
                    CompletionStageV5::SignReceipt => CompletionStageV5::SignStatus,
                    _ => CompletionStageV5::PrepareComplete,
                };
            }
            CompletionStageV5::PrepareComplete => {
                self.prepare_original_complete_checkpoint_v5()?;
                self.original_completion_mut_v5()?.stage = CompletionStageV5::CommitComplete;
            }
            CompletionStageV5::CommitComplete => {
                self.append_original_producer_step_v5(Append::CompletionCommitted)?;
                self.require_original_completion_readback_v5(Append::CompletionCommitted)?;
                self.original_completion_mut_v5()?.stage = CompletionStageV5::CompleteHeld;
            }
            CompletionStageV5::CompleteHeld => {
                self.require_original_completion_readback_v5(Append::CompletionCommitted)?;
                return Ok(Progress::CompleteCommitted);
            }
            CompletionStageV5::Closed => return Ok(Progress::Closed),
        }
        self.require_original_completion_current_v5()?;
        Ok(if self.original_completion_v5()?.stage == CompletionStageV5::CompleteHeld {
            Progress::CompleteCommitted
        } else {
            Progress::Pending
        })
    }

    fn prepare_original_spend_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_completion_current_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?.request().claims().provider_acquisition().1;
        {
            let challenges = self.hold_challenges.original_history_v5()?;
            let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&challenges)?;
            authority.require_original_completion_headroom_v5(producer.readback(Append::StoragePrepared)?, acquisition)?;
        }
        let expected = producer.staged.as_ref().ok_or(ProviderLedgerError::Unavailable)?.record();
        let receipt = producer.storage_offer.as_ref().ok_or(ProviderLedgerError::Unavailable)?.reply()?.receipt().digest();
        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        self.hold_challenges.stage_original_spend_v5(expected, receipt, &mut completion.spend)?;
        self.require_original_completion_current_v5()?;
        Ok(())
    }

    fn prepare_original_spent_checkpoint_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?.request().claims().provider_acquisition().1;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&history)?;
        let replay = authority.replayed_origins()?;
        let key = native_completion_key_v2(acquisition);
        let previous = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key,
            replay.current_rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone())).ok_or(ProviderLedgerError::Unavailable)?)?;
        if previous.suffix().phase() != 2 { return Err(ProviderLedgerError::Equivocation.into()); }
        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let mut original = previous.original().clone();
        original.revision = original.revision.checked_add(1).ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
        completion.phase3 = Some(SourceNativeHeldCompletionRecordV1::new(original,
            NativeHeldCompletionSuffixV1::new(Role::Provider, 3, previous.suffix().flight(), previous.suffix().prepared().cloned(), previous.suffix().controls().to_vec())?)?);
        let bytes = completion.phase3.as_ref().ok_or(ProviderLedgerError::Unavailable)?.to_canonical_bytes()?;
        let limits = authority.configured_limits();
        storage_offer::retain_projection(&mut completion.before, replay.current_rows(), None, limits)?;
        storage_offer::retain_projection(&mut completion.after, replay.current_rows(), Some((&key, &bytes)), limits)?;
        propose_native_held_transition_v1(
            completion.before.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            completion.after.iter().map(|(key, value)| (key.as_slice(), value.as_slice())), acquisition,
            SourceNativeHeldStepV1::ChallengeSpent,
            completion.spend.as_ref().and_then(StagedOriginalZfsHoldSpendV5::readback),
        )?;
        let owner = owner_transaction_v5(b"original-source-challenge-spent-v5", vec![(key, Some(bytes))])?;
        let transaction = original_floor_transaction_v5(&authority, owner, acquisition)?;
        producer.park(Append::ChallengeSpent, transaction)?;
        Ok(())
    }

    fn retain_original_completion_handoff_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let physical = producer.storage_offer.as_ref().ok_or(ProviderLedgerError::Unavailable)?.physical()?;
        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        completion.duplicate = Some(physical.retain_original());
        if completion.duplicate.as_ref().is_some_and(Result::is_err) {
            completion.failure = Some(CompletionFailureV5::Duplicate);
            return Ok(());
        }
        // Only this genuine same-mount duplicate moves. The original physical
        // owner and lower original received mount remain in the Storage offer.
        if let Some(Ok(duplicate)) = completion.duplicate.take() {
            completion.handoff = Some(duplicate.into_security_handoff());
        }
        if completion.handoff.as_ref().is_some_and(Result::is_err) {
            completion.failure = Some(CompletionFailureV5::Handoff);
        }
        Ok(())
    }

    fn prepare_original_completion_subjects_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let configuration = original.history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let readback = producer.readback(Append::ChallengeSpent)?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let claims = signed.request().claims();
        let (_, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified_request) = acquire.verified() else { return Err(ProviderLedgerError::Equivocation.into()); };
        let projection = verified_request.ingress_projection();
        let acquisition_identity = AcquisitionKeyV1 {
            provider_id: claims.provider_acquisition().0,
            holder_id: claims.holder_session().0,
            acquisition_id: claims.provider_acquisition().1,
        };
        let acquisition_key = acquisition_key(&acquisition_identity);
        let attempt_identity = AttemptKeyV1 {
            provider_id: acquisition_identity.provider_id,
            holder_id: acquisition_identity.holder_id,
            root_record_key_id: projection.ordered_signers()[1].key_id(),
            method: aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire as u8,
            request_id: verified_request.request().request_id(),
        };
        let attempt_key = attempt_key(&attempt_identity);
        let session_key = session_key(acquisition_identity.provider_id, acquisition_identity.holder_id);
        let decode = |key: &[u8]| -> Result<DecodedRecordV1, OriginalProducerErrorV5> {
            let bytes = readback.rows().get(&(RecordNamespace::SourceProviderAuthority, key.to_vec())).ok_or(ProviderLedgerError::Unavailable)?;
            Ok(decode_record(key, bytes)?)
        };
        let DecodedRecordV1::Acquisition(acquisition) = decode(&acquisition_key)? else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let DecodedRecordV1::Attempt(attempt) = decode(&attempt_key)? else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let DecodedRecordV1::Session(session) = decode(&session_key)? else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let DecodedRecordV1::Authority(authority) = decode(&authority_key(acquisition_identity.provider_id))? else {
            return Err(ProviderLedgerError::Equivocation.into());
        };

        crate::acquire::require_completion_headroom(
            session.revision,
            session.next_response_sequence,
            authority.revision,
            authority.inventory_generation,
        )?;
        let generation = authority.last_lease_issue_generation.checked_add(1).ok_or(ProviderLedgerError::InvalidTransition("lease generation exhausted"))?;
        if acquisition.lease_history.len() >= crate::limits::MAXIMUM_LEASE_HISTORY_PER_ACQUISITION {
            return Err(ProviderLedgerError::LimitExceeded("acquisition lease history").into());
        }
        let offer = producer.storage_offer.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let physical = offer.physical()?;
        let receipt = offer.reply()?.receipt();
        let (resource, snapshot) = claims.catalog().select_under_head(claims.catalog().generation(), claims.catalog().digest(), claims.catalog().namespace_digest(), claims.selection().0)?;
        let proof = SourceProviderProofV1::ZfsHeldSnapshot {
            proof: snapshot.clone(),
            topology: offer.verified()?.topology().clone(),
        };
        let observed = physical.original_observed_seconds();
        let expiry = observed.checked_add(acquisition.normalized_intent.requested_lease_seconds() as i64)
            .ok_or(ProviderLedgerError::InvalidTransition("lease time overflow"))?
            .min(attempt.deadline_seconds).min(attempt.current_valid_until_seconds)
            .min(claims.validity().1).min(receipt.receipt().validity().1);
        if observed > current_seconds()? || expiry <= observed {
            return Err(ProviderLedgerError::BackendConflict.into());
        }

        let evidence = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::ZfsHeldSnapshot,
            receipt.signer().authority().0,
            receipt.signer().authority().1,
            receipt.signer().authority().2,
            receipt.receipt().head().journal().0,
            receipt.digest(),
            Vec::new(),
        )?;
        let reopen = ReopenIdentityV1::new(
            BackendEvidenceClassV1::ZfsHeldSnapshot,
            producer.physical_plan.as_ref().ok_or(ProviderLedgerError::Unavailable)?.backend_id(),
            receipt.signer().authority().1,
            receipt.signer().authority().2,
            resource.resource_id(),
            resource.resource_generation(),
            resource.resource_digest(),
            snapshot.storage_handle(),
            snapshot.storage_version(),
            snapshot.active_hold_digest(),
        )?;

        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        completion.lease = Some(SourceExportLeaseV1::new(
            crate::acquire::derive_lease_id(acquisition.acquisition_id, generation, acquisition.backend_id)?,
            attempt.request_id,
            attempt.typed_request_digest,
            acquisition.holder.authority_id(),
            acquisition.holder.authority_generation(),
            acquisition.holder.authority_digest(),
            acquisition.provider.clone(),
            resource.clone(),
            proof.clone(),
            acquisition.normalized_intent.binding_digest(),
            observed,
            expiry,
            acquisition.normalized_intent.holder_revocation_digest(),
        )?);
        let patch = AcquireCompletionPatchV1::new(
            acquisition_key,
            attempt.attempt_digest,
            generation,
            digest_provider_proof(&proof),
            provider_resource_commitment_v1(&resource, digest_provider_proof(&proof)),
            Some(evidence.encode()),
            Some(reopen.encode().to_vec()),
            completion.phase3.as_ref().ok_or(ProviderLedgerError::Unavailable)?.original().original_root,
        )?;
        let active = completion.phase3.as_ref().ok_or(ProviderLedgerError::Unavailable)?.original().advance(NativeAcquireCompletionStateV2::Active)?;
        let previous = completion.phase3.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        completion.phase4 = Some(SourceNativeHeldCompletionRecordV1::new(active.clone(), NativeHeldCompletionSuffixV1::new(
            Role::Provider, 4, previous.suffix().flight(), previous.suffix().prepared().cloned(), previous.suffix().controls().to_vec(),
        )?)?);
        completion.plan = Some(AcquireCompletionPlanV1::new(attempt_key, patch, configuration.limits().maximum_inventory_tombstones_per_holder())?.with_native_completion(active)?);
        let clock = self.original_ingress.borrowed_clock_v5()?;
        let (initial, _) = clock.original_sample_and_deadline();
        completion.signatures = Some(OriginalProviderCompletionSignaturesV5::pending_original(initial,
            clock.original_stage_deadline(expiry)?, (claims.validity().0.max(receipt.receipt().validity().0), expiry)));
        if projection.session_binding() != session.session_binding {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        Ok(())
    }

    fn sign_original_completion_v5(&mut self, stage: CompletionStageV5) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_completion_current_v5()?;
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else { return Err(ProviderLedgerError::Unavailable.into()); };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&history)?;
        let (readback, completion) = producer.completion_signing_parts_v5()?;
        let physical = completion.handoff.as_ref().and_then(|handoff| handoff.as_ref().ok()).ok_or(ProviderLedgerError::Unavailable)?;
        let signatures = completion.signatures.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let succeeded = match stage {
            CompletionStageV5::SignLease => held.session.sign_original_completion_lease_v5(&authority, readback, root, acquire, physical,
                completion.lease.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(), signatures),
            CompletionStageV5::SignReceipt => held.session.sign_original_completion_receipt_v5(&authority, readback, root, acquire, physical, signatures),
            CompletionStageV5::SignStatus => held.session.sign_original_completion_status_v5(&authority, readback, root, acquire, physical, signatures),
            _ => return Err(ProviderLedgerError::Equivocation.into()),
        };
        if !succeeded {
            completion.failure = Some(CompletionFailureV5::Signatures);
            return Ok(());
        }
        self.require_original_completion_current_v5()?;
        Ok(())
    }

    fn prepare_original_complete_checkpoint_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else { return Err(ProviderLedgerError::Unavailable.into()); };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut()).ok_or(ProviderLedgerError::Unavailable)?;
        let history = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&history)?;
        let replay = authority.replayed_origins()?;
        let completion = producer.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        storage_offer::retain_projection(&mut completion.before, replay.current_rows(), None, authority.configured_limits())?;
        let signatures = completion.signatures.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let next = completion.phase4.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = next.original().acquisition_id;
        let plan = completion.plan.take().ok_or(ProviderLedgerError::Unavailable)?;
        completion.finalized = Some(plan.finalize_native_held(
            completion.before.iter().map(|(key, value)| (key.as_slice(), value.as_slice())), next,
            signatures.response().ok_or(ProviderLedgerError::Unavailable)?.to_vec(),
            signatures.signed_lease().ok_or(ProviderLedgerError::Unavailable)?.clone(),
            signatures.completed_at_seconds().ok_or(ProviderLedgerError::Unavailable)?,
        )?);
        let finalized = completion.finalized.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let owner = owner_transaction_v5(finalized.purpose(), finalized.mutations().to_vec())?;
        let transaction = original_floor_transaction_v5(&authority, owner, acquisition)?;
        producer.park(Append::CompletionCommitted, transaction)?;
        Ok(())
    }

    fn require_original_completion_readback_v5(&mut self, step: Append) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_v5()?;
        let completion = producer.original_completion.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let readback = producer.readback(step)?;
        let expected = match step {
            Append::ChallengeSpent => completion.phase3.as_ref(),
            Append::CompletionCommitted => completion.phase4.as_ref(),
            _ => return Err(ProviderLedgerError::Equivocation.into()),
        }.ok_or(ProviderLedgerError::Unavailable)?;
        let key = native_completion_key_v2(expected.original().acquisition_id);
        if readback.rows().get(&(RecordNamespace::SourceProviderAuthority, key)) != Some(&expected.to_canonical_bytes()?) {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        if step == Append::CompletionCommitted {
            let finalized = completion.finalized.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            if finalized.mutations().len() != 6 { return Err(ProviderLedgerError::Equivocation.into()); }
            for (key, value) in finalized.mutations() {
                if readback.rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone())) != value.as_ref() {
                    return Err(ProviderLedgerError::Equivocation.into());
                }
            }
        }
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else { return Err(ProviderLedgerError::Unavailable.into()); };
        let producer = held.original.as_ref().and_then(|original| original.producer.as_ref()).ok_or(ProviderLedgerError::Unavailable)?;
        let history = self.hold_challenges.original_history_v5()?;
        self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?.claim_source_original_native_v5(&history)?.validate_readback(producer.readback(step)?)?;
        Ok(())
    }
}

// This is the existing Source5 transfer, not a floor factory or a copied engine.
fn original_floor_transaction_v5(
    authority: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
    owner: JournalTransaction,
    acquisition: ObjectDigest,
) -> Result<JournalTransaction, OriginalProducerErrorV5> {
    let (before, after) = authority.derive_original_floor_transfer_v5(&owner, acquisition)?;
    let mut records = owner.records().to_vec();
    records.push(JournalRecord::delete(RecordNamespace::GlobalCapacityReservation, before.to_journal_record()?.key().to_vec()));
    records.push(after.to_journal_record()?);
    Ok(JournalTransaction::new(*owner.id(), records)?)
}
