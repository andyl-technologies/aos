//! Runtime retention and dispatch fencing for the private native Acquire seam.
//!
//! The same protected completion row retains exact signed bytes before any
//! send. The owner holds Provider then challenge custody throughout; recovery
//! reuses the original nonce and never turns uncertainty into proven absence.

use aos_sandbox::{JournalRecord, JournalTransaction, ProtectedJournalPreflight, RecordNamespace};
use aos_sandbox_source_provider_protocol::{
    ProviderHeldSnapshotCatalogV1, SignedSourceProviderRequestV1,
    SignedStorageNativeAcquireRequestV2, StorageNativeAcquireRequestV2,
    StorageZfsHoldTransportRequestV1,
};

use super::*;
use crate::DurableAcquireEffectPermitV1;
use crate::held_snapshot_selection::{
    current_native_attempt_window, select_current_held_snapshot_claim,
    validate_current_native_attempt,
};
use crate::zfs_hold_challenge::{
    ProtectedZfsHoldChallengesV1, StagedZfsHoldChallengeV1, current_seconds, expiry,
};

/// Joins exact durable Requested readback to the protected current owner graph.
///
/// Only this runtime module constructs the token. It carries no Storage send
/// authority and cannot be recovered from caller-supplied signed bytes alone.
pub(crate) struct RetainedNativeChallengeRequestV1<'a> {
    record: &'a NativeAcquireCompletionRecordV2,
}

impl<'a> RetainedNativeChallengeRequestV1<'a> {
    fn from_owner_readback(
        ledger: &ProviderLedgerV1<'_>,
        record: &'a NativeAcquireCompletionRecordV2,
    ) -> Result<Self, ProviderLedgerError> {
        super::clock::retained_clock_anchor(record)?;
        if ledger.qualified_native_bridge.is_none()
            || record.original_clock.is_none()
            || !matches!(
                record.state,
                NativeAcquireCompletionStateV2::Requested
                    | NativeAcquireCompletionStateV2::Prepared
            )
            || ledger
                .recovered
                .native_completions
                .get(&record.acquisition_id)
                != Some(record)
            || ledger
                .journal
                .get(&native_completion_key_v2(record.acquisition_id))?
                != Some(crate::format::encode_native_completion_v2(record).as_slice())
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        let acquisition = ledger
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == record.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        crate::ledger::native_completion::validate_native_export_open_v1(acquisition, Some(record))
            .map_err(crate::transaction::map_pure_ledger_error)?;
        let attempt = ledger
            .recovered
            .attempts
            .values()
            .find(|row| row.attempt_digest == record.attempt_digest)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let session = ledger
            .recovered
            .sessions
            .get(&(record.provider_id, record.holder_id))
            .ok_or(ProviderLedgerError::Unavailable)?;
        record
            .validate_provider_graph(attempt, acquisition)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        if session.session_binding != record.session_binding
            || session.pending_attempt_digest != Some(record.attempt_digest)
            || attempt.state != crate::model::ProviderAttemptStateV1::Reserved
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        crate::native_no_dispatch_capacity::validate_set(&ledger.journal, &ledger.recovered)?;
        ledger
            .native_acquire_custody
            .get(&record.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?
            .clock
            .require_record(record)?;
        Ok(Self { record })
    }

    pub(crate) const fn record(&self) -> &NativeAcquireCompletionRecordV2 {
        self.record
    }
}

/// Retains the exact suffix preflight while the Provider writer stays held.
pub(crate) struct NativeAcquireSuffixCapacityV2 {
    preflight: ProtectedJournalPreflight,
    transactions: Vec<JournalTransaction>,
}

impl NativeAcquireSuffixCapacityV2 {
    pub(crate) fn require_before_dispatch(
        &self,
        ledger: &ProviderLedgerV1<'_>,
    ) -> Result<(), ProviderLedgerError> {
        ledger
            .journal
            .validate_preflight_for_effect(&self.preflight, &self.transactions)?;
        Ok(())
    }
}

impl ProviderLedgerV1<'_> {
    /// Commits one typed native row and installs exact checked readback.
    ///
    /// Phase admission, nonce ordering and fresh original-request authorization
    /// remain at the call sites; this helper grants no effect authority.
    ///
    /// # Errors
    ///
    /// Rejects the existing graph/CAS/capacity checks or mismatched readback.
    pub(super) fn commit_retained_native_record(
        &mut self,
        purpose: &[u8],
        record: &NativeAcquireCompletionRecordV2,
    ) -> Result<(), ProviderLedgerError> {
        let key = native_completion_key_v2(record.acquisition_id);
        let encoded = crate::format::encode_native_completion_v2(record);
        crate::transaction::commit_records(self, purpose, vec![(key.clone(), encoded.clone())])?;
        if self.journal.get(&key)? != Some(encoded.as_slice()) {
            self.poison_runtime();
            return Err(ProviderLedgerError::Equivocation);
        }
        self.recovered =
            crate::recovery::recover_capacity_checked(&self.journal, &self.configuration)?;
        self.refresh_recovery_work();
        Ok(())
    }

    /// Recovers only the still-current original attempt's fresh authorization.
    ///
    /// Admission must just have authenticated these exact Root bytes. This
    /// does not rotate a session, renew an expired request, or restamp native
    /// bytes. Historical-to-successor session recovery remains unsupported.
    pub(crate) fn resume_native_original_request_v3(
        &mut self,
        acquisition_id: ObjectDigest,
        effect_id: [u8; 16],
        original: &SignedSourceProviderRequestV1,
    ) -> Result<DurableAcquireEffectPermitV1, ProviderLedgerError> {
        if self.qualified_native_bridge.is_none() {
            return Err(ProviderLedgerError::Unavailable);
        }
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|row| row.attempt_digest == acquisition.effect_attempt_digest)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let session = self
            .recovered
            .sessions
            .get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
            ))
            .ok_or(ProviderLedgerError::Unavailable)?;
        if !is_native_dispatch_acquisition(acquisition)
            || acquisition.state != ProviderAcquisitionStateV1::Applying
            || acquisition.effect_id != effect_id
            || acquisition.current_attempt_digest != attempt.attempt_digest
            || attempt.state != crate::model::ProviderAttemptStateV1::Reserved
            || attempt.signed_request != original.to_canonical_bytes()
            || attempt.session_binding != session.session_binding
            || session.pending_attempt_digest != Some(attempt.attempt_digest)
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        let reservation_digest = match self.recovered.native_completions.get(&acquisition_id) {
            Some(record) => {
                super::clock::retained_clock_anchor(record)?;
                if record
                    .canonical_request
                    .as_ref()
                    .map(|signed| signed.request().signed_root_request())
                    != Some(original)
                    || record.original_clock.is_none()
                    || !matches!(
                        record.state,
                        NativeAcquireCompletionStateV2::Requested
                            | NativeAcquireCompletionStateV2::Prepared
                    )
                {
                    return Err(ProviderLedgerError::Unavailable);
                }
                record
                    .reservation_acquisition_digest
                    .ok_or(ProviderLedgerError::Unavailable)?
            }
            None => crate::format::record_digest(&crate::format::encode_acquisition(acquisition))?,
        };
        let plan = crate::AcquirePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: attempt.session_binding,
            attempt_digest: attempt.attempt_digest,
            acquisition_id,
            effect_id,
            normalized_intent_digest: acquisition.normalized_intent.digest(),
            kernel_coupled: false,
            backend_id: acquisition.backend_id,
        };
        let signing_authorization = self
            .recovery_authorizations
            .remove(&attempt.attempt_digest)
            .ok_or(ProviderLedgerError::Unavailable)?;
        Ok(DurableAcquireEffectPermitV1 {
            completion_session_binding: attempt.session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest,
            journal_snapshot: self.journal.snapshot()?,
            completion_capacity: crate::transaction::CompletionCapacityV1::NativeDispatch,
            signing_authorization,
            plan,
        })
    }

    /// Commits and reads back Requested, then freshly authorizes exact replay.
    pub(crate) fn prepare_native_acquire_request_v2(
        &mut self,
        challenges: &mut ProtectedZfsHoldChallengesV1,
        permit: DurableAcquireEffectPermitV1,
        original: &SignedSourceProviderRequestV1,
        current_catalog: (&[u8], &[u8]),
    ) -> Result<
        (
            DurableAcquireEffectPermitV1,
            NativeAcquireCompletionRecordV2,
            NativeAcquireSuffixCapacityV2,
        ),
        ProviderLedgerError,
    > {
        if self.qualified_native_bridge.is_none() || permit.plan.kernel_coupled() {
            return Err(ProviderLedgerError::Unavailable);
        }
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == permit.plan.acquisition_id())
            .cloned()
            .ok_or(ProviderLedgerError::Unavailable)?;
        if !is_native_dispatch_acquisition(&acquisition)
            || acquisition.effect_attempt_digest != permit.plan.attempt_digest()
            || acquisition.current_attempt_digest != permit.completion_attempt_digest
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let mut staged_challenge = None;
        let record = match self
            .recovered
            .native_completions
            .get(&acquisition.acquisition_id)
        {
            Some(record) => {
                super::clock::retained_clock_anchor(record)?;
                let request = record
                    .canonical_request
                    .as_ref()
                    .ok_or(ProviderLedgerError::Unavailable)?;
                if request.request().signed_root_request() != original {
                    return Err(ProviderLedgerError::Equivocation);
                }
                if !self
                    .native_acquire_custody
                    .contains_key(&record.acquisition_id)
                {
                    // The protected block is the ORIGINAL pair, not a fresh
                    // delivery/restart anchor. Old no-clock rows stay closed.
                    let attempt = self
                        .recovered
                        .attempts
                        .values()
                        .find(|attempt| attempt.attempt_digest == record.attempt_digest)
                        .ok_or(ProviderLedgerError::Unavailable)?;
                    if let Some(challenge) = challenges.retained_for_attempt(
                        record.provider_id,
                        record.holder_id,
                        record.attempt_digest,
                    )? {
                        require_exact_challenge(record, challenge)?;
                    } else if record.state != NativeAcquireCompletionStateV2::Requested {
                        return Err(ProviderLedgerError::Unavailable);
                    }
                    let clock =
                        std::sync::Arc::new(NativeAcquireClockGuardV1::from_retained_record(
                            record,
                            attempt,
                            &acquisition,
                        )?);
                    self.native_acquire_custody.insert(
                        record.acquisition_id,
                        super::NativeAcquireHotCustodyV3 {
                            clock,
                            source_root: None,
                        },
                    );
                }
                self.native_acquire_custody
                    .get(&record.acquisition_id)
                    .ok_or(ProviderLedgerError::Unavailable)?
                    .clock
                    .require_record(record)?;
                record.clone()
            }
            None => {
                let (signed, staged) =
                    self.sign_native_reserved_request_v2(challenges, &permit, current_catalog)?;
                staged_challenge = Some(staged);
                if signed.request().signed_root_request() != original {
                    return Err(ProviderLedgerError::Equivocation);
                }
                let record = NativeAcquireCompletionRecordV2::requested(
                    signed.clone(),
                    crate::format::record_digest(&crate::format::encode_acquisition(&acquisition))?,
                    self.native_acquire_custody
                        .get(&acquisition.acquisition_id)
                        .ok_or(ProviderLedgerError::Unavailable)?
                        .clock
                        .durable_anchor(&signed)?,
                )
                .map_err(crate::transaction::map_pure_ledger_error)?;
                self.commit_retained_native_record(b"retain-native-request", &record)?;
                record
            }
        };
        // The two journals are not atomic. Requested + ORIGINAL clock is
        // durable and read back FIRST; only then can its exact nonce be issued
        // or recovered. A crash at this cut cannot force a replacement nonce.
        let retained = RetainedNativeChallengeRequestV1::from_owner_readback(self, &record)?;
        let challenge = challenges.ensure_for_retained_request(&retained, staged_challenge)?;
        require_exact_challenge(&record, challenge)?;

        // No stale permit is rebased. The unchanged original signed request is
        // authenticated again and mints a new authorization at this exact cut.
        let permit = match record.state {
            NativeAcquireCompletionStateV2::Requested => {
                crate::transaction::reauthorize_requested_native_reservation(
                    self,
                    permit,
                    original,
                    current_catalog,
                )?
            }
            NativeAcquireCompletionStateV2::Prepared => {
                crate::transaction::reauthorize_prepared_native_reservation(
                    self,
                    permit,
                    original,
                    current_catalog,
                )?
            }
            _ => return Err(ProviderLedgerError::Unavailable),
        };
        let capacity = preflight_native_suffix(self, &record)?;
        Ok((permit, record, capacity))
    }

    fn sign_native_reserved_request_v2(
        &mut self,
        challenges: &mut ProtectedZfsHoldChallengesV1,
        permit: &DurableAcquireEffectPermitV1,
        current_catalog: (&[u8], &[u8]),
    ) -> Result<
        (
            SignedStorageNativeAcquireRequestV2,
            StagedZfsHoldChallengeV1,
        ),
        ProviderLedgerError,
    > {
        let plan = permit.plan();
        let binding = self
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == plan.acquisition_id())
            .map(|row| row.normalized_intent.binding_digest())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let claim = select_current_held_snapshot_claim(
            self,
            current_catalog.0,
            current_catalog.1,
            plan.holder_id(),
            binding,
        )?;
        let (attempt_digest, deadline) =
            current_native_attempt_window(self, plan.acquisition_id())?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|row| row.attempt_digest == attempt_digest)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let verified_at = attempt.verified_at_seconds;
        let original = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| ProviderLedgerError::Corrupt("native retained Root request"))?;
        let retained = challenges.retained_for_attempt(
            plan.provider_id(),
            plan.holder_id(),
            attempt_digest,
        )?;
        // A challenge without Requested has no durable original clock fence.
        // It is historical/incomplete, not permission to issue or re-sign.
        if retained.is_some() {
            return Err(ProviderLedgerError::Unavailable);
        }
        if !self
            .native_acquire_custody
            .contains_key(&plan.acquisition_id())
        {
            let clock = std::sync::Arc::new(NativeAcquireClockGuardV1::before_challenge(
                &original,
                attempt_digest,
                verified_at,
                deadline,
            )?);
            self.native_acquire_custody.insert(
                plan.acquisition_id(),
                super::NativeAcquireHotCustodyV3 {
                    clock,
                    source_root: None,
                },
            );
        }
        let clock = std::sync::Arc::clone(
            &self
                .native_acquire_custody
                .get(&plan.acquisition_id())
                .ok_or(ProviderLedgerError::Unavailable)?
                .clock,
        );
        clock.require_original(&original, attempt_digest)?;
        let issued = current_seconds()?;
        let expires = expiry(issued)?.min(deadline);
        validate_current_native_attempt(
            self,
            &claim,
            plan.acquisition_id(),
            attempt_digest,
            issued,
            expires,
        )?;
        let staged = challenges.stage(ChallengeRecordV1::new(
            plan.provider_id(),
            plan.holder_id(),
            claim.session_binding,
            attempt_digest,
            plan.acquisition_id(),
            binding,
            claim.publication_head_commitment(),
            issued,
            expires,
        ))?;
        let challenge = staged.record();
        let (issued, expires) = challenge.challenge.validity();
        validate_current_native_attempt(
            self,
            &claim,
            plan.acquisition_id(),
            attempt_digest,
            issued,
            expires,
        )?;
        if challenge.spent_receipt().is_some() || current_seconds()? >= expires {
            return Err(ProviderLedgerError::Unavailable);
        }
        let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(current_catalog.1)
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        // This is the first native carrier. Exact retry retains sequence one,
        // independently of the original RootMount request's sequence space.
        let claims = StorageZfsHoldTransportRequestV1::new(
            1,
            challenge.challenge.nonce(),
            attempt_digest,
            plan.provider_id(),
            plan.holder_id(),
            claim.session_binding,
            plan.acquisition_id(),
            binding,
            claim.publication_head_commitment(),
            issued,
            expires,
            catalog,
        )
        .map_err(|_| ProviderLedgerError::Unavailable)?;
        let request = StorageNativeAcquireRequestV2::new(claims, original)
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let session = self
            .current_sessions
            .get_mut(&plan.holder_id())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let configuration = session.session.revalidated_provider_configuration()?;
        let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
            &configuration,
            current_catalog.0,
        )?;
        let current = session
            .session
            .authorize_fixed_current_catalog_publication_v1(
                &self.journal,
                self.journal.snapshot()?,
                publication,
            )?;
        let selected =
            current.select_held_snapshot_row(&self.journal, current_catalog.1, binding)?;
        let signed = session
            .session
            .provider_outcome_facade(&self.journal, &permit.signing_authorization)?
            .sign_current_storage_native_request_v2(&selected, request)
            .map_err(ProviderLedgerError::from)?;
        clock.require_request(&signed)?;
        Ok((signed, staged))
    }
}

fn preflight_native_suffix(
    ledger: &ProviderLedgerV1<'_>,
    record: &NativeAcquireCompletionRecordV2,
) -> Result<NativeAcquireSuffixCapacityV2, ProviderLedgerError> {
    use aos_sandbox_source_provider_ledger::ledger::format::{
        MAXIMUM_NATIVE_ACQUIRE_CARRIER_MUTATION_BYTES_V2,
        NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2,
    };

    let mut transactions = Vec::new();
    if record.state == NativeAcquireCompletionStateV2::Requested {
        transactions.push(capacity_transaction(
            record,
            1,
            &[MAXIMUM_NATIVE_ACQUIRE_CARRIER_MUTATION_BYTES_V2],
        )?);
    }
    transactions.push(capacity_transaction(
        record,
        2,
        &NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2,
    )?);
    let preflight = ledger.journal.preflight_transactions(&transactions)?;
    Ok(NativeAcquireSuffixCapacityV2 {
        preflight,
        transactions,
    })
}

fn capacity_transaction(
    record: &NativeAcquireCompletionRecordV2,
    phase: u8,
    bounds: &[usize],
) -> Result<JournalTransaction, ProviderLedgerError> {
    let mut id = [0; 16];
    id.copy_from_slice(&record.native_request_digest.as_bytes()[..16]);
    id[0] ^= phase;
    if id == [0; 16] {
        id[0] = phase;
    }
    let records = bounds
        .iter()
        .enumerate()
        .map(|(index, bound)| {
            let mut key = b"native-completion-capacity-only".to_vec();
            key.extend_from_slice(record.acquisition_id.as_bytes());
            key.extend_from_slice(&[phase, index as u8]);
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                key,
                vec![0; *bound],
            )
        })
        .collect();
    Ok(JournalTransaction::new(id, records)?)
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
pub(crate) mod tests;
