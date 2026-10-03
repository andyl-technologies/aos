//! Same-claim Cache verification and dormant mutable ownership.
//!
//! The retained callback is not a Root decision, Read issuer or release contract.
//! A positive post-Root caller remains closed until genuine disposition can keep
//! every original guard alive on success, ambiguity, and unwind.

use super::*;
use crate::cache_residency::protected_owner::CacheClockWriterReadbackGuard;
use crate::journal::{ProtectedJournalAuthority, ProtectedJournalSnapshot};

/// Holds only current borrowed-claim verification results.
pub(super) struct VerifiedCacheAuthorityViewV1 {
    /// Contains the requested exact V1 capabilities, without widened scope.
    pub(super) capabilities: Vec<super::super::VerifiedCacheCapabilityV1>,
    replay: Vec<(
        CacheAuthorityPurposeV1,
        super::super::VerifiedCacheCapabilityV1,
    )>,
    /// Shares the same validated Replay session allocation.
    pub(super) validator: CacheResidencyReplayValidatorV1,
}

/// Verifies existing requested records at the original sampled deadline.
///
/// # Errors
/// Refuses malformed, stale or expired exact V1 authority records.
pub(super) fn verify_requested(
    owner: &CacheAuthorityOwner<'_, '_>,
    requests: &[(CacheAuthorityPurposeV1, Vec<u8>)],
    now: u64,
) -> Result<Vec<super::super::VerifiedCacheCapabilityV1>, CacheResidencyProtectedJournalErrorV1> {
    let capabilities = requests
        .iter()
        .map(|(purpose, key)| {
            owner
                .verify_current_record_for_purpose(*purpose, key)
                .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if capabilities
        .iter()
        .any(|capability| now == 0 || now >= capability.scope().valid_until())
    {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    Ok(capabilities)
}

/// Regenerates original partition Replay verification under this same claim.
///
/// # Errors
/// Refuses malformed, stale or expired Replay records and inventory.
pub(super) fn verify_replay(
    authority: &ProtectedJournalAuthority<'_>,
    owner: &CacheAuthorityOwner<'_, '_>,
    owner_scope: ObjectDigest,
    limits: CacheRecoveryLimitsV1,
    partitions: &BTreeMap<ObjectDigest, CacheResidencyReplayPartitionEvidenceV1>,
    capabilities: Vec<super::super::VerifiedCacheCapabilityV1>,
    now: u64,
) -> Result<VerifiedCacheAuthorityViewV1, CacheResidencyProtectedJournalErrorV1> {
    let mut replay = Vec::with_capacity(partitions.len());
    let mut session_partitions = BTreeMap::new();
    for evidence in partitions.values() {
        let capability = owner
            .verify_current_record(evidence.purpose, evidence.scope, &evidence.record_key)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
        if now >= capability.scope().valid_until() {
            return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        session_partitions.insert(
            evidence.partition.digest(),
            CacheResidencyAuthoritySessionPartitionV1 {
                evidence: evidence.clone(),
                scope: capability.scope(),
                record_digest: capability.record_digest(),
            },
        );
        replay.push((evidence.purpose, capability));
    }
    let effect_observations = authority
        .records()?
        .filter(|(key, _)| key.starts_with(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX))
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    let validator = CacheResidencyReplayValidatorV1::new(
        Arc::new(CacheResidencyAuthoritySessionV1 {
            owner_scope,
            partitions: session_partitions,
            effect_observations,
        }),
        limits,
    )?;
    Ok(VerifiedCacheAuthorityViewV1 {
        capabilities,
        replay,
        validator,
    })
}

/// Rechecks existing requested and Replay capabilities at one current time.
///
/// # Errors
/// Refuses stale snapshots, changed scope or expired original deadlines.
pub(super) fn validate_current(
    owner: &CacheAuthorityOwner<'_, '_>,
    requests: &[(CacheAuthorityPurposeV1, Vec<u8>)],
    view: &VerifiedCacheAuthorityViewV1,
    current: u64,
) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
    for ((purpose, _), capability) in requests.iter().zip(&view.capabilities) {
        owner
            .validate_for_effect_at(capability, *purpose, capability.scope(), current)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    }
    for (purpose, capability) in &view.replay {
        owner
            .validate_for_effect_at(capability, *purpose, capability.scope(), current)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    }
    Ok(current)
}

/// Borrows original journals/clock; it exposes neither a claim nor an issuer.
///
/// The callback's result is outside its quantified borrow. This compile-fail
/// example tests that language-level shape only, not a Root/Read producer:
///
/// ```compile_fail
/// fn held<R>(action: impl for<'cut> FnOnce(&'cut mut u8) -> R) -> R {
///     let mut local = 0;
///     action(&mut local)
/// }
/// let escaped = held(|original| original);
/// ```
///
/// A view likewise cannot overlap a mutable borrow of its original owner:
///
/// ```compile_fail
/// let mut owner = 0_u8;
/// let view = &owner;
/// let successor = &mut owner;
/// *successor = 1;
/// assert_eq!(*view, 0);
/// ```
pub(in crate::cache_residency) struct RetainedCacheAuthoritySessionV1<
    'claim,
    'journal,
    'gate,
    'clock,
> {
    authority: &'claim mut ProtectedJournalAuthority<'journal>,
    gate: CacheMutationGateV1<'gate>,
    clock: &'clock CacheClockWriterReadbackGuard<'clock>,
    source: &'claim ProtectedCacheResidencyReplayAuthorityV1,
    partitions: BTreeMap<ObjectDigest, CacheResidencyReplayPartitionEvidenceV1>,
    snapshot: ProtectedJournalSnapshot,
    original_records: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl RetainedCacheAuthoritySessionV1<'_, '_, '_, '_> {
    /// Samples only the same initialization-owned protected clock.
    pub(in crate::cache_residency) fn current_unix_seconds(
        &self,
    ) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        self.clock.current_unix_seconds()
    }

    /// Issues only the scope derived from this actual acquisition proof.
    ///
    /// # Errors
    /// Keeps the first append result and exact original deadline on failure.
    pub(in crate::cache_residency) fn issue_pin_acquire(
        &mut self,
        acquisition: &super::super::ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        pin: super::super::CachePinId,
        progress: &mut ResidentPinAuthorityAppendV1,
        budget: &mut super::ResidentDomainPayloadBudgetV1,
    ) -> Result<(Vec<u8>, u64), CacheResidencyProtectedJournalErrorV1> {
        if progress.valid_until.is_some() || progress.record_key.is_some() {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        let valid_until = self.clock.current_unix_seconds()?
            .checked_add(super::provisioning::LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS)
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        progress.valid_until = Some(valid_until);
        let scope = acquisition.authority_scope(pin, valid_until)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        progress.record_key = Some(super::provisioning::acquire_record_key(acquisition.partition()));
        self.finish_pin_issuance(
            CacheAuthorityPurposeV1::PinAcquire,
            scope,
            b"aos.sandbox.cache-residency.logical-pin-acquire-authority.v1\0",
            progress,
            budget,
        )?;
        let key = progress.record_key.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        Ok((key.clone(), valid_until))
    }

    /// Issues only the scope derived from an exact retained logical pin.
    ///
    /// # Errors
    /// Keeps the first append result and original deadline on failed reuse.
    pub(in crate::cache_residency) fn issue_pin_drain(
        &mut self,
        pin: &super::super::CachePinV1,
        progress: &mut ResidentPinAuthorityAppendV1,
        budget: &mut super::ResidentDomainPayloadBudgetV1,
    ) -> Result<Vec<u8>, CacheResidencyProtectedJournalErrorV1> {
        if progress.valid_until.is_some() || progress.record_key.is_some() {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        let valid_until = self.clock.current_unix_seconds()?
            .checked_add(super::provisioning::LOGICAL_PIN_DRAIN_LIFETIME_SECONDS)
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        progress.valid_until = Some(valid_until);
        let scope = pin.logical_drain_scope(valid_until)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        progress.record_key = Some(super::provisioning::drain_record_key(pin.partition));
        self.finish_pin_issuance(
            CacheAuthorityPurposeV1::PinDrain,
            scope,
            b"aos.sandbox.cache-residency.logical-pin-drain-authority.v1\0",
            progress,
            budget,
        )?;
        progress.record_key.clone().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)
    }

    fn finish_pin_issuance(
        &mut self,
        purpose: CacheAuthorityPurposeV1,
        scope: CacheAuthorityScopeV1,
        transaction_domain: &[u8],
        progress: &mut ResidentPinAuthorityAppendV1,
        budget: &mut super::ResidentDomainPayloadBudgetV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        super::provisioning::append_resident_pin_authority(
            self.authority,
            self.source.owner_scope,
            self.source.maximum_record_bytes,
            purpose,
            scope,
            transaction_domain,
            &mut self.gate,
            progress,
            budget,
        )?;
        if progress.unchanged {
            return self.while_current_records(&[], |_, _, _, _, _| Ok(()));
        }
        let transaction = progress.transaction.as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let Some(Ok(result)) = progress.commit.as_ref() else {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        };
        if let Err(cause) = self.reverify_purpose_own_successor(transaction, result, purpose) {
            progress.postcheck.get_or_insert(cause);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    // No issuer calls this yet. Its only mutation is replacing a nonauthorizing
    // exact snapshot after the REAL engine sealed this original own append.
    // It grants neither a Root decision nor per-request authority beyond V1.
    fn reverify_own_successor(
        &mut self,
        transaction: &crate::journal::JournalTransaction,
        result: &crate::journal::CommitResult,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.reverify_purpose_own_successor(transaction, result, CacheAuthorityPurposeV1::Read)
    }

    fn reverify_purpose_own_successor(
        &mut self,
        transaction: &crate::journal::JournalTransaction,
        result: &crate::journal::CommitResult,
        purpose: CacheAuthorityPurposeV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.authority.require_original_cache_own_append_v1(
            &self.snapshot,
            transaction,
            result,
            &mut self.gate,
        )?;
        self.clock.revalidate()?;
        let partitions = self
            .source
            .partitions
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if *partitions != self.partitions {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        drop(partitions);
        let owner = CacheAuthorityOwner::new(
            self.authority,
            self.source.owner_scope,
            self.source.maximum_record_bytes,
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let now = self.clock.current_unix_seconds()?;
        let mut expected = self.original_records.clone();
        for record in transaction.records() {
            if record.namespace() != RecordNamespace::DesiredState
                || self
                    .partitions
                    .values()
                    .any(|evidence| evidence.record_key == record.key())
                || record
                    .key()
                    .starts_with(super::super::protected_owner::CACHE_MANIFEST_KEY_PREFIX)
                || record
                    .key()
                    .starts_with(EFFECT_OBSERVATION_AUTHORITY_KEY_PREFIX)
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            let read = owner
                .verify_current_record_for_purpose(purpose, record.key())
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            owner
                .validate_for_effect_at(&read, purpose, read.scope(), now)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let value = record
                .value()
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            if self.authority.get(record.key())? != Some(value) {
                return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
            }
            expected.insert(record.key().to_vec(), value.to_vec());
        }
        let current: BTreeMap<_, _> = self
            .authority
            .records()?
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        if current != expected {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        // Reverify EVERY unchanged original Replay scope/digest/floor/deadline
        // at the real new snapshot; no stale token sequence is patched.
        let _view = verify_replay(
            self.authority,
            &owner,
            self.source.owner_scope,
            self.source.limits,
            &self.partitions,
            Vec::new(),
            now,
        )?;
        self.authority.require_original_cache_own_append_v1(
            &self.snapshot,
            transaction,
            result,
            &mut self.gate,
        )?;
        self.clock.revalidate()?;
        self.snapshot = self.authority.snapshot()?;
        self.original_records = current;
        Ok(())
    }

    /// Checks a short immutable view; mutable succession cannot overlap its borrow.
    ///
    /// # Errors
    /// Refuses changed original names/gate/clock/snapshot or expired authority.
    pub(in crate::cache_residency) fn while_current_records<R>(
        &mut self,
        requests: &[(CacheAuthorityPurposeV1, Vec<u8>)],
        action: impl FnOnce(
            &CacheAuthorityOwner<'_, '_>,
            &[super::super::VerifiedCacheCapabilityV1],
            u64,
            CacheResidencyReplayValidatorV1,
            &dyn Fn() -> Result<u64, CacheResidencyProtectedJournalErrorV1>,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        self.while_current_records_with_gate(requests, |owner, capabilities, now, validator, refresh, _| {
            action(owner, capabilities, now, validator, refresh)
        })
    }

    /// Checks requested records while borrowing the same original gate.
    ///
    /// The resident caller parks its full action result before the final checks.
    pub(in crate::cache_residency) fn while_current_records_with_gate<R>(
        &mut self,
        requests: &[(CacheAuthorityPurposeV1, Vec<u8>)],
        action: impl FnOnce(
            &CacheAuthorityOwner<'_, '_>,
            &[super::super::VerifiedCacheCapabilityV1],
            u64,
            CacheResidencyReplayValidatorV1,
            &dyn Fn() -> Result<u64, CacheResidencyProtectedJournalErrorV1>,
            &mut CacheMutationGateV1<'_>,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        self.authority
            .validate_snapshot_for_effect(&self.snapshot)?;
        self.authority.require_original_cache_gate_v1(&mut self.gate)?;
        let now = self.clock.current_unix_seconds()?;
        let owner = CacheAuthorityOwner::new(
            self.authority,
            self.source.owner_scope,
            self.source.maximum_record_bytes,
        )
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let capabilities = verify_requested(&owner, requests, now)?;
        let view = verify_replay(
            self.authority,
            &owner,
            self.source.owner_scope,
            self.source.limits,
            &self.partitions,
            capabilities,
            now,
        )?;
        let clock = self.clock;
        let refresh =
            || validate_current(&owner, requests, &view, clock.current_unix_seconds()?);
        let result = action(
            &owner,
            &view.capabilities,
            now,
            view.validator.clone(),
            &refresh,
            &mut self.gate,
        );
        refresh()?;
        self.authority.require_original_cache_gate_v1(&mut self.gate)?;
        result
    }
}

impl ProtectedCacheResidencyReplayAuthorityV1 {
    /// Establishes a dormant same-held cut, not a positive post-Root continuation.
    ///
    /// # Errors
    /// Refuses substituted clocks, unsafe writers, held/pending gates or stale
    /// authority. Returning an error is not post-Root release authorization.
    pub(in crate::cache_residency) fn with_retained_mutable_authority_v1<R>(
        &self,
        state: &mut Journal,
        clock: &CacheClockWriterReadbackGuard<'_>,
        action: impl for<'session, 'claim, 'journal, 'gate, 'clock> FnOnce(
            &'session mut RetainedCacheAuthoritySessionV1<'claim, 'journal, 'gate, 'clock>,
            &'session mut Journal,
        ) -> Result<
            R,
            CacheResidencyProtectedJournalErrorV1,
        >,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        clock.require_time_authority(&self.current_time)?;
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        clock.require_cache_targets(state, &journal)?;
        let mut gate = Journal::retain_cache_read_mutation_gate_v1(state, &journal)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let snapshot = authority.snapshot()?;
        let original_records = authority
            .records()?
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let partitions = self
            .partitions
            .lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?
            .clone();
        let mut session = RetainedCacheAuthoritySessionV1 {
            authority: &mut authority,
            gate: CacheMutationGateV1::Retained(&mut gate),
            clock,
            source: self,
            partitions,
            snapshot,
            original_records,
        };
        let result = action(&mut session, state);
        // Return/unwind releases this cut. No positive post-Root caller is
        // exposed: such a caller first needs actual retained-owner disposition.
        session.while_current_records(&[], |_, _, _, _, _| Ok(()))?;
        result
    }

    /// Loans the existing resident interlock without releasing or reopening it.
    ///
    /// The action parks its complete result in the caller's resident progress
    /// before this method performs its final authority and clock checks.
    ///
    /// # Errors
    /// Refuses foreign clocks, changed original writers, active holds, pending
    /// policy state or expired authority. Failure is never release permission.
    pub(in crate::cache_residency) fn with_borrowed_mutable_authority_v1<R>(
        &self,
        state: &mut Journal,
        hold: &mut Journal,
        clock: &CacheClockWriterReadbackGuard<'_>,
        action: impl for<'session, 'claim, 'journal, 'gate, 'clock> FnOnce(
            &'session mut RetainedCacheAuthoritySessionV1<'claim, 'journal, 'gate, 'clock>,
            &'session mut Journal,
        ) -> Result<R, CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<R, CacheResidencyProtectedJournalErrorV1> {
        clock.require_time_authority(&self.current_time)?;
        let mut journal = self.journal.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        clock.require_cache_targets(state, &journal)?;
        let mut gate = Journal::borrow_cache_mutation_gate_v1(state, &journal, hold)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let snapshot = authority.snapshot()?;
        let original_records = authority.records()?
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let partitions = self.partitions.lock()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?
            .clone();
        let mut session = RetainedCacheAuthoritySessionV1 {
            authority: &mut authority,
            gate: gate.as_gate(),
            clock,
            source: self,
            partitions,
            snapshot,
            original_records,
        };
        let result = action(&mut session, state);
        session.while_current_records(&[], |_, _, _, _, _| Ok(()))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_residency::protected_owner::tests::retained_owner_fixture;
    use crate::journal::{JournalRecord, JournalTransaction};

    #[test]
    fn actual_owner_retains_gate_and_clock_without_reopening() {
        let (root, mut owner) = retained_owner_fixture();
        let clock = root.path().join("clock.journal");
        let before = std::fs::read(&clock).unwrap();
        owner
            .with_retained_mutable_authority_v1(|session, state| {
                session.while_current_records(&[], |_, _, _, _, refresh| {
                    refresh()?;
                    Ok(())
                })?;
                assert!(matches!(
                    state.preflight_transactions(&[]),
                    Err(JournalError::AlreadyLocked)
                ));
                Ok(())
            })
            .unwrap();
        assert_eq!(std::fs::read(clock).unwrap(), before);
    }

    #[test]
    fn changed_original_clock_mode_refuses_the_still_held_view() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, mut owner) = retained_owner_fixture();
        let result = owner.with_retained_mutable_authority_v1(|session, state| {
            std::fs::set_permissions(
                root.path().join("clock.journal"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(
                session
                    .while_current_records(&[], |_, _, _, _, _| Ok(()))
                    .is_err()
            );
            // A failed view does not silently release/reacquire the interlock.
            assert!(matches!(
                state.preflight_transactions(&[]),
                Err(JournalError::AlreadyLocked)
            ));
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn genuine_own_append_cannot_refresh_original_replay_inventory() {
        let (_root, mut owner) = retained_owner_fixture();
        let result = owner.with_retained_mutable_authority_v1(|session, _state| {
            let key = session
                .partitions
                .values()
                .next()
                .unwrap()
                .record_key
                .clone();
            let original = session.authority.get(&key)?.unwrap().to_vec();
            let before = session.snapshot.sequence();
            // Even an identical original Replay record cannot be turned into
            // a Read own-successor exception by a genuine durable append.
            let transaction = JournalTransaction::new(
                [92; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    key,
                    original,
                )],
            )
            .unwrap();
            let preflight = session.authority.preflight_with_cache_gate(
                std::slice::from_ref(&transaction),
                session.gate.reborrow(),
            )?;
            let result = session.authority.commit_with_original_cache_gate_v1(
                &preflight,
                &transaction,
                session.gate.reborrow(),
            )?;
            assert!(
                session
                    .reverify_own_successor(&transaction, &result)
                    .is_err()
            );
            assert_eq!(session.snapshot.sequence(), before);
            Ok(())
        });
        // The stale original snapshot is not replaced on callback return.
        assert!(result.is_err());
    }

    #[test]
    fn real_own_append_regenerates_same_replay_but_copied_or_reused_result_refuses() {
        let (_root, mut owner) = retained_owner_fixture();
        owner
            .with_retained_mutable_authority_v1(|session, _state| {
                let evidence = session.partitions.values().next().unwrap();
                let scope = evidence.scope;
                let owner = CacheAuthorityOwner::new(
                    session.authority,
                    session.source.owner_scope,
                    session.source.maximum_record_bytes,
                )
                .unwrap();
                let old_replay = owner
                    .verify_current_record(evidence.purpose, scope, &evidence.record_key)
                    .unwrap();
                // Canonical scope DATA only: not a Root/read decision.
                let key = b"component-read-data".to_vec();
                let record = owner.canonical_record(CacheAuthorityPurposeV1::Read, scope);
                let transaction = JournalTransaction::new(
                    [91; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key.clone(),
                        record.to_vec(),
                    )],
                )
                .unwrap();
                let preflight = session.authority.preflight_with_cache_gate(
                    std::slice::from_ref(&transaction),
                    session.gate.reborrow(),
                )?;
                let result = session.authority.commit_with_original_cache_gate_v1(
                    &preflight,
                    &transaction,
                    session.gate.reborrow(),
                )?;
                let verifier = CacheAuthorityOwner::new(
                    session.authority,
                    session.source.owner_scope,
                    session.source.maximum_record_bytes,
                )
                .unwrap();
                assert!(
                    verifier
                        .validate_for_effect_at(
                            &old_replay,
                            evidence.purpose,
                            scope,
                            session.clock.current_unix_seconds()?
                        )
                        .is_err()
                );
                let mut substituted = result;
                substituted.durable_bytes += 1;
                assert!(
                    session
                        .reverify_own_successor(&transaction, &substituted)
                        .is_err()
                );
                session.reverify_own_successor(&transaction, &result)?;
                assert!(
                    session
                        .reverify_own_successor(&transaction, &result)
                        .is_err()
                );
                session.while_current_records(
                    &[(CacheAuthorityPurposeV1::Read, key.clone())],
                    |_, capabilities, _, _, refresh| {
                        assert_eq!(capabilities[0].scope(), scope);
                        refresh()?;
                        Ok(())
                    },
                )?;
                // Same-record replay must check the actual retained target/gate too.
                let sequence = session.authority.snapshot()?.sequence();
                super::super::provisioning::commit_canonical_record_under_claim_v1(
                    session.authority,
                    session.source.owner_scope,
                    session.source.maximum_record_bytes,
                    CacheAuthorityPurposeV1::Read,
                    scope,
                    key,
                    b"component-test-only\0",
                    session.gate.reborrow(),
                )?;
                assert_eq!(session.authority.snapshot()?.sequence(), sequence);
                Ok(())
            })
            .unwrap();
    }
}
