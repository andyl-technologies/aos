//! Protected native challenge-to-Active recovery while positive Acquire is closed.
//!
//! Provider holds its ledger before the separate challenge writer. Retained
//! native acceptance is typed and immutable; recovery never chooses a nonce,
//! supersedes a session, signs backend evidence, or reopens a descriptor path.

use aos_sandbox_core::ObjectDigest;

use crate::ledger::native_completion::{
    NativeAcquireCompletionRecordV2, NativeAcquireCompletionStateV2,
    NativeAcquireRecoveryDecisionV2, native_completion_key_v2, reduce_native_acquire_recovery_v2,
};
use crate::model::ProviderAcquisitionStateV1;
use crate::zfs_hold_challenge::ChallengeRecordV1;
use crate::{FixedProviderOwnerV1, ProviderLedgerError, ProviderLedgerV1, SourceRootIdentityV1};

#[path = "native_completion/runtime.rs"]
mod runtime;

pub(crate) use runtime::RetainedNativeChallengeRequestV1;

#[cfg(test)]
pub(crate) use runtime::tests::{
    prepared as fixture_prepared, prepared_with_descriptor as fixture_prepared_with_descriptor,
    requested_with_boot as fixture_requested_with_boot,
    requested_with_session as fixture_requested,
};

#[path = "native_completion/live.rs"]
mod live;

pub(crate) use live::NativeAcquireLiveObservationV3;

#[path = "native_completion/clock.rs"]
mod clock;

pub(crate) use clock::NativeAcquireClockGuardV1;

#[path = "native_completion/reply_custody.rs"]
mod reply_custody;

pub(crate) use reply_custody::{
    NativeReplyCustody, NativeReplyIdentity, NativeReplyPhase, NativeReplyReauthentication,
};

/// Keeps the hot original anchor and optional same-mount custody together.
pub(crate) struct NativeAcquireHotCustodyV3 {
    pub(crate) clock: std::sync::Arc<NativeAcquireClockGuardV1>,
    pub(crate) source_root: Option<crate::ProviderPhysicalSourceRootV1>,
}

/// Qualifies the private runtime seam without changing published capabilities.
///
/// Production has no constructor. Installed bridge qualification and its
/// reviewed activation are deliberately separate from compiling this path.
pub(crate) struct QualifiedNativeBridgeV2 {
    _private: (),
}

impl QualifiedNativeBridgeV2 {
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Retains exact protected cleanup identity without authorizing Storage release.
///
/// Only the fixed Provider owner can mint this projection after joining both
/// journals and durably closing native completion after original FD loss.
/// Storage still needs its authenticated terminal/absence protocol and active
/// interest settlement; this value alone cannot release a hold.
pub struct ProtectedProviderNativeCleanupObservationV2 {
    record: NativeAcquireCompletionRecordV2,
    record_digest: ObjectDigest,
}

impl ProtectedProviderNativeCleanupObservationV2 {
    /// Returns Storage issuance, signed acceptance, and original payload digests.
    #[must_use]
    pub const fn acceptance(&self) -> ([u8; 16], ObjectDigest, ObjectDigest) {
        (
            self.record.issuance_id,
            self.record.acceptance_digest,
            self.record.acceptance_payload_digest,
        )
    }

    /// Returns the immutable native and original Root Mount request digests.
    #[must_use]
    pub const fn requests(&self) -> (ObjectDigest, ObjectDigest) {
        (
            self.record.native_request_digest,
            self.record.root_request_digest,
        )
    }

    /// Returns the original one-shot challenge and exact signed receipt digest.
    #[must_use]
    pub const fn challenge_receipt(&self) -> ([u8; 32], ObjectDigest) {
        (self.record.challenge, self.record.receipt_digest)
    }

    /// Returns the exact Provider, holder, session, acquisition, and attempt.
    #[must_use]
    pub const fn scope(&self) -> ([u8; 16], [u8; 16], ObjectDigest, ObjectDigest, ObjectDigest) {
        (
            self.record.provider_id,
            self.record.holder_id,
            self.record.session_binding,
            self.record.acquisition_id,
            self.record.attempt_digest,
        )
    }

    /// Returns the original descriptor identity and its commitment.
    #[must_use]
    pub const fn original_root(&self) -> (SourceRootIdentityV1, ObjectDigest) {
        (self.record.original_root, self.record.descriptor_commitment)
    }

    /// Returns the exact durable Provider cleanup-record digest.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }
}

impl FixedProviderOwnerV1 {
    /// Classifies legacy inert custody without claiming another owner's FD loss.
    ///
    /// Digest-only legacy rows retain their closed cleanup projection. Exact
    /// native request rows return unavailable when original custody cannot be
    /// authenticated: Storage or RootMount may still retain the same FD. This
    /// method never proves total custody loss, current Storage state or terminal
    /// Storage settlement.
    ///
    /// # Errors
    ///
    /// Rejects absent or malformed typed records, changed challenge/session/
    /// receipt identity, invalid Provider graph links, or failed durable CAS.
    pub fn reconcile_native_acquire_closed_v2(
        &mut self,
        acquisition_id: ObjectDigest,
    ) -> Result<ProtectedProviderNativeCleanupObservationV2, ProviderLedgerError> {
        self.with_ledger_and_hold_challenges(|ledger, challenges| {
            let record = ledger
                .recovered
                .native_completions
                .get(&acquisition_id)
                .cloned()
                .ok_or(ProviderLedgerError::Unavailable)?;
            let challenge = challenges.retained_for(record.challenge)?;
            require_exact_challenge(&record, challenge)?;

            let acquisition = ledger
                .recovered
                .acquisitions
                .values()
                .find(|acquisition| acquisition.acquisition_id == acquisition_id)
                .ok_or(ProviderLedgerError::Corrupt("native acquisition missing"))?;
            let active = acquisition.state == ProviderAcquisitionStateV1::Active;
            let decision = reduce_native_acquire_recovery_v2(
                &record,
                challenge.spent_receipt(),
                active,
                None,
                None,
            )
            .map_err(crate::transaction::map_pure_ledger_error)?;
            if decision != NativeAcquireRecoveryDecisionV2::CleanupRequired {
                return Err(ProviderLedgerError::Unavailable);
            }

            let next = record
                .advance(NativeAcquireCompletionStateV2::CleanupRequired)
                .map_err(crate::transaction::map_pure_ledger_error)?;
            let key = native_completion_key_v2(acquisition_id);
            let bytes = crate::format::encode_native_completion_v2(&next);
            if next != record {
                crate::transaction::commit_records(
                    ledger,
                    b"close-native-fd-custody",
                    vec![(key, bytes.clone())],
                )?;
                ledger.recovered =
                    crate::recovery::recover(&ledger.journal, &ledger.configuration)?;
                ledger.refresh_recovery_work();
            }

            crate::transaction::confirm_current_after_commit(ledger)?;
            Ok(ProtectedProviderNativeCleanupObservationV2 {
                record: next,
                record_digest: crate::format::record_digest(&bytes)?,
            })
        })
    }
}

// Neither generic backend attestation nor path reopen can substitute for
// native acceptance, original FD custody, or authenticated Storage cleanup.
pub(crate) fn require_original_native_custody_closed(
    ledger: &ProviderLedgerV1<'_>,
    acquisition_id: ObjectDigest,
) -> Result<(), ProviderLedgerError> {
    if ledger
        .recovered
        .native_completions
        .contains_key(&acquisition_id)
        || ledger.recovered.acquisitions.values().any(|acquisition| {
            acquisition.acquisition_id == acquisition_id
                && is_native_dispatch_acquisition(acquisition)
        })
    {
        return Err(ProviderLedgerError::Unavailable);
    }

    Ok(())
}

pub(crate) fn is_native_dispatch_acquisition(
    acquisition: &crate::model::AcquisitionRecordV1,
) -> bool {
    acquisition.backend_id
        == aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
            acquisition.normalized_intent.digest(),
            acquisition.catalog_generation,
            acquisition.catalog_digest,
            acquisition.effect_attempt_digest,
        )
}

fn require_exact_challenge(
    record: &NativeAcquireCompletionRecordV2,
    challenge: ChallengeRecordV1,
) -> Result<(), ProviderLedgerError> {
    if challenge.challenge.nonce() != record.challenge
        || challenge.provider_id != record.provider_id
        || challenge.holder_id != record.holder_id
        || challenge.session_binding != record.session_binding
        || challenge.challenge.attempt_digest() != record.attempt_digest
        || challenge.acquisition_id != record.acquisition_id
        || challenge.binding_digest != record.binding_digest
        || challenge.publication_head != record.publication_head
        || challenge.challenge.validity()
            != (
                record.challenge_issued_seconds,
                record.challenge_valid_until_seconds,
            )
        || challenge
            .spent_receipt()
            .is_some_and(|receipt| receipt != record.receipt_digest)
    {
        return Err(ProviderLedgerError::Equivocation);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

    use super::*;
    use crate::ledger::model::DecodedRecordV1;
    use crate::zfs_hold_challenge::{ProtectedZfsHoldChallengesV1, current_seconds, expiry};

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn open_provider(directory: &Path) -> Journal {
        Journal::open_protected_at_uid(
            directory,
            "provider.journal",
            JournalLimits::default(),
            rustix::process::geteuid().as_raw(),
        )
        .unwrap()
        .0
    }

    fn read_native(
        journal: &mut Journal,
        acquisition: ObjectDigest,
    ) -> NativeAcquireCompletionRecordV2 {
        let authority = journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
            .unwrap();
        let key = native_completion_key_v2(acquisition);
        let bytes = authority.get(&key).unwrap().unwrap();
        let DecodedRecordV1::NativeCompletion(record) =
            crate::format::decode_record(&key, bytes).unwrap()
        else {
            panic!("wrong native family");
        };
        record
    }

    fn commit_native(journal: &mut Journal, record: &NativeAcquireCompletionRecordV2) {
        let bytes = crate::format::encode_native_completion_v2(record);
        let key = native_completion_key_v2(record.acquisition_id);
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
            .unwrap();
        if let Some(current) = authority.get(&key).unwrap() {
            let DecodedRecordV1::NativeCompletion(current) =
                crate::format::decode_record(&key, current).unwrap()
            else {
                panic!("wrong native family");
            };
            current.validate_successor(record).unwrap();
            if current == *record {
                return;
            }
        }
        let mut id = [0; 16];
        id.copy_from_slice(&crate::format::record_digest(&bytes).unwrap().as_bytes()[..16]);
        let transaction = JournalTransaction::new(
            id,
            vec![JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                key,
                bytes,
            )],
        )
        .unwrap();
        authority.commit(&transaction).unwrap();
    }

    fn fixture_record(challenge: ChallengeRecordV1) -> NativeAcquireCompletionRecordV2 {
        let (issued, expires) = challenge.challenge.validity();
        NativeAcquireCompletionRecordV2 {
            revision: 1,
            state: NativeAcquireCompletionStateV2::Prepared,
            provider_id: challenge.provider_id,
            holder_id: challenge.holder_id,
            session_binding: challenge.session_binding,
            attempt_digest: challenge.challenge.attempt_digest(),
            acquisition_id: challenge.acquisition_id,
            challenge: challenge.challenge.nonce(),
            challenge_issued_seconds: issued,
            challenge_valid_until_seconds: expires,
            root_request_digest: digest(8),
            root_request_id: [9; 16],
            typed_request_digest: digest(10),
            native_request_digest: digest(11),
            receipt_digest: digest(12),
            acceptance_digest: digest(13),
            acceptance_payload_digest: digest(23),
            issuance_id: [14; 16],
            binding_digest: challenge.binding_digest,
            publication_head: challenge.publication_head,
            original_root: SourceRootIdentityV1::new([15; 16], 16, 17, 18).unwrap(),
            descriptor_commitment: digest(19),
            canonical_request: None,
            accepted_reply: None,
            reservation_acquisition_digest: None,
            original_clock: None,
        }
    }

    #[test]
    fn native_two_journal_crash_replay_retains_original_nonce_and_receipt() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = open_provider(directory.path());
        let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let now = current_seconds().unwrap();
        let proposed = ChallengeRecordV1::new(
            [1; 16],
            [2; 16],
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            now,
            expiry(now).unwrap(),
        );
        let issued = challenges.issue(proposed).unwrap();
        let challenge = challenges.retained_for(issued.nonce()).unwrap();
        let prepared = fixture_record(challenge);
        commit_native(&mut provider, &prepared);
        drop(challenges);
        drop(provider);

        let mut provider = open_provider(directory.path());
        let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let replayed = read_native(&mut provider, prepared.acquisition_id);
        let retained = challenges.retained_for(prepared.challenge).unwrap();
        require_exact_challenge(&replayed, retained).unwrap();
        let live = Some((replayed.original_root, replayed.descriptor_commitment));
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &replayed,
                retained.spent_receipt(),
                false,
                Some(replayed.session_binding),
                live
            )
            .unwrap(),
            NativeAcquireRecoveryDecisionV2::AwaitOriginalSpend
        );
        challenges.spend(retained, replayed.receipt_digest).unwrap();
        drop(challenges);
        drop(provider);

        let mut provider = open_provider(directory.path());
        let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let replayed = read_native(&mut provider, prepared.acquisition_id);
        let retained = challenges.retained_for(prepared.challenge).unwrap();
        require_exact_challenge(&replayed, retained).unwrap();
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &replayed,
                retained.spent_receipt(),
                false,
                Some(replayed.session_binding),
                live
            )
            .unwrap(),
            NativeAcquireRecoveryDecisionV2::OriginalCompletionPending
        );
        challenges
            .spend(challenge, replayed.receipt_digest)
            .unwrap();
        assert!(challenges.spend(challenge, digest(20)).is_err());
        assert!(challenges.issue(proposed).is_err());
        let spent = replayed
            .advance(NativeAcquireCompletionStateV2::Spent)
            .unwrap();
        commit_native(&mut provider, &spent);
        let active = spent
            .advance(NativeAcquireCompletionStateV2::Active)
            .unwrap();
        commit_native(&mut provider, &active);
        drop(challenges);
        drop(provider);

        let mut provider = open_provider(directory.path());
        let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let active = read_native(&mut provider, prepared.acquisition_id);
        let retained = challenges.retained_for(prepared.challenge).unwrap();
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &active,
                retained.spent_receipt(),
                true,
                Some(active.session_binding),
                live
            )
            .unwrap(),
            NativeAcquireRecoveryDecisionV2::OriginalActive
        );
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &active,
                retained.spent_receipt(),
                true,
                Some(active.session_binding),
                None
            )
            .unwrap(),
            NativeAcquireRecoveryDecisionV2::CleanupRequired
        );
        let cleanup = active
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap();
        commit_native(&mut provider, &cleanup);
        commit_native(&mut provider, &cleanup);
        assert_eq!(
            read_native(&mut provider, prepared.acquisition_id).challenge,
            prepared.challenge
        );
        assert!(
            cleanup
                .advance(NativeAcquireCompletionStateV2::Active)
                .is_err()
        );
    }

    #[test]
    fn native_cleanup_join_rejects_changed_session_and_receipt() {
        let now = current_seconds().unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let proposed = ChallengeRecordV1::new(
            [1; 16],
            [2; 16],
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            now,
            expiry(now).unwrap(),
        );
        let issued = challenges.issue(proposed).unwrap();
        let challenge = challenges.retained_for(issued.nonce()).unwrap();
        let record = fixture_record(challenge);
        let mut changed = record.clone();
        changed.session_binding = digest(21);
        assert!(require_exact_challenge(&changed, challenge).is_err());
        challenges.spend(challenge, record.receipt_digest).unwrap();
        let spent = challenges.retained_for(issued.nonce()).unwrap();
        changed = record;
        changed.receipt_digest = digest(22);
        assert!(require_exact_challenge(&changed, spent).is_err());
    }
}
