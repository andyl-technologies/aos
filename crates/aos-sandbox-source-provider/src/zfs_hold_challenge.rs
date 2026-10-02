//! Durable, bounded replay exclusion for native Storage hold observations.
//!
//! This dedicated protected journal is opened after the Provider ledger, so
//! every operation holds locks in ledger-then-challenge order. It retains one
//! immutable key per attempt, including spent and expired challenges. Losing
//! the live holder session across reboot makes a retained challenge unusable.
//! The 1,024-record lifetime ceiling deliberately closes new issuance when
//! exhausted. Native Acquire must remain disabled until a versioned,
//! rollback-safe retention epoch can replace this conservative bound.
//!
//! ```text
//! key: AOSZHK01 | challenge[32]
//! value: AOSZHC01 | version:u16be=1 | reserved[6]=0 |
//! challenge[32] | provider-id[16] | holder-id[16] |
//! session-binding[32] | attempt-digest[32] | acquisition-id[32] |
//! binding-digest[32] | publication-head[32] |
//! issued-seconds:i64be | valid-until-seconds:i64be |
//! state:u8 (1=issued, 2=spent) | reserved[7]=0 | receipt-digest[32]
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, ProtectedJournalPreflight,
    RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use rustix::rand::GetRandomFlags;
use sha2::{Digest as _, Sha256};

use crate::ProviderLedgerError;

const ROOT: &str = "/var/lib/aos/source-provider";
const FILE: &str = "native-hold-challenges.journal";
const KEY_MAGIC: &[u8; 8] = b"AOSZHK01";
const VALUE_MAGIC: &[u8; 8] = b"AOSZHC01";
const VERSION: u16 = 1;
const KEY_BYTES: usize = 40;
const RECORD_BYTES: usize = 296;
const MAXIMUM_CHALLENGES: usize = 1024;
const LIFETIME_SECONDS: i64 = 60;
const ISSUED: u8 = 1;
const SPENT: u8 = 2;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.native-hold-challenge.v1\0";

type ChallengeAttemptIndexV1 = BTreeMap<([u8; 16], [u8; 16], ObjectDigest), ChallengeRecordV1>;

/// Proposes one nonce without committing or authorizing a Storage send.
pub(crate) struct StagedZfsHoldChallengeV1 {
    record: ChallengeRecordV1,
    transaction: JournalTransaction,
    preflight: ProtectedJournalPreflight,
    attempted: bool,
    original_readback: Option<Vec<u8>>,
}

impl StagedZfsHoldChallengeV1 {
    pub(crate) const fn record(&self) -> ChallengeRecordV1 {
        self.record
    }

    /// Borrows the original bytes actually read back after this staged append.
    pub(crate) fn original_readback_v5(&self) -> Option<&[u8]> {
        self.original_readback.as_deref()
    }
}

/// Retains the same original nonce's Spent candidate before fallible checks.
///
/// This never issues a nonce or calls the issuance-only staging predicates.
pub(crate) struct StagedOriginalZfsHoldSpendV5 {
    expected: ChallengeRecordV1,
    receipt: ObjectDigest,
    spent: Option<ChallengeRecordV1>,
    transaction: Option<JournalTransaction>,
    preflight: Option<ProtectedJournalPreflight>,
    readback: Option<Vec<u8>>,
    attempted: bool,
    failed: bool,
}

impl StagedOriginalZfsHoldSpendV5 {
    pub(crate) fn readback(&self) -> Option<&[u8]> {
        self.readback.as_deref()
    }
}

/// Carries one durable Provider-issued challenge for an exact native attempt.
///
/// It is nonauthorizing and can be sent to Storage only after the protected
/// journal commit succeeds. No caller can construct or choose its nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderZfsHoldChallengeV1 {
    nonce: [u8; 32],
    attempt_digest: ObjectDigest,
    issued_seconds: i64,
    valid_until_seconds: i64,
}

impl ProviderZfsHoldChallengeV1 {
    /// Returns the exact nonce that Storage must sign in its receipt.
    #[must_use]
    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    /// Returns the durable Provider attempt committed before issuance.
    #[must_use]
    pub const fn attempt_digest(self) -> ObjectDigest {
        self.attempt_digest
    }

    /// Returns the inclusive issue and exclusive expiry second.
    #[must_use]
    pub const fn validity(self) -> (i64, i64) {
        (self.issued_seconds, self.valid_until_seconds)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChallengeRecordV1 {
    pub(crate) challenge: ProviderZfsHoldChallengeV1,
    pub(crate) provider_id: [u8; 16],
    pub(crate) holder_id: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) binding_digest: ObjectDigest,
    pub(crate) publication_head: ObjectDigest,
    state: u8,
    receipt_digest: ObjectDigest,
}

#[derive(Clone, Copy)]
pub(crate) struct CurrentZfsHoldChallengeContextV1 {
    pub(crate) nonce: [u8; 32],
    pub(crate) provider_id: [u8; 16],
    pub(crate) holder_id: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) attempt_digest: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) binding_digest: ObjectDigest,
    pub(crate) publication_head: ObjectDigest,
    pub(crate) validity: (i64, i64),
}

pub(crate) struct ProtectedZfsHoldChallengesV1 {
    journal: Journal,
    location: ChallengeJournalLocationV1,
}

#[derive(Clone, Copy)]
enum ChallengeJournalLocationV1 {
    Fixed,
    #[cfg(test)]
    Fixture,
}

enum ChallengeReadbackCustodyV5 {
    Legacy,
    RetainOriginal,
}

impl ProtectedZfsHoldChallengesV1 {
    /// Lends actual uncompacted history only after the existing codec validates it.
    pub(crate) fn original_history_v5(
        &mut self,
    ) -> Result<aos_sandbox::journal::SourceOriginalChallengeHistoryViewV5<'_>, ProviderLedgerError> {
        let (_, current) = self.validate_records()?;
        let history = self.journal.source_original_challenge_history_v5()?;
        validate_original_history_v5(&history, &current)?;
        history.validate_current()?;
        Ok(history)
    }

    pub(crate) fn open_fixed() -> Result<Self, ProviderLedgerError> {
        let (journal, _) = Journal::open_protected_at(Path::new(ROOT), FILE, limits())?;
        let mut owner = Self {
            journal,
            location: ChallengeJournalLocationV1::Fixed,
        };
        owner.validate_records()?;
        Ok(owner)
    }

    #[cfg(test)]
    pub(crate) fn open_fixture(directory: &Path) -> Result<Self, ProviderLedgerError> {
        let uid = rustix::process::geteuid().as_raw();
        let (journal, _) = Journal::open_protected_at_uid(directory, FILE, limits(), uid)?;
        let mut owner = Self {
            journal,
            location: ChallengeJournalLocationV1::Fixture,
        };
        owner.validate_records()?;
        Ok(owner)
    }

    pub(crate) fn issue(
        &mut self,
        record: ChallengeRecordV1,
    ) -> Result<ProviderZfsHoldChallengeV1, ProviderLedgerError> {
        let staged = self.stage(record)?;
        Ok(self.commit_staged(staged)?.challenge)
    }

    /// Stages the exact nonce and append headroom without writing either journal.
    ///
    /// Native dispatch must retain Requested and its original clock first.
    ///
    /// # Errors
    ///
    /// Rejects expiry, duplicate attempts, corruption, limits or insufficient
    /// durable challenge capacity before Requested may be retained.
    pub(crate) fn stage(
        &mut self,
        mut record: ChallengeRecordV1,
    ) -> Result<StagedZfsHoldChallengeV1, ProviderLedgerError> {
        let now = current_seconds()?;
        if !record.is_issued_now(now) {
            return Err(ProviderLedgerError::Unavailable);
        }
        let (count, attempts) = self.validate_records()?;
        if count >= MAXIMUM_CHALLENGES {
            return Err(ProviderLedgerError::LimitExceeded("native hold challenges"));
        }
        if attempts.contains_key(&(
            record.provider_id,
            record.holder_id,
            record.challenge.attempt_digest,
        )) {
            return Err(ProviderLedgerError::InvalidTransition(
                "native hold challenge already issued for attempt",
            ));
        }
        record.challenge.nonce = random_nonce()?;
        record.state = ISSUED;
        record.receipt_digest = ObjectDigest::from_bytes([0; 32]);
        let key = key(record.challenge.nonce);
        let value = record.encode();
        if ChallengeRecordV1::decode(&key, &value)? != record {
            return Err(ProviderLedgerError::Corrupt(
                "native hold challenge proposal",
            ));
        }
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        if authority.get(&key)?.is_some() {
            return Err(ProviderLedgerError::Equivocation);
        }
        let transaction = challenge_transaction(key, value)?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        Ok(StagedZfsHoldChallengeV1 {
            record,
            transaction,
            preflight,
            attempted: false,
            original_readback: None,
        })
    }

    fn commit_staged(
        &mut self,
        mut staged: StagedZfsHoldChallengeV1,
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        self.commit_staged_borrowed(&mut staged, ChallengeReadbackCustodyV5::Legacy)
    }

    /// Keeps the actual staged transaction resident for the original-only caller.
    fn commit_staged_borrowed(
        &mut self,
        staged: &mut StagedZfsHoldChallengeV1,
        custody: ChallengeReadbackCustodyV5,
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        if staged.attempted {
            return Err(ProviderLedgerError::InvalidTransition("challenge append already attempted"));
        }
        let (_, attempts) = self.validate_records()?;
        if attempts.contains_key(&(
            staged.record.provider_id,
            staged.record.holder_id,
            staged.record.challenge.attempt_digest,
        )) {
            return Err(ProviderLedgerError::Equivocation);
        }
        if !staged.record.is_issued_now(current_seconds()?) {
            return Err(ProviderLedgerError::Unavailable);
        }
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        authority.validate_preflight_for_effect(
            &staged.preflight,
            std::slice::from_ref(&staged.transaction),
        )?;
        staged.attempted = true;
        authority.commit(&staged.transaction)?;
        let key = key(staged.record.challenge.nonce);
        let retained = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let retained = match custody {
            ChallengeReadbackCustodyV5::Legacy => retained,
            ChallengeReadbackCustodyV5::RetainOriginal => {
                staged.original_readback = Some(retained.to_vec());
                staged.original_readback.as_deref().ok_or(ProviderLedgerError::RuntimePoisoned)?
            }
        };
        if ChallengeRecordV1::decode(&key, retained)? != staged.record {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        Ok(staged.record)
    }

    /// Issues only the same staged nonce after genuine Source Requested readback.
    ///
    /// Source and challenge journals are not atomic. Their original owners stay
    /// borrowed throughout this crossing, and the staged transaction/readback
    /// remain in caller custody on every failure or unwind. No recovery or nonce
    /// replacement is permitted on this hot path.
    ///
    /// # Errors
    ///
    /// Rejects changed original claims, stale Requested custody, expiry,
    /// attempted issuance, insufficient capacity or failed append/readback.
    pub(crate) fn commit_original_requested_v5(
        &mut self,
        source: &mut Journal,
        requested: &aos_sandbox::journal::OriginalSourceProtectedReadbackV5,
        signed: &aos_sandbox_source_provider_protocol::SignedStorageNativeAcquireRequestV2,
        staged: &mut StagedZfsHoldChallengeV1,
    ) -> Result<(), ProviderLedgerError> {
        let claims = signed.request().claims();
        if staged.record.challenge.nonce() != claims.attempt().0
            || staged.record.challenge.attempt_digest() != claims.attempt().1
            || (staged.record.provider_id, staged.record.acquisition_id)
                != claims.provider_acquisition()
            || (staged.record.holder_id, staged.record.session_binding) != claims.holder_session()
            || (staged.record.binding_digest, staged.record.publication_head) != claims.selection()
            || staged.record.challenge.validity() != claims.validity()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        {
            let history = self.original_history_v5()?;
            source.complete_source_original_replay_v5(&history)?;
            source.claim_source_original_native_v5(&history)?
                .require_original_requested_readback_v5(requested, signed)?;
        }

        self.commit_staged_borrowed(staged, ChallengeReadbackCustodyV5::RetainOriginal)?;

        let history = self.original_history_v5()?;
        source.complete_source_original_replay_v5(&history)?;
        source.claim_source_original_native_v5(&history)?
            .require_original_requested_readback_v5(requested, signed)?;
        Ok(())
    }

    /// Appends or recovers only the nonce already retained in protected Requested.
    ///
    /// The opaque caller token comes from exact owner readback and graph joins.
    /// Neither a raw nonce nor signed bytes alone can authorize this recovery.
    ///
    /// # Errors
    ///
    /// Rejects any changed subject, legacy no-clock row, expiry, attempted
    /// renewal, missing challenge after acceptance, or insufficient capacity.
    pub(crate) fn ensure_for_retained_request(
        &mut self,
        requested: &crate::native_completion::RetainedNativeChallengeRequestV1<'_>,
        staged: Option<StagedZfsHoldChallengeV1>,
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        let row = requested.record();
        if row.original_clock.is_none() {
            return Err(ProviderLedgerError::Unavailable);
        }
        let mut expected = ChallengeRecordV1::new(
            row.provider_id,
            row.holder_id,
            row.session_binding,
            row.attempt_digest,
            row.acquisition_id,
            row.binding_digest,
            row.publication_head,
            row.challenge_issued_seconds,
            row.challenge_valid_until_seconds,
        );
        expected.challenge.nonce = row.challenge;
        let (count, attempts) = self.validate_records()?;
        if let Some(actual) = attempts.get(&(row.provider_id, row.holder_id, row.attempt_digest)) {
            if !actual.same_subject(expected)
                || actual
                    .spent_receipt()
                    .is_some_and(|receipt| receipt != row.receipt_digest)
                || staged.is_some()
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            return Ok(*actual);
        }
        if row.state != crate::ledger::native_completion::NativeAcquireCompletionStateV2::Requested
            || row.original_clock.is_none()
            || !expected.is_issued_now(current_seconds()?)
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        if count >= MAXIMUM_CHALLENGES {
            return Err(ProviderLedgerError::LimitExceeded("native hold challenges"));
        }
        if let Some(staged) = staged {
            if staged.record != expected {
                return Err(ProviderLedgerError::Equivocation);
            }
            return self.commit_staged(staged);
        }

        // A crash after Requested but before this journal append reuses its
        // EXACT retained proposal. It never samples a replacement random nonce.
        let key = key(expected.challenge.nonce);
        let value = expected.encode();
        if ChallengeRecordV1::decode(&key, &value)? != expected {
            return Err(ProviderLedgerError::Equivocation);
        }
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        if authority.get(&key)?.is_some() {
            return Err(ProviderLedgerError::Equivocation);
        }
        commit(&mut authority, self.location, key.clone(), value)?;
        let retained = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if ChallengeRecordV1::decode(&key, retained)? != expected {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        Ok(expected)
    }

    pub(crate) fn issued_for(
        &mut self,
        challenge: [u8; 32],
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        self.issued_for_at(challenge, current_seconds()?)
    }

    fn issued_for_at(
        &mut self,
        challenge: [u8; 32],
        now: i64,
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        self.validate_records()?;
        let key = key(challenge);
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        let value = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::Unavailable)?;
        let record = ChallengeRecordV1::decode(&key, value)?;
        if !record.is_issued_now(now) {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(record)
    }

    pub(crate) fn spend(
        &mut self,
        expected: ChallengeRecordV1,
        receipt_digest: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        if receipt_digest.as_bytes() == &[0; 32] {
            return Err(ProviderLedgerError::Unavailable);
        }
        let actual = self.retained_for(expected.challenge.nonce)?;
        if !actual.same_subject(expected) {
            return Err(ProviderLedgerError::Equivocation);
        }
        if actual.state == SPENT {
            return if actual.receipt_digest == receipt_digest {
                Ok(())
            } else {
                Err(ProviderLedgerError::Equivocation)
            };
        }
        if !actual.is_issued_now(current_seconds()?) {
            return Err(ProviderLedgerError::Unavailable);
        }
        let mut spent = actual;
        spent.state = SPENT;
        spent.receipt_digest = receipt_digest;
        let key = key(spent.challenge.nonce);
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        commit(&mut authority, self.location, key.clone(), spent.encode())?;
        let retained = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if ChallengeRecordV1::decode(&key, retained)? != spent {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        Ok(())
    }

    /// Parks an actual same-nonce Spent proposal, without an issuance predicate.
    pub(crate) fn stage_original_spend_v5(
        &mut self,
        expected: ChallengeRecordV1,
        receipt: ObjectDigest,
        slot: &mut Option<StagedOriginalZfsHoldSpendV5>,
    ) -> Result<(), ProviderLedgerError> {
        if let Some(previous) = slot.as_mut() {
            previous.failed = true;
            return Err(ProviderLedgerError::InvalidTransition("original challenge spend occupied"));
        }
        *slot = Some(StagedOriginalZfsHoldSpendV5 {
            expected, receipt, spent: None, transaction: None, preflight: None,
            readback: None, attempted: false, failed: false,
        });
        let staged = slot.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let result = (|| {
            // Preserve the old spend sentinel/subject/equivocation order.
            if receipt.as_bytes() == &[0; 32] {
                return Err(ProviderLedgerError::Unavailable);
            }
            let actual = self.retained_for(expected.challenge.nonce)?;
            if !actual.same_subject(expected) {
                return Err(ProviderLedgerError::Equivocation);
            }
            if actual.state == SPENT {
                if actual.receipt_digest != receipt {
                    return Err(ProviderLedgerError::Equivocation);
                }
                // The hot caller's prior phase-two headroom check excludes this
                // case. Idempotent historical DATA does not create another effect.
                staged.spent = Some(actual);
                let authority = self.journal.claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
                validate_location(self.location, &authority)?;
                staged.readback = Some(authority.get(&key(actual.challenge.nonce))?
                    .ok_or(ProviderLedgerError::RuntimePoisoned)?.to_vec());
                return Ok(());
            }
            if !actual.is_issued_now(current_seconds()?) {
                return Err(ProviderLedgerError::Unavailable);
            }
            let mut spent = actual;
            spent.state = SPENT;
            spent.receipt_digest = receipt;
            staged.spent = Some(spent);
            staged.transaction = Some(challenge_transaction(key(spent.challenge.nonce), spent.encode())?);
            let authority = self.journal.claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
            validate_location(self.location, &authority)?;
            staged.preflight = Some(authority.preflight_transactions(std::slice::from_ref(
                staged.transaction.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            ))?);
            Ok(())
        })();
        if result.is_err() {
            staged.failed = true;
        }
        result
    }

    /// Attempts the retained Spent transaction once and parks actual readback.
    pub(crate) fn commit_original_spend_v5(
        &mut self,
        staged: &mut StagedOriginalZfsHoldSpendV5,
        clock: &crate::native_completion::NativeAcquireClockGuardV1,
        receipt_expiry: i64,
    ) -> Result<(), ProviderLedgerError> {
        if staged.failed || staged.attempted {
            staged.failed = true;
            return Err(ProviderLedgerError::InvalidTransition("original challenge spend already attempted"));
        }
        let result = (|| {
            let actual = self.retained_for(staged.expected.challenge.nonce)?;
            if !actual.same_subject(staged.expected) {
                return Err(ProviderLedgerError::Equivocation);
            }
            if actual.state == SPENT {
                if actual.receipt_digest != staged.receipt || staged.transaction.is_some() {
                    return Err(ProviderLedgerError::Equivocation);
                }
                staged.attempted = true;
                return Ok(());
            }
            if !actual.is_issued_now(current_seconds()?) {
                return Err(ProviderLedgerError::Unavailable);
            }
            let spent = staged.spent.ok_or(ProviderLedgerError::Unavailable)?;
            let transaction = staged.transaction.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            let mut authority = self.journal.claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
            validate_location(self.location, &authority)?;
            authority.validate_preflight_for_effect(
                staged.preflight.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
                std::slice::from_ref(transaction),
            )?;
            clock.revalidate(Some(receipt_expiry))?;
            staged.attempted = true;
            authority.commit(transaction)?;
            staged.readback = Some(authority.get(&key(spent.challenge.nonce))?
                .ok_or(ProviderLedgerError::RuntimePoisoned)?.to_vec());
            clock.revalidate(Some(receipt_expiry))?;
            if ChallengeRecordV1::decode(&key(spent.challenge.nonce),
                staged.readback.as_deref().ok_or(ProviderLedgerError::RuntimePoisoned)?)? != spent
            {
                return Err(ProviderLedgerError::RuntimePoisoned);
            }
            Ok(())
        })();
        if result.is_err() {
            staged.failed = true;
        }
        result
    }

    /// Reads historical one-shot custody without renewing its validity.
    pub(crate) fn retained_for(
        &mut self,
        nonce: [u8; 32],
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        self.validate_records()?;
        let key = key(nonce);
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        let value = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::Unavailable)?;
        ChallengeRecordV1::decode(&key, value)
    }

    /// Looks up a historical one-shot record without granting issuance authority.
    ///
    /// Expired and spent records remain discoverable. Neither presence nor
    /// absence permits dispatch or a new nonce. The caller must join the exact
    /// stored subject and original validity to current protected authority;
    /// native recovery also requires durable Requested and its original clock.
    /// A challenge without Requested remains closed, while new issuance needs
    /// the staged proposal and the owner's exact request/graph/clock checks.
    ///
    /// # Errors
    ///
    /// Rejects changed protected custody, corrupt records, duplicate attempts,
    /// or a challenge set exceeding its closed lifetime bound.
    pub(crate) fn retained_for_attempt(
        &mut self,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        attempt_digest: ObjectDigest,
    ) -> Result<Option<ChallengeRecordV1>, ProviderLedgerError> {
        let (_, mut attempts) = self.validate_records()?;
        Ok(attempts.remove(&(provider_id, holder_id, attempt_digest)))
    }

    fn validate_records(
        &mut self,
    ) -> Result<(usize, ChallengeAttemptIndexV1), ProviderLedgerError> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        validate_location(self.location, &authority)?;
        validate_record_set(authority.records()?)
    }
}

fn validate_original_history_v5(
    history: &aos_sandbox::journal::SourceOriginalChallengeHistoryViewV5<'_>,
    current: &ChallengeAttemptIndexV1,
) -> Result<(), ProviderLedgerError> {
    validate_original_checkpoint_rows_v5(
        history.checkpoints()?.map(|checkpoint| (checkpoint.key(), checkpoint.value())), current,
    )
}

fn validate_original_checkpoint_rows_v5<'row>(
    rows: impl IntoIterator<Item = (&'row [u8], &'row [u8])>,
    current: &ChallengeAttemptIndexV1,
) -> Result<(), ProviderLedgerError> {
    let mut retained = BTreeMap::new();
    let mut issued_attempts = BTreeMap::new();
    for (key, value) in rows {
        let record = ChallengeRecordV1::decode(key, value)?;
        let nonce = record.challenge.nonce();
        match retained.get(&nonce).copied() {
            None => {
                if record.state != ISSUED || issued_attempts.len() >= MAXIMUM_CHALLENGES {
                    return Err(ProviderLedgerError::Corrupt("original challenge issue history"));
                }
                let attempt = (record.provider_id, record.holder_id, record.challenge.attempt_digest);
                if issued_attempts.insert(attempt, nonce).is_some() {
                    return Err(ProviderLedgerError::Corrupt("duplicate original challenge attempt"));
                }
            }
            Some(previous) => {
                let previous: ChallengeRecordV1 = previous;
                if previous.state != ISSUED
                    || record.state != SPENT
                    || !previous.same_subject(record)
                {
                    return Err(ProviderLedgerError::Corrupt("original challenge spend history"));
                }
            }
        }
        retained.insert(nonce, record);
    }

    if retained.len() != current.len()
        || current.values().any(|record| retained.get(&record.challenge.nonce()) != Some(record))
    {
        return Err(ProviderLedgerError::Corrupt("original challenge current materialization"));
    }
    Ok(())
}

fn validate_record_set<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(usize, ChallengeAttemptIndexV1), ProviderLedgerError> {
    let mut attempts = BTreeMap::new();
    let mut count = 0;
    for (key, value) in records {
        count += 1;
        if count > MAXIMUM_CHALLENGES {
            return Err(ProviderLedgerError::LimitExceeded("native hold challenges"));
        }
        let record = ChallengeRecordV1::decode(key, value)?;
        if attempts
            .insert(
                (
                    record.provider_id,
                    record.holder_id,
                    record.challenge.attempt_digest,
                ),
                record,
            )
            .is_some()
        {
            return Err(ProviderLedgerError::Corrupt(
                "duplicate native hold challenge attempt",
            ));
        }
    }
    Ok((count, attempts))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn issued_record() -> ChallengeRecordV1 {
        let mut record = ChallengeRecordV1::new(
            [1; 16],
            [2; 16],
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            100,
            160,
        );
        record.challenge.nonce = [8; 32];
        record
    }

    fn fixture_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn original_history_requires_actual_issued_then_exact_spent_without_reconstruction() {
        let issued = issued_record();
        let mut spent = issued;
        spent.state = SPENT;
        spent.receipt_digest = digest(9);
        let key = key(issued.challenge.nonce());
        let issued_bytes = issued.encode();
        let spent_bytes = spent.encode();
        let current = validate_record_set([(key.as_slice(), spent_bytes.as_slice())]).unwrap().1;

        validate_original_checkpoint_rows_v5([
            (key.as_slice(), issued_bytes.as_slice()), (key.as_slice(), spent_bytes.as_slice()),
        ], &current).unwrap();
        assert!(validate_original_checkpoint_rows_v5([
            (key.as_slice(), spent_bytes.as_slice()),
        ], &current).is_err());
        assert!(validate_original_checkpoint_rows_v5([
            (key.as_slice(), issued_bytes.as_slice()),
            (key.as_slice(), spent_bytes.as_slice()),
            (key.as_slice(), spent_bytes.as_slice()),
        ], &current).is_err());
    }

    #[test]
    fn original_history_refuses_changed_subject_duplicate_attempt_and_lost_current_row() {
        let issued = issued_record();
        let key = key(issued.challenge.nonce());
        let encoded = issued.encode();
        let current = validate_record_set([(key.as_slice(), encoded.as_slice())]).unwrap().1;
        let mut changed = issued;
        changed.state = SPENT;
        changed.receipt_digest = digest(9);
        changed.acquisition_id = digest(10);
        let changed = changed.encode();

        assert!(validate_original_checkpoint_rows_v5([
            (key.as_slice(), encoded.as_slice()), (key.as_slice(), changed.as_slice()),
        ], &current).is_err());
        assert!(validate_original_checkpoint_rows_v5(std::iter::empty(), &current).is_err());
        let mut duplicate = issued;
        duplicate.challenge.nonce = [11; 32];
        let second_key = super::key(duplicate.challenge.nonce());
        let second = duplicate.encode();
        assert!(validate_original_checkpoint_rows_v5([
            (key.as_slice(), encoded.as_slice()), (second_key.as_slice(), second.as_slice()),
        ], &current).is_err());
    }

    #[test]
    fn protected_issue_is_durable_before_return_and_replay_is_exact_after_reopen() {
        let directory = fixture_directory();
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

        let mut owner = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let issued = owner.issue(proposed).unwrap();
        assert_ne!(issued.nonce(), [0; 32]);
        assert_eq!(issued.attempt_digest(), proposed.challenge.attempt_digest());
        assert_eq!(owner.validate_records().unwrap().0, 1);
        drop(owner);

        let mut reopened = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let retained = reopened.issued_for_at(issued.nonce(), now).unwrap();
        assert_eq!(retained.challenge, issued);
        assert_eq!(retained.session_binding, proposed.session_binding);
        assert_eq!(retained.publication_head, proposed.publication_head);
        let current = CurrentZfsHoldChallengeContextV1 {
            nonce: issued.nonce(),
            provider_id: proposed.provider_id,
            holder_id: proposed.holder_id,
            session_binding: proposed.session_binding,
            attempt_digest: issued.attempt_digest(),
            acquisition_id: proposed.acquisition_id,
            binding_digest: proposed.binding_digest,
            publication_head: proposed.publication_head,
            validity: issued.validity(),
        };
        assert!(retained.matches_current(current));
        assert!(!retained.matches_current(CurrentZfsHoldChallengeContextV1 {
            session_binding: digest(8),
            ..current
        }));
        assert!(!retained.matches_current(CurrentZfsHoldChallengeContextV1 {
            attempt_digest: digest(9),
            ..current
        }));
        assert!(!retained.matches_current(CurrentZfsHoldChallengeContextV1 {
            publication_head: digest(10),
            ..current
        }));
        assert!(reopened.issue(proposed).is_err());
        assert!(
            reopened
                .issued_for_at(issued.nonce(), issued.validity().1)
                .is_err()
        );
        assert_eq!(reopened.validate_records().unwrap().0, 1);
    }

    #[test]
    fn rejected_expired_issue_does_not_mutate_protected_journal() {
        let directory = fixture_directory();
        let now = current_seconds().unwrap();
        let expired = ChallengeRecordV1::new(
            [1; 16],
            [2; 16],
            digest(3),
            digest(4),
            digest(5),
            digest(6),
            digest(7),
            now - 61,
            now - 1,
        );
        let mut owner = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();

        assert!(owner.issue(expired).is_err());
        assert_eq!(owner.validate_records().unwrap().0, 0);
        drop(owner);

        let mut reopened = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        assert_eq!(reopened.validate_records().unwrap().0, 0);
    }

    #[test]
    fn retained_attempt_lookup_preserves_nonce_and_spend_across_reopen() {
        let directory = fixture_directory();
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
        let mut owner = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        assert!(
            owner
                .retained_for_attempt([1; 16], [2; 16], digest(4))
                .unwrap()
                .is_none()
        );
        let issued = owner.issue(proposed).unwrap();
        drop(owner);

        let mut owner = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let retained = owner
            .retained_for_attempt([1; 16], [2; 16], digest(4))
            .unwrap()
            .unwrap();
        assert_eq!(retained.challenge, issued);
        assert_eq!(retained.challenge.validity(), (now, expiry(now).unwrap()));
        assert!(owner.issue(proposed).is_err());
        assert!(
            owner
                .retained_for_attempt([9; 16], [2; 16], digest(4))
                .unwrap()
                .is_none()
        );
        assert!(
            owner
                .retained_for_attempt([1; 16], [9; 16], digest(4))
                .unwrap()
                .is_none()
        );
        assert!(
            owner
                .retained_for_attempt([1; 16], [2; 16], digest(9))
                .unwrap()
                .is_none()
        );
        owner.spend(retained, digest(8)).unwrap();
        drop(owner);

        let mut owner = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
        let spent = owner
            .retained_for_attempt([1; 16], [2; 16], digest(4))
            .unwrap()
            .unwrap();
        assert_eq!(spent.challenge, issued);
        assert_eq!(spent.spent_receipt(), Some(digest(8)));
        assert!(owner.issue(proposed).is_err());
        assert_eq!(owner.validate_records().unwrap().0, 1);
    }

    #[test]
    fn protected_reopen_rejects_unknown_record_bytes() {
        let directory = fixture_directory();
        let uid = rustix::process::geteuid().as_raw();
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory.path(), FILE, limits(), uid).unwrap();
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
            .unwrap();
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"old-format-key".to_vec(),
                b"old-format-value".to_vec(),
            )],
        )
        .unwrap();
        authority.commit(&transaction).unwrap();
        drop(authority);
        drop(journal);

        assert!(ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).is_err());
    }

    #[test]
    fn retained_challenge_rejects_changed_holder_attempt_and_publication_head() {
        let record = issued_record();
        let context = CurrentZfsHoldChallengeContextV1 {
            nonce: record.challenge.nonce(),
            provider_id: record.provider_id,
            holder_id: record.holder_id,
            session_binding: record.session_binding,
            attempt_digest: record.challenge.attempt_digest(),
            acquisition_id: record.acquisition_id,
            binding_digest: record.binding_digest,
            publication_head: record.publication_head,
            validity: record.challenge.validity(),
        };
        assert!(record.matches_current(context));

        let mut changed = context;
        changed.session_binding = digest(10);
        assert!(!record.matches_current(changed));
        changed = context;
        changed.attempt_digest = digest(11);
        assert!(!record.matches_current(changed));
        changed = context;
        changed.holder_id = [12; 16];
        assert!(!record.matches_current(changed));
        changed = context;
        changed.publication_head = digest(13);
        assert!(!record.matches_current(changed));
        changed = context;
        changed.validity.1 -= 1;
        assert!(!record.matches_current(changed));
    }

    #[test]
    fn challenge_record_rejects_unknown_key_bytes_and_noncanonical_fields() {
        let record = issued_record();
        let key = key(record.challenge.nonce);
        let bytes = record.encode();
        assert_eq!(ChallengeRecordV1::decode(&key, &bytes).unwrap(), record);

        let mut altered_key = key.clone();
        altered_key[0] ^= 1;
        assert!(ChallengeRecordV1::decode(&altered_key, &bytes).is_err());
        altered_key = key.clone();
        altered_key[8] ^= 1;
        assert!(ChallengeRecordV1::decode(&altered_key, &bytes).is_err());

        for index in [
            0, 8, 10, 16, 48, 64, 80, 112, 144, 176, 208, 240, 248, 256, 257, 264,
        ] {
            let mut altered = bytes.clone();
            altered[index] ^= 1;
            if [48, 64, 80, 112, 144, 176, 208, 240, 248].contains(&index) {
                // Some nonzero scalar changes are valid encodings; all other
                // structural and issued-state changes must fail.
                continue;
            }
            assert!(
                ChallengeRecordV1::decode(&key, &altered).is_err(),
                "index {index}"
            );
        }
        assert!(ChallengeRecordV1::decode(&key, &bytes[..bytes.len() - 1]).is_err());
        let mut oversized = bytes;
        oversized.push(0);
        assert!(ChallengeRecordV1::decode(&key, &oversized).is_err());
    }

    #[test]
    fn challenge_state_has_one_way_spent_encoding() {
        let issued = issued_record();
        assert!(issued.is_issued_now(100));
        assert!(issued.is_issued_now(159));
        assert!(!issued.is_issued_now(99));
        assert!(!issued.is_issued_now(160));
        let mut spent = issued;
        spent.state = SPENT;
        spent.receipt_digest = digest(9);
        assert_eq!(
            ChallengeRecordV1::decode(&key(spent.challenge.nonce), &spent.encode()).unwrap(),
            spent
        );
        let replayed =
            ChallengeRecordV1::decode(&key(spent.challenge.nonce), &spent.encode()).unwrap();
        assert!(!replayed.is_issued_now(120));

        let mut missing_receipt = spent;
        missing_receipt.receipt_digest = digest(0);
        assert!(
            ChallengeRecordV1::decode(&key(spent.challenge.nonce), &missing_receipt.encode())
                .is_err()
        );
        let mut premature_receipt = issued;
        premature_receipt.receipt_digest = digest(9);
        assert!(
            ChallengeRecordV1::decode(&key(issued.challenge.nonce), &premature_receipt.encode())
                .is_err()
        );
    }

    #[test]
    fn recovery_rejects_duplicate_attempt_and_old_format_records() {
        let first = issued_record();
        let mut second = first;
        second.challenge.nonce = [9; 32];
        let first_key = key(first.challenge.nonce);
        let second_key = key(second.challenge.nonce);
        let first_value = first.encode();
        let second_value = second.encode();
        assert!(validate_record_set([(first_key.as_slice(), first_value.as_slice())]).is_ok());
        assert!(
            validate_record_set([
                (first_key.as_slice(), first_value.as_slice()),
                (second_key.as_slice(), second_value.as_slice()),
            ])
            .is_err()
        );

        let mut old_key = first_key;
        old_key[..8].copy_from_slice(b"AOSZHK00");
        assert!(validate_record_set([(old_key.as_slice(), first_value.as_slice())]).is_err());
    }
}

impl ChallengeRecordV1 {
    pub(crate) fn spent_receipt(self) -> Option<ObjectDigest> {
        (self.state == SPENT).then_some(self.receipt_digest)
    }

    fn same_subject(self, other: Self) -> bool {
        let mut left = self;
        let mut right = other;
        left.state = ISSUED;
        right.state = ISSUED;
        left.receipt_digest = ObjectDigest::from_bytes([0; 32]);
        right.receipt_digest = ObjectDigest::from_bytes([0; 32]);
        left == right
    }

    pub(crate) fn matches_current(self, current: CurrentZfsHoldChallengeContextV1) -> bool {
        self.challenge.nonce == current.nonce
            && self.provider_id == current.provider_id
            && self.holder_id == current.holder_id
            && self.session_binding == current.session_binding
            && self.challenge.attempt_digest == current.attempt_digest
            && self.acquisition_id == current.acquisition_id
            && self.binding_digest == current.binding_digest
            && self.publication_head == current.publication_head
            && self.challenge.validity() == current.validity
    }

    fn is_issued_now(self, now: i64) -> bool {
        self.state == ISSUED
            && now >= self.challenge.issued_seconds
            && now < self.challenge.valid_until_seconds
    }

    pub(crate) fn new(
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        session_binding: ObjectDigest,
        attempt_digest: ObjectDigest,
        acquisition_id: ObjectDigest,
        binding_digest: ObjectDigest,
        publication_head: ObjectDigest,
        issued_seconds: i64,
        valid_until_seconds: i64,
    ) -> Self {
        Self {
            challenge: ProviderZfsHoldChallengeV1 {
                nonce: [0; 32],
                attempt_digest,
                issued_seconds,
                valid_until_seconds,
            },
            provider_id,
            holder_id,
            session_binding,
            acquisition_id,
            binding_digest,
            publication_head,
            state: ISSUED,
            receipt_digest: ObjectDigest::from_bytes([0; 32]),
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(VALUE_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.challenge.nonce);
        bytes.extend_from_slice(&self.provider_id);
        bytes.extend_from_slice(&self.holder_id);
        for digest in [
            self.session_binding,
            self.challenge.attempt_digest,
            self.acquisition_id,
            self.binding_digest,
            self.publication_head,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.challenge.issued_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.challenge.valid_until_seconds.to_be_bytes());
        bytes.push(self.state);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(self.receipt_digest.as_bytes());
        bytes
    }

    fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, ProviderLedgerError> {
        if key.len() != KEY_BYTES
            || key[..8] != *KEY_MAGIC
            || bytes.len() != RECORD_BYTES
            || bytes[..8] != *VALUE_MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..16] != [0; 6]
            || bytes[256 + 1..264] != [0; 7]
        {
            return Err(ProviderLedgerError::Corrupt(
                "native hold challenge encoding",
            ));
        }
        let record = Self {
            challenge: ProviderZfsHoldChallengeV1 {
                nonce: field(bytes, 16)?,
                attempt_digest: digest(bytes, 112)?,
                issued_seconds: i64::from_be_bytes(field(bytes, 240)?),
                valid_until_seconds: i64::from_be_bytes(field(bytes, 248)?),
            },
            provider_id: field(bytes, 48)?,
            holder_id: field(bytes, 64)?,
            session_binding: digest(bytes, 80)?,
            acquisition_id: digest(bytes, 144)?,
            binding_digest: digest(bytes, 176)?,
            publication_head: digest(bytes, 208)?,
            state: bytes[256],
            receipt_digest: digest(bytes, 264)?,
        };
        if key[8..] != record.challenge.nonce
            || record.challenge.nonce == [0; 32]
            || record.provider_id == [0; 16]
            || record.holder_id == [0; 16]
            || [
                record.session_binding,
                record.challenge.attempt_digest,
                record.acquisition_id,
                record.binding_digest,
                record.publication_head,
            ]
            .iter()
            .any(|value| value.as_bytes() == &[0; 32])
            || record.challenge.issued_seconds <= 0
            || record.challenge.valid_until_seconds <= record.challenge.issued_seconds
            || record.challenge.valid_until_seconds - record.challenge.issued_seconds
                > LIFETIME_SECONDS
            || !matches!(record.state, ISSUED | SPENT)
            || (record.state == ISSUED) != (record.receipt_digest.as_bytes() == &[0; 32])
            || record.encode() != bytes
        {
            return Err(ProviderLedgerError::Corrupt("native hold challenge fields"));
        }
        Ok(record)
    }
}

fn key(challenge: [u8; 32]) -> Vec<u8> {
    [KEY_MAGIC.as_slice(), challenge.as_slice()].concat()
}

fn field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], ProviderLedgerError> {
    bytes[start..start + N]
        .try_into()
        .map_err(|_| ProviderLedgerError::Corrupt("native hold challenge field"))
}

fn digest(bytes: &[u8], start: usize) -> Result<ObjectDigest, ProviderLedgerError> {
    Ok(ObjectDigest::from_bytes(field(bytes, start)?))
}

fn commit(
    authority: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
    location: ChallengeJournalLocationV1,
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), ProviderLedgerError> {
    let transaction = challenge_transaction(key, value)?;
    validate_location(location, authority)?;
    let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
    authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
    validate_location(location, authority)?;
    authority.commit(&transaction)?;
    Ok(())
}

fn challenge_transaction(
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<JournalTransaction, ProviderLedgerError> {
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_DOMAIN);
    hasher.update(&key);
    hasher.update(&value);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    Ok(JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            key,
            value,
        )],
    )?)
}

fn validate_location(
    location: ChallengeJournalLocationV1,
    authority: &aos_sandbox::ProtectedJournalAuthority<'_>,
) -> Result<(), ProviderLedgerError> {
    match location {
        ChallengeJournalLocationV1::Fixed => {
            authority.validate_fixed_source_provider_hold_challenge_storage()?
        }
        #[cfg(test)]
        ChallengeJournalLocationV1::Fixture => authority.validate_source_provider_authority()?,
    }
    Ok(())
}

pub(crate) fn current_seconds() -> Result<i64, ProviderLedgerError> {
    let seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if seconds <= 0 {
        Err(ProviderLedgerError::Unavailable)
    } else {
        Ok(seconds)
    }
}

pub(crate) fn expiry(issued_seconds: i64) -> Result<i64, ProviderLedgerError> {
    issued_seconds
        .checked_add(LIFETIME_SECONDS)
        .ok_or(ProviderLedgerError::Unavailable)
}

fn random_nonce() -> Result<[u8; 32], ProviderLedgerError> {
    let mut nonce = [0; 32];
    let mut offset = 0;
    let mut interruptions = 0;
    while offset < nonce.len() {
        match rustix::rand::getrandom(&mut nonce[offset..], GetRandomFlags::empty()) {
            Ok(0) => return Err(ProviderLedgerError::Unavailable),
            Ok(written) if written <= nonce.len() - offset => offset += written,
            Ok(_) => return Err(ProviderLedgerError::Unavailable),
            Err(rustix::io::Errno::INTR) if interruptions < 8 => interruptions += 1,
            Err(_) => return Err(ProviderLedgerError::Unavailable),
        }
    }
    if nonce == [0; 32] {
        Err(ProviderLedgerError::Unavailable)
    } else {
        Ok(nonce)
    }
}

const fn limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 2 * 1024 * 1024,
        maximum_record_bytes: 512,
        maximum_key_bytes: KEY_BYTES,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 1024,
        maximum_transactions: MAXIMUM_CHALLENGES * 2,
        maximum_materialized_bytes: MAXIMUM_CHALLENGES * (KEY_BYTES + RECORD_BYTES),
        maximum_materialized_records: MAXIMUM_CHALLENGES,
    }
}
