//! Durable, bounded replay exclusion for native Storage hold observations.
//!
//! This dedicated protected journal is opened after the Provider ledger, so
//! every operation holds locks in ledger-then-challenge order. It retains one
//! immutable key per attempt, including spent and expired challenges. Losing
//! the live holder session across reboot makes a retained challenge unusable.
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

use std::collections::BTreeSet;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
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

pub(crate) struct ProtectedZfsHoldChallengesV1 {
    journal: Journal,
}

impl ProtectedZfsHoldChallengesV1 {
    pub(crate) fn open_fixed() -> Result<Self, ProviderLedgerError> {
        let (journal, _) = Journal::open_protected_at(Path::new(ROOT), FILE, limits())?;
        let mut owner = Self { journal };
        owner.validate_records()?;
        Ok(owner)
    }

    pub(crate) fn issue(
        &mut self,
        mut record: ChallengeRecordV1,
    ) -> Result<ProviderZfsHoldChallengeV1, ProviderLedgerError> {
        let (count, attempts) = self.validate_records()?;
        if count >= MAXIMUM_CHALLENGES {
            return Err(ProviderLedgerError::LimitExceeded("native hold challenges"));
        }
        if attempts.contains(&(
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
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        authority.validate_fixed_source_provider_hold_challenge_storage()?;
        if authority.get(&key)?.is_some() {
            return Err(ProviderLedgerError::Equivocation);
        }
        commit(&mut authority, key.clone(), value)?;
        let retained = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if ChallengeRecordV1::decode(&key, retained)? != record {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        Ok(record.challenge)
    }

    pub(crate) fn issued_for(
        &mut self,
        challenge: [u8; 32],
    ) -> Result<ChallengeRecordV1, ProviderLedgerError> {
        self.validate_records()?;
        let key = key(challenge);
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        authority.validate_fixed_source_provider_hold_challenge_storage()?;
        let value = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::Unavailable)?;
        let record = ChallengeRecordV1::decode(&key, value)?;
        let now = current_seconds()?;
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
        let actual = self.issued_for(expected.challenge.nonce)?;
        if actual != expected {
            return Err(ProviderLedgerError::Equivocation);
        }
        let mut spent = actual;
        spent.state = SPENT;
        spent.receipt_digest = receipt_digest;
        let key = key(spent.challenge.nonce);
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        authority.validate_fixed_source_provider_hold_challenge_storage()?;
        commit(&mut authority, key.clone(), spent.encode())?;
        let retained = authority
            .get(&key)?
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if ChallengeRecordV1::decode(&key, retained)? != spent {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        Ok(())
    }

    fn validate_records(
        &mut self,
    ) -> Result<(usize, BTreeSet<([u8; 16], [u8; 16], ObjectDigest)>), ProviderLedgerError> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        authority.validate_fixed_source_provider_hold_challenge_storage()?;
        validate_record_set(authority.records()?)
    }
}

fn validate_record_set<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(usize, BTreeSet<([u8; 16], [u8; 16], ObjectDigest)>), ProviderLedgerError> {
    let mut attempts = BTreeSet::new();
    let mut count = 0;
    for (key, value) in records {
        count += 1;
        if count > MAXIMUM_CHALLENGES {
            return Err(ProviderLedgerError::LimitExceeded("native hold challenges"));
        }
        let record = ChallengeRecordV1::decode(key, value)?;
        if !attempts.insert((
            record.provider_id,
            record.holder_id,
            record.challenge.attempt_digest,
        )) {
            return Err(ProviderLedgerError::Corrupt(
                "duplicate native hold challenge attempt",
            ));
        }
    }
    Ok((count, attempts))
}

#[cfg(test)]
mod tests {
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
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<(), ProviderLedgerError> {
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_DOMAIN);
    hasher.update(&key);
    hasher.update(&value);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            key,
            value,
        )],
    )?;
    authority.validate_fixed_source_provider_hold_challenge_storage()?;
    let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
    authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
    authority.validate_fixed_source_provider_hold_challenge_storage()?;
    authority.commit(&transaction)?;
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
