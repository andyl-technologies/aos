//! Durable, exact replay fence for inspected LocalLive export plans.
//!
//! ```text
//! journal key: provider-authority-id[16] | provider-generation:u64be |
//!              plan-id[16]
//! journal value: AOSSLR01 | version:u16be=1 | reserved[6]=0 |
//!                signed-plan-digest[32] | physical-readback-digest[32]
//! ```
//!
//! Only a private Storage readback can be recorded. This journal holds no
//! lease or effect state: it fences exact retries across process death while
//! independent kernel clone/grant authority is still absent. A replay must
//! repeat both the signed plan and the physical observation; changed current
//! state fails closed instead of silently replacing the recorded origin. The
//! journal is written only under Storage's protected state root; historical
//! authority-side history must be explicitly migrated, not ignored.

use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::live_export_key::{open_protected_directory, reject_legacy_authority_journal};
use crate::live_export_request_readback::StorageLiveExportReadbackV1;

const JOURNAL_FILE: &str = "storage-live-export-plan-replay.journal";
const MAGIC: &[u8; 8] = b"AOSSLR01";
const VERSION: u16 = 1;
const KEY_BYTES: usize = 40;
const VALUE_BYTES: usize = 80;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-plan-replay.v1\0";

/// Reports conflicting identity or failed protected journal custody.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageLiveExportReplayErrorV1 {
    /// The same Provider-scoped plan ID named different signed or physical bytes.
    #[error("Storage live-export plan replay conflicts with protected history")]
    Conflict,
    /// A protected replay record is malformed or a postcommit readback differs.
    #[error("Storage live-export replay journal is noncanonical")]
    Noncanonical,
    /// The protected journal could not be opened, replayed, or committed.
    #[error("Storage live-export replay journal failed: {0}")]
    Journal(#[from] JournalError),
    /// The immutable authority directory could not be safely pinned.
    #[error("Storage live-export authority custody is unsafe")]
    AuthorityCustody,
    /// A historical journal still exists under immutable authority custody.
    #[error("Storage live-export legacy replay history requires explicit migration")]
    LegacyAuthorityHistory,
}

/// Classifies one exact protected replay without authorizing an export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageLiveExportReplayOutcomeV1 {
    /// A new inspected plan was durably fenced.
    Recorded,
    /// The exact signed plan and physical observation already have a fence.
    ExactReplay,
}

/// Owns the protected append-only plan replay journal.
pub(crate) struct StorageLiveExportReplayLedgerV1 {
    journal: Journal,
}

impl StorageLiveExportReplayLedgerV1 {
    /// Reopens replay state under Storage's protected writable state root.
    ///
    /// Recovery accepts only the journal's validated durable prefix. A partial
    /// trailing frame can be retried with the same identity and signed bytes;
    /// an ambiguous in-process commit requires dropping this owner and reopen.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unsafe authority custody, legacy history,
    /// or protected state-journal locking, replay, and bounds failures.
    pub(crate) fn open_root_owned(
        authority_directory: &Path,
        state_directory: &Path,
    ) -> Result<Self, StorageLiveExportReplayErrorV1> {
        let authority = open_protected_directory(authority_directory, 0)
            .map_err(|_| StorageLiveExportReplayErrorV1::AuthorityCustody)?;
        reject_legacy_authority_journal(authority.as_fd(), JOURNAL_FILE)
            .map_err(|_| StorageLiveExportReplayErrorV1::LegacyAuthorityHistory)?;
        let journal =
            Journal::open_protected_at(state_directory, JOURNAL_FILE, journal_limits())?.0;
        Ok(Self { journal })
    }

    /// Fences one signed plan and physical readback before any response.
    ///
    /// The argument is constructible only after independent pinned signatures,
    /// current Storage publication, and physical origin checks succeed. It is
    /// still non-authorizing: Provider's current selected-row proof and an
    /// enforcing KernelExportGrant are separate prerequisites.
    ///
    /// # Errors
    ///
    /// Returns a conflict for changed bytes under one plan identity, or a
    /// journal error for an unsafe or ambiguous durable transition.
    pub(crate) fn record(
        &mut self,
        readback: &StorageLiveExportReadbackV1,
    ) -> Result<StorageLiveExportReplayOutcomeV1, StorageLiveExportReplayErrorV1> {
        let (provider_id, provider_generation, plan_id) = readback.replay_identity();
        self.record_exact(
            provider_id,
            provider_generation,
            plan_id,
            readback.signed_request_digest(),
            readback.digest(),
        )
    }

    fn record_exact(
        &mut self,
        provider_id: [u8; 16],
        provider_generation: u64,
        plan_id: [u8; 16],
        signed_plan_digest: ObjectDigest,
        readback_digest: ObjectDigest,
    ) -> Result<StorageLiveExportReplayOutcomeV1, StorageLiveExportReplayErrorV1> {
        let key = replay_key(provider_id, provider_generation, plan_id)?;
        let value = replay_value(signed_plan_digest, readback_digest)?;
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::AuthorityPublication)?;
        if let Some(outcome) = classify_replay(authority.get(&key)?, value)? {
            return Ok(outcome);
        }

        authority.commit(&replay_transaction(key, value)?)?;
        if authority.get(&key)? != Some(value.as_slice()) {
            return Err(StorageLiveExportReplayErrorV1::Noncanonical);
        }
        Ok(StorageLiveExportReplayOutcomeV1::Recorded)
    }
}

fn classify_replay(
    previous: Option<&[u8]>,
    value: [u8; VALUE_BYTES],
) -> Result<Option<StorageLiveExportReplayOutcomeV1>, StorageLiveExportReplayErrorV1> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    if parse_value(previous)? == value {
        Ok(Some(StorageLiveExportReplayOutcomeV1::ExactReplay))
    } else {
        Err(StorageLiveExportReplayErrorV1::Conflict)
    }
}

fn replay_transaction(
    key: [u8; KEY_BYTES],
    value: [u8; VALUE_BYTES],
) -> Result<JournalTransaction, StorageLiveExportReplayErrorV1> {
    let hash = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(key)
        .chain_update(value)
        .finalize();
    let transaction_id: [u8; 16] = hash[..16]
        .try_into()
        .map_err(|_| StorageLiveExportReplayErrorV1::Noncanonical)?;
    Ok(JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::AuthorityPublication,
            key.to_vec(),
            value.to_vec(),
        )],
    )?)
}

fn replay_key(
    provider_id: [u8; 16],
    provider_generation: u64,
    plan_id: [u8; 16],
) -> Result<[u8; KEY_BYTES], StorageLiveExportReplayErrorV1> {
    if provider_id == [0; 16] || provider_generation == 0 || plan_id == [0; 16] {
        return Err(StorageLiveExportReplayErrorV1::Noncanonical);
    }
    let mut key = [0; KEY_BYTES];
    key[..16].copy_from_slice(&provider_id);
    key[16..24].copy_from_slice(&provider_generation.to_be_bytes());
    key[24..40].copy_from_slice(&plan_id);
    Ok(key)
}

fn replay_value(
    signed_plan_digest: ObjectDigest,
    readback_digest: ObjectDigest,
) -> Result<[u8; VALUE_BYTES], StorageLiveExportReplayErrorV1> {
    if signed_plan_digest.as_bytes() == &[0; 32] || readback_digest.as_bytes() == &[0; 32] {
        return Err(StorageLiveExportReplayErrorV1::Noncanonical);
    }
    let mut value = [0; VALUE_BYTES];
    value[..8].copy_from_slice(MAGIC);
    value[8..10].copy_from_slice(&VERSION.to_be_bytes());
    value[16..48].copy_from_slice(signed_plan_digest.as_bytes());
    value[48..80].copy_from_slice(readback_digest.as_bytes());
    Ok(value)
}

fn parse_value(bytes: &[u8]) -> Result<[u8; VALUE_BYTES], StorageLiveExportReplayErrorV1> {
    let value: [u8; VALUE_BYTES] = bytes
        .try_into()
        .map_err(|_| StorageLiveExportReplayErrorV1::Noncanonical)?;
    if &value[..8] != MAGIC
        || value[8..10] != VERSION.to_be_bytes()
        || value[10..16] != [0; 6]
        || value[16..48] == [0; 32]
        || value[48..80] == [0; 32]
    {
        return Err(StorageLiveExportReplayErrorV1::Noncanonical);
    }
    Ok(value)
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 256,
        maximum_key_bytes: KEY_BYTES,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 512,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: 8 * 1024 * 1024,
        maximum_materialized_records: 65_536,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn open_test_journal(directory: &Path) -> Journal {
        Journal::open(directory.join(JOURNAL_FILE), journal_limits())
            .unwrap()
            .0
    }

    fn record_test(
        journal: &mut Journal,
        provider_id: [u8; 16],
        provider_generation: u64,
        plan_id: [u8; 16],
        signed_plan_digest: ObjectDigest,
        readback_digest: ObjectDigest,
    ) -> Result<StorageLiveExportReplayOutcomeV1, StorageLiveExportReplayErrorV1> {
        // The journal crate tests the protected opener itself. This fixture
        // exercises the identical replay codec/transaction and crash prefix
        // without requiring a root-owned ancestry in the test sandbox.
        let key = replay_key(provider_id, provider_generation, plan_id)?;
        let value = replay_value(signed_plan_digest, readback_digest)?;
        if let Some(outcome) = classify_replay(
            journal.get(RecordNamespace::AuthorityPublication, &key),
            value,
        )? {
            return Ok(outcome);
        }
        journal.commit(&replay_transaction(key, value)?)?;
        Ok(StorageLiveExportReplayOutcomeV1::Recorded)
    }

    #[test]
    fn replay_survives_restart_and_rejects_changed_signed_or_physical_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = open_test_journal(directory.path());
        let identity = ([1; 16], 2, [3; 16]);
        assert!(matches!(
            record_test(
                &mut journal,
                identity.0,
                identity.1,
                identity.2,
                digest(4),
                digest(5)
            ),
            Ok(StorageLiveExportReplayOutcomeV1::Recorded)
        ));
        drop(journal);

        let mut reopened = open_test_journal(directory.path());
        assert!(matches!(
            record_test(
                &mut reopened,
                identity.0,
                identity.1,
                identity.2,
                digest(4),
                digest(5)
            ),
            Ok(StorageLiveExportReplayOutcomeV1::ExactReplay)
        ));
        assert!(matches!(
            record_test(
                &mut reopened,
                identity.0,
                identity.1,
                identity.2,
                digest(6),
                digest(5)
            ),
            Err(StorageLiveExportReplayErrorV1::Conflict)
        ));
        assert!(matches!(
            record_test(
                &mut reopened,
                identity.0,
                identity.1,
                identity.2,
                digest(4),
                digest(6)
            ),
            Err(StorageLiveExportReplayErrorV1::Conflict)
        ));
    }

    #[test]
    fn torn_tail_reopens_exact_durable_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = open_test_journal(directory.path());
        record_test(&mut journal, [7; 16], 8, [9; 16], digest(10), digest(11)).unwrap();
        drop(journal);

        let path = directory.path().join(JOURNAL_FILE);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0xA0, 0x53, 0x17]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut reopened = open_test_journal(directory.path());
        assert!(matches!(
            record_test(&mut reopened, [7; 16], 8, [9; 16], digest(10), digest(11)),
            Ok(StorageLiveExportReplayOutcomeV1::ExactReplay)
        ));
    }

    #[test]
    fn replay_wire_rejects_sentinels_and_noncanonical_records() {
        assert!(replay_key([0; 16], 1, [2; 16]).is_err());
        assert!(replay_key([1; 16], 0, [2; 16]).is_err());
        assert!(replay_key([1; 16], 1, [0; 16]).is_err());
        assert!(replay_value(digest(1), digest(0)).is_err());

        let canonical = replay_value(digest(1), digest(2)).unwrap();
        assert!(matches!(parse_value(&canonical), Ok(value) if value == canonical));
        for (index, value) in [(0, 0), (9, 2), (10, 1)] {
            let mut changed = canonical;
            changed[index] = value;
            assert!(parse_value(&changed).is_err(), "changed byte {index}");
        }
        let mut zero_signed_digest = canonical;
        zero_signed_digest[16..48].fill(0);
        assert!(parse_value(&zero_signed_digest).is_err());
        let mut zero_readback_digest = canonical;
        zero_readback_digest[48..80].fill(0);
        assert!(parse_value(&zero_readback_digest).is_err());
        assert!(parse_value(&canonical[..VALUE_BYTES - 1]).is_err());
    }
}
