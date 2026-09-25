//! Durable Cache policy-state freeze for an inert Create binding cut.
//!
//! ```text
//! AOSCPH01 | version:u16 | phase:held|released | reserved:5 |
//! project:16 | partition:32 | cache-head:32 | binding:32 | epoch:u64 |
//! SHA-256(Cache-hold-domain || preceding 136 bytes):32
//! ```
//!
//! A separate protected journal lets Cache state and manifest commits hold its
//! writer lock through sync. The Cache clock may still advance its monotone
//! floor; it cannot change quota, domain, or replay head.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction,
    ReadOnlyProtectedJournal, RecordNamespace,
};

pub(crate) const NAME: &str = "policy-hold.journal";
const GENESIS_KEY: &[u8] = b"\0aos-cache-policy-hold-genesis-v1\0";
const HOLD_KEY: &[u8] = b"\0aos-cache-policy-hold-v1\0";
const GENESIS: &[u8] = b"AOSCPG01";
const MAGIC: &[u8; 8] = b"AOSCPH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-hold.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-hold-transaction.v1\0";
const RECORD_BYTES: usize = 168;

fn hold_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 16 * 1024 * 1024,
        maximum_record_bytes: 512,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 1024,
        maximum_transactions: 50_000,
        maximum_materialized_bytes: 1024,
        maximum_materialized_records: 2,
    }
}

/// Identifies one exact, nonauthorizing protected Cache policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePolicyHoldV1 {
    project: ProjectId,
    partition: ObjectDigest,
    cache_head: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl CachePolicyHoldV1 {
    /// Constructs the exact Cache cut to freeze before root submission.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities and a zero epoch.
    pub fn new(
        project: ProjectId,
        partition: ObjectDigest,
        cache_head: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, JournalError> {
        let hold = Self {
            project,
            partition,
            cache_head,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the held project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the held physical partition digest.
    #[must_use]
    pub const fn partition(self) -> ObjectDigest {
        self.partition
    }

    /// Returns the exact protected Cache replay head.
    #[must_use]
    pub const fn cache_head(self) -> ObjectDigest {
        self.cache_head
    }

    /// Returns the proposed root binding digest.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the proposed root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether Cache policy state remains frozen.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    fn validate(self) -> Result<(), JournalError> {
        if self.project.as_bytes() == &[0; 16]
            || self.partition.as_bytes() == &[0; 32]
            || self.cache_head.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(self.project.as_bytes());
        bytes[32..64].copy_from_slice(self.partition.as_bytes());
        bytes[64..96].copy_from_slice(self.cache_head.as_bytes());
        bytes[96..128].copy_from_slice(self.binding.as_bytes());
        bytes[128..136].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..136])
            .finalize();
        bytes[136..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let hold = Self {
            project: ProjectId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            partition: ObjectDigest::from_bytes(
                bytes[32..64]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            cache_head: ObjectDigest::from_bytes(
                bytes[64..96]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[96..128]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[128..136]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(hold)
    }
}

fn transaction(key: &[u8], value: &[u8]) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(key)
        .chain_update(value)
        .finalize();
    JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            key.to_vec(),
            value.to_vec(),
        )],
    )
}

fn current(journal: &mut Journal) -> Result<Option<CachePolicyHoldV1>, JournalError> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let mut records = authority.records()?;
    if records.next() != Some((GENESIS_KEY, GENESIS)) {
        return Err(JournalError::ProtectedBoundary);
    }
    let held = match records.next() {
        Some((HOLD_KEY, value)) => Some(CachePolicyHoldV1::decode(value)?),
        Some(_) => return Err(JournalError::ProtectedBoundary),
        None => None,
    };
    if records.next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(held)
}

impl ReadOnlyProtectedJournal {
    /// Returns only an active, canonical hold from the fixed read-only name.
    pub(crate) fn held_cache_policy_hold(&mut self) -> Result<CachePolicyHoldV1, JournalError> {
        if self.witness.name != NAME {
            return Err(JournalError::ProtectedBoundary);
        }
        current(&mut self.journal)?
            .filter(|hold| hold.is_held())
            .ok_or(JournalError::ProtectedBoundary)
    }
}

impl Journal {
    /// Reads an active Cache hold while retaining its protected writer lock.
    ///
    /// # Errors
    ///
    /// Rejects a foreign name, released or malformed hold, or lost named custody.
    pub(crate) fn held_cache_policy_hold_for_writer(
        &mut self,
    ) -> Result<CachePolicyHoldV1, JournalError> {
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.name != NAME {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_protected_names_current()?;
        current(self)?
            .filter(|hold| hold.is_held())
            .ok_or(JournalError::ProtectedBoundary)
    }
}

fn open(directory: &Path, uid: u32) -> Result<Journal, JournalError> {
    #[cfg(test)]
    let opened = Journal::open_protected_at_uid(directory, NAME, hold_limits(), uid);
    #[cfg(not(test))]
    let opened = Journal::open_protected_at_for_uid(directory, NAME, hold_limits(), uid);
    opened.map(|(journal, _)| journal)
}

pub(crate) fn initialize_fresh(directory: &Path, uid: u32) -> Result<(), JournalError> {
    let hold_path = directory.join(NAME);
    let existing = match fs::symlink_metadata(&hold_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(JournalError::Io(error)),
    };
    if !existing {
        for name in ["state.journal", "authority.journal", "clock.journal"] {
            for suffix in ["", ".lock", ".compact.tmp"] {
                match fs::symlink_metadata(directory.join(format!("{name}{suffix}"))) {
                    Ok(_) => return Err(JournalError::ProtectedBoundary),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(JournalError::Io(error)),
                }
            }
        }
    }
    let mut journal = open(directory, uid)?;
    if journal.all_records().next().is_none() && !existing {
        journal.commit(&transaction(GENESIS_KEY, GENESIS)?)?;
    }
    current(&mut journal)?;
    Ok(())
}

pub(super) fn check_unheld(journal: &Journal) -> Result<(), JournalError> {
    let _guard = mutation_guard(journal)?;
    Ok(())
}

pub(super) fn mutation_guard(journal: &Journal) -> Result<Option<Journal>, JournalError> {
    let Some((directory, uid)) = &journal.cache_policy_gate else {
        return Ok(None);
    };
    #[cfg(not(test))]
    journal.require_protected_location(
        directory,
        &journal
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .name,
        *uid,
        journal.limits,
    )?;
    let mut hold = open(directory, *uid)?;
    if current(&mut hold)?.is_some_and(CachePolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(Some(hold))
}

impl Journal {
    /// Returns the fixed replay bounds for the protected Cache hold name.
    pub(crate) fn cache_policy_hold_limits() -> JournalLimits {
        hold_limits()
    }

    pub(crate) fn initialize_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        initialize_fresh(directory, uid)
    }

    pub(crate) fn enable_cache_policy_hold_gate(
        &mut self,
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.expected_uid != uid
            || !matches!(
                location.name.as_str(),
                "state.journal" | "authority.journal"
            )
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cache_policy_gate = Some((PathBuf::from(directory), uid));
        Ok(())
    }

    pub(crate) fn read_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<Option<CachePolicyHoldV1>, JournalError> {
        current(&mut open(directory, uid)?)
    }

    pub(crate) fn acquire_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
        hold: CachePolicyHoldV1,
    ) -> Result<(), JournalError> {
        if !hold.held {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut journal = open(directory, uid)?;
        if current(&mut journal)?.is_some_and(CachePolicyHoldV1::is_held) {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(HOLD_KEY, &hold.encode()?)?;
        let release = transaction(
            HOLD_KEY,
            &CachePolicyHoldV1 {
                held: false,
                ..hold
            }
            .encode()?,
        )?;
        journal.preflight_transactions(&[acquire.clone(), release])?;
        journal.commit(&acquire)?;
        if current(&mut journal)? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn release_cache_policy_hold_if_at<E>(
        directory: &Path,
        uid: u32,
        expected: CachePolicyHoldV1,
        verify_root: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<JournalError>,
    {
        let mut journal = open(directory, uid)?;
        if !expected.held || current(&mut journal)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // No state or manifest writer can cross this check: each commit must
        // borrow this same hold-journal lock until its durable sync completes.
        verify_root()?;
        let released = CachePolicyHoldV1 {
            held: false,
            ..expected
        };
        journal.commit(&transaction(HOLD_KEY, &released.encode()?)?)?;
        if current(&mut journal)? != Some(released) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn fixture() -> (tempfile::TempDir, u32) {
        let directory = tempfile::tempdir().expect("private Cache fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let uid = fs::metadata(directory.path())
            .expect("directory metadata")
            .uid();
        (directory, uid)
    }

    fn open_gated(directory: &Path, uid: u32, name: &str) -> Journal {
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory, name, JournalLimits::default(), uid)
                .expect("protected Cache journal");
        journal
            .enable_cache_policy_hold_gate(directory, uid)
            .expect("Cache gate");
        journal
    }

    fn put(id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![id],
                vec![id],
            )],
        )
        .expect("test transaction")
    }

    fn hold() -> CachePolicyHoldV1 {
        CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("Cache hold")
    }

    #[test]
    fn held_cache_cuts_survive_reopen_and_fence_state_and_manifest_writes() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh hold genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let mut authority = open_gated(directory.path(), uid, "authority.journal");
        state.commit(&put(10)).expect("state before hold");

        Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold())
            .expect("durable Cache freeze");
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).unwrap(),
            Some(hold())
        );
        assert!(matches!(
            state.commit(&put(11)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            authority.commit(&put(12)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            state.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            authority.preflight_transactions(&[put(13)]),
            Err(JournalError::ProtectedBoundary)
        ));
        drop(state);
        drop(authority);

        let mut reopened = open_gated(directory.path(), uid, "state.journal");
        assert!(matches!(
            reopened.commit(&put(14)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(Journal::acquire_cache_policy_hold_at(directory.path(), uid, hold()).is_err());
        assert!(
            Journal::release_cache_policy_hold_if_at::<JournalError>(
                directory.path(),
                uid,
                hold(),
                || Err(JournalError::ProtectedBoundary)
            )
            .is_err()
        );
        assert_eq!(
            Journal::read_cache_policy_hold_at(directory.path(), uid).unwrap(),
            Some(hold())
        );

        let wrong = CachePolicyHoldV1::new(
            hold().project(),
            hold().partition(),
            hold().cache_head(),
            ObjectDigest::from_bytes([9; 32]),
            hold().epoch(),
        )
        .expect("different root binding");
        assert!(
            Journal::release_cache_policy_hold_if_at::<JournalError>(
                directory.path(),
                uid,
                wrong,
                || Ok(())
            )
            .is_err()
        );
        Journal::release_cache_policy_hold_if_at::<JournalError>(
            directory.path(),
            uid,
            hold(),
            || Ok(()),
        )
        .expect("exact cold release");
        reopened.commit(&put(15)).expect("state after release");
        assert!(
            !Journal::read_cache_policy_hold_at(directory.path(), uid)
                .unwrap()
                .expect("released record")
                .is_held()
        );
    }

    #[test]
    fn missing_hold_custody_never_reinitializes_existing_cache() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        state.commit(&put(20)).expect("Cache history");
        drop(state);
        fs::remove_file(directory.path().join(NAME)).expect("remove fixture hold");

        assert!(matches!(
            initialize_fresh(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            open_gated(directory.path(), uid, "state.journal").commit(&put(21)),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn malformed_hold_custody_fails_before_any_cache_mutation() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let mut hold_journal = open(directory.path(), uid).expect("hold journal");
        hold_journal
            .commit(&transaction(HOLD_KEY, b"invalid").expect("malformed transaction"))
            .expect("fixture corruption");
        drop(hold_journal);

        assert!(matches!(
            state.commit(&put(22)),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            initialize_fresh(directory.path(), uid),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn cache_commit_waits_for_the_same_lock_used_by_freeze() {
        let (directory, uid) = fixture();
        initialize_fresh(directory.path(), uid).expect("fresh genesis");
        let mut state = open_gated(directory.path(), uid, "state.journal");
        let hold_writer = open(directory.path(), uid).expect("held freeze lock");

        assert!(matches!(
            state.commit(&put(30)),
            Err(JournalError::AlreadyLocked)
        ));
        drop(hold_writer);
        state
            .commit(&put(30))
            .expect("commit after freeze lock release");
    }
}
