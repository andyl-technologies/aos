//! Durable Source-writer challenge custody for a held Q04 signer flight.
//!
//! ```text
//! AOSSCW01 | version:u16=1 | reserved[6]=0 | issue:u64 |
//! Root nonce[16] | Root cut[32] | project[16] | held Source record digest[32] |
//! directory, journal, lock (device:u64, inode:u64 each) |
//! SHA-256(Source challenge domain || preceding 168 bytes)[32]
//! ```
//!
//! Controller writes this row only through its retained Source writer. The
//! read-only signer independently replays it; Root must later prove it spent
//! the challenge under its last-acquired writer. A row alone authorizes nothing.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalNamesV1,
    RecordNamespace, SourceDomainPolicyHoldV1, source_domain_policy_hold,
};

const KEY: &[u8] = b"\0aos-source-domain-root-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSSCW01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-domain-root-challenge.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-domain-root-challenge-transaction.v1\0";
const RECORD_BYTES: usize = 200;

/// Retains one Root challenge spent in the held Source writer journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainChallengeV1 {
    issue: u64,
    nonce: [u8; 16],
    cut: ObjectDigest,
    project: ProjectId,
    hold: ObjectDigest,
    names: ProtectedJournalNamesV1,
}

impl SourceDomainChallengeV1 {
    /// Returns this Source journal's monotone challenge issue number.
    #[must_use]
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the exact Root challenge nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the exact Root cut.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }

    /// Returns the held project whose ancestry the signer must replay.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the digest of the current held Source record.
    #[must_use]
    pub const fn hold(self) -> ObjectDigest {
        self.hold
    }

    /// Returns the directory, journal, and lock identities named by the writer.
    #[must_use]
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the digest of the exact canonical challenge record.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.encode()).into())
    }

    /// Compares the row to the signer's independently replayed held Source cut.
    ///
    /// # Errors
    ///
    /// Rejects an invalid held Source record.
    pub fn matches_current(
        self,
        nonce: [u8; 16],
        cut: ObjectDigest,
        project: ProjectId,
        hold: SourceDomainPolicyHoldV1,
        names: ProtectedJournalNamesV1,
    ) -> Result<bool, JournalError> {
        Ok(self.nonce == nonce
            && self.cut == cut
            && self.project == project
            && self.hold == hold.record_digest()?
            && self.names == names
            && hold.is_held())
    }

    fn encode(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..40].copy_from_slice(&self.nonce);
        bytes[40..72].copy_from_slice(self.cut.as_bytes());
        bytes[72..88].copy_from_slice(self.project.as_bytes());
        bytes[88..120].copy_from_slice(self.hold.as_bytes());
        bytes[120..168].copy_from_slice(&self.names.to_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..168])
            .finalize();
        bytes[168..].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
            || bytes[168..]
                != Sha256::new()
                    .chain_update(CHECKSUM_DOMAIN)
                    .chain_update(&bytes[..168])
                    .finalize()[..]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let row = Self {
            issue: u64::from_be_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            nonce: bytes[24..40]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            cut: ObjectDigest::from_bytes(
                bytes[40..72]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            project: ProjectId::from_bytes(
                bytes[72..88]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            hold: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            names: ProtectedJournalNamesV1::from_bytes(&bytes[120..168])?,
        };
        if row.issue == 0
            || row.nonce == [0; 16]
            || row.cut.as_bytes() == &[0; 32]
            || row.project.as_bytes() == &[0; 16]
            || row.hold.as_bytes() == &[0; 32]
            || row.encode().as_slice() != bytes
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }
}

/// Replays only the challenge row; callers establish protected writer or
/// read-only signer-view custody before relying on it.
pub(crate) fn replay_source_domain_challenge_v1(
    journal: &Journal,
) -> Result<Option<SourceDomainChallengeV1>, JournalError> {
    journal
        .get(RecordNamespace::DesiredState, KEY)
        .map(SourceDomainChallengeV1::decode)
        .transpose()
}

impl Journal {
    /// Spends one Root challenge under the retained fixed Source writer.
    ///
    /// Only this exact row can bypass the held Source journal mutation fence.
    /// It remains nonauthorizing until Root and Controller join the same
    /// writer, signed read-only view, and CAS/postflight.
    ///
    /// # Errors
    ///
    /// Rejects a foreign or stale writer, released hold, the current row's nonce,
    /// substituted names, exhausted issue counter, or failed durability.
    pub(crate) fn record_source_domain_challenge_v1(
        &mut self,
        expected_hold: SourceDomainPolicyHoldV1,
        project: ProjectId,
        nonce: [u8; 16],
        cut: ObjectDigest,
        names: ProtectedJournalNamesV1,
    ) -> Result<SourceDomainChallengeV1, JournalError> {
        source_domain_policy_hold::ensure_source_domain(self)?;
        if !expected_hold.is_held()
            || self.source_domain_policy_hold_v1()? != Some(expected_hold)
            || project.as_bytes() == &[0; 16]
            || nonce == [0; 16]
            || cut.as_bytes() == &[0; 32]
            || self.protected_writer_physical_names_v1()? != names
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let prior = replay_source_domain_challenge_v1(self)?;
        if prior.is_some_and(|row| row.nonce == nonce) {
            return Err(JournalError::ProtectedBoundary);
        }
        let issue = prior
            .map_or(Some(1), |row| row.issue.checked_add(1))
            .ok_or(JournalError::ProtectedBoundary)?;
        let row = SourceDomainChallengeV1 {
            issue,
            nonce,
            cut,
            project,
            hold: expected_hold.record_digest()?,
            names,
        };
        let bytes = row.encode();
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(bytes)
            .finalize();
        let id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let transaction = JournalTransaction::new(
            id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                KEY.to_vec(),
                bytes.to_vec(),
            )],
        )?;
        let release = source_domain_policy_hold::release_transaction(expected_hold)?;
        self.preflight_transactions_with_capacity_scope(
            &[transaction.clone(), release],
            None,
            false,
            true,
        )?;
        self.commit_with_capacity_scope(&transaction, None, false, true)?;
        if replay_source_domain_challenge_v1(self)? != Some(row)
            || self.protected_writer_physical_names_v1()? != names
            || self.source_domain_policy_hold_v1()? != Some(expected_hold)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::{OperationId, SandboxId};

    use super::*;
    use crate::lifecycle::protected_journal_join::source_domain_journal_limits;

    #[test]
    fn held_source_challenge_survives_reopen_and_rejects_replay_or_replaced_names() {
        let directory = tempfile::tempdir().expect("protected Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let name = "source-domains-v1.journal";
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("Source writer");
        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
        )
        .expect("held Source");
        writer
            .acquire_source_domain_policy_hold_v1(hold)
            .expect("hold");
        let foreign = JournalTransaction::new(
            [20; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"foreign".to_vec(),
                vec![1],
            )],
        )
        .expect("foreign transaction");
        assert!(writer.commit(&foreign).is_err());
        let names = writer.protected_writer_physical_names_v1().expect("names");
        let project = ProjectId::from_bytes([7; 16]);
        let cut = ObjectDigest::from_bytes([8; 32]);
        let first = writer
            .record_source_domain_challenge_v1(hold, project, [9; 16], cut, names)
            .expect("first challenge");
        assert_eq!(first.issue(), 1);
        assert!(
            first
                .matches_current([9; 16], cut, project, hold, names)
                .unwrap()
        );
        assert!(
            !first
                .matches_current([10; 16], cut, project, hold, names)
                .unwrap()
        );
        assert!(
            !first
                .matches_current(
                    [9; 16],
                    ObjectDigest::from_bytes([11; 32]),
                    project,
                    hold,
                    names,
                )
                .unwrap()
        );
        assert!(
            !first
                .matches_current([9; 16], cut, ProjectId::from_bytes([12; 16]), hold, names,)
                .unwrap()
        );
        assert!(
            !first
                .matches_current(
                    [9; 16],
                    cut,
                    project,
                    SourceDomainPolicyHoldV1::new(
                        hold.operation(),
                        hold.sandbox(),
                        hold.controller_source(),
                        hold.ancestry(),
                        hold.binding(),
                        hold.epoch() + 1,
                    )
                    .unwrap(),
                    names,
                )
                .unwrap()
        );
        assert!(
            writer
                .record_source_domain_challenge_v1(hold, project, [9; 16], cut, names)
                .is_err()
        );
        let mut changed_names = names.to_bytes();
        changed_names[47] ^= 1;
        let changed_names = ProtectedJournalNamesV1::from_bytes(&changed_names).unwrap();
        assert!(
            !first
                .matches_current([9; 16], cut, project, hold, changed_names)
                .unwrap()
        );
        assert!(
            writer
                .record_source_domain_challenge_v1(hold, project, [10; 16], cut, changed_names)
                .is_err()
        );
        drop(writer);

        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("cold Source writer");
        assert_eq!(
            replay_source_domain_challenge_v1(&writer).unwrap(),
            Some(first)
        );
        assert_eq!(writer.source_domain_policy_hold_v1().unwrap(), Some(hold));
        let (mut readback, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("read-only Source signer view");
        assert_eq!(readback.physical_names_v1(), names);
        assert_eq!(
            replay_source_domain_challenge_v1(readback.journal_mut()).unwrap(),
            Some(first)
        );
        drop(readback);

        let second = writer
            .record_source_domain_challenge_v1(hold, project, [10; 16], cut, names)
            .expect("next challenge");
        assert_eq!(second.issue(), 2);
        assert_ne!(first.record_digest(), second.record_digest());
        let third = writer
            .record_source_domain_challenge_v1(hold, project, [9; 16], cut, names)
            .expect("older nonce can recur only as a newly issued row");
        assert_eq!(third.issue(), 3);
        assert_ne!(first.record_digest(), third.record_digest());
        assert_eq!(
            replay_source_domain_challenge_v1(&writer).unwrap(),
            Some(third)
        );

        let mut forged = third.encode();
        forged[24] ^= 1;
        let mutation = JournalTransaction::new(
            [21; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                KEY.to_vec(),
                forged.to_vec(),
            )],
        )
        .expect("offline mutation fixture");
        writer
            .commit_with_capacity_scope(&mutation, None, false, true)
            .expect("offline malformed row");
        assert!(replay_source_domain_challenge_v1(&writer).is_err());
        drop(writer);
        let (cold, _) = Journal::open_protected_at_uid(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("cold mutated Source journal");
        assert!(replay_source_domain_challenge_v1(&cold).is_err());
        let (mut readback, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            name,
            source_domain_journal_limits(),
            uid,
        )
        .expect("cold read-only Source view");
        assert!(replay_source_domain_challenge_v1(readback.journal_mut()).is_err());
    }
}
