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

use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

use crate::journal::{CacheMutationGateV1, PreflightTransactionViewV1};
use crate::journal::semantic_append::{AppendScope, PreflightScope};

use aos_sandbox_model::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    Journal,
    JournalError,
    JournalRecord,
    JournalTransaction,
    ProtectedJournalNamesV1,
    RecordNamespace,
    source_domain_policy_hold,
};

use aos_sandbox_ledger_replay::source_domain_challenge::{
    KEY, MAGIC, CHECKSUM_DOMAIN, TRANSACTION_DOMAIN, RECORD_BYTES,
};

/// Retains one Root challenge spent in the held Source writer journal.
///
/// The historical fields remain DATA. Actual issuance still requires the
/// original held writer and its existing native and cross-owner checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SourceDomainChallengeV1 {
    data: aos_sandbox_ledger_replay::source_domain_challenge::SourceDomainChallengeDataV1,
}

impl SourceDomainChallengeV1 {
    /// Returns the same historical issue comparison DATA.
    #[must_use]
    pub const fn issue(self) -> u64 {
        self.data.issue()
    }

    /// Returns the same historical nonce comparison DATA.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.data.nonce()
    }

    /// Returns the same historical cut comparison DATA.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.data.cut()
    }

    /// Returns the same historical project comparison DATA.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.data.project()
    }

    /// Returns the same historical hold comparison DATA.
    #[must_use]
    pub const fn hold(self) -> ObjectDigest {
        self.data.hold()
    }

    /// Returns the same historical names comparison DATA.
    #[must_use]
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.data.names()
    }

    /// Returns the digest of the exact canonical challenge record.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        self.data.record_digest()
    }

    /// Compares historical fields under the caller's independently held cut.
    ///
    /// # Errors
    /// Preserves the original invalid held-record classification.
    pub fn matches_current(
        self, nonce: [u8; 16], cut: ObjectDigest, project: ProjectId,
        hold: SourceDomainPolicyHoldV1, names: ProtectedJournalNamesV1,
    ) -> Result<bool, JournalError> {
        self.data.matches_current(nonce, cut, project, hold, names)
            .map_err(JournalError::from)
    }

    fn encode(self) -> [u8; RECORD_BYTES] {
        self.data.encode()
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        aos_sandbox_ledger_replay::source_domain_challenge::SourceDomainChallengeDataV1::decode(bytes)
            .map(|data| Self { data }).map_err(JournalError::from)
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
        if prior.is_some_and(|row| row.nonce() == nonce) {
            return Err(JournalError::ProtectedBoundary);
        }
        let issue = prior
            .map_or(Some(1), |row| row.issue().checked_add(1))
            .ok_or(JournalError::ProtectedBoundary)?;
        let row = SourceDomainChallengeV1 {
            data: aos_sandbox_ledger_replay::source_domain_challenge::SourceDomainChallengeDataV1 {
                issue,
                nonce,
                cut,
                project,
                hold: expected_hold.record_digest()?,
                names,
            },
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
        let [v8_release, v8_clear] =
            source_domain_policy_hold::v8_retirement_and_clear_transactions(expected_hold)?;
        // This challenge spends held-writer capacity before either release path.
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(&[transaction.clone(), release]),
            PreflightScope {
                allow_policy_hold_transition: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(&[transaction.clone(), v8_release, v8_clear]),
            PreflightScope {
                allow_policy_hold_transition: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        self.commit_in_scope(
            &transaction,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
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

    use aos_sandbox_model::{OperationId, SandboxId};

    use super::*;
    use crate::journal::JournalLimits;
    use crate::source_domain::source_domain_journal_limits;

    #[test]
    fn challenge_preserves_capacity_for_v8_release_and_marker_clear() {
        let directory = tempfile::tempdir().expect("protected Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let limits = JournalLimits {
            maximum_transactions: 3,
            ..source_domain_journal_limits()
        };
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            limits,
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
        writer.acquire_source_domain_policy_hold_v1(hold).unwrap();

        let names = writer.protected_writer_physical_names_v1().unwrap();
        assert!(
            writer
                .record_source_domain_challenge_v1(
                    hold,
                    ProjectId::from_bytes([7; 16]),
                    [9; 16],
                    ObjectDigest::from_bytes([8; 32]),
                    names,
                )
                .is_err()
        );
        writer.retire_source_domain_policy_hold_v8(hold).unwrap();
        let released = writer.source_domain_policy_hold_v1().unwrap().unwrap();
        writer
            .clear_source_domain_policy_v8_pending_settlement_v1(released)
            .expect("reserved final marker clear");
    }

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
            .commit_in_scope(
                &mutation,
                AppendScope {
                    allow_policy_hold_transition: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
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
