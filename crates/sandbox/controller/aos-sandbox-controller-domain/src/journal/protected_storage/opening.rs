//! Ordinary and protected opening over the original descriptor/replay recipe.
//!
//! Existing named constructors, exact-owner modes, diagnostic readers, and
//! first-time operator provisioning retain their original gates and effects.
//! Retained openings live in the retained child so their partial originals and
//! native first causes remain owned rather than flattened into projections.
//! No constructor, retry, fallback, authority port, or callback is added.

use std::path::Path;

use super::super::RecoveryReport;
use super::{
    Journal, JournalError, JournalLimits, ReadOnlyProtectedJournal,
    reject_operator_provisioning_history, require_empty_operator_provisioning_state,
};

mod retained;

pub(crate) use retained::{
    ProtectedWriterOpenOriginalsV1,
    ReadOnlyJournalOpenOriginalsV1,
};
use super::super::ordinary_opening::OrdinaryPathV1;

pub(in crate::journal) const STORAGE_OPERATOR_STATE_DIRECTORY: &str =
    "/var/lib/aos/sandbox-storage";
pub(in crate::journal) const STORAGE_OPERATOR_JOURNAL_NAME: &str = "operator-recovery.journal";


impl Journal {
    /// Replays one protected name without writing or taking the writer lock.
    ///
    /// This is diagnostic evidence only. The caller must check all names again
    /// after use and must not turn the result into effect or publication authority.
    pub(crate) fn open_read_only_protected_at(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        Self::open_read_only_protected_at_with_identity(directory_path, name, limits, 0, None)
    }

    /// Replays one protected name only from the observed idmapped directory.
    ///
    /// The resolved directory descriptor must match the caller's mount witness
    /// before opening or replaying either file. Callers must still recheck the
    /// mount and original source name after the full observation.
    pub(crate) fn open_read_only_protected_at_for_uid_bound(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
        expected_directory_identity: (u64, u64),
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        Self::open_read_only_protected_at_with_identity(
            directory_path,
            name,
            limits,
            expected_uid,
            Some(expected_directory_identity),
        )
    }

    pub(in crate::journal) fn open_read_only_protected_at_with_identity(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
        expected_directory_identity: Option<(u64, u64)>,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let (readback, report) = Self::open_actual_ordinary_readonly_v1(
            directory_path, name, limits, expected_uid, expected_directory_identity,
            #[cfg(test)]
            false,
        )?;
        readback.check_named_currentness()?;
        Ok((readback, report))
    }

    #[cfg(test)]
    /// Opens the actual provided test directory without a root-ancestry grant.
    pub(crate) fn open_read_only_protected_at_uid_for_test(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let (readback, report) = Self::open_actual_ordinary_readonly_v1(
            directory_path, name, limits, expected_uid, None, true,
        )?;
        readback.check_named_currentness_at_uid_for_test()?;
        Ok((readback, report))
    }

    /// Opens, exclusively locks, validates, and replays a journal.
    ///
    /// The parent directory must already exist. A partial final frame or a
    /// complete but uncommitted tail is truncated and synced before return.
    /// Complete corrupt frames and committed semantic corruption fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when ownership cannot be acquired, filesystem
    /// operations fail, a configured bound is exceeded, or durable bytes fail
    /// structural, sequence, checksum, or transaction validation.
    pub fn open(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(OrdinaryPathV1::Unprotected(path.as_ref()), limits)
    }

    /// Opens a root-owned journal beneath one protected directory.
    ///
    /// `directory` must be an unambiguous absolute path. Resolution starts at
    /// an opened `/`, never follows symlinks, and requires every traversed
    /// directory to be root-owned and not group- or other-writable. The final
    /// directory must additionally be mode 0700 and remains open. `name` must
    /// be one ordinary basename. Journal and lock files are no-follow
    /// root-owned regular files mode 0600.
    /// Compaction uses an exclusive, unique temporary name and remains entirely
    /// relative to the retained directory FD, including cleanup and directory
    /// synchronization.
    ///
    /// This boundary provides local integrity and confidentiality against
    /// unprivileged users while the kernel and supplied root-owned directory
    /// remain trusted. It does not encrypt journal contents or authenticate
    /// records copied from another equally protected directory.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] for a path, type, owner, or
    /// mode violation, [`JournalError::UnsupportedProtectedOpen`] when the
    /// kernel cannot enforce the required resolution policy, or another
    /// [`JournalError`] for lock, replay, or I/O failure. Callers must not fall
    /// back to [`Journal::open`] after either protected-opening error.
    pub fn open_protected_at(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(
            OrdinaryPathV1::Protected {
                directory: directory.as_ref(),
                name,
                uid: 0,
                allow_create: true,
            },
            limits,
        )
    }

    /// Replays an already provisioned root-owned journal without creating it.
    ///
    /// Both the journal and its lock must already exist with the protected
    /// ownership and mode required by [`Self::open_protected_at`]. A missing
    /// file never becomes an empty authority journal through this opener.
    ///
    /// # Errors
    ///
    /// Rejects absent or unsafe protected names, a held lock, corrupt replay,
    /// and every protected-open failure of [`Self::open_protected_at`].
    pub fn open_existing_protected_at(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(
            OrdinaryPathV1::Protected {
                directory: directory.as_ref(),
                name,
                uid: 0,
                allow_create: false,
            },
            limits,
        )
    }

    /// Provisions only the fixed empty Storage operator receipt journal.
    ///
    /// The actual exclusive writer lock precedes the physical-length check.
    /// Existing nonempty history, interrupted tails, and stale compaction are
    /// refused without repair or cleanup. Newly created names are synchronized;
    /// an error leaves any partially provisioned names in place for diagnosis.
    /// This does not initialize a receipt, rollback floor, or Storage runtime.
    ///
    /// # Errors
    ///
    /// Rejects unsafe fixed custody, a held writer lock, any physical history,
    /// stale compaction, or an opening, replay, or synchronization failure.
    pub fn provision_empty_storage_operator_recovery_v4(
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        let (journal, _) = Self::open_actual_ordinary_v1(
            super::super::ordinary_opening::OrdinaryPathV1::StorageOperatorEmpty,
            limits,
        )?;
        journal.validate_empty_storage_operator_recovery_v4()?;
        Ok(journal)
    }

    /// Rechecks the same fixed writer and its physically empty native history.
    ///
    /// A materialized-empty map alone is insufficient: deleted rows or a
    /// compacted history do not count as first-time receipt provisioning.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy, replaced, foreign, or nonempty fixed writer custody.
    pub fn validate_empty_storage_operator_recovery_v4(&self) -> Result<(), JournalError> {
        self.validate_held_root_owned_at(
            STORAGE_OPERATOR_STATE_DIRECTORY,
            STORAGE_OPERATOR_JOURNAL_NAME,
        )?;
        let journal_identity =
            self.native.file_identity::<crate::journal::JournalError>()?;
        let lock_identity =
            self.native.lock_identity::<crate::journal::JournalError>()?;
        reject_operator_provisioning_history::<crate::journal::JournalError>(
            journal_identity.byte_len(),
        )?;
        reject_operator_provisioning_history::<crate::journal::JournalError>(
            lock_identity.byte_len(),
        )?;
        let has_history = !self.native.transaction_ids().is_empty()
            || !self.native.committed_namespaces().is_empty()
            || !self.native.state().is_empty()
            || self.native.materialized_bytes() != 0
            || !self.native.idempotency().is_empty();
        require_empty_operator_provisioning_state(
            self.native.next_sequence(),
            self.native.committed_transactions(),
            has_history,
        )?;
        self.validate_held_root_owned_at(
            STORAGE_OPERATOR_STATE_DIRECTORY,
            STORAGE_OPERATOR_JOURNAL_NAME,
        )?;
        if self.native.file_identity::<crate::journal::JournalError>()? != journal_identity
            || self.native.lock_identity::<crate::journal::JournalError>()?
                != lock_identity
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Opens a protected journal owned by one configured service UID.
    ///
    /// Resolution starts at `/` and rejects symlinks and ambiguous components.
    /// Ancestors must be root-owned until ownership first transitions to
    /// `expected_uid`; all remaining ancestors must belong to that UID. No
    /// traversed directory may be group- or other-writable, including sticky
    /// directories. The final directory must have exactly mode 0700 and the
    /// expected owner. UID zero selects an entirely root-owned chain.
    ///
    /// Journal, lock, and compaction files retain the exact-owner, regular-file,
    /// mode-0600 checks of [`Self::open_protected_at`]. All effects stay relative
    /// to the retained final directory. This method neither changes credentials
    /// nor authenticates the configured UID: the service and root remain trusted,
    /// as do the kernel and filesystem enforcing these checks. Checksums do not
    /// authenticate records against that service or provide rollback protection.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] for unsafe paths, ownership,
    /// types or modes, [`JournalError::UnsupportedProtectedOpen`] when the kernel
    /// cannot enforce resolution, or another journal error for I/O, locking or
    /// replay failures. Callers must not fall back to an unprotected opener.
    pub fn open_protected_at_for_uid(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(
            OrdinaryPathV1::Protected {
                directory: directory.as_ref(),
                name,
                uid: expected_uid,
                allow_create: true,
            },
            limits,
        )
    }

    /// Replays a provisioned service-owned journal without creating or repairing it.
    ///
    /// Resolution and ownership are identical to [`Self::open_protected_at_for_uid`].
    /// Both journal and lock must exist; an interrupted tail or stale compaction
    /// remains an error rather than becoming an empty or repaired authority.
    ///
    /// # Errors
    ///
    /// Rejects missing or unsafe names, a held lock, corrupt or incomplete replay,
    /// and every protected-open failure of [`Self::open_protected_at_for_uid`].
    pub fn open_existing_protected_at_for_uid(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(
            OrdinaryPathV1::Protected {
                directory: directory.as_ref(),
                name,
                uid: expected_uid,
                allow_create: false,
            },
            limits,
        )
    }

    /// Opens a final private directory for dependent crate journal fixtures.
    ///
    /// This opener retains final-directory and journal-file owner/mode checks,
    /// but deliberately omits production root-ancestry validation so an
    /// unprivileged test can use its private temporary directory. The feature
    /// is never enabled by production SourceProvider builds.
    ///
    /// # Errors
    ///
    /// Returns a protected-boundary or journal error for an unsafe final
    /// directory, symlink, lock, or malformed journal.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    #[doc(hidden)]
    pub fn open_protected_at_uid(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(
            OrdinaryPathV1::Fixture {
                directory: directory_path,
                name,
                uid: expected_uid,
                allow_create: true,
            },
            limits,
        )
    }

    /// Replays an existing test-owned journal without creating missing state.
    ///
    /// # Errors
    ///
    /// Rejects absent or unsafe protected names, a held lock, or corrupt replay.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    #[doc(hidden)]
    pub fn open_existing_protected_at_uid(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_actual_ordinary_v1(
            OrdinaryPathV1::Fixture {
                directory: directory_path,
                name,
                uid: expected_uid,
                allow_create: false,
            },
            limits,
        )
    }

}
