//! Ordinary and protected opening over the original descriptor/replay recipe.
//!
//! Existing named constructors, exact-owner modes, diagnostic readers, and
//! first-time operator provisioning retain their original gates and effects.
//! Retained openings live in the retained child so their partial originals and
//! native first causes remain owned rather than flattened into projections.
//! No constructor, retry, fallback, authority port, or callback is added.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{CWD, FileType, FlockOperation, Mode, ResolveFlags, flock, fsync, openat2};

#[cfg(target_os = "linux")]
use super::super::runtime_deployment_history;
use super::super::{
    JournalAuthorityInstance, RecoveryReport, sibling_with_suffix, sync_parent, validate_limits,
};
use super::{
    FileIdentity, Journal, JournalError, JournalLimits, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES,
    ProtectedJournalLocation, ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal,
    open_protected_file, open_read_only_protected_file, protected_directory_flags,
    protected_open_error, reject_operator_provisioning_history, reject_stale_protected_compaction,
    remove_stale_protected_compaction, require_empty_operator_provisioning_state,
    require_opened_directory_identity, resolve_protected_directory_from_root, rustix_io,
    validate_basename, validate_protected_fd,
};

mod retained;

pub(crate) use retained::{
    ControllerJournalOpenOriginalsV1, ProtectedWriterOpenOriginalsV1,
    ReadOnlyJournalOpenOriginalsV1,
};
use retained::{OpenedReplayDestinationV1, prepare_opened_replay};

#[derive(Clone, Copy)]
pub(in crate::journal) enum ProtectedOwnerPolicy {
    Root,
    Exact(u32),
}

#[derive(Clone, Copy)]
pub(in crate::journal) enum ProtectedJournalOpenMode {
    Ordinary { allow_create: bool },
    StorageOperatorEmptyProvisionV4,
}

impl ProtectedJournalOpenMode {
    pub(in crate::journal) fn allows_creation(self) -> bool {
        match self {
            Self::Ordinary { allow_create } => allow_create,
            Self::StorageOperatorEmptyProvisionV4 => true,
        }
    }

    pub(in crate::journal) fn allows_repair(self) -> bool {
        matches!(self, Self::Ordinary { allow_create: true })
    }
}

pub(in crate::journal) const STORAGE_OPERATOR_STATE_DIRECTORY: &str =
    "/var/lib/aos/sandbox-storage";
pub(in crate::journal) const STORAGE_OPERATOR_JOURNAL_NAME: &str = "operator-recovery.journal";

impl ProtectedOwnerPolicy {
    pub(in crate::journal) fn expected_uid(self) -> u32 {
        match self {
            Self::Root => 0,
            Self::Exact(uid) => uid,
        }
    }
}

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
        let directory = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            directory_path,
            expected_uid,
        )?;
        if let Some(expected) = expected_directory_identity {
            require_opened_directory_identity::<crate::journal::JournalError>(
                &directory, expected,
            )?;
        }
        let (readback, report) = Self::open_read_only_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            expected_uid,
        )?;
        readback.check_named_currentness()?;
        Ok((readback, report))
    }

    #[cfg(test)]
    /// Opens a protected test fixture read-only without requiring a root UID.
    pub(crate) fn open_read_only_protected_at_uid_for_test(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let directory: File = openat2(
            CWD,
            directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error::<crate::journal::JournalError>)?
        .into();
        validate_protected_fd::<crate::journal::JournalError>(
            &directory,
            expected_uid,
            FileType::Directory,
            Mode::RWXU,
        )?;
        let (readback, report) = Self::open_read_only_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            expected_uid,
        )?;
        readback.check_named_currentness_at_uid_for_test()?;
        Ok((readback, report))
    }

    // Production and test openings share the same no-follow journal, lock,
    // replay, and physical-name witness construction.
    pub(in crate::journal) fn open_read_only_protected_directory(
        directory_path: &Path,
        directory: File,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        validate_limits(limits)?;
        if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_basename::<crate::journal::JournalError>(name)?;
        let directory_identity = FileIdentity::of::<crate::journal::JournalError>(&directory)?;
        let lock = open_read_only_protected_file::<crate::journal::JournalError>(
            &directory,
            &format!("{name}.lock"),
            expected_uid,
        )?;
        let lock_identity = FileIdentity::of::<crate::journal::JournalError>(&lock)?;
        let file = open_read_only_protected_file::<crate::journal::JournalError>(
            &directory,
            name,
            expected_uid,
        )?;
        let file_identity = FileIdentity::of::<crate::journal::JournalError>(&file)?;
        let protected = ProtectedJournalLocation::from_original_parts((
            directory,
            name.to_owned(),
            expected_uid,
            #[cfg(target_os = "linux")]
            runtime_deployment_history::OriginalCompactionSelectionV1::capture(
                directory_path,
                name,
            ),
            #[cfg(not(target_os = "linux"))]
            (),
        ));
        let (journal, report) = Self::recover_opened(
            PathBuf::from(name),
            file,
            lock,
            limits,
            Some(protected),
            false,
        )?;
        let readback = ReadOnlyProtectedJournal {
            journal,
            witness: ReadOnlyJournalNameWitness {
                physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness::from_original_parts((
                    directory_path.to_owned(),
                    name.to_owned(),
                    expected_uid,
                    directory_identity,
                    file_identity,
                    lock_identity,
                )),
            },
        };
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
        validate_limits(limits)?;
        let path = path.as_ref().to_path_buf();
        let lock_path = sibling_with_suffix(&path, ".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                JournalError::AlreadyLocked
            } else {
                JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
            }
        })?;

        let existed = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if !existed {
            sync_parent(&path)?;
        }
        Self::recover_opened(path, file, lock, limits, None, true)
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
        let directory_path = directory.as_ref();
        let directory = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            directory_path,
            0,
        )?;
        Self::open_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Root,
            true,
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
        let directory_path = directory.as_ref();
        let directory = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            directory_path,
            0,
        )?;
        Self::open_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Root,
            false,
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
        let path = Path::new(STORAGE_OPERATOR_STATE_DIRECTORY);
        let directory =
            resolve_protected_directory_from_root::<crate::journal::JournalError>(path, 0)?;
        let (journal, _) = Self::open_protected_directory_with_mode(
            path,
            directory,
            STORAGE_OPERATOR_JOURNAL_NAME,
            limits,
            ProtectedOwnerPolicy::Root,
            ProtectedJournalOpenMode::StorageOperatorEmptyProvisionV4,
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
            FileIdentity::of::<crate::journal::JournalError>(self.native.file())?;
        let lock_identity =
            FileIdentity::of::<crate::journal::JournalError>(self.native.lock_file())?;
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
            || !self.idempotency.is_empty();
        require_empty_operator_provisioning_state(
            self.native.next_sequence(),
            self.native.committed_transactions(),
            has_history,
        )?;
        self.validate_held_root_owned_at(
            STORAGE_OPERATOR_STATE_DIRECTORY,
            STORAGE_OPERATOR_JOURNAL_NAME,
        )?;
        if FileIdentity::of::<crate::journal::JournalError>(self.native.file())? != journal_identity
            || FileIdentity::of::<crate::journal::JournalError>(self.native.lock_file())?
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
        let directory_path = directory.as_ref();
        let directory = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            directory_path,
            expected_uid,
        )?;
        Self::open_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Exact(expected_uid),
            true,
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
        let directory_path = directory.as_ref();
        let directory = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            directory_path,
            expected_uid,
        )?;
        Self::open_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Exact(expected_uid),
            false,
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
        let directory: File = openat2(
            CWD,
            directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error::<crate::journal::JournalError>)?
        .into();
        Self::open_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Exact(expected_uid),
            true,
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
        let directory: File = openat2(
            CWD,
            directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error::<crate::journal::JournalError>)?
        .into();
        Self::open_protected_directory(
            directory_path,
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Exact(expected_uid),
            false,
        )
    }

    pub(in crate::journal) fn open_protected_directory(
        directory_path: &Path,
        directory: File,
        name: &str,
        limits: JournalLimits,
        owner: ProtectedOwnerPolicy,
        allow_create: bool,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_protected_directory_with_mode(
            directory_path,
            directory,
            name,
            limits,
            owner,
            ProtectedJournalOpenMode::Ordinary { allow_create },
        )
    }

    pub(in crate::journal) fn open_protected_directory_with_mode(
        directory_path: &Path,
        directory: File,
        name: &str,
        limits: JournalLimits,
        owner: ProtectedOwnerPolicy,
        mode: ProtectedJournalOpenMode,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let allow_create = mode.allows_creation();
        let expected_uid = owner.expected_uid();
        validate_limits(limits)?;
        if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_basename::<crate::journal::JournalError>(name)?;
        validate_protected_fd::<crate::journal::JournalError>(
            &directory,
            expected_uid,
            FileType::Directory,
            Mode::RWXU,
        )?;
        let lock_name = format!("{name}.lock");
        let lock = open_protected_file::<crate::journal::JournalError>(
            &directory,
            &lock_name,
            expected_uid,
            allow_create,
            false,
            false,
        )?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                JournalError::AlreadyLocked
            } else {
                rustix_io::<crate::journal::JournalError>(error)
            }
        })?;
        if matches!(
            mode,
            ProtectedJournalOpenMode::StorageOperatorEmptyProvisionV4
        ) {
            reject_operator_provisioning_history::<crate::journal::JournalError>(
                lock.metadata()?.len(),
            )?;
        }
        if mode.allows_repair() {
            remove_stale_protected_compaction::<crate::journal::JournalError>(&directory, name)?;
        } else {
            reject_stale_protected_compaction::<crate::journal::JournalError>(&directory, name)?;
        }
        let file = open_protected_file::<crate::journal::JournalError>(
            &directory,
            name,
            expected_uid,
            allow_create,
            false,
            false,
        )?;
        if matches!(
            mode,
            ProtectedJournalOpenMode::StorageOperatorEmptyProvisionV4
        ) {
            reject_operator_provisioning_history::<crate::journal::JournalError>(
                file.metadata()?.len(),
            )?;
        }
        if allow_create {
            fsync(&directory).map_err(rustix_io::<crate::journal::JournalError>)?;
        }

        let protected = ProtectedJournalLocation::from_original_parts((
            directory,
            name.to_owned(),
            expected_uid,
            #[cfg(target_os = "linux")]
            runtime_deployment_history::OriginalCompactionSelectionV1::capture(
                directory_path,
                name,
            ),
            #[cfg(not(target_os = "linux"))]
            (),
        ));
        Self::recover_opened(
            PathBuf::from(name),
            file,
            lock,
            limits,
            Some(protected),
            mode.allows_repair(),
        )
    }

    // Both openers finish the same durable replay after their distinct lock,
    // directory, and file-boundary checks have completed.
    pub(in crate::journal) fn recover_opened(
        path: PathBuf,
        mut file: File,
        lock: File,
        limits: JournalLimits,
        protected: Option<ProtectedJournalLocation>,
        repair_tail: bool,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let (replay, report) = prepare_opened_replay(
            &mut file,
            limits,
            repair_tail,
            OpenedReplayDestinationV1::Ordinary,
        )?;
        let replay = replay.ok_or(JournalError::ProtectedBoundary)?;
        Ok((
            journal_from_original_replay!(
                path,
                file,
                lock,
                limits,
                protected,
                replay,
                Arc::new(JournalAuthorityInstance)
            ),
            report,
        ))
    }
}
