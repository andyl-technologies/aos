//! Native protected Journal orchestration, replay, and retained failure custody.
//!
//! The shared Journal physical owner retains the actual protected location and
//! name observations. This group keeps ordinary and retained opening recipes,
//! semantic replay, original failure reservoirs, and the public lock-description
//! loan with its private constructor. Replacement encoding and replay borrow the
//! lower physical cleanup guard through the complete original compaction scope.
//!
//! Native Journal, protected admission, compaction guards, genuine role loans,
//! and final authority crossings remain domain-owned. The physical prerequisite
//! does not complete the protected authority boundary or add a sealed FD factory.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{OFlags, fcntl_getfl};

#[cfg(target_os = "linux")]
use super::runtime_deployment_history;
use super::{
    Journal, JournalError, JournalLimits, RecordNamespace, ReplayState, replay, write_compacted,
};

mod opening;

pub(crate) use opening::{
    ControllerJournalOpenOriginalsV1, ProtectedWriterOpenOriginalsV1,
    ReadOnlyJournalOpenOriginalsV1,
};
#[cfg(test)]
pub(super) use opening::{ProtectedJournalOpenMode, ProtectedOwnerPolicy};

pub(super) use aos_sandbox_journal::protected_storage::{
    FileIdentity, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES,
    open_protected_file, open_protected_file_into,
    open_protected_file_into_original, open_read_only_protected_file,
    open_read_only_protected_file_original, protected_directory_flags,
    protected_open_error, reject_operator_provisioning_history, reject_stale_protected_compaction,
    remove_stale_protected_compaction, require_opened_directory_identity,
    require_protected_file_names_current, resolve_protected_directory_from_root,
    resolve_protected_directory_from_root_original, rustix_io,
    validate_basename, validate_protected_fd,
};

#[cfg(test)]
pub(super) use aos_sandbox_journal::protected_storage::{
    ProtectedAncestry, traverse_protected_directory,
};

pub(crate) use aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness;

impl aos_sandbox_journal::protected_storage::ProtectedFailure for JournalError {
    const BOUNDARY: Self = Self::ProtectedBoundary;
    const UNSUPPORTED_OPEN: Self = Self::UnsupportedProtectedOpen;
    const STALE_NAME: Self = Self::StaleAuthoritySnapshot;
}

#[cfg(target_os = "linux")]
pub(super) type ProtectedJournalLocation =
    aos_sandbox_journal::protected_storage::ProtectedJournalLocation<
        runtime_deployment_history::OriginalCompactionSelectionV1,
    >;
#[cfg(not(target_os = "linux"))]
pub(super) type ProtectedJournalLocation =
    aos_sandbox_journal::protected_storage::ProtectedJournalLocation<()>;

/// Retains only an existing protected writer's lock open-file description.
///
/// This custody loan exposes no journal data or writer API. Duplicating or
/// transferring it preserves the original `flock`, but a recipient could
/// explicitly unlock that shared description. It must therefore be delivered
/// only to an independently trusted, confined child. It establishes neither
/// a journal cut nor currentness, rollback protection, or effect authority.
pub struct ProtectedJournalLockCustodyV1 {
    pub(super) lock: File,
}

impl ProtectedJournalLockCustodyV1 {
    /// Borrows the exact duplicated lock description for a confined handoff.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.lock.as_fd()
    }

    /// Returns the held lock's device, inode, and owner for recipient checks.
    ///
    /// These metadata are not proof of the original flock or any authority.
    ///
    /// # Errors
    ///
    /// Rejects a nonempty, nonregular, linked, incorrectly permissioned, or
    /// non-read/write lock description, or an inspection failure.
    pub fn identity(&self) -> Result<(u64, u64, u32), JournalError> {
        let metadata = self.lock.metadata()?;
        if !metadata.is_file()
            || metadata.len() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || fcntl_getfl(&self.lock).map_err(rustix_io::<crate::journal::JournalError>)?
                & OFlags::ACCMODE
                != OFlags::RDWR
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((metadata.dev(), metadata.ino(), metadata.uid()))
    }
}

pub use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

fn names_from_identities(
    directory: FileIdentity,
    journal: FileIdentity,
    lock: FileIdentity,
) -> ProtectedJournalNamesV1 {
    ProtectedJournalNamesV1::from_historical_fields(
        directory.physical_pair(),
        journal.physical_pair(),
        lock.physical_pair(),
    )
}

/// Holds a nonauthorizing replay of one named protected journal.
///
/// The descriptors are read-only and no flock is taken. A successful name
/// check detects ordinary append and compaction races, but cannot prove a
/// simultaneous cut with another journal or a concurrent owner.
pub(crate) struct ReadOnlyProtectedJournal {
    pub(super) journal: Journal,
    pub(super) witness: ReadOnlyJournalNameWitness,
}

/// Keeps the original role-private read-only witness API over physical custody.
pub(crate) struct ReadOnlyJournalNameWitness {
    physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness,
}

impl ReadOnlyProtectedJournal {
    /// Borrows replayed records for the closed Cache verifier.
    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    /// Re-resolves the directory and both physical names independently.
    pub(crate) fn check_named_currentness(&self) -> Result<(), JournalError> {
        self.witness.check_named_currentness()?;
        self.witness
            .physical
            .require_file_identity::<JournalError>(self.journal.native.file())?;
        Ok(())
    }

    /// Returns only the fixed names observed by this read-only replay.
    pub(crate) fn physical_names_v1(&self) -> ProtectedJournalNamesV1 {
        let (directory, journal, lock) = self.witness.physical.physical_pairs();
        ProtectedJournalNamesV1::from_historical_fields(directory, journal, lock)
    }

    #[cfg(test)]
    /// Checks the retained name using the test fixture's exact UID.
    pub(crate) fn check_named_currentness_at_uid_for_test(&self) -> Result<(), JournalError> {
        self.witness.check_named_currentness_at_uid_for_test()?;
        self.witness
            .physical
            .require_file_identity::<JournalError>(self.journal.native.file())?;
        Ok(())
    }

    /// Separates the read-only journal from its physical-name witness.
    pub(crate) fn into_parts(self) -> (Journal, ReadOnlyJournalNameWitness) {
        (self.journal, self.witness)
    }
}

impl ReadOnlyJournalNameWitness {
    pub(super) fn name(&self) -> &str {
        self.physical.name()
    }

    pub(crate) fn check_named_currentness(&self) -> Result<(), JournalError> {
        self.physical.check_named_currentness::<JournalError>()
    }

    #[cfg(test)]
    pub(crate) fn check_named_currentness_at_uid_for_test(&self) -> Result<(), JournalError> {
        self.physical
            .check_named_currentness_at_uid_for_test::<JournalError>()
    }

    pub(super) fn check_in_directory(&self, directory: &File) -> Result<(), JournalError> {
        self.physical.check_in_directory::<JournalError>(directory)
    }
}

impl Journal {
    /// Checks that this live lock still belongs to one fixed protected path.
    ///
    /// The directory is resolved afresh and compared by device and inode with
    /// the retained protected directory descriptor. Call
    /// [`Self::require_protected_named_location`] when the journal and lock
    /// basenames must also remain current.
    pub(crate) fn require_protected_location(
        &self,
        directory: &Path,
        name: &str,
        expected_uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let retained = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if retained.name() != name
            || retained.expected_uid() != expected_uid
            || self.native.limits() != limits
        {
            return Err(JournalError::ProtectedBoundary);
        }

        // Keep the independent current description through the health bookend.
        let _current = retained.require_directory::<JournalError>(directory, expected_uid)?;

        self.ensure_healthy()
    }

    /// Rechecks the fixed directory and both names against this retained writer.
    ///
    /// A same-UID rename can replace a journal pathname without releasing the
    /// old inode's flock. A signed owner witness must not describe that orphan.
    pub(crate) fn require_protected_named_location(
        &self,
        directory: &Path,
        name: &str,
        expected_uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        self.require_protected_location(directory, name, expected_uid, limits)?;
        self.require_protected_names_current()
    }

    pub(crate) fn protected_writer_name_witness(
        &self,
    ) -> Result<ProtectedWriterNameWitness, JournalError> {
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        location.writer_witness::<JournalError>(self.native.file(), self.native.lock_file())
    }

    /// Returns the retained writer's physical names after fixed-name revalidation.
    pub(crate) fn protected_writer_physical_names_v1(
        &self,
    ) -> Result<ProtectedJournalNamesV1, JournalError> {
        self.require_protected_names_current()?;
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let witness =
            location.writer_witness::<JournalError>(self.native.file(), self.native.lock_file())?;
        Ok(names_from_identities(
            witness.directory(),
            witness.file(),
            witness.lock(),
        ))
    }

    pub(crate) fn validate_protected_writer_name_witness(
        &self,
        witness: &ProtectedWriterNameWitness,
    ) -> Result<(), JournalError> {
        let location = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.require_protected_names_current()?;
        location.require_writer_witness::<JournalError>(
            self.native.file(),
            self.native.lock_file(),
            witness,
        )
    }

    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub(crate) fn require_protected_named_location_at_uid_for_test(
        &self,
        directory_path: &Path,
        name: &str,
        expected_uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let retained = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if retained.name() != name
            || retained.expected_uid() != expected_uid
            || self.native.limits() != limits
        {
            return Err(JournalError::ProtectedBoundary);
        }
        // Keep this independent description through the original name bookend.
        let _current = retained
            .require_directory_at_uid_for_test::<JournalError>(directory_path, expected_uid)?;
        self.require_protected_names_current()
    }

    /// Returns the owner UID retained by this protected journal opener.
    pub(crate) fn protected_owner_uid(&self) -> Result<u32, JournalError> {
        self.protected
            .as_ref()
            .map(|location| location.expected_uid())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_protected_names_current(&self) -> Result<(), JournalError> {
        let retained = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        retained.require_names::<JournalError>(self.native.lock_file(), self.native.file())
    }

    #[cfg(test)]
    pub(crate) fn require_protected_names_current_for_test(&self) -> Result<(), JournalError> {
        self.require_protected_names_current()
    }

    /// Checks that a protected writer still owns its named journal and lock.
    ///
    /// This checks names inside the retained protected directory. It does not
    /// re-resolve that directory's original path or establish another owner's
    /// currentness; callers needing a fixed path must separately check it.
    ///
    /// # Errors
    ///
    /// Rejects an unprotected or poisoned journal, a replaced journal or lock
    /// name, and any protected file-boundary failure.
    pub fn validate_held_protected_names(&self) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        self.require_protected_names_current()
    }

    /// Duplicates only a healthy protected writer's exact lock description.
    ///
    /// The original named journal and lock are checked before and after the
    /// duplication. This retains custody across a trusted child lifetime; it
    /// is not another writer and cannot authorize reads, commits, or effects.
    ///
    /// # Errors
    ///
    /// Rejects an unprotected, poisoned, or replaced writer, or a failed
    /// descriptor duplication. No journal data descriptor is returned.
    pub fn loan_protected_lock_custody(
        &self,
    ) -> Result<ProtectedJournalLockCustodyV1, JournalError> {
        self.validate_held_protected_names()?;
        let lock = self.native.lock_file().try_clone()?;
        self.validate_held_protected_names()?;
        let custody = ProtectedJournalLockCustodyV1 { lock };
        custody.identity()?;
        Ok(custody)
    }

    /// Checks a live root-owned writer against its original protected path.
    ///
    /// The directory is resolved again, then its identity and both named files
    /// are compared with the retained writer. A renamed directory or journal
    /// cannot leave an orphaned lock acting as current authority.
    ///
    /// # Errors
    ///
    /// Rejects a changed path, journal, or lock and an unhealthy writer.
    pub fn validate_held_root_owned_at(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
    ) -> Result<(), JournalError> {
        self.require_protected_named_location(directory.as_ref(), name, 0, self.native.limits())
    }

    /// Rechecks a service-owned writer's original protected path and both names.
    ///
    /// This validates retained ownership; it neither chooses a new owner nor
    /// constructs authority. The full root-to-service ancestry policy of the
    /// production opener is re-applied.
    ///
    /// # Errors
    ///
    /// Rejects a changed directory, journal, lock, owner, or unhealthy writer.
    pub fn validate_held_owned_at_for_uid(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
        expected_uid: u32,
    ) -> Result<(), JournalError> {
        self.require_protected_named_location(
            directory.as_ref(),
            name,
            expected_uid,
            self.native.limits(),
        )
    }

    /// Rechecks exact UID-owned fixture custody without relaxing release openers.
    ///
    /// This test-only adapter uses the retained limits and the existing fixture
    /// path, UID, directory identity, journal, and lock-name checker. Production
    /// owners must use their fixed protected-path adapter instead.
    ///
    /// # Errors
    ///
    /// Rejects a poisoned journal or changed path, owner, directory, or names.
    #[doc(hidden)]
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub fn validate_held_protected_at_uid_for_test(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
        expected_uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        self.require_protected_named_location_at_uid_for_test(
            directory.as_ref(),
            name,
            expected_uid,
            self.native.limits(),
        )
    }
}

pub(super) fn require_empty_operator_provisioning_state(
    next_sequence: u64,
    committed_transactions: usize,
    has_history: bool,
) -> Result<(), JournalError> {
    if next_sequence != 1 || committed_transactions != 0 || has_history {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn compact_protected(
    location: &ProtectedJournalLocation,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(File, ReplayState), JournalError> {
    let (temporary, mut replacement, mut cleanup) = location.begin_replacement::<JournalError>()?;
    write_compacted(&mut replacement, state, limits)?;
    replacement.sync_all()?;
    if replacement.metadata()?.len() > limits.maximum_journal_bytes {
        return Err(JournalError::JournalTooLarge);
    }
    drop(replacement);
    let mut file =
        location.install_replacement::<JournalError>(temporary.as_str(), &mut cleanup)?;
    let replay = replay(&mut file, limits)?;
    if replay.durable_end != file.metadata()?.len() {
        return Err(JournalError::MalformedTransaction(
            "compacted journal has an uncommitted tail",
        ));
    }
    file.seek(SeekFrom::End(0))?;
    Ok((file, replay))
}
