//! Protected journal descriptors, physical names, and replacement custody.
//!
//! The owner retains the actual protected directory, read-only name witnesses,
//! and lock-description loan. Rooted traversal, no-follow file admission, name
//! revalidation, and temporary-file cleanup stay with their concrete descriptors.
//! The private opening children own ordinary recovery and complete retained
//! failure reservoirs; they never grant namespace or transition authority.
//!
//! Journal's native owner, semantic replay, protected claims, and compaction
//! admission remain with their actual domain owner. This private source group
//! does not establish a lower-crate authority boundary or add an FD factory.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, fcntl_getfl, fstat, fsync, openat2,
    renameat, statat, unlinkat,
};

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

pub(super) const MAXIMUM_PROTECTED_COMPONENT_BYTES: usize = 255;
pub(super) const MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES: usize = 200;

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
            || fcntl_getfl(&self.lock).map_err(rustix_io)? & OFlags::ACCMODE != OFlags::RDWR
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((metadata.dev(), metadata.ino(), metadata.uid()))
    }
}

/// Retains byte-level metadata for a protected writer readback.
///
/// Its caller must also recheck the fixed directory and names. A flock alone
/// does not prevent another same-UID process from writing an already open file.
pub(crate) struct ProtectedWriterNameWitness {
    pub(super) directory: FileIdentity,
    pub(super) file: FileIdentity,
    pub(super) lock: FileIdentity,
}

pub use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

fn names_from_identities(
    directory: FileIdentity,
    journal: FileIdentity,
    lock: FileIdentity,
) -> ProtectedJournalNamesV1 {
    ProtectedJournalNamesV1::from_historical_fields(
        (directory.device, directory.inode),
        (journal.device, journal.inode),
        (lock.device, lock.inode),
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

/// Retains the physical names observed by one read-only replay.
pub(crate) struct ReadOnlyJournalNameWitness {
    pub(super) directory_path: PathBuf,
    pub(super) name: String,
    pub(super) expected_uid: u32,
    pub(super) directory_identity: FileIdentity,
    pub(super) file_identity: FileIdentity,
    pub(super) lock_identity: FileIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) size: u64,
    pub(super) modified_seconds: i64,
    pub(super) modified_nanoseconds: i64,
    pub(super) changed_seconds: i64,
    pub(super) changed_nanoseconds: i64,
}

impl FileIdentity {
    pub(super) fn of(file: &File) -> Result<Self, JournalError> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

pub(super) fn require_opened_directory_identity(
    directory: &File,
    expected: (u64, u64),
) -> Result<(), JournalError> {
    let opened = FileIdentity::of(directory)?;
    if (opened.device, opened.inode) != expected {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl ReadOnlyProtectedJournal {
    /// Borrows replayed records for the closed Cache verifier.
    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    /// Re-resolves the directory and both physical names independently.
    pub(crate) fn check_named_currentness(&self) -> Result<(), JournalError> {
        self.witness.check_named_currentness()?;
        if FileIdentity::of(self.journal.native.file())? != self.witness.file_identity {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Returns only the fixed names observed by this read-only replay.
    pub(crate) fn physical_names_v1(&self) -> ProtectedJournalNamesV1 {
        names_from_identities(
            self.witness.directory_identity,
            self.witness.file_identity,
            self.witness.lock_identity,
        )
    }

    #[cfg(test)]
    /// Checks the retained name using the test fixture's exact UID.
    pub(crate) fn check_named_currentness_at_uid_for_test(&self) -> Result<(), JournalError> {
        self.witness.check_named_currentness_at_uid_for_test()?;
        if FileIdentity::of(self.journal.native.file())? != self.witness.file_identity {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Separates the read-only journal from its physical-name witness.
    pub(crate) fn into_parts(self) -> (Journal, ReadOnlyJournalNameWitness) {
        (self.journal, self.witness)
    }
}

impl ReadOnlyJournalNameWitness {
    /// Re-resolves the originally observed directory, lock, and journal.
    pub(crate) fn check_named_currentness(&self) -> Result<(), JournalError> {
        let directory =
            resolve_protected_directory_from_root(&self.directory_path, self.expected_uid)?;
        self.check_in_directory(&directory)
    }

    #[cfg(test)]
    /// Resolves a test-owned directory without changing production root ancestry checks.
    pub(crate) fn check_named_currentness_at_uid_for_test(&self) -> Result<(), JournalError> {
        let directory: File = openat2(
            CWD,
            &self.directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error)?
        .into();
        validate_protected_fd(
            &directory,
            self.expected_uid,
            FileType::Directory,
            Mode::RWXU,
        )?;
        self.check_in_directory(&directory)
    }

    pub(super) fn check_in_directory(&self, directory: &File) -> Result<(), JournalError> {
        if FileIdentity::of(&directory)? != self.directory_identity {
            return Err(JournalError::ProtectedBoundary);
        }
        let lock = open_read_only_protected_file(
            directory,
            &format!("{}.lock", self.name),
            self.expected_uid,
        )?;
        let file = open_read_only_protected_file(directory, &self.name, self.expected_uid)?;
        if FileIdentity::of(&lock)? != self.lock_identity
            || FileIdentity::of(&file)? != self.file_identity
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

pub(super) struct ProtectedJournalLocation {
    pub(super) directory: File,
    pub(super) name: String,
    pub(super) expected_uid: u32,
    // Denial only; this never substitutes for the actual native-history audit.
    #[cfg(target_os = "linux")]
    pub(super) original_compaction_selection:
        runtime_deployment_history::OriginalCompactionSelectionV1,
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
        if retained.name != name
            || retained.expected_uid != expected_uid
            || self.native.limits() != limits
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let current = resolve_protected_directory_from_root(directory, expected_uid)?;
        let retained_stat = fstat(&retained.directory).map_err(rustix_io)?;
        let current_stat = fstat(&current).map_err(rustix_io)?;
        if retained_stat.st_dev != current_stat.st_dev
            || retained_stat.st_ino != current_stat.st_ino
        {
            return Err(JournalError::ProtectedBoundary);
        }

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
        Ok(ProtectedWriterNameWitness {
            directory: FileIdentity::of(&location.directory)?,
            file: FileIdentity::of(self.native.file())?,
            lock: FileIdentity::of(self.native.lock_file())?,
        })
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
        Ok(names_from_identities(
            FileIdentity::of(&location.directory)?,
            FileIdentity::of(self.native.file())?,
            FileIdentity::of(self.native.lock_file())?,
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
        if FileIdentity::of(&location.directory)? != witness.directory
            || FileIdentity::of(self.native.file())? != witness.file
            || FileIdentity::of(self.native.lock_file())? != witness.lock
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
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
        if retained.name != name
            || retained.expected_uid != expected_uid
            || self.native.limits() != limits
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let current: File = openat2(
            CWD,
            directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error)?
        .into();
        validate_protected_fd(&current, expected_uid, FileType::Directory, Mode::RWXU)?;
        let held = fstat(&retained.directory).map_err(rustix_io)?;
        let named = fstat(&current).map_err(rustix_io)?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.require_protected_names_current()
    }

    /// Returns the owner UID retained by this protected journal opener.
    pub(crate) fn protected_owner_uid(&self) -> Result<u32, JournalError> {
        self.protected
            .as_ref()
            .map(|location| location.expected_uid)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_protected_names_current(&self) -> Result<(), JournalError> {
        let retained = self
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        require_protected_file_names_current(
            &retained.directory,
            &retained.name,
            retained.expected_uid,
            self.native.lock_file(),
            self.native.file(),
        )
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

pub(super) fn protected_directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

pub(super) fn resolve_protected_directory_from_root(
    path: &Path,
    expected_uid: u32,
) -> Result<File, JournalError> {
    resolve_protected_directory_from_root_with_retention(path, expected_uid, None)
}

pub(super) fn resolve_protected_directory_from_root_with_retention(
    path: &Path,
    expected_uid: u32,
    retained: Option<&mut Vec<File>>,
) -> Result<File, JournalError> {
    resolve_protected_directory_from_root_original(path, expected_uid, retained, None)
}

pub(super) fn resolve_protected_directory_from_root_original(
    path: &Path,
    expected_uid: u32,
    retained: Option<&mut Vec<File>>,
    mut native_error: Option<&mut Option<rustix::io::Errno>>,
) -> Result<File, JournalError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return Err(JournalError::ProtectedBoundary);
    }
    let components = &bytes[1..];
    if components.is_empty() {
        return Err(JournalError::ProtectedBoundary);
    }
    let components = components.split(|byte| *byte == b'/');
    if components.clone().any(|component| {
        component.is_empty()
            || component == b"."
            || component == b".."
            || component.contains(&0)
            || component.len() > MAXIMUM_PROTECTED_COMPONENT_BYTES
    }) {
        return Err(JournalError::ProtectedBoundary);
    }

    if let Some(ancestors) = retained.as_ref() {
        if !ancestors.is_empty() {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    let retained = match retained {
        Some(ancestors) => {
            ancestors
                .try_reserve_exact(components.clone().count().saturating_add(1))
                .map_err(io::Error::other)?;
            Some(ancestors)
        }
        None => None,
    };
    let root: File = openat2(
        CWD,
        "/",
        protected_directory_flags(),
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        if let Some(slot) = native_error.as_mut() {
            **slot = Some(error);
        }
        protected_open_error(error)
    })?
    .into();
    match retained {
        None => traverse_protected_directory(root, components, expected_uid),
        Some(ancestors) => {
            // Capacity was reserved before the first descriptor exists.
            ancestors.push(root);
            traverse_protected_directory_observed(
                ControllerDirectoryTraversalV1::Retained(ancestors),
                components,
                expected_uid,
                native_error,
            )
        }
    }
}

pub(super) fn traverse_protected_directory<'a>(
    directory: File,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
) -> Result<File, JournalError> {
    traverse_protected_directory_originals(
        ControllerDirectoryTraversalV1::Ordinary(directory),
        components,
        expected_uid,
    )
}

pub(super) enum ControllerDirectoryTraversalV1<'owner> {
    Ordinary(File),
    Retained(&'owner mut Vec<File>),
}

impl ControllerDirectoryTraversalV1<'_> {
    pub(super) fn current(&self) -> Result<&File, JournalError> {
        match self {
            Self::Ordinary(directory) => Ok(directory),
            Self::Retained(ancestors) => ancestors.last().ok_or(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn admit_child(
        &mut self,
        child: File,
        ancestry: &mut ProtectedAncestry,
    ) -> Result<(), JournalError> {
        match self {
            Self::Ordinary(directory) => {
                ancestry.admit(&child)?;
                *directory = child;
                Ok(())
            }
            Self::Retained(ancestors) => {
                ancestors.push(child);
                ancestry.admit(ancestors.last().ok_or(JournalError::ProtectedBoundary)?)
            }
        }
    }

    pub(super) fn finish(self) -> Result<File, JournalError> {
        match self {
            Self::Ordinary(directory) => Ok(directory),
            Self::Retained(ancestors) => ancestors.pop().ok_or(JournalError::ProtectedBoundary),
        }
    }
}

pub(super) fn traverse_protected_directory_originals<'a>(
    directory: ControllerDirectoryTraversalV1<'_>,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
) -> Result<File, JournalError> {
    traverse_protected_directory_observed(directory, components, expected_uid, None)
}

pub(super) fn traverse_protected_directory_observed<'a>(
    mut directory: ControllerDirectoryTraversalV1<'_>,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
    mut native_error: Option<&mut Option<rustix::io::Errno>>,
) -> Result<File, JournalError> {
    let mut ancestry = ProtectedAncestry::new(expected_uid);
    ancestry.admit(directory.current()?)?;
    for component in components {
        let child: File = openat2(
            directory.current()?,
            OsStr::from_bytes(component),
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| {
            if let Some(slot) = native_error.as_mut() {
                **slot = Some(error);
            }
            protected_open_error(error)
        })?
        .into();
        directory.admit_child(child, &mut ancestry)?;
    }
    validate_protected_fd(
        directory.current()?,
        expected_uid,
        FileType::Directory,
        Mode::RWXU,
    )?;
    directory.finish()
}

/// Tracks the one-way transition from administrative to service-owned ancestry.
pub(super) struct ProtectedAncestry {
    pub(super) expected_uid: u32,
    pub(super) service_owned: bool,
}

impl ProtectedAncestry {
    pub(super) const fn new(expected_uid: u32) -> Self {
        Self {
            expected_uid,
            service_owned: false,
        }
    }

    pub(super) fn admit(&mut self, file: &File) -> Result<(), JournalError> {
        let stat = fstat(file).map_err(rustix_io)?;
        self.admit_metadata(stat.st_uid, stat.st_mode)
    }

    pub(super) fn admit_metadata(&mut self, uid: u32, mode: u32) -> Result<(), JournalError> {
        if FileType::from_raw_mode(mode) != FileType::Directory || mode & 0o022 != 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        if uid == self.expected_uid {
            self.service_owned = true;
        } else if uid != 0 || self.service_owned {
            // A root-owned descendant cannot restore trust after a service has
            // acquired authority over the path above it.
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

pub(super) fn validate_basename(name: &str) -> Result<(), JournalError> {
    if name.is_empty()
        || name.len() > MAXIMUM_PROTECTED_COMPONENT_BYTES
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'/')
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn rustix_io(error: rustix::io::Errno) -> JournalError {
    JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
}

pub(super) fn protected_open_error(error: rustix::io::Errno) -> JournalError {
    if error == rustix::io::Errno::NOSYS
        || error == rustix::io::Errno::PERM
        || error == rustix::io::Errno::INVAL
    {
        JournalError::UnsupportedProtectedOpen
    } else if error == rustix::io::Errno::LOOP
        || error == rustix::io::Errno::XDEV
        || error == rustix::io::Errno::NOTDIR
        || error == rustix::io::Errno::ISDIR
        || error == rustix::io::Errno::ACCESS
    {
        JournalError::ProtectedBoundary
    } else {
        rustix_io(error)
    }
}

pub(super) fn protected_compaction_name(name: &str) -> String {
    format!("{name}.compact.tmp")
}

pub(super) fn reject_operator_provisioning_history(length: u64) -> Result<(), JournalError> {
    if length != 0 {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
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

pub(super) fn remove_stale_protected_compaction(
    directory: &File,
    name: &str,
) -> Result<(), JournalError> {
    let temporary = protected_compaction_name(name);
    validate_basename(&temporary)?;
    match unlinkat(directory, temporary.as_str(), AtFlags::empty()) {
        Ok(()) => fsync(directory).map_err(rustix_io),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(rustix_io(error)),
    }
}

pub(super) fn reject_stale_protected_compaction(
    directory: &File,
    name: &str,
) -> Result<(), JournalError> {
    let temporary = protected_compaction_name(name);
    validate_basename(&temporary)?;
    match statat(directory, temporary.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(JournalError::ProtectedBoundary),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(protected_open_error(error)),
    }
}

pub(super) fn validate_protected_fd(
    file: &File,
    expected_uid: u32,
    expected_type: FileType,
    expected_mode: Mode,
) -> Result<(), JournalError> {
    let stat = fstat(file).map_err(rustix_io)?;
    if stat.st_uid != expected_uid
        || FileType::from_raw_mode(stat.st_mode) != expected_type
        || Mode::from_raw_mode(stat.st_mode) != expected_mode
        || (expected_type == FileType::RegularFile && stat.st_nlink != 1)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn open_protected_file(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
) -> Result<File, JournalError> {
    let mut original = None;
    let result = open_protected_file_into(
        directory,
        name,
        expected_uid,
        create,
        exclusive,
        truncate,
        &mut original,
    );
    if let Err(error) = result {
        if create && exclusive && original.is_some() {
            drop(original);
            let _ = unlinkat(directory, name, AtFlags::empty());
            let _ = fsync(directory);
        }
        return Err(error);
    }
    original.ok_or(JournalError::ProtectedBoundary)
}

// The selected purpose parks the same actual open result before the shared
// checks. The ordinary adapter keeps its historical local cleanup disposition.
pub(super) fn open_protected_file_into(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
    original: &mut Option<File>,
) -> Result<(), JournalError> {
    open_protected_file_into_original(
        directory,
        name,
        expected_uid,
        create,
        exclusive,
        truncate,
        original,
        None,
    )
}

pub(super) fn open_protected_file_into_original(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
    original: &mut Option<File>,
    native_error: Option<&mut Option<rustix::io::Errno>>,
) -> Result<(), JournalError> {
    if original.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    validate_basename(name)?;
    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE;
    }
    if exclusive {
        flags |= OFlags::EXCL;
    }
    if truncate {
        flags |= OFlags::TRUNC;
    }
    let create_mode = if create {
        Mode::RUSR | Mode::WUSR
    } else {
        Mode::empty()
    };
    *original = Some(
        openat2(
            directory,
            name,
            flags,
            create_mode,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| {
            if let Some(slot) = native_error {
                *slot = Some(error);
            }
            protected_open_error(error)
        })?
        .into(),
    );
    validate_protected_fd(
        original.as_ref().ok_or(JournalError::ProtectedBoundary)?,
        expected_uid,
        FileType::RegularFile,
        Mode::RUSR | Mode::WUSR,
    )
}

pub(super) fn open_read_only_protected_file(
    directory: &File,
    name: &str,
    expected_uid: u32,
) -> Result<File, JournalError> {
    let mut original = None;
    open_read_only_protected_file_original(directory, name, expected_uid, &mut original)?;
    match original {
        Some(Ok(file)) => Ok(file),
        _ => Err(JournalError::ProtectedBoundary),
    }
}

pub(super) fn require_protected_file_names_current(
    directory: &File,
    name: &str,
    expected_uid: u32,
    lock: &File,
    file: &File,
) -> Result<(), JournalError> {
    let named_lock =
        open_read_only_protected_file(directory, &format!("{name}.lock"), expected_uid)?;
    let named_file = open_read_only_protected_file(directory, name, expected_uid)?;
    let held_lock = fstat(lock).map_err(rustix_io)?;
    let held_file = fstat(file).map_err(rustix_io)?;
    let current_lock = fstat(&named_lock).map_err(rustix_io)?;
    let current_file = fstat(&named_file).map_err(rustix_io)?;
    if held_lock.st_dev != current_lock.st_dev
        || held_lock.st_ino != current_lock.st_ino
        || held_file.st_dev != current_file.st_dev
        || held_file.st_ino != current_file.st_ino
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

pub(super) fn open_read_only_protected_file_original(
    directory: &File,
    name: &str,
    expected_uid: u32,
    original: &mut Option<Result<File, rustix::io::Errno>>,
) -> Result<(), JournalError> {
    if original.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    validate_basename(name)?;
    *original = Some(
        openat2(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from),
    );
    let file = match original.as_ref() {
        Some(Ok(file)) => file,
        Some(Err(error)) => return Err(protected_open_error(*error)),
        None => return Err(JournalError::ProtectedBoundary),
    };
    validate_protected_fd(
        file,
        expected_uid,
        FileType::RegularFile,
        Mode::RUSR | Mode::WUSR,
    )
}

/// Removes an uncommitted compaction file relative to the retained directory.
pub(super) struct ProtectedTemporary<'a> {
    pub(super) directory: &'a File,
    pub(super) name: String,
    pub(super) armed: bool,
}

impl ProtectedTemporary<'_> {
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProtectedTemporary<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.directory, self.name.as_str(), AtFlags::empty());
            let _ = fsync(self.directory);
        }
    }
}

pub(super) fn compact_protected(
    location: &ProtectedJournalLocation,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(File, ReplayState), JournalError> {
    let temporary = protected_compaction_name(&location.name);
    let mut replacement = open_protected_file(
        &location.directory,
        &temporary,
        location.expected_uid,
        true,
        true,
        true,
    )?;
    let mut cleanup = ProtectedTemporary {
        directory: &location.directory,
        name: temporary.clone(),
        armed: true,
    };
    write_compacted(&mut replacement, state, limits)?;
    replacement.sync_all()?;
    if replacement.metadata()?.len() > limits.maximum_journal_bytes {
        return Err(JournalError::JournalTooLarge);
    }
    drop(replacement);
    renameat(
        &location.directory,
        temporary.as_str(),
        &location.directory,
        location.name.as_str(),
    )
    .map_err(rustix_io)?;
    cleanup.disarm();
    fsync(&location.directory).map_err(rustix_io)?;
    let mut file = open_protected_file(
        &location.directory,
        &location.name,
        location.expected_uid,
        false,
        false,
        false,
    )?;
    let replay = replay(&mut file, limits)?;
    if replay.durable_end != file.metadata()?.len() {
        return Err(JournalError::MalformedTransaction(
            "compacted journal has an uncommitted tail",
        ));
    }
    file.seek(SeekFrom::End(0))?;
    Ok((file, replay))
}
