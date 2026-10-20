//! Owned protected physical locations, name observations, and replacement cleanup.
//!
//! This opt-in Unix owner retains real descriptors and uninterpreted denial
//! data. It performs no semantic replay, protected admission, signing, or
//! current-owner construction. Callers retain their original result reservoirs
//! and instantiate the fixed physical error vocabulary with their actual error.
//!
//! Replacement encoding and replay remain above this module while the same
//! directory-borrowing cleanup guard and original temporary name remain live.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, fstat, fsync, openat2, renameat, statat,
};

mod readonly_archive;
pub use readonly_archive::{ReadonlyNameArchiveGeometryV1, ReadonlyNameArchiveV1};

mod writer_witness;
pub use writer_witness::{FileIdentityOriginalsV1, FileIdentityReceivingFootprintV1, WriterWitnessOriginalsV1, WriterWitnessReceivingFootprintV1};

/// Supplies only the original static physical refusal categories.
///
/// I/O conversion retains the actual owned native error. Implementations do not
/// provide replay, signing, authority, or filesystem callbacks.
pub trait ProtectedFailure: From<io::Error> {
    /// Rejects the fixed descriptor, basename, or ancestry boundary.
    const BOUNDARY: Self;
    /// Rejects unavailable no-follow protected opening.
    const UNSUPPORTED_OPEN: Self;
    /// Rejects a replaced original physical name.
    const STALE_NAME: Self;
}

/// Bounds one original Unix path component in bytes.
pub const MAXIMUM_PROTECTED_COMPONENT_BYTES: usize = 255;
/// Bounds the original Journal basename while reserving suffix space.
pub const MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES: usize = 200;

/// Retains the complete original seven-value metadata observation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    /// Returns the original device and inode, without a currentness claim.
    #[must_use]
    pub const fn physical_pair(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the original sampled physical byte length.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.size
    }

    /// Samples the original metadata fields in their declaration order.
    ///
    /// # Errors
    /// Returns the original metadata I/O failure.
    pub fn of<E: From<io::Error>>(file: &File) -> Result<Self, E> {
        let metadata = writer_witness::observe_metadata_once(file, writer_witness::OrdinaryMetadata)?;
        Ok(Self::from_metadata(&metadata))
    }

    /// Projects comparison fields from one already observed metadata sample.
    ///
    /// This performs no IO and supplies no file, native owner, currentness,
    /// protected name, or role authority. Mechanical callers can reuse their
    /// actual metadata sample without performing a second observation.
    #[must_use]
    pub fn from_metadata_data_v1(metadata: &std::fs::Metadata) -> Self {
        Self::from_metadata(metadata)
    }

    // One projection body serves ordinary and retained metadata dispositions.
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

/// Compares the opened directory with the original device and inode pair.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn require_opened_directory_identity<E: ProtectedFailure>(
    directory: &File,
    expected: (u64, u64),
) -> Result<(), E> {
    let opened = FileIdentity::of::<E>(directory)?;
    if (opened.device, opened.inode) != expected {
        return Err(E::BOUNDARY);
    }
    Ok(())
}

/// Retains byte-level metadata for a protected writer readback.
///
/// Its caller must also recheck the fixed directory and names. A flock alone
/// does not prevent another same-UID process from writing an already open file.
pub struct ProtectedWriterNameWitness {
    directory: FileIdentity,
    file: FileIdentity,
    lock: FileIdentity,
}

impl ProtectedWriterNameWitness {
    /// Returns the retained Directory observation.
    #[must_use]
    pub const fn directory(&self) -> FileIdentity {
        self.directory
    }

    /// Returns the retained Journal observation.
    #[must_use]
    pub const fn file(&self) -> FileIdentity {
        self.file
    }

    /// Returns the retained Lock observation.
    #[must_use]
    pub const fn lock(&self) -> FileIdentity {
        self.lock
    }
}

/// Retains the physical names observed by one read-only replay.
pub struct ReadOnlyJournalNameWitness {
    directory_path: PathBuf,
    name: String,
    expected_uid: u32,
    directory_identity: FileIdentity,
    file_identity: FileIdentity,
    lock_identity: FileIdentity,
}

impl ReadOnlyJournalNameWitness {
    /// Re-resolves the originally observed directory, lock, and journal.
    ///
    /// # Errors
    /// Preserves the original native failure or fixed physical refusal.
    pub fn check_named_currentness<E: ProtectedFailure>(&self) -> Result<(), E> {
        let originals = ReadOnlyJournalNamesOriginalsV1::new();
        originals.capture_rooted(self, false, None);
        originals.into_result()
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    /// Resolves a test-owned directory without changing production root ancestry checks.
    ///
    /// # Errors
    /// Preserves the original native failure or fixed physical refusal.
    pub fn check_named_currentness_at_uid_for_test<E: ProtectedFailure>(&self) -> Result<(), E> {
        let directory: File = openat2(
            CWD,
            &self.directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error::<E>)?
        .into();
        validate_protected_fd::<E>(
            &directory,
            self.expected_uid,
            FileType::Directory,
            Mode::RWXU,
        )?;
        self.check_in_directory::<E>(&directory)
    }

    /// Rechecks the original Directory, Lock, and Journal observations in order.
    ///
    /// # Errors
    /// Preserves the original native failure or fixed physical refusal.
    pub fn check_in_directory<E: ProtectedFailure>(&self, directory: &File) -> Result<(), E> {
        let originals = ReadOnlyJournalNamesOriginalsV1::new();
        originals.capture_in_directory(self, directory);
        originals.into_result()
    }
}

impl ReadOnlyJournalNameWitness {
    /// Borrows the original basename without asserting named currentness.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Moves the original path/name/UID and three observations without validation.
    #[must_use]
    pub fn from_original_parts(
        parts: (
            PathBuf,
            String,
            u32,
            FileIdentity,
            FileIdentity,
            FileIdentity,
        ),
    ) -> Self {
        let (directory_path, name, expected_uid, directory_identity, file_identity, lock_identity) =
            parts;
        Self {
            directory_path,
            name,
            expected_uid,
            directory_identity,
            file_identity,
            lock_identity,
        }
    }

    /// Returns the Directory/Journal/Lock pairs already sampled by the caller.
    #[must_use]
    pub const fn physical_pairs(&self) -> ((u64, u64), (u64, u64), (u64, u64)) {
        (
            self.directory_identity.physical_pair(),
            self.file_identity.physical_pair(),
            self.lock_identity.physical_pair(),
        )
    }

    /// Compares the original Journal observation after the caller's name check.
    ///
    /// # Errors
    /// Returns the original metadata failure or fixed boundary refusal.
    pub fn require_file_identity<E: ProtectedFailure>(&self, file: &File) -> Result<(), E> {
        if FileIdentity::of::<E>(file)? != self.file_identity {
            return Err(E::BOUNDARY);
        }
        Ok(())
    }
}

/// Owns the same directory/name/UID and uninterpreted original denial value.
///
/// Construction merely moves existing parts. It cannot create a protected
/// semantic Journal or an accepted current owner.
pub struct ProtectedJournalLocation<P> {
    directory: File,
    name: String,
    expected_uid: u32,
    // Denial data only; the upper owner performs the actual native-history audit.
    original_compaction_selection: P,
}

impl<P> ProtectedJournalLocation<P> {
    /// Moves original parts in the original declaration order without validation.
    #[must_use]
    pub fn from_original_parts(parts: (File, String, u32, P)) -> Self {
        let (directory, name, expected_uid, original_compaction_selection) = parts;
        Self {
            directory,
            name,
            expected_uid,
            original_compaction_selection,
        }
    }

    /// Borrows the original fixed basename.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the original expected owner UID.
    #[must_use]
    pub const fn expected_uid(&self) -> u32 {
        self.expected_uid
    }

    /// Borrows uninterpreted denial data for the original upper audit.
    #[must_use]
    pub const fn original_compaction_selection(&self) -> &P {
        &self.original_compaction_selection
    }

    /// Re-resolves the path and compares the actual retained directory.
    ///
    /// # Errors
    /// Preserves rooted-opening, inspection, and fixed-boundary failures.
    pub fn require_directory<E: ProtectedFailure>(&self, path: &Path, uid: u32) -> Result<File, E> {
        let current = resolve_protected_directory_from_root::<E>(path, uid)?;
        let retained_stat = fstat(&self.directory).map_err(rustix_io::<E>)?;
        let current_stat = fstat(&current).map_err(rustix_io::<E>)?;
        if retained_stat.st_dev != current_stat.st_dev
            || retained_stat.st_ino != current_stat.st_ino
        {
            return Err(E::BOUNDARY);
        }
        Ok(current)
    }

    /// Compares the directory at the original pre-opened consumer frontier.
    ///
    /// # Errors
    /// Returns original fstat errors or the fixed boundary refusal.
    pub fn require_opened_directory<E: ProtectedFailure>(&self, current: &File) -> Result<(), E> {
        let retained_stat = fstat(&self.directory).map_err(rustix_io::<E>)?;
        let current_stat = fstat(current).map_err(rustix_io::<E>)?;
        if retained_stat.st_dev != current_stat.st_dev
            || retained_stat.st_ino != current_stat.st_ino
        {
            return Err(E::BOUNDARY);
        }
        Ok(())
    }

    /// Rechecks Lock then Journal names against the actual retained files.
    ///
    /// # Errors
    /// Preserves original opening, inspection, and stale-name failures.
    pub fn require_names<E: ProtectedFailure>(&self, lock: &File, file: &File) -> Result<(), E> {
        require_protected_file_names_current::<E>(
            &self.directory,
            &self.name,
            self.expected_uid,
            lock,
            file,
        )
    }

    /// Parks the same Lock, Journal and metadata checks in their resident owner.
    ///
    /// Reentry leaves the first result and every reached descriptor unchanged.
    pub fn observe_names_once<E: ProtectedFailure>(
        &self,
        lock: &File,
        file: &File,
        originals: &mut ProtectedFileNamesCurrentOriginalsV1<E>,
    ) {
        originals.capture_once(&self.directory, &self.name, self.expected_uid, lock, file);
    }

    /// Retains the same requested pre-materialization Lock and Journal checks.
    ///
    /// This selects no authority; the enclosing original owns the fixed names.
    pub fn observe_named_files_once<E: ProtectedFailure>(
        &self, name: &str, uid: u32, lock: &File, file: &File,
        originals: &mut ProtectedFileNamesCurrentOriginalsV1<E>,
    ) {
        originals.capture_once(&self.directory, name, uid, lock, file);
    }

    /// Samples Directory, Journal, and Lock in the original writer order.
    ///
    /// # Errors
    /// Returns the first original metadata failure.
    pub fn writer_witness<E: ProtectedFailure>(
        &self,
        file: &File,
        lock: &File,
    ) -> Result<ProtectedWriterNameWitness, E> {
        writer_witness::sample_ordinary(&self.directory, file, lock)
    }

    /// Checks the original writer observations after the caller's name check.
    ///
    /// # Errors
    /// Returns original metadata failures or the fixed stale-name refusal.
    pub fn require_writer_witness<E: ProtectedFailure>(
        &self,
        file: &File,
        lock: &File,
        witness: &ProtectedWriterNameWitness,
    ) -> Result<(), E> {
        writer_witness::compare_ordinary(&self.directory, file, lock, witness)
    }

    /// Begins replacement with the original name, File, and borrowed cleanup.
    ///
    /// # Errors
    /// Preserves exact exclusive-opening and cleanup errors.
    pub fn begin_replacement<E: ProtectedFailure>(
        &self,
    ) -> Result<(String, File, ProtectedTemporary<'_>), E> {
        let (temporary, replacement) = self.begin_replacement_parts::<E>()?;
        let cleanup = ProtectedTemporary {
            directory: &self.directory,
            name: temporary.clone(),
            armed: true,
        };
        Ok((temporary, replacement, cleanup))
    }

    fn begin_replacement_parts<E: ProtectedFailure>(&self) -> Result<(String, File), E> {
        let temporary = protected_compaction_name(&self.name);
        let mut replacement = None;
        self.open_replacement_into::<E>(&temporary, &mut replacement, None)?;
        Ok((temporary, replacement.ok_or(E::BOUNDARY)?))
    }


    fn open_replacement_into<E: ProtectedFailure>(
        &self,
        name: &str,
        file: &mut Option<File>,
        native_error: Option<&mut Option<rustix::io::Errno>>,
    ) -> Result<(), E> {
        open_protected_file_into_original::<E>(
            &self.directory, name, self.expected_uid, true, true, true,
            file, native_error,
        )
    }

    /// Prepares owned cleanup before retaining the actual replacement open.
    ///
    /// The mutable File destination keeps a successfully opened description
    /// even when its following native validation fails. A failed exclusive open
    /// never arms cleanup for someone else's existing temporary name.
    ///
    /// # Errors
    /// Retains the original native/opening refusal beside its actual partials.
    pub fn begin_owned_replacement_retaining_v1<E: ProtectedFailure>(
        self: &Arc<Self>,
        temporary: &mut Option<String>,
        cleanup: &mut Option<OwnedProtectedTemporaryV1<P>>,
        file: &mut Option<File>,
        native_error: &mut Option<rustix::io::Errno>,
    ) -> Result<(), E> {
        if temporary.is_some() || cleanup.is_some() || file.is_some() {
            return Err(E::BOUNDARY);
        }
        let name = temporary.insert(protected_compaction_name(&self.name));
        let debt = cleanup.insert(OwnedProtectedTemporaryV1 {
            location: Arc::clone(self), name: name.clone(), armed: false,
        });
        let result = self.open_replacement_into::<E>(name, file, Some(native_error));
        debt.armed = file.is_some();
        result
    }

    /// Installs the replacement while the same cleanup loan remains alive.
    ///
    /// # Errors
    /// Preserves rename, directory synchronization, and protected reopen errors.
    pub fn install_replacement<E: ProtectedFailure>(
        &self,
        temporary: &str,
        cleanup: &mut ProtectedTemporary<'_>,
    ) -> Result<File, E> {
        self.rename_replacement::<E>(temporary)?;
        cleanup.disarm();
        self.sync_and_reopen_replacement::<E>()
    }
}

impl<P> ProtectedJournalLocation<P> {
    fn rename_replacement<E: ProtectedFailure>(&self, temporary: &str) -> Result<(), E> {
        renameat(
            &self.directory,
            temporary,
            &self.directory,
            self.name.as_str(),
        )
        .map_err(rustix_io::<E>)
    }

    fn sync_and_reopen_replacement<E: ProtectedFailure>(&self) -> Result<File, E> {
        let mut file = None;
        self.sync_and_open_replacement_into::<E>(&mut file, None)?;
        file.ok_or(E::BOUNDARY)
    }

    fn sync_and_open_replacement_into<E: ProtectedFailure>(
        &self,
        file: &mut Option<File>,
        native_error: Option<&mut Option<rustix::io::Errno>>,
    ) -> Result<(), E> {
        fsync(&self.directory).map_err(rustix_io::<E>)?;
        open_protected_file_into_original::<E>(
            &self.directory, &self.name, self.expected_uid, false, false, false,
            file, native_error,
        )
    }

    /// Installs owned cleanup while retaining a reached reopened description.
    ///
    /// # Errors
    /// Preserves original rename/sync/open failures or rejects foreign debt.
    pub fn install_owned_replacement_retaining_v1<E: ProtectedFailure>(
        self: &Arc<Self>,
        temporary: &str,
        cleanup: &mut OwnedProtectedTemporaryV1<P>,
        file: &mut Option<File>,
        native_error: &mut Option<rustix::io::Errno>,
    ) -> Result<(), E> {
        if !Arc::ptr_eq(self, &cleanup.location) || !cleanup.armed
            || temporary != cleanup.name || file.is_some()
        {
            return Err(E::BOUNDARY);
        }
        self.rename_replacement::<E>(temporary)?;
        cleanup.armed = false;
        self.sync_and_open_replacement_into::<E>(file, Some(native_error))
    }

}

/// Retains cleanup debt against the original physical directory allocation.
///
/// An unfinished selected owner can park this complete carrier beside the
/// replacement File without borrowing itself. It duplicates no descriptor and
/// exposes no directory or mutation API. The closed caller owns disposition.
pub struct OwnedProtectedTemporaryV1<P> {
    location: Arc<ProtectedJournalLocation<P>>,
    name: String,
    armed: bool,
}

impl<P> Drop for OwnedProtectedTemporaryV1<P> {
    fn drop(&mut self) {
        opening::retire_temporary(&self.location.directory, &self.name, self.armed);
    }
}

mod names;
pub use names::ProtectedFileNamesCurrentOriginalsV1;

mod readonly_names;
pub use readonly_names::ReadOnlyJournalNamesOriginalsV1;

mod opening;
pub use opening::{
    ProtectedAncestry, ProtectedTemporary, protected_directory_flags,
    WriterAcquisitionRetentionV1, WriterAcquisitionSlotsV1, acquire_writer_originals_v1,
    acquire_writer_originals_ordinary_v1, acquire_empty_writer_originals_ordinary_v1, writer_acquisition_temporary_shape_v1,
    resolve_protected_directory_from_root, resolve_protected_directory_from_root_original,
    traverse_protected_directory, validate_basename, rustix_io, protected_open_error,
    protected_compaction_name, reject_operator_provisioning_history,
    remove_stale_protected_compaction, reject_stale_protected_compaction, validate_protected_fd,
    open_protected_file, open_protected_file_into, open_protected_file_into_original,
    open_read_only_protected_file, require_protected_file_names_current,
    open_read_only_protected_file_original,
};

/// Names the original physical metadata DATA, not an admitted file owner.
pub type OriginalFileMetadataV1 = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

/// Observes the complete original physical metadata recipe without admitting custody.
///
/// Directory entry/link/time changes are intentionally excluded because the
/// serialized purpose owner creates entries. File links, extents and times
/// remain exact; the genuine caller owns names, modes, bounds and OFD custody.
///
/// # Errors
/// Returns the actual metadata error. No descriptor is moved or duplicated.
pub fn inspect_original_file_metadata(
    file: &std::fs::File,
) -> std::io::Result<OriginalFileMetadataV1> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    let (links, length, modified, modified_ns, changed, changed_ns) = if metadata.is_dir() {
        (0, 0, 0, 0, 0, 0)
    } else {
        (
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        links,
        length,
        modified,
        modified_ns,
        changed,
        changed_ns,
    ))
}

impl<P> ProtectedJournalLocation<P> {
    /// Samples the original complete directory metadata recipe.
    ///
    /// # Errors
    /// Returns the original metadata I/O error.
    pub fn directory_metadata(&self) -> io::Result<OriginalFileMetadataV1> {
        inspect_original_file_metadata(&self.directory)
    }

    /// Inspects the retained directory with the existing Linux mount API.
    ///
    /// # Errors
    /// Returns the existing Linux error from the original MountId operation.
    #[cfg(target_os = "linux")]
    pub fn directory_mount_id(
        &self,
    ) -> Result<aos_sandbox_linux::inventory::MountId, aos_sandbox_linux::Error> {
        use std::os::fd::AsFd as _;
        aos_sandbox_linux::inventory::MountId::from_fd(self.directory.as_fd())
    }

    /// Reads an original directory attribute at the caller's policy frontier.
    ///
    /// # Errors
    /// Returns the original xattr I/O error.
    pub fn directory_xattr(
        &self,
        name: &str,
        bytes: &mut [u8],
    ) -> Result<usize, rustix::io::Errno> {
        rustix::fs::fgetxattr(&self.directory, name, bytes)
    }

    /// Opens a named child with the existing Linux no-follow implementation.
    ///
    /// # Errors
    /// Returns the exact raw errno before the caller parks or projects it.
    #[cfg(target_os = "linux")]
    pub fn open_named_child(&self, name: &str) -> Result<std::os::fd::OwnedFd, rustix::io::Errno> {
        aos_sandbox_linux::protected_file::open_nofollow_child(&self.directory, name)
    }

    /// Parks a named original before the existing protected-file checks.
    ///
    /// # Errors
    /// Returns the caller's actual physical error before its original cleanup.
    pub fn open_named_original<E: ProtectedFailure>(
        &self,
        name: &str,
        expected_uid: u32,
        create: bool,
        exclusive: bool,
        truncate: bool,
        original: &mut Option<File>,
    ) -> Result<(), E> {
        open_protected_file_into::<E>(
            &self.directory,
            name,
            expected_uid,
            create,
            exclusive,
            truncate,
            original,
        )
    }

    /// Inspects a staged name without following a symlink.
    ///
    /// # Errors
    /// Returns the original statat errno.
    pub fn inspect_staged_name(&self, name: &str) -> Result<rustix::fs::Stat, rustix::io::Errno> {
        statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
    }

    /// Opens the original writable exclusive stage and returns the real file.
    ///
    /// # Errors
    /// Returns the original openat errno.
    pub fn open_exclusive_stage(
        &self,
        name: &str,
    ) -> Result<std::os::fd::OwnedFd, rustix::io::Errno> {
        rustix::fs::openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
    }

    /// Publishes the original stage using the original no-replace rename.
    ///
    /// # Errors
    /// Returns the original rename errno.
    #[cfg(target_os = "linux")]
    pub fn publish_exclusive_stage(
        &self,
        temporary: &str,
        output: &str,
    ) -> Result<(), rustix::io::Errno> {
        rustix::fs::renameat_with(
            &self.directory,
            temporary,
            &self.directory,
            output,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    }

    /// Synchronizes the original directory at the caller's publication frontier.
    ///
    /// # Errors
    /// Returns the original fsync errno.
    pub fn sync_directory(&self) -> Result<(), rustix::io::Errno> {
        fsync(&self.directory)
    }

    /// Duplicates the actual directory only for the existing test fixture.
    ///
    /// # Errors
    /// Returns the original descriptor-duplication I/O error.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn clone_directory_for_test(&self) -> io::Result<File> {
        self.directory.try_clone()
    }

    /// Rechecks an existing test-owned path before its original name bookend.
    ///
    /// # Errors
    /// Returns original physical opening, inspection, or stale-name failures.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn require_directory_at_uid_for_test<E: ProtectedFailure>(
        &self,
        path: &Path,
        uid: u32,
    ) -> Result<File, E> {
        let current: File = openat2(
            CWD,
            path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error::<E>)?
        .into();
        validate_protected_fd::<E>(&current, uid, FileType::Directory, Mode::RWXU)?;
        let held = fstat(&self.directory).map_err(rustix_io::<E>)?;
        let named = fstat(&current).map_err(rustix_io::<E>)?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(E::STALE_NAME);
        }
        Ok(current)
    }
}

impl<P> ProtectedJournalLocation<P> {
    /// Checks the requested names at the retained pre-materialization frontier.
    ///
    /// # Errors
    /// Returns the same original opening, inspection, or stale-name error.
    pub fn require_named_files<E: ProtectedFailure>(
        &self,
        name: &str,
        uid: u32,
        lock: &File,
        file: &File,
    ) -> Result<(), E> {
        require_protected_file_names_current::<E>(&self.directory, name, uid, lock, file)
    }
}

mod readonly_acquisition;
mod readonly_prefix;

pub use readonly_prefix::CapturedReplayPrefixPostV1;
pub use readonly_acquisition::{
    CompletedReadOnlyAcquisitionV1, ReadOnlyAcquisitionOriginalsV1, ReadOnlyAcquisitionSlotsV1,
    acquire_readonly_directory_originals_v1, acquire_readonly_files_originals_v1,
};

/// Fills the existing Nix child/HELLO pair from one supplied actual lock file.
///
/// This mechanical recipe accepts an already-owned native capability, not a
/// path, original, payment or role proof. Selected private writers invoke it
/// only through their sealed operation port; actual callers retain each slot.
///
/// # Errors
/// Preserves duplicate, duplicate, then original metadata order. A reached
/// duplicate remains in its real destination if the following step fails.
pub fn duplicate_nix_lock_pair_original_v1(
    original: &File,
    child: &mut Option<std::os::fd::OwnedFd>,
    hello: &mut Option<std::os::fd::OwnedFd>,
) -> io::Result<OriginalFileMetadataV1> {
    *child = Some(rustix::io::fcntl_dupfd_cloexec(original, 3)
        .map_err(|cause| io::Error::from_raw_os_error(cause.raw_os_error()))?);
    *hello = Some(rustix::io::fcntl_dupfd_cloexec(original, 3)
        .map_err(|cause| io::Error::from_raw_os_error(cause.raw_os_error()))?);
    inspect_original_file_metadata(original)
}

#[cfg(any(test, feature = "test-fixtures"))]
pub use opening::{acquire_writer_fixture_originals_ordinary_v1,
    acquire_writer_fixture_originals_retaining_v1};
