//! Shares the ordered native writer acquisition without a semantic constructor.
//!
//! Callers supply their actual resident destinations and error vocabulary.
//! No callback, policy grant, parser or role selector crosses this boundary.

use std::fs::File;
use std::path::Path;
use rustix::fs::{FileType, FlockOperation, Mode, flock, fsync};

use super::{open_protected_file_into_original, resolve_protected_directory_from_root_original,
    remove_stale_protected_compaction, reject_stale_protected_compaction, rustix_io,
    validate_basename, validate_protected_fd, open_protected_file};
use crate::geometry::{NativeGeometryBounds, validate_native_bounds};
use crate::framing::FrameError;
use crate::protected_storage::{ProtectedFailure, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES};

/// Borrows actual native acquisition slots without transferring their custody.
///
/// This cannot construct a journal, admit replay or issue a protected writer.
/// Field order follows the existing upper acquisition destinations.
pub struct WriterAcquisitionSlotsV1<'owner, E> {
    /// Retains every reached root/path ancestor.
    pub ancestors: &'owner mut Vec<File>,
    /// Parks the final original directory before its later checks.
    pub directory: &'owner mut Option<File>,
    /// Parks the lock FD before its validation.
    pub lock: &'owner mut Option<File>,
    /// Parks the data FD before its validation.
    pub file: &'owner mut Option<File>,
    /// Retains the complete lock-open result.
    pub lock_open: &'owner mut Option<Result<(), E>>,
    /// Retains the complete flock result.
    pub lock_claim: &'owner mut Option<Result<(), E>>,
    /// Retains stale-compaction cleanup or refusal.
    pub compaction: &'owner mut Option<Result<(), E>>,
    /// Retains the complete data-open result.
    pub file_open: &'owner mut Option<Result<(), E>>,
    /// Retains directory sync after a create-capable entrance.
    pub directory_sync: &'owner mut Option<Result<(), E>>,
}

/// Borrows optional additional errno and typed-error destinations.
pub struct WriterAcquisitionRetentionV1<'owner, E> {
    /// Retains the actual root traversal's typed refusal.
    pub directory_error: &'owner mut Option<E>,
    /// Retains the root traversal's native errno before error projection.
    pub directory_native_error: &'owner mut Option<rustix::io::Errno>,
    /// Retains lock-open native errno.
    pub lock_native_error: &'owner mut Option<rustix::io::Errno>,
    /// Retains flock native errno.
    pub lock_claim_native_error: &'owner mut Option<rustix::io::Errno>,
    /// Retains data-open native errno.
    pub file_native_error: &'owner mut Option<rustix::io::Errno>,
}

#[derive(Clone, Copy)]
enum HistoryMode {
    Ordinary,
    EmptyProvision,
}

/// Acquires native originals in the original traversal/limits/lock/data order.
///
/// All actual files and reached errors remain in the supplied destinations.
/// The static `already_locked` error is classification DATA, not a callback.
/// Semantic replay and protected-location construction remain upper-owned.
///
/// # Errors
/// Returns the original physical/configuration refusal; retained paths project
/// their typed/native causes only after parking them in the actual owner.
pub fn acquire_writer_originals_v1<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    retention: Option<WriterAcquisitionRetentionV1<'_, E>>,
) -> Result<(), E> {
    acquire_writer_inner(slots, path, name, limits, uid, allow_create,
        already_locked, retention, false, None, HistoryMode::Ordinary)
}

/// Runs the same acquisition with the original immediate native dispositions.
///
/// The caller keeps `lock_name` through its later recovery call and consumes
/// the actual result slots before disposing the other ordinary originals.
/// No retained or selected-role caller uses this immediate adapter.
///
/// # Errors
/// Preserves traversal and per-file immediate errors; complete step errors stay
/// in the supplied slots until the caller moves them at its return boundary.
pub fn acquire_writer_originals_ordinary_v1<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    lock_name: &mut Option<String>,
) -> Result<(), E> {
    acquire_writer_inner(slots, path, name, limits, uid, allow_create,
        already_locked, None, true, Some(lock_name), HistoryMode::Ordinary)
}

/// Acquires an empty journal while rejecting every preexisting physical history.
///
/// This stricter mechanical profile shares the rooted/lock/file engine. It
/// checks the held lock length after flock and the data length before directory
/// sync, rejects stale compaction without cleanup, and grants no role or funding.
///
/// # Errors
/// Preserves actual IO/physical errors and refuses any nonempty lock or data.
pub fn acquire_empty_writer_originals_ordinary_v1<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    already_locked: E,
    lock_name: &mut Option<String>,
) -> Result<(), E> {
    acquire_writer_inner(slots, path, name, limits, uid, true,
        already_locked, None, true, Some(lock_name), HistoryMode::EmptyProvision)
}

/// Acquires a genuine private fixture directory through the same writer body.
///
/// Only the explicit test fixture feature omits root ancestry. Actual final
/// directory/name/owner/mode/lock/data checks and native causes stay unchanged.
/// No File, opened native prefix, map, identity or successful result is adopted.
///
/// # Errors
/// Preserves the actual no-follow directory open and subsequent writer refusal.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn acquire_writer_fixture_originals_ordinary_v1<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    lock_name: &mut Option<String>,
) -> Result<(), E> {
    acquire_writer_fixture_inner(
        slots, path, name, limits, uid, allow_create, already_locked,
        None, true, Some(lock_name),
    )
}

/// Acquires a real fixture while retaining reached native acquisition errors.
///
/// This fixture-only entry omits root ancestry, while sharing all final
/// directory, no-follow file, owner, mode and lock checks with production.
/// No File, replay state, identity or successful DATA can be supplied.
///
/// # Errors
/// Preserves actual fixture directory and subsequent file acquisition causes.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn acquire_writer_fixture_originals_retaining_v1<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    retention: Option<WriterAcquisitionRetentionV1<'_, E>>,
) -> Result<(), E> {
    acquire_writer_fixture_inner(
        slots, path, name, limits, uid, allow_create, already_locked,
        retention, false, None,
    )
}

#[cfg(any(test, feature = "test-fixtures"))]
fn acquire_writer_fixture_inner<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    mut retention: Option<WriterAcquisitionRetentionV1<'_, E>>,
    ordinary: bool,
    lock_name: Option<&mut Option<String>>,
) -> Result<(), E> {
    use rustix::fs::{CWD, ResolveFlags, openat2};
    use super::{protected_directory_flags, protected_open_error};

    let directory: File = match openat2(
        CWD, path, protected_directory_flags(), Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(directory) => directory.into(),
        Err(cause) => {
            let error = protected_open_error::<E>(cause);
            return if let Some(originals) = retention.as_mut() {
                *originals.directory_native_error = Some(cause);
                *originals.directory_error = Some(error);
                Err(E::BOUNDARY)
            } else {
                Err(error)
            };
        }
    };
    *slots.directory = Some(directory);
    acquire_writer_files_inner(slots, name, limits, uid, allow_create,
        already_locked, retention, ordinary, lock_name, HistoryMode::Ordinary)
}

fn acquire_writer_inner<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    path: &Path,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    mut retention: Option<WriterAcquisitionRetentionV1<'_, E>>,
    ordinary: bool,
    ordinary_lock_name: Option<&mut Option<String>>,
    history: HistoryMode,
) -> Result<(), E> {
    let directory = resolve_protected_directory_from_root_original::<E>(
        path, uid, if ordinary { None } else { Some(&mut *slots.ancestors) },
        retention.as_mut().map(|originals| &mut *originals.directory_native_error),
    );
    *slots.directory = Some(match directory {
        Ok(directory) => directory,
        Err(error) => {
            if let Some(originals) = retention.as_mut() {
                *originals.directory_error = Some(error);
                return Err(E::BOUNDARY);
            }
            return Err(error);
        }
    });
    acquire_writer_files_inner(slots, name, limits, uid, allow_create,
        already_locked, retention, ordinary, ordinary_lock_name, history)
}

fn acquire_writer_files_inner<E: ProtectedFailure + From<FrameError>>(
    slots: WriterAcquisitionSlotsV1<'_, E>,
    name: &str,
    limits: NativeGeometryBounds,
    uid: u32,
    allow_create: bool,
    already_locked: E,
    mut retention: Option<WriterAcquisitionRetentionV1<'_, E>>,
    ordinary: bool,
    ordinary_lock_name: Option<&mut Option<String>>,
    history: HistoryMode,
) -> Result<(), E> {
    validate_native_bounds(limits)?;
    if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
        return Err(E::BOUNDARY);
    }
    validate_basename::<E>(name)?;
    let directory = slots.directory.as_ref().ok_or(E::BOUNDARY)?;
    validate_protected_fd::<E>(directory, uid, FileType::Directory, Mode::RWXU)?;
    let lock_name = format!("{name}.lock");
    let lock_name = if let Some(slot) = ordinary_lock_name {
        *slot = Some(lock_name);
        slot.as_deref().ok_or(E::BOUNDARY)?
    } else {
        &lock_name
    };
    *slots.lock_open = Some(if ordinary {
        open_protected_file::<E>(directory, lock_name, uid, allow_create, false, false)
            .map(|file| { *slots.lock = Some(file); })
    } else {
        open_protected_file_into_original::<E>(
            directory, lock_name, uid, allow_create, false, false, slots.lock,
            retention.as_mut().map(|originals| &mut *originals.lock_native_error),
        )
    });
    require_step(slots.lock_open)?;
    let lock = slots.lock.as_ref().ok_or(E::BOUNDARY)?;
    *slots.lock_claim = Some(flock(lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if let Some(originals) = retention.as_mut() {
            *originals.lock_claim_native_error = Some(error);
        }
        if error == rustix::io::Errno::WOULDBLOCK { already_locked }
        else { rustix_io::<E>(error) }
    }));
    require_step(slots.lock_claim)?;
    if matches!(history, HistoryMode::EmptyProvision) {
        super::reject_operator_provisioning_history::<E>(lock.metadata()?.len())?;
    }
    *slots.compaction = Some(if allow_create && matches!(history, HistoryMode::Ordinary) {
        remove_stale_protected_compaction::<E>(directory, name)
    } else {
        reject_stale_protected_compaction::<E>(directory, name)
    });
    require_step(slots.compaction)?;
    *slots.file_open = Some(if ordinary {
        open_protected_file::<E>(directory, name, uid, allow_create, false, false)
            .map(|file| { *slots.file = Some(file); })
    } else {
        open_protected_file_into_original::<E>(
            directory, name, uid, allow_create, false, false, slots.file,
            retention.as_mut().map(|originals| &mut *originals.file_native_error),
        )
    });
    require_step(slots.file_open)?;
    if matches!(history, HistoryMode::EmptyProvision) {
        let file = slots.file.as_ref().ok_or(E::BOUNDARY)?;
        super::reject_operator_provisioning_history::<E>(file.metadata()?.len())?;
    }
    if allow_create {
        *slots.directory_sync = Some(fsync(directory).map_err(rustix_io::<E>));
        require_step(slots.directory_sync)?;
    }
    Ok(())
}

/// Prices the reached lower traversal, native-stat and basename temporaries.
///
/// The pair is additional memory bytes and resident metadata cells, not a
/// descriptor promise, account, paid original or traversal permission. Actual
/// rooted File owners, path/name backing bytes and upper acquisition slots are
/// priced separately by their caller. Native Stat/Result cells use their actual
/// compiled scalar storage width rather than a descriptor-count proxy.
#[must_use]
pub fn writer_acquisition_temporary_shape_v1(path: &Path) -> Option<(usize, usize)> {
    use std::mem::{size_of, size_of_val};
    use std::os::unix::ffi::OsStrExt as _;
    use super::{ControllerDirectoryTraversalV1, ProtectedAncestry};

    let components = path.as_os_str().as_bytes().get(1..)?.split(|byte| *byte == b'/');
    let stat_bytes = size_of::<rustix::fs::Stat>()
        .checked_add(size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>())?;
    let memory = size_of::<ProtectedAncestry>()
        .checked_add(size_of::<WriterAcquisitionSlotsV1<'_, ()>>().checked_mul(2)?)?
        .checked_add(size_of::<Option<WriterAcquisitionRetentionV1<'_, ()>>>().checked_mul(2)?)?
        .checked_add(size_of::<ControllerDirectoryTraversalV1<'_>>())?
        .checked_add(stat_bytes)?
        .checked_add(size_of::<String>().checked_mul(2)?)?
        .checked_add(size_of_val(&components).checked_mul(2)?)?
        .checked_add(size_of::<File>())?
        .checked_add(size_of::<&[u8]>().checked_mul(2)?)?
        .checked_add(size_of::<Mode>())?
        .checked_add(size_of::<rustix::fs::OFlags>())?
        .checked_add(size_of::<rustix::fs::ResolveFlags>())?
        .checked_add(size_of::<u32>())?
        .checked_add(size_of::<HistoryMode>().checked_mul(2)?)?
        .checked_add(size_of::<bool>().checked_mul(2)?)?;
    let stat_cells = stat_bytes.checked_add(size_of::<usize>().checked_sub(1)?)?
        .checked_div(size_of::<usize>())?;
    // Ancestry2, traversal tag/payload2, current child1, iterator/original2,
    // basename controls2, byte-slice controls2, flags3 and expected UID1.
    let cells = stat_cells.checked_add(2 + 2 + 1 + 2 + 2 + 2 + 3 + 1)?;
    Some((memory, cells))
}

fn require_step<E: ProtectedFailure>(step: &Option<Result<(), E>>) -> Result<(), E> {
    if matches!(step, Some(Ok(()))) { Ok(()) } else { Err(E::BOUNDARY) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    #[derive(Debug, thiserror::Error)]
    enum Failure {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Frame(#[from] FrameError),
        #[error("physical boundary")]
        Boundary,
    }

    impl ProtectedFailure for Failure {
        const BOUNDARY: Self = Self::Boundary;
        const UNSUPPORTED_OPEN: Self = Self::Boundary;
        const STALE_NAME: Self = Self::Boundary;
    }

    fn provision(path: &Path) -> Result<(), Failure> {
        let mut ancestors = Vec::new();
        let mut directory = Some(File::open(path)?);
        let uid = directory.as_ref().unwrap().metadata()?.uid();
        let mut lock = None;
        let mut file = None;
        let mut lock_open = None;
        let mut lock_claim = None;
        let mut compaction = None;
        let mut file_open = None;
        let mut directory_sync = None;
        let mut lock_name = None;
        let limits = NativeGeometryBounds {
            maximum_journal_bytes: 4096,
            maximum_record_bytes: 512,
            maximum_key_bytes: 32,
            maximum_records_per_transaction: 16,
            maximum_transaction_bytes: 2048,
            maximum_transactions: 32,
            maximum_materialized_bytes: 4096,
            maximum_materialized_records: 32,
        };
        acquire_writer_files_inner(
            WriterAcquisitionSlotsV1 {
                ancestors: &mut ancestors,
                directory: &mut directory,
                lock: &mut lock,
                file: &mut file,
                lock_open: &mut lock_open,
                lock_claim: &mut lock_claim,
                compaction: &mut compaction,
                file_open: &mut file_open,
                directory_sync: &mut directory_sync,
            },
            "history", limits, uid, true, Failure::Boundary, None, true,
            Some(&mut lock_name), HistoryMode::EmptyProvision,
        )
    }

    fn put(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).mode(0o600).open(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn nonempty_lock_refuses_before_creating_or_cleaning_other_names() {
        let directory = tempfile::tempdir().unwrap();
        put(&directory.path().join("history.lock"), b"old lock history");
        put(&directory.path().join("history.compact.tmp"), b"old replacement");

        assert!(matches!(provision(directory.path()), Err(Failure::Boundary)));

        assert!(!directory.path().join("history").exists());
        assert_eq!(std::fs::read(directory.path().join("history.lock")).unwrap(), b"old lock history");
        assert_eq!(std::fs::read(directory.path().join("history.compact.tmp")).unwrap(), b"old replacement");
    }

    #[test]
    fn stale_compaction_and_nonempty_data_are_preserved_without_repair() {
        let directory = tempfile::tempdir().unwrap();
        put(&directory.path().join("history.compact.tmp"), b"old replacement");

        assert!(matches!(provision(directory.path()), Err(Failure::Boundary)));
        assert!(!directory.path().join("history").exists());
        assert_eq!(std::fs::read(directory.path().join("history.compact.tmp")).unwrap(), b"old replacement");

        std::fs::remove_file(directory.path().join("history.compact.tmp")).unwrap();
        put(&directory.path().join("history"), b"uncommitted history");
        assert!(matches!(provision(directory.path()), Err(Failure::Boundary)));
        assert_eq!(std::fs::read(directory.path().join("history")).unwrap(), b"uncommitted history");
    }
}
