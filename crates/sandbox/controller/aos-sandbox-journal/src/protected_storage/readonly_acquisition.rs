//! Shares the original retained read-only directory, lock and file acquisition.
//!
//! The directory and files are separate physical frontiers because the existing
//! caller validates its configured replay limits between them. Both frontiers
//! borrow the same actual destinations. Neither creates a semantic reader,
//! grants a role, authenticates a path, or supplies a receiving allowance.

use std::error::Error;
use std::fs::File;
use std::path::Path;

use super::{
    FileIdentity, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES, ProtectedFailure,
    open_read_only_protected_file_original, require_opened_directory_identity,
    resolve_protected_directory_from_root_original, validate_basename,
};

/// Borrows the actual physical destinations of one retained read-only opener.
///
/// Fields are custody slots rather than proof inputs. The role owns fixed path,
/// UID, configuration, funding, semantic replay and independent later posts.
pub struct ReadOnlyAcquisitionSlotsV1<'original, E> {
    /// Retains each reached ancestor before its original checks.
    pub ancestors: &'original mut Vec<File>,
    /// Retains the complete directory-opening result.
    pub directory: &'original mut Option<Result<File, E>>,
    /// Retains the raw rooted-opening error before its typed projection.
    pub directory_native_error: &'original mut Option<rustix::io::Errno>,
    /// Retains the comparison with the caller's original directory identity.
    pub directory_binding: &'original mut Option<Result<(), E>>,
    /// Retains the complete original directory metadata result.
    pub directory_identity: &'original mut Option<Result<FileIdentity, E>>,
    /// Retains the actual opened lock or its raw error.
    pub lock: &'original mut Option<Result<File, rustix::io::Errno>>,
    /// Retains the original lock-opening and validation result.
    pub lock_validation: &'original mut Option<Result<(), E>>,
    /// Retains the complete original lock metadata result.
    pub lock_identity: &'original mut Option<Result<FileIdentity, E>>,
    /// Retains the actual opened journal or its raw error.
    pub file: &'original mut Option<Result<File, rustix::io::Errno>>,
    /// Retains the original journal-opening and validation result.
    pub file_validation: &'original mut Option<Result<(), E>>,
    /// Retains the complete original journal metadata result.
    pub file_identity: &'original mut Option<Result<FileIdentity, E>>,
    /// Optionally retains the actual formatted lock basename before its open.
    /// Ordinary callers preserve the original argument-temporary disposal.
    pub lock_name: Option<&'original mut Option<String>>,
}

impl<E> ReadOnlyAcquisitionSlotsV1<'_, E> {
    /// Prices the actual borrowed slot construction and two returned results.
    ///
    /// This is representation DATA. Existing role suppliers add it before the
    /// shared acquisition engine; this helper creates no receiving allowance.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<(), E>>().checked_mul(2)?)
    }

    /// Reports no namespace entries for borrowed slots and result carriers.
    ///
    /// Their complete construction uses byte permits. Actual rooted names and
    /// descriptor custody remain priced by the caller's native recipe.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        0
    }
}

/// Resolves and binds the original directory in the existing operation order.
///
/// The caller must enter once and already fund this physical prefix. Its own
/// replay-limit validation remains between this function and file acquisition.
///
/// # Errors
/// Returns the original rooted-opening or identity refusal; every reached
/// descriptor and whole error remains in its actual supplied destination.
pub fn acquire_readonly_directory_originals_v1<E: ProtectedFailure>(
    path: &Path,
    uid: u32,
    expected_directory: (u64, u64),
    originals: &mut ReadOnlyAcquisitionSlotsV1<'_, E>,
) -> Result<(), E> {
    *originals.directory = Some(resolve_protected_directory_from_root_original::<E>(
        path,
        uid,
        Some(&mut *originals.ancestors),
        Some(&mut *originals.directory_native_error),
    ));
    let directory = originals.directory.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::BOUNDARY)?;
    *originals.directory_binding = Some(require_opened_directory_identity::<E>(
        directory, expected_directory,
    ));
    require_step(originals.directory_binding)
}

/// Opens the same retained directory's lock and journal in the original order.
///
/// The role validates its replay limits immediately before this frontier. This
/// function retains the existing basename, directory, lock and file predicates;
/// it performs no flock, replay, mutation, or semantic admission.
///
/// # Errors
/// Returns the original basename, opening, metadata or physical refusal while
/// preserving all reached originals and their unprojected errors in place.
pub fn acquire_readonly_files_originals_v1<E: ProtectedFailure>(
    name: &str,
    uid: u32,
    originals: &mut ReadOnlyAcquisitionSlotsV1<'_, E>,
) -> Result<(), E> {
    let directory = originals.directory.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::BOUNDARY)?;
    if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
        return Err(E::BOUNDARY);
    }
    validate_basename::<E>(name)?;
    *originals.directory_identity = Some(FileIdentity::of::<E>(directory));
    originals.directory_identity.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::BOUNDARY)?;
    match originals.lock_name.as_mut() {
        None => {
            *originals.lock_validation = Some(open_read_only_protected_file_original::<E>(
                directory, &format!("{name}.lock"), uid, originals.lock,
            ));
        }
        Some(slot) => {
            **slot = Some(format!("{name}.lock"));
            let lock_name = slot.as_ref().ok_or(E::BOUNDARY)?;
            *originals.lock_validation = Some(open_read_only_protected_file_original::<E>(
                directory, lock_name, uid, originals.lock,
            ));
        }
    }
    require_step(originals.lock_validation)?;
    let lock = originals.lock.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::BOUNDARY)?;
    *originals.lock_identity = Some(FileIdentity::of::<E>(lock));
    originals.lock_identity.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::BOUNDARY)?;
    *originals.file_validation = Some(open_read_only_protected_file_original::<E>(
        directory, name, uid, originals.file,
    ));
    require_step(originals.file_validation)?;
    let file = originals.file.as_mut()
        .and_then(|result| result.as_mut().ok())
        .ok_or(E::BOUNDARY)?;
    *originals.file_identity = Some(FileIdentity::of::<E>(file));
    originals.file_identity.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(E::BOUNDARY)?;
    Ok(())
}

fn require_step<E: ProtectedFailure>(result: &Option<Result<(), E>>) -> Result<(), E> {
    if matches!(result, Some(Ok(()))) {
        Ok(())
    } else {
        Err(E::BOUNDARY)
    }
}

/// Owns the same physical acquisition destinations for a new role adapter.
///
/// This mechanical owner has no positive role constructor. A role must use its
/// real fixed recipe and original purpose before entry and must retain the same
/// owner through canonical replay, semantic validation and all owed posts.
pub struct ReadOnlyAcquisitionOriginalsV1<E> {
    ancestors: Vec<File>,
    directory: Option<Result<File, E>>,
    directory_native_error: Option<rustix::io::Errno>,
    directory_binding: Option<Result<(), E>>,
    directory_identity: Option<Result<FileIdentity, E>>,
    lock: Option<Result<File, rustix::io::Errno>>,
    lock_validation: Option<Result<(), E>>,
    lock_identity: Option<Result<FileIdentity, E>>,
    file: Option<Result<File, rustix::io::Errno>>,
    file_validation: Option<Result<(), E>>,
    file_identity: Option<Result<FileIdentity, E>>,
    lock_name: Option<String>,
    directory_completion: Option<Result<(), E>>,
    files_completion: Option<Result<(), E>>,
    closed: bool,
    transferred: bool,
    ordinary_error_taken: bool,
}

impl<E> ReadOnlyAcquisitionOriginalsV1<E> {
    /// Creates inert physical destinations without allocation or I/O.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ancestors: Vec::new(),
            directory: None,
            directory_native_error: None,
            directory_binding: None,
            directory_identity: None,
            lock: None,
            lock_validation: None,
            lock_identity: None,
            file: None,
            file_validation: None,
            file_identity: None,
            lock_name: None,
            directory_completion: None,
            files_completion: None,
            closed: false,
            transferred: false,
            ordinary_error_taken: false,
        }
    }

    fn slots(&mut self) -> ReadOnlyAcquisitionSlotsV1<'_, E> {
        ReadOnlyAcquisitionSlotsV1 {
            ancestors: &mut self.ancestors,
            directory: &mut self.directory,
            directory_native_error: &mut self.directory_native_error,
            directory_binding: &mut self.directory_binding,
            directory_identity: &mut self.directory_identity,
            lock: &mut self.lock,
            lock_validation: &mut self.lock_validation,
            lock_identity: &mut self.lock_identity,
            file: &mut self.file,
            file_validation: &mut self.file_validation,
            file_identity: &mut self.file_identity,
            lock_name: Some(&mut self.lock_name),
        }
    }

    /// Borrows the same actual held journal after physical acquisition.
    #[must_use]
    pub fn file(&self) -> Option<&File> {
        self.file.as_ref()?.as_ref().ok()
    }

    /// Borrows the same actual directory without creating currentness.
    #[must_use]
    pub fn directory(&self) -> Option<&File> {
        self.directory.as_ref()?.as_ref().ok()
    }

    /// Borrows the same actual lock without claiming or writing it.
    #[must_use]
    pub fn lock(&self) -> Option<&File> {
        self.lock.as_ref()?.as_ref().ok()
    }

    /// Copies the three actual metadata observations as comparison DATA.
    #[must_use]
    pub fn identities(&self) -> Option<(FileIdentity, FileIdentity, FileIdentity)> {
        Some((
            *self.directory_identity.as_ref()?.as_ref().ok()?,
            *self.file_identity.as_ref()?.as_ref().ok()?,
            *self.lock_identity.as_ref()?.as_ref().ok()?,
        ))
    }

    /// Prices actual owner, borrowed slots and both result/return carriers.
    ///
    /// This excludes path/name, ancestor backing, replay/model growth and later
    /// name archives, which the role must price from its actual fixed recipe.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(ReadOnlyAcquisitionSlotsV1::<E>::receiving_construction_bytes_v1()?)
    }

    /// Reports no namespace entries for the fixed acquisition carriers.
    ///
    /// The caller separately prices rooted names, ancestry and descriptors;
    /// this owner's fields and construction destinations use byte permits.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        0
    }
}

/// Moves the same three actual acquired files across a crate boundary once.
///
/// This outgoing physical capability has no public constructor, role or replay
/// claim. No common journal constructor accepts supplied files from this type.
pub struct CompletedReadOnlyAcquisitionV1 {
    directory: File,
    file: File,
    lock: File,
}

impl CompletedReadOnlyAcquisitionV1 {
    /// Consumes the actual completed acquisition into its original files.
    ///
    /// The mechanical consumer combines these outgoing originals only with its
    /// own canonical parser prefix. This performs no opening, copy or probe.
    #[must_use]
    pub fn into_original_files(self) -> (File, File, File) {
        (self.directory, self.file, self.lock)
    }
}

impl<E: ProtectedFailure> ReadOnlyAcquisitionOriginalsV1<E> {
    /// Opens the exact provided fixture directory with the existing no-follow recipe.
    ///
    /// This debug-only entry does not claim protected root ancestry. It retains
    /// the actual opened directory and checks the requested UID/type/mode before
    /// the ordinary upper limits and readonly file recipe run.
    ///
    /// # Errors
    /// Preserves the original openat2 or protected-directory validation error.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub fn prepare_fixture_directory_once_v1(&mut self, path: &Path, uid: u32) -> Result<(), E> {
        use rustix::fs::{CWD, FileType, Mode, ResolveFlags, openat2};

        if self.closed || self.transferred || self.directory_completion.is_some() {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.directory = Some(match openat2(
            CWD, path, super::protected_directory_flags(), Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(directory) => Ok(directory.into()),
            Err(cause) => {
                self.directory_native_error = Some(cause);
                Err(super::protected_open_error::<E>(cause))
            }
        });
        self.directory_completion = Some(match self.directory.as_ref() {
            Some(Ok(directory)) => super::validate_protected_fd::<E>(
                directory, uid, FileType::Directory, Mode::RWXU,
            ),
            _ => Err(E::BOUNDARY),
        });
        require_step(&self.directory_completion)
    }

    /// Moves the first ordinary physical cause while retaining actual files.
    ///
    /// This closes further transfer. Selected callers retain this original and
    /// borrow `failure` instead. The ordinary caller drops the whole acquisition
    /// only at its original error-return boundary; no descriptor is projected.
    #[must_use]
    pub fn take_ordinary_error_once_v1(&mut self) -> Option<E> {
        if self.transferred || self.ordinary_error_taken {
            return None;
        }
        self.ordinary_error_taken = true;
        self.closed = true;
        macro_rules! take_error {
            ($field:ident) => {
                match self.$field.take() {
                    Some(Err(cause)) => Some(cause),
                    original => {
                        self.$field = original;
                        None
                    }
                }
            };
        }
        // Ordinary callers return the existing protected projection. Retained
        // diagnostics independently keep their raw-native-first selector.
        take_error!(directory)
            .or_else(|| self.directory_native_error.take().map(super::protected_open_error::<E>))
            .or_else(|| take_error!(directory_binding))
            .or_else(|| take_error!(directory_identity))
            .or_else(|| take_error!(lock_validation))
            .or_else(|| take_error!(lock).map(super::protected_open_error::<E>))
            .or_else(|| take_error!(lock_identity))
            .or_else(|| take_error!(file_validation))
            .or_else(|| take_error!(file).map(super::protected_open_error::<E>))
            .or_else(|| take_error!(file_identity))
            .or_else(|| take_error!(directory_completion))
            .or_else(|| take_error!(files_completion))
    }

    /// Resolves the initial rooted directory without a supplied prior identity.
    ///
    /// The actual role compares its mount witness with the first sampled
    /// directory identity after file acquisition. No expected identity is made
    /// up for this initial observation.
    ///
    /// # Errors
    /// Retains every reached ancestor and the original native/typed refusal;
    /// reentry or a previously transferred acquisition refuses before IO.
    pub fn prepare_rooted_directory_once(&mut self, path: &Path, uid: u32) -> Result<(), E> {
        if self.closed || self.transferred || self.directory_completion.is_some() {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.directory = Some(resolve_protected_directory_from_root_original::<E>(
            path, uid, Some(&mut self.ancestors), Some(&mut self.directory_native_error),
        ));
        self.directory_completion = Some(if matches!(self.directory, Some(Ok(_))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        });
        require_step(&self.directory_completion)
    }

    /// Moves only this acquisition's own completed files as one outgoing owner.
    ///
    /// An incomplete group is restored in place. Metadata results, ancestors
    /// and every original refusal remain with this acquisition reservoir.
    #[must_use]
    pub fn take_completed_files_once_v1(&mut self) -> Option<CompletedReadOnlyAcquisitionV1> {
        if !self.is_complete() {
            return None;
        }
        let originals = (self.directory.take(), self.file.take(), self.lock.take());
        let (directory, file, lock) = match originals {
            (Some(Ok(directory)), Some(Ok(file)), Some(Ok(lock))) => (directory, file, lock),
            (directory, file, lock) => {
                self.directory = directory;
                self.file = file;
                self.lock = lock;
                return None;
            }
        };
        self.transferred = true;
        Some(CompletedReadOnlyAcquisitionV1 { directory, file, lock })
    }

    /// Enters the same rooted directory prefix once under the role's funding.
    ///
    /// # Errors
    /// Preserves the actual first refusal and rejects absent/repeated entry.
    pub fn prepare_directory_once(
        &mut self,
        path: &Path,
        uid: u32,
        expected_directory: (u64, u64),
    ) -> Result<(), E> {
        if self.closed || self.directory_completion.is_some() {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.directory_completion = Some(acquire_readonly_directory_originals_v1(
            path, uid, expected_directory, &mut self.slots(),
        ));
        require_step(&self.directory_completion)
    }

    /// Continues the same physical owner after the role's replay-limit check.
    ///
    /// # Errors
    /// Preserves the first refusal; absent or repeated directory/files entry
    /// closes further positive borrowing without replacing reached originals.
    pub fn prepare_files_once(&mut self, name: &str, uid: u32) -> Result<(), E> {
        if self.closed || self.files_completion.is_some()
            || !matches!(self.directory_completion, Some(Ok(())))
        {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        self.files_completion = Some(acquire_readonly_files_originals_v1(
            name, uid, &mut self.slots(),
        ));
        require_step(&self.files_completion)
    }

    /// Continues the original bound opener with its existing lock-name slot.
    ///
    /// `None` keeps the original temporary basename lifetime. A genuine Root
    /// caller can instead retain that same name in its prepaid original field.
    /// This chooses only DATA custody and supplies no role or allowance.
    ///
    /// # Errors
    /// Preserves the actual native/typed refusal and prevents repeated entry.
    pub fn prepare_files_with_original_lock_name_once_v1(
        &mut self,
        name: &str,
        uid: u32,
        retained_lock_name: Option<&mut Option<String>>,
    ) -> Result<(), E> {
        if self.closed || self.files_completion.is_some()
            || !matches!(self.directory_completion, Some(Ok(())))
        {
            self.closed = true;
            return Err(E::BOUNDARY);
        }
        let mut slots = self.slots();
        slots.lock_name = retained_lock_name;
        let result = acquire_readonly_files_originals_v1(name, uid, &mut slots);
        self.files_completion = Some(result);
        require_step(&self.files_completion)
    }

    /// Reports physical completion only; this is never semantic currentness.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.closed && !self.transferred
            && matches!(self.directory_completion, Some(Ok(())))
            && matches!(self.files_completion, Some(Ok(())))
    }
}

impl<E: Error + 'static> ReadOnlyAcquisitionOriginalsV1<E> {
    /// Borrows the earliest reached whole physical cause without resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            };
        }
        self.directory_native_error.as_ref().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| cause!(self.directory))
            .or_else(|| cause!(self.directory_binding))
            .or_else(|| cause!(self.directory_identity))
            .or_else(|| cause!(self.lock))
            .or_else(|| cause!(self.lock_validation))
            .or_else(|| cause!(self.lock_identity))
            .or_else(|| cause!(self.file))
            .or_else(|| cause!(self.file_validation))
            .or_else(|| cause!(self.file_identity))
            .or_else(|| cause!(self.directory_completion))
            .or_else(|| cause!(self.files_completion))
            .or_else(|| self.closed.then_some(&ACQUISITION_CLOSED as &(dyn Error + 'static)))
    }
}

impl<E> Default for ReadOnlyAcquisitionOriginalsV1<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct AcquisitionClosed;

impl std::fmt::Display for AcquisitionClosed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("read-only physical acquisition is closed")
    }
}

impl Error for AcquisitionClosed {}

static ACQUISITION_CLOSED: AcquisitionClosed = AcquisitionClosed;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions, Permissions};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    enum Failure {
        Io(std::io::Error),
        Boundary,
        Unsupported,
        Stale,
    }

    impl std::fmt::Display for Failure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(error) => std::fmt::Display::fmt(error, formatter),
                _ => formatter.write_str("test physical refusal"),
            }
        }
    }

    impl Error for Failure {}

    impl From<std::io::Error> for Failure {
        fn from(error: std::io::Error) -> Self {
            Self::Io(error)
        }
    }

    impl ProtectedFailure for Failure {
        const BOUNDARY: Self = Self::Boundary;
        const UNSUPPORTED_OPEN: Self = Self::Unsupported;
        const STALE_NAME: Self = Self::Stale;
    }

    struct Directory(std::path::PathBuf);

    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "aos-readonly-acquisition-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn create(&self, name: &str, mode: u32) -> File {
            OpenOptions::new().write(true).read(true).create_new(true).mode(mode)
                .open(self.0.join(name)).unwrap()
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ordinary_symlink_refusal_moves_protected_error_without_reclassifying_raw_errno() {
        use std::os::unix::fs::symlink;

        for target in ["journal.lock", "journal"] {
            let directory = Directory::new();
            directory.create("real", 0o600);
            let other = if target == "journal.lock" { "journal" } else { "journal.lock" };
            directory.create(other, 0o600);
            symlink("real", directory.0.join(target)).unwrap();
            let mut original = ReadOnlyAcquisitionOriginalsV1::<Failure>::new();
            original.prepare_fixture_directory_once_v1(
                &directory.0, rustix::process::geteuid().as_raw(),
            ).unwrap();

            assert!(original.prepare_files_with_original_lock_name_once_v1("journal",
                rustix::process::geteuid().as_raw(), None).is_err());
            let raw = if target == "journal.lock" { original.lock.as_ref().unwrap().as_ref().err() }
                else { original.file.as_ref().unwrap().as_ref().err() };
            assert_eq!(raw, Some(&rustix::io::Errno::LOOP));
            assert!(matches!(original.take_ordinary_error_once_v1(), Some(Failure::Boundary)));
            assert!(original.directory.as_ref().unwrap().is_ok());
            assert!(!original.is_complete());
            assert!(original.take_ordinary_error_once_v1().is_none());
        }
    }

    #[test]
    fn invalid_directory_cause_is_resident_and_reentry_does_not_replace_it() {
        let mut original = ReadOnlyAcquisitionOriginalsV1::<Failure>::new();

        assert!(original.prepare_directory_once(Path::new("relative"), 0, (0, 0)).is_err());
        let first = original.failure().unwrap().downcast_ref::<Failure>().unwrap() as *const Failure;
        assert!(original.prepare_directory_once(Path::new("/another"), 0, (1, 1)).is_err());

        let later = original.failure().unwrap().downcast_ref::<Failure>().unwrap() as *const Failure;
        assert_eq!(first, later);
        assert!(matches!(original.directory, Some(Err(Failure::Boundary))));
        assert!(original.ancestors.is_empty());
        assert!(!original.is_complete());
    }

    #[test]
    fn late_file_validation_keeps_lock_name_lock_and_actual_opened_file() {
        let directory = Directory::new();
        let lock = directory.create("journal.lock", 0o600);
        let file = directory.create("journal", 0o600);
        fs::set_permissions(directory.0.join("journal"), Permissions::from_mode(0o644)).unwrap();
        let uid = file.metadata().unwrap().uid();
        let mut original = ReadOnlyAcquisitionOriginalsV1::<Failure>::new();
        // Test-only raw directory fixture. It grants no protected ancestry or
        // role success; the actual file-opening/validation engine is unchanged.
        original.directory = Some(Ok(File::open(&directory.0).unwrap()));
        original.directory_completion = Some(Ok(()));

        assert!(original.prepare_files_once("journal", uid).is_err());
        let first = original.failure().unwrap().downcast_ref::<Failure>().unwrap() as *const Failure;
        assert!(original.prepare_files_once("substitute", uid).is_err());

        assert_eq!(original.lock_name.as_deref(), Some("journal.lock"));
        assert_eq!(original.lock().unwrap().metadata().unwrap().ino(), lock.metadata().unwrap().ino());
        assert_eq!(original.file().unwrap().metadata().unwrap().ino(), file.metadata().unwrap().ino());
        assert!(original.lock_identity.as_ref().unwrap().is_ok());
        assert!(original.file_identity.is_none());
        assert_eq!(first, original.failure().unwrap().downcast_ref::<Failure>().unwrap() as *const Failure);
        assert!(!original.is_complete());
    }

    #[test]
    fn physical_file_success_borrows_the_same_actual_read_only_originals() {
        let directory = Directory::new();
        let lock = directory.create("journal.lock", 0o600);
        let file = directory.create("journal", 0o600);
        let uid = file.metadata().unwrap().uid();
        let mut original = ReadOnlyAcquisitionOriginalsV1::<Failure>::new();
        original.directory = Some(Ok(File::open(&directory.0).unwrap()));
        original.directory_completion = Some(Ok(()));

        original.prepare_files_once("journal", uid).unwrap();

        assert!(original.is_complete());
        let (_, file_identity, lock_identity) = original.identities().unwrap();
        assert_eq!(file_identity.physical_pair().1, file.metadata().unwrap().ino());
        assert_eq!(lock_identity.physical_pair().1, lock.metadata().unwrap().ino());
        assert!(original.failure().is_none());
        assert_eq!(original.lock_name.as_deref(), Some("journal.lock"));
    }
}
