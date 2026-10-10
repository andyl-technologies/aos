//! Rooted traversal, fixed-file opening, and original replacement cleanup.
//!
//! Ordinary and retained traversal preserve their different File parking
//! policies. Native errno slots are populated before the original typed physical
//! checks. This module cannot replay or materialize a semantic Journal.

use super::{MAXIMUM_PROTECTED_COMPONENT_BYTES, ProtectedFailure};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, fstat, fsync, openat2, statat, unlinkat,
};

/// Selects the original readable no-follow directory flags.
pub fn protected_directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

/// Resolves a rooted protected directory with the original ancestry policy.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn resolve_protected_directory_from_root<E: ProtectedFailure>(
    path: &Path,
    expected_uid: u32,
) -> Result<File, E> {
    resolve_protected_directory_from_root_with_retention::<E>(path, expected_uid, None)
}

fn resolve_protected_directory_from_root_with_retention<E: ProtectedFailure>(
    path: &Path,
    expected_uid: u32,
    retained: Option<&mut Vec<File>>,
) -> Result<File, E> {
    resolve_protected_directory_from_root_original::<E>(path, expected_uid, retained, None)
}

/// Parks every opened ancestor before applying the original ancestry checks.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn resolve_protected_directory_from_root_original<E: ProtectedFailure>(
    path: &Path,
    expected_uid: u32,
    retained: Option<&mut Vec<File>>,
    mut native_error: Option<&mut Option<rustix::io::Errno>>,
) -> Result<File, E> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return Err(E::BOUNDARY);
    }
    let components = &bytes[1..];
    if components.is_empty() {
        return Err(E::BOUNDARY);
    }
    let components = components.split(|byte| *byte == b'/');
    if components.clone().any(|component| {
        component.is_empty()
            || component == b"."
            || component == b".."
            || component.contains(&0)
            || component.len() > MAXIMUM_PROTECTED_COMPONENT_BYTES
    }) {
        return Err(E::BOUNDARY);
    }

    if let Some(ancestors) = retained.as_ref() {
        if !ancestors.is_empty() {
            return Err(E::BOUNDARY);
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
        protected_open_error::<E>(error)
    })?
    .into();
    match retained {
        None => traverse_protected_directory::<E>(root, components, expected_uid),
        Some(ancestors) => {
            // Capacity was reserved before the first descriptor exists.
            ancestors.push(root);
            traverse_protected_directory_observed::<E>(
                ControllerDirectoryTraversalV1::Retained(ancestors),
                components,
                expected_uid,
                native_error,
            )
        }
    }
}

/// Traverses the original component sequence while preserving its descriptor custody.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn traverse_protected_directory<'a, E: ProtectedFailure>(
    directory: File,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
) -> Result<File, E> {
    traverse_protected_directory_originals::<E>(
        ControllerDirectoryTraversalV1::Ordinary(directory),
        components,
        expected_uid,
    )
}

enum ControllerDirectoryTraversalV1<'owner> {
    Ordinary(File),
    Retained(&'owner mut Vec<File>),
}

impl ControllerDirectoryTraversalV1<'_> {
    fn current<E: ProtectedFailure>(&self) -> Result<&File, E> {
        match self {
            Self::Ordinary(directory) => Ok(directory),
            Self::Retained(ancestors) => ancestors.last().ok_or(E::BOUNDARY),
        }
    }

    fn admit_child<E: ProtectedFailure>(
        &mut self,
        child: File,
        ancestry: &mut ProtectedAncestry,
    ) -> Result<(), E> {
        match self {
            Self::Ordinary(directory) => {
                ancestry.admit::<E>(&child)?;
                *directory = child;
                Ok(())
            }
            Self::Retained(ancestors) => {
                ancestors.push(child);
                ancestry.admit::<E>(ancestors.last().ok_or(E::BOUNDARY)?)
            }
        }
    }

    fn finish<E: ProtectedFailure>(self) -> Result<File, E> {
        match self {
            Self::Ordinary(directory) => Ok(directory),
            Self::Retained(ancestors) => ancestors.pop().ok_or(E::BOUNDARY),
        }
    }
}

fn traverse_protected_directory_originals<'a, E: ProtectedFailure>(
    directory: ControllerDirectoryTraversalV1<'_>,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
) -> Result<File, E> {
    traverse_protected_directory_observed::<E>(directory, components, expected_uid, None)
}

fn traverse_protected_directory_observed<'a, E: ProtectedFailure>(
    mut directory: ControllerDirectoryTraversalV1<'_>,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
    mut native_error: Option<&mut Option<rustix::io::Errno>>,
) -> Result<File, E> {
    let mut ancestry = ProtectedAncestry::new(expected_uid);
    ancestry.admit::<E>(directory.current::<E>()?)?;
    for component in components {
        let child: File = openat2(
            directory.current::<E>()?,
            OsStr::from_bytes(component),
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| {
            if let Some(slot) = native_error.as_mut() {
                **slot = Some(error);
            }
            protected_open_error::<E>(error)
        })?
        .into();
        directory.admit_child::<E>(child, &mut ancestry)?;
    }
    validate_protected_fd::<E>(
        directory.current::<E>()?,
        expected_uid,
        FileType::Directory,
        Mode::RWXU,
    )?;
    directory.finish::<E>()
}

/// Tracks the one-way transition from administrative to service-owned ancestry.
pub struct ProtectedAncestry {
    expected_uid: u32,
    service_owned: bool,
}

impl ProtectedAncestry {
    /// Begins the original administrative-to-service ancestry observation.
    pub const fn new(expected_uid: u32) -> Self {
        Self {
            expected_uid,
            service_owned: false,
        }
    }

    fn admit<E: ProtectedFailure>(&mut self, file: &File) -> Result<(), E> {
        let stat = fstat(file).map_err(rustix_io::<E>)?;
        self.admit_metadata::<E>(stat.st_uid, stat.st_mode)
    }

    /// Checks a directory observation against the one-way ancestry ownership policy.
    ///
    /// # Errors
    /// Preserves the original native failure or fixed physical refusal.
    pub fn admit_metadata<E: ProtectedFailure>(&mut self, uid: u32, mode: u32) -> Result<(), E> {
        if FileType::from_raw_mode(mode) != FileType::Directory || mode & 0o022 != 0 {
            return Err(E::BOUNDARY);
        }
        if uid == self.expected_uid {
            self.service_owned = true;
        } else if uid != 0 || self.service_owned {
            // A root-owned descendant cannot restore trust after a service has
            // acquired authority over the path above it.
            return Err(E::BOUNDARY);
        }
        Ok(())
    }
}

/// Rejects empty, special, overlong, or non-component basenames.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn validate_basename<E: ProtectedFailure>(name: &str) -> Result<(), E> {
    if name.is_empty()
        || name.len() > MAXIMUM_PROTECTED_COMPONENT_BYTES
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'/')
    {
        return Err(E::BOUNDARY);
    }
    Ok(())
}

/// Preserves a raw errno as the caller's actual owned I/O error.
pub fn rustix_io<E: ProtectedFailure>(error: rustix::io::Errno) -> E {
    E::from(io::Error::from_raw_os_error(error.raw_os_error()))
}

/// Classifies the original protected opening errno without losing its cause.
pub fn protected_open_error<E: ProtectedFailure>(error: rustix::io::Errno) -> E {
    if error == rustix::io::Errno::NOSYS
        || error == rustix::io::Errno::PERM
        || error == rustix::io::Errno::INVAL
    {
        E::UNSUPPORTED_OPEN
    } else if error == rustix::io::Errno::LOOP
        || error == rustix::io::Errno::XDEV
        || error == rustix::io::Errno::NOTDIR
        || error == rustix::io::Errno::ISDIR
        || error == rustix::io::Errno::ACCESS
    {
        E::BOUNDARY
    } else {
        rustix_io::<E>(error)
    }
}

/// Allocates the fixed replacement basename for the original compaction.
pub fn protected_compaction_name(name: &str) -> String {
    format!("{name}.compact.tmp")
}

/// Rejects nonempty operator-provided history before semantic replay.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn reject_operator_provisioning_history<E: ProtectedFailure>(length: u64) -> Result<(), E> {
    if length != 0 {
        return Err(E::BOUNDARY);
    }
    Ok(())
}

/// Removes an original replacement name and synchronizes its directory.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn remove_stale_protected_compaction<E: ProtectedFailure>(
    directory: &File,
    name: &str,
) -> Result<(), E> {
    let temporary = protected_compaction_name(name);
    validate_basename::<E>(&temporary)?;
    match unlinkat(directory, temporary.as_str(), AtFlags::empty()) {
        Ok(()) => fsync(directory).map_err(rustix_io::<E>),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(rustix_io::<E>(error)),
    }
}

/// Rejects an existing replacement name before read-only replay.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn reject_stale_protected_compaction<E: ProtectedFailure>(
    directory: &File,
    name: &str,
) -> Result<(), E> {
    let temporary = protected_compaction_name(name);
    validate_basename::<E>(&temporary)?;
    match statat(directory, temporary.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(E::BOUNDARY),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(protected_open_error::<E>(error)),
    }
}

/// Checks the original descriptor type, owner, links, and mode.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn validate_protected_fd<E: ProtectedFailure>(
    file: &File,
    expected_uid: u32,
    expected_type: FileType,
    expected_mode: Mode,
) -> Result<(), E> {
    let stat = fstat(file).map_err(rustix_io::<E>)?;
    if stat.st_uid != expected_uid
        || FileType::from_raw_mode(stat.st_mode) != expected_type
        || Mode::from_raw_mode(stat.st_mode) != expected_mode
        || (expected_type == FileType::RegularFile && stat.st_nlink != 1)
    {
        return Err(E::BOUNDARY);
    }
    Ok(())
}

/// Opens and validates one original fixed file with exclusive-failure cleanup.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn open_protected_file<E: ProtectedFailure>(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
) -> Result<File, E> {
    let mut original = None;
    let result = open_protected_file_into::<E>(
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
    original.ok_or(E::BOUNDARY)
}

// The selected purpose parks the same actual open result before the shared
// checks. The ordinary adapter keeps its historical local cleanup disposition.
/// Parks the original opened file before its fixed descriptor checks.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn open_protected_file_into<E: ProtectedFailure>(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
    original: &mut Option<File>,
) -> Result<(), E> {
    open_protected_file_into_original::<E>(
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

/// Parks the native opening result before classifying and validating it.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn open_protected_file_into_original<E: ProtectedFailure>(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
    original: &mut Option<File>,
    native_error: Option<&mut Option<rustix::io::Errno>>,
) -> Result<(), E> {
    if original.is_some() {
        return Err(E::BOUNDARY);
    }
    validate_basename::<E>(name)?;
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
            protected_open_error::<E>(error)
        })?
        .into(),
    );
    validate_protected_fd::<E>(
        original.as_ref().ok_or(E::BOUNDARY)?,
        expected_uid,
        FileType::RegularFile,
        Mode::RUSR | Mode::WUSR,
    )
}

/// Opens and validates one original read-only fixed file.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn open_read_only_protected_file<E: ProtectedFailure>(
    directory: &File,
    name: &str,
    expected_uid: u32,
) -> Result<File, E> {
    let mut original = None;
    open_read_only_protected_file_original::<E>(directory, name, expected_uid, &mut original)?;
    match original {
        Some(Ok(file)) => Ok(file),
        _ => Err(E::BOUNDARY),
    }
}

/// Reopens Lock then Journal and compares them with the original held files.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn require_protected_file_names_current<E: ProtectedFailure>(
    directory: &File,
    name: &str,
    expected_uid: u32,
    lock: &File,
    file: &File,
) -> Result<(), E> {
    let named_lock =
        open_read_only_protected_file::<E>(directory, &format!("{name}.lock"), expected_uid)?;
    let named_file = open_read_only_protected_file::<E>(directory, name, expected_uid)?;
    let held_lock = fstat(lock).map_err(rustix_io::<E>)?;
    let held_file = fstat(file).map_err(rustix_io::<E>)?;
    let current_lock = fstat(&named_lock).map_err(rustix_io::<E>)?;
    let current_file = fstat(&named_file).map_err(rustix_io::<E>)?;
    if held_lock.st_dev != current_lock.st_dev
        || held_lock.st_ino != current_lock.st_ino
        || held_file.st_dev != current_file.st_dev
        || held_file.st_ino != current_file.st_ino
    {
        return Err(E::STALE_NAME);
    }
    Ok(())
}

/// Parks the read-only native result before its original physical checks.
///
/// # Errors
/// Preserves the original native failure or fixed physical refusal.
pub fn open_read_only_protected_file_original<E: ProtectedFailure>(
    directory: &File,
    name: &str,
    expected_uid: u32,
    original: &mut Option<Result<File, rustix::io::Errno>>,
) -> Result<(), E> {
    if original.is_some() {
        return Err(E::BOUNDARY);
    }
    validate_basename::<E>(name)?;
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
        Some(Err(error)) => return Err(protected_open_error::<E>(*error)),
        None => return Err(E::BOUNDARY),
    };
    validate_protected_fd::<E>(
        file,
        expected_uid,
        FileType::RegularFile,
        Mode::RUSR | Mode::WUSR,
    )
}

/// Removes an uncommitted compaction file relative to the retained directory.
pub struct ProtectedTemporary<'a> {
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
