//! Bounded idempotent population of a fresh Create workspace from AOS packages.
//!
//! This copier is only a physical effect primitive. Its privileged caller
//! must authenticate the Storage Create intent, prove that the attached root
//! is the intended fresh dataset, retain exclusive custody through copying,
//! and publish [`crate::guest_root_publication::GuestRootPublicationProofV1`]
//! only after the returned tree digest has been read back.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::Path;

use crate::guest_root_tree::compare_guest_root_template_v1;

const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;
const MAXIMUM_ENTRIES: usize = 250_000;
const MAXIMUM_PATH_BYTES: usize = 4096;
const MAXIMUM_FILE_BYTES: u64 = 512 * 1_048_576;

/// Copies the exact immutable template into a protected fresh Create root.
///
/// A crash after an individual file write leaves no publication marker. A
/// retry may repair only root-owned regular files and directories already
/// named in the immutable template, then remeasures the complete fixed tree.
/// Clone roots and roots exposed to a guest require a different transition;
/// callers must not pass them to this primitive.
///
/// # Errors
///
/// Returns an error for substituted types, unsafe ownership or modes,
/// unsupported entries, oversized content, or physical I/O failure.
pub fn populate_fresh_guest_root_v1(
    template: &Path,
    workspace: &Path,
) -> Result<[u8; 32], GuestRootPopulateErrorV1> {
    populate_fresh_guest_root_before_v1(template, workspace, || true)
}

/// Copies a fresh guest root while checking one admitted effect deadline.
///
/// The caller supplies a protected clock predicate. It is checked before
/// every filesystem mutation and between bounded regular-file chunks. An
/// expired operation leaves an unmarked partial tree for later authenticated
/// recovery; this function never publishes launch authority.
///
/// # Errors
///
/// Returns an error for an expired deadline, unsafe root, substituted entry,
/// oversized content, or physical I/O failure.
pub fn populate_fresh_guest_root_before_v1(
    template: &Path,
    workspace: &Path,
    mut before_deadline: impl FnMut() -> bool,
) -> Result<[u8; 32], GuestRootPopulateErrorV1> {
    if !template.is_absolute() || !workspace.is_absolute() {
        return Err(GuestRootPopulateErrorV1::InvalidRoot);
    }
    check_deadline(&mut before_deadline)?;
    verify_directory(&fs::symlink_metadata(template)?)?;
    verify_directory(&fs::symlink_metadata(workspace)?)?;

    let mut count = 0;
    copy_directory(template, workspace, &mut count, &mut before_deadline)?;
    check_deadline(&mut before_deadline)?;
    compare_guest_root_template_v1(template, workspace)
        .map_err(|_| GuestRootPopulateErrorV1::InvalidRoot)
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    count: &mut usize,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootPopulateErrorV1> {
    let mut names = fs::read_dir(source)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        check_deadline(before_deadline)?;
        *count = count
            .checked_add(1)
            .filter(|value| *value <= MAXIMUM_ENTRIES)
            .ok_or(GuestRootPopulateErrorV1::InvalidRoot)?;
        let source_path = source.join(&name);
        let destination_path = destination.join(&name);
        if source_path.as_os_str().as_bytes().len() > MAXIMUM_PATH_BYTES
            || destination_path.as_os_str().as_bytes().len() > MAXIMUM_PATH_BYTES
        {
            return Err(GuestRootPopulateErrorV1::InvalidRoot);
        }

        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.uid() != 0 || !metadata.file_type().is_symlink() && metadata.mode() & 0o022 != 0
        {
            return Err(GuestRootPopulateErrorV1::InvalidRoot);
        }
        if metadata.is_dir() {
            copy_child_directory(
                &source_path,
                &destination_path,
                &metadata,
                count,
                before_deadline,
            )?;
        } else if metadata.is_file() {
            copy_regular(&source_path, &destination_path, &metadata, before_deadline)?;
        } else if metadata.file_type().is_symlink() {
            check_deadline(before_deadline)?;
            copy_symlink(&source_path, &destination_path)?;
        } else {
            return Err(GuestRootPopulateErrorV1::InvalidRoot);
        }
    }
    check_deadline(before_deadline)?;
    File::open(destination)?.sync_all()?;
    Ok(())
}

fn copy_child_directory(
    source: &Path,
    destination: &Path,
    metadata: &Metadata,
    count: &mut usize,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootPopulateErrorV1> {
    check_deadline(before_deadline)?;
    match fs::create_dir(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verify_directory(&fs::symlink_metadata(destination)?)?;
    // A crash may leave a completed read-only directory with later children
    // missing. Restrict it to owner access during replay, then restore its
    // exact template mode only after every descendant has synced.
    check_deadline(before_deadline)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    copy_directory(source, destination, count, before_deadline)?;
    check_deadline(before_deadline)?;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(metadata.mode() & 0o7777),
    )?;
    check_deadline(before_deadline)?;
    File::open(destination)?.sync_all()?;
    Ok(())
}

fn copy_regular(
    source: &Path,
    destination: &Path,
    metadata: &Metadata,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootPopulateErrorV1> {
    if metadata.len() > MAXIMUM_FILE_BYTES {
        return Err(GuestRootPopulateErrorV1::InvalidRoot);
    }
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(source)?;
    if input.metadata()?.ino() != metadata.ino() {
        return Err(GuestRootPopulateErrorV1::InvalidRoot);
    }

    check_deadline(before_deadline)?;
    let mut output = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(destination)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::symlink_metadata(destination)?;
            if !existing.is_file() || existing.uid() != 0 || existing.mode() & 0o022 != 0 {
                return Err(GuestRootPopulateErrorV1::InvalidRoot);
            }
            check_deadline(before_deadline)?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .custom_flags(O_NOFOLLOW | O_CLOEXEC)
                .open(destination)?
        }
        Err(error) => return Err(error.into()),
    };
    let mut input = input.take(metadata.len() + 1);
    let mut copied = 0_u64;
    let mut chunk = [0_u8; 1_048_576];
    loop {
        check_deadline(before_deadline)?;
        let count = input.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        check_deadline(before_deadline)?;
        output.write_all(&chunk[..count])?;
        copied += count as u64;
    }
    if copied != metadata.len() {
        return Err(GuestRootPopulateErrorV1::InvalidRoot);
    }
    check_deadline(before_deadline)?;
    output.sync_all()?;
    check_deadline(before_deadline)?;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(metadata.mode() & 0o7777),
    )?;
    Ok(())
}

fn copy_symlink(source: &Path, destination: &Path) -> Result<(), GuestRootPopulateErrorV1> {
    let target = fs::read_link(source)?;
    match symlink(&target, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::symlink_metadata(destination)?;
            if !existing.file_type().is_symlink()
                || existing.uid() != 0
                || fs::read_link(destination)? != target
            {
                return Err(GuestRootPopulateErrorV1::InvalidRoot);
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_directory(metadata: &Metadata) -> Result<(), GuestRootPopulateErrorV1> {
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestRootPopulateErrorV1::InvalidRoot);
    }
    Ok(())
}

fn check_deadline(
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootPopulateErrorV1> {
    if before_deadline() {
        Ok(())
    } else {
        Err(GuestRootPopulateErrorV1::Deadline)
    }
}

/// Reports an invalid fresh workspace or physical population failure.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootPopulateErrorV1 {
    /// The admitted effect window ended before physical population completed.
    #[error("guest-root population deadline expired")]
    Deadline,
    /// The source or target is unsafe, substituted, oversized, or incomplete.
    #[error("fresh guest root population is invalid")]
    InvalidRoot,
    /// A filesystem operation failed while copying the fixed template.
    #[error("fresh guest root population I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn expired_effect_does_not_start_copying() {
        let result = populate_fresh_guest_root_before_v1(
            Path::new("/protected/template"),
            Path::new("/protected/workspace"),
            || false,
        );
        assert!(matches!(result, Err(GuestRootPopulateErrorV1::Deadline)));
    }
}
