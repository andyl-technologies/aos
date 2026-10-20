//! Retains the sole Guardian executable metadata and positional hash recipe.
//!
//! Descriptor trust/size/identity predicates remain Guardian-owned. The actual
//! fixed-buffer hash loop is shared with Nspawn below both role layers.

use std::os::fd::{AsFd as _, BorrowedFd};
use aos_sandbox_linux::protected_file::positional_hash::{
    PositionalHashFailureV2, PositionalHashOriginalV2,
};
use super::{GuardianExecutableDescriptor, GuardianExecutableSnapshot, MAXIMUM_EXECUTABLE_BYTES, invalid};
use crate::error::Result;

/// Owns one actual Guardian executable revalidation and its first native cause.
///
/// It provides no descriptor adopter, role admission or service-manager grant.
#[derive(Debug)]
pub struct GuardianExecutableValidationOriginalV2 {
    metadata: [Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>; 2],
    flags: Option<std::result::Result<rustix::fs::OFlags, rustix::io::Errno>>,
    file: Option<std::io::Result<std::fs::File>>,
    hash: PositionalHashOriginalV2,
    entered: bool,
    returned: Option<Result<()>>,
}

impl GuardianExecutableValidationOriginalV2 {
    /// Constructs inert destinations without allocation, IO or admission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: std::array::from_fn(|_| None), flags: None, file: None,
            hash: PositionalHashOriginalV2::new(), entered: false, returned: None,
        }
    }

    /// Bounds constructor/held/read bytes and its one temporary read duplicate.
    ///
    /// The caller prepays this passive shape before constructing the owner.
    /// The executable source pin remains separately held; namespace demand is0.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(PositionalHashOriginalV2::receiving_bytes_v2()?)?, 1))
    }

    /// Borrows the actual first failed native read/check or returned predicate.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        failed(&self.metadata[0]).or_else(|| failed(&self.flags))
            .or_else(|| failed(&self.file))
            .or_else(|| self.hash.failure().map(|cause| cause as _))
            .or_else(|| failed(&self.metadata[1]))
            .or_else(|| failed(&self.returned))
    }
}

impl Default for GuardianExecutableValidationOriginalV2 {
    fn default() -> Self { Self::new() }
}

fn failed<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

pub(super) fn validate_once(
    descriptor: BorrowedFd<'_>,
    destination: Option<&mut GuardianExecutableValidationOriginalV2>,
    after_chunk: impl FnMut(u64),
) -> Result<GuardianExecutableSnapshot> {
    validate_once_engine(descriptor, destination, after_chunk, false)
}

fn validate_once_engine(
    descriptor: BorrowedFd<'_>,
    destination: Option<&mut GuardianExecutableValidationOriginalV2>,
    after_chunk: impl FnMut(u64),
    keep_completed_file: bool,
) -> Result<GuardianExecutableSnapshot> {
    let mut local = GuardianExecutableValidationOriginalV2::new();
    let original = destination.unwrap_or(&mut local);
    if original.entered { return Err(invalid("guardian executable revalidation is already entered")); }
    original.entered = true;
    let result = validate_body(descriptor, original, after_chunk);
    if result.is_ok() && !keep_completed_file {
        // Match the old checker-return boundary after complete readback; failed
        // metadata/read/comparison paths retain the SAME native File instead.
        drop(original.file.take());
    }
    result
}

pub(super) fn revalidate(
    executable: &GuardianExecutableDescriptor,
    destination: Option<&mut GuardianExecutableValidationOriginalV2>,
) -> Result<()> {
    let retained = destination.is_some();
    let mut local = GuardianExecutableValidationOriginalV2::new();
    let original = destination.unwrap_or(&mut local);
    if original.entered {
        return Err(invalid("guardian executable revalidation is already entered"));
    }
    let result = validate_once_engine(
        executable.path.descriptor(), Some(&mut *original), |_| {}, retained,
    )
        .and_then(|current| if current == executable.snapshot { Ok(()) }
            else { Err(invalid("guardian executable identity or content changed after admission")) });
    if !retained { return result; }
    if result.is_ok() {
        // The selected duplicate survives both the read's internal bookends
        // and this admitted-baseline conjunction. A baseline mismatch keeps
        // that same File and all native observations through the owed posts.
        drop(original.file.take());
    }
    original.returned = Some(result);
    match original.returned.as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(_)) => Err(invalid("guardian executable revalidation failed; original retained")),
        None => std::process::abort(),
    }
}

fn validate_body(
    descriptor: BorrowedFd<'_>,
    original: &mut GuardianExecutableValidationOriginalV2,
    after_chunk: impl FnMut(u64),
) -> Result<GuardianExecutableSnapshot> {
    use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat};

    original.metadata[0] = Some(fstat(descriptor));
    let before = match original.metadata[0].as_ref() {
        Some(Ok(metadata)) => *metadata,
        Some(Err(error)) => return Err(invalid(format!("cannot inspect guardian executable: {error}"))),
        None => std::process::abort(),
    };
    let bytes = u64::try_from(before.st_size)
        .ok()
        .filter(|bytes| (1..=MAXIMUM_EXECUTABLE_BYTES).contains(bytes))
        .ok_or_else(|| invalid("guardian executable size is invalid"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != rustix::process::geteuid().as_raw()
        || before.st_mode & 0o111 == 0
        || before.st_mode & 0o022 != 0
        || {
            original.flags = Some(fcntl_getfl(descriptor));
            match original.flags.as_ref() {
                Some(Ok(flags)) => *flags,
                Some(Err(error)) => return Err(invalid(format!("cannot read guardian executable flags: {error}"))),
                None => std::process::abort(),
            }
        } & OFlags::ACCMODE
            != OFlags::RDONLY
    {
        return Err(invalid("guardian executable descriptor is not protected"));
    }

    let length = usize::try_from(bytes)
        .map_err(|_| invalid("guardian executable size does not fit memory"))?;
    original.file = Some(descriptor.try_clone_to_owned().map(std::fs::File::from));
    let file = match original.file.as_ref() {
        Some(Ok(file)) => file,
        Some(Err(error)) => return Err(invalid(format!("cannot duplicate guardian executable: {error}"))),
        None => std::process::abort(),
    };
    let digest = original.hash.hash_once_v2(file.as_fd(), length as u64, after_chunk);
    let digest = digest.map_err(|_| match original.hash.failure() {
        Some(PositionalHashFailureV2::Read(error)) => invalid(format!(
            "cannot read guardian executable: {}",
            std::io::Error::from_raw_os_error(error.raw_os_error()),
        )),
        Some(PositionalHashFailureV2::EarlyEnd) => invalid(
            "guardian executable ended before its declared size",
        ),
        Some(PositionalHashFailureV2::Extent) => invalid(
            "guardian executable size does not fit memory",
        ),
        None => invalid("guardian executable hash is already entered"),
    })?;
    original.metadata[1] = Some(fstat(descriptor));
    let after = match original.metadata[1].as_ref() {
        Some(Ok(metadata)) => *metadata,
        Some(Err(error)) => return Err(invalid(format!("cannot recheck guardian executable: {error}"))),
        None => std::process::abort(),
    };
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
    {
        return Err(invalid("guardian executable changed during exact readback"));
    }
    let modified_nanoseconds = i64::try_from(before.st_mtime_nsec)
        .map_err(|_| invalid("guardian executable modification time is invalid"))?;
    let changed_nanoseconds = i64::try_from(before.st_ctime_nsec)
        .map_err(|_| invalid("guardian executable metadata-change time is invalid"))?;

    Ok(GuardianExecutableSnapshot {
        device: before.st_dev,
        inode: before.st_ino,
        bytes,
        uid: before.st_uid,
        mode: before.st_mode,
        modified_seconds: before.st_mtime,
        modified_nanoseconds,
        changed_seconds: before.st_ctime,
        changed_nanoseconds,
        sha256_content: digest,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use super::*;
    use aos_sandbox_linux::protected_file::positional_hash::POSITIONAL_HASH_BUFFER_BYTES_V2;

    fn executable() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        file
    }

    #[test]
    fn oversized_native_executable_refuses_before_duplicate_or_read() {
        let file = executable();
        file.as_file().set_len(MAXIMUM_EXECUTABLE_BYTES + 1).unwrap();
        let mut original = GuardianExecutableValidationOriginalV2::new();

        let result = validate_once(file.as_file().as_fd(), Some(&mut original), |_| {});

        assert!(result.is_err());
        assert!(matches!(original.metadata[0], Some(Ok(_))));
        assert!(original.file.is_none());
        assert_eq!(original.hash.confirmed_bytes_v2(), 0);
    }

    #[test]
    fn native_badf_keeps_the_same_read_duplicate_and_errno() {
        let mut file = executable();
        file.write_all(b"executable").unwrap();
        let source = rustix::fs::open(file.path(), rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let mut original = GuardianExecutableValidationOriginalV2::new();

        let result = validate_once(source.as_fd(), Some(&mut original), |_| {});

        assert!(result.is_err());
        assert_eq!(original.hash.native_errno_v2(), Some(rustix::io::Errno::BADF));
        let retained = original.file.as_ref().unwrap().as_ref().unwrap();
        let actual = rustix::fs::fstat(retained).unwrap();
        let before = original.metadata[0].as_ref().unwrap().as_ref().unwrap();
        assert_eq!((actual.st_dev, actual.st_ino), (before.st_dev, before.st_ino));
        assert!(original.metadata[1].is_none());
    }

    #[test]
    fn stable_current_read_with_baseline_drift_keeps_the_actual_duplicate() {
        let mut file = executable();
        file.write_all(b"original").unwrap();
        let source = std::fs::File::open(file.path()).unwrap();
        let executable = GuardianExecutableDescriptor::from_descriptor(source.as_fd()).unwrap();
        file.as_file().set_len(9).unwrap();
        let mut original = GuardianExecutableValidationOriginalV2::new();

        let returned = executable.revalidate_retaining_v2(&mut original);

        assert!(returned.is_err());
        assert!(original.hash.failure().is_none());
        assert_eq!(original.hash.confirmed_bytes_v2(), 9);
        let before = original.metadata[0].as_ref().unwrap().as_ref().unwrap();
        let after = original.metadata[1].as_ref().unwrap().as_ref().unwrap();
        assert_eq!((before.st_dev, before.st_ino, before.st_size),
            (after.st_dev, after.st_ino, after.st_size));
        let duplicate = original.file.as_ref().unwrap().as_ref().unwrap();
        let actual = rustix::fs::fstat(duplicate).unwrap();
        assert_eq!((actual.st_dev, actual.st_ino, actual.st_size),
            (before.st_dev, before.st_ino, before.st_size));
        assert_eq!(executable.snapshot.bytes, 8);
        let cause = original.failure().unwrap() as *const dyn std::error::Error;
        assert!(executable.revalidate_retaining_v2(&mut original).is_err());
        assert!(std::ptr::eq(cause, original.failure().unwrap() as *const dyn std::error::Error));
    }

    #[test]
    fn actual_truncation_stops_the_shared_prefix_before_final_metadata() {
        let mut file = executable();
        file.write_all(&vec![7; POSITIONAL_HASH_BUFFER_BYTES_V2 + 1]).unwrap();
        let source = std::fs::File::open(file.path()).unwrap();
        let mut original = GuardianExecutableValidationOriginalV2::new();

        let result = validate_once(source.as_fd(), Some(&mut original), |_| {
            file.as_file().set_len(POSITIONAL_HASH_BUFFER_BYTES_V2 as u64).unwrap();
        });

        assert!(result.is_err());
        assert!(matches!(original.hash.failure(), Some(PositionalHashFailureV2::EarlyEnd)));
        assert_eq!(original.hash.confirmed_bytes_v2(), POSITIONAL_HASH_BUFFER_BYTES_V2 as u64);
        assert!(original.file.as_ref().is_some_and(|file| file.is_ok()));
        assert!(original.metadata[1].is_none());
    }

    #[test]
    fn same_prefix_with_later_native_size_change_retains_both_metadata_results() {
        let mut file = executable();
        file.write_all(b"executable").unwrap();
        let source = std::fs::File::open(file.path()).unwrap();
        let mut original = GuardianExecutableValidationOriginalV2::new();

        let result = validate_once(source.as_fd(), Some(&mut original), |_| {
            file.as_file().set_len(11).unwrap();
        });

        assert!(result.is_err());
        let before = original.metadata[0].as_ref().unwrap().as_ref().unwrap();
        let after = original.metadata[1].as_ref().unwrap().as_ref().unwrap();
        assert_eq!(before.st_size, 10);
        assert_eq!(after.st_size, 11);
        assert!(original.file.as_ref().is_some_and(|file| file.is_ok()));
        assert!(original.hash.failure().is_none());
    }
}
