//! Retains one protected packaged executable and its complete measurement.
//!
//! Role/path contracts and genuine payment remain with the caller. The sole
//! Linux positioned hasher supplies the64KiB buffer and exact-prefix loop;
//! this owner adds complete file metadata, actual EOF and independent posts.
//! A measured digest is historical DATA, not backend readiness or a floor.

use std::error::Error;
use std::fs::File;
use std::mem::size_of;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::{Path, PathBuf};

use aos_linux_descriptors::positional_hash::PositionalHashClosedV2;
use aos_linux_descriptors::positional_hash::PositionalHashOriginalV2;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, statat, open};

const MAXIMUM_BYTES: u64 = 256 * 1024 * 1024;

/// Reports a refused or incomplete measurement while its native owner stays held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("protected executable measurement is incomplete or refused")]
pub struct PackagedExecutableHashClosedV2;

/// Describes actual native/executable representation without issuing payment.
#[derive(Clone, Copy, Debug)]
pub struct PackagedExecutableHashShapeDataV2 {
    /// Complete retained and constructor bytes, including the shared hash heap.
    pub memory_bytes: u64,
    /// One actual executable OFD; positional hashing opens no additional FD.
    pub open_files: u64,
    /// Actual path components observed through this packaged executable path.
    pub namespace_entries: u64,
}

#[derive(Clone, Copy)]
enum First {
    Reentry,
    PathAllocation,
    Open,
    Before,
    Policy,
    Hash,
    Eof,
    After(usize),
    NamedAfter(usize),
    Comparison(usize),
}

#[derive(Debug, thiserror::Error)]
enum ComparisonFailure {
    #[error("packaged executable has invalid protected metadata")]
    Metadata,
    #[error("packaged executable has trailing bytes")]
    Trailing,
    #[error("packaged executable changed during measurement")]
    Changed,
}

/// Owns one reached file/hash prefix through every independent observation.
///
/// Construction is inert. The enclosing genuine scope prepays the complete
/// shape before entry, including the single shared hasher allocation. Failed
/// and completed files remain owned through the enclosing native interval.
/// A positive pin can be borrowed without a reopen or raw-file adopter.
#[must_use = "retain partial executable originals through all owed posts"]
pub struct ProtectedPackagedExecutableHashOriginalV2 {
    path: PathBuf,
    path_allocation: Option<Result<(), std::collections::TryReserveError>>,
    file: Option<Result<File, rustix::io::Errno>>,
    before: Option<Result<Stat, rustix::io::Errno>>,
    policy: Option<Result<u64, ComparisonFailure>>,
    hash: Option<Box<PositionalHashOriginalV2>>,
    hash_result: Option<Result<[u8; 32], PositionalHashClosedV2>>,
    eof_byte: [u8; 1],
    eof: Option<Result<usize, rustix::io::Errno>>,
    eof_policy: Option<Result<(), ComparisonFailure>>,
    after_entered: [bool; 2],
    after: [Option<Result<Stat, rustix::io::Errno>>; 2],
    named_after: [Option<Result<Stat, rustix::io::Errno>>; 2],
    comparison: [Option<Result<(), ComparisonFailure>>; 2],
    first: Option<First>,
    entered: bool,
}

impl ProtectedPackagedExecutableHashOriginalV2 {
    /// Creates an inert destination without opening a file or allocating a hash.
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: PathBuf::new(),
            path_allocation: None,
            file: None,
            before: None,
            policy: None,
            hash: None,
            hash_result: None,
            eof_byte: [0],
            eof: None,
            eof_policy: None,
            after_entered: [false; 2],
            after: std::array::from_fn(|_| None),
            named_after: std::array::from_fn(|_| None),
            comparison: std::array::from_fn(|_| None),
            first: None,
            entered: false,
        }
    }

    /// Reports the existing maximum executable read and one trailing EOF byte.
    #[must_use]
    pub const fn maximum_requested_read_bytes_v2() -> u64 {
        MAXIMUM_BYTES + 1
    }

    /// Quotes the full shape before path growth, file opening or hash allocation.
    ///
    /// Namespace cardinality is the actual path component count, including the
    /// root component. It is unrelated to private Rust field/parser counts.
    #[must_use]
    pub fn receiving_shape_v2(path: &Path) -> Option<PackagedExecutableHashShapeDataV2> {
        let memory = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(path.as_os_str().len())?
            .checked_add(PositionalHashOriginalV2::receiving_bytes_v2()?)?;
        Some(PackagedExecutableHashShapeDataV2 {
            memory_bytes: u64::try_from(memory).ok()?,
            open_files: 1,
            namespace_entries: u64::try_from(path.components().count()).ok()?,
        })
    }

    /// Measures one actual protected executable using the sole positioned loop.
    ///
    /// The caller first checks its fixed role/path predicate and admits the
    /// complete shape. Both held and named metadata afters are owed even after
    /// an earlier hash or EOF refusal. A second entry never resets the owner.
    ///
    /// # Errors
    /// Refuses path allocation, open/stat/metadata/hash/EOF failures, drift,
    /// reentry or an executable above the existing256MiB hard bound.
    pub fn observe_once_v2(&mut self, path: &Path) -> Result<(), PackagedExecutableHashClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(PackagedExecutableHashClosedV2);
        }
        self.entered = true;
        self.path_allocation = Some(self.path.try_reserve_exact(path.as_os_str().len()));
        if !matches!(self.path_allocation, Some(Ok(()))) {
            self.first = Some(First::PathAllocation);
            return Err(PackagedExecutableHashClosedV2);
        }
        self.path.push(path);
        self.file = Some(
            open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map(File::from),
        );
        if !matches!(self.file, Some(Ok(_))) {
            self.first = Some(First::Open);
            return Err(PackagedExecutableHashClosedV2);
        }
        let body = self.measure_body_v2();
        let posts = self.observe_posts_v2(0);
        body.and(posts)
    }

    fn measure_body_v2(&mut self) -> Result<(), PackagedExecutableHashClosedV2> {
        let file = self
            .file
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(PackagedExecutableHashClosedV2)?;
        self.before = Some(fstat(file));
        let Some(Ok(before)) = self.before.as_ref() else {
            self.first = Some(First::Before);
            return Err(PackagedExecutableHashClosedV2);
        };
        let size = u64::try_from(before.st_size).ok();
        self.policy = Some(
            if FileType::from_raw_mode(before.st_mode) == FileType::RegularFile
                && before.st_uid == 0
                && before.st_mode & 0o022 == 0
                && before.st_mode & 0o111 != 0
                && size.is_some_and(|size| size > 0 && size <= MAXIMUM_BYTES)
            {
                size.ok_or(ComparisonFailure::Metadata)
            } else {
                Err(ComparisonFailure::Metadata)
            },
        );
        let Some(Ok(size)) = self.policy.as_ref() else {
            self.first = Some(First::Policy);
            return Err(PackagedExecutableHashClosedV2);
        };
        let size = *size;

        self.hash = Some(Box::new(PositionalHashOriginalV2::new()));
        self.hash_result = Some(
            self.hash
                .as_mut()
                .ok_or(PackagedExecutableHashClosedV2)?
                .hash_once_v2(file.as_fd(), size, |_| {}),
        );
        if !matches!(self.hash_result, Some(Ok(_))) {
            self.first = Some(First::Hash);
            return Err(PackagedExecutableHashClosedV2);
        }
        self.eof = Some(rustix::io::pread(file, &mut self.eof_byte, size));
        match self.eof.as_ref() {
            Some(Ok(0)) => self.eof_policy = Some(Ok(())),
            Some(Ok(_)) => {
                self.eof_policy = Some(Err(ComparisonFailure::Trailing));
                self.first = Some(First::Eof);
                return Err(PackagedExecutableHashClosedV2);
            }
            Some(Err(_)) | None => {
                self.first = Some(First::Eof);
                return Err(PackagedExecutableHashClosedV2);
            }
        }
        Ok(())
    }

    /// Observes the separately prepaid final held/named file bookend once.
    ///
    /// This method has no healthy-body guard and performs no new allocation or
    /// debit. A reached file receives both observations after a hash failure.
    ///
    /// # Errors
    /// Refuses missing entry, reentry, drift or actual native after failures.
    pub fn observe_after_owed_once_v2(&mut self) -> Result<(), PackagedExecutableHashClosedV2> {
        if !self.entered || self.after_entered[1] {
            self.first.get_or_insert(First::Reentry);
            return Err(PackagedExecutableHashClosedV2);
        }
        self.observe_posts_v2(1)
    }

    fn observe_posts_v2(&mut self, index: usize) -> Result<(), PackagedExecutableHashClosedV2> {
        if self.after_entered[index] {
            self.first.get_or_insert(First::Reentry);
            return Err(PackagedExecutableHashClosedV2);
        }
        self.after_entered[index] = true;
        let Some(Ok(file)) = self.file.as_ref() else {
            return Err(PackagedExecutableHashClosedV2);
        };
        self.after[index] = Some(fstat(file));
        self.named_after[index] = Some(statat(
            rustix::fs::CWD,
            &self.path,
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        if !matches!(self.after[index], Some(Ok(_))) {
            self.first.get_or_insert(First::After(index));
        }
        if !matches!(self.named_after[index], Some(Ok(_))) {
            self.first.get_or_insert(First::NamedAfter(index));
        }
        let compared = match (&self.before, &self.after[index], &self.named_after[index]) {
            (Some(Ok(before)), Some(Ok(after)), Some(Ok(named)))
                if same_metadata(before, after) && same_metadata(before, named) =>
            {
                Ok(())
            }
            _ => Err(ComparisonFailure::Changed),
        };
        self.comparison[index] = Some(compared);
        if !matches!(self.comparison[index], Some(Ok(()))) {
            self.first.get_or_insert(First::Comparison(index));
        }
        if self.first.is_some() {
            Err(PackagedExecutableHashClosedV2)
        } else {
            Ok(())
        }
    }

    /// Borrows the actual measured digest only after positive hash/EOF/bookends.
    #[must_use]
    pub fn digest_v2(&self) -> Option<[u8; 32]> {
        if self.first.is_some() || !matches!(self.comparison[0], Some(Ok(()))) {
            return None;
        }
        self.hash_result.as_ref()?.as_ref().ok().copied()
    }

    /// Borrows the same retained positive executable pin without reopening it.
    #[must_use]
    pub fn completed_file_v2(&self) -> Option<BorrowedFd<'_>> {
        self.digest_v2()?;
        Some(self.file.as_ref()?.as_ref().ok()?.as_fd())
    }

    /// Borrows the actual protected metadata captured before hashing.
    #[must_use]
    pub fn snapshot_v2(&self) -> Option<&Stat> {
        self.digest_v2()?;
        self.before.as_ref()?.as_ref().ok()
    }

    /// Borrows the actual selected native/hash/comparison cause without IO.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::PathAllocation => self
                .path_allocation
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Open => self.file.as_ref()?.as_ref().err().map(|error| error as _),
            First::Before => self.before.as_ref()?.as_ref().err().map(|error| error as _),
            First::Policy => self.policy.as_ref()?.as_ref().err().map(|error| error as _),
            First::Hash => self.hash.as_ref()?.failure().map(|error| error as _),
            First::Eof => self
                .eof
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _)
                .or_else(|| {
                    self.eof_policy
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|error| error as _)
                }),
            First::After(index) => self.after[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::NamedAfter(index) => self.named_after[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Comparison(index) => self.comparison[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Reentry => Some(&PackagedExecutableHashClosedV2),
        }
    }
}

impl Default for ProtectedPackagedExecutableHashOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn same_metadata(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_size == after.st_size
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn failed_body_keeps_its_file_and_runs_the_independent_named_after() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-executable");
        std::fs::write(&path, b"actual retained prefix").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut original = ProtectedPackagedExecutableHashOriginalV2::new();
        assert!(original.observe_once_v2(&path).is_err());
        assert!(matches!(original.first, Some(First::Policy)));
        assert!(matches!(original.file, Some(Ok(_))));
        let first = original.failure_v2().unwrap() as *const dyn Error;

        std::fs::remove_file(&path).unwrap();
        assert!(original.observe_after_owed_once_v2().is_err());
        assert!(matches!(
            original.named_after[1],
            Some(Err(rustix::io::Errno::NOENT))
        ));
        assert!(std::ptr::eq(
            first,
            original.failure_v2().unwrap() as *const dyn Error
        ));
        assert!(original.digest_v2().is_none());
        assert!(original.observe_after_owed_once_v2().is_err());
        assert!(matches!(original.file, Some(Ok(_))));
    }

    #[test]
    fn failed_open_is_not_replaced_by_reentry_or_later_after_marker() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent");
        let mut original = ProtectedPackagedExecutableHashOriginalV2::new();
        assert!(original.observe_once_v2(&path).is_err());
        assert_eq!(
            original
                .failure_v2()
                .unwrap()
                .downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::NOENT)
        );

        std::fs::write(&path, b"later unrelated file").unwrap();
        assert!(original.observe_once_v2(&path).is_err());
        assert!(original.observe_after_owed_once_v2().is_err());
        assert!(original.after_entered[1]);
        assert!(matches!(original.file, Some(Err(rustix::io::Errno::NOENT))));
        assert_eq!(
            original
                .failure_v2()
                .unwrap()
                .downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::NOENT)
        );
    }
}
