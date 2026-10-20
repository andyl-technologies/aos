//! Keeps the same beneath-root regular-file open/read recipe through its posts.
//!
//! This is a mechanical descriptor/read destination. Its lengths and completed
//! observations convey no role, currentness, resource, signing or launch grant.

use super::*;

/// Retains one regular-file prefix, partial bytes and independent name readback.
#[derive(Debug, Default)]
pub struct BeneathRegularFileReadOriginalV2 {
    opening: PendingRegularFileV1,
    opened: Option<Result<()>>,
    metadata: Option<Result<libc::stat>>,
    extent: Option<Result<usize>>,
    file: Option<std::fs::File>,
    bytes: Vec<u8>,
    read: Option<Result<()>>,
    bookend: PendingRegularFileV1,
    named: Option<Result<()>>,
    after: Option<Result<libc::stat>>,
    comparison: Option<Result<()>>,
    entered: bool,
    read_entered: bool,
    post_entered: bool,
    closed: Option<Error>,
    bytes_taken: bool,
    native_retired: bool,
}

impl BeneathRegularFileReadOriginalV2 {
    /// Constructs inert destinations without opening or allocating file bytes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens the exact regular file with the existing strict beneath-root engine.
    ///
    /// Its actual length can be priced before the separate bounded read. The
    /// raw descriptor stays resident even if a later type or metadata check fails.
    ///
    /// # Errors
    /// Retains the first actual open/type/metadata error and refuses reentry.
    pub fn capture_once_v2(&mut self, root: &BeneathRoot, relative: &Path) -> Result<()> {
        if self.entered {
            return self.refuse();
        }
        self.entered = true;
        self.opened = Some(root.open_regular_retaining(relative, &mut self.opening));
        if !matches!(self.opened, Some(Ok(()))) {
            return Err(closed());
        }
        self.metadata = Some(match self.opening.file() {
            Ok(file) => uapi::fstat(file.as_fd()),
            Err(error) => Err(error),
        });
        if !matches!(self.metadata, Some(Ok(_))) {
            return Err(closed());
        }
        self.extent = Some(
            self.metadata
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(|metadata| usize::try_from(metadata.st_size).ok())
                .ok_or_else(|| {
                    Error::invalid("retained regular read", "file length does not fit usize")
                }),
        );
        if matches!(self.extent, Some(Ok(_))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Borrows the captured native byte extent without reading file contents.
    #[must_use]
    pub fn captured_bytes_v2(&self) -> Option<usize> {
        if self.closed.is_some() || self.read_entered || self.post_entered {
            return None;
        }
        self.extent.as_ref()?.as_ref().ok().copied()
    }

    /// Borrows metadata captured by this exact strict regular-file opening.
    ///
    /// The fields are native DATA for a caller's additional policy checks.
    #[must_use]
    pub fn captured_metadata_data_v2(&self) -> Option<&libc::stat> {
        self.metadata.as_ref()?.as_ref().ok()
    }

    /// Reads the same held regular file after its caller's separate byte payment.
    ///
    /// # Errors
    /// Retains the actual bounded-read error, file and partial buffer. Reentry
    /// or absence of the captured same original refuses without another read.
    pub fn read_once_v2(&mut self, maximum: usize) -> Result<()> {
        if self.read_entered || self.captured_bytes_v2().is_none() {
            return self.refuse();
        }
        self.read_entered = true;
        self.file = self.opening.take_readable_file();
        let Some(file) = self.file.as_mut() else {
            return self.refuse();
        };
        self.read = Some(super::read_bounded_recipe(file, maximum, &mut self.bytes));
        if matches!(self.read, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Performs the independent name and original-file posts after primary work.
    ///
    /// Both native attempts run before either result is interpreted. Partial
    /// reads and decoding failures do not suppress this owed native observation.
    ///
    /// # Errors
    /// Retains native failures or a changed name, identity, size or timestamp.
    pub fn finish_once_v2(&mut self, root: &BeneathRoot, relative: &Path) -> Result<()> {
        if self.post_entered {
            return self.refuse();
        }
        self.post_entered = true;
        self.named = Some(root.open_regular_retaining(relative, &mut self.bookend));
        let original = self
            .file
            .as_ref()
            .map(AsFd::as_fd)
            .or_else(|| self.opening.file().ok().map(ResolvedFile::as_fd))
            .or_else(|| self.opening.raw.as_ref().map(AsFd::as_fd));
        self.after = original.map(uapi::fstat);
        self.comparison = Some(self.compare());
        if matches!(self.comparison, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn compare(&self) -> Result<()> {
        let before = self
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(closed)?;
        let after = self
            .after
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(closed)?;
        let named = self.bookend.file()?.identity();
        if !matches!(self.named, Some(Ok(())))
            || before.st_dev != named.device
            || before.st_ino != named.inode
            || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(closed());
        }
        Ok(())
    }

    /// Borrows the actual bounded bytes without extracting their native owner.
    #[must_use]
    pub fn bytes_v2(&self) -> Option<&[u8]> {
        if self.closed.is_some() || self.bytes_taken {
            return None;
        }
        matches!(self.read, Some(Ok(()))).then_some(self.bytes.as_slice())
    }

    /// Moves fully read bytes after both genuine native name/file posts.
    ///
    /// This once-only DATA transfer leaves every native Result and descriptor
    /// on the same original. It cannot construct a role or receiving permit.
    #[must_use]
    pub fn take_completed_bytes_v2(&mut self) -> Option<Vec<u8>> {
        if self.bytes_taken || !self.post_entered || self.failure().is_some()
            || !matches!(self.read, Some(Ok(()))) || !matches!(self.comparison, Some(Ok(())))
        { return None; }
        self.bytes_taken = true;
        Some(std::mem::take(&mut self.bytes))
    }

    /// Closes only fully positive regular-file descriptors after their posts.
    ///
    /// Metadata, bytes and one-shot latches stay on this same original.
    ///
    /// # Errors
    /// Refuses a partial, failed, already retired or unobserved original.
    pub fn retire_positive_native_v2(&mut self) -> Result<()> {
        if self.native_retired || !self.post_entered || self.failure().is_some()
            || !matches!(self.read, Some(Ok(()))) || !matches!(self.comparison, Some(Ok(())))
        { return Err(closed()); }
        drop(self.file.take());
        drop(self.opening.raw.take());
        drop(self.opening.validated.take());
        drop(self.bookend.raw.take());
        drop(self.bookend.validated.take());
        self.native_retired = true;
        Ok(())
    }

    /// Borrows the earliest retained actual native failure without new IO.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        cause(&self.opened)
            .or_else(|| cause(&self.metadata))
            .or_else(|| cause(&self.extent))
            .or_else(|| cause(&self.read))
            .or(self.closed.as_ref())
            .or_else(|| cause(&self.named))
            .or_else(|| cause(&self.after))
            .or_else(|| cause(&self.comparison))
    }

    fn refuse(&mut self) -> Result<()> {
        if self.failure().is_none() {
            self.closed = Some(closed());
        }
        Err(closed())
    }

    /// Reports compiled receiving bytes and the two possible native descriptors.
    ///
    /// The caller separately pays captured buffer/decoder sizes before read.
    /// No namespace entry is charged for a Rust field or descriptor carrier.
    #[must_use]
    pub fn fixed_receiving_demand_v2(relative_bytes: usize) -> Option<(usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(relative_bytes.checked_add(1)?.checked_mul(4)?)?
            .checked_add(4 * 1024)?;
        Some((bytes, 2))
    }
}

fn cause<T>(slot: &Option<Result<T>>) -> Option<&Error> {
    slot.as_ref()?.as_ref().err()
}

fn closed() -> Error {
    Error::invalid(
        "retained regular read",
        "original was refused, changed or already entered",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root(path: &Path) -> BeneathRoot {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        BeneathRoot::from_owned(descriptor).unwrap()
    }

    #[test]
    fn captures_before_read_and_keeps_same_file_through_name_posts() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("catalog"), b"abc").unwrap();
        let root = root(directory.path());
        let mut original = BeneathRegularFileReadOriginalV2::new();

        original
            .capture_once_v2(&root, Path::new("catalog"))
            .unwrap();
        assert_eq!(original.captured_bytes_v2(), Some(3));
        assert!(original.bytes_v2().is_none());
        original.read_once_v2(3).unwrap();
        original
            .finish_once_v2(&root, Path::new("catalog"))
            .unwrap();

        assert_eq!(original.bytes_v2(), Some(b"abc".as_slice()));
        assert!(original.file.is_some());
        assert!(original.bookend.file().is_ok());
        assert!(original.failure().is_none());

        assert_eq!(original.captured_metadata_data_v2().unwrap().st_size, 3);
        assert_eq!(original.take_completed_bytes_v2().unwrap(), b"abc");
        assert!(original.take_completed_bytes_v2().is_none());
        assert!(original.bytes_v2().is_none());
        original.retire_positive_native_v2().unwrap();
        assert!(original.file.is_none());
        assert!(original.bookend.validated.is_none());
        assert!(original.metadata.is_some());
        assert!(original.retire_positive_native_v2().is_err());
    }

    #[test]
    fn replacement_name_does_not_replace_the_original_or_suppress_posts() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("catalog"), b"abc").unwrap();
        let root = root(directory.path());
        let mut original = BeneathRegularFileReadOriginalV2::new();
        original
            .capture_once_v2(&root, Path::new("catalog"))
            .unwrap();
        original.read_once_v2(3).unwrap();

        fs::rename(
            directory.path().join("catalog"),
            directory.path().join("old"),
        )
        .unwrap();
        fs::write(directory.path().join("catalog"), b"abc").unwrap();
        assert!(
            original
                .finish_once_v2(&root, Path::new("catalog"))
                .is_err()
        );

        assert!(matches!(original.after, Some(Ok(_))));
        assert!(matches!(original.named, Some(Ok(()))));
        assert!(original.file.is_some());
        assert!(original.bookend.file().is_ok());
        assert!(original.failure().is_some());
    }

    #[test]
    fn failed_read_keeps_partial_bytes_and_both_owed_native_observations() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("catalog"), b"abc").unwrap();
        let root = root(directory.path());
        let mut original = BeneathRegularFileReadOriginalV2::new();
        original
            .capture_once_v2(&root, Path::new("catalog"))
            .unwrap();

        assert!(original.read_once_v2(2).is_err());
        assert!(
            original
                .finish_once_v2(&root, Path::new("catalog"))
                .is_err()
        );

        assert_eq!(original.bytes, b"abc");
        assert!(original.bytes_v2().is_none());
        assert!(matches!(original.after, Some(Ok(_))));
        assert!(matches!(original.named, Some(Ok(()))));
        assert!(original.file.is_some());
        assert!(original.failure().is_some());
    }

    #[test]
    fn reentry_closes_bytes_without_skipping_owed_name_posts() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("catalog"), b"abc").unwrap();
        let root = root(directory.path());
        let mut original = BeneathRegularFileReadOriginalV2::new();
        original
            .capture_once_v2(&root, Path::new("catalog"))
            .unwrap();
        original.read_once_v2(3).unwrap();

        assert!(original.read_once_v2(3).is_err());
        assert!(
            original
                .finish_once_v2(&root, Path::new("catalog"))
                .is_err()
        );

        assert!(original.bytes_v2().is_none());
        assert!(matches!(original.after, Some(Ok(_))));
        assert!(matches!(original.named, Some(Ok(()))));
        assert!(original.failure().is_some());
    }
}

#[cfg(test)]
mod raw_prefix_tests {
    use super::*;

    #[test]
    fn wrong_type_keeps_both_raw_descriptors_and_performs_original_post() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("not-regular")).unwrap();
        let fd = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let root = BeneathRoot::from_owned(fd).unwrap();
        let mut original = BeneathRegularFileReadOriginalV2::new();

        assert!(
            original
                .capture_once_v2(&root, Path::new("not-regular"))
                .is_err()
        );
        assert!(
            original
                .finish_once_v2(&root, Path::new("not-regular"))
                .is_err()
        );

        let before = original.opening.raw.as_ref().unwrap();
        let named = original.bookend.raw.as_ref().unwrap();
        assert!(rustix::fs::fstat(before).is_ok());
        assert!(rustix::fs::fstat(named).is_ok());
        assert!(matches!(original.after, Some(Ok(_))));
        assert!(matches!(
            original.failure(),
            Some(Error::WrongDescriptorType { .. })
        ));
    }
}
