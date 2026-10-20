//! Retains bounded directory absence observations beneath a held descriptor.
//!
//! The caller supplies a genuine retained protected root and pays all receiving
//! before entry. An empty result is DATA, never pathname, cleanup, finance or
//! service authority. Unknown entries remain resident and refuse the observation.

use std::error::Error;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

/// Reports a retained directory observation that did not complete.
#[derive(Debug, thiserror::Error)]
#[error("retained empty-directory observation is closed")]
pub struct EmptyDirectoryClosedV2;

#[derive(Debug, thiserror::Error)]
enum Comparison {
    #[error("directory contains an unknown child or repeated dot entry")]
    Entry,
    #[error("directory did not reach bounded canonical EOF")]
    Eof,
    #[error("held directory identity changed")]
    Identity,
}

#[derive(Clone, Copy)]
enum EntryFirst { Native, Comparison, Reentry }

/// Retains the sole fixed-buffer directory-entry collector.
///
/// Existing callers with their own held read descriptor and native bookends
/// can use this collector directly. It performs at most three entry steps.
#[doc(hidden)]
pub struct EmptyDirectoryEntriesOriginalV2 {
    entered: bool,
    buffer: [MaybeUninit<u8>; 4096],
    native: Option<Result<(), rustix::io::Errno>>,
    comparison: Option<Comparison>,
    reentry: Option<EmptyDirectoryClosedV2>,
    first: Option<EntryFirst>,
    complete: bool,
}

impl Default for EmptyDirectoryEntriesOriginalV2 {
    fn default() -> Self {
        Self { entered: false, buffer: [MaybeUninit::uninit(); 4096],
            native: None, comparison: None, reentry: None, first: None, complete: false }
    }
}

impl EmptyDirectoryEntriesOriginalV2 {
    /// Reads only dot, parent and EOF from the actual held read descriptor.
    ///
    /// # Errors
    /// Retains the first getdents error, unknown entry, missing canonical EOF or
    /// reentry. No arbitrary population is allocated or silently skipped.
    pub fn capture_once_v2(&mut self, descriptor: BorrowedFd<'_>)
        -> Result<(), EmptyDirectoryClosedV2> {
        if self.entered {
            self.reentry.get_or_insert(EmptyDirectoryClosedV2);
            self.first.get_or_insert(EntryFirst::Reentry);
            return Err(EmptyDirectoryClosedV2);
        }
        self.entered = true;
        let mut directory = rustix::fs::RawDir::new(descriptor, &mut self.buffer);
        let mut dot = false;
        let mut parent = false;
        for _ in 0..3 {
            match directory.next() {
                None if dot && parent => {
                    self.native = Some(Ok(()));
                    self.complete = true;
                    return Ok(());
                }
                None => {
                    self.comparison = Some(Comparison::Eof);
                    self.first = Some(EntryFirst::Comparison);
                    return Err(EmptyDirectoryClosedV2);
                }
                Some(Err(cause)) => {
                    self.native = Some(Err(cause));
                    self.first = Some(EntryFirst::Native);
                    return Err(EmptyDirectoryClosedV2);
                }
                Some(Ok(entry)) => match entry.file_name().to_bytes() {
                    b"." if !dot => dot = true,
                    b".." if !parent => parent = true,
                    _ => {
                        self.comparison = Some(Comparison::Entry);
                        self.first = Some(EntryFirst::Comparison);
                        return Err(EmptyDirectoryClosedV2);
                    }
                },
            }
        }
        self.comparison = Some(Comparison::Eof);
        self.first = Some(EntryFirst::Comparison);
        Err(EmptyDirectoryClosedV2)
    }

    /// Borrows the exact first native or comparison refusal.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            EntryFirst::Native => self.native.as_ref()?.as_ref().err().map(|cause| cause as _),
            EntryFirst::Comparison => self.comparison.as_ref().map(|cause| cause as _),
            EntryFirst::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

#[derive(Clone, Copy)]
enum First { Before, Open, ReadBefore, IdentityBefore, Seek, Entries, After, ReadAfter, IdentityAfter, Reentry }

/// Owns a complete bounded empty-directory native observation.
///
/// The actual root remains borrowed from its caller. The opened read descriptor,
/// raw entry buffer and every failed prefix remain in this owner through the
/// caller's enclosing native afters and disposal.
#[doc(hidden)]
#[derive(Default)]
pub struct RetainedEmptyDirectoryOriginalV2 {
    entered: bool,
    before: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    read_before: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    identity_before: Option<Result<(), Comparison>>,
    seek: Option<Result<u64, rustix::io::Errno>>,
    entries: EmptyDirectoryEntriesOriginalV2,
    after: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    read_after: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    identity_after: Option<Result<(), Comparison>>,
    reentry: Option<EmptyDirectoryClosedV2>,
    first: Option<First>,
    complete: bool,
}

impl RetainedEmptyDirectoryOriginalV2 {
    /// Returns the complete compiled receiving layout and retained file count.
    ///
    /// The caller separately joins semantic Boot/MountId/current-recipient and
    /// protected path observations. This cost creates no allowance.
    pub fn receiving_shape_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?, 1, 1))
    }

    /// Observes the held root and always reaches its independent metadata after.
    ///
    /// # Errors
    /// Retains raw native failures, another descriptor identity, a nonempty
    /// directory, bounded EOF refusal or reentry. No failure drops its read FD.
    pub fn capture_once_v2(&mut self, root: BorrowedFd<'_>) -> Result<(), EmptyDirectoryClosedV2> {
        if self.entered {
            self.reentry.get_or_insert(EmptyDirectoryClosedV2);
            self.first.get_or_insert(First::Reentry);
            self.complete = false;
            return Err(EmptyDirectoryClosedV2);
        }
        self.entered = true;
        let _body = self.capture_body(root);
        self.after = Some(rustix::fs::fstat(root));
        if matches!(self.after, Some(Err(_))) { self.first.get_or_insert(First::After); }
        if let Some(Ok(opened)) = self.opened.as_ref() {
            self.read_after = Some(rustix::fs::fstat(opened.as_fd()));
            if matches!(self.read_after, Some(Err(_))) { self.first.get_or_insert(First::ReadAfter); }
        }
        self.identity_after = Some((|| {
            let before = self.before.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Comparison::Identity)?;
            let after = self.after.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Comparison::Identity)?;
            require_same(before, after)?;
            if let Some(read) = self.read_after.as_ref() {
                require_same(before, read.as_ref().map_err(|_| Comparison::Identity)?)?;
            }
            Ok(())
        })());
        if matches!(self.identity_after, Some(Err(_))) { self.first.get_or_insert(First::IdentityAfter); }
        self.complete = self.first.is_none() && self.entries.complete;
        self.require_complete_v2()
    }

    fn capture_body(&mut self, root: BorrowedFd<'_>) -> Result<(), EmptyDirectoryClosedV2> {
        self.before = Some(rustix::fs::fstat(root));
        let Some(Ok(before)) = self.before.as_ref() else {
            self.first = Some(First::Before);
            return Err(EmptyDirectoryClosedV2);
        };
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory {
            self.identity_before = Some(Err(Comparison::Identity));
            self.first = Some(First::IdentityBefore);
            return Err(EmptyDirectoryClosedV2);
        }
        self.opened = Some(rustix::fs::openat(root, ".",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()));
        let Some(Ok(opened)) = self.opened.as_ref() else {
            self.first = Some(First::Open);
            return Err(EmptyDirectoryClosedV2);
        };
        self.read_before = Some(rustix::fs::fstat(opened.as_fd()));
        let Some(Ok(read)) = self.read_before.as_ref() else {
            self.first = Some(First::ReadBefore);
            return Err(EmptyDirectoryClosedV2);
        };
        self.identity_before = Some(require_same(before, read));
        if matches!(self.identity_before, Some(Err(_))) {
            self.first = Some(First::IdentityBefore);
            return Err(EmptyDirectoryClosedV2);
        }
        self.seek = Some(rustix::fs::seek(opened.as_fd(), rustix::fs::SeekFrom::Start(0)));
        if matches!(self.seek, Some(Err(_))) {
            self.first = Some(First::Seek);
            return Err(EmptyDirectoryClosedV2);
        }
        if self.entries.capture_once_v2(opened.as_fd()).is_err() {
            self.first = Some(First::Entries);
            return Err(EmptyDirectoryClosedV2);
        }
        Ok(())
    }

    /// Requires the same complete native observation without doing more IO.
    ///
    /// # Errors
    /// Refuses incomplete, nonempty, failed or reentered observations.
    pub fn require_complete_v2(&self) -> Result<(), EmptyDirectoryClosedV2> {
        if self.complete && self.first.is_none() { Ok(()) } else { Err(EmptyDirectoryClosedV2) }
    }

    /// Borrows original held-root metadata after all metadata afters succeeded.
    pub fn root_metadata_v2(&self) -> Option<&rustix::fs::Stat> {
        self.require_complete_v2().ok()?;
        self.before.as_ref()?.as_ref().ok()
    }

    /// Borrows the actual earliest native or comparison original.
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Before => self.before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Open => self.opened.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ReadBefore => self.read_before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::IdentityBefore => self.identity_before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Seek => self.seek.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Entries => self.entries.failure_v2(),
            First::After => self.after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ReadAfter => self.read_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::IdentityAfter => self.identity_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

fn require_same(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> Result<(), Comparison> {
    if left.st_dev != right.st_dev || left.st_ino != right.st_ino
        || left.st_mode != right.st_mode || left.st_uid != right.st_uid
        || left.st_gid != right.st_gid {
        Err(Comparison::Identity)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_empty_root_keeps_the_native_read_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::File::open(directory.path()).unwrap();
        let mut original = RetainedEmptyDirectoryOriginalV2::default();

        original.capture_once_v2(root.as_fd()).unwrap();

        original.require_complete_v2().unwrap();
        assert!(matches!(original.opened, Some(Ok(_))));
        assert!(matches!(original.after, Some(Ok(_))));
        assert!(matches!(original.read_after, Some(Ok(_))));
        assert!(original.root_metadata_v2().is_some());
    }

    #[test]
    fn unknown_child_refuses_with_independent_posts_and_cannot_be_retried() {
        let directory = tempfile::tempdir().unwrap();
        let child = directory.path().join("untracked");
        std::fs::write(&child, b"residual").unwrap();
        let root = std::fs::File::open(directory.path()).unwrap();
        let mut original = RetainedEmptyDirectoryOriginalV2::default();

        assert!(original.capture_once_v2(root.as_fd()).is_err());

        assert!(matches!(original.opened, Some(Ok(_))));
        assert!(matches!(original.after, Some(Ok(_))));
        assert!(matches!(original.read_after, Some(Ok(_))));
        assert!(original.failure_v2().unwrap().downcast_ref::<Comparison>().is_some());
        std::fs::remove_file(child).unwrap();
        assert!(original.capture_once_v2(root.as_fd()).is_err());
        assert!(original.require_complete_v2().is_err());
        assert!(original.failure_v2().unwrap().downcast_ref::<Comparison>().is_some());
    }

    #[test]
    fn non_directory_still_observes_the_held_root_after() {
        let file = tempfile::tempfile().unwrap();
        let mut original = RetainedEmptyDirectoryOriginalV2::default();

        assert!(original.capture_once_v2(file.as_fd()).is_err());

        assert!(original.opened.is_none());
        assert!(matches!(original.after, Some(Ok(_))));
        assert!(original.failure_v2().unwrap().downcast_ref::<Comparison>().is_some());
        assert!(original.root_metadata_v2().is_none());
    }
}
