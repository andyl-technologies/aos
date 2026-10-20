//! Shares the exact protected readiness atomic-write sequence.
//!
//! Callers own protected directory selection, content validation, funding and
//! all enclosing posts. This mechanical destination creates no readiness,
//! publisher-generation, Source, floor or native-success authority.

use rustix::fs::{AtFlags, Mode, OFlags, openat};
use std::{
    error::Error,
    fs::File,
    io::{self, Write as _},
    mem::size_of,
    os::fd::BorrowedFd,
};

/// Selects the fixed readiness file pairs on a caller-pinned directory.
#[derive(Clone, Copy, Debug)]
pub enum ReadinessAtomicWritePurposeV2 {
    /// Preserves the Host's monotone watermark names and strict 4096-byte limit.
    Watermark,
    /// Publishes the normal boot preparation's bounded canonical credential.
    BootPreparation,
    /// Publishes the exact signed completed055 companion on the same directory.
    BootPreparationCompletion,
}

impl ReadinessAtomicWritePurposeV2 {
    fn names(self) -> (&'static str, &'static str) {
        match self {
            Self::Watermark => (
                "backend-readiness-watermark.next",
                "backend-readiness-watermark.json",
            ),
            Self::BootPreparation => ("backend-readiness.next", "backend-readiness.json"),
            Self::BootPreparationCompletion => (
                "backend-readiness-completion-v1.next",
                "backend-readiness-completion-v1",
            ),
        }
    }

    fn maximum_bytes(self) -> usize {
        match self {
            Self::Watermark => 4096,
            Self::BootPreparation => 16 * 1024,
            Self::BootPreparationCompletion => 888,
        }
    }
}

/// Refuses an incomplete or reused mechanical atomic write.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the readiness atomic write is incomplete or refused")]
pub struct ReadinessAtomicWriteClosedV2;

#[derive(Clone, Copy)]
enum First {
    Entry,
    StaleUnlink,
    Open,
    Write,
    FileSync,
    Rename,
    DirectorySync,
}

/// Supplies passive checked representation for the actual mechanical writer.
///
/// These values issue no capacity, account, file, role or IO permission.
#[derive(Clone, Copy, Debug)]
pub struct ReadinessAtomicWriteShapeDataV2 {
    /// Compiled native carrier and the two reached literal-name buffers.
    pub memory_bytes: usize,
    /// Retained temporary OFD; the directory remains owned by the caller.
    pub open_files: usize,
    /// Actual final/temp directory entries, excluding Rust fields.
    pub namespace_entries: usize,
    /// Bounded newly written persistent bytes.
    pub storage_bytes: usize,
    /// Bounded actual write traffic.
    pub output_bytes: usize,
}

/// Retains the actual temporary OFD, primary errors and failure-only cleanup.
#[derive(Default)]
#[must_use = "retain the actual prefix through the caller's independently owed posts"]
pub struct ReadinessAtomicWriteOriginalV2 {
    entered: bool,
    stale_unlink: Option<rustix::io::Result<()>>,
    file: Option<File>,
    opened: Option<rustix::io::Result<()>>,
    write: Option<io::Result<()>>,
    file_sync: Option<io::Result<()>>,
    rename: Option<rustix::io::Result<()>>,
    directory_sync: Option<rustix::io::Result<()>>,
    cleanup: Option<rustix::io::Result<()>>,
    first: Option<First>,
    closed: ReadinessAtomicWriteClosedV2,
}

impl Default for ReadinessAtomicWriteClosedV2 {
    fn default() -> Self {
        Self
    }
}

impl ReadinessAtomicWriteOriginalV2 {
    /// Creates empty native destinations without allocation, IO or permission.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Quotes this actual native carrier and bounded borrowed-byte write.
    ///
    /// The upper owner separately pays its directory FD, encoded bytes, schema
    /// and readback. The two literal names refer to real filesystem entries.
    #[must_use]
    pub fn receiving_shape_v2(
        purpose: ReadinessAtomicWritePurposeV2,
        encoded_bytes: usize,
    ) -> Option<ReadinessAtomicWriteShapeDataV2> {
        if encoded_bytes == 0 || encoded_bytes > purpose.maximum_bytes() {
            return None;
        }
        let (next, final_name) = purpose.names();
        let memory = size_of::<Self>()
            .checked_add(next.len() + 1)?
            .checked_add(final_name.len() + 1)?;
        Some(ReadinessAtomicWriteShapeDataV2 {
            memory_bytes: memory,
            open_files: 1,
            namespace_entries: 2,
            storage_bytes: encoded_bytes,
            output_bytes: encoded_bytes,
        })
    }

    /// Runs the existing unlink/open/write/sync/rename/directory-sync sequence.
    ///
    /// # Errors
    /// Refuses reused entry, oversized bytes or any actual native operation.
    /// A failed entered write still attempts the existing temp cleanup and
    /// retains that Result without replacing the primary cause. It does not
    /// invent directory synchronization after a failed write or a readback.
    pub fn replace_once_v2(
        &mut self,
        directory: BorrowedFd<'_>,
        purpose: ReadinessAtomicWritePurposeV2,
        bytes: &[u8],
    ) -> Result<(), ReadinessAtomicWriteClosedV2> {
        if self.entered || bytes.is_empty() || bytes.len() > purpose.maximum_bytes() {
            self.first.get_or_insert(First::Entry);
            return Err(self.closed);
        }
        self.entered = true;
        let (next, final_name) = purpose.names();
        self.stale_unlink = Some(rustix::fs::unlinkat(directory, next, AtFlags::empty()));
        if !matches!(
            self.stale_unlink,
            Some(Ok(()) | Err(rustix::io::Errno::NOENT))
        ) {
            self.first = Some(First::StaleUnlink);
            return Err(self.closed);
        }
        match openat(
            directory,
            next,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => {
                self.file = Some(File::from(descriptor));
                self.opened = Some(Ok(()));
            }
            Err(cause) => {
                self.opened = Some(Err(cause));
                self.first = Some(First::Open);
                return Err(self.closed);
            }
        }
        self.write = Some(self.file.as_mut().ok_or(self.closed)?.write_all(bytes));
        if !matches!(self.write, Some(Ok(()))) {
            self.first = Some(First::Write);
        }
        if self.first.is_none() {
            self.file_sync = Some(self.file.as_ref().ok_or(self.closed)?.sync_all());
            if !matches!(self.file_sync, Some(Ok(()))) {
                self.first = Some(First::FileSync);
            }
        }
        if self.first.is_none() {
            self.rename = Some(rustix::fs::renameat(directory, next, directory, final_name));
            if !matches!(self.rename, Some(Ok(()))) {
                self.first = Some(First::Rename);
            }
        }
        if self.first.is_none() {
            self.directory_sync = Some(rustix::fs::fsync(directory));
            if !matches!(self.directory_sync, Some(Ok(()))) {
                self.first = Some(First::DirectorySync);
            }
        }
        if self.first.is_some() {
            self.cleanup = Some(rustix::fs::unlinkat(directory, next, AtFlags::empty()));
            return Err(self.closed);
        }
        Ok(())
    }

    /// Borrows the selected actual cause while every native original stays held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<E: Error + 'static>(
            slot: &Option<Result<(), E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Entry => Some(&self.closed),
            First::StaleUnlink => error(&self.stale_unlink),
            First::Open => error(&self.opened),
            First::Write => error(&self.write),
            First::FileSync => error(&self.file_sync),
            First::Rename => error(&self.rename),
            First::DirectorySync => error(&self.directory_sync),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_cleanup_does_not_replace_the_original_write_cause() {
        let mut original = ReadinessAtomicWriteOriginalV2::new();
        original.first = Some(First::Write);
        original.write = Some(Err(io::Error::from(io::ErrorKind::WriteZero)));
        original.cleanup = Some(Err(rustix::io::Errno::ACCESS));
        let actual = original
            .failure()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert!(std::ptr::eq(
            actual,
            original.write.as_ref().unwrap().as_ref().unwrap_err()
        ));
        assert!(original.cleanup.as_ref().unwrap().is_err());
    }
}
