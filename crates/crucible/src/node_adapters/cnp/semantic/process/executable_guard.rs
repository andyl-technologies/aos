//! Authenticates one original executable through its retained descriptor.
//!
//! A fresh descriptor attempts a Linux read lease exactly once, before the
//! complete initial measurement. Kernel-backed immutability permits subsequent
//! checks without rereading bytes. Unsupported acquisition retains complete-byte
//! validation; a break or changed process, namespace or file fact is terminal.

use std::{
    cell::Cell,
    fs::{self, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
    sync::Arc,
    thread::ThreadId,
};

use crucible_linux_resource::{LinuxReadLeaseFile, LinuxReadLeaseOwner};
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::ProviderError;

use super::current::KernelIdentity;

const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(PartialEq, Eq)]
struct FileRevision {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileRevision {
    fn read(metadata: Metadata) -> Result<Self, ProviderError> {
        if !metadata.is_file() || metadata.len() > MAXIMUM_EXECUTABLE_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "generic original executable measurement",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

pub(super) struct OriginalExecutable {
    creator: u32,
    thread: ThreadId,
    process_path: PathBuf,
    original_target: PathBuf,
    original: LinuxReadLeaseFile,
    revision: FileRevision,
    expected: ContentRef,
    revoked: Cell<bool>,
}

impl OriginalExecutable {
    pub(super) fn open(
        pid: u32,
        expected: &ContentRef,
        kernel: &KernelIdentity,
    ) -> Result<Self, ProviderError> {
        kernel.ensure_current()?;
        let process_path = PathBuf::from(format!("/proc/{pid}/exe"));
        Self::open_original(process_path, expected, kernel)
    }

    fn open_original(
        process_path: PathBuf,
        expected: &ContentRef,
        kernel: &KernelIdentity,
    ) -> Result<Self, ProviderError> {
        let original_target = fs::read_link(&process_path)?;
        let owner = LinuxReadLeaseOwner::new().ok().map(Arc::new);
        // The wrapper opens its own private descriptor and retains a terminal
        // acquisition attempt. No read handle can renew or replace its lease.
        let original = LinuxReadLeaseFile::open(&process_path, owner)
            .map_err(|_| changed("generic original executable acquisition failed"))?;
        let revision = FileRevision::read(original.file().metadata()?)?;
        let guard = Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            process_path,
            original_target,
            original,
            revision,
            expected: expected.clone(),
            revoked: Cell::new(false),
        };

        guard.fences(kernel)?;
        guard.measure_complete()?;
        guard.fences(kernel)?;
        Ok(guard)
    }

    pub(super) fn ensure_origin(&self) -> Result<(), ProviderError> {
        // PID precedes thread-local state and inherited notification ownership.
        if std::process::id() != self.creator {
            return Err(changed(
                "generic original executable belongs to another process",
            ));
        }
        if std::thread::current().id() != self.thread {
            return Err(changed(
                "generic original executable belongs to another thread",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_current(&self, kernel: &KernelIdentity) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.revoked.get() {
            return Err(changed("generic original executable permanently revoked"));
        }
        let result = (|| {
            self.fences(kernel)?;
            if self.original.lease().is_none() {
                self.measure_complete()?;
                self.fences(kernel)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.revoked.set(true);
        }
        result
    }

    fn fences(&self, kernel: &KernelIdentity) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        kernel.ensure_current()?;
        if let Some(lease) = self.original.lease() {
            lease
                .verify_current()
                .map_err(|_| changed("generic original executable read lease revoked"))?;
        }
        if FileRevision::read(self.original.file().metadata()?)? != self.revision
            || FileRevision::read(fs::metadata(&self.process_path)?)? != self.revision
            || fs::read_link(&self.process_path)? != self.original_target
        {
            return Err(changed(
                "generic original executable descriptor or namespace changed",
            ));
        }
        if let Some(lease) = self.original.lease() {
            lease
                .verify_current()
                .map_err(|_| changed("generic original executable read lease revoked"))?;
        }
        kernel.ensure_current()
    }

    fn measure_complete(&self) -> Result<(), ProviderError> {
        let length = usize::try_from(self.revision.length)
            .map_err(|_| ProviderError::ResourceExhausted("generic executable address space"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProviderError::ResourceExhausted("generic executable complete bytes"))?;
        bytes.resize(length, 0);
        // Positional reads leave the original descriptor's cursor untouched.
        self.original.file().read_exact_at(&mut bytes, 0)?;
        let mut excess = [0_u8; 1];
        if self
            .original
            .file()
            .read_at(&mut excess, self.revision.length)?
            != 0
            || canonical::content_ref(&bytes, "application/octet-stream")? != self.expected
        {
            return Err(changed(
                "generic original executable complete bytes changed",
            ));
        }
        Ok(())
    }
}

fn changed(reason: &'static str) -> ProviderError {
    ProviderError::Correlation(reason)
}

#[cfg(test)]
mod tests;
