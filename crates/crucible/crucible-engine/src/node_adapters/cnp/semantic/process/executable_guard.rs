//! Authenticates one original executable through its retained descriptor.
//!
//! The ordinary path attempts one Linux read lease before its complete initial
//! measurement. Complete-source custody can instead select complete-byte checks
//! before any notification worker exists. Both paths preserve original kernel,
//! namespace, descriptor and code fences; a mismatch is terminal. An acquired
//! lease is never converted into the separate prebirth complete-byte selection.

use std::{
    cell::Cell,
    fs::{self, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
    sync::Arc,
    thread::ThreadId,
};

use crucible_host_resources::{LinuxReadLeaseFile, LinuxReadLeaseOwner};
use crucible_node_format::{ContentRef, canonical};
use crucible_node_transport::ProviderError;

use super::current::KernelIdentity;

#[path = "executable_guard/fresh_current.rs"]
mod fresh_current;

#[path = "executable_guard/native_startup.rs"]
mod native_startup;

pub(in crate::node_adapters::cnp::semantic) use fresh_current::FreshCurrentScratch;

#[path = "executable_guard/metadata.rs"]
mod metadata;

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
    bounded_birth: bool,
}

impl OriginalExecutable {
    pub(in crate::node_adapters::cnp::semantic) fn storage_origin_precredit_data(
        &self,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;

        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn charge_retained_storage_precredit_data(
        &self,
        counter: &mut super::super::retained_storage::preparation::PreparationCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.storage_origin_precredit_data()?;
        counter.path(&self.process_path)?;
        counter.path(&self.original_target)?;
        counter.content_reference(&self.expected)?;
        if self.original.lease().is_some() {
            counter.unknowns.executable_lease_worker = true;
        }
        counter.arc_file(self.original.file())?;
        self.storage_origin_precredit_data()
    }

    pub(super) fn open(
        pid: u32,
        expected: &ContentRef,
        kernel: &KernelIdentity,
    ) -> Result<Self, ProviderError> {
        kernel.ensure_current()?;
        let process_path = PathBuf::from(format!("/proc/{pid}/exe"));
        Self::open_original(process_path, expected, kernel)
    }

    pub(super) fn open_complete_bytes(
        pid: u32,
        expected: &ContentRef,
        kernel: &KernelIdentity,
    ) -> Result<Self, ProviderError> {
        kernel.ensure_current()?;
        let process_path = PathBuf::from(format!("/proc/{pid}/exe"));
        Self::open_selected(process_path, expected, kernel, true)
    }

    fn open_original(
        process_path: PathBuf,
        expected: &ContentRef,
        kernel: &KernelIdentity,
    ) -> Result<Self, ProviderError> {
        Self::open_selected(process_path, expected, kernel, false)
    }

    fn open_selected(
        process_path: PathBuf,
        expected: &ContentRef,
        kernel: &KernelIdentity,
        complete_bytes: bool,
    ) -> Result<Self, ProviderError> {
        let original_target = fs::read_link(&process_path)?;
        // Choose the complete-only path before any notification owner or
        // worker exists. An acquired or revoked lease is never converted here.
        let owner = if complete_bytes {
            None
        } else {
            LinuxReadLeaseOwner::new().ok().map(Arc::new)
        };
        // The wrapper opens its own private descriptor and retains its original
        // validation mode. No read handle can renew or replace an acquired lease.
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
            bounded_birth: false,
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
        if self.bounded_birth {
            let mut scratch = self
                .fresh_current_scratch()
                .map_err(|_| changed("selected native executable scratch refused"))?;
            return self
                .ensure_fresh_current(kernel, &mut scratch)
                .map_err(|_| changed("selected native executable changed"));
        }
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

/// Observes only the original executable's retained user-space owner layout.
impl OriginalExecutable {
    pub(in crate::node_adapters::cnp::semantic) fn charge_retained_storage_data(
        &self,
        counter: &mut super::super::retained_storage::Counter,
    ) -> Result<(), crate::node_contract::OperationFailure> {
        self.ensure_origin().map_err(super::super::unknown)?;
        counter.charge(&self.process_path)?;
        counter.charge(&self.original_target)?;
        counter.charge(&self.expected)?;
        if self.original.lease().is_some() {
            // The acquired lease retains a notification worker and private std
            // synchronization backing. File/lease inline fields are already in
            // Self, but that opaque owner cannot be priced from a byte limit.
            counter.unknowns.executable_lease_worker = true;
        }
        counter.arc_file(self.original.file())?;
        self.ensure_origin().map_err(super::super::unknown)
    }
}

impl OriginalExecutable {
    pub(in crate::node_adapters::cnp::semantic) fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        self.storage_origin_precredit_data()?;
        // An opaque notification worker is unsupported by the selected typed
        // owner walk as well. Never reinterpret that worker as zero resources.
        if self.original.lease().is_some() {
            return Err(crate::node_contract::RuntimeError::UnsupportedFacet);
        }
        let _original = self.original.file();
        Ok(1)
    }
}
