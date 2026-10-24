//! Bounds the selected HOST query's executable and procfs validation banks.
//!
//! The ordinary executable guard keeps its existing behavior. This selected
//! complete-byte path reuses the retained descriptor and immutable identity;
//! it neither opens a notification worker nor constructs another ContentRef.

use std::{ffi::CStr, mem::size_of, os::unix::ffi::OsStrExt};

use super::*;
use crate::node_contract::RuntimeError;

// Batch complete-byte reads under the same independently quoted scratch row.
const EXECUTABLE_STREAM_BYTES: usize = 256 * 1024;

/// Owns one sequential kernel/namespace/executable validation window.
///
/// Core precredits the header and full stream-bank capacity. The original
/// namespace length plus one is quoted separately from the retained owner.
/// Compiler frames and OS resources are separate from these requested banks.
pub(in crate::node_adapters::cnp::semantic) struct FreshCurrentScratch {
    pub(in crate::node_adapters::cnp::semantic) stat: [u8; 32 * 1024 + 1],
    bytes: Vec<u8>,
    link: Vec<u8>,
    path: [u8; 32],
}

impl FreshCurrentScratch {
    fn stream_bank() -> Result<Vec<u8>, RuntimeError> {
        // A large inline array materializes in nested currentness frames and
        // overflows the ordinary native-test stack. Reserve directly on heap.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(EXECUTABLE_STREAM_BYTES)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if bytes.capacity() > EXECUTABLE_STREAM_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        bytes.resize(EXECUTABLE_STREAM_BYTES, 0);
        Ok(bytes)
    }

    pub(super) fn read_original_native_link(&mut self, pid: u32) -> Result<usize, RuntimeError> {
        let path_len = self.proc_path(pid, b"/exe")?.to_bytes_with_nul().len();
        let path = CStr::from_bytes_with_nul(&self.path[..path_len])
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        rustix::fs::readlinkat_raw(rustix::fs::CWD, path, &mut self.link[..])
            .map_err(|_| RuntimeError::OwnerUnavailable)
    }

    pub(super) fn original_native_link_data(&self) -> &[u8] {
        &self.link
    }

    pub(in crate::node_adapters::cnp::semantic) fn for_original_native_startup()
    -> Result<Self, RuntimeError> {
        let maximum = OriginalExecutable::original_native_startup_link_bytes();
        let mut link = Vec::new();
        link.try_reserve_exact(maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if link.capacity() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        link.resize(maximum, 0);
        Ok(Self {
            stat: [0; 32 * 1024 + 1],
            bytes: Self::stream_bank()?,
            link,
            path: [0; 32],
        })
    }

    pub(in crate::node_adapters::cnp::semantic) fn declared_scratch_data() -> usize {
        size_of::<Self>()
            + EXECUTABLE_STREAM_BYTES
            + size_of::<blake3::Hasher>()
            + 3 * size_of::<Metadata>()
            + 3 * size_of::<std::fs::File>()
            + size_of::<FileRevision>()
            + size_of::<blake3::Hash>()
            + result_layout(|| blake3::Hash::from([0; 32]).to_hex())
            + size_of::<std::io::Error>()
            + size_of::<rustix::io::Errno>()
            + size_of::<KernelIdentity>()
            + size_of::<std::str::SplitAsciiWhitespace<'static>>()
            + 2 * size_of::<&CStr>()
            + 2 * size_of::<&[u8]>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn proc_path(
        &mut self,
        pid: u32,
        suffix: &[u8],
    ) -> Result<&CStr, RuntimeError> {
        // Write digits backwards, then move them behind the fixed prefix.
        self.path.fill(0);
        let mut value = pid;
        let mut start = 16;
        loop {
            start -= 1;
            self.path[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        let digits = 16 - start;
        self.path.copy_within(start..16, 6);
        self.path[..6].copy_from_slice(b"/proc/");
        let end = 6usize
            .checked_add(digits)
            .and_then(|end| end.checked_add(suffix.len()))
            .filter(|end| *end < self.path.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        self.path[6 + digits..end].copy_from_slice(suffix);
        self.path[end] = 0;
        CStr::from_bytes_with_nul(&self.path[..=end]).map_err(|_| RuntimeError::InvalidReceipt)
    }
}

impl OriginalExecutable {
    pub(in crate::node_adapters::cnp::semantic) fn fresh_current_storage_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.storage_origin_precredit_data()?;
        if self.original.lease().is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if self.bounded_birth {
            return Ok(Self::original_native_startup_link_bytes());
        }
        self.original_target
            .as_os_str()
            .as_bytes()
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(in crate::node_adapters::cnp::semantic) fn fresh_current_scratch(
        &self,
    ) -> Result<FreshCurrentScratch, RuntimeError> {
        let maximum = self.fresh_current_storage_data()?;
        let mut link = Vec::new();
        link.try_reserve_exact(maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if link.capacity() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        link.resize(maximum, 0);
        Ok(FreshCurrentScratch {
            stat: [0; 32 * 1024 + 1],
            bytes: FreshCurrentScratch::stream_bank()?,
            link,
            path: [0; 32],
        })
    }

    pub(in crate::node_adapters::cnp::semantic) fn ensure_fresh_current(
        &self,
        kernel: &KernelIdentity,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_precredit_data()?;
        if self.revoked.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let result = (|| {
            let maximum = self.fresh_current_storage_data()?;
            if scratch.link.len() != maximum || scratch.link.capacity() > maximum {
                return Err(RuntimeError::ResourceLimit);
            }
            self.fresh_fences(kernel, scratch)?;
            self.measure_fresh_bytes(scratch)?;
            self.fresh_fences(kernel, scratch)
        })();
        if result.is_err() {
            self.revoked.set(true);
        }
        result
    }

    pub(super) fn fresh_fences(
        &self,
        kernel: &KernelIdentity,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_precredit_data()?;
        kernel.ensure_fresh_current(scratch)?;
        let path = scratch.proc_path(kernel.original_pid_data(), b"/exe")?;
        if path.to_bytes() != self.process_path.as_os_str().as_bytes() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let descriptor = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
        let current = std::fs::File::from(descriptor);
        if FileRevision::read(
            self.original
                .file()
                .metadata()
                .map_err(|_| RuntimeError::OwnerUnavailable)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?
            != self.revision
            || FileRevision::read(
                current
                    .metadata()
                    .map_err(|_| RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?
                != self.revision
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let path = scratch.proc_path(kernel.original_pid_data(), b"/exe")?;
        // CStr avoids rustix's allocating Path conversion. Split the scratch
        // fields so the fixed path and exact-length output bank coexist.
        let path_bytes = path.to_bytes_with_nul().len();
        let path = CStr::from_bytes_with_nul(&scratch.path[..path_bytes])
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let read = rustix::fs::readlinkat_raw(rustix::fs::CWD, path, &mut scratch.link[..])
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        if read != self.original_target.as_os_str().as_bytes().len()
            || scratch.link[..read] != *self.original_target.as_os_str().as_bytes()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        kernel.ensure_fresh_current(scratch)
    }

    pub(super) fn measure_fresh_bytes(
        &self,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<(), RuntimeError> {
        self.measure_fresh_bytes_in_bank(&mut scratch.bytes)
    }

    // The caller owns and independently funds the bank. This helper measures
    // complete bytes only; kernel, namespace and revision fences stay outside.
    fn measure_fresh_bytes_in_bank(&self, bank: &mut [u8]) -> Result<(), RuntimeError> {
        let expected = &self.expected;
        if expected.hash.algorithm != "blake3-256"
            || expected.hash.domain != "cnp.blob.v1"
            || expected.media_type != "application/octet-stream"
            || expected.length.get() != self.revision.length
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"CNP/1\0");
        hash.update(&11_u32.to_be_bytes());
        hash.update(b"cnp.blob.v1");
        hash.update(&self.revision.length.to_be_bytes());
        let mut offset = 0_u64;
        while offset < self.revision.length {
            let remaining = self.revision.length - offset;
            let count = remaining.min(bank.len() as u64) as usize;
            let read = self
                .original
                .file()
                .read_at(&mut bank[..count], offset)
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            if read == 0 {
                return Err(RuntimeError::OwnerUnavailable);
            }
            hash.update(&bank[..read]);
            offset += read as u64;
        }
        if self
            .original
            .file()
            .read_at(&mut bank[..1], offset)
            .map_err(|_| RuntimeError::OwnerUnavailable)?
            != 0
            || hash.finalize().to_hex().as_str() != expected.hash.digest
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

// Infer the actual external return type without running its formatter before
// observer credit. The closure is zero-sized and is never invoked.
fn result_layout<T>(_: impl FnOnce() -> T) -> usize {
    size_of::<T>()
}

#[cfg(test)]
#[path = "fresh_current_tests.rs"]
mod tests;
