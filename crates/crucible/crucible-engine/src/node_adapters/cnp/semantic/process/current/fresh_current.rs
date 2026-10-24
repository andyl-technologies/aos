//! Validates the selected host query's same original read with admitted banks.
//!
//! Raw storage quotes perform no syscall, hash or live registrar renewal. The
//! later ticketed validation retains the original owner and performs every
//! descriptor, namespace, kernel and SDK fence using the quoted scratch.

use super::super::executable_guard::FreshCurrentScratch;
use super::*;
use crate::node_contract::RuntimeError;

impl CnpSemanticSourceRead {
    pub(in crate::node_adapters::cnp::semantic) fn original_fresh_current_storage_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.executable.storage_origin_precredit_data()?;
        self.owner.original_fresh_query_custody_data()?;
        self.executable.fresh_current_storage_data()
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_fresh_current_scratch(
        &self,
    ) -> Result<FreshCurrentScratch, RuntimeError> {
        self.original_fresh_current_storage_data()?;
        self.executable.fresh_current_scratch()
    }

    pub(in crate::node_adapters::cnp::semantic) fn ensure_original_fresh_current(
        &self,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<(), RuntimeError> {
        self.original_fresh_current_storage_data()?;
        self.registration
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.executable
            .ensure_fresh_current(&self.kernel, scratch)?;
        self.registration
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.owner.original_fresh_query_custody_data()?;
        self.executable.ensure_fresh_current(&self.kernel, scratch)
    }
}

impl KernelIdentity {
    pub(in crate::node_adapters::cnp::semantic) fn original_pid_data(&self) -> u32 {
        self.pid
    }

    pub(in crate::node_adapters::cnp::semantic) fn ensure_fresh_current(
        &self,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<(), RuntimeError> {
        let path = scratch.proc_path(self.pid, b"/stat")?;
        let descriptor = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
        let mut file = File::from(descriptor);
        let mut length = 0;
        while length < scratch.stat.len() {
            let count = file
                .read(&mut scratch.stat[length..])
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            if count == 0 {
                break;
            }
            length += count;
        }
        if length > 32 * 1024 {
            return Err(RuntimeError::ResourceLimit);
        }
        let body = std::str::from_utf8(&scratch.stat[..length])
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let (prefix, tail) = body.rsplit_once(") ").ok_or(RuntimeError::InvalidReceipt)?;
        let (actual_pid, command) = prefix.split_once(' ').ok_or(RuntimeError::InvalidReceipt)?;
        if actual_pid
            .parse::<u32>()
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != self.pid
            || !command.starts_with('(')
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut fields = tail.split_ascii_whitespace();
        let _state = fields.next().ok_or(RuntimeError::InvalidReceipt)?;
        let parent: u32 = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(RuntimeError::InvalidReceipt)?;
        let group: u32 = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(RuntimeError::InvalidReceipt)?;
        let start: u64 = fields
            .nth(16)
            .and_then(|value| value.parse().ok())
            .ok_or(RuntimeError::InvalidReceipt)?;
        let path = scratch.proc_path(self.pid, b"")?;
        let descriptor = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
        use std::os::unix::fs::MetadataExt;
        let uid = File::from(descriptor)
            .metadata()
            .map_err(|_| RuntimeError::OwnerUnavailable)?
            .uid();
        if parent != std::process::id()
            || group != self.pid
            || uid != rustix::process::geteuid().as_raw()
            || (Self {
                pid: self.pid,
                parent,
                group,
                start,
                uid,
            }) != *self
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}
