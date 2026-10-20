//! Captures the selected native child's kernel identity with fixed procfs banks.
//!
//! This separate constructor precedes executable acquisition. Ordinary launch
//! capture remains unchanged, and this data owner grants no launch permission.

use super::super::executable_guard::FreshCurrentScratch;
use super::*;
use crate::node_contract::RuntimeError;

impl KernelIdentity {
    pub(in crate::node_adapters::cnp::semantic) fn capture_original_native_startup(
        pid: u32,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<Self, RuntimeError> {
        let path = scratch.proc_path(pid, b"/stat")?;
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
            != pid
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
        let path = scratch.proc_path(pid, b"")?;
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
            || group != pid
            || uid != rustix::process::geteuid().as_raw()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(Self {
            pid,
            parent,
            group,
            start,
            uid,
        })
    }
}
