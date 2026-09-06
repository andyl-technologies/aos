//! Fork-cost measurements for the live hot-fork flights.
//!
//! The flights report how long a fork takes until the child answers on its
//! private QMP endpoint, what a child costs in threads, descriptors, and
//! private dirty memory, and whether the source keeps every thread and
//! descriptor it had before a child across the child's whole lifecycle.
//! The numbers are operational evidence for the Phase 6 record; nothing in
//! Crucible's state paths depends on them.

use std::fs;
use std::path::PathBuf;

use super::child_files::invariant;
use super::*;

/// One process's footprint from procfs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProcessFootprint {
    /// Threads in the thread group.
    pub(super) threads: u64,
    /// Open descriptors.
    pub(super) descriptors: u64,
    /// Anonymous resident memory in KiB.
    pub(super) rss_anon_kib: u64,
    /// Private dirty memory in KiB across every mapping.
    pub(super) private_dirty_kib: u64,
}

impl ProcessFootprint {
    /// Reads the footprint of `process_id`.
    pub(super) fn read(process_id: u32) -> Result<Self, QemuLiveNodeStepGateError> {
        let process = PathBuf::from(format!("/proc/{process_id}"));
        let status = fs::read_to_string(process.join("status")).map_err(|source| {
            QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: process.join("status"),
                source,
            }
        })?;
        let threads = status_field(&status, "Threads:")
            .ok_or_else(|| invariant("process status lacks a thread count"))?;
        let rss_anon_kib = status_field(&status, "RssAnon:").unwrap_or(0);
        let descriptors = fs::read_dir(process.join("fd"))
            .map_err(|source| QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: process.join("fd"),
                source,
            })?
            .count();
        let descriptors = u64::try_from(descriptors)
            .map_err(|_error| invariant("descriptor count overflowed"))?;
        let rollup = fs::read_to_string(process.join("smaps_rollup")).unwrap_or_default();
        let private_dirty_kib = status_field(&rollup, "Private_Dirty:").unwrap_or(0);
        Ok(Self {
            threads,
            descriptors,
            rss_anon_kib,
            private_dirty_kib,
        })
    }
}

/// Parses the first numeric field of the line starting with `key`.
fn status_field(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

/// Monotonic host time in nanoseconds for flight measurements.
///
/// The crate keeps host clocks out of Crucible's state paths; this reading
/// only times the flight's own operations for the Phase 6 record and never
/// reaches a node, a checkpoint, or a decision.
pub(super) fn monotonic_nanoseconds() -> u128 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes only into the local `timespec`, which
    // outlives the call; CLOCK_MONOTONIC is always available on Linux.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    if status != 0 {
        return 0;
    }
    let seconds = u128::try_from(now.tv_sec).unwrap_or(0);
    let nanoseconds = u128::try_from(now.tv_nsec).unwrap_or(0);
    seconds * 1_000_000_000 + nanoseconds
}

/// Elapsed whole milliseconds since `start`, saturating.
pub(super) fn elapsed_milliseconds(start: u128) -> u64 {
    let elapsed = monotonic_nanoseconds().saturating_sub(start) / 1_000_000;
    u64::try_from(elapsed).unwrap_or(u64::MAX)
}
