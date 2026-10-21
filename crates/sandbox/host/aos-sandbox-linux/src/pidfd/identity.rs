//! Stable process-instance observations anchored by a live pidfd.
//!
//! Numeric process IDs are reusable. This module couples repeated identity
//! observations returned by `PIDFD_GET_INFO` to Linux's boot-relative process
//! start time, while the pidfd keeps the observed process instance pinned.

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;

use super::{PidFd, PidFdInfo};
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

pub(super) const MAXIMUM_PROC_STAT_BYTES: usize = 4096;

mod original;
pub use original::PidFdProcessIdentityOriginalV1;

/// Captures process facts while a [`PidFd`] retains the observed instance.
///
/// Callers that persist this value must additionally bind the current kernel
/// boot ID and must not treat the numeric tuple as a replacement for a live
/// pidfd. `start_time_ticks` is boot-relative and has no cross-boot meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PidFdProcessIdentity {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: Option<u64>,
    start_time_ticks: u64,
}

impl PidFdProcessIdentity {
    /// Returns the process ID in the observing process's PID namespace.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Returns the thread-group leader ID.
    #[must_use]
    pub const fn thread_group_id(self) -> u32 {
        self.thread_group_id
    }

    /// Returns the parent process ID from the stable observation.
    #[must_use]
    pub const fn parent_pid(self) -> u32 {
        self.parent_pid
    }

    /// Returns the kernel cgroup identity when `PIDFD_GET_INFO` supplied it.
    #[must_use]
    pub const fn cgroup_id(self) -> Option<u64> {
        self.cgroup_id
    }

    /// Returns `/proc/PID/stat` field 22 in clock ticks since boot.
    #[must_use]
    pub const fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }
}


/// Observes a stable process instance while retaining this pidfd.
///
/// The procfs start time is read between two equal `PIDFD_GET_INFO`
/// observations. Equality is a consistency sandwich, not a globally atomic
/// snapshot or proof against a mutable field changing and changing back.
/// Final liveness rejects the case where the pinned process exits and its
/// numeric PID is reused while procfs is being inspected. No field is
/// guaranteed fresh after this method returns.
///
/// # Errors
///
/// Returns an error when pidfd inspection is unavailable, procfs returns a
/// malformed or oversized stat record, the stat record contradicts the
/// pidfd, the process changes during observation, or the process exits.
pub fn process_identity(process: &PidFd) -> Result<PidFdProcessIdentity> {
    process_identity_observed(process, &mut None)
}

pub(super) fn process_identity_observed(
    process: &PidFd,
    original: &mut Option<&mut PidFdProcessIdentityOriginalV1>,
) -> Result<PidFdProcessIdentity> {
    let before = original::observe_copy(process.info(), original.as_deref_mut()
        .map(|original| &mut original.before))?;
    let stat = read_proc_stat_observed(before.pid(), original)?;
    let after = original::observe_copy(process.info(), original.as_deref_mut()
        .map(|original| &mut original.after))?;

    identity_from_stat_observed(process, before, stat, after, original)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcStatIdentity {
    pid: u32,
    parent_pid: u32,
    start_time_ticks: u64,
}

impl ProcStatIdentity {
    /// Returns the process ID in the original procfs mount's PID namespace.
    pub(super) const fn pid(self) -> u32 {
        self.pid
    }

    /// Returns the parent ID in that same original procfs namespace.
    pub(super) const fn parent_pid(self) -> u32 {
        self.parent_pid
    }

    /// Returns the parsed boot-relative start time without branding identity.
    pub(super) const fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }
}

fn read_proc_stat_observed(
    pid: u32,
    original: &mut Option<&mut PidFdProcessIdentityOriginalV1>,
) -> Result<ProcStatIdentity> {
    let pid = NonZeroU32::new(pid).ok_or_else(|| {
        Error::invalid("pidfd process identity", "kernel returned process ID zero")
    })?;
    let path = format!("/proc/{pid}/stat");
    if let Some(original) = original.as_deref_mut() {
        original.path = Some(path.clone());
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open(/proc/PID/stat)",
        source: source.into(),
    });
    match original.as_deref_mut() {
        None => {
            let mut bytes = Vec::new();
            File::from(descriptor?)
                .take((MAXIMUM_PROC_STAT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|source| Error::Syscall {
                    operation: "read(/proc/PID/stat)",
                    source,
                })?;
            if bytes.len() > MAXIMUM_PROC_STAT_BYTES {
                return Err(too_long());
            }
            parse_proc_stat(&bytes)
        }
        Some(original) => {
            match descriptor {
                Ok(file) => {
                    original.file = Some(File::from(file));
                    original.open = Some(Ok(()));
                }
                Err(cause) => {
                    original.open = Some(Err(cause));
                    return Err(original::closed());
                }
            }
            let file = original.file.as_ref().ok_or_else(original::closed)?;
            original.read = Some(file.take((MAXIMUM_PROC_STAT_BYTES + 1) as u64)
                .read_to_end(&mut original.bytes)
                .map_err(|source| Error::Syscall {
                    operation: "read(/proc/PID/stat)",
                    source,
                }));
            if !matches!(original.read, Some(Ok(_))) {
                return Err(original::closed());
            }
            original.length = Some(if original.bytes.len() > MAXIMUM_PROC_STAT_BYTES {
                Err(too_long())
            } else {
                Ok(())
            });
            if !matches!(original.length, Some(Ok(()))) {
                return Err(original::closed());
            }
            original.parsed = Some(parse_proc_stat(&original.bytes));
            match original.parsed.as_ref() {
                Some(Ok(stat)) => Ok(*stat),
                _ => Err(original::closed()),
            }
        }
    }
}

pub(super) fn parse_proc_stat(bytes: &[u8]) -> Result<ProcStatIdentity> {
    let open = bytes
        .windows(2)
        .position(|pair| pair == b" (")
        .ok_or_else(|| {
            Error::invalid("pidfd process identity", "proc stat omitted process name")
        })?;
    let close = bytes
        .windows(2)
        .rposition(|pair| pair == b") ")
        .filter(|close| *close > open + 1)
        .ok_or_else(|| {
            Error::invalid(
                "pidfd process identity",
                "proc stat process name is malformed",
            )
        })?;
    let pid = parse_decimal(&bytes[..open], "process ID")?;
    let fields = bytes[close + 2..]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    // The suffix starts at field 3 (`state`), so indices 1 and 19 are fields
    // 4 (`ppid`) and 22 (`starttime`) respectively.
    let parent_pid = fields
        .get(1)
        .ok_or_else(|| Error::invalid("pidfd process identity", "proc stat omitted parent PID"))
        .and_then(|value| parse_decimal(value, "parent PID"))?;
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| Error::invalid("pidfd process identity", "proc stat omitted start time"))
        .and_then(|value| parse_decimal_u64(value, "start time"))?;
    Ok(ProcStatIdentity {
        pid,
        parent_pid,
        start_time_ticks,
    })
}

fn parse_decimal(value: &[u8], field: &'static str) -> Result<u32> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| Error::invalid("pidfd process identity", format!("invalid {field}")))
}

fn parse_decimal_u64(value: &[u8], field: &'static str) -> Result<u64> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| Error::invalid("pidfd process identity", format!("invalid {field}")))
}

// Both routes keep the same info -> stat -> info -> conditional liveness
// ordering. In particular, a contradicted stat does not trigger another syscall.
pub(super) fn identity_from_stat(
    pidfd: &PidFd,
    before: PidFdInfo,
    stat: ProcStatIdentity,
    after: PidFdInfo,
) -> Result<PidFdProcessIdentity> {
    identity_from_stat_observed(pidfd, before, stat, after, &mut None)
}

fn identity_from_stat_observed(
    pidfd: &PidFd,
    before: PidFdInfo,
    stat: ProcStatIdentity,
    after: PidFdInfo,
    original: &mut Option<&mut PidFdProcessIdentityOriginalV1>,
) -> Result<PidFdProcessIdentity> {
    original::observe_copy(require_stat_coordinates(before, stat, after),
        original.as_deref_mut().map(|original| &mut original.coordinates))?;
    let alive = original::observe_copy(pidfd.is_alive(),
        original.as_deref_mut().map(|original| &mut original.alive))?;
    original::observe_copy(identity_with_liveness(before, stat, alive),
        original.as_deref_mut().map(|original| &mut original.binding))
}

fn too_long() -> Error {
    Error::invalid("pidfd process identity", "proc stat record exceeds its fixed bound")
}

pub(super) fn require_stat_coordinates(
    before: PidFdInfo,
    stat: ProcStatIdentity,
    after: PidFdInfo,
) -> Result<()> {
    if before != after || stat.pid != before.pid() || stat.parent_pid != before.parent_pid() {
        return Err(changed_identity());
    }
    Ok(())
}

pub(super) fn identity_with_liveness(
    before: PidFdInfo,
    stat: ProcStatIdentity,
    alive: bool,
) -> Result<PidFdProcessIdentity> {
    if !alive {
        return Err(changed_identity());
    }
    Ok(PidFdProcessIdentity {
        pid: before.pid(),
        thread_group_id: before.thread_group_id(),
        parent_pid: before.parent_pid(),
        cgroup_id: before.cgroup_id(),
        start_time_ticks: stat.start_time_ticks,
    })
}

fn changed_identity() -> Error {
    Error::invalid(
        "pidfd process identity",
        "process changed or exited during observation",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(comm: &str, parent_pid: u32, start_time_ticks: u64) -> Vec<u8> {
        // Fields 5 through 21 may be zero for parser tests. Field 3 is state.
        format!(
            "123 ({comm}) S {parent_pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start_time_ticks} 0\n"
        )
        .into_bytes()
    }

    #[test]
    fn parses_names_containing_spaces_and_parentheses() {
        assert_eq!(
            parse_proc_stat(&stat("worker ) name", 45, 67)).unwrap(),
            ProcStatIdentity {
                pid: 123,
                parent_pid: 45,
                start_time_ticks: 67,
            }
        );
    }

    #[test]
    fn accepts_zero_but_rejects_missing_start_time() {
        assert_eq!(
            parse_proc_stat(&stat("worker", 45, 0))
                .unwrap()
                .start_time_ticks,
            0
        );
        assert!(parse_proc_stat(b"123 (worker) S 45\n").is_err());
    }

    #[test]
    fn ignores_non_utf8_process_names() {
        let mut bytes = stat("worker", 45, 67);
        bytes[6] = 0xff;

        assert_eq!(parse_proc_stat(&bytes).unwrap().start_time_ticks, 67);
    }

    #[test]
    fn observes_the_current_process_through_its_pidfd() {
        let raw_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get()).unwrap();
        let pid = NonZeroU32::new(raw_pid).unwrap();
        let process = PidFd::open(pid).unwrap();
        let identity = crate::pidfd::process_identity(&process).unwrap();

        assert_eq!(identity.pid(), raw_pid);
        assert_eq!(identity.thread_group_id(), raw_pid);
        assert_eq!(identity.pid(), process.info().unwrap().pid());
    }
}
