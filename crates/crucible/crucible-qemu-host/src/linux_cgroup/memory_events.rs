//! Records kernel OOM-kill evidence for the same pinned process family.
//!
//! A counter delta describes the cgroup, including its descendants. It cannot
//! identify a particular child or infer OOM from an exit signal. Sampling uses
//! one bounded read and fixed stack storage, without retrying an interrupted
//! read under a renewed deadline or retaining another descriptor.

use super::*;

/// Reports observed kernel OOM kills during one retained process family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("QEMU process family recorded kernel OOM kills ({baseline} -> {observed})")]
pub struct LinuxQemuMemoryLimitFailure {
    baseline: u64,
    observed: u64,
}

impl LinuxQemuMemoryLimitFailure {
    /// Returns the counter before the first child could launch.
    pub const fn baseline(&self) -> u64 {
        self.baseline
    }

    /// Returns the counter observed through the same pinned cgroup at closure.
    pub const fn observed(&self) -> u64 {
        self.observed
    }
}

/// Reads the kernel event count once through existing pinned authority.
///
/// # Errors
/// Refuses failed/open/interrupted reads, missing or duplicated counters,
/// noncanonical/overflow counts, and an incomplete or oversized record.
pub(super) fn read_oom_kills(
    directory: &OwnedFd,
    path: &Path,
) -> Result<u64, LinuxQemuCgroupError> {
    let file = open_control(directory, path, "memory.events", ControlAccess::Read)?;
    let mut bytes = [0u8; MAX_CGROUP_CONTROL_BYTES as usize];
    let count =
        rustix::io::pread(&file, &mut bytes[..], 0).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "read QEMU memory.events once",
            path: path.join("memory.events"),
            source: source.into(),
        })?;
    if count == bytes.len() {
        return Err(invalid(path, "memory.events exceeds bounded read"));
    }
    parse_oom_kills(&bytes[..count]).map_err(|reason| invalid(path, reason))
}

fn invalid(path: &Path, reason: &'static str) -> LinuxQemuCgroupError {
    LinuxQemuCgroupError::MemoryEvents {
        path: path.join("memory.events"),
        reason,
    }
}

fn parse_oom_kills(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err("memory.events is empty or incomplete");
    }
    let mut oom_kills = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let separator = line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or("missing event separator")?;
        let (name, value) = (&line[..separator], &line[separator + 1..]);
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || *byte == b'_')
        {
            return Err("invalid memory event name");
        }
        if value.is_empty() || (value.len() > 1 && value[0] == b'0') {
            return Err("noncanonical memory event count");
        }
        let mut count = 0u64;
        for byte in value {
            if !byte.is_ascii_digit() {
                return Err("invalid memory event count");
            }
            count = count
                .checked_mul(10)
                .and_then(|count| count.checked_add(u64::from(*byte - b'0')))
                .ok_or("memory event count overflow")?;
        }
        if name == b"oom_kill" && oom_kills.replace(count).is_some() {
            return Err("duplicate oom_kill event");
        }
    }
    oom_kills.ok_or("missing oom_kill event")
}

impl LinuxQemuCgroup {
    /// Observes a monotonic OOM delta without substituting for process reap.
    ///
    /// # Errors
    /// Refuses failed kernel reads, malformed records or a regressed counter.
    pub(super) fn memory_limit_failure(
        &self,
    ) -> Result<Option<LinuxQemuMemoryLimitFailure>, LinuxQemuCgroupError> {
        let Some(baseline) = self.memory_oom_kill_baseline else {
            return Ok(None);
        };
        // Wait handles and descendant retirement remain separate obligations;
        // this read never substitutes for the authenticated empty-group cut.
        let observed = read_oom_kills(&self.control.directory, &self.path)?;
        if observed < baseline {
            return Err(invalid(&self.path, "oom_kill counter moved backwards"));
        }
        Ok((observed > baseline).then_some(LinuxQemuMemoryLimitFailure { baseline, observed }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_event_counter_requires_complete_canonical_kernel_record() {
        assert_eq!(
            parse_oom_kills(b"low 0\nhigh 3\nmax 4\noom 2\noom_kill 1\noom_group_kill 0\n"),
            Ok(1)
        );
        for bad in [
            b"oom 1\n".as_slice(),
            b"oom_kill 1",
            b"oom_kill 01\n",
            b"oom_kill 1\noom_kill 2\n",
            b"oom_kill 18446744073709551616\n",
        ] {
            assert!(parse_oom_kills(bad).is_err());
        }
    }

    #[test]
    fn other_kernel_events_never_replace_the_oom_kill_counter() {
        assert_eq!(parse_oom_kills(b"oom 99\noom_kill 0\n"), Ok(0));
        assert!(parse_oom_kills(b"oom 99\noom_group_kill 2\n").is_err());
        assert_eq!(parse_oom_kills(b"oom 0\noom_kill 2\n"), Ok(2));
    }
}
