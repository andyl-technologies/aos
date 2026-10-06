//! Pins memory-limit updates to the live attempt cgroup without namespace reuse.

use super::*;

/// Process-private memory control lent to the combined retirement-gated owner.
#[derive(Debug)]
pub(crate) struct LinuxQemuCgroupMemoryControl {
    directory: OwnedFd,
    path: PathBuf,
    watcher_state: Arc<AtomicU8>,
}

impl LinuxQemuCgroupControl {
    /// Pins one read-back-verified memory controller while the watcher is live.
    ///
    /// # Errors
    /// Refuses terminal supervision or failed descriptor duplication.
    pub(crate) fn memory_control(
        &self,
    ) -> Result<LinuxQemuCgroupMemoryControl, LinuxQemuCgroupError> {
        if self.watcher_state.load(Ordering::Acquire) != WATCHER_RUNNING {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: self.path.clone(),
            });
        }
        Ok(LinuxQemuCgroupMemoryControl {
            directory: duplicate_fd(
                self.directory.as_raw_fd(),
                "pin QEMU memory controller",
                &self.path,
            )?,
            path: self.path.clone(),
            watcher_state: self.watcher_state.clone(),
        })
    }
}

impl LinuxQemuCgroupMemoryControl {
    /// Installs a monotonic memory limit through the retained cgroup descriptor.
    ///
    /// # Errors
    /// Refuses increased/zero limits, terminal supervision, stale prior limits,
    /// or failed filesystem, write or read-back authentication.
    pub(crate) fn tighten(
        &self,
        expected: u64,
        requested: u64,
    ) -> Result<(), LinuxQemuCgroupError> {
        if requested == 0 || requested > expected {
            return Err(LinuxQemuCgroupError::InvalidLimit);
        }
        if self.watcher_state.load(Ordering::Acquire) != WATCHER_RUNNING {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: self.path.clone(),
            });
        }
        validate_cgroup_v2(&self.directory, &self.path)?;
        let mut current = open_control(
            &self.directory,
            &self.path,
            "memory.max",
            ControlAccess::Read,
        )?;
        let actual = read_control(
            &mut current,
            &self.path.join("memory.max"),
            "authenticate current QEMU memory limit",
            MAX_CGROUP_CONTROL_BYTES,
        )?;
        if actual.trim_ascii_end() != expected.to_string() {
            return Err(LinuxQemuCgroupError::ControlValue {
                path: self.path.join("memory.max"),
                expected: expected.to_string(),
                actual,
            });
        }
        drop(current);
        write_control(
            &self.directory,
            &self.path,
            "memory.max",
            format!("{requested}\n").as_bytes(),
        )?;
        if self.watcher_state.load(Ordering::Acquire) != WATCHER_RUNNING {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: self.path.clone(),
            });
        }
        Ok(())
    }
}
