//! Joins Network's actual donated events file to the canonical cgroup monitor.
//!
//! The parent separately authenticates PID1, its real birth, payer and child
//! PIDFD. This owner proves native file identity only. It retains the donated
//! file and the canonical same-anchor monitor through all failed prefixes.

use super::*;

#[derive(Clone, Copy, Debug)]
enum First { Before, Cloexec, Stat, Filesystem, Flags, Input, Monitor, MonitorStat, Binding, After, Order }

/// Retains an actual event donation and its independently bracketed native join.
///
/// A completed native comparison supplies no Source, payer, child authority or
/// Empty/Retired conclusion. The genuine parent must separately observe both
/// its actual leader PIDFD and this same monitor for the required disposition.
#[derive(Default)]
pub struct NetworkBirthPopulationDonationOriginalV2 {
    entered: bool,
    donated: Option<File>,
    before: CgroupActiveOriginalV2,
    before_result: Option<Result<()>>,
    cloexec: Option<Result<bool>>,
    stat: Option<Result<libc::stat>>,
    filesystem: Option<Result<libc::c_long>>,
    flags: Option<Result<libc::c_int>>,
    monitor_original: CgroupPopulationMonitorOriginalV3,
    monitor_result: Option<Result<()>>,
    monitor: Option<CgroupPopulationMonitor>,
    monitor_stat: Option<Result<libc::stat>>,
    after: CgroupActiveOriginalV2,
    after_result: Option<Result<()>>,
    first: Option<First>,
    closed: Option<Error>,
}

impl NetworkBirthPopulationDonationOriginalV2 {
    /// Creates inert destinations without opening or validating anything.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Matches the retained donation with a fresh canonical same-cgroup monitor.
    ///
    /// The original donated FD moves from its caller-held slot into this owner
    /// before any validation. A refused reentry leaves the input slot untouched.
    /// The independently owed same-anchor after runs even when input, monitor
    /// acquisition or identity comparison fails. No reentry replaces a prefix.
    ///
    /// # Errors
    /// Retains every reached native acquisition/result and the first refusal.
    /// Refuses wrong descriptor type/access/filesystem, a different events
    /// object, stale cgroup, unavailable canonical monitor or repeated entry.
    pub fn capture_once_v2(&mut self, donated: &mut Option<OwnedFd>, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        let Some(donated) = donated.take() else { return self.refuse(First::Input); };
        self.donated = Some(File::from(donated));
        self.before_result = Some(self.before.capture_once_v2(anchor));
        if matches!(self.before_result, Some(Ok(()))) {
            let _ = self.capture_inner(anchor);
        } else { self.first = Some(First::Before); }

        self.after_result = Some(self.after.capture_once_v2(anchor));
        if !matches!(self.after_result, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        if self.first.is_some() { Err(closed()) } else { Ok(()) }
    }

    fn capture_inner(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        let Some(donated) = self.donated.as_ref() else { return self.refuse(First::Input); };
        self.cloexec = Some(uapi::is_cloexec(donated.as_fd()));
        if !matches!(self.cloexec, Some(Ok(true))) { return self.refuse(First::Cloexec); }
        self.stat = Some(uapi::fstat(donated.as_fd()));
        let Some(Ok(stat)) = self.stat.as_ref() else { return self.refuse(First::Stat); };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_ino == 0 {
            return self.refuse(First::Input);
        }
        self.filesystem = Some(uapi::filesystem_type(donated.as_fd()));
        if !matches!(self.filesystem, Some(Ok(CGROUP2_SUPER_MAGIC))) { return self.refuse(First::Filesystem); }
        self.flags = Some(uapi::get_status_flags(donated.as_fd()));
        let Some(Ok(flags)) = self.flags.as_ref() else { return self.refuse(First::Flags); };
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
            return self.refuse(First::Input);
        }
        self.monitor_result = Some(self.monitor_original.capture_once_v3(anchor));
        if !matches!(self.monitor_result, Some(Ok(()))) { return self.refuse(First::Monitor); }
        self.monitor = self.monitor_original.take_completed_once_v3();
        let Some(monitor) = self.monitor.as_ref() else { return self.refuse(First::Monitor); };
        self.monitor_stat = Some(uapi::fstat(monitor.events.as_fd()));
        let Some(Ok(named)) = self.monitor_stat.as_ref() else { return self.refuse(First::MonitorStat); };
        if named.st_dev != stat.st_dev || named.st_ino != stat.st_ino
            || named.st_mode & libc::S_IFMT != libc::S_IFREG
            || monitor.require_same_cgroup(anchor).is_err() {
            return self.refuse(First::Binding);
        }
        Ok(())
    }

    fn refuse(&mut self, cause: First) -> Result<()> {
        self.first.get_or_insert(cause);
        self.closed.get_or_insert_with(closed);
        Err(closed())
    }

    /// Borrows only the same completely joined canonical monitor.
    ///
    /// This performs no observation and proves no current population state.
    #[must_use]
    pub fn monitor_data_v2(&self) -> Option<&CgroupPopulationMonitor> {
        if self.first.is_some() || !matches!(self.after_result, Some(Ok(()))) { return None; }
        self.monitor.as_ref()
    }

    /// Borrows the selected actual native or comparison cause without resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = match self.first? {
            First::Before => self.before.failure(),
            First::Cloexec => self.cloexec.as_ref()?.as_ref().err(),
            First::Stat => self.stat.as_ref()?.as_ref().err(),
            First::Filesystem => self.filesystem.as_ref()?.as_ref().err(),
            First::Flags => self.flags.as_ref()?.as_ref().err(),
            First::Monitor => return self.monitor_original.failure()
                .or_else(|| self.closed.as_ref().map(|cause| cause as _)),
            First::MonitorStat => self.monitor_stat.as_ref()?.as_ref().err(),
            First::After => self.after.failure(),
            First::Input | First::Binding | First::Order => None,
        };
        cause.or(self.closed.as_ref()).map(|cause| cause as _)
    }

    /// Prices native joining beyond the three rights already paid on receipt.
    ///
    /// The donated FD is deliberately not charged twice. Two active bookends
    /// and the canonical monitor add four real OFDs and four actual names.
    /// Native/allocator overhead still uses the caller's genuine containment.
    #[must_use]
    pub fn receiving_obligations_data_v2() -> Option<(usize, usize, usize)> {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let monitor = CgroupPopulationMonitorOriginalV3::receiving_obligations_v3()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(active.0.checked_mul(2)?)?.checked_add(monitor.0)?
            .checked_add(3 * 256)?;
        Some((bytes, active.1.checked_mul(2)?.checked_add(monitor.1)?,
            active.2.checked_mul(2)?.checked_add(monitor.2)?))
    }
}

fn closed() -> Error {
    Error::invalid("Network birth events original", "original native join is closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_native_before_still_runs_after_and_retains_actual_input_and_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        let root = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let anchor = RetainedCgroupAnchor { kernel_id: root.identity().inode, root };
        let mut donor = Some(tempfile::tempfile().unwrap().into());
        let mut original = NetworkBirthPopulationDonationOriginalV2::new();

        assert!(original.capture_once_v2(&mut donor, &anchor).is_err());

        assert!(matches!(original.before_result, Some(Err(_))));
        assert!(matches!(original.after_result, Some(Err(_))));
        assert!(original.donated.is_some());
        assert!(donor.is_none());
        assert!(original.monitor_data_v2().is_none());
        assert!(std::ptr::eq(original.failure().unwrap().downcast_ref::<Error>().unwrap(),
            original.before.failure().unwrap()));
        let first = original.before.failure().unwrap() as *const Error;
        let mut another = Some(tempfile::tempfile().unwrap().into());
        assert!(original.capture_once_v2(&mut another, &anchor).is_err());
        assert!(another.is_some());
        assert!(std::ptr::eq(original.failure().unwrap().downcast_ref::<Error>().unwrap(), first));
    }
}
