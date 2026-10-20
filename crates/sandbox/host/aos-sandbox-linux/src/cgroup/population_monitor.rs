//! Retains the shared active-file and population-monitor acquisition prefix.
//!
//! The caller supplies an already held cgroup anchor and pays the finite
//! receiving obligations before entry. This owner uses the ordinary monitor's
//! native recipe and grants no service, process or destruction authority.

use super::*;

/// Holds all reached files and the first error of one population acquisition.
#[derive(Debug, Default)]
#[must_use = "retain partial files and errors until the enclosing operation finishes"]
pub struct CgroupPopulationMonitorOriginalV3 {
    active: PendingRegularFileV1,
    events: PendingRegularFileV1,
    returned: Option<Result<CgroupPopulationMonitor>>,
    closed: Option<Error>,
    taken: bool,
}

impl CgroupPopulationMonitorOriginalV3 {
    /// Creates inert inline destinations without native work or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures the same active reference and events file as the ordinary path.
    ///
    /// # Errors
    /// Retains the exact original acquisition or identity error and all reached
    /// files. Reentry closes without replacing any original or native prefix.
    pub fn capture_once_v3(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.returned.is_some() || self.taken || self.closed.is_some() {
            self.closed.get_or_insert_with(retained_native::closed);
            return Err(retained_native::closed());
        }

        self.returned =
            Some(anchor.population_monitor_retaining(&mut self.active, &mut self.events));

        if matches!(self.returned, Some(Ok(_))) {
            Ok(())
        } else {
            Err(retained_native::closed())
        }
    }

    /// Borrows the earliest retained acquisition or reentry cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.returned
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .or(self.closed.as_ref())
            .map(|error| error as _)
    }

    /// Moves the same completed events monitor once, preserving other custody.
    ///
    /// A failed or closed acquisition never yields a monitor. The active-file
    /// prefix remains in this owner through the enclosing independent posts.
    #[must_use]
    pub fn take_completed_once_v3(&mut self) -> Option<CgroupPopulationMonitor> {
        if self.taken || self.closed.is_some() || !matches!(self.returned, Some(Ok(_))) {
            return None;
        }

        self.taken = true;
        match self.returned.take() {
            Some(Ok(monitor)) => Some(monitor),
            _ => std::process::abort(),
        }
    }

    /// Bounds complete construction bytes, two files and two actual names.
    ///
    /// Native layouts include the shared active/open helper stack and return
    /// carriers. Fixed path and error text are source bounded; allocator and
    /// kernel overhead still require the caller's independent containment.
    #[must_use]
    pub fn receiving_obligations_v3() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<ReceivingFrames<'static>>())?
            .checked_add(b"cgroup.procs\0".len())?
            .checked_add(b"cgroup.events\0".len())?
            .checked_add("kernel directory identity changed or is unspecified".len())?
            .checked_add("original operation remains closed".len().checked_mul(3)?)?;
        Some((bytes, 2, 2))
    }
}

// Compiled representation of the two shared helper invocations and their
// native return temporaries; this type is passive and never constructed.
#[allow(dead_code)]
struct ReceivingFrames<'anchor> {
    anchors: [&'anchor RetainedCgroupAnchor; 2],
    pending: [&'anchor mut PendingRegularFileV1; 2],
    paths: [std::ffi::CString; 2],
    path_arguments: [&'anchor Path; 2],
    identities: [crate::path::FileIdentity; 2],
    stats: [libc::stat; 2],
    filesystems: [libc::statfs; 2],
    open_how: [uapi::OpenHow; 2],
    flags: [u64; 2],
    native_returns: [Result<OwnedFd>; 2],
    monitor_returns: [Result<CgroupPopulationMonitor>; 2],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_filesystem_refusal_stays_first_and_never_yields_a_monitor() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let root = BeneathRoot::from_owned(descriptor).unwrap();
        let anchor = anchor_from_root!(root);
        let mut original = CgroupPopulationMonitorOriginalV3::new();

        assert!(original.capture_once_v3(&anchor).is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(original.capture_once_v3(&anchor).is_err());
        assert_eq!(
            original.failure().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(original.take_completed_once_v3().is_none());
        assert!(uapi::fstat(anchor.as_fd()).is_ok());
        assert!(original.active.file().is_err());
        assert!(original.events.file().is_err());
    }
}
