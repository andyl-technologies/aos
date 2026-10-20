//! Passive joining of a fixed inherited aggregate directory to the live hierarchy.
//!
//! A launch name or descriptor does not admit a worker or provide a resource
//! original. The recipient independently resolves the compiled aggregate and
//! compares the supplied directory before resolving the fixed Storage main.

use super::*;

/// Retains an inherited aggregate candidate and every reached native prefix.
#[derive(Debug, Default)]
pub struct StorageWorkerAggregateReadbackV1 {
    supplied: InitialServiceCgroupCaptureV1,
    supplied_result: Option<Result<()>>,
    flags: Option<Result<rustix::fs::OFlags>>,
    fixed: StorageReceivingAggregateCgroupReadbackV1,
    fixed_result: Option<Result<()>>,
    fixed_root: Option<CgroupV2Root>,
    fixed_anchor: Option<RetainedCgroupAnchor>,
    pair: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    comparison: Option<Result<()>>,
    transferred: bool,
    settled: bool,
}

impl StorageWorkerAggregateReadbackV1 {
    /// Bounds the additional inherited-directory OFDs through one child clone.
    ///
    /// The supplied prefix retains six directory/probe FDs, the independent
    /// fixed aggregate retains six, and the original fd3 remains close-on-exec.
    /// One existing worker hierarchy root makes fourteen. Before closefrom/
    /// exec, the sequential ZFS child can temporarily hold the same fourteen
    /// OFDs in its own table; no such descriptor survives its final exec.
    /// This does not price the child's separate NOFILE128 ceiling or model.
    #[must_use]
    pub const fn maximum_fork_descriptor_slots_v1() -> u64 {
        2 * 14
    }

    /// Creates empty native destinations without observing a descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins one supplied directory to the actual compiled aggregate once.
    ///
    /// # Errors
    /// Retains the supplied FD before directory validation, all partial fixed
    /// resolution probes, and the original error. A wrong anchor never falls
    /// back to the ordinary cgroup pathname.
    pub fn capture_once(&mut self, directory: OwnedFd) -> Result<()> {
        if self.supplied_result.is_some() {
            return Err(Error::invalid("worker aggregate", "capture already entered"));
        }
        self.supplied_result = Some(self.supplied.capture_initial(
            directory, InitialServiceCgroupV1::StorageAggregateMain,
        ));
        if !matches!(self.supplied_result, Some(Ok(()))) {
            return Err(Error::invalid("worker aggregate", "supplied prefix retained"));
        }
        self.pair = self.supplied.take_validated_pair();
        let Some((supplied, _)) = self.pair.as_ref() else {
            std::process::abort();
        };
        self.flags = Some(rustix::fs::fcntl_getfl(supplied.as_fd()).map_err(|source| Error::Syscall {
            operation: "worker aggregate fcntl(F_GETFL)", source: source.into(),
        }));
        match self.flags.as_ref() {
            Some(Ok(flags)) if *flags & rustix::fs::OFlags::ACCMODE == rustix::fs::OFlags::RDONLY
                && !flags.contains(rustix::fs::OFlags::PATH) => {},
            _ => return Err(Error::invalid("worker aggregate", "readonly directory required")),
        }
        self.fixed_result = Some(self.fixed.capture_once());
        if !matches!(self.fixed_result, Some(Ok(()))) {
            return Err(Error::invalid("worker aggregate", "fixed prefix retained"));
        }
        let Some((root, anchor)) = self.fixed.take_validated_pair() else {
            std::process::abort();
        };
        self.fixed_root = Some(root);
        self.fixed_anchor = Some(anchor);
        self.comparison = Some((|| {
            let Some((supplied, _)) = self.pair.as_ref() else {
                std::process::abort();
            };
            let Some(fixed) = self.fixed_anchor.as_ref() else {
                std::process::abort();
            };
            if supplied.anchor.kernel_id != fixed.kernel_id
                || supplied.anchor.root.identity().device != fixed.root.identity().device
            {
                return Err(Error::invalid("worker aggregate", "supplied directory differs"));
            }
            Ok(())
        })());
        if matches!(self.comparison, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::invalid("worker aggregate", "directory comparison retained"))
        }
    }

    /// Moves only the fully validated aggregate/main pair once without IO.
    #[must_use]
    pub fn take_validated_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        if self.transferred || !matches!(self.comparison, Some(Ok(()))) {
            return None;
        }
        let pair = self.pair.take()?;
        self.transferred = true;
        Some(pair)
    }

    /// Disposes successful comparison probes after the actual pair was parked.
    ///
    /// The caller keeps the returned root and main anchor resident before this
    /// boundary. Their native identity and compact comparison Results survive;
    /// no resource claim, descriptor ceiling or failure state is reset.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or untransferred observations. No
    /// failed prefix is disposed and no observation is performed by this call.
    pub fn settle_transferred_once_v1(&mut self) -> std::result::Result<(), ()> {
        if !self.transferred || self.settled || self.pair.is_some()
            || !matches!(self.supplied_result, Some(Ok(())))
            || !matches!(self.flags, Some(Ok(_)))
            || !matches!(self.fixed_result, Some(Ok(())))
            || !matches!(self.comparison, Some(Ok(())))
            || self.failure().is_some()
        {
            return Err(());
        }
        self.settled = true;
        self.supplied = InitialServiceCgroupCaptureV1::default();
        self.fixed = StorageReceivingAggregateCgroupReadbackV1::new();
        drop(self.fixed_root.take());
        drop(self.fixed_anchor.take());
        Ok(())
    }

    /// Borrows the first actual native failure without resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.supplied_result.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| self.flags.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.fixed.failure())
            .or_else(|| self.comparison.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as _))
    }
}
