//! Retains the fixed Storage executor's two initial cgroup anchors.
//!
//! Both descendants use the existing exact child-resolution recipe under the
//! same actually opened hierarchy. Partial roots, children and active-file
//! probes stay resident on failure; paths or DATA do not grant service payment.

use super::{
    CgroupV2Root, Error, InitialCgroupChildV5, InitialServiceCgroupCaptureV1,
    InitialServiceCgroupV1, Result, RetainedCgroupAnchor,
};
use std::os::fd::OwnedFd;

/// Keeps the fixed hierarchy, manager and Storage control-slice opening.
///
/// Empty construction performs no IO. The external actual startup must fund
/// and retain this DATA attempt. The full reached peak is ten descriptors:
/// hierarchy plus its initial probe, two children and six resolution probes.
#[derive(Debug, Default)]
pub struct StorageExecutorInitialCgroupReadbackV1 {
    initial: InitialServiceCgroupCaptureV1,
    root_open: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    root: Option<CgroupV2Root>,
    manager: Option<RetainedCgroupAnchor>,
    control: InitialCgroupChildV5,
    initial_capture: Option<Result<()>>,
    control_capture: Option<Result<()>>,
    capture: Option<Result<()>>,
    closed: Option<Error>,
    entered: bool,
    taken: bool,
    settled: bool,
}

impl StorageExecutorInitialCgroupReadbackV1 {
    /// Creates empty fixed slots without an observation or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts only the fixed hierarchy, child components and active-file names.
    ///
    /// The manager and control child use the same hierarchy. Three distinct
    /// `cgroup.procs` names cover the root and both children; repeated native
    /// probes, parser bytes and result fields create no additional entry.
    /// This passive source-derived count grants no observation or role.
    #[must_use]
    pub fn receiving_namespace_entries_v2() -> usize {
        std::path::Path::new("/sys/fs/cgroup").components().count()
            + InitialServiceCgroupV1::StorageManager.relative().components().count()
            + InitialServiceCgroupV1::StorageControl.relative().components().count()
            + 3
    }

    /// Opens only the compiled hierarchy, then manager and control-slice roles.
    ///
    /// # Errors
    /// Retains the original native result and every reached partial object.
    /// Repeated or interrupted entry is refused without another acquisition.
    pub fn capture_once(&mut self) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| Error::invalid(
                "Storage executor initial cgroups", "already attempted"));
            return Err(Error::invalid(
                "Storage executor initial cgroups", "original failure retained"));
        }
        self.entered = true;
        self.capture = Some(self.capture_inner());
        if matches!(self.capture, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::invalid(
                "Storage executor initial cgroups", "original failure retained"))
        }
    }

    fn capture_inner(&mut self) -> Result<()> {
        self.root_open = Some(rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ));
        let Some(Ok(_)) = self.root_open.as_ref() else {
            return Err(Error::invalid(
                "Storage executor hierarchy", "original open failure retained"));
        };
        let Some(Ok(root)) = self.root_open.take() else {
            return Err(Error::invalid("Storage executor hierarchy", "root absent"));
        };
        self.initial_capture = Some(self.initial.capture_initial(
            root, InitialServiceCgroupV1::StorageManager,
        ));
        if !matches!(self.initial_capture, Some(Ok(()))) {
            return Err(Error::invalid(
                "Storage executor initial manager", "original failure retained"));
        }
        let Some((root, manager)) = self.initial.take_validated_pair() else {
            return Err(Error::invalid("Storage executor hierarchy", "pair incomplete"));
        };
        // Park both actual returned owners before resolving the second child.
        self.root = Some(root);
        self.manager = Some(manager);
        self.control_capture = Some(self.root.as_ref()
            .ok_or_else(|| Error::invalid("Storage executor hierarchy", "root absent"))?
            .anchor.resolve_initial_service_retaining(
                &mut self.control, InitialServiceCgroupV1::StorageControl,
            ));
        if !matches!(self.control_capture, Some(Ok(()))) {
            return Err(Error::invalid(
                "Storage executor initial control", "original failure retained"));
        }
        Ok(())
    }

    /// Transfers the two fully validated anchors without another observation.
    ///
    /// The hierarchy and native probes remain here until the caller parks its
    /// completed normal executor and explicitly settles this positive attempt.
    #[must_use]
    pub fn take_validated_anchors(&mut self) -> Option<(RetainedCgroupAnchor, RetainedCgroupAnchor)> {
        if self.taken || self.settled || self.closed.is_some()
            || !matches!(self.capture, Some(Ok(())))
            || self.manager.is_none() || self.control.anchor.is_none()
        {
            return None;
        }
        self.taken = true;
        Some((self.manager.take()?, self.control.anchor.take()?))
    }

    /// Disposes only the completed hierarchy/probes after its anchors moved.
    ///
    /// # Errors
    /// Refuses incomplete, failed, repeated or untransferred attempts. The
    /// actual caller must park its normal output before positive disposal;
    /// this native DATA operation is not a refund or resource admission port.
    pub fn settle_transferred_once(&mut self) -> std::result::Result<(), ()> {
        if !self.taken || self.settled || self.failure().is_some()
            || !matches!(self.capture, Some(Ok(())))
        {
            return Err(());
        }
        self.settled = true;
        drop(self.root.take());
        self.initial = InitialServiceCgroupCaptureV1::default();
        self.control = InitialCgroupChildV5::default();
        Ok(())
    }

    /// Borrows the first actual kernel or shared-engine failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.root_open { return Some(cause); }
        if let Some(Err(cause)) = &self.initial_capture { return Some(cause); }
        if let Some(Err(cause)) = &self.control_capture { return Some(cause); }
        if let Some(Err(cause)) = &self.capture { return Some(cause); }
        self.closed.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}
