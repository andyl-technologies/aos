//! Retains the fixed initial executor opening under genuine Storage receiving.
//!
//! This empty DATA owner accepts no socket or hierarchy argument. The existing
//! ordinary constructor remains unchanged and the shared Linux engine owns all
//! selected root/child/probe prefixes until normal executor handoff.

use std::path::PathBuf;

use super::{SystemdZfsExecutor, ZfsWorkerError};
use aos_sandbox_linux::cgroup::StorageExecutorInitialCgroupReadbackV1;

const SOCKET: &str = "/run/aos/sandbox-zfs-worker/control.sock";

pub(crate) struct StorageExecutorStartupV1 {
    native: StorageExecutorInitialCgroupReadbackV1,
    observation: Option<Result<(), aos_linux_descriptors::Error>>,
    completed: Option<SystemdZfsExecutor>,
    entered: bool,
    taken: bool,
    closed: Option<ZfsWorkerError>,
}

impl StorageExecutorStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: StorageExecutorInitialCgroupReadbackV1::new(),
            observation: None,
            completed: None,
            entered: false,
            taken: false,
            closed: None,
        }
    }

    /// Includes the actual inline attempt and dominant fixed input carriers.
    ///
    /// This passive bound supplies no payer or fit. The genuine original must
    /// accept it before construction/capture grows any dynamic representation.
    pub(crate) fn receiving_memory_bytes() -> Option<usize> {
        // Fixed paths/probe and native error carriers are independent of any
        // configured journal maximum or future per-request worker allocation.
        std::mem::size_of::<Self>().checked_add(32 * 256)?
            .checked_add(3 * SOCKET.len())
    }

    /// Returns the reached native descriptor peak, including partial prefixes.
    pub(crate) const fn receiving_open_files() -> usize {
        10
    }

    /// Counts actual fixed hierarchy/child components and active-file names.
    pub(crate) fn receiving_metadata_entries() -> usize {
        StorageExecutorInitialCgroupReadbackV1::receiving_namespace_entries_v2()
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), ()> {
        if self.entered || self.taken || self.closed.is_some() {
            self.closed.get_or_insert(ZfsWorkerError::Protocol("initial executor repeated"));
            return Err(());
        }
        self.entered = true;
        self.observation = Some(self.native.capture_once());
        if matches!(self.observation, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    pub(crate) fn take_success(&mut self) -> Option<SystemdZfsExecutor> {
        if !self.entered || self.taken || self.failure().is_some()
            || !matches!(self.observation, Some(Ok(())))
        {
            return None;
        }
        // This compiled normalized literal has the same policy as new(). It is
        // allocated while both completed native anchors remain on this owner.
        let socket_path = PathBuf::from(SOCKET);
        let (systemd_manager_cgroup, worker_parent_cgroup) =
            self.native.take_validated_anchors()?;
        self.taken = true;
        self.completed = Some(SystemdZfsExecutor {
            socket_path,
            systemd_manager_cgroup,
            worker_parent_cgroup,
            fail_stopped: false,
        });
        if self.native.settle_transferred_once().is_err() {
            self.closed.get_or_insert(ZfsWorkerError::Protocol("initial executor incomplete"));
            return None;
        }
        self.completed.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure()
            .or_else(|| self.observation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}
