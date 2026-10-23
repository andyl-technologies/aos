//! Keeps the actual wait authority distinct for generic and admitted Sources.
// SPDX-License-Identifier: Apache-2.0

use std::process::{Child, ExitStatus};

#[derive(Debug)]
pub(crate) enum OwnedNodeChild {
    Ordinary(Child),
    #[cfg(target_os = "linux")]
    Source(crucible_host_resources::host_services::process_birth::AuthenticatedSourceChild),
    // Exists only after the actual owner moves into its preborn recipient.
    #[cfg(target_os = "linux")]
    Transferred,
}

impl OwnedNodeChild {
    /// Moves the real wait authority out only during terminal abandonment.
    #[cfg(target_os = "linux")]
    pub(super) fn take_for_abandonment(&mut self) -> Self {
        std::mem::replace(self, Self::Transferred)
    }

    /// Reports an already completed physical owner transfer, never a reap.
    #[cfg(target_os = "linux")]
    pub(super) fn transferred(&self) -> bool {
        matches!(self, Self::Transferred)
    }

    pub(super) fn id(&self) -> u32 {
        match self {
            Self::Ordinary(child) => child.id(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.id(),
            #[cfg(target_os = "linux")]
            Self::Transferred => unreachable!("the child owner was consumed by terminal Drop"),
        }
    }

    pub(super) fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self {
            Self::Ordinary(child) => child.try_wait(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.try_wait(),
            #[cfg(target_os = "linux")]
            Self::Transferred => Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
        }
    }

    pub(super) fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Ordinary(child) => child.kill(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.kill(),
            #[cfg(target_os = "linux")]
            Self::Transferred => Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
        }
    }

    pub(super) fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Ordinary(child) => child.wait(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.wait(),
            #[cfg(target_os = "linux")]
            Self::Transferred => Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
        }
    }
}

impl crate::shutdown::OwnedChildWait for OwnedNodeChild {
    fn try_wait_owned(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.try_wait()
    }
}
