//! Keeps the actual wait authority distinct for generic and admitted Sources.
// SPDX-License-Identifier: Apache-2.0

use std::process::{Child, ExitStatus};

#[derive(Debug)]
pub(crate) enum OwnedNodeChild {
    Ordinary(Child),
    #[cfg(target_os = "linux")]
    Source(crucible_host_resources::host_services::process_birth::AuthenticatedSourceChild),
}

impl OwnedNodeChild {
    pub(super) fn id(&self) -> u32 {
        match self {
            Self::Ordinary(child) => child.id(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.id(),
        }
    }

    pub(super) fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self {
            Self::Ordinary(child) => child.try_wait(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.try_wait(),
        }
    }

    pub(super) fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Ordinary(child) => child.kill(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.kill(),
        }
    }

    pub(super) fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Ordinary(child) => child.wait(),
            #[cfg(target_os = "linux")]
            Self::Source(child) => child.wait(),
        }
    }
}

impl crate::shutdown::OwnedChildWait for OwnedNodeChild {
    fn try_wait_owned(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.try_wait()
    }
}
