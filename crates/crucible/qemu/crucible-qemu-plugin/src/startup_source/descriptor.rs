//! Distinguishes owned receive custody from native process-lifetime role views.
//!
//! Only the authenticated native setup borrow constructs a borrowed role. Such
//! views never close, duplicate or transfer the native owner's descriptor.
// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};

/// Retains ordinary ownership or a view of an authenticated native-owned role.
#[derive(Debug)]
pub(crate) enum SetupDescriptor {
    Owned(OwnedFd),
    Native(BorrowedFd<'static>),
}

impl From<OwnedFd> for SetupDescriptor {
    fn from(descriptor: OwnedFd) -> Self {
        Self::Owned(descriptor)
    }
}

impl AsFd for SetupDescriptor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Owned(descriptor) => descriptor.as_fd(),
            Self::Native(descriptor) => *descriptor,
        }
    }
}

impl AsRawFd for SetupDescriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

impl SetupDescriptor {
    /// Leaves uncertain custody with its actual process-lifetime owner.
    pub(crate) fn retain_until_process_exit(self) {
        if let Self::Owned(descriptor) = self {
            let _retained = descriptor.into_raw_fd();
        }
    }

    /// Returns a uniquely owned descriptor only for the ordinary receive route.
    pub(crate) fn into_owned(self) -> Option<OwnedFd> {
        match self {
            Self::Owned(descriptor) => Some(descriptor),
            Self::Native(_) => None,
        }
    }

    pub(crate) fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }
}
