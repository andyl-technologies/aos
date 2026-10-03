//! Retains one genuine accepted socket without competing transport I/O.
//!
//! Kernel observation and same-original shutdown use the captured descriptor;
//! no cookie, historical record or caller-selected raw descriptor reconstructs it.

use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketAddrAny, SocketType, getpeername, getsockname, sockopt};

/// Preserves the actual kernel cause without exposing descriptor or address data.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalPublicSocketErrorV1 {
    /// A kernel descriptor or observation syscall failed.
    #[error("original public socket syscall failed")]
    Physical(#[from] rustix::io::Errno),
    /// The accepted descriptor is not a connected supported stream socket.
    #[error("original public socket profile is invalid")]
    Profile,
    /// Current kernel observations no longer match the same original socket.
    #[error("original public socket changed or ended")]
    Changed,
}

pub(super) struct OriginalPublicSocketV1 {
    descriptor: OwnedFd,
    cookie: NonZeroU64,
    family: AddressFamily,
    local: SocketAddrAny,
    remote: SocketAddrAny,
}

impl OriginalPublicSocketV1 {
    pub(super) fn capture(descriptor: BorrowedFd<'_>) -> Result<Self, OriginalPublicSocketErrorV1> {
        let family = sockopt::socket_domain(descriptor)?;
        if !matches!(
            family,
            AddressFamily::INET | AddressFamily::INET6 | AddressFamily::UNIX,
        )
            || sockopt::socket_type(descriptor)? != SocketType::STREAM
        {
            return Err(OriginalPublicSocketErrorV1::Profile);
        }
        let cookie = NonZeroU64::new(sockopt::socket_cookie(descriptor)?)
            .ok_or(OriginalPublicSocketErrorV1::Profile)?;
        let duplicate = rustix::io::fcntl_dupfd_cloexec(descriptor, 64)?;
        let retained = Self {
            local: getsockname(&duplicate)?,
            remote: getpeername(&duplicate)?.ok_or(OriginalPublicSocketErrorV1::Profile)?,
            descriptor: duplicate,
            cookie,
            family,
        };

        retained.recheck()?;
        if sockopt::socket_cookie(descriptor)? != cookie.get() {
            return Err(OriginalPublicSocketErrorV1::Changed);
        }
        Ok(retained)
    }

    pub(super) fn recheck(&self) -> Result<(), OriginalPublicSocketErrorV1> {
        let descriptor = self.descriptor.as_fd();
        if sockopt::socket_cookie(descriptor)? != self.cookie.get()
            || sockopt::socket_domain(descriptor)? != self.family
            || sockopt::socket_type(descriptor)? != SocketType::STREAM
            || getsockname(descriptor)? != self.local
            || getpeername(descriptor)?.as_ref() != Some(&self.remote)
        {
            return Err(OriginalPublicSocketErrorV1::Changed);
        }

        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, PollFlags::RDHUP)];
        let zero_timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
        poll(&mut descriptors, Some(&zero_timeout))?;
        if descriptors[0].revents().intersects(
            PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL,
        ) {
            return Err(OriginalPublicSocketErrorV1::Changed);
        }
        Ok(())
    }

    pub(super) const fn cookie(&self) -> NonZeroU64 {
        self.cookie
    }

    /// Ends the actual socket without erasing its retained observation descriptor.
    pub(super) fn end_original(&self) -> Result<(), rustix::io::Errno> {
        rustix::net::shutdown(self.descriptor.as_fd(), rustix::net::Shutdown::Both)
    }
}
