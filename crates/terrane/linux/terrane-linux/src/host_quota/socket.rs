//! Owns bounded descriptor-free Linux Unix seqpacket connections.

use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) struct PacketSocket(OwnedFd);

/// Supplies monotonic native ticks only to the bounded socket receive loop.
trait ReceiveClock {
    fn monotonic(&self) -> Instant;
}

/// Binds host-only transport deadlines independently of optional Tokio support.
struct NativeReceiveClock;

impl ReceiveClock for NativeReceiveClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "This private native clock binding is the injection boundary for host socket deadlines."
    )]
    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

impl PacketSocket {
    fn socket() -> io::Result<Self> {
        // SAFETY: socket has no pointer arguments and returns a new descriptor.
        let raw =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly created descriptor with unique ownership.
        let socket = Self(unsafe { OwnedFd::from_raw_fd(raw) });
        socket.set_timeout()?;
        Ok(socket)
    }

    fn address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: all-zero is a valid initialized sockaddr_un before filling it.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid quota socket path",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
            *destination = *source as libc::c_char;
        }
        Ok((address, size_of::<libc::sockaddr_un>() as libc::socklen_t))
    }

    pub(super) fn connect(path: &Path) -> io::Result<Self> {
        let socket = Self::socket()?;
        let (address, length) = Self::address(path)?;
        // SAFETY: address and length describe a live initialized Unix address.
        if unsafe {
            libc::connect(
                socket.0.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                length,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    pub(super) fn bind(path: &Path) -> io::Result<Self> {
        let socket = Self::socket()?;
        let (address, length) = Self::address(path)?;
        // SAFETY: address and length describe a live initialized Unix address.
        if unsafe {
            libc::bind(
                socket.0.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                length,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket is a live bound seqpacket descriptor.
        if unsafe { libc::listen(socket.0.as_raw_fd(), 16) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    pub(super) fn accept(&self) -> io::Result<Self> {
        // SAFETY: no peer-address output is requested; returned descriptor is new.
        let raw = unsafe {
            libc::accept4(
                self.0.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly accepted descriptor with unique ownership.
        let socket = Self(unsafe { OwnedFd::from_raw_fd(raw) });
        socket.set_timeout()?;
        Ok(socket)
    }

    fn set_timeout(&self) -> io::Result<()> {
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            // SAFETY: timeout and its size match the socket option ABI.
            if unsafe {
                libc::setsockopt(
                    self.0.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    &timeout as *const _ as *const libc::c_void,
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn peer_uid(&self) -> io::Result<u32> {
        // SAFETY: zero is a valid initial representation of ucred.
        let mut credentials: libc::ucred = unsafe { zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: writable credentials and length match SO_PEERCRED's ABI.
        if unsafe {
            libc::getsockopt(
                self.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credentials as *mut _ as *mut libc::c_void,
                &mut length,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of::<libc::ucred>() {
            return Err(io::Error::other("invalid peer credentials"));
        }
        Ok(credentials.uid)
    }

    pub(super) fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > 16384 {
            return Err(io::Error::other("quota packet too large"));
        }
        // SAFETY: packet is readable for its length; send retains no pointer.
        let result = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        if result as usize != packet.len() {
            return Err(io::Error::other("partial quota packet"));
        }
        Ok(())
    }

    pub(super) fn receive(&self) -> io::Result<Vec<u8>> {
        self.receive_until(NativeReceiveClock.monotonic() + Duration::from_secs(5))
    }

    fn receive_until(&self, deadline: Instant) -> io::Result<Vec<u8>> {
        self.receive_until_with_clock(deadline, &NativeReceiveClock)
    }

    fn receive_until_with_clock(
        &self,
        deadline: Instant,
        clock: &impl ReceiveClock,
    ) -> io::Result<Vec<u8>> {
        loop {
            let remaining = deadline.saturating_duration_since(clock.monotonic());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "quota receive deadline expired",
                ));
            }

            // Stop/continue can interrupt timed socket reads without a signal
            // handler. Keep this connection and its correlation state, while
            // charging every retry against the original monotonic deadline.
            let bounded = remaining.min(Duration::from_secs(5));
            let micros = bounded.as_micros().max(1);
            let timeout = libc::timeval {
                tv_sec: (micros / 1_000_000) as libc::time_t,
                tv_usec: (micros % 1_000_000) as libc::suseconds_t,
            };
            // SAFETY: timeout is initialized ABI storage, retained for the call;
            // its duration is positive and bounded by five seconds.
            if unsafe {
                libc::setsockopt(
                    self.0.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout as *const _ as *const libc::c_void,
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
            match self.receive_packet() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "quota receive deadline expired",
                    ));
                }
                result => return result,
            }
        }
    }

    // Each attempt starts with fresh packet/control buffers and a new msghdr:
    // recvmsg output lengths and flags must never become the next call's input.
    fn receive_packet(&self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0u8; 16384];
        // Space for Linux's maximum SCM_RIGHTS payload. Every received descriptor
        // must be closed even when the packet will be rejected.
        let mut control = [0usize; 256];
        let mut vector = libc::iovec {
            iov_base: packet.as_mut_ptr().cast(),
            iov_len: packet.len(),
        };
        // SAFETY: zero is a valid empty msghdr; all used pointers are assigned below.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        // SAFETY: message references writable, aligned buffers for the whole call.
        let length =
            unsafe { libc::recvmsg(self.0.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if length == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: recvmsg initialized the control chain bounded by msg_controllen.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let base = libc::CMSG_LEN(0) as usize;
                    let count = (*header).cmsg_len.saturating_sub(base) / size_of::<libc::c_int>();
                    let descriptors = libc::CMSG_DATA(header).cast::<libc::c_int>();
                    for index in 0..count {
                        drop(OwnedFd::from_raw_fd(*descriptors.add(index)));
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if length == 0
            || message.msg_controllen != 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated, empty or ancillary quota packet",
            ));
        }
        packet.truncate(length as usize);
        Ok(packet)
    }
}

#[cfg(test)]
#[path = "socket_signal_tests.rs"]
mod signal_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Creates two retained kernel seqpacket endpoints for socket tests.
    ///
    /// # Panics
    /// Panics if the kernel cannot create the isolated socket pair.
    pub(super) fn pair() -> (PacketSocket, PacketSocket) {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors supplies the two writable integer slots required
        // by socketpair; success transfers two independent descriptors.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: successful socketpair returned two new, distinct descriptors.
        unsafe {
            (
                PacketSocket(OwnedFd::from_raw_fd(descriptors[0])),
                PacketSocket(OwnedFd::from_raw_fd(descriptors[1])),
            )
        }
    }

    #[test]
    fn kernel_peer_identity_is_not_a_packet_assertion() {
        let (sender, receiver) = pair();
        assert_eq!(
            receiver.peer_uid().expect("kernel credentials"),
            rustix::process::geteuid().as_raw()
        );
        sender.send(b"claimed uid zero").expect("send assertion");
        assert_eq!(
            receiver.receive().expect("receive assertion"),
            b"claimed uid zero"
        );
        assert_eq!(
            receiver.peer_uid().expect("unchanged kernel credentials"),
            rustix::process::geteuid().as_raw()
        );
    }

    #[test]
    fn oversized_native_packet_is_rejected_after_receive_truncation() {
        let (sender, receiver) = pair();
        let bytes = vec![1u8; 16385];
        // SAFETY: bytes remains readable and sender is a live socket.
        assert_eq!(
            unsafe {
                libc::send(
                    sender.0.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            bytes.len() as isize
        );
        assert!(receiver.receive().is_err());
    }

    #[test]
    fn descriptor_ancillary_is_rejected_without_returning_custody() {
        let (sender, receiver) = pair();
        let file = std::fs::File::open("/dev/null").expect("descriptor fixture");
        let mut byte = [1u8];
        let mut vector = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 8];
        // SAFETY: zero initializes unused msghdr members, pointers below refer
        // to aligned buffers retained until sendmsg returns.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        // SAFETY: one c_int fits in the control buffer with required alignment.
        unsafe {
            message.msg_controllen = libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
            *libc::CMSG_DATA(header).cast::<libc::c_int>() = file.as_raw_fd();
            assert_eq!(
                libc::sendmsg(sender.0.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                1
            );
        }
        assert!(receiver.receive().is_err());
        assert!(
            file.metadata().is_ok(),
            "sending retains the original descriptor"
        );
    }
}
