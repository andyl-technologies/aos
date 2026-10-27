//! Keeps actual child-process identity and ancillary descriptor custody.

use super::wire::{MAX_PACKET, invalid};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{
        self, RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage,
    },
    process::{Pid, PidfdFlags},
};
use std::{
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    process::Child,
    sync::atomic::{AtomicBool, Ordering},
};

/// Retains the actual unreused process incarnation of a supervised worker.
///
/// Construction uses an original child handle and a kernel pidfd. Public
/// identifiers, socket peer UID alone and caller-provided pidfds cannot create
/// this value. The caller retains responsibility for terminating and reaping
/// the child. This is process custody, not worker sandbox qualification.
pub struct WorkerIdentity {
    pid: Pid,
    uid: u32,
    pidfd: OwnedFd,
}

impl WorkerIdentity {
    /// Pins a still-running original child before its handle can be reaped.
    ///
    /// The expected UID is checked against kernel credentials on every request.
    /// This method does not change the child's identity or install confinement.
    ///
    /// # Errors
    /// Refuses an exited child, an invalid process identifier, missing kernel
    /// pidfd support and native process-observation failures.
    pub fn from_child(child: &mut Child, expected_uid: u32) -> io::Result<Self> {
        if child.try_wait()?.is_some() {
            return Err(invalid("worker already exited"));
        }
        let raw = i32::try_from(child.id()).map_err(|_| invalid("worker PID overflow"))?;
        let pid = Pid::from_raw(raw).ok_or_else(|| invalid("invalid worker PID"))?;
        let pidfd = rustix::process::pidfd_open(pid, PidfdFlags::empty())?;
        if child.try_wait()?.is_some() {
            return Err(invalid("worker exited during incarnation binding"));
        }
        let identity = Self {
            pid,
            uid: expected_uid,
            pidfd,
        };
        identity.check_current()?;
        Ok(identity)
    }

    /// Checks that the original kernel process incarnation has not exited.
    ///
    /// # Errors
    /// Refuses exited processes and native pidfd observation failures.
    pub fn check_current(&self) -> io::Result<()> {
        let mut descriptors = [PollFd::new(&self.pidfd, PollFlags::IN)];
        if poll(&mut descriptors, Some(&Timespec::default()))? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "original worker process exited",
            ));
        }
        Ok(())
    }
}

pub(super) struct Endpoint {
    socket: OwnedFd,
    peer: WorkerIdentity,
    active: AtomicBool,
}

impl Endpoint {
    pub(super) fn new(socket: OwnedFd, peer: WorkerIdentity) -> io::Result<Self> {
        if net::sockopt::socket_type(&socket)? != net::SocketType::SEQPACKET
            || net::sockopt::socket_domain(&socket)? != net::AddressFamily::UNIX
            || peer.uid == rustix::process::geteuid().as_raw()
        {
            return Err(invalid(
                "backing channel requires distinct Unix process roles",
            ));
        }
        net::getpeername(&socket)?;
        net::sockopt::set_socket_passcred(&socket, true)?;
        net::sockopt::set_socket_recv_buffer_size(&socket, MAX_PACKET * 2)?;
        net::sockopt::set_socket_send_buffer_size(&socket, MAX_PACKET * 2)?;
        peer.check_current()?;
        Ok(Self {
            socket,
            peer,
            active: AtomicBool::new(true),
        })
    }

    pub(super) fn check_current(&self) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker channel faulted",
            ));
        }
        self.peer.check_current()
    }

    pub(super) fn abort(&self) {
        self.active.store(false, Ordering::Release);
        let _ = net::shutdown(&self.socket, net::Shutdown::Both);
    }

    pub(super) fn receive(&self) -> io::Result<Vec<u8>> {
        self.check_current()?;
        let mut bytes = [0; MAX_PACKET];
        // Reserve the complete Linux SCM_RIGHTS maximum. Rustix drops received
        // rights, including unconsumed messages, before any refusal escapes.
        let mut space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253), ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let message = net::recvmsg(
            &self.socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            net::RecvFlags::DONTWAIT | net::RecvFlags::CMSG_CLOEXEC,
        )?;
        let mut credentials = None;
        let mut rejected = message.bytes == 0
            || message
                .flags
                .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC);
        for field in ancillary.drain() {
            match field {
                RecvAncillaryMessage::ScmCredentials(value) if credentials.is_none() => {
                    credentials = Some(value);
                }
                _ => rejected = true,
            }
        }
        let authenticated = credentials
            .is_some_and(|value| value.pid == self.peer.pid && value.uid.as_raw() == self.peer.uid);
        if rejected || !authenticated {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid worker packet or process credentials",
            ));
        }
        self.check_current()?;
        Ok(bytes[..message.bytes].to_vec())
    }

    pub(super) fn send(&self, bytes: &[u8], backing: BorrowedFd<'_>) -> io::Result<()> {
        self.check_current()?;
        let rights = [backing];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
            return Err(invalid("backing ancillary bound"));
        }
        let count = net::sendmsg(
            &self.socket,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
        )?;
        if count != bytes.len() {
            return Err(invalid("incomplete backing record"));
        }
        Ok(())
    }
}

impl AsFd for Endpoint {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}
