//! Authenticates each bounded maintenance packet and rejects all ancillary rights.

use super::wire::{MAX_PACKET, invalid};
use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage};
use std::{
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

pub(super) fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let pair = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )?;
    for socket in [&pair.0, &pair.1] {
        net::sockopt::set_socket_passcred(socket, true)?;
        net::sockopt::set_socket_recv_buffer_size(socket, MAX_PACKET * 2)?;
        net::sockopt::set_socket_send_buffer_size(socket, MAX_PACKET * 2)?;
    }
    Ok(pair)
}

pub(super) struct Endpoint {
    socket: OwnedFd,
    peer_uid: u32,
    active: bool,
}

impl Endpoint {
    pub(super) fn descriptor(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }

    pub(super) fn new(socket: OwnedFd, peer_uid: u32) -> io::Result<Self> {
        if net::sockopt::socket_domain(&socket)? != net::AddressFamily::UNIX
            || net::sockopt::socket_type(&socket)? != net::SocketType::SEQPACKET
        {
            return Err(invalid("maintenance requires Unix sequenced packets"));
        }
        net::getpeername(&socket)?;
        net::sockopt::set_socket_passcred(&socket, true)?;
        net::sockopt::set_socket_recv_buffer_size(&socket, MAX_PACKET * 2)?;
        net::sockopt::set_socket_send_buffer_size(&socket, MAX_PACKET * 2)?;
        Ok(Self {
            socket,
            peer_uid,
            active: true,
        })
    }

    fn check(&self) -> io::Result<()> {
        if !self.active {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "maintenance channel faulted",
            ));
        }
        Ok(())
    }

    pub(super) fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.check()?;
        let result = self.receive_packet();
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn receive_packet(&self) -> io::Result<Option<Vec<u8>>> {
        let mut bytes = [0; MAX_PACKET];
        // Own every possible received right until refusal. Draining Rustix's
        // ancillary buffer drops even rights attached to truncated packets.
        let mut space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253), ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let message = match net::recvmsg(
            &self.socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            net::RecvFlags::DONTWAIT | net::RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => return Ok(None),
            result => result?,
        };
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
        if rejected || !credentials.is_some_and(|value| value.uid.as_raw() == self.peer_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "maintenance packet credentials or ancillary data refused",
            ));
        }
        Ok(Some(bytes[..message.bytes].to_vec()))
    }

    pub(super) fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.check()?;
        match net::send(
            &self.socket,
            bytes,
            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
        ) {
            Ok(count) if count == bytes.len() => Ok(()),
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => Err(error.into()),
            result => {
                self.abort();
                Err(match result {
                    Err(error) => error.into(),
                    Ok(_) => invalid("incomplete maintenance packet"),
                })
            }
        }
    }

    pub(super) fn abort(&mut self) {
        self.active = false;
        let _ = net::shutdown(&self.socket, net::Shutdown::Both);
    }
}

/// Faults an incomplete exchange even when its enclosing future is cancelled.
pub(super) struct Exchange<'endpoint> {
    endpoint: &'endpoint mut Endpoint,
    completed: bool,
}

impl<'endpoint> Exchange<'endpoint> {
    pub(super) fn start(endpoint: &'endpoint mut Endpoint) -> Self {
        Self {
            endpoint,
            completed: false,
        }
    }

    pub(super) fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let result = self.endpoint.receive();
        if result.is_err() {
            self.endpoint.abort();
        }
        result
    }

    pub(super) fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.endpoint.send(bytes)
    }

    pub(super) fn complete(&mut self) {
        self.completed = true;
    }

    pub(super) fn refuse(&mut self) {
        self.endpoint.abort();
    }
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.endpoint.abort();
        }
    }
}
