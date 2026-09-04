//! Systemd-activated bounded `SOCK_SEQPACKET` ingress.
//!
//! Hostd never binds a caller-selected path. It adopts one socket supplied by
//! PID 1, validates its type and listening state, accepts close-on-exec peers,
//! obtains credentials with `SO_PEERCRED`, receives exactly one bounded packet,
//! rejects and closes all ancillary descriptors, and emits one bounded packet.

use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use aos_sandbox_protocol::{MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PeerCredentials};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{socket_acceptconn, socket_peercred, socket_type};
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketFlags, SocketType, accept_with,
    recvmsg, send,
};

use crate::{HostError, Result};

const MAXIMUM_UNEXPECTED_DESCRIPTORS: usize = 8;

/// Owns the sole validated systemd-activated host broker listener.
#[derive(Debug)]
pub struct ActivatedSeqpacketListener {
    fd: OwnedFd,
}

impl ActivatedSeqpacketListener {
    /// Validates and adopts one already-listening Unix sequence-packet socket.
    ///
    /// # Errors
    ///
    /// Returns an error unless `fd` is a listening `SOCK_SEQPACKET`. The
    /// descriptor is made close-on-exec before it crosses this boundary.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        if socket_type(&fd).map_err(transport_error)? != SocketType::SEQPACKET
            || !socket_acceptconn(&fd).map_err(transport_error)?
        {
            return Err(HostError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::InvalidField("activated listener"),
            ));
        }
        let flags = fcntl_getfd(&fd).map_err(transport_error)?;
        fcntl_setfd(&fd, flags | FdFlags::CLOEXEC).map_err(transport_error)?;
        Ok(Self { fd })
    }

    /// Accepts one peer with close-on-exec descriptor ownership.
    ///
    /// # Errors
    ///
    /// Returns an error when `accept4` or `SO_PEERCRED` fails, or when the
    /// kernel reports a peer PID that cannot fit the protocol representation.
    pub fn accept(&self) -> Result<HostConnection> {
        let fd = accept_with(&self.fd, SocketFlags::CLOEXEC).map_err(transport_error)?;
        let credentials = socket_peercred(&fd).map_err(transport_error)?;
        let pid = u32::try_from(credentials.pid.as_raw_nonzero().get())
            .map_err(|_| HostError::Worker("peer PID does not fit u32".to_owned()))?;
        Ok(HostConnection {
            fd,
            peer: PeerCredentials {
                uid: credentials.uid.as_raw(),
                gid: credentials.gid.as_raw(),
                pid: Some(pid),
            },
        })
    }

    /// Borrows the activated listener for event-loop registration.
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Owns one accepted, one-request host broker connection.
#[derive(Debug)]
pub struct HostConnection {
    fd: OwnedFd,
    peer: PeerCredentials,
}

impl HostConnection {
    /// Returns credentials read from the connected kernel socket.
    #[must_use]
    pub const fn peer(&self) -> PeerCredentials {
        self.peer
    }

    /// Receives exactly one bounded request packet with no descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for EOF, payload/control truncation, an overlong
    /// packet, any ancillary message, or a receive failure. Received
    /// `SCM_RIGHTS` descriptors are owned by rustix and closed on every path.
    pub fn receive(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; MAXIMUM_REQUEST_BYTES];
        let mut iov = [IoSliceMut::new(&mut bytes)];
        let mut control_space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAXIMUM_UNEXPECTED_DESCRIPTORS))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let message = recvmsg(
            &self.fd,
            &mut iov,
            &mut control,
            RecvFlags::TRUNC | RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(transport_error)?;
        let has_ancillary = control.drain().next().is_some();
        if message.bytes == 0 {
            return Err(protocol_field("empty packet"));
        }
        if message.bytes > MAXIMUM_REQUEST_BYTES
            || message
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return Err(protocol_field("truncated packet"));
        }
        if has_ancillary {
            return Err(protocol_field("unexpected ancillary descriptors"));
        }
        bytes.truncate(message.bytes);
        Ok(bytes)
    }

    /// Sends exactly one bounded response packet.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/overlong response, send failure, or a
    /// kernel short write, which is never accepted as a split packet.
    pub fn send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RESPONSE_BYTES as usize {
            return Err(protocol_field("invalid response packet length"));
        }
        let written = send(&self.fd, bytes, SendFlags::NOSIGNAL).map_err(transport_error)?;
        if written != bytes.len() {
            return Err(HostError::State(
                "sequence-packet response was partially written".to_owned(),
            ));
        }
        Ok(())
    }
}

fn protocol_field(field: &'static str) -> HostError {
    HostError::Protocol(aos_sandbox_protocol::ProtocolValidationError::InvalidField(
        field,
    ))
}

fn transport_error(error: rustix::io::Errno) -> HostError {
    HostError::State(format!("host packet transport failed: {error}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::fd::AsFd as _;

    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SocketAddrUnix, bind, connect,
        listen, sendmsg, socket_with,
    };

    use super::*;

    fn listener(path: &std::path::Path) -> (ActivatedSeqpacketListener, OwnedFd) {
        let server = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let address = SocketAddrUnix::new(path).unwrap();
        bind(&server, &address).unwrap();
        listen(&server, 4).unwrap();
        let listener = ActivatedSeqpacketListener::from_owned(server).unwrap();

        let client = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        connect(&client, &address).unwrap();
        (listener, client)
    }

    #[test]
    fn activated_listener_round_trips_one_packet_and_kernel_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.sock");
        let (listener, client) = listener(&path);
        send(&client, b"request", SendFlags::empty()).unwrap();
        let connection = listener.accept().unwrap();
        assert_eq!(connection.receive().unwrap(), b"request");
        assert_eq!(connection.peer().uid, rustix::process::getuid().as_raw());
        connection.send(b"response").unwrap();
        let mut response = [0; 8];
        let (received, _) = rustix::net::recv(&client, &mut response, RecvFlags::empty()).unwrap();
        assert_eq!(received, response.len());
        assert_eq!(&response, b"response");
    }

    #[test]
    fn ancillary_descriptors_are_rejected_and_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.sock");
        let (listener, client) = listener(&path);
        let borrowed = [client.as_fd()];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&borrowed)));
        let iov = [std::io::IoSlice::new(b"request")];
        sendmsg(&client, &iov, &mut control, SendFlags::empty()).unwrap();
        let connection = listener.accept().unwrap();
        assert!(connection.receive().is_err());
    }

    #[test]
    fn stream_and_unlistening_sockets_are_rejected() {
        let stream = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert!(ActivatedSeqpacketListener::from_owned(stream).is_err());
        let packet = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert!(ActivatedSeqpacketListener::from_owned(packet).is_err());
    }
}
