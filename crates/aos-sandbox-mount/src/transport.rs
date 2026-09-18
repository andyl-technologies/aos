//! Systemd-activated bounded `SOCK_SEQPACKET` ingress for mountd.
//!
//! The socket's kernel-supplied peer pidfd pins the connection establisher.
//! Delegating the connected descriptor delegates this legacy channel; packet
//! writers are not independently authenticated by its `SCM_RIGHTS` carrier.

use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::{MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PeerCredentials};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_acceptconn, socket_type};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendFlags, SocketFlags,
    SocketType, accept_with, recvmsg, send,
};

use crate::{MountError, Result};

const MAXIMUM_PACKET_DESCRIPTORS: usize = aos_sandbox_protocol::MAXIMUM_PACKET_DESCRIPTORS;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns the sole validated systemd-activated mount-broker listener.
#[derive(Debug)]
pub struct ActivatedSeqpacketListener {
    fd: OwnedFd,
}

impl ActivatedSeqpacketListener {
    /// Validates and adopts one already-listening Unix sequence-packet socket.
    ///
    /// # Errors
    ///
    /// Returns an error unless the descriptor is a listening `SOCK_SEQPACKET`.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        if socket_type(&fd).map_err(transport_error)? != SocketType::SEQPACKET
            || !socket_acceptconn(&fd).map_err(transport_error)?
        {
            return Err(protocol_field("activated listener"));
        }
        let flags = fcntl_getfd(&fd).map_err(transport_error)?;
        fcntl_setfd(&fd, flags | FdFlags::CLOEXEC).map_err(transport_error)?;
        Ok(Self { fd })
    }

    /// Accepts one close-on-exec peer and reads kernel credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when acceptance, socket timeout configuration, or
    /// kernel-pinned connection identity retrieval fails.
    pub fn accept(&self) -> Result<MountConnection> {
        let fd = accept_with(&self.fd, SocketFlags::CLOEXEC).map_err(transport_error)?;
        set_socket_timeout(&fd, Timeout::Recv, Some(CONNECTION_IO_TIMEOUT))
            .map_err(transport_error)?;
        set_socket_timeout(&fd, Timeout::Send, Some(CONNECTION_IO_TIMEOUT))
            .map_err(transport_error)?;
        let peer = ConnectionPeerIdentity::from_socket(fd.as_fd()).map_err(|_| {
            MountError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch,
            )
        })?;
        Ok(MountConnection { fd, peer })
    }
}

/// Owns one accepted, one-request mount-broker connection.
#[derive(Debug)]
pub struct MountConnection {
    fd: OwnedFd,
    peer: ConnectionPeerIdentity,
}

/// Owns one packet and every close-on-exec descriptor received beside it.
#[derive(Debug)]
pub struct ReceivedPacket {
    /// Bounded packet payload.
    pub bytes: Vec<u8>,
    /// Ancillary descriptors in their exact `SCM_RIGHTS` order.
    pub descriptors: Vec<OwnedFd>,
}

impl MountConnection {
    /// Returns credentials read from the connected kernel socket.
    #[must_use]
    pub const fn peer(&self) -> PeerCredentials {
        let credentials = self.peer.credentials();
        PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        }
    }

    /// Borrows the pinned connection establisher, not a later packet writer.
    #[must_use]
    pub const fn peer_identity(&self) -> &ConnectionPeerIdentity {
        &self.peer
    }

    /// Receives exactly one bounded packet and adopts its ancillary descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error for EOF, truncation, an invalid caller ceiling,
    /// unsupported ancillary messages, too many descriptors, or receive
    /// failure. Adopted descriptors close on every rejection path.
    pub fn receive(&self, maximum_bytes: usize) -> Result<ReceivedPacket> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_REQUEST_BYTES {
            return Err(protocol_field("invalid receive packet ceiling"));
        }
        let mut bytes = vec![0; maximum_bytes];
        let mut iov = [IoSliceMut::new(&mut bytes)];
        let mut control_space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAXIMUM_PACKET_DESCRIPTORS))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let message = recvmsg(
            &self.fd,
            &mut iov,
            &mut control,
            RecvFlags::TRUNC | RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(transport_error)?;
        if message.bytes == 0 {
            return Err(protocol_field("empty packet"));
        }
        if message.bytes > maximum_bytes
            || message
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return Err(protocol_field("truncated packet"));
        }
        let mut descriptors = Vec::new();
        for ancillary in control.drain() {
            match ancillary {
                RecvAncillaryMessage::ScmRights(received) => descriptors.extend(received),
                _ => return Err(protocol_field("unsupported ancillary message")),
            }
        }
        if descriptors.len() > MAXIMUM_PACKET_DESCRIPTORS {
            return Err(protocol_field("too many ancillary descriptors"));
        }
        bytes.truncate(message.bytes);
        Ok(ReceivedPacket { bytes, descriptors })
    }

    /// Sends exactly one bounded response packet.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid length, send failure, or a short write.
    pub fn send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RESPONSE_BYTES as usize {
            return Err(protocol_field("invalid response packet length"));
        }
        let written = send(&self.fd, bytes, SendFlags::NOSIGNAL).map_err(transport_error)?;
        if written != bytes.len() {
            return Err(MountError::State(
                "mount response packet was partially written".to_owned(),
            ));
        }
        Ok(())
    }
}

fn protocol_field(field: &'static str) -> MountError {
    MountError::Protocol(aos_sandbox_protocol::ProtocolValidationError::InvalidField(
        field,
    ))
}

fn transport_error(error: rustix::io::Errno) -> MountError {
    MountError::State(format!("mount packet transport failed: {error}"))
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
    fn packet_transport_preserves_boundaries_credentials_and_response() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.sock");
        let (listener, client) = listener(&path);
        send(&client, b"request", SendFlags::empty()).unwrap();
        let connection = listener.accept().unwrap();
        let packet = connection.receive(MAXIMUM_REQUEST_BYTES).unwrap();
        assert_eq!(packet.bytes, b"request");
        assert!(packet.descriptors.is_empty());
        assert_eq!(connection.peer().uid, rustix::process::getuid().as_raw());
        connection.send(b"response").unwrap();
        let mut response = [0; 8];
        let (received, _) = rustix::net::recv(&client, &mut response, RecvFlags::empty()).unwrap();
        assert_eq!(received, response.len());
        assert_eq!(&response, b"response");
    }

    #[test]
    fn ancillary_descriptors_are_adopted_close_on_exec() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.sock");
        let (listener, client) = listener(&path);
        let borrowed = [client.as_fd()];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&borrowed)));
        let iov = [std::io::IoSlice::new(b"request")];
        sendmsg(&client, &iov, &mut control, SendFlags::empty()).unwrap();
        let connection = listener.accept().unwrap();
        let packet = connection.receive(MAXIMUM_REQUEST_BYTES).unwrap();
        assert_eq!(packet.descriptors.len(), 1);
        assert!(
            fcntl_getfd(&packet.descriptors[0])
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn caller_ceiling_rejects_truncated_packets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.sock");
        let (listener, client) = listener(&path);
        send(&client, b"too long", SendFlags::empty()).unwrap();
        let connection = listener.accept().unwrap();
        assert!(connection.receive(3).is_err());
    }
}
