//! Systemd-activated bounded `SOCK_SEQPACKET` ingress.
//!
//! Hostd never binds a caller-selected path. It adopts one socket supplied by
//! PID 1, validates its type and listening state, accepts close-on-exec peers,
//! pins the connection establisher with `SO_PEERCRED` and `SO_PEERPIDFD`, receives
//! bounded packets and their close-on-exec ancillary descriptors, and emits
//! bounded packets.
//! A delegated connection retains its establisher identity; this carrier does
//! not authenticate individual packet writers.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::session::MAXIMUM_HOST_QUERY_PACKET_BYTES;
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, PeerCredentials};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_acceptconn, socket_type};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType, accept_with, recvmsg, send, sendmsg,
};

use crate::{HostError, Result};

const MAXIMUM_PACKET_DESCRIPTORS: usize = aos_sandbox_protocol::MAXIMUM_PACKET_DESCRIPTORS;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Returns an error when acceptance, socket timeout configuration, or
    /// kernel-pinned connection identity retrieval fails.
    pub fn accept(&self) -> Result<HostConnection> {
        let fd = accept_with(&self.fd, SocketFlags::CLOEXEC).map_err(transport_error)?;
        set_socket_timeout(&fd, Timeout::Recv, Some(CONNECTION_IO_TIMEOUT))
            .map_err(transport_error)?;
        set_socket_timeout(&fd, Timeout::Send, Some(CONNECTION_IO_TIMEOUT))
            .map_err(transport_error)?;
        let peer = ConnectionPeerIdentity::from_socket(fd.as_fd()).map_err(|_| {
            HostError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::PeerCredentialMismatch,
            )
        })?;
        Ok(HostConnection { fd, peer })
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

impl HostConnection {
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
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_HOST_QUERY_PACKET_BYTES {
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

    /// Sends the closed payload-scope descriptor pair in one atomic packet.
    ///
    /// The service must check signed query authority and fresh scope immediately
    /// before calling this method. These descriptors retain kernel objects; they
    /// are not kernel-attenuated read-only capabilities. The receiver authenticates
    /// the kernel record subject separately from the activated listener's creator.
    /// A full send queue fails immediately: waiting or retrying here would reuse
    /// authority observations taken before the wait.
    pub(crate) fn send_payload_scope(
        &self,
        bytes: &[u8],
        descriptors: [BorrowedFd<'_>; 2],
    ) -> Result<()> {
        self.send_scope_descriptors(bytes, &descriptors)
    }

    /// Sends the closed RootMount scope table after fresh authority verification.
    pub(crate) fn send_mount_scope(
        &self,
        bytes: &[u8],
        descriptors: [BorrowedFd<'_>; 5],
    ) -> Result<()> {
        self.send_scope_descriptors(bytes, &descriptors)
    }

    fn send_scope_descriptors(&self, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RESPONSE_BYTES as usize {
            return Err(protocol_field("invalid payload-scope response length"));
        }

        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
            return Err(protocol_field("payload-scope ancillary capacity"));
        }

        let written = sendmsg(
            &self.fd,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        )
        .map_err(transport_error)?;
        if written != bytes.len() {
            return Err(protocol_field("partial payload-scope response"));
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
        let packet = connection
            .receive(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES)
            .unwrap();
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
    fn ancillary_descriptors_are_adopted_in_packet_order() {
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
        let packet = connection
            .receive(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES)
            .unwrap();
        assert_eq!(packet.bytes, b"request");
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
        let path = directory.path().join("host.sock");
        let (listener, client) = listener(&path);
        send(&client, b"too long", SendFlags::empty()).unwrap();
        let connection = listener.accept().unwrap();
        assert!(connection.receive(3).is_err());
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "Elapsed host time detects a blocking test send, never enters runtime state."
    )]
    fn saturated_payload_scope_send_fails_without_waiting_or_queuing_descriptors() {
        let directory = tempfile::tempdir().unwrap();
        let (listener, client) = listener(&directory.path().join("full-send.sock"));
        let connection = listener.accept().unwrap();
        rustix::net::sockopt::set_socket_send_buffer_size(&connection.fd, 4096).unwrap();

        // Fill with minimum-size records so the descriptor response cannot fit
        // merely because it is smaller than the record that reached EAGAIN.
        let mut queued = 0;
        for _ in 0..4096 {
            match send(
                &connection.fd,
                b"q",
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            ) {
                Ok(1) => queued += 1,
                Err(rustix::io::Errno::AGAIN) => break,
                outcome => panic!("unexpected queue-fill result: {outcome:?}"),
            }
        }
        assert!((1..4096).contains(&queued), "send queue was not saturated");
        let started = std::time::Instant::now();
        let result = connection.send_payload_scope(b"scope", [client.as_fd(), listener.as_fd()]);
        assert!(result.is_err());
        // The accepted socket retains its five-second blocking send timeout.
        // This method must instead use per-call DONTWAIT, without changing the
        // descriptor's shared status flags or retrying after authority expires.
        assert!(started.elapsed() < CONNECTION_IO_TIMEOUT - Duration::from_secs(1));

        for _ in 0..queued {
            let mut bytes = [0; 16];
            let mut iov = [IoSliceMut::new(&mut bytes)];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let message = recvmsg(
                &client,
                &mut iov,
                &mut control,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            assert_eq!(message.bytes, 1);
            assert!(
                !message
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            );
            assert!(control.drain().next().is_none());
            assert_eq!(bytes[0], b'q');
        }
        let mut remaining = [0; 16];
        assert_eq!(
            rustix::net::recv(&client, &mut remaining, RecvFlags::DONTWAIT),
            Err(rustix::io::Errno::AGAIN)
        );
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
