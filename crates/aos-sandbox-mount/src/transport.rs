//! Systemd-activated bounded `SOCK_SEQPACKET` ingress for mountd.

use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::time::Duration;

use aos_sandbox_protocol::{MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, PeerCredentials};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt::{
    Timeout, set_socket_timeout, socket_acceptconn, socket_peercred, socket_type,
};
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketFlags, SocketType, accept_with,
    recvmsg, send,
};

use crate::{MountError, Result};

const MAXIMUM_UNEXPECTED_DESCRIPTORS: usize = 8;
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
    /// Returns an error when accept, socket timeout, credential retrieval, or
    /// PID conversion fails.
    pub fn accept(&self) -> Result<MountConnection> {
        let fd = accept_with(&self.fd, SocketFlags::CLOEXEC).map_err(transport_error)?;
        set_socket_timeout(&fd, Timeout::Recv, Some(CONNECTION_IO_TIMEOUT))
            .map_err(transport_error)?;
        set_socket_timeout(&fd, Timeout::Send, Some(CONNECTION_IO_TIMEOUT))
            .map_err(transport_error)?;
        let credentials = socket_peercred(&fd).map_err(transport_error)?;
        let pid = u32::try_from(credentials.pid.as_raw_nonzero().get())
            .map_err(|_| MountError::State("mount peer PID does not fit u32".to_owned()))?;
        Ok(MountConnection {
            fd,
            peer: PeerCredentials {
                uid: credentials.uid.as_raw(),
                gid: credentials.gid.as_raw(),
                pid: Some(pid),
            },
        })
    }
}

/// Owns one accepted, one-request mount-broker connection.
#[derive(Debug)]
pub struct MountConnection {
    fd: OwnedFd,
    peer: PeerCredentials,
}

impl MountConnection {
    /// Returns credentials read from the connected kernel socket.
    #[must_use]
    pub const fn peer(&self) -> PeerCredentials {
        self.peer
    }

    /// Receives exactly one bounded packet and rejects all ancillary data.
    ///
    /// # Errors
    ///
    /// Returns an error for EOF, truncation, overlength, ancillary messages,
    /// or a receive failure. Any received `SCM_RIGHTS` FDs are closed.
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
