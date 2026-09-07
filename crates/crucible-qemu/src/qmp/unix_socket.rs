//! Unix-domain socket connection helpers for typed QMP clients.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::{QmpClient, QmpError, QmpIoTimeoutPolicy, QmpJobPollPolicy};
use crate::QemuQmpVmStateControlChannel;

pub(super) fn send_bytes_with_descriptor(
    stream: &UnixStream,
    bytes: &[u8],
    descriptor: BorrowedFd<'_>,
) -> io::Result<usize> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QMP descriptor transfer requires at least one request byte",
        ));
    }

    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: bytes.len(),
    };
    let mut control = [empty_control_header(); DESCRIPTOR_CONTROL_HEADERS];
    let message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: DESCRIPTOR_CONTROL_BYTES,
        msg_flags: 0,
    };

    // SAFETY: `message` owns cmsghdr-aligned storage sized with CMSG_SPACE.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QMP descriptor transfer has no ancillary header",
        ));
    }
    // SAFETY: `header` points inside `control`; the storage has room for one RawFd.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
        std::ptr::write(
            libc::CMSG_DATA(header).cast::<RawFd>(),
            descriptor.as_raw_fd(),
        );
    }

    loop {
        // SAFETY: `message` references live request and ancillary buffers for this call.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if sent >= 0 {
            return usize::try_from(sent)
                .map_err(|_| io::Error::other("QMP sendmsg returned a negative success length"));
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

const DESCRIPTOR_CONTROL_BYTES: usize = {
    // `CMSG_SPACE(sizeof(int))` is constant on supported Unix targets, while
    // libc exposes it as an unsafe const function rather than a Rust constant.
    // SAFETY: the payload length is the size of exactly one RawFd.
    unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) as usize }
};
const DESCRIPTOR_CONTROL_HEADERS: usize =
    DESCRIPTOR_CONTROL_BYTES.div_ceil(std::mem::size_of::<libc::cmsghdr>());

const fn empty_control_header() -> libc::cmsghdr {
    libc::cmsghdr {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
    }
}

impl QmpClient<UnixStream> {
    /// Connects to a QMP Unix socket and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened, when the QMP
    /// greeting cannot be read or decoded, or when capability negotiation fails.
    pub fn connect_unix_socket(path: impl AsRef<Path>) -> Result<Self, QmpError> {
        let stream = crate::unix_socket_path::connect(path.as_ref())
            .map_err(|source| QmpError::from_io("connect QMP Unix socket", source))?;
        Self::connect(stream)
    }

    /// Connects to a QMP Unix socket with explicit snapshot and I/O policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened, when the QMP
    /// greeting cannot be read or decoded, when capability negotiation fails, or
    /// when either supplied policy is invalid.
    pub fn connect_unix_socket_with_policies(
        path: impl AsRef<Path>,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        let stream = crate::unix_socket_path::connect(path.as_ref())
            .map_err(|source| QmpError::from_io("connect QMP Unix socket", source))?;
        Self::connect_with_policies(stream, job_poll_policy, io_timeout_policy)
    }
}

impl QemuQmpVmStateControlChannel<UnixStream> {
    /// Connects a checkpoint-tagged VMState control channel to a QMP Unix socket.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened or QMP
    /// connection setup fails.
    pub fn connect_unix_socket(path: impl AsRef<Path>) -> Result<Self, QmpError> {
        QmpClient::connect_unix_socket(path).map(Self::new)
    }

    /// Connects a VMState control channel with explicit snapshot and I/O policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the Unix socket cannot be opened, QMP connection
    /// setup fails, or either supplied policy is invalid.
    pub fn connect_unix_socket_with_policies(
        path: impl AsRef<Path>,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        QmpClient::connect_unix_socket_with_policies(path, job_poll_policy, io_timeout_policy)
            .map(Self::new)
    }
}
