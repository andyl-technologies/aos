//! Bounded systemd notification transport and complete FD-store inspection.

use std::ffi::OsStr;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use aos_systemd::fd_store::FdStoreInspector;
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, recv, sendmsg_addr, socket_with, socketpair,
};

use super::format::{NetworkNamespaceStoreName, StoreSnapshot, parse_systemd_snapshot};
use super::{BackendMutationError, NetworkNamespaceStoreError, StoreBackend};

const SERVICE_NAME: &str = "aos-netd.service";
const BARRIER_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMD_METHOD_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct SystemdStoreBackend {
    notifier: SystemdNotifier,
    inspector: FdStoreInspector,
}

impl SystemdStoreBackend {
    pub(super) fn from_environment() -> Result<Self, NetworkNamespaceStoreError> {
        Ok(Self {
            notifier: SystemdNotifier::from_environment()?,
            inspector: FdStoreInspector::connect(SERVICE_NAME, SYSTEMD_METHOD_TIMEOUT)
                .map_err(NetworkNamespaceStoreError::Systemd)?,
        })
    }
}

impl StoreBackend for SystemdStoreBackend {
    fn snapshot(&self) -> Result<StoreSnapshot, String> {
        let snapshot = self.inspector.snapshot()?;
        parse_systemd_snapshot(
            snapshot.maximum_entries,
            snapshot.reported_entries,
            snapshot.rows,
        )
        .map_err(|error| error.to_string())
    }

    fn store(
        &self,
        name: &NetworkNamespaceStoreName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), BackendMutationError> {
        let payload = format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str());
        self.notifier
            .notify(payload.as_bytes(), Some(descriptor))
            .map_err(BackendMutationError::NotSent)?;
        self.notifier
            .barrier()
            .map_err(BackendMutationError::Ambiguous)
    }

    fn remove(&self, name: &NetworkNamespaceStoreName) -> Result<(), BackendMutationError> {
        let payload = format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str());
        self.notifier
            .notify(payload.as_bytes(), None)
            .map_err(BackendMutationError::NotSent)?;
        self.notifier
            .barrier()
            .map_err(BackendMutationError::Ambiguous)
    }
}

struct SystemdNotifier {
    socket: OwnedFd,
    address: SocketAddrUnix,
}

impl SystemdNotifier {
    fn from_environment() -> Result<Self, NetworkNamespaceStoreError> {
        let value = std::env::var_os("NOTIFY_SOCKET").ok_or_else(|| {
            NetworkNamespaceStoreError::Systemd("NOTIFY_SOCKET is absent".to_owned())
        })?;
        Self::from_notify_socket(&value)
    }

    fn from_notify_socket(value: &OsStr) -> Result<Self, NetworkNamespaceStoreError> {
        let value = value.to_str().ok_or_else(|| {
            NetworkNamespaceStoreError::Systemd("NOTIFY_SOCKET is not Unicode".to_owned())
        })?;
        if value.is_empty() {
            return Err(NetworkNamespaceStoreError::Systemd(
                "NOTIFY_SOCKET is empty".to_owned(),
            ));
        }
        let address = if let Some(name) = value.strip_prefix('@') {
            if name.is_empty() {
                return Err(NetworkNamespaceStoreError::Systemd(
                    "NOTIFY_SOCKET abstract name is empty".to_owned(),
                ));
            }
            SocketAddrUnix::new_abstract_name(name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .map_err(systemd_io_error)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(systemd_io_error)?;
        set_socket_timeout(&socket, Timeout::Send, Some(BARRIER_TIMEOUT))
            .map_err(systemd_io_error)?;

        Ok(Self { socket, address })
    }

    fn notify(&self, payload: &[u8], descriptor: Option<BorrowedFd<'_>>) -> Result<(), String> {
        let iov = [IoSlice::new(payload)];
        let borrowed = descriptor.into_iter().collect::<Vec<_>>();
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
            return Err("systemd notification ancillary buffer is exhausted".to_owned());
        }
        let written = sendmsg_addr(
            &self.socket,
            &self.address,
            &iov,
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(|error| format!("systemd notification send failed: {error}"))?;
        if written != payload.len() {
            return Err("systemd notification was partially written".to_owned());
        }
        Ok(())
    }

    fn barrier(&self) -> Result<(), String> {
        let (waiter, manager_end) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|error| format!("systemd barrier socketpair failed: {error}"))?;
        set_socket_timeout(&waiter, Timeout::Recv, Some(BARRIER_TIMEOUT))
            .map_err(|error| format!("systemd barrier timeout setup failed: {error}"))?;
        self.notify(b"BARRIER=1", Some(manager_end.as_fd()))?;
        drop(manager_end);

        let mut byte = [0_u8; 1];
        let (received, _) = recv(&waiter, &mut byte, RecvFlags::empty())
            .map_err(|error| format!("systemd barrier wait failed: {error}"))?;
        if received != 0 {
            return Err("systemd barrier descriptor carried data".to_owned());
        }
        Ok(())
    }
}

fn systemd_io_error(error: rustix::io::Errno) -> NetworkNamespaceStoreError {
    NetworkNamespaceStoreError::Systemd(format!("systemd notification socket failed: {error}"))
}
