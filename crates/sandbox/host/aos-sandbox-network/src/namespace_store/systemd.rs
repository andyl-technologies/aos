//! Bounded systemd notification transport and complete FD-store inspection.

pub(super) mod notifier_original;

use std::ffi::OsStr;
use std::sync::Arc;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use aos_systemd_client::fd_store::FdStoreInspector;
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

enum NotifierOwnerV4 {
    Ordinary(SystemdNotifier),
    Selected(Arc<SystemdNotifier>),
}

impl std::ops::Deref for NotifierOwnerV4 {
    type Target = SystemdNotifier;
    fn deref(&self) -> &Self::Target {
        match self { Self::Ordinary(notifier) => notifier, Self::Selected(notifier) => notifier }
    }
}

pub(super) struct SystemdStoreBackend {
    notifier: NotifierOwnerV4,
    inspector: Option<FdStoreInspector>,
}

impl SystemdStoreBackend {
    pub(super) fn from_environment() -> Result<Self, NetworkNamespaceStoreError> {
        Ok(Self {
            notifier: NotifierOwnerV4::Ordinary(SystemdNotifier::from_environment()?),
            inspector: Some(FdStoreInspector::connect(SERVICE_NAME, SYSTEMD_METHOD_TIMEOUT)
                .map_err(NetworkNamespaceStoreError::Systemd)?),
        })
    }
    pub(super) fn selected_from_notifier_v4(notifier: Arc<SystemdNotifier>) -> Self {
        Self { notifier: NotifierOwnerV4::Selected(notifier), inspector: None }
    }

    pub(super) fn is_selected_v4(&self) -> bool {
        matches!(self.notifier, NotifierOwnerV4::Selected(_))
    }

    pub(super) fn selected_notifier_v4(&self) -> Option<Arc<SystemdNotifier>> {
        match &self.notifier {
            NotifierOwnerV4::Selected(notifier) => Some(Arc::clone(notifier)),
            NotifierOwnerV4::Ordinary(_) => None,
        }
    }

}

impl StoreBackend for SystemdStoreBackend {
    fn snapshot(&self) -> Result<StoreSnapshot, String> {
        let inspector = self.inspector.as_ref().ok_or_else(||
            "fixed Network Store requires its retained receiving interval".to_owned())?;
        let snapshot = inspector.snapshot()?;
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

pub(super) struct SystemdNotifier {
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
        notifier_original::open_notifier_local(value)
    }

    fn notify(&self, payload: &[u8], descriptor: Option<BorrowedFd<'_>>) -> Result<(), String> {
        notifier_original::notify_engine(
            self, payload, descriptor, &mut notifier_original::NotifyAttemptV4::default(), None,
        )
    }

    fn barrier(&self) -> Result<(), String> {
        notifier_original::barrier_engine(
            self, &mut notifier_original::BarrierAttemptV4::default(), None, None,
        )
    }

}

fn systemd_io_error(error: rustix::io::Errno) -> NetworkNamespaceStoreError {
    NetworkNamespaceStoreError::Systemd(format!("systemd notification socket failed: {error}"))
}
