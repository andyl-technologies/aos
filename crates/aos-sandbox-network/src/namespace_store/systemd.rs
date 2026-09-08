//! Bounded systemd notification transport and complete FD-store inspection.

use std::ffi::OsStr;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, recv, sendmsg_addr, socket_with, socketpair,
};

use super::format::{
    NetworkNamespaceStoreName, RawSystemdStoreRow, StoreSnapshot, parse_systemd_snapshot,
};
use super::{BackendMutationError, NetworkNamespaceStoreError, StoreBackend};

const SERVICE_NAME: &str = "aos-netd.service";
const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const BARRIER_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMD_METHOD_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMD_DUMP_BODY_MAX: usize = 4 * 1024 * 1024;

pub(super) struct SystemdStoreBackend {
    notifier: SystemdNotifier,
    inspector: SystemdStoreInspector,
}

impl SystemdStoreBackend {
    pub(super) fn from_environment() -> Result<Self, NetworkNamespaceStoreError> {
        Ok(Self {
            notifier: SystemdNotifier::from_environment()?,
            inspector: SystemdStoreInspector::connect()?,
        })
    }
}

impl StoreBackend for SystemdStoreBackend {
    fn snapshot(&self) -> Result<StoreSnapshot, String> {
        self.inspector.snapshot()
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

enum InspectorRequest {
    Snapshot(mpsc::SyncSender<Result<StoreSnapshot, String>>),
}

pub(super) struct SystemdStoreInspector {
    requests: Option<mpsc::Sender<InspectorRequest>>,
    worker: Option<thread::JoinHandle<()>>,
    operation_timeout: Duration,
}

impl SystemdStoreInspector {
    fn connect() -> Result<Self, NetworkNamespaceStoreError> {
        Self::connect_with_address(None, SYSTEMD_METHOD_TIMEOUT)
    }

    fn connect_with_address(
        bus_address: Option<String>,
        operation_timeout: Duration,
    ) -> Result<Self, NetworkNamespaceStoreError> {
        let (requests, request_receiver) = mpsc::channel();
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("aos-netd-systemd-inspector".to_owned())
            .spawn(move || {
                inspector_worker(
                    request_receiver,
                    startup_sender,
                    bus_address.as_deref(),
                    operation_timeout,
                )
            })
            .map_err(|error| {
                NetworkNamespaceStoreError::Systemd(format!(
                    "systemd inspector worker creation failed: {error}"
                ))
            })?;
        let inspector = Self {
            requests: Some(requests),
            worker: Some(worker),
            operation_timeout,
        };
        startup_receiver
            .recv_timeout(operation_timeout + Duration::from_secs(1))
            .map_err(|_| {
                NetworkNamespaceStoreError::Systemd(
                    "systemd inspector did not complete its bounded connection".to_owned(),
                )
            })?
            .map_err(NetworkNamespaceStoreError::Systemd)?;

        Ok(inspector)
    }

    #[cfg(test)]
    pub(super) fn connect_to_address(
        bus_address: &str,
        operation_timeout: Duration,
    ) -> Result<Self, NetworkNamespaceStoreError> {
        Self::connect_with_address(Some(bus_address.to_owned()), operation_timeout)
    }

    fn snapshot(&self) -> Result<StoreSnapshot, String> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        self.requests
            .as_ref()
            .ok_or_else(|| "systemd inspector is stopped".to_owned())?
            .send(InspectorRequest::Snapshot(reply_sender))
            .map_err(|_| "systemd inspector exited before snapshot".to_owned())?;
        reply_receiver
            .recv_timeout(self.operation_timeout + Duration::from_secs(1))
            .map_err(|error| format!("systemd inspector snapshot deadline failed: {error}"))?
    }
}

impl Drop for SystemdStoreInspector {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn inspector_worker(
    requests: mpsc::Receiver<InspectorRequest>,
    startup: mpsc::SyncSender<Result<(), String>>,
    bus_address: Option<&str>,
    operation_timeout: Duration,
) {
    let result = run_inspector_worker(requests, &startup, bus_address, operation_timeout);
    if let Err(error) = result {
        let _ = startup.send(Err(error));
    }
}

fn run_inspector_worker(
    requests: mpsc::Receiver<InspectorRequest>,
    startup: &mpsc::SyncSender<Result<(), String>>,
    bus_address: Option<&str>,
    operation_timeout: Duration,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("system bus runtime creation failed: {error}"))?;
    let connection = runtime
        .block_on(async {
            tokio::time::timeout(operation_timeout, async {
                // Production pins AOS's packaged Unix system-bus endpoint and
                // never admits DBUS_SYSTEM_BUS_ADDRESS, TCP, or DNS authority.
                let address = bus_address.unwrap_or(SYSTEM_BUS_ADDRESS);
                let builder = zbus::connection::Builder::address(address)?;
                builder.method_timeout(operation_timeout).build().await
            })
            .await
        })
        .map_err(|_| "system bus connection exceeded its deadline".to_owned())?
        .map_err(|error| format!("system bus connection failed: {error}"))?;

    // Connection success is reported only once the cancellable build has
    // completed and this worker owns both its transport and runtime.
    let _ = startup.send(Ok(()));

    for request in requests {
        match request {
            InspectorRequest::Snapshot(reply) => {
                let snapshot = runtime
                    .block_on(async {
                        tokio::time::timeout(operation_timeout, read_systemd_snapshot(&connection))
                            .await
                    })
                    .map_err(|_| "systemd FD-store snapshot exceeded its deadline".to_owned())
                    .and_then(|result| result);
                let _ = reply.send(snapshot);
            }
        }
    }

    Ok(())
}

async fn read_systemd_snapshot(connection: &zbus::Connection) -> Result<StoreSnapshot, String> {
    // The systemd method is unprivileged at the D-Bus vtable, but PID 1 still
    // applies its SELinux `status` check for this unit. Deployment must grant
    // that narrow self-observation; denial is a failed or ambiguous snapshot.
    let manager = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await
    .map_err(|error| format!("systemd manager proxy failed: {error}"))?;
    let dump_reply = manager
        .call_method("DumpUnitFileDescriptorStore", &(SERVICE_NAME,))
        .await
        .map_err(|error| format!("systemd FD-store dump failed: {error}"))?;
    let dump_body = dump_reply.body();
    if dump_body.len() > SYSTEMD_DUMP_BODY_MAX {
        return Err("systemd FD-store dump exceeds the fixed decode bound".to_owned());
    }
    let rows: Vec<RawSystemdStoreRow> = dump_body
        .deserialize()
        .map_err(|error| format!("systemd FD-store dump decode failed: {error}"))?;
    let unit_path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnit", &(SERVICE_NAME,))
        .await
        .map_err(|error| format!("systemd unit lookup failed: {error}"))?;
    let service = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        unit_path,
        SYSTEMD_SERVICE_INTERFACE,
    )
    .await
    .map_err(|error| format!("systemd service proxy failed: {error}"))?;
    let maximum_entries: u32 = service
        .get_property("FileDescriptorStoreMax")
        .await
        .map_err(|error| format!("systemd FD-store capacity read failed: {error}"))?;
    let reported_entries: u32 = service
        .get_property("NFileDescriptorStore")
        .await
        .map_err(|error| format!("systemd FD-store count read failed: {error}"))?;

    parse_systemd_snapshot(maximum_entries, reported_entries, rows)
        .map_err(|error| error.to_string())
}

fn systemd_io_error(error: rustix::io::Errno) -> NetworkNamespaceStoreError {
    NetworkNamespaceStoreError::Systemd(format!("systemd notification socket failed: {error}"))
}
