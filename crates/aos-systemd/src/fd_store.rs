//! Bounded, read-only inspection of one systemd service's descriptor store.
//!
//! The manager dump returns metadata, not descriptors. Callers must validate
//! the complete row set against their own typed custody state before treating
//! any observation as authority.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const SYSTEMD_DUMP_BODY_MAX: usize = 4 * 1024 * 1024;

/// One metadata row from systemd's `DumpUnitFileDescriptorStore` method.
///
/// The path is diagnostic; it is not a stable descriptor identity. In
/// particular, the tuple does not report a kernel-unique mount ID.
pub type RawFdStoreRow = (String, u32, u32, u32, u64, u32, u32, String, u32);

/// Reports one bounded manager dump and its separate service-property reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdStoreSnapshot {
    /// Configured maximum entries for this service.
    pub maximum_entries: u32,
    /// Manager-reported current entry count.
    pub reported_entries: u32,
    /// Complete decoded dump rows, subject to caller validation.
    pub rows: Vec<RawFdStoreRow>,
}

enum InspectorRequest {
    Snapshot(mpsc::SyncSender<Result<FdStoreSnapshot, String>>),
}

/// Owns a bounded system-bus connection on a cancellable worker thread.
pub struct FdStoreInspector {
    requests: Option<mpsc::Sender<InspectorRequest>>,
    worker: Option<thread::JoinHandle<()>>,
    operation_timeout: Duration,
}

impl FdStoreInspector {
    /// Connects to AOS's fixed local system bus for one fixed service unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker, bus connection, or bounded handshake
    /// fails. The unit name must be supplied by trusted application code.
    pub fn connect(unit_name: &'static str, operation_timeout: Duration) -> Result<Self, String> {
        Self::connect_with_address(unit_name, None, operation_timeout)
    }

    fn connect_with_address(
        unit_name: &'static str,
        bus_address: Option<String>,
        operation_timeout: Duration,
    ) -> Result<Self, String> {
        let (requests, receiver) = mpsc::channel();
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("aos-systemd-fd-store-inspector".to_owned())
            .spawn(move || {
                inspector_worker(
                    receiver,
                    startup_sender,
                    unit_name,
                    bus_address.as_deref(),
                    operation_timeout,
                );
            })
            .map_err(|error| format!("systemd inspector worker creation failed: {error}"))?;
        let inspector = Self {
            requests: Some(requests),
            worker: Some(worker),
            operation_timeout,
        };
        startup_receiver
            .recv_timeout(operation_timeout.saturating_add(Duration::from_secs(1)))
            .map_err(|_| {
                "systemd inspector did not complete its bounded connection".to_owned()
            })??;

        Ok(inspector)
    }

    /// Reads the manager dump, configured capacity, and reported count.
    ///
    /// # Errors
    ///
    /// Returns an error on timeout, transport or SELinux denial, an oversized
    /// dump, or invalid D-Bus framing. It does not validate descriptor names.
    pub fn snapshot(&self) -> Result<FdStoreSnapshot, String> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        self.requests
            .as_ref()
            .ok_or_else(|| "systemd inspector is stopped".to_owned())?
            .send(InspectorRequest::Snapshot(reply_sender))
            .map_err(|_| "systemd inspector exited before snapshot".to_owned())?;
        reply_receiver
            .recv_timeout(
                self.operation_timeout
                    .saturating_add(Duration::from_secs(1)),
            )
            .map_err(|error| format!("systemd inspector snapshot deadline failed: {error}"))?
    }
}

impl Drop for FdStoreInspector {
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
    unit_name: &'static str,
    bus_address: Option<&str>,
    operation_timeout: Duration,
) {
    let result = run_inspector_worker(
        requests,
        &startup,
        unit_name,
        bus_address,
        operation_timeout,
    );
    if let Err(error) = result {
        let _ = startup.send(Err(error));
    }
}

fn run_inspector_worker(
    requests: mpsc::Receiver<InspectorRequest>,
    startup: &mpsc::SyncSender<Result<(), String>>,
    unit_name: &'static str,
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
                // Production never accepts an environment-selected or remote bus.
                let address = bus_address.unwrap_or(SYSTEM_BUS_ADDRESS);
                let builder = zbus::connection::Builder::address(address)?;
                builder.method_timeout(operation_timeout).build().await
            })
            .await
        })
        .map_err(|_| "system bus connection exceeded its deadline".to_owned())?
        .map_err(|error| format!("system bus connection failed: {error}"))?;

    let _ = startup.send(Ok(()));
    for request in requests {
        match request {
            InspectorRequest::Snapshot(reply) => {
                let snapshot = runtime
                    .block_on(async {
                        tokio::time::timeout(
                            operation_timeout,
                            read_systemd_snapshot(&connection, unit_name),
                        )
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

async fn read_systemd_snapshot(
    connection: &zbus::Connection,
    unit_name: &str,
) -> Result<FdStoreSnapshot, String> {
    // The method is unprivileged at the D-Bus vtable, but PID 1 requires
    // SELinux `status` permission for the addressed service.
    let manager = zbus::Proxy::new(
        connection,
        SYSTEMD_DESTINATION,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await
    .map_err(|error| format!("systemd manager proxy failed: {error}"))?;
    let dump_reply = manager
        .call_method("DumpUnitFileDescriptorStore", &(unit_name,))
        .await
        .map_err(|error| format!("systemd FD-store dump failed: {error}"))?;
    let dump_body = dump_reply.body();
    if dump_body.len() > SYSTEMD_DUMP_BODY_MAX {
        return Err("systemd FD-store dump exceeds the fixed decode bound".to_owned());
    }
    let rows: Vec<RawFdStoreRow> = dump_body
        .deserialize()
        .map_err(|error| format!("systemd FD-store dump decode failed: {error}"))?;
    let unit_path: zbus::zvariant::OwnedObjectPath =
        manager
            .call("GetUnit", &(unit_name,))
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
    let maximum_entries = service
        .get_property("FileDescriptorStoreMax")
        .await
        .map_err(|error| format!("systemd FD-store capacity read failed: {error}"))?;
    let reported_entries = service
        .get_property("NFileDescriptorStore")
        .await
        .map_err(|error| format!("systemd FD-store count read failed: {error}"))?;

    Ok(FdStoreSnapshot {
        maximum_entries,
        reported_entries,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::FdStoreInspector;

    #[test]
    fn missing_bus_fails_without_a_caller_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let address = format!(
            "unix:path={}",
            directory.path().join("missing-system-bus.sock").display()
        );

        let error = match FdStoreInspector::connect_with_address(
            "test.service",
            Some(address),
            Duration::from_secs(1),
        ) {
            Ok(_) => panic!("missing system bus unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.contains("system bus connection failed"));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "This deadline regression observes duration but never persists it."
    )]
    fn stalled_handshake_is_cancelled_before_worker_join() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("stalled-system-bus.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let (eof_sender, eof_receiver) = mpsc::sync_channel(1);
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = [0_u8; 256];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        eof_sender.send(()).unwrap();
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => panic!("stalled peer did not observe EOF: {error}"),
                }
            }
        });
        let address = format!("unix:path={}", socket_path.display());
        let started = Instant::now();

        let error = match FdStoreInspector::connect_with_address(
            "test.service",
            Some(address),
            Duration::from_millis(100),
        ) {
            Ok(_) => panic!("stalled system bus handshake unexpectedly completed"),
            Err(error) => error,
        };
        assert!(error.contains("connection exceeded its deadline"));
        assert!(started.elapsed() < Duration::from_secs(2));
        eof_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        peer.join().unwrap();
    }
}
