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
    MountCoverage(mpsc::SyncSender<FdStoreCoverageObservationV1>),
}

#[derive(Debug, thiserror::Error)]
enum SnapshotReadErrorV1 {
    #[error("{operation}: {source}")]
    Bus {
        operation: &'static str,
        #[source]
        source: zbus::Error,
    },
    #[error("systemd FD-store dump failed; its original error is resident")]
    ResidentDump,
    #[error("{0}")]
    Refused(&'static str),
}

impl SnapshotReadErrorV1 {
    fn bus(operation: &'static str, source: zbus::Error) -> Self {
        Self::Bus { operation, source }
    }
}

enum SnapshotReadStorageV1<'resident> {
    Legacy,
    Retained {
        dump: &'resident mut Option<Result<zbus::Message, zbus::Error>>,
        parts: &'resident mut SnapshotPartsV1,
    },
}

#[derive(Clone, Copy)]
enum SnapshotReadModeV1 {
    Legacy,
    Retained,
}

enum SnapshotReadFailureV1 {
    Legacy(String),
    Retained(SnapshotReadErrorV1),
}

impl SnapshotReadModeV1 {
    // Legacy allocates its original String while the query's proxies and
    // Message still live. Retained keeps the actual typed cause instead.
    fn bus(self, operation: &'static str, cause: zbus::Error) -> SnapshotReadFailureV1 {
        match self {
            Self::Legacy => SnapshotReadFailureV1::Legacy(format!("{operation}: {cause}")),
            Self::Retained => SnapshotReadFailureV1::Retained(
                SnapshotReadErrorV1::bus(operation, cause),
            ),
        }
    }

    fn refused(self, message: &'static str) -> SnapshotReadFailureV1 {
        match self {
            Self::Legacy => SnapshotReadFailureV1::Legacy(message.to_owned()),
            Self::Retained => SnapshotReadFailureV1::Retained(SnapshotReadErrorV1::Refused(message)),
        }
    }
}

enum SnapshotDumpV1<'resident> {
    Local(zbus::Message),
    Resident(&'resident zbus::Message),
}

impl SnapshotDumpV1<'_> {
    fn message(&self) -> &zbus::Message {
        match self {
            Self::Local(message) => message,
            Self::Resident(message) => message,
        }
    }
}

/// Retains a fixed Mount observation and its actual first error or later debt.
///
/// The complete dump, unique-PID-1 proxies and typed failed results remain
/// owned even after timeout or failed postcheck. Successful metadata is DATA,
/// not descriptor ownership, a currentness lease or permission to allocate.
/// The existing bus/library/thread constructor prefixes are not covered by
/// this returned custody, and opaque library allocations are not funded here.
pub struct FdStoreCoverageObservationV1 {
    original: Option<crate::Result<crate::client::ServicePropertyBookendV1<'static>>>,
    dump: Option<Result<zbus::Message, zbus::Error>>,
    snapshot: Option<Result<FdStoreSnapshot, SnapshotReadErrorV1>>,
    parts: SnapshotPartsV1,
    final_bookend: Option<crate::Result<()>>,
    timeout: Option<tokio::time::error::Elapsed>,
}

#[derive(Default)]
struct SnapshotPartsV1 {
    rows: Option<Vec<RawFdStoreRow>>,
    maximum_entries: Option<u32>,
    reported_entries: Option<u32>,
}

impl FdStoreCoverageObservationV1 {
    fn pending() -> Self {
        Self {
            original: None,
            dump: None,
            snapshot: None,
            parts: SnapshotPartsV1::default(),
            final_bookend: None,
            timeout: None,
        }
    }

    /// Borrows the complete snapshot only after the original bookend succeeds.
    ///
    /// # Errors
    /// Refuses a pending, failed, timed-out or changed observation. The short
    /// redacted failure is not owning authority; actual causes stay resident.
    pub fn snapshot(&self) -> Result<&FdStoreSnapshot, FdStoreCoverageFailureV1> {
        if self.timeout.is_some()
            || !matches!(self.original, Some(Ok(_)))
            || !matches!(self.dump, Some(Ok(_)))
            || !matches!(self.final_bookend, Some(Ok(())))
        {
            return Err(FdStoreCoverageFailureV1);
        }
        match self.snapshot.as_ref() {
            Some(Ok(snapshot)) => Ok(snapshot),
            _ => Err(FdStoreCoverageFailureV1),
        }
    }

    /// Borrows the fixed original invocation for independent sample comparison.
    ///
    /// This coordinate is observation DATA, never a service or peer factory.
    #[must_use]
    pub fn invocation(&self) -> Option<&[u8]> {
        match self.original.as_ref() {
            Some(Ok(original)) => Some(original.invocation()),
            _ => None,
        }
    }

    /// Borrows the unique manager name for same-owner sample comparison DATA.
    #[must_use]
    pub fn manager_owner(&self) -> Option<&str> {
        match self.original.as_ref() {
            Some(Ok(original)) => Some(original.destination()),
            _ => None,
        }
    }

    /// Borrows the first actual typed cause without taking or cloning it.
    ///
    /// Capture/read failures precede later deadline/bookend debt. A missing
    /// cause never proves success; `snapshot` also checks complete disposition.
    #[must_use]
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.original.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.dump.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.snapshot.as_ref() {
            return Some(cause);
        }
        if let Some(cause) = self.timeout.as_ref() {
            return Some(cause);
        }
        self.final_bookend
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    /// Borrows independent later PID1 debt without replacing the first cause.
    #[must_use]
    pub fn final_bookend_cause(&self) -> Option<&crate::Error> {
        self.final_bookend
            .as_ref()
            .and_then(|result| result.as_ref().err())
    }
}

/// Reports a negative borrowed observation without detaching its owned cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("fixed Mount FD-store coverage observation failed or is incomplete")]
pub struct FdStoreCoverageFailureV1;

/// Retains an actual worker-channel send/receive failure, not a ready token.
#[derive(Debug, thiserror::Error)]
#[error("fixed Mount FD-store observation channel failed: {cause}")]
pub struct FdStoreCoverageTransportErrorV1 {
    #[source]
    cause: Box<dyn std::error::Error + Send + Sync>,
}

impl FdStoreCoverageTransportErrorV1 {
    fn retain(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            cause: Box::new(cause),
        }
    }
}

/// Owns a bounded system-bus connection on a cancellable worker thread.
pub struct FdStoreInspector {
    requests: Option<mpsc::Sender<InspectorRequest>>,
    worker: Option<thread::JoinHandle<()>>,
    operation_timeout: Duration,
}

impl FdStoreInspector {
    /// Connects the existing inspector solely to the fixed Mount unit.
    ///
    /// This chooses no caller path, PID, role or manager destination. Its
    /// selected snapshot uses the same connection, worker and dump decoder.
    ///
    /// # Errors
    /// Returns the unchanged inspector construction/handshake errors. Those
    /// lower pre-return prefixes remain outside returned observation custody.
    pub fn connect_mount_git_coverage_v1(operation_timeout: Duration) -> Result<Self, String> {
        Self::connect("aos-sandbox-mountd.service", operation_timeout)
    }

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

    /// Returns the whole fixed Mount observation, including failed originals.
    ///
    /// The existing inspector worker remains owned. A failed returned
    /// observation must be parked before the consumer's independent checks;
    /// neither cancellation nor error produces descriptor or release authority.
    ///
    /// # Errors
    /// Retains an actual worker channel failure or bounded receive timeout.
    /// Bus/decode/deadline/bookend failures are owned in the returned observation.
    pub fn snapshot_mount_git_coverage_v1(
        &self,
    ) -> Result<FdStoreCoverageObservationV1, FdStoreCoverageTransportErrorV1> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let requests = self.requests.as_ref().ok_or_else(|| {
            FdStoreCoverageTransportErrorV1::retain(FdStoreCoverageFailureV1)
        })?;
        requests
            .send(InspectorRequest::MountCoverage(sender))
            .map_err(FdStoreCoverageTransportErrorV1::retain)?;
        receiver
            .recv_timeout(self.operation_timeout.saturating_add(Duration::from_secs(1)))
            .map_err(FdStoreCoverageTransportErrorV1::retain)
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
    let mut failed_mount_delivery = None;
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
            InspectorRequest::MountCoverage(reply) => {
                // This original reservoir outlives the timed future, so a
                // cancellation cannot discard a returned dump or first cause.
                let mut observation = FdStoreCoverageObservationV1::pending();
                if failed_mount_delivery.is_some() {
                    observation.snapshot = Some(Err(SnapshotReadErrorV1::Refused(
                        "original Mount observation delivery failed",
                    )));
                } else {
                    let result = runtime.block_on(async {
                        tokio::time::timeout(
                            operation_timeout,
                            read_mount_coverage_snapshot(&connection, &mut observation),
                        )
                        .await
                    });
                    if let Err(cause) = result {
                        observation.timeout = Some(cause);
                    }
                }
                if let Err(cause) = reply.send(observation) {
                    // A cancelled receiver cannot discard the actual returned
                    // dump/proxies/errors. The same worker retains them until
                    // whole-inspector disposal; no subsequent read revives it.
                    if failed_mount_delivery.is_none() {
                        failed_mount_delivery = Some(cause);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn read_systemd_snapshot(
    connection: &zbus::Connection,
    unit_name: &str,
) -> Result<FdStoreSnapshot, String> {
    read_systemd_snapshot_from_original(
        connection, unit_name, SYSTEMD_DESTINATION, None, SnapshotReadStorageV1::Legacy,
    ).await.map_err(|cause| match cause {
        SnapshotReadFailureV1::Legacy(cause) => cause,
        // The closed Legacy recipe emits only Legacy failures.
        SnapshotReadFailureV1::Retained(cause) => cause.to_string(),
    })
}

async fn read_mount_coverage_snapshot(
    connection: &zbus::Connection,
    observation: &mut FdStoreCoverageObservationV1,
) {
    observation.original = Some(crate::client::capture_mount_fd_store_bookend_v1(connection).await);
    let original = match observation.original.as_ref() {
        Some(Ok(original)) => original,
        _ => return,
    };
    observation.snapshot = Some(
        read_systemd_snapshot_from_original(
            connection,
            "aos-sandbox-mountd.service",
            original.destination(),
            Some(original.unit_path()),
            SnapshotReadStorageV1::Retained {
                dump: &mut observation.dump,
                parts: &mut observation.parts,
            },
        )
        .await.map_err(|cause| match cause {
            SnapshotReadFailureV1::Retained(cause) => cause,
            // The closed Retained recipe emits only Retained failures.
            SnapshotReadFailureV1::Legacy(_) => SnapshotReadErrorV1::Refused(
                "fixed Mount snapshot used an ordinary disposition",
            ),
        }),
    );
    // The complete owning dump/read result is resident before postchecks.
    observation.final_bookend = Some(original.finish().await);
}

async fn read_systemd_snapshot_from_original(
    connection: &zbus::Connection,
    unit_name: &str,
    destination: &str,
    expected_path: Option<&zbus::zvariant::OwnedObjectPath>,
    storage: SnapshotReadStorageV1<'_>,
) -> Result<FdStoreSnapshot, SnapshotReadFailureV1> {
    let (mode, mut dump, mut parts) = match storage {
        SnapshotReadStorageV1::Legacy => (SnapshotReadModeV1::Legacy, None, None),
        SnapshotReadStorageV1::Retained { dump, parts } => (
            SnapshotReadModeV1::Retained, Some(dump), Some(parts),
        ),
    };

    // The method is unprivileged at the D-Bus vtable, but PID 1 requires
    // SELinux `status` permission for the addressed service.
    let manager = zbus::Proxy::new(
        connection,
        destination,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .await
    .map_err(|cause| mode.bus("systemd manager proxy failed", cause))?;
    let returned_dump = manager
        .call_method("DumpUnitFileDescriptorStore", &(unit_name,))
        .await;
    let dump_reply = match dump.as_mut() {
        Some(resident) => {
            **resident = Some(returned_dump);
            match resident.as_ref() {
                Some(Ok(reply)) => SnapshotDumpV1::Resident(reply),
                _ => return Err(SnapshotReadFailureV1::Retained(SnapshotReadErrorV1::ResidentDump)),
            }
        }
        None => SnapshotDumpV1::Local(returned_dump
            .map_err(|cause| mode.bus("systemd FD-store dump failed", cause))?),
    };
    let dump_body = dump_reply.message().body();
    if dump_body.len() > SYSTEMD_DUMP_BODY_MAX {
        return Err(mode.refused("systemd FD-store dump exceeds the fixed decode bound"));
    }
    #[cfg(unix)]
    if expected_path.is_some() && !dump_body.data().fds().is_empty() {
        return Err(mode.refused("fixed Mount FD-store metadata carried descriptors"));
    }
    #[cfg(not(unix))]
    if expected_path.is_some() {
        return Err(mode.refused("fixed Mount FD-store coverage requires Unix transport"));
    }
    let rows: Vec<RawFdStoreRow> = dump_body
        .deserialize()
        .map_err(|cause| mode.bus("systemd FD-store dump decode failed", cause))?;
    let mut local_rows = Some(rows);
    if let Some(resident) = parts.as_mut() {
        resident.rows = local_rows.take();
    }
    let unit_path: zbus::zvariant::OwnedObjectPath =
        manager
            .call("GetUnit", &(unit_name,))
            .await
            .map_err(|cause| mode.bus("systemd unit lookup failed", cause))?;
    if expected_path.is_some_and(|original| original != &unit_path) {
        return Err(mode.refused("original Mount unit path changed"));
    }
    let service = zbus::Proxy::new(
        connection,
        destination.to_owned(),
        unit_path,
        SYSTEMD_SERVICE_INTERFACE,
    )
    .await
    .map_err(|cause| mode.bus("systemd service proxy failed", cause))?;
    let maximum_entries = service
        .get_property("FileDescriptorStoreMax")
        .await
        .map_err(|cause| mode.bus("systemd FD-store capacity read failed", cause))?;
    if let Some(resident) = parts.as_mut() {
        resident.maximum_entries = Some(maximum_entries);
    }
    let reported_entries = service
        .get_property("NFileDescriptorStore")
        .await
        .map_err(|cause| mode.bus("systemd FD-store count read failed", cause))?;
    if let Some(resident) = parts.as_mut() {
        resident.reported_entries = Some(reported_entries);
    }

    // All fallible calls have finished. Move the sole decoded backing into
    // its final owning result, which the selected caller immediately parks.
    let rows = match parts {
        Some(resident) => resident.rows.take(),
        None => local_rows,
    }.ok_or_else(|| mode.refused("original FD-store dump rows are absent"))?;

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
    fn incomplete_coverage_never_lends_even_a_complete_empty_dump() {
        let mut observation = super::FdStoreCoverageObservationV1::pending();
        observation.snapshot = Some(Ok(super::FdStoreSnapshot {
            maximum_entries: 1024,
            reported_entries: 0,
            rows: Vec::new(),
        }));
        observation.final_bookend = Some(Ok(()));

        // Metadata alone cannot substitute for the original PID1/dump loans.
        assert!(observation.snapshot().is_err());
        assert!(observation.invocation().is_none());
        assert!(observation.manager_owner().is_none());
        assert!(observation.first_cause().is_none());
    }

    #[test]
    fn failed_coverage_keeps_decoded_rows_and_borrows_its_actual_cause() {
        let mut observation = super::FdStoreCoverageObservationV1::pending();
        observation.parts.rows = Some(Vec::new());
        observation.snapshot = Some(Err(super::SnapshotReadErrorV1::Refused(
            "inert negative observation",
        )));

        let first = observation.first_cause().unwrap();
        let second = observation.first_cause().unwrap();
        assert!(std::ptr::eq(first, second));
        assert!(observation.parts.rows.is_some());
        assert!(observation.snapshot().is_err());
    }

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
