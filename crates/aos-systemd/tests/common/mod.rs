//! In-process `FakeSystemd` test double.
//!
//! Stands up a fake `org.freedesktop.systemd1.Manager` on the server end of a
//! `UnixStream` pair (zbus `p2p` + `bus-impl`), with the real `SystemdClient`
//! driving the client end. The fake records every method call and emits
//! synthetic `JobRemoved` / `Reloading` signals so the tests can drive each
//! `JobResult` branch deterministically without a real systemd.

#![allow(clippy::disallowed_types)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "exact-unit-test-util")]
use aos_systemd::ExactUnitClient;
use aos_systemd::{ListUnitsEntry, SystemdClient};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

type RecordedTransientRequest = (String, String, Vec<(String, String)>);

/// Shared, cheaply-cloneable state the test inspects/controls.
#[derive(Clone)]
pub struct FakeState {
    /// Method names, in call order.
    pub calls: Arc<Mutex<Vec<String>>>,
    /// Result label emitted for jobs with no per-unit override.
    pub next_result: Arc<Mutex<String>>,
    /// Per-unit result overrides (unit name → result label).
    pub unit_results: Arc<Mutex<BTreeMap<String, String>>>,
    /// Whether the client has called Subscribe(). The fake only emits
    /// JobRemoved while subscribed — faithfully simulating systemd's API-bus
    /// behaviour, so a client that forgot to Subscribe would hang.
    pub subscribed: Arc<AtomicBool>,
    /// When set, `submit` allocates and returns a job path but does NOT emit
    /// the terminal `JobRemoved` — modelling a job that systemd has accepted
    /// but not yet reported complete. Used to leave a waiter parked so a
    /// subsequent connection drop (see [`Harness::close_server`]) exercises
    /// the bus-died-mid-flight path that restarting `dbus.service` triggers
    /// in production.
    pub suppress_emit: Arc<AtomicBool>,
    /// Last transient unit request as `(name, mode, property signatures)`.
    pub transient_request: Arc<Mutex<Option<RecordedTransientRequest>>>,
    /// Unit name most recently resolved through `GetUnit`.
    pub observed_unit: Arc<Mutex<String>>,
    /// Synthetic response returned by `ListUnitsByPatterns`.
    pub discovery_units: Arc<Mutex<Vec<ListUnitsEntry>>>,
    /// Optional response used from the second discovery pass onward.
    pub discovery_alternate: Arc<Mutex<Option<Vec<ListUnitsEntry>>>>,
    discovery_calls: Arc<AtomicU32>,
    /// Optional hostile `Unit.Id` substitution.
    pub unit_id_override: Arc<Mutex<Option<String>>>,
    /// Manager-retained service environment returned by the fake unit.
    pub environment: Arc<Mutex<Vec<String>>>,
    /// Current high-level activation state.
    pub active_state: Arc<Mutex<String>>,
    /// Current service-specific substate.
    pub sub_state: Arc<Mutex<String>>,
    /// Current service leader PID.
    pub main_pid: Arc<AtomicU32>,
    /// Net accepted `RefUnit` calls minus accepted `UnrefUnit` calls.
    pub reference_balance: Arc<AtomicI32>,
    /// Makes `GetUnit` return the authoritative systemd `NoSuchUnit` error.
    pub unit_missing: Arc<AtomicBool>,
    /// Holds an accepted `RefUnit` call before its method reply.
    pub hold_ref_reply: Arc<AtomicBool>,
    /// Holds an accepted `UnrefUnit` call before its method reply.
    pub hold_unref_reply: Arc<AtomicBool>,
    /// Set only after the fake's server-side socket observes peer shutdown.
    pub disconnect_observed: Arc<AtomicBool>,
    /// Records a poll failure instead of treating it as successful shutdown.
    pub disconnect_error: Arc<Mutex<Option<String>>>,
    job_counter: Arc<AtomicU32>,
}

impl FakeState {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            next_result: Arc::new(Mutex::new("done".to_string())),
            unit_results: Arc::new(Mutex::new(BTreeMap::new())),
            subscribed: Arc::new(AtomicBool::new(false)),
            suppress_emit: Arc::new(AtomicBool::new(false)),
            transient_request: Arc::new(Mutex::new(None)),
            observed_unit: Arc::new(Mutex::new(String::new())),
            discovery_units: Arc::new(Mutex::new(Vec::new())),
            discovery_alternate: Arc::new(Mutex::new(None)),
            discovery_calls: Arc::new(AtomicU32::new(0)),
            unit_id_override: Arc::new(Mutex::new(None)),
            environment: Arc::new(Mutex::new(Vec::new())),
            active_state: Arc::new(Mutex::new("active".to_owned())),
            sub_state: Arc::new(Mutex::new("running".to_owned())),
            main_pid: Arc::new(AtomicU32::new(4242)),
            reference_balance: Arc::new(AtomicI32::new(0)),
            unit_missing: Arc::new(AtomicBool::new(false)),
            hold_ref_reply: Arc::new(AtomicBool::new(false)),
            hold_unref_reply: Arc::new(AtomicBool::new(false)),
            disconnect_observed: Arc::new(AtomicBool::new(false)),
            disconnect_error: Arc::new(Mutex::new(None)),
            job_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    #[cfg(feature = "exact-unit-test-util")]
    pub async fn wait_for_disconnect(&self) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if let Some(error) = self.disconnect_error.lock().unwrap().clone() {
                panic!("disconnect observer failed: {error}");
            }
            if self.disconnect_observed.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("client socket shutdown was not observed");
    }
}

pub struct FakeSystemd {
    state: FakeState,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.systemd1")]
enum FakeManagerError {
    NoSuchUnit(String),
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeSystemd {
    async fn subscribe(&self) {
        self.record("subscribe");
        self.state.subscribed.store(true, Ordering::SeqCst);
    }

    async fn unsubscribe(&self) {
        self.record("unsubscribe");
        self.state.subscribed.store(false, Ordering::SeqCst);
    }

    async fn start_unit(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        name: &str,
        _mode: &str,
    ) -> OwnedObjectPath {
        self.record("start_unit");
        self.submit(&emitter, name).await
    }

    async fn stop_unit(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        name: &str,
        _mode: &str,
    ) -> OwnedObjectPath {
        self.record("stop_unit");
        *self.state.active_state.lock().unwrap() = "inactive".to_owned();
        *self.state.sub_state.lock().unwrap() = "dead".to_owned();
        self.state.main_pid.store(0, Ordering::SeqCst);
        self.submit(&emitter, name).await
    }

    async fn ref_unit(&self, _name: &str) {
        self.record("ref_unit");
        self.state.reference_balance.fetch_add(1, Ordering::SeqCst);
        if self.state.hold_ref_reply.load(Ordering::SeqCst) {
            let accepted = PendingAcceptedReference {
                balance: Arc::clone(&self.state.reference_balance),
            };
            std::future::pending::<()>().await;
            drop(accepted);
        }
    }

    async fn unref_unit(&self, _name: &str) {
        self.record("unref_unit");
        self.state.reference_balance.fetch_sub(1, Ordering::SeqCst);
        if self.state.hold_unref_reply.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }

    async fn restart_unit(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        name: &str,
        _mode: &str,
    ) -> OwnedObjectPath {
        self.record("restart_unit");
        self.submit(&emitter, name).await
    }

    async fn reload_unit(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        name: &str,
        _mode: &str,
    ) -> OwnedObjectPath {
        self.record("reload_unit");
        self.submit(&emitter, name).await
    }

    async fn start_transient_unit(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        name: &str,
        mode: &str,
        properties: Vec<(String, OwnedValue)>,
        auxiliary_units: Vec<(String, Vec<(String, OwnedValue)>)>,
    ) -> OwnedObjectPath {
        self.record("start_transient_unit");
        assert!(auxiliary_units.is_empty());
        let signatures = properties
            .iter()
            .map(|(name, value)| (name.clone(), value.value_signature().to_string()))
            .collect();
        *self.state.transient_request.lock().unwrap() =
            Some((name.to_string(), mode.to_string(), signatures));
        self.submit(&emitter, name).await
    }

    async fn freeze_unit(&self, _name: &str) {
        self.record("freeze_unit");
    }

    async fn thaw_unit(&self, _name: &str) {
        self.record("thaw_unit");
    }

    async fn kill_unit(&self, _name: &str, whom: &str, signal: i32) {
        assert_eq!(whom, "all");
        assert_eq!(signal, libc::SIGKILL);
        self.record("kill_unit");
    }

    async fn get_unit(&self, name: &str) -> Result<OwnedObjectPath, FakeManagerError> {
        self.record("get_unit");
        if self.state.unit_missing.load(Ordering::SeqCst) {
            return Err(FakeManagerError::NoSuchUnit(name.to_owned()));
        }
        *self.state.observed_unit.lock().unwrap() = name.to_string();
        Ok(OwnedObjectPath::try_from(UNIT_PATH).unwrap())
    }

    async fn list_units_by_patterns(
        &self,
        _states: Vec<String>,
        patterns: Vec<String>,
    ) -> Vec<ListUnitsEntry> {
        self.record("list_units_by_patterns");
        assert_eq!(patterns, vec!["aos-sandbox-*.service"]);
        let call = self.state.discovery_calls.fetch_add(1, Ordering::SeqCst);
        if call > 0
            && let Some(units) = self.state.discovery_alternate.lock().unwrap().clone()
        {
            return units;
        }
        self.state.discovery_units.lock().unwrap().clone()
    }

    async fn reload(&self) {
        self.record("reload");
    }

    async fn reset_failed(&self) {
        self.record("reset_failed");
    }

    async fn reset_failed_unit(&self, _name: &str) {
        self.record("reset_failed_unit");
    }

    async fn reboot(&self) {
        self.record("reboot");
    }

    #[zbus(signal)]
    async fn job_removed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn reloading(emitter: &SignalEmitter<'_>, active: bool) -> zbus::Result<()>;
}

struct PendingAcceptedReference {
    balance: Arc<AtomicI32>,
}

impl Drop for PendingAcceptedReference {
    fn drop(&mut self) {
        let _ = self
            .balance
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |balance| {
                Some(balance.saturating_sub(1))
            });
    }
}

struct FakeUnit {
    state: FakeState,
}

#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl FakeUnit {
    #[zbus(property)]
    fn id(&self) -> String {
        if let Some(value) = self.state.unit_id_override.lock().unwrap().clone() {
            return value;
        }
        self.state.observed_unit.lock().unwrap().clone()
    }

    #[zbus(property)]
    fn active_state(&self) -> String {
        self.state.active_state.lock().unwrap().clone()
    }

    #[zbus(property)]
    fn sub_state(&self) -> String {
        self.state.sub_state.lock().unwrap().clone()
    }

    #[zbus(property)]
    fn load_state(&self) -> &str {
        "loaded"
    }

    #[zbus(property)]
    fn freezer_state(&self) -> &str {
        "frozen"
    }

    // Match the wire ABI explicitly, independently of proxy name conversion.
    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        vec![9; 16]
    }
}

struct FakeService {
    state: FakeState,
}

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl FakeService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        self.state.main_pid.load(Ordering::SeqCst)
    }

    #[zbus(property)]
    fn control_group(&self) -> String {
        let name = self.state.observed_unit.lock().unwrap();
        if name.starts_with("aos-lease-guard-") {
            format!("/aos.slice/aos-assignment-guardians.slice/{name}")
        } else {
            format!("/aos.slice/aos-sandboxes.slice/{name}")
        }
    }

    #[zbus(property)]
    fn environment(&self) -> Vec<String> {
        self.state.environment.lock().unwrap().clone()
    }
}

impl FakeSystemd {
    fn record(&self, name: &str) {
        self.state.calls.lock().unwrap().push(name.to_string());
    }

    /// Allocate a synthetic job path and (if subscribed) emit its terminal
    /// `JobRemoved` *before* returning the path — exercising the client's
    /// race-free completed-map path, where the signal can beat the method
    /// reply.
    async fn submit(&self, emitter: &SignalEmitter<'_>, unit: &str) -> OwnedObjectPath {
        let id = self.state.job_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let path = OwnedObjectPath::try_from(format!("/org/freedesktop/systemd1/job/{id}"))
            .expect("synthetic job path is valid");
        if self.state.subscribed.load(Ordering::SeqCst)
            && !self.state.suppress_emit.load(Ordering::SeqCst)
        {
            let result = self
                .state
                .unit_results
                .lock()
                .unwrap()
                .get(unit)
                .cloned()
                .unwrap_or_else(|| self.state.next_result.lock().unwrap().clone());
            let _ = Self::job_removed(emitter, id, path.clone(), unit.to_string(), result).await;
        }
        path
    }
}

/// A connected client + the fake's shared state + the server connection (for
/// emitting standalone signals).
pub struct Harness {
    pub client: SystemdClient,
    pub state: FakeState,
    /// The fake's server-side connection, behind interior mutability so
    /// [`Harness::close_server`] can take and close it through a shared `&self`
    /// (it runs concurrently with an in-flight `&self.client` call). Closing it
    /// severs the `UnixStream` pair and drives the client's signal stream to
    /// EOF — the in-process analogue of `dbus.service` restarting out from
    /// under the reconcile.
    server_conn: Mutex<Option<zbus::Connection>>,
}

/// Harness whose client connection is owned by an exact-unit shutdown anchor.
#[cfg(feature = "exact-unit-test-util")]
pub struct ExactHarness {
    pub client: ExactUnitClient,
    pub state: FakeState,
    pub server_conn: Mutex<Option<zbus::Connection>>,
}

const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/aos_2dsandbox";

async fn build_harness<C, F, BuildClient>(
    build_client: BuildClient,
) -> (C, FakeState, Mutex<Option<zbus::Connection>>)
where
    F: std::future::Future<Output = C>,
    BuildClient: FnOnce(std::os::unix::net::UnixStream) -> F,
{
    let guid = zbus::Guid::generate();
    let (server_sock, client_sock) = std::os::unix::net::UnixStream::pair().unwrap();
    let disconnect_observer = server_sock.try_clone().unwrap();
    server_sock.set_nonblocking(true).unwrap();
    let server_sock = tokio::net::UnixStream::from_std(server_sock).unwrap();
    let state = FakeState::new();
    let reference_balance = Arc::clone(&state.reference_balance);
    let disconnect_observed = Arc::clone(&state.disconnect_observed);
    let disconnect_error = Arc::clone(&state.disconnect_error);
    std::thread::spawn(move || {
        use rustix::event::{PollFd, PollFlags, poll};

        let mut disconnect_events = PollFlags::HUP;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            disconnect_events |= PollFlags::RDHUP;
        }
        let error_events = PollFlags::ERR | PollFlags::NVAL;
        let events = disconnect_events | error_events;
        let mut descriptors = [PollFd::new(&disconnect_observer, events)];
        loop {
            match poll(&mut descriptors, None) {
                Ok(_) if descriptors[0].revents().intersects(error_events) => {
                    *disconnect_error.lock().unwrap() = Some(format!(
                        "socket poll reported {:?}",
                        descriptors[0].revents()
                    ));
                    return;
                }
                Ok(_) if descriptors[0].revents().intersects(disconnect_events) => break,
                Ok(_) => descriptors[0].clear_revents(),
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => {
                    *disconnect_error.lock().unwrap() = Some(error.to_string());
                    return;
                }
            }
        }

        // systemd's RefUnit ownership is connection-scoped. Publish the HUP
        // only after the fake's reference state reflects that cleanup.
        reference_balance.store(0, Ordering::SeqCst);
        disconnect_observed.store(true, Ordering::SeqCst);
    });
    let fake = FakeSystemd {
        state: state.clone(),
    };

    let server_builder = zbus::connection::Builder::unix_stream(server_sock)
        .server(guid)
        .unwrap()
        .p2p()
        .serve_at(MANAGER_PATH, fake)
        .unwrap()
        .serve_at(
            UNIT_PATH,
            FakeUnit {
                state: state.clone(),
            },
        )
        .unwrap()
        .serve_at(
            UNIT_PATH,
            FakeService {
                state: state.clone(),
            },
        )
        .unwrap();

    // Build both ends concurrently — the auth handshake needs both active.
    let (server_conn, client) = tokio::join!(server_builder.build(), build_client(client_sock));

    (client, state, Mutex::new(Some(server_conn.unwrap())))
}

impl Harness {
    pub async fn new() -> Self {
        let (client, state, server_conn) = build_harness(|client_sock| async move {
            client_sock.set_nonblocking(true).unwrap();
            let client_sock = tokio::net::UnixStream::from_std(client_sock).unwrap();
            let connection = zbus::connection::Builder::unix_stream(client_sock)
                .p2p()
                .build()
                .await
                .unwrap();

            SystemdClient::from_connection(connection).await.unwrap()
        })
        .await;

        Self {
            client,
            state,
            server_conn,
        }
    }

    pub fn calls(&self) -> Vec<String> {
        self.state.calls.lock().unwrap().clone()
    }

    pub fn set_next_result(&self, result: &str) {
        *self.state.next_result.lock().unwrap() = result.to_string();
    }

    /// Stop the fake from emitting terminal `JobRemoved` signals: subsequent
    /// lifecycle calls return a job path but never report completion, leaving
    /// the client's waiter parked. Pair with [`Harness::close_server`].
    pub fn suppress_job_emission(&self) {
        self.state.suppress_emit.store(true, Ordering::SeqCst);
    }

    /// Close the server side of the connection, severing the `UnixStream` pair
    /// so the client's `JobRemoved` stream reaches EOF. This is exactly what
    /// happens to the reconcile's bus connection when it restarts
    /// `dbus.service`: the transport dies mid-flight with a job still pending.
    pub async fn close_server(&self) {
        let conn = self.server_conn.lock().unwrap().take();
        if let Some(conn) = conn {
            let _ = conn.close().await;
        }
    }

    pub fn set_unit_result(&self, unit: &str, result: &str) {
        self.state
            .unit_results
            .lock()
            .unwrap()
            .insert(unit.to_string(), result.to_string());
    }

    pub fn set_discovery_units(&self, units: Vec<ListUnitsEntry>) {
        *self.state.discovery_units.lock().unwrap() = units;
        *self.state.discovery_alternate.lock().unwrap() = None;
        self.state.discovery_calls.store(0, Ordering::SeqCst);
    }

    pub fn set_discovery_sequence(&self, first: Vec<ListUnitsEntry>, second: Vec<ListUnitsEntry>) {
        *self.state.discovery_units.lock().unwrap() = first;
        *self.state.discovery_alternate.lock().unwrap() = Some(second);
        self.state.discovery_calls.store(0, Ordering::SeqCst);
    }

    pub fn set_unit_id_override(&self, value: &str) {
        *self.state.unit_id_override.lock().unwrap() = Some(value.to_owned());
    }

    /// Emit a standalone `JobRemoved` (no corresponding method call) — used to
    /// exercise `settle()`'s late-message draining.
    pub async fn emit_job_removed(&self, id: u32, unit: &str, result: &str) {
        let conn = self.server_conn_clone();
        let iref = conn
            .object_server()
            .interface::<_, FakeSystemd>(MANAGER_PATH)
            .await
            .unwrap();
        let job = OwnedObjectPath::try_from(format!("/org/freedesktop/systemd1/job/{id}")).unwrap();
        iref.job_removed(id, job, unit.to_string(), result.to_string())
            .await
            .unwrap();
    }

    pub async fn emit_reloading(&self, active: bool) {
        let conn = self.server_conn_clone();
        let iref = conn
            .object_server()
            .interface::<_, FakeSystemd>(MANAGER_PATH)
            .await
            .unwrap();
        iref.reloading(active).await.unwrap();
    }

    /// Clone the live server connection. Panics if it was already closed via
    /// [`Harness::close_server`] — emitting after a deliberate drop is a test
    /// bug.
    fn server_conn_clone(&self) -> zbus::Connection {
        self.server_conn
            .lock()
            .unwrap()
            .as_ref()
            .expect("server connection is open")
            .clone()
    }
}

#[cfg(feature = "exact-unit-test-util")]
impl ExactHarness {
    pub async fn new() -> Self {
        let (client, state, server_conn) = build_harness(|client_sock| async move {
            ExactUnitClient::from_test_peer_stream(client_sock)
                .await
                .unwrap()
        })
        .await;

        Self {
            client,
            state,
            server_conn,
        }
    }

    pub fn set_next_result(&self, result: &str) {
        *self.state.next_result.lock().unwrap() = result.to_owned();
    }

    pub fn suppress_job_emission(&self) {
        self.state.suppress_emit.store(true, Ordering::SeqCst);
    }

    pub fn set_environment(&self, values: Vec<String>) {
        *self.state.environment.lock().unwrap() = values;
    }

    pub fn hold_ref_reply(&self) {
        self.state.hold_ref_reply.store(true, Ordering::SeqCst);
    }

    pub fn hold_unref_reply(&self) {
        self.state.hold_unref_reply.store(true, Ordering::SeqCst);
    }

    pub fn set_unit_missing(&self) {
        self.state.unit_missing.store(true, Ordering::SeqCst);
    }
}
