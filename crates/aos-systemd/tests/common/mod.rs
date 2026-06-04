//! In-process `FakeSystemd` test double.
//!
//! Stands up a fake `org.freedesktop.systemd1.Manager` on the server end of a
//! `UnixStream` pair (zbus `p2p` + `bus-impl`), with the real `SystemdClient`
//! driving the client end. The fake records every method call and emits
//! synthetic `JobRemoved` / `Reloading` signals so the tests can drive each
//! `JobResult` branch deterministically without a real systemd.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use aos_systemd::SystemdClient;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

/// Shared, cheaply-cloneable state the test inspects/controls.
#[derive(Clone)]
pub struct FakeState {
    /// Method names, in call order.
    pub calls: Arc<Mutex<Vec<String>>>,
    /// Result label emitted for jobs with no per-unit override.
    pub next_result: Arc<Mutex<String>>,
    /// Per-unit result overrides (unit name → result label).
    pub unit_results: Arc<Mutex<HashMap<String, String>>>,
    /// Whether the client has called Subscribe(). The fake only emits
    /// JobRemoved while subscribed — faithfully simulating systemd's API-bus
    /// behaviour, so a client that forgot to Subscribe would hang.
    pub subscribed: Arc<AtomicBool>,
    job_counter: Arc<AtomicU32>,
}

impl FakeState {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            next_result: Arc::new(Mutex::new("done".to_string())),
            unit_results: Arc::new(Mutex::new(HashMap::new())),
            subscribed: Arc::new(AtomicBool::new(false)),
            job_counter: Arc::new(AtomicU32::new(0)),
        }
    }
}

pub struct FakeSystemd {
    state: FakeState,
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
        self.submit(&emitter, name).await
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
        if self.state.subscribed.load(Ordering::SeqCst) {
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
    server_conn: zbus::Connection,
}

const MANAGER_PATH: &str = "/org/freedesktop/systemd1";

impl Harness {
    pub async fn new() -> Self {
        let guid = zbus::Guid::generate();
        let (server_sock, client_sock) = tokio::net::UnixStream::pair().unwrap();
        let state = FakeState::new();
        let fake = FakeSystemd {
            state: state.clone(),
        };

        let server_builder = zbus::connection::Builder::unix_stream(server_sock)
            .server(guid)
            .unwrap()
            .p2p()
            .serve_at(MANAGER_PATH, fake)
            .unwrap();
        let client_builder = zbus::connection::Builder::unix_stream(client_sock).p2p();

        // Build both ends concurrently — the auth handshake needs both active.
        let (server_conn, client_conn) =
            tokio::join!(server_builder.build(), client_builder.build());
        let server_conn = server_conn.unwrap();
        let client_conn = client_conn.unwrap();

        let client = SystemdClient::from_connection(client_conn).await.unwrap();
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

    pub fn set_unit_result(&self, unit: &str, result: &str) {
        self.state
            .unit_results
            .lock()
            .unwrap()
            .insert(unit.to_string(), result.to_string());
    }

    /// Emit a standalone `JobRemoved` (no corresponding method call) — used to
    /// exercise `settle()`'s late-message draining.
    pub async fn emit_job_removed(&self, id: u32, unit: &str, result: &str) {
        let iref = self
            .server_conn
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
        let iref = self
            .server_conn
            .object_server()
            .interface::<_, FakeSystemd>(MANAGER_PATH)
            .await
            .unwrap();
        iref.reloading(active).await.unwrap();
    }
}
