//! `SystemdClient` — a typed async client for `org.freedesktop.systemd1`.
//!
//! One [`SystemdClient`] is constructed per apm invocation. It owns a single
//! `zbus::Connection`, subscribes to manager signals, and runs background
//! tasks that forward `JobRemoved` / `Reloading` events into shared state.
//! Method callers `await` on a per-job oneshot; the stream task owns the
//! signal stream continuously, dodging the "stream not polled" hang.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::error::{Error, Result, is_no_such_unit};
use crate::manager_proxy::{ListUnitsEntry, ManagerProxy, ServiceProxy, UnitProxy};

const SYSTEMD_ALREADY_SUBSCRIBED: &str = "org.freedesktop.systemd1.AlreadySubscribed";
const PINNED_COMPLETION_LIMIT: usize = 1_024;

/// Classification of a systemd job's terminal `result`, per the `job_result`
/// table in systemd's `src/core/job.h`. We name only the four cases
/// switch-to-configuration-ng classifies explicitly; everything else
/// (`canceled`, `skipped`, `assert`, `frozen`, …) lands in `Unknown` with the
/// raw label preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobResult {
    /// The job completed successfully (`"done"`).
    Done,
    /// The job failed (`"failed"`).
    Failed,
    /// The job hit its timeout (`"timeout"`).
    Timeout,
    /// A dependency of the job failed (`"dependency"`).
    Dependency,
    /// Any other terminal result, with the raw systemd label preserved.
    Unknown(String),
}

impl JobResult {
    /// Parse a systemd `result` string.
    pub fn from_systemd(s: &str) -> Self {
        match s {
            "done" => Self::Done,
            "failed" => Self::Failed,
            "timeout" => Self::Timeout,
            "dependency" => Self::Dependency,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// The systemd label for this result (round-trips `from_systemd`).
    pub fn label(&self) -> &str {
        match self {
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Dependency => "dependency",
            Self::Unknown(s) => s,
        }
    }

    /// Whether the job completed successfully.
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }
}

impl serde::Serialize for JobResult {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

/// The outcome of a unit lifecycle operation: the submitted job's object path
/// plus its classified terminal result.
#[derive(Debug, Clone)]
pub struct JobOutcome {
    /// Object path of the job systemd enqueued for the operation.
    pub job_path: OwnedObjectPath,
    /// Classified terminal result from the job's `JobRemoved` signal.
    pub result: JobResult,
}

/// Classifies a unit's exact systemd `ActiveState` while preserving new labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnitActiveState {
    /// The unit is fully active.
    Active,
    /// The unit is active while reloading its configuration.
    Reloading,
    /// The unit is fully inactive.
    Inactive,
    /// The unit entered a failed state.
    Failed,
    /// The unit is still activating.
    Activating,
    /// The unit is still deactivating.
    Deactivating,
    /// The unit is in systemd's maintenance state.
    Maintenance,
    /// The unit is refreshing its state.
    Refreshing,
    /// The manager returned an unrecognized future state.
    Unknown(String),
}

impl UnitActiveState {
    /// Classifies one raw systemd `ActiveState` label without discarding it.
    #[must_use]
    pub fn from_systemd(state: &str) -> Self {
        match state {
            "active" => Self::Active,
            "reloading" => Self::Reloading,
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            "maintenance" => Self::Maintenance,
            "refreshing" => Self::Refreshing,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Returns the exact systemd label represented by this state.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Reloading => "reloading",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Activating => "activating",
            Self::Deactivating => "deactivating",
            Self::Maintenance => "maintenance",
            Self::Refreshing => "refreshing",
            Self::Unknown(state) => state,
        }
    }

    /// Reports whether the unit is fully active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Identifies one system bus lifetime and the exact systemd service owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerIncarnation {
    bus_id: String,
    owner: String,
}

impl ManagerIncarnation {
    /// Returns the D-Bus GUID identifying this bus lifetime.
    #[must_use]
    pub fn bus_id(&self) -> &str {
        &self.bus_id
    }

    /// Returns systemd's unique service owner within the bus lifetime.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns an opaque durable token suitable for provider assignment identity.
    #[must_use]
    pub fn token(&self) -> String {
        format!("bus:{};owner:{}", self.bus_id, self.owner)
    }
}

/// A unit found in a failed (or failed-and-auto-restarting) state by
/// [`SystemdClient::failed_units`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailedUnit {
    /// Unit name, including the type suffix (e.g. `foo.service`).
    pub name: String,
    /// `ActiveState` at scan time (`"failed"`, or `"activating"` for the
    /// auto-restart case).
    pub active_state: String,
    /// `SubState` at scan time (e.g. `"auto-restart"`).
    pub sub_state: String,
    /// `ExecMainStatus` for `.service` units (exit status of the main
    /// process); `None` for non-services or if the read failed.
    pub exec_main_status: Option<i32>,
    /// Captured `systemctl status` output for human display.
    pub status_dump: String,
}

/// Result of a post-run failed-unit scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailedUnitsReport {
    /// All units found in a failed (or failing-and-retrying) state.
    pub failed: Vec<FailedUnit>,
}

impl FailedUnitsReport {
    /// Returns `true` if no failed units were found.
    pub fn is_empty(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Automatic-restart policy of a `.service` unit, read to size the settle
/// deadline in a post-activation health gate.
#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// `RestartSec` — the backoff systemd waits before each automatic restart.
    pub restart_sec: Duration,
    /// `NRestarts` — automatic restarts performed so far.
    pub n_restarts: u32,
}

/// Terminal classification of a unit that was observed in `auto-restart`,
/// returned by [`SystemdClient::wait_until_settled`] after waiting out the
/// unit's `RestartSec` backoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The unit reached `active` — it recovered on a retry.
    Recovered {
        /// `NRestarts` observed once the unit went active.
        n_restarts: u32,
    },
    /// The unit reached terminal `failed` (systemd gave up restarting it).
    Failed,
    /// The unit was still auto-restarting when the deadline elapsed — it is
    /// not converging within the budget.
    StillRestarting,
}

/// Shared job-tracking state.
///
/// `waiters` holds the oneshot sender for jobs we've submitted and are awaiting.
/// `completed` holds results for `JobRemoved` events that arrived *before* the
/// submitting call had a chance to register its waiter — the method reply
/// (carrying the job path) and the `JobRemoved` signal are dispatched on
/// independent tasks, so the signal can win the race. Keeping a completed-map
/// makes the wait race-free: the submitter checks `completed` under the same
/// lock before inserting a waiter.
#[derive(Default)]
struct JobRegistry {
    waiters: BTreeMap<String, oneshot::Sender<JobResult>>,
    completed: BTreeMap<String, JobResult>,
    /// Set once the `JobRemoved` signal stream closes — i.e. the bus connection
    /// died. No further `JobRemoved` will ever arrive, so any pending or future
    /// waiter can never be satisfied. Read under the same lock as `waiters` so
    /// the close-side drain and the `await_job` registration are serialized:
    /// every awaiter either gets drained or sees `closed` before parking, and
    /// none is left to hang. The canonical case is the reconcile restarting
    /// `dbus.service` and killing the very bus it was driving.
    closed: bool,
}

#[derive(Default)]
struct PinnedJobRegistry {
    /// Awaiters grouped by job path. systemd may merge concurrent requests and
    /// return the same path to each caller, so one completion wakes the group.
    waiters: BTreeMap<String, BTreeMap<u64, oneshot::Sender<JobResult>>>,
    /// Results that raced ahead of one or more outstanding method replies.
    completed: BTreeMap<String, JobResult>,
    /// Calls whose method reply has not exposed the job path yet.
    active_submissions: usize,
    /// Total lifecycle calls holding one bounded registry reservation.
    pending_calls: usize,
    next_waiter_id: u64,
    closed: bool,
    /// Set when unrelated signals exhaust the bounded early-completion map.
    overflowed: bool,
}

struct PinnedSubmission {
    jobs: Arc<Mutex<PinnedJobRegistry>>,
    before_reply: bool,
    waiter: Option<(String, u64)>,
    pending: bool,
}

enum PinnedRegistration {
    Completed(JobResult),
    Pending(oneshot::Receiver<JobResult>),
}

impl PinnedSubmission {
    fn begin(jobs: &Arc<Mutex<PinnedJobRegistry>>) -> Result<Self> {
        let mut registry = lock_pinned_registry(jobs);
        if registry.overflowed {
            return Err(Error::JobCompletionOverflow);
        }
        if registry.closed {
            return Err(Error::JobSenderDropped("manager signal stream".to_string()));
        }
        if registry.pending_calls >= PINNED_COMPLETION_LIMIT {
            return Err(Error::JobCompletionOverflow);
        }
        registry.pending_calls += 1;
        registry.active_submissions += 1;

        Ok(Self {
            jobs: Arc::clone(jobs),
            before_reply: true,
            waiter: None,
            pending: true,
        })
    }

    fn register(&mut self, path_key: &str) -> Result<PinnedRegistration> {
        let mut registry = lock_pinned_registry(&self.jobs);
        registry.active_submissions = registry.active_submissions.saturating_sub(1);
        self.before_reply = false;

        if registry.overflowed {
            return Err(Error::JobCompletionOverflow);
        }
        if let Some(result) = registry.completed.get(path_key).cloned() {
            if registry.active_submissions == 0 {
                registry.completed.clear();
            }
            registry.pending_calls = registry.pending_calls.saturating_sub(1);
            self.pending = false;
            return Ok(PinnedRegistration::Completed(result));
        }
        if registry.closed {
            return Err(Error::JobSenderDropped(path_key.to_string()));
        }
        if registry.active_submissions == 0 {
            registry.completed.clear();
        }

        let waiter_id = registry.next_waiter_id;
        registry.next_waiter_id = registry
            .next_waiter_id
            .checked_add(1)
            .ok_or(Error::JobCompletionOverflow)?;
        let (sender, receiver) = oneshot::channel();
        registry
            .waiters
            .entry(path_key.to_string())
            .or_default()
            .insert(waiter_id, sender);
        self.waiter = Some((path_key.to_string(), waiter_id));

        Ok(PinnedRegistration::Pending(receiver))
    }

    fn finish(&mut self) {
        let mut registry = lock_pinned_registry(&self.jobs);
        registry.pending_calls = registry.pending_calls.saturating_sub(1);
        self.waiter = None;
        self.pending = false;
    }
}

impl Drop for PinnedSubmission {
    fn drop(&mut self) {
        if self.pending {
            let mut registry = lock_pinned_registry(&self.jobs);
            if self.before_reply {
                registry.active_submissions = registry.active_submissions.saturating_sub(1);
            }
            if let Some((path, waiter_id)) = self.waiter.take()
                && let Some(waiters) = registry.waiters.get_mut(&path)
            {
                waiters.remove(&waiter_id);
                if waiters.is_empty() {
                    registry.waiters.remove(&path);
                }
            }
            registry.pending_calls = registry.pending_calls.saturating_sub(1);
            if registry.active_submissions == 0 {
                registry.completed.clear();
            }
        }
    }
}

/// Typed async client for `org.freedesktop.systemd1`.
pub struct SystemdClient {
    conn: zbus::Connection,
    manager: ManagerProxy<'static>,
    jobs: Arc<Mutex<JobRegistry>>,
    reloading: Arc<AtomicBool>,
    /// One tick per observed `JobRemoved`, regardless of whether a waiter was
    /// registered. Drained by [`SystemdClient::settle`] to tell "bus quiet"
    /// from "bus still chattering" without inspecting the job map.
    job_event_rx: AsyncMutex<mpsc::UnboundedReceiver<()>>,
    /// Background signal-listener tasks; aborted on drop.
    tasks: Vec<JoinHandle<()>>,
}

/// A listener-free capability for one caller-selected systemd bus.
///
/// The connection itself fixes the manager scope. Native catalogs retain this
/// capability and create bounded unique-owner pins from it; they never replace
/// a supplied user, container, or initrd transport with the host system bus.
#[derive(Clone)]
pub struct SystemdManagerConnection {
    conn: zbus::Connection,
}

/// A lifecycle client bound to one exact systemd service owner.
///
/// Calls are addressed to the owner's D-Bus unique name, and job completion
/// signals flow into a registry owned only by this pin. This keeps an unrelated
/// `JobRemoved` from a replacement manager from completing an earlier call
/// that happened to receive the same object path.
pub struct PinnedSystemdManager {
    conn: zbus::Connection,
    incarnation: ManagerIncarnation,
    manager: ManagerProxy<'static>,
    jobs: Arc<Mutex<PinnedJobRegistry>>,
    job_task: JoinHandle<()>,
}

impl SystemdClient {
    /// Open the system bus, build the Manager proxy, `Subscribe()`, and start
    /// the background signal-handler tasks.
    ///
    /// Uses the shared **system bus** (`/run/dbus/system_bus_socket`), the same
    /// transport nixpkgs `switch-to-configuration-ng` uses. (systemd's private
    /// socket would decouple us from `dbus.service`, but it is a *direct*, non-
    /// bus endpoint whose message framing zbus 5 cannot round-trip — it rejects
    /// systemd's sender field as an invalid unique name. We therefore avoid
    /// restarting the bus in the first place: `dbus.service` is `reloadIfChanged`
    /// so the reconcile reloads rather than restarts it, and a connection that
    /// dies mid-reconcile anyway is surfaced as a `JobSenderDropped` error
    /// rather than an indefinite hang.)
    ///
    /// # Errors
    ///
    /// Returns [`Error::SystemdUnavailable`] if the system bus cannot be
    /// reached (e.g. `/run/dbus/system_bus_socket` is absent), or any
    /// error from [`SystemdClient::from_connection`].
    pub async fn connect() -> Result<Self> {
        let conn = zbus::Connection::system()
            .await
            .map_err(Error::SystemdUnavailable)?;
        Self::from_connection(conn).await
    }

    /// Build a client around a caller-supplied connection. Used by the unit
    /// tests to inject one end of a p2p pair pointing at a `FakeSystemd`; also
    /// a legitimate embedding API. Unconditionally `pub` so the integration
    /// test crate (a separate compilation unit) can reach it.
    ///
    /// # Errors
    ///
    /// Returns an error if the Manager proxy cannot be built, if the
    /// `Subscribe()` call fails, or if the signal streams cannot be
    /// established.
    pub async fn from_connection(conn: zbus::Connection) -> Result<Self> {
        let manager = ManagerProxy::new(&conn).await?;

        // MUST come before constructing any signal stream below. API-bus peers
        // receive NO JobNew/JobRemoved/Reloading until they call Subscribe();
        // direct (private-socket) peers are subscribed implicitly. systemd
        // source: src/core/dbus-manager.c:1376-1410 (method_subscribe). Skip
        // this and the streams silently produce nothing — the JobRemoved
        // waiter then hangs/times out for the wrong reason, and tests can go
        // green for the wrong reason too.
        manager.subscribe().await?;

        let jobs = Arc::new(Mutex::new(JobRegistry::default()));
        let reloading = Arc::new(AtomicBool::new(false));
        let (event_tx, event_rx) = mpsc::unbounded_channel::<()>();

        // Build the streams AFTER Subscribe so we never miss an event for a
        // job submitted later in this process.
        let mut job_removed = manager.receive_job_removed().await?;
        let mut reloading_stream = manager.receive_reloading().await?;

        let mut tasks = Vec::with_capacity(2);

        // One task, double duty (see JobRegistry): route the result to any
        // waiter (or stash it in `completed`), AND tick the settle channel.
        let jobs_for_task = jobs.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(signal) = job_removed.next().await {
                let Ok(args) = signal.args() else { continue };
                let path = args.job;
                let path_key = path.as_str().to_owned();
                let result = JobResult::from_systemd(&args.result);
                {
                    let mut reg = jobs_for_task.lock().unwrap();
                    if let Some(tx) = reg.waiters.remove(&path_key) {
                        // Fire-and-forget; if the awaiter dropped (caller timed
                        // out at a higher level), there's nothing to do.
                        let _ = tx.send(result);
                    } else {
                        reg.completed.insert(path_key, result);
                    }
                }
                let _ = event_tx.send(());
            }
            // Stream closed = bus connection died (e.g. we just restarted
            // dbus.service out from under our own connection). No more
            // JobRemoved will ever arrive, so flip `closed` and drop every
            // parked sender: each awaiting `await_job` then observes a closed
            // oneshot and returns `JobSenderDropped` instead of hanging
            // forever. Future `await_job` calls see `closed` and bail up front.
            {
                let mut reg = jobs_for_task.lock().unwrap();
                reg.closed = true;
                reg.waiters.clear();
            }
        }));

        let reloading_for_task = reloading.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(signal) = reloading_stream.next().await {
                if let Ok(args) = signal.args() {
                    reloading_for_task.store(args.active, Ordering::SeqCst);
                }
            }
        }));

        Ok(Self {
            conn,
            manager,
            jobs,
            reloading,
            job_event_rx: AsyncMutex::new(event_rx),
            tasks,
        })
    }

    // ---- Unit lifecycle ---------------------------------------------------
    // Each submits the job, awaits JobRemoved, classifies, and returns. Mode is
    // "replace" except `isolate_unit`.

    /// Start `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails (e.g. `NoSuchUnit`) or if
    /// the bus connection dies while awaiting the job's `JobRemoved`.
    /// A job that finishes with `failed`/`timeout`/... is *not* an error;
    /// inspect [`JobOutcome::result`].
    pub async fn start_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.start_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Queue a start job for `name` without awaiting the job result.
    ///
    /// This matches `systemctl start --no-block`: systemd validates and queues
    /// the job, then the caller continues while the unit reaches its terminal
    /// state asynchronously.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails, for example when systemd
    /// rejects the unit name or cannot queue the job.
    pub async fn start_unit_no_wait(&self, name: &str) -> Result<()> {
        self.manager.start_unit(name, "replace").await?;
        Ok(())
    }

    /// Stop `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn stop_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.stop_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Restart `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn restart_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.restart_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Reload `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn reload_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.reload_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Start `name` in `"isolate"` mode (stop everything not required by
    /// it, like `systemctl isolate`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn isolate_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.start_unit(name, "isolate").await?;
        self.await_job(path).await
    }

    /// Register interest in `path` and await its `JobRemoved`. Race-free: if
    /// the result already landed in `completed`, return it immediately. There
    /// is no caller-side timeout — per switch-to-configuration-ng's contract,
    /// "this job is in flight; we wait for systemd's answer." Callers wanting
    /// an upper bound wrap this in `tokio::time::timeout` themselves.
    async fn await_job(&self, path: OwnedObjectPath) -> Result<JobOutcome> {
        let path_key = path.as_str().to_owned();
        let rx = {
            let mut reg = self.jobs.lock().unwrap();
            if let Some(result) = reg.completed.remove(&path_key) {
                return Ok(JobOutcome {
                    job_path: path,
                    result,
                });
            }
            // The signal stream already closed (bus died) — no JobRemoved can
            // arrive, so don't park a waiter that would never wake.
            if reg.closed {
                return Err(Error::JobSenderDropped(path.as_str().to_string()));
            }
            let (tx, rx) = oneshot::channel();
            reg.waiters.insert(path_key, tx);
            rx
        };
        let result = rx
            .await
            .map_err(|_| Error::JobSenderDropped(path.as_str().to_string()))?;
        Ok(JobOutcome {
            job_path: path,
            result,
        })
    }

    // ---- Manager-level operations ----------------------------------------

    /// `Manager.Reload()` — equivalent to `systemctl daemon-reload`.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn daemon_reload(&self) -> Result<()> {
        self.manager.reload().await?;
        Ok(())
    }

    /// Clear the "failed" state of all units (`systemctl reset-failed`).
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn reset_failed(&self) -> Result<()> {
        self.manager.reset_failed().await?;
        Ok(())
    }

    /// Clear the "failed" state of a single unit.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails (e.g. `NoSuchUnit`).
    pub async fn reset_failed_unit(&self, name: &str) -> Result<()> {
        self.manager.reset_failed_unit(name).await?;
        Ok(())
    }

    /// Queue a reboot. Like `systemctl reboot`, this returns once systemd has
    /// *queued* the reboot, not when it happens; the caller then exits cleanly
    /// or is killed as systemd tears the system down.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn reboot(&self) -> Result<()> {
        self.manager.reboot().await?;
        Ok(())
    }

    // ---- Inspection -------------------------------------------------------

    /// Returns the current bus and service-owner incarnation of systemd.
    ///
    /// A D-Bus unique name is unique only during one bus lifetime and may be
    /// reused after restart. This token therefore combines the bus GUID with
    /// the current unique owner of `org.freedesktop.systemd1`. Callers can
    /// persist and recheck it across reconnection without confusing two bus
    /// lifetimes that both assigned a name such as `:1.0`.
    ///
    /// # Errors
    ///
    /// Returns an error when the bus daemon cannot resolve
    /// `org.freedesktop.systemd1` to a current unique owner.
    pub async fn manager_incarnation(&self) -> Result<ManagerIncarnation> {
        read_manager_incarnation(&self.conn).await
    }

    /// Whether `name`'s `ActiveState == "active"`. A unit that isn't loaded
    /// (systemd returns `NoSuchUnit`) counts as not-active — matching
    /// `systemctl is-active` on an unknown unit.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus calls fail for any reason other than
    /// `NoSuchUnit`.
    pub async fn is_active(&self, name: &str) -> Result<bool> {
        match self.manager.get_unit(name).await {
            Ok(path) => {
                let unit = UnitProxy::builder(&self.conn)
                    .path(path)?
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await?;
                Ok(unit.active_state().await? == "active")
            }
            Err(e) if is_no_such_unit(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Read a single property off a unit's `org.freedesktop.systemd1.Unit`
    /// interface, returning the raw `OwnedValue`. Callers convert with
    /// `T::try_from(value)`. (The spec sketched a generic `unit_property::<T>`;
    /// returning `OwnedValue` avoids gnarly trait bounds while serving the same
    /// callers — `is_active` and the `_test-systemd-client property` op.)
    ///
    /// # Errors
    ///
    /// Returns an error if the unit is not loaded (`NoSuchUnit`), if the
    /// property does not exist, or if the D-Bus calls fail.
    pub async fn unit_property(&self, name: &str, prop: &str) -> Result<OwnedValue> {
        let path = self.manager.get_unit(name).await?;
        let props = zbus::fdo::PropertiesProxy::builder(&self.conn)
            .destination("org.freedesktop.systemd1")?
            .path(path)?
            .build()
            .await?;
        let iface = zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Unit")
            .expect("static interface name is valid");
        Ok(props.get(iface, prop).await?)
    }

    /// List units filtered by active states and shell-glob name patterns;
    /// empty slices mean "no filter".
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> Result<Vec<ListUnitsEntry>> {
        Ok(self
            .manager
            .list_units_by_patterns(states, patterns)
            .await?)
    }

    /// Whether systemd is currently reloading (last observed `Reloading`
    /// signal). Useful for callers that want to wait out a daemon reload.
    pub fn is_reloading(&self) -> bool {
        self.reloading.load(Ordering::SeqCst)
    }

    /// Post-run failed-unit scan, cribbed from switch-to-configuration-ng
    /// (`main.rs:2464-2526` / `get_active_units`):
    ///
    /// 1. List *all* units, skip ones that are `inactive` or `followed`.
    /// 2. A unit is failed if `ActiveState == "failed"`, OR it's a `.service`
    ///    in `SubState == "auto-restart"` whose `ExecMainStatus` is non-zero
    ///    (it previously failed to start and is waiting to retry).
    /// 3. Capture `systemctl status` text for each, for human display.
    ///
    /// NOTE: filtering on `states = ["failed"]` alone (as the spec sketched in
    /// §5.8) would MISS the auto-restart case, whose `ActiveState` is
    /// `activating`, not `failed`. We mirror STC and scan all units.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit listing fails. Per-unit property reads
    /// and status captures are best-effort and never fail the scan.
    pub async fn failed_units(&self) -> Result<FailedUnitsReport> {
        let units = self.manager.list_units_by_patterns(&[], &[]).await?;
        let mut failed = Vec::new();
        for u in units {
            if !u.followed.is_empty() || u.active_state == "inactive" {
                continue;
            }
            let is_service = u.name.ends_with(".service");

            // Read ExecMainStatus once (used for both classification and the
            // report). Best-effort: a unit can disappear between list and read.
            let exec_main_status = if is_service {
                match ServiceProxy::builder(&self.conn)
                    .path(u.object_path.clone())?
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await
                {
                    Ok(svc) => svc.exec_main_status().await.ok(),
                    Err(_) => None,
                }
            } else {
                None
            };

            let is_failed = u.active_state == "failed"
                || (u.sub_state == "auto-restart"
                    && is_service
                    && exec_main_status.map(|s| s != 0).unwrap_or(false));

            if !is_failed {
                continue;
            }

            failed.push(FailedUnit {
                status_dump: systemctl_status(&u.name).await,
                name: u.name,
                active_state: u.active_state,
                sub_state: u.sub_state,
                exec_main_status,
            });
        }
        Ok(FailedUnitsReport { failed })
    }

    /// Drain the signal stream until it goes quiet (250 ms per-message patience
    /// window) or 90 s elapses, returning the count of late `JobRemoved`
    /// events seen. Mirrors switch-to-configuration-ng's settle window
    /// (`main.rs:2452-2462`). Invoke after the last submit + wait so late
    /// events still get counted/reported.
    ///
    /// # Errors
    ///
    /// Currently infallible (always returns `Ok`); the `Result` is kept
    /// for forward compatibility with bus-error reporting.
    pub async fn settle(&self) -> Result<usize> {
        let mut count = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        let mut rx = self.job_event_rx.lock().await;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let tick = Duration::from_millis(250).min(deadline - now);
            match tokio::time::timeout(tick, rx.recv()).await {
                Ok(Some(())) => count += 1,
                // Channel closed (bus died) or the patience window elapsed
                // with no new event: the bus is quiet, we're done.
                Ok(None) | Err(_) => break,
            }
        }
        Ok(count)
    }

    /// Read the automatic-restart policy of a `.service` unit off its
    /// `org.freedesktop.systemd1.Service` interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit is not loaded (`NoSuchUnit`) or the D-Bus
    /// property reads fail.
    pub async fn restart_policy(&self, name: &str) -> Result<RestartPolicy> {
        let path = self.manager.get_unit(name).await?;
        let svc = ServiceProxy::builder(&self.conn)
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        Ok(RestartPolicy {
            restart_sec: Duration::from_micros(svc.restart_usec().await?),
            n_restarts: svc.n_restarts().await.unwrap_or(0),
        })
    }

    /// Wait up to `budget` for an auto-restarting unit to settle to a terminal
    /// state, polling its `ActiveState`/`SubState` every 250 ms.
    ///
    /// A `.service` caught in `SubState == "auto-restart"` is mid-backoff, not
    /// terminally failed: its next start may succeed. This resolves that
    /// ambiguity by waiting until the unit leaves `auto-restart` and reaches
    /// `active` ([`SettleOutcome::Recovered`]) or `failed`
    /// ([`SettleOutcome::Failed`]) — or the budget elapses
    /// ([`SettleOutcome::StillRestarting`]). A unit that has left `auto-restart`
    /// but is still mid-start (`activating`) keeps the poll going until it
    /// terminalizes.
    ///
    /// Transient D-Bus read errors (e.g. the unit momentarily unloaded between
    /// restarts) are tolerated: the poll retries until the deadline. Infallible
    /// by construction — every path resolves to a [`SettleOutcome`].
    pub async fn wait_until_settled(&self, name: &str, budget: Duration) -> SettleOutcome {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            // Only act once the unit has left `auto-restart`; while it's still
            // mid-backoff (or a read transiently fails) we fall through and poll
            // again. A unit that left auto-restart but isn't yet active/failed
            // (mid start job) also falls through until it terminalizes.
            let settled = self
                .unit_active_sub(name)
                .await
                .ok()
                .filter(|(_, sub)| sub != "auto-restart");
            if let Some((active, _)) = settled {
                if active == "active" {
                    let n_restarts = self
                        .restart_policy(name)
                        .await
                        .map(|p| p.n_restarts)
                        .unwrap_or(0);
                    return SettleOutcome::Recovered { n_restarts };
                }
                if active == "failed" {
                    return SettleOutcome::Failed;
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return SettleOutcome::StillRestarting;
            }
            tokio::time::sleep(Duration::from_millis(250).min(deadline - now)).await;
        }
    }

    /// Read `(ActiveState, SubState)` off a unit's `Unit` interface with
    /// properties uncached, so each poll reflects the live state.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit is not loaded (`NoSuchUnit`) or the D-Bus
    /// property reads fail.
    async fn unit_active_sub(&self, name: &str) -> Result<(String, String)> {
        let path = self.manager.get_unit(name).await?;
        let unit = UnitProxy::builder(&self.conn)
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        Ok((unit.active_state().await?, unit.sub_state().await?))
    }
}

impl PinnedSystemdManager {
    /// Opens the host system bus and pins its current systemd manager owner.
    ///
    /// # Errors
    ///
    /// Returns an error if the system bus is unavailable or the manager cannot
    /// be identified, subscribed, and rechecked on the new connection.
    pub async fn connect() -> Result<Self> {
        SystemdManagerConnection::system().await?.pin().await
    }

    /// Pins the current systemd manager on a caller-supplied bus connection.
    ///
    /// The connection must be attached to a real D-Bus broker because manager
    /// identity uses the bus GUID and unique-name owner.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot be identified, subscribed, or
    /// rechecked on the supplied connection.
    pub async fn from_connection(conn: zbus::Connection) -> Result<Self> {
        let incarnation = read_manager_incarnation(&conn).await?;
        let manager = ManagerProxy::builder(&conn)
            .destination(incarnation.owner.clone())?
            .build()
            .await?;

        // Subscription state belongs to this bus connection and manager
        // process, not to the proxy object. Addressing Subscribe to the unique
        // owner proves which process accepted it and keeps replacement owners
        // outside this pin's signal stream.
        if let Err(error) = manager.subscribe().await
            && !is_already_subscribed(&error)
        {
            return Err(error.into());
        }

        let mut job_removed = manager.receive_job_removed().await?;
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let jobs_for_task = Arc::clone(&jobs);
        let job_task = tokio::spawn(async move {
            while let Some(signal) = job_removed.next().await {
                let Ok(args) = signal.args() else { continue };
                let path_key = args.job.as_str().to_owned();
                let result = JobResult::from_systemd(&args.result);
                route_pinned_completion(&jobs_for_task, path_key, result);
            }

            let mut registry = lock_pinned_registry(&jobs_for_task);
            registry.closed = true;
            registry.waiters.clear();
        });

        let pinned = Self {
            conn,
            incarnation,
            manager,
            jobs,
            job_task,
        };
        pinned.ensure_current().await?;
        Ok(pinned)
    }

    /// Returns the bus and manager identity held by this pin.
    #[must_use]
    pub fn incarnation(&self) -> &ManagerIncarnation {
        &self.incarnation
    }

    /// Starts a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager incarnation changed, the call fails, or
    /// the pinned signal stream closes before the job result arrives.
    pub async fn start_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.start_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Stops a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PinnedSystemdManager::start_unit`].
    pub async fn stop_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.stop_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Restarts a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PinnedSystemdManager::start_unit`].
    pub async fn restart_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.restart_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reloads a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PinnedSystemdManager::start_unit`].
    pub async fn reload_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.reload_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Starts one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is an alias, the unit object changed since
    /// admission, the manager incarnation changed, or the job does not complete.
    pub async fn start_unit_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.start("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Stops one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`].
    pub async fn stop_unit_exact(&self, name: &str, expected_identity: &str) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.stop("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Restarts one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`].
    pub async fn restart_unit_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.restart("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reloads one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`].
    pub async fn reload_unit_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.reload("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reports whether a unit is active according to the pinned owner.
    ///
    /// An unloaded unit is inactive.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager incarnation changed or the D-Bus
    /// inspection fails for a reason other than `NoSuchUnit`.
    pub async fn is_active(&self, name: &str) -> Result<bool> {
        self.ensure_current().await?;
        match self.manager.get_unit(name).await {
            Ok(path) => {
                let unit = UnitProxy::builder(&self.conn)
                    .destination(self.incarnation.owner.clone())?
                    .path(path)?
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await?;
                Ok(unit.active_state().await? == "active")
            }
            Err(error) if is_no_such_unit(&error) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Reports activity only after rechecking a canonical qualified unit identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`], plus failures
    /// while reading the unit's active state.
    pub async fn is_active_exact(&self, name: &str, expected_identity: &str) -> Result<bool> {
        Ok(self
            .active_state_exact(name, expected_identity)
            .await?
            .is_active())
    }

    /// Returns a unit's exact active state after rechecking its qualified identity.
    ///
    /// Unknown future systemd labels remain available through
    /// [`UnitActiveState::Unknown`] instead of being collapsed into inactivity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`], plus failures
    /// while reading the unit's active state.
    pub async fn active_state_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<UnitActiveState> {
        let unit = self.exact_unit(name, expected_identity).await?;
        Ok(UnitActiveState::from_systemd(&unit.active_state().await?))
    }

    /// Resolves a configured unit name to systemd's canonical object identity.
    ///
    /// The resolved object's canonical `Id` must equal `name`, so aliases are
    /// rejected before they can become durable resource bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager incarnation changed or the unit cannot
    /// be resolved by the pinned owner.
    pub async fn unit_identity(&self, name: &str) -> Result<String> {
        let (identity, canonical_name) = self.resolve_unit_identity(name).await?;
        if canonical_name != name {
            return Err(Error::UnitAlias {
                requested: name.to_string(),
                canonical: canonical_name,
            });
        }
        Ok(identity)
    }

    async fn exact_unit<'a>(
        &'a self,
        name: &str,
        expected_identity: &str,
    ) -> Result<UnitProxy<'a>> {
        self.ensure_current().await?;
        let path = self.manager.get_unit(name).await?;
        let actual = path.as_str().to_string();
        let unit = UnitProxy::builder(&self.conn)
            .destination(self.incarnation.owner.clone())?
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let canonical_name = unit.id().await?;
        if canonical_name != name {
            return Err(Error::UnitAlias {
                requested: name.to_string(),
                canonical: canonical_name,
            });
        }
        if actual != expected_identity {
            return Err(Error::UnitIdentityChanged {
                unit: name.to_string(),
                expected: expected_identity.to_string(),
                actual,
            });
        }
        Ok(unit)
    }

    async fn resolve_unit_identity(&self, name: &str) -> Result<(String, String)> {
        self.ensure_current().await?;
        let path = self.manager.get_unit(name).await?;
        let unit = UnitProxy::builder(&self.conn)
            .destination(self.incarnation.owner.clone())?
            .path(path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let canonical_name = unit.id().await?;
        Ok((path.as_str().to_string(), canonical_name))
    }

    async fn ensure_current(&self) -> Result<()> {
        if read_manager_incarnation(&self.conn).await? == self.incarnation {
            Ok(())
        } else {
            Err(Error::ManagerIncarnationChanged)
        }
    }

    fn begin_submission(&self) -> Result<PinnedSubmission> {
        PinnedSubmission::begin(&self.jobs)
    }

    async fn await_submission(
        &self,
        mut submission: PinnedSubmission,
        path: OwnedObjectPath,
    ) -> Result<JobOutcome> {
        let path_key = path.as_str().to_owned();
        let receiver = match submission.register(&path_key)? {
            PinnedRegistration::Completed(result) => {
                return Ok(JobOutcome {
                    job_path: path,
                    result,
                });
            }
            PinnedRegistration::Pending(receiver) => receiver,
        };
        let result = match receiver.await {
            Ok(result) => result,
            Err(_) if lock_pinned_registry(&self.jobs).overflowed => {
                return Err(Error::JobCompletionOverflow);
            }
            Err(_) => return Err(Error::JobSenderDropped(path.as_str().to_string())),
        };
        submission.finish();
        Ok(JobOutcome {
            job_path: path,
            result,
        })
    }
}

impl SystemdManagerConnection {
    /// Opens an explicit host system-bus capability without starting listeners.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SystemdUnavailable`] when the host system bus cannot be
    /// reached.
    pub async fn system() -> Result<Self> {
        let conn = zbus::Connection::system()
            .await
            .map_err(Error::SystemdUnavailable)?;
        Ok(Self { conn })
    }

    /// Wraps a caller-selected bus connection without changing its scope.
    #[must_use]
    pub const fn from_connection(conn: zbus::Connection) -> Self {
        Self { conn }
    }

    /// Pins the current manager on this exact connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot be identified, subscribed, or
    /// rechecked on the retained connection.
    pub async fn pin(&self) -> Result<PinnedSystemdManager> {
        PinnedSystemdManager::from_connection(self.conn.clone()).await
    }
}

impl Drop for PinnedSystemdManager {
    fn drop(&mut self) {
        self.job_task.abort();
    }
}

async fn read_manager_incarnation(conn: &zbus::Connection) -> Result<ManagerIncarnation> {
    let proxy = zbus::fdo::DBusProxy::new(conn).await?;
    let service =
        zbus::names::BusName::try_from("org.freedesktop.systemd1").map_err(zbus::Error::from)?;
    let bus = proxy.get_id().await?;
    let owner = proxy.get_name_owner(service).await?;
    Ok(ManagerIncarnation {
        bus_id: bus.to_string(),
        owner: owner.to_string(),
    })
}

fn is_already_subscribed(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _) if name.as_str() == SYSTEMD_ALREADY_SUBSCRIBED)
}

fn lock_pinned_registry(
    registry: &Mutex<PinnedJobRegistry>,
) -> std::sync::MutexGuard<'_, PinnedJobRegistry> {
    registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn route_pinned_completion(jobs: &Mutex<PinnedJobRegistry>, path_key: String, result: JobResult) {
    let mut registry = lock_pinned_registry(jobs);
    let waiters = registry.waiters.remove(&path_key).unwrap_or_default();
    for sender in waiters.into_values() {
        let _ = sender.send(result.clone());
    }

    if registry.active_submissions == 0 {
        return;
    }
    if registry.completed.contains_key(&path_key)
        || registry.completed.len() < PINNED_COMPLETION_LIMIT
    {
        registry.completed.insert(path_key, result);
        return;
    }

    registry.overflowed = true;
    registry.completed.clear();
    registry.waiters.clear();
}

impl Drop for SystemdClient {
    fn drop(&mut self) {
        // Stop the background listeners.
        for task in &self.tasks {
            task.abort();
        }
        // Best-effort Unsubscribe. Drop can't await, so spawn a detached,
        // time-boxed task (only if we're inside a runtime). The manager proxy
        // holds an Arc to the connection internals, keeping it alive long
        // enough for the call.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let manager = self.manager.clone();
            handle.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), manager.unsubscribe()).await;
            });
        }
        let _ = &self.conn;
    }
}

/// Capture `systemctl status --no-pager --full <unit>` for human display. This
/// is the *only* `systemctl` shell-out remaining after this spec lands —
/// D-Bus introspection of the journal would be substantial extra work and the
/// resulting text is for display only, never policy.
async fn systemctl_status(unit: &str) -> String {
    match tokio::process::Command::new("systemctl")
        .args(["status", "--no-pager", "--full", unit])
        .output()
        .await
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(e) => format!("(failed to capture `systemctl status {unit}`: {e})"),
    }
}

#[cfg(test)]
mod pinned_tests {
    use super::*;

    #[test]
    fn unrelated_early_completions_fail_closed_at_the_bound() {
        let jobs = Mutex::new(PinnedJobRegistry {
            active_submissions: 1,
            pending_calls: 1,
            ..PinnedJobRegistry::default()
        });

        for index in 0..PINNED_COMPLETION_LIMIT {
            route_pinned_completion(&jobs, format!("/unrelated/{index}"), JobResult::Done);
        }
        assert_eq!(
            lock_pinned_registry(&jobs).completed.len(),
            PINNED_COMPLETION_LIMIT
        );

        route_pinned_completion(&jobs, "/overflow".to_string(), JobResult::Done);
        let registry = lock_pinned_registry(&jobs);
        assert!(registry.overflowed);
        assert!(registry.completed.is_empty());
    }

    #[test]
    fn idle_pinned_registry_discards_unrelated_completions() {
        let jobs = Mutex::new(PinnedJobRegistry::default());

        route_pinned_completion(&jobs, "/unrelated/1".to_string(), JobResult::Done);

        assert!(lock_pinned_registry(&jobs).completed.is_empty());
    }

    #[test]
    fn never_completing_calls_are_bounded_across_registered_waiters() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut calls = Vec::with_capacity(PINNED_COMPLETION_LIMIT);

        for index in 0..PINNED_COMPLETION_LIMIT {
            let mut submission = PinnedSubmission::begin(&jobs).unwrap();
            let registration = submission.register(&format!("/job/{index}")).unwrap();
            assert!(matches!(registration, PinnedRegistration::Pending(_)));
            calls.push(submission);
        }

        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, PINNED_COMPLETION_LIMIT);
        assert_eq!(
            registry.waiters.values().map(BTreeMap::len).sum::<usize>(),
            PINNED_COMPLETION_LIMIT
        );
        drop(registry);
        assert!(matches!(
            PinnedSubmission::begin(&jobs),
            Err(Error::JobCompletionOverflow)
        ));

        drop(calls);
        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.waiters.is_empty());
    }

    #[test]
    fn dropping_an_awaiting_call_removes_its_waiter() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut submission = PinnedSubmission::begin(&jobs).unwrap();
        let registration = submission.register("/job/cancelled").unwrap();
        assert!(matches!(registration, PinnedRegistration::Pending(_)));
        assert_eq!(lock_pinned_registry(&jobs).pending_calls, 1);

        drop(submission);

        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.waiters.is_empty());
    }

    #[tokio::test]
    async fn duplicate_job_path_completion_wakes_every_waiter() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut first = PinnedSubmission::begin(&jobs).unwrap();
        let mut second = PinnedSubmission::begin(&jobs).unwrap();
        let PinnedRegistration::Pending(first_receiver) = first.register("/job/merged").unwrap()
        else {
            panic!("first call unexpectedly completed before a signal");
        };
        let PinnedRegistration::Pending(second_receiver) = second.register("/job/merged").unwrap()
        else {
            panic!("second call unexpectedly completed before a signal");
        };

        route_pinned_completion(&jobs, "/job/merged".to_string(), JobResult::Done);

        assert_eq!(first_receiver.await.unwrap(), JobResult::Done);
        assert_eq!(second_receiver.await.unwrap(), JobResult::Done);
        first.finish();
        second.finish();
        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.waiters.is_empty());
    }

    #[tokio::test]
    async fn merged_early_completion_reaches_a_later_method_reply() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut first = PinnedSubmission::begin(&jobs).unwrap();
        let mut second = PinnedSubmission::begin(&jobs).unwrap();
        let PinnedRegistration::Pending(first_receiver) = first.register("/job/merged").unwrap()
        else {
            panic!("first call unexpectedly completed before a signal");
        };

        route_pinned_completion(&jobs, "/job/merged".to_string(), JobResult::Done);

        let PinnedRegistration::Completed(second_result) = second.register("/job/merged").unwrap()
        else {
            panic!("early completion was not retained for the pending method reply");
        };
        assert_eq!(first_receiver.await.unwrap(), JobResult::Done);
        assert_eq!(second_result, JobResult::Done);
        first.finish();
        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.completed.is_empty());
        assert!(registry.waiters.is_empty());
    }
}
