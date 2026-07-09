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

use crate::error::{Error, Result};
use crate::manager_proxy::{ListUnitsEntry, ManagerProxy, ServiceProxy, UnitProxy};

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

/// Whether a zbus error is systemd's `NoSuchUnit` method error.
fn is_no_such_unit(e: &zbus::Error) -> bool {
    matches!(e, zbus::Error::MethodError(name, _, _) if name.as_str().contains("NoSuchUnit"))
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
