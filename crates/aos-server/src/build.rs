use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, Notify, Semaphore};

use crate::drain::BuildState;
use crate::routes::AppState;

/// A single SSE event for a build.
#[derive(Debug, Clone)]
pub struct BuildEvent {
    pub id: u64,
    pub kind: BuildEventKind,
}

#[derive(Debug, Clone)]
pub enum BuildEventKind {
    Status {
        phase: String,
        drv: String,
    },
    Log {
        line: String,
    },
    Complete {
        success: bool,
        outputs: Vec<String>,
        duration_secs: u64,
    },
    Error {
        drv: String,
        exit_code: Option<i32>,
        log_tail: String,
    },
    DaemonUnavailable {
        attempt: u32,
        max_attempts: u32,
        message: String,
    },
    Drain {
        message: String,
    },
}

impl BuildEvent {
    /// Format as an SSE text frame: `id: N\nevent: type\ndata: ...\n\n`
    pub fn to_sse(&self) -> String {
        let (event_type, data) = match &self.kind {
            BuildEventKind::Status { phase, drv } => (
                "status",
                serde_json::json!({"phase": phase, "drv": drv}).to_string(),
            ),
            BuildEventKind::Log { line } => ("log", line.clone()),
            BuildEventKind::Complete {
                success,
                outputs,
                duration_secs,
            } => (
                "complete",
                serde_json::json!({
                    "success": success,
                    "outputs": outputs,
                    "duration_secs": duration_secs,
                })
                .to_string(),
            ),
            BuildEventKind::Error {
                drv,
                exit_code,
                log_tail,
            } => (
                "error",
                serde_json::json!({
                    "success": false,
                    "drv": drv,
                    "exit_code": exit_code,
                    "log_tail": log_tail,
                })
                .to_string(),
            ),
            BuildEventKind::DaemonUnavailable {
                attempt,
                max_attempts,
                message,
            } => (
                "daemon-unavailable",
                serde_json::json!({
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "message": message,
                })
                .to_string(),
            ),
            BuildEventKind::Drain { message } => ("drain", message.clone()),
        };

        format!("id: {}\nevent: {event_type}\ndata: {data}\n\n", self.id)
    }
}

/// Ring buffer for replay of build events to late joiners.
/// Caps at `MAX_EVENTS`; oldest events are dropped when full.
pub struct LogBuffer {
    events: RwLock<VecDeque<BuildEvent>>,
}

const MAX_EVENTS: usize = 100_000;

impl LogBuffer {
    fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(1024)),
        }
    }

    fn append(&self, event: BuildEvent) {
        let mut events = self.events.write().unwrap();
        if events.len() >= MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Get all events from `start_id` onward.
    pub fn events_from(&self, start_id: u64) -> Vec<BuildEvent> {
        let events = self.events.read().unwrap();
        // Binary search on the contiguous slices since IDs are monotonically increasing.
        let (front, back) = events.as_slices();
        let skip_front = front.partition_point(|e| e.id < start_id);
        if skip_front < front.len() {
            front[skip_front..].iter().chain(back.iter()).cloned().collect()
        } else {
            let skip_back = back.partition_point(|e| e.id < start_id);
            back[skip_back..].to_vec()
        }
    }

    /// Get all events.
    pub fn all_events(&self) -> Vec<BuildEvent> {
        self.events.read().unwrap().iter().cloned().collect()
    }
}

/// Handle to an active or recently-completed build.
pub struct BuildHandle {
    pub drv_path: String,
    pub tx: broadcast::Sender<BuildEvent>,
    pub log_buffer: Arc<LogBuffer>,
    pub done: Arc<Notify>,
    next_id: AtomicU64,
}

impl BuildHandle {
    fn new(drv_path: String) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self {
            drv_path,
            tx,
            log_buffer: Arc::new(LogBuffer::new()),
            done: Arc::new(Notify::new()),
            next_id: AtomicU64::new(0),
        }
    }

    fn next_event_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn emit(&self, kind: BuildEventKind) {
        let event = BuildEvent {
            id: self.next_event_id(),
            kind,
        };
        self.log_buffer.append(event.clone());
        let _ = self.tx.send(event);
    }
}

/// Manages active builds with deduplication and per-view concurrency limits.
pub struct BuildManager {
    /// drv_path -> active build handle.
    builds: RwLock<HashMap<String, Arc<BuildHandle>>>,
    /// Per-view build concurrency semaphore.
    semaphores: RwLock<HashMap<String, Arc<Semaphore>>>,
    /// Number of in-flight builds (for drain coordination).
    active_count: AtomicU64,
}

impl BuildManager {
    pub fn new() -> Self {
        Self {
            builds: RwLock::new(HashMap::new()),
            semaphores: RwLock::new(HashMap::new()),
            active_count: AtomicU64::new(0),
        }
    }

    /// Get the semaphore for a view, creating it with `max` permits if needed.
    fn view_semaphore(&self, view: &str, max: u32) -> Arc<Semaphore> {
        {
            let sems = self.semaphores.read().unwrap();
            if let Some(s) = sems.get(view) {
                return Arc::clone(s);
            }
        }
        let mut sems = self.semaphores.write().unwrap();
        Arc::clone(
            sems.entry(view.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(max as usize))),
        )
    }

    /// Get an existing build handle for this drv, or start a new build.
    ///
    /// Returns the shared handle. The caller subscribes to its broadcast
    /// channel and replays from the log buffer.
    pub fn get_or_start(
        self: &Arc<Self>,
        state: &Arc<AppState>,
        view: &str,
        drv_path: &str,
    ) -> Arc<BuildHandle> {
        // Check for existing build.
        {
            let builds = self.builds.read().unwrap();
            if let Some(handle) = builds.get(drv_path) {
                return Arc::clone(handle);
            }
        }

        // Create a new build handle.
        let handle = Arc::new(BuildHandle::new(drv_path.to_string()));
        {
            let mut builds = self.builds.write().unwrap();
            // Double-check after acquiring write lock.
            if let Some(existing) = builds.get(drv_path) {
                return Arc::clone(existing);
            }
            builds.insert(drv_path.to_string(), Arc::clone(&handle));
        }

        // Spawn the build task.
        let mgr = Arc::clone(self);
        let state = Arc::clone(state);
        let view = view.to_string();
        let drv = drv_path.to_string();
        let handle_clone = Arc::clone(&handle);

        tokio::spawn(async move {
            run_build(&mgr, &state, &view, &drv, &handle_clone).await;
        });

        handle
    }

    /// Remove a completed build from the map (after a delay for late joiners).
    fn remove_build(&self, drv_path: &str) {
        let mut builds = self.builds.write().unwrap();
        builds.remove(drv_path);
    }

    /// Broadcast a drain event to all active builds.
    pub fn broadcast_drain(&self) {
        let builds = self.builds.read().unwrap();
        for handle in builds.values() {
            handle.emit(BuildEventKind::Drain {
                message: "server shutting down".to_string(),
            });
        }
    }
}

/// Execute a build: acquire semaphore, run nix-store --realise, emit events,
/// create GC roots on success.
async fn run_build(
    mgr: &Arc<BuildManager>,
    state: &Arc<AppState>,
    view: &str,
    drv_path: &str,
    handle: &Arc<BuildHandle>,
) {
    let view_config = state.views.get_view(view);
    let max_concurrent = view_config
        .map(|v| v.max_concurrent_builds)
        .unwrap_or(4);
    let sem = mgr.view_semaphore(view, max_concurrent);

    // Emit queued status.
    handle.emit(BuildEventKind::Status {
        phase: "queued".to_string(),
        drv: drv_path.to_string(),
    });

    let root = crate::aos_root();
    let mut build_state = BuildState::new(drv_path, view);
    let _ = build_state.save(&root);
    mgr.active_count.fetch_add(1, Ordering::Relaxed);

    /// Helper macro: clean up build state, decrement counter, signal drain if needed.
    macro_rules! build_cleanup {
        ($build_state:expr, $root:expr, $mgr:expr, $state:expr, $status:expr) => {{
            $build_state.status = $status.to_string();
            $build_state.remove($root);
            let remaining = $mgr.active_count.fetch_sub(1, Ordering::Relaxed) - 1;
            if $state.drain.is_draining() && remaining == 0 {
                $state.drain.signal_complete();
            }
        }};
    }

    // Acquire the per-view semaphore.
    let _permit = sem.acquire().await.expect("semaphore closed");

    handle.emit(BuildEventKind::Status {
        phase: "building".to_string(),
        drv: drv_path.to_string(),
    });

    build_state.status = "building".to_string();
    let _ = build_state.save(&root);

    let start = Instant::now();

    // Spawn nix-store --realise with retry on daemon connection errors.
    const MAX_DAEMON_RETRIES: u32 = 3;
    let mut log_lines = Vec::new();

    let status = 'build: {
        for attempt in 1..=MAX_DAEMON_RETRIES {
            let mut child = match Command::new("nix-store")
                .args(["--realise", drv_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) if attempt < MAX_DAEMON_RETRIES => {
                    handle.emit(BuildEventKind::DaemonUnavailable {
                        attempt,
                        max_attempts: MAX_DAEMON_RETRIES,
                        message: format!("failed to spawn nix-store: {e}"),
                    });
                    tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
                    continue;
                }
                Err(e) => {
                    handle.emit(BuildEventKind::Error {
                        drv: drv_path.to_string(),
                        exit_code: None,
                        log_tail: format!("failed to spawn nix-store after {MAX_DAEMON_RETRIES} attempts: {e}"),
                    });
                    build_cleanup!(build_state, &root, mgr, state, "failed");
                    handle.done.notify_waiters();
                    schedule_cleanup(mgr, drv_path);
                    return;
                }
            };

            // Stream stderr lines as log events.
            let stderr = child.stderr.take().unwrap();
            let mut lines = BufReader::new(stderr).lines();
            log_lines.clear();

            while let Ok(Some(line)) = lines.next_line().await {
                log_lines.push(line.clone());
                handle.emit(BuildEventKind::Log { line });
            }

            let exit = match child.wait().await {
                Ok(s) => s,
                Err(e) => {
                    handle.emit(BuildEventKind::Error {
                        drv: drv_path.to_string(),
                        exit_code: None,
                        log_tail: format!("waiting for nix-store: {e}"),
                    });
                    build_cleanup!(build_state, &root, mgr, state, "failed");
                    handle.done.notify_waiters();
                    schedule_cleanup(mgr, drv_path);
                    return;
                }
            };

            // Check for daemon connection errors (exit code 1 + stderr mentions connection).
            if !exit.success() {
                let stderr_text = log_lines.join("\n");
                let is_daemon_error = stderr_text.contains("error connecting to daemon")
                    || stderr_text.contains("Connection refused")
                    || stderr_text.contains("No such file or directory")
                        && stderr_text.contains("daemon-socket");

                if is_daemon_error && attempt < MAX_DAEMON_RETRIES {
                    handle.emit(BuildEventKind::DaemonUnavailable {
                        attempt,
                        max_attempts: MAX_DAEMON_RETRIES,
                        message: format!("daemon unavailable, retrying in {}s", 2u64.pow(attempt)),
                    });
                    tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
                    continue;
                }
            }

            break 'build exit;
        }

        // Should not reach here, but satisfy the type system.
        unreachable!()
    };

    let duration_secs = start.elapsed().as_secs();

    if !status.success() {
        let tail: String = log_lines
            .iter()
            .rev()
            .take(50)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        handle.emit(BuildEventKind::Error {
            drv: drv_path.to_string(),
            exit_code: status.code(),
            log_tail: tail,
        });
        build_cleanup!(build_state, &root, mgr, state, "failed");
        handle.done.notify_waiters();
        schedule_cleanup(mgr, drv_path);
        return;
    }

    // Query outputs separately.
    let outputs = match query_outputs(drv_path).await {
        Ok(paths) => paths,
        Err(e) => {
            handle.emit(BuildEventKind::Error {
                drv: drv_path.to_string(),
                exit_code: None,
                log_tail: format!("querying outputs: {e}"),
            });
            build_cleanup!(build_state, &root, mgr, state, "failed");
            handle.done.notify_waiters();
            schedule_cleanup(mgr, drv_path);
            return;
        }
    };

    // Query runtime closure and create GC roots.
    let mut closure = Vec::new();
    for out in &outputs {
        match query_closure(out).await {
            Ok(paths) => closure.extend(paths),
            Err(e) => {
                handle.emit(BuildEventKind::Error {
                    drv: drv_path.to_string(),
                    exit_code: None,
                    log_tail: format!("querying closure: {e}"),
                });
                build_cleanup!(build_state, &root, mgr, state, "failed");
                handle.done.notify_waiters();
                schedule_cleanup(mgr, drv_path);
                return;
            }
        }
    }

    closure.sort();
    closure.dedup();

    if let Err(e) = state
        .views
        .create_roots_for_closure(view, "bin", &closure)
    {
        handle.emit(BuildEventKind::Error {
            drv: drv_path.to_string(),
            exit_code: None,
            log_tail: format!("creating GC roots: {e}"),
        });
        build_cleanup!(build_state, &root, mgr, state, "failed");
        handle.done.notify_waiters();
        schedule_cleanup(mgr, drv_path);
        return;
    }

    // Create source roots if source_mirror is enabled for this view.
    if view_config.map(|v| v.source_mirror).unwrap_or(true) {
        let source_ttl = view_config.and_then(|v| v.source_ttl);
        if let Err(e) = state.views.create_source_roots(view, drv_path, source_ttl) {
            // Non-fatal: log but don't fail the build.
            handle.emit(BuildEventKind::Log {
                line: format!("warning: failed to create source roots: {e}"),
            });
        }
    }

    handle.emit(BuildEventKind::Complete {
        success: true,
        outputs,
        duration_secs,
    });

    build_cleanup!(build_state, &root, mgr, state, "complete");
    handle.done.notify_waiters();
    schedule_cleanup(mgr, drv_path);
}

/// Schedule removal of a build handle after a delay (allows late reconnectors).
fn schedule_cleanup(mgr: &Arc<BuildManager>, drv_path: &str) {
    let mgr = Arc::clone(mgr);
    let drv = drv_path.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        mgr.remove_build(&drv);
    });
}

/// Query the output paths of a derivation via `nix-store -q --outputs`.
async fn query_outputs(drv_path: &str) -> Result<Vec<String>, String> {
    let output = Command::new("nix-store")
        .args(["-q", "--outputs", drv_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("spawning nix-store -q --outputs: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nix-store -q --outputs failed: {stderr}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Query the runtime closure of a store path via `nix-store -qR`.
async fn query_closure(store_path: &str) -> Result<Vec<String>, String> {
    let output = Command::new("nix-store")
        .args(["-qR", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("spawning nix-store -qR: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nix-store -qR failed: {stderr}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}
