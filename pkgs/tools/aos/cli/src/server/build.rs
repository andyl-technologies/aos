use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, Notify, Semaphore};

use crate::server::routes::AppState;

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
        };

        format!("id: {}\nevent: {event_type}\ndata: {data}\n\n", self.id)
    }
}

/// Append-only buffer for replay of build events to late joiners.
pub struct LogBuffer {
    events: RwLock<Vec<BuildEvent>>,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            events: RwLock::new(Vec::with_capacity(1024)),
        }
    }

    fn append(&self, event: BuildEvent) {
        let mut events = self.events.write().unwrap();
        events.push(event);
    }

    /// Get all events from `start_id` onward.
    pub fn events_from(&self, start_id: u64) -> Vec<BuildEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|e| e.id >= start_id)
            .cloned()
            .collect()
    }

    /// Get all events.
    pub fn all_events(&self) -> Vec<BuildEvent> {
        self.events.read().unwrap().clone()
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
    /// drv_path → active build handle.
    builds: RwLock<HashMap<String, Arc<BuildHandle>>>,
    /// Per-view build concurrency semaphore.
    semaphores: RwLock<HashMap<String, Arc<Semaphore>>>,
}

impl BuildManager {
    pub fn new() -> Self {
        Self {
            builds: RwLock::new(HashMap::new()),
            semaphores: RwLock::new(HashMap::new()),
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

    // Acquire the per-view semaphore.
    let _permit = sem.acquire().await.expect("semaphore closed");

    handle.emit(BuildEventKind::Status {
        phase: "building".to_string(),
        drv: drv_path.to_string(),
    });

    let start = Instant::now();

    // Spawn nix-store --realise.
    let mut child = match Command::new("nix-store")
        .args(["--realise", drv_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            handle.emit(BuildEventKind::Error {
                drv: drv_path.to_string(),
                exit_code: None,
                log_tail: format!("failed to spawn nix-store: {e}"),
            });
            handle.done.notify_waiters();
            schedule_cleanup(mgr, drv_path);
            return;
        }
    };

    // Stream stderr lines as log events.
    let stderr = child.stderr.take().unwrap();
    let mut lines = BufReader::new(stderr).lines();
    let mut log_lines = Vec::new();

    while let Ok(Some(line)) = lines.next_line().await {
        log_lines.push(line.clone());
        handle.emit(BuildEventKind::Log { line });
    }

    // Wait for the process to finish.
    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            handle.emit(BuildEventKind::Error {
                drv: drv_path.to_string(),
                exit_code: None,
                log_tail: format!("waiting for nix-store: {e}"),
            });
            handle.done.notify_waiters();
            schedule_cleanup(mgr, drv_path);
            return;
        }
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
        handle.done.notify_waiters();
        schedule_cleanup(mgr, drv_path);
        return;
    }

    // Read stdout for output paths (nix-store --realise prints them on success).
    // Since we consumed stdout, we need to read it. But we piped stdout too.
    // Actually we need to collect stdout. Let's query outputs separately.
    let outputs = match query_outputs(drv_path).await {
        Ok(paths) => paths,
        Err(e) => {
            handle.emit(BuildEventKind::Error {
                drv: drv_path.to_string(),
                exit_code: None,
                log_tail: format!("querying outputs: {e}"),
            });
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
        handle.done.notify_waiters();
        schedule_cleanup(mgr, drv_path);
        return;
    }

    handle.emit(BuildEventKind::Complete {
        success: true,
        outputs,
        duration_secs,
    });

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
