//! Build execution, deduplication, and event streaming.
//!
//! [`BuildManager`] is the heart of the server's build path. For each
//! requested derivation it runs `nix-store --realise` exactly once, no
//! matter how many clients ask ([`BuildManager::get_or_start`] dedupes by
//! drv path), throttled by a per-view concurrency semaphore.
//!
//! Each build owns a [`BuildHandle`] that fans progress out to observers:
//!
//! - a `tokio::sync::broadcast` channel carries live [`BuildEvent`]s, and
//! - a [`LogBuffer`] ring buffer retains recent events so late joiners and
//!   SSE reconnections (`Last-Event-ID`) can replay history.
//!
//! Events ([`BuildEventKind`]) cover queueing, log lines (split on both
//! `\n` and `\r` so Nix progress output renders live), terminal
//! completion/error, daemon-unavailable retries (exponential backoff, up
//! to 3 attempts), and drain notifications. On success the manager roots
//! the output closure in the view (`bin/` namespace), removes the
//! temporary upload roots, and optionally mirrors source inputs; finished
//! handles linger for five minutes so reconnecting clients can still fetch
//! the outcome.
//!
//! The HTTP/SSE surface for these events lives in [`crate::routes`]; the
//! ConnectRPC surface is in [`crate::services`].

use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{Notify, Semaphore, broadcast};

use aos_core::nix::aos_nix_env;

use crate::drain::BuildState;
use crate::routes::AppState;

/// A single progress event for a build.
#[derive(Debug, Clone)]
pub struct BuildEvent {
    /// Monotonically increasing, per-build sequence number. Doubles as the
    /// SSE event id so clients can resume with `Last-Event-ID`.
    pub id: u64,
    /// The event payload.
    pub kind: BuildEventKind,
}

/// The payload of a [`BuildEvent`].
#[derive(Debug, Clone)]
pub enum BuildEventKind {
    /// Build phase transition (`queued` -> `building`).
    Status {
        /// Phase name: `"queued"` or `"building"`.
        phase: String,
        /// Derivation being built.
        drv: String,
    },
    /// One line of builder output (from `nix-store --realise` stderr).
    Log {
        /// The log line, without its trailing newline.
        line: String,
    },
    /// Terminal event: the build finished successfully.
    Complete {
        /// Always `true` (failures are reported as [`Error`](Self::Error)).
        success: bool,
        /// Output store paths of the derivation.
        outputs: Vec<String>,
        /// Wall-clock build duration in seconds.
        duration_secs: u64,
    },
    /// Terminal event: the build failed.
    Error {
        /// Derivation that failed.
        drv: String,
        /// Builder exit code, when the process ran to completion.
        exit_code: Option<i32>,
        /// Last lines of builder output (up to 50) for diagnosis.
        log_tail: String,
    },
    /// The Nix daemon could not be reached; the server is retrying with
    /// exponential backoff.
    DaemonUnavailable {
        /// Current attempt number (1-based).
        attempt: u32,
        /// Total number of attempts that will be made.
        max_attempts: u32,
        /// Human-readable description of the failure.
        message: String,
    },
    /// The server has entered drain mode and is shutting down.
    Drain {
        /// Human-readable drain notice.
        message: String,
    },
}

impl BuildEvent {
    /// Formats the event as an SSE text frame:
    /// `id: N\nevent: type\ndata: ...\n\n`.
    ///
    /// The `data` payload is JSON for structured events and the raw line
    /// for [`BuildEventKind::Log`] / [`BuildEventKind::Drain`].
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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_sse_event(kind: BuildEventKind, event_type: &str) {
        let frame = BuildEvent { id: 7, kind }.to_sse();
        assert!(frame.starts_with("id: 7\n"));
        assert!(frame.contains(&format!("event: {event_type}\n")));
        assert!(frame.contains("data: "));
        assert!(frame.ends_with("\n\n"));
    }

    #[test]
    fn sse_frames_cover_every_internal_build_activity_type() {
        assert_sse_event(
            BuildEventKind::Status {
                phase: "queued".into(),
                drv: "/nix/store/example.drv".into(),
            },
            "status",
        );
        assert_sse_event(
            BuildEventKind::Log {
                line: "building".into(),
            },
            "log",
        );
        assert_sse_event(
            BuildEventKind::Complete {
                success: true,
                outputs: vec!["/nix/store/out".into()],
                duration_secs: 3,
            },
            "complete",
        );
        assert_sse_event(
            BuildEventKind::Error {
                drv: "/nix/store/bad.drv".into(),
                exit_code: Some(42),
                log_tail: "failed".into(),
            },
            "error",
        );
        assert_sse_event(
            BuildEventKind::DaemonUnavailable {
                attempt: 2,
                max_attempts: 3,
                message: "daemon unavailable".into(),
            },
            "daemon-unavailable",
        );
        assert_sse_event(
            BuildEventKind::Drain {
                message: "server shutting down".into(),
            },
            "drain",
        );
    }

    #[test]
    fn log_record_drain_splits_newlines_and_carriage_returns() {
        let mut pending = Vec::new();

        let first = drain_log_records(&mut pending, b"copying path\rbuilding");
        assert_eq!(first, vec!["copying path"]);
        assert_eq!(pending, b"building");

        let second = drain_log_records(&mut pending, b" package\nfinished\r\n");
        assert_eq!(second, vec!["building package", "finished"]);
        assert!(pending.is_empty());
    }

    #[test]
    fn log_record_drain_flushes_large_records_without_delimiters() {
        let mut pending = Vec::new();
        let chunk = vec![b'x'; MAX_PENDING_LOG_BYTES];

        let records = drain_log_records(&mut pending, &chunk);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), MAX_PENDING_LOG_BYTES);
        assert!(pending.is_empty());
    }
}

/// Ring buffer for replay of build events to late joiners.
///
/// Caps at `MAX_LOG_EVENTS`; oldest events are dropped when full. Clients
/// that connect (or reconnect) after a build has started read history from
/// here before switching to the live broadcast channel.
pub struct LogBuffer {
    events: RwLock<VecDeque<BuildEvent>>,
}

/// Maximum number of events retained in the log replay buffer.
/// Oldest events are dropped when this limit is reached.
const MAX_LOG_EVENTS: usize = 100_000;

/// Maximum bytes a delimiter-less log record may accumulate before being
/// flushed as a single oversized record.
const MAX_PENDING_LOG_BYTES: usize = 16 * 1024;

impl LogBuffer {
    /// Creates an empty buffer.
    fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(1024)),
        }
    }

    /// Appends an event, evicting the oldest entry when at capacity.
    /// A poisoned lock drops the event with a warning instead of panicking.
    fn append(&self, event: BuildEvent) {
        let Ok(mut events) = self.events.write() else {
            tracing::warn!("log buffer write lock poisoned, dropping event");
            return;
        };
        if events.len() >= MAX_LOG_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Returns all buffered events with `id >= start_id`, in order.
    ///
    /// Uses binary search over the ring buffer's contiguous slices (event
    /// IDs are monotonically increasing). Pass `0` to replay everything
    /// still retained. Returns an empty vector if the lock is poisoned.
    pub fn events_from(&self, start_id: u64) -> Vec<BuildEvent> {
        let Ok(events) = self.events.read() else {
            tracing::warn!("log buffer read lock poisoned, returning empty");
            return Vec::new();
        };
        // Binary search on the contiguous slices since IDs are monotonically increasing.
        let (front, back) = events.as_slices();
        let skip_front = front.partition_point(|e| e.id < start_id);
        if skip_front < front.len() {
            front[skip_front..]
                .iter()
                .chain(back.iter())
                .cloned()
                .collect()
        } else {
            let skip_back = back.partition_point(|e| e.id < start_id);
            back[skip_back..].to_vec()
        }
    }

    /// Returns a snapshot of every buffered event, in order.
    /// Returns an empty vector if the lock is poisoned.
    pub fn all_events(&self) -> Vec<BuildEvent> {
        let Ok(events) = self.events.read() else {
            tracing::warn!("log buffer read lock poisoned, returning empty");
            return Vec::new();
        };
        events.iter().cloned().collect()
    }
}

/// Handle to an active or recently-completed build.
///
/// Observers subscribe to `tx` for live events and read `log_buffer` for
/// history; the combination gives gap-free replay (see
/// [`LogBuffer::events_from`]).
pub struct BuildHandle {
    /// Derivation this handle's build realises.
    pub drv_path: String,
    /// Broadcast channel carrying live build events.
    pub tx: broadcast::Sender<BuildEvent>,
    /// Replay buffer of all events emitted so far (bounded).
    pub log_buffer: Arc<LogBuffer>,
    /// Notified once when the build reaches a terminal state.
    pub done: Arc<Notify>,
    next_id: AtomicU64,
}

impl BuildHandle {
    /// Creates a handle with a fresh broadcast channel and empty buffer.
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

    /// Allocates the next per-build event sequence number.
    fn next_event_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Records an event in the replay buffer and broadcasts it to live
    /// subscribers (a send failure just means nobody is listening).
    fn emit(&self, kind: BuildEventKind) {
        let event = BuildEvent {
            id: self.next_event_id(),
            kind,
        };
        self.log_buffer.append(event.clone());
        let _ = self.tx.send(event);
    }
}

/// Records a builder log line both in the in-memory tail (used for error
/// reporting) and as a broadcast [`BuildEventKind::Log`] event.
fn record_log_line(handle: &BuildHandle, log_lines: &mut Vec<String>, line: String) {
    log_lines.push(line.clone());
    handle.emit(BuildEventKind::Log { line });
}

/// Splits a raw stderr chunk into complete log records.
///
/// Records are delimited by `\n`, `\r`, or `\r\n` — Nix progress output
/// uses bare carriage returns, so newline-only splitting would hide
/// progress until the build exits. Incomplete trailing bytes are kept in
/// `pending` for the next chunk; if `pending` grows past
/// `MAX_PENDING_LOG_BYTES` without a delimiter it is flushed as one
/// oversized record.
fn drain_log_records(pending: &mut Vec<u8>, chunk: &[u8]) -> Vec<String> {
    pending.extend_from_slice(chunk);

    let mut records = Vec::new();
    let mut start = 0;
    let mut idx = 0;

    while idx < pending.len() {
        let byte = pending[idx];
        if byte == b'\n' || byte == b'\r' {
            records.push(String::from_utf8_lossy(&pending[start..idx]).into_owned());
            idx += 1;
            if byte == b'\r' && idx < pending.len() && pending[idx] == b'\n' {
                idx += 1;
            }
            start = idx;
        } else {
            idx += 1;
        }
    }

    if start > 0 {
        pending.drain(..start);
    }

    if pending.len() >= MAX_PENDING_LOG_BYTES {
        records.push(String::from_utf8_lossy(pending).into_owned());
        pending.clear();
    }

    records
}

/// Streams the builder's stderr to completion, emitting each record as a
/// log event. Any unterminated tail is flushed as a final record at EOF.
async fn stream_build_stderr<R>(
    mut stderr: R,
    handle: &BuildHandle,
    log_lines: &mut Vec<String>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut pending = Vec::new();
    let mut buf = [0_u8; 8192];

    loop {
        let read = stderr.read(&mut buf).await?;
        if read == 0 {
            break;
        }

        for line in drain_log_records(&mut pending, &buf[..read]) {
            record_log_line(handle, log_lines, line);
        }
    }

    if !pending.is_empty() {
        record_log_line(
            handle,
            log_lines,
            String::from_utf8_lossy(&pending).into_owned(),
        );
    }

    Ok(())
}

/// Returns a `nix-store` command pre-populated with the AOS Nix
/// environment (store root, daemon socket, etc.).
fn nix_store_command() -> Command {
    let mut command = Command::new("nix-store");
    command.envs(aos_nix_env());
    command
}

/// Manages active builds with deduplication and per-view concurrency
/// limits.
///
/// One instance is shared across the whole server (in
/// [`crate::routes::AppState`]). See the [module docs](self) for the
/// overall lifecycle.
pub struct BuildManager {
    /// drv_path -> active build handle.
    builds: RwLock<HashMap<String, Arc<BuildHandle>>>,
    /// Per-view build concurrency semaphore.
    semaphores: RwLock<HashMap<String, Arc<Semaphore>>>,
    /// Number of in-flight builds (for drain coordination).
    active_count: AtomicU64,
}

impl BuildManager {
    /// Creates an empty manager with no active builds.
    pub fn new() -> Self {
        Self {
            builds: RwLock::new(HashMap::new()),
            semaphores: RwLock::new(HashMap::new()),
            active_count: AtomicU64::new(0),
        }
    }

    /// Returns the semaphore for a view, creating it with `max` permits on
    /// first use. The permit count is fixed at creation; later config
    /// changes do not resize an existing semaphore.
    fn view_semaphore(&self, view: &str, max: u32) -> Arc<Semaphore> {
        {
            let Ok(sems) = self.semaphores.read() else {
                tracing::warn!("semaphore lock poisoned, creating ephemeral semaphore");
                return Arc::new(Semaphore::new(max as usize));
            };
            if let Some(s) = sems.get(view) {
                return Arc::clone(s);
            }
        }
        let Ok(mut sems) = self.semaphores.write() else {
            tracing::warn!("semaphore lock poisoned, creating ephemeral semaphore");
            return Arc::new(Semaphore::new(max as usize));
        };
        Arc::clone(
            sems.entry(view.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(max as usize))),
        )
    }

    /// Returns an existing build handle for this drv, or starts a new
    /// build.
    ///
    /// If a build for `drv_path` is already running (or recently finished
    /// and not yet cleaned up), its handle is returned and no new process
    /// is spawned — concurrent requests for the same derivation share one
    /// build. Otherwise the build task is spawned in the background and a
    /// fresh handle returned. The caller subscribes to the handle's
    /// broadcast channel and replays from its log buffer.
    pub fn get_or_start(
        self: &Arc<Self>,
        state: &Arc<AppState>,
        view: &str,
        drv_path: &str,
    ) -> Arc<BuildHandle> {
        // Check for existing build.
        {
            let Ok(builds) = self.builds.read() else {
                tracing::warn!("builds lock poisoned, starting fresh build handle");
                return Arc::new(BuildHandle::new(drv_path.to_string()));
            };
            if let Some(handle) = builds.get(drv_path) {
                tracing::debug!(view = %view, drv = %drv_path, "build deduplicated, joining existing");
                return Arc::clone(handle);
            }
        }

        // Create a new build handle.
        let handle = Arc::new(BuildHandle::new(drv_path.to_string()));
        {
            let Ok(mut builds) = self.builds.write() else {
                tracing::warn!("builds lock poisoned, starting fresh build handle");
                return handle;
            };
            // Double-check after acquiring write lock.
            if let Some(existing) = builds.get(drv_path) {
                tracing::debug!(view = %view, drv = %drv_path, "build deduplicated, joining existing");
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

    /// Removes a completed build from the map (scheduled by
    /// `schedule_cleanup` after a delay so late joiners can still attach).
    fn remove_build(&self, drv_path: &str) {
        let Ok(mut builds) = self.builds.write() else {
            tracing::warn!("builds lock poisoned, cannot remove completed build");
            return;
        };
        builds.remove(drv_path);
    }

    /// Broadcasts a [`BuildEventKind::Drain`] event to all active builds,
    /// telling connected clients the server is shutting down.
    pub fn broadcast_drain(&self) {
        let Ok(builds) = self.builds.read() else {
            tracing::warn!("builds lock poisoned, cannot broadcast drain");
            return;
        };
        for handle in builds.values() {
            handle.emit(BuildEventKind::Drain {
                message: "server shutting down".to_string(),
            });
        }
    }
}

/// Executes a build end to end: acquires the per-view semaphore, runs
/// `nix-store --realise` (with daemon-unavailable retries), streams stderr
/// as log events, and on success roots the output closure in the view.
///
/// Always finishes by emitting a terminal event, persistently clearing the
/// crash-recovery [`BuildState`], notifying `handle.done`, and scheduling
/// removal of the handle. If the server is draining and this was the last
/// in-flight build, drain completion is signalled.
async fn run_build(
    mgr: &Arc<BuildManager>,
    state: &Arc<AppState>,
    view: &str,
    drv_path: &str,
    handle: &Arc<BuildHandle>,
) {
    let view_config = state.views.get_view(view);
    let max_concurrent = view_config.map(|v| v.max_concurrent_builds).unwrap_or(4);
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
    let _permit = match sem.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            tracing::error!(view = %view, drv = %drv_path, "build semaphore closed");
            handle.emit(BuildEventKind::Error {
                drv: drv_path.to_string(),
                exit_code: None,
                log_tail: "build semaphore closed".to_string(),
            });
            build_cleanup!(build_state, &root, mgr, state, "failed");
            handle.done.notify_waiters();
            schedule_cleanup(mgr, drv_path);
            return;
        }
    };

    tracing::info!(view = %view, drv = %drv_path, "build started");

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
            let mut child = match nix_store_command()
                .args(["--realise", drv_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) if attempt < MAX_DAEMON_RETRIES => {
                    tracing::warn!(view = %view, drv = %drv_path, attempt, max_attempts = MAX_DAEMON_RETRIES, error = %e, "daemon unavailable, retrying");
                    handle.emit(BuildEventKind::DaemonUnavailable {
                        attempt,
                        max_attempts: MAX_DAEMON_RETRIES,
                        message: format!("failed to spawn nix-store: {e}"),
                    });
                    tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
                    continue;
                }
                Err(e) => {
                    tracing::error!(view = %view, drv = %drv_path, error = %e, "build failed after all daemon retries");
                    handle.emit(BuildEventKind::Error {
                        drv: drv_path.to_string(),
                        exit_code: None,
                        log_tail: format!(
                            "failed to spawn nix-store after {MAX_DAEMON_RETRIES} attempts: {e}"
                        ),
                    });
                    build_cleanup!(build_state, &root, mgr, state, "failed");
                    handle.done.notify_waiters();
                    schedule_cleanup(mgr, drv_path);
                    return;
                }
            };

            // Stream stderr as log events. Nix progress output often uses
            // carriage returns, so newline-only readers can hide progress
            // until the build exits.
            let Some(stderr) = child.stderr.take() else {
                tracing::error!(view = %view, drv = %drv_path, "failed to capture stderr from nix-store");
                handle.emit(BuildEventKind::Error {
                    drv: drv_path.to_string(),
                    exit_code: None,
                    log_tail: "failed to capture stderr from nix-store".to_string(),
                });
                build_cleanup!(build_state, &root, mgr, state, "failed");
                handle.done.notify_waiters();
                schedule_cleanup(mgr, drv_path);
                return;
            };
            log_lines.clear();

            if let Err(e) = stream_build_stderr(stderr, handle, &mut log_lines).await {
                tracing::error!(view = %view, drv = %drv_path, error = %e, "failed reading nix-store stderr");
                handle.emit(BuildEventKind::Error {
                    drv: drv_path.to_string(),
                    exit_code: None,
                    log_tail: format!("reading nix-store stderr: {e}"),
                });
                build_cleanup!(build_state, &root, mgr, state, "failed");
                handle.done.notify_waiters();
                schedule_cleanup(mgr, drv_path);
                return;
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
                    tracing::warn!(view = %view, drv = %drv_path, attempt, "daemon connection error, retrying");
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

        // Every iteration of the loop either `continue`s (retry) or `break 'build exit`s.
        // The final iteration (attempt == MAX_DAEMON_RETRIES) always breaks or returns,
        // so this point is structurally unreachable.
        unreachable!("all loop iterations break or return")
    };

    let duration_secs = start.elapsed().as_secs();

    if !status.success() {
        tracing::error!(view = %view, drv = %drv_path, exit_code = ?status.code(), duration_secs, "build failed");

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

    tracing::debug!(view = %view, drv = %drv_path, closure_size = closure.len(), "creating GC roots");

    if let Err(e) = state.views.create_roots_for_closure(view, "bin", &closure) {
        tracing::error!(view = %view, drv = %drv_path, error = %e, "failed to create GC roots");
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

    // Clean up temporary GC roots now that proper bin/ roots exist.
    if let Err(e) = state.views.remove_tmp_roots(view) {
        tracing::warn!(view = %view, drv = %drv_path, error = %e, "failed to clean up tmp GC roots");
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

    tracing::info!(view = %view, drv = %drv_path, duration_secs, outputs = ?outputs, "build completed");

    handle.emit(BuildEventKind::Complete {
        success: true,
        outputs,
        duration_secs,
    });

    build_cleanup!(build_state, &root, mgr, state, "complete");
    handle.done.notify_waiters();
    schedule_cleanup(mgr, drv_path);
}

/// Schedules removal of a build handle after a 5-minute delay, giving
/// late reconnectors a window to replay the finished build's events.
fn schedule_cleanup(mgr: &Arc<BuildManager>, drv_path: &str) {
    let mgr = Arc::clone(mgr);
    let drv = drv_path.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        mgr.remove_build(&drv);
    });
}

/// Queries the output paths of a derivation via `nix-store -q --outputs`.
async fn query_outputs(drv_path: &str) -> Result<Vec<String>, String> {
    let output = nix_store_command()
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

/// Queries the runtime closure of a store path via `nix-store -qR`.
async fn query_closure(store_path: &str) -> Result<Vec<String>, String> {
    let output = nix_store_command()
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
