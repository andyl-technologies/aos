//! Graceful shutdown (drain) coordination and build crash recovery.
//!
//! Two related concerns live here:
//!
//! - [`DrainState`] — shared flag-plus-notification used to coordinate
//!   graceful shutdown. When a SIGTERM/SIGINT arrives (see
//!   [`wait_for_shutdown_signal`]), the binary flips the drain flag; the
//!   HTTP build handlers then reject new builds with `503` while the build
//!   manager finishes in-flight work and finally signals completion.
//! - [`BuildState`] — a small JSON state file written per in-flight build
//!   (`views/{view}/builds/{drv-hash}.json`) so that builds interrupted by
//!   a crash can be discovered on the next startup via
//!   [`BuildState::scan_incomplete`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// Server drain state.
///
/// When drain is active, new build requests are rejected with `503` and the
/// server waits for in-flight builds to complete before shutting down. The
/// type is cheap to share behind an `Arc` and all methods take `&self`.
pub struct DrainState {
    draining: AtomicBool,
    shutdown_complete: Arc<Notify>,
}

impl DrainState {
    /// Creates a new drain state with draining inactive.
    pub fn new() -> Self {
        Self {
            draining: AtomicBool::new(false),
            shutdown_complete: Arc::new(Notify::new()),
        }
    }

    /// Enters drain mode.
    ///
    /// Returns `true` if this call initiated the drain, `false` if the
    /// server was already draining (the operation is idempotent).
    pub fn start_drain(&self) -> bool {
        let initiated = !self.draining.swap(true, Ordering::SeqCst);
        if initiated {
            tracing::info!("drain initiated");
        }
        initiated
    }

    /// Returns `true` if the server is currently draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Signals that all in-flight work is complete, waking every task
    /// blocked in [`wait_for_completion`](Self::wait_for_completion).
    pub fn signal_complete(&self) {
        tracing::info!("drain complete, all in-flight work finished");
        self.shutdown_complete.notify_waiters();
    }

    /// Waits for shutdown to complete, with a timeout.
    ///
    /// Returns `true` if [`signal_complete`](Self::signal_complete) fired
    /// within the timeout, `false` if the timeout elapsed first.
    pub async fn wait_for_completion(&self, timeout: Duration) -> bool {
        tokio::select! {
            _ = self.shutdown_complete.notified() => true,
            _ = tokio::time::sleep(timeout) => false,
        }
    }
}

/// Waits until a shutdown signal (SIGTERM or SIGINT) is received.
///
/// The binary awaits this future and then calls
/// [`DrainState::start_drain`] to begin graceful shutdown.
///
/// # Panics
///
/// Panics if the SIGTERM or SIGINT handler cannot be installed. This is
/// intentional: it only happens at startup, and the server cannot operate
/// safely without graceful-shutdown signal handling.
pub async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    // Signal handler registration is a hard requirement for graceful shutdown.
    // Panicking here during startup is intentional — the server cannot operate
    // safely without signal handling.
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }
}

/// Build state file for crash recovery.
///
/// One JSON file is written per in-flight build to
/// `views/{view}/builds/{drv-hash}.json` and removed once the build reaches
/// a terminal state. After an unclean shutdown,
/// [`scan_incomplete`](Self::scan_incomplete) finds builds that never
/// finished.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BuildState {
    /// Full store path of the derivation being built.
    pub drv: String,
    /// Name of the view the build was requested in.
    pub view: String,
    /// Unix timestamp when the build was queued.
    pub started_at: i64,
    /// Current phase: `"queued"`, `"building"`, `"complete"`, or `"failed"`.
    pub status: String, // "queued", "building", "complete", "failed"
    /// PID of the builder process, when known.
    pub pid: Option<u32>,
    /// Output store paths, populated on successful completion.
    pub outputs: Option<Vec<String>>,
}

impl BuildState {
    /// Creates a fresh state for `drv` in `view` with status `"queued"` and
    /// `started_at` set to now.
    pub fn new(drv: &str, view: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            drv: drv.to_string(),
            view: view.to_string(),
            started_at: now,
            status: "queued".to_string(),
            pid: None,
            outputs: None,
        }
    }

    /// Writes the build state atomically to disk (temp file + fsync +
    /// rename) under `{root}/views/{view}/builds/`.
    ///
    /// # Errors
    ///
    /// Returns an error if the builds directory cannot be created, the
    /// state cannot be serialized, or any filesystem step (write, sync,
    /// rename) fails.
    pub fn save(&self, root: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;

        let builds_dir = root.join("views").join(&self.view).join("builds");
        std::fs::create_dir_all(&builds_dir)?;

        let drv_hash = self.drv.rsplit('/').next().unwrap_or("unknown");
        let path = builds_dir.join(format!("{drv_hash}.json"));
        let tmp = builds_dir.join(format!(".{drv_hash}.json.tmp"));

        let data = serde_json::to_string_pretty(self)?;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;

        Ok(())
    }

    /// Removes the build state file after completion (best-effort; a
    /// missing file is not an error).
    pub fn remove(&self, root: &std::path::Path) {
        let drv_hash = self.drv.rsplit('/').next().unwrap_or("unknown");
        let path = root
            .join("views")
            .join(&self.view)
            .join("builds")
            .join(format!("{drv_hash}.json"));
        let _ = std::fs::remove_file(&path);
    }

    /// Scans for builds that were in-flight when the server last crashed.
    ///
    /// Walks `{root}/views/*/builds/*.json` and returns every state whose
    /// status is still `"queued"` or `"building"`. Unreadable or unparsable
    /// files are silently skipped.
    pub fn scan_incomplete(root: &std::path::Path) -> Vec<BuildState> {
        let mut results = Vec::new();
        let views_dir = root.join("views");

        if let Ok(views) = std::fs::read_dir(&views_dir) {
            for view_entry in views.flatten() {
                let builds_dir = view_entry.path().join("builds");
                if let Ok(builds) = std::fs::read_dir(&builds_dir) {
                    for build_entry in builds.flatten() {
                        let path = build_entry.path();
                        if path.extension().map(|e| e == "json").unwrap_or(false) {
                            if let Ok(data) = std::fs::read_to_string(&path) {
                                if let Ok(state) = serde_json::from_str::<BuildState>(&data) {
                                    if state.status == "building" || state.status == "queued" {
                                        results.push(state);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }
}
