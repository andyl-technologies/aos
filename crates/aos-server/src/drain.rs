use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

/// Server drain state. When drain is active, new build requests
/// are rejected with 503 and the server waits for in-flight builds
/// to complete before shutting down.
pub struct DrainState {
    draining: AtomicBool,
    shutdown_complete: Arc<Notify>,
}

impl DrainState {
    pub fn new() -> Self {
        Self {
            draining: AtomicBool::new(false),
            shutdown_complete: Arc::new(Notify::new()),
        }
    }

    /// Enter drain mode. Returns true if this call initiated the drain.
    pub fn start_drain(&self) -> bool {
        let initiated = !self.draining.swap(true, Ordering::SeqCst);
        if initiated {
            tracing::info!("drain initiated");
        }
        initiated
    }

    /// Check if the server is currently draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Signal that all in-flight work is complete.
    pub fn signal_complete(&self) {
        tracing::info!("drain complete, all in-flight work finished");
        self.shutdown_complete.notify_waiters();
    }

    /// Wait for shutdown to complete, with a timeout.
    /// Returns true if shutdown completed within the timeout.
    pub async fn wait_for_completion(&self, timeout: Duration) -> bool {
        tokio::select! {
            _ = self.shutdown_complete.notified() => true,
            _ = tokio::time::sleep(timeout) => false,
        }
    }
}

/// Install a SIGTERM handler that initiates drain mode.
/// Returns a future that resolves when the signal is received.
pub async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    // Signal handler registration is a hard requirement for graceful shutdown.
    // Panicking here during startup is intentional — the server cannot operate
    // safely without signal handling.
    let mut sigterm = signal(SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt())
        .expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }
}

/// Build state file for crash recovery.
/// Written to `views/{view}/builds/{drv-hash}.json`.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BuildState {
    pub drv: String,
    pub view: String,
    pub started_at: i64,
    pub status: String,    // "queued", "building", "complete", "failed"
    pub pid: Option<u32>,
    pub outputs: Option<Vec<String>>,
}

impl BuildState {
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

    /// Write build state atomically to disk.
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

    /// Remove build state file after completion.
    pub fn remove(&self, root: &std::path::Path) {
        let drv_hash = self.drv.rsplit('/').next().unwrap_or("unknown");
        let path = root.join("views").join(&self.view).join("builds").join(format!("{drv_hash}.json"));
        let _ = std::fs::remove_file(&path);
    }

    /// Scan for builds that were in-flight when the server last crashed.
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
