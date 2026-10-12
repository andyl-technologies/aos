//! Owns temporary recipe nodes and creates FIFOs through the existing SDK tool.

#![allow(clippy::unwrap_used, reason = "fixture failures are test assertions")]

use std::path::{Path, PathBuf};

/// Owns a unique temporary tree until its witness completes.
pub(super) struct Directory {
    /// Names the witness's private temporary root.
    pub(super) path: PathBuf,
}

impl Directory {
    /// Creates an independent temporary root.
    ///
    /// # Panics
    /// Panics if the temporary root cannot be created.
    pub(super) fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "terrane-ordinary-recipe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

/// Creates a real FIFO with the existing coreutils binding.
///
/// # Panics
/// Panics if the SDK tool is unavailable or FIFO creation fails.
pub(super) fn fifo(path: &Path) {
    assert!(
        std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}
