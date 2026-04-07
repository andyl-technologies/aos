//! Progress bar helpers (indicatif wrappers).
//!
//! Shared progress bar creation patterns used by download, upload, and
//! other network operations.

use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

/// Create a progress bar for tracking individual file downloads/uploads.
///
/// Shows: spinner, label, progress bar, bytes transferred, and transfer speed.
pub fn create_transfer_bar(total: u64, label: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.cyan} {msg} [{bar:20.cyan/dim}] {bytes}/{total_bytes} ({bytes_per_sec})")
            .expect("valid download bar template")
            .progress_chars("=> "),
    );
    pb.set_message(label.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

/// Create an overall progress bar for batch operations.
///
/// Shows: message, progress bar, position/total count.
pub fn create_overall_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:30.cyan/dim}] {pos}/{len}")
            .expect("valid template")
            .progress_chars("=> "),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a new `MultiProgress` container for grouping progress bars.
pub fn create_multi_progress() -> MultiProgress {
    MultiProgress::new()
}

/// Extract a short label from a store path for progress display.
///
/// Input:  `"/var/lib/store/abc123...-curl-8.5.0"`
/// Output: `"curl-8.5.0"`
pub fn short_label(store_path: &str) -> String {
    store_path
        .rsplit('/')
        .next()
        .and_then(|basename| {
            // Strip the hash prefix (32 chars + dash).
            if basename.len() > 33 {
                Some(basename[33..].to_string())
            } else {
                Some(basename.to_string())
            }
        })
        .unwrap_or_else(|| store_path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_label_full_store_path() {
        let label =
            short_label("/var/lib/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-curl-8.5.0");
        assert_eq!(label, "curl-8.5.0");
    }

    #[test]
    fn short_label_short_path() {
        let label = short_label("short");
        assert_eq!(label, "short");
    }

    #[test]
    fn short_label_just_basename() {
        let label = short_label("/some/path/x");
        assert_eq!(label, "x");
    }
}
