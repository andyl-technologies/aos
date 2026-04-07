use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use aos_core::error::AosError;
use aos_core::output::Printer;
use aos_net::{
    HashAlgorithm, TransferEngine, TransferEngineConfig, TransferRequest,
};
use super::types::RegistryConfig;

// ---------------------------------------------------------------------------
// Request / result types
// ---------------------------------------------------------------------------

/// A NAR to download.
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub store_path: String,
    /// Hash of the uncompressed NAR: `"sha256:..."`. Used in the URL.
    pub nar_hash: String,
    /// SHA-256 of the compressed file: `"sha256:..."`.
    pub download_hash: String,
    /// Expected size of the compressed file in bytes.
    pub download_size: u64,
    /// Base mirror URL (e.g. `"https://cache.aos.dev/nar"`).
    pub mirror_url: String,
}

/// Result of a successful download.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub store_path: String,
    /// Path to the downloaded `.nar.zst` in the cache directory.
    pub local_path: PathBuf,
    /// SHA-256 of the compressed file (as verified).
    pub download_hash: String,
    /// Hash of the uncompressed NAR (passed through from the request).
    pub nar_hash: String,
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Construct the download URL for a NAR.
///
/// Format: `<mirror_url>/<nar_hash>.nar.zst`
///
/// The `nar_hash` is expected in `"sha256:<hex>"` format.  We use the full
/// string (including the `sha256:` prefix) in the filename so the URL is
/// unambiguous.
pub fn nar_url(mirror_url: &str, nar_hash: &str) -> String {
    let base = mirror_url.trim_end_matches('/');
    format!("{base}/{nar_hash}.nar.zst")
}

/// Determine the mirror URL for a package.
///
/// First checks the local registry clone for a `registry.toml` with
/// `[[caches]]` entries (sorted by priority). Falls back to the registry
/// URL with `/nar/` appended.
pub fn resolve_mirror(registry: &RegistryConfig) -> String {
    // Try to read caches from the local registry clone.
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    let registries_dir = std::path::PathBuf::from(&home)
        .join(".local/share/apm/registries")
        .join(&registry.name);

    let mirrors = crate::registry_ops::resolve_mirrors(&registries_dir);
    if let Some(cache) = mirrors.first() {
        return cache.url.clone();
    }

    // Fallback: derive from registry URL.
    let base = registry.url.trim_end_matches('/');
    format!("{base}/nar")
}

// ---------------------------------------------------------------------------
// Single-file download
// ---------------------------------------------------------------------------

/// Download a single NAR file with progress reporting and hash verification.
///
/// The downloaded file is written to `dest` (a `.nar.zst` path inside the
/// cache directory).  On success, the SHA-256 of the compressed file is
/// compared against `req.download_hash`.
async fn download_one(
    engine: &TransferEngine,
    req: &DownloadRequest,
    dest: &Path,
    _printer: &Printer,
) -> Result<DownloadResult> {
    let url = nar_url(&req.mirror_url, &req.nar_hash);
    let label = short_label(&req.store_path);

    // Strip the "sha256:" prefix from the download hash for verification.
    let expected_hex = req
        .download_hash
        .strip_prefix("sha256:")
        .unwrap_or(&req.download_hash);

    // Build a TransferRequest with hash verification.
    // The engine handles retry and hash checking automatically.
    let transfer_req = TransferRequest::get(&url)
        .with_hash(HashAlgorithm::Sha256, expected_hex);

    let pb = create_download_bar(req.download_size, &label);

    let result = engine.execute(transfer_req).await;

    pb.finish_and_clear();

    let result = result.with_context(|| format!("downloading {url}"))?;

    // Write the response body to the destination file.
    if let Some(body) = &result.body {
        tokio::fs::write(dest, body)
            .await
            .with_context(|| format!("writing to {}", dest.display()))?;
    } else {
        return Err(AosError::DownloadError {
            message: format!("no response body for {url}"),
        }
        .into());
    }

    Ok(DownloadResult {
        store_path: req.store_path.clone(),
        local_path: dest.to_path_buf(),
        download_hash: req.download_hash.clone(),
        nar_hash: req.nar_hash.clone(),
    })
}

// ---------------------------------------------------------------------------
// Parallel download engine
// ---------------------------------------------------------------------------

/// Create a default `TransferEngine` suitable for NAR downloads.
pub fn default_engine() -> TransferEngine {
    TransferEngine::new(TransferEngineConfig::default())
}

/// Download multiple NARs in parallel.
///
/// - Uses a semaphore to limit concurrency to `parallel` simultaneous
///   downloads.
/// - Shows per-file progress bars via indicatif.
/// - Downloads to `cache_dir`, creating it if necessary.
/// - Retries each download up to 3 times on transient errors (via the
///   engine's built-in retry logic).
pub async fn download_nars(
    requests: &[DownloadRequest],
    cache_dir: &Path,
    parallel: u32,
    printer: &Printer,
) -> Result<Vec<DownloadResult>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }

    // Ensure cache directory exists.
    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("creating cache directory {}", cache_dir.display()))?;

    printer.info(&format!(
        "Downloading {} NAR(s) ({} parallel)...",
        requests.len(),
        parallel,
    ));

    let semaphore = Arc::new(Semaphore::new(parallel as usize));
    let engine = Arc::new(default_engine());
    let mut handles = Vec::with_capacity(requests.len());

    for req in requests {
        // Build the destination filename from the nar_hash.
        let filename = nar_cache_filename(&req.nar_hash);
        let dest = cache_dir.join(&filename);

        let req = req.clone();
        let printer = printer.clone();
        let engine = Arc::clone(&engine);

        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("acquiring semaphore permit")?;

        let handle = tokio::spawn(async move {
            let result = download_one(&engine, &req, &dest, &printer).await;
            drop(permit);
            result
        });

        handles.push(handle);
    }

    // Collect results, failing fast on the first error.
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        let result = handle
            .await
            .context("download task panicked")??;
        results.push(result);
    }

    printer.success(&format!(
        "Downloaded {} NAR(s) to {}",
        results.len(),
        cache_dir.display(),
    ));

    Ok(results)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a cache filename from a NAR hash.
///
/// Input:  `"sha256:abcdef0123456789..."`
/// Output: `"sha256-abcdef0123456789....nar.zst"`
fn nar_cache_filename(nar_hash: &str) -> String {
    // Replace the colon with a dash for filesystem safety.
    let safe = nar_hash.replace(':', "-");
    format!("{safe}.nar.zst")
}

/// Extract a short label from a store path for progress display.
///
/// Input:  `"/var/lib/store/abc123...-curl-8.5.0"`
/// Output: `"curl-8.5.0"`
fn short_label(store_path: &str) -> String {
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

/// Create an indicatif progress bar for a download.
fn create_download_bar(total: u64, label: &str) -> ProgressBar {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nar_url_basic() {
        let url = nar_url("https://cache.aos.dev/nar", "sha256:abc123def456");
        assert_eq!(url, "https://cache.aos.dev/nar/sha256:abc123def456.nar.zst");
    }

    #[test]
    fn test_nar_url_trailing_slash() {
        let url = nar_url("https://cache.aos.dev/nar/", "sha256:abc123");
        assert_eq!(url, "https://cache.aos.dev/nar/sha256:abc123.nar.zst");
    }

    #[test]
    fn test_nar_url_no_path() {
        let url = nar_url("https://cache.aos.dev", "sha256:deadbeef");
        assert_eq!(url, "https://cache.aos.dev/sha256:deadbeef.nar.zst");
    }

    #[test]
    fn test_resolve_mirror() {
        let reg = RegistryConfig {
            name: "aos-core".into(),
            url: "https://registry.aos.dev/core".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            tag: None,
            version: None,
            pin: None,
            signing: None,
        };
        assert_eq!(resolve_mirror(&reg), "https://registry.aos.dev/core/nar");
    }

    #[test]
    fn test_resolve_mirror_trailing_slash() {
        let reg = RegistryConfig {
            name: "test".into(),
            url: "https://registry.aos.dev/core/".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            tag: None,
            version: None,
            pin: None,
            signing: None,
        };
        assert_eq!(resolve_mirror(&reg), "https://registry.aos.dev/core/nar");
    }

    #[test]
    fn test_nar_cache_filename() {
        let filename = nar_cache_filename("sha256:abcdef0123456789");
        assert_eq!(filename, "sha256-abcdef0123456789.nar.zst");
    }

    #[test]
    fn test_nar_cache_filename_no_colon() {
        let filename = nar_cache_filename("sha256-already");
        assert_eq!(filename, "sha256-already.nar.zst");
    }

    #[test]
    fn test_short_label_full_store_path() {
        // Nix store path hashes are 32 characters of base32 + a dash separator.
        let label =
            short_label("/var/lib/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-curl-8.5.0");
        assert_eq!(label, "curl-8.5.0");
    }

    #[test]
    fn test_short_label_short_path() {
        let label = short_label("short");
        assert_eq!(label, "short");
    }

    #[test]
    fn test_short_label_just_basename() {
        let label = short_label("/some/path/x");
        assert_eq!(label, "x");
    }

    #[test]
    fn test_download_request_fields() {
        let req = DownloadRequest {
            store_path: "/var/lib/store/abc123-curl-8.5.0".into(),
            nar_hash: "sha256:aabbccdd".into(),
            download_hash: "sha256:11223344".into(),
            download_size: 5242880,
            mirror_url: "https://cache.aos.dev/nar".into(),
        };
        assert_eq!(req.download_size, 5242880);
        assert_eq!(
            nar_url(&req.mirror_url, &req.nar_hash),
            "https://cache.aos.dev/nar/sha256:aabbccdd.nar.zst"
        );
    }

    #[tokio::test]
    async fn test_download_nars_empty() {
        let printer = Printer::new(0, true, false);
        let tmp = tempfile::TempDir::new().unwrap();

        let results = download_nars(&[], tmp.path(), 4, &printer)
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_download_result_fields() {
        let result = DownloadResult {
            store_path: "/var/lib/store/abc123-curl-8.5.0".into(),
            local_path: PathBuf::from("/tmp/test.nar.zst"),
            download_hash: "sha256:aabbccdd".into(),
            nar_hash: "sha256:eeff0011".into(),
        };
        assert_eq!(result.store_path, "/var/lib/store/abc123-curl-8.5.0");
        assert_eq!(result.local_path, PathBuf::from("/tmp/test.nar.zst"));
    }
}
