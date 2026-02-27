use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use aos::error::AosError;
use aos::output::Printer;
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
/// Uses the registry URL with `/nar/` appended as the mirror base.
/// Future versions will support an explicit `[[mirrors]]` list in the
/// registry config.
pub fn resolve_mirror(registry: &RegistryConfig) -> String {
    let base = registry.url.trim_end_matches('/');
    format!("{base}/nar")
}

// ---------------------------------------------------------------------------
// Single-file download
// ---------------------------------------------------------------------------

/// Maximum number of retry attempts per download.
const MAX_RETRIES: u32 = 3;

/// Base delay between retries (exponential backoff: delay * 2^attempt).
const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Download a single NAR file with progress reporting and hash verification.
///
/// The downloaded file is written to `dest` (a `.nar.zst` path inside the
/// cache directory).  On success, the SHA-256 of the compressed file is
/// compared against `req.download_hash`.
async fn download_one(
    client: &reqwest::Client,
    req: &DownloadRequest,
    dest: &Path,
    printer: &Printer,
) -> Result<DownloadResult> {
    let url = nar_url(&req.mirror_url, &req.nar_hash);
    let label = short_label(&req.store_path);

    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
            printer.info(&format!(
                "  retrying {label} (attempt {}/{MAX_RETRIES}) after {delay:?}",
                attempt + 1,
            ));
            tokio::time::sleep(delay).await;
        }

        match download_attempt(client, &url, dest, req.download_size, &label).await {
            Ok(actual_hash) => {
                // Verify download hash immediately.
                if actual_hash != req.download_hash {
                    // Not retryable — content mismatch.
                    return Err(AosError::HashMismatch {
                        expected: req.download_hash.clone(),
                        actual: actual_hash,
                    }
                    .into());
                }

                return Ok(DownloadResult {
                    store_path: req.store_path.clone(),
                    local_path: dest.to_path_buf(),
                    download_hash: actual_hash,
                    nar_hash: req.nar_hash.clone(),
                });
            }
            Err(e) => {
                // Classify: 4xx errors are not retryable.
                if is_permanent_error(&e) {
                    return Err(e);
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        AosError::DownloadError {
            message: format!("download failed after {MAX_RETRIES} attempts: {url}"),
        }
        .into()
    }))
}

/// Perform a single download attempt.  Returns the `"sha256:<hex>"` hash of
/// the downloaded file on success.
async fn download_attempt(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    expected_size: u64,
    label: &str,
) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("connecting to {url}"))?;

    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        return Err(AosError::DownloadError {
            message: format!("HTTP {status} for {url}"),
        }
        .into());
    }

    let total = response.content_length().unwrap_or(expected_size);
    let pb = create_download_bar(total, label);

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("creating {}", dest.display()))?;

    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading from {url}"))?
    {
        hasher.update(&chunk);
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .with_context(|| format!("writing to {}", dest.display()))?;
        downloaded += chunk.len() as u64;
        pb.set_position(downloaded);
    }

    pb.finish_and_clear();

    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    Ok(format!("sha256:{hex}"))
}

/// Check if an error represents a permanent (non-retryable) failure.
fn is_permanent_error(err: &anyhow::Error) -> bool {
    if let Some(aos_err) = err.downcast_ref::<AosError>() {
        if let AosError::DownloadError { message } = aos_err {
            // 4xx status codes are permanent.
            return message.contains("HTTP 4");
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Parallel download engine
// ---------------------------------------------------------------------------

/// Download multiple NARs in parallel.
///
/// - Uses a semaphore to limit concurrency to `parallel` simultaneous
///   downloads.
/// - Shows per-file progress bars via indicatif.
/// - Downloads to `cache_dir`, creating it if necessary.
/// - Retries each download up to 3 times on transient errors.
pub async fn download_nars(
    client: &reqwest::Client,
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
    let mut handles = Vec::with_capacity(requests.len());

    for req in requests {
        // Build the destination filename from the nar_hash.
        let filename = nar_cache_filename(&req.nar_hash);
        let dest = cache_dir.join(&filename);

        let client = client.clone();
        let req = req.clone();
        let printer = printer.clone();

        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("acquiring semaphore permit")?;

        let handle = tokio::spawn(async move {
            let result = download_one(&client, &req, &dest, &printer).await;
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
            pin: None,
            branch: None,
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
            pin: None,
            branch: None,
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
    fn test_is_permanent_error_4xx() {
        let err: anyhow::Error = AosError::DownloadError {
            message: "HTTP 404 for https://example.com/test.nar.zst".into(),
        }
        .into();
        assert!(is_permanent_error(&err));
    }

    #[test]
    fn test_is_permanent_error_5xx() {
        let err: anyhow::Error = AosError::DownloadError {
            message: "HTTP 503 for https://example.com/test.nar.zst".into(),
        }
        .into();
        assert!(!is_permanent_error(&err));
    }

    #[test]
    fn test_is_permanent_error_other() {
        let err = anyhow::anyhow!("connection refused");
        assert!(!is_permanent_error(&err));
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
        let client = reqwest::Client::new();
        let printer = Printer::new(0, true, false);
        let tmp = tempfile::TempDir::new().unwrap();

        let results = download_nars(&client, &[], tmp.path(), 4, &printer)
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
