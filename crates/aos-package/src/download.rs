use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use aos_core::error::AosError;
use aos_core::nar::info::{self as narinfo, NarInfo};
use aos_core::output::Printer;
use aos_net::{
    HashAlgorithm, TransferEngine, TransferEngineConfig, TransferRequest,
};
use super::types::RegistryConfig;

// ---------------------------------------------------------------------------
// Request / result types
// ---------------------------------------------------------------------------

/// A NAR to download. After Option A, this is just the store-path identity
/// and the cache base URL; everything else (URL on disk, file hash, size,
/// nar hash) comes from the narinfo fetched in `fetch_narinfos`.
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub store_path: String,
    /// Cache base URL — the prefix shared by `<base>/<storeHash>.narinfo`
    /// and `<base>/<narinfo.url>`. No `/nar` suffix.
    pub mirror_url: String,
}

/// A `DownloadRequest` paired with its fetched narinfo. Produced by
/// `fetch_narinfos`; consumed by `download_nars`.
#[derive(Debug, Clone)]
pub struct ResolvedDownload {
    pub req: DownloadRequest,
    pub narinfo: NarInfo,
}

/// Result of a successful download.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub store_path: String,
    /// Path to the downloaded `.nar.zst` in the cache directory.
    pub local_path: PathBuf,
    /// SHA-256 of the compressed file (from narinfo `FileHash`).
    pub download_hash: String,
    /// SHA-256 of the uncompressed NAR (from narinfo `NarHash`).
    pub nar_hash: String,
    /// Runtime references (from narinfo `References`). Needed to build the
    /// export trailer at import time.
    pub references: Vec<String>,
    /// Deriver (from narinfo `Deriver`), if any.
    pub deriver: Option<String>,
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Join a cache base URL with a path component.
///
/// Trims a trailing slash from `base` and a leading slash from `path` to
/// avoid `//` in the result. Used for both narinfo and NAR URLs.
pub fn join_cache_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/'),
    )
}

/// Build the narinfo URL for a store path.
pub fn narinfo_url(mirror_url: &str, store_path: &str) -> String {
    let store_hash = narinfo::store_hash(store_path);
    join_cache_url(mirror_url, &format!("{store_hash}.narinfo"))
}

/// Determine the cache base URL for a registry.
///
/// First checks the local registry clone for a `registry.toml` with
/// `[[caches]]` entries (sorted by priority). Falls back to the registry
/// URL itself. The returned value is a base — apm appends
/// `<storeHash>.narinfo` and the narinfo-supplied `URL:` field to it.
pub fn resolve_mirror(registry: &RegistryConfig) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    let registries_dir = std::path::PathBuf::from(&home)
        .join(".local/share/apm/registries")
        .join(&registry.name);

    let mirrors = crate::registry_ops::resolve_mirrors(&registries_dir);
    if let Some(cache) = mirrors.first() {
        return cache.url.trim_end_matches('/').to_string();
    }

    registry.url.trim_end_matches('/').to_string()
}

// ---------------------------------------------------------------------------
// Narinfo fetch
// ---------------------------------------------------------------------------

/// Fetch and parse the narinfo for each request in parallel.
///
/// Each GET hits `<mirror_url>/<storeHash>.narinfo`. The returned vector
/// preserves the input order. Fails fast on the first error.
pub async fn fetch_narinfos(
    engine: Arc<TransferEngine>,
    requests: &[DownloadRequest],
    parallel: u32,
    printer: &Printer,
) -> Result<Vec<ResolvedDownload>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }

    printer.info(&format!(
        "Fetching {} narinfo(s)...",
        requests.len(),
    ));

    let semaphore = Arc::new(Semaphore::new(parallel as usize));
    let mut handles = Vec::with_capacity(requests.len());

    for (idx, req) in requests.iter().enumerate() {
        let url = narinfo_url(&req.mirror_url, &req.store_path);
        let req_clone = req.clone();
        let engine = Arc::clone(&engine);
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("acquiring semaphore permit")?;

        let handle = tokio::spawn(async move {
            let result = fetch_one_narinfo(&engine, &url, &req_clone).await;
            drop(permit);
            result.map(|info| (idx, ResolvedDownload { req: req_clone, narinfo: info }))
        });

        handles.push(handle);
    }

    let mut buf: Vec<Option<ResolvedDownload>> = (0..requests.len()).map(|_| None).collect();
    for handle in handles {
        let (idx, resolved) = handle
            .await
            .context("narinfo task panicked")??;
        buf[idx] = Some(resolved);
    }

    Ok(buf.into_iter().map(|o| o.expect("all slots filled")).collect())
}

async fn fetch_one_narinfo(
    engine: &TransferEngine,
    url: &str,
    req: &DownloadRequest,
) -> Result<NarInfo> {
    let transfer_req = TransferRequest::get(url);
    let result = engine
        .execute(transfer_req)
        .await
        .with_context(|| format!("fetching {url}"))?;
    let body = result.body.ok_or_else(|| AosError::DownloadError {
        message: format!("no response body for {url}"),
    })?;
    let text = std::str::from_utf8(&body)
        .with_context(|| format!("narinfo body is not UTF-8: {url}"))?;
    narinfo::parse(text)
        .with_context(|| format!("parsing narinfo for {} from {url}", req.store_path))
}

// ---------------------------------------------------------------------------
// Single-file download
// ---------------------------------------------------------------------------

/// Download a single NAR file with progress reporting and hash verification.
async fn download_one(
    engine: &TransferEngine,
    resolved: &ResolvedDownload,
    dest: &Path,
    _printer: &Printer,
) -> Result<DownloadResult> {
    let url = join_cache_url(&resolved.req.mirror_url, &resolved.narinfo.url);
    let label = short_label(&resolved.req.store_path);

    // FileHash is authoritative for the compressed stream when the cache
    // emits a compressed NAR. AOS-server populates it unconditionally;
    // a missing FileHash on a compressed NAR is a server bug we want to
    // catch loudly rather than silently skip.
    let file_hash = match (&resolved.narinfo.file_hash, resolved.narinfo.compression.as_str()) {
        (Some(h), _) => h.clone(),
        (None, "none") => resolved.narinfo.nar_hash.clone(),
        (None, comp) => bail!(
            "narinfo for {} declares Compression: {comp} but no FileHash",
            resolved.req.store_path,
        ),
    };
    let expected_hex = file_hash
        .strip_prefix("sha256:")
        .unwrap_or(&file_hash);

    let transfer_req = TransferRequest::get(&url)
        .with_hash(HashAlgorithm::Sha256, expected_hex);

    let pb_size = resolved.narinfo.file_size.unwrap_or(0);
    let pb = create_download_bar(pb_size, &label);

    let result = engine.execute(transfer_req).await;

    pb.finish_and_clear();

    let result = result.with_context(|| format!("downloading {url}"))?;

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
        store_path: resolved.req.store_path.clone(),
        local_path: dest.to_path_buf(),
        download_hash: file_hash,
        nar_hash: resolved.narinfo.nar_hash.clone(),
        references: resolved.narinfo.references.clone(),
        deriver: resolved.narinfo.deriver.clone(),
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
pub async fn download_nars(
    resolved: &[ResolvedDownload],
    cache_dir: &Path,
    parallel: u32,
    printer: &Printer,
) -> Result<Vec<DownloadResult>> {
    if resolved.is_empty() {
        return Ok(Vec::new());
    }

    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("creating cache directory {}", cache_dir.display()))?;

    printer.info(&format!(
        "Downloading {} NAR(s) ({} parallel)...",
        resolved.len(),
        parallel,
    ));

    let semaphore = Arc::new(Semaphore::new(parallel as usize));
    let engine = Arc::new(default_engine());
    let mut handles = Vec::with_capacity(resolved.len());

    for r in resolved {
        let filename = nar_cache_filename(&r.narinfo.nar_hash);
        let dest = cache_dir.join(&filename);

        let r = r.clone();
        let printer = printer.clone();
        let engine = Arc::clone(&engine);

        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("acquiring semaphore permit")?;

        let handle = tokio::spawn(async move {
            let result = download_one(&engine, &r, &dest, &printer).await;
            drop(permit);
            result
        });

        handles.push(handle);
    }

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
fn nar_cache_filename(nar_hash: &str) -> String {
    let safe = nar_hash.replace(':', "-");
    format!("{safe}.nar.zst")
}

/// Extract a short label from a store path for progress display.
fn short_label(store_path: &str) -> String {
    store_path
        .rsplit('/')
        .next()
        .and_then(|basename| {
            if basename.len() >= 33 {
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
    fn join_basic() {
        assert_eq!(
            join_cache_url("https://cache.aos.dev", "nar/abc.nar.zst"),
            "https://cache.aos.dev/nar/abc.nar.zst",
        );
    }

    #[test]
    fn join_trims_slashes() {
        assert_eq!(
            join_cache_url("https://cache.aos.dev/", "/nar/abc.nar.zst"),
            "https://cache.aos.dev/nar/abc.nar.zst",
        );
    }

    #[test]
    fn join_view_prefix() {
        assert_eq!(
            join_cache_url("http://server:15000/default", "abc.narinfo"),
            "http://server:15000/default/abc.narinfo",
        );
    }

    #[test]
    fn narinfo_url_builds_from_store_path() {
        let url = narinfo_url(
            "http://server:15000/default",
            "/var/lib/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-testpkg-1.0",
        );
        assert_eq!(
            url,
            "http://server:15000/default/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo",
        );
    }

    #[test]
    fn resolve_mirror_strips_trailing_slash() {
        let reg = RegistryConfig {
            name: "test".into(),
            url: "https://registry.aos.dev/core/".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            signing: None,
        };
        assert_eq!(resolve_mirror(&reg), "https://registry.aos.dev/core");
    }

    #[test]
    fn nar_cache_filename_replaces_colon() {
        assert_eq!(
            nar_cache_filename("sha256:abcdef0123456789"),
            "sha256-abcdef0123456789.nar.zst",
        );
    }

    #[test]
    fn short_label_strips_store_hash() {
        let label =
            short_label("/var/lib/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-curl-8.5.0");
        assert_eq!(label, "curl-8.5.0");
    }

    #[test]
    fn short_label_short_path() {
        assert_eq!(short_label("short"), "short");
    }

    #[tokio::test]
    async fn download_nars_empty() {
        let printer = Printer::new(0, true, false);
        let tmp = tempfile::TempDir::new().unwrap();

        let results = download_nars(&[], tmp.path(), 4, &printer)
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn fetch_narinfos_empty() {
        let printer = Printer::new(0, true, false);
        let engine = Arc::new(default_engine());
        let out = fetch_narinfos(engine, &[], 4, &printer).await.unwrap();
        assert!(out.is_empty());
    }
}
