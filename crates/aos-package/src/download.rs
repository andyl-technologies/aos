//! The narinfo/NAR download pipeline.
//!
//! apm fetches packages from binary caches that speak the Nix binary-cache
//! protocol: for each store path the cache serves
//! `<base>/<storeHash>.narinfo` (a small key-value document carrying the NAR
//! URL, compression, file/NAR hashes, sizes, references, and deriver) and
//! the compressed NAR itself at `<base>/<narinfo URL field>`.
//!
//! The pipeline runs in three stages:
//!
//! 1. **Mirror resolution** ([`resolve_mirror`]): pick the cache base URL
//!    for a registry from its `[[caches]]` entries, falling back to the
//!    registry URL.
//! 2. **Narinfo fetch** ([`fetch_narinfos`], [`fetch_narinfo_closure`]):
//!    fetch narinfos in parallel; the closure variant transitively follows
//!    `References` (skipping paths already valid in the local store) and
//!    returns the set dependency-first so NARs can be imported in order.
//! 3. **NAR download** ([`download_nars`]): parallel, semaphore-bounded
//!    downloads into the NAR cache directory, verifying the compressed
//!    `FileHash` in flight and reusing already-cached files whose hash still
//!    checks out.
//!
//! Downloaded files land in the cache as `<escaped-nar-hash>.nar.zst`; the
//! resulting [`DownloadResult`]s carry everything [`crate::store::import_nar`]
//! needs to synthesize the import trailer.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use super::store::filter_missing;
use super::types::RegistryConfig;
use super::verify::{sha256_digest_hex, verify_download_hash};
use aos_core::error::AosError;
use aos_core::nar::cache::hash_path_fragment;
use aos_core::nar::info::{self as narinfo, NarInfo};
use aos_core::output::Printer;
use aos_net::{HashAlgorithm, TransferEngine, TransferEngineConfig, TransferRequest};

// ---------------------------------------------------------------------------
// Request / result types
// ---------------------------------------------------------------------------

/// A NAR to download. After Option A, this is just the store-path identity
/// and the cache base URL; everything else (URL on disk, file hash, size,
/// nar hash) comes from the narinfo fetched in `fetch_narinfos`.
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    /// Full store path of the NAR to download.
    pub store_path: String,
    /// Primary cache base URL — the prefix shared by
    /// `<base>/<storeHash>.narinfo` and `<base>/<narinfo.url>`. No `/nar`
    /// suffix. This is the highest-priority cache; on a narinfo/NAR
    /// not-found (404) it falls through to [`Self::fallback_mirrors`]
    /// (RFC-0004 "Cache stores, stacks, and consistency validation":
    /// miss-fallthrough, the flattened-`[[caches]]` `try` stack).
    pub mirror_url: String,
    /// Lower-priority cache base URLs, in descending priority, consulted in
    /// order when the primary (and earlier fallbacks) return not-found.
    /// Empty for a single-cache registry, in which case behavior is
    /// identical to before this field existed.
    #[allow(clippy::struct_field_names)]
    pub fallback_mirrors: Vec<String>,
}

impl DownloadRequest {
    /// The mirror base URLs to try in order: the primary then each fallback.
    fn mirror_chain(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.mirror_url.as_str())
            .chain(self.fallback_mirrors.iter().map(String::as_str))
    }
}

/// A `DownloadRequest` paired with its fetched narinfo. Produced by
/// `fetch_narinfos`; consumed by `download_nars`.
#[derive(Debug, Clone)]
pub struct ResolvedDownload {
    /// The original request (store path + mirror base URL).
    pub req: DownloadRequest,
    /// The narinfo fetched for the request's store path.
    pub narinfo: NarInfo,
}

/// Result of a successful download.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// Store path the downloaded NAR materializes when imported.
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

/// Render the planned NAR downloads for machine-readable command output.
///
/// Package metadata closures can omit anonymous store references that are
/// discovered only by reading narinfos. This helper exposes the real download
/// plan so JSON clients can audit exactly which NARs were fetched or reused.
pub(crate) fn resolved_downloads_json(resolved: &[ResolvedDownload]) -> Vec<serde_json::Value> {
    resolved
        .iter()
        .map(|item| {
            serde_json::json!({
                "store_path": item.narinfo.store_path.as_str(),
                "nar_hash": item.narinfo.nar_hash.as_str(),
                "nar_size": item.narinfo.nar_size,
                "file_hash": item.narinfo.file_hash.as_deref(),
                "file_size": item.narinfo.file_size,
                "compression": item.narinfo.compression.as_str(),
                "url": item.narinfo.url.as_str(),
                "references": &item.narinfo.references,
            })
        })
        .collect()
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
/// First checks the local registry clone under `registries_base` for a
/// `registry.toml` with `[[caches]]` entries (sorted by priority). Falls back
/// to the registry URL itself. The returned value is a base — apm appends
/// `<storeHash>.narinfo` and the narinfo-supplied `URL:` field to it.
///
/// `registries_base` is the active scope's registry-storage directory (see
/// [`ProfileScope::registries_path`]); the registry's own name is joined onto
/// it to locate the clone. Passing the scope path rather than deriving one
/// from `$HOME` keeps user- and system-scope lookups consistent.
///
/// [`ProfileScope::registries_path`]: crate::types::ProfileScope::registries_path
pub fn resolve_mirror(registries_base: &Path, registry: &RegistryConfig) -> String {
    let registries_dir = registries_base.join(&registry.name);

    let mirrors = crate::registry_ops::resolve_mirrors_for_registry(&registries_dir, registry);
    if let Some(cache) = mirrors.first() {
        return cache.url.trim_end_matches('/').to_string();
    }

    registry.url.trim_end_matches('/').to_string()
}

/// Determine the full ordered cache base-URL chain for a registry.
///
/// Like [`resolve_mirror`], but returns *every* committed-plus-client cache
/// base URL in descending priority (trailing slashes trimmed), enabling
/// miss-fallthrough: the narinfo/NAR fetch tries each in turn and only fails
/// when all return not-found. The first element matches what [`resolve_mirror`]
/// returns; the rest become a [`DownloadRequest`]'s
/// [`fallback_mirrors`](DownloadRequest::fallback_mirrors). When no cache is
/// committed or configured, falls back to the single registry URL — identical
/// to [`resolve_mirror`].
///
/// [`fallback_mirrors`]: DownloadRequest::fallback_mirrors
pub fn resolve_mirror_chain(registries_base: &Path, registry: &RegistryConfig) -> Vec<String> {
    let registries_dir = registries_base.join(&registry.name);
    let mirrors = crate::registry_ops::resolve_mirrors_for_registry(&registries_dir, registry);

    let mut chain: Vec<String> = Vec::new();
    for cache in &mirrors {
        let url = cache.url.trim_end_matches('/').to_string();
        if !chain.contains(&url) {
            chain.push(url);
        }
    }
    if chain.is_empty() {
        chain.push(registry.url.trim_end_matches('/').to_string());
    }
    chain
}

/// Split a mirror chain into its primary URL and fallback URLs.
///
/// The first element of `chain` (the highest-priority cache) becomes the
/// [`DownloadRequest::mirror_url`]; the rest become its
/// [`fallback_mirrors`](DownloadRequest::fallback_mirrors). An empty chain
/// yields an empty primary (no caches configured) — callers should pass a
/// non-empty chain from [`resolve_mirror_chain`].
pub fn split_mirror_chain(chain: &[String]) -> (String, Vec<String>) {
    match chain.split_first() {
        Some((primary, rest)) => (primary.clone(), rest.to_vec()),
        None => (String::new(), Vec::new()),
    }
}

/// Whether an error is a cache *not-found* (a missing object) — the signal to
/// fall through to the next cache rather than fail.
///
/// Recognizes both transports: an HTTP 404 (the protocol layer formats these
/// as `HTTP 404 for …`) and a `file://` miss (a [`std::io::Error`] of kind
/// [`NotFound`](std::io::ErrorKind::NotFound) somewhere in the cause chain).
/// Any other error — hash mismatch, transient network failure, a non-404
/// status — is *not* a miss and must not trigger fallthrough.
fn is_not_found(err: &anyhow::Error) -> bool {
    if err
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::NotFound)
    {
        return true;
    }
    let message = format!("{err:#}");
    message.contains("HTTP 404")
}

// ---------------------------------------------------------------------------
// Narinfo fetch
// ---------------------------------------------------------------------------

/// Fetch and parse the narinfo for each request in parallel.
///
/// Each GET hits `<mirror_url>/<storeHash>.narinfo`. The returned vector
/// preserves the input order. Fails fast on the first error.
///
/// # Errors
///
/// Returns an error if any narinfo fetch fails (network error, missing
/// body, non-UTF-8 body, or unparseable narinfo) or a fetch task panics.
pub async fn fetch_narinfos(
    engine: Arc<TransferEngine>,
    requests: &[DownloadRequest],
    parallel: u32,
    printer: &Printer,
) -> Result<Vec<ResolvedDownload>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }

    printer.info(&format!("Fetching {} narinfo(s)...", requests.len(),));

    let semaphore = Arc::new(Semaphore::new(parallel as usize));
    let mut handles = Vec::with_capacity(requests.len());

    for (idx, req) in requests.iter().enumerate() {
        let req_clone = req.clone();
        let engine = Arc::clone(&engine);
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("acquiring semaphore permit")?;

        let handle = tokio::spawn(async move {
            let result = fetch_one_narinfo(&engine, &req_clone).await;
            drop(permit);
            result.map(|(mirror_url, info)| {
                (
                    idx,
                    ResolvedDownload {
                        req: DownloadRequest {
                            // Pin the request to the mirror that actually
                            // served the narinfo, so the matching NAR is
                            // fetched from the same cache without re-probing.
                            mirror_url,
                            ..req_clone
                        },
                        narinfo: info,
                    },
                )
            })
        });

        handles.push(handle);
    }

    let mut buf: Vec<Option<ResolvedDownload>> = (0..requests.len()).map(|_| None).collect();
    for handle in handles {
        let (idx, resolved) = handle.await.context("narinfo task panicked")??;
        buf[idx] = Some(resolved);
    }

    Ok(buf
        .into_iter()
        .map(|o| o.expect("all slots filled"))
        .collect())
}

/// Fetch narinfos for the requested paths and all recursive NAR references.
///
/// References are fetched from the same cache mirror as the path that named
/// them. The returned vector is dependency-first, so callers can import the
/// downloaded NARs in order.
///
/// References whose store paths are already valid locally are not fetched
/// (checked via `nix-store --check-validity` between BFS waves).
///
/// # Errors
///
/// Returns an error if a narinfo fetch fails, the local store validity
/// check fails, or the fetched reference graph contains a cycle.
pub async fn fetch_narinfo_closure(
    engine: Arc<TransferEngine>,
    requests: &[DownloadRequest],
    parallel: u32,
    printer: &Printer,
) -> Result<Vec<ResolvedDownload>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }

    let mut fetched: HashMap<String, ResolvedDownload> = HashMap::new();
    let mut requested: HashSet<String> = HashSet::new();
    let mut pending = Vec::new();

    for request in requests {
        let hash = narinfo::store_hash(&request.store_path).to_string();
        if requested.insert(hash) {
            pending.push(request.clone());
        }
    }

    while !pending.is_empty() {
        let resolved = fetch_narinfos(Arc::clone(&engine), &pending, parallel, printer).await?;
        let mut candidates = Vec::new();

        for item in resolved {
            let hash = narinfo::store_hash(&item.narinfo.store_path).to_string();
            if fetched.contains_key(&hash) {
                continue;
            }

            for reference in &item.narinfo.references {
                let reference_hash = narinfo::store_hash(reference).to_string();
                if fetched.contains_key(&reference_hash) || requested.contains(&reference_hash) {
                    continue;
                }
                requested.insert(reference_hash);
                candidates.push(DownloadRequest {
                    store_path: reference_store_path(reference, &item.narinfo.store_path),
                    mirror_url: item.req.mirror_url.clone(),
                    fallback_mirrors: item.req.fallback_mirrors.clone(),
                });
            }

            fetched.insert(hash, item);
        }

        pending = filter_missing_download_requests(candidates).await?;
    }

    order_narinfo_closure(requests, &fetched)
}

/// Drop candidate requests whose store paths are already valid locally,
/// keeping only those that actually need downloading.
async fn filter_missing_download_requests(
    candidates: Vec<DownloadRequest>,
) -> Result<Vec<DownloadRequest>> {
    if candidates.is_empty() {
        return Ok(candidates);
    }

    let candidate_paths = candidates
        .iter()
        .map(|request| request.store_path.clone())
        .collect::<Vec<_>>();
    let missing = filter_missing(&candidate_paths).await?;
    let missing = missing.into_iter().collect::<HashSet<_>>();

    Ok(candidates
        .into_iter()
        .filter(|request| missing.contains(&request.store_path))
        .collect())
}

/// GET and parse a single narinfo document, falling through on cache misses.
///
/// Tries each cache in the request's [`mirror_chain`](DownloadRequest), in
/// priority order: a not-found (404 / `file://` miss) from one cache falls
/// through to the next, and only an all-caches miss surfaces the last
/// not-found error. Any non-miss error (hash mismatch, transient network,
/// unparseable body) fails immediately without consulting later caches.
///
/// Returns the base URL of the cache that served the narinfo alongside the
/// parsed document, so the NAR can be fetched from the same cache.
async fn fetch_one_narinfo(
    engine: &TransferEngine,
    req: &DownloadRequest,
) -> Result<(String, NarInfo)> {
    let mut last_not_found: Option<anyhow::Error> = None;
    for mirror_url in req.mirror_chain() {
        let url = narinfo_url(mirror_url, &req.store_path);
        match fetch_one_narinfo_from(engine, &url, req).await {
            Ok(info) => return Ok((mirror_url.to_string(), info)),
            Err(err) if is_not_found(&err) => {
                // Cache miss: fall through to the next cache in priority order.
                last_not_found = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_not_found
        .unwrap_or_else(|| anyhow::anyhow!("no cache configured for {}", req.store_path)))
}

/// GET and parse a single narinfo document from one specific cache URL.
async fn fetch_one_narinfo_from(
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
    let text =
        std::str::from_utf8(&body).with_context(|| format!("narinfo body is not UTF-8: {url}"))?;
    narinfo::parse(text)
        .with_context(|| format!("parsing narinfo for {} from {url}", req.store_path))
}

/// Expand a narinfo reference (bare basename or full path) to a full store
/// path, rooting basenames under the parent path's store directory.
pub(crate) fn reference_store_path(reference: &str, parent_store_path: &str) -> String {
    if reference.starts_with('/') {
        return reference.to_string();
    }

    let store_dir = parent_store_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("/nix/store");
    format!("{store_dir}/{reference}")
}

/// Re-order an already-fetched set of narinfos into dependency-first order
/// rooted at `roots` (used when the caller fetched narinfos itself).
pub(crate) fn order_resolved_downloads(
    roots: &[DownloadRequest],
    resolved: Vec<ResolvedDownload>,
) -> Result<Vec<ResolvedDownload>> {
    let mut fetched = HashMap::new();

    for item in resolved {
        let hash = narinfo::store_hash(&item.narinfo.store_path).to_string();
        fetched.insert(hash, item);
    }

    order_narinfo_closure(roots, &fetched)
}

/// Topologically sort fetched narinfos so references precede referrers,
/// starting from each root.
fn order_narinfo_closure(
    roots: &[DownloadRequest],
    fetched: &HashMap<String, ResolvedDownload>,
) -> Result<Vec<ResolvedDownload>> {
    let mut ordered = Vec::with_capacity(fetched.len());
    let mut pushed = HashSet::new();
    let mut visiting = HashSet::new();

    for root in roots {
        let hash = narinfo::store_hash(&root.store_path);
        push_narinfo_dependencies_first(hash, fetched, &mut pushed, &mut visiting, &mut ordered)?;
    }

    Ok(ordered)
}

/// Depth-first post-order push of one narinfo and its (fetched) references.
/// `visiting` tracks the current DFS stack so reference cycles are detected
/// rather than recursing forever; self-references are ignored.
fn push_narinfo_dependencies_first(
    hash: &str,
    fetched: &HashMap<String, ResolvedDownload>,
    pushed: &mut HashSet<String>,
    visiting: &mut HashSet<String>,
    ordered: &mut Vec<ResolvedDownload>,
) -> Result<()> {
    if pushed.contains(hash) {
        return Ok(());
    }
    if !visiting.insert(hash.to_string()) {
        bail!("cycle in narinfo references at {hash}");
    }

    let item = fetched
        .get(hash)
        .with_context(|| format!("missing fetched narinfo for {hash}"))?;
    for reference in &item.narinfo.references {
        let reference_hash = narinfo::store_hash(reference);
        if reference_hash == hash {
            continue;
        }
        if fetched.contains_key(reference_hash) {
            push_narinfo_dependencies_first(reference_hash, fetched, pushed, visiting, ordered)?;
        }
    }

    visiting.remove(hash);
    pushed.insert(hash.to_string());
    ordered.push(item.clone());
    Ok(())
}

// ---------------------------------------------------------------------------
// Single-file download
// ---------------------------------------------------------------------------

/// Download a single NAR file with progress reporting and hash verification.
///
/// The expected hash for the wire bytes is the narinfo `FileHash`; when the
/// cache serves an uncompressed NAR (`Compression: none`) without one, the
/// `NarHash` covers the same bytes and is used instead. A valid cached copy
/// at `dest` short-circuits the network entirely.
///
/// Like the narinfo fetch, the NAR download falls through on a cache miss:
/// the request's [`mirror_chain`](DownloadRequest) is tried in priority order
/// (starting from the cache that served the narinfo), and a not-found from one
/// cache moves on to the next; only an all-caches miss surfaces. The narinfo's
/// `URL:` field is content-addressed and therefore identical across caches.
async fn download_one(
    engine: &TransferEngine,
    resolved: &ResolvedDownload,
    dest: &Path,
    _printer: &Printer,
) -> Result<DownloadResult> {
    // FileHash is authoritative for the compressed stream when the cache
    // emits a compressed NAR. AOS-server populates it unconditionally;
    // a missing FileHash on a compressed NAR is a server bug we want to
    // catch loudly rather than silently skip.
    let file_hash = match (
        &resolved.narinfo.file_hash,
        resolved.narinfo.compression.as_str(),
    ) {
        (Some(h), _) => h.clone(),
        (None, "none") => resolved.narinfo.nar_hash.clone(),
        (None, comp) => bail!(
            "narinfo for {} declares Compression: {comp} but no FileHash",
            resolved.req.store_path,
        ),
    };
    let expected_hex = sha256_digest_hex(&file_hash)?;

    if let Some(result) = cached_download_result(resolved, dest, &file_hash).await? {
        return Ok(result);
    }

    let label = short_label(&resolved.req.store_path);
    let mut last_not_found: Option<anyhow::Error> = None;
    for mirror_url in resolved.req.mirror_chain() {
        let url = join_cache_url(mirror_url, &resolved.narinfo.url);
        match download_nar_from(engine, &url, dest, &expected_hex, &resolved.narinfo, &label).await
        {
            Ok(()) => {
                return Ok(DownloadResult {
                    store_path: resolved.req.store_path.clone(),
                    local_path: dest.to_path_buf(),
                    download_hash: file_hash,
                    nar_hash: resolved.narinfo.nar_hash.clone(),
                    references: resolved.narinfo.references.clone(),
                    deriver: resolved.narinfo.deriver.clone(),
                });
            }
            Err(err) if is_not_found(&err) => {
                // Cache miss: fall through to the next cache in priority order.
                last_not_found = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_not_found
        .unwrap_or_else(|| anyhow::anyhow!("no cache configured for {}", resolved.req.store_path)))
}

/// Download one NAR from a single fully-qualified URL into `dest`, verifying
/// the compressed-stream hash.
async fn download_nar_from(
    engine: &TransferEngine,
    url: &str,
    dest: &Path,
    expected_hex: &str,
    narinfo: &NarInfo,
    label: &str,
) -> Result<()> {
    let transfer_req = TransferRequest::get(url).with_hash(HashAlgorithm::Sha256, expected_hex);

    let pb_size = narinfo.file_size.unwrap_or(0);
    let pb = create_download_bar(pb_size, label);

    let result = engine.execute(transfer_req).await;

    pb.finish_and_clear();

    let result = result.with_context(|| format!("downloading {url}"))?;

    if let Some(body) = &result.body {
        tokio::fs::write(dest, body)
            .await
            .with_context(|| format!("writing to {}", dest.display()))?;
        Ok(())
    } else {
        Err(AosError::DownloadError {
            message: format!("no response body for {url}"),
        }
        .into())
    }
}

/// Reuse a previously downloaded NAR at `dest` if its hash still matches.
///
/// Returns `Ok(None)` when the file is absent or stale (a stale file is
/// deleted so the caller re-downloads it).
async fn cached_download_result(
    resolved: &ResolvedDownload,
    dest: &Path,
    file_hash: &str,
) -> Result<Option<DownloadResult>> {
    match tokio::fs::metadata(dest).await {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => bail!(
            "cached NAR path exists but is not a regular file: {}",
            dest.display(),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("checking cached NAR {}", dest.display()));
        }
    }

    let dest_for_verify = dest.to_path_buf();
    let expected_hash = file_hash.to_string();
    let valid =
        tokio::task::spawn_blocking(move || verify_download_hash(&dest_for_verify, &expected_hash))
            .await
            .context("cached NAR hash verification task panicked")?
            .is_ok();

    if !valid {
        tokio::fs::remove_file(dest)
            .await
            .with_context(|| format!("removing stale cached NAR {}", dest.display()))?;
        return Ok(None);
    }

    Ok(Some(DownloadResult {
        store_path: resolved.req.store_path.clone(),
        local_path: dest.to_path_buf(),
        download_hash: file_hash.to_string(),
        nar_hash: resolved.narinfo.nar_hash.clone(),
        references: resolved.narinfo.references.clone(),
        deriver: resolved.narinfo.deriver.clone(),
    }))
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
/// Concurrency is bounded by `parallel`; each NAR lands in `cache_dir`
/// under a filename derived from its NAR hash, with valid cached files
/// reused instead of re-downloaded.
///
/// # Errors
///
/// Returns an error if the cache directory cannot be created, any download
/// fails (network error, hash mismatch, missing body, write failure), or a
/// download task panics.
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
        let result = handle.await.context("download task panicked")??;
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

/// Generate a cache filename from a NAR hash (path-hostile characters such
/// as `:`, `/`, `+`, `=` are escaped).
fn nar_cache_filename(nar_hash: &str) -> String {
    format!("{}.nar.zst", hash_path_fragment(nar_hash))
}

/// Extract a short label from a store path for progress display
/// (`name-version`, with the 32-char hash prefix stripped).
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
    use sha2::{Digest, Sha256};

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
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };
        // No local clone exists at this base, so it falls back to the URL.
        assert_eq!(
            resolve_mirror(Path::new("/nonexistent/registries"), &reg),
            "https://registry.aos.dev/core"
        );
    }

    #[test]
    fn nar_cache_filename_replaces_colon() {
        assert_eq!(
            nar_cache_filename("sha256:abcdef0123456789"),
            "sha256-abcdef0123456789.nar.zst",
        );
    }

    #[test]
    fn nar_cache_filename_escapes_sri_path_separators() {
        assert_eq!(
            nar_cache_filename("sha256-/zAx+ko="),
            "sha256-_zAx_ko_.nar.zst",
        );
    }

    #[test]
    fn short_label_strips_store_hash() {
        let label = short_label("/var/lib/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-curl-8.5.0");
        assert_eq!(label, "curl-8.5.0");
    }

    #[test]
    fn short_label_short_path() {
        assert_eq!(short_label("short"), "short");
    }

    #[test]
    fn reference_store_path_uses_parent_store_dir() {
        assert_eq!(
            reference_store_path(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-lib-1.0",
                "/aos/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-app-1.0",
            ),
            "/aos/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-lib-1.0",
        );
        assert_eq!(
            reference_store_path(
                "/nix/store/cccccccccccccccccccccccccccccccc-lib-2.0",
                "/aos/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-app-1.0",
            ),
            "/nix/store/cccccccccccccccccccccccccccccccc-lib-2.0",
        );
    }

    #[test]
    fn order_narinfo_closure_places_references_before_referrers() {
        let root = resolved_download(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root-1.0",
            &["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-mid-1.0"],
        );
        let mid = resolved_download(
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-mid-1.0",
            &["cccccccccccccccccccccccccccccccc-leaf-1.0"],
        );
        let leaf = resolved_download("/nix/store/cccccccccccccccccccccccccccccccc-leaf-1.0", &[]);

        let mut fetched = HashMap::new();
        fetched.insert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(), root.clone());
        fetched.insert("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), mid);
        fetched.insert("cccccccccccccccccccccccccccccccc".to_string(), leaf);

        let ordered = order_narinfo_closure(&[root.req], &fetched).unwrap();
        let paths = ordered
            .iter()
            .map(|resolved| resolved.narinfo.store_path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                "/nix/store/cccccccccccccccccccccccccccccccc-leaf-1.0",
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-mid-1.0",
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root-1.0",
            ],
        );
    }

    #[tokio::test]
    async fn download_nars_empty() {
        let printer = Printer::new(0, true, false);
        let tmp = tempfile::TempDir::new().unwrap();

        let results = download_nars(&[], tmp.path(), 4, &printer).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn download_nars_uses_narinfo_supplied_colon_free_url() {
        let printer = Printer::new(0, true, false);
        let source = tempfile::TempDir::new().unwrap();
        let cache_dir = tempfile::TempDir::new().unwrap();
        let nar_bytes = b"nar-bytes";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(nar_bytes)));
        let nar_url = "nar/abc123-sha256-def456.nar.zst";

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(source.path().join(nar_url), nar_bytes).unwrap();

        let resolved = ResolvedDownload {
            req: DownloadRequest {
                store_path: "/nix/store/abc123-package".to_string(),
                mirror_url: format!("file://{}", source.path().display()),
                fallback_mirrors: Vec::new(),
            },
            narinfo: NarInfo {
                store_path: "/nix/store/abc123-package".to_string(),
                url: nar_url.to_string(),
                compression: "zstd".to_string(),
                file_hash: Some(file_hash.clone()),
                file_size: Some(nar_bytes.len() as u64),
                nar_hash: "sha256:def456".to_string(),
                nar_size: 5,
                references: Vec::new(),
                deriver: None,
                signatures: Vec::new(),
            },
        };

        let results = download_nars(&[resolved], cache_dir.path(), 1, &printer)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].download_hash, file_hash);
        assert_eq!(
            results[0].local_path,
            cache_dir.path().join("sha256-def456.nar.zst"),
        );
        assert_eq!(std::fs::read(&results[0].local_path).unwrap(), nar_bytes);
    }

    #[tokio::test]
    async fn download_nars_reuses_valid_cached_file_without_network() {
        let printer = Printer::new(0, true, false);
        let cache_dir = tempfile::TempDir::new().unwrap();
        let nar_bytes = b"cached-nar-bytes";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(nar_bytes)));
        let nar_hash = "sha256:abcdef0123456789";
        let local_path = cache_dir.path().join(nar_cache_filename(nar_hash));
        std::fs::write(&local_path, nar_bytes).unwrap();

        let resolved = ResolvedDownload {
            req: DownloadRequest {
                store_path: "/nix/store/abc123-package".to_string(),
                mirror_url: "http://127.0.0.1:9".to_string(),
                fallback_mirrors: Vec::new(),
            },
            narinfo: NarInfo {
                store_path: "/nix/store/abc123-package".to_string(),
                url: "nar/unreachable.nar.zst".to_string(),
                compression: "zstd".to_string(),
                file_hash: Some(file_hash.clone()),
                file_size: Some(nar_bytes.len() as u64),
                nar_hash: nar_hash.to_string(),
                nar_size: 5,
                references: Vec::new(),
                deriver: None,
                signatures: Vec::new(),
            },
        };

        let results = download_nars(&[resolved], cache_dir.path(), 1, &printer)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].download_hash, file_hash);
        assert_eq!(results[0].local_path, local_path);
        assert_eq!(std::fs::read(&results[0].local_path).unwrap(), nar_bytes);
    }

    #[tokio::test]
    async fn download_nars_replaces_stale_cached_file() {
        let printer = Printer::new(0, true, false);
        let source = tempfile::TempDir::new().unwrap();
        let cache_dir = tempfile::TempDir::new().unwrap();
        let nar_bytes = b"fresh-nar-bytes";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(nar_bytes)));
        let nar_hash = "sha256:freshnarhash";
        let nar_url = "nar/fresh.nar.zst";
        let local_path = cache_dir.path().join(nar_cache_filename(nar_hash));

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(source.path().join(nar_url), nar_bytes).unwrap();
        std::fs::write(&local_path, b"stale-cache").unwrap();

        let resolved = ResolvedDownload {
            req: DownloadRequest {
                store_path: "/nix/store/abc123-package".to_string(),
                mirror_url: format!("file://{}", source.path().display()),
                fallback_mirrors: Vec::new(),
            },
            narinfo: NarInfo {
                store_path: "/nix/store/abc123-package".to_string(),
                url: nar_url.to_string(),
                compression: "zstd".to_string(),
                file_hash: Some(file_hash.clone()),
                file_size: Some(nar_bytes.len() as u64),
                nar_hash: nar_hash.to_string(),
                nar_size: 5,
                references: Vec::new(),
                deriver: None,
                signatures: Vec::new(),
            },
        };

        let results = download_nars(&[resolved], cache_dir.path(), 1, &printer)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].download_hash, file_hash);
        assert_eq!(results[0].local_path, local_path);
        assert_eq!(std::fs::read(&results[0].local_path).unwrap(), nar_bytes);
    }

    #[test]
    fn is_not_found_recognizes_404_and_file_miss() {
        let http = anyhow::anyhow!("downloading x: HTTP 404 for http://c/a.narinfo: not found");
        assert!(is_not_found(&http));
        let io = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file",
        ));
        assert!(is_not_found(&io));
        let other = anyhow::anyhow!("hash mismatch for http://c/a.nar");
        assert!(!is_not_found(&other));
        let http_500 = anyhow::anyhow!("HTTP 500 for http://c/a.narinfo");
        assert!(!is_not_found(&http_500));
    }

    #[test]
    fn split_mirror_chain_separates_primary_and_fallbacks() {
        let chain = vec!["https://a".to_string(), "https://b".to_string()];
        let (primary, fallbacks) = split_mirror_chain(&chain);
        assert_eq!(primary, "https://a");
        assert_eq!(fallbacks, vec!["https://b".to_string()]);
        assert_eq!(split_mirror_chain(&[]), (String::new(), Vec::new()));
    }

    /// Write a valid narinfo + NAR for `store_path` into a `file://` cache
    /// directory, returning the directory's `file://` URL. The NAR bytes are
    /// `b"narbytes"` and the narinfo's `URL:` points at it.
    fn seed_cache(store_path: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let hash = narinfo::store_hash(store_path);
        let nar_bytes = b"narbytes";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(nar_bytes)));
        std::fs::create_dir_all(dir.path().join("nar")).unwrap();
        std::fs::write(dir.path().join("nar/data.nar"), nar_bytes).unwrap();
        std::fs::write(
            dir.path().join(format!("{hash}.narinfo")),
            format!(
                "StorePath: {store_path}\nURL: nar/data.nar\nNarHash: sha256:def\n\
                 NarSize: 8\nFileHash: {file_hash}\nFileSize: 8\nCompression: none\n\
                 References: \n"
            ),
        )
        .unwrap();
        let url = format!("file://{}", dir.path().display());
        (dir, url)
    }

    #[tokio::test]
    async fn narinfo_fetch_falls_through_to_second_cache_on_miss() {
        let printer = Printer::new(0, true, false);
        let engine = Arc::new(default_engine());
        let store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg-1.0";

        // First cache is empty (every narinfo 404s); the second holds it.
        let empty = tempfile::TempDir::new().unwrap();
        let empty_url = format!("file://{}", empty.path().display());
        let (_holder, holder_url) = seed_cache(store_path);

        let request = DownloadRequest {
            store_path: store_path.to_string(),
            mirror_url: empty_url,
            fallback_mirrors: vec![holder_url.clone()],
        };
        let resolved = fetch_narinfos(engine, std::slice::from_ref(&request), 1, &printer)
            .await
            .unwrap();

        assert_eq!(resolved.len(), 1);
        // The request was pinned to the cache that actually served it, so the
        // NAR fetch targets the holder.
        assert_eq!(resolved[0].req.mirror_url, holder_url);
        assert_eq!(resolved[0].narinfo.store_path, store_path);
    }

    #[tokio::test]
    async fn narinfo_fetch_fails_when_all_caches_miss() {
        let printer = Printer::new(0, true, false);
        let engine = Arc::new(default_engine());
        let store_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-pkg-1.0";

        let a = tempfile::TempDir::new().unwrap();
        let b = tempfile::TempDir::new().unwrap();
        let request = DownloadRequest {
            store_path: store_path.to_string(),
            mirror_url: format!("file://{}", a.path().display()),
            fallback_mirrors: vec![format!("file://{}", b.path().display())],
        };

        let err = fetch_narinfos(engine, std::slice::from_ref(&request), 1, &printer)
            .await
            .unwrap_err();
        // The surfaced error is the (last) not-found, not a generic failure.
        assert!(is_not_found(&err), "expected not-found, got: {err:#}");
    }

    #[tokio::test]
    async fn fetch_narinfos_empty() {
        let printer = Printer::new(0, true, false);
        let engine = Arc::new(default_engine());
        let out = fetch_narinfos(engine, &[], 4, &printer).await.unwrap();
        assert!(out.is_empty());
    }

    fn resolved_download(store_path: &str, references: &[&str]) -> ResolvedDownload {
        ResolvedDownload {
            req: DownloadRequest {
                store_path: store_path.to_string(),
                mirror_url: "http://cache.example.invalid".to_string(),
                fallback_mirrors: Vec::new(),
            },
            narinfo: NarInfo {
                store_path: store_path.to_string(),
                url: "nar/demo.nar.zst".to_string(),
                compression: "zstd".to_string(),
                file_hash: Some("sha256:filehash".to_string()),
                file_size: Some(1),
                nar_hash: "sha256:narhash".to_string(),
                nar_size: 1,
                references: references
                    .iter()
                    .map(|reference| reference.to_string())
                    .collect(),
                deriver: None,
                signatures: Vec::new(),
            },
        }
    }
}
