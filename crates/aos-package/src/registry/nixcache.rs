//! Static Nix binary-cache generation for registry store paths.
//!
//! Producer-side tooling that turns the store paths referenced by a
//! registry's package TOML files into a standard static Nix binary cache: a
//! `nix-cache-info` file, one `<hash>.narinfo` per path, and
//! zstd-compressed NARs under `nar/`. The local Nix store supplies the
//! bytes (`nix-store --dump`) and metadata (`nix path-info`); narinfos are
//! optionally Ed25519-signed.
//!
//! The cache is laid out on disk first ([`generate_static_cache`]) and then
//! mirrored to one or more upload destinations via `aos-cache` backends
//! ([`upload_static_cache`], [`upload_static_cache_to_all`]).
//! [`upsert_registry_cache`] records the published cache URL in the
//! registry's `registry.toml` so consumers discover it after sync.
//!
//! Store paths from the package metadata may live in an alternate store
//! directory (e.g. `/var/lib/store`); metadata reported by the local
//! `/nix/store` is re-rooted onto the requested store dir so the published
//! narinfos describe the paths consumers will actually install.

use std::collections::BTreeSet;
#[cfg(unix)]
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions};
use aos_core::nar::cache::{
    NarCompression, NarInfoSigner, StaticNarInfoInput, canonical_sha256_hex, nar_url,
    nix_cache_info, render_static_narinfo,
};
use aos_core::nar::info::{basename, store_hash};
use aos_core::nix::aos_nix_env;
use aos_core::output::Printer;
use futures_util::future::join_all;
use futures_util::stream::{StreamExt, TryStreamExt};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use toml::Value as TomlValue;

use super::membership::CacheMembership;
use super::store::StoreMap;

/// Zstandard compression level used for published NARs.
///
/// Level 3 matches Nix's normal binary-cache default. Higher levels make
/// publishing large, already-compressed system images disproportionately
/// expensive while yielding little additional transfer-size reduction.
const NAR_ZSTD_LEVEL: i32 = 3;

/// Maximum uploads kept in flight per destination. The `aos_net`
/// connection pool enforces the real per-host limit (8 connections);
/// this only bounds how many file reads/requests we stage at once.
const UPLOAD_CONCURRENCY: usize = 16;

/// Summary of a generated static cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCacheReport {
    /// Number of store paths covered by this run.
    pub paths: usize,
    /// Number of `.narinfo` files written.
    pub narinfos: usize,
    /// Number of compressed NAR files freshly written this run.
    pub nars: usize,
    /// Number of staged NARs reused without re-dumping or re-compressing.
    pub local_reused: usize,
    /// Number of paths skipped because every destination already had their
    /// narinfo.
    pub remote_skipped: usize,
    /// Store hashes for registry root paths. These narinfos are uploaded
    /// after all member narinfos so a visible root implies a complete closure.
    pub root_hashes: Vec<String>,
    /// The directory the cache was generated into.
    pub output_dir: PathBuf,
}

/// Summary of a static-cache staging garbage-collection pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticCacheGcReport {
    /// Number of narinfo/NAR pairs selected by the age policy.
    pub candidates: usize,
    /// Number of files deleted (two per pair when both files exist).
    pub deleted_files: usize,
    /// Bytes deleted from the staging directory.
    pub deleted_bytes: u64,
    /// Candidate narinfo hashes, useful for dry-run output.
    pub hashes: Vec<String>,
}

/// One closure path scheduled for cache emission.
struct CacheEntry {
    /// Re-rooted path metadata from `nix path-info`.
    info: CachePathInfo,
    /// Byte-verified staged NAR, absent when this entry must be compressed.
    reusable: Option<ReusableNar>,
}

/// Identity captured while validating a staged compressed NAR for reuse.
struct ReusableNar {
    /// Backend-relative filename with the `nar/` prefix stripped.
    name: String,
    /// Canonical hash of the exact compressed bytes.
    file_hash: String,
    /// Exact compressed byte count.
    file_size: u64,
}

/// Per-path metadata extracted from `nix path-info`, re-rooted onto the
/// registry's store directory.
#[derive(Debug, Clone)]
struct CachePathInfo {
    path: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
}

/// Generate a complete static Nix binary cache for a registry's store paths.
///
/// Collects every `store_path`, `source_drv`, and sysroot image path from
/// the registry's package TOML files, expands each to its full closure with
/// `nix-store -qR`, and writes `nix-cache-info`, a zstd NAR, and a narinfo
/// for every member into `output_dir`. When `key_path` (or the signer's
/// default configuration) yields a signing key, narinfos are signed.
///
/// `jobs` bounds compression parallelism (see [`resolve_jobs`]); a NAR
/// already present in `output_dir` is reused without re-dumping or
/// re-compressing.
///
/// # Errors
///
/// Returns an error when the registry references no store paths, the paths
/// span mixed store directories, a path is missing from the local Nix
/// store, a `nix`/`nix-store` invocation fails, or an output file cannot be
/// written.
pub async fn generate_static_cache(
    registry_dir: &Path,
    output_dir: &Path,
    key_path: Option<&Path>,
    priority: u32,
    jobs: Option<usize>,
    membership: Option<&dyn CacheMembership>,
    no_skip: bool,
    printer: &Printer,
) -> Result<StaticCacheReport> {
    let roots = collect_static_cache_roots(registry_dir)?;
    if roots.is_empty() {
        bail!("registry contains no store paths to cache");
    }
    let store_dir = common_store_dir(&roots)?;
    let root_hashes = roots
        .iter()
        .map(|path| store_hash(path).to_string())
        .collect::<Vec<_>>();

    // The store/ realisation graph is the authority for blessed output bytes
    // (RFC-0005). Generation reads the local store, so guard against emitting
    // a narinfo+NAR for a path whose local bytes were never blessed - every
    // enforcing consumer would reject it. Paths outside the graph (sources,
    // images) are unaffected.
    let store_graph =
        Arc::new(StoreMap::load(registry_dir).context("loading store/ realisation graph")?);

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;
    std::fs::create_dir_all(output_dir.join("nar"))
        .with_context(|| format!("creating {}", output_dir.join("nar").display()))?;
    std::fs::write(
        output_dir.join("nix-cache-info"),
        nix_cache_info(&store_dir, priority),
    )
    .with_context(|| format!("writing {}", output_dir.join("nix-cache-info").display()))?;

    let signer = NarInfoSigner::load(key_path)?;
    let signer = Arc::new(signer.is_configured().then_some(signer));

    let workers = resolve_jobs(jobs);
    let output_dir = Arc::new(output_dir.to_path_buf());
    // `--no-skip` forces full regeneration by ignoring remote membership.
    let membership = if no_skip { None } else { membership };

    // Root-level early-out: a root narinfo present on every destination implies
    // its whole closure was published by a prior release (the upload always
    // writes member narinfos before the root, so a visible root is complete),
    // so the entire subtree is skipped without any store access.
    let (roots_to_expand, skipped_roots) =
        partition_remote_absent(roots, |root| store_hash(root), membership, workers).await?;
    let mut remote_skipped = skipped_roots.len();
    for root in &skipped_roots {
        printer.info(&format!("Skipping remotely-present cache root {root}"));
    }

    let paths = collect_store_path_closures(&roots_to_expand)?;

    // Phase A: gather metadata (validity + path-info + blessing) for every
    // path concurrently. Fails fast before any compression happens.
    let infos = gather_all_path_info(&paths, &store_graph, workers).await?;

    // Per-member skip: drop paths whose narinfo is already on every
    // destination before any dump or compression. Shared dependencies a prior
    // release pushed cost one concurrent HEAD each, not a re-compression.
    let (infos, skipped_members) =
        partition_remote_absent(infos, |info| store_hash(&info.path), membership, workers).await?;
    remote_skipped += skipped_members.len();
    for info in &skipped_members {
        printer.info(&format!(
            "Skipping remotely-present cache member {}",
            info.path
        ));
    }

    // Classify each remaining path as already-cached (skip) or pending
    // compression, and total the pending uncompressed bytes for the budget.
    let mut entries = Vec::with_capacity(infos.len());
    let mut pending_bytes = 0u64;
    for info in infos {
        let reusable = (!no_skip)
            .then(|| reusable_nar(output_dir.as_path(), &info))
            .transpose()?
            .flatten();
        if reusable.is_none() {
            pending_bytes += info.nar_size;
        }
        entries.push(CacheEntry { info, reusable });
    }

    // The fair share is one core's slice of the pending work. A NAR larger
    // than its fair share is "dominant": it gets enough zstd threads
    // (zstdmt) to bring it back to ~fair share, while smaller jobs fill the
    // remaining cores. Total in-flight threads never exceed `workers`, so
    // there is no oversubscription and peak RAM is bounded by the budget.
    let fair_share = if pending_bytes > 0 {
        (pending_bytes / workers as u64).max(1)
    } else {
        1
    };

    // Largest first (LPT): big NARs start while permits are free, so their
    // long pole overlaps all the small work instead of stranding at the tail.
    entries.sort_by(|a, b| b.info.nar_size.cmp(&a.info.nar_size));

    // Phase B: compress (or reuse) each NAR and write its narinfo, bounded by
    // a `workers`-permit budget. A dominant NAR acquires several permits and
    // runs zstdmt across that many threads. Each entry is logged as it is
    // dispatched (once a permit is free), so progress streams live rather
    // than arriving in a burst after the slowest NAR finishes.
    let total = entries.len();
    let path_count = total + remote_skipped;
    let sem = Arc::new(Semaphore::new(workers));
    let mut handles = Vec::with_capacity(total);
    for (index, entry) in entries.into_iter().enumerate() {
        let reused = entry.reusable.is_some();
        let threads = if reused {
            1
        } else {
            (entry.info.nar_size.div_ceil(fair_share)).clamp(1, workers as u64) as u32
        };
        let permit = Arc::clone(&sem)
            .acquire_many_owned(threads)
            .await
            .context("acquiring compression permits")?;
        let position = index + 1;
        if reused {
            printer.info(&format!(
                "[{position}/{total}] Reusing cached NAR for {}",
                entry.info.path
            ));
        } else {
            printer.info(&format!(
                "[{position}/{total}] Generating static cache entry for {}",
                entry.info.path
            ));
        }
        let output_dir = Arc::clone(&output_dir);
        let store_dir = store_dir.clone();
        let signer = Arc::clone(&signer);
        handles.push(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            write_cache_entry(
                &entry,
                output_dir.as_path(),
                &store_dir,
                (*signer).as_ref(),
                threads,
            )
            .map(|()| reused)
        }));
    }

    let mut narinfos = 0usize;
    let mut nars = 0usize;
    let mut local_reused = 0usize;
    for handle in handles {
        let skipped = handle.await.context("static cache entry task panicked")??;
        narinfos += 1;
        if skipped {
            local_reused += 1;
        } else {
            nars += 1;
        }
    }

    Ok(StaticCacheReport {
        paths: path_count,
        narinfos,
        nars,
        local_reused,
        remote_skipped,
        root_hashes,
        output_dir: (*output_dir).clone(),
    })
}

/// Partition `items` into those whose narinfo is absent from the remote
/// (returned first, for generation) and those already present everywhere.
///
/// Membership for each item is probed concurrently, up to `workers` in
/// flight. When `membership` is `None` — no destinations, or `--no-skip` —
/// every item is treated as absent and returned unchanged.
async fn partition_remote_absent<T, F>(
    items: Vec<T>,
    hash_of: F,
    membership: Option<&dyn CacheMembership>,
    workers: usize,
) -> Result<(Vec<T>, Vec<T>)>
where
    F: Fn(&T) -> &str,
{
    let Some(membership) = membership else {
        return Ok((items, Vec::new()));
    };
    let present =
        futures_util::stream::iter(items.iter().map(|item| membership.narinfo(hash_of(item))))
            .buffered(workers.max(1))
            .try_collect::<Vec<bool>>()
            .await?;
    let mut absent = Vec::new();
    let mut found = Vec::new();
    for (item, is_present) in items.into_iter().zip(present) {
        if is_present {
            found.push(item);
        } else {
            absent.push(item);
        }
    }
    Ok((absent, found))
}

/// Resolve the compression worker count: an explicit `--jobs` value wins,
/// then the `AOS_CACHE_JOBS` environment variable, then the machine's
/// available parallelism. Always at least 1.
fn resolve_jobs(explicit: Option<usize>) -> usize {
    if let Some(n) = explicit {
        return n.max(1);
    }
    if let Ok(value) = std::env::var("AOS_CACHE_JOBS")
        && let Ok(n) = value.trim().parse::<usize>()
        && n >= 1
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Concurrently gather [`CachePathInfo`] for every path, bounded by
/// `workers`. Each task validates the path, queries `nix path-info`, and
/// enforces the store/ blessing gate. The first failure aborts.
async fn gather_all_path_info(
    paths: &[String],
    store_graph: &Arc<StoreMap>,
    workers: usize,
) -> Result<Vec<CachePathInfo>> {
    let sem = Arc::new(Semaphore::new(workers));
    let mut handles = Vec::with_capacity(paths.len());
    for path in paths {
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .context("acquiring path-info permit")?;
        let path = path.clone();
        let store_graph = Arc::clone(store_graph);
        handles.push(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            gather_path_info(&path, &store_graph)
        }));
    }

    let mut infos = Vec::with_capacity(paths.len());
    for handle in handles {
        infos.push(handle.await.context("path-info task panicked")??);
    }
    Ok(infos)
}

/// Validate one path, query its metadata, and enforce the blessing gate.
fn gather_path_info(path: &str, store_graph: &StoreMap) -> Result<CachePathInfo> {
    check_store_path_valid(path)?;
    let info = query_path_info(path)?;

    // If the graph blesses this path, the local bytes must match a blessed
    // NAR before we publish them.
    let blessed = store_graph.blessed_nars(store_hash(&info.path));
    if !blessed.is_empty()
        && !blessed
            .iter()
            .any(|nar| nar.matches(&info.nar_hash, info.nar_size))
    {
        bail!(
            "refusing to publish {}: local NAR ({} / {} bytes) is not blessed in store/ \
             - `apr store bless` it or rebuild to a blessed realisation",
            info.path,
            info.nar_hash,
            info.nar_size,
        );
    }
    Ok(info)
}

/// Returns a verified staged NAR identity when the local pair is complete.
fn reusable_nar(output_dir: &Path, info: &CachePathInfo) -> Result<Option<ReusableNar>> {
    let narinfo_path = output_dir.join(format!("{}.narinfo", store_hash(&info.path)));
    let Ok(text) = std::fs::read_to_string(&narinfo_path) else {
        return Ok(None);
    };
    let Ok(existing) = aos_core::nar::info::parse(&text) else {
        return Ok(None);
    };
    if existing.nar_hash != info.nar_hash {
        return Ok(None);
    }
    if existing.compression != NarCompression::Zstd.name() {
        return Ok(None);
    }
    let Some(file_hash) = existing.file_hash.as_deref() else {
        return Ok(None);
    };
    let Some(file_size) = existing.file_size else {
        return Ok(None);
    };
    let Ok(expected_url) = nar_url(&info.path, file_hash, NarCompression::Zstd) else {
        return Ok(None);
    };
    if existing.url != expected_url {
        return Ok(None);
    }
    let Some(name) = expected_url.strip_prefix("nar/") else {
        return Ok(None);
    };
    let nar_path = output_dir.join("nar").join(name);
    if name.contains('/') || !nar_path.is_file() {
        return Ok(None);
    }

    let (actual_hash, actual_size) = file_digest(&nar_path)?;
    let Ok(declared_hash) = canonical_sha256_hex(file_hash) else {
        return Ok(None);
    };
    if actual_size != file_size || canonical_sha256_hex(&actual_hash)? != declared_hash {
        return Ok(None);
    }
    if !nar_payload_matches(&nar_path, &info.nar_hash, info.nar_size).unwrap_or(false) {
        return Ok(None);
    }
    Ok(Some(ReusableNar {
        name: name.to_string(),
        file_hash: actual_hash,
        file_size: actual_size,
    }))
}

/// Write one cache entry: produce (or reuse) the compressed NAR, then render
/// and write its narinfo. `threads` is the zstd thread count for a fresh
/// compression (ignored when the NAR is reused).
fn write_cache_entry(
    entry: &CacheEntry,
    output_dir: &Path,
    store_dir: &str,
    signer: Option<&NarInfoSigner>,
    threads: u32,
) -> Result<()> {
    let info = &entry.info;
    let previous_nar_path = staged_nar_path(output_dir, info);
    let (file_hash, file_size, nar_path) = if let Some(reusable) = &entry.reusable {
        let nar_path = output_dir.join("nar").join(&reusable.name);
        let (file_hash, file_size) = reuse_file_digest(output_dir, info, &nar_path, reusable)?;
        (file_hash, file_size, nar_path)
    } else {
        let pending_path = output_dir
            .join("nar")
            .join(format!(".{}.nar.zst.pending", store_hash(&info.path)));
        let (file_hash, file_size) =
            compress_nar_to_file(&info.path, &pending_path, NAR_ZSTD_LEVEL, threads)?;
        let url = nar_url(&info.path, &file_hash, NarCompression::Zstd)?;
        let nar_name = url
            .strip_prefix("nar/")
            .context("generated NAR URL does not use the nar/ prefix")?;
        let nar_path = output_dir.join("nar").join(nar_name);
        std::fs::rename(&pending_path, &nar_path).with_context(|| {
            format!(
                "renaming {} -> {}",
                pending_path.display(),
                nar_path.display()
            )
        })?;
        (file_hash, file_size, nar_path)
    };

    let body = render_static_narinfo(
        &StaticNarInfoInput {
            store_path: &info.path,
            nar_hash: &info.nar_hash,
            nar_size: info.nar_size,
            references: &info.references,
            deriver: info.deriver.as_deref(),
            signatures: &[],
            file_hash: &file_hash,
            file_size,
            compression: NarCompression::Zstd,
        },
        store_dir,
        signer,
    )?;
    let hash = store_hash(&info.path);
    let narinfo_path = output_dir.join(format!("{hash}.narinfo"));
    std::fs::write(&narinfo_path, body)
        .with_context(|| format!("writing {}", narinfo_path.display()))?;
    touch_path(&nar_path)?;
    touch_path(&narinfo_path)?;
    if let Some(previous_nar_path) = previous_nar_path
        && previous_nar_path != nar_path
    {
        std::fs::remove_file(&previous_nar_path).with_context(|| {
            format!(
                "removing superseded staged NAR {}",
                previous_nar_path.display()
            )
        })?;
    }
    Ok(())
}

/// Resolves the currently staged NAR for one narinfo without accepting escapes.
fn staged_nar_path(output_dir: &Path, info: &CachePathInfo) -> Option<PathBuf> {
    let narinfo_path = output_dir.join(format!("{}.narinfo", store_hash(&info.path)));
    let text = std::fs::read_to_string(narinfo_path).ok()?;
    let existing = aos_core::nar::info::parse(&text).ok()?;
    if existing.compression != NarCompression::Zstd.name() {
        return None;
    }
    let file_hash = existing.file_hash.as_deref()?;
    let expected_url = nar_url(&info.path, file_hash, NarCompression::Zstd).ok()?;
    if existing.url != expected_url {
        return None;
    }
    let name = expected_url.strip_prefix("nar/")?;
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let path = output_dir.join("nar").join(name);
    std::fs::symlink_metadata(&path)
        .ok()?
        .file_type()
        .is_file()
        .then_some(path)
}

/// Verify and recover a reused NAR's `(file_hash, file_size)` without recompressing.
fn reuse_file_digest(
    output_dir: &Path,
    info: &CachePathInfo,
    nar_path: &Path,
    reusable: &ReusableNar,
) -> Result<(String, u64)> {
    let hash = store_hash(&info.path);
    let narinfo_path = output_dir.join(format!("{hash}.narinfo"));
    let text = std::fs::read_to_string(&narinfo_path)
        .with_context(|| format!("reading reused narinfo {}", narinfo_path.display()))?;
    let existing = aos_core::nar::info::parse(&text)
        .with_context(|| format!("parsing reused narinfo {}", narinfo_path.display()))?;
    if existing.nar_hash != info.nar_hash || existing.compression != NarCompression::Zstd.name() {
        bail!("reused NAR metadata changed while generating {}", info.path);
    }
    let declared_hash = existing
        .file_hash
        .context("reused narinfo has no FileHash")?;
    let declared_size = existing
        .file_size
        .context("reused narinfo has no FileSize")?;
    let expected_url = nar_url(&info.path, &declared_hash, NarCompression::Zstd)?;
    if existing.url != expected_url
        || expected_url.strip_prefix("nar/") != Some(reusable.name.as_str())
        || existing.file_size != Some(reusable.file_size)
        || canonical_sha256_hex(&declared_hash)? != canonical_sha256_hex(&reusable.file_hash)?
    {
        bail!("reused narinfo URL changed while generating {}", info.path);
    }

    let (actual_hash, actual_size) = file_digest(nar_path)?;
    if actual_size != declared_size
        || actual_size != reusable.file_size
        || canonical_sha256_hex(&actual_hash)? != canonical_sha256_hex(&reusable.file_hash)?
    {
        bail!("reused NAR bytes changed while generating {}", info.path);
    }
    Ok((actual_hash, actual_size))
}

/// Verifies that zstd bytes decode to the declared uncompressed NAR identity.
fn nar_payload_matches(nar_path: &Path, expected_hash: &str, expected_size: u64) -> Result<bool> {
    let file = File::open(nar_path).with_context(|| format!("reading {}", nar_path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file)
        .with_context(|| format!("decoding {} as zstd", nar_path.display()))?;
    let mut bounded = decoder.take(expected_size.saturating_add(1));
    let mut hasher = HashingWriter::new(io::sink());
    io::copy(&mut bounded, &mut hasher)
        .with_context(|| format!("verifying NAR payload {}", nar_path.display()))?;
    let (actual_hash, actual_size) = hasher.finish().context("finalizing NAR payload hash")?;
    Ok(actual_size == expected_size
        && canonical_sha256_hex(&actual_hash)? == canonical_sha256_hex(expected_hash)?)
}

/// Streams a potentially multi-gigabyte NAR through a bounded-memory hasher.
fn file_digest(nar_path: &Path) -> Result<(String, u64)> {
    let mut file =
        File::open(nar_path).with_context(|| format!("reading {}", nar_path.display()))?;
    let mut hasher = HashingWriter::new(io::sink());
    io::copy(&mut file, &mut hasher).with_context(|| format!("hashing {}", nar_path.display()))?;
    hasher.finish().context("finalizing reused NAR hash")
}

/// Upload a generated static cache directory to one destination.
///
/// Pushes `nix-cache-info`, every top-level `*.narinfo`, and the canonical NAR
/// payload referenced by each narinfo through the cache backend selected by
/// `upload_url`'s scheme (e.g. `file://`, S3-style object stores). Superseded
/// payloads retained in the local staging cache are not published.
///
/// # Errors
///
/// Returns an error if the backend cannot be constructed for `upload_url`,
/// a local file cannot be read, or any upload request fails.
pub async fn upload_static_cache(
    output_dir: &Path,
    upload_url: &str,
    auth: &AuthOptions,
    root_hashes: &[String],
    no_skip: bool,
    printer: &Printer,
) -> Result<()> {
    let cache = backend::from_url(upload_url, auth).await?;
    let cache = &*cache;

    let narinfos = list_narinfo_files(output_dir)?;
    let nars = referenced_nar_files(output_dir, &narinfos)?;

    // Immutable payloads first (NARs), then narinfos, then the
    // nix-cache-info marker last. A consumer racing a partial upload never
    // sees a narinfo or marker pointing at NAR bytes that are not there yet.
    upload_concurrently(nars.into_iter().map(|(name, path)| async move {
        let relative_path = format!("nar/{name}");
        if !no_skip && cache.exists(&relative_path).await? {
            return Ok(());
        }
        cache
            .put_static_file(
                &relative_path,
                &path,
                Some("application/x-nix-nar"),
                Some(aos_cache::backend::IMMUTABLE_CACHE_CONTROL),
                None,
                None,
            )
            .await
    }))
    .await?;

    let root_hashes = root_hashes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let (root_narinfos, member_narinfos): (Vec<_>, Vec<_>) = narinfos
        .into_iter()
        .partition(|(stem, _)| root_hashes.contains(stem.as_str()));
    upload_concurrently(member_narinfos.into_iter().map(|(stem, path)| async move {
        let relative_path = format!("{stem}.narinfo");
        if !no_skip && cache.exists(&relative_path).await? {
            return Ok(());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        cache.put_narinfo(&stem, &content).await
    }))
    .await?;

    upload_concurrently(root_narinfos.into_iter().map(|(stem, path)| async move {
        let relative_path = format!("{stem}.narinfo");
        if !no_skip && cache.exists(&relative_path).await? {
            return Ok(());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        cache.put_narinfo(&stem, &content).await
    }))
    .await?;

    let cache_info_path = output_dir.join("nix-cache-info");
    let cache_info = std::fs::read_to_string(&cache_info_path)
        .with_context(|| format!("reading {}", cache_info_path.display()))?;
    cache.put_cache_info(&cache_info).await?;

    printer.success(&format!("Uploaded static cache files to {upload_url}"));
    Ok(())
}

/// Drive a set of upload futures with at most [`UPLOAD_CONCURRENCY`] in
/// flight, returning the first error encountered.
async fn upload_concurrently<I, F>(uploads: I) -> Result<()>
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = Result<()>>,
{
    futures_util::stream::iter(uploads)
        .buffer_unordered(UPLOAD_CONCURRENCY)
        .try_collect::<Vec<()>>()
        .await
        .map(|_| ())
}

/// List every top-level `*.narinfo` file under `dir` as `(stem, path)`.
fn list_narinfo_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("narinfo") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        files.push((stem.to_string(), path));
    }
    Ok(files)
}

/// Resolves the canonical NAR payload named by every staged narinfo.
///
/// The staging directory is a regenerable cache and can retain superseded
/// payloads. Uploading the whole `nar/` directory would republish those
/// unreferenced bytes and can violate the current content-addressed URL
/// contract. Each selected path is therefore derived from parsed narinfo,
/// canonicalized from its store path and file hash, and required to be a
/// direct regular child of `nar/`.
fn referenced_nar_files(
    output_dir: &Path,
    narinfos: &[(String, PathBuf)],
) -> Result<Vec<(String, PathBuf)>> {
    let mut names = BTreeSet::new();

    for (_, narinfo_path) in narinfos {
        let text = std::fs::read_to_string(narinfo_path)
            .with_context(|| format!("reading {}", narinfo_path.display()))?;
        let info = aos_core::nar::info::parse(&text)
            .with_context(|| format!("parsing {}", narinfo_path.display()))?;
        if info.compression != NarCompression::Zstd.name() {
            bail!(
                "staged narinfo {} does not declare zstd compression",
                narinfo_path.display()
            );
        }
        let file_hash = info.file_hash.as_deref().with_context(|| {
            format!("staged narinfo {} has no FileHash", narinfo_path.display())
        })?;
        let expected_url = nar_url(&info.store_path, file_hash, NarCompression::Zstd)?;
        if info.url != expected_url {
            bail!(
                "staged narinfo {} has non-canonical URL {}",
                narinfo_path.display(),
                info.url
            );
        }
        let name = expected_url
            .strip_prefix("nar/")
            .context("canonical NAR URL does not use the nar/ prefix")?;
        if name.is_empty() || name.contains('/') {
            bail!("canonical NAR URL is not a direct nar/ child: {expected_url}");
        }

        let path = output_dir.join("nar").join(name);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading referenced NAR {}", path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("referenced NAR is not a regular file: {}", path.display());
        }
        names.insert(name.to_string());
    }

    Ok(names
        .into_iter()
        .map(|name| {
            let path = output_dir.join("nar").join(&name);
            (name, path)
        })
        .collect())
}

/// Garbage-collect old staged static-cache narinfo/NAR pairs.
///
/// A pair is eligible when both the top-level `<hash>.narinfo` and the NAR
/// referenced by its `URL:` field are older than `max_age_days`. `dry_run`
/// reports candidates without removing files.
///
/// # Errors
///
/// Returns an error when the staging directory cannot be scanned, metadata
/// cannot be read, or an eligible file cannot be deleted.
pub fn gc_static_cache(
    output_dir: &Path,
    max_age_days: u64,
    dry_run: bool,
) -> Result<StaticCacheGcReport> {
    if !output_dir.exists() {
        return Ok(StaticCacheGcReport::default());
    }

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(
            max_age_days.saturating_mul(24 * 60 * 60),
        ))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut report = StaticCacheGcReport::default();

    for (hash, narinfo_path) in list_narinfo_files(output_dir)? {
        let text = std::fs::read_to_string(&narinfo_path)
            .with_context(|| format!("reading {}", narinfo_path.display()))?;
        let parsed = match aos_core::nar::info::parse(&text) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        let nar_path = output_dir.join(parsed.url.trim_start_matches('/'));
        if !nar_path.is_file() {
            continue;
        }
        if !older_than(&narinfo_path, cutoff)? || !older_than(&nar_path, cutoff)? {
            continue;
        }

        report.candidates += 1;
        report.hashes.push(hash);
        let narinfo_bytes = std::fs::metadata(&narinfo_path)
            .with_context(|| format!("stat {}", narinfo_path.display()))?
            .len();
        let nar_bytes = std::fs::metadata(&nar_path)
            .with_context(|| format!("stat {}", nar_path.display()))?
            .len();
        if !dry_run {
            std::fs::remove_file(&narinfo_path)
                .with_context(|| format!("removing {}", narinfo_path.display()))?;
            std::fs::remove_file(&nar_path)
                .with_context(|| format!("removing {}", nar_path.display()))?;
            report.deleted_files += 2;
            report.deleted_bytes += narinfo_bytes + nar_bytes;
        }
    }

    Ok(report)
}

fn older_than(path: &Path, cutoff: SystemTime) -> Result<bool> {
    let modified = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .modified()
        .with_context(|| format!("reading mtime for {}", path.display()))?;
    Ok(modified < cutoff)
}

fn touch_path(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("path contains NUL byte: {}", path.display()))?;
        // SAFETY: `c_path` is a valid, NUL-terminated pathname and a null
        // times pointer asks the OS to set atime/mtime to the current time.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), std::ptr::null(), 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("touching {}", path.display()));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        Ok(())
    }
}

/// Upload a generated static cache to every destination URL.
///
/// Destinations are attempted independently; a failure on one does not stop
/// uploads to the others.
///
/// # Errors
///
/// Returns an error aggregating all per-destination failures when any
/// upload fails.
pub async fn upload_static_cache_to_all(
    output_dir: &Path,
    upload_urls: &[String],
    auth: &AuthOptions,
    root_hashes: &[String],
    no_skip: bool,
    printer: &Printer,
) -> Result<()> {
    let results = join_all(upload_urls.iter().map(|upload_url| async move {
        upload_static_cache(output_dir, upload_url, auth, root_hashes, no_skip, printer)
            .await
            .map_err(|err| format!("{upload_url}: {err:#}"))
    }))
    .await;

    let failures: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    if !failures.is_empty() {
        bail!(
            "static cache upload failed for {}/{} destination(s):\n{}",
            failures.len(),
            upload_urls.len(),
            failures.join("\n")
        );
    }

    Ok(())
}

/// Insert a cache endpoint into the registry's committed `[caches]` stack.
///
/// Adds `cache_url` to the ordered top-level `try` stack, preserving an
/// existing nested stack as the first member. Returns `true` when the file was
/// modified and `false` when the endpoint is already present. The `priority`
/// argument remains the `nix-cache-info` priority; committed topology order,
/// not a second numeric field, defines endpoint preference after cutover.
///
/// # Errors
///
/// Returns an error when `registry.toml` cannot be read, parsed, or
/// rewritten, or when its `[caches]` value is malformed.
pub fn upsert_registry_cache(registry_dir: &Path, cache_url: &str, _priority: u32) -> Result<bool> {
    let path = registry_dir.join("registry.toml");
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut value: TomlValue =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let root = value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("registry.toml root is not a table"))?;
    let endpoint = || {
        let mut table = toml::map::Map::new();
        table.insert(
            "endpoint".to_string(),
            TomlValue::String(cache_url.to_string()),
        );
        TomlValue::Table(table)
    };
    let already_present = root
        .get("caches")
        .is_some_and(|value| cache_stack_contains_endpoint(value, cache_url));
    let changed = !already_present;
    if changed {
        match root.remove("caches") {
            None => {
                root.insert("caches".to_string(), endpoint());
            }
            Some(existing) => {
                let mut table = toml::map::Map::new();
                table.insert("kind".to_string(), TomlValue::String("try".to_string()));
                table.insert(
                    "members".to_string(),
                    TomlValue::Array(vec![existing, endpoint()]),
                );
                root.insert("caches".to_string(), TomlValue::Table(table));
            }
        }
    }

    if changed {
        std::fs::write(&path, toml::to_string_pretty(&value)?)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(changed)
}

fn cache_stack_contains_endpoint(value: &TomlValue, expected: &str) -> bool {
    value
        .get("endpoint")
        .and_then(TomlValue::as_str)
        .is_some_and(|endpoint| endpoint == expected)
        || value
            .get("members")
            .and_then(TomlValue::as_array)
            .is_some_and(|members| {
                members
                    .iter()
                    .any(|member| cache_stack_contains_endpoint(member, expected))
            })
}

/// Returns whether the registry references at least one cacheable store path.
///
/// # Errors
///
/// Returns an error when package metadata cannot be read or parsed.
pub fn registry_has_store_roots(registry_dir: &Path) -> Result<bool> {
    Ok(!collect_static_cache_roots(registry_dir)?.is_empty())
}

/// Collect the sorted root store paths the registry references.
///
/// Roots are the paths directly recorded in package TOML metadata: runtime
/// outputs, source derivations, image outputs, configuration outputs, and
/// configuration evaluation base libraries. Closure expansion happens later so
/// remote root membership can skip entire closures.
///
/// # Errors
///
/// Returns an error when package metadata cannot be read or parsed.
pub fn collect_static_cache_roots(registry_dir: &Path) -> Result<Vec<String>> {
    let packages = registry_dir.join("packages");
    if !packages.exists() {
        return Ok(Vec::new());
    }
    let mut roots = BTreeSet::new();
    collect_store_paths_from_dir(&packages, &mut roots)?;

    Ok(roots.into_iter().collect())
}

/// Collect the sorted closure of the selected root store paths.
fn collect_store_path_closures(roots: &[String]) -> Result<Vec<String>> {
    let mut paths = BTreeSet::new();
    for root in roots {
        collect_store_path_closure(root, &mut paths)?;
    }
    Ok(paths.into_iter().collect())
}

/// Determine the single store directory shared by all paths.
///
/// A static cache advertises one `StoreDir`, so mixed store roots cannot be
/// served from the same cache and are rejected.
fn common_store_dir(paths: &[String]) -> Result<String> {
    let first = paths
        .first()
        .ok_or_else(|| anyhow::anyhow!("registry contains no store paths to cache"))?;
    let store_dir = store_dir_of(first)?;

    for path in &paths[1..] {
        let candidate = store_dir_of(path)?;
        if candidate != store_dir {
            bail!(
                "cannot generate one static cache for mixed store directories: {store_dir} and {candidate}"
            );
        }
    }

    Ok(store_dir)
}

/// Return the parent (store) directory of a store path.
fn store_dir_of(store_path: &str) -> Result<String> {
    Path::new(store_path)
        .parent()
        .map(|path| path.display().to_string())
        .ok_or_else(|| anyhow::anyhow!("store path has no parent directory: {store_path}"))
}

/// Expand a root path to its runtime closure via `nix-store -qR`, re-rooting
/// every member onto the root's store directory. Falls back to the root
/// alone if the query returns nothing.
fn collect_store_path_closure(store_path: &str, paths: &mut BTreeSet<String>) -> Result<()> {
    let store_dir = store_dir_of(store_path)?;
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["-qR", store_path])
        .output()
        .with_context(|| format!("running nix-store -qR {store_path}"))?;
    if !output.status.success() {
        bail!(
            "nix-store -qR failed for {store_path}: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    let mut found = false;
    for path in String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        paths.insert(re_root_store_path(path, &store_dir)?);
        found = true;
    }

    if !found {
        paths.insert(store_path.to_string());
    }

    Ok(())
}

/// Recursively scan a packages directory for TOML files and harvest their
/// store paths.
fn collect_store_paths_from_dir(dir: &Path, paths: &mut BTreeSet<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_store_paths_from_dir(&path, paths)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let value: TomlValue =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        collect_store_paths_from_package(&value, paths);
    }
    Ok(())
}

/// Harvest every cacheable store root from one parsed package TOML document.
fn collect_store_paths_from_package(value: &TomlValue, paths: &mut BTreeSet<String>) {
    let Some(versions) = value.get("versions").and_then(TomlValue::as_array) else {
        return;
    };
    for version in versions {
        let Some(platforms) = version.get("platforms").and_then(TomlValue::as_table) else {
            continue;
        };
        for platform in platforms.values() {
            if let Some(path) = platform.get("store_path").and_then(TomlValue::as_str) {
                paths.insert(path.to_string());
            }
            if let Some(path) = platform.get("source_drv").and_then(TomlValue::as_str)
                && !path.is_empty()
            {
                paths.insert(path.to_string());
            }
            if let Some(images) = platform.get("images").and_then(TomlValue::as_array) {
                for image in images {
                    if let Some(path) = image.get("store_path").and_then(TomlValue::as_str) {
                        paths.insert(path.to_string());
                    }
                }
            }
            if let Some(config_module) = platform.get("config_module") {
                for output in ["config_output", "evaluation_base_lib"] {
                    if let Some(path) = config_module
                        .get(output)
                        .and_then(|metadata| metadata.get("store_path"))
                        .and_then(TomlValue::as_str)
                    {
                        paths.insert(path.to_string());
                    }
                }
            }
        }
    }
}

/// Assert that a store path is valid in the local Nix store.
fn check_store_path_valid(path: &str) -> Result<()> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--check-validity", path])
        .output()
        .with_context(|| format!("running nix-store --check-validity {path}"))?;
    if !output.status.success() {
        bail!("registry store path {path} is not present in the local Nix store");
    }
    Ok(())
}

/// Query NAR metadata for one path via `nix path-info --json`.
fn query_path_info(path: &str) -> Result<CachePathInfo> {
    let output = Command::new("nix")
        .envs(aos_nix_env())
        .args(["path-info", "--json", path])
        .output()
        .with_context(|| format!("running nix path-info on {path}"))?;
    if !output.status.success() {
        bail!(
            "nix path-info failed for {path}: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: JsonValue = serde_json::from_str(&stdout)
        .with_context(|| format!("parsing nix path-info JSON for {path}"))?;
    path_info_from_json(path, &json)
}

/// Convert `nix path-info` JSON into [`CachePathInfo`] for `requested_path`.
///
/// Validates that the reported path's hash matches the request, re-roots the
/// path, references, and deriver onto the requested store directory, and
/// drops self-references.
fn path_info_from_json(requested_path: &str, json: &JsonValue) -> Result<CachePathInfo> {
    let info = select_path_info(json);
    let store_dir = store_dir_of(requested_path)?;
    let requested_hash = store_hash(requested_path);
    let reported_path = info
        .get("path")
        .and_then(JsonValue::as_str)
        .unwrap_or(requested_path);

    if store_hash(reported_path) != requested_hash {
        bail!("nix path-info returned {reported_path} for requested {requested_path}");
    }

    let nar_hash = info
        .get("narHash")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("nix path-info missing narHash for {requested_path}"))?
        .to_string();
    let nar_size = info
        .get("narSize")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow::anyhow!("nix path-info missing narSize for {requested_path}"))?;
    let path = re_root_store_path(reported_path, &store_dir)?;
    let references = info
        .get("references")
        .and_then(JsonValue::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(JsonValue::as_str)
                .filter(|reference| store_hash(reference) != requested_hash)
                .map(|reference| re_root_store_path(reference, &store_dir))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let deriver = info
        .get("deriver")
        .or_else(|| info.get("deriverPath"))
        .and_then(JsonValue::as_str)
        .filter(|deriver| !deriver.is_empty())
        .map(|deriver| re_root_store_path(deriver, &store_dir))
        .transpose()?;

    Ok(CachePathInfo {
        path,
        nar_hash,
        nar_size,
        references,
        deriver,
    })
}

/// Rewrite a store path's directory prefix, keeping its basename.
fn re_root_store_path(store_path: &str, store_dir: &str) -> Result<String> {
    let name = basename(store_path);
    if name.is_empty() {
        bail!("store path has no basename: {store_path}");
    }
    Ok(format!("{store_dir}/{name}"))
}

/// Normalize the `nix path-info --json` output shape, which varies across
/// Nix versions: an array of entries, a direct info object, or an object
/// keyed by store path.
fn select_path_info(json: &JsonValue) -> JsonValue {
    if let Some(array) = json.as_array() {
        return array.first().cloned().unwrap_or_else(|| json.clone());
    }
    if let Some(object) = json.as_object() {
        if object.contains_key("path")
            || object.contains_key("narHash")
            || object.contains_key("narSize")
        {
            return json.clone();
        }
        return object
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| json.clone());
    }
    json.clone()
}

/// Stream `nix-store --dump <path>` through a zstd encoder straight to
/// `dest`, returning the compressed file's `(file_hash, file_size)`.
///
/// The uncompressed NAR is never fully buffered: it streams from the dump
/// subprocess through the encoder into the output file while the compressed
/// bytes are hashed on the fly. `threads > 1` enables zstd multithreading
/// (zstdmt) for the single stream. The output is written to a temp file and
/// atomically renamed into place so a crash never leaves a half-written NAR.
fn compress_nar_to_file(
    store_path: &str,
    dest: &Path,
    level: i32,
    threads: u32,
) -> Result<(String, u64)> {
    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let mut child = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--dump", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning nix-store --dump {store_path}"))?;
    let mut dump_stdout = child
        .stdout
        .take()
        .context("nix-store --dump produced no stdout")?;

    let file = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let mut encoder =
        zstd::stream::write::Encoder::new(HashingWriter::new(BufWriter::new(file)), level)
            .context("initializing zstd encoder")?;
    if threads > 1 {
        encoder
            .multithread(threads)
            .context("enabling zstd multithreading")?;
    }

    let copy_result = io::copy(&mut dump_stdout, &mut encoder).context("compressing NAR stream");
    // Always reap the child to avoid a zombie, even if copy/finish failed.
    let digest = copy_result.and_then(|_| {
        let writer = encoder.finish().context("finalizing zstd stream")?;
        writer.finish().context("flushing compressed NAR")
    });

    let status = child.wait().context("waiting for nix-store --dump")?;
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut handle) = child.stderr.take() {
            let _ = handle.read_to_string(&mut stderr);
        }
        let _ = std::fs::remove_file(&tmp);
        bail!(
            "nix-store --dump failed for {store_path}: {}",
            stderr.trim()
        );
    }

    let digest = match digest {
        Ok(digest) => digest,
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
    };

    std::fs::rename(&tmp, dest)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), dest.display()))?;
    Ok(digest)
}

/// A [`Write`] wrapper that forwards bytes to an inner writer while hashing
/// them (SHA-256) and counting them. Used to compute a compressed NAR's
/// `FileHash`/`FileSize` as it streams to disk.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    count: u64,
}

impl<W: Write> HashingWriter<W> {
    /// Wraps `inner`, starting an empty hash and zero byte count.
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    /// Flushes the inner writer and returns the `(file_hash, file_size)` of
    /// everything written so far.
    fn finish(mut self) -> io::Result<(String, u64)> {
        self.inner.flush()?;
        let digest = self.hasher.finalize();
        Ok((format!("sha256:{}", hex::encode(digest)), self.count))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::nar::info as narinfo;
    use tempfile::TempDir;

    #[test]
    fn local_reuse_requires_file_hash_addressed_nar_url() {
        let output = TempDir::new().unwrap();
        std::fs::create_dir_all(output.path().join("nar")).unwrap();
        let payload = b"payload";
        let compressed = zstd::stream::encode_all(payload.as_slice(), 3).unwrap();
        let info = CachePathInfo {
            path: "/nix/store/abc123-package".into(),
            nar_hash: format!("sha256:{}", hex::encode(Sha256::digest(payload))),
            nar_size: payload.len() as u64,
            references: Vec::new(),
            deriver: None,
        };
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&compressed)));
        let file_size = compressed.len();
        let expected = nar_url(&info.path, &file_hash, NarCompression::Zstd).unwrap();
        std::fs::write(output.path().join(&expected), &compressed).unwrap();
        std::fs::write(
            output.path().join("abc123.narinfo"),
            format!(
                "StorePath: {}\nURL: {expected}\nCompression: zstd\nFileHash: {file_hash}\nFileSize: {file_size}\nNarHash: {}\nNarSize: 7\n",
                info.path, info.nar_hash
            ),
        )
        .unwrap();

        assert_eq!(
            reusable_nar(output.path(), &info)
                .unwrap()
                .map(|nar| nar.name),
            expected.strip_prefix("nar/").map(str::to_string),
        );

        std::fs::write(output.path().join(&expected), b"PAYLOAD").unwrap();
        assert!(reusable_nar(output.path(), &info).unwrap().is_none());
        std::fs::write(output.path().join(&expected), &compressed).unwrap();
        std::fs::write(
            output.path().join("abc123.narinfo"),
            format!(
                "StorePath: {}\nURL: {expected}\nCompression: xz\nFileHash: {file_hash}\nFileSize: {file_size}\nNarHash: {}\nNarSize: 7\n",
                info.path, info.nar_hash
            ),
        )
        .unwrap();
        assert!(reusable_nar(output.path(), &info).unwrap().is_none());

        let legacy = format!("nar/{}-legacy.nar.zst", store_hash(&info.path));
        std::fs::write(
            output.path().join("abc123.narinfo"),
            format!(
                "StorePath: {}\nURL: {legacy}\nCompression: zstd\nFileHash: {file_hash}\nFileSize: {file_size}\nNarHash: {}\nNarSize: 7\n",
                info.path, info.nar_hash
            ),
        )
        .unwrap();
        assert!(reusable_nar(output.path(), &info).unwrap().is_none());
    }

    #[test]
    fn staged_nar_cleanup_rejects_another_store_paths_payload() {
        let output = TempDir::new().unwrap();
        std::fs::create_dir_all(output.path().join("nar")).unwrap();
        let info = CachePathInfo {
            path: "/nix/store/abc123-package".into(),
            nar_hash: format!("sha256:{}", "11".repeat(32)),
            nar_size: 7,
            references: Vec::new(),
            deriver: None,
        };
        let file_hash = format!("sha256:{}", "22".repeat(32));
        let other_url = nar_url(
            "/nix/store/other123-package",
            &file_hash,
            NarCompression::Zstd,
        )
        .unwrap();
        std::fs::write(output.path().join(&other_url), b"other payload").unwrap();
        std::fs::write(
            output.path().join("abc123.narinfo"),
            format!(
                "StorePath: {}\nURL: {other_url}\nCompression: zstd\nFileHash: {file_hash}\nFileSize: 13\nNarHash: {}\nNarSize: 7\n",
                info.path, info.nar_hash
            ),
        )
        .unwrap();

        assert_eq!(staged_nar_path(output.path(), &info), None);
        assert!(output.path().join(other_url).is_file());
    }

    #[test]
    fn collect_store_paths_reads_all_package_outputs() {
        let mut paths = BTreeSet::new();
        let value: TomlValue = toml::from_str(
            r#"
[package]
name = "kernel"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/root111-kernel"
nar_hash = "sha256:root"
nar_size = 1
source_drv = "/nix/store/src111-kernel-source"
source_nar_hash = "sha256:source"
references = []

[[versions.platforms.x86_64-linux.images]]
format = "qcow2"
store_path = "/nix/store/img111-system-image"
nar_hash = "sha256:image"
nar_size = 2

[versions.platforms.x86_64-linux.config_module.config_output]
store_path = "/nix/store/cfg111-kernel-config"
nar_hash = "sha256:config"
nar_size = 3
references = []

[versions.platforms.x86_64-linux.config_module.evaluation_base_lib]
store_path = "/nix/store/lib111-config-base-lib"
nar_hash = "sha256:base-lib"
nar_size = 4
references = []
"#,
        )
        .unwrap();
        collect_store_paths_from_package(&value, &mut paths);
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            vec![
                "/nix/store/cfg111-kernel-config".to_string(),
                "/nix/store/img111-system-image".to_string(),
                "/nix/store/lib111-config-base-lib".to_string(),
                "/nix/store/root111-kernel".to_string(),
                "/nix/store/src111-kernel-source".to_string(),
            ]
        );
    }

    #[test]
    fn common_store_dir_accepts_alternate_store_paths() {
        let paths = vec![
            "/tmp/aos-root/store/aaa111-package-a".to_string(),
            "/tmp/aos-root/store/bbb222-package-b".to_string(),
        ];

        assert_eq!(common_store_dir(&paths).unwrap(), "/tmp/aos-root/store");
    }

    #[test]
    fn common_store_dir_rejects_mixed_store_paths() {
        let paths = vec![
            "/tmp/aos-root/store/aaa111-package-a".to_string(),
            "/nix/store/bbb222-package-b".to_string(),
        ];

        let err = common_store_dir(&paths).unwrap_err().to_string();
        assert!(err.contains("mixed store directories"));
    }

    #[test]
    fn re_root_store_path_uses_requested_store_dir() {
        assert_eq!(
            re_root_store_path("/nix/store/aaa111-package-a", "/tmp/aos-root/store").unwrap(),
            "/tmp/aos-root/store/aaa111-package-a",
        );
    }

    #[test]
    fn path_info_from_json_preserves_requested_alternate_store_path() {
        let json = serde_json::json!({
            "path": "/nix/store/aaa111-package-a",
            "narHash": "sha256-test",
            "narSize": 123,
            "references": [
                "/nix/store/aaa111-package-a",
                "/nix/store/bbb222-library-b"
            ],
            "deriver": "/nix/store/ccc333-package-a.drv"
        });

        let info = path_info_from_json("/tmp/aos-root/store/aaa111-package-a", &json).unwrap();

        assert_eq!(info.path, "/tmp/aos-root/store/aaa111-package-a");
        assert_eq!(info.nar_hash, "sha256-test");
        assert_eq!(info.nar_size, 123);
        assert_eq!(
            info.references,
            vec!["/tmp/aos-root/store/bbb222-library-b"],
        );
        assert_eq!(
            info.deriver.as_deref(),
            Some("/tmp/aos-root/store/ccc333-package-a.drv"),
        );
    }

    #[test]
    fn path_info_from_json_rejects_mismatched_reported_path() {
        let json = serde_json::json!({
            "path": "/nix/store/zzz999-package-a",
            "narHash": "sha256-test",
            "narSize": 123,
        });

        let err = path_info_from_json("/tmp/aos-root/store/aaa111-package-a", &json).unwrap_err();
        assert!(err.to_string().contains("nix path-info returned"));
    }

    #[test]
    fn upsert_registry_cache_adds_and_updates_entry() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("registry.toml"),
            r#"[registry]
name = "test"
"#,
        )
        .unwrap();

        assert!(upsert_registry_cache(tmp.path(), "https://cache.example", 100).unwrap());
        assert!(!upsert_registry_cache(tmp.path(), "https://cache.example", 100).unwrap());
        assert!(!upsert_registry_cache(tmp.path(), "https://cache.example", 200).unwrap());

        let content = std::fs::read_to_string(tmp.path().join("registry.toml")).unwrap();
        assert!(content.contains("[caches]"));
        assert!(content.contains("endpoint = \"https://cache.example\""));
    }

    #[tokio::test]
    async fn upload_static_cache_to_all_writes_each_filesystem_destination() {
        let source = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);
        let store_path = "/nix/store/abc123-pkg";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"nar-bytes")));
        let payload_url = nar_url(store_path, &file_hash, NarCompression::Zstd).unwrap();
        let narinfo_body = render_static_narinfo(
            &StaticNarInfoInput {
                store_path,
                nar_hash: "sha256:def456",
                nar_size: 5,
                references: &[],
                deriver: None,
                signatures: &[],
                file_hash: &file_hash,
                file_size: 9,
                compression: NarCompression::Zstd,
            },
            "/nix/store",
            None,
        )
        .unwrap();

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("nix-cache-info"),
            nix_cache_info("/nix/store", 37),
        )
        .unwrap();
        std::fs::write(source.path().join("abc123.narinfo"), &narinfo_body).unwrap();
        std::fs::write(source.path().join(&payload_url), b"nar-bytes").unwrap();

        let upload_urls = vec![
            format!("file://{}", first.path().display()),
            format!("file://{}", second.path().display()),
        ];
        upload_static_cache_to_all(
            source.path(),
            &upload_urls,
            &AuthOptions::default(),
            &[],
            false,
            &printer,
        )
        .await
        .unwrap();

        for dest in [first.path(), second.path()] {
            assert!(dest.join("nix-cache-info").exists());
            assert_eq!(
                std::fs::read_to_string(dest.join("nix-cache-info")).unwrap(),
                nix_cache_info("/nix/store", 37),
            );
            assert_eq!(
                std::fs::read_to_string(dest.join("abc123.narinfo")).unwrap(),
                narinfo_body
            );
            assert_eq!(
                std::fs::read(dest.join(&payload_url)).unwrap(),
                b"nar-bytes"
            );
        }
    }

    #[tokio::test]
    async fn static_cache_upload_preserves_narinfo_url_object_path() {
        let source = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);
        let store_path = "/nix/store/abc123-package";
        let nar_hash = "sha256:def456";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"nar-bytes")));
        let nar_url = nar_url(store_path, &file_hash, NarCompression::Zstd).unwrap();

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("nix-cache-info"),
            nix_cache_info("/nix/store", 40),
        )
        .unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            render_static_narinfo(
                &StaticNarInfoInput {
                    store_path,
                    nar_hash,
                    nar_size: 5,
                    references: &[],
                    deriver: None,
                    signatures: &[],
                    file_hash: &file_hash,
                    file_size: 9,
                    compression: NarCompression::Zstd,
                },
                "/nix/store",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(source.path().join(&nar_url), b"nar-bytes").unwrap();
        std::fs::write(
            source.path().join("nar/obsolete-legacy-name.nar.zst"),
            b"obsolete",
        )
        .unwrap();

        upload_static_cache(
            source.path(),
            &format!("file://{}", dest.path().display()),
            &AuthOptions::default(),
            &[],
            false,
            &printer,
        )
        .await
        .unwrap();

        let uploaded_narinfo = std::fs::read_to_string(dest.path().join("abc123.narinfo")).unwrap();
        let parsed = narinfo::parse(&uploaded_narinfo).unwrap();
        assert_eq!(parsed.url, nar_url);
        assert_eq!(
            std::fs::read(dest.path().join(parsed.url)).unwrap(),
            b"nar-bytes",
        );
        assert!(
            !dest
                .path()
                .join("nar/obsolete-legacy-name.nar.zst")
                .exists()
        );
    }

    #[tokio::test]
    async fn upload_static_cache_to_all_reports_partial_failures() {
        let source = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);
        let store_path = "/nix/store/abc123-pkg";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"nar-bytes")));
        let payload_url = nar_url(store_path, &file_hash, NarCompression::Zstd).unwrap();
        let narinfo_body = render_static_narinfo(
            &StaticNarInfoInput {
                store_path,
                nar_hash: "sha256:def456",
                nar_size: 5,
                references: &[],
                deriver: None,
                signatures: &[],
                file_hash: &file_hash,
                file_size: 9,
                compression: NarCompression::Zstd,
            },
            "/nix/store",
            None,
        )
        .unwrap();

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("nix-cache-info"),
            nix_cache_info("/nix/store", 40),
        )
        .unwrap();
        std::fs::write(source.path().join("abc123.narinfo"), narinfo_body).unwrap();
        std::fs::write(source.path().join(payload_url), b"nar-bytes").unwrap();

        let upload_urls = vec![
            format!("file://{}", first.path().display()),
            "not-a-url".to_string(),
            format!("file://{}", second.path().display()),
        ];
        let err = upload_static_cache_to_all(
            source.path(),
            &upload_urls,
            &AuthOptions::default(),
            &[],
            false,
            &printer,
        )
        .await
        .unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("static cache upload failed for 1/3 destination"));
        assert!(message.contains("not-a-url"));
        for dest in [first.path(), second.path()] {
            assert!(dest.join("nix-cache-info").exists());
            assert!(dest.join("abc123.narinfo").exists());
        }
    }

    #[test]
    fn gc_static_cache_reports_and_deletes_old_pairs() {
        let source = TempDir::new().unwrap();
        let store_path = "/nix/store/abc123-package";
        let nar_hash = "sha256:def456";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"nar-bytes")));
        let nar_url = nar_url(store_path, &file_hash, NarCompression::Zstd).unwrap();
        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            render_static_narinfo(
                &StaticNarInfoInput {
                    store_path,
                    nar_hash,
                    nar_size: 5,
                    references: &[],
                    deriver: None,
                    signatures: &[],
                    file_hash: &file_hash,
                    file_size: 9,
                    compression: NarCompression::Zstd,
                },
                "/nix/store",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(source.path().join(&nar_url), b"nar-bytes").unwrap();
        set_mtime_days_ago(&source.path().join("abc123.narinfo"), 2);
        set_mtime_days_ago(&source.path().join(&nar_url), 2);

        let dry_run = gc_static_cache(source.path(), 1, true).unwrap();
        assert_eq!(dry_run.candidates, 1);
        assert_eq!(dry_run.deleted_files, 0);
        assert!(source.path().join("abc123.narinfo").exists());
        assert!(source.path().join(&nar_url).exists());

        let deleted = gc_static_cache(source.path(), 1, false).unwrap();
        assert_eq!(deleted.candidates, 1);
        assert_eq!(deleted.deleted_files, 2);
        assert!(!source.path().join("abc123.narinfo").exists());
        assert!(!source.path().join(&nar_url).exists());
    }

    #[test]
    fn gc_static_cache_keeps_recent_pairs() {
        let source = TempDir::new().unwrap();
        let store_path = "/nix/store/abc123-package";
        let nar_hash = "sha256:def456";
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"nar-bytes")));
        let nar_url = nar_url(store_path, &file_hash, NarCompression::Zstd).unwrap();
        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            render_static_narinfo(
                &StaticNarInfoInput {
                    store_path,
                    nar_hash,
                    nar_size: 5,
                    references: &[],
                    deriver: None,
                    signatures: &[],
                    file_hash: &file_hash,
                    file_size: 9,
                    compression: NarCompression::Zstd,
                },
                "/nix/store",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(source.path().join(&nar_url), b"nar-bytes").unwrap();

        let report = gc_static_cache(source.path(), 30, false).unwrap();
        assert_eq!(report.candidates, 0);
        assert!(source.path().join("abc123.narinfo").exists());
        assert!(source.path().join(&nar_url).exists());
    }

    #[cfg(unix)]
    fn set_mtime_days_ago(path: &Path, days: u64) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(days * 24 * 60 * 60) as libc::time_t;
        let times = [
            libc::timespec {
                tv_sec: timestamp,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: timestamp,
                tv_nsec: 0,
            },
        ];
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is NUL-terminated and `times` points to two valid
        // timespec values for atime and mtime.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat failed for {}", path.display());
    }

    #[cfg(not(unix))]
    fn set_mtime_days_ago(_path: &Path, _days: u64) {}
}
