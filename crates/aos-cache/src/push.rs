//! The `aos cache push` operation: upload closure paths to a cache.
//!
//! Push resolves installables to store paths, enumerates their closure,
//! asks the [`CacheBackend`] which paths it is missing, and uploads each
//! missing path as a compressed NAR plus a `.narinfo` metadata file.
//!
//! For AOS servers (backends where [`CacheBackend::supports_pack`] is
//! true), small NARs are accumulated into *packs* — concatenated
//! `nix-store --export` streams uploaded in one request — to amortise
//! per-request overhead. Paths are uploaded in dependency order
//! (references before referrers) so the server can import each entry as
//! it arrives.

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use anyhow::{Context, Result};
use futures::stream::{StreamExt, TryStreamExt};
use indicatif::HumanBytes;
use sha2::{Digest, Sha256};

use aos_core::nar::info as narinfo;
use aos_core::nar::pack::{self, PackPath};
use aos_core::nix::{NixCli, PathInfo};
use aos_core::output::Printer;
use aos_net::{
    MultipartAdmission, MultipartBackend, MultipartSessionState, MultipartSource,
    MultipartUploadRequest, TransferEngine, TransferEngineConfig,
};

use crate::backend::{CacheBackend, ObjectUploadAdmission, UploadedNarinfo};
use crate::bandwidth;
use crate::compress::{compression_ext, compression_name, streaming_compress, streaming_export};
use crate::resolve::resolve_installables;

/// Uploads all closure paths missing from the cache.
///
/// The pipeline is:
///
/// 1. Resolve `installables` / `file` / `attr` / `expr` to store paths.
/// 2. Enumerate the combined closure, gather path metadata, and order it
///    so references come before referrers.
/// 3. Query the backend for missing paths (in chunks of 500 hashes).
/// 4. For each missing path: compress the NAR (`compression` is `zstd`,
///    `xz`, or `none`; `compression_level` is passed to the compressor),
///    generate the narinfo, and upload.
///
/// On backends that support packs (the AOS server), NARs whose
/// compressed size is below `batch_threshold` (a human-readable size
/// such as `"1MB"`) are batched into a single pack upload; larger NARs
/// flush the pending batch first so dependency order is preserved, then
/// upload as a single-entry pack. Other backends receive individual
/// `put_nar` / `put_narinfo` uploads.
///
/// `jobs` caps concurrent uploads (a value of `0` is treated as `1`);
/// `max_bandwidth` accepts a rate such as `"100MB/s"` and `None` means
/// unlimited. With `dry_run` the missing paths and their NAR sizes are
/// printed and nothing is uploaded.
///
/// # Errors
///
/// Returns an error if installable resolution, closure enumeration,
/// metadata gathering, threshold or bandwidth parsing, compression, or
/// any backend upload or query fails.
#[allow(clippy::too_many_arguments, clippy::disallowed_methods)]
pub async fn run_push(
    printer: &Printer,
    backend: &dyn CacheBackend,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
    target: Option<&str>,
    jobs: usize,
    max_bandwidth: Option<&str>,
    batch_threshold: &str,
    compression: &str,
    compression_level: i32,
    dry_run: bool,
) -> Result<()> {
    let start = Instant::now();
    let nix = NixCli::new(0);
    let batch_threshold_bytes = bandwidth::parse_size(batch_threshold)?;

    // 1. Resolve installables to store paths.
    printer.info("Resolving installables...");
    let store_paths = resolve_installables(&nix, installables, file, attr, expr, target)?;

    // 2. Enumerate closure — one `nix-store -qR` over all installables rather
    //    than one subprocess per path.
    printer.info("Enumerating closure...");
    let store_path_refs: Vec<&str> = store_paths.iter().map(String::as_str).collect();
    let mut all_paths = nix.closure_many(&store_path_refs)?;
    all_paths.sort();
    all_paths.dedup();
    printer.info(&format!("{} paths in closure", all_paths.len()));

    // 3. Gather metadata.
    printer.info("Gathering path metadata...");
    let path_refs: Vec<&str> = all_paths.iter().map(String::as_str).collect();
    let mut infos = nix.path_info_batch(&path_refs)?;
    order_path_infos_for_import(&mut infos);

    // 4. Query missing (in chunks of 500).
    let store_hashes: Vec<&str> = all_paths.iter().map(|p| narinfo::store_hash(p)).collect();
    printer.info("Querying cache for missing paths...");
    let mut missing_hashes = Vec::new();
    for chunk in store_hashes.chunks(500) {
        let mut chunk_missing = backend.query_missing(chunk).await?;
        missing_hashes.append(&mut chunk_missing);
    }

    if missing_hashes.is_empty() {
        printer.success("All paths already cached.");
        return Ok(());
    }

    printer.info(&format!(
        "{}/{} paths need uploading",
        missing_hashes.len(),
        all_paths.len()
    ));

    if dry_run {
        for info in &infos {
            let hash = narinfo::store_hash(&info.path);
            if missing_hashes.contains(&hash.to_string()) {
                printer.plain(&format!(
                    "  {} ({})",
                    narinfo::basename(&info.path),
                    HumanBytes(info.nar_size)
                ));
            }
        }
        printer.info("Dry run — nothing uploaded.");
        return Ok(());
    }

    // 5. Initialize cache.
    backend.ensure_cache_info("/nix/store").await?;

    // 6. Upload missing paths with streaming compression pipeline.
    let limiter = bandwidth::BandwidthLimiter::new(
        max_bandwidth
            .map(bandwidth::parse_bandwidth)
            .transpose()?
            .unwrap_or(0),
    );

    let overall = printer.items("Uploading cache paths", missing_hashes.len() as u64);

    let effective_jobs = if jobs == 0 { 1 } else { jobs };
    let mut total_bytes: u64 = 0;
    let uploaded: u64;

    if backend.supports_pack() {
        // AOS pack mode: small NARs are batched into dependency-ordered pack
        // uploads. This accumulation is stateful, so it stays sequential.
        let mut pack_paths: Vec<PackPath> = Vec::new();
        let mut pack_narinfos: Vec<(String, String)> = Vec::new();
        let mut count = 0u64;
        for info in &infos {
            let hash = narinfo::store_hash(&info.path);
            if !missing_hashes.contains(&hash.to_string()) {
                continue;
            }

            let compressed = streaming_compress(&info.path, compression, compression_level)?;
            let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&compressed)));
            let file_size = compressed.len() as u64;
            if limiter.is_active() {
                limiter.acquire(file_size).await;
            }
            let nar_filename = format!(
                "{}.{}",
                file_hash.replace(':', "-"),
                compression_ext(compression)
            );
            let narinfo_text =
                build_narinfo(info, &file_hash, file_size, &nar_filename, compression);

            // AOS pack upload imports Nix export streams server-side.
            let exported = streaming_export(&info.path)?;
            let pack_path = PackPath {
                hash: hash.to_string(),
                nar_data: exported,
            };
            let pack_narinfo = (hash.to_string(), narinfo_text);

            if file_size < batch_threshold_bytes {
                pack_paths.push(pack_path);
                pack_narinfos.push(pack_narinfo);
            } else {
                upload_pack_entries(backend, &pack_paths, &pack_narinfos).await?;
                pack_paths.clear();
                pack_narinfos.clear();
                upload_pack_entries(backend, &[pack_path], &[pack_narinfo]).await?;
            }

            total_bytes += file_size;
            count += 1;
            overall.inc(1);
        }
        // Flush any remaining pack paths.
        upload_pack_entries(backend, &pack_paths, &pack_narinfos).await?;
        uploaded = count;
    } else {
        // Direct-upload mode (the common HTTP/Worker path): genuinely
        // concurrent. Each missing path compresses on a blocking thread and
        // uploads independently, up to `effective_jobs` in flight at once — the
        // earlier semaphore loop awaited each path serially, so `--jobs` had no
        // effect. NAR bytes go straight to a presigned origin URL when the cache
        // offers one (bypassing the Hub data proxy); narinfo admission always
        // goes through the typed Hub API so inventory and GC stay authoritative.
        let work: Vec<&PathInfo> = infos
            .iter()
            .filter(|info| missing_hashes.contains(&narinfo::store_hash(&info.path).to_string()))
            .collect();
        let wave_size = effective_jobs.min(MAX_DIRECT_UPLOAD_WAVE).max(1);
        let mut completed = 0u64;
        for wave in work.chunks(wave_size) {
            let prepared: Vec<PreparedUpload> = futures::stream::iter(wave.iter().copied())
                .map(|info| prepare_upload(info, compression, compression_level))
                .buffer_unordered(effective_jobs)
                .try_collect()
                .await?;
            let admission_inputs = prepared
                .iter()
                .map(|upload| (upload.nar_path.clone(), upload.file_size))
                .collect::<Vec<_>>();
            let admissions = backend.create_object_uploads(&admission_inputs).await?;
            let results: Vec<(u64, UploadedNarinfo)> =
                futures::stream::iter(prepared.into_iter())
                    .map(|upload| {
                        let limiter = &limiter;
                        let admission = admissions.get(&upload.nar_path).cloned();
                        async move {
                            upload_prepared(backend, upload, admission.as_ref(), limiter).await
                        }
                    })
                    .buffer_unordered(effective_jobs)
                    .try_collect()
                    .await?;
            let narinfos = results
                .iter()
                .map(|(_, narinfo)| narinfo.clone())
                .collect::<Vec<_>>();
            backend.register_narinfos(&narinfos).await?;

            let wave_count = u64::try_from(results.len()).unwrap_or(u64::MAX);
            completed = completed.saturating_add(wave_count);
            total_bytes =
                total_bytes.saturating_add(results.iter().map(|(size, _)| *size).sum::<u64>());
            overall.inc(wave_count);
        }
        uploaded = completed;
    }

    overall.finish_and_clear();

    let elapsed = start.elapsed();
    printer.success(&format!(
        "Uploaded {uploaded}/{} paths ({}) in {:.1}s",
        all_paths.len(),
        HumanBytes(total_bytes),
        elapsed.as_secs_f64()
    ));

    Ok(())
}

/// Builds the narinfo text for a path from its metadata and computed NAR file
/// digest/size, mirroring the fields the cache records.
fn build_narinfo(
    info: &PathInfo,
    file_hash: &str,
    file_size: u64,
    nar_filename: &str,
    compression: &str,
) -> String {
    let ref_basenames: Vec<String> = info
        .references
        .iter()
        .map(|r| narinfo::basename(r).to_string())
        .collect();
    let deriver_basename = info.deriver.as_deref().map(narinfo::basename);
    let nar_url = format!("nar/{nar_filename}");
    let ni = narinfo::from_path_info(&narinfo::PathInfoParams {
        path: &info.path,
        nar_hash: &info.nar_hash,
        nar_size: info.nar_size,
        references: &ref_basenames,
        deriver: deriver_basename,
        signatures: &info.signatures,
        file_hash,
        file_size,
        compression: compression_name(compression),
        nar_url: &nar_url,
    });
    narinfo::format(&ni)
}

/// Returns whether an admission refusal should switch to typed multipart.
fn use_multipart_after_admission(admitted_url: Option<&str>, supported: bool) -> bool {
    admitted_url.is_none() && supported
}

/// Maximum number of compressed objects retained by one batch-admission wave.
const MAX_DIRECT_UPLOAD_WAVE: usize = 64;

struct PreparedUpload {
    store_hash: String,
    compressed: Vec<u8>,
    file_size: u64,
    nar_filename: String,
    nar_path: String,
    narinfo_text: String,
}

/// Compresses one missing path and constructs its immutable upload metadata.
///
/// Compression runs on a blocking thread (it is CPU-bound) so it never stalls
/// the async runtime when many of these run concurrently.
///
/// # Errors
///
/// Returns an error if compression fails or produces an unrepresentable size.
async fn prepare_upload(
    info: &PathInfo,
    compression: &str,
    compression_level: i32,
) -> Result<PreparedUpload> {
    let hash = narinfo::store_hash(&info.path).to_string();
    let path = info.path.clone();
    let comp = compression.to_string();
    let compressed =
        tokio::task::spawn_blocking(move || streaming_compress(&path, &comp, compression_level))
            .await
            .context("compression task panicked")??;

    let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&compressed)));
    let file_size = compressed.len() as u64;
    let nar_filename = format!(
        "{}.{}",
        file_hash.replace(':', "-"),
        compression_ext(compression)
    );
    let narinfo_text = build_narinfo(info, &file_hash, file_size, &nar_filename, compression);
    let nar_path = format!("nar/{nar_filename}");

    Ok(PreparedUpload {
        store_hash: hash,
        compressed,
        file_size,
        nar_filename,
        nar_path,
        narinfo_text,
    })
}

/// Uploads one prepared NAR and returns its batched narinfo registration.
///
/// # Errors
///
/// Returns an error if the admitted, multipart, or backend upload fails.
async fn upload_prepared(
    backend: &dyn CacheBackend,
    upload: PreparedUpload,
    admission: Option<&ObjectUploadAdmission>,
    limiter: &bandwidth::BandwidthLimiter,
) -> Result<(u64, UploadedNarinfo)> {
    if limiter.is_active() {
        limiter.acquire(upload.file_size).await;
    }

    let use_multipart = use_multipart_after_admission(
        admission.map(|value| value.upload_url.as_str()),
        backend.supports_multipart(),
    );
    match admission {
        Some(admission) => {
            backend
                .upload_to_admitted_url(&admission.upload_url, &upload.compressed)
                .await?
        }
        None if use_multipart => {
            // Admission is authoritative for Hub proxy limits. A Worker may
            // require multipart below the client's normal in-memory threshold.
            upload_nar_multipart(backend, &upload.nar_filename, upload.compressed).await?;
        }
        None => {
            backend
                .put_nar(&upload.nar_filename, &upload.compressed)
                .await?
        }
    }
    let ticket = admission
        .filter(|value| value.requires_observation)
        .map(|value| value.upload_ticket_id.clone())
        .unwrap_or_default();
    Ok((
        upload.file_size,
        UploadedNarinfo {
            store_hash: upload.store_hash,
            narinfo: upload.narinfo_text,
            nar_upload_ticket_id: ticket,
        },
    ))
}

const PART_CONCURRENCY: usize = 8;
const MIN_MULTIPART_PART_SIZE: usize = 5 * 1024 * 1024;
const MAX_MULTIPART_PART_SIZE: usize = 16 * 1024 * 1024;
const MAX_MULTIPART_WINDOW_BYTES: usize = 64 * 1024 * 1024;
const MAX_MULTIPART_PARTS: usize = 10_000;

struct CacheMultipartAdapter<'a> {
    backend: &'a dyn CacheBackend,
    path: &'a str,
    sha256: Option<&'a str>,
}

#[async_trait::async_trait]
impl MultipartBackend for CacheMultipartAdapter<'_> {
    type Session = String;
    type Part = (u32, String);

    async fn begin(&self, size: u64) -> Result<MultipartAdmission<Self::Session>> {
        let (session, part_size) = self
            .backend
            .initiate_multipart(self.path, size, self.sha256)
            .await?;
        Ok(MultipartAdmission {
            session,
            part_size,
            next_part_number: 1,
            state: MultipartSessionState::Active,
        })
    }

    async fn upload_part(
        &self,
        session: &Self::Session,
        part_number: u32,
        _offset: u64,
        bytes: aos_net::Bytes,
    ) -> Result<Self::Part> {
        let part = self
            .backend
            .upload_part(self.path, session, part_number, &bytes)
            .await?;
        anyhow::ensure!(
            part.0 == part_number,
            "backend returned a mismatched multipart part number"
        );
        Ok(part)
    }

    async fn complete(&self, session: &Self::Session, parts: &[Self::Part]) -> Result<()> {
        self.backend
            .complete_multipart(self.path, session, parts)
            .await
    }

    async fn abort(&self, session: &Self::Session) -> Result<()> {
        self.backend.abort_multipart(self.path, session).await
    }
}

/// Uploads any rewindable source through the cache backend's typed multipart API.
pub(crate) async fn upload_multipart_source(
    backend: &dyn CacheBackend,
    path: &str,
    source: MultipartSource,
    sha256: Option<&str>,
) -> Result<()> {
    let fallback;
    let manager = match backend.transfer_manager() {
        Some(manager) => manager,
        None => {
            fallback = TransferEngine::new(TransferEngineConfig::default());
            &fallback
        }
    };
    let adapter = CacheMultipartAdapter {
        backend,
        path,
        sha256,
    };
    let request = MultipartUploadRequest::new(format!("cache:{path}"), source)
        .with_concurrency(PART_CONCURRENCY)
        .with_maximum_in_flight_bytes(MAX_MULTIPART_WINDOW_BYTES as u64)
        .with_part_limits(
            MIN_MULTIPART_PART_SIZE as u64,
            MAX_MULTIPART_PART_SIZE as u64,
            MAX_MULTIPART_PARTS as u32,
        );
    manager.upload_multipart(request, &adapter).await?;
    Ok(())
}

pub(crate) async fn upload_nar_multipart(
    backend: &dyn CacheBackend,
    nar_filename: &str,
    compressed: Vec<u8>,
) -> Result<()> {
    let nar_path = format!("nar/{nar_filename}");
    upload_multipart_source(backend, &nar_path, MultipartSource::bytes(compressed), None).await
}

/// Uploads a batch of pack entries and registers their narinfos.
///
/// No-op when `pack_paths` is empty, so callers can flush
/// unconditionally. The narinfo puts are issued after the pack upload —
/// on the AOS server they are no-ops anyway (narinfo is synthesised
/// server-side once the pack import registers the paths).
async fn upload_pack_entries(
    backend: &dyn CacheBackend,
    pack_paths: &[PackPath],
    pack_narinfos: &[(String, String)],
) -> Result<()> {
    if pack_paths.is_empty() {
        return Ok(());
    }

    let pack_data = pack::create_pack(pack_paths);
    backend.upload_pack(&pack_data).await?;
    for (hash, narinfo_text) in pack_narinfos {
        backend.put_narinfo(hash, narinfo_text).await?;
    }
    Ok(())
}

/// Topologically sorts path infos so references precede their referrers.
///
/// `nix-store --import` on the receiving side rejects a path whose
/// references are not yet valid, so upload order matters. This is Kahn's
/// algorithm over the in-closure reference edges; references outside the
/// set and self-references are ignored. If a cycle prevents a complete
/// ordering (which should not happen for a valid closure), the leftover
/// paths are appended in their original order rather than dropped.
fn order_path_infos_for_import(infos: &mut Vec<PathInfo>) {
    let index_by_path: BTreeMap<&str, usize> = infos
        .iter()
        .enumerate()
        .map(|(idx, info)| (info.path.as_str(), idx))
        .collect();
    let mut indegree = vec![0usize; infos.len()];
    let mut dependents = vec![Vec::new(); infos.len()];

    for (idx, info) in infos.iter().enumerate() {
        for reference in &info.references {
            let Some(&reference_idx) = index_by_path.get(reference.as_str()) else {
                continue;
            };
            if reference_idx == idx {
                continue;
            }
            indegree[idx] += 1;
            dependents[reference_idx].push(idx);
        }
    }

    let mut ready = VecDeque::new();
    for (idx, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            ready.push_back(idx);
        }
    }

    let mut ordered_indices = Vec::with_capacity(infos.len());
    while let Some(idx) = ready.pop_front() {
        ordered_indices.push(idx);
        for dependent in &dependents[idx] {
            indegree[*dependent] -= 1;
            if indegree[*dependent] == 0 {
                ready.push_back(*dependent);
            }
        }
    }

    if ordered_indices.len() != infos.len() {
        let mut seen = vec![false; infos.len()];
        for idx in &ordered_indices {
            seen[*idx] = true;
        }
        for (idx, is_seen) in seen.iter().enumerate() {
            if !is_seen {
                ordered_indices.push(idx);
            }
        }
    }

    *infos = ordered_indices
        .into_iter()
        .map(|idx| infos[idx].clone())
        .collect();
}

#[cfg(test)]
mod tests {
    use aos_core::nix::PathInfo;

    use super::{
        MAX_MULTIPART_PART_SIZE, MAX_MULTIPART_PARTS, MIN_MULTIPART_PART_SIZE, PreparedUpload,
        order_path_infos_for_import, upload_multipart_source, upload_prepared,
        use_multipart_after_admission,
    };

    struct MaliciousNegotiationBackend {
        part_size: u64,
        initiated: std::sync::atomic::AtomicUsize,
        aborted: std::sync::atomic::AtomicUsize,
        uploaded: std::sync::atomic::AtomicUsize,
        completed: std::sync::atomic::AtomicUsize,
        admitted: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MaliciousNegotiationBackend {
        fn new(part_size: u64) -> Self {
            Self {
                part_size,
                initiated: std::sync::atomic::AtomicUsize::new(0),
                aborted: std::sync::atomic::AtomicUsize::new(0),
                uploaded: std::sync::atomic::AtomicUsize::new(0),
                completed: std::sync::atomic::AtomicUsize::new(0),
                admitted: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::backend::CacheBackend for MaliciousNegotiationBackend {
        async fn exists(&self, _relative_path: &str) -> anyhow::Result<bool> {
            anyhow::bail!("unused test operation")
        }

        async fn get_narinfo(&self, _store_hash: &str) -> anyhow::Result<String> {
            anyhow::bail!("unused test operation")
        }

        async fn put_narinfo(&self, _store_hash: &str, _content: &str) -> anyhow::Result<()> {
            anyhow::bail!("unused test operation")
        }

        async fn get_nar(&self, _url: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("unused test operation")
        }

        async fn put_nar(&self, _filename: &str, _data: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("unused test operation")
        }

        async fn query_missing(&self, _store_hashes: &[&str]) -> anyhow::Result<Vec<String>> {
            anyhow::bail!("unused test operation")
        }

        async fn ensure_cache_info(&self, _store_dir: &str) -> anyhow::Result<()> {
            anyhow::bail!("unused test operation")
        }

        async fn put_cache_info(&self, _content: &str) -> anyhow::Result<()> {
            anyhow::bail!("unused test operation")
        }

        async fn put_static_file(
            &self,
            _relative_path: &str,
            _source: &std::path::Path,
            _content_type: Option<&str>,
            _cache_control: Option<&str>,
            _content_disposition: Option<&str>,
            _sha256: Option<&str>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("unused test operation")
        }

        async fn upload_to_admitted_url(&self, url: &str, data: &[u8]) -> anyhow::Result<()> {
            self.admitted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((url.to_string(), data.to_vec()));
            Ok(())
        }

        fn supports_multipart(&self) -> bool {
            true
        }

        async fn initiate_multipart(
            &self,
            _nar_path: &str,
            _size: u64,
            _sha256: Option<&str>,
        ) -> anyhow::Result<(String, u64)> {
            self.initiated
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(("malicious-upload".to_string(), self.part_size))
        }

        async fn upload_part(
            &self,
            _nar_path: &str,
            _upload_id: &str,
            part_number: u32,
            _data: &[u8],
        ) -> anyhow::Result<(u32, String)> {
            self.uploaded
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((part_number, "etag".to_string()))
        }

        async fn complete_multipart(
            &self,
            _nar_path: &str,
            _upload_id: &str,
            _parts: &[(u32, String)],
        ) -> anyhow::Result<()> {
            self.completed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn abort_multipart(&self, _nar_path: &str, _upload_id: &str) -> anyhow::Result<()> {
            self.aborted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    fn info(path: &str, references: &[&str]) -> PathInfo {
        PathInfo {
            path: path.to_string(),
            nar_hash: "sha256:fixture".to_string(),
            nar_size: 1,
            references: references
                .iter()
                .map(|reference| reference.to_string())
                .collect(),
            deriver: None,
            signatures: Vec::new(),
        }
    }

    #[test]
    fn import_order_places_references_before_referrers() {
        let dep = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-lib";
        let app = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-app";
        let mut infos = vec![info(app, &[dep]), info(dep, &[])];

        order_path_infos_for_import(&mut infos);

        let paths: Vec<&str> = infos.iter().map(|info| info.path.as_str()).collect();
        assert_eq!(paths, vec![dep, app]);
    }

    #[test]
    fn multipart_follows_admission_instead_of_a_local_size_threshold() {
        assert!(use_multipart_after_admission(None, true));
        assert!(!use_multipart_after_admission(Some("https://upload"), true));
        assert!(!use_multipart_after_admission(None, false));
    }

    #[test]
    fn import_order_handles_transitive_references() {
        let leaf = "/nix/store/cccccccccccccccccccccccccccccccc-leaf";
        let middle = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-middle";
        let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root";
        let mut infos = vec![
            info(root, &[middle]),
            info(middle, &[leaf]),
            info(leaf, &[]),
        ];

        order_path_infos_for_import(&mut infos);

        let paths: Vec<&str> = infos.iter().map(|info| info.path.as_str()).collect();
        assert_eq!(paths, vec![leaf, middle, root]);
    }

    #[tokio::test]
    async fn admitted_upload_preserves_direct_origin_ticket_for_batch_settlement() {
        let backend = MaliciousNegotiationBackend::new(MIN_MULTIPART_PART_SIZE as u64);
        let prepared = PreparedUpload {
            store_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            compressed: b"compressed-nar".to_vec(),
            file_size: 14,
            nar_filename: "fixture.nar.zst".to_string(),
            nar_path: "nar/fixture.nar.zst".to_string(),
            narinfo_text: "StorePath: /nix/store/fixture".to_string(),
        };
        let admission = crate::backend::ObjectUploadAdmission {
            upload_url: "https://origin.example/upload".to_string(),
            upload_ticket_id: "ticket-1".to_string(),
            requires_observation: true,
        };

        let (size, narinfo) = upload_prepared(
            &backend,
            prepared,
            Some(&admission),
            &crate::bandwidth::BandwidthLimiter::new(0),
        )
        .await
        .unwrap();

        assert_eq!(size, 14);
        assert_eq!(narinfo.nar_upload_ticket_id, "ticket-1");
        assert_eq!(
            backend
                .admitted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[(
                "https://origin.example/upload".to_string(),
                b"compressed-nar".to_vec()
            )]
        );
    }

    #[tokio::test]
    async fn malicious_backend_geometry_aborts_without_parts_or_completion() {
        let excessive_part_count = MIN_MULTIPART_PART_SIZE
            .checked_mul(MAX_MULTIPART_PARTS)
            .and_then(|size| size.checked_add(1))
            .unwrap();
        for (part_size, payload_len) in [
            (0, 32 * 1024 * 1024),
            (u64::MAX, 32 * 1024 * 1024),
            ((MIN_MULTIPART_PART_SIZE - 1) as u64, 32 * 1024 * 1024),
            ((MAX_MULTIPART_PART_SIZE + 1) as u64, 32 * 1024 * 1024),
            (MIN_MULTIPART_PART_SIZE as u64, excessive_part_count),
        ] {
            let backend = MaliciousNegotiationBackend::new(part_size);
            let source = tempfile::NamedTempFile::new().unwrap();
            source.as_file().set_len(payload_len as u64).unwrap();
            assert!(
                upload_multipart_source(
                    &backend,
                    "nar/malicious.nar",
                    aos_net::MultipartSource::File(source.path().to_path_buf()),
                    None,
                )
                .await
                .is_err()
            );
            assert_eq!(
                backend.initiated.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(backend.aborted.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                backend.uploaded.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
            assert_eq!(
                backend.completed.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
        }
    }
}
