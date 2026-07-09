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
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use aos_core::nar::info as narinfo;
use aos_core::nar::pack::{self, PackPath};
use aos_core::nix::{NixCli, PathInfo};
use aos_core::output::Printer;

use crate::backend::CacheBackend;
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
    let store_paths = resolve_installables(&nix, installables, file, attr, expr)?;

    // 2. Enumerate closure.
    printer.info("Enumerating closure...");
    let mut all_paths = Vec::new();
    for path in &store_paths {
        let closure = nix.closure(path)?;
        all_paths.extend(closure);
    }
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

    let mp = MultiProgress::new();
    let overall = mp.add(ProgressBar::new(missing_hashes.len() as u64));
    overall.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:30.cyan/dim}] {pos}/{len}")
            .expect("valid template")
            .progress_chars("=> "),
    );
    overall.set_message("Uploading");

    let effective_jobs = if jobs == 0 { 1 } else { jobs };
    let semaphore = Arc::new(Semaphore::new(effective_jobs));
    let mut total_bytes: u64 = 0;
    let mut uploaded = 0u64;

    // Accumulate small NARs for pack batching (HTTP backends only).
    let use_packs = backend.supports_pack();
    let mut pack_paths: Vec<PackPath> = Vec::new();
    let mut pack_narinfos: Vec<(String, String)> = Vec::new();

    for info in &infos {
        let hash = narinfo::store_hash(&info.path);
        if !missing_hashes.contains(&hash.to_string()) {
            continue;
        }

        let _permit = semaphore.acquire().await?;

        let compressed = streaming_compress(&info.path, compression, compression_level)?;

        // Compute file hash from compressed stream (tee through SHA-256).
        let file_hash_bytes = Sha256::digest(&compressed);
        let file_hash = format!("sha256:{}", hex::encode(file_hash_bytes));
        let file_size = compressed.len() as u64;

        // Apply bandwidth limiting (block until budget available).
        if limiter.is_active() {
            limiter.acquire(file_size).await;
        }

        // Generate NAR URL.
        let comp_ext = compression_ext(compression);
        let nar_filename = format!("{}.{}", file_hash.replace(':', "-"), comp_ext);

        // Generate narinfo.
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
            file_hash: &file_hash,
            file_size,
            compression: compression_name(compression),
            nar_url: &nar_url,
        });
        let narinfo_text = narinfo::format(&ni);

        if use_packs {
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
        } else {
            // Upload NAR + narinfo individually.
            backend.put_nar(&nar_filename, &compressed).await?;
            backend.put_narinfo(hash, &narinfo_text).await?;
        }

        total_bytes += file_size;
        uploaded += 1;
        overall.inc(1);
    }

    // Flush any remaining pack paths.
    upload_pack_entries(backend, &pack_paths, &pack_narinfos).await?;

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

    use super::order_path_infos_for_import;

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
}
