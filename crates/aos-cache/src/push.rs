use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use aos_core::nar::info as narinfo;
use aos_core::nar::pack::{self, PackPath};
use aos_core::nix::NixCli;
use aos_core::output::Printer;

use crate::backend::CacheBackend;
use crate::bandwidth;
use crate::compress::{compression_ext, compression_name, streaming_compress};
use crate::resolve::resolve_installables;

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
    let infos = nix.path_info_batch(&path_refs)?;

    // 4. Query missing (in chunks of 500).
    let store_hashes: Vec<&str> = all_paths
        .iter()
        .map(|p| narinfo::store_hash(p))
        .collect();
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

    let semaphore = Arc::new(Semaphore::new(jobs));
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
        let nar_filename = format!(
            "{}.{}",
            file_hash.replace(':', "-"),
            comp_ext
        );

        // Generate narinfo.
        let ref_basenames: Vec<String> = info
            .references
            .iter()
            .map(|r| narinfo::basename(r).to_string())
            .collect();
        let deriver_basename = info.deriver.as_deref().map(narinfo::basename);

        let ni = narinfo::from_path_info(
            &info.path,
            &info.nar_hash,
            info.nar_size,
            &ref_basenames,
            deriver_basename,
            &info.signatures,
            &file_hash,
            file_size,
            compression_name(compression),
            &format!("nar/{nar_filename}"),
        );
        let narinfo_text = narinfo::format(&ni);

        // Batch small NARs into packs for HTTP backends.
        if use_packs && file_size < batch_threshold_bytes {
            pack_paths.push(PackPath {
                hash: hash.to_string(),
                nar_data: compressed,
            });
            pack_narinfos.push((hash.to_string(), narinfo_text));
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
    if !pack_paths.is_empty() {
        let pack_data = pack::create_pack(&pack_paths);
        match backend.upload_pack(&pack_data).await {
            Ok(_) => {
                // Upload narinfos for packed paths.
                for (hash, narinfo_text) in &pack_narinfos {
                    backend.put_narinfo(hash, narinfo_text).await?;
                }
            }
            Err(e) => {
                // Fall back to individual uploads if pack fails.
                printer.warning(&format!("pack upload failed, falling back: {e}"));
                for (i, pp) in pack_paths.iter().enumerate() {
                    let (hash, narinfo_text) = &pack_narinfos[i];
                    let comp_ext = compression_ext(compression);
                    let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&pp.nar_data)));
                    let nar_filename = format!("{}.{}", file_hash.replace(':', "-"), comp_ext);
                    backend.put_nar(&nar_filename, &pp.nar_data).await?;
                    backend.put_narinfo(hash, narinfo_text).await?;
                }
            }
        }
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
