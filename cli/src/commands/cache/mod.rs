pub mod backend;
pub mod bandwidth;
pub mod discover;
pub mod nix_export;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::cli::CacheCmd;
use crate::client::pack::{self, PackPath};
use crate::narinfo;
use crate::nix_cli::NixCli;
use crate::output::Printer;

use backend::{AuthOptions, CacheBackend};

/// Entry point for `aos cache <subcommand>`.
pub async fn run(printer: &Printer, cmd: &CacheCmd) -> Result<()> {
    match cmd {
        CacheCmd::Push {
            installables,
            to,
            file,
            attr,
            expr,
            jobs,
            max_bandwidth,
            batch_threshold,
            compression,
            compression_level,
            dry_run,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(to, &auth_opts).await?;
            run_push(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
                *jobs,
                max_bandwidth.as_deref(),
                batch_threshold,
                compression.as_deref().unwrap_or("zstd"),
                *compression_level,
                *dry_run,
            )
            .await
        }
        CacheCmd::Pull {
            installables,
            from,
            file,
            attr,
            expr,
            jobs,
            max_bandwidth,
            dry_run,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(from, &auth_opts).await?;
            run_pull(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
                *jobs,
                max_bandwidth.as_deref(),
                *dry_run,
            )
            .await
        }
        CacheCmd::Prefetch {
            installables,
            to,
            file,
            attr,
            expr,
            jobs,
            dry_run,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(to, &auth_opts).await?;
            run_prefetch(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
                *jobs,
                *dry_run,
            )
            .await
        }
        CacheCmd::List {
            installables,
            from,
            file,
            attr,
            expr,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(from, &auth_opts).await?;
            run_list(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

async fn run_push(
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

        // Streaming compression pipeline:
        // nix-store --dump <path> | zstd -c -<level> → compressed bytes
        // The uncompressed NAR is never fully buffered — it streams through
        // the compressor subprocess. Only the compressed result is held in RAM.
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
            // For pack upload we need the NAR export format, not just compressed NAR.
            // Store the compressed data + narinfo for later upload.
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

// ---------------------------------------------------------------------------
// Pull
// ---------------------------------------------------------------------------

async fn run_pull(
    printer: &Printer,
    backend: &dyn CacheBackend,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
    jobs: usize,
    max_bandwidth: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let start = Instant::now();
    let nix = NixCli::new(0);

    let limiter = bandwidth::BandwidthLimiter::new(
        max_bandwidth
            .map(bandwidth::parse_bandwidth)
            .transpose()?
            .unwrap_or(0),
    );

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

    // 3. Check which paths are missing locally.
    let mut missing: Vec<String> = Vec::new();
    for path in &all_paths {
        if !nix.is_valid(path)? {
            missing.push(path.clone());
        }
    }

    if missing.is_empty() {
        printer.success("All paths already in local store.");
        return Ok(());
    }

    printer.info(&format!(
        "{}/{} paths need downloading",
        missing.len(),
        all_paths.len()
    ));

    if dry_run {
        for path in &missing {
            printer.plain(&format!("  {}", narinfo::basename(path)));
        }
        printer.info("Dry run — nothing downloaded.");
        return Ok(());
    }

    // 4. Download missing paths.
    let mp = MultiProgress::new();
    let overall = mp.add(ProgressBar::new(missing.len() as u64));
    overall.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:30.cyan/dim}] {pos}/{len}")
            .expect("valid template")
            .progress_chars("=> "),
    );
    overall.set_message("Downloading");

    let semaphore = Arc::new(Semaphore::new(jobs));
    let mut total_bytes: u64 = 0;
    let mut downloaded = 0u64;

    for path in &missing {
        let _permit = semaphore.acquire().await?;
        let hash = narinfo::store_hash(path);

        // Fetch narinfo.
        let narinfo_text = backend
            .get_narinfo(hash)
            .await
            .with_context(|| format!("fetching narinfo for {hash}"))?;
        let ni = narinfo::parse(&narinfo_text)?;

        // Download compressed NAR.
        let nar_compressed = backend
            .get_nar(&ni.url)
            .await
            .with_context(|| format!("downloading NAR {}", ni.url))?;

        // Apply bandwidth limiting.
        if limiter.is_active() {
            limiter.acquire(nar_compressed.len() as u64).await;
        }

        // Streaming decompression + export construction + import pipeline:
        // Decompress NAR → build export format → pipe to nix-store --import.
        // The decompressed NAR streams through the export builder into import
        // without being fully buffered (only the compressed data is in RAM,
        // which is already downloaded).
        streaming_import(
            &nix,
            &nar_compressed,
            &ni.compression,
            &ni.store_path,
            &ni.references,
            ni.deriver.as_deref(),
        )?;

        // Verify the import succeeded.
        if !nix.is_valid(&ni.store_path).unwrap_or(false) {
            printer.warning(&format!("import may have failed for {}", ni.store_path));
        }

        total_bytes += nar_compressed.len() as u64;
        downloaded += 1;
        overall.inc(1);
    }

    overall.finish_and_clear();

    let elapsed = start.elapsed();
    printer.success(&format!(
        "Downloaded {downloaded}/{} paths ({}) in {:.1}s",
        all_paths.len(),
        HumanBytes(total_bytes),
        elapsed.as_secs_f64()
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// Prefetch
// ---------------------------------------------------------------------------

async fn run_prefetch(
    printer: &Printer,
    backend: &dyn CacheBackend,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
    _jobs: usize,
    dry_run: bool,
) -> Result<()> {
    let start = Instant::now();
    let nix = NixCli::new(0);

    // 1. Resolve to .drv path(s).
    printer.info("Resolving installables to derivations...");
    let mut all_fods = Vec::new();

    for installable in installables {
        let drv = discover::resolve_to_drv(
            &nix,
            file.map(Path::new),
            attr,
            expr,
            Some(installable),
        )?;
        let fods = discover::discover_fods(&nix, &drv)?;
        all_fods.extend(fods);
    }

    // If no installables, use attr/expr.
    if installables.is_empty() {
        let drv = discover::resolve_to_drv(
            &nix,
            file.map(Path::new),
            attr,
            expr,
            None,
        )?;
        let fods = discover::discover_fods(&nix, &drv)?;
        all_fods.extend(fods);
    }

    if all_fods.is_empty() {
        printer.info("No fixed-output derivations found.");
        return Ok(());
    }

    printer.info(&format!("{} FODs discovered", all_fods.len()));

    // 2. Query missing from cache (in chunks of 500).
    let store_hashes: Vec<&str> = all_fods
        .iter()
        .map(|f| narinfo::store_hash(&f.output_path))
        .collect();
    let mut missing_hashes = Vec::new();
    for chunk in store_hashes.chunks(500) {
        let mut chunk_missing = backend.query_missing(chunk).await?;
        missing_hashes.append(&mut chunk_missing);
    }

    let missing_fods: Vec<_> = all_fods
        .iter()
        .filter(|f| {
            let hash = narinfo::store_hash(&f.output_path);
            missing_hashes.contains(&hash.to_string())
        })
        .collect();

    if missing_fods.is_empty() {
        printer.success("All sources already cached.");
        return Ok(());
    }

    printer.info(&format!(
        "{}/{} sources need fetching and pushing",
        missing_fods.len(),
        all_fods.len()
    ));

    if dry_run {
        for fod in &missing_fods {
            printer.plain(&format!(
                "  {} ({})",
                fod.name,
                fod.url.as_deref().unwrap_or("no url")
            ));
        }
        printer.info("Dry run — nothing fetched.");
        return Ok(());
    }

    // 3. Realise missing FODs (fetches sources from upstream).
    printer.info("Realising sources...");
    for fod in &missing_fods {
        if let Err(e) = nix.realise(&fod.drv_path) {
            printer.warning(&format!("failed to realise {}: {e}", fod.drv_path));
        }
    }

    // 4. Push realised FODs to cache using streaming compression.
    backend.ensure_cache_info("/nix/store").await?;

    let mut pushed = 0u64;
    for fod in &missing_fods {
        if !nix.is_valid(&fod.output_path)? {
            continue;
        }

        let info = match nix.path_info(&fod.output_path) {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Streaming compression: nix-store --dump | zstd → compressed bytes.
        let compressed = streaming_compress(&fod.output_path, "zstd", 3)?;
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&compressed)));
        let file_size = compressed.len() as u64;
        let nar_filename = format!("{}.nar.zst", file_hash.replace(':', "-"));

        let ref_basenames: Vec<String> = info
            .references
            .iter()
            .map(|r| narinfo::basename(r).to_string())
            .collect();

        let ni = narinfo::from_path_info(
            &fod.output_path,
            &info.nar_hash,
            info.nar_size,
            &ref_basenames,
            info.deriver.as_deref().map(narinfo::basename),
            &info.signatures,
            &file_hash,
            file_size,
            "zstd",
            &format!("nar/{nar_filename}"),
        );

        let hash = narinfo::store_hash(&fod.output_path);
        backend.put_nar(&nar_filename, &compressed).await?;
        backend.put_narinfo(hash, &narinfo::format(&ni)).await?;

        pushed += 1;
    }

    let elapsed = start.elapsed();
    printer.success(&format!(
        "Prefetched {pushed}/{} sources in {:.1}s",
        all_fods.len(),
        elapsed.as_secs_f64()
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

async fn run_list(
    printer: &Printer,
    backend: &dyn CacheBackend,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
) -> Result<()> {
    let nix = NixCli::new(0);

    if installables.is_empty() && attr.is_none() && expr.is_none() {
        printer.warning("No installable specified. Provide an installable to check against the cache.");
        return Ok(());
    }

    // Resolve and enumerate closure.
    let store_paths = resolve_installables(&nix, installables, file, attr, expr)?;
    let mut all_paths = Vec::new();
    for path in &store_paths {
        let closure = nix.closure(path)?;
        all_paths.extend(closure);
    }
    all_paths.sort();
    all_paths.dedup();

    // Check each path against local store and cache.
    printer.header(&format!(
        "{:<44} {:>10} {:>10} {}",
        "Path", "Local", "Cached", "Status"
    ));

    let mut local_count = 0u64;
    let mut cached_count = 0u64;

    for path in &all_paths {
        let hash = narinfo::store_hash(path);
        let basename = narinfo::basename(path);

        let in_local = nix.is_valid(path).unwrap_or(false);
        let in_cache = backend.has_narinfo(hash).await.unwrap_or(false);

        let local_str = if in_local { "yes" } else { "no" };
        let cached_str = if in_cache { "yes" } else { "no" };

        let status = match (in_local, in_cache) {
            (true, true) => "synced",
            (true, false) => "local only",
            (false, true) => "cache only",
            (false, false) => "missing",
        };

        if in_local {
            local_count += 1;
        }
        if in_cache {
            cached_count += 1;
        }

        let display_name = if basename.len() > 42 {
            format!("{}...", &basename[..39])
        } else {
            basename.to_string()
        };

        printer.plain(&format!(
            "{:<44} {:>10} {:>10} {}",
            display_name, local_str, cached_str, status
        ));
    }

    printer.plain("");
    printer.info(&format!(
        "Total: {} paths, {} local, {} cached",
        all_paths.len(),
        local_count,
        cached_count
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming helpers
// ---------------------------------------------------------------------------

/// Streaming compression pipeline: `nix-store --dump <path> | compressor`
///
/// The uncompressed NAR is never fully buffered in RAM — it streams through
/// the compressor subprocess. Only the compressed output is collected.
fn streaming_compress(store_path: &str, algorithm: &str, level: i32) -> Result<Vec<u8>> {
    match algorithm {
        "zstd" => {
            // Pipe: nix-store --dump <path> → zstd -c -<level>
            let mut dump = Command::new("nix-store")
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("spawning nix-store --dump {store_path}"))?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let zstd_output = Command::new("zstd")
                .args(["-c", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .context("spawning zstd compressor")?;

            dump.wait()?;

            if !zstd_output.status.success() {
                anyhow::bail!("zstd compression failed for {store_path}");
            }

            Ok(zstd_output.stdout)
        }
        "xz" => {
            let mut dump = Command::new("nix-store")
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("spawning nix-store --dump {store_path}"))?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let xz_output = Command::new("xz")
                .args(["-c", "-T0", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .context("spawning xz compressor")?;

            dump.wait()?;

            if !xz_output.status.success() {
                anyhow::bail!("xz compression failed for {store_path}");
            }

            Ok(xz_output.stdout)
        }
        "none" => {
            // No compression: read directly from nix-store --dump.
            let output = Command::new("nix-store")
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .with_context(|| format!("nix-store --dump {store_path}"))?;

            if !output.status.success() {
                anyhow::bail!("nix-store --dump failed for {store_path}");
            }

            Ok(output.stdout)
        }
        other => anyhow::bail!("unsupported compression algorithm: {other}"),
    }
}

/// Streaming import pipeline: decompress → build export → pipe to nix-store --import.
///
/// The decompressed NAR streams through the export trailer builder into the
/// import process. Only the compressed data (already downloaded) is in RAM.
fn streaming_import(
    _nix: &NixCli,
    compressed_nar: &[u8],
    compression: &str,
    store_path: &str,
    references: &[String],
    deriver: Option<&str>,
) -> Result<Vec<String>> {
    // Decompress NAR.
    let nar_data = decompress_nar(compressed_nar, compression)?;

    // Resolve references to full store paths.
    let full_refs: Vec<String> = references
        .iter()
        .map(|r| {
            if r.starts_with("/nix/store/") {
                r.clone()
            } else {
                format!("/nix/store/{r}")
            }
        })
        .collect();

    let full_deriver = deriver.map(|d| {
        if d.starts_with("/nix/store/") {
            d.to_string()
        } else {
            format!("/nix/store/{d}")
        }
    });

    // Build export format: NAR + trailer.
    // Use the ExportTrailer to stream the trailer after the NAR data.
    let trailer = nix_export::ExportTrailer::new(
        store_path,
        full_refs,
        full_deriver,
    );

    // Spawn nix-store --import and pipe the export data.
    let mut child = std::process::Command::new("nix-store")
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning nix-store --import")?;

    {
        let stdin = child.stdin.as_mut().context("no stdin for nix-store --import")?;
        // Write NAR data.
        stdin.write_all(&nar_data).context("writing NAR to import")?;
        // Write export trailer.
        trailer.write_to(stdin).context("writing export trailer")?;
    }

    let output = child.wait_with_output().context("waiting for nix-store --import")?;
    if !output.status.success() {
        anyhow::bail!("nix-store --import failed for {store_path}");
    }

    let text = String::from_utf8(output.stdout).context("invalid utf-8 from import")?;
    Ok(text.lines().filter(|l| !l.is_empty()).map(String::from).collect())
}

/// Decompress NAR data.
fn decompress_nar(data: &[u8], compression: &str) -> Result<Vec<u8>> {
    match compression {
        "zstd" => {
            let mut decoder = zstd::Decoder::new(data)?;
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        "xz" => {
            let mut child = Command::new("xz")
                .args(["-d", "-c"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .context("spawning xz -d")?;

            {
                let stdin = child.stdin.as_mut().unwrap();
                stdin.write_all(data)?;
            }

            let output = child.wait_with_output()?;
            if !output.status.success() {
                anyhow::bail!("xz decompression failed");
            }
            Ok(output.stdout)
        }
        "none" | "" => Ok(data.to_vec()),
        other => anyhow::bail!("unsupported decompression: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve installable arguments to store paths.
fn resolve_installables(
    nix: &NixCli,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
) -> Result<Vec<String>> {
    // Raw expression.
    if let Some(expr) = expr {
        let drv = nix.instantiate_expr(expr)?;
        let path = nix.realise(&drv.to_string_lossy())?;
        return Ok(vec![path]);
    }

    // Explicit -A attr.
    if let Some(attr) = attr {
        let file_path = Path::new(file.unwrap_or("./default.nix"));
        let path = nix.build(file_path, attr)?;
        return Ok(vec![path.to_string_lossy().to_string()]);
    }

    let mut paths = Vec::new();
    let file_path = Path::new(file.unwrap_or("./default.nix"));

    for installable in installables {
        // Direct store paths.
        if installable.starts_with("/nix/store/") {
            paths.push(installable.clone());
            continue;
        }

        // Bare name -> pkgs.<name> (AOS convention).
        let attr = format!("pkgs.{installable}");
        let path = nix.build(file_path, &attr)?;
        paths.push(path.to_string_lossy().to_string());
    }

    if paths.is_empty() {
        anyhow::bail!("no installables specified");
    }

    Ok(paths)
}

/// Get the compression name for narinfo.
fn compression_name(algorithm: &str) -> &str {
    match algorithm {
        "zstd" => "zstd",
        "xz" => "xz",
        "none" => "none",
        _ => "none",
    }
}

/// Get the file extension for compressed NARs.
fn compression_ext(algorithm: &str) -> &str {
    match algorithm {
        "zstd" => "nar.zst",
        "xz" => "nar.xz",
        "none" => "nar",
        _ => "nar",
    }
}

/// Convert CLI auth args to AuthOptions.
fn auth_from_args(args: &crate::cli::CacheAuthArgs) -> AuthOptions {
    AuthOptions {
        token: args.token.clone(),
        view: args.view.clone(),
        http_user: args.http_user.clone(),
        http_password: args.http_password.clone(),
        headers: args.header.clone(),
        s3_region: args.s3_region.clone(),
        s3_profile: args.s3_profile.clone(),
        s3_endpoint: args.s3_endpoint.clone(),
        ssh_key: args.ssh_key.clone(),
        ssh_password: args.ssh_password.clone(),
        ssh_ask_pass: args.ssh_ask_pass,
        ftp_user: args.ftp_user.clone(),
        ftp_password: args.ftp_password.clone(),
    }
}
