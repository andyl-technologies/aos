//! The `aos cache prefetch` operation: cache build sources ahead of time.
//!
//! Prefetch walks the *derivation* closure of an installable rather than
//! its output closure, collecting every fixed-output derivation (the
//! `fetchurl`-style source downloads; see [`crate::discover`]). Sources
//! the cache does not already hold are realised — fetched from their
//! upstream mirrors — and pushed as zstd-compressed NARs, so subsequent
//! builds can substitute them from the cache instead of the network.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use sha2::{Digest, Sha256};

use aos_core::nar::info as narinfo;
use aos_core::nix::NixCli;
use aos_core::output::Printer;

use crate::backend::CacheBackend;
use crate::compress::streaming_compress;
use crate::discover;

/// Discovers, realises, and pushes the missing sources of a build.
///
/// The pipeline is:
///
/// 1. Resolve each installable (or `attr` / `expr` when no installables
///    are given) to a `.drv` and discover its fixed-output derivations.
/// 2. Query the backend for FOD output paths it is missing (in chunks
///    of 500 hashes).
/// 3. Realise each missing FOD, fetching the source from upstream.
/// 4. Push each realised source to the cache as a zstd-compressed NAR
///    (level 3) plus its narinfo.
///
/// With `dry_run` the missing sources and their URLs are printed and
/// nothing is fetched. FODs that fail to realise, or whose path info
/// cannot be read, are skipped with a warning so one dead upstream
/// mirror does not abort the whole prefetch. The `_jobs` parameter is
/// currently unused; uploads run sequentially.
///
/// # Errors
///
/// Returns an error if derivation resolution or FOD discovery fails, if
/// the cache missing-query fails, or if compressing or uploading a
/// realised source fails.
#[allow(clippy::too_many_arguments, clippy::disallowed_methods)]
pub async fn run_prefetch(
    printer: &Printer,
    backend: &dyn CacheBackend,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
    target: Option<&str>,
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
            target,
        )?;
        let fods = discover::discover_fods(&nix, &drv)?;
        all_fods.extend(fods);
    }

    // If no installables, use attr/expr.
    if installables.is_empty() {
        let drv = discover::resolve_to_drv(&nix, file.map(Path::new), attr, expr, None, target)?;
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
            printer.warning(&format!(
                "failed to realise {} (will skip upload): {e}",
                fod.drv_path
            ));
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
            Err(e) => {
                printer.warning(&format!(
                    "failed to get path info for {}: {e}",
                    fod.output_path
                ));
                continue;
            }
        };

        // Streaming compression: nix-store --dump | zstd -> compressed bytes.
        let compressed = streaming_compress(&fod.output_path, "zstd", 3)?;
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&compressed)));
        let file_size = compressed.len() as u64;
        let nar_filename = format!("{}.nar.zst", file_hash.replace(':', "-"));

        let ref_basenames: Vec<String> = info
            .references
            .iter()
            .map(|r| narinfo::basename(r).to_string())
            .collect();

        let nar_url = format!("nar/{nar_filename}");
        let ni = narinfo::from_path_info(&narinfo::PathInfoParams {
            path: &fod.output_path,
            nar_hash: &info.nar_hash,
            nar_size: info.nar_size,
            references: &ref_basenames,
            deriver: info.deriver.as_deref().map(narinfo::basename),
            signatures: &info.signatures,
            file_hash: &file_hash,
            file_size,
            compression: "zstd",
            nar_url: &nar_url,
        });

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
