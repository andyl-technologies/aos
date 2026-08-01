//! The `aos cache pull` operation: download closure paths from a cache.
//!
//! Pull resolves installables to store paths, enumerates their closure,
//! and for every path missing from the local store fetches the narinfo
//! and compressed NAR from the [`CacheBackend`], then imports it via
//! `nix-store --import` (see [`streaming_import`]). Downloads honour an
//! optional shared bandwidth limit and a concurrency cap.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use aos_core::nar::info as narinfo;
use aos_core::nix::NixCli;
use aos_core::output::Printer;

use crate::backend::CacheBackend;
use crate::bandwidth;
use crate::compress::streaming_import;
use crate::resolve::resolve_installables;

/// Downloads and imports all closure paths missing from the local store.
///
/// The pipeline is:
///
/// 1. Resolve `installables` / `file` / `attr` / `expr` to store paths.
/// 2. Enumerate the combined closure and check local validity.
/// 3. For each missing path: fetch narinfo, download the compressed NAR,
///    and import it with `nix-store --import`.
///
/// `jobs` caps concurrent downloads (a value of `0` is treated as `1`);
/// `max_bandwidth` accepts a human-readable rate such as `"100MB/s"`
/// (see [`bandwidth::parse_bandwidth`]) and `None` means unlimited. With
/// `dry_run` the missing paths are printed and nothing is downloaded.
///
/// A path that imports but fails post-import validation only produces a
/// warning; the pull continues with the remaining paths.
///
/// # Errors
///
/// Returns an error if installable resolution, closure enumeration,
/// local validity checks, bandwidth parsing, a narinfo or NAR fetch, or
/// a `nix-store --import` invocation fails.
#[allow(clippy::too_many_arguments, clippy::disallowed_methods)]
pub async fn run_pull(
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

    let effective_jobs = if jobs == 0 { 1 } else { jobs };
    let semaphore = Arc::new(Semaphore::new(effective_jobs));
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

        streaming_import(
            &nix,
            &nar_compressed,
            &ni.compression,
            &ni.store_path,
            &ni.references,
            ni.deriver.as_deref(),
        )?;

        // Verify the import succeeded.
        match nix.is_valid(&ni.store_path) {
            Ok(true) => {}
            Ok(false) => {
                printer.warning(&format!("import may have failed for {}", ni.store_path));
            }
            Err(e) => {
                printer.warning(&format!(
                    "could not verify import of {}: {e}",
                    ni.store_path
                ));
            }
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
