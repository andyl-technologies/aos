//! `aos prefetch` — compute source hashes with parallel downloads and
//! mirror failover.
//!
//! Evaluates the whole package set once to discover every `fetchurl`
//! source (URLs + declared hash), then downloads the selected sources
//! concurrently, streaming each body through SHA-256 (nothing is written
//! to disk). By default only sources whose hash is still a placeholder
//! (`AAAAAAA...`) are fetched; `--package` restricts to specific
//! packages and `--all` re-fetches everything. Mirrors are tried in
//! order, downloads that fall below the minimum speed are aborted, and
//! `--update` writes the computed `sha256-...` hashes back into the
//! package `.nix` files under `pkgs/`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use glob::glob;
use indicatif::HumanBytes;
use regex::Regex;
use serde::Deserialize;
use tokio::sync::Semaphore;

use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer, TransferProgress};
use aos_net::{
    HashAlgorithm, HashDownloadRequest, TransferEngineConfig, TransferEvent, TransferManager,
    TransferObserver,
};

// -----------------------------------------------------------------------
// Nix-evaluated source metadata
// -----------------------------------------------------------------------

/// A package's `fetchurl` source as evaluated from Nix: mirror URLs plus
/// the currently declared output hash.
#[derive(Debug, Deserialize)]
struct SourceInfo {
    urls: Vec<String>,
    hash: String,
}

/// Query Nix for all packages and their source metadata (urls + hash).
/// Returns a map from package name to optional SourceInfo (null for packages
/// without fetchurl-style sources).
fn discover_sources(nix: &NixRunner) -> Result<BTreeMap<String, Option<SourceInfo>>> {
    let expr = format!(
        r#"let pkgs = import {root}; in
       builtins.mapAttrs (n: p:
         if p ? src && p.src ? urls then
           {{ urls = p.src.urls; hash = p.src.outputHash; }}
         else null
       ) pkgs.pkgs"#,
        root = nix.root().join("default.nix").display()
    );

    let value = nix.eval_expr_json(&expr)?;

    let map: BTreeMap<String, Option<SourceInfo>> = serde_json::from_value(value)
        .context("failed to deserialize package source metadata from Nix")?;

    Ok(map)
}

// -----------------------------------------------------------------------
// async fetcher with mirror fallover
// -----------------------------------------------------------------------

/// A successful fetch: the computed SRI hash, the byte count, the wall
/// time, and which mirror ultimately served the file.
struct FetchOk {
    hash: String,
    bytes: u64,
    elapsed: Duration,
    source_url: String,
}

/// Try each mirror URL in order. Returns the first successful result or the
/// last error if all mirrors fail.
async fn fetch_hash(
    manager: &TransferManager,
    urls: &[String],
    progress: TransferProgress,
    name: &str,
) -> Result<FetchOk> {
    if urls.is_empty() {
        progress.finish();
        anyhow::bail!("no URLs provided for {name}");
    }

    let started = Instant::now();
    let observer = PrefetchProgress::new(progress);
    let primary = urls
        .first()
        .cloned()
        .context("prefetch source list became empty")?;
    let request =
        HashDownloadRequest::new(primary, HashAlgorithm::Sha256).with_sources(urls.to_vec());
    let result = manager.hash_download_observed(request, &observer).await;
    observer.finish();
    let result = result?;
    let digest =
        hex::decode(&result.hash).context("transfer manager returned an invalid digest")?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    Ok(FetchOk {
        hash: format!("sha256-{b64}"),
        bytes: result.bytes,
        elapsed: started.elapsed(),
        source_url: result.source,
    })
}

/// Adapts transfer-manager events to one prefetch progress reporter.
struct PrefetchProgress {
    progress: Mutex<TransferProgress>,
}

impl PrefetchProgress {
    /// Wraps one progress reporter for synchronized event delivery.
    fn new(progress: TransferProgress) -> Self {
        Self {
            progress: Mutex::new(progress),
        }
    }

    /// Finishes the reporter after the manager releases the observer.
    fn finish(self) {
        if let Ok(progress) = self.progress.into_inner() {
            progress.finish();
        }
    }
}

impl TransferObserver for PrefetchProgress {
    fn observe(&self, event: TransferEvent<'_>) {
        let Ok(mut progress) = self.progress.lock() else {
            return;
        };
        match event {
            TransferEvent::Started {
                total_bytes,
                resumed_bytes,
                ..
            } => {
                if let Some(total_bytes) = total_bytes {
                    progress.set_total(total_bytes);
                }
                progress.set_position(resumed_bytes);
            }
            TransferEvent::Progress {
                transferred_bytes, ..
            } => progress.set_position(transferred_bytes),
            TransferEvent::Retrying {
                attempt,
                delay,
                error,
                ..
            } => progress.warning(&format!(
                "source transfer interrupted ({error}); retrying attempt {attempt} in {:.1}s",
                delay.as_secs_f64()
            )),
            TransferEvent::Verifying { .. } => progress.phase("Verifying source"),
            TransferEvent::Completed { .. } | TransferEvent::Failed { .. } => {}
        }
    }
}

// -----------------------------------------------------------------------
// update: write hashes back into individual package .nix files
// -----------------------------------------------------------------------

/// Find the .nix file for a package by globbing `pkgs/**/<name>.nix` and
/// replace the `hash = "..."` value in-place.  When `old_hash` is provided,
/// matches that specific value (important for files with multiple hash fields,
/// e.g. per-architecture sources).
fn update_package_hash(
    nix: &NixRunner,
    name: &str,
    old_hash: Option<&str>,
    new_hash: &str,
) -> Result<bool> {
    let escaped_name = glob::Pattern::escape(name);
    let pattern = format!("{}/pkgs/**/{}.nix", nix.root().display(), escaped_name);
    let matches: Vec<_> = glob(&pattern)
        .with_context(|| format!("invalid glob pattern for package '{name}'"))?
        .filter_map(|entry| entry.ok())
        .collect();

    if matches.is_empty() {
        return Ok(false);
    }

    let mut updated_any = false;
    for path in &matches {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

        // When the old hash is known, match it specifically to avoid updating
        // the wrong field in files with multiple hashes (e.g. per-arch).
        let new_content = if let Some(old) = old_hash {
            let old_pattern = format!(r#"hash\s*=\s*"{}""#, regex::escape(old));
            let re = Regex::new(&old_pattern).expect("valid regex");
            if re.is_match(&content) {
                let replacement = format!(r#"hash = "{new_hash}""#);
                re.replace(&content, replacement.as_str()).to_string()
            } else {
                continue;
            }
        } else {
            let re = Regex::new(r#"hash\s*=\s*"[^"]*""#).expect("valid regex");
            if re.is_match(&content) {
                let replacement = format!(r#"hash = "{new_hash}""#);
                re.replace(&content, replacement.as_str()).to_string()
            } else {
                continue;
            }
        };

        if new_content != content {
            std::fs::write(path, &new_content)
                .with_context(|| format!("writing {}", path.display()))?;
            updated_any = true;
        }
    }

    Ok(updated_any)
}

// -----------------------------------------------------------------------
// command entry point
// -----------------------------------------------------------------------

/// `aos prefetch` — fetch package sources and report their SRI hashes.
///
/// See the module docs for the selection rules (`packages`, `all`, and
/// the placeholder-hash default) and the download behaviour (`jobs`
/// parallel fetches, per-mirror `connect_timeout`, `min_speed` abort
/// threshold). With `update`, hashes are written back into the package
/// `.nix` files.
///
/// # Errors
///
/// Returns an error if the Nix evaluation of the package set fails, if
/// none of the requested packages have `fetchurl` sources, or if any
/// source fails to download from all of its mirrors (the remaining
/// sources are still fetched and reported first).
pub fn run(
    nix: &NixRunner,
    printer: &Printer,
    packages: &[String],
    all: bool,
    update: bool,
    jobs: usize,
    connect_timeout: u64,
    min_speed: u64,
) -> Result<()> {
    let eval_start = Instant::now();
    printer.info("Querying Nix for package source metadata...");
    let all_sources = discover_sources(nix)?;
    if printer.mode() == OutputMode::Verbose {
        printer.info(&format!(
            "Nix evaluation took {:.1}s",
            eval_start.elapsed().as_secs_f64(),
        ));
    }

    // Filter to only packages that have source info (non-null).
    let mut sources: BTreeMap<String, SourceInfo> = all_sources
        .into_iter()
        .filter_map(|(name, info)| info.map(|i| (name, i)))
        .collect();

    if !packages.is_empty() {
        sources.retain(|name, _| packages.iter().any(|p| p == name));
        let found: Vec<&str> = sources.keys().map(|s| s.as_str()).collect();
        for pkg in packages {
            if !found.contains(&pkg.as_str()) {
                printer.warning(&format!(
                    "package '{pkg}' not found or has no fetchurl source"
                ));
            }
        }
        if sources.is_empty() {
            anyhow::bail!("none of the requested packages found with fetchurl sources");
        }
    } else if !all {
        let total = sources.len();
        sources.retain(|_, info| info.hash.contains("AAAAAAA"));
        printer.info(&format!(
            "Found {} of {total} sources with placeholder hashes",
            sources.len(),
        ));
    }

    if sources.is_empty() {
        printer.success("All hashes are already populated.");
        return Ok(());
    }

    printer.info(&format!(
        "Prefetching {} source{} ({} parallel, connect {}s, min {}/s)...",
        sources.len(),
        if sources.len() == 1 { "" } else { "s" },
        jobs,
        connect_timeout,
        HumanBytes(min_speed),
    ));

    let wall_start = Instant::now();
    let speed_window = Duration::from_secs(15);

    // Collect entries into a Vec for iteration order.
    let entries: Vec<(String, SourceInfo)> = sources.into_iter().collect();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;

    let mut manager_config = TransferEngineConfig::default();
    manager_config.pool.connect_timeout = Duration::from_secs(connect_timeout);
    manager_config.min_speed = (min_speed > 0).then_some(min_speed);
    manager_config.min_speed_duration = speed_window;
    let manager = TransferManager::new(manager_config);
    let results: Vec<(String, Result<FetchOk>)> = rt.block_on(async {
        let semaphore = Arc::new(Semaphore::new(jobs));
        let manager = Arc::new(manager);
        let overall = Arc::new(printer.items("Prefetching sources", entries.len() as u64));

        let mut handles = Vec::new();

        for (name, info) in &entries {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .context("prefetch concurrency controller closed unexpectedly")?;
            let manager = manager.clone();
            let urls = info.urls.clone();
            let name = name.clone();
            let overall = overall.clone();
            let progress = printer.transfer(&name, 0);

            handles.push(tokio::spawn(async move {
                let result = fetch_hash(&manager, &urls, progress, &name).await;
                drop(permit);
                overall.inc(1);
                (name, result)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(join_err) => {
                    // A JoinError means the spawned task panicked or was
                    // cancelled. Surface it as a failed fetch result.
                    results.push((
                        "<unknown>".to_string(),
                        Err(anyhow::anyhow!("prefetch task panicked: {join_err}")),
                    ));
                }
            }
        }

        overall.finish_and_clear();
        Ok::<_, anyhow::Error>(results)
    })?;

    let wall_elapsed = wall_start.elapsed();

    // ---- results --------------------------------------------------------

    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    for (name, result) in &results {
        match result {
            Ok(ok) => {
                total_bytes += ok.bytes;
                printer.kv(
                    name,
                    &format!(
                        "{} ({}, {:.1}s, {})",
                        ok.hash,
                        HumanBytes(ok.bytes),
                        ok.elapsed.as_secs_f64(),
                        ok.source_url,
                    ),
                );
                hashes.insert(name.clone(), ok.hash.clone());
            }
            Err(err) => {
                printer.error(&format!("{name}: {err:#}"));
                failures.push(name.clone());
            }
        }
    }

    if printer.json_if_active(&serde_json::json!({
        "prefetched": hashes,
        "failed": failures,
        "total_bytes": total_bytes,
        "elapsed_secs": wall_elapsed.as_secs_f64(),
    })) {
        if !failures.is_empty() {
            anyhow::bail!("{} source(s) failed to prefetch", failures.len());
        }
        return Ok(());
    }

    printer.header(&format!(
        "\nPrefetched {}/{} sources ({}, {:.1}s)",
        hashes.len(),
        results.len(),
        HumanBytes(total_bytes),
        wall_elapsed.as_secs_f64(),
    ));

    // ---- update individual package .nix files ----------------------------

    if update && !hashes.is_empty() {
        // Build map of old hashes for precise matching in multi-hash files.
        let old_hashes: BTreeMap<&str, &str> = entries
            .iter()
            .map(|(name, info)| (name.as_str(), info.hash.as_str()))
            .collect();

        let mut update_count = 0;
        for (name, hash) in &hashes {
            let old_hash = old_hashes.get(name.as_str()).copied();
            match update_package_hash(nix, name, old_hash, hash) {
                Ok(true) => update_count += 1,
                Ok(false) => {
                    printer.warning(&format!(
                        "could not find .nix file for '{name}' under pkgs/"
                    ));
                }
                Err(err) => {
                    printer.error(&format!("failed to update '{name}': {err:#}"));
                }
            }
        }
        printer.success(&format!(
            "Updated {} hash{} in package .nix files",
            update_count,
            if update_count == 1 { "" } else { "es" },
        ));
    } else if !hashes.is_empty() && !update {
        printer.info("Run with --update to write hashes back to package .nix files");
    }

    if !failures.is_empty() {
        anyhow::bail!("{} source(s) failed to prefetch", failures.len());
    }

    Ok(())
}
