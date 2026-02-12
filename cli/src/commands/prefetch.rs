use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use glob::glob;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::nix::NixRunner;
use crate::output::Printer;

// -----------------------------------------------------------------------
// Nix-evaluated source metadata
// -----------------------------------------------------------------------

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

struct FetchOk {
    hash: String,
    bytes: u64,
    elapsed: Duration,
    source_url: String,
}

/// Try downloading from a single URL. Streams chunks through a SHA-256 hasher
/// so the full body is never held in memory or written to disk.
///
/// Aborts early if the average speed over `speed_window` drops below
/// `min_speed` bytes/sec.
async fn try_one_url(
    client: &reqwest::Client,
    url: &str,
    pb: &ProgressBar,
    min_speed: u64,
    speed_window: Duration,
) -> Result<FetchOk> {
    let start = Instant::now();

    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("connect {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error {url}"))?;

    if let Some(len) = response.content_length() {
        pb.set_length(len);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("    {spinner:.cyan} {msg} [{bar:20.cyan/dim}] {bytes}/{total_bytes} ({bytes_per_sec})")
                .expect("valid template")
                .progress_chars("=> "),
        );
    }

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut window_start = Instant::now();
    let mut window_bytes: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read {url}"))?
    {
        hasher.update(&chunk);
        downloaded += chunk.len() as u64;
        window_bytes += chunk.len() as u64;
        pb.set_position(downloaded);

        // Check minimum speed after the window elapses.
        let window_elapsed = window_start.elapsed();
        if min_speed > 0 && window_elapsed >= speed_window {
            let speed = window_bytes as f64 / window_elapsed.as_secs_f64();
            if (speed as u64) < min_speed {
                anyhow::bail!(
                    "too slow ({}/s < {}/s minimum)",
                    HumanBytes(speed as u64),
                    HumanBytes(min_speed),
                );
            }
            // Reset the window.
            window_start = Instant::now();
            window_bytes = 0;
        }
    }

    let digest = hasher.finalize();
    let b64 = base64::engine::general_purpose::STANDARD.encode(digest);

    Ok(FetchOk {
        hash: format!("sha256-{b64}"),
        bytes: downloaded,
        elapsed: start.elapsed(),
        source_url: url.to_string(),
    })
}

/// Try each mirror URL in order. Returns the first successful result or the
/// last error if all mirrors fail.
async fn fetch_hash(
    client: &reqwest::Client,
    urls: &[String],
    pb: ProgressBar,
    name: &str,
    min_speed: u64,
    speed_window: Duration,
) -> Result<FetchOk> {
    let mut last_err = None;

    for (i, url) in urls.iter().enumerate() {
        if i > 0 {
            pb.set_message(format!("{name} (mirror {}/{})", i + 1, urls.len()));
            pb.set_position(0);
            pb.set_length(0);
            // Reset to spinner style for new attempt.
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("    {spinner:.cyan} {msg} ({bytes}, {elapsed})")
                    .expect("valid template")
                    .tick_chars("-\\|/ "),
            );
        }

        match try_one_url(client, url, &pb, min_speed, speed_window).await {
            Ok(ok) => {
                pb.finish_and_clear();
                return Ok(ok);
            }
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        }
    }

    pb.finish_and_clear();
    Err(last_err.unwrap())
}

// -----------------------------------------------------------------------
// update: write hashes back into individual package .nix files
// -----------------------------------------------------------------------

/// Find the .nix file for a package by globbing `pkgs/**/<name>.nix` and
/// replace the `hash = "..."` value in-place.
fn update_package_hash(nix: &NixRunner, name: &str, new_hash: &str) -> Result<bool> {
    let pattern = format!("{}/pkgs/**/{}.nix", nix.root().display(), name);
    let matches: Vec<_> = glob(&pattern)
        .with_context(|| format!("invalid glob pattern for package '{name}'"))?
        .filter_map(|entry| entry.ok())
        .collect();

    if matches.is_empty() {
        return Ok(false);
    }

    let hash_re = Regex::new(r#"hash\s*=\s*"[^"]*""#).expect("valid regex");

    let mut updated_any = false;
    for path in &matches {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;

        if hash_re.is_match(&content) {
            let replacement = format!(r#"hash = "{new_hash}""#);
            let new_content = hash_re.replace(&content, replacement.as_str()).to_string();
            if new_content != content {
                std::fs::write(path, &new_content)
                    .with_context(|| format!("writing {}", path.display()))?;
                updated_any = true;
            }
        }
    }

    Ok(updated_any)
}

// -----------------------------------------------------------------------
// command entry point
// -----------------------------------------------------------------------

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
    printer.info("Querying Nix for package source metadata...");
    let all_sources = discover_sources(nix)?;

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
                printer.warning(&format!("package '{pkg}' not found or has no fetchurl source"));
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

    let results: Vec<(String, Result<FetchOk>)> = rt.block_on(async {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(connect_timeout))
            .timeout(Duration::from_secs(600))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .expect("valid HTTP client");

        let semaphore = Arc::new(Semaphore::new(jobs));
        let client = Arc::new(client);

        let mp = MultiProgress::new();
        let overall = mp.add(ProgressBar::new(entries.len() as u64));
        overall.set_style(
            ProgressStyle::default_bar()
                .template("  [{bar:30.cyan/dim}] {pos}/{len}  {msg}")
                .expect("valid template")
                .progress_chars("=> "),
        );
        overall.set_message("sources");

        let spinner_style = ProgressStyle::default_spinner()
            .template("    {spinner:.cyan} {msg} ({bytes}, {elapsed})")
            .expect("valid template")
            .tick_chars("-\\|/ ");

        let mut handles = Vec::new();

        for (name, info) in &entries {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let urls = info.urls.clone();
            let name = name.clone();
            let overall = overall.clone();

            let pb = mp.insert_before(&overall, ProgressBar::new_spinner());
            pb.set_style(spinner_style.clone());
            pb.set_message(name.clone());
            pb.enable_steady_tick(Duration::from_millis(120));

            handles.push(tokio::spawn(async move {
                let result =
                    fetch_hash(&client, &urls, pb, &name, min_speed, speed_window).await;
                drop(permit);
                overall.inc(1);
                (name, result)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        overall.finish_and_clear();
        results
    });

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
        let mut update_count = 0;
        for (name, hash) in &hashes {
            match update_package_hash(nix, name, hash) {
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
