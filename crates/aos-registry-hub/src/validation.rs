//! Presence-depth cache consistency validation.
//!
//! RFC-0004's "Cache stores, stacks, and consistency validation" defines
//! three validation depths; this module implements phase 1, **presence**:
//! for every store hash the registry's verified index references, check
//! that `<hash>.narinfo` exists in each cache the committed
//! `registry.toml` `[[caches]]` list advertises. Presence runs after every
//! index refresh, so the hub continuously knows what fraction of each
//! cache's advertised set actually resolves.
//!
//! Later phases — `integrity` (HEAD the NAR, `FileSize`/`Compression`
//! consistency) and `deep` (sampled download + `FileHash` verification) —
//! are not implemented yet; runs are recorded with their depth so the
//! schema already accommodates them.
//!
//! Two cache transports are probed:
//!
//! - `file://` URLs and bare absolute paths: filesystem existence of
//!   `<root>/<hash>.narinfo`.
//! - `http(s)://` URLs: a `HEAD <url>/<hash>.narinfo` with the hardened
//!   client (200 = present, 404 = missing). Any transport error or
//!   unexpected status marks the whole cache *unreachable* for the run
//!   (recorded with `reachable = false` and `checked = 0`).
//!
//! Each run is recorded in the database (`validation_runs` plus per-hash
//! `validation_findings`) and summarized for callers.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::db::{Database, RegistryRecord};
use crate::fetch;

/// Maximum store hashes probed per cache per run.
///
/// Larger hash sets are truncated (deterministically — the hash list is
/// sorted) with a warning, never silently.
pub const MAX_HASHES_PER_RUN: usize = 4096;

/// Per-cache summary of one presence-validation run.
#[derive(Debug, Clone)]
pub struct ValidationSummary {
    /// The cache endpoint that was probed.
    pub cache_url: String,
    /// Number of store hashes probed (0 when unreachable).
    pub checked: u64,
    /// Number of probed hashes whose narinfo was absent.
    pub missing: u64,
    /// Whether the cache endpoint was reachable.
    pub reachable: bool,
    /// Percentage of probed hashes present (0 when nothing was checked).
    pub coverage_percent: f64,
}

/// How a cache URL is probed.
enum CacheKind {
    /// A directory on the local filesystem.
    File(PathBuf),
    /// An HTTP(S) base URL.
    Http(String),
}

/// Result of probing one cache against the hash set.
struct ProbeOutcome {
    checked: u64,
    missing: Vec<String>,
    reachable: bool,
}

impl ProbeOutcome {
    fn unreachable() -> Self {
        Self {
            checked: 0,
            missing: Vec::new(),
            reachable: false,
        }
    }
}

/// Run presence validation for every committed cache of one registry.
///
/// Probes every hash from [`Database::all_store_hashes`] (capped at
/// [`MAX_HASHES_PER_RUN`] with a warning) against each cache from
/// [`Database::list_caches`], records each run plus its missing findings
/// in the database, and returns per-cache summaries.
///
/// # Errors
///
/// Returns an error on database failure. Unreachable caches are *not*
/// errors — they are recorded as `reachable = false` runs.
pub async fn validate_presence(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<Vec<ValidationSummary>> {
    let mut hashes = db.all_store_hashes(registry.id)?;
    if hashes.len() > MAX_HASHES_PER_RUN {
        tracing::warn!(
            registry = %registry.slug,
            total = hashes.len(),
            cap = MAX_HASHES_PER_RUN,
            "capping presence validation; probing the first {MAX_HASHES_PER_RUN} hashes"
        );
        hashes.truncate(MAX_HASHES_PER_RUN);
    }

    let client = fetch::hardened_client();
    let mut summaries = Vec::new();
    for (cache_url, _priority) in db.list_caches(registry.id)? {
        let started_at = unix_now();
        let outcome = probe_cache(&client, &cache_url, &hashes).await;
        let finished_at = unix_now();

        db.record_validation_run(
            registry.id,
            &cache_url,
            "presence",
            outcome.checked,
            &outcome.missing,
            outcome.reachable,
            started_at,
            finished_at,
        )?;
        summaries.push(ValidationSummary {
            cache_url,
            checked: outcome.checked,
            missing: outcome.missing.len() as u64,
            reachable: outcome.reachable,
            coverage_percent: coverage_percent(outcome.checked, outcome.missing.len() as u64),
        });
    }
    Ok(summaries)
}

/// Percentage of `checked` hashes that were present.
fn coverage_percent(checked: u64, missing: u64) -> f64 {
    if checked == 0 {
        0.0
    } else {
        (checked.saturating_sub(missing)) as f64 * 100.0 / checked as f64
    }
}

/// Classify a cache URL into its probe transport.
///
/// Returns `None` for schemes the validator cannot probe (recorded as
/// unreachable).
fn classify_cache(url: &str) -> Option<CacheKind> {
    if let Some(path) = url.strip_prefix("file://") {
        return Some(CacheKind::File(PathBuf::from(path)));
    }
    if url.starts_with('/') {
        return Some(CacheKind::File(PathBuf::from(url)));
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(CacheKind::Http(url.trim_end_matches('/').to_string()));
    }
    None
}

/// Probe one cache for the presence of every hash's narinfo.
async fn probe_cache(client: &reqwest::Client, cache_url: &str, hashes: &[String]) -> ProbeOutcome {
    match classify_cache(cache_url) {
        Some(CacheKind::File(root)) => probe_file_cache(&root, hashes).await,
        Some(CacheKind::Http(base)) => probe_http_cache(client, &base, hashes).await,
        None => {
            tracing::warn!(cache = %cache_url, "unsupported cache URL scheme; recording unreachable");
            ProbeOutcome::unreachable()
        }
    }
}

/// Filesystem presence probe: `<root>/<hash>.narinfo` must exist.
async fn probe_file_cache(root: &Path, hashes: &[String]) -> ProbeOutcome {
    if !root.is_dir() {
        return ProbeOutcome::unreachable();
    }
    let mut missing = Vec::new();
    for hash in hashes {
        let present = tokio::fs::try_exists(root.join(format!("{hash}.narinfo")))
            .await
            .unwrap_or(false);
        if !present {
            missing.push(hash.clone());
        }
    }
    ProbeOutcome {
        checked: hashes.len() as u64,
        missing,
        reachable: true,
    }
}

/// HTTP presence probe: `HEAD <base>/<hash>.narinfo`.
///
/// 200 = present, 404 = missing; any transport error or other status
/// makes the whole cache unreachable for this run.
async fn probe_http_cache(client: &reqwest::Client, base: &str, hashes: &[String]) -> ProbeOutcome {
    let mut missing = Vec::new();
    for hash in hashes {
        let url = format!("{base}/{hash}.narinfo");
        let response = match client.head(&url).send().await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(cache = %base, error = %err, "cache unreachable");
                return ProbeOutcome::unreachable();
            }
        };
        match response.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::NOT_FOUND => missing.push(hash.clone()),
            status => {
                tracing::warn!(cache = %base, %status, "unexpected cache status; recording unreachable");
                return ProbeOutcome::unreachable();
            }
        }
    }
    ProbeOutcome {
        checked: hashes.len() as u64,
        missing,
        reachable: true,
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_dispatches_schemes() {
        assert!(matches!(
            classify_cache("file:///srv/cache"),
            Some(CacheKind::File(_))
        ));
        assert!(matches!(
            classify_cache("/srv/cache"),
            Some(CacheKind::File(_))
        ));
        assert!(matches!(
            classify_cache("https://cache.example.com/"),
            Some(CacheKind::Http(base)) if base == "https://cache.example.com"
        ));
        assert!(classify_cache("s3://bucket").is_none());
    }

    #[test]
    fn coverage_handles_empty_and_partial() {
        assert_eq!(coverage_percent(0, 0), 0.0);
        assert_eq!(coverage_percent(4, 0), 100.0);
        assert_eq!(coverage_percent(4, 1), 75.0);
    }

    #[tokio::test]
    async fn file_probe_reports_missing_and_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("aaa.narinfo"), b"StorePath: /x\n").unwrap();
        let hashes = vec!["aaa".to_string(), "bbb".to_string()];

        let outcome = probe_file_cache(dir.path(), &hashes).await;
        assert!(outcome.reachable);
        assert_eq!(outcome.checked, 2);
        assert_eq!(outcome.missing, vec!["bbb".to_string()]);

        let gone = probe_file_cache(&dir.path().join("nope"), &hashes).await;
        assert!(!gone.reachable);
        assert_eq!(gone.checked, 0);
    }
}
