//! Frontend cache-freshness probes (RFC-0004 phase 1).
//!
//! After indexing, the hub probes each committed `[[caches]]` endpoint of a
//! registry to record whether it is reachable and serving a binary-cache
//! `nix-cache-info`. The probe is deliberately lightweight — one request per
//! endpoint — and never fatal: an unreachable cache is *recorded*, not raised.
//!
//! The observed state is upserted into the `cache_probes` table (one row per
//! `(registry, cache_url)`, see [`crate::db`]) and surfaced on the registry
//! health page as a small "cache freshness" table.
//!
//! # Status vocabulary
//!
//! ```text
//! ok          reachable and a non-empty nix-cache-info was served
//! stale       reachable, but no/empty nix-cache-info (not a valid binary cache)
//! unreachable transport failure, non-2xx HTTP, or missing file:// root
//! ```

use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::db::{Database, RegistryRecord};
use crate::stack::StackNode;

/// One cache endpoint's freshness observation, as probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheProbe {
    /// The committed cache endpoint that was probed.
    pub cache_url: String,
    /// Probe outcome: [`ProbeStatus`].
    pub status: ProbeStatus,
    /// Whether a non-empty `nix-cache-info` was served.
    pub observed_nix_cache_info: bool,
    /// Round-trip latency of the probe, in milliseconds.
    pub latency_ms: i64,
    /// Unix time the probe ran.
    pub checked_at: i64,
}

/// The outcome of probing one cache endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// Reachable and serving a valid (non-empty) `nix-cache-info`.
    Ok,
    /// Reachable, but no/empty `nix-cache-info` was served.
    Stale,
    /// Transport failure, non-2xx HTTP, or a missing `file://` root.
    Unreachable,
}

impl ProbeStatus {
    /// The lowercase wire/DB spelling (`ok`, `stale`, `unreachable`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "ok",
            ProbeStatus::Stale => "stale",
            ProbeStatus::Unreachable => "unreachable",
        }
    }
}

/// Probes every committed cache of `registry` and records each observation.
///
/// The cache set is the committed `[cache_stack]` endpoints when present,
/// otherwise the flat `[[caches]]` list — the same source [`crate::validation`]
/// uses. Each probe result is upserted via
/// [`Database::upsert_cache_probe`](crate::db::Database::upsert_cache_probe)
/// and also returned for logging or testing. Unreachable caches are *not*
/// errors; only a database failure aborts.
///
/// # Errors
///
/// Returns an error only on a database failure (reading the cache list or
/// upserting a probe row). A cache being unreachable is recorded, not raised.
pub async fn probe_caches(
    db: &Database,
    http: &reqwest::Client,
    registry: &RegistryRecord,
) -> Result<Vec<CacheProbe>> {
    let cache_urls = committed_cache_urls(db, registry.id)?;
    let mut probes = Vec::with_capacity(cache_urls.len());
    for cache_url in cache_urls {
        let probe = probe_one(http, &cache_url).await;
        db.upsert_cache_probe(
            registry.id,
            &probe.cache_url,
            probe.status.as_str(),
            probe.observed_nix_cache_info,
            probe.latency_ms,
            probe.checked_at,
        )?;
        probes.push(probe);
    }
    Ok(probes)
}

/// The committed cache URLs for a registry: stack endpoints, else flat list.
fn committed_cache_urls(db: &Database, registry_id: i64) -> Result<Vec<String>> {
    let stack = db.registry_cache_stack(registry_id)?;
    Ok(match stack {
        Some(node) => StackNode::endpoints(&node),
        None => db
            .list_caches(registry_id)?
            .into_iter()
            .map(|(url, _)| url)
            .collect(),
    })
}

/// Probes a single cache URL for its `nix-cache-info`, timing the request.
async fn probe_one(http: &reqwest::Client, cache_url: &str) -> CacheProbe {
    let checked_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let started = Instant::now();
    let (status, observed) = if let Some(root) = local_root(cache_url) {
        probe_file(&root)
    } else if cache_url.starts_with("http://") || cache_url.starts_with("https://") {
        probe_http(http, cache_url).await
    } else {
        (ProbeStatus::Unreachable, false)
    };
    let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    CacheProbe {
        cache_url: cache_url.to_string(),
        status,
        observed_nix_cache_info: observed,
        latency_ms,
        checked_at,
    }
}

/// The local filesystem root of a `file://` (or bare-path) cache, else `None`.
fn local_root(url: &str) -> Option<PathBuf> {
    if let Some(path) = url.strip_prefix("file://") {
        return Some(PathBuf::from(path));
    }
    if url.starts_with('/') {
        return Some(PathBuf::from(url));
    }
    None
}

/// File probe: the root must exist; `nix-cache-info` presence picks ok vs stale.
fn probe_file(root: &std::path::Path) -> (ProbeStatus, bool) {
    if !root.is_dir() {
        return (ProbeStatus::Unreachable, false);
    }
    match std::fs::read(root.join("nix-cache-info")) {
        Ok(bytes) if !bytes.is_empty() => (ProbeStatus::Ok, true),
        _ => (ProbeStatus::Stale, false),
    }
}

/// HTTP probe: `GET <base>/nix-cache-info`; a 2xx with a non-empty body is ok,
/// any other 2xx/empty body is stale, and transport/non-2xx is unreachable.
async fn probe_http(http: &reqwest::Client, base: &str) -> (ProbeStatus, bool) {
    let url = format!("{}/nix-cache-info", base.trim_end_matches('/'));
    let response = match http.get(&url).send().await {
        Ok(response) => response,
        Err(_) => return (ProbeStatus::Unreachable, false),
    };
    if !response.status().is_success() {
        return (ProbeStatus::Unreachable, false);
    }
    match response.bytes().await {
        Ok(body) if !body.is_empty() => (ProbeStatus::Ok, true),
        _ => (ProbeStatus::Stale, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_probe_ok_when_nix_cache_info_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nix-cache-info"), b"StoreDir: /nix/store\n").unwrap();
        let (status, observed) = probe_file(dir.path());
        assert_eq!(status, ProbeStatus::Ok);
        assert!(observed);
    }

    #[test]
    fn file_probe_stale_without_nix_cache_info() {
        let dir = tempfile::tempdir().unwrap();
        let (status, observed) = probe_file(dir.path());
        assert_eq!(status, ProbeStatus::Stale);
        assert!(!observed);
    }

    #[test]
    fn file_probe_unreachable_when_root_missing() {
        let (status, _) = probe_file(std::path::Path::new("/nonexistent/aos-probe-root"));
        assert_eq!(status, ProbeStatus::Unreachable);
    }
}
