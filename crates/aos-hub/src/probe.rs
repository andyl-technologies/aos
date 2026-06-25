//! Cache-freshness and frontend-freshness probes (RFC-0004 phase 1).
//!
//! After indexing, the hub probes two kinds of endpoint and records what it
//! observes; both probes are deliberately lightweight — one request per
//! endpoint — and never fatal: an unreachable endpoint is *recorded*, not
//! raised.
//!
//! - [`probe_caches`] probes each committed `[[caches]]` endpoint for a
//!   reachable binary-cache `nix-cache-info`, upserting one row per
//!   `(registry, cache_url)` into `cache_probes`.
//! - [`probe_frontends`] probes each configured [`Frontend`](crate::db::FrontendRecord)
//!   domain's machine surface (`info/refs` for the git surface, falling back to
//!   `nix-cache-info`), records its observed channel frontier and how many
//!   releases behind the local index it is, and upserts one row per frontend
//!   into `frontend_probes` (RFC-0004's `FrontendProbe`).
//!
//! Both observations are surfaced on the registry health page (the cache
//! freshness table and the frontend freshness table).
//!
//! # Status vocabulary
//!
//! ```text
//! ok          reachable and serving the expected surface
//! stale       reachable, but the expected surface was missing/empty
//! unreachable transport failure, non-2xx HTTP, or missing file:// root
//! ```

use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::db::{Database, FrontendRecord, RegistryRecord};
use crate::stack::StackNode;
use crate::surface::refs::parse_info_refs;

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
    let cache_urls = committed_cache_urls(db, registry.id).await?;
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
        )
        .await?;
        probes.push(probe);
    }
    Ok(probes)
}

/// The committed cache URLs for a registry: stack endpoints, else flat list.
async fn committed_cache_urls(db: &Database, registry_id: i64) -> Result<Vec<String>> {
    let stack = db.registry_cache_stack(registry_id).await?;
    Ok(match stack {
        Some(node) => StackNode::endpoints(&node),
        None => db
            .list_advertised_caches(registry_id)
            .await?
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
        // SECURITY (SSRF): the hardened client's ValidatingResolver only vets
        // DNS hostnames — a cache URL whose host is a literal internal/link-
        // local/metadata IP (e.g. http://169.254.169.254/) is never routed
        // through the resolver and would otherwise be fetched. Pre-check the
        // URL exactly as the frontend probe does and record an unsafe target as
        // unreachable (fail-closed), never issuing the request.
        if crate::fetch::is_safe_remote_url(cache_url).is_err() {
            (ProbeStatus::Unreachable, false)
        } else {
            probe_http(http, cache_url).await
        }
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
    // `nix-cache-info` is a tiny pointer file; cap the read so a hostile or
    // MITM'd cache cannot stream an unbounded body into memory.
    match crate::fetch::read_body_capped(
        response,
        crate::fetch::MAX_FETCH_BYTES,
        &format!("GET {url}"),
    )
    .await
    {
        Ok(body) if !body.is_empty() => (ProbeStatus::Ok, true),
        _ => (ProbeStatus::Stale, false),
    }
}

/// One frontend's freshness observation, as probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendProbe {
    /// The frontend id that was probed.
    pub frontend_id: i64,
    /// The base URL probed (`https://{domain}{base_path}`).
    pub base_url: String,
    /// Probe outcome: [`ProbeStatus`].
    pub status: ProbeStatus,
    /// The newest release the frontend's `info/refs` advertised, when readable.
    pub observed_frontier: Option<String>,
    /// How many releases behind the local index frontier the frontend is, when
    /// both frontiers are known.
    pub lag_releases: Option<i64>,
    /// Round-trip latency of the probe, in milliseconds.
    pub latency_ms: i64,
    /// Unix time the probe ran.
    pub checked_at: i64,
}

/// Probes every configured frontend of `registry` and records each observation.
///
/// For each frontend the probe fetches the frontend's `info/refs` over its
/// `https://{domain}{base_path}` base; a reachable, parseable advertisement
/// yields `ok` with the newest semver tag as the observed frontier and a
/// `lag_releases` count against the local index (the number of release tags the
/// local index has that the frontend does not). When `info/refs` is missing the
/// probe falls back to `nix-cache-info` so a cache-only frontend still reports
/// reachability. Each result is upserted via
/// [`Database::upsert_frontend_probe`](crate::db::Database::upsert_frontend_probe)
/// and also returned for logging or testing. An unreachable frontend is
/// recorded, not raised; only a database failure aborts.
///
/// # Errors
///
/// Returns an error only on a database failure (reading frontends, the local
/// release set, or upserting a probe row).
pub async fn probe_frontends(
    db: &Database,
    http: &reqwest::Client,
    registry: &RegistryRecord,
) -> Result<Vec<FrontendProbe>> {
    let frontends = db.list_frontends(registry.id).await?;
    if frontends.is_empty() {
        return Ok(Vec::new());
    }
    // The local index's release set bounds lag: a frontend that advertises
    // fewer release tags than the local index is behind by the difference.
    let local_releases = db.list_releases(registry.id).await?.len() as i64;

    let mut probes = Vec::with_capacity(frontends.len());
    for frontend in &frontends {
        let probe = probe_one_frontend(http, frontend, local_releases).await;
        db.upsert_frontend_probe(
            probe.frontend_id,
            probe.status.as_str(),
            probe.observed_frontier.as_deref(),
            probe.lag_releases,
            probe.latency_ms,
            probe.checked_at,
        )
        .await?;
        probes.push(probe);
    }
    Ok(probes)
}

/// The base URL a frontend's surface is served at: `https://{domain}{base_path}`.
///
/// The base path is normalized to drop any wrapping slashes so machine paths
/// append cleanly. The `https://` scheme is the default; a `domain` that
/// already carries an explicit `http://`/`https://` scheme is honored as-is
/// (an operator with a plain-HTTP internal frontend, and the test harness).
fn frontend_base_url(frontend: &FrontendRecord) -> String {
    let scheme =
        if frontend.domain.starts_with("http://") || frontend.domain.starts_with("https://") {
            ""
        } else {
            "https://"
        };
    let host = frontend.domain.trim_end_matches('/');
    let base = frontend.base_path.trim_matches('/');
    if base.is_empty() {
        format!("{scheme}{host}")
    } else {
        format!("{scheme}{host}/{base}")
    }
}

/// Probe one frontend's machine surface, timing the request.
async fn probe_one_frontend(
    http: &reqwest::Client,
    frontend: &FrontendRecord,
    local_releases: i64,
) -> FrontendProbe {
    let checked_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let base_url = frontend_base_url(frontend);
    let started = Instant::now();
    // Defense in depth: never probe a frontend whose URL resolves to a
    // local/internal address (SSRF), even if it slipped past creation
    // validation. An unsafe target is recorded as unreachable, not fetched.
    let (status, observed_frontier, lag_releases) =
        if crate::fetch::is_safe_remote_url(&base_url).is_err() {
            (ProbeStatus::Unreachable, None, None)
        } else {
            probe_frontend_surface(http, &base_url, local_releases).await
        };
    let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    FrontendProbe {
        frontend_id: frontend.id,
        base_url,
        status,
        observed_frontier,
        lag_releases,
        latency_ms,
        checked_at,
    }
}

/// Fetch and classify a frontend surface: `info/refs` (git) first, then
/// `nix-cache-info` (cache) as a fallback.
async fn probe_frontend_surface(
    http: &reqwest::Client,
    base: &str,
    local_releases: i64,
) -> (ProbeStatus, Option<String>, Option<i64>) {
    let refs_url = format!("{}/info/refs", base.trim_end_matches('/'));
    match http.get(&refs_url).send().await {
        Ok(response) if response.status().is_success() => {
            // `info/refs` is a small advertisement; cap the read so a hostile
            // or MITM'd frontend cannot stream an unbounded body into memory.
            if let Ok(body) = crate::fetch::read_text_capped(
                response,
                crate::fetch::MAX_FETCH_BYTES,
                &format!("GET {refs_url}"),
            )
            .await
            {
                if let Ok(refs) = parse_info_refs(&body) {
                    let semvers: Vec<semver::Version> = refs
                        .tags
                        .keys()
                        .filter_map(|name| semver::Version::parse(name).ok())
                        .collect();
                    let observed = semvers.iter().max().map(|v| v.to_string());
                    // Lag is how many release tags the local index has beyond
                    // what the frontend advertises (never negative).
                    let lag = (local_releases - semvers.len() as i64).max(0);
                    return (ProbeStatus::Ok, observed, Some(lag));
                }
            }
            // Reachable but unparseable refs: stale.
            return (ProbeStatus::Stale, None, None);
        }
        Ok(_) | Err(_) => {}
    }
    // Git surface missing/unreachable: fall back to the cache surface so a
    // cache-only frontend still reports reachability.
    let cache_url = format!("{}/nix-cache-info", base.trim_end_matches('/'));
    match http.get(&cache_url).send().await {
        // `nix-cache-info` is a tiny pointer file; cap the read against an
        // unbounded body from a hostile or MITM'd cache.
        Ok(response) if response.status().is_success() => {
            match crate::fetch::read_body_capped(
                response,
                crate::fetch::MAX_FETCH_BYTES,
                &format!("GET {cache_url}"),
            )
            .await
            {
                Ok(body) if !body.is_empty() => (ProbeStatus::Ok, None, None),
                _ => (ProbeStatus::Stale, None, None),
            }
        }
        _ => (ProbeStatus::Unreachable, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_base_url_normalizes_path() {
        let frontend = |domain: &str, base_path: &str| FrontendRecord {
            id: 1,
            registry_id: Some(1),
            cache_id: None,
            storage_binding_id: None,
            domain: domain.to_string(),
            base_path: base_path.to_string(),
            mode: "direct".to_string(),
            serves_git: true,
            serves_cache: true,
            serves_web: true,
            consumer_priority: 100,
            advertised: true,
            proxy_config: None,
            is_primary: false,
            created_at: 0,
        };
        assert_eq!(
            frontend_base_url(&frontend("cdn.acme.com", "")),
            "https://cdn.acme.com"
        );
        assert_eq!(
            frontend_base_url(&frontend("hub.acme.com", "/acme/infra/prod/")),
            "https://hub.acme.com/acme/infra/prod"
        );
    }

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

    /// A cache URL whose host is a literal internal/metadata IP must be
    /// recorded as unreachable without a request being issued — the
    /// `ValidatingResolver` only vets DNS hostnames, so the
    /// [`crate::fetch::is_safe_remote_url`] pre-check in [`probe_one`] is what
    /// closes the SSRF hole. The link-local metadata address is refused by the
    /// pre-check, so this test issues no live network request.
    #[tokio::test]
    async fn probe_one_rejects_literal_internal_ip_cache() {
        let http = crate::fetch::hardened_client().await;
        let probe = probe_one(&http, "http://169.254.169.254/").await;
        assert_eq!(probe.status, ProbeStatus::Unreachable);
        assert!(!probe.observed_nix_cache_info);
        // Sanity: the pre-check itself rejects this target, so `probe_one`
        // never reaches `probe_http`/`send()`.
        assert!(crate::fetch::is_safe_remote_url("http://169.254.169.254/").is_err());
    }
}
