//! Cache consistency validation: presence, integrity, stack-aware coverage,
//! and repair planning.
//!
//! RFC-0004's "Cache stores, stacks, and consistency validation" defines
//! three validation depths; this module implements the first two:
//!
//! - **presence** — for every store hash the registry's verified index
//!   references, check that `<hash>.narinfo` exists in each advertised cache.
//! - **integrity** — beyond presence, fetch each present narinfo, parse its
//!   `URL:` field, and check the referenced NAR exists (HEAD), with a
//!   `file://`-only size sanity check against the narinfo's `FileSize`.
//!
//! The remaining `deep` depth (sampled download + `FileHash` verification) is
//! still unimplemented; runs record their depth so the schema already
//! accommodates it.
//!
//! # Stack-aware coverage
//!
//! Coverage requirements derive from a registry's cache-stack semantics (see
//! [`crate::stack`]). [`validate_registry`] probes the stack's distinct
//! endpoints when a `[cache_stack]` is committed, else the flat `[[caches]]`
//! list. For every `mirror` group in the stack, each member must
//! *individually* cover the full closure set — a shortfall is a replication
//! failure reported as a [`ValidationSummary::mirror_shortfall`]. For `try`
//! semantics the *union* must cover, and each member's coverage fraction is
//! surfaced.
//!
//! # Repair planning
//!
//! [`plan_repair`] turns the latest runs into a list of [`RepairAction`]s:
//! for each missing `(cache, hash)` it finds another cache that *has* the
//! hash to copy from (content-addressed, so always safe). [`execute_repair`]
//! carries out `file://`-to-`file://` repairs by copying the narinfo and its
//! NAR; `http` targets are left as a plan (hub-managed upload-credential
//! repair is a later phase).
//!
//! Two cache transports are probed:
//!
//! - `file://` URLs and bare absolute paths: filesystem existence of
//!   `<root>/<hash>.narinfo` (and, at integrity depth, the NAR file).
//! - `http(s)://` URLs: a `HEAD <url>/<hash>.narinfo` with the hardened
//!   client (200 = present, 404 = missing); at integrity depth a `GET` of the
//!   narinfo followed by a `HEAD` of its NAR URL. Any transport error or
//!   unexpected status marks the whole cache *unreachable* for the run
//!   (recorded with `reachable = false` and `checked = 0`).
//!
//! Each run is recorded in the database (`validation_runs` plus per-hash
//! `validation_findings`) and summarized for callers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::db::{Database, RegistryRecord};
use crate::fetch;
use crate::stack::StackNode;

/// Maximum store hashes probed per cache per run.
///
/// Larger hash sets are truncated (deterministically — the hash list is
/// sorted) with a warning, never silently.
pub const MAX_HASHES_PER_RUN: usize = 4096;

/// The depth of a consistency-validation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationDepth {
    /// HEAD each `<hash>.narinfo`.
    Presence,
    /// Also fetch each narinfo and HEAD its referenced NAR (with a
    /// `file://` size sanity check).
    Integrity,
}

impl ValidationDepth {
    /// The depth label recorded in `validation_runs.depth`.
    pub fn as_str(self) -> &'static str {
        match self {
            ValidationDepth::Presence => "presence",
            ValidationDepth::Integrity => "integrity",
        }
    }
}

/// Per-cache summary of one validation run.
#[derive(Debug, Clone)]
pub struct ValidationSummary {
    /// The cache endpoint that was probed.
    pub cache_url: String,
    /// Number of store hashes probed (0 when unreachable).
    pub checked: u64,
    /// Number of probed hashes whose narinfo (or, at integrity depth, NAR)
    /// was absent or inconsistent.
    pub missing: u64,
    /// Whether the cache endpoint was reachable.
    pub reachable: bool,
    /// Percentage of probed hashes present (0 when nothing was checked).
    pub coverage_percent: f64,
    /// When this cache is a member of a `mirror` group that it does not
    /// fully cover, the shortfall: `(group_index, missing_count)`. A mirror
    /// member is expected to hold the *whole* set, so any miss is a
    /// replication failure rather than a fall-through.
    pub mirror_shortfall: Option<MirrorShortfall>,
}

/// A mirror-group coverage shortfall for one member cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorShortfall {
    /// Index of the mirror group in [`StackNode::mirror_groups`] order.
    pub group_index: usize,
    /// Number of closure hashes this member is missing.
    pub missing: u64,
}

/// A planned content-addressed repair: copy one missing object into a cache
/// from another cache that already has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairAction {
    /// The cache that is missing the object (the repair target).
    pub cache_url: String,
    /// The store hash to copy.
    pub store_hash: String,
    /// A cache that holds the object (the repair source).
    pub source_cache_url: String,
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
/// A thin wrapper over [`validate_registry`] at [`ValidationDepth::Presence`],
/// kept for callers (and the scheduler) that always want presence depth.
///
/// # Errors
///
/// Returns an error on database failure. Unreachable caches are *not* errors.
pub async fn validate_presence(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<Vec<ValidationSummary>> {
    validate_registry(db, registry, ValidationDepth::Presence).await
}

/// Run consistency validation for one registry at the requested depth.
///
/// Probes every hash from [`Database::all_store_hashes`] (capped at
/// [`MAX_HASHES_PER_RUN`] with a warning) against each cache the registry
/// advertises, records each run plus its missing findings in the database,
/// and returns per-cache summaries.
///
/// The cache set is the registry's committed cache stack's distinct endpoints
/// when a `[cache_stack]` is committed (see [`Database::registry_cache_stack`]),
/// else the flat `[[caches]]` list. For every `mirror` group, each member's
/// per-member coverage is computed and a shortfall is attached to that
/// member's summary (and recorded as findings).
///
/// # Errors
///
/// Returns an error on database failure. Unreachable caches are *not*
/// errors — they are recorded as `reachable = false` runs.
pub async fn validate_registry(
    db: &Database,
    registry: &RegistryRecord,
    depth: ValidationDepth,
) -> Result<Vec<ValidationSummary>> {
    let mut hashes = db.all_store_hashes(registry.id)?;
    if hashes.len() > MAX_HASHES_PER_RUN {
        tracing::warn!(
            registry = %registry.slug,
            total = hashes.len(),
            cap = MAX_HASHES_PER_RUN,
            "capping validation; probing the first {MAX_HASHES_PER_RUN} hashes"
        );
        hashes.truncate(MAX_HASHES_PER_RUN);
    }

    // The cache set and the mirror groups both come from the committed stack
    // when present, falling back to the flat [[caches]] list otherwise.
    let stack = db.registry_cache_stack(registry.id)?;
    let cache_urls: Vec<String> = match &stack {
        Some(node) => node.endpoints(),
        None => db
            .list_caches(registry.id)?
            .into_iter()
            .map(|(u, _)| u)
            .collect(),
    };
    let mirror_groups: Vec<Vec<String>> = stack
        .as_ref()
        .map(StackNode::mirror_groups)
        .unwrap_or_default();

    let client = fetch::hardened_client();
    let mut summaries = Vec::new();
    // Missing hashes per cache, for the mirror-group shortfall pass.
    let mut missing_by_cache: std::collections::HashMap<String, BTreeSet<String>> =
        std::collections::HashMap::new();
    for cache_url in cache_urls {
        let started_at = unix_now();
        let outcome = probe_cache(&client, &cache_url, &hashes, depth).await;
        let finished_at = unix_now();

        db.record_validation_run(
            registry.id,
            &cache_url,
            depth.as_str(),
            outcome.checked,
            &outcome.missing,
            outcome.reachable,
            started_at,
            finished_at,
        )?;
        missing_by_cache.insert(cache_url.clone(), outcome.missing.iter().cloned().collect());
        summaries.push(ValidationSummary {
            cache_url,
            checked: outcome.checked,
            missing: outcome.missing.len() as u64,
            reachable: outcome.reachable,
            coverage_percent: coverage_percent(outcome.checked, outcome.missing.len() as u64),
            mirror_shortfall: None,
        });
    }

    annotate_mirror_shortfalls(&mut summaries, &mirror_groups, &missing_by_cache);
    Ok(summaries)
}

/// Attach a [`MirrorShortfall`] to every summary whose cache is a mirror
/// member that does not fully cover its group's closure set.
///
/// A mirror member must hold the *whole* set; any missing hash is a
/// replication failure. The first group a cache belongs to is reported (a
/// cache in several groups is unusual but the lowest-indexed shortfall wins).
fn annotate_mirror_shortfalls(
    summaries: &mut [ValidationSummary],
    mirror_groups: &[Vec<String>],
    missing_by_cache: &std::collections::HashMap<String, BTreeSet<String>>,
) {
    for (group_index, group) in mirror_groups.iter().enumerate() {
        for member in group {
            let Some(missing) = missing_by_cache.get(member) else {
                continue;
            };
            if missing.is_empty() {
                continue;
            }
            if let Some(summary) = summaries
                .iter_mut()
                .find(|s| &s.cache_url == member && s.mirror_shortfall.is_none())
            {
                summary.mirror_shortfall = Some(MirrorShortfall {
                    group_index,
                    missing: missing.len() as u64,
                });
            }
        }
    }
}

/// Plan content-addressed repairs from the latest validation runs.
///
/// For every `(cache, hash)` the latest run found missing, find another
/// reachable cache whose latest run did *not* find that hash missing — a
/// source that holds the object. Because objects are content-addressed,
/// copying from any holder is safe. Missing hashes with no holder are skipped
/// (nothing can repair them).
///
/// The plan is deterministic: targets and hashes are walked in sorted order,
/// and the source is the lexicographically-first holding cache.
///
/// # Errors
///
/// Returns an error on database failure.
pub fn plan_repair(db: &Database, registry: &RegistryRecord) -> Result<Vec<RepairAction>> {
    let runs = db.latest_validation_runs(registry.id)?;

    // For each cache: the set of hashes its latest run found missing, and
    // whether it was reachable (an unreachable cache is neither a valid
    // target's evidence nor a usable source).
    let mut missing_by_cache: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();
    let mut reachable: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    for run in &runs {
        reachable.insert(run.cache_url.clone(), run.reachable);
        let missing = db.validation_missing(run.id)?.into_iter().collect();
        missing_by_cache.insert(run.cache_url.clone(), missing);
    }

    let mut actions = Vec::new();
    for (target, missing) in &missing_by_cache {
        for hash in missing {
            // A holder is a reachable cache whose latest run did not flag
            // this hash as missing.
            let source = reachable
                .iter()
                .filter(|(url, ok)| **ok && url.as_str() != target.as_str())
                .map(|(url, _)| url)
                .find(|url| {
                    missing_by_cache
                        .get(url.as_str())
                        .is_none_or(|set| !set.contains(hash))
                });
            if let Some(source) = source {
                actions.push(RepairAction {
                    cache_url: target.clone(),
                    store_hash: hash.clone(),
                    source_cache_url: source.clone(),
                });
            }
        }
    }
    Ok(actions)
}

/// Execute a `file://`-to-`file://` repair by content-addressed copy.
///
/// Copies `<hash>.narinfo` from the source directory into the target
/// directory, then copies the NAR file the narinfo's `URL:` field names
/// (resolved relative to each cache root). `http` sources or targets are
/// rejected — hub-managed upload-credential repair for HTTP caches is a later
/// phase.
///
/// Returns the number of files copied (1 for the narinfo plus 1 for the NAR
/// when a `URL:` is present).
///
/// # Errors
///
/// Returns an error when either endpoint is not a local directory, the source
/// narinfo is missing or malformed, or a filesystem copy fails.
pub async fn execute_repair(action: &RepairAction) -> Result<usize> {
    let source = local_root(&action.source_cache_url).with_context(|| {
        format!(
            "repair source {} is not a local cache",
            action.source_cache_url
        )
    })?;
    let target = local_root(&action.cache_url)
        .with_context(|| format!("repair target {} is not a local cache", action.cache_url))?;

    let narinfo_name = format!("{}.narinfo", action.store_hash);
    let src_narinfo = source.join(&narinfo_name);
    let narinfo_text = tokio::fs::read_to_string(&src_narinfo)
        .await
        .with_context(|| format!("reading source narinfo {}", src_narinfo.display()))?;

    tokio::fs::create_dir_all(&target)
        .await
        .with_context(|| format!("creating repair target {}", target.display()))?;
    tokio::fs::copy(&src_narinfo, target.join(&narinfo_name))
        .await
        .with_context(|| format!("copying narinfo into {}", target.display()))?;
    let mut copied = 1;

    if let Some(nar_rel) = narinfo_field(&narinfo_text, "URL") {
        let src_nar = source.join(&nar_rel);
        let dst_nar = target.join(&nar_rel);
        if let Some(parent) = dst_nar.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating NAR directory {}", parent.display()))?;
        }
        tokio::fs::copy(&src_nar, &dst_nar).await.with_context(|| {
            format!("copying NAR {} -> {}", src_nar.display(), dst_nar.display())
        })?;
        copied += 1;
    }
    Ok(copied)
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

/// The local filesystem root of a `file://` (or bare-path) cache, or `None`
/// for an HTTP cache.
fn local_root(url: &str) -> Option<PathBuf> {
    match classify_cache(url) {
        Some(CacheKind::File(root)) => Some(root),
        _ => None,
    }
}

/// Extract a single-line narinfo field value (`Name: value`).
fn narinfo_field(text: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Probe one cache for every hash at the requested depth.
async fn probe_cache(
    client: &reqwest::Client,
    cache_url: &str,
    hashes: &[String],
    depth: ValidationDepth,
) -> ProbeOutcome {
    match classify_cache(cache_url) {
        Some(CacheKind::File(root)) => probe_file_cache(&root, hashes, depth).await,
        Some(CacheKind::Http(base)) => probe_http_cache(client, &base, hashes, depth).await,
        None => {
            tracing::warn!(cache = %cache_url, "unsupported cache URL scheme; recording unreachable");
            ProbeOutcome::unreachable()
        }
    }
}

/// Filesystem probe: `<root>/<hash>.narinfo` must exist; at integrity depth
/// its `URL:` NAR must exist too and (when `FileSize` is present) match the
/// NAR file's byte length.
async fn probe_file_cache(root: &Path, hashes: &[String], depth: ValidationDepth) -> ProbeOutcome {
    if !root.is_dir() {
        return ProbeOutcome::unreachable();
    }
    let mut missing = Vec::new();
    for hash in hashes {
        let narinfo_path = root.join(format!("{hash}.narinfo"));
        let present = tokio::fs::try_exists(&narinfo_path).await.unwrap_or(false);
        if !present {
            missing.push(hash.clone());
            continue;
        }
        if depth == ValidationDepth::Integrity && !file_integrity_ok(root, &narinfo_path).await {
            missing.push(hash.clone());
        }
    }
    ProbeOutcome {
        checked: hashes.len() as u64,
        missing,
        reachable: true,
    }
}

/// Integrity check for a `file://` cache: the narinfo's NAR exists and (when
/// `FileSize` is declared) the file's length matches.
async fn file_integrity_ok(root: &Path, narinfo_path: &Path) -> bool {
    let Ok(text) = tokio::fs::read_to_string(narinfo_path).await else {
        return false;
    };
    let Some(nar_rel) = narinfo_field(&text, "URL") else {
        // No URL field: nothing further to integrity-check, treat as present.
        return true;
    };
    let nar_path = root.join(&nar_rel);
    let Ok(metadata) = tokio::fs::metadata(&nar_path).await else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    match narinfo_field(&text, "FileSize").and_then(|s| s.parse::<u64>().ok()) {
        Some(declared) => metadata.len() == declared,
        None => true,
    }
}

/// HTTP probe: `HEAD <base>/<hash>.narinfo`; at integrity depth additionally
/// `GET` the narinfo and `HEAD` its NAR URL.
///
/// 200 = present, 404 = missing; any transport error or other status makes
/// the whole cache unreachable for this run.
async fn probe_http_cache(
    client: &reqwest::Client,
    base: &str,
    hashes: &[String],
    depth: ValidationDepth,
) -> ProbeOutcome {
    let mut missing = Vec::new();
    for hash in hashes {
        let narinfo_url = format!("{base}/{hash}.narinfo");
        match head_status(client, &narinfo_url).await {
            Some(reqwest::StatusCode::OK) => {}
            Some(reqwest::StatusCode::NOT_FOUND) => {
                missing.push(hash.clone());
                continue;
            }
            Some(status) => {
                tracing::warn!(cache = %base, %status, "unexpected cache status; recording unreachable");
                return ProbeOutcome::unreachable();
            }
            None => {
                tracing::warn!(cache = %base, "cache unreachable");
                return ProbeOutcome::unreachable();
            }
        }
        if depth == ValidationDepth::Integrity {
            match http_integrity_ok(client, base, &narinfo_url).await {
                Some(true) => {}
                Some(false) => missing.push(hash.clone()),
                None => {
                    tracing::warn!(cache = %base, "cache unreachable during integrity probe");
                    return ProbeOutcome::unreachable();
                }
            }
        }
    }
    ProbeOutcome {
        checked: hashes.len() as u64,
        missing,
        reachable: true,
    }
}

/// Integrity check for an HTTP cache: GET the narinfo, parse its `URL:`, and
/// HEAD the NAR. `Some(true)`/`Some(false)` = NAR present/missing;
/// `None` = transport failure (unreachable).
async fn http_integrity_ok(
    client: &reqwest::Client,
    base: &str,
    narinfo_url: &str,
) -> Option<bool> {
    let response = client.get(narinfo_url).send().await.ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    let text = response.text().await.ok()?;
    let Some(nar_rel) = narinfo_field(&text, "URL") else {
        // No URL field to follow; the narinfo itself is present.
        return Some(true);
    };
    let nar_url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        nar_rel.trim_start_matches('/')
    );
    match head_status(client, &nar_url).await {
        Some(reqwest::StatusCode::OK) => Some(true),
        Some(reqwest::StatusCode::NOT_FOUND) => Some(false),
        _ => None,
    }
}

/// HEAD a URL, returning its status or `None` on transport error.
async fn head_status(client: &reqwest::Client, url: &str) -> Option<reqwest::StatusCode> {
    client.head(url).send().await.ok().map(|r| r.status())
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

    #[test]
    fn narinfo_field_extracts_url_and_size() {
        let text = "StorePath: /x\nURL: nar/abc.nar.zst\nFileSize: 42\n";
        assert_eq!(
            narinfo_field(text, "URL").as_deref(),
            Some("nar/abc.nar.zst")
        );
        assert_eq!(narinfo_field(text, "FileSize").as_deref(), Some("42"));
        assert_eq!(narinfo_field(text, "Missing"), None);
    }

    #[tokio::test]
    async fn file_probe_reports_missing_and_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("aaa.narinfo"), b"StorePath: /x\n").unwrap();
        let hashes = vec!["aaa".to_string(), "bbb".to_string()];

        let outcome = probe_file_cache(dir.path(), &hashes, ValidationDepth::Presence).await;
        assert!(outcome.reachable);
        assert_eq!(outcome.checked, 2);
        assert_eq!(outcome.missing, vec!["bbb".to_string()]);

        let gone =
            probe_file_cache(&dir.path().join("nope"), &hashes, ValidationDepth::Presence).await;
        assert!(!gone.reachable);
        assert_eq!(gone.checked, 0);
    }

    #[tokio::test]
    async fn integrity_depth_heads_the_nar() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("nar")).unwrap();
        // Present narinfo whose NAR exists with matching size.
        std::fs::write(dir.path().join("nar/aaa.nar"), b"12345").unwrap();
        std::fs::write(
            dir.path().join("aaa.narinfo"),
            b"StorePath: /x\nURL: nar/aaa.nar\nFileSize: 5\n",
        )
        .unwrap();
        // Present narinfo whose NAR is absent — fails integrity, passes
        // presence.
        std::fs::write(
            dir.path().join("bbb.narinfo"),
            b"StorePath: /y\nURL: nar/bbb.nar\nFileSize: 9\n",
        )
        .unwrap();
        let hashes = vec!["aaa".to_string(), "bbb".to_string()];

        let presence = probe_file_cache(dir.path(), &hashes, ValidationDepth::Presence).await;
        assert_eq!(presence.missing, Vec::<String>::new());

        let integrity = probe_file_cache(dir.path(), &hashes, ValidationDepth::Integrity).await;
        assert_eq!(integrity.missing, vec!["bbb".to_string()]);

        // A size mismatch also fails integrity.
        std::fs::write(
            dir.path().join("ccc.narinfo"),
            b"StorePath: /z\nURL: nar/aaa.nar\nFileSize: 999\n",
        )
        .unwrap();
        let mismatch =
            probe_file_cache(dir.path(), &["ccc".to_string()], ValidationDepth::Integrity).await;
        assert_eq!(mismatch.missing, vec!["ccc".to_string()]);
    }

    /// Build a registry whose index references a single store hash `abc`,
    /// with the given `[[caches]]` URLs, in a fresh in-memory db.
    fn registry_with_caches(caches: Vec<(String, u32)>) -> (Database, RegistryRecord) {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .register_registry("demo", "/srv/demo", &[], false)
            .unwrap();
        let package: aos_package::registry::parse::PackageToml = toml::from_str(
            r#"
            [package]
            name = "curl"
            description = "URL transfers"
            license = "MIT"
            maintainer = "aos"
            [[versions]]
            version = "8.5.0"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/abc-curl-8.5.0"
            nar_hash = "sha256:aa"
            nar_size = 10
            closure_size = 20
            source_drv = "/var/lib/store/abc.drv"
            source_nar_hash = "sha256:bb"
            "#,
        )
        .unwrap();
        let snapshot = crate::db::IndexSnapshot {
            commit: "c".repeat(64),
            name: "demo".into(),
            caches,
            packages: vec![package],
            ..Default::default()
        };
        db.apply_snapshot(id, &snapshot).unwrap();
        let registry = db.registry_by_slug("demo").unwrap().unwrap();
        (db, registry)
    }

    #[tokio::test]
    async fn file_repair_plan_execute_round_trip() {
        let complete = tempfile::tempdir().unwrap();
        let incomplete = tempfile::tempdir().unwrap();

        // The complete cache holds abc.narinfo + its NAR; the incomplete one
        // is empty.
        std::fs::create_dir_all(complete.path().join("nar")).unwrap();
        std::fs::write(complete.path().join("nar/abc.nar"), b"narbytes").unwrap();
        std::fs::write(
            complete.path().join("abc.narinfo"),
            b"StorePath: /var/lib/store/abc-curl-8.5.0\nURL: nar/abc.nar\nFileSize: 8\n",
        )
        .unwrap();

        let complete_url = format!("file://{}", complete.path().display());
        let incomplete_url = format!("file://{}", incomplete.path().display());
        let (db, registry) = registry_with_caches(vec![
            (complete_url.clone(), 100),
            (incomplete_url.clone(), 50),
        ]);

        // First validation: the incomplete cache is missing the hash.
        let summaries = validate_registry(&db, &registry, ValidationDepth::Presence)
            .await
            .unwrap();
        let incomplete_summary = summaries
            .iter()
            .find(|s| s.cache_url == incomplete_url)
            .unwrap();
        assert_eq!(incomplete_summary.missing, 1);
        assert_eq!(incomplete_summary.coverage_percent, 0.0);

        // The plan finds the missing hash sourced from the complete cache.
        let plan = plan_repair(&db, &registry).unwrap();
        assert_eq!(
            plan,
            vec![RepairAction {
                cache_url: incomplete_url.clone(),
                store_hash: "abc".to_string(),
                source_cache_url: complete_url.clone(),
            }],
        );

        // Execute copies the narinfo + NAR into the incomplete cache.
        let copied = execute_repair(&plan[0]).await.unwrap();
        assert_eq!(copied, 2);
        assert!(incomplete.path().join("abc.narinfo").exists());
        assert!(incomplete.path().join("nar/abc.nar").exists());

        // Re-validate: both caches now cover everything.
        let after = validate_registry(&db, &registry, ValidationDepth::Integrity)
            .await
            .unwrap();
        let incomplete_after = after
            .iter()
            .find(|s| s.cache_url == incomplete_url)
            .unwrap();
        assert_eq!(incomplete_after.missing, 0);
        assert_eq!(incomplete_after.coverage_percent, 100.0);
        assert!(plan_repair(&db, &registry).unwrap().is_empty());
    }

    #[tokio::test]
    async fn stack_aware_validation_finds_mirror_member_shortfall() {
        let complete = tempfile::tempdir().unwrap();
        let incomplete = tempfile::tempdir().unwrap();
        std::fs::write(
            complete.path().join("abc.narinfo"),
            b"StorePath: /var/lib/store/abc-curl-8.5.0\n",
        )
        .unwrap();

        let complete_url = format!("file://{}", complete.path().display());
        let incomplete_url = format!("file://{}", incomplete.path().display());

        // Commit a mirror [complete, incomplete] stack: both members are
        // expected to hold the full set.
        let stack = StackNode::Mirror(vec![
            StackNode::Endpoint(complete_url.clone()),
            StackNode::Endpoint(incomplete_url.clone()),
        ]);
        let (db, registry) = registry_with_caches(vec![
            (complete_url.clone(), 100),
            (incomplete_url.clone(), 99),
        ]);
        // Store the stack by re-applying a snapshot carrying its JSON.
        let package: aos_package::registry::parse::PackageToml = toml::from_str(
            r#"
            [package]
            name = "curl"
            description = "d"
            license = "MIT"
            maintainer = "aos"
            [[versions]]
            version = "8.5.0"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/abc-curl-8.5.0"
            nar_hash = "sha256:aa"
            nar_size = 10
            closure_size = 20
            source_drv = "/var/lib/store/abc.drv"
            source_nar_hash = "sha256:bb"
            "#,
        )
        .unwrap();
        db.apply_snapshot(
            registry.id,
            &crate::db::IndexSnapshot {
                commit: "c".repeat(64),
                name: "demo".into(),
                caches: vec![(complete_url.clone(), 100), (incomplete_url.clone(), 99)],
                cache_stack: Some(stack.to_json().unwrap()),
                packages: vec![package],
                ..Default::default()
            },
        )
        .unwrap();

        let summaries = validate_registry(&db, &registry, ValidationDepth::Presence)
            .await
            .unwrap();
        let complete_summary = summaries
            .iter()
            .find(|s| s.cache_url == complete_url)
            .unwrap();
        assert_eq!(complete_summary.mirror_shortfall, None);
        let incomplete_summary = summaries
            .iter()
            .find(|s| s.cache_url == incomplete_url)
            .unwrap();
        assert_eq!(
            incomplete_summary.mirror_shortfall,
            Some(MirrorShortfall {
                group_index: 0,
                missing: 1,
            }),
        );
    }

    #[test]
    fn mirror_shortfall_flags_incomplete_member() {
        let mut summaries = vec![
            ValidationSummary {
                cache_url: "https://a".into(),
                checked: 2,
                missing: 0,
                reachable: true,
                coverage_percent: 100.0,
                mirror_shortfall: None,
            },
            ValidationSummary {
                cache_url: "https://b".into(),
                checked: 2,
                missing: 1,
                reachable: true,
                coverage_percent: 50.0,
                mirror_shortfall: None,
            },
        ];
        let groups = vec![vec!["https://a".to_string(), "https://b".to_string()]];
        let mut missing = std::collections::HashMap::new();
        missing.insert("https://a".to_string(), BTreeSet::new());
        missing.insert("https://b".to_string(), BTreeSet::from(["xyz".to_string()]));

        annotate_mirror_shortfalls(&mut summaries, &groups, &missing);
        assert_eq!(summaries[0].mirror_shortfall, None);
        assert_eq!(
            summaries[1].mirror_shortfall,
            Some(MirrorShortfall {
                group_index: 0,
                missing: 1,
            }),
        );
    }
}
