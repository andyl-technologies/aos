//! Cache consistency validation: presence, integrity, stack-aware coverage,
//! and repair planning.
//!
//! RFC-0004's "Cache stores, stacks, and consistency validation" defines
//! three validation depths; this module implements all three:
//!
//! - **presence** — for every store hash the registry's verified index
//!   references, check that `<hash>.narinfo` exists in each advertised cache.
//! - **integrity** — beyond presence, fetch each present narinfo, parse its
//!   `URL:` field, and check the referenced NAR exists (HEAD), with a
//!   `file://`-only size sanity check against the narinfo's `FileSize`.
//! - **deep** — beyond integrity, on a deterministic *sample* of up to
//!   [`DEEP_SAMPLE_SIZE`] hashes, verify the narinfo's `Sig:` against the
//!   registry's trust roster ([`verify_narinfo_signature`]) and download the
//!   NAR to verify its content hash against the narinfo's declared `FileHash`
//!   (falling back to `NarHash`). A narinfo with no trusted signature, or a
//!   NAR whose bytes do not match its declared hash, is a `corrupt` finding,
//!   recorded distinctly from `missing` — corruption cannot be repaired by a
//!   content-addressed copy (the copy would carry the same bad bytes), so it
//!   flags a cache that must be re-uploaded from a good source. The signature
//!   check is what lets a green deep result mean *authenticity* rather than
//!   mere internal consistency: the hash check alone cannot catch an adversary
//!   who controls both files. The sample is the first [`DEEP_SAMPLE_SIZE`]
//!   hashes in sorted order, so reruns are stable.
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
//! NAR.
//!
//! For an **http target the hub is authorized to write** — a managed registry
//! facade URL the hub serves — [`run_repairs`] mints an internal short-lived
//! Publish token (the same path as [`crate::rpc`]'s `MintUploadCredentials`)
//! and PUTs the narinfo + NAR to the target through the facade with a Bearer
//! JWT ([`execute_repair_http`]). Targets the hub has *no* credential for
//! (arbitrary external caches) remain plan-only: [`run_repairs`] records them
//! as `plan_only` repair jobs and never writes to them. Every repair attempt
//! is recorded in `repair_jobs` (`pending | done | failed | plan_only`).
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
use sha2::{Digest, Sha256};

use crate::db::{Database, FindingStatus, RegistryRecord, ValidationFinding};
use crate::fetch;
use crate::stack::StackNode;

/// Maximum store hashes probed per cache per run.
///
/// Larger hash sets are truncated (deterministically — the hash list is
/// sorted) with a warning, never silently.
pub const MAX_HASHES_PER_RUN: usize = 4096;

/// Maximum NARs downloaded and content-verified per cache in a deep run.
///
/// A deep run is expensive (it transfers NAR bytes), so it samples a bounded
/// subset of the closure rather than the whole set. The sample is the first
/// `DEEP_SAMPLE_SIZE` hashes in sorted order, so the choice is deterministic
/// and reruns are stable for tests.
///
/// The deep run verifies each sampled narinfo's `Sig:` against the registry's
/// trust roster *and* its NAR content hash. Note the hash check alone cannot
/// detect an adversary who controls *both* the narinfo and the NAR (they can
/// forge a self-consistent `FileHash`/`NarHash`); the `Sig:` check is what
/// establishes authenticity, since it requires a trusted private key. The
/// sample bound trades coverage for cost — a clean deep result attests the
/// sampled subset, not the entire closure.
pub const DEEP_SAMPLE_SIZE: usize = 16;

/// The depth of a consistency-validation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationDepth {
    /// HEAD each `<hash>.narinfo`.
    Presence,
    /// Also fetch each narinfo and HEAD its referenced NAR (with a
    /// `file://` size sanity check).
    Integrity,
    /// Also download a deterministic sample of NARs and verify their content
    /// hash against the narinfo's declared hash (flagging mismatches
    /// `corrupt`).
    Deep,
}

impl ValidationDepth {
    /// The depth label recorded in `validation_runs.depth`.
    pub fn as_str(self) -> &'static str {
        match self {
            ValidationDepth::Presence => "presence",
            ValidationDepth::Integrity => "integrity",
            ValidationDepth::Deep => "deep",
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
    /// Number of probed hashes that did not resolve correctly: absent at any
    /// depth, plus (at deep depth) content-hash mismatches.
    pub missing: u64,
    /// Number of deep-sampled hashes whose downloaded content did not match
    /// its declared hash (a subset of [`ValidationSummary::missing`]). Always
    /// zero below [`ValidationDepth::Deep`].
    pub corrupt: u64,
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
    /// Hashes whose narinfo/NAR was absent.
    missing: Vec<String>,
    /// Hashes (a subset of the deep sample) whose downloaded NAR content did
    /// not match its declared hash.
    corrupt: Vec<String>,
    reachable: bool,
}

impl ProbeOutcome {
    fn unreachable() -> Self {
        Self {
            checked: 0,
            missing: Vec::new(),
            corrupt: Vec::new(),
            reachable: false,
        }
    }

    /// All findings (missing then corrupt) as typed [`ValidationFinding`]s.
    fn findings(&self) -> Vec<ValidationFinding> {
        self.missing
            .iter()
            .map(|hash| ValidationFinding {
                store_hash: hash.clone(),
                status: FindingStatus::Missing,
            })
            .chain(self.corrupt.iter().map(|hash| ValidationFinding {
                store_hash: hash.clone(),
                status: FindingStatus::Corrupt,
            }))
            .collect()
    }

    /// The total finding count (missing + corrupt) — the run's `missing`
    /// column.
    fn problem_count(&self) -> u64 {
        (self.missing.len() + self.corrupt.len()) as u64
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

/// Run deep validation for every committed cache of one registry.
///
/// A thin wrapper over [`validate_registry`] at [`ValidationDepth::Deep`]: a
/// deterministic sample of NARs is downloaded and content-verified, flagging
/// any mismatch `corrupt`.
///
/// # Errors
///
/// Returns an error on database failure. Unreachable caches are *not* errors.
pub async fn validate_deep(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<Vec<ValidationSummary>> {
    validate_registry(db, registry, ValidationDepth::Deep).await
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
        let outcome = probe_cache(&client, &cache_url, &hashes, depth, &registry.trust_keys).await;
        let finished_at = unix_now();

        db.record_validation_run_with_findings(
            registry.id,
            &cache_url,
            depth.as_str(),
            outcome.checked,
            &outcome.findings(),
            outcome.reachable,
            started_at,
            finished_at,
        )?;
        // Only *missing* hashes drive mirror-shortfall and repair planning;
        // a corrupt hash is present (so not a replication gap) and is not
        // safely copyable.
        missing_by_cache.insert(cache_url.clone(), outcome.missing.iter().cloned().collect());
        summaries.push(ValidationSummary {
            cache_url,
            checked: outcome.checked,
            missing: outcome.problem_count(),
            corrupt: outcome.corrupt.len() as u64,
            reachable: outcome.reachable,
            coverage_percent: coverage_percent(outcome.checked, outcome.problem_count()),
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

/// One narinfo and its NAR, read from a source cache for a repair.
struct RepairObject {
    /// The narinfo file's text (`<hash>.narinfo`).
    narinfo: String,
    /// The narinfo's `URL:` (NAR path relative to the cache root), if any.
    nar_rel: Option<String>,
    /// The NAR bytes, when a `URL:` named one.
    nar_bytes: Option<Vec<u8>>,
}

/// Read a `(narinfo, NAR)` object for one store hash from a source cache.
///
/// Works against a `file://`/bare-path source (filesystem read) or an
/// `http(s)://` source (GET through the hardened client). The narinfo's `URL:`
/// NAR is fetched too when present. Content is **not** trusted blindly — the
/// caller verifies the hash before writing it anywhere (content-addressed, so
/// a hash mismatch means the source itself is corrupt and is rejected).
///
/// # Errors
///
/// Returns an error when the source narinfo (or its named NAR) cannot be read.
async fn read_repair_object(
    client: &reqwest::Client,
    source_cache_url: &str,
    store_hash: &str,
) -> Result<RepairObject> {
    let narinfo_name = format!("{store_hash}.narinfo");
    match classify_cache(source_cache_url) {
        Some(CacheKind::File(root)) => {
            let narinfo = tokio::fs::read_to_string(root.join(&narinfo_name))
                .await
                .with_context(|| format!("reading source narinfo for {store_hash}"))?;
            let nar_rel = narinfo_field(&narinfo, "URL");
            let nar_bytes = match &nar_rel {
                Some(rel) => Some(
                    tokio::fs::read(root.join(rel))
                        .await
                        .with_context(|| format!("reading source NAR for {store_hash}"))?,
                ),
                None => None,
            };
            Ok(RepairObject {
                narinfo,
                nar_rel,
                nar_bytes,
            })
        }
        Some(CacheKind::Http(base)) => {
            let narinfo = http_get_text(client, &format!("{base}/{narinfo_name}"))
                .await
                .with_context(|| format!("fetching source narinfo for {store_hash}"))?;
            let nar_rel = narinfo_field(&narinfo, "URL");
            let nar_bytes = match &nar_rel {
                Some(rel) => {
                    let nar_url = format!("{}/{}", base, rel.trim_start_matches('/'));
                    Some(
                        http_get_bytes(client, &nar_url)
                            .await
                            .with_context(|| format!("fetching source NAR for {store_hash}"))?,
                    )
                }
                None => None,
            };
            Ok(RepairObject {
                narinfo,
                nar_rel,
                nar_bytes,
            })
        }
        None => anyhow::bail!("repair source {source_cache_url} has an unsupported scheme"),
    }
}

/// GET a URL and return its body text, erroring on any non-200.
///
/// The body is read with the surface cap ([`MAX_FETCH_BYTES`](crate::fetch::MAX_FETCH_BYTES)) so a hostile
/// upstream cannot stream an unbounded narinfo/text body into memory.
async fn http_get_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client.get(url).send().await?;
    if response.status() != reqwest::StatusCode::OK {
        anyhow::bail!("GET {url}: HTTP {}", response.status());
    }
    crate::fetch::read_text_capped(
        response,
        crate::fetch::MAX_FETCH_BYTES,
        &format!("GET {url}"),
    )
    .await
}

/// GET a URL and return its body bytes, erroring on any non-200.
///
/// The body is read with the generous NAR cap ([`MAX_NAR_BYTES`](crate::fetch::MAX_NAR_BYTES)) so a
/// legitimate large NAR is accepted while a runaway body is still bounded.
async fn http_get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client.get(url).send().await?;
    if response.status() != reqwest::StatusCode::OK {
        anyhow::bail!("GET {url}: HTTP {}", response.status());
    }
    crate::fetch::read_body_capped(response, crate::fetch::MAX_NAR_BYTES, &format!("GET {url}"))
        .await
}

/// Execute a `file://`-to-`file://` repair by content-addressed copy.
///
/// Copies `<hash>.narinfo` from the source directory into the target
/// directory, then copies the NAR file the narinfo's `URL:` field names
/// (resolved relative to each cache root). For HTTP *targets*, use
/// [`execute_repair_http`] instead.
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

/// A credential for writing one missing object into an http target the hub is
/// authorized to write.
#[derive(Debug, Clone)]
pub struct RepairCredential {
    /// The facade base URL to PUT surface paths under (the registry's
    /// canonical upload URL, e.g. `https://hub.example.com/acme/infra/prod`).
    pub upload_url: String,
    /// A Bearer JWT granting `publish` on that registry's scope.
    pub bearer_jwt: String,
}

/// Resolves the upload credential for an http repair target.
///
/// Implemented by the hub server to mint an internal short-lived Publish JWT
/// for a target that is one of the hub's own managed registry facade URLs (the
/// same authorization the `MintUploadCredentials` RPC grants a producer). For
/// a target the hub does not serve — an arbitrary external cache with no
/// configured credential — it returns `None`, and [`run_repairs`] records the
/// repair as `plan_only` rather than writing somewhere it cannot authorize.
pub trait RepairAuthorizer: Send + Sync {
    /// Return a write credential for `target_cache_url`, or `None` when the
    /// hub is not authorized to write to it.
    ///
    /// # Errors
    ///
    /// Returns an error on an internal failure while minting the credential
    /// (e.g. a database or signing error).
    fn credential_for(&self, target_cache_url: &str) -> Result<Option<RepairCredential>>;
}

/// Execute a repair into an **http** target the hub is authorized to write.
///
/// Reads the `(narinfo, NAR)` object from the source cache (file or http),
/// **verifies the NAR's content hash against the narinfo** before trusting it
/// (a source whose bytes do not match is corrupt and is rejected, never
/// propagated), then PUTs the narinfo and NAR to the target through the
/// registry facade with the supplied Bearer JWT, exactly as `apr origin
/// upload` would. Surface paths are written relative to `credential.upload_url`
/// (`<hash>.narinfo` and the narinfo's `URL:` NAR path).
///
/// Returns the number of files PUT (1 for the narinfo plus 1 for the NAR when
/// the narinfo names one).
///
/// # Errors
///
/// Returns an error when the source object cannot be read, the source NAR
/// fails content-hash verification, or a target PUT returns a non-2xx status.
pub async fn execute_repair_http(
    client: &reqwest::Client,
    action: &RepairAction,
    credential: &RepairCredential,
) -> Result<usize> {
    let object = read_repair_object(client, &action.source_cache_url, &action.store_hash).await?;

    // Content-addressed safety: never propagate bytes that do not match the
    // narinfo. (file:// repair copies bit-for-bit so it is trivially safe; an
    // http round-trip is where a mid-flight corruption could enter.)
    if let Some(bytes) = &object.nar_bytes {
        if matches!(verify_nar_bytes(&object.narinfo, bytes), DeepCheck::Corrupt) {
            anyhow::bail!(
                "source {} holds a corrupt NAR for {} (content hash mismatch); refusing to propagate",
                action.source_cache_url,
                action.store_hash,
            );
        }
    }

    let base = credential.upload_url.trim_end_matches('/');
    put_surface_file(
        client,
        &format!("{base}/{}.narinfo", action.store_hash),
        &credential.bearer_jwt,
        "text/x-nix-narinfo",
        object.narinfo.into_bytes(),
    )
    .await
    .context("PUT narinfo to repair target")?;
    let mut written = 1;

    if let (Some(rel), Some(bytes)) = (object.nar_rel, object.nar_bytes) {
        put_surface_file(
            client,
            &format!("{base}/{}", rel.trim_start_matches('/')),
            &credential.bearer_jwt,
            "application/x-nix-nar",
            bytes,
        )
        .await
        .context("PUT NAR to repair target")?;
        written += 1;
    }
    Ok(written)
}

/// PUT one surface file to a facade target with a Bearer JWT.
async fn put_surface_file(
    client: &reqwest::Client,
    url: &str,
    bearer_jwt: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<()> {
    let response = client
        .put(url)
        .bearer_auth(bearer_jwt)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(body)
        .send()
        .await
        .with_context(|| format!("PUT {url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("PUT {url}: HTTP {}", response.status());
    }
    Ok(())
}

/// Summary of one [`run_repairs`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepairSummary {
    /// Repairs that completed (file copy or http PUT).
    pub done: u64,
    /// Repairs left as a plan (no write credential for the http target).
    pub plan_only: u64,
    /// Repairs attempted but failed (recorded with the error).
    pub failed: u64,
}

/// Plan and execute every repairable missing object for one registry,
/// recording each attempt in `repair_jobs`.
///
/// Plans with [`plan_repair`], then for each action:
///
/// - a `file://`/bare-path target is repaired by content-addressed copy
///   ([`execute_repair`]) and recorded `done` (or `failed`);
/// - an `http(s)://` target the `authorizer` grants a [`RepairCredential`] for
///   is repaired by fetch-verify-PUT ([`execute_repair_http`]) and recorded
///   `done` (or `failed`);
/// - an `http(s)://` target the authorizer declines (no credential) is left
///   untouched and recorded `plan_only`.
///
/// Returns the per-status tally. A single action's failure does not abort the
/// pass — its `repair_jobs` row carries the error and the pass continues.
///
/// # Errors
///
/// Returns an error only on a database failure (planning, or recording a job);
/// individual repair failures are captured as `failed` jobs, not propagated.
pub async fn run_repairs(
    db: &Database,
    client: &reqwest::Client,
    registry: &RegistryRecord,
    authorizer: &dyn RepairAuthorizer,
) -> Result<RepairSummary> {
    let actions = plan_repair(db, registry)?;
    let mut summary = RepairSummary::default();
    for action in &actions {
        let created_at = unix_now();
        // An http target needs a write credential; a file target never does.
        let credential = match classify_cache(&action.cache_url) {
            Some(CacheKind::File(_)) => None,
            Some(CacheKind::Http(_)) => match authorizer.credential_for(&action.cache_url)? {
                Some(credential) => Some(credential),
                None => {
                    // No credential: record plan-only and move on.
                    db.record_repair_job(
                        registry.id,
                        &action.cache_url,
                        &action.store_hash,
                        &action.source_cache_url,
                        "plan_only",
                        None,
                        created_at,
                        Some(unix_now()),
                    )?;
                    summary.plan_only += 1;
                    continue;
                }
            },
            None => {
                db.record_repair_job(
                    registry.id,
                    &action.cache_url,
                    &action.store_hash,
                    &action.source_cache_url,
                    "failed",
                    Some("unsupported target cache scheme"),
                    created_at,
                    Some(unix_now()),
                )?;
                summary.failed += 1;
                continue;
            }
        };

        let result = match &credential {
            Some(credential) => execute_repair_http(client, action, credential)
                .await
                .map(|_| ()),
            None => execute_repair(action).await.map(|_| ()),
        };
        match result {
            Ok(()) => {
                db.record_repair_job(
                    registry.id,
                    &action.cache_url,
                    &action.store_hash,
                    &action.source_cache_url,
                    "done",
                    None,
                    created_at,
                    Some(unix_now()),
                )?;
                summary.done += 1;
            }
            Err(err) => {
                let message = format!("{err:#}");
                tracing::warn!(
                    registry = %registry.slug,
                    target = %action.cache_url,
                    hash = %action.store_hash,
                    error = %message,
                    "repair failed"
                );
                db.record_repair_job(
                    registry.id,
                    &action.cache_url,
                    &action.store_hash,
                    &action.source_cache_url,
                    "failed",
                    Some(&message),
                    created_at,
                    Some(unix_now()),
                )?;
                summary.failed += 1;
            }
        }
    }
    Ok(summary)
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

/// Verify downloaded NAR `bytes` against the hashes a narinfo declares.
///
/// Prefers `FileHash` (the hash of the compressed NAR as stored, which is what
/// is downloaded); falls back to `NarHash` only when the NAR is uncompressed
/// (`Compression: none`), since `NarHash` is over the uncompressed bytes.
///
/// The check **fails closed**: a declared hash whose encoding cannot be parsed
/// (`sha256_hash_matches` returns `None`) does not short-circuit to
/// [`DeepCheck::Ok`] — instead it falls through to the next available hash. If
/// the narinfo declares *some* hash but none of them can be parsed and matched,
/// the result is [`DeepCheck::Corrupt`]: a payload whose declared integrity is
/// uncheckable is treated as a finding, not silently accepted. Only a narinfo
/// that declares **no** integrity field at all is [`DeepCheck::Ok`] (there is
/// genuinely nothing to refute).
fn verify_nar_bytes(narinfo: &str, bytes: &[u8]) -> DeepCheck {
    let digest = Sha256::digest(bytes);
    let file_hash = narinfo_field(narinfo, "FileHash");
    // `NarHash` only applies to the raw bytes when the NAR is uncompressed.
    let uncompressed = narinfo_field(narinfo, "Compression")
        .map(|c| c == "none")
        .unwrap_or(true);
    let nar_hash = if uncompressed {
        narinfo_field(narinfo, "NarHash")
    } else {
        None
    };

    // No usable integrity field at all: nothing to refute.
    if file_hash.is_none() && nar_hash.is_none() {
        return DeepCheck::Ok;
    }

    // A definite match on any declared hash confirms integrity; an
    // unparseable declared hash is *not* a pass — fall through to the next.
    for declared in [file_hash, nar_hash].into_iter().flatten() {
        match sha256_hash_matches(&declared, &digest) {
            Some(true) => return DeepCheck::Ok,
            Some(false) => return DeepCheck::Corrupt,
            None => continue,
        }
    }
    // A hash was declared but none could be parsed and matched: fail closed.
    DeepCheck::Corrupt
}

/// Verify that a narinfo carries at least one valid Ed25519 `Sig:` by a key
/// in the registry's trust roster.
///
/// This is the **single source of truth** for narinfo authenticity across the
/// hub: the full-mirror sync ([`crate::mirror::sync_full_mirror`]), the
/// pull-through cache ([`crate::mirror::fetch_through`]), and the deep
/// health-validation path all call it so a poisoned narinfo is rejected
/// uniformly.
///
/// A narinfo `Sig:` field is `name:<base64-ed25519-sig>`; the signature is
/// over the Nix narinfo *fingerprint*
/// `1;<store_path>;<nar_hash>;<nar_size>;<refs,…>` (see
/// [`aos_core::nar::cache::NarInfoSigner::fingerprint`]). The reference paths
/// in the fingerprint are full store paths, reconstructed by re-rooting each
/// `References:` basename under the directory of `StorePath`. A trusted key is
/// a registry roster line `name:Ed25519:<base64-wire-blob>` (the same form
/// the git-commit/tag trust anchor uses); its `name` must match the `Sig:`
/// name and its Ed25519 key must verify the fingerprint.
///
/// Verification is **fail-closed**: an unparseable narinfo, a missing `Sig:`,
/// or no signature that verifies against a trusted key all return an error.
/// A narinfo that an adversary controls the *bytes* of (so it could forge a
/// self-consistent `FileHash`/`NarHash`) cannot forge this signature without a
/// trusted private key, which is what makes the NAR hash check downstream
/// trustworthy.
///
/// # Errors
///
/// Returns an error when `trusted_keys` is empty, the narinfo cannot be
/// parsed, it declares no `Sig:`, or none of its signatures is a valid
/// Ed25519 signature over the fingerprint by a trusted key.
pub fn verify_narinfo_signature(narinfo: &str, trusted_keys: &[String]) -> Result<()> {
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if trusted_keys.is_empty() {
        anyhow::bail!("cannot verify narinfo signature: trusted key set is empty");
    }
    let info =
        aos_core::nar::info::parse(narinfo).context("parsing narinfo for signature check")?;
    if info.signatures.is_empty() {
        anyhow::bail!("narinfo for {} carries no Sig", info.store_path);
    }

    // The fingerprint references are full store paths: re-root each
    // `References:` basename under the StorePath's own store directory.
    let store_dir = info
        .store_path
        .rsplit_once('/')
        .map(|(dir, _)| dir.to_string())
        .unwrap_or_default();
    let refs: Vec<String> = info
        .references
        .iter()
        .map(|r| {
            let base = r.rsplit('/').next().unwrap_or(r);
            if store_dir.is_empty() {
                base.to_string()
            } else {
                format!("{store_dir}/{base}")
            }
        })
        .collect();
    let fingerprint = aos_core::nar::cache::NarInfoSigner::fingerprint(
        &info.store_path,
        &info.nar_hash,
        info.nar_size as i64,
        &refs,
    );

    // Index the trust roster by signature name so a `Sig:` only verifies
    // against a key the registry actually pins under that name.
    for sig in &info.signatures {
        let Some((sig_name, sig_b64)) = sig.split_once(':') else {
            continue;
        };
        let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(sig_b64) else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&sig_bytes) else {
            continue;
        };
        for trusted in trusted_keys {
            let Ok((key_name, raw_key)) =
                aos_registry_surface::sshsig::trusted_key_ed25519(trusted)
            else {
                continue;
            };
            if key_name != sig_name {
                continue;
            }
            let Ok(verifying_key) = VerifyingKey::from_bytes(&raw_key) else {
                continue;
            };
            if verifying_key
                .verify(fingerprint.as_bytes(), &signature)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
    anyhow::bail!(
        "narinfo for {} has no valid Sig by a trusted key",
        info.store_path
    )
}

/// Verify downloaded NAR `bytes` against the hashes a narinfo declares,
/// returning an error on a mismatch (the public, fail-on-corrupt wrapper of
/// [`verify_nar_bytes`]).
///
/// Used by the mirror sync and pull-through paths, which must *reject* a NAR
/// whose bytes do not match the (now signature-verified) narinfo rather than
/// merely flag it. Mirrors the semantics of [`verify_nar_bytes`]: a narinfo
/// declaring no integrity field at all is accepted (there is nothing to
/// refute), but a declared-yet-unmatchable hash fails closed.
///
/// # Errors
///
/// Returns an error when the NAR bytes do not match a declared `FileHash`/
/// `NarHash`, or when an integrity field is declared but cannot be parsed and
/// matched.
pub fn verify_nar_against_narinfo(narinfo: &str, bytes: &[u8]) -> Result<()> {
    match verify_nar_bytes(narinfo, bytes) {
        DeepCheck::Ok => Ok(()),
        DeepCheck::Corrupt => anyhow::bail!("NAR bytes do not match the narinfo's declared hash"),
        // `verify_nar_bytes` never returns `Missing` (it only inspects the
        // bytes it was handed); treat it as a corrupt finding defensively.
        DeepCheck::Missing => anyhow::bail!("NAR integrity could not be established"),
    }
}

/// Whether a declared `sha256:`/`sha256-` hash matches a computed digest.
///
/// Accepts the three encodings a narinfo hash may use — hex
/// (`sha256:<64 hex>`), SRI base64 (`sha256-<base64>`), and Nix base32
/// (`sha256:<52 base32>`) — by encoding the computed digest into the matching
/// form and comparing. Returns `None` when the declared string is not a
/// recognizable `sha256` hash (so the caller treats it as un-refuted).
fn sha256_hash_matches(declared: &str, digest: &[u8]) -> Option<bool> {
    if let Some(encoded) = declared.strip_prefix("sha256:") {
        if encoded.len() == 64 && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(encoded.eq_ignore_ascii_case(&hex::encode(digest)));
        }
        // Otherwise assume Nix base32.
        return Some(encoded == encode_nix_base32(digest));
    }
    if let Some(encoded) = declared.strip_prefix("sha256-") {
        use base64::Engine as _;
        return Some(encoded == base64::engine::general_purpose::STANDARD.encode(digest));
    }
    None
}

/// Nix's custom base32 alphabet (omits `e`, `o`, `t`, `u`).
const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Encodes bytes in Nix's base32 variant (little-endian bit order, most-
/// significant digit first), matching `nix hash convert --to nix32`.
fn encode_nix_base32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let len = (bytes.len() * 8).div_ceil(5);
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        let mut c = (bytes[i] >> j) as u16;
        if i + 1 < bytes.len() {
            c |= (bytes[i + 1] as u16) << (8 - j);
        }
        out.push(NIX_BASE32[(c & 0x1f) as usize] as char);
    }
    out
}

/// Probe one cache for every hash at the requested depth.
///
/// `trusted_keys` is the registry's narinfo trust roster, used at
/// [`ValidationDepth::Deep`] to verify each sampled narinfo's `Sig:`.
async fn probe_cache(
    client: &reqwest::Client,
    cache_url: &str,
    hashes: &[String],
    depth: ValidationDepth,
    trusted_keys: &[String],
) -> ProbeOutcome {
    match classify_cache(cache_url) {
        Some(CacheKind::File(root)) => probe_file_cache(&root, hashes, depth, trusted_keys).await,
        Some(CacheKind::Http(base)) => {
            probe_http_cache(client, &base, hashes, depth, trusted_keys).await
        }
        None => {
            tracing::warn!(cache = %cache_url, "unsupported cache URL scheme; recording unreachable");
            ProbeOutcome::unreachable()
        }
    }
}

/// Filesystem probe: `<root>/<hash>.narinfo` must exist; at integrity depth
/// its `URL:` NAR must exist too and (when `FileSize` is present) match the
/// NAR file's byte length; at deep depth a deterministic sample additionally
/// has its narinfo `Sig:` verified against `trusted_keys` and its NAR content
/// hash verified against the narinfo's declared hash.
async fn probe_file_cache(
    root: &Path,
    hashes: &[String],
    depth: ValidationDepth,
    trusted_keys: &[String],
) -> ProbeOutcome {
    if !root.is_dir() {
        return ProbeOutcome::unreachable();
    }
    let deep_sample = deep_sample(hashes, depth);
    let mut missing = Vec::new();
    let mut corrupt = Vec::new();
    for hash in hashes {
        let narinfo_path = root.join(format!("{hash}.narinfo"));
        let present = tokio::fs::try_exists(&narinfo_path).await.unwrap_or(false);
        if !present {
            missing.push(hash.clone());
            continue;
        }
        if depth != ValidationDepth::Presence && !file_integrity_ok(root, &narinfo_path).await {
            missing.push(hash.clone());
            continue;
        }
        if deep_sample.contains(hash.as_str()) {
            match file_deep_ok(root, &narinfo_path, trusted_keys).await {
                DeepCheck::Ok => {}
                DeepCheck::Missing => missing.push(hash.clone()),
                DeepCheck::Corrupt => corrupt.push(hash.clone()),
            }
        }
    }
    ProbeOutcome {
        checked: hashes.len() as u64,
        missing,
        corrupt,
        reachable: true,
    }
}

/// The deterministic deep-validation sample: the first [`DEEP_SAMPLE_SIZE`]
/// hashes (the input is already sorted), or all of them if fewer. Empty below
/// [`ValidationDepth::Deep`].
fn deep_sample(hashes: &[String], depth: ValidationDepth) -> BTreeSet<&str> {
    if depth != ValidationDepth::Deep {
        return BTreeSet::new();
    }
    hashes
        .iter()
        .take(DEEP_SAMPLE_SIZE)
        .map(String::as_str)
        .collect()
}

/// Outcome of a deep content-hash check of one narinfo's NAR.
enum DeepCheck {
    /// Content hash matched the declared hash.
    Ok,
    /// The NAR (or a declared hash to verify against) was absent.
    Missing,
    /// The NAR was present but its content hash did not match.
    Corrupt,
}

/// Deep check for a `file://` cache: verify the narinfo's `Sig:` against the
/// trust roster, then read the NAR the narinfo names and verify its content
/// hash against the declared `FileHash` (falling back to `NarHash`).
///
/// The signature check is what makes a green deep result mean *authenticity*,
/// not just internal consistency: an adversary controlling both the narinfo
/// and the NAR can forge a self-consistent `FileHash`/`NarHash`, but cannot
/// forge a `Sig:` by a trusted key. When `trusted_keys` is empty (an unsigned
/// registry), the signature step is skipped and only the hash is checked.
async fn file_deep_ok(root: &Path, narinfo_path: &Path, trusted_keys: &[String]) -> DeepCheck {
    let Ok(text) = tokio::fs::read_to_string(narinfo_path).await else {
        return DeepCheck::Missing;
    };
    if !trusted_keys.is_empty() && verify_narinfo_signature(&text, trusted_keys).is_err() {
        return DeepCheck::Corrupt;
    }
    let Some(nar_rel) = narinfo_field(&text, "URL") else {
        // No URL to download; nothing to deep-verify.
        return DeepCheck::Ok;
    };
    let Ok(bytes) = tokio::fs::read(root.join(&nar_rel)).await else {
        return DeepCheck::Missing;
    };
    verify_nar_bytes(&text, &bytes)
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
    trusted_keys: &[String],
) -> ProbeOutcome {
    let deep_sample = deep_sample(hashes, depth);
    let mut missing = Vec::new();
    let mut corrupt = Vec::new();
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
        if depth != ValidationDepth::Presence {
            match http_integrity_ok(client, base, &narinfo_url).await {
                Some(true) => {}
                Some(false) => {
                    missing.push(hash.clone());
                    continue;
                }
                None => {
                    tracing::warn!(cache = %base, "cache unreachable during integrity probe");
                    return ProbeOutcome::unreachable();
                }
            }
        }
        if deep_sample.contains(hash.as_str()) {
            match http_deep_ok(client, base, &narinfo_url, trusted_keys).await {
                DeepCheck::Ok => {}
                DeepCheck::Missing => missing.push(hash.clone()),
                DeepCheck::Corrupt => corrupt.push(hash.clone()),
            }
        }
    }
    ProbeOutcome {
        checked: hashes.len() as u64,
        missing,
        corrupt,
        reachable: true,
    }
}

/// Deep check for an HTTP cache: GET the narinfo, verify its `Sig:` against
/// the trust roster, then GET the NAR it names and verify the downloaded NAR's
/// content hash against the declared hash.
///
/// As with [`file_deep_ok`], the signature check raises the deep result from
/// internal consistency to authenticity; it is skipped only when
/// `trusted_keys` is empty.
async fn http_deep_ok(
    client: &reqwest::Client,
    base: &str,
    narinfo_url: &str,
    trusted_keys: &[String],
) -> DeepCheck {
    let Ok(response) = client.get(narinfo_url).send().await else {
        return DeepCheck::Missing;
    };
    if response.status() != reqwest::StatusCode::OK {
        return DeepCheck::Missing;
    }
    let Ok(text) = response.text().await else {
        return DeepCheck::Missing;
    };
    if !trusted_keys.is_empty() && verify_narinfo_signature(&text, trusted_keys).is_err() {
        return DeepCheck::Corrupt;
    }
    let Some(nar_rel) = narinfo_field(&text, "URL") else {
        return DeepCheck::Ok;
    };
    let nar_url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        nar_rel.trim_start_matches('/')
    );
    let Ok(response) = client.get(&nar_url).send().await else {
        return DeepCheck::Missing;
    };
    if response.status() != reqwest::StatusCode::OK {
        return DeepCheck::Missing;
    }
    let Ok(bytes) = response.bytes().await else {
        return DeepCheck::Missing;
    };
    verify_nar_bytes(&text, &bytes)
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

    /// Build a signed narinfo for `nar_bytes` and the matching trust roster
    /// key for a fixed test key, returning `(narinfo_text, trust_key_line)`.
    /// The narinfo's `FileHash`/`NarHash` are the SHA-256 of `nar_bytes`, so
    /// the NAR hash check passes and only the *signature* distinguishes a
    /// trusted from an untrusted roster.
    fn signed_narinfo_fixture(nar_bytes: &[u8]) -> (String, String) {
        use base64::Engine as _;
        use sha2::Digest as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let trust_key =
            aos_registry_surface::sshsig::trusted_key_line("demo", &key.verifying_key());

        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&key.to_bytes());
        secret.extend_from_slice(key.verifying_key().as_bytes());
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
        let signer =
            aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret_b64}"))
                .unwrap();

        let store_path = "/var/lib/store/abc123-pkg";
        let hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(nar_bytes)));
        let size = nar_bytes.len() as u64;
        let fingerprint =
            aos_core::nar::cache::NarInfoSigner::fingerprint(store_path, &hash, size as i64, &[]);
        let sig = signer.sign(&fingerprint).unwrap();
        let narinfo = format!(
            "StorePath: {store_path}\nURL: nar/abc.nar\nCompression: none\n\
             FileHash: {hash}\nFileSize: {size}\nNarHash: {hash}\nNarSize: {size}\nSig: {sig}\n",
        );
        (narinfo, trust_key)
    }

    #[test]
    fn narinfo_signature_accepts_trusted_and_rejects_others() {
        let (narinfo, trust_key) = signed_narinfo_fixture(b"narbytes");

        // A valid Sig by a trusted key verifies.
        verify_narinfo_signature(&narinfo, std::slice::from_ref(&trust_key)).unwrap();

        // An empty roster fails closed.
        assert!(verify_narinfo_signature(&narinfo, &[]).is_err());

        // A different trusted key (right name, wrong key) does not verify.
        let other = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let wrong = aos_registry_surface::sshsig::trusted_key_line("demo", &other.verifying_key());
        assert!(verify_narinfo_signature(&narinfo, &[wrong]).is_err());

        // A narinfo with no Sig at all is rejected.
        let unsigned: String = narinfo
            .lines()
            .filter(|l| !l.starts_with("Sig:"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(verify_narinfo_signature(&unsigned, std::slice::from_ref(&trust_key)).is_err());
    }

    #[tokio::test]
    async fn deep_validation_flags_untrusted_narinfo_signature() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("nar")).unwrap();

        let nar_bytes = b"good-nar-bytes";
        let (narinfo, trust_key) = signed_narinfo_fixture(nar_bytes);
        std::fs::write(dir.path().join("nar/abc.nar"), nar_bytes).unwrap();
        std::fs::write(dir.path().join("abc.narinfo"), &narinfo).unwrap();
        let hashes = vec!["abc".to_string()];

        // With the correct trust key, both the signature and the NAR hash pass:
        // a clean deep result, no corrupt finding.
        let trusted = vec![trust_key.clone()];
        let signed = probe_file_cache(dir.path(), &hashes, ValidationDepth::Deep, &trusted).await;
        assert!(signed.corrupt.is_empty(), "trusted narinfo passes deep");
        assert!(signed.missing.is_empty());

        // With an untrusted roster, the narinfo is flagged corrupt purely on
        // the failed signature, even though the NAR bytes match the declared
        // hash.
        let other = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let untrusted = vec![aos_registry_surface::sshsig::trusted_key_line(
            "demo",
            &other.verifying_key(),
        )];
        let bad = probe_file_cache(dir.path(), &hashes, ValidationDepth::Deep, &untrusted).await;
        assert_eq!(bad.corrupt, vec!["abc".to_string()]);
    }

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

    #[test]
    fn verify_nar_bytes_fails_closed_on_unparseable_declared_hash() {
        let bytes = b"some-nar-bytes";
        let good = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));

        // A good FileHash over the real bytes passes.
        let ok = format!("StorePath: /x\nCompression: none\nFileHash: {good}\nNarHash: {good}\n");
        assert!(matches!(verify_nar_bytes(&ok, bytes), DeepCheck::Ok));

        // A garbage FileHash that cannot be parsed must NOT short-circuit to
        // Ok; with a valid NarHash over tampered bytes the check falls through
        // to NarHash and flags the mismatch as corrupt.
        let tampered = b"tampered";
        let info =
            format!("StorePath: /x\nCompression: none\nFileHash: garbage\nNarHash: {good}\n");
        assert!(
            matches!(verify_nar_bytes(&info, tampered), DeepCheck::Corrupt),
            "unparseable FileHash + valid NarHash over tampered bytes must be corrupt"
        );

        // A declared-but-entirely-unparseable hash set fails closed (corrupt),
        // rather than silently accepting an uncheckable payload.
        let unparseable =
            "StorePath: /x\nCompression: none\nFileHash: garbage\nNarHash: nonsense\n";
        assert!(matches!(
            verify_nar_bytes(unparseable, bytes),
            DeepCheck::Corrupt
        ));

        // No integrity field at all: nothing to refute -> Ok.
        let none = "StorePath: /x\nCompression: none\n";
        assert!(matches!(verify_nar_bytes(none, bytes), DeepCheck::Ok));
    }

    #[tokio::test]
    async fn file_probe_reports_missing_and_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("aaa.narinfo"), b"StorePath: /x\n").unwrap();
        let hashes = vec!["aaa".to_string(), "bbb".to_string()];

        let outcome = probe_file_cache(dir.path(), &hashes, ValidationDepth::Presence, &[]).await;
        assert!(outcome.reachable);
        assert_eq!(outcome.checked, 2);
        assert_eq!(outcome.missing, vec!["bbb".to_string()]);

        let gone = probe_file_cache(
            &dir.path().join("nope"),
            &hashes,
            ValidationDepth::Presence,
            &[],
        )
        .await;
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

        let presence = probe_file_cache(dir.path(), &hashes, ValidationDepth::Presence, &[]).await;
        assert_eq!(presence.missing, Vec::<String>::new());

        let integrity =
            probe_file_cache(dir.path(), &hashes, ValidationDepth::Integrity, &[]).await;
        assert_eq!(integrity.missing, vec!["bbb".to_string()]);

        // A size mismatch also fails integrity.
        std::fs::write(
            dir.path().join("ccc.narinfo"),
            b"StorePath: /z\nURL: nar/aaa.nar\nFileSize: 999\n",
        )
        .unwrap();
        let mismatch = probe_file_cache(
            dir.path(),
            &["ccc".to_string()],
            ValidationDepth::Integrity,
            &[],
        )
        .await;
        assert_eq!(mismatch.missing, vec!["ccc".to_string()]);
    }

    #[test]
    fn sha256_hash_matches_all_encodings() {
        // SHA-256 of "abc".
        let digest =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        // hex
        assert_eq!(
            sha256_hash_matches(
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                &digest,
            ),
            Some(true)
        );
        // nix base32 (the stock `nix hash convert` value for "abc")
        assert_eq!(
            sha256_hash_matches(
                "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s",
                &digest,
            ),
            Some(true)
        );
        // SRI base64
        use base64::Engine as _;
        let sri = base64::engine::general_purpose::STANDARD.encode(&digest);
        assert_eq!(
            sha256_hash_matches(&format!("sha256-{sri}"), &digest),
            Some(true)
        );
        // A mismatch is refuted.
        assert_eq!(
            sha256_hash_matches(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                &digest,
            ),
            Some(false)
        );
        // An unrecognized form is un-refuted.
        assert_eq!(sha256_hash_matches("md5:deadbeef", &digest), None);
    }

    #[tokio::test]
    async fn deep_depth_flags_corrupt_nar_and_passes_good() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("nar")).unwrap();

        // A good NAR: FileHash matches its bytes.
        let good_bytes = b"good-nar-bytes";
        let good_hash = format!("sha256:{}", hex::encode(Sha256::digest(good_bytes)));
        std::fs::write(dir.path().join("nar/good.nar"), good_bytes).unwrap();
        std::fs::write(
            dir.path().join("good.narinfo"),
            format!(
                "StorePath: /x\nURL: nar/good.nar\nCompression: none\nFileSize: {}\nFileHash: {good_hash}\nNarHash: {good_hash}\n",
                good_bytes.len()
            ),
        )
        .unwrap();

        // A corrupt NAR: bytes do not match the declared FileHash.
        let bad_bytes = b"tampered-nar-bytes";
        std::fs::write(dir.path().join("nar/bad.nar"), bad_bytes).unwrap();
        std::fs::write(
            dir.path().join("bad.narinfo"),
            format!(
                "StorePath: /y\nURL: nar/bad.nar\nCompression: none\nFileSize: {}\nFileHash: {good_hash}\nNarHash: {good_hash}\n",
                bad_bytes.len()
            ),
        )
        .unwrap();

        let hashes = vec!["good".to_string(), "bad".to_string()];

        // Integrity passes both (NAR present, size matches).
        let integrity =
            probe_file_cache(dir.path(), &hashes, ValidationDepth::Integrity, &[]).await;
        assert!(integrity.missing.is_empty());
        assert!(integrity.corrupt.is_empty());

        // Deep flags the tampered NAR as corrupt, not missing.
        let deep = probe_file_cache(dir.path(), &hashes, ValidationDepth::Deep, &[]).await;
        assert!(deep.missing.is_empty(), "corrupt is not missing");
        assert_eq!(deep.corrupt, vec!["bad".to_string()]);
        assert_eq!(deep.problem_count(), 1);
    }

    #[tokio::test]
    async fn deep_validation_records_corrupt_finding() {
        let cache = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cache.path().join("nar")).unwrap();
        let bad_bytes = b"not-the-declared-bytes";
        // Declare a FileHash for different content.
        let declared = format!("sha256:{}", hex::encode(Sha256::digest(b"real-bytes")));
        std::fs::write(cache.path().join("nar/abc.nar"), bad_bytes).unwrap();
        std::fs::write(
            cache.path().join("abc.narinfo"),
            format!(
                "StorePath: /var/lib/store/abc-curl-8.5.0\nURL: nar/abc.nar\nCompression: none\nFileSize: {}\nFileHash: {declared}\nNarHash: {declared}\n",
                bad_bytes.len()
            ),
        )
        .unwrap();

        let cache_url = format!("file://{}", cache.path().display());
        let (db, registry) = registry_with_caches(vec![(cache_url.clone(), 100)]);

        let summaries = validate_registry(&db, &registry, ValidationDepth::Deep)
            .await
            .unwrap();
        let summary = summaries.iter().find(|s| s.cache_url == cache_url).unwrap();
        assert_eq!(summary.corrupt, 1);
        assert_eq!(summary.missing, 1, "corrupt counts toward problems");

        // The finding is recorded as `corrupt`, distinct from `missing`.
        let runs = db.latest_validation_runs(registry.id).unwrap();
        let run = runs.iter().find(|r| r.cache_url == cache_url).unwrap();
        assert_eq!(
            db.validation_corrupt(run.id).unwrap(),
            vec!["abc".to_string()]
        );
        assert!(db.validation_missing(run.id).unwrap().is_empty());

        // A corrupt hash is NOT planned for repair (a copy would carry the
        // same bad bytes).
        assert!(plan_repair(&db, &registry).unwrap().is_empty());
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
                corrupt: 0,
                reachable: true,
                coverage_percent: 100.0,
                mirror_shortfall: None,
            },
            ValidationSummary {
                cache_url: "https://b".into(),
                checked: 2,
                missing: 1,
                corrupt: 0,
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
