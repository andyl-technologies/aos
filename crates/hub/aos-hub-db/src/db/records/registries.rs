//! Registries records returned by typed Hub persistence operations.

use super::*;

/// A registered registry (system-of-record row).
#[derive(Debug, Clone)]
pub struct RegistryRecord {
    /// Database id.
    pub id: i64,
    /// Immutable non-reusable registry identity.
    pub stable_id: String,
    /// Exact registry authorization scope.
    pub scope_key: String,
    /// Infrastructure-owner scope used by placements and delivery grants.
    pub owner_scope_key: String,
    /// URL path slug the registry is served under.
    ///
    /// For phase-1 unowned registries this is a flat slug (`"cdn"`); for
    /// phase-2 managed registries it is the full canonical path
    /// (`"acme/infra/prod/cdn"`) — see the [module docs](self).
    pub slug: String,
    /// Pinned trust anchors in `name:Ed25519:<base64>` form.
    pub trust_keys: Vec<String>,
    /// Whether indexing fails closed on missing/invalid signatures.
    pub require_signatures: bool,
    /// Owning org id, or `None` for an instance-level unowned registry.
    pub org_id: Option<i64>,
    /// Owning project's materialized path (`""` for an org-root registry).
    pub project_path: String,
    /// Visibility: `public`, `internal`, or `private`.
    pub visibility: String,
    /// Crawl posture for the generated `robots.txt`: one of `allow_all`,
    /// `allow_no_ai`, or `deny_all` (see [`aos_hub_model::crawl::CrawlPolicy`]).
    pub crawl_policy: String,
    /// Operator-authored `llms.txt` body served verbatim, or `None` to serve
    /// the document generated from the registry's packages and channels.
    pub llms_txt_body: Option<String>,
    /// Optimistic concurrency version for registry configuration.
    pub resource_version: i64,
    /// Last configuration update time in Unix seconds.
    pub updated_at: i64,
}

/// Index freshness state for one registry.
#[derive(Debug, Clone)]
pub struct IndexStatus {
    /// `fresh`, `indexing`, `stale`, or `failed`.
    pub state: String,
    /// Failure detail when `state = failed`.
    pub error: Option<String>,
    /// The commit the current index was built from.
    pub last_indexed_commit: Option<String>,
    /// Committed registry name from `registry.toml`.
    pub name: Option<String>,
    /// Committed registry description.
    pub description: Option<String>,
    /// Committed registry readme (longer preamble), shown on the home page.
    pub readme: Option<String>,
    /// Committed release-train support policy from `registry.toml`.
    pub support: Option<aos_registry_format::support::SupportPolicy>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
    /// Monotonic immutable index generation.
    pub generation: i64,
    /// Digest of every retention-relevant row in this generation.
    pub content_digest: Option<String>,
}

/// One package row for index pages.
#[derive(Debug, Clone)]
pub struct PackageRow {
    /// Package name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Published license metadata.
    pub license: String,
    /// Latest indexed version string.
    pub latest_version: Option<String>,
    /// Closure size in bytes of the latest version's primary platform
    /// artifact (the platform that sorts first), or `None` when the latest
    /// version has no platform artifacts.
    pub closure_size: Option<u64>,
    /// Platform triples published for the latest version, sorted.
    pub platforms: Vec<String>,
}

/// Full package detail for the package page.
#[derive(Debug, Clone)]
pub struct PackageDetail {
    /// Package name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Optional homepage URL.
    pub homepage: Option<String>,
    /// Published license metadata.
    pub license: String,
    /// Maintainer handle.
    pub maintainer: String,
    /// Whether the package is a system toplevel.
    pub sysroot: bool,
    /// Versions, newest first, with their platform artifacts.
    pub versions: Vec<VersionDetail>,
}

/// One version of a package, with platform artifacts.
#[derive(Debug, Clone)]
pub struct VersionDetail {
    /// Version string.
    pub version: String,
    /// Previous version in the sysroot chain.
    pub previous: Option<String>,
    /// Per-platform artifacts.
    pub platforms: Vec<PlatformDetail>,
}

/// One platform artifact row.
#[derive(Debug, Clone)]
pub struct PlatformDetail {
    /// Platform triple.
    pub platform: String,
    /// Store path of the output.
    pub store_path: String,
    /// NAR hash.
    pub nar_hash: String,
    /// NAR size in bytes.
    pub nar_size: u64,
    /// Closure size in bytes.
    pub closure_size: u64,
    /// Store path of the derivation that produced this output, or empty when
    /// the index did not record one (rows written before schema v19).
    pub source_drv: String,
    /// Referenced store hashes (the `refs` JSON column).
    pub refs: Vec<String>,
    /// Sysroot disk images (the `images` JSON column).
    pub images: Vec<ImageDetail>,
}

/// A registry's upstream mirror source (system-of-record row).
///
/// A registry that has a `mirror_sources` row *is* a mirror (see
/// [`Database::is_mirror`]). The [`MirrorSource::mode`] selects the
/// replication strategy: `full` copies the verified upstream surface into the
/// local binding on a schedule; `pullthrough` fetches on demand through a Hub
/// route. See the hub's `mirror` module for sync and fetch logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSource {
    /// The upstream registry surface URL (`file://`, `/path`, or `http(s)://`).
    pub upstream_url: String,
    /// Replication mode: `full` (scheduled byte-identical copy) or
    /// `pullthrough` (fetch-on-miss proxy).
    pub mode: String,
    /// Whether the full-mirror sync verifies upstream signatures before
    /// accepting anything (default `true`; a poisoned upstream never
    /// propagates).
    pub verify: bool,
    /// Full-mirror sync cadence, in seconds.
    pub schedule_secs: i64,
    /// Unix time of the last completed sync attempt, or `None` if never run.
    pub last_sync_at: Option<i64>,
    /// Outcome of the last sync attempt: `ok` or `failed`, or `None` if never
    /// run.
    pub last_sync_status: Option<String>,
    /// Failure detail when [`Self::last_sync_status`] is `failed`.
    pub last_sync_error: Option<String>,
    /// The upstream channel frontier observed at the last successful sync.
    pub upstream_frontier: Option<String>,
}

/// Final registry-owned upstream synchronization configuration and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryMirrorRecord {
    /// Registry database identity.
    pub registry_id: i64,
    /// Validated HTTP(S) upstream root.
    pub source_url: String,
    /// Upstream ref-selection expression.
    pub refspec: String,
    /// Write-only secret-manager reference used by the mirror controller.
    pub auth_secret_ref: String,
    /// `full` or `pull_through`.
    pub mode: String,
    /// `required` or `allow_unsigned`.
    pub signature_policy: String,
    /// Full-mirror polling interval.
    pub interval_seconds: i64,
    /// Latest controller state.
    pub state: String,
    /// Latest observed upstream frontier.
    pub observed_commit: Option<String>,
    /// Latest controller failure.
    pub error: Option<String>,
    /// Latest controller attempt time.
    pub last_sync_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One immutable registry publication assembled before mutable pointers move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationRecord {
    /// Stable opaque publication id.
    pub publication_id: String,
    /// Registry whose bytes and pointers are published.
    pub registry_id: i64,
    /// Monotonic per-registry ordering number.
    pub ordinal: i64,
    /// Source generation identifier.
    pub generation: String,
    /// Digest of the immutable publication manifest.
    pub manifest_digest: String,
    /// Digest of the complete refs snapshot.
    pub refs_digest: String,
    /// Default Git commit, when the registry defines one.
    pub default_commit: Option<String>,
    /// Immediately preceding publication, when any.
    pub parent_publication_id: Option<String>,
    /// `preparing`, `writing_pointers`, `ready`, `failed`, or `retired`.
    pub state: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Completion time once ready or retired.
    pub completed_at: Option<i64>,
    /// Retirement time.
    pub retired_at: Option<i64>,
}

/// One keyset-paginated registry publication inventory page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationPage {
    /// Publications in newest-first ordinal order.
    pub records: Vec<RegistryPublicationRecord>,
    /// Exclusive ordinal cursor for the next page.
    pub next_cursor: Option<i64>,
}

/// The single authoritative current-publication pointer for a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationStateRecord {
    /// Registry owning this singleton state row.
    pub registry_id: i64,
    /// Current ready publication, or `None` before first publication.
    pub current_publication_id: Option<String>,
    /// Ordinal reserved for the next publication.
    pub next_ordinal: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// Immutable expected-object snapshot captured by one publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationObjectRecord {
    /// Publication owning the snapshot entry.
    pub publication_id: String,
    /// Registry repeated to enforce same-registry composite references.
    pub registry_id: i64,
    /// Logical surface object.
    pub surface_object_id: i64,
    /// Snapshotted object kind.
    pub object_kind: String,
    /// Expected content digest.
    pub expected_hash: String,
    /// Expected byte size.
    pub expected_size: i64,
}

/// Expected object snapshot attached to a preparing registry publication.
#[derive(Debug, Clone)]
pub struct SetRegistryPublicationObject {
    /// Publication receiving the immutable snapshot row.
    pub publication_id: String,
    /// Logical registry object included by the publication.
    pub surface_object_id: i64,
    /// Snapshotted object kind.
    pub object_kind: String,
    /// Expected content digest.
    pub expected_hash: String,
    /// Expected byte size.
    pub expected_size: i64,
}

/// Immutable fields used to begin one registry publication.
#[derive(Debug, Clone)]
pub struct NewRegistryPublication {
    /// Stable opaque publication id.
    pub publication_id: String,
    /// Registry receiving the publication.
    pub registry_id: i64,
    /// Producer generation identifier.
    pub generation: String,
    /// Digest of the complete declared object manifest.
    pub manifest_digest: String,
    /// Digest of the complete refs snapshot.
    pub refs_digest: String,
    /// Default Git commit, when the registry defines one.
    pub default_commit: Option<String>,
    /// Current publication observed by the producer.
    pub parent_publication_id: Option<String>,
}

/// One declared publication object together with its stable upload identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationUploadObjectRecord {
    /// Publication owning the object.
    pub publication_id: String,
    /// Registry owning the object.
    pub registry_id: i64,
    /// Stable logical object id used by the typed upload URL.
    pub surface_object_id: i64,
    /// Surface-relative machine path.
    pub object_key: String,
    /// `immutable` or `mutable_pointer`.
    pub object_kind: String,
    /// Exact lowercase SHA-256 digest.
    pub expected_hash: String,
    /// Exact byte size.
    pub expected_size: i64,
    /// Whether every required publication placement has exact observed bytes.
    pub verified: bool,
}

/// One durable multipart transaction for a declared publication object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationMultipartUploadRecord {
    /// Opaque upload identity carried by multipart requests.
    pub upload_id: String,
    /// Publication owning the object.
    pub publication_id: String,
    /// Registry owning the publication.
    pub registry_id: i64,
    /// Stable logical object id.
    pub surface_object_id: i64,
    /// `active`, `completing`, `completed`, `aborted`, or `failed`.
    pub state: String,
    /// Expiry time in Unix seconds.
    pub expires_at: i64,
    /// Number of contiguous object bytes incorporated into `sha256_state`.
    pub hashed_size: i64,
    /// Portable hexadecimal SHA-256 compression state.
    pub sha256_state: String,
    /// Part currently claimed for a provider write, when any.
    pub pending_part: Option<i64>,
    /// Exact body digest for the claimed part.
    pub pending_hash: Option<String>,
    /// Unique lease owner authorized to commit the claimed provider writes.
    pub pending_token: Option<String>,
    /// Claim acquisition time in Unix seconds.
    pub pending_since: Option<i64>,
    /// Unique request authorized to perform provider completion.
    pub completion_token: Option<String>,
    /// Completion ownership acquisition time in Unix seconds.
    pub completion_since: Option<i64>,
}

/// One backend-confirmed part identity retained for crash-safe completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationMultipartPartRecord {
    /// Opaque upload identity owning the part.
    pub upload_id: String,
    /// 1-based contiguous part number.
    pub part_number: u32,
    /// Frozen physical placement that accepted the part.
    pub placement_id: i64,
    /// Opaque backend entity tag required at completion.
    pub etag: String,
}

/// The full index payload one successful indexing run produces.
#[derive(Debug, Clone, Default)]
pub struct IndexSnapshot {
    /// The commit the snapshot was loaded from.
    pub commit: String,
    /// Verified release commit selected by the default signed channel.
    pub public_catalog_commit: Option<String>,
    /// Exact release tag selected by the default signed channel.
    pub public_catalog_release: Option<String>,
    /// Committed registry name.
    pub name: String,
    /// Committed registry description.
    pub description: Option<String>,
    /// Committed registry readme (longer preamble).
    pub readme: Option<String>,
    /// Committed release-train support policy as canonical JSON.
    pub support: Option<String>,
    /// The committed `[caches]` stack flattened to `(url, priority)` entries.
    ///
    /// This is the priority list a stack-unaware client resolves; when the
    /// snapshot also carries a [`Self::cache_stack`] it is the flattening of
    /// that same stack.
    pub caches: Vec<(String, u32)>,
    /// The committed `[caches]` stack expression as compact JSON
    /// ([`aos_registry_format::stack::StackNode::to_json`]), or `None` when the registry has
    /// no committed cache stack.
    pub cache_stack: Option<String>,
    /// Roster entries as `(key_id, public_key, status)`.
    pub roster: Vec<(String, String, String)>,
    /// Full package documents.
    pub packages: Vec<aos_registry_format::manifest::PackageToml>,
    /// Verified releases.
    pub releases: Vec<ReleaseRow>,
    /// Complete immutable artifact snapshots for verified releases.
    pub release_artifact_snapshots: Vec<ReleaseArtifactSnapshot>,
    /// Direct-delivery catalogs loaded from exact signed release commits.
    pub release_images: Vec<ReleaseImageSnapshot>,
    /// Channels with verified partition maps.
    pub channels: Vec<ChannelSummary>,
    /// SHA-256 hex digest of the raw `info/refs` bytes the snapshot was
    /// built from; powers the incremental channel-refresh fast path.
    pub refs_digest: Option<String>,
}
