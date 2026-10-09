//! Caches records returned by typed Hub persistence operations.

use super::*;

/// One verified release and its complete artifact snapshot for retention evaluation.
#[derive(Debug, Clone)]
pub struct RetentionReleaseSnapshotRecord {
    /// Stable database release id.
    pub release_id: i64,
    /// Exact release tag spelling.
    pub tag: String,
    /// Verified tag object id.
    pub verified_tag_oid: String,
    /// Immutable verified tag timestamp.
    pub tagged_at: Option<i64>,
    /// Complete snapshot identity.
    pub snapshot_id: String,
    /// Complete snapshot manifest digest.
    pub manifest_digest: String,
    /// Artifact identities in canonical order.
    pub artifacts: Vec<ReleaseSnapshotArtifact>,
}

/// One live channel partition resolved to a complete release snapshot.
#[derive(Debug, Clone)]
pub struct RetentionChannelPartitionRecord {
    /// Stable channel database id.
    pub channel_id: i64,
    /// Channel name.
    pub channel_name: String,
    /// Partition bucket from 0 through 255.
    pub bucket: i64,
    /// Stable release database id.
    pub release_id: i64,
    /// Exact release tag spelling.
    pub release_tag: String,
    /// Complete release snapshot identity.
    pub snapshot_id: String,
    /// Complete snapshot artifacts.
    pub artifacts: Vec<ReleaseSnapshotArtifact>,
}

/// A registry workflow destination that populates one binary cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePopulationTargetRecord {
    /// Database id.
    pub id: i64,
    /// Destination binary cache.
    pub cache_id: i64,
    /// Source registry.
    pub registry_id: i64,
    /// Population trigger: `release`, `manual`, or `continuous`.
    pub trigger_kind: String,
    /// Whether failure blocks the publishing workflow.
    pub required: bool,
    /// Exact published placement-policy revision, when population does not use the cache default.
    pub placement_policy_revision_id: Option<String>,
    /// Serialized artifact selector.
    pub selector_json: String,
    /// Required validation gate.
    pub validation_gate: String,
    /// Whether the target may enqueue population work.
    pub enabled: bool,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// Input for creating or replacing a population target.
#[derive(Debug, Clone)]
pub struct SetCachePopulationTarget {
    /// Destination binary cache.
    pub cache_id: i64,
    /// Artifact-source registry.
    pub registry_id: i64,
    /// `release`, `manual`, or `continuous`.
    pub trigger_kind: String,
    /// Whether failure blocks publication.
    pub required: bool,
    /// Exact published placement-policy revision controlling destination writes.
    pub placement_policy_revision_id: Option<String>,
    /// Serialized artifact selector.
    pub selector_json: String,
    /// `none`, `presence`, `closure`, or `deep`.
    pub validation_gate: String,
    /// Whether population work may be enqueued.
    pub enabled: bool,
    /// Expected version, or `None` when creating the target.
    pub expected_version: Option<i64>,
}

/// A managed cache (system-of-record row) — a hub-hosted Nix binary cache.
///
/// A cache is a first-class sibling of a [`RegistryRecord`]: an org-scoped (or
/// instance-level) logical surface with zero or more topology placements,
/// optionally associated with a retained signing-key usage and exposed through routes.
/// Where a registry serves a git wire surface, a cache serves a Nix
/// binary cache (`nix-cache-info` + content-addressed NARs + Ed25519-signed
/// `.narinfo`). See RFC-0004 `11-caches`.
#[derive(Debug, Clone)]
pub struct BinaryCache {
    /// Database id.
    pub id: i64,
    /// Immutable non-reusable cache identity.
    pub stable_id: String,
    /// Exact cache authorization scope.
    pub scope_key: String,
    /// Infrastructure-owner scope used by placements and delivery grants.
    pub owner_scope_key: String,
    /// Owning org, or `None` for an instance-level standalone cache.
    pub org_id: Option<i64>,
    /// URL slug the cache is served under (globally unique).
    pub slug: String,
    /// Human-readable display name.
    pub name: String,
    /// Access scope: `public` | `internal` | `private`.
    pub visibility: String,
    /// `nix-cache-info` `Priority` (substituter ordering; lower = preferred).
    pub priority: i64,
    /// Default NAR compression (`zstd` | `xz` | `none`).
    pub compression: String,
    /// `nix-cache-info` `WantMassQuery` flag.
    pub want_mass_query: bool,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Soft-delete tombstone (unix seconds), or `None` while live.
    pub deleted_at: Option<i64>,
    /// When a soft-deleted cache becomes eligible for hard purge.
    pub purge_after: Option<i64>,
    /// Optimistic-concurrency version for identity and policy changes.
    pub resource_version: i64,
    /// Last identity or policy update time in Unix seconds.
    pub updated_at: i64,
}
