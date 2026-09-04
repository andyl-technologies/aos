//! Tenant-bound OCI administration records and persistence operations.
//!
//! The Distribution API owns byte transfer. This module owns the bounded
//! control-plane projections used by an authenticated administration service:
//! repository metadata, immutable graph inspection, signed-release provenance,
//! durable mutation plans, manual-tag compare-and-swap, and retention policy
//! configuration. Every public lookup begins with an exact registry id; a
//! caller-authorized repository id is never treated as authority on its own.
//!
//! List cursors use a canonical base64url JSON envelope:
//!
//! ```text
//! {"version":1,"registryId":7,"selectorDigest":"sha256:...",
//!  "mutationEpoch":42,"afterPrimary":"aos","afterSecondary":""}
//! ```
//!
//! The selector digest prevents a cursor from moving between resources or
//! filters. The registry mutation epoch makes a page set a stable snapshot:
//! any intervening catalog or administration mutation rejects the cursor.

use aos_oci_types::{Descriptor, MediaType, Platform, RepositoryName, Sha256Digest, Tag};

mod cursor;
mod mutation;
mod read;

#[cfg(test)]
mod tests;

pub use mutation::*;

/// Maximum records returned by one OCI administration page.
pub const OCI_ADMIN_MAX_PAGE_SIZE: u32 = 250;

/// Maximum UTF-8 bytes accepted for a repository description.
pub const OCI_REPOSITORY_DESCRIPTION_MAX_BYTES: usize = 4_096;

/// Effective untagged-content grace period when no registry policy is stored.
pub const OCI_RETENTION_DEFAULT_UNTAGGED_GRACE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Effective deleted tag-history period when no registry policy is stored.
pub const OCI_RETENTION_DEFAULT_DELETED_TAG_HISTORY_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Effective recent manual-tag revision count when no registry policy is stored.
pub const OCI_RETENTION_DEFAULT_RECENT_MANUAL_TAG_REVISIONS: u32 = 10;

/// Effective referrer-root behavior when no registry policy is stored.
pub const OCI_RETENTION_DEFAULT_RETAIN_REFERRERS: bool = true;

/// One cursor-bound page from an OCI administration read model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminPage<T> {
    /// Records in deterministic keyset order.
    pub items: Vec<T>,
    /// Opaque cursor for the next page, or `None` at the end.
    pub next_cursor: Option<String>,
    /// Registry mutation epoch captured for this page set.
    pub mutation_epoch: i64,
}

/// Repository summary with inherited registry visibility and bounded counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminRepositoryRecord {
    /// Portable repository id.
    pub id: i64,
    /// Owning registry id.
    pub registry_id: i64,
    /// Registry-local canonical repository name.
    pub name: RepositoryName,
    /// Operator-authored description.
    pub description: String,
    /// Visibility inherited from the owning registry.
    pub inherited_visibility: String,
    /// Repository lifecycle state.
    pub lifecycle_state: String,
    /// Repository optimistic-concurrency version.
    pub resource_version: i64,
    /// Metadata optimistic-concurrency version.
    pub metadata_resource_version: i64,
    /// Number of linked immutable manifests and indexes.
    pub manifest_count: u64,
    /// Sum of all repository-linked compressed/config/manifest bytes.
    pub compressed_byte_size: u64,
    /// Bytes linked only from this repository within the registry.
    pub unique_byte_size: u64,
    /// Number of current tag pointers.
    pub tag_count: u64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last repository or metadata mutation time in Unix seconds.
    pub updated_at: i64,
}

/// Selector bound into a repository-list cursor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciRepositoryListFilter {
    /// Optional bytewise repository-name prefix.
    pub repository_prefix: Option<String>,
    /// Optional exact `active`, `deleting`, or `deleted` lifecycle state.
    pub lifecycle_state: Option<String>,
}

/// Current tag pointer with exact target and signed ownership context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminTagRecord {
    /// Case-sensitive tag.
    pub name: Tag,
    /// Current manifest or index digest.
    pub digest: Sha256Digest,
    /// Exact target media type.
    pub media_type: MediaType,
    /// `manual`, `release`, or `channel`.
    pub ownership_kind: String,
    /// Signed release identity, when release-owned.
    pub release: Option<String>,
    /// Signed channel identity, when channel-owned.
    pub channel: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Immutable creation time in Unix seconds.
    pub created_at: i64,
    /// Last move time in Unix seconds.
    pub updated_at: i64,
}

/// Selector bound into a tag-list cursor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciTagListFilter {
    /// Optional bytewise tag prefix.
    pub tag_prefix: Option<String>,
    /// Optional exact `manual`, `release`, or `channel` owner.
    pub ownership_kind: Option<String>,
}

/// One immutable tag-history transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminTagHistoryRecord {
    /// Stable history id.
    pub id: String,
    /// Case-sensitive tag name.
    pub name: Tag,
    /// Prior target, absent for first creation.
    pub prior_digest: Option<Sha256Digest>,
    /// Next target, absent for deletion.
    pub next_digest: Option<Sha256Digest>,
    /// `manual`, `release`, `channel`, or `retention`.
    pub source_kind: String,
    /// Stable actor identity recorded at mutation time.
    pub actor_id: String,
    /// Per-tag monotonic transition version.
    pub resource_version: i64,
    /// Mutation time in Unix seconds.
    pub changed_at: i64,
}

/// Exact repository-bound manifest or image index inspection record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminManifestRecord {
    /// Exact immutable manifest or index digest.
    pub digest: Sha256Digest,
    /// Exact document media type.
    pub media_type: MediaType,
    /// Exact serialized byte length.
    pub byte_size: u64,
    /// Artifact payload type, when this is an artifact manifest.
    pub artifact_type: Option<MediaType>,
    /// Referred subject digest, when this is an artifact manifest.
    pub subject_digest: Option<Sha256Digest>,
    /// Runnable image configuration digest, when present.
    pub config_digest: Option<Sha256Digest>,
    /// Validated document annotations.
    pub annotations: aos_oci_types::Annotations,
    /// Exact number of filesystem layer edges.
    pub layer_count: u32,
    /// Exact number of child manifest edges.
    pub child_count: u32,
    /// Catalog admission time in Unix seconds.
    pub created_at: i64,
}

/// One runnable platform projected from an index child or direct manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminPlatformRecord {
    /// Root index or direct manifest digest.
    pub root_digest: Sha256Digest,
    /// Runnable manifest digest.
    pub manifest_digest: Sha256Digest,
    /// Exact runnable-manifest media type.
    pub media_type: MediaType,
    /// Exact manifest byte length.
    pub byte_size: u64,
    /// Config-derived or signed index-descriptor platform.
    pub platform: Platform,
    /// Runnable image configuration digest.
    pub config_digest: Sha256Digest,
    /// Number of filesystem layer descriptors.
    pub layer_count: u32,
    /// Canonical Nix platform selector, such as `x86_64-linux`.
    pub aos_system: String,
    /// Config plus compressed layer bytes.
    pub compressed_byte_size: u64,
    /// Sum of independently verified uncompressed layer bytes.
    pub unpacked_byte_size: u64,
    /// Exact bounded image configuration JSON.
    pub config_json: String,
}

/// One layer or artifact-payload edge in manifest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminLayerRecord {
    /// Root index or direct manifest digest.
    pub root_digest: Sha256Digest,
    /// Runnable manifest carrying this layer.
    pub manifest_digest: Sha256Digest,
    /// Zero-based descriptor order within its role.
    pub ordinal: u32,
    /// Exact immutable descriptor.
    pub descriptor: Descriptor,
    /// Independently verified uncompressed tar byte length.
    pub unpacked_byte_size: u64,
    /// Number of repositories in this registry linking the layer digest.
    pub shared_repository_count: u64,
    /// Exact uncompressed DiffID from the image configuration.
    pub diff_id: Sha256Digest,
    /// Signed AOS closure group, or an empty string for non-closure layers.
    pub closure_group: String,
}

/// Referrer descriptor with its persisted verification state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminReferrerRecord {
    /// Exact referred subject.
    pub subject_digest: Sha256Digest,
    /// Exact referrer descriptor.
    pub descriptor: Descriptor,
    /// `verified` when bound by a signed release root, otherwise `unverified`.
    pub verification: String,
    /// Catalog admission time in Unix seconds.
    pub created_at: i64,
}

/// Secret-free durable publication summary for operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminPublicationRecord {
    /// Stable publication id.
    pub id: String,
    /// Destination repository name.
    pub repository: RepositoryName,
    /// Optional target tag.
    pub target_tag: Option<Tag>,
    /// Exact declared graph root.
    pub root_digest: Sha256Digest,
    /// Frozen catalog declaration digest.
    pub catalog_digest: Sha256Digest,
    /// Signed release tag, when applicable.
    pub release_tag: Option<String>,
    /// Review confirmation hash.
    pub confirmation_hash: Sha256Digest,
    /// Frozen topology capability digest.
    pub topology_digest: Sha256Digest,
    /// Number of required placements.
    pub required_placement_count: u32,
    /// `manual`, `release`, or `channel`.
    pub source_kind: String,
    /// Durable lifecycle state.
    pub state: String,
    /// Session expiration time in Unix seconds.
    pub expires_at: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Commit time in Unix seconds, when ready.
    pub committed_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Signed source provenance for one indexed container release root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminProvenanceRecord {
    /// Registry-local repository name.
    pub repository: RepositoryName,
    /// Exact publishable index digest.
    pub root_digest: Sha256Digest,
    /// AOS package represented by the image.
    pub package: String,
    /// Verified release identity.
    pub release: String,
    /// Verified channel identity, when the root is channel-published.
    pub channel: Option<String>,
    /// Exact signed release-root identity.
    pub signed_release_root: String,
    /// SHA-256 of the exact signed container-release sidecar.
    pub catalog_digest: Sha256Digest,
    /// Persisted verification state.
    pub verification: String,
    /// Complete signed Nix closure projection.
    pub closure_members: Vec<OciAdminClosureMemberRecord>,
    /// Complete signed evidence projection.
    pub evidence: Vec<OciAdminEvidenceRecord>,
    /// Time the release root was verified.
    pub verified_at: i64,
}

/// One signed Nix closure member mapped to its image layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminClosureMemberRecord {
    /// Full Nix store path.
    pub store_path: String,
    /// Exact NAR hash.
    pub nar_hash: String,
    /// Uncompressed NAR byte length.
    pub nar_size: u64,
    /// Image layer containing the store path.
    pub layer_digest: Sha256Digest,
    /// Whether this path is a direct release root.
    pub direct: bool,
}

/// One mandatory signed release-evidence role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminEvidenceRecord {
    /// Stable evidence role.
    pub kind: String,
    /// Evidence payload or role digest.
    pub digest: Sha256Digest,
    /// Exact evidence media type.
    pub media_type: MediaType,
    /// Persisted verification state.
    pub verification: String,
    /// OCI referrer manifest carrying the evidence.
    pub referrer_digest: Sha256Digest,
}

/// Registry-scoped OCI retention policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRetentionPolicyRecord {
    /// Owning registry id.
    pub registry_id: i64,
    /// Minimum age of untagged content before it may become collectible.
    pub untagged_grace_seconds: u64,
    /// Age after which deleted tag-history records may be trimmed.
    pub deleted_tag_history_seconds: u64,
    /// Recent manual tag revisions retained regardless of age.
    pub recent_manual_tag_revisions: u32,
    /// Whether referrers of retained subjects remain roots.
    pub retain_referrers: bool,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}
